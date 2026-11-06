"""QuantumGuard command-line entry point.

    python main.py capture      Phase 1   eBPF capture with CCA
    python main.py graph        Phase 2/3 normalise and build the graph
    python main.py visualize              readable picture of the graph
    python main.py train        Phase 4   train the GraphSAGE detector
    python main.py detect       Phase 4   rule + GNN poisoning detection
    python main.py seal         Phase 5   Merkle partitions, dual signing
    python main.py anchor       Phase 6   risk scoring and tiered anchoring
    python main.py evaluate     Phase 7   forensic survivability
    python main.py verify                 verify everything independently
    python main.py tamper apply           write a tampered copy of the graph
    python main.py tamper test            attack every layer and score it
    python main.py all                    the whole pipeline, in order
    python main.py demo                   offline end-to-end demonstration
"""
from __future__ import annotations

import argparse
import json
import pickle
import uuid
from pathlib import Path

from core import config


def _load_graph(path: str | None):
    graph_path = Path(path or config.GRAPH_PICKLE)
    if not graph_path.exists():
        raise SystemExit(
            f"graph not found: {graph_path}\n"
            f"  build one with : python main.py graph\n"
            f"  or run offline : python main.py demo")
    with graph_path.open("rb") as handle:
        return pickle.load(handle)


def _known_missing() -> set[int]:
    """Sequences CCA already attested as lost - see detection rule R7."""
    from core.store import get_store
    try:
        return get_store().load_missing_sequences()
    except Exception as exc:
        print(f"[detect] note: could not load CCA attestations ({exc}); "
              f"sequence_gap cannot rule out capture loss")
        return set()


def _persist(label: str, action) -> None:
    """Write a phase result to the store without letting an outage abort
    the run - the JSON report on disk is already written by then."""
    try:
        action()
    except Exception as exc:
        reason = str(getattr(exc, "orig", None) or exc).strip().splitlines()[0]
        print(f"[{label}] note: result not written to the store ({reason}); "
              f"has database/schema.sql been re-applied?")


def _latest_run_id(store) -> str | None:
    """Run id of the most recently sealed run.

    Partition indices restart at 0 for every run, so loading several runs
    at once would make partitions from different runs overwrite one
    another inside the risk scorer. A command that operates on "the"
    sealed run therefore has to pick exactly one.
    """
    latest: dict[str, str] = {}
    for record in store.load_partitions():
        run, created = record.get("run_id"), str(record.get("created_at") or "")
        if run and created >= latest.get(run, ""):
            latest[run] = created
    return max(latest, key=latest.get) if latest else None


# ======================================================================
# Phases
# ======================================================================


def capture(args):
    from capture.collector import EBPFCollector
    EBPFCollector(run_id=args.run_id).start()


def graph(args):
    from graph.service import ProvenanceGraphService
    result = ProvenanceGraphService().run()
    print(f"Graph saved: {result.number_of_nodes()} nodes, "
          f"{result.number_of_edges()} edges")

    # An empty graph is almost always "no events captured yet" rather
    # than a real result, and every later phase would otherwise run
    # against nothing and report a meaningless pass.
    if result.number_of_edges() == 0:
        print("\n  WARNING: the graph is empty - no captured events were "
              "found in the store.\n"
              "  Capture some first  : python main.py capture\n"
              "  Or run fully offline: python main.py demo\n")
    return result


def visualize(args):
    from graph.visualize import main as draw_graph
    draw_graph(args.graph, args.output, args.max_programs)


def train(args):
    from detection.model import main as train_model
    import sys
    argv = sys.argv
    try:
        sys.argv = ["detection.model", "--epochs", str(args.epochs),
                    "--graph", args.graph or config.GRAPH_PICKLE]
        if getattr(args, "synthetic", None):
            sys.argv += ["--synthetic", str(args.synthetic)]
        train_model()
    finally:
        sys.argv = argv


def detect(args):
    from detection.detector import PoisoningDetector, format_report
    from core.store import get_store

    report = PoisoningDetector(
        known_missing_sequences=_known_missing()
    ).detect(_load_graph(args.graph), run_id=args.run_id)

    print(format_report(report))

    if getattr(args, "persist", False):
        get_store().save_detection_report(report)
    if getattr(args, "output", None):
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Report: {output}")
    return report


def seal(args):
    from crypto.integrity import EvidenceVerifier, IntegrityService, export_evidence

    graph_data = _load_graph(args.graph)
    service = IntegrityService(partition_size=args.partition_size)
    run_id = args.run_id or str(uuid.uuid4())
    records = service.seal(graph_data, run_id=run_id)
    evidence = export_evidence(records, args.output)
    report = EvidenceVerifier(store=service.store).verify(
        graph_data, records=records)

    print(f"Run id     : {run_id}")
    print(f"Evidence   : {evidence}")
    print(f"Partitions : {len(records)}")
    print(f"Signed by  : Ed25519 + {records[0]['mldsa_algorithm']}")
    print(f"Verified   : {'PASS' if report.ok else 'FAIL'}")

    # so `all` anchors exactly the run it just sealed
    args.run_id = run_id
    return records


def anchor(args):
    """Phase 6 - score every sealed partition and anchor by risk tier."""
    from anchoring.service import AnchoringService, format_report
    from anchoring.ledger import get_ledger
    from crypto.integrity import partition_graph
    from core.store import get_store

    graph_data = _load_graph(args.graph)
    store = get_store()
    if not args.run_id:
        args.run_id = _latest_run_id(store)
        if args.run_id:
            print(f"no --run-id given; anchoring the latest sealed run "
                  f"{args.run_id}\n")
    records = store.load_partitions(args.run_id) if args.run_id else []
    if not records:
        raise SystemExit(
            "no sealed partitions found; run 'python main.py seal' first")

    report = None
    report_path = Path(config.EVIDENCE_DIR) / "detection_report.json"
    if report_path.exists():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        # Risk computed from another graph's verdict would be meaningless.
        if (report.get("graph_nodes"), report.get("graph_edges")) != (
                graph_data.number_of_nodes(), graph_data.number_of_edges()):
            print("note: detection_report.json describes a different graph; "
                  "ignoring it. Run 'python main.py detect' first.\n")
            report = None

    service = AnchoringService(ledger=get_ledger(args.ledger),
                               batch_size=args.batch_size)
    # The size the run was actually sealed with, not whatever this command
    # was given, or edges get attributed to the wrong partitions.
    partitions = partition_graph(graph_data, records[0]["leaf_count"])
    result = service.anchor_run(
        records, graph=graph_data, partitions=partitions, report=report,
        tamper_alert_indices=service.alerted_partitions(
            records, graph_data, report, partitions))

    print(format_report(result))
    checks = service.verify_run(result)
    print(f"  anchors verified    : "
          f"{'PASS' if checks['ok'] else 'FAIL'}  "
          f"({checks['externally_anchored']} external, "
          f"{checks['local_only']} local-only)")
    print(f"  ledger              : {checks['ledger']['path']} "
          f"({checks['ledger']['blocks']} blocks)")
    _persist("anchor", lambda: store.save_anchor_receipts(result))
    return result


def evaluate(args):
    from evaluation.main import evaluate as run_evaluation, format_report, save_report

    metrics = run_evaluation(_load_graph(args.graph), args.ratio,
                             args.seed, args.mode)
    print(format_report(metrics))
    print(f"Report: {save_report(metrics, args.output)}")

    from core.store import get_store
    _persist("evaluate", lambda: get_store().save_survivability_report(
        metrics, run_id=args.run_id))
    return metrics


def verify(args):
    """Independently verify sealed evidence, anchors and certificates."""
    from crypto.integrity import EvidenceVerifier
    from core.store import get_store

    from crypto.integrity import DualVerifier, KeyStore, load_trust_file

    graph_data = None if args.no_graph else _load_graph(args.graph)
    store = get_store()

    if not args.run_id:
        args.run_id = _latest_run_id(store)
        if args.run_id:
            print(f"no --run-id given; verifying the latest sealed run "
                  f"{args.run_id}\n")

    # Records carry their own public keys, so the expected signer has to come
    # from somewhere else, or re-signed evidence verifies.
    trust = load_trust_file(args.trust_file) if args.trust_file \
        else KeyStore.public_identity()
    if trust:
        print(f"signer pinned to {trust['ed25519_public_key'][:16]}... "
              f"({'trust file' if args.trust_file else 'local key store'})")
        if not args.trust_file:
            print("  a root attacker can replace the local key store too; "
                  "use --trust-file with a copy kept off this host\n")
    else:
        print("WARNING: no key store or --trust-file: the signer is not "
              "pinned, so re-signed evidence would verify\n")
    pins = (trust["ed25519_public_key"], trust["mldsa_public_key"]) if trust \
        else (None, None)
    pinned = DualVerifier(*pins)

    report = EvidenceVerifier(store, *pins).verify(
        graph_data, run_id=args.run_id,
        partition_size=args.partition_size)
    print(report)

    ok = report.ok

    # the check anchoring exists for: does the ledger agree with the evidence?
    records = store.load_partitions(args.run_id) if args.run_id else []
    if records:
        from anchoring.service import AnchoringService
        from anchoring.ledger import get_ledger
        problems = AnchoringService(
            ledger=get_ledger(args.ledger)).cross_check(records)
        print(f"\nEvidence vs ledger: {'PASS' if not problems else 'FAIL'}")
        for problem in problems[:5]:
            print(f"  {problem}")
        ok = ok and not problems

    # anchors, if a Phase 6 report exists
    anchor_path = Path(config.ANCHOR_REPORT)
    if anchor_path.exists():
        from anchoring.service import AnchoringService
        from anchoring.ledger import get_ledger
        result = json.loads(anchor_path.read_text(encoding="utf-8"))
        if args.run_id and result.get("run_id") != args.run_id:
            print(f"\nnote: {anchor_path} describes run {result.get('run_id')}; "
                  f"its partitions are not this run's")
        checks = AnchoringService(ledger=get_ledger(args.ledger)).verify_run(
            result, pinned)
        print(f"\nAnchors: {'PASS' if checks['ok'] else 'FAIL'}  "
              f"({checks['externally_anchored']} externally anchored, "
              f"{checks['local_only']} local-only, "
              f"ledger {checks['ledger']['blocks']} blocks)")
        for failure in checks["failures"][:5]:
            print(f"  partition {failure['partition_index']}: {failure['reason']}")
        ok = ok and checks["ok"]

    # completeness certificates, if any
    from capture.cca import verify_certificate
    certificates = sorted(Path(config.EVIDENCE_DIR).glob("completeness_*.json"))
    for path in certificates:
        result = verify_certificate(
            json.loads(path.read_text(encoding="utf-8")), pinned)
        print(f"\nCompleteness {path.name}: "
              f"{'PASS' if result['ok'] else 'FAIL'}  "
              f"range {result['range'][0]}-{result['range'][1]}, "
              f"{len(result['attested_missing'])} attested missing")
        ok = ok and result["ok"]

    raise SystemExit(0 if ok else 2)


def certify(args):
    """Re-verify a standalone completeness certificate."""
    from capture.cca import verify_certificate
    result = verify_certificate(
        json.loads(Path(args.certificate).read_text(encoding="utf-8")))
    print(json.dumps(result, indent=2, default=str))
    raise SystemExit(0 if result["ok"] else 2)


# ======================================================================
# Composite commands
# ======================================================================


def all_steps(args):
    built = graph(args)
    if built.number_of_edges() == 0:
        raise SystemExit(
            "stopping: there is nothing to detect, seal, anchor or "
            "evaluate.\nRun 'python main.py capture' first, or "
            "'python main.py demo' for an offline demonstration.")

    # Each phase writes its own artefact. A single shared --output would
    # make detect, seal and evaluate overwrite one another's file - and
    # anchor reads detection_report.json, so it would score risk from a
    # stale report left by some earlier run.
    def step(func, output):
        args.output = output
        print()
        return func(args)

    step(detect, f"{config.EVIDENCE_DIR}/detection_report.json")
    step(seal, f"{config.EVIDENCE_DIR}/sealed_graph.json")      # sets args.run_id
    step(anchor, None)
    step(evaluate, config.EVALUATION_REPORT)


def demo(args):
    """Full offline demonstration - no database, no eBPF, no root."""
    import random
    import shutil
    import tempfile

    from anchoring.ledger import LocalLedger
    from anchoring.service import AnchoringService, format_report as anchor_report
    from core.store import FileStore
    from crypto.integrity import (DualSigner, EvidenceVerifier,
                                  IntegrityService, KeyStore, partition_graph)
    from detection.detector import PoisoningDetector, format_report
    from detection.synthetic import TamperGenerator, generate
    from evaluation.main import evaluate as survivability
    from evaluation.main import format_report as survivability_report

    workspace = Path(tempfile.mkdtemp(prefix="quantumguard-demo-"))
    rng = random.Random(args.seed)
    try:
        store = FileStore(workspace / "evidence")
        keystore = KeyStore(str(workspace / "keys.json"), "demo").create()
        # Signs with the throwaway key: the demo must not touch keys/.
        ledger = LocalLedger(workspace / "ledger.json",
                             signer=DualSigner(keystore))

        print("\n[1/6] building a provenance graph")
        clean = generate(rng, n_events=args.events)
        print(f"      {clean.number_of_nodes()} nodes, "
              f"{clean.number_of_edges()} relations")

        print("\n[2/6] sealing it  (Merkle partitions, hash chain, "
              "Ed25519 + ML-DSA)")
        service = IntegrityService(keystore, store,
                                   partition_size=args.partition_size)
        records = service.seal(clean, run_id="demo")
        print(f"      {len(records)} partitions, signed with Ed25519 + "
              f"{records[0]['mldsa_algorithm']}")

        print("\n[3/6] verifying the untouched graph")
        verifier = EvidenceVerifier(store=store)
        print("     ", verifier.verify(clean, records=records))
        detector = PoisoningDetector()
        clean_report = detector.detect(clean, run_id="demo")
        print(f"      detector verdict: "
              f"{'TAMPERED' if clean_report['tampered'] else 'CLEAN'}")

        print("\n[4/6] risk-adaptive anchoring of the clean run")
        anchoring = AnchoringService(ledger=ledger, batch_size=args.batch_size)
        clean_anchor = anchoring.anchor_run(
            records, graph=clean, report=clean_report,
            partitions=partition_graph(clean, args.partition_size),
            persist=False)
        print(anchor_report(clean_anchor))

        print(f"\n[5/6] an attacker tampers with the record "
              f"({args.strategy})")
        tampered = TamperGenerator(rng, sophistication=args.sophistication) \
            .apply(clean, [args.strategy], intensity=0.1).graph
        tamper_report = detector.detect(tampered, run_id="demo")
        print(format_report(tamper_report))
        print()
        print("     ", verifier.verify(tampered, records=records))

        print("\n      the same evidence, now anchored by risk:")
        tampered_partitions = partition_graph(tampered, args.partition_size)
        tampered_anchor = anchoring.anchor_run(
            records, graph=tampered, report=tamper_report,
            partitions=tampered_partitions,
            tamper_alert_indices=anchoring.alerted_partitions(
                records, tampered, tamper_report, tampered_partitions),
            persist=False)
        print(anchor_report(tampered_anchor))

        print("\n[6/6] how much evidence would survive a 25% wipe")
        print(survivability_report(
            survivability(clean, 0.25, args.seed, "mixed", records=records)))

        ledger_state = ledger.verify()
        print(f"\nledger: {'PASS' if ledger_state['ok'] else 'FAIL'} "
              f"({ledger_state['blocks']} blocks, independently verified)")
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def keys(args):
    from crypto.integrity import KeyStore
    store = KeyStore().load_or_create()
    print(json.dumps(store.summary(), indent=2))
    if args.export_trust:
        output = Path(args.export_trust)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(KeyStore.public_identity(store.path),
                                     indent=2) + "\n", encoding="utf-8")
        print(f"Public keys written to {output}. Keep a copy off this host "
              f"and pass it to: python main.py verify --trust-file {output}")


def tamper(args):
    """Attack the system and measure which layer notices."""
    from evaluation import tamper as module
    if args.action == "apply":
        module.apply_command(args, _load_graph(args.graph))
        return
    graph_path = Path(args.graph or config.GRAPH_PICKLE)
    real = _load_graph(str(graph_path)) if graph_path.exists() else None
    results = module.run_all(real, trials=args.trials,
                             intensity=args.intensity, seed=args.seed,
                             model_path=args.model)
    print(module.format_report(results))
    print(f"Report: {module.save_report(results, args.output)}")
    if results["evidence_attacks_missed"]:
        raise SystemExit(2)


# ======================================================================


def main(argv: list[str] | None = None) -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--graph", default=None, help="provenance graph pickle")
    common.add_argument("--run-id", default=None)
    common.add_argument("--partition-size", type=int,
                        default=config.PARTITION_SIZE)

    parser = argparse.ArgumentParser(description="QuantumGuard pipeline",
                                     parents=[common])
    sub = parser.add_subparsers(dest="command", required=True)

    node = sub.add_parser("keys", parents=[common])
    node.add_argument("--export-trust", default=None, metavar="PATH",
                      help="write the public keys for verify --trust-file")
    node.set_defaults(func=keys)
    sub.add_parser("capture", parents=[common]).set_defaults(func=capture)
    sub.add_parser("graph", parents=[common]).set_defaults(func=graph)

    node = sub.add_parser("visualize", parents=[common],
                          help="draw what ran what, one box per program")
    node.add_argument("--output", default=None)
    node.add_argument("--max-programs", type=int, default=24)
    node.set_defaults(func=visualize)

    node = sub.add_parser("train", parents=[common])
    node.add_argument("--epochs", type=int, default=40)
    node.add_argument("--synthetic", type=int, default=None)
    node.set_defaults(func=train)

    node = sub.add_parser("detect", parents=[common])
    node.add_argument("--persist", action="store_true")
    node.add_argument("--output", default=f"{config.EVIDENCE_DIR}/detection_report.json")
    node.set_defaults(func=detect)

    node = sub.add_parser("seal", parents=[common])
    node.add_argument("--output", default=f"{config.EVIDENCE_DIR}/sealed_graph.json")
    node.set_defaults(func=seal)

    node = sub.add_parser("anchor", parents=[common])
    node.add_argument("--ledger", default=config.LEDGER_BACKEND,
                      choices=["local", "fabric"])
    node.add_argument("--batch-size", type=int, default=config.ANCHOR_BATCH_SIZE)
    node.set_defaults(func=anchor)

    node = sub.add_parser("evaluate", parents=[common])
    node.add_argument("--ratio", type=float, default=0.15)
    node.add_argument("--mode", default="edge",
                      choices=["edge", "node", "window", "insert", "mixed", "edit"])
    node.add_argument("--seed", type=int, default=42)
    node.add_argument("--output", default=config.EVALUATION_REPORT)
    node.set_defaults(func=evaluate)

    node = sub.add_parser("verify", parents=[common])
    node.add_argument("--no-graph", action="store_true",
                      help="check signatures and chain only")
    node.add_argument("--trust-file", default=None,
                      help="public keys from 'keys --export-trust'")
    node.add_argument("--ledger", default=config.LEDGER_BACKEND,
                      choices=["local", "fabric"])
    node.set_defaults(func=verify)

    node = sub.add_parser("certify", parents=[common])
    node.add_argument("certificate")
    node.set_defaults(func=certify)

    node = sub.add_parser("all", parents=[common])
    node.add_argument("--persist", action="store_true")
    node.add_argument("--ledger", default=config.LEDGER_BACKEND,
                      choices=["local", "fabric"])
    node.add_argument("--batch-size", type=int, default=config.ANCHOR_BATCH_SIZE)
    node.add_argument("--ratio", type=float, default=0.15)
    node.add_argument("--mode", default="edge",
                      choices=["edge", "node", "window", "insert", "mixed", "edit"])
    node.add_argument("--seed", type=int, default=42)
    node.set_defaults(func=all_steps)

    node = sub.add_parser("tamper", parents=[common],
                          help="attack a copy of the evidence and score detection")
    node.add_argument("action", choices=["apply", "test"])
    node.add_argument("--attack", default="adaptive_forgery",
                      help="attack name for 'apply' (see evaluation/tamper.py)")
    node.add_argument("--intensity", type=float, default=0.1)
    node.add_argument("--seed", type=int, default=7)
    node.add_argument("--trials", type=int, default=20,
                      help="synthetic graphs per attack for 'test'")
    node.add_argument("--model", default=None, help="model to test")
    node.add_argument("--output", default=None)
    node.set_defaults(func=tamper)

    node = sub.add_parser("demo", parents=[common])
    node.add_argument("--events", type=int, default=120)
    node.add_argument("--strategy", default="forgery",
                      choices=["deletion", "reorder", "forgery", "timeshift"])
    node.add_argument("--sophistication", type=float, default=1.0)
    node.add_argument("--batch-size", type=int, default=config.ANCHOR_BATCH_SIZE)
    node.add_argument("--seed", type=int, default=42)
    node.set_defaults(func=demo)

    # shared flags are accepted either before or after the subcommand
    pre, _ = parser.parse_known_args(argv)
    args = parser.parse_args(argv)
    for field, default in (("graph", None), ("run_id", None),
                           ("partition_size", config.PARTITION_SIZE)):
        if getattr(args, field) == default and getattr(pre, field) != default:
            setattr(args, field, getattr(pre, field))

    from core.store import SchemaOutdated
    from crypto.integrity import KeyStoreLocked, SealedRunExists

    try:
        args.func(args)
    except NotImplementedError as exc:
        # An adapter declining to fake a result is an expected outcome,
        # not a crash. Report it as a message rather than a traceback.
        raise SystemExit(f"\n{exc}\n")
    except (KeyStoreLocked, SealedRunExists, SchemaOutdated) as exc:
        raise SystemExit(f"\n{exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
