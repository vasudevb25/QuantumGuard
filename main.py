"""QuantumGuard command-line entry point.

Examples:
    python main.py capture
    python main.py graph
    python main.py detect
    python main.py seal
    python main.py evaluate
    python main.py all
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
        raise SystemExit(f"graph not found: {graph_path}; run 'python main.py graph' first")
    with graph_path.open("rb") as handle:
        return pickle.load(handle)


def capture(_args):
    from capture.collector import EBPFCollector
    EBPFCollector().start()


def graph(_args):
    from graph.service import ProvenanceGraphService
    service = ProvenanceGraphService()
    result = service.run()
    print(f"Graph saved: {result.number_of_nodes()} nodes, {result.number_of_edges()} edges")


def detect(args):
    from detection.detector import PoisoningDetector, format_report
    from core.store import get_store

    # A sequence gap the CCA layer (Phase 1/2) already attested as capture
    # loss is not tampering - this is the one place Pillar 1 (capture
    # completeness) and Pillar 2 (poisoning detection) connect. Detection
    # still runs without it (e.g. against a graph with no known session)
    # so a store outage never blocks an otherwise-offline `detect`.
    known_missing: set[int] = set()
    try:
        known_missing = get_store().load_missing_sequences()
    except Exception as exc:
        print(f"[detect] note: could not load CCA attestations ({exc}); "
              f"sequence_gap will not be able to rule out capture loss")

    report = PoisoningDetector(known_missing_sequences=known_missing).detect(
        _load_graph(args.graph), run_id=args.run_id)
    print(format_report(report))
    if args.persist:
        get_store().save_detection_report(report)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Report: {output}")


def seal(args):
    from crypto.integrity import EvidenceVerifier, IntegrityService, export_evidence
    graph_data = _load_graph(args.graph)
    service = IntegrityService(partition_size=args.partition_size)
    records = service.seal(graph_data, run_id=args.run_id or str(uuid.uuid4()))
    evidence = export_evidence(records, args.output)
    report = EvidenceVerifier(store=service.store).verify(graph_data, records=records)
    print(f"Evidence   : {evidence}\nPartitions : {len(records)}\nVerified   : {report.ok}")


def evaluate(args):
    from evaluation.main import evaluate as run_evaluation, save_report
    metrics = run_evaluation(_load_graph(args.graph), args.ratio, args.seed)
    output = save_report(metrics, args.output)
    print("Forensic survivability:", ", ".join(f"{name}={value}%" for name, value in metrics.items()))
    print(f"Report: {output}")


def train(args):
    from detection.model import main as train_model
    import sys
    old_argv = sys.argv
    try:
        sys.argv = ["detection.model", "--epochs", str(args.epochs), "--graph", args.graph or config.GRAPH_PICKLE]
        train_model()
    finally:
        sys.argv = old_argv


def all_steps(args):
    graph(args)
    detect(argparse.Namespace(graph=args.graph, run_id=args.run_id, persist=args.persist,
                              output="evidence/detection_report.json"))
    seal(argparse.Namespace(graph=args.graph, run_id=args.run_id,
                            partition_size=args.partition_size, output="evidence/sealed_graph.json"))
    evaluate(argparse.Namespace(graph=args.graph, ratio=args.ratio, seed=args.seed,
                               output="evaluation/report.json"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="QuantumGuard pipeline")
    parser.add_argument("--graph", default=None, help="provenance graph pickle path")
    parser.add_argument("--run-id")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("capture").set_defaults(func=capture)
    sub.add_parser("graph").set_defaults(func=graph)
    train_parser = sub.add_parser("train")
    train_parser.add_argument("--epochs", type=int, default=100)
    train_parser.set_defaults(func=train)
    detect_parser = sub.add_parser("detect")
    detect_parser.add_argument("--persist", action="store_true")
    detect_parser.add_argument("--output", default="evidence/detection_report.json")
    detect_parser.set_defaults(func=detect)
    seal_parser = sub.add_parser("seal")
    seal_parser.add_argument("--partition-size", type=int, default=config.PARTITION_SIZE)
    seal_parser.add_argument("--output", default="evidence/sealed_graph.json")
    seal_parser.set_defaults(func=seal)
    evaluation_parser = sub.add_parser("evaluate")
    evaluation_parser.add_argument("--ratio", type=float, default=0.15)
    evaluation_parser.add_argument("--seed", type=int, default=42)
    evaluation_parser.add_argument("--output", default="evaluation/report.json")
    evaluation_parser.set_defaults(func=evaluate)
    all_parser = sub.add_parser("all")
    all_parser.add_argument("--persist", action="store_true")
    all_parser.add_argument("--partition-size", type=int, default=config.PARTITION_SIZE)
    all_parser.add_argument("--ratio", type=float, default=0.15)
    all_parser.add_argument("--seed", type=int, default=42)
    all_parser.add_argument("--output", default="evidence/sealed_graph.json")
    all_parser.set_defaults(func=all_steps)
    args = parser.parse_args(argv)
    config.init_dirs()
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
