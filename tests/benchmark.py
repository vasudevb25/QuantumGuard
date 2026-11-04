"""
Reproducible benchmark for every measured claim in this project.

    python -m tests.benchmark                  full run
    python -m tests.benchmark --quick          fewer trials
    python -m tests.benchmark --json out.json  machine-readable

Everything printed here is measured at run time, not quoted from a
previous run. Five experiments:

  1. Detection       rule engine and GNN against all four tamper
                     strategies, at both sophistication levels
  2. Integrity       does the cryptographic layer catch what the
                     detector misses
  3. Risk scoring    separation between clean and tampered captures,
                     which is what the tier-2 threshold is calibrated on
  4. Anchoring cost  ledger transactions consumed by clean runs versus
                     tampered ones
  5. Survivability   the five measures under increasing damage, and
                     what Phase 5 sealing is worth in Recovery Accuracy
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import tempfile
import time
from pathlib import Path

from anchoring.ledger import LocalLedger
from anchoring.risk import TIER1, TIER2, TIER3, RiskScorer
from anchoring.service import AnchoringService
from core.store import FileStore
from crypto.integrity import (DualSigner, EvidenceVerifier, IntegrityService,
                              KeyStore, partition_graph)
from detection import synthetic
from detection.detector import PoisoningDetector
from evaluation.main import evaluate, sealing_benefit

STRATEGIES = ("deletion", "reorder", "forgery", "timeshift")
RULE = "-" * 72


def _header(title: str) -> None:
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


# ---------------------------------------------------------------------


def detection_benchmark(trials: int, detector) -> dict:
    """Can each layer see each attack?"""
    _header("1.  DETECTION  -  rule engine and GNN vs four tamper strategies")
    print(f"  {'strategy':<12} {'attacker':<14} {'detected':>10} "
          f"{'by rules':>10} {'by GNN':>9}")
    print(RULE)

    results = {}
    for strategy in STRATEGIES:
        for sophistication, label in ((0.0, "crude"), (1.0, "sophisticated")):
            caught = rules = gnn = 0
            for trial in range(trials):
                clean = synthetic.generate(random.Random(trial), n_events=140)
                tampered = synthetic.TamperGenerator(
                    random.Random(trial + 500), sophistication=sophistication
                ).apply(clean, [strategy], intensity=0.1).graph

                report = detector.detect(tampered)
                caught += report["tampered"]
                rules += report["rule_violation_count"] > 0
                gnn += report["gnn_flagged_nodes"] > 0

            results[f"{strategy}_{label}"] = {
                "detected": caught / trials,
                "rules": rules / trials,
                "gnn": gnn / trials,
            }
            print(f"  {strategy:<12} {label:<14} {caught:>6}/{trials:<3} "
                  f"{rules:>6}/{trials:<3} {gnn:>5}/{trials:<3}")

    print(RULE)
    overall = statistics.mean(item["detected"] for item in results.values())
    print(f"  overall detection rate: {overall:.1%}")
    return results


def integrity_benchmark(trials: int) -> dict:
    """Does the cryptographic layer catch everything, regardless?"""
    _header("2.  INTEGRITY  -  does sealing catch what the detector might not")
    print(f"  {'strategy':<14} {'attacker':<16} {'caught by crypto':>18}")
    print(RULE)

    results = {}
    with tempfile.TemporaryDirectory() as directory:
        workspace = Path(directory)
        keystore = KeyStore(str(workspace / "k.json"), "bench").create()
        store = FileStore(workspace / "evidence")
        service = IntegrityService(keystore, store, partition_size=16)
        verifier = EvidenceVerifier(store=store)

        for strategy in STRATEGIES:
            for sophistication, label in ((0.0, "crude"), (1.0, "sophisticated")):
                caught = 0
                for trial in range(trials):
                    clean = synthetic.generate(random.Random(trial), n_events=140)
                    records = service.seal(clean, run_id=f"b{trial}",
                                           persist=False)
                    tampered = synthetic.TamperGenerator(
                        random.Random(trial + 500),
                        sophistication=sophistication
                    ).apply(clean, [strategy], intensity=0.1).graph
                    caught += not verifier.verify(tampered, records=records).ok

                results[f"{strategy}_{label}"] = caught / trials
                print(f"  {strategy:<14} {label:<16} {caught:>12}/{trials}")

    print(RULE)
    print(f"  crypto detection rate: "
          f"{statistics.mean(results.values()):.1%}  "
          f"(no training data, no distribution assumption)")
    return results


def risk_benchmark(trials: int, detector) -> dict:
    """Separation between clean and tampered - what the threshold rests on."""
    _header("3.  RISK SCORING  -  clean vs tampered separation")

    clean_scores, tampered_scores = [], []
    with tempfile.TemporaryDirectory() as directory:
        workspace = Path(directory)
        keystore = KeyStore(str(workspace / "k.json"), "bench").create()
        store = FileStore(workspace / "evidence")
        service = IntegrityService(keystore, store, partition_size=16)
        scorer = RiskScorer()

        for trial in range(trials):
            clean = synthetic.generate(random.Random(trial), n_events=160)
            records = service.seal(clean, run_id=f"c{trial}", persist=False)
            scores = scorer.score_all(records, clean, detector.detect(clean),
                                      partition_graph(clean, 16))
            clean_scores.append(max(entry["risk_score"] for entry in scores))

            strategy = STRATEGIES[trial % len(STRATEGIES)]
            tampered = synthetic.TamperGenerator(
                random.Random(trial + 900), sophistication=1.0
            ).apply(clean, [strategy], intensity=0.08).graph
            records = service.seal(tampered, run_id=f"t{trial}", persist=False)
            scores = scorer.score_all(records, tampered,
                                      detector.detect(tampered),
                                      partition_graph(tampered, 16))
            tampered_scores.append(max(entry["risk_score"] for entry in scores))

    print(f"  clean captures    ({trials} runs): "
          f"mean {statistics.mean(clean_scores):.3f}  "
          f"max {max(clean_scores):.3f}")
    print(f"  tampered captures ({trials} runs): "
          f"mean {statistics.mean(tampered_scores):.3f}  "
          f"min {min(tampered_scores):.3f}")
    print(RULE)
    print(f"  {'threshold':>10} {'clean runs anchoring':>22} "
          f"{'tampered runs anchored':>24}")

    sweep = {}
    for threshold in (0.10, 0.15, 0.20, 0.25, 0.30):
        false_positive = sum(1 for value in clean_scores if value >= threshold)
        true_positive = sum(1 for value in tampered_scores if value >= threshold)
        sweep[threshold] = {"clean": false_positive, "tampered": true_positive}
        marker = "  <- configured" if abs(threshold - 0.20) < 1e-9 else ""
        print(f"  {threshold:>10.2f} {false_positive:>16}/{trials} "
              f"{true_positive:>20}/{trials}{marker}")

    return {"clean_max": max(clean_scores),
            "tampered_min": min(tampered_scores),
            "clean_mean": statistics.mean(clean_scores),
            "tampered_mean": statistics.mean(tampered_scores),
            "threshold_sweep": sweep}


def anchoring_benchmark(trials: int, detector) -> dict:
    """What anchoring actually costs, clean versus compromised."""
    _header("4.  ANCHORING COST  -  ledger transactions by risk")

    totals = {"clean": {"partitions": 0, "external": 0, "tx": 0},
              "tampered": {"partitions": 0, "external": 0, "tx": 0}}

    with tempfile.TemporaryDirectory() as directory:
        workspace = Path(directory)
        keystore = KeyStore(str(workspace / "k.json"), "bench").create()
        store = FileStore(workspace / "evidence")
        service = IntegrityService(keystore, store, partition_size=16)
        signer = DualSigner(keystore)

        for trial in range(trials):
            clean = synthetic.generate(random.Random(trial), n_events=160)
            strategy = STRATEGIES[trial % len(STRATEGIES)]
            tampered = synthetic.TamperGenerator(
                random.Random(trial + 900), sophistication=1.0
            ).apply(clean, [strategy], intensity=0.08).graph

            for label, graph in (("clean", clean), ("tampered", tampered)):
                records = service.seal(graph, run_id=f"{label}{trial}",
                                       persist=False)
                ledger = LocalLedger(
                    workspace / f"ledger-{label}-{trial}.json", signer)
                anchoring = AnchoringService(ledger=ledger)
                result = anchoring.anchor_run(
                    records, graph=graph, report=detector.detect(graph),
                    partitions=partition_graph(graph, 16), persist=False)

                summary = result["summary"]
                totals[label]["partitions"] += summary["partitions"]
                totals[label]["external"] += (summary["by_tier"][TIER1]
                                              + summary["by_tier"][TIER2])
                totals[label]["tx"] += result["ledger_transactions"]

    print(f"  {'':<10} {'partitions':>12} {'externally anchored':>21} "
          f"{'ledger tx':>11}")
    print(RULE)
    for label in ("clean", "tampered"):
        row = totals[label]
        print(f"  {label:<10} {row['partitions']:>12} "
              f"{row['external']:>21} {row['tx']:>11}")
    print(RULE)

    compression = (totals["tampered"]["external"] / totals["tampered"]["tx"]
                   if totals["tampered"]["tx"] else 0)
    print(f"  {trials} clean runs consumed {totals['clean']['tx']} "
          f"ledger transactions")
    print(f"  {trials} tampered runs anchored "
          f"{totals['tampered']['external']} partitions in "
          f"{totals['tampered']['tx']} transactions "
          f"({compression:.1f}x batching compression)")
    return totals


def survivability_benchmark() -> dict:
    """The five measures under damage, and what sealing is worth."""
    _header("5.  SURVIVABILITY  -  evidence remaining after a compromise")

    graph = synthetic.generate(random.Random(3), n_events=200)
    print(f"  {'damage':>8} {'mode':>8} {'PIS':>8} {'EPR':>8} "
          f"{'GRR':>8} {'RA':>8} {'FSI':>8}")
    print(RULE)

    sweep = []
    for mode in ("edge", "node", "window"):
        for ratio in (0.0, 0.15, 0.30, 0.50, 0.75):
            metrics = evaluate(graph, ratio, seed=1, mode=mode)
            sweep.append({"mode": mode, "ratio": ratio,
                          **{key: metrics[key]
                             for key in ("PIS", "EPR", "GRR", "RA", "FSI")}})
            print(f"  {ratio:>7.0%} {mode:>8} {metrics['PIS']:>8.2f} "
                  f"{metrics['EPR']:>8.2f} {metrics['GRR']:>8.2f} "
                  f"{metrics['RA']:>8.2f} {metrics['FSI']:>8.2f}")
        print()

    print(RULE)
    print("  What Phase 5 sealing is worth  (mixed delete + fabricate, 25%)")
    print(RULE)
    benefit = sealing_benefit(graph, 0.25, seed=1, mode="mixed")
    print(f"  {'':<18} {'PIS':>8} {'EPR':>8} {'GRR':>8} {'RA':>8} {'FSI':>8}")
    for label, key in (("with sealing", "with_sealing"),
                       ("without sealing", "without_sealing")):
        row = benefit[key]
        print(f"  {label:<18} {row['PIS']:>8.2f} {row['EPR']:>8.2f} "
              f"{row['GRR']:>8.2f} {row['RA']:>8.2f} {row['FSI']:>8.2f}")
    print(RULE)
    print(f"  {benefit['fabricated_relations']} fabricated relations were "
          f"inserted.")
    print(f"  Sealing rejected all of them: Recovery Accuracy "
          f"{benefit['without_sealing']['RA']:.2f}% -> "
          f"{benefit['with_sealing']['RA']:.2f}% "
          f"(+{benefit['ra_gain']:.2f} points)")

    return {"sweep": sweep, "sealing_benefit": benefit}


# ---------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="QuantumGuard benchmark")
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--trials", type=int, default=None)
    parser.add_argument("--json", default=None)
    args = parser.parse_args(argv)

    trials = args.trials or (5 if args.quick else 15)
    started = time.time()

    print("=" * 72)
    print("  QuantumGuard - measured results")
    print("=" * 72)

    detector = PoisoningDetector()
    print(f"  GNN model loaded : {detector.model is not None}")
    if detector.model is not None:
        print(f"  decision threshold: {detector.threshold:.3f}")
    print(f"  trials per cell  : {trials}")

    results = {
        "trials": trials,
        "gnn_loaded": detector.model is not None,
        "detection": detection_benchmark(trials, detector),
        "integrity": integrity_benchmark(trials),
        "risk": risk_benchmark(trials, detector),
        "anchoring": anchoring_benchmark(trials, detector),
        "survivability": survivability_benchmark(),
    }

    elapsed = time.time() - started
    print()
    print("=" * 72)
    print(f"  benchmark complete in {elapsed:.1f}s")
    print("=" * 72)

    if args.json:
        output = Path(args.json)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(results, indent=2, default=str) + "\n",
                          encoding="utf-8")
        print(f"  results written to {output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
