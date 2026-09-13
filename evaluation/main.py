"""QuantumGuard forensic-survivability evaluation CLI.

This one module contains controlled edge poisoning, baseline recovery, all
survivability metrics, JSON reporting, and ``python -m evaluation.main``.
"""
from __future__ import annotations

import argparse
import copy
import json
import pickle
import random
from pathlib import Path

import networkx as nx


class AttackSimulator:
    """Controlled provenance-edge removal used to model poisoning damage."""
    @staticmethod
    def poison(graph, ratio: float = 0.15, seed: int | None = None):
        if not 0 <= ratio <= 1:
            raise ValueError("poison ratio must be between 0 and 1")
        damaged, edges = copy.deepcopy(graph), list(graph.edges())
        random.Random(seed).shuffle(edges)
        damaged.remove_edges_from(edges[:int(len(edges) * ratio)])
        return damaged


class RecoveryEngine:
    """Baseline recovery: remove isolated fragments after poisoning."""
    @staticmethod
    def recover(graph):
        recovered = graph.copy()
        recovered.remove_nodes_from(list(nx.isolates(recovered)))
        return recovered


class SurvivabilityMetrics:
    @staticmethod
    def pis(original, recovered):
        total = original.number_of_nodes() + original.number_of_edges()
        return round(100 * (recovered.number_of_nodes() + recovered.number_of_edges()) / total, 2) if total else 0.0

    @staticmethod
    def epr(original_events, recovered_events):
        return round(100 * recovered_events / original_events, 2) if original_events else 0.0

    @staticmethod
    def grr(original, recovered):
        return round(100 * recovered.number_of_edges() / original.number_of_edges(), 2) if original.number_of_edges() else 0.0

    @staticmethod
    def recovery_accuracy(original, recovered):
        observed = set(recovered.edges())
        return round(100 * len(set(original.edges()) & observed) / len(observed), 2) if observed else 0.0

    @staticmethod
    def fsi(pis, epr, grr, recovery_accuracy):
        return round(0.30 * pis + 0.25 * epr + 0.25 * grr + 0.20 * recovery_accuracy, 2)


def evaluate(original, ratio: float = 0.15, seed: int | None = None) -> dict[str, float]:
    """Run the complete attack/recovery experiment and return its metrics."""
    recovered = RecoveryEngine.recover(AttackSimulator.poison(original, ratio, seed))
    original_events = original.graph.get("event_count", original.number_of_edges())
    recovered_events = recovered.graph.get("event_count", original_events)
    pis = SurvivabilityMetrics.pis(original, recovered)
    epr = SurvivabilityMetrics.epr(original_events, recovered_events)
    grr = SurvivabilityMetrics.grr(original, recovered)
    accuracy = SurvivabilityMetrics.recovery_accuracy(original, recovered)
    return {"PIS": pis, "EPR": epr, "GRR": grr, "RA": accuracy,
            "FSI": SurvivabilityMetrics.fsi(pis, epr, grr, accuracy)}


def save_report(metrics: dict[str, float], path: str | Path = "evaluation/report.json") -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate QuantumGuard forensic survivability")
    parser.add_argument("--graph", default="graphs/provenance_graph.gpickle")
    parser.add_argument("--ratio", type=float, default=0.15, help="fraction of edges removed by poisoning")
    parser.add_argument("--seed", type=int, default=42, help="random seed for reproducible results")
    parser.add_argument("--output", default="evaluation/report.json")
    args = parser.parse_args(argv)
    with open(args.graph, "rb") as handle:
        original = pickle.load(handle)
    metrics = evaluate(original, args.ratio, args.seed)
    output = save_report(metrics, args.output)
    print("\n====== FORENSIC SURVIVABILITY ======")
    for name, value in metrics.items():
        print(f"{name:4} : {value}%")
        print()
    print(f"Report: {output}\n===================================")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
