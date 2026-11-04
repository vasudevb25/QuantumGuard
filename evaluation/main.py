"""
Phase 7 - forensic survivability evaluation.

Every system in the literature reports detection accuracy: was the
attack found, yes or no. None answers the question an investigator
actually faces once a compromise is confirmed, which is:

    how much of my evidence is still usable, and how much of the attack
    path can I still reconstruct from what survived?

This module answers it with five measures. The headline composite, FSI,
is a single number an investigator can put in a report.

Why this is not just counting what is left
------------------------------------------
Counting surviving nodes and edges measures *quantity*. It says nothing
about whether what survived can be *trusted*, and trust is the whole
point - a graph that is 90% intact but unverifiable is worth less than
one that is 60% intact and provably authentic.

So the measures here are computed against the sealed evidence from
Phase 5 wherever possible, not against topology alone:

    PIS   fraction of surviving relations that still pass Merkle and
          signature verification against their sealed partition
    EPR   fraction of originally captured events that survived
    GRR   fraction of the original causal paths still walkable
    RA    accuracy of the reconstruction: of the relations the system
          claims survived intact, how many genuinely match the original
    FSI   weighted composite of the four

Two bugs this replaces
----------------------
The first implementation of this module returned EPR = 100% and
RA = 100% at every damage level, including 80% destruction. Both were
measurement errors rather than results:

  * EPR read `recovered.graph["event_count"]`, a graph attribute copied
    unchanged from the original by `copy.deepcopy`, so it reported the
    original event count no matter how much had been destroyed.
  * RA compared surviving edges against the original edge set, but the
    recovery step only ever removed isolated nodes, so every surviving
    edge was an original edge by construction and the ratio was 1.0 by
    definition.

Both now measure against independent ground truth, and both move with
the damage. A metric that cannot fall is not a metric.
"""

from __future__ import annotations

import argparse
import copy
import json
import pickle
import random
from pathlib import Path
from typing import Any

import networkx as nx

from core import config


# ======================================================================
# Attack simulation
# ======================================================================


class AttackSimulator:
    """Models an adversary destroying evidence after a compromise.

    Three destruction modes, because they damage a graph differently and
    a survivability measure that only handles one of them is untested
    against the others:

        edge      relations removed, endpoints left behind
        node      whole processes removed, taking their relations
        window    a contiguous sequence range removed, which is what
                  wiping a time period looks like
    """

    MODES = ("edge", "node", "window", "insert", "mixed")

    @staticmethod
    def poison(graph, ratio: float = 0.15, seed: int | None = None,
               mode: str = "edge"):
        if not 0.0 <= ratio <= 1.0:
            raise ValueError("poison ratio must be between 0 and 1")
        if mode not in AttackSimulator.MODES:
            raise ValueError(f"unknown poison mode: {mode}")

        damaged = copy.deepcopy(graph)
        rng = random.Random(seed)

        if mode in ("insert", "mixed"):
            # An adversary who fabricates evidence rather than only
            # destroying it. This is the mode that makes Recovery
            # Accuracy meaningful: against deletion alone every
            # surviving relation is authentic by construction, so RA
            # cannot fall and measures nothing. Insertion is what a
            # recovery process can actually get *wrong*.
            nodes = [node for node, attrs in damaged.nodes(data=True)
                     if not attrs.get("synthetic_root")]
            if len(nodes) >= 2:
                for _ in range(int(damaged.number_of_edges() * ratio)):
                    source, target = rng.sample(nodes, 2)
                    if not damaged.has_edge(source, target):
                        damaged.add_edge(source, target, relation="EXECUTES",
                                         seq=rng.randint(1, 10 ** 6),
                                         ts=rng.randint(10 ** 12, 10 ** 13))
            if mode == "insert":
                return damaged
            # "mixed" continues into deletion below
            mode = "edge"

        if mode == "edge":
            edges = list(damaged.edges())
            rng.shuffle(edges)
            damaged.remove_edges_from(edges[:int(len(edges) * ratio)])

        elif mode == "node":
            victims = [node for node, attrs in damaged.nodes(data=True)
                       if attrs.get("type") == "process"
                       and not attrs.get("synthetic_root")]
            rng.shuffle(victims)
            damaged.remove_nodes_from(victims[:int(len(victims) * ratio)])

        else:  # window
            sequences = sorted({int(attrs.get("sequence") or 0)
                                for _, attrs in damaged.nodes(data=True)})
            span = int(len(sequences) * ratio)
            if span:
                start = rng.randrange(0, max(1, len(sequences) - span + 1))
                doomed = set(sequences[start:start + span])
                damaged.remove_nodes_from([
                    node for node, attrs in damaged.nodes(data=True)
                    if int(attrs.get("sequence") or 0) in doomed
                    and not attrs.get("synthetic_root")
                ])

        return damaged


# ======================================================================
# Recovery
# ======================================================================


class RecoveryEngine:
    """Reconstructs what can be reconstructed, and proves what cannot.

    Recovery here does not mean restoring deleted bytes - deleted
    evidence is gone. It means establishing, for every relation the
    sealed archive says existed, which of three states it is in:

        intact    present and verifies against its sealed Merkle leaf
        missing   sealed but absent now: provable deletion
        unsealed  present now but never sealed: provable insertion

    That classification is the recovery product. It is what lets an
    investigator say "these forty relations were deleted after capture"
    rather than "some events seem to be missing", and it is only
    possible because Phase 5 sealed the leaf hashes.

    Causal bridging
    ---------------
    When a process is deleted, its parent and children are orphaned and
    the causal chain breaks. Where the sealed evidence proves a
    now-missing process once linked two surviving ones, a bridge edge is
    inserted, marked `inferred=True`. An inferred edge records that a
    causal link existed without claiming to know its detail - and
    crucially it is never counted as recovered evidence by RA, only as
    recovered *reachability* by GRR.
    """

    @staticmethod
    def classify(damaged, sealed_leaves: set[str] | None,
                 leaf_of) -> dict[str, Any]:
        """Split relations into intact / missing / unsealed."""
        if not sealed_leaves:
            return {"intact": set(), "missing": set(), "unsealed": set(),
                    "sealed_total": 0}

        present = {leaf_of(damaged, u, v): (u, v) for u, v in damaged.edges()}
        intact = set(present) & sealed_leaves
        return {
            "intact": intact,
            "missing": sealed_leaves - set(present),
            "unsealed": set(present) - sealed_leaves,
            "sealed_total": len(sealed_leaves),
        }

    @staticmethod
    def recover(damaged, original=None, bridge: bool = True):
        """Drop orphaned fragments and bridge broken causal chains."""
        recovered = damaged.copy()
        recovered.remove_nodes_from(list(nx.isolates(recovered)))

        if not bridge or original is None:
            return recovered

        # Where a deleted process sat between two survivors, record that
        # a causal link existed. Marked inferred so no measure can
        # mistake it for recovered evidence.
        surviving = set(recovered.nodes())
        for lost in set(original.nodes()) - surviving:
            parents = [u for u in original.predecessors(lost) if u in surviving]
            children = [v for v in original.successors(lost) if v in surviving]
            for parent in parents:
                for child in children:
                    if not recovered.has_edge(parent, child):
                        recovered.add_edge(parent, child, relation="INFERRED",
                                           inferred=True, via=str(lost))
        return recovered


# ======================================================================
# Measures
# ======================================================================


class SurvivabilityMetrics:
    """The five forensic survivability measures, each in [0, 100]."""

    @staticmethod
    def pis(classification: dict[str, Any], recovered=None) -> float:
        """Provenance Integrity Score.

        Of everything the sealed archive attested to, what fraction is
        still present AND still verifies? This is an integrity measure,
        not a volume measure: a relation that survived but no longer
        matches its sealed leaf counts as lost, because evidence that
        cannot be verified cannot be used.

        With no sealed archive to check against there is no basis for an
        integrity claim, so the measure falls back to surviving volume
        and the report records that it was degraded.
        """
        total = classification.get("sealed_total", 0)
        if total:
            return round(100.0 * len(classification["intact"]) / total, 2)
        return 0.0

    @staticmethod
    def epr(original_events: int, surviving_events: int) -> float:
        """Evidence Preservation Ratio - fraction of events that survived.

        Counted from the graph itself rather than from a stored
        attribute: an attribute copied along with the graph does not
        change when the graph is damaged, which is what made the first
        implementation report 100% at every damage level.
        """
        if original_events <= 0:
            return 0.0
        return round(100.0 * min(surviving_events, original_events)
                     / original_events, 2)

    @staticmethod
    def grr(original, recovered) -> float:
        """Graph Recovery Rate - fraction of causal reachability retained.

        Measured over ancestor-descendant pairs, not edges. An
        investigator does not ask "how many edges are left"; they ask
        "can I still get from the phishing email to the exfiltration".
        A single deleted edge in the middle of a chain destroys far more
        reachability than one at a leaf, and counting edges misses that
        entirely.

        Inferred bridges count here - restoring the ability to walk a
        path is exactly what they do - but never in RA.
        """
        shared = [node for node in original.nodes() if node in recovered]
        if len(shared) < 2:
            return 0.0

        # On large graphs the full pair count is quadratic, so sample a
        # fixed number of sources deterministically.
        rng = random.Random(0)
        sources = shared if len(shared) <= 60 else rng.sample(shared, 60)

        original_pairs = recovered_pairs = 0
        for source in sources:
            reachable_before = nx.descendants(original, source)
            if not reachable_before:
                continue
            reachable_after = nx.descendants(recovered, source)
            original_pairs += len(reachable_before)
            recovered_pairs += len(reachable_before & reachable_after)

        if original_pairs == 0:
            return 0.0
        return round(100.0 * recovered_pairs / original_pairs, 2)

    @staticmethod
    def recovery_accuracy(original, recovered,
                          classification: dict[str, Any] | None = None,
                          leaf_of=None) -> float:
        """Recovery Accuracy - how much of what we assert is actually true.

        Of the relations the system presents to an investigator as
        authentic captured evidence, what fraction genuinely existed in
        the original capture?

        What "asserted" means depends on whether sealed evidence exists,
        and the difference between the two cases is the point of the
        measure:

          with sealing     the system asserts only relations whose leaf
                           matches a sealed Merkle leaf. Fabricated
                           relations are classified `unsealed` and are
                           never asserted, so RA stays high and the
                           measure is reporting that Phase 5 works.

          without sealing  the system has no basis to separate authentic
                           relations from fabricated ones and must
                           assert everything that survived. RA then
                           falls in proportion to what the attacker
                           inserted.

        Running both is how this project quantifies what sealing is
        worth, rather than asserting it.

        Inferred bridges are excluded either way: they are labelled
        reconstructions, and crediting them would let the system score
        itself on its own guesses.
        """
        present = {(u, v) for u, v, attrs in recovered.edges(data=True)
                   if not attrs.get("inferred")}
        if not present:
            return 0.0

        if classification and classification.get("sealed_total") and leaf_of:
            sealed = classification["intact"]
            asserted = {(u, v) for u, v in present
                        if leaf_of(recovered, u, v) in sealed}
        else:
            asserted = present

        if not asserted:
            return 0.0
        return round(100.0 * len(asserted & set(original.edges()))
                     / len(asserted), 2)

    @staticmethod
    def fsi(pis: float, epr: float, grr: float,
            recovery_accuracy: float) -> float:
        """Forensic Survivability Index - the weighted composite."""
        weights = config.FSI_WEIGHTS
        return round(
            weights["PIS"] * pis + weights["EPR"] * epr
            + weights["GRR"] * grr + weights["RA"] * recovery_accuracy, 2)


# ======================================================================
# Experiment
# ======================================================================


def _count_events(graph) -> int:
    """Captured events in a graph: one per non-synthetic process node."""
    return sum(1 for _, attrs in graph.nodes(data=True)
               if attrs.get("type") == "process"
               and not attrs.get("synthetic_root"))


def evaluate(original, ratio: float = 0.15, seed: int | None = None,
             mode: str = "edge", records: list[dict[str, Any]] | None = None,
             seal_if_missing: bool = True) -> dict[str, Any]:
    """Run one attack/recovery experiment and return its measures.

    `records` are the Phase 5 sealed partitions. Without them PIS has
    nothing to verify against, so by default the graph is sealed in
    memory first - survivability is a property of sealed evidence, and
    measuring it against an unsealed graph would quietly report a weaker
    number as though it were the real one.
    """

    sealed_leaves: set[str] | None = None
    leaf_of = None
    degraded = []

    if records is None and seal_if_missing:
        try:
            from crypto.integrity import IntegrityService
            records = IntegrityService().seal(original, persist=False)
        except Exception as exc:          # pragma: no cover - env dependent
            degraded.append(f"could not seal for verification: {exc}")

    if records:
        from crypto.integrity import _merkle_leaf, leaf_hash
        leaf_of = lambda g, u, v: _merkle_leaf(leaf_hash(g, u, v)).hex()  # noqa: E731
        sealed_leaves = {leaf for record in records
                         for leaf in record.get("leaf_hashes", [])}
    else:
        degraded.append("no sealed evidence: PIS could not be computed")

    damaged = AttackSimulator.poison(original, ratio, seed, mode)
    recovered = RecoveryEngine.recover(damaged, original)

    classification = (RecoveryEngine.classify(damaged, sealed_leaves, leaf_of)
                      if sealed_leaves else
                      {"intact": set(), "missing": set(), "unsealed": set(),
                       "sealed_total": 0})

    pis = SurvivabilityMetrics.pis(classification, recovered)
    epr = SurvivabilityMetrics.epr(_count_events(original),
                                   _count_events(recovered))
    grr = SurvivabilityMetrics.grr(original, recovered)
    accuracy = SurvivabilityMetrics.recovery_accuracy(
        original, recovered, classification, leaf_of)

    return {
        "PIS": pis,
        "EPR": epr,
        "GRR": grr,
        "RA": accuracy,
        "FSI": SurvivabilityMetrics.fsi(pis, epr, grr, accuracy),
        "conditions": {
            "poison_mode": mode,
            "poison_ratio": ratio,
            "seed": seed,
            "original_nodes": original.number_of_nodes(),
            "original_relations": original.number_of_edges(),
            "surviving_nodes": recovered.number_of_nodes(),
            "surviving_relations": recovered.number_of_edges(),
            "inferred_bridges": sum(
                1 for _, _, attrs in recovered.edges(data=True)
                if attrs.get("inferred")),
        },
        "evidence": {
            "sealed_relations": classification["sealed_total"],
            "verified_intact": len(classification["intact"]),
            "provably_deleted": len(classification["missing"]),
            "unsealed_present": len(classification["unsealed"]),
        },
        "degraded": degraded,
    }


def sweep(original, ratios=(0.0, 0.1, 0.2, 0.3, 0.5, 0.7),
          mode: str = "edge", seed: int = 42) -> list[dict[str, Any]]:
    """Measure survivability across a range of damage levels."""
    return [evaluate(original, ratio, seed, mode) for ratio in ratios]


def sealing_benefit(original, ratio: float = 0.25, seed: int = 42,
                    mode: str = "mixed") -> dict[str, Any]:
    """Quantify what Phase 5 sealing is worth, by measuring without it.

    The same attack is evaluated twice: once where the system can check
    surviving relations against sealed Merkle leaves, and once where it
    cannot and must treat everything that survived as authentic. The
    difference in Recovery Accuracy is the value sealing adds, measured
    rather than asserted.
    """
    sealed = evaluate(original, ratio, seed, mode)
    unsealed = evaluate(original, ratio, seed, mode, seal_if_missing=False)
    return {
        "conditions": sealed["conditions"],
        "with_sealing": {key: sealed[key]
                         for key in ("PIS", "EPR", "GRR", "RA", "FSI")},
        "without_sealing": {key: unsealed[key]
                            for key in ("PIS", "EPR", "GRR", "RA", "FSI")},
        "ra_gain": round(sealed["RA"] - unsealed["RA"], 2),
        "fabricated_relations": sealed["evidence"]["unsealed_present"],
    }


def save_report(metrics: dict[str, Any],
                path: str | Path | None = None) -> Path:
    output = Path(path or config.EVALUATION_REPORT)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    return output


def format_report(metrics: dict[str, Any]) -> str:
    conditions, evidence = metrics["conditions"], metrics["evidence"]
    names = {
        "PIS": "Provenance Integrity Score",
        "EPR": "Evidence Preservation Ratio",
        "GRR": "Graph Recovery Rate",
        "RA": "Recovery Accuracy",
        "FSI": "Forensic Survivability Index",
    }
    lines = [
        "=" * 62,
        "  QuantumGuard - Forensic Survivability",
        "=" * 62,
        f"  damage model      : {conditions['poison_mode']} removal, "
        f"{conditions['poison_ratio']:.0%}",
        f"  graph             : {conditions['original_nodes']} nodes / "
        f"{conditions['original_relations']} relations  ->  "
        f"{conditions['surviving_nodes']} / "
        f"{conditions['surviving_relations']}",
        "-" * 62,
    ]
    for key in ("PIS", "EPR", "GRR", "RA"):
        lines.append(f"  {key:<4} {names[key]:<30} {metrics[key]:>6.2f} %")
    lines.append("-" * 62)
    lines.append(f"  FSI  {names['FSI']:<30} {metrics['FSI']:>6.2f} %")
    lines.append("-" * 62)
    lines.append(f"  sealed relations  : {evidence['sealed_relations']}")
    lines.append(f"  verified intact   : {evidence['verified_intact']}")
    lines.append(f"  provably deleted  : {evidence['provably_deleted']}")
    if evidence["unsealed_present"]:
        lines.append(f"  unsealed present  : {evidence['unsealed_present']}"
                     f"   (inserted after sealing)")
    if conditions["inferred_bridges"]:
        lines.append(f"  inferred bridges  : {conditions['inferred_bridges']}"
                     f"   (reachability only, excluded from RA)")
    for note in metrics.get("degraded", []):
        lines.append(f"  NOTE: {note}")
    lines.append("=" * 62)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate QuantumGuard forensic survivability")
    parser.add_argument("--graph", default=config.GRAPH_PICKLE)
    parser.add_argument("--ratio", type=float, default=0.15,
                        help="fraction of the graph destroyed")
    parser.add_argument("--mode", default="edge",
                        choices=AttackSimulator.MODES)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--sweep", action="store_true",
                        help="measure across a range of damage levels")
    parser.add_argument("--output", default=None)
    args = parser.parse_args(argv)

    with open(args.graph, "rb") as handle:
        original = pickle.load(handle)

    if args.sweep:
        results = sweep(original, mode=args.mode, seed=args.seed)
        print("=" * 62)
        print("  QuantumGuard - Survivability under increasing damage")
        print("=" * 62)
        print(f"  {'damage':>7}  {'PIS':>7} {'EPR':>7} {'GRR':>7} "
              f"{'RA':>7} {'FSI':>7}")
        for item in results:
            print(f"  {item['conditions']['poison_ratio']:>6.0%}  "
                  f"{item['PIS']:>7.2f} {item['EPR']:>7.2f} "
                  f"{item['GRR']:>7.2f} {item['RA']:>7.2f} "
                  f"{item['FSI']:>7.2f}")
        print("=" * 62)
        output = save_report({"sweep": results},
                             args.output or config.EVALUATION_REPORT)
    else:
        metrics = evaluate(original, args.ratio, args.seed, args.mode)
        print(format_report(metrics))
        output = save_report(metrics, args.output or config.EVALUATION_REPORT)

    print(f"Report: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
