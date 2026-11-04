"""
Phase 6a - forensic risk scoring.

Every sealed partition is scored for how much it would cost the
investigation to lose it. That score, not the partition's size or age,
decides how expensively it is protected in anchoring/service.py.

Why score at all
----------------
Post-quantum signatures are large: an ML-DSA-65 signature is 3309 bytes
against Ed25519's 64, and an external ledger anchor costs a round trip
and a transaction fee. Anchoring every partition to a blockchain is
therefore not affordable at realistic event rates, and anchoring none of
them leaves the whole archive destructible by an attacker who wipes the
host. This is precisely the cost that Baseri et al. (2025) quantify and
answer with risk-adaptive anchoring; their proposal was never
implemented, and this module is that implementation.

The scoring model
-----------------
Score is a weighted sum over six signals, each normalised to [0, 1], so
the total also lands in [0, 1]:

    score = Σ wᵢ · sᵢ

    signal                       weight   rationale
    ------------------------------------------------------------------
    tamper_alert                  0.20    a partition carrying evidence
                                          that somebody was caught is
                                          the first thing an attacker
                                          would destroy. Weighted modestly
                                          here only because the hard
                                          escalation rule in RiskPolicy
                                          already forces it to tier 1 -
                                          a large weight would be
                                          redundant with that rule
    rule_violations               0.25    deterministic proof of an
                                          inconsistency in this range
    gnn_suspicion                 0.25    learned anomaly. Weighted equal
                                          to rules because it is the only
                                          signal that responds at all to
                                          a sophisticated attacker who
                                          leaves every deterministic
                                          invariant satisfied
    privilege_activity            0.15    uid transitions and root
                                          execution - the actions an
                                          intrusion must perform
    unattested_gap                0.10    events absent with no CCA
                                          record: possible deletion
    rare_image                    0.05    execution of binaries that
                                          appear rarely in this capture

The weights are a policy choice, not a learned quantity, and they are
deliberately legible: an investigator or an auditor can read them and
disagree. They are overridable per deployment through RiskWeights.

Determinism
-----------
Scoring reads only the sealed partition record, the graph it was built
from, and the detection report. It performs no sampling and no learned
inference, so two parties scoring the same evidence agree exactly - a
requirement if the tier assignment itself is to be auditable.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, asdict
from typing import Any

# Tier boundaries on the [0, 1] score. Overridable through RiskPolicy.
#
# TIER2_THRESHOLD is calibrated, not chosen. Over 25 paired runs of
# clean and tampered captures (tests/test_all.py::RiskCalibrationTest
# reproduces the measurement), the highest score reached by any
# partition of a clean capture was 0.07, while the lowest score reached
# by the most suspicious partition of a tampered capture was 0.22.
# 0.20 sits inside that gap: in the measured runs it anchored something
# in every tampered capture and nothing in any clean one. An earlier
# guessed value of 0.25 missed roughly a quarter of tampered runs, which
# is why the number is now derived from the separation rather than set
# by intuition.
TIER1_THRESHOLD = 0.45      # immediate external anchor
TIER2_THRESHOLD = 0.20      # batched external anchor
# below TIER2_THRESHOLD -> tier 3, local hash chain only

TIER1 = "tier1_immediate"
TIER2 = "tier2_batched"
TIER3 = "tier3_local"


@dataclass(frozen=True)
class RiskWeights:
    """Relative importance of each signal. Must sum to 1.0."""

    tamper_alert: float = 0.20
    rule_violations: float = 0.25
    gnn_suspicion: float = 0.25
    privilege_activity: float = 0.15
    unattested_gap: float = 0.10
    rare_image: float = 0.05

    def validate(self) -> None:
        total = sum(asdict(self).values())
        if abs(total - 1.0) > 1e-9:
            raise ValueError(f"risk weights must sum to 1.0, got {total}")


@dataclass(frozen=True)
class RiskPolicy:
    """Weights, tier boundaries, and the hard escalation rules.

    Real risk policies are not pure weighted sums. Some findings are
    categorically different from "a bit more suspicious than usual" and
    must escalate regardless of what the arithmetic says. Two do here:

      escalate_tamper_alert   a partition carrying a tamper alert is
                              the single thing an attacker most wants
                              destroyed, so it is anchored immediately
                              whatever its other signals look like
      escalate_blocking       a critical or high rule violation is
                              deterministic proof of an inconsistency;
                              treating that as merely "elevated" would
                              let a quiet partition carrying real proof
                              fall into the local-only tier

    Keeping these explicit, named and overridable is deliberate: a
    hidden override inside a scoring function is far harder for an
    auditor to find than a documented one.
    """

    weights: RiskWeights = RiskWeights()
    tier1_threshold: float = TIER1_THRESHOLD
    tier2_threshold: float = TIER2_THRESHOLD
    escalate_tamper_alert: bool = True
    escalate_blocking_violation: bool = True

    def validate(self) -> None:
        self.weights.validate()
        if not 0.0 < self.tier2_threshold < self.tier1_threshold <= 1.0:
            raise ValueError("thresholds must satisfy 0 < tier2 < tier1 <= 1")

    def tier_for(self, score: float) -> str:
        if score >= self.tier1_threshold:
            return TIER1
        if score >= self.tier2_threshold:
            return TIER2
        return TIER3


def _saturate(count: int, half: float) -> float:
    """Map a count to [0, 1), reaching 0.5 at `half`.

    A partition with twelve rule violations is not twelve times more
    urgent than one with a single violation - the first violation
    carries most of the information. A saturating curve encodes that;
    a linear count would let one noisy partition dominate the budget.
    """
    if count <= 0:
        return 0.0
    return 1.0 - math.exp(-math.log(2.0) * count / max(half, 1e-9))


class RiskScorer:
    """Scores sealed partitions against the evidence available for them."""

    def __init__(self, policy: RiskPolicy | None = None):
        self.policy = policy or RiskPolicy()
        self.policy.validate()

    # ------------------------------------------------------------------
    # Signal extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _violations_in_range(report: dict[str, Any] | None,
                             seq_start: int, seq_end: int,
                             nodes: set[Any] | None = None
                             ) -> tuple[int, int, int]:
        """(blocking, advisory, unattested gaps) for one partition.

        Severity is split rather than filtered. A critical or high
        violation is deterministic proof and escalates; a low or medium
        one - an orphaned process, a self-loop - is not proof but is
        still forensically meaningful, and feeds the graded score.

        That split matters against a competent attacker. A sophisticated
        deletion removes the orphans it creates, leaving only low-severity
        traces; counting nothing below "high" would score such an attack
        at exactly zero and anchor it nowhere.

        Localising a violation to a partition is what makes tiering
        meaningful. A violation that cannot be localised must NOT be
        attributed to every partition: doing so escalates the entire run
        to tier 1 and the risk model stops adapting to anything, which
        is the exact failure this method was rewritten to avoid.

        The rule engine emits four shapes of target, and each is matched
        on its own terms:

            "seq=57" / "seq=57..59"   sequence number or range
            "P:4821:57"                a node identifier
            "P:4821:57 -> F:/bin/ls"   an edge, matched on either endpoint
            "pid=4821"                 an attribute conflict, matched by
                                       the pid carried on this partition's
                                       process nodes

        Anything still unmatched is skipped rather than counted
        everywhere, so an unlocalisable violation lowers precision
        instead of destroying the tier distribution.
        """
        if not report:
            return 0, 0, 0

        nodes = nodes or set()
        node_strings = {str(node) for node in nodes}
        pids = {part.split(":")[1] for part in node_strings
                if part.startswith("P:") and part.count(":") >= 2}

        blocking = advisory = gaps = 0
        for violation in report.get("detail", {}).get("violations", []):
            target = str(violation.get("target", ""))
            rule = violation.get("rule", "")

            if target.startswith("seq="):
                digits = [int(part) for part in
                          target[4:].replace("..", " ").split()
                          if part.isdigit()]
                matched = bool(digits) and (
                    seq_start <= min(digits) <= seq_end
                    or seq_start <= max(digits) <= seq_end)

            elif target.startswith("pid="):
                matched = target[4:].strip() in pids

            elif " -> " in target:
                source, _, destination = target.partition(" -> ")
                matched = (source.strip() in node_strings
                           or destination.strip() in node_strings)

            else:
                matched = target in node_strings

            if not matched:
                continue
            if rule == "sequence_gap":
                gaps += 1
            elif violation.get("severity") in ("critical", "high"):
                blocking += 1
            else:
                advisory += 1

        return blocking, advisory, gaps

    @staticmethod
    def _graph_signals(graph, edges: list[tuple[Any, Any]],
                       suspicious: dict[str, float],
                       image_counts: dict[str, int],
                       total_execs: int) -> tuple[float, float, float]:
        """(gnn suspicion, privilege activity, rare-image) for one partition."""
        if graph is None or not edges:
            return 0.0, 0.0, 0.0

        nodes = {node for edge in edges for node in edge}

        # --- GNN suspicion: intensity AND extent.
        # The mean score of flagged nodes alone would rate a partition
        # with one borderline node the same as one with six, so the mean
        # is scaled by a saturating function of how many were flagged.
        flagged = [suspicious[node] for node in nodes if node in suspicious]
        gnn = (sum(flagged) / len(flagged)) * _saturate(len(flagged), 2.0) \
            if flagged else 0.0

        # --- privilege activity
        uids, root_execs = set(), 0
        for node in nodes:
            attrs = graph.nodes[node]
            if attrs.get("type") != "process" or attrs.get("synthetic_root"):
                continue
            uid = attrs.get("uid")
            if uid is not None and uid != -1:
                uids.add(int(uid))
                if int(uid) == 0:
                    root_execs += 1

        # a uid transition inside one partition is the signature of a
        # privilege change; root execution is weighted on its own
        privilege = min(1.0, 0.5 * _saturate(max(0, len(uids) - 1), 1.0)
                        + 0.5 * _saturate(root_execs, 2.0))

        # --- rare image: binaries seen once or twice in the whole capture
        rare = 0
        for node in nodes:
            attrs = graph.nodes[node]
            if attrs.get("type") != "process" or attrs.get("synthetic_root"):
                continue
            image = attrs.get("filename") or ""
            if image and image_counts.get(image, 0) <= max(1, total_execs // 50):
                rare += 1
        rare_score = _saturate(rare, 3.0)

        return gnn, privilege, rare_score

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score_partition(self, record: dict[str, Any], graph=None,
                        report: dict[str, Any] | None = None,
                        edges: list[tuple[Any, Any]] | None = None,
                        image_counts: dict[str, int] | None = None,
                        total_execs: int = 0,
                        is_tamper_alert: bool = False) -> dict[str, Any]:
        """Return the score, its tier, and every contributing signal."""

        weights = self.policy.weights
        seq_start = int(record.get("seq_start") or 0)
        seq_end = int(record.get("seq_end") or 0)

        nodes = {node for edge in (edges or []) for node in edge}
        blocking, advisory, gaps = self._violations_in_range(
            report, seq_start, seq_end, nodes)

        suspicious = {}
        if report:
            for item in report.get("detail", {}).get("top_suspicious_nodes", []):
                suspicious[item["node"]] = float(item.get("score", 0.0))

        gnn, privilege, rare = self._graph_signals(
            graph, edges or [], suspicious,
            image_counts or {}, total_execs)

        signals = {
            "tamper_alert": 1.0 if is_tamper_alert else 0.0,
            # Blocking violations saturate at one - a single proof is
            # enough. Advisory violations contribute at half weight and
            # saturate faster (half strength at one), because a
            # sophisticated deletion leaves only low-severity traces and
            # a curve tuned for blocking counts would score it at noise.
            "rule_violations": min(
                1.0,
                _saturate(blocking, 1.0) + 0.5 * _saturate(advisory, 1.0),
            ),
            "gnn_suspicion": gnn,
            "privilege_activity": privilege,
            "unattested_gap": _saturate(gaps, 3.0),
            "rare_image": rare,
        }

        score = sum(getattr(weights, name) * value
                    for name, value in signals.items())
        score = round(min(1.0, max(0.0, score)), 4)

        # Graded score first, then the hard escalation rules. Recording
        # which rule fired keeps the decision auditable - a reviewer can
        # see that a partition reached tier 1 by escalation rather than
        # by arithmetic, and why.
        tier = self.policy.tier_for(score)
        escalated_by = None

        if self.policy.escalate_tamper_alert and is_tamper_alert:
            tier, escalated_by = TIER1, "tamper_alert"
        elif self.policy.escalate_blocking_violation and blocking > 0 \
                and tier != TIER1:
            tier, escalated_by = TIER1, "blocking_rule_violation"

        return {
            "partition_index": record.get("partition_index"),
            "seq_start": seq_start,
            "seq_end": seq_end,
            "risk_score": score,
            "risk_tier": tier,
            "escalated_by": escalated_by,
            "signals": {name: round(value, 4) for name, value in signals.items()},
            "evidence": {
                "blocking_violations": blocking,
                "advisory_violations": advisory,
                "unattested_gaps": gaps,
                "flagged_nodes": sum(1 for edge in (edges or [])
                                     for node in edge if node in suspicious),
            },
        }

    def score_all(self, records: list[dict[str, Any]], graph=None,
                  report: dict[str, Any] | None = None,
                  partitions: list[dict[str, Any]] | None = None,
                  tamper_alert_indices: set[int] | None = None
                  ) -> list[dict[str, Any]]:
        """Score a whole sealed run, newest evidence first."""

        tamper_alert_indices = tamper_alert_indices or set()

        # how often each executed image appears across the whole capture,
        # used to decide what counts as "rare" within it
        image_counts: dict[str, int] = {}
        total_execs = 0
        if graph is not None:
            for _, attrs in graph.nodes(data=True):
                if attrs.get("type") == "process" and not attrs.get("synthetic_root"):
                    image = attrs.get("filename") or ""
                    if image:
                        image_counts[image] = image_counts.get(image, 0) + 1
                        total_execs += 1

        edges_by_index = {part["index"]: part["edges"]
                          for part in (partitions or [])}

        return [
            self.score_partition(
                record, graph, report,
                edges=edges_by_index.get(record.get("partition_index")),
                image_counts=image_counts,
                total_execs=total_execs,
                is_tamper_alert=record.get("partition_index") in tamper_alert_indices,
            )
            for record in sorted(records,
                                 key=lambda item: item.get("partition_index", 0))
        ]


def summarise(scores: list[dict[str, Any]]) -> dict[str, Any]:
    """Tier counts and score distribution, for the anchoring report."""
    tiers: dict[str, int] = {TIER1: 0, TIER2: 0, TIER3: 0}
    for entry in scores:
        tiers[entry["risk_tier"]] = tiers.get(entry["risk_tier"], 0) + 1
    values = [entry["risk_score"] for entry in scores] or [0.0]
    return {
        "partitions": len(scores),
        "by_tier": tiers,
        "score_min": round(min(values), 4),
        "score_max": round(max(values), 4),
        "score_mean": round(sum(values) / len(values), 4),
    }
