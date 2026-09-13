"""
Phase 4 - Poisoning Detection (inference side).

Two detectors run over the same graph and their outputs are combined:

    RuleEngine   deterministic invariants. High precision, zero training.
                 A violation is proof, not a guess.
    GraphSAGE    learned structural/temporal anomaly score per node
                 (detection/model.py). Catches tampering the rules were
                 not written for.

Fusion policy
-------------
    any critical/high rule violation      -> tampered (confidence 1.0)
    >= GRAPH_ALERT_MIN_NODES nodes above
      the learned threshold               -> tampered
    otherwise                             -> clean

The rule engine deliberately dominates: it cannot produce a false
positive on a correctly captured graph, so when it fires we do not let a
low GNN score talk us out of it. The GNN only ever ADDS detections.

The report this produces is itself evidence. Phase 5 (crypto/integrity.py)
seals it, which is what stops an attacker from deleting the alert that
says they were caught.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import os

import numpy as np

from core import config
from detection import features
from detection.model import GraphSAGE

# ===================================================================
# Rule engine
# ===================================================================
#
# The GNN generalises but can be wrong. These rules cannot: each one
# encodes an invariant that a correctly captured provenance graph is
# guaranteed to satisfy, so a violation is hard evidence of tampering (or
# of a capture bug, which is equally worth surfacing).
#
# Rules
# -----
# R1  sequence_gap           gap in capture sequence not explained by a CCA
#                             attestation record
# R2  duplicate_sequence     two relations claim the same sequence number
# R3  temporal_inversion     a later sequence number carries an earlier
#                             timestamp
# R4  causal_inversion       a child process is timestamped before the
#                             parent that spawned it
# R5  process_hash_mismatch  process_hash != sha256("pid:timestamp:comm")
# R6  orphan_process         a non-root process with no parent edge
# R7  dangling_edge          edge endpoint missing from the node set
# R8  self_loop              a process that spawned or executed itself
# R9  attribute_conflict     the same process node carries inconsistent
#                             uid/comm across its relations
# R10 impossible_timestamp   negative timestamp (see _temporal_rules for
#                             why far-future is deliberately not checked)
#
# Every violation names the node or edge, so the report is actionable and
# can be handed to the integrity layer as a "tamper alert" artefact.

SEVERITY = {
    "sequence_gap": "medium",
    "duplicate_sequence": "high",
    "temporal_inversion": "high",
    "causal_inversion": "high",
    "process_hash_mismatch": "critical",
    "orphan_process": "low",
    "dangling_edge": "critical",
    "self_loop": "medium",
    "attribute_conflict": "high",
    "impossible_timestamp": "medium",
}

BLOCKING_SEVERITIES = {"critical", "high"}


def _violation(rule, target, detail):
    return {
        "rule": rule,
        "severity": SEVERITY.get(rule, "medium"),
        "target": target,
        "detail": detail,
    }


class RuleEngine:

    def __init__(self, known_missing_sequences: set[int] | None = None):
        # sequences the CCA layer already attested as lost - a gap that
        # matches a signed attestation is NOT tampering.
        self.known_missing = known_missing_sequences or set()

    def check(self, G) -> list[dict]:
        v: list[dict] = []
        v += self._sequence_rules(G)
        v += self._temporal_rules(G)
        v += self._structural_rules(G)
        v += self._attribute_rules(G)
        return v

    def _sequence_rules(self, G):
        out = []
        seqs = {}
        for u, w, d in G.edges(data=True):
            s = int(d.get("seq") or 0)
            if s <= 0:
                continue
            seqs.setdefault(s, []).append((u, w))

        for s, edges in seqs.items():
            # one execve legitimately produces an EXECUTES and a SPAWNS
            # edge, so up to two relations may share a sequence number.
            if len(edges) > 2:
                out.append(_violation(
                    "duplicate_sequence", f"seq={s}",
                    f"{len(edges)} relations share sequence {s}"))

        ordered = sorted(seqs)
        for i in range(1, len(ordered)):
            prev, cur = ordered[i - 1], ordered[i]
            if cur == prev + 1:
                continue
            missing = set(range(prev + 1, cur))
            unexplained = sorted(missing - self.known_missing)
            if unexplained:
                out.append(_violation(
                    "sequence_gap", f"seq={prev}..{cur}",
                    f"{len(unexplained)} sequence number(s) absent with no "
                    f"CCA attestation: {unexplained[:10]}"))
        return out

    def _temporal_rules(self, G):
        out = []
        edges = sorted(
            ((int(d.get("seq") or 0), int(d.get("ts") or 0), u, w)
             for u, w, d in G.edges(data=True)),
            key=lambda e: e[0],
        )

        prev_seq = prev_ts = None
        prev_edge = None
        for seq, ts, u, w in edges:
            if prev_ts is not None and ts < prev_ts:
                out.append(_violation(
                    "temporal_inversion", f"{u} -> {w}",
                    f"sequence {seq} has timestamp {ts}, earlier than "
                    f"sequence {prev_seq} at {prev_ts} ({prev_edge})"))
            prev_seq, prev_ts, prev_edge = seq, ts, f"{u} -> {w}"

        # "Far-future" is deliberately NOT checked here: event timestamps
        # are bpf_ktime_get_ns() - nanoseconds since boot, not wall-clock -
        # so there is no correct way to compare them against a freshly
        # computed time.time() "now" without also knowing which boot
        # session produced the capture. Forensic review routinely happens
        # after a reboot (or on a different machine), where every
        # legitimate timestamp would then look impossibly far in the
        # future; wiring that comparison up "for completeness" would turn
        # normal evidence handling into a false-positive generator. Only
        # a negative timestamp - never valid under any clock - is safe to
        # flag without a wall-clock anchor recorded at capture time.
        for node, a in G.nodes(data=True):
            ts = int(a.get("timestamp") or 0)
            if a.get("synthetic_root"):
                continue
            if ts < 0:
                out.append(_violation("impossible_timestamp", node,
                                      f"negative timestamp {ts}"))

        for u, w, d in G.edges(data=True):
            if d.get("relation") != "SPAWNS":
                continue
            pt = int(G.nodes[u].get("timestamp") or 0)
            ct = int(G.nodes[w].get("timestamp") or 0)
            if G.nodes[u].get("synthetic_root"):
                continue
            if pt and ct and ct < pt:
                out.append(_violation(
                    "causal_inversion", f"{u} -> {w}",
                    f"child timestamp {ct} precedes parent timestamp {pt}"))
        return out

    def _structural_rules(self, G):
        out = []
        # NetworkX auto-creates any node an edge refers to, so this can
        # never fire against a live, single in-memory graph - it only
        # guards a graph reconstructed from a partial external source
        # (e.g. a node table and an edge table loaded separately and out
        # of sync). Kept because that is exactly what a future storage
        # backend could do; harmless dead weight until then.
        node_set = set(G.nodes())

        for u, w in G.edges():
            if u not in node_set or w not in node_set:
                out.append(_violation("dangling_edge", f"{u} -> {w}",
                                      "edge references a missing node"))
            if u == w:
                out.append(_violation("self_loop", u,
                                      "node has a relation to itself"))

        for node, a in G.nodes(data=True):
            if a.get("type") != "process" or a.get("synthetic_root"):
                continue
            has_parent = any(
                d.get("relation") == "SPAWNS"
                for *_, d in G.in_edges(node, data=True)
            )
            if not has_parent:
                out.append(_violation(
                    "orphan_process", node,
                    "process node with no SPAWNS parent - its causal origin "
                    "cannot be reconstructed"))
        return out

    def _attribute_rules(self, G):
        out = []
        for node, a in G.nodes(data=True):
            if a.get("type") != "process" or a.get("synthetic_root"):
                continue
            stored = a.get("process_hash")
            if not stored:
                continue
            expected = hashlib.sha256(
                f"{a.get('pid')}:{a.get('timestamp')}:{a.get('comm')}".encode()
            ).hexdigest()
            if stored != expected:
                out.append(_violation(
                    "process_hash_mismatch", node,
                    "stored process_hash does not match its own pid/"
                    "timestamp/comm - the node was edited after capture"))

        # a pid reused with conflicting uid inside one capture window
        by_pid: dict[int, set] = {}
        for node, a in G.nodes(data=True):
            if a.get("type") != "process" or a.get("synthetic_root"):
                continue
            pid = a.get("pid")
            if pid in (None, -1):
                continue
            by_pid.setdefault(pid, set()).add(a.get("uid"))
        for pid, uids in by_pid.items():
            if len(uids) > 1:
                out.append(_violation(
                    "attribute_conflict", f"pid={pid}",
                    f"same pid appears under conflicting uids {sorted(uids)}"))
        return out


def summarise(violations: list[dict]) -> dict:
    counts: dict[str, int] = {}
    sev: dict[str, int] = {}
    for v in violations:
        counts[v["rule"]] = counts.get(v["rule"], 0) + 1
        sev[v["severity"]] = sev.get(v["severity"], 0) + 1
    return {"total": len(violations), "by_rule": counts, "by_severity": sev}


# ===================================================================
# Fusion detector
# ===================================================================


class PoisoningDetector:

    def __init__(self, model_path: str | None = None,
                 known_missing_sequences: set[int] | None = None,
                 require_model: bool = False):
        self.rules = RuleEngine(known_missing_sequences)
        self.model = None
        self.meta = None

        path = model_path or config.MODEL_PATH
        if os.path.exists(path):
            self.model, self.meta = GraphSAGE.load(path)
        elif require_model:
            raise FileNotFoundError(
                f"no trained model at {path} - run: python -m detection.model"
            )

    @property
    def threshold(self) -> float:
        return float(self.meta["threshold"]) if self.meta else 0.5

    def score_nodes(self, G) -> dict[str, float]:
        if self.model is None:
            return {}

        X, nodes = features.extract(G)
        if len(nodes) == 0:
            return {}

        mean = np.array(self.meta["feature_mean"])
        std = np.array(self.meta["feature_std"])
        X = (X - mean) / std

        A = features.adjacency(G, nodes)
        scores = self.model.predict(X, A)
        return {n: float(s) for n, s in zip(nodes, scores)}

    def detect(self, G, run_id: str | None = None) -> dict:
        violations = self.rules.check(G)
        scores = self.score_nodes(G)

        thr = self.threshold
        flagged = sorted(
            ((n, s) for n, s in scores.items() if s >= thr),
            key=lambda kv: -kv[1],
        )

        blocking = [v for v in violations
                    if v["severity"] in BLOCKING_SEVERITIES]

        rules_say = bool(blocking)
        gnn_says = len(flagged) >= config.GRAPH_ALERT_MIN_NODES

        if rules_say:
            confidence = 1.0
        elif gnn_says:
            confidence = float(np.mean([s for _, s in flagged]))
        else:
            confidence = float(max([s for _, s in flagged], default=0.0))

        report = {
            "run_id": run_id,
            "created_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "tampered": bool(rules_say or gnn_says),
            "confidence": round(confidence, 4),
            "verdict_source": (
                "rules+gnn" if rules_say and gnn_says
                else "rules" if rules_say
                else "gnn" if gnn_says
                else "clean"
            ),
            "rule_violation_count": len(violations),
            "gnn_flagged_nodes": len(flagged),
            "graph_nodes": G.number_of_nodes(),
            "graph_edges": G.number_of_edges(),
            "detail": {
                "model_loaded": self.model is not None,
                "threshold": thr,
                "rule_summary": summarise(violations),
                "violations": violations[:200],
                "top_suspicious_nodes": [
                    {"node": n, "score": round(s, 4),
                     "type": G.nodes[n].get("type"),
                     "label": G.nodes[n].get("label")}
                    for n, s in flagged[:25]
                ],
            },
        }
        return report


def format_report(report: dict) -> str:
    lines = [
        "=" * 62,
        "  QuantumGuard - Provenance Poisoning Detection",
        "=" * 62,
        f"  graph            : {report['graph_nodes']} nodes, "
        f"{report['graph_edges']} relations",
        f"  verdict          : "
        f"{'TAMPERED' if report['tampered'] else 'CLEAN'} "
        f"({report['verdict_source']})",
        f"  confidence       : {report['confidence']}",
        f"  rule violations  : {report['rule_violation_count']}",
        f"  GNN flagged      : {report['gnn_flagged_nodes']} node(s) "
        f"above {report['detail']['threshold']:.3f}",
    ]

    by_rule = report["detail"]["rule_summary"].get("by_rule", {})
    if by_rule:
        lines.append("-" * 62)
        lines.append("  rule violations by type:")
        for rule, count in sorted(by_rule.items(), key=lambda kv: -kv[1]):
            lines.append(f"    {rule:<24} {count}")

    top = report["detail"]["top_suspicious_nodes"]
    if top:
        lines.append("-" * 62)
        lines.append("  most suspicious nodes:")
        for t in top[:10]:
            label = (t.get("label") or "").replace("\n", " ")
            lines.append(f"    {t['score']:.3f}  {t['node']}  {label}")

    if not report["detail"]["model_loaded"]:
        lines.append("-" * 62)
        lines.append("  note: no trained GNN loaded - rules only. "
                     "Run: python -m detection.model")

    lines.append("=" * 62)
    return "\n".join(lines)
