"""
Tampering test harness: attack the evidence, then measure which layer notices.

Everything here works on copies inside a temporary directory, with a throwaway
key store and ledger. It never modifies the real graph, evidence, keys or
ledger.

Two kinds of attack
-------------------
**Graph attacks** change the provenance graph and are scored against each
detection layer separately:

    rules    the deterministic checks in detection/detector.py
    gnn      the GraphSAGE model alone
    fusion   the verdict the system actually reports (rules OR gnn)
    seal     verification against partitions sealed before the attack

They come in two families, and the difference between them is the point:

    trained    the strategies the GNN saw during training
               (detection/synthetic.py), at crude and expert levels
    held_out   attacks the GNN never saw, written to keep the graph
               self-consistent: sequence numbers renumbered, hashes
               recomputed, timestamps moved on nodes and edges together

Scores on the trained family show the model learned its training data. Scores
on the held-out family show what it does against an attacker who has read this
code. Expect the seal to catch everything, because it does not depend on the
graph looking wrong, only on it being different.

**Evidence attacks** leave the graph alone and modify the sealed records and
the ledger. Each one must make verification fail.

Real-graph caveat: a model trained on a capture has seen that capture, so its
scores on windows of the same graph are optimistic. The report keeps real and
synthetic results separate for this reason.
"""

from __future__ import annotations

import copy
import json
import random
import tempfile
import zlib
from pathlib import Path
from typing import Any, Callable

from core import config
from core.store import FileStore
from anchoring.ledger import LocalLedger
from anchoring.service import AnchoringService, batch_root
from crypto.integrity import (DualSigner, DualVerifier, EvidenceVerifier,
                              IntegrityService, KeyStore, record_hash)
from detection import synthetic
from detection.detector import BLOCKING_SEVERITIES, PoisoningDetector
from detection.model import binary_metrics, roc_auc

# Far from the range detection/synthetic.py draws its training graphs from.
_FIRST_SYNTHETIC_SEED = 1_000_000


# ======================================================================
# Helpers for self-consistent attacks
# ======================================================================


def _events(graph) -> list[Any]:
    """Real process nodes in capture order."""
    nodes = [node for node, attrs in graph.nodes(data=True)
             if attrs.get("type") == "process" and not attrs.get("synthetic_root")]
    return sorted(nodes, key=lambda node: graph.nodes[node].get("sequence") or 0)


def _spawn_parent(graph, node):
    for parent, _, attrs in graph.in_edges(node, data=True):
        if attrs.get("relation") == "SPAWNS":
            return parent
    return None


def _spawn_children(graph, node) -> list[Any]:
    return [child for _, child, attrs in graph.out_edges(node, data=True)
            if attrs.get("relation") == "SPAWNS"]


def _exec_edge(graph, node):
    for _, target, attrs in graph.out_edges(node, data=True):
        if attrs.get("relation") == "EXECUTES":
            return target
    return None


def _refresh_files(graph) -> None:
    """Remove unused file nodes and make the rest agree with their edges.

    A file node carries the sequence and time of the last exec of that file,
    so a careful attacker has to keep those in step.
    """
    for node, attrs in list(graph.nodes(data=True)):
        if attrs.get("type") != "file":
            continue
        incoming = list(graph.in_edges(node, data=True))
        if not incoming:
            graph.remove_node(node)
            continue
        latest = max(incoming, key=lambda edge: edge[2].get("seq") or 0)[2]
        attrs["sequence"], attrs["timestamp"] = latest.get("seq"), latest.get("ts")


def _renumber(graph) -> None:
    """Close every sequence gap, as an attacker hiding a deletion would."""
    numbers = sorted({int(attrs["seq"]) for _, _, attrs in graph.edges(data=True)
                      if attrs.get("seq")})
    mapping = {old: new for new, old in enumerate(numbers, start=1)}
    for _, _, attrs in graph.edges(data=True):
        if attrs.get("seq"):
            attrs["seq"] = mapping[int(attrs["seq"])]
    for node in _events(graph):
        attrs = graph.nodes[node]
        attrs["sequence"] = mapping.get(int(attrs.get("sequence") or 0),
                                        attrs.get("sequence"))


def _count(events: list[Any], intensity: float) -> int:
    return max(1, int(len(events) * intensity))


def _result(graph, positives, info) -> synthetic.TamperResult:
    labels = {node: 0 for node in graph.nodes()}
    for node in positives:
        if node in labels:
            labels[node] = 1
    return synthetic.TamperResult(graph, labels, [info])


# ======================================================================
# Held-out attacks
# ======================================================================


def adaptive_deletion(graph, rng, intensity):
    """Remove whole events, re-parent their children, renumber everything."""
    H = graph.copy()
    events = _events(H)
    if len(events) < 4:
        return None
    touched = set()
    for victim in rng.sample(events, min(_count(events, intensity), len(events) - 2)):
        parent = _spawn_parent(H, victim)
        for child in _spawn_children(H, victim):
            if parent is not None:
                attrs = H.edges[victim, child]
                H.add_edge(parent, child, **attrs)
                touched.add(child)
        if parent is not None:
            touched.add(parent)
        H.remove_node(victim)
    _refresh_files(H)
    _renumber(H)
    return _result(H, touched, {"strategy": "adaptive_deletion"})


def tail_truncate(graph, rng, intensity):
    """Remove the newest events. Nothing later exists to reveal the gap."""
    H = graph.copy()
    events = _events(H)
    if len(events) < 4:
        return None
    count = min(_count(events, intensity), len(events) - 2)
    touched = set()
    for victim in events[-count:]:
        # only children of removed events are also removed, as they are newer
        parent = _spawn_parent(H, victim)
        if parent is not None:
            touched.add(parent)
        H.remove_node(victim)
    _refresh_files(H)
    return _result(H, touched, {"strategy": "tail_truncate"})


def adaptive_reorder(graph, rng, intensity):
    """Swap two events' place in time on nodes, edges and hashes together."""
    H = graph.copy()
    events = _events(H)
    if len(events) < 4:
        return None

    def bounds_hold(node, new_ts):
        parent = _spawn_parent(H, node)
        if parent is not None and not H.nodes[parent].get("synthetic_root") \
                and new_ts < int(H.nodes[parent].get("timestamp") or 0):
            return False
        return all(new_ts <= int(H.nodes[child].get("timestamp") or 0)
                   for child in _spawn_children(H, node))

    touched = set()
    for _ in range(_count(events, intensity)):
        for _attempt in range(30):
            first, second = rng.sample(events, 2)
            a, b = H.nodes[first], H.nodes[second]
            if bounds_hold(first, b["timestamp"]) and bounds_hold(second, a["timestamp"]):
                a["sequence"], b["sequence"] = b["sequence"], a["sequence"]
                a["timestamp"], b["timestamp"] = b["timestamp"], a["timestamp"]
                for node in (first, second):
                    attrs = H.nodes[node]
                    attrs["process_hash"] = synthetic._process_hash(
                        attrs["pid"], attrs["timestamp"], attrs["comm"])
                    parent = _spawn_parent(H, node)
                    if parent is not None:
                        H.edges[parent, node].update(
                            seq=attrs["sequence"], ts=attrs["timestamp"])
                    target = _exec_edge(H, node)
                    if target is not None:
                        H.edges[node, target].update(
                            seq=attrs["sequence"], ts=attrs["timestamp"])
                touched.update((first, second))
                break
    if not touched:
        return None
    _refresh_files(H)
    return _result(H, touched, {"strategy": "adaptive_reorder"})


def adaptive_forgery(graph, rng, intensity):
    """Append invented events that obey every rule the builder follows."""
    H = graph.copy()
    events = _events(H)
    if len(events) < 2:
        return None
    files = [node for node, attrs in H.nodes(data=True) if attrs.get("type") == "file"]
    if not files:
        return None
    sequence = max(int(attrs.get("seq") or 0) for _, _, attrs in H.edges(data=True))
    timestamp = max(int(attrs.get("ts") or 0) for _, _, attrs in H.edges(data=True))
    touched = set()
    for _ in range(_count(events, intensity)):
        sequence += 1
        timestamp += rng.randint(200_000, 3_000_000)
        parent = rng.choice(events)
        target = rng.choice(files)
        path = H.nodes[target].get("filename") or ""
        comm = (H.nodes[parent].get("filename") or "").rsplit("/", 1)[-1][:15]
        pid = rng.randint(1000, 60000)
        fake = f"P:{pid}:{sequence}"
        H.add_node(fake, type="process", label=f"{path.rsplit('/', 1)[-1]}\nPID {pid}",
                   pid=pid, uid=H.nodes[parent].get("uid"), comm=comm, filename=path,
                   sequence=sequence, timestamp=timestamp,
                   process_hash=synthetic._process_hash(pid, timestamp, comm),
                   synthetic_root=False)
        H.add_edge(parent, fake, relation="SPAWNS", method="execve",
                   seq=sequence, ts=timestamp)
        H.add_edge(fake, target, relation="EXECUTES", seq=sequence, ts=timestamp)
        touched.update((fake, parent, target))
    _refresh_files(H)
    return _result(H, touched, {"strategy": "adaptive_forgery"})


def binary_swap(graph, rng, intensity):
    """Make a malicious exec look like a harmless one. The process hash does
    not cover the file name, so nothing has to be recomputed."""
    H = graph.copy()
    events = _events(H)
    files = [node for node, attrs in H.nodes(data=True) if attrs.get("type") == "file"]
    if len(events) < 2 or len(files) < 2:
        return None
    touched = set()
    for victim in rng.sample(events, _count(events, intensity)):
        old = _exec_edge(H, victim)
        options = [node for node in files if node != old and node in H]
        if old is None or not options:
            continue
        new = rng.choice(options)
        attrs = dict(H.edges[victim, old])
        H.remove_edge(victim, old)
        H.add_edge(victim, new, **attrs)
        H.nodes[victim]["filename"] = H.nodes[new].get("filename")
        touched.update((victim, new))
    if not touched:
        return None
    _refresh_files(H)
    return _result(H, touched, {"strategy": "binary_swap"})


def uid_rewrite(graph, rng, intensity):
    """Blame a different user. The process hash does not cover the uid."""
    H = graph.copy()
    events = _events(H)
    if len(events) < 2:
        return None
    victims = rng.sample(events, _count(events, intensity))
    for victim in victims:
        H.nodes[victim]["uid"] = int(H.nodes[victim].get("uid") or 1000) + 1
    return _result(H, victims, {"strategy": "uid_rewrite"})


def flag_abuse(graph, rng, intensity):
    """Mark real processes as the session root and blank their hashes, which
    is an attempt to be skipped by the rule checks."""
    H = graph.copy()
    events = _events(H)
    if len(events) < 2:
        return None
    victims = rng.sample(events, _count(events, intensity))
    for victim in victims:
        H.nodes[victim].update(synthetic_root=True, process_hash="")
    return _result(H, victims, {"strategy": "flag_abuse"})


HELD_OUT: dict[str, Callable] = {
    "adaptive_deletion": adaptive_deletion,
    "tail_truncate": tail_truncate,
    "adaptive_reorder": adaptive_reorder,
    "adaptive_forgery": adaptive_forgery,
    "binary_swap": binary_swap,
    "uid_rewrite": uid_rewrite,
    "flag_abuse": flag_abuse,
}


def _trained(strategy: str, sophistication: float) -> Callable:
    def attack(graph, rng, intensity):
        result = synthetic.TamperGenerator(rng, sophistication=sophistication) \
            .apply(graph, [strategy], intensity=intensity)
        return result if result.applied else None
    return attack


TRAINED: dict[str, Callable] = {
    f"{strategy}_{level}": _trained(strategy, value)
    for strategy in synthetic.STRATEGIES
    for level, value in (("crude", 0.0), ("expert", 1.0))
}

ATTACKS: dict[str, Callable] = {**TRAINED, **HELD_OUT}


def apply_attack(graph, name: str, intensity: float = 0.1, seed: int = 7):
    """Apply one named attack to a copy of `graph`."""
    if name not in ATTACKS:
        raise ValueError(f"unknown attack: {name}. Choose from: "
                         f"{', '.join(sorted(ATTACKS))}")
    return ATTACKS[name](graph, random.Random(seed), intensity)


# ======================================================================
# Graph-attack matrix
# ======================================================================


def _rate(hits: int, total: int) -> float | None:
    return round(hits / total, 4) if total else None


class _Tally:
    def __init__(self):
        self.total = self.rules = self.gnn = self.fusion = self.seal = 0
        self.y: list[float] = []
        self.p: list[float] = []

    def add(self, detector, verifier, graph, records, labels=None):
        report = detector.detect(graph)
        by_severity = report["detail"]["rule_summary"].get("by_severity", {})
        self.total += 1
        self.rules += any(by_severity.get(level) for level in BLOCKING_SEVERITIES)
        self.gnn += report["gnn_flagged_nodes"] >= config.GRAPH_ALERT_MIN_NODES
        self.fusion += bool(report["tampered"])
        self.seal += not verifier.verify(graph, records=records).ok
        if labels is not None and detector.model is not None:
            scores = detector.score_nodes(graph)
            for node, score in scores.items():
                self.y.append(float(labels.get(node, 0)))
                self.p.append(score)

    def summary(self, threshold: float) -> dict[str, Any]:
        result = {
            "trials": self.total,
            "rules": _rate(self.rules, self.total),
            "gnn": _rate(self.gnn, self.total),
            "fusion": _rate(self.fusion, self.total),
            "seal": _rate(self.seal, self.total),
        }
        if self.y and 0 < sum(self.y) < len(self.y):
            node = binary_metrics(self.y, self.p, threshold)
            result["node_precision"] = node["precision"]
            result["node_recall"] = node["recall"]
            result["node_auc"] = round(roc_auc(self.y, self.p), 4)
        return result


def _base_graphs(real, trials: int, seed: int) -> dict[str, list]:
    bases: dict[str, list] = {"synthetic": []}
    for trial in range(trials):
        rng = random.Random(_FIRST_SYNTHETIC_SEED + seed + trial)
        # a third include normal sudo use, so the CLEAN row covers admin work
        bases["synthetic"].append(synthetic.generate(rng, n_events=rng.randint(60, 140),
                                                     privileged=trial % 3 == 0))
    if real is not None and real.number_of_edges() > 0:
        pieces = synthetic.windows(real, size=60, stride=60)
        bases["real"] = pieces or [real]
    return bases


def attack_matrix(real, trials: int = 20, intensity: float = 0.1, seed: int = 7,
                  model_path: str | None = None) -> dict[str, Any]:
    detector = PoisoningDetector(model_path=model_path)
    results: dict[str, Any] = {}

    with tempfile.TemporaryDirectory() as directory:
        workspace = Path(directory)
        keystore = KeyStore(str(workspace / "keys.json"), "tamper-test").create()
        service = IntegrityService(keystore, FileStore(workspace / "evidence"),
                                   partition_size=64)
        verifier = EvidenceVerifier(store=service.store)

        for source, graphs in _base_graphs(real, trials, seed).items():
            sealed = [(graph, service.seal(graph, run_id="t", persist=False))
                      for graph in graphs]

            clean = _Tally()
            for graph, records in sealed:
                clean.add(detector, verifier, graph, records)

            attacks = {}
            for name, attack in ATTACKS.items():
                tally = _Tally()
                for position, (graph, records) in enumerate(sealed):
                    # crc32, because hash() of a string changes on every run
                    rng = random.Random(zlib.crc32(name.encode()) + seed + position)
                    outcome = attack(graph, rng, intensity)
                    if outcome is not None:
                        tally.add(detector, verifier, outcome.graph, records,
                                  outcome.labels)
                attacks[name] = {"family": "trained" if name in TRAINED else "held_out",
                                 **tally.summary(detector.threshold)}

            results[source] = {"graphs": len(graphs),
                               "clean": clean.summary(detector.threshold),
                               "attacks": attacks}

        # The windows above are small enough to suit the model. `detect` runs
        # on the whole capture, so report what it says there as well.
        if real is not None and real.number_of_edges() > 0:
            whole = detector.detect(real)
            results["real"]["whole_capture"] = {
                "events": whole["detail"]["events"],
                "verdict": whole["verdict"],
                "gnn_flagged_nodes": whole["gnn_flagged_nodes"],
                "larger_than_training": whole["detail"]["larger_than_training"],
            }

    return {"model_loaded": detector.model is not None,
            "threshold": detector.threshold, "intensity": intensity,
            "sources": results}


# ======================================================================
# Evidence attacks
# ======================================================================


def _refresh_record(record: dict[str, Any], signer: DualSigner) -> None:
    record["record_hash"] = record_hash(record)
    record.update(signer.sign(record["record_hash"]))


def evidence_attacks() -> list[dict[str, Any]]:
    """Attack the sealed records and ledger. Every entry must be detected."""
    rng = random.Random(11)
    graph = synthetic.generate(rng, n_events=120)
    results = []

    with tempfile.TemporaryDirectory() as directory:
        workspace = Path(directory)
        keystore = KeyStore(str(workspace / "keys.json"), "real").create()
        attacker = DualSigner(KeyStore(str(workspace / "attacker.json"), "x").create())
        service = IntegrityService(keystore, FileStore(workspace / "evidence"),
                                   partition_size=16)
        sealed = service.seal(graph, run_id="t", persist=False)
        identity = KeyStore.public_identity(keystore.path)
        pins = (identity["ed25519_public_key"], identity["mldsa_public_key"])
        verifier = EvidenceVerifier(service.store, *pins)

        def check(name: str, mutate: Callable, target=None):
            records = copy.deepcopy(sealed)
            changed = mutate(records)
            records = changed if changed is not None else records
            report = verifier.verify(target if target is not None else graph,
                                     records=records)
            results.append({"attack": name, "layer": "seal", "detected": not report.ok,
                            "reason": report.errors[0] if report.errors else None})

        def flip(text: str) -> str:
            return ("0" if text[0] != "0" else "1") + text[1:]

        check("edit a leaf hash", lambda r: r[0]["leaf_hashes"].__setitem__(
            0, flip(r[0]["leaf_hashes"][0])))
        check("edit a Merkle root", lambda r: r[1].__setitem__(
            "merkle_root", flip(r[1]["merkle_root"])))
        check("edit a signed field", lambda r: r[0].__setitem__("seq_start", 999))
        check("forge the Ed25519 signature", lambda r: r[0].__setitem__(
            "ed25519_signature", "00" * 64))
        check("forge the ML-DSA signature", lambda r: r[0].__setitem__(
            "mldsa_signature", flip(r[0]["mldsa_signature"])))
        check("delete a middle partition", lambda r: r[:1] + r[2:])
        check("swap two partitions", lambda r: (
            r[0].__setitem__("partition_index", 1),
            r[1].__setitem__("partition_index", 0)) and None)
        check("add a duplicate leaf", lambda r: r[0]["leaf_hashes"].append(
            r[0]["leaf_hashes"][-1]))

        # truncation: the newest partitions and their relations both removed
        from crypto.integrity import partition_graph
        short = graph.copy()
        for part in partition_graph(graph, 16)[-2:]:
            short.remove_edges_from(part["edges"])
        check("truncate the newest partitions", lambda r: r[:-2], short)

        # the attacker controls everything except the real private keys
        rewritten = graph.copy()
        rewritten.remove_node(_events(rewritten)[5])
        forged_service = IntegrityService(
            attacker.ks, FileStore(workspace / "attacker"), partition_size=16)
        forged = forged_service.seal(rewritten, run_id="t", persist=False)
        check("rewrite and re-sign with own key", lambda r: forged, rewritten)

        # second signature swapped to an attacker's ML-DSA key: the case of a
        # quantum attacker who can forge Ed25519 but not ML-DSA
        def swap_mldsa(records):
            for record in records:
                record["mldsa_public_key"] = attacker.ks.mldsa_public.hex()
        check("replace the ML-DSA key", swap_mldsa)

        # --- ledger
        ledger_path = workspace / "ledger.json"
        ledger = LocalLedger(ledger_path, signer=DualSigner(keystore))
        anchoring = AnchoringService(ledger=ledger, batch_size=4)
        scores = [{"partition_index": r["partition_index"], "merkle_root": r["merkle_root"],
                   "risk_score": 0.3, "record_hash": r["record_hash"]} for r in sealed]
        batched = anchoring._flush(scores[:4], "t", "tier2_batched")
        pinned = DualVerifier(*pins)
        original_blocks = copy.deepcopy(ledger._blocks)

        def ledger_check(name: str, detected: bool, reason: str | None = None):
            results.append({"attack": name, "layer": "ledger", "detected": detected,
                            "reason": reason})

        evil_root, evil_tree = batch_root([sealed[0]["merkle_root"], "ab" * 32])
        forged_anchor = {**batched[0], "inclusion": {
            "batch_root": evil_root, "leaf_index": 0, "path": evil_tree.proof(0)}}
        ledger_check("inclusion proof to a fake batch root",
                     not anchoring.verify_anchor(forged_anchor)["ok"])

        rewritten_records = copy.deepcopy(sealed)
        rewritten_records[0]["merkle_root"] = flip(rewritten_records[0]["merkle_root"])
        problems = anchoring.cross_check(rewritten_records)
        ledger_check("sealed root differs from the anchored root", bool(problems),
                     problems[0] if problems else None)

        ledger._blocks[0]["payload"]["member_count"] = 99
        state = ledger.verify(pinned)
        ledger_check("edit a ledger block", not state["ok"],
                     state["errors"][0] if state["errors"] else None)

        ledger._blocks = copy.deepcopy(original_blocks)
        rogue = LocalLedger(workspace / "rogue.json", signer=attacker)
        rogue.anchor({"kind": "batch", "run_id": "t", "merkle_root": "ab" * 32})
        state = rogue.verify(pinned)
        ledger_check("rebuild the ledger with own key", not state["ok"],
                     state["errors"][0] if state["errors"] else None)

        ledger.anchor({"kind": "partition", "run_id": "other", "partition_index": 0,
                       "merkle_root": "cd" * 32, "record_hash": None, "risk_score": 0.5})
        ledger._blocks[0:1] = []
        state = ledger.verify(pinned)
        ledger_check("remove a ledger block", not state["ok"],
                     state["errors"][0] if state["errors"] else None)

        ledger._blocks = copy.deepcopy(original_blocks)
        ledger._blocks.clear()
        ledger_check("delete the anchored block entirely",
                     not anchoring.verify_anchor(batched[0])["ok"])

    return results


# ======================================================================
# Commands and reporting
# ======================================================================


def run_all(real, trials: int = 20, intensity: float = 0.1, seed: int = 7,
            model_path: str | None = None) -> dict[str, Any]:
    matrix = attack_matrix(real, trials, intensity, seed, model_path)
    evidence = evidence_attacks()
    matrix["evidence_attacks"] = evidence
    matrix["evidence_attacks_missed"] = [item["attack"] for item in evidence
                                         if not item["detected"]]
    return matrix


def _percent(value) -> str:
    return "   - " if value is None else f"{value * 100:4.0f}%"


def format_report(results: dict[str, Any]) -> str:
    lines = ["=" * 78, "  QuantumGuard - Tamper Test", "=" * 78]
    if results["model_loaded"]:
        lines.append(f"  GNN threshold {results['threshold']:.3f}, "
                     f"attack intensity {results['intensity']:.0%}")
        lines.append("  REAL scores are optimistic if the model was trained on "
                     "this same capture.")
    else:
        lines.append("  NO TRAINED MODEL: the gnn column is meaningless. "
                     "Run: python main.py train")

    header = (f"  {'attack':<22}{'n':>4} {'rules':>6}{'gnn':>6}{'fusion':>7}"
              f"{'seal':>6}   {'node P':>6}{'node R':>7}{'AUC':>6}")
    for source, data in results["sources"].items():
        lines += ["", f"  {source.upper()} graphs ({data['graphs']})", "-" * 78, header]
        clean = data["clean"]
        lines.append(f"  {'CLEAN (false alarms)':<22}{clean['trials']:>4} "
                     f"{_percent(clean['rules']):>6}{_percent(clean['gnn']):>6}"
                     f"{_percent(clean['fusion']):>7}{_percent(clean['seal']):>6}")
        for family, title in (("trained", "seen in training"),
                              ("held_out", "never seen in training")):
            lines.append(f"  -- {title}")
            rows = {name: row for name, row in data["attacks"].items()
                    if row["family"] == family}
            for name, row in rows.items():
                node = ""
                if "node_auc" in row:
                    node = (f"   {row['node_precision']:>6.2f}"
                            f"{row['node_recall']:>7.2f}{row['node_auc']:>6.2f}")
                lines.append(f"  {name:<22}{row['trials']:>4} "
                             f"{_percent(row['rules']):>6}{_percent(row['gnn']):>6}"
                             f"{_percent(row['fusion']):>7}{_percent(row['seal']):>6}{node}")
        whole = data.get("whole_capture")
        if whole:
            lines.append(f"  -- this capture as a whole, assumed clean ({whole['events']} events)")
            lines.append(f"  verdict {whole['verdict']}, {whole['gnn_flagged_nodes']} node(s) "
                         f"flagged by the GNN"
                         + ("; larger than any training graph" if whole["larger_than_training"] else ""))

    lines += ["", "  EVIDENCE ATTACKS (the graph is untouched)", "-" * 78]
    for item in results["evidence_attacks"]:
        lines.append(f"  {'caught' if item['detected'] else 'MISSED':<8}"
                     f"{item['layer']:<8}{item['attack']}")
    caught = sum(item["detected"] for item in results["evidence_attacks"])
    lines.append(f"  {caught}/{len(results['evidence_attacks'])} caught")
    lines.append("=" * 78)
    return "\n".join(lines)


def save_report(results: dict[str, Any], path: str | Path | None = None) -> Path:
    output = Path(path or f"{config.EVALUATION_DIR}/tamper_report.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return output


def apply_command(args, graph) -> Path:
    """`tamper apply`: write a tampered copy and its ground truth."""
    import pickle

    outcome = apply_attack(graph, args.attack, args.intensity, args.seed)
    if outcome is None:
        raise SystemExit(f"graph is too small for attack {args.attack}")

    output = Path(args.output or f"{config.GRAPH_DIR}/tampered_{args.attack}.gpickle")
    if output.resolve() == Path(config.GRAPH_PICKLE).resolve():
        raise SystemExit("refusing to overwrite the real provenance graph")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as handle:
        pickle.dump(outcome.graph, handle)

    truth = output.with_suffix(".truth.json")
    truth.write_text(json.dumps({
        "attack": args.attack, "intensity": args.intensity, "seed": args.seed,
        "tampered_nodes": sorted(map(str, outcome.positives())),
        "applied": outcome.applied,
    }, indent=2, default=str) + "\n", encoding="utf-8")

    print(f"Tampered graph : {output}")
    print(f"Ground truth   : {truth}")
    print(f"Relations      : {graph.number_of_edges()} -> "
          f"{outcome.graph.number_of_edges()}")
    print(f"Nodes changed  : {len(outcome.positives())}")
    print("\nNow see who notices (the real evidence is not modified):")
    print(f"  python main.py detect --graph {output} "
          f"--output evidence/tampered_detection.json")
    print(f"  python main.py verify --graph {output}")
    return output
