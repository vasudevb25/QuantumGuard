"""
Data and simulations behind the dashboard.

Two kinds of function live here, and the split is the main safety property:

  live_*       read the real graph, store, ledger and reports. They never write.
  simulate_*   run real project code inside a temporary directory with a
               throwaway key store and ledger. Nothing leaves that directory.

Neither needs the key store passphrase: verification uses public keys only.
"""
from __future__ import annotations

import glob
import json
import os
import pickle
import random
import tempfile
import threading
import time
import traceback
import uuid
from collections import Counter
from pathlib import Path
from typing import Any, Callable

from anchoring.ledger import LocalLedger, get_ledger
from anchoring.risk import RiskWeights, TIER1_THRESHOLD, TIER2_THRESHOLD
from anchoring.service import AnchoringService
from capture.cca import CCA, verify_certificate
from core import config
from core.store import FileStore, get_store
from crypto.integrity import (DualSigner, DualVerifier, EvidenceVerifier,
                              IntegrityService, KeyStore, partition_graph)
from detection import synthetic
from detection.detector import SEVERITY, PoisoningDetector
from evaluation import tamper
from evaluation.main import AttackSimulator, evaluate, sealing_benefit
from graph.service import ProvenanceGraphService
from graph.visualize import _layout, summarise

_DESCRIPTIONS = {
    "deletion": "Removes relations from the record",
    "reorder": "Swaps sequence numbers so events read in a different order",
    "forgery": "Inserts invented processes copied from real ones",
    "timeshift": "Moves a window of events to another time",
}
_LEVELS = {"crude": "leaves obvious traces", "expert": "recomputes hashes and timing"}


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _mtime(path: str | Path) -> float:
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0


def _read_json(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _load_graph():
    path = Path(config.GRAPH_PICKLE)
    if not path.exists():
        return None
    with path.open("rb") as handle:
        return pickle.load(handle)


def _clamp(value: Any, low: float, high: float, default: float) -> float:
    try:
        return min(high, max(low, float(value)))
    except (TypeError, ValueError):
        return default


_detector_cache: dict[str, Any] = {"key": None, "detector": None}
_cache: dict[str, tuple[Any, Any]] = {}
_lock = threading.RLock()


def _detector() -> PoisoningDetector:
    with _lock:
        key = _mtime(config.MODEL_PATH)
        if _detector_cache["key"] != key or _detector_cache["detector"] is None:
            _detector_cache.update(key=key, detector=PoisoningDetector())
        return _detector_cache["detector"]


def _cached(name: str, key: Any, build: Callable[[], Any]) -> Any:
    with _lock:
        hit = _cache.get(name)
        if hit and hit[0] == key:
            return hit[1]
    value = build()
    with _lock:
        _cache[name] = (key, value)
    return value


def _capture_running() -> bool:
    # Compared argument by argument: a shell command that merely mentions these
    # words in its text is not a capture.
    for path in glob.glob("/proc/[0-9]*/cmdline"):
        try:
            argv = Path(path).read_bytes().split(b"\0")
        except OSError:
            continue
        if argv[0].endswith(b"ebpf/loader"):
            return True
        if len(argv) >= 2 and b"capture" in argv[1:4] \
                and any(item.endswith(b"main.py") for item in argv[:3]):
            return True
    return False


def _latest_run(records: list[dict[str, Any]]) -> str | None:
    latest: dict[str, str] = {}
    for record in records:
        run, created = record.get("run_id"), str(record.get("created_at") or "")
        if run and created >= latest.get(run, ""):
            latest[run] = created
    return max(latest, key=latest.get) if latest else None


# ----------------------------------------------------------------------
# Graph payloads
# ----------------------------------------------------------------------


def _program_details(graph) -> dict[str, dict[str, Any]]:
    details: dict[str, dict[str, Any]] = {}
    for _, attrs in graph.nodes(data=True):
        if attrs.get("type") != "process" or attrs.get("synthetic_root"):
            continue
        name = os.path.basename(attrs.get("filename") or "") or "(unknown)"
        item = details.setdefault(name, {"paths": Counter(), "uids": set(), "pids": set()})
        item["paths"][attrs.get("filename")] += 1
        item["uids"].add(attrs.get("uid"))
        item["pids"].add(attrs.get("pid"))
    return {name: {"paths": item["paths"].most_common(8),
                   "uids": sorted(u for u in item["uids"] if u is not None),
                   "processes": len(item["pids"])}
            for name, item in details.items()}


def _flagged_from(report: dict[str, Any] | None) -> set[str]:
    if not report:
        return set()
    return {item["node"] for item in report["detail"]["top_suspicious_nodes"]}


def graph_payload(graph, flagged: set[str] | None = None, max_programs: int = 24,
                  max_arrows: int = 30) -> dict[str, Any]:
    summary = summarise(graph, max_programs, flagged or set(), max_arrows)
    positions = _layout(summary) if summary["programs"] else {}
    details = _program_details(graph)
    nodes = [{
        "name": name, "column": positions[name][0], "row": positions[name][1],
        "starts": summary["starts"][name],
        "kind": ("root" if name in summary["root"] else
                 "external" if name in summary["external"] else "user"),
        "flagged": name in summary["flagged"],
        "detail": details.get(name),
    } for name in sorted(summary["programs"])]
    edges = [{"source": caller, "target": program, "execs": call["events"],
              "runs": len(call["pids"]), "root": call["root"], "status": "same"}
             for (caller, program), call in summary["calls"].items()]
    return {"nodes": nodes, "edges": edges, "events": summary["events"],
            "folded": summary["folded"], "hidden": summary["hidden_calls"],
            "graph_nodes": graph.number_of_nodes(), "graph_edges": graph.number_of_edges()}


def diff_payload(before, after, flagged: set[str] | None = None) -> dict[str, Any]:
    """One picture of both graphs, marking what the attack changed."""
    old = summarise(before, 24, set(), 40)
    new = summarise(after, 24, flagged or set(), 40)
    calls = {**old["calls"], **new["calls"]}
    merged = {"programs": old["programs"] | new["programs"], "calls": calls,
              "starts": old["starts"] + new["starts"]}
    positions = _layout(merged)
    details = _program_details(after)

    def status(key):
        if key not in old["calls"]:
            return "added"
        if key not in new["calls"]:
            return "removed"
        return "same" if old["calls"][key]["events"] == new["calls"][key]["events"] else "changed"

    edges = [{"source": key[0], "target": key[1], "execs": call["events"],
              "runs": len(call["pids"]), "root": call["root"], "status": status(key),
              "before": old["calls"].get(key, {}).get("events", 0),
              "after": new["calls"].get(key, {}).get("events", 0)}
             for key, call in calls.items()]
    nodes = [{
        "name": name, "column": positions[name][0], "row": positions[name][1],
        "starts": new["starts"][name], "before": old["starts"][name],
        "kind": ("root" if name in new["root"] else
                 "external" if name not in new["starts"] and name not in old["starts"] else "user"),
        "flagged": name in new["flagged"], "detail": details.get(name),
    } for name in sorted(merged["programs"])]
    return {"nodes": nodes, "edges": edges, "events": new["events"], "folded": new["folded"],
            "hidden": new["hidden_calls"], "graph_nodes": after.number_of_nodes(),
            "graph_edges": after.number_of_edges(),
            "changed": sum(edge["status"] != "same" for edge in edges)}


def _detection_view(report: dict[str, Any]) -> dict[str, Any]:
    detail = report["detail"]
    return {
        "verdict": report["verdict"], "source": report["verdict_source"],
        "confidence": report["confidence"], "rule_violations": report["rule_violation_count"],
        "gnn_flagged": report["gnn_flagged_nodes"], "threshold": detail["threshold"],
        "model_loaded": detail["model_loaded"], "events": detail["events"],
        "larger_than_training": detail["larger_than_training"],
        "rules": SEVERITY,
        "by_rule": detail["rule_summary"]["by_rule"],
        "by_severity": detail["rule_summary"]["by_severity"],
        "violations": detail["violations"][:40],
        "suspicious": detail["top_suspicious_nodes"][:12],
    }


# ----------------------------------------------------------------------
# Live views: read only
# ----------------------------------------------------------------------


def live_detection() -> dict[str, Any] | None:
    graph = _load_graph()
    if graph is None:
        return None

    def build():
        try:
            known = get_store().load_missing_sequences()
        except Exception:
            known = set()
        # its own detector: `known` must not carry over into a simulation
        return PoisoningDetector(known_missing_sequences=known).detect(graph)

    report = _cached("detect", (_mtime(config.GRAPH_PICKLE), _mtime(config.MODEL_PATH)), build)
    return _detection_view(report)


def live_graph() -> dict[str, Any] | None:
    graph = _load_graph()
    if graph is None:
        return None
    flagged = _cached("flagged", (_mtime(config.GRAPH_PICKLE), _mtime(config.MODEL_PATH)),
                      lambda: {item["node"] for item in _detector().detect(graph)
                               ["detail"]["top_suspicious_nodes"]})
    return graph_payload(graph, flagged)


def _verification(records, graph) -> dict[str, Any]:
    identity = KeyStore.public_identity()
    pins = ((identity["ed25519_public_key"], identity["mldsa_public_key"])
            if identity else (None, None))
    report = EvidenceVerifier(get_store(), *pins).verify(graph, records=records)
    ledger = get_ledger("local")
    anchoring = AnchoringService(ledger=ledger)
    problems = anchoring.cross_check(records)
    state = ledger.verify(DualVerifier(*pins))
    certificates = []
    for path in sorted(Path(config.EVIDENCE_DIR).glob("completeness_*.json")):
        certificate = _read_json(path)
        if not certificate:
            continue
        result = verify_certificate(certificate, DualVerifier(*pins))
        body = certificate.get("body", {})
        certificates.append({"name": path.name, "ok": result["ok"], "start": body.get("seq_start"),
                             "end": body.get("seq_end"), "observed": body.get("events_observed"),
                             "missing": len(body.get("attested_missing") or []),
                             "complete": body.get("complete")})
    return {"ok": report.ok and not problems and state["ok"],
            "pinned": bool(identity), "signer": (identity or {}).get("ed25519_public_key"),
            "errors": report.errors[:30], "partitions": report.partitions,
            "inserted": len(report.inserted), "missing_leaves": report.missing_leaf_count,
            "ledger_ok": state["ok"], "ledger_blocks": state["blocks"],
            "ledger_errors": state["errors"][:10], "cross_check": problems[:10],
            "certificates": certificates}


def live_seal() -> dict[str, Any]:
    store = get_store()
    records = store.load_partitions()
    run = _latest_run(records)
    runs = Counter(record.get("run_id") for record in records)
    if not run:
        return {"run": None, "runs": 0, "partitions": []}
    mine = [record for record in records if record.get("run_id") == run]
    graph = _load_graph()
    key = (run, _mtime(config.GRAPH_PICKLE), _mtime(config.LEDGER_PATH),
           _mtime(config.KEYSTORE), len(mine))
    check = _cached("verify", key, lambda: _verification(mine, graph))
    status = {item["partition_index"]: item for item in check["partitions"]}
    return {
        "run": run, "runs": len(runs), "created_at": mine[0].get("created_at"),
        "format": mine[0].get("seal_format") or 1,
        "algorithm": mine[0].get("mldsa_algorithm"),
        "verification": {k: v for k, v in check.items() if k != "partitions"},
        "partitions": [{
            "index": r["partition_index"], "start": r["seq_start"], "end": r["seq_end"],
            "leaves": r["leaf_count"], "root": r["merkle_root"], "hash": r["record_hash"],
            "previous": r["prev_record_hash"], "tier": r.get("risk_tier_hint"),
            "signature_size": len(r.get("mldsa_signature") or "") // 2,
            **{flag: status.get(r["partition_index"], {}).get(flag)
               for flag in ("signature_ok", "record_hash_ok", "chain_ok", "merkle_ok")},
        } for r in sorted(mine, key=lambda item: item["partition_index"])],
    }


def live_anchoring() -> dict[str, Any]:
    report = _read_json(config.ANCHOR_REPORT)
    ledger = get_ledger("local")
    blocks = [{"number": r["block_number"], "tx": r["transaction_id"], "hash": r["block_hash"],
               "time": r["timestamp"], "kind": r["anchored"].get("kind"),
               "run": r["anchored"].get("run_id"),
               "members": r["anchored"].get("member_count", 1),
               "root": r["anchored"].get("merkle_root")} for r in ledger.receipts()]
    return {"report": report, "blocks": blocks,
            "weights": {name: getattr(RiskWeights(), name)
                        for name in RiskWeights.__dataclass_fields__},
            "tier1": TIER1_THRESHOLD, "tier2": TIER2_THRESHOLD}


def live_capture(limit: int = 120) -> dict[str, Any]:
    store = get_store()
    events = store.load_events()
    missing = sorted(store.load_missing_sequences())
    boundaries = sorted(store.load_session_boundaries())
    wall = [e["timestamp"] for e in events if int(e["timestamp"]) > 10 ** 18]
    timeline: Counter = Counter()
    for stamp in wall:
        timeline[int(stamp) // (60 * 10 ** 9) * 60] += 1
    return {
        "backend": store.kind, "running": _capture_running(), "total": len(events),
        "by_uid": Counter(str(e["uid"]) for e in events).most_common(),
        "by_caller": Counter(e["comm"] for e in events).most_common(10),
        "root_events": sum(1 for e in events if e["uid"] == 0),
        "missing": missing[:200], "missing_count": len(missing), "restarts": boundaries,
        "sessions": [{"run": str(s.get("run_id"))[:8], "started": str(s.get("started_at")),
                      "ended": None if s.get("ended_at") is None else str(s.get("ended_at")),
                      "last": s.get("last_sequence")} for s in store.load_sessions()],
        "timeline": sorted(timeline.items()),
        "events": [{"seq": e["sequence"], "ts": e["timestamp"], "pid": e["pid"], "uid": e["uid"],
                    "comm": e["comm"], "file": e["filename"]} for e in events[-limit:]][::-1],
    }


def live_survivability() -> dict[str, Any]:
    return {"saved": _read_json(config.EVALUATION_REPORT), "modes": list(AttackSimulator.MODES),
            "has_graph": Path(config.GRAPH_PICKLE).exists(), "weights": config.FSI_WEIGHTS}


def live_overview() -> dict[str, Any]:
    store = get_store()
    graph = _load_graph()
    events = store.load_events()
    detection = live_detection()
    seal = live_seal()
    anchor = _read_json(config.ANCHOR_REPORT)
    survival = _read_json(config.EVALUATION_REPORT)
    meta = _read_json(config.MODEL_PATH.replace(".npz", ".meta.json"))
    running = _capture_running()
    root_events = sum(1 for e in events if e["uid"] == 0)
    verification = seal.get("verification")

    def phase(key, title, state, value, note):
        return {"key": key, "title": title, "state": state, "value": value, "note": note}

    built = graph.graph if graph is not None else {}
    missing = len(store.load_missing_sequences())
    phases = [
        phase("capture", "Capture", "active" if running else ("ok" if events else "idle"),
              f"{len(events)} events", "recording now" if running else f"{missing} attested lost"),
        phase("capture", "Normalise", "ok" if built else "idle",
              f"{built.get('event_count', 0)} kept",
              f"{len([x for x in str(built.get('deduplicated_sequences') or '').split(',') if x])} duplicates merged"),
        phase("graph", "Graph", "ok" if graph is not None else "idle",
              f"{graph.number_of_nodes()} nodes" if graph is not None else "not built",
              f"{graph.number_of_edges()} relations" if graph is not None else "run: main.py graph"),
        phase("detection", "Detect",
              ("idle" if not detection else
               {"CLEAN": "ok", "SUSPICIOUS": "warn", "TAMPERED": "fail"}[detection["verdict"]]),
              detection["verdict"] if detection else "no graph",
              f"{detection['rule_violations']} rule hits, {detection['gnn_flagged']} GNN flags" if detection else ""),
        phase("seal", "Seal",
              "idle" if not verification else ("ok" if verification["ok"] else "fail"),
              f"{len(seal['partitions'])} partitions" if seal["partitions"] else "not sealed",
              ("verified" if verification and verification["ok"] else
               "verification failed" if verification else "run: main.py seal")),
        phase("anchoring", "Anchor", "ok" if anchor else "idle",
              f"{anchor['ledger_transactions']} ledger tx" if anchor else "not anchored",
              f"{anchor['summary']['by_tier'].get('tier3_local', 0)} local only" if anchor else "run: main.py anchor"),
        phase("survivability", "Survive", "ok" if survival and "FSI" in survival else "idle",
              f"FSI {survival['FSI']:.1f}%" if survival and "FSI" in survival else "not measured",
              f"{survival['conditions']['poison_mode']} damage, {survival['conditions']['poison_ratio']:.0%}"
              if survival and "FSI" in survival else "run: main.py evaluate"),
    ]

    advisories = []

    def advise(level, title, text):
        advisories.append({"level": level, "title": title, "text": text})

    if meta and _mtime(config.MODEL_PATH) < _mtime(config.GRAPH_PICKLE):
        advise("warn", "Model is older than the graph",
               "It was trained before this graph was built, so its GNN scores are unreliable. "
               "Run: python main.py train")
    if detection and detection["verdict"] == "SUSPICIOUS":
        advise("warn", "GNN-only alert",
               "No rule was broken and this is not proof. The GNN has raised false alarms on "
               "real captures. Check the seal status.")
    if detection and detection["larger_than_training"]:
        advise("warn", "Capture is larger than the training data",
               f"{detection['events']} events; the model trained on up to "
               f"{synthetic.TRAIN_MAX_EVENTS}. False alarms are likely.")
    if events and root_events == 0:
        advise("info", "No root activity recorded",
               "Run sudo ls during a capture. If it still does not appear, terminal commands "
               "may not be reaching the probe.")
    if verification and not verification["ok"]:
        advise("critical", "Evidence verification failed",
               "; ".join(verification["errors"][:2]) or "See the Seal view.")
    if verification and not verification.get("pinned"):
        advise("warn", "Signer is not pinned", "No key store was found, so re-signed evidence would verify.")

    return {
        "phases": phases, "advisories": advisories, "backend": store.kind, "running": running,
        "detection": detection,
        "verified": verification["ok"] if verification else None,
        "stats": {"events": len(events), "root_events": root_events, "lost": missing,
                  "nodes": graph.number_of_nodes() if graph is not None else 0,
                  "edges": graph.number_of_edges() if graph is not None else 0,
                  "partitions": len(seal["partitions"]),
                  "ledger_blocks": verification["ledger_blocks"] if verification else 0,
                  "fsi": survival.get("FSI") if survival else None},
        "model": ({"threshold": meta["threshold"], "trained_at": meta.get("trained_at"),
                   "real_windows": meta.get("real_windows"), "test": meta.get("test")}
                  if meta else None),
        "tamper": _tamper_headline(_read_json(f"{config.EVALUATION_DIR}/tamper_report.json")),
    }


def _tamper_headline(report: dict[str, Any] | None) -> dict[str, Any] | None:
    if not report or "synthetic" not in report.get("sources", {}):
        return None
    source = report["sources"]["synthetic"]
    held = [row for row in source["attacks"].values() if row["family"] == "held_out"]
    trained = [row for row in source["attacks"].values() if row["family"] == "trained"]
    mean = lambda rows, key: sum(r[key] or 0 for r in rows) / max(1, len(rows))  # noqa: E731
    return {"seal": mean(held + trained, "seal"), "held_fusion": mean(held, "fusion"),
            "trained_fusion": mean(trained, "fusion"), "clean_false": source["clean"]["fusion"],
            "evidence_total": len(report.get("evidence_attacks", [])),
            "evidence_caught": sum(i["detected"] for i in report.get("evidence_attacks", []))}


# ----------------------------------------------------------------------
# Catalogue
# ----------------------------------------------------------------------


def catalogue() -> dict[str, Any]:
    attacks = []
    for name, function in tamper.ATTACKS.items():
        if name in tamper.TRAINED:
            base, level = name.rsplit("_", 1)
            text = f"{_DESCRIPTIONS[base]}; {_LEVELS[level]}"
            family = "trained"
        else:
            text = " ".join((function.__doc__ or "").split()).split(". ")[0].rstrip(".")
            family = "held_out"
        attacks.append({"name": name, "family": family, "description": text})
    return {"attacks": attacks, "modes": list(AttackSimulator.MODES)}


# ----------------------------------------------------------------------
# Simulations: a temporary directory and throwaway keys
# ----------------------------------------------------------------------


class _Sandbox:
    def __init__(self, partition_size: int = 32):
        self._directory = tempfile.TemporaryDirectory(prefix="quantumguard-sim-")
        root = Path(self._directory.name)
        self.keys = KeyStore(str(root / "keys.json"), "sandbox").create()
        self.store = FileStore(root / "evidence")
        self.service = IntegrityService(self.keys, self.store, partition_size=partition_size)
        identity = KeyStore.public_identity(self.keys.path)
        self.pins = (identity["ed25519_public_key"], identity["mldsa_public_key"])
        self.verifier = EvidenceVerifier(self.store, *self.pins)
        self.anchoring = AnchoringService(
            ledger=LocalLedger(root / "ledger.json", signer=DualSigner(self.keys)))
        self.partition_size = partition_size

    def anchor(self, records, graph, report):
        parts = partition_graph(graph, self.partition_size)
        return self.anchoring.anchor_run(
            records, graph=graph, report=report, partitions=parts, persist=False,
            tamper_alert_indices=self.anchoring.alerted_partitions(records, graph, report, parts))

    def close(self):
        self._directory.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _anchor_view(result) -> dict[str, Any]:
    return {"summary": result["summary"], "transactions": result["ledger_transactions"],
            "scores": [{"index": s["partition_index"], "score": s["risk_score"],
                        "tier": s["risk_tier"], "escalated_by": s["escalated_by"]}
                       for s in result["scores"]]}


def _seal_view(report) -> dict[str, Any]:
    return {"ok": report.ok, "errors": report.errors[:12], "error_count": len(report.errors),
            "inserted": len(report.inserted), "missing_leaves": report.missing_leaf_count,
            "partitions": report.partitions}


def _base_graph(source: str, seed: int, events: int):
    if source == "real":
        graph = _load_graph()
        if graph is None or graph.number_of_edges() == 0:
            raise ValueError("no real graph yet: run python main.py graph, or use synthetic data")
        return graph
    return synthetic.generate(random.Random(10 ** 7 + seed), n_events=events,
                              privileged=seed % 3 == 0)


def simulate_attack(attack: str, intensity: float = 0.1, seed: int = 7, source: str = "synthetic",
                    events: int = 120) -> dict[str, Any]:
    """Seal a copy, attack it, and report what each layer saw."""
    if attack not in tamper.ATTACKS:
        raise ValueError(f"unknown attack: {attack}")
    if source not in ("synthetic", "real"):
        raise ValueError("source must be synthetic or real")
    intensity = _clamp(intensity, 0.02, 0.5, 0.1)
    seed = int(_clamp(seed, 0, 10 ** 6, 7))
    events = int(_clamp(events, 30, 300, 120))
    base = _base_graph(source, seed, events)
    detector = _detector()

    with _Sandbox() as box:
        records = box.service.seal(base, run_id="sim", persist=False)
        clean_report = detector.detect(base)
        clean_seal = box.verifier.verify(base, records=records)
        outcome = tamper.apply_attack(base, attack, intensity, seed)
        if outcome is None:
            raise ValueError("this graph is too small for that attack")
        report = detector.detect(outcome.graph)
        seal = box.verifier.verify(outcome.graph, records=records)
        anchor = box.anchor(records, outcome.graph, report)
        survival = evaluate(base, intensity, seed, "mixed", records=records)

    view = _detection_view(report)
    blocking = sum(view["by_severity"].get(level, 0) for level in ("high", "critical"))
    return {
        "attack": attack, "source": source, "intensity": intensity, "seed": seed,
        "family": "trained" if attack in tamper.TRAINED else "held_out",
        "applied": outcome.applied, "nodes_changed": len(outcome.positives()),
        "clean": {"verdict": clean_report["verdict"], "seal_ok": clean_seal.ok,
                  "gnn_flagged": clean_report["gnn_flagged_nodes"]},
        "layers": {
            "rules": {"caught": blocking > 0, "hits": blocking, "by_rule": view["by_rule"]},
            "gnn": {"caught": view["gnn_flagged"] >= config.GRAPH_ALERT_MIN_NODES,
                    "flagged": view["gnn_flagged"], "model": view["model_loaded"],
                    "threshold": view["threshold"]},
            "seal": {"caught": not seal.ok},
        },
        "detection": view,
        "seal": _seal_view(seal),
        "anchor": _anchor_view(anchor),
        "survival": {key: survival[key] for key in ("PIS", "EPR", "GRR", "RA", "FSI")},
        "graph": diff_payload(base, outcome.graph, _flagged_from(report)),
    }


def simulate_evidence() -> dict[str, Any]:
    results = tamper.evidence_attacks()
    return {"attacks": results, "caught": sum(item["detected"] for item in results),
            "total": len(results)}


def simulate_survivability(mode: str = "mixed", ratio: float = 0.25, seed: int = 42,
                           source: str = "real") -> dict[str, Any]:
    if mode not in AttackSimulator.MODES:
        raise ValueError(f"unknown damage mode: {mode}")
    ratio = _clamp(ratio, 0.0, 0.9, 0.25)
    seed = int(_clamp(seed, 0, 10 ** 6, 42))
    base = _base_graph(source, seed, 160)
    metrics = evaluate(base, ratio, seed, mode)
    levels = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
    curve = [evaluate(base, level, seed, mode) for level in levels]
    benefit = sealing_benefit(base, ratio, seed, mode)
    keys = ("PIS", "EPR", "GRR", "RA", "FSI")
    return {
        "source": source, "metrics": {k: metrics[k] for k in keys},
        "grr_bridged": metrics["GRR_bridged"], "conditions": metrics["conditions"],
        "evidence": metrics["evidence"],
        "curve": [{"damage": level, **{k: item[k] for k in keys}}
                  for level, item in zip(levels, curve)],
        "benefit": benefit,
    }


def simulate_pipeline(events: int = 120, loss: int = 3, attack: str = "forgery_expert",
                      intensity: float = 0.1, seed: int = 7) -> dict[str, Any]:
    """All seven phases in order, on simulated capture data, in a sandbox.

    Simulated exec events go through the real CCA, graph builder, detector,
    sealing, anchoring and survivability code. Only the kernel is simulated.
    """
    if attack not in tamper.ATTACKS:
        raise ValueError(f"unknown attack: {attack}")
    events = int(_clamp(events, 30, 300, 120))
    loss = int(_clamp(loss, 0, 25, 3))
    intensity = _clamp(intensity, 0.02, 0.5, 0.1)
    seed = int(_clamp(seed, 0, 10 ** 6, 7))
    rng = random.Random(seed + 991)
    steps: list[dict[str, Any]] = []

    def step(key, title, state, lines, **extra):
        steps.append({"key": key, "title": title, "state": state, "lines": lines,
                      "ms": round((time.perf_counter() - timer[0]) * 1000), **extra})
        timer[0] = time.perf_counter()

    timer = [time.perf_counter()]

    with _Sandbox() as box:
        # Phase 1: exec events through CCA, some lost as if the ring buffer filled
        source = synthetic.generate(random.Random(10 ** 7 + seed), n_events=events,
                                    privileged=seed % 3 == 0)
        rows = sorted((a for _, a in source.nodes(data=True)
                       if a.get("type") == "process" and not a.get("synthetic_root")),
                      key=lambda a: a["sequence"])
        interior = [a["sequence"] for a in rows[1:-1]]
        lost = set(rng.sample(interior, min(loss, len(interior))))
        cca = CCA(run_id="sim")
        for attrs in rows:
            if attrs["sequence"] in lost:
                continue
            box.store.save_event({"sequence": attrs["sequence"], "timestamp": attrs["timestamp"],
                                  "pid": attrs["pid"], "uid": attrs["uid"], "comm": attrs["comm"],
                                  "filename": attrs["filename"], "event_type": 1})
            box.store.save_attestation(cca.verify(attrs["sequence"]))
        certificate = cca.certificate(DualSigner(box.keys))
        attested = certificate["body"]["attested_missing"]
        check = verify_certificate(certificate, DualVerifier(*box.pins))
        step("capture", "Capture and attest", "ok",
             [f"{len(rows) - len(lost)} of {len(rows)} simulated exec events received",
              f"{len(attested)} lost in the ring buffer and attested: {attested[:8]}",
              f"completeness certificate signed: {'valid' if check['ok'] else 'INVALID'}"],
             metrics={"events": len(rows) - len(lost), "lost": len(attested)})

        # Phases 2 and 3: the real builder, without its save step
        builder = ProvenanceGraphService(store=box.store)
        cleaned = builder.validate(builder.deduplicate(builder.load_events()))
        step("normalise", "Normalise", "ok",
             [f"{len(builder.deduplicated)} duplicates merged, {len(builder.dropped)} dropped",
              f"{len(builder.anomalies)} timing anomalies kept for the detector"],
             metrics={"kept": len(cleaned)})
        graph = builder.build(builder.enrich(cleaned))
        step("graph", "Build provenance graph", "ok",
             [f"{graph.number_of_nodes()} nodes, {graph.number_of_edges()} relations"],
             metrics={"nodes": graph.number_of_nodes(), "relations": graph.number_of_edges()},
             graph=graph_payload(graph))

        # Phase 4 on the clean graph
        detector = PoisoningDetector(known_missing_sequences=set(attested))
        clean_report = detector.detect(graph)
        step("detect", "Detect (before the attack)",
             {"CLEAN": "ok", "SUSPICIOUS": "warn", "TAMPERED": "fail"}[clean_report["verdict"]],
             [f"verdict {clean_report['verdict']}: {clean_report['rule_violation_count']} rule hits, "
              f"{clean_report['gnn_flagged_nodes']} GNN flags"],
             detection=_detection_view(clean_report))

        # Phase 5
        records = box.service.seal(graph, run_id="sim", persist=False)
        clean_seal = box.verifier.verify(graph, records=records)
        step("seal", "Seal", "ok" if clean_seal.ok else "fail",
             [f"{len(records)} partitions: Merkle root, hash chain, Ed25519 + {records[0]['mldsa_algorithm']}",
              f"verification: {'PASS' if clean_seal.ok else 'FAIL'}"],
             seal=_seal_view(clean_seal),
             roots=[r["merkle_root"] for r in records])

        # Phase 6
        clean_anchor = box.anchor(records, graph, clean_report)
        step("anchor", "Anchor by risk", "ok",
             [f"{clean_anchor['summary']['by_tier'].get('tier3_local', 0)} partitions local only, "
              f"{clean_anchor['ledger_transactions']} ledger transactions"],
             anchor=_anchor_view(clean_anchor))

        # The attack, then the same checks again
        outcome = tamper.apply_attack(graph, attack, intensity, seed)
        if outcome is None:
            raise ValueError("this graph is too small for that attack")
        step("attack", f"Attack: {attack}", "fail",
             [f"{len(outcome.positives())} nodes changed",
              f"{graph.number_of_edges()} relations became {outcome.graph.number_of_edges()}"],
             graph=diff_payload(graph, outcome.graph))

        report = detector.detect(outcome.graph)
        step("redetect", "Detect (after the attack)",
             "fail" if report["verdict"] == "TAMPERED" else
             "warn" if report["verdict"] == "SUSPICIOUS" else "miss",
             [f"verdict {report['verdict']}: {report['rule_violation_count']} rule hits, "
              f"{report['gnn_flagged_nodes']} GNN flags"],
             detection=_detection_view(report))

        seal = box.verifier.verify(outcome.graph, records=records)
        step("reverify", "Verify against the seal", "fail" if not seal.ok else "miss",
             [f"verification: {'FAIL, tampering proven' if not seal.ok else 'PASS'}",
              f"{seal.missing_leaf_count} sealed relations missing or edited, "
              f"{len(seal.inserted)} unsealed relations present"],
             seal=_seal_view(seal))

        attacked_anchor = box.anchor(records, outcome.graph, report)
        step("reanchor", "Anchor after the attack", "ok",
             [f"{attacked_anchor['summary']['by_tier'].get('tier1_immediate', 0)} partitions escalated to tier 1, "
              f"{attacked_anchor['ledger_transactions']} ledger transactions"],
             anchor=_anchor_view(attacked_anchor))
        ledger = box.anchoring.ledger.verify(DualVerifier(*box.pins))

        # Phase 7
        survival = evaluate(graph, intensity, seed, "mixed", records=records)
        step("survive", "Measure survivability", "ok",
             [f"FSI {survival['FSI']:.2f}%: {survival['evidence']['verified_intact']} relations verified, "
              f"{survival['evidence']['provably_deleted']} provably deleted"],
             survival={key: survival[key] for key in ("PIS", "EPR", "GRR", "RA", "FSI")})

    return {"steps": steps, "attack": attack, "seed": seed,
            "family": "trained" if attack in tamper.TRAINED else "held_out",
            "verdict": report["verdict"], "seal_caught": not seal.ok,
            "ledger_ok": ledger["ok"], "ledger_blocks": ledger["blocks"]}


# ----------------------------------------------------------------------
# Background job: the full tamper scorecard
# ----------------------------------------------------------------------


class Jobs:
    """One scorecard at a time. Results stay in memory, nothing is saved."""

    def __init__(self):
        self.lock = threading.Lock()
        self.current: dict[str, Any] | None = None

    def start(self, trials: int = 20, intensity: float = 0.1, seed: int = 7) -> dict[str, Any]:
        trials = int(_clamp(trials, 1, 60, 20))
        intensity = _clamp(intensity, 0.02, 0.5, 0.1)
        seed = int(_clamp(seed, 0, 10 ** 6, 7))
        with self.lock:
            if self.current and self.current["state"] == "running":
                return self.public()
            self.current = {"id": uuid.uuid4().hex, "state": "running", "done": 0, "total": 1,
                            "label": "starting", "result": None, "error": None,
                            "trials": trials, "intensity": intensity}
        threading.Thread(target=self._run, args=(trials, intensity, seed), daemon=True).start()
        return self.public()

    def _run(self, trials, intensity, seed):
        job = self.current

        def progress(done, total, label):
            job.update(done=done, total=total, label=label)

        try:
            job["result"] = tamper.run_all(_load_graph(), trials=trials, intensity=intensity,
                                           seed=seed, progress=progress)
            job["state"] = "done"
        except Exception as exc:
            traceback.print_exc()
            job.update(state="failed", error=str(exc))

    def public(self) -> dict[str, Any]:
        with self.lock:
            return dict(self.current) if self.current else {"state": "idle"}


def saved_scorecard() -> dict[str, Any] | None:
    return _read_json(f"{config.EVALUATION_DIR}/tamper_report.json")
