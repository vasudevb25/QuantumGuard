"""
Regression tests for the bugs found in the full project review, and for the
tamper harness. Each test states the failure it pins.

    python -m tests.test_tamper
"""
from __future__ import annotations

from tests import _sandbox  # noqa: F401  (must come before project imports)

import copy
import json
import pickle
import random
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from anchoring.ledger import LocalLedger
from anchoring.service import AnchoringService
from capture.cca import CCA
from capture.collector import AUID_UNSET, EBPFCollector, SequenceManager, is_captured
from core.store import FileStore
from crypto.integrity import (DualSigner, EvidenceVerifier, IntegrityService,
                              KeyStore, KeyStoreLocked, SealedRunExists,
                              partition_graph, record_hash)
from detection import synthetic
from detection.detector import PoisoningDetector, RuleEngine
from evaluation import tamper
from evaluation.main import evaluate, sealing_benefit
from graph.service import ProvenanceGraphService


def _graph(seed=3, events=120):
    return synthetic.generate(random.Random(seed), n_events=events)


class _Workspace(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.keys = KeyStore(str(self.dir / "k.json"), "t").create()
        self.store = FileStore(self.dir / "e")
        self.service = IntegrityService(self.keys, self.store, partition_size=16)
        identity = KeyStore.public_identity(self.keys.path)
        self.pins = (identity["ed25519_public_key"], identity["mldsa_public_key"])
        self.verifier = EvidenceVerifier(self.store, *self.pins)


# ---------------------------------------------------------------------
# Graph builder, against real-capture shapes
# ---------------------------------------------------------------------


class RebootTest(unittest.TestCase):
    """A reboot restarts the capture clock. The builder used to treat every
    later event as out of order and dropped them: 166 of 247 real events."""

    def _service(self, boundary=True):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = FileStore(tmp.name)
        rows = [(1, 9_000_000), (2, 9_500_000), (3, 1_000), (4, 2_000_000)]
        for sequence, timestamp in rows:
            store.save_event({"sequence": sequence, "timestamp": timestamp,
                              "pid": 100 + sequence, "uid": 1000, "comm": "bash",
                              "filename": "/usr/bin/ls", "event_type": 1})
        if boundary:
            store.save_attestation({"complete": False, "expected": 3, "received": 3,
                                    "missing": [], "reason": "session_gap"})
        service = ProvenanceGraphService(store=store)
        return service, service.validate(service.deduplicate(service.load_events()))

    def test_events_after_an_attested_restart_are_kept_in_order(self):
        service, events = self._service()
        self.assertEqual([e.sequence for e in events], [1, 2, 3, 4])
        times = [e.timestamp for e in events]
        self.assertEqual(times, sorted(times))
        self.assertEqual(service.rebased_at, [3])
        built = service.build(service.enrich(events))
        report = RuleEngine().check(built)
        self.assertFalse([v for v in report if v["severity"] in ("high", "critical")])

    def test_an_unattested_clock_jump_is_kept_and_reported(self):
        """Dropping it would erase the proof before the detector saw it."""
        service, events = self._service(boundary=False)
        self.assertEqual(len(events), 4)
        self.assertEqual(len(service.anomalies), 1)
        built = service.build(service.enrich(events))
        self.assertIn("temporal_inversion", {v["rule"] for v in RuleEngine().check(built)})

    def test_dedup_does_not_treat_a_clock_restart_as_a_duplicate(self):
        service = ProvenanceGraphService(store=FileStore(tempfile.mkdtemp()))
        from graph.models import ProvenanceEvent
        make = lambda seq, ts: ProvenanceEvent(seq, ts, 7, 1000, "sh", "/bin/ls", 1)  # noqa: E731
        kept = service.deduplicate([make(1, 9_000_000), make(2, 10)])
        self.assertEqual(len(kept), 2)


class DeduplicationGapTest(unittest.TestCase):
    """Deduplication left holes that rule R7 reported as deletion: 5 false
    hits on the project's clean capture."""

    def test_deduplicated_sequence_is_not_a_gap_but_a_deleted_one_is(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = FileStore(tmp.name)
        for sequence, ts, pid in ((1, 0, 1), (2, 10_000_000, 2), (3, 10_000_500, 2),
                                  (4, 90_000_000, 4), (6, 99_000_000, 6)):
            store.save_event({"sequence": sequence, "timestamp": ts + 1, "pid": pid,
                              "uid": 1000, "comm": "bash", "filename": "/bin/ls",
                              "event_type": 1})
        built = ProvenanceGraphService(store=store).run()
        gaps = [v for v in RuleEngine().check(built) if v["rule"] == "sequence_gap"]
        self.assertEqual(len(gaps), 1)
        self.assertIn("[5]", gaps[0]["detail"])


# ---------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------


class RuleVerdictTest(unittest.TestCase):
    def test_deleting_one_event_is_a_tampered_verdict_without_a_model(self):
        """An unexplained gap was 'medium', so this came back CLEAN."""
        graph = _graph()
        graph.remove_node(tamper._events(graph)[5])
        report = PoisoningDetector(model_path="absent.npz").detect(graph)
        self.assertTrue(report["tampered"])

    def test_flagging_a_real_process_as_session_root_is_caught(self):
        graph = _graph()
        graph.nodes[tamper._events(graph)[5]]["synthetic_root"] = True
        self.assertIn("attribute_conflict", {v["rule"] for v in RuleEngine().check(graph)})

    def test_blanking_a_process_hash_is_caught(self):
        graph = _graph()
        graph.nodes[tamper._events(graph)[5]]["process_hash"] = ""
        self.assertIn("process_hash_mismatch", {v["rule"] for v in RuleEngine().check(graph)})


# ---------------------------------------------------------------------
# Sealing
# ---------------------------------------------------------------------


class SealingAttackTest(_Workspace):
    def test_truncating_the_newest_partitions_is_detected(self):
        """The chain has no head, so this used to verify as PASS."""
        graph = _graph()
        records = self.service.seal(graph, run_id="r", persist=False)
        shorter = graph.copy()
        for part in partition_graph(graph, 16)[-2:]:
            shorter.remove_edges_from(part["edges"])
        report = self.verifier.verify(shorter, records=records[:-2])
        self.assertFalse(report.ok)
        self.assertTrue(any("truncated" in error for error in report.errors))

    def test_resigning_with_another_key_fails_when_pinned(self):
        graph = _graph()
        other = KeyStore(str(self.dir / "o.json"), "x").create()
        forged = IntegrityService(other, FileStore(self.dir / "o"), partition_size=16) \
            .seal(graph, run_id="r", persist=False)
        self.assertFalse(self.verifier.verify(graph, records=forged).ok)
        self.assertTrue(EvidenceVerifier(self.store).verify(graph, records=forged).ok,
                        "unpinned verification is expected to pass: this is why pinning matters")

    def test_replacing_only_the_mldsa_key_fails_when_pinned(self):
        graph = _graph()
        records = self.service.seal(graph, run_id="r", persist=False)
        other = KeyStore(str(self.dir / "o.json"), "x").create()
        for record in records:
            record["mldsa_public_key"] = other.mldsa_public.hex()
        self.assertFalse(self.verifier.verify(graph, records=records).ok)

    def test_flipping_the_session_root_flag_breaks_the_seal(self):
        graph = _graph()
        records = self.service.seal(graph, run_id="r", persist=False)
        graph.nodes[tamper._events(graph)[5]]["synthetic_root"] = True
        self.assertFalse(self.verifier.verify(graph, records=records).ok)

    def test_duplicate_final_leaf_is_rejected(self):
        """[a,b,c] and [a,b,c,c] share a Merkle root."""
        graph = _graph(events=7)
        service = IntegrityService(self.keys, self.store, partition_size=64)
        records = service.seal(graph, run_id="r", persist=False)
        self.assertEqual(len(records[0]["leaf_hashes"]) % 2, 0)
        odd = _graph(events=7)
        odd.remove_edge(*list(odd.edges())[-1])
        records = service.seal(odd, run_id="s", persist=False)
        self.assertEqual(len(records[0]["leaf_hashes"]) % 2, 1)
        records[0]["leaf_hashes"].append(records[0]["leaf_hashes"][-1])
        self.assertFalse(self.verifier.verify(odd, records=records).ok)

    def test_a_sealed_run_cannot_be_overwritten(self):
        graph = _graph()
        self.service.seal(graph, run_id="r")
        with self.assertRaises(SealedRunExists):
            self.service.seal(graph, run_id="r")

    def test_format_one_records_still_verify(self):
        """Evidence sealed before format 2 must not start looking tampered."""
        from crypto.integrity import (GENESIS, MerkleTree, _merkle_leaf, leaf_hash,
                                      ordered_edges)
        graph = _graph(events=10)
        leaves = [_merkle_leaf(leaf_hash(graph, u, v, 1)) for u, v in ordered_edges(graph)]
        record = {"run_id": "old", "partition_index": 0, "seq_start": 1, "seq_end": 10,
                  "leaf_count": len(leaves), "merkle_root": MerkleTree(leaves).root_hex,
                  "prev_record_hash": GENESIS, "risk_tier_hint": "tier3_local"}
        record["record_hash"] = record_hash(record)
        record.update(DualSigner(self.keys).sign(record["record_hash"]))
        record["leaf_hashes"] = [leaf.hex() for leaf in leaves]
        # as read back from a database with the new, empty columns
        record.update(seal_format=None, total_partitions=None)
        self.assertTrue(self.verifier.verify(graph, records=[record]).ok)

    def test_wrong_passphrase_says_what_to_do(self):
        with self.assertRaises(KeyStoreLocked) as caught:
            KeyStore(self.keys.path, "wrong").load()
        self.assertIn("QG_KEYSTORE_PASSPHRASE", str(caught.exception))


# ---------------------------------------------------------------------
# Anchoring
# ---------------------------------------------------------------------


class AnchoringAttackTest(_Workspace):
    def setUp(self):
        super().setUp()
        self.graph = _graph()
        self.records = self.service.seal(self.graph, run_id="r", persist=False)
        self.anchoring = AnchoringService(
            ledger=LocalLedger(self.dir / "l.json", signer=DualSigner(self.keys)),
            batch_size=4)
        self.members = [{"partition_index": r["partition_index"],
                         "merkle_root": r["merkle_root"], "risk_score": 0.3,
                         "record_hash": r["record_hash"]} for r in self.records[:4]]

    def test_inclusion_must_reach_a_root_the_ledger_holds(self):
        """The proof was only checked against the root it brought with it."""
        from anchoring.service import batch_root
        anchors = self.anchoring._flush(self.members, "r", "tier2_batched")
        self.assertTrue(self.anchoring.verify_anchor(anchors[0])["ok"])
        root, tree = batch_root([self.records[0]["merkle_root"], "ab" * 32])
        forged = {**anchors[0], "inclusion": {"batch_root": root, "leaf_index": 0,
                                              "path": tree.proof(0)}}
        self.assertFalse(self.anchoring.verify_anchor(forged)["ok"])

    def test_rewritten_evidence_disagrees_with_the_ledger(self):
        self.anchoring._flush(self.members, "r", "tier2_batched")
        self.assertEqual(self.anchoring.cross_check(self.records), [])
        changed = copy.deepcopy(self.records)
        changed[0]["merkle_root"] = "00" * 32
        self.assertTrue(self.anchoring.cross_check(changed))

    def test_tampered_verdict_escalates_where_the_evidence_is(self):
        report = {"tampered": True, "detail": {
            "violations": [{"rule": "temporal_inversion", "severity": "high",
                            "target": str(partition_graph(self.graph, 16)[2]["edges"][0][0])}],
            "top_suspicious_nodes": []}}
        parts = partition_graph(self.graph, 16)
        hits = self.anchoring.alerted_partitions(self.records, self.graph, report, parts)
        self.assertIn(2, hits)
        self.assertLess(len(hits), len(self.records))
        self.assertEqual(self.anchoring.alerted_partitions(
            self.records, self.graph, {"tampered": False}, parts), set())


# ---------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------


class _Collector(EBPFCollector):
    """The ingest path, with the store and session stubbed out."""

    def __init__(self, store):
        self.store = store
        self.sequence = SequenceManager()
        self.cca = CCA(run_id="t")
        self.clock_offset = 1_000
        self.kernel_dropped = 0
        self.malformed = 0
        self.running = True
        self.loader = None


def _line(ts=1, dropped=0, path="/bin/ls"):
    return json.dumps({"ts": ts, "pid": 5, "uid": 1000, "comm": "sh", "file": path,
                       "type": 1, "dropped": dropped})


class CollectorTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = FileStore(tmp.name)
        self.collector = _Collector(self.store)

    def test_kernel_losses_become_attested_gaps(self):
        """Numbering was assigned after the ring buffer, so CCA could never
        see a loss: its gap detection was unreachable in production."""
        self.collector.ingest(_line(dropped=0))
        self.collector.ingest(_line(ts=2, dropped=3))
        self.assertEqual(self.store.load_missing_sequences(), {2, 3, 4})
        self.assertEqual([e["sequence"] for e in self.store.load_events()], [1, 5])
        self.assertFalse(self.collector.cca.certificate(signer=_NoSign())["body"]["complete"])

    def test_losses_after_the_last_event_are_attested(self):
        self.collector.ingest(_line())
        self.collector.ingest('{"final_dropped":2}')
        self.assertEqual(self.store.load_missing_sequences(), {2, 3})

    def test_an_unreadable_event_leaves_a_gap_instead_of_vanishing(self):
        """A quote in a file name made the event invisible to the system."""
        self.collector.ingest(_line())
        self.collector.ingest('{"ts":2,"pid":1,"uid":1000,"comm":"sh","file":"/tmp/a"b","type":1}')
        self.collector.ingest(_line(ts=3))
        self.assertEqual(self.store.load_missing_sequences(), {2})

    def test_timestamps_are_stored_as_wall_clock(self):
        self.collector.ingest(_line(ts=5))
        self.assertEqual(self.store.load_events()[0]["timestamp"], 1_005)


class RootCaptureTest(unittest.TestCase):
    """The stated attacker has root, and uid < 1000 used to hide all of it."""

    def test_filter_keeps_sessions_and_drops_services(self):
        self.assertTrue(is_captured(1000, 1000), "ordinary user")
        self.assertTrue(is_captured(0, 1000), "user running sudo")
        self.assertTrue(is_captured(0, 0), "root who logged in directly")
        self.assertTrue(is_captured(116, 1000), "sudo -u a service account")
        self.assertFalse(is_captured(0, AUID_UNSET), "system service")
        self.assertFalse(is_captured(116, AUID_UNSET), "service account")

    def test_collector_stores_a_sudo_child_and_drops_a_service(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = FileStore(tmp.name)
        collector = _Collector(store)
        event = {"ts": 1, "pid": 5, "uid": 0, "comm": "sudo", "file": "/usr/bin/apt",
                 "type": 1, "dropped": 0}
        collector.ingest(json.dumps({**event, "auid": 1000}))
        collector.ingest(json.dumps({**event, "auid": AUID_UNSET}))
        self.assertEqual([e["uid"] for e in store.load_events()], [0])

    def _graph_from(self, rows):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = FileStore(tmp.name)
        for sequence, (pid, uid, comm, path) in enumerate(rows, start=1):
            store.save_event({"sequence": sequence, "timestamp": sequence * 10_000_000,
                              "pid": pid, "uid": uid, "comm": comm, "filename": path,
                              "event_type": 1})
        service = ProvenanceGraphService(store=store)
        return service.build(service.enrich(
            service.validate(service.deduplicate(service.load_events()))))

    def test_sudo_links_the_root_command_to_the_user_who_ran_it(self):
        graph = self._graph_from([(10, 1000, "bash", "/usr/bin/sudo"),
                                  (11, 0, "sudo", "/usr/bin/apt")])
        self.assertTrue(graph.has_edge("P:10:1", "P:11:2"))
        self.assertEqual(graph.edges["P:10:1", "P:11:2"]["relation"], "SPAWNS")

    def test_unrelated_programs_do_not_link_across_uids(self):
        graph = self._graph_from([(10, 1000, "bash", "/usr/bin/python3"),
                                  (11, 0, "python3", "/usr/bin/ls")])
        self.assertFalse(graph.has_edge("P:10:1", "P:11:2"))

    def test_ordinary_admin_work_is_not_called_tampering(self):
        graph = self._graph_from([
            (10, 1000, "bash", "/usr/bin/sudo"), (11, 0, "sudo", "/usr/bin/apt"),
            (12, 1000, "bash", "/usr/bin/pkexec"), (12, 0, "pkexec", "/usr/bin/ls")])
        blocking = [v for v in RuleEngine().check(graph)
                    if v["severity"] in ("high", "critical")]
        self.assertEqual(blocking, [])

    def test_uid_change_without_a_helper_is_still_caught(self):
        graph = self._graph_from([(12, 1000, "bash", "/usr/bin/ls"),
                                  (12, 0, "ls", "/usr/bin/cat")])
        self.assertIn("attribute_conflict", {v["rule"] for v in RuleEngine().check(graph)})

    def test_synthetic_sudo_graphs_break_no_rule(self):
        for seed in range(20):
            graph = synthetic.generate(random.Random(seed), n_events=200, privileged=True)
            blocking = [v for v in RuleEngine().check(graph)
                        if v["severity"] in ("high", "critical")]
            self.assertEqual(blocking, [], f"seed {seed}")

    def test_privileged_generation_really_contains_root(self):
        graph = synthetic.generate(random.Random(5), n_events=300, privileged=True)
        self.assertIn(0, {a.get("uid") for _, a in graph.nodes(data=True)
                          if a.get("type") == "process"})

    def test_a_capture_that_cannot_start_leaves_no_session(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        Path("ebpf").mkdir(exist_ok=True)
        Path("ebpf/loader").touch()
        Path("keys").mkdir(exist_ok=True)
        KeyStore("keys/quantumguard.keystore.json", "a-different-passphrase").create()
        try:
            with self.assertRaises(KeyStoreLocked):
                EBPFCollector()
            self.assertEqual(FileStore().load_sessions(), [])
        finally:
            Path("keys/quantumguard.keystore.json").unlink()
            Path("ebpf/loader").unlink()


class VisualizeTest(unittest.TestCase):
    """One box per program, so a long capture stays readable."""

    def _service_graph(self, rows):
        return RootCaptureTest._graph_from(self, rows)

    def setUp(self):
        self.graph = self._service_graph([
            (10, 1000, "code", "/usr/bin/git"), (10, 1000, "code", "/usr/sbin/git"),
            (11, 1000, "code", "/bin/sh"), (12, 1000, "sh", "/usr/bin/sudo"),
            (13, 0, "sudo", "/usr/bin/apt")])

    def test_repeated_programs_merge_and_the_real_caller_is_shown(self):
        from graph.visualize import summarise
        summary = summarise(self.graph)
        self.assertEqual(summary["starts"]["git"], 2)
        call = summary["calls"][("code", "git")]
        self.assertEqual((call["events"], len(call["pids"])), (2, 1))
        self.assertIn("code", summary["external"])
        self.assertNotIn("session", summary["programs"])

    def test_root_is_marked_and_linked_to_the_user(self):
        from graph.visualize import summarise
        summary = summarise(self.graph)
        self.assertEqual(summary["root"], {"apt"})
        self.assertTrue(summary["calls"][("sudo", "apt")]["root"])
        self.assertIn(("sh", "sudo"), summary["calls"])

    def test_rare_programs_fold_but_root_programs_never_do(self):
        from graph.visualize import OTHER, summarise
        rows = [(100 + i, 1000, "bash", f"/usr/bin/tool{i}") for i in range(40)]
        rows.append((99, 0, "sudo", "/usr/bin/rootkit"))
        summary = summarise(self._service_graph(rows), max_programs=5)
        self.assertLess(len(summary["programs"]), 12)
        self.assertIn(OTHER, summary["programs"])
        self.assertIn("rootkit", summary["programs"])
        self.assertEqual(summary["events"], 41)

    def test_arrows_are_capped_and_root_calls_are_kept(self):
        from graph.visualize import summarise
        rows = [(100 + i, 1000, f"caller{i % 9}", f"/usr/bin/tool{i % 11}") for i in range(99)]
        rows.append((99, 0, "sudo", "/usr/bin/rootkit"))
        summary = summarise(self._service_graph(rows), max_programs=40, max_arrows=10)
        self.assertEqual(len(summary["calls"]), 10)
        self.assertGreater(summary["hidden_calls"], 0)
        self.assertIn(("sudo", "rootkit"), summary["calls"])
        self.assertEqual(summary["events"], 100)

    def test_draws_png_and_svg_including_cycles(self):
        from graph.visualize import draw
        graph = self._service_graph([
            (1, 1000, "bash", "/bin/sh"), (2, 1000, "sh", "/bin/bash"),
            (3, 1000, "bash", "/bin/bash"), (4, 1000, "sh", "/bin/ls")])
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "g.png"
            draw(graph, target)
            self.assertGreater(target.stat().st_size, 1000)
            self.assertTrue(target.with_suffix(".svg").exists())


class VerdictWordingTest(unittest.TestCase):
    """TAMPERED must mean proof. The model alone can only raise a suspicion."""

    def test_verdicts(self):
        detector = PoisoningDetector(model_path="absent.npz")
        self.assertEqual(detector.detect(_graph())["verdict"], "CLEAN")
        graph = _graph()
        graph.remove_node(tamper._events(graph)[5])
        self.assertEqual(detector.detect(graph)["verdict"], "TAMPERED")

    def test_gnn_alone_is_suspicious_and_large_captures_are_flagged(self):
        graph = _graph(events=400)
        detector = PoisoningDetector(model_path="absent.npz")
        detector.model = object()
        detector.meta = {"threshold": 0.5}
        detector.score_nodes = lambda G: {n: 0.9 for n in list(G.nodes())[:3]}
        report = detector.detect(graph)
        self.assertEqual(report["verdict"], "SUSPICIOUS")
        self.assertTrue(report["detail"]["larger_than_training"])
        from detection.detector import format_report
        self.assertIn("false alarms are", format_report(report))


class CleanVerdictTest(unittest.TestCase):
    def test_a_clean_verdict_reports_no_confidence_in_tampering(self):
        report = PoisoningDetector(model_path="absent.npz").detect(_graph())
        self.assertFalse(report["tampered"])
        self.assertEqual(report["confidence"], 0.0)


class _NoSign:
    def sign(self, payload):
        return {}


# ---------------------------------------------------------------------
# Survivability
# ---------------------------------------------------------------------


class SurvivabilityTest(unittest.TestCase):
    def test_no_key_store_is_needed(self):
        """A locked store silently scored PIS 0 and FSI 70."""
        Path("keys").mkdir(exist_ok=True)
        KeyStore("keys/quantumguard.keystore.json", "another-passphrase").create()
        try:
            self.assertEqual(evaluate(_graph(), 0.0, seed=1)["PIS"], 100.0)
        finally:
            Path("keys/quantumguard.keystore.json").unlink()

    def test_edited_relations_lower_unsealed_accuracy(self):
        """RA compared endpoints only, so an edited relation counted as genuine."""
        benefit = sealing_benefit(_graph(), 0.3, seed=1, mode="edit")
        self.assertLess(benefit["without_sealing"]["RA"], 100.0)
        self.assertEqual(benefit["with_sealing"]["RA"], 100.0)

    def test_fsi_does_not_use_knowledge_of_the_original_graph(self):
        metrics = evaluate(_graph(), 0.3, seed=1, mode="node")
        self.assertGreaterEqual(metrics["GRR_bridged"], metrics["GRR"])
        self.assertGreater(metrics["conditions"]["inferred_bridges"], 0)


# ---------------------------------------------------------------------
# The tamper harness
# ---------------------------------------------------------------------


class TamperHarnessTest(unittest.TestCase):
    def test_every_attack_changes_the_graph_and_labels_something(self):
        graph = _graph()
        before = pickle.dumps(graph)
        for name in tamper.ATTACKS:
            outcome = tamper.apply_attack(graph, name, 0.1, seed=4)
            self.assertIsNotNone(outcome, name)
            self.assertTrue(outcome.positives(), name)
            self.assertEqual(pickle.dumps(graph), before, f"{name} modified its input")

    def test_the_seal_catches_every_attack(self):
        """The seal does not depend on the graph looking wrong."""
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            keys = KeyStore(str(workspace / "k.json"), "t").create()
            store = FileStore(workspace / "e")
            graph = _graph()
            records = IntegrityService(keys, store, partition_size=32).seal(
                graph, run_id="r", persist=False)
            verifier = EvidenceVerifier(store)
            self.assertTrue(verifier.verify(graph, records=records).ok)
            for name in tamper.ATTACKS:
                outcome = tamper.apply_attack(graph, name, 0.1, seed=4)
                self.assertFalse(verifier.verify(outcome.graph, records=records).ok, name)

    def test_adaptive_attacks_leave_no_ordering_evidence(self):
        """These must really be self-consistent, or the held-out scores would
        be testing nothing harder than the training attacks."""
        graph = _graph()
        for name in ("adaptive_deletion", "adaptive_reorder", "adaptive_forgery",
                     "tail_truncate"):
            outcome = tamper.apply_attack(graph, name, 0.1, seed=4)
            rules = {v["rule"] for v in RuleEngine().check(outcome.graph)}
            self.assertFalse(rules & {"sequence_gap", "temporal_inversion",
                                      "causal_inversion", "process_hash_mismatch",
                                      "duplicate_sequence"}, f"{name}: {rules}")

    def test_every_evidence_attack_is_caught(self):
        missed = [item["attack"] for item in tamper.evidence_attacks() if not item["detected"]]
        self.assertEqual(missed, [])

    def test_apply_refuses_to_overwrite_the_real_graph(self):
        args = Namespace(attack="flag_abuse", intensity=0.1, seed=1,
                         output="graphs/provenance_graph.gpickle")
        with self.assertRaises(SystemExit):
            tamper.apply_command(args, _graph())

    def test_a_small_matrix_runs_end_to_end(self):
        results = tamper.run_all(_graph(), trials=1, model_path="absent.npz")
        self.assertIn("real", results["sources"])
        self.assertEqual(results["sources"]["synthetic"]["clean"]["fusion"], 0.0)
        self.assertIn("CLEAN", tamper.format_report(results))


if __name__ == "__main__":
    unittest.main()
