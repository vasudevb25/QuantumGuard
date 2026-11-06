"""
Tests for Phase 6 (risk-adaptive anchoring), Phase 7 (forensic
survivability) and the Phase 1 completeness attestation.

    python -m tests.test_phase67

Nothing here needs PostgreSQL, eBPF or root.

Three regressions are guarded explicitly, because each one produced a
result that looked plausible and was wrong:

  1. Phase 7's EPR read a graph attribute copied unchanged by deepcopy,
     so it reported 100% survival at every damage level including total
     destruction.                              -> MetricsRespondToDamageTest
  2. Phase 7's RA compared surviving edges against the original edge
     set after a recovery step that only removed isolated nodes, so
     every surviving edge was original by construction and the ratio
     was 1.0 by definition.                    -> RecoveryAccuracyTest
  3. Phase 6 attributed un-localisable rule violations to every
     partition, which escalated whole runs to tier 1 and removed any
     adaptation from "risk-adaptive".          -> ViolationLocalisationTest
"""
from __future__ import annotations

from tests import _sandbox  # noqa: F401  (must come before project imports)

import random
import sys
import tempfile
import unittest
from pathlib import Path

from anchoring.ledger import FabricLedger, LocalLedger
from anchoring.risk import (TIER1, TIER2, TIER3, RiskPolicy, RiskScorer,
                            RiskWeights, _saturate)
from anchoring.service import AnchoringService, batch_root
from capture.cca import (CCA, SessionManager, verify_certificate)
from core.store import FileStore
from crypto.integrity import (IntegrityService, KeyStore, _merkle_leaf,
                              partition_graph, verify_proof)
from detection import synthetic
from evaluation.main import (AttackSimulator, RecoveryEngine,
                             SurvivabilityMetrics, evaluate, sealing_benefit)


def _graph(seed: int = 1, events: int = 100):
    return synthetic.generate(random.Random(seed), n_events=events)


def _sealed(graph, workspace: Path, size: int = 16):
    keystore = KeyStore(str(workspace / "keys.json"), "test").create()
    store = FileStore(workspace / "evidence")
    service = IntegrityService(keystore, store, partition_size=size)
    return service.seal(graph, run_id="test", persist=False), service


def _anchoring(workspace: Path, **kwargs):
    keystore = KeyStore(str(workspace / "anchor-keys.json"), "test").create()
    from crypto.integrity import DualSigner
    ledger = LocalLedger(workspace / "ledger.json", signer=DualSigner(keystore))
    return AnchoringService(ledger=ledger, **kwargs)


# =====================================================================
# Phase 6 - risk scoring
# =====================================================================


class RiskWeightsTest(unittest.TestCase):
    def test_default_weights_sum_to_one(self):
        RiskWeights().validate()

    def test_bad_weights_rejected(self):
        with self.assertRaises(ValueError):
            RiskWeights(tamper_alert=0.9).validate()

    def test_thresholds_must_be_ordered(self):
        with self.assertRaises(ValueError):
            RiskPolicy(tier1_threshold=0.2, tier2_threshold=0.5).validate()

    def test_saturation_is_monotonic_and_bounded(self):
        values = [_saturate(n, 2.0) for n in range(0, 20)]
        self.assertEqual(values[0], 0.0)
        self.assertTrue(all(b >= a for a, b in zip(values, values[1:])))
        self.assertLess(values[-1], 1.0)
        self.assertAlmostEqual(_saturate(2, 2.0), 0.5, places=6)


class CleanCaptureScoresLowTest(unittest.TestCase):
    """A clean capture must not consume the anchoring budget.

    If an untampered run anchors anything externally, the risk model has
    failed at its only cost-control job.
    """

    def test_clean_graph_stays_tier3(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            graph = _graph(seed=5, events=160)
            records, _ = _sealed(graph, workspace)
            scores = RiskScorer().score_all(
                records, graph, None, partition_graph(graph, 16))

            self.assertTrue(all(entry["risk_tier"] == TIER3
                                for entry in scores))
            self.assertTrue(all(entry["risk_score"] < 0.2
                                for entry in scores))


class TamperAlertEscalatesTest(unittest.TestCase):
    """A partition carrying a tamper alert is anchored immediately."""

    def test_alert_forces_tier1_regardless_of_score(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            graph = _graph(seed=6, events=120)
            records, _ = _sealed(graph, workspace)

            scores = RiskScorer().score_all(
                records, graph, None, partition_graph(graph, 16),
                tamper_alert_indices={2})
            flagged = next(e for e in scores if e["partition_index"] == 2)

            self.assertEqual(flagged["risk_tier"], TIER1)
            self.assertEqual(flagged["escalated_by"], "tamper_alert")

    def test_escalation_can_be_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            graph = _graph(seed=6, events=120)
            records, _ = _sealed(graph, workspace)

            policy = RiskPolicy(escalate_tamper_alert=False)
            scores = RiskScorer(policy).score_all(
                records, graph, None, partition_graph(graph, 16),
                tamper_alert_indices={2})
            flagged = next(e for e in scores if e["partition_index"] == 2)
            self.assertIsNone(flagged["escalated_by"])


class ViolationLocalisationTest(unittest.TestCase):
    """Regression 3: violations must be attributed to the right partition.

    An earlier version counted any violation whose target was not a
    sequence number against EVERY partition. A single forgery then
    escalated an entire run to tier 1, which means the system anchors
    everything - exactly the cost that risk-adaptive anchoring exists to
    avoid. These tests pin each target shape to its own partition.
    """

    def _report(self, violations):
        return {"detail": {"violations": violations,
                           "top_suspicious_nodes": []}}

    def test_node_target_matches_only_its_partition(self):
        scorer = RiskScorer()
        report = self._report([{"rule": "process_hash_mismatch",
                                "severity": "critical",
                                "target": "P:100:5"}])
        inside = scorer._violations_in_range(report, 1, 10, {"P:100:5", "F:/a"})
        outside = scorer._violations_in_range(report, 1, 10, {"P:999:9"})
        self.assertEqual(inside[0], 1)
        self.assertEqual(outside[0], 0)

    def test_edge_target_matches_on_either_endpoint(self):
        scorer = RiskScorer()
        report = self._report([{"rule": "temporal_inversion",
                                "severity": "high",
                                "target": "P:100:5 -> F:/usr/bin/ls"}])
        self.assertEqual(
            scorer._violations_in_range(report, 1, 10, {"F:/usr/bin/ls"})[0], 1)
        self.assertEqual(
            scorer._violations_in_range(report, 1, 10, {"P:7:7"})[0], 0)

    def test_pid_target_matches_by_pid(self):
        scorer = RiskScorer()
        report = self._report([{"rule": "attribute_conflict",
                                "severity": "high", "target": "pid=100"}])
        self.assertEqual(
            scorer._violations_in_range(report, 1, 10, {"P:100:5"})[0], 1)
        self.assertEqual(
            scorer._violations_in_range(report, 1, 10, {"P:200:5"})[0], 0)

    def test_sequence_gap_counted_separately_from_blocking(self):
        scorer = RiskScorer()
        report = self._report([{"rule": "sequence_gap", "severity": "medium",
                                "target": "seq=4..6"}])
        blocking, advisory, gaps = scorer._violations_in_range(report, 1, 10, set())
        self.assertEqual((blocking, advisory, gaps), (0, 0, 1))

    def test_advisory_violations_feed_the_score(self):
        """A sophisticated deletion leaves only low-severity traces.

        Counting nothing below 'high' scored such an attack at zero and
        anchored it nowhere, so advisory violations contribute to the
        graded score without escalating.
        """
        scorer = RiskScorer()
        report = self._report([{"rule": "orphan_process", "severity": "low",
                                "target": "P:100:5"}])
        blocking, advisory, _ = scorer._violations_in_range(
            report, 1, 10, {"P:100:5"})
        self.assertEqual(blocking, 0)
        self.assertEqual(advisory, 1)


# =====================================================================
# Phase 6 - ledger
# =====================================================================


class LedgerTest(unittest.TestCase):
    def test_append_chain_and_verify(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            keystore = KeyStore(str(workspace / "k.json"), "test").create()
            from crypto.integrity import DualSigner
            ledger = LocalLedger(workspace / "l.json", DualSigner(keystore))

            for index in range(4):
                ledger.anchor({"kind": "partition", "merkle_root": f"{index:064x}"})

            state = ledger.verify()
            self.assertTrue(state["ok"], state["errors"])
            self.assertEqual(state["blocks"], 4)

    def test_reopening_preserves_the_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            keystore = KeyStore(str(workspace / "k.json"), "test").create()
            from crypto.integrity import DualSigner
            signer = DualSigner(keystore)

            LocalLedger(workspace / "l.json", signer).anchor({"merkle_root": "a" * 64})
            reopened = LocalLedger(workspace / "l.json", signer)
            reopened.anchor({"merkle_root": "b" * 64})

            self.assertEqual(len(reopened.receipts()), 2)
            self.assertTrue(reopened.verify()["ok"])

    def test_edited_block_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            keystore = KeyStore(str(workspace / "k.json"), "test").create()
            from crypto.integrity import DualSigner
            ledger = LocalLedger(workspace / "l.json", DualSigner(keystore))
            ledger.anchor({"merkle_root": "a" * 64})
            ledger.anchor({"merkle_root": "b" * 64})

            ledger._blocks[0]["payload"]["merkle_root"] = "c" * 64
            state = ledger.verify()
            self.assertFalse(state["ok"])
            self.assertTrue(any("hash" in error for error in state["errors"]))

    def test_removed_block_breaks_the_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            keystore = KeyStore(str(workspace / "k.json"), "test").create()
            from crypto.integrity import DualSigner
            ledger = LocalLedger(workspace / "l.json", DualSigner(keystore))
            for index in range(3):
                ledger.anchor({"merkle_root": f"{index:064x}"})

            del ledger._blocks[1]
            state = ledger.verify()
            self.assertFalse(state["ok"])
            self.assertTrue(any("chain" in error or "order" in error
                                for error in state["errors"]))

    def test_fabric_adapter_refuses_rather_than_faking(self):
        """A simulated Fabric receipt would be worse than an honest failure."""
        for call in (lambda l: l.anchor({}), lambda l: l.receipts(),
                     lambda l: l.lookup("x"), lambda l: l.verify()):
            with self.assertRaises(NotImplementedError):
                call(FabricLedger())


# =====================================================================
# Phase 6 - batching and anchoring
# =====================================================================


class SecondOrderBatchTest(unittest.TestCase):
    """Batching must not cost a partition its independent provability."""

    def test_every_member_can_prove_its_own_inclusion(self):
        roots = [f"{index:064x}" for index in range(7)]
        root, tree = batch_root(roots)
        for position, member in enumerate(roots):
            self.assertTrue(verify_proof(_merkle_leaf(bytes.fromhex(member)),
                                         tree.proof(position),
                                         bytes.fromhex(root)))

    def test_a_root_outside_the_batch_cannot_prove_inclusion(self):
        roots = [f"{index:064x}" for index in range(4)]
        root, tree = batch_root(roots)
        outsider = _merkle_leaf(bytes.fromhex("f" * 64))
        self.assertFalse(verify_proof(outsider, tree.proof(0),
                                      bytes.fromhex(root)))

    def test_empty_batch_rejected(self):
        with self.assertRaises(ValueError):
            batch_root([])


class AnchoringCostTest(unittest.TestCase):
    """The point of the whole phase: cost must follow risk."""

    def test_clean_run_costs_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            graph = _graph(seed=11, events=160)
            records, _ = _sealed(graph, workspace)
            service = _anchoring(workspace)

            result = service.anchor_run(
                records, graph=graph, partitions=partition_graph(graph, 16),
                persist=False)

            self.assertEqual(result["ledger_transactions"], 0)
            self.assertEqual(result["summary"]["by_tier"][TIER3],
                             result["summary"]["partitions"])

    def test_widespread_tampering_is_anchored_but_batched(self):
        """Many urgent partitions share one transaction, not N of them."""
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            graph = _graph(seed=12, events=160)
            records, _ = _sealed(graph, workspace)
            service = _anchoring(workspace)

            # every partition escalated
            alerts = {record["partition_index"] for record in records}
            result = service.anchor_run(
                records, graph=graph, partitions=partition_graph(graph, 16),
                tamper_alert_indices=alerts, persist=False)

            self.assertEqual(result["summary"]["by_tier"][TIER1], len(records))
            self.assertEqual(result["ledger_transactions"], 1)
            self.assertTrue(service.verify_run(result)["ok"])

    def test_every_anchor_verifies_independently(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            graph = _graph(seed=13, events=200)
            records, _ = _sealed(graph, workspace)
            service = _anchoring(workspace, batch_size=3)

            alerts = {0, 4}
            result = service.anchor_run(
                records, graph=graph, partitions=partition_graph(graph, 16),
                tamper_alert_indices=alerts, persist=False)

            checks = service.verify_run(result)
            self.assertTrue(checks["ok"], checks["failures"])
            self.assertEqual(checks["anchors_checked"],
                             result["summary"]["partitions"])

    def test_forged_inclusion_proof_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            graph = _graph(seed=14, events=120)
            records, _ = _sealed(graph, workspace)
            service = _anchoring(workspace, batch_size=2)

            result = service.anchor_run(
                records, graph=graph, partitions=partition_graph(graph, 16),
                tamper_alert_indices={0, 1, 2}, persist=False)

            batched = next(item for item in result["anchors"]
                           if item.get("inclusion"))
            batched["merkle_root"] = "f" * 64
            self.assertFalse(service.verify_anchor(batched)["ok"])

    def test_tier3_reports_its_own_limitation(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            graph = _graph(seed=15, events=120)
            records, _ = _sealed(graph, workspace)
            service = _anchoring(workspace)

            result = service.anchor_run(
                records, graph=graph, partitions=partition_graph(graph, 16),
                persist=False)
            local = next(item for item in result["anchors"]
                         if item["tier"] == TIER3)
            check = service.verify_anchor(local)
            self.assertTrue(check["ok"])
            self.assertIsNone(check["ledger_ok"])
            self.assertIn("local chain only", check["reason"])


# =====================================================================
# Phase 7 - survivability
# =====================================================================


class MetricsRespondToDamageTest(unittest.TestCase):
    """Regression 1: a measure that cannot fall is not a measure.

    EPR previously read an attribute copied unchanged by deepcopy and
    reported 100% at every damage level, including near-total
    destruction. Every measure is now required to fall monotonically as
    damage rises.
    """

    def test_epr_falls_as_events_are_destroyed(self):
        graph = _graph(seed=21, events=160)
        values = [evaluate(graph, ratio, seed=1, mode="node")["EPR"]
                  for ratio in (0.0, 0.25, 0.5, 0.75)]
        self.assertEqual(values[0], 100.0)
        self.assertTrue(all(b < a for a, b in zip(values, values[1:])),
                        f"EPR did not fall with damage: {values}")

    def test_pis_falls_as_sealed_relations_are_destroyed(self):
        graph = _graph(seed=22, events=160)
        values = [evaluate(graph, ratio, seed=1, mode="edge")["PIS"]
                  for ratio in (0.0, 0.25, 0.5, 0.75)]
        self.assertEqual(values[0], 100.0)
        self.assertTrue(all(b < a for a, b in zip(values, values[1:])),
                        f"PIS did not fall with damage: {values}")

    def test_grr_falls_as_causal_paths_break(self):
        graph = _graph(seed=23, events=160)
        values = [evaluate(graph, ratio, seed=1, mode="edge")["GRR"]
                  for ratio in (0.0, 0.3, 0.6)]
        self.assertEqual(values[0], 100.0)
        self.assertTrue(all(b < a for a, b in zip(values, values[1:])),
                        f"GRR did not fall with damage: {values}")

    def test_fsi_falls_as_damage_rises(self):
        graph = _graph(seed=24, events=160)
        values = [evaluate(graph, ratio, seed=1, mode="edge")["FSI"]
                  for ratio in (0.0, 0.2, 0.4, 0.6, 0.8)]
        self.assertEqual(values[0], 100.0)
        self.assertTrue(all(b < a for a, b in zip(values, values[1:])),
                        f"FSI did not fall with damage: {values}")

    def test_undamaged_graph_scores_a_hundred(self):
        metrics = evaluate(_graph(seed=25, events=120), 0.0, seed=1)
        for key in ("PIS", "EPR", "GRR", "RA", "FSI"):
            self.assertEqual(metrics[key], 100.0, f"{key} != 100 at zero damage")


class RecoveryAccuracyTest(unittest.TestCase):
    """Regression 2: RA was 1.0 by construction and measured nothing.

    Recovery only removed isolated nodes, so every surviving edge was an
    original edge and the ratio could not fall. RA is only meaningful
    against an attacker who INSERTS evidence, so these tests use one.
    """

    def test_ra_falls_without_sealing_when_evidence_is_fabricated(self):
        graph = _graph(seed=26, events=140)
        unsealed = evaluate(graph, 0.3, seed=1, mode="insert",
                            seal_if_missing=False)
        self.assertLess(unsealed["RA"], 95.0,
                        "RA stayed high despite fabricated relations")

    def test_sealing_restores_accuracy(self):
        graph = _graph(seed=26, events=140)
        benefit = sealing_benefit(graph, 0.3, seed=1, mode="mixed")
        self.assertGreater(benefit["with_sealing"]["RA"],
                           benefit["without_sealing"]["RA"])
        self.assertGreater(benefit["ra_gain"], 0.0)
        self.assertGreater(benefit["fabricated_relations"], 0)

    def test_inferred_bridges_never_counted_as_recovered_evidence(self):
        """A bridge restores reachability; it is not recovered evidence."""
        graph = _graph(seed=27, events=140)
        damaged = AttackSimulator.poison(graph, 0.3, 1, "node")
        recovered = RecoveryEngine.recover(damaged, graph, bridge=True)

        bridges = [(u, v) for u, v, attrs in recovered.edges(data=True)
                   if attrs.get("inferred")]
        self.assertTrue(bridges, "no bridges were inferred to test against")
        # none of the bridges exist in the original, so if RA counted
        # them it would be below 100 here
        self.assertEqual(
            SurvivabilityMetrics.recovery_accuracy(graph, recovered), 100.0)


class ClassificationTest(unittest.TestCase):
    """Recovery's real product: which relations are provably gone."""

    def test_deleted_relations_are_provably_identified(self):
        graph = _graph(seed=28, events=140)
        metrics = evaluate(graph, 0.25, seed=1, mode="edge")
        evidence = metrics["evidence"]

        self.assertEqual(
            evidence["verified_intact"] + evidence["provably_deleted"],
            evidence["sealed_relations"])
        self.assertGreater(evidence["provably_deleted"], 0)

    def test_inserted_relations_are_identified_as_unsealed(self):
        graph = _graph(seed=29, events=140)
        metrics = evaluate(graph, 0.25, seed=1, mode="insert")
        self.assertGreater(metrics["evidence"]["unsealed_present"], 0)


class AttackModeTest(unittest.TestCase):
    def test_every_mode_damages_the_graph(self):
        graph = _graph(seed=30, events=160)
        for mode in (m for m in AttackSimulator.MODES if m != "edit"):
            damaged = AttackSimulator.poison(graph, 0.3, 1, mode)
            if mode in ("insert",):
                self.assertGreater(damaged.number_of_edges(),
                                   graph.number_of_edges(), mode)
            else:
                self.assertLess(damaged.number_of_edges(),
                                graph.number_of_edges(), mode)

    def test_unknown_mode_and_ratio_rejected(self):
        graph = _graph(seed=31, events=60)
        with self.assertRaises(ValueError):
            AttackSimulator.poison(graph, 0.3, 1, "nonsense")
        with self.assertRaises(ValueError):
            AttackSimulator.poison(graph, 1.5, 1, "edge")

    def test_poisoning_is_deterministic_under_a_seed(self):
        graph = _graph(seed=32, events=120)
        first = AttackSimulator.poison(graph, 0.3, 7, "edge")
        second = AttackSimulator.poison(graph, 0.3, 7, "edge")
        self.assertEqual(set(first.edges()), set(second.edges()))


# =====================================================================
# Phase 1 - completeness attestation
# =====================================================================


class CompletenessCertificateTest(unittest.TestCase):
    """CCA is only an attestation if a third party can verify it."""

    def _certificate(self, workspace: Path, sequences):
        keystore = KeyStore(str(workspace / "k.json"), "test").create()
        from crypto.integrity import DualSigner
        cca = CCA(run_id="run-1")
        for sequence in sequences:
            cca.verify(sequence)
        return cca.certificate(DualSigner(keystore))

    def test_certificate_records_and_verifies_gaps(self):
        with tempfile.TemporaryDirectory() as directory:
            certificate = self._certificate(Path(directory),
                                            [1, 2, 3, 5, 6, 9])
            body = certificate["body"]
            self.assertEqual(body["attested_missing"], [4, 7, 8])
            self.assertFalse(body["complete"])
            self.assertEqual(body["events_observed"], 6)
            self.assertTrue(verify_certificate(certificate)["ok"])

    def test_complete_capture_is_marked_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            certificate = self._certificate(Path(directory), range(1, 20))
            self.assertTrue(certificate["body"]["complete"])
            self.assertEqual(certificate["body"]["attested_missing"], [])

    def test_editing_the_certificate_is_detected(self):
        """Hiding a gap after the fact must not verify."""
        with tempfile.TemporaryDirectory() as directory:
            certificate = self._certificate(Path(directory), [1, 2, 5])
            forged = {**certificate,
                      "body": {**certificate["body"], "attested_missing": []}}
            result = verify_certificate(forged)
            self.assertFalse(result["ok"])
            self.assertFalse(result["payload_ok"])

    def test_a_different_key_cannot_sign_a_certificate(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            certificate = self._certificate(workspace, [1, 2, 3])
            tampered = {**certificate,
                        "ed25519_signature": "00" * 64}
            self.assertFalse(verify_certificate(tampered)["ok"])


class SessionContinuityTest(unittest.TestCase):
    """A counter that resets to 1 cannot attest across restarts."""

    def test_second_session_resumes_and_records_the_downtime(self):
        with tempfile.TemporaryDirectory() as directory:
            store = FileStore(Path(directory) / "evidence")

            first = SessionManager(store)
            self.assertIsNone(first.open())
            for sequence in range(1, 11):
                store.save_event({"sequence": sequence})
            first.close(10)

            second = SessionManager(store)
            gap = second.open()

            self.assertEqual(second.resumed_from, 10)
            self.assertIsNotNone(gap)
            self.assertEqual(gap.reason, "session_gap")
            self.assertNotEqual(first.run_id, second.run_id)

    def test_resumed_counter_does_not_collide(self):
        from capture.collector import SequenceManager
        manager = SequenceManager(start=10)
        self.assertEqual(manager.next(), 11)

    def test_sessions_are_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            store = FileStore(Path(directory) / "evidence")
            session = SessionManager(store)
            session.open()
            session.close(42)

            sessions = store.load_sessions()
            self.assertEqual(len(sessions), 1)
            self.assertEqual(sessions[0]["last_sequence"], 42)


# =====================================================================
# Cross-phase
# =====================================================================


class PipelineIntegrationTest(unittest.TestCase):
    """Seal -> detect -> anchor -> evaluate, on one graph."""

    def test_tampering_is_caught_by_every_layer(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            from crypto.integrity import EvidenceVerifier
            from detection.detector import PoisoningDetector

            clean = _graph(seed=40, events=160)
            records, service = _sealed(clean, workspace)

            # untouched evidence verifies
            verifier = EvidenceVerifier(store=service.store)
            self.assertTrue(verifier.verify(clean, records=records).ok)

            tampered = synthetic.TamperGenerator(
                random.Random(3), sophistication=0.0
            ).apply(clean, ["forgery"], intensity=0.1).graph

            # crypto layer catches it regardless of the model
            self.assertFalse(verifier.verify(tampered, records=records).ok)

            # detector catches it
            report = PoisoningDetector().detect(tampered)
            self.assertTrue(report["tampered"])

            # anchoring escalates it
            anchoring = _anchoring(workspace)
            result = anchoring.anchor_run(
                records, graph=tampered, report=report,
                partitions=partition_graph(tampered, 16),
                tamper_alert_indices={0}, persist=False)
            self.assertGreater(result["ledger_transactions"], 0)
            self.assertTrue(anchoring.verify_run(result)["ok"])

            # survivability quantifies the damage
            metrics = evaluate(clean, 0.3, seed=1, mode="mixed",
                               records=records)
            self.assertLess(metrics["FSI"], 100.0)
            self.assertGreater(metrics["FSI"], 0.0)


class Phase67PersistenceTest(unittest.TestCase):
    """Phase 6/7 results reach the store, one row per partition / run."""

    def test_anchor_receipts_round_trip_every_partition(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            clean = _graph(seed=4, events=120)
            records, _ = _sealed(clean, workspace)
            result = _anchoring(workspace).anchor_run(
                records, graph=clean,
                partitions=partition_graph(clean, 16),
                tamper_alert_indices={0}, persist=False)

            store = FileStore(workspace / "evidence")
            store.save_anchor_receipts(result)
            store.save_anchor_receipts(result)      # idempotent per partition
            rows = store.load_anchor_receipts("test")

            self.assertEqual(len(rows), len(records))
            first = rows[0]
            self.assertEqual(first["risk_tier"], TIER1)
            self.assertEqual(first["escalated_by"], "tamper_alert")
            self.assertIsNotNone(first["transaction_id"])
            for row in rows:
                if row["risk_tier"] == TIER3:
                    self.assertIsNone(row["transaction_id"])

    def test_survivability_report_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            clean = _graph(seed=5)
            records, _ = _sealed(clean, workspace)
            metrics = evaluate(clean, 0.2, seed=1, mode="edge", records=records)

            store = FileStore(workspace / "evidence")
            store.save_survivability_report(metrics, run_id="test")
            [row] = store.load_survivability_reports("test")
            self.assertEqual(row["fsi"], metrics["FSI"])
            self.assertEqual(row["poison_mode"], "edge")
            self.assertEqual(row["poison_ratio"], 0.2)

    def test_anchor_defaults_to_one_run_not_all_runs(self):
        # Partition indices restart at 0 per run; mixing runs would let
        # one run's partitions overwrite another's inside the scorer.
        import main as cli
        with tempfile.TemporaryDirectory() as tmp:
            store = FileStore(Path(tmp))
            store.save_partitions([
                {"run_id": "old", "partition_index": 0,
                 "created_at": "2026-01-01T00:00:00+00:00"},
                {"run_id": "new", "partition_index": 0,
                 "created_at": "2026-02-01T00:00:00+00:00"},
            ])
            self.assertEqual(cli._latest_run_id(store), "new")
            self.assertIsNone(cli._latest_run_id(FileStore(Path(tmp) / "empty")))


def main() -> int:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
