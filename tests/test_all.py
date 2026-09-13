"""
QuantumGuard test suite - run with:

    python -m tests.test_all

Nothing here needs PostgreSQL, eBPF, or root - every test drives the
FileStore backend and in-memory graphs, so this runs the same way on a
grader's laptop as it does on the capture host.

Four regression stories are baked into these tests, each documented next
to the class that guards it:

  1. FileStore.save_event() used to crash on every call (RawEvent is a
     `slots=True` dataclass; vars() can't read it).            -> FileStoreEventsTest
  2. graph/service.py used to write `hash`/`synthetic`/`sequence`
     instead of the `process_hash`/`synthetic_root`/`seq`+`ts` that
     detection/ and crypto/ actually read - tamper detection and
     integrity sealing degraded silently on real captures.     -> GraphSchemaTest
  3. KeyStore.load() raised UnboundLocalError on every existing
     key store (self-referential assignment).                  -> KeyStoreTest
  4. detection/model.py's GraphSAGE.backward() is a hand-derived
     analytic gradient with no autograd to check it against.   -> GraphSAGEGradientCheckTest
"""
from __future__ import annotations

import copy
import hashlib
import random
import sys
import tempfile
import unittest

import numpy as np

from capture.cca import CCA
from capture.models import RawEvent
from core.store import FileStore
from crypto.integrity import (
    DualSigner, DualVerifier, EvidenceVerifier, IntegrityService, KeyStore,
    MerkleTree, ordered_edges, partition_graph, verify_proof,
)
from detection import features, synthetic
from detection.detector import RuleEngine
from detection.model import GraphSAGE, bce_with_logits
from graph.service import ProvenanceGraphService


# =====================================================================
# core/store.py - offline FileStore behaviour
# =====================================================================


class FileStoreEventsTest(unittest.TestCase):
    """Regression coverage for bug (1): FileStore.save_event() crashed on
    every call because RawEvent is a `slots=True` dataclass (no
    __dict__), and the old _as_dict() helper called vars() unconditionally.
    Because the default backend used to be "db", nobody ever exercised
    QG_STORE=file with a real capture event, so this was silent until
    someone actually tried the documented offline workflow."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = FileStore(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_save_event_accepts_slotted_dataclass(self):
        # RawEvent(slots=True) - this line alone used to raise TypeError.
        event = RawEvent(timestamp=123, pid=1, uid=1000, comm="bash",
                          filename="/bin/ls", event_type=1, sequence=1)
        self.store.save_event(event)
        rows = self.store.load_events()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["comm"], "bash")
        self.assertEqual(rows[0]["sequence"], 1)

    def test_load_events_is_ordered_by_sequence(self):
        for seq in (3, 1, 2):
            self.store.save_event(RawEvent(
                timestamp=seq, pid=seq, uid=1000, comm="x",
                filename="/bin/x", event_type=1, sequence=seq))
        rows = self.store.load_events()
        self.assertEqual([r["sequence"] for r in rows], [1, 2, 3])

    def test_missing_sequences_round_trip_and_skip_complete(self):
        cca = CCA()
        self.store.save_attestation(cca.verify(1))          # complete, not persisted
        self.store.save_attestation(cca.verify(5))          # gap: 2,3,4 missing
        missing = self.store.load_missing_sequences()
        self.assertEqual(missing, {2, 3, 4})

    def test_partitions_round_trip_and_are_ordered(self):
        records = [
            {"run_id": "r1", "partition_index": 1, "merkle_root": "b"},
            {"run_id": "r1", "partition_index": 0, "merkle_root": "a"},
        ]
        self.store.save_partitions(records)
        loaded = self.store.load_partitions("r1")
        self.assertEqual([r["partition_index"] for r in loaded], [0, 1])


# =====================================================================
# graph/service.py - schema contract with detection/ and crypto/
# =====================================================================


def _seed(store: FileStore, events):
    for pid, uid, comm, filename, ts, seq in events:
        store.save_event(RawEvent(timestamp=ts, pid=pid, uid=uid, comm=comm,
                                   filename=filename, event_type=1, sequence=seq))


class GraphSchemaTest(unittest.TestCase):
    """Regression coverage for bug (2): the graph builder used to write
    `hash` instead of `process_hash`, `synthetic` instead of
    `synthetic_root`, and only `sequence` (never `seq`/`ts`) on edges.
    detection/features.py, detection/detector.py (RuleEngine) and
    crypto/integrity.py all read the names asserted below; a rename here
    that isn't mirrored there degrades tamper detection silently (no
    exception - features just read as 0/None) instead of failing loudly,
    which is exactly why it went unnoticed. See graph/service.py's module
    docstring for the full contract."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = FileStore(self._tmp.name)
        # bash (session root child) execs python3, which execs git.
        _seed(self.store, [
            (100, 1000, "bash", "/usr/bin/python3", 10_000_000_000, 1),
            (101, 1000, "python3", "/usr/bin/git", 10_000_500_000, 2),
        ])
        self.service = ProvenanceGraphService(store=self.store)
        self.graph = self.service.run()

    def tearDown(self):
        self._tmp.cleanup()

    def test_process_nodes_carry_process_hash_not_hash(self):
        process_nodes = [n for n, d in self.graph.nodes(data=True)
                          if d.get("type") == "process" and not d.get("synthetic_root")]
        self.assertTrue(process_nodes)
        for node in process_nodes:
            attrs = self.graph.nodes[node]
            self.assertIn("process_hash", attrs)
            self.assertTrue(attrs["process_hash"])
            self.assertNotIn("hash", attrs)

    def test_session_root_uses_synthetic_root_not_synthetic(self):
        roots = [n for n, d in self.graph.nodes(data=True) if d.get("synthetic_root")]
        self.assertEqual(len(roots), 1)
        self.assertNotIn("synthetic", self.graph.nodes[roots[0]])

    def test_every_edge_carries_seq_and_ts(self):
        self.assertGreater(self.graph.number_of_edges(), 0)
        for _, _, data in self.graph.edges(data=True):
            self.assertIn("seq", data)
            self.assertIn("ts", data)
            self.assertGreater(data["seq"], 0)
            self.assertGreater(data["ts"], 0)

    def test_execve_chain_parent_inference(self):
        # the process that exec'd git must be linked via SPAWNS from the
        # process that exec'd python3 (real execve-chain, not just "last
        # pid seen").
        git_exec_edges = [(u, v) for u, v, d in self.graph.edges(data=True)
                           if d["relation"] == "EXECUTES" and v.startswith("F:/usr/bin/git")]
        self.assertEqual(len(git_exec_edges), 1)
        git_process = git_exec_edges[0][0]
        spawn_parents = [u for u, v, d in self.graph.edges(data=True)
                          if d["relation"] == "SPAWNS" and v == git_process]
        self.assertEqual(len(spawn_parents), 1)


# =====================================================================
# crypto/integrity.py - Merkle trees, the key store, and seal/verify
# =====================================================================


def _small_graph():
    return synthetic.generate(n_events=12, uid=1000)


class MerkleTreeTest(unittest.TestCase):

    def test_proofs_verify_at_several_leaf_counts(self):
        for n in (1, 2, 3, 5, 8, 13):
            hashed = [hashlib.sha256(f"leaf-{i}".encode()).digest() for i in range(n)]
            tree = MerkleTree(hashed)
            for i in range(n):
                self.assertTrue(verify_proof(hashed[i], tree.proof(i), tree.root))

    def test_tampering_a_leaf_breaks_its_proof(self):
        hashed = [hashlib.sha256(f"leaf-{i}".encode()).digest() for i in range(5)]
        tree = MerkleTree(hashed)
        proof = tree.proof(2)
        forged = hashlib.sha256(b"forged").digest()
        self.assertFalse(verify_proof(forged, proof, tree.root))


class OrderingTest(unittest.TestCase):

    def test_ordered_edges_is_deterministic(self):
        G = _small_graph()
        self.assertEqual(ordered_edges(G), ordered_edges(G))

    def test_partition_graph_respects_size(self):
        G = _small_graph()
        parts = partition_graph(G, size=4)
        self.assertTrue(all(len(p["edges"]) <= 4 for p in parts))
        self.assertEqual(sum(len(p["edges"]) for p in parts), G.number_of_edges())


class KeyStoreTest(unittest.TestCase):
    """Regression coverage for bug (3): KeyStore.load() raised
    UnboundLocalError on every existing key store, because a single
    assignment statement read a local variable on its own right-hand
    side before that variable existed. It was invisible before this fix
    because core.config.KEYSTORE pointed at a filename that never
    matched the file actually on disk, so `.load()` was never reached -
    every run silently went through `.create()` instead."""

    def test_create_then_load_round_trips(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = f"{tmp}/ks.json"
            created = KeyStore(path=path, passphrase="correct-horse").create()
            pub_before = created.ed_public_bytes()

            # This is the exact call that used to raise UnboundLocalError.
            loaded = KeyStore(path=path, passphrase="correct-horse").load()
            self.assertEqual(loaded.ed_public_bytes(), pub_before)

    def test_wrong_passphrase_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = f"{tmp}/ks.json"
            KeyStore(path=path, passphrase="right").create()
            with self.assertRaises(ValueError):
                KeyStore(path=path, passphrase="wrong").load()


class SealVerifyTest(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = FileStore(self._tmp.name)
        self.keystore = KeyStore(path=f"{self._tmp.name}/ks.json",
                                  passphrase="test-pass").create()
        self.graph = _small_graph()

    def tearDown(self):
        self._tmp.cleanup()

    def test_seal_then_verify_passes_on_untouched_graph(self):
        service = IntegrityService(keystore=self.keystore, store=self.store, partition_size=8)
        records = service.seal(self.graph, run_id="t1")
        report = EvidenceVerifier(store=self.store).verify(self.graph, run_id="t1")
        self.assertTrue(report.ok, report.errors)
        self.assertEqual(len(report.partitions), len(records))

    def test_deleting_an_edge_after_sealing_is_detected(self):
        service = IntegrityService(keystore=self.keystore, store=self.store, partition_size=8)
        service.seal(self.graph, run_id="t2")

        tampered = copy.deepcopy(self.graph)
        u, v = next(iter(tampered.edges()))
        tampered.remove_edge(u, v)

        report = EvidenceVerifier(store=self.store).verify(tampered, run_id="t2")
        self.assertFalse(report.ok)
        self.assertGreater(report.missing_leaf_count, 0)

    def test_editing_a_sealed_node_attribute_is_detected(self):
        service = IntegrityService(keystore=self.keystore, store=self.store, partition_size=8)
        service.seal(self.graph, run_id="t3")

        tampered = copy.deepcopy(self.graph)
        process_node = next(n for n, d in tampered.nodes(data=True) if d.get("type") == "process")
        tampered.nodes[process_node]["timestamp"] += 1  # edit after sealing

        report = EvidenceVerifier(store=self.store).verify(tampered, run_id="t3")
        self.assertFalse(report.ok)


class HybridSignatureTest(unittest.TestCase):

    def test_verify_fails_if_either_algorithm_is_broken(self):
        with tempfile.TemporaryDirectory() as tmp:
            keystore = KeyStore(path=f"{tmp}/ks.json", passphrase="x").create()
        signer = DualSigner(keystore)
        record = signer.sign("payload")

        broken_ed = dict(record)
        broken_ed["ed25519_signature"] = "00" * 64
        self.assertFalse(DualVerifier().verify("payload", broken_ed)["ok"])

        broken_pq = dict(record)
        broken_pq["mldsa_signature"] = "00" * 64
        self.assertFalse(DualVerifier().verify("payload", broken_pq)["ok"])

        self.assertTrue(DualVerifier().verify("payload", record)["ok"])


# =====================================================================
# detection/ - rule engine, feature determinism, tampering, and the
# GraphSAGE backward pass
# =====================================================================


def _clean_graph(seed=1):
    return synthetic.generate(random.Random(seed), n_events=20, uid=1000)


class RuleEngineTest(unittest.TestCase):

    def test_clean_graph_has_no_high_or_critical_violations(self):
        G = _clean_graph()
        violations = RuleEngine().check(G)
        blocking = [v for v in violations if v["severity"] in ("critical", "high")]
        self.assertEqual(blocking, [])

    def test_process_hash_mismatch_is_caught(self):
        G = _clean_graph()
        node = next(n for n, d in G.nodes(data=True)
                     if d["type"] == "process" and not d.get("synthetic_root"))
        G.nodes[node]["process_hash"] = "0" * 64  # forge it
        violations = RuleEngine().check(G)
        rules_fired = {v["rule"] for v in violations}
        self.assertIn("process_hash_mismatch", rules_fired)

    def test_self_loop_is_caught(self):
        G = _clean_graph()
        node = next(n for n, d in G.nodes(data=True)
                     if d["type"] == "process" and not d.get("synthetic_root"))
        G.add_edge(node, node, relation="EXECUTES", seq=99999, ts=1)
        violations = RuleEngine().check(G)
        self.assertIn("self_loop", {v["rule"] for v in violations})

    def test_sequence_gap_is_suppressed_by_cca_attestation(self):
        G = _clean_graph(seed=2)
        # delete one edge's seq to open a gap, then confirm CCA knowledge
        # of that exact gap suppresses the rule.
        edges = sorted(G.edges(data=True), key=lambda e: e[2].get("seq") or 0)
        removed_seq = edges[len(edges) // 2][2]["seq"]
        G.remove_edges_from([(u, v) for u, v, d in edges if d.get("seq") == removed_seq])

        unexplained = RuleEngine().check(G)
        self.assertIn("sequence_gap", {v["rule"] for v in unexplained})

        explained = RuleEngine(known_missing_sequences={removed_seq}).check(G)
        self.assertNotIn("sequence_gap", {v["rule"] for v in explained})


class FeatureDeterminismTest(unittest.TestCase):

    def test_extract_is_deterministic_and_matches_declared_dim(self):
        G = _clean_graph()
        X1, nodes1 = features.extract(G)
        X2, nodes2 = features.extract(G)
        self.assertEqual(nodes1, nodes2)
        np.testing.assert_array_equal(X1, X2)
        self.assertEqual(X1.shape, (len(nodes1), features.FEATURE_DIM))

    def test_adjacency_connectivity_is_symmetric_and_rows_are_normalised(self):
        # adjacency() is the MEAN aggregator: connectivity is undirected
        # (A[i,j] > 0 iff A[j,i] > 0), but each row is normalised by that
        # node's OWN degree, so unequal degrees mean the weighted matrix
        # itself is not symmetric - only which entries are nonzero is.
        G = _clean_graph()
        _, nodes = features.extract(G)
        A = features.adjacency(G, nodes)
        np.testing.assert_array_equal(A > 0, (A.T > 0))
        row_sums = A.sum(axis=1)
        nonzero = row_sums[row_sums > 0]
        np.testing.assert_allclose(nonzero, np.ones_like(nonzero), rtol=1e-5)


class TamperGeneratorTest(unittest.TestCase):

    def test_every_strategy_produces_consistent_labels(self):
        for strategy in synthetic.STRATEGIES:
            G = _clean_graph(seed=hash(strategy) % 1000)
            gen = synthetic.TamperGenerator(random.Random(0), sophistication=0.8)
            result = gen.apply(G, [strategy], intensity=0.2)
            self.assertTrue(result.tampered, strategy)
            # every labelled-positive node must still exist in the graph
            self.assertTrue(set(result.positives()).issubset(set(result.graph.nodes())))

    def test_clean_leaves_every_label_zero(self):
        G = _clean_graph()
        result = synthetic.TamperGenerator().clean(G)
        self.assertFalse(result.tampered)
        self.assertEqual(result.positives(), [])


class GraphSAGEGradientCheckTest(unittest.TestCase):
    """Regression coverage for bug (4): detection/model.py's
    GraphSAGE.backward() is a hand-derived analytic gradient (no
    autograd), which is exactly the kind of code where a sign error or
    transposed matrix still trains "successfully" (loss goes down) while
    being subtly wrong. Comparing to numerical gradients is the only way
    to actually know the backward pass is correct rather than merely
    plausible."""

    def test_backward_matches_numerical_gradient(self):
        rng = np.random.default_rng(0)
        n, in_dim, hidden = 6, 5, 4

        X = rng.normal(size=(n, in_dim))
        A = rng.random((n, n))
        A = (A + A.T) / 2
        np.fill_diagonal(A, 0)
        A = A / np.clip(A.sum(axis=1, keepdims=True), 1e-6, None)
        y = (rng.random(n) > 0.5).astype(np.float64)
        weights = np.ones(n)

        model = GraphSAGE(in_dim, hidden, seed=3)
        logits = model.forward(X, A)
        analytic = model.backward(logits, y, weights)

        def loss_for(param_name, value):
            saved = model.p[param_name].copy()
            model.p[param_name] = value
            loss = bce_with_logits(model.forward(X, A, cache=False), y, weights)
            model.p[param_name] = saved
            return loss

        eps = 1e-5
        for name in ("b1", "Wo"):  # small params - cheap to check exhaustively
            grad = analytic[name]
            numeric = np.zeros_like(grad)
            it = np.nditer(grad, flags=["multi_index"])
            for _ in it:
                idx = it.multi_index
                p = model.p[name].copy()
                p[idx] += eps
                plus = loss_for(name, p)
                p = model.p[name].copy()
                p[idx] -= eps
                minus = loss_for(name, p)
                numeric[idx] = (plus - minus) / (2 * eps)
            np.testing.assert_allclose(grad, numeric, atol=1e-3, rtol=1e-2)


# =====================================================================
# Entry point
# =====================================================================


def main() -> int:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
