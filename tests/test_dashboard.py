"""
Dashboard tests. Run with: python -m tests.test_dashboard

The main guarantee is that simulations leave no trace outside their sandbox.
"""
from __future__ import annotations

from tests import _sandbox  # noqa: F401  (must come before project imports)

import hashlib
import http.client
import json
import os
import pickle
import random
import threading
import unittest
from pathlib import Path

from anchoring.ledger import LocalLedger
from anchoring.service import AnchoringService
from core.store import FileStore
from crypto.integrity import DualSigner, IntegrityService, KeyStore
from dashboard import server, service
from detection import synthetic
from evaluation import tamper
from graph.service import ProvenanceGraphService


def _snapshot() -> dict[str, str]:
    found = {}
    for folder, _, names in os.walk("."):
        for name in names:
            path = os.path.join(folder, name)
            found[path] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    return found


def _real_project() -> None:
    """Graph, seal and ledger on disk, as after a real pipeline run."""
    graph = synthetic.generate(random.Random(1), n_events=70)
    Path("graphs").mkdir(exist_ok=True)
    with open("graphs/provenance_graph.gpickle", "wb") as handle:
        pickle.dump(graph, handle)
    keys = KeyStore().load_or_create()
    store = FileStore()
    if not store.load_partitions():
        records = IntegrityService(keys, store, partition_size=32).seal(graph, run_id="real")
        AnchoringService(ledger=LocalLedger(signer=DualSigner(keys))).anchor_run(records, graph=graph)


class LiveViewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _real_project()

    def test_live_views_work_and_write_nothing(self):
        before = _snapshot()
        overview = service.live_overview()
        self.assertEqual(len(overview["phases"]), 7)
        self.assertTrue(overview["verified"])
        self.assertTrue(service.live_seal()["partitions"])
        self.assertTrue(service.live_graph()["nodes"])
        self.assertIn("verdict", service.live_detection())
        self.assertIn("blocks", service.live_anchoring())
        self.assertIn("events", service.live_capture())
        self.assertEqual(_snapshot(), before)

    def test_edited_graph_shows_as_failed_verification(self):
        original = Path("graphs/provenance_graph.gpickle").read_bytes()
        try:
            graph = pickle.loads(original)
            graph.remove_node(tamper._events(graph)[3])
            with open("graphs/provenance_graph.gpickle", "wb") as handle:
                pickle.dump(graph, handle)
            os.utime("graphs/provenance_graph.gpickle", (1, 1))
            overview = service.live_overview()
            self.assertFalse(overview["verified"])
            self.assertIn("Evidence verification failed", [a["title"] for a in overview["advisories"]])
        finally:
            Path("graphs/provenance_graph.gpickle").write_bytes(original)

    def test_capture_detection_ignores_text_that_only_mentions_it(self):
        self.assertFalse(service._capture_running())

    def test_stale_model_is_reported(self):
        Path("models").mkdir(exist_ok=True)
        meta = Path("models/gnn_detector.meta.json")
        meta.write_text(json.dumps({"threshold": 0.5}))
        Path("models/gnn_detector.npz").touch()
        os.utime("models/gnn_detector.npz", (1, 1))
        try:
            service._cache.clear()
            original = service.live_detection
            service.live_detection = lambda: None
            titles = [a["title"] for a in service.live_overview()["advisories"]]
            self.assertIn("Model is older than the graph", titles)
        finally:
            service.live_detection = original
            meta.unlink()
            Path("models/gnn_detector.npz").unlink()
            service._cache.clear()


class SimulationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _real_project()

    def test_simulations_leave_no_trace(self):
        before = _snapshot()
        service.simulate_attack("adaptive_forgery", source="real")
        service.simulate_attack("tail_truncate", source="synthetic")
        service.simulate_pipeline(events=50)
        service.simulate_survivability(source="real")
        service.simulate_evidence()
        self.assertEqual(_snapshot(), before)

    def test_every_attack_is_proven_by_the_seal(self):
        for attack in tamper.ATTACKS:
            result = service.simulate_attack(attack, events=60)
            self.assertTrue(result["layers"]["seal"]["caught"], attack)
            self.assertTrue(result["clean"]["seal_ok"], attack)

    def test_pipeline_covers_every_phase_and_attests_losses(self):
        result = service.simulate_pipeline(events=60, loss=4, attack="forgery_expert")
        keys = [step["key"] for step in result["steps"]]
        for key in ("capture", "normalise", "graph", "detect", "seal", "anchor",
                    "attack", "redetect", "reverify", "survive"):
            self.assertIn(key, keys)
        self.assertEqual(result["steps"][0]["metrics"]["lost"], 4)
        self.assertEqual(result["steps"][3]["detection"]["by_rule"].get("sequence_gap"), None,
                         "attested losses must not read as deletion")
        self.assertTrue(result["seal_caught"])
        self.assertTrue(result["ledger_ok"])

    def test_detector_state_does_not_leak_between_simulations(self):
        service.simulate_pipeline(events=50, loss=5)
        self.assertEqual(service._detector().rules.known_missing, set())

    def test_bad_input_is_refused_or_clamped(self):
        with self.assertRaises(ValueError):
            service.simulate_attack("rm -rf")
        with self.assertRaises(ValueError):
            service.simulate_attack("flag_abuse", source="/etc/passwd")
        with self.assertRaises(ValueError):
            service.simulate_survivability(mode="nope")
        self.assertEqual(service.simulate_attack("flag_abuse", intensity=99, events=40)["intensity"], 0.5)

    def test_diff_marks_added_and_removed_calls(self):
        graph = synthetic.generate(random.Random(2), n_events=60)
        changed = tamper.apply_attack(graph, "binary_swap", 0.2, 3).graph
        statuses = {edge["status"] for edge in service.diff_payload(graph, changed)["edges"]}
        self.assertTrue(statuses & {"added", "removed", "changed"})
        same = {edge["status"] for edge in service.diff_payload(graph, graph)["edges"]}
        self.assertEqual(same, {"same"})

    def test_missing_real_graph_gives_a_clear_error(self):
        path = Path("graphs/provenance_graph.gpickle")
        saved = path.read_bytes()
        path.unlink()
        try:
            with self.assertRaisesRegex(ValueError, "no real graph"):
                service.simulate_attack("flag_abuse", source="real")
            self.assertIsNone(service.live_graph())
        finally:
            path.write_bytes(saved)


class HttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _real_project()
        cls.server = server.make_server(0)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        connection.request(method, path, body, headers or {})
        response = connection.getresponse()
        data = response.read()
        connection.close()
        return response, data

    def test_listens_only_on_loopback(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_serves_only_its_own_files(self):
        for path in ("/", "/app.js", "/style.css"):
            response, _ = self._request("GET", path)
            self.assertEqual(response.status, 200, path)
            self.assertIn("default-src 'self'", response.getheader("Content-Security-Policy"))
        for path in ("/../../main.py", "/static/../server.py", "/keys/quantumguard.keystore.json"):
            self.assertEqual(self._request("GET", path)[0].status, 404, path)

    def test_every_get_route_answers(self):
        for path in server.Handler.GET:
            response, data = self._request("GET", path)
            self.assertEqual(response.status, 200, path)
            json.loads(data)

    def test_simulation_over_http(self):
        response, data = self._request(
            "POST", "/api/simulate/attack",
            json.dumps({"attack": "flag_abuse", "source": "synthetic", "events": 40}),
            {"Content-Type": "application/json"})
        self.assertEqual(response.status, 200)
        self.assertTrue(json.loads(data)["layers"]["seal"]["caught"])

    def test_other_websites_cannot_drive_it(self):
        body = json.dumps({"attack": "flag_abuse"})
        json_type = {"Content-Type": "application/json"}
        cases = [
            ({**json_type, "Origin": "https://evil.example"}, 403),
            ({"Content-Type": "text/plain"}, 415),
            ({**json_type, "Host": "evil.example"}, 403),
        ]
        for headers, status in cases:
            self.assertEqual(self._request("POST", "/api/simulate/attack", body, headers)[0].status,
                             status, headers)
        self.assertEqual(self._request("GET", "/api/overview", None, {"Host": "evil.example"})[0].status, 403)

    def test_bad_requests_get_clean_errors(self):
        json_type = {"Content-Type": "application/json"}
        self.assertEqual(self._request("POST", "/api/simulate/attack", "{bad", json_type)[0].status, 400)
        self.assertEqual(self._request("POST", "/api/simulate/attack", '{"attack":"x"}', json_type)[0].status, 400)
        self.assertEqual(self._request("POST", "/api/simulate/attack", '{"nope":1}', json_type)[0].status, 400)
        self.assertEqual(self._request("POST", "/api/nope", "{}", json_type)[0].status, 404)

    def test_policy_blocks_inline_scripts(self):
        """Captured file names are attacker-controlled and reach the browser, so
        scripts may only come from this server, as a second line behind esc()."""
        self.assertIn("default-src 'self'", server.CSP)
        self.assertNotIn("script-src", server.CSP)
        page = (server.STATIC / "index.html").read_text()
        self.assertNotIn("<script>", page)
        self.assertNotIn("eval(", (server.STATIC / "app.js").read_text())

    def test_scorecard_job_runs_to_completion(self):
        import time
        jobs = server.Handler.jobs
        jobs.start(trials=1)
        for _ in range(240):
            if jobs.public()["state"] != "running":
                break
            time.sleep(0.25)
        job = jobs.public()
        self.assertEqual(job["state"], "done", job.get("error"))
        self.assertEqual(job["done"], job["total"] - 1)
        self.assertEqual(job["result"]["evidence_attacks_missed"], [])


class GraphPayloadTest(unittest.TestCase):
    def test_nodes_and_edges_are_json_ready(self):
        tmp = FileStore(Path("sub"))
        for sequence, (pid, uid, comm, path) in enumerate(
                [(1, 1000, "bash", "/usr/bin/sudo"), (2, 0, "sudo", "/usr/bin/apt")], start=1):
            tmp.save_event({"sequence": sequence, "timestamp": sequence * 10 ** 7, "pid": pid,
                            "uid": uid, "comm": comm, "filename": path, "event_type": 1})
        builder = ProvenanceGraphService(store=tmp)
        graph = builder.build(builder.enrich(builder.validate(builder.deduplicate(builder.load_events()))))
        payload = service.graph_payload(graph)
        json.dumps(payload)
        self.assertEqual({n["name"]: n["kind"] for n in payload["nodes"]}["apt"], "root")


if __name__ == "__main__":
    unittest.main()
