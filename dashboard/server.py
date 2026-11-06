"""
Local HTTP server for the dashboard, using only the standard library.

It listens on 127.0.0.1. Simulations run real code, so two checks stop other
websites open in the same browser from reaching this server: the Host header
must be local (blocks DNS rebinding), and a POST must be JSON from this origin.
"""
from __future__ import annotations

import json
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from dashboard import service

STATIC = Path(__file__).parent / "static"
FILES = {"/": ("index.html", "text/html; charset=utf-8"),
         "/style.css": ("style.css", "text/css; charset=utf-8"),
         "/app.js": ("app.js", "text/javascript; charset=utf-8")}
MAX_BODY = 64 * 1024
CSP = ("default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none'; "
       "base-uri 'none'; form-action 'none'")


def _default(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    return str(value)


class Handler(BaseHTTPRequestHandler):
    server_version = "QuantumGuard"
    jobs = service.Jobs()

    GET = {
        "/api/overview": service.live_overview,
        "/api/capture": service.live_capture,
        "/api/graph": service.live_graph,
        "/api/detection": service.live_detection,
        "/api/seal": service.live_seal,
        "/api/anchoring": service.live_anchoring,
        "/api/survivability": service.live_survivability,
        "/api/catalogue": service.catalogue,
        "/api/scorecard/saved": service.saved_scorecard,
    }
    POST = {
        "/api/simulate/attack": service.simulate_attack,
        "/api/simulate/evidence": service.simulate_evidence,
        "/api/simulate/pipeline": service.simulate_pipeline,
        "/api/simulate/survivability": service.simulate_survivability,
    }

    def log_message(self, *_):
        pass

    def _send(self, status: int, body: bytes, kind: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, value: Any) -> None:
        self._send(status, json.dumps(value, default=_default).encode(), "application/json")

    def _local_host(self) -> bool:
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        return host in ("127.0.0.1", "localhost")

    def _call(self, function, **arguments) -> None:
        try:
            self._json(200, function(**arguments))
        except (ValueError, TypeError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:
            traceback.print_exc()
            reason = str(getattr(exc, "orig", None) or exc).strip().splitlines()
            self._json(500, {"error": reason[0] if reason else type(exc).__name__})

    def do_GET(self):
        if not self._local_host():
            return self._json(403, {"error": "local access only"})
        path = urlsplit(self.path).path
        if path in FILES:
            name, kind = FILES[path]
            return self._send(200, (STATIC / name).read_bytes(), kind)
        if path == "/api/scorecard/job":
            return self._json(200, self.jobs.public())
        if path in self.GET:
            return self._call(self.GET[path])
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._local_host():
            return self._json(403, {"error": "local access only"})
        origin = self.headers.get("Origin")
        if origin and origin != f"http://{self.headers.get('Host')}":
            return self._json(403, {"error": "cross-origin request refused"})
        if (self.headers.get("Content-Type") or "").split(";")[0] != "application/json":
            return self._json(415, {"error": "send application/json"})
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            return self._json(413, {"error": "request too large"})
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError
        except ValueError:
            return self._json(400, {"error": "invalid JSON"})

        path = urlsplit(self.path).path
        if path == "/api/scorecard/start":
            allowed = {k: body[k] for k in ("trials", "intensity", "seed") if k in body}
            return self._call(self.jobs.start, **allowed)
        if path in self.POST:
            return self._call(self.POST[path], **body)
        return self._json(404, {"error": "not found"})


def make_server(port: int = 8765) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server


def run(port: int = 8765) -> None:
    server = make_server(port)
    print(f"QuantumGuard dashboard: http://127.0.0.1:{server.server_address[1]}")
    print("Live views only read your data. Simulations run in a temporary sandbox.")
    print("Press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()
