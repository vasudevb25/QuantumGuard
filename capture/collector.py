import json
import os
import signal
import subprocess
import sys
from threading import Lock

from capture.models import RawEvent
from capture.cca import CCA, SessionManager, save_certificate
from core import config
from core.store import get_store

_HOME = os.path.expanduser("~")


class SequenceManager:
    """Thread-safe monotonically increasing sequence generator.

    `start` is the highest sequence already in the store. Resuming from
    it rather than from zero is what keeps completeness provable across
    collector restarts - a counter that resets would collide with the
    primary key of events already captured, and would make every
    restart look like a sequence discontinuity.
    """

    def __init__(self, start: int = 0):
        self.counter = start
        self.lock = Lock()

    def next(self):
        with self.lock:
            self.counter += 1
            return self.counter


class EBPFCollector:
    """
    QuantumGuard Phase 1

    eBPF → JSON → Filter → Sequence → CCA → PostgreSQL
    """

    # Noisy per-user tool installs, not filtered by UID because they run
    # as the logged-in user. Derived from $HOME so this is portable across
    # machines instead of tied to one developer's account.
    IGNORE_PREFIXES = (
        "/snap/",
        f"{_HOME}/.local/",
        f"{_HOME}/go/",
    )

    def __init__(self, run_id: str | None = None):
        self.store = get_store()
        self.session = SessionManager(self.store, run_id)

        resume = self.session.open()
        start = self.session.resumed_from

        self.sequence = SequenceManager(start)
        self.cca = CCA(run_id=self.session.run_id, start=start)
        self.loader = None
        self.running = True

        if resume is not None:
            # The time the collector was down is a genuine gap in the
            # record. Writing it as an attestation means it reads later
            # as documented downtime rather than as deletion.
            self.store.save_attestation(resume)
            print(f"[session] resuming at sequence {start + 1} "
                  f"(run {self.session.run_id[:8]})")

    def shutdown(self, *_):
        """Gracefully stop the eBPF loader."""
        self.running = False

        if self.loader and self.loader.poll() is None:
            self.loader.terminate()

            try:
                self.loader.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.loader.kill()

        # Seal the session: a signed statement of exactly what this run
        # claims to have captured, and which sequences it lost.
        try:
            certificate = self.cca.certificate()
            path = save_certificate(
                certificate,
                f"{config.EVIDENCE_DIR}/completeness_"
                f"{self.session.run_id[:8]}.json")
            missing = len(certificate["body"]["attested_missing"])
            print(f"[cca] {certificate['body']['events_observed']} events, "
                  f"{missing} attested missing -> {path}")
        except Exception as exc:
            print(f"[cca] could not write completeness certificate: {exc}")

        self.session.close(self.sequence.counter)

        print("\nQuantumGuard collector stopped.")
        sys.exit(0)

    def start(self):

        signal.signal(signal.SIGINT, self.shutdown)

        self.loader = subprocess.Popen(
            ["sudo", "./ebpf/loader"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        print("=== QuantumGuard Collector Started ===")

        for line in self.loader.stdout:

            if not self.running:
                break

            line = line.strip()

            if not line:
                continue

            # Loader status messages
            if not line.startswith("{"):
                print(f"[LOADER] {line}")
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            event = RawEvent(
                timestamp=data["ts"],
                pid=data["pid"],
                uid=data["uid"],
                comm=data["comm"],
                filename=data["file"],
                event_type=data["type"],
            )

            # ---------- Provenance Filters ----------

            if event.uid < 1000:
                continue

            if event.filename.startswith(self.IGNORE_PREFIXES):
                continue

            # ---------------------------------------

            event.sequence = self.sequence.next()

            attestation = self.cca.verify(event.sequence)

            self.store.save_event(event)
            self.store.save_attestation(attestation)

            print(
                f"[{event.sequence}] "
                f"{event.comm} (PID {event.pid}) → "
                f"{event.filename}"
            )

        self.shutdown()


if __name__ == "__main__":
    EBPFCollector().start()
