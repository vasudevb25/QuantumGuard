import json
import os
import signal
import subprocess
import sys
import threading
import time
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

    def skip(self, count: int):
        """Leave a hole for events known to be lost, so CCA attests them."""
        with self.lock:
            self.counter += count


AUID_UNSET = 4294967295     # (u32)-1, the kernel's "never logged in"


def is_captured(uid: int, auid: int) -> bool:
    """Must match the filter in ebpf/probes.c."""
    return uid >= 1000 or auid != AUID_UNSET


class EBPFCollector:
    """
    QuantumGuard Phase 1

    eBPF → JSON → Filter → Sequence → CCA → PostgreSQL
    """

    # bpf_ktime_get_ns() is CLOCK_MONOTONIC: nanoseconds since boot, which
    # restart at zero on reboot. Adding this offset, fixed once per capture so
    # NTP adjustments cannot reorder events, stores Unix time instead, which
    # stays comparable across reboots.
    @staticmethod
    def _wall_clock_offset() -> int:
        return time.time_ns() - time.monotonic_ns()

    # Noisy per-user tool installs, not filtered by UID because they run
    # as the logged-in user. Derived from $HOME so this is portable across
    # machines instead of tied to one developer's account.
    IGNORE_PREFIXES = (
        "/snap/",
        f"{_HOME}/.local/",
        f"{_HOME}/go/",
    )

    def __init__(self, run_id: str | None = None):
        # Checked before the session opens: a capture that cannot start must
        # not leave a session row or a restart attestation behind. Fails now
        # rather than after hours of capture, when the completeness
        # certificate could not be signed.
        if not os.path.exists("./ebpf/loader"):
            raise SystemExit("eBPF loader not built; run: make -C ebpf")
        from crypto.integrity import KeyStore
        KeyStore().load_or_create()

        self.store = get_store()
        self.session = SessionManager(self.store, run_id)

        resume = self.session.open()
        start = self.session.resumed_from

        self.sequence = SequenceManager(start)
        self.cca = CCA(run_id=self.session.run_id, start=start)
        self.loader = None
        self.running = True
        self.clock_offset = self._wall_clock_offset()
        self.kernel_dropped = 0
        self.malformed = 0

        if resume is not None:
            # The time the collector was down is a genuine gap in the
            # record. Writing it as an attestation means it reads later
            # as documented downtime rather than as deletion.
            self.store.save_attestation(resume)
            print(f"[session] resuming at sequence {start + 1} "
                  f"(run {self.session.run_id[:8]})")

    def _request_stop(self, *_):
        """Signal handler: ask the loader to exit and let start() finish.

        Reading the loader's output here would re-enter the stream the main
        loop is blocked on. Its last line reports final losses, so the main
        loop has to be left to read up to end-of-file.
        """
        self.running = False
        if self.loader and self.loader.poll() is None:
            self.loader.terminate()
            killer = threading.Timer(3.0, self._force_kill)
            killer.daemon = True
            killer.start()

    def _force_kill(self):
        if self.loader and self.loader.poll() is None:
            self.loader.kill()

    def _account_for_drops(self, total: int) -> None:
        """Turn the kernel's running loss count into a sequence gap."""
        lost = total - self.kernel_dropped
        if lost > 0:
            self.kernel_dropped = total
            self.sequence.skip(lost)

    def ingest(self, line: str) -> None:
        """Process one line of loader output."""
        if not line.startswith("{"):
            print(f"[LOADER] {line}")
            return

        try:
            data = json.loads(line)
            if "final_dropped" in data:
                self._account_for_drops(int(data["final_dropped"]))
                self._attest_trailing_loss()
                return
            event = RawEvent(
                timestamp=int(data["ts"]) + self.clock_offset,
                pid=data["pid"],
                uid=data["uid"],
                comm=data["comm"],
                filename=data["file"],
                event_type=data["type"],
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            # An event happened and could not be read. It has to leave a gap:
            # skipping it silently would let a crafted file name run unrecorded.
            self.malformed += 1
            self.sequence.skip(1)
            print(f"[capture] unreadable event, attested as lost: {line[:120]!r}")
            return

        self._account_for_drops(int(data.get("dropped", 0)))

        # ---------- Provenance Filters ----------

        if not is_captured(event.uid, int(data.get("auid", AUID_UNSET))):
            return

        if event.filename.startswith(self.IGNORE_PREFIXES):
            return

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

    def _attest_trailing_loss(self) -> None:
        attestation = self.cca.record_loss(self.sequence.counter - self.cca.last)
        if attestation:
            self.store.save_attestation(attestation)

    def shutdown(self, *_):
        """Finish the session once the loader has stopped."""
        self.running = False
        self._attest_trailing_loss()

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

        signal.signal(signal.SIGINT, self._request_stop)
        signal.signal(signal.SIGTERM, self._request_stop)

        self.loader = subprocess.Popen(
            ["sudo", "./ebpf/loader"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            bufsize=1,
        )

        print("=== QuantumGuard Collector Started ===")

        for line in self.loader.stdout:
            line = line.strip()
            if line:
                self.ingest(line)

        if self.running:
            print(f"[capture] loader exited unexpectedly "
                  f"(status {self.loader.wait()})")
        self.shutdown()


if __name__ == "__main__":
    EBPFCollector().start()
