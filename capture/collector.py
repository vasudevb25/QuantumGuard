import json
import signal
import subprocess
import sys

from capture.models import RawEvent
from capture.sequence import SequenceManager
from capture.cca import CCA
from capture.database import save_event, save_attestation


class EBPFCollector:
    """Kernel provenance collector with CCA and PostgreSQL persistence."""

    IGNORE_PREFIXES = (
        "/snap/",
        "/home/profmoriarty/.local/",
        "/home/profmoriarty/go/",
    )

    def __init__(self):
        self.sequence = SequenceManager()
        self.cca = CCA()
        self.loader = None
        self.running = True

    def _shutdown(self, *_):
        """Gracefully terminate loader."""
        self.running = False

        if self.loader and self.loader.poll() is None:
            self.loader.terminate()
            try:
                self.loader.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.loader.kill()

        print("\nCollector stopped.")
        sys.exit(0)

    def start(self):
        """Start eBPF loader and process provenance events."""

        signal.signal(signal.SIGINT, self._shutdown)

        self.loader = subprocess.Popen(
            ["sudo", "./ebpf/loader"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        print("=== QuantumGuard eBPF Collector Started ===")

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

            # Parse JSON event
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

            # -------- Selective Provenance Filtering --------

            if event.uid < 1000:
                continue

            if event.filename.startswith(self.IGNORE_PREFIXES):
                continue

            # ------------------------------------------------

            event.sequence = self.sequence.next()

            attestation = self.cca.verify(event.sequence)

            save_event(event)
            save_attestation(attestation)

            print(
                f"[{event.sequence}] "
                f"{event.comm} (PID {event.pid}) → {event.filename}"
            )

        self._shutdown()


if __name__ == "__main__":
    EBPFCollector().start()