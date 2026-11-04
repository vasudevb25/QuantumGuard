"""
Phase 1 - Capture Completeness Attestation.

Every collector loses events when the machine is busy; that is a
consequence of bounded ring-buffer capacity, not a defect. What no
reported system does is emit evidence that a given range of events was
captured in full. Without that evidence, an investigator who finds
sequence 47 missing cannot distinguish two very different situations:

    the collector dropped it under load      - noise
    somebody removed it after capture        - a cover-up

CCA makes that distinction decidable. Every event is assigned a
monotonic sequence number at the moment it leaves the ring buffer, and
any discontinuity is recorded as an attestation before anything else is
done with the event. Downstream, rule R7 in detection/detector.py
subtracts the attested set from the observed gaps: what remains is
unexplained, and unexplained absence is deletion.

Two properties this file adds beyond gap detection
--------------------------------------------------

**Continuity across restarts.** A counter that resets to 1 whenever the
collector restarts can only attest within one session, and it silently
collides with sequence numbers already in the database. `SessionManager`
resumes from the highest sequence already stored and records the
restart itself as a `SESSION_GAP` attestation, so the discontinuity
between two sessions is documented rather than inferred.

**Signature.** A gap record that is only checkable locally is a log
entry, not an attestation - an attestation is something a third party
can verify without trusting the host that produced it.
`CompletenessCertificate` covers a whole sequence range, names every
gap inside it, and is signed with Ed25519 and ML-DSA through the same
Phase 5 key store. A verifier with the public key can confirm what the
collector asserted about completeness, and can detect any later edit to
that assertion.
"""

from __future__ import annotations

import datetime as dt
import json
import socket
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


@dataclass
class Attestation:
    """One statement about whether a stretch of sequence arrived intact."""

    complete: bool
    expected: int
    received: int
    missing: list[int]
    run_id: str | None = None
    reason: str = "gap"          # "gap" | "session_gap"
    recorded_at: str = field(default_factory=_now)


class SessionManager:
    """Allocates a capture session and keeps sequence numbers continuous.

    Two collector runs against the same database must not both start at
    sequence 1: `raw_events.sequence` is the primary key, so the second
    run would collide with the first, and completeness could only ever
    be claimed within a single session.
    """

    def __init__(self, store=None, run_id: str | None = None):
        self.store = store
        self.run_id = run_id or str(uuid.uuid4())
        self.host = socket.gethostname()
        self.resumed_from = 0
        self.started_at = _now()

    def resume_point(self) -> int:
        """Highest sequence already stored, or 0 for a fresh database."""
        if self.store is None:
            return 0
        try:
            events = self.store.load_events()
        except Exception:                       # pragma: no cover
            return 0
        if not events:
            return 0
        self.resumed_from = max(int(event.get("sequence") or 0)
                                for event in events)
        return self.resumed_from

    def open(self) -> Attestation | None:
        """Begin the session. Returns a SESSION_GAP attestation on restart.

        The gap between two sessions is real: events occurring while the
        collector was down were never captured. Recording it as an
        explicit attestation is what stops that silence being read later
        as deletion.
        """
        start = self.resume_point()
        if hasattr(self.store, "save_session"):
            try:
                self.store.save_session({
                    "run_id": self.run_id, "host": self.host,
                    "started_at": self.started_at, "ended_at": None,
                    "last_sequence": start,
                })
            except Exception:                   # pragma: no cover
                pass

        if start == 0:
            return None

        return Attestation(
            complete=False, expected=start + 1, received=start + 1,
            missing=[], run_id=self.run_id, reason="session_gap",
        )

    def close(self, last_sequence: int) -> None:
        if hasattr(self.store, "save_session"):
            try:
                self.store.save_session({
                    "run_id": self.run_id, "host": self.host,
                    "started_at": self.started_at, "ended_at": _now(),
                    "last_sequence": last_sequence,
                })
            except Exception:                   # pragma: no cover
                pass


class CCA:
    """Detects sequence discontinuities and summarises them for signing."""

    def __init__(self, run_id: str | None = None, start: int = 0):
        self.last = start
        self.run_id = run_id
        self.first_seen = start + 1 if start else 0
        self.observed = 0
        self.missing: list[int] = []

    def verify(self, seq: int) -> Attestation:
        """Check one sequence number against the one before it."""
        self.observed += 1
        if self.first_seen == 0:
            self.first_seen = seq

        if self.last == 0:
            self.last = seq
            return Attestation(True, seq, seq, [], self.run_id)

        expected = self.last + 1
        if seq == expected:
            self.last = seq
            return Attestation(True, expected, seq, [], self.run_id)

        missing = list(range(expected, seq))
        self.missing.extend(missing)
        self.last = seq
        return Attestation(False, expected, seq, missing, self.run_id)

    # ------------------------------------------------------------------

    def certificate(self, signer=None) -> dict[str, Any]:
        """A signed statement about completeness over the whole session.

        This is what makes CCA an attestation rather than a local check.
        The certificate names the range covered, how many events were
        observed inside it, and exactly which sequence numbers were
        attested as lost. Anyone holding the public key can verify both
        that the collector made this statement and that nobody has
        edited it since.
        """
        body = {
            "format": "quantumguard-completeness-v1",
            "run_id": self.run_id,
            "seq_start": self.first_seen,
            "seq_end": self.last,
            "events_observed": self.observed,
            "attested_missing": sorted(set(self.missing)),
            "complete": not self.missing,
            "issued_at": _now(),
        }
        payload = _digest(body)
        certificate = {"body": body, "payload_hash": payload}

        if signer is None:
            try:
                from crypto.integrity import DualSigner
                signer = DualSigner()
            except Exception as exc:            # pragma: no cover
                certificate["unsigned_reason"] = str(exc)
                return certificate

        certificate.update(signer.sign(payload))
        return certificate


def _digest(body: dict[str, Any]) -> str:
    import hashlib
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, default=str).encode("utf-8")
    return hashlib.sha256(b"\x04QG-CCA-CERT\x00" + encoded).hexdigest()


def verify_certificate(certificate: dict[str, Any]) -> dict[str, Any]:
    """Verify a completeness certificate without trusting its source."""
    from crypto.integrity import DualVerifier

    body = certificate.get("body", {})
    recomputed = _digest(body)
    payload_ok = recomputed == certificate.get("payload_hash")

    signature = DualVerifier().verify(certificate.get("payload_hash", ""),
                                      certificate)
    return {
        "ok": payload_ok and signature["ok"],
        "payload_ok": payload_ok,
        "signature_ok": signature["ok"],
        "reason": None if payload_ok else "certificate body was edited",
        "attested_missing": body.get("attested_missing", []),
        "range": (body.get("seq_start"), body.get("seq_end")),
    }


def save_certificate(certificate: dict[str, Any],
                     path: str | Path) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(certificate, indent=2) + "\n",
                      encoding="utf-8")
    return output
