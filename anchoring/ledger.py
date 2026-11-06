"""
Phase 6b - the external anchor.

An anchor is a copy of a partition's fingerprint held somewhere the
attacker on the monitored host cannot reach. Signing proves evidence was
not *edited*; anchoring is what survives the evidence being *destroyed*.
Those are different guarantees and the project needs both: an adversary
at root can delete the entire local archive, signatures included, and a
hash chain that only exists on the wiped machine proves nothing
afterwards.

What is implemented here
------------------------
`LocalLedger` is an append-only, hash-chained, dual-signed ledger stored
outside the evidence directory. It provides the properties anchoring
actually depends on:

  * append-only    - blocks are only ever added, never rewritten
  * chained        - each block carries its predecessor's hash, so
                     removing or reordering a block is detectable
  * signed         - each block is signed with Ed25519 and ML-DSA, so a
                     block cannot be forged by whoever holds the file
  * independently   - `verify()` reconstructs the whole chain from the
    verifiable        file alone, with no access to the host's evidence

What is NOT implemented, stated plainly
---------------------------------------
This is a LOCAL ledger. It simulates the anchoring semantics of a
permissioned blockchain; it does not provide the property a real
distributed ledger provides, which is that no single party can rewrite
history because no single party holds it. An attacker with root on this
host and the key store passphrase could discard this file and forge a
replacement chain.

Deploying against a real Hyperledger Fabric network closes that gap and
changes nothing else: `FabricLedger` below implements the same four-method
interface, and `anchoring/service.py` depends only on that interface. The
Fabric client itself is intentionally left as a stub rather than faked.

The honest summary for a reviewer: the anchoring *policy*, the *risk
model* that drives it, and the *batching construction* are implemented
and testable. The external trust root is simulated.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any, Protocol

from core import config

GENESIS = "0" * 64


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _block_hash(block: dict[str, Any]) -> str:
    """Hash of a block, excluding its own hash and signature fields."""
    payload = {key: value for key, value in block.items()
               if key not in ("block_hash", "ed25519_signature",
                              "mldsa_signature", "ed25519_public_key",
                              "mldsa_public_key", "mldsa_algorithm")}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, default=str).encode("utf-8")
    return hashlib.sha256(b"\x03QG-LEDGER-BLOCK\x00" + encoded).hexdigest()


class Ledger(Protocol):
    """The four operations anchoring/service.py requires of any ledger."""

    def anchor(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Append one anchor and return its receipt."""

    def receipts(self) -> list[dict[str, Any]]:
        """Every receipt issued so far, in order."""

    def lookup(self, merkle_root: str) -> dict[str, Any] | None:
        """Find the receipt anchoring a given root, if any."""

    def verify(self, verifier=None) -> dict[str, Any]:
        """Re-verify the whole chain independently."""


class LocalLedger:
    """Append-only, hash-chained, dual-signed local ledger."""

    FORMAT = "quantumguard-ledger-v1"

    def __init__(self, path: str | Path | None = None, signer=None):
        self.path = Path(path or config.LEDGER_PATH)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._signer = signer
        self._blocks: list[dict[str, Any]] = self._read()

    # ------------------------------------------------------------------

    @property
    def signer(self):
        # Deferred so that constructing a ledger never forces a key store
        # to be created - `verify` and `receipts` work without keys.
        if self._signer is None:
            from crypto.integrity import DualSigner
            self._signer = DualSigner()
        return self._signer

    def _read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        text = self.path.read_text(encoding="utf-8").strip()
        if not text:
            return []
        document = json.loads(text)
        if document.get("format") != self.FORMAT:
            raise ValueError(f"not a QuantumGuard ledger: {self.path}")
        return document.get("blocks", [])

    def _write(self) -> None:
        document = {"format": self.FORMAT, "blocks": self._blocks}
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(document, indent=2) + "\n",
                             encoding="utf-8")
        os.replace(temporary, self.path)

    # ------------------------------------------------------------------

    def anchor(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Append one anchor block and return its receipt.

        `payload` carries what is being anchored - a partition's Merkle
        root for a Tier-1 anchor, or a second-order batch root for
        Tier-2. The block never contains the evidence itself, only its
        fingerprint, so the ledger leaks nothing about what was captured.
        """
        previous = self._blocks[-1]["block_hash"] if self._blocks else GENESIS

        block = {
            "block_number": len(self._blocks),
            "transaction_id": uuid.uuid4().hex,
            "timestamp": _now(),
            "prev_block_hash": previous,
            "payload": payload,
        }
        block["block_hash"] = _block_hash(block)
        block.update(self.signer.sign(block["block_hash"]))

        self._blocks.append(block)
        self._write()

        return {
            "ledger": "local",
            "block_number": block["block_number"],
            "transaction_id": block["transaction_id"],
            "block_hash": block["block_hash"],
            "timestamp": block["timestamp"],
            "anchored": payload,
        }

    def receipts(self) -> list[dict[str, Any]]:
        return [
            {
                "ledger": "local",
                "block_number": block["block_number"],
                "transaction_id": block["transaction_id"],
                "block_hash": block["block_hash"],
                "timestamp": block["timestamp"],
                "anchored": block["payload"],
            }
            for block in self._blocks
        ]

    def lookup(self, merkle_root: str) -> dict[str, Any] | None:
        """Find the receipt whose payload anchors this root.

        Tier-1 anchors name the root directly; Tier-2 anchors name a
        batch root and list the member roots underneath it.
        """
        for receipt in self.receipts():
            payload = receipt["anchored"]
            if payload.get("merkle_root") == merkle_root:
                return receipt
            if merkle_root in payload.get("member_roots", []):
                return receipt
        return None

    def verify(self, verifier=None) -> dict[str, Any]:
        """Re-verify every block: hash, chain linkage, both signatures.

        Pass a pinned DualVerifier; without one, a chain rebuilt and re-signed
        with an attacker's own key also verifies.
        """
        from crypto.integrity import DualVerifier

        verifier = verifier or DualVerifier()
        errors: list[str] = []
        previous = GENESIS

        for position, block in enumerate(self._blocks):
            if block.get("block_number") != position:
                errors.append(f"block {position}: out of order or missing")

            if _block_hash(block) != block.get("block_hash"):
                errors.append(f"block {position}: contents do not match "
                              f"their recorded hash")

            if block.get("prev_block_hash") != previous:
                errors.append(f"block {position}: broken chain - a block "
                              f"was removed, reordered or inserted")

            signature = verifier.verify(block.get("block_hash", ""), block)
            if not signature["ok"]:
                errors.append(f"block {position}: signature invalid "
                              f"({signature.get('reason')})")

            previous = block.get("block_hash", "")

        return {
            "ok": not errors,
            "blocks": len(self._blocks),
            "errors": errors,
            "path": str(self.path),
        }


class FabricLedger:
    """Hyperledger Fabric anchor - interface only, intentionally not faked.

    A deployment replaces LocalLedger with this class and nothing else
    changes: anchoring/service.py depends only on the four methods of the
    Ledger protocol above.

    Implementing it requires a running Fabric network, a channel, the
    chaincode that stores (merkle_root -> transaction) pairs, and an
    enrolled identity under `fabric-sdk-py` or the Fabric Gateway. None
    of that is available in this project's environment, so the methods
    raise rather than return fabricated transaction identifiers - a
    simulated receipt that looks like a real Fabric transaction would be
    worse than an honest failure.
    """

    def __init__(self, channel: str = "provenance",
                 chaincode: str = "qganchor", **connection: Any):
        self.channel, self.chaincode, self.connection = channel, chaincode, connection

    def _unavailable(self):
        raise NotImplementedError(
            "FabricLedger requires a running Hyperledger Fabric network "
            "(channel, chaincode and an enrolled identity). Use LocalLedger "
            "for local operation; see anchoring/ledger.py for what the "
            "local ledger does and does not guarantee."
        )

    def anchor(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._unavailable()

    def receipts(self) -> list[dict[str, Any]]:
        self._unavailable()

    def lookup(self, merkle_root: str) -> dict[str, Any] | None:
        self._unavailable()

    def verify(self, verifier=None) -> dict[str, Any]:
        self._unavailable()


def get_ledger(kind: str | None = None, **kwargs: Any) -> Ledger:
    """Construct the configured ledger. 'local' (default) or 'fabric'."""
    kind = (kind or config.LEDGER_BACKEND).lower()
    if kind == "fabric":
        return FabricLedger(**kwargs)
    if kind == "local":
        return LocalLedger(**kwargs)
    raise ValueError(f"unknown ledger backend: {kind}")
