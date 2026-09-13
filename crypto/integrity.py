"""QuantumGuard Phase 5 cryptographic integrity module.

The complete Phase 5 implementation intentionally lives here: canonical edge
hashing, Merkle proofs, deterministic partitions, encrypted Ed25519/ML-DSA
keys, hybrid signatures, evidence verification, JSON export, and the CLI.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import pickle
import secrets
import uuid
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from core import config
from core.store import get_store

GENESIS = "0" * 64
NODE_SEALED_ATTRS = ("type", "pid", "uid", "comm", "filename", "path", "timestamp", "sequence", "process_hash")
EDGE_SEALED_ATTRS = ("relation", "seq", "ts")
_ML_DSA_PARAMS = {"ML-DSA-44": "ML_DSA_44", "ML-DSA-65": "ML_DSA_65", "ML-DSA-87": "ML_DSA_87"}


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode("utf-8")


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _node_record(graph, node: Any) -> dict[str, Any]:
    return {"id": str(node), **{key: graph.nodes[node].get(key) for key in NODE_SEALED_ATTRS}}


def leaf_hash(graph, source: Any, target: Any) -> bytes:
    record = {"src": _node_record(graph, source), "dst": _node_record(graph, target),
              "edge": {key: graph.edges[source, target].get(key) for key in EDGE_SEALED_ATTRS}}
    return sha256(b"\x00QG-LEAF\x00" + canonical_json(record))


def record_hash(record: dict[str, Any]) -> str:
    excluded = {"record_hash", "ed25519_signature", "mldsa_signature", "ed25519_public_key",
                "mldsa_public_key", "mldsa_algorithm", "created_at", "leaf_hashes"}
    return sha256(b"\x00QG-RECORD\x00" + canonical_json({k: v for k, v in record.items() if k not in excluded})).hex()


def _merkle_leaf(value: bytes) -> bytes:
    return sha256(b"\x00" + value)


def _merkle_pair(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)


class MerkleTree:
    def __init__(self, leaves: list[bytes]):
        if not leaves:
            raise ValueError("Merkle tree needs at least one leaf")
        self.leaves = list(leaves)
        self.layers = [list(leaves)]
        layer = self.layers[0]
        while len(layer) > 1:
            if len(layer) % 2:
                layer = layer + [layer[-1]]
                self.layers[-1] = layer
            layer = [_merkle_pair(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
            self.layers.append(layer)

    @property
    def root(self) -> bytes:
        return self.layers[-1][0]

    @property
    def root_hex(self) -> str:
        return self.root.hex()

    def proof(self, index: int) -> list[dict[str, str]]:
        if not 0 <= index < len(self.leaves):
            raise IndexError(index)
        path, position = [], index
        for layer in self.layers[:-1]:
            sibling = position ^ 1
            if sibling >= len(layer):
                sibling = position
            path.append({"hash": layer[sibling].hex(), "position": "right" if sibling > position else "left"})
            position //= 2
        return path


def verify_proof(leaf: bytes, proof: list[dict[str, str]], root: bytes) -> bool:
    current = leaf
    for step in proof:
        sibling = bytes.fromhex(step["hash"])
        current = _merkle_pair(current, sibling) if step["position"] == "right" else _merkle_pair(sibling, current)
    return current == root


def ordered_edges(graph) -> list[tuple[Any, Any]]:
    edges = list(graph.edges(data=True))
    edges.sort(key=lambda item: (int(item[2].get("seq") or 0), int(item[2].get("ts") or 0),
                                 str(item[2].get("relation") or ""), str(item[0]), str(item[1])))
    return [(source, target) for source, target, _ in edges]


def partition_graph(graph, size: int | None = None) -> list[dict[str, Any]]:
    size = size or config.PARTITION_SIZE
    if size < 1:
        raise ValueError("partition size must be >= 1")
    parts = []
    for start in range(0, len(ordered_edges(graph)), size):
        chunk = ordered_edges(graph)[start:start + size]
        sequences = [int(graph.edges[u, v].get("seq") or 0) for u, v in chunk]
        parts.append({"index": len(parts), "edges": chunk, "seq_start": min(sequences), "seq_end": max(sequences)})
    return parts


class MLDSA:
    """ML-DSA adapter supporting liboqs or dilithium-py."""
    def __init__(self, algorithm: str = "ML-DSA-65"):
        if algorithm not in _ML_DSA_PARAMS:
            raise ValueError(f"unsupported ML-DSA parameter set: {algorithm}")
        self.algorithm, self.backend = algorithm, None
        try:
            import oqs
            self._oqs, self.backend = oqs, "liboqs"
        except Exception:
            try:
                import dilithium_py.ml_dsa as ml_dsa
                self._impl, self.backend = getattr(ml_dsa, _ML_DSA_PARAMS[algorithm]), "dilithium-py"
            except Exception as exc:
                raise ImportError("Install 'dilithium-py' or 'liboqs-python' to use ML-DSA") from exc

    def keygen(self) -> tuple[bytes, bytes]:
        if self.backend == "liboqs":
            signer = self._oqs.Signature(self.algorithm)
            public, private = signer.generate_keypair(), signer.export_secret_key()
            signer.free()
            return public, private
        return self._impl.keygen()

    def sign(self, private: bytes, message: bytes) -> bytes:
        if self.backend == "liboqs":
            signer = self._oqs.Signature(self.algorithm, private)
            signature = signer.sign(message)
            signer.free()
            return signature
        return self._impl.sign(private, message)

    def verify(self, public: bytes, message: bytes, signature: bytes) -> bool:
        try:
            if self.backend == "liboqs":
                verifier = self._oqs.Signature(self.algorithm)
                valid = verifier.verify(message, signature, public)
                verifier.free()
                return bool(valid)
            return bool(self._impl.verify(public, message, signature))
        except Exception:
            return False


class KeyStore:
    """Passphrase-encrypted local key store (a software-HSM simulation)."""
    VERSION = 1
    def __init__(self, path: str | None = None, passphrase: str | None = None):
        self.path = path or config.KEYSTORE
        self.passphrase = passphrase or config.KEYSTORE_PASSPHRASE
        self.ed_private = self.ed_public = self.mldsa = self.mldsa_public = self._mldsa_private = None

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def create(self, overwrite: bool = False):
        if self.exists() and not overwrite:
            raise FileExistsError(f"key store already exists: {self.path}")
        self.ed_private = Ed25519PrivateKey.generate()
        self.ed_public = self.ed_private.public_key()
        self.mldsa = MLDSA(config.MLDSA)
        self.mldsa_public, self._mldsa_private = self.mldsa.keygen()
        self._write()
        return self

    def load_or_create(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        return self.load() if self.exists() else self.create()

    def load(self):
        blob = json.loads(Path(self.path).read_text(encoding="utf-8"))
        if blob.get("version") != self.VERSION:
            raise ValueError("unsupported key store version")
        kdf = blob["kdf"]
        aes = AESGCM(Scrypt(salt=base64.b64decode(kdf["salt"]), length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(self.passphrase.encode()))
        try:
            ed_raw = aes.decrypt(base64.b64decode(blob["ed25519"]["nonce"]), base64.b64decode(blob["ed25519"]["ciphertext"]), b"QG-ED25519")
            pq_raw = aes.decrypt(base64.b64decode(blob["mldsa"]["nonce"]), base64.b64decode(blob["mldsa"]["ciphertext"]), b"QG-MLDSA")
        except Exception as exc:
            raise ValueError("key store could not be unlocked") from exc
        self.ed_private, self.ed_public = Ed25519PrivateKey.from_private_bytes(ed_raw), Ed25519PrivateKey.from_private_bytes(ed_raw).public_key()
        self.mldsa = MLDSA(blob["mldsa"]["algorithm"])
        self.mldsa_public, self._mldsa_private = base64.b64decode(blob["mldsa"]["public_key"]), pq_raw
        return self

    def _write(self) -> None:
        salt, n1, n2 = secrets.token_bytes(16), secrets.token_bytes(12), secrets.token_bytes(12)
        kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
        aes = AESGCM(kdf.derive(self.passphrase.encode()))
        ed_raw = self.ed_private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        b64 = lambda value: base64.b64encode(value).decode()
        blob = {"version": self.VERSION, "kdf": {"algorithm": "scrypt", "n": 2**15, "r": 8, "p": 1, "salt": b64(salt)},
                "ed25519": {"algorithm": "Ed25519", "public_key": b64(self.ed_public_bytes()), "nonce": b64(n1), "ciphertext": b64(aes.encrypt(n1, ed_raw, b"QG-ED25519"))},
                "mldsa": {"algorithm": self.mldsa.algorithm, "public_key": b64(self.mldsa_public), "nonce": b64(n2), "ciphertext": b64(aes.encrypt(n2, self._mldsa_private, b"QG-MLDSA"))}}
        Path(self.path).write_text(json.dumps(blob, indent=2), encoding="utf-8")
        os.chmod(self.path, 0o600)

    def ed_public_bytes(self) -> bytes:
        return self.ed_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def mldsa_private_bytes(self) -> bytes:
        return self._mldsa_private

    def summary(self) -> dict[str, Any]:
        return {"path": self.path, "ed25519_public_key": self.ed_public_bytes().hex(), "mldsa_algorithm": self.mldsa.algorithm, "mldsa_backend": self.mldsa.backend}


def _signing_message(payload: str, ed_public: bytes, algorithm: str, pq_public: bytes) -> bytes:
    header = canonical_json({"domain": "QuantumGuard/hybrid-signature/v1", "payload": payload,
                             "ed25519_pk": ed_public.hex(), "mldsa_alg": algorithm, "mldsa_pk": sha256(pq_public).hex()})
    return b"QuantumGuard/hybrid-signature/v1\x00" + header


class DualSigner:
    def __init__(self, keystore: KeyStore | None = None):
        self.ks = keystore or KeyStore().load_or_create()

    def sign(self, payload: str) -> dict[str, str]:
        ed_public, message = self.ks.ed_public_bytes(), _signing_message(payload, self.ks.ed_public_bytes(), self.ks.mldsa.algorithm, self.ks.mldsa_public)
        return {"ed25519_public_key": ed_public.hex(), "ed25519_signature": self.ks.ed_private.sign(message).hex(),
                "mldsa_algorithm": self.ks.mldsa.algorithm, "mldsa_public_key": self.ks.mldsa_public.hex(),
                "mldsa_signature": self.ks.mldsa.sign(self.ks.mldsa_private_bytes(), message).hex()}


class DualVerifier:
    def __init__(self, expected_ed_public_key: str | None = None):
        self.expected = expected_ed_public_key

    def verify(self, payload: str, record: dict[str, Any]) -> dict[str, Any]:
        result = {"ed25519_ok": False, "mldsa_ok": False, "key_trusted": True, "ok": False, "reason": None}
        try:
            ed_public = bytes.fromhex(record["ed25519_public_key"])
            pq_public = bytes.fromhex(record["mldsa_public_key"])
            algorithm = record["mldsa_algorithm"]
            if self.expected and self.expected != record["ed25519_public_key"]:
                result.update(key_trusted=False, reason="signed by an unexpected key")
                return result
            message = _signing_message(payload, ed_public, algorithm, pq_public)
            Ed25519PublicKey.from_public_bytes(ed_public).verify(bytes.fromhex(record["ed25519_signature"]), message)
            result["ed25519_ok"] = True
            result["mldsa_ok"] = MLDSA(algorithm).verify(pq_public, message, bytes.fromhex(record["mldsa_signature"]))
            result["ok"] = result["ed25519_ok"] and result["mldsa_ok"]
            if not result["ok"]:
                result["reason"] = "ML-DSA signature invalid"
        except (KeyError, ValueError, InvalidSignature) as exc:
            result["reason"] = f"malformed or invalid signature: {exc}"
        return result


class IntegrityService:
    def __init__(self, keystore: KeyStore | None = None, store=None, partition_size: int | None = None):
        self.ks, self.signer = (keystore or KeyStore()).load_or_create(), None
        self.signer, self.store = DualSigner(self.ks), store or get_store()
        self.partition_size = partition_size or config.PARTITION_SIZE

    def seal(self, graph, run_id: str | None = None, risk_tier_hint: str = "tier3_local", persist: bool = True) -> list[dict[str, Any]]:
        parts = partition_graph(graph, self.partition_size)
        if not parts:
            raise ValueError("graph has no relations to seal")
        previous, records, run_id = GENESIS, [], run_id or str(uuid.uuid4())
        for part in parts:
            leaves = [_merkle_leaf(leaf_hash(graph, u, v)) for u, v in part["edges"]]
            record = {"run_id": run_id, "partition_index": part["index"], "seq_start": part["seq_start"], "seq_end": part["seq_end"],
                      "leaf_count": len(leaves), "merkle_root": MerkleTree(leaves).root_hex, "prev_record_hash": previous, "risk_tier_hint": risk_tier_hint}
            record["record_hash"] = record_hash(record)
            record.update(self.signer.sign(record["record_hash"]))
            record["leaf_hashes"], record["created_at"] = [leaf.hex() for leaf in leaves], dt.datetime.now(dt.timezone.utc).isoformat()
            records.append(record)
            previous = record["record_hash"]
        if persist:
            self.store.save_partitions(records)
        return records

    def inclusion_proof(self, graph, source: Any, target: Any, records: list[dict[str, Any]] | None = None, run_id: str | None = None):
        target_hash = _merkle_leaf(leaf_hash(graph, source, target)).hex()
        for record in records or self.store.load_partitions(run_id):
            leaves = record.get("leaf_hashes", [])
            if target_hash in leaves:
                index, tree = leaves.index(target_hash), MerkleTree([bytes.fromhex(item) for item in leaves])
                return {key: record[key] for key in ("run_id", "partition_index", "merkle_root", "record_hash", "ed25519_signature", "mldsa_signature", "ed25519_public_key", "mldsa_public_key", "mldsa_algorithm")} | {"leaf_index": index, "leaf": target_hash, "path": tree.proof(index)}
        return None


class VerificationReport:
    def __init__(self):
        self.partitions, self.errors, self.inserted, self.missing_leaf_count = [], [], [], 0
    @property
    def ok(self): return not self.errors
    def as_dict(self): return {"ok": self.ok, "partition_count": len(self.partitions), "errors": self.errors, "inserted_relations": self.inserted, "missing_leaf_count": self.missing_leaf_count, "partitions": self.partitions}
    def __str__(self):
        return "QuantumGuard verification: " + ("PASS" if self.ok else "FAIL") + f" ({len(self.partitions)} partitions)" + ("\n" + "\n".join(self.errors) if self.errors else "")


class EvidenceVerifier:
    def __init__(self, store=None, expected_ed_public_key: str | None = None):
        self.store, self.dual = store or get_store(), DualVerifier(expected_ed_public_key)

    def verify(self, graph=None, run_id: str | None = None, records: list[dict[str, Any]] | None = None, partition_size: int | None = None) -> VerificationReport:
        report, records = VerificationReport(), records if records is not None else self.store.load_partitions(run_id)
        if not records:
            report.errors.append("no sealed partitions found for this run")
            return report
        live = None if graph is None else {_merkle_leaf(leaf_hash(graph, u, v)).hex(): f"{u} -> {v}" for u, v in ordered_edges(graph)}
        previous = GENESIS
        for expected, record in enumerate(sorted(records, key=lambda item: item["partition_index"])):
            leaves = record.get("leaf_hashes", [])
            try: root_ok = MerkleTree([bytes.fromhex(item) for item in leaves]).root_hex == record.get("merkle_root")
            except ValueError: root_ok = False
            signature = self.dual.verify(record.get("record_hash", ""), record)
            entry = {"partition_index": record["partition_index"], "seq_start": record["seq_start"], "seq_end": record["seq_end"], "signature_ok": signature["ok"], "record_hash_ok": record_hash(record) == record.get("record_hash"), "chain_ok": record["partition_index"] == expected and record.get("prev_record_hash") == previous, "merkle_ok": root_ok if live is None else root_ok and set(leaves).issubset(live), "tampered_leaves": []}
            if live is not None:
                entry["tampered_leaves"] = [{"leaf_index": index, "detail": "sealed relation is missing or was edited"} for index, value in enumerate(leaves) if value not in live]
                report.missing_leaf_count += len(entry["tampered_leaves"])
            report.partitions.append(entry)
            report.errors.extend(f"partition {record['partition_index']}: {flag} failed" for flag, passed in entry.items() if flag.endswith("_ok") and not passed)
            previous = record.get("record_hash", "")
        if live is not None:
            sealed = {item for record in records for item in record.get("leaf_hashes", [])}
            report.inserted = sorted(name for value, name in live.items() if value not in sealed)
            if report.inserted: report.errors.append(f"{len(report.inserted)} unsealed relation(s) found in graph")
        return report

    def verify_inclusion(self, proof: dict[str, Any]) -> dict[str, Any]:
        path_ok = verify_proof(bytes.fromhex(proof["leaf"]), proof["path"], bytes.fromhex(proof["merkle_root"]))
        signature = self.dual.verify(proof["record_hash"], proof)
        return {"path_ok": path_ok, "signature_ok": signature["ok"], "ok": path_ok and signature["ok"], "signature_detail": signature}


def export_evidence(records: list[dict[str, Any]], path: str | Path) -> Path:
    """Write portable, self-contained sealed evidence for archival or transfer."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"format": "quantumguard-sealed-graph-v1", "partitions": records}, indent=2) + "\n", encoding="utf-8")
    return output


def load_evidence(path: str | Path) -> list[dict[str, Any]]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if document.get("format") != "quantumguard-sealed-graph-v1":
        raise ValueError("not a QuantumGuard sealed-evidence file")
    return document["partitions"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seal and verify a QuantumGuard provenance graph")
    parser.add_argument("--graph", default="graphs/provenance_graph.gpickle")
    parser.add_argument("--output", default="evidence/sealed_graph.json")
    parser.add_argument("--partition-size", type=int, default=config.PARTITION_SIZE)
    parser.add_argument("--run-id")
    args = parser.parse_args(argv)
    with open(args.graph, "rb") as handle: graph = pickle.load(handle)
    service = IntegrityService(partition_size=args.partition_size)
    records = service.seal(graph, args.run_id)
    output = export_evidence(records, args.output)
    report = EvidenceVerifier(store=service.store).verify(graph, records=records)
    print(f"Evidence   : {output}\nPartitions : {len(records)}\nVerified   : {report.ok}\nSignature  : {'Valid' if all(item['signature_ok'] for item in report.partitions) else 'Invalid'}\nMerkle     : {'Valid' if all(item['merkle_ok'] for item in report.partitions) else 'Invalid'}\nChain      : {'Valid' if all(item['chain_ok'] for item in report.partitions) else 'Invalid'}")
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
