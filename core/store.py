"""Unified persistence boundary for QuantumGuard.

All phases use :func:`get_store` rather than importing PostgreSQL helpers
directly. ``QG_STORE=file`` provides an offline JSON backend; ``db`` uses the
project PostgreSQL schema; and ``auto`` falls back to files when PostgreSQL is
unavailable.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

from core import config


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if dataclasses.is_dataclass(value):
        # capture/models.py's RawEvent is a `slots=True` dataclass, which
        # has no `__dict__` - vars() raises TypeError on it. dataclasses.
        # asdict() works for slotted and unslotted dataclasses alike.
        return dataclasses.asdict(value)
    return dict(vars(value))


class FileStore:
    """Portable JSON evidence backend, useful for demos and local testing."""
    kind = "file"

    def __init__(self, directory: str | Path | None = None):
        self.directory = Path(directory or config.EVIDENCE_DIR)
        self.directory.mkdir(parents=True, exist_ok=True)

    def _append(self, name: str, item: dict[str, Any]) -> None:
        with (self.directory / name).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(item, default=str, sort_keys=True) + "\n")

    def _read(self, name: str) -> list[dict[str, Any]]:
        path = self.directory / name
        if not path.exists():
            return []
        content = path.read_text(encoding="utf-8").strip()
        if not content:
            return []
        # Partition snapshots are a JSON array so they can be atomically
        # replaced; event and report streams remain JSON Lines.
        if content.startswith("["):
            return json.loads(content)
        return [json.loads(line) for line in content.splitlines()]

    def save_event(self, event: Any) -> None:
        self._append("raw_events.jsonl", _as_dict(event))

    def load_events(self) -> list[dict[str, Any]]:
        """Every captured event, oldest first - what graph/service.py
        builds the provenance graph from when QG_STORE is file/auto."""
        return sorted(self._read("raw_events.jsonl"), key=lambda e: e.get("sequence", 0))

    def save_attestation(self, attestation: Any) -> None:
        data = _as_dict(attestation)
        if not data.get("complete", False):
            self._append("cca_attestation.jsonl", data)

    def load_missing_sequences(self) -> set[int]:
        """Union of every sequence number CCA ever attested as lost. Feeds
        detection.detector.RuleEngine so a capture-side gap the CCA layer
        already explained is never reported as tampering (sequence_gap)."""
        missing: set[int] = set()
        for record in self._read("cca_attestation.jsonl"):
            missing.update(record.get("missing") or [])
        return missing

    def save_partitions(self, records: list[dict[str, Any]]) -> None:
        path = self.directory / "graph_partitions.json"
        existing = {(item["run_id"], item["partition_index"]): item for item in self._read(path.name)}
        for record in records:
            existing[(record["run_id"], record["partition_index"])] = record
        path.write_text(json.dumps(list(existing.values()), indent=2, default=str) + "\n", encoding="utf-8")

    def load_partitions(self, run_id: str | None = None) -> list[dict[str, Any]]:
        records = self._read("graph_partitions.json")
        if run_id is not None:
            records = [record for record in records if record.get("run_id") == run_id]
        return sorted(records, key=lambda record: record["partition_index"])

    def save_report(self, report: dict[str, Any]) -> None:
        self._append("detection_reports.jsonl", report)

    save_detection_report = save_report

    def load_reports(self, run_id: str | None = None) -> list[dict[str, Any]]:
        reports = self._read("detection_reports.jsonl")
        return reports if run_id is None else [report for report in reports if report.get("run_id") == run_id]


class PostgreSQLStore:
    """PostgreSQL implementation backed by ``database/schema*.sql``."""
    kind = "postgresql"

    def __init__(self, url: str | None = None):
        from sqlalchemy import create_engine, text
        self._text = text
        self.engine = create_engine(url or config.DATABASE_URL, future=True)

    def save_event(self, event: Any) -> None:
        data = _as_dict(event)
        with self.engine.begin() as connection:
            connection.execute(self._text("""INSERT INTO raw_events
                (sequence, timestamp, pid, uid, comm, filename, event_type)
                VALUES (:sequence, :timestamp, :pid, :uid, :comm, :filename, :event_type)"""), data)

    def load_events(self) -> list[dict[str, Any]]:
        """Every captured event, oldest first - what graph/service.py
        builds the provenance graph from."""
        with self.engine.begin() as connection:
            rows = connection.execute(
                self._text("SELECT * FROM raw_events ORDER BY sequence")
            ).mappings()
            return [dict(row) for row in rows]

    def save_attestation(self, attestation: Any) -> None:
        data = _as_dict(attestation)
        if data.get("complete", False):
            return
        data["missing"] = json.dumps(data.get("missing", []))
        with self.engine.begin() as connection:
            connection.execute(self._text("""INSERT INTO cca_attestation
                (expected, received, complete, missing_sequences)
                VALUES (:expected, :received, false, CAST(:missing AS JSONB))"""), data)

    def load_missing_sequences(self) -> set[int]:
        """Union of every sequence number CCA ever attested as lost. Feeds
        detection.detector.RuleEngine so a capture-side gap the CCA layer
        already explained is never reported as tampering (sequence_gap)."""
        with self.engine.begin() as connection:
            rows = connection.execute(self._text(
                "SELECT missing_sequences FROM cca_attestation WHERE complete = false"
            )).scalars().all()
        missing: set[int] = set()
        for value in rows:
            data = json.loads(value) if isinstance(value, str) else (value or [])
            missing.update(data)
        return missing

    def save_partitions(self, records: list[dict[str, Any]]) -> None:
        sql = self._text("""INSERT INTO graph_partitions
            (run_id, partition_index, seq_start, seq_end, leaf_count, merkle_root,
             prev_record_hash, record_hash, risk_tier_hint, ed25519_public_key,
             ed25519_signature, mldsa_algorithm, mldsa_public_key, mldsa_signature,
             leaf_hashes, created_at)
            VALUES (:run_id, :partition_index, :seq_start, :seq_end, :leaf_count,
             :merkle_root, :prev_record_hash, :record_hash, :risk_tier_hint,
             :ed25519_public_key, :ed25519_signature, :mldsa_algorithm,
             :mldsa_public_key, :mldsa_signature, CAST(:leaf_hashes AS JSONB), :created_at)
            ON CONFLICT (run_id, partition_index) DO UPDATE SET
             record_hash=EXCLUDED.record_hash, merkle_root=EXCLUDED.merkle_root,
             leaf_hashes=EXCLUDED.leaf_hashes, created_at=EXCLUDED.created_at""")
        with self.engine.begin() as connection:
            for record in records:
                data = dict(record)
                data["leaf_hashes"] = json.dumps(data["leaf_hashes"])
                connection.execute(sql, data)

    def load_partitions(self, run_id: str | None = None) -> list[dict[str, Any]]:
        statement = "SELECT * FROM graph_partitions"
        parameters: dict[str, Any] = {}
        if run_id is not None:
            statement += " WHERE run_id = :run_id"
            parameters["run_id"] = run_id
        statement += " ORDER BY partition_index"
        with self.engine.begin() as connection:
            records = [dict(row) for row in connection.execute(self._text(statement), parameters).mappings()]
        for record in records:
            if isinstance(record.get("leaf_hashes"), str):
                record["leaf_hashes"] = json.loads(record["leaf_hashes"])
        return records

    def save_report(self, report: dict[str, Any]) -> None:
        data = dict(report)
        data["detail"] = json.dumps(data.get("detail", {}))
        with self.engine.begin() as connection:
            connection.execute(self._text("""INSERT INTO detection_reports
                (run_id, created_at, tampered, rule_violation_count, gnn_flagged_nodes,
                 graph_nodes, graph_edges, detail)
                VALUES (:run_id, :created_at, :tampered, :rule_violation_count,
                 :gnn_flagged_nodes, :graph_nodes, :graph_edges, CAST(:detail AS JSONB))"""), data)

    save_detection_report = save_report

    def load_reports(self, run_id: str | None = None) -> list[dict[str, Any]]:
        statement, parameters = "SELECT * FROM detection_reports", {}
        if run_id is not None:
            statement += " WHERE run_id = :run_id"
            parameters["run_id"] = run_id
        with self.engine.begin() as connection:
            records = [dict(row) for row in connection.execute(self._text(statement), parameters).mappings()]
        for record in records:
            if isinstance(record.get("detail"), str):
                record["detail"] = json.loads(record["detail"])
        return records


_store = None


def get_store():
    """Return the configured singleton store without leaking backend details."""
    global _store
    if _store is not None:
        return _store
    backend = config.STORE_BACKEND.lower()
    if backend == "file":
        _store = FileStore()
    elif backend == "db":
        _store = PostgreSQLStore()
    elif backend == "auto":
        try:
            candidate = PostgreSQLStore()
            with candidate.engine.connect():
                pass
            _store = candidate
        except Exception:
            _store = FileStore()
    else:
        raise ValueError("QG_STORE must be one of: db, file, auto")
    return _store
