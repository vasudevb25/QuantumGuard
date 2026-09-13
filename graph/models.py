from dataclasses import dataclass

@dataclass(slots=True)
class ProvenanceEvent:
    sequence: int
    timestamp: int
    pid: int
    uid: int
    comm: str
    filename: str
    event_type: int

    process_id: str | None = None
    process_hash: str | None = None

    parent_node: str | None = None
    parent_pid: int | None = None
    parent_kind: str | None = None