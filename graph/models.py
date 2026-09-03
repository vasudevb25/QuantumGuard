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
    parent_pid: int | None = None
    process_hash: str | None = None