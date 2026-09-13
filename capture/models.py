from dataclasses import dataclass

@dataclass(slots=True)
class RawEvent:
    timestamp: int
    pid: int
    uid: int
    comm: str
    filename: str
    event_type: int

    sequence: int = 0