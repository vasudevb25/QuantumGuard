from sqlalchemy import create_engine, text

DATABASE_URL = (
    "postgresql+psycopg2://quantumguard:"
    "StrongPassword123@localhost/provenance"
)

engine = create_engine(DATABASE_URL, future=True)


def save_event(event):
    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO raw_events
                (sequence, timestamp, pid, uid, comm, filename, event_type)
                VALUES
                (:sequence, :timestamp, :pid, :uid, :comm, :filename, :event_type)
            """),
            {
                "sequence": event.sequence,
                "timestamp": event.timestamp,
                "pid": event.pid,
                "uid": event.uid,
                "comm": event.comm,
                "filename": event.filename,
                "event_type": event.event_type,
            },
        )


def save_attestation(att):
    if att.complete:
        return

    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO cca_attestation
                (expected, received, complete, missing_sequences)
                VALUES
                (:expected, :received, :complete, :missing)
            """),
            {
                "expected": att.expected,
                "received": att.received,
                "complete": False,
                "missing": str(att.missing),
            },
        )