from sqlalchemy import create_engine, text
from graph.models import ProvenanceEvent
import hashlib
import networkx as nx
import pickle
import os

class ProvenanceGraphService:

    WINDOW_NS = 2_000_000

    def __init__(self):

        self.engine = create_engine(
            "postgresql+psycopg2://quantumguard:StrongPassword123@localhost/provenance",
            future=True
        )

    # -------------------------
    # Load
    # -------------------------

    def load_events(self):

        with self.engine.begin() as conn:

            rows = conn.execute(text("""
                SELECT *
                FROM raw_events
                ORDER BY sequence
            """))

            return [
                ProvenanceEvent(
                    sequence=r.sequence,
                    timestamp=r.timestamp,
                    pid=r.pid,
                    uid=r.uid,
                    comm=r.comm,
                    filename=r.filename,
                    event_type=r.event_type
                )
                for r in rows
            ]

    # -------------------------
    # Normalize
    # -------------------------

    def deduplicate(self, events):

        cache = {}
        cleaned = []

        for e in events:

            key = (e.pid, e.filename)

            if key in cache:

                if e.timestamp - cache[key] < self.WINDOW_NS:
                    continue

            cache[key] = e.timestamp
            cleaned.append(e)

        return cleaned

    # -------------------------
    # Temporal validation
    # -------------------------

    def validate(self, events):

        valid = []

        previous_seq = 0
        previous_ts = 0

        for e in events:

            if e.sequence <= previous_seq:
                continue

            if e.timestamp < previous_ts:
                continue

            valid.append(e)

            previous_seq = e.sequence
            previous_ts = e.timestamp

        return valid

    # -------------------------
    # Enrichment
    # -------------------------

    def enrich(self, events):

        latest = {}

        for e in events:

            e.parent_pid = latest.get(e.uid)

            e.process_hash = hashlib.sha256(
                f"{e.pid}:{e.timestamp}:{e.comm}".encode()
            ).hexdigest()

            latest[e.uid] = e.pid

        return events

    # -------------------------
    # Build graph
    # -------------------------

    def build(self, events):

        G = nx.DiGraph()

        for e in events:

            process_id = e.process_hash
            file_id = f"F:{e.filename}"

            # Human readable labels
            process_label = f"{e.comm}\nPID {e.pid}"
            file_label = os.path.basename(e.filename)

            G.add_node(
                process_id,
                type="process",
                label=process_label,
                pid=e.pid,
                comm=e.comm
            )

            G.add_node(
                file_id,
                type="file",
                label=file_label,
                path=e.filename
            )

            G.add_edge(
                process_id,
                file_id,
                relation="EXECUTES",
                seq=e.sequence,
                ts=e.timestamp
            )

            if e.parent_pid:
                parent = f"P:{e.parent_pid}"

                G.add_node(
                    parent,
                    type="process",
                    label=f"PID {e.parent_pid}"
                )

                G.add_edge(
                    parent,
                    process_id,
                    relation="SPAWNS"
                )

        return G

    # -------------------------
    # Export
    # -------------------------

    def save(self, G):

        os.makedirs("graphs", exist_ok=True)

        with open("graphs/provenance_graph.gpickle","wb") as f:
            pickle.dump(G,f)

        nx.write_graphml(
            G,
            "graphs/provenance.graphml"
        )