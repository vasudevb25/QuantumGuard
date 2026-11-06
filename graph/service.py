"""
Phase 3 - provenance graph construction.

Pipeline: load_events -> deduplicate -> validate -> enrich -> build -> save.
Events come from core.store.get_store() (Postgres or the offline FileStore,
whichever QG_STORE selects), so this module never talks to a database
directly and works identically against a live capture or a FileStore
capture produced without eBPF/root.

SCHEMA CONTRACT - read this before touching detection/ or crypto/
------------------------------------------------------------------
Every node/edge attribute name written by build() below is load-bearing
for detection/features.py, detection/detector.py (RuleEngine) and
crypto/integrity.py (NODE_SEALED_ATTRS / EDGE_SEALED_ATTRS), and must
match the shape detection/synthetic.py's generate() uses for training
data. In particular:

  - process_hash   (not "hash")        node attribute
  - synthetic_root (not "synthetic")   node attribute, session-root flag
  - seq, ts        (not just "sequence" on edges)

These three were mismatched in an earlier version of this file: real
captured graphs silently produced meaningless sequence/temporal rule
checks and a process_hash check that never fired, because the detection
layer was reading attribute names this builder never wrote. Renaming or
dropping any of the names above reintroduces that bug without raising an
error - features.py and detector.py degrade to defaults instead of
crashing, so it will not be caught by testing that only checks "did it
run". Process, file and session-root nodes also all carry the same
attribute set (pid, uid, comm, filename, timestamp, sequence,
process_hash) - even file nodes and the synthetic session root - so that
detection/features.py's per-node statistics (ts_zscore, seq_rank, ...)
are computed over a consistent schema rather than being biased by nodes
with attributes silently defaulting to 0.
"""

from __future__ import annotations

import hashlib
import os
import pickle

import networkx as nx

from core import config
from core.store import get_store
from graph.models import ProvenanceEvent


class ProvenanceGraphService:

    def __init__(self, store=None):
        self.store = store or get_store()
        self.dropped: list[dict] = []
        self.deduplicated: list[int] = []
        self.anomalies: list[dict] = []
        self.rebased_at: list[int] = []
        self.session_roots: dict[int, str] = {}

    # =====================================================
    # LOAD EVENTS
    # =====================================================

    def load_events(self) -> list[ProvenanceEvent]:
        rows = self.store.load_events()
        return [
            ProvenanceEvent(
                sequence=row["sequence"],
                timestamp=row["timestamp"],
                pid=row["pid"],
                uid=row["uid"],
                comm=row["comm"],
                filename=row["filename"],
                event_type=row["event_type"],
            )
            for row in rows
        ]

    # =====================================================
    # DEDUPLICATION
    # =====================================================

    def deduplicate(self, events: list[ProvenanceEvent]) -> list[ProvenanceEvent]:
        cache: dict[tuple, int] = {}
        cleaned = []
        self.deduplicated.clear()

        for e in events:
            key = (e.pid, e.filename)

            # The lower bound matters: after a reboot the clock restarts, the
            # difference goes negative, and without it every pid/file pair
            # seen before the reboot would count as a duplicate.
            if key in cache and 0 <= e.timestamp - cache[key] < config.DEDUP_WINDOW_NS:
                # Remembered so rule R7 does not report the sequence number
                # this leaves behind as deletion.
                self.deduplicated.append(e.sequence)
                continue

            cache[key] = e.timestamp
            cleaned.append(e)

        return cleaned

    # =====================================================
    # TEMPORAL VALIDATION
    # =====================================================

    def _session_boundaries(self) -> set[int]:
        loader = getattr(self.store, "load_session_boundaries", None)
        return set(loader()) if loader else set()

    def validate(self, events: list[ProvenanceEvent]) -> list[ProvenanceEvent]:
        """Normalise ordering without destroying evidence.

        A backwards timestamp is one of two things:

          * the first event of a resumed session. Older captures stored
            nanoseconds since boot, which restart at zero after a reboot.
            These are rebased so the graph's time keeps moving forward.
          * anything else. It is kept, unmodified, for rule R2 to report.
            Dropping it here would erase the evidence of tampering before
            the detector could see it.
        """
        valid = []
        previous_seq = 0
        previous_ts = 0
        offset = 0
        boundaries = self._session_boundaries()
        self.dropped.clear()
        self.anomalies.clear()
        self.rebased_at.clear()

        for e in events:
            if e.sequence <= previous_seq:
                self.dropped.append({"sequence": e.sequence, "reason": "sequence_order"})
                continue

            e.timestamp += offset
            if e.timestamp < previous_ts:
                # any(): the boundary event itself may have been deduplicated
                if any(previous_seq < b <= e.sequence for b in boundaries):
                    shift = previous_ts + 1_000_000_000 - e.timestamp
                    offset += shift
                    e.timestamp += shift
                    self.rebased_at.append(e.sequence)
                else:
                    self.anomalies.append({"sequence": e.sequence, "reason": "timestamp_order"})

            valid.append(e)
            previous_seq = e.sequence
            previous_ts = e.timestamp

        return valid

    # =====================================================
    # ENRICHMENT
    # =====================================================

    @staticmethod
    def process_node(event: ProvenanceEvent) -> str:
        return f"P:{event.pid}:{event.sequence}"

    def enrich(self, events: list[ProvenanceEvent]) -> list[ProvenanceEvent]:
        """Assign each event a canonical process id, its integrity hash,
        and a parent via real execve-chain inference: at sys_enter_execve
        the kernel has already forked, so `pid` is the NEW process but
        `comm` is still the name of the image being replaced - the
        parent. An event (pid=4321, comm="bash", file="/usr/bin/ls")
        means "something called bash exec'd ls", so it is linked to the
        most recent earlier event, same uid, whose executed binary's
        basename equals this event's comm (truncated to 15 chars, since
        TASK_COMM_LEN is 16 bytes including the NUL). A child of a privilege
        helper may have a different uid: sudo runs as the user and its child
        as root, and that link is the one an investigator most needs. Events
        with no match attach to a per-uid session root instead of being
        orphaned."""

        image_index: dict[tuple[int, str], tuple[str, int, int]] = {}
        helper_index: dict[str, tuple[str, int, int]] = {}
        roots: dict[int, str] = {}

        for e in events:
            e.process_id = self.process_node(e)
            e.process_hash = hashlib.sha256(
                f"{e.pid}:{e.timestamp}:{e.comm}".encode()
            ).hexdigest()

            parent = image_index.get((e.uid, e.comm))
            helper = helper_index.get(e.comm)
            if helper and (not parent or helper[2] > parent[2]):
                parent = helper

            if parent and (e.timestamp - parent[2]) <= config.PARENT_WINDOW_NS:
                e.parent_node = parent[0]
                e.parent_pid = parent[1]
                e.parent_kind = "execve"
            else:
                root = roots.setdefault(e.uid, f"P:ROOT:{e.uid}")
                e.parent_node = root
                e.parent_kind = "session"

            image = os.path.basename(e.filename)[:15]
            image_index[(e.uid, image)] = (e.process_id, e.pid, e.timestamp)
            if image in config.PRIVILEGE_HELPERS:
                helper_index[image] = image_index[(e.uid, image)]

        self.session_roots = roots
        return events

    # =====================================================
    # GRAPH BUILDING
    # =====================================================

    def build(self, events: list[ProvenanceEvent]) -> nx.DiGraph:
        G = nx.DiGraph()

        # Session roots - one synthetic process per uid, standing in for
        # "whatever spawned the first observed process of this session".
        for uid, root in self.session_roots.items():
            G.add_node(
                root,
                type="process",
                label=f"SESSION\nUID {uid}",
                pid=-1,
                uid=uid,
                comm="session",
                filename="",
                sequence=0,
                timestamp=0,
                process_hash="",
                synthetic_root=True,
            )

        for e in events:
            process = e.process_id
            file_node = f"F:{e.filename}"
            image = os.path.basename(e.filename)

            G.add_node(
                process,
                type="process",
                label=f"{image}\nPID {e.pid}",
                pid=e.pid,
                uid=e.uid,
                comm=e.comm,
                filename=e.filename,
                sequence=e.sequence,
                timestamp=e.timestamp,
                process_hash=e.process_hash,
                synthetic_root=False,
            )

            # Same attribute set as a process node (minus identity fields
            # that don't apply) so per-node statistics in
            # detection/features.py aren't skewed by an inconsistent
            # schema - see the module docstring.
            G.add_node(
                file_node,
                type="file",
                label=image,
                path=e.filename,
                pid=-1,
                uid=e.uid,
                comm="",
                filename=e.filename,
                sequence=e.sequence,
                timestamp=e.timestamp,
                process_hash="",
                synthetic_root=False,
            )

            G.add_edge(
                process, file_node,
                relation="EXECUTES",
                seq=e.sequence,
                ts=e.timestamp,
            )

            if e.parent_node:
                G.add_edge(
                    e.parent_node, process,
                    relation="SPAWNS",
                    method=e.parent_kind,
                    seq=e.sequence,
                    ts=e.timestamp,
                )

        G.graph["builder"] = "QuantumGuard Phase 3"
        G.graph["event_count"] = len(events)
        G.graph["dropped_count"] = len(self.dropped)
        # Comma-joined because GraphML cannot store lists.
        G.graph["deduplicated_sequences"] = ",".join(map(str, self.deduplicated))
        G.graph["timestamp_rebased_at"] = ",".join(map(str, self.rebased_at))
        G.graph["timestamp_anomalies"] = len(self.anomalies)

        return G

    # =====================================================
    # SAVE
    # =====================================================

    def save(self, G: nx.DiGraph) -> None:
        os.makedirs(config.GRAPH_DIR, exist_ok=True)

        with open(config.GRAPH_PICKLE, "wb") as f:
            pickle.dump(G, f)

        nx.write_graphml(G, config.GRAPH_GRAPHML)

    # =====================================================
    # COMPLETE PIPELINE
    # =====================================================

    def run(self) -> nx.DiGraph:
        events = self.load_events()
        events = self.deduplicate(events)
        events = self.validate(events)
        events = self.enrich(events)
        graph = self.build(events)
        self.save(graph)
        return graph
