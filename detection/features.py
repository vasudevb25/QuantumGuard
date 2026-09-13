"""
Node feature extraction for the poisoning detector.

Design rule: every feature must be computable from the graph AS GIVEN,
with no access to ground truth and no access to the untampered original.
Features are also *relative* (z-scores, ratios, ranks) rather than
absolute, so a model trained on one capture session transfers to another
machine with different PIDs, paths and clock offsets.

Three families of signal are encoded:

  structural  - degrees, orphan/sink flags, depth, 2-hop size
  temporal    - timestamp z-score, sequence rank, local ordering
                violations, gaps to neighbouring sequence numbers
  attribute   - process-hash recomputation, uid conformity, node type,
                hashed identifier buckets

The process-hash feature deserves a note: a forged node whose
process_hash does not equal sha256("pid:timestamp:comm") is trivially
detectable. A competent attacker recomputes it. The tamper generator
therefore produces correct hashes half the time on purpose, which forces
the model to learn the structural and temporal signals as well.
"""

from __future__ import annotations

import hashlib
import math

import numpy as np
import networkx as nx

COMM_BUCKETS = 8

FEATURE_NAMES = [
    # type
    "is_process", "is_file", "is_synthetic_root",
    # degree
    "log_in_degree", "log_out_degree",
    "log_spawn_in", "log_spawn_out",
    "log_exec_in", "log_exec_out",
    "degree_ratio",
    "is_orphan", "is_sink", "is_isolated",
    # neighbourhood
    "log_neighbour_degree_mean", "log_two_hop", "neighbour_type_mix",
    # temporal
    "ts_zscore", "seq_rank", "log_local_time_violations",
    "log_gap_prev", "log_gap_next", "edge_ts_span_norm",
    "edge_node_ts_mismatch",
    # attribute
    "process_hash_ok", "uid_is_majority", "pid_norm",
    "duplicate_sequence", "has_self_loop", "depth_norm", "reachable_from_root",
] + [f"name_bucket_{i}" for i in range(COMM_BUCKETS)]

FEATURE_DIM = len(FEATURE_NAMES)


def _log1p(x):
    return math.log1p(max(0.0, float(x)))


def _bucket(text: str) -> int:
    if not text:
        return 0
    return int.from_bytes(
        hashlib.sha256(text.encode()).digest()[:4], "big"
    ) % COMM_BUCKETS


def _expected_process_hash(attrs) -> str:
    return hashlib.sha256(
        f"{attrs.get('pid')}:{attrs.get('timestamp')}:{attrs.get('comm')}".encode()
    ).hexdigest()


def extract(G) -> tuple[np.ndarray, list[str]]:
    """Return (feature_matrix [N, FEATURE_DIM], node_id list)."""

    nodes = sorted(G.nodes())
    index = {n: i for i, n in enumerate(nodes)}
    n = len(nodes)

    if n == 0:
        return np.zeros((0, FEATURE_DIM), dtype=np.float32), []

    und = G.to_undirected(as_view=False)

    # ---- graph level normalisers ------------------------------
    all_ts = [int(G.nodes[x].get("timestamp") or 0) for x in nodes]
    ts_arr = np.array(all_ts, dtype=np.float64)
    ts_mean = float(ts_arr.mean())
    ts_std = float(ts_arr.std()) or 1.0

    all_seq = sorted({int(G.nodes[x].get("sequence") or 0) for x in nodes})
    seq_max = max(all_seq) or 1
    seq_pos = {s: i for i, s in enumerate(all_seq)}

    uids = [int(G.nodes[x].get("uid") or -1) for x in nodes]
    majority_uid = max(set(uids), key=uids.count) if uids else -1

    seq_counts: dict[int, int] = {}
    for x in nodes:
        s = int(G.nodes[x].get("sequence") or 0)
        seq_counts[s] = seq_counts.get(s, 0) + 1

    # ---- depth from any root (SPAWNS tree) --------------------
    spawn = nx.DiGraph()
    spawn.add_nodes_from(nodes)
    for u, v, d in G.edges(data=True):
        if d.get("relation") == "SPAWNS":
            spawn.add_edge(u, v)

    roots = [x for x in nodes if spawn.in_degree(x) == 0]
    depth = {x: -1 for x in nodes}
    frontier, level = list(roots), 0
    seen = set(roots)
    for r in roots:
        depth[r] = 0
    while frontier:
        level += 1
        nxt = []
        for x in frontier:
            for y in spawn.successors(x):
                if y not in seen:
                    seen.add(y)
                    depth[y] = level
                    nxt.append(y)
        frontier = nxt
    max_depth = max([d for d in depth.values() if d >= 0] or [1]) or 1

    degrees = {x: und.degree(x) for x in nodes}

    X = np.zeros((n, FEATURE_DIM), dtype=np.float32)

    for node in nodes:
        i = index[node]
        a = G.nodes[node]
        row = []

        ntype = a.get("type")
        row += [
            1.0 if ntype == "process" else 0.0,
            1.0 if ntype == "file" else 0.0,
            1.0 if a.get("synthetic_root") else 0.0,
        ]

        in_edges = list(G.in_edges(node, data=True))
        out_edges = list(G.out_edges(node, data=True))
        indeg, outdeg = len(in_edges), len(out_edges)

        spawn_in = sum(1 for *_, d in in_edges if d.get("relation") == "SPAWNS")
        spawn_out = sum(1 for *_, d in out_edges if d.get("relation") == "SPAWNS")
        exec_in = sum(1 for *_, d in in_edges if d.get("relation") == "EXECUTES")
        exec_out = sum(1 for *_, d in out_edges if d.get("relation") == "EXECUTES")

        row += [
            _log1p(indeg), _log1p(outdeg),
            _log1p(spawn_in), _log1p(spawn_out),
            _log1p(exec_in), _log1p(exec_out),
            indeg / (indeg + outdeg + 1.0),
            1.0 if (ntype == "process" and indeg == 0
                    and not a.get("synthetic_root")) else 0.0,
            1.0 if outdeg == 0 else 0.0,
            1.0 if (indeg + outdeg) == 0 else 0.0,
        ]

        neigh = list(und.neighbors(node))
        nd = [degrees[m] for m in neigh]
        two_hop = set()
        for m in neigh:
            two_hop.update(und.neighbors(m))
        two_hop.discard(node)

        ntypes = {G.nodes[m].get("type") for m in neigh}
        row += [
            _log1p(sum(nd) / len(nd)) if nd else 0.0,
            _log1p(len(two_hop)),
            len(ntypes) / 2.0,
        ]

        ts = float(a.get("timestamp") or 0)
        seq = int(a.get("sequence") or 0)

        # ordering violations among incident edges
        incident = [(int(d.get("seq") or 0), int(d.get("ts") or 0))
                    for *_, d in in_edges + out_edges]
        violations = 0
        for p in range(len(incident)):
            for q in range(p + 1, len(incident)):
                s1, t1 = incident[p]
                s2, t2 = incident[q]
                if (s1 < s2 and t1 > t2) or (s2 < s1 and t2 > t1):
                    violations += 1

        pos = seq_pos.get(seq, 0)
        gap_prev = seq - all_seq[pos - 1] if pos > 0 else 0
        gap_next = all_seq[pos + 1] - seq if pos + 1 < len(all_seq) else 0

        e_ts = [t for _, t in incident]
        span = (max(e_ts) - min(e_ts)) if e_ts else 0

        mismatch = 0.0
        if e_ts and ts > 0 and min(e_ts) > 0:
            if abs(min(e_ts) - ts) > 0 and ntype == "process":
                mismatch = 1.0

        row += [
            float(np.clip((ts - ts_mean) / ts_std, -5, 5)),
            seq / seq_max,
            _log1p(violations),
            _log1p(gap_prev),
            _log1p(gap_next),
            _log1p(span) / 25.0,
            mismatch,
        ]

        if ntype == "process" and a.get("process_hash"):
            hash_ok = 1.0 if a["process_hash"] == _expected_process_hash(a) else 0.0
        else:
            hash_ok = 0.5

        row += [
            hash_ok,
            1.0 if int(a.get("uid") or -1) == majority_uid else 0.0,
            float(np.clip((a.get("pid") or 0) / 65536.0, 0, 1)),
            1.0 if seq_counts.get(seq, 0) > 2 else 0.0,
            1.0 if G.has_edge(node, node) else 0.0,
            (depth[node] / max_depth) if depth[node] >= 0 else -1.0,
            1.0 if depth[node] >= 0 else 0.0,
        ]

        bucket = [0.0] * COMM_BUCKETS
        key = a.get("filename") or a.get("path") or a.get("comm") or node
        bucket[_bucket(str(key))] = 1.0
        row += bucket

        X[i] = np.asarray(row, dtype=np.float32)

    return X, nodes


def adjacency(G, nodes: list[str]) -> np.ndarray:
    """Row-normalised symmetric adjacency (the mean aggregator of
    GraphSAGE, expressed as a dense matrix)."""

    n = len(nodes)
    index = {x: i for i, x in enumerate(nodes)}
    A = np.zeros((n, n), dtype=np.float32)

    for u, v in G.edges():
        i, j = index[u], index[v]
        A[i, j] = 1.0
        A[j, i] = 1.0

    deg = A.sum(axis=1, keepdims=True)
    deg[deg == 0] = 1.0
    return A / deg
