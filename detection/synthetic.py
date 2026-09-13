"""
Training-data generation for the poisoning detector.

This module owns everything needed to turn "a graph" into "a labelled
training set" for `detection/model.py`, because there is no public dataset
of *poisoned provenance graphs* (DARPA TC / OpTC label attacks, not
tampering with the audit record itself). Four responsibilities live here,
kept in one file because they form a single pipeline and are only ever
used together:

  1. generate()      - synthetic base graphs with the same schema NetworkX
                        shape the real Phase 3 builder emits (used because
                        one capture session alone has too few distinct
                        subgraphs to train on).
  2. windows()        - slices a real captured graph into overlapping
                        sequence windows, so some training data reflects
                        THIS host's actual behaviour rather than only the
                        synthetic distribution.
  3. TamperGenerator  - the label source: applies one of four realistic
                        "attacker covering their tracks" strategies to a
                        clean base graph and records which nodes it
                        touched (label = 1).
  4. build_base_graphs / build_samples / split / standardiser
                      - assembles (1)-(3) into train/val/test splits of
                        feature matrices, ready for detection/model.py.

Splits are made at the level of BASE graphs, before tampering, so a clean
and a tampered version of the same window can never land in different
splits (that would leak).
"""

from __future__ import annotations

import hashlib
import random

import networkx as nx
import numpy as np

from detection import features

# ===================================================================
# 1. Synthetic base-graph generation
# ===================================================================

SHELLS = ["bash", "sh", "zsh", "python3", "node", "make"]
BINARIES = [
    "/usr/bin/ls", "/usr/bin/cat", "/usr/bin/grep", "/usr/bin/sed",
    "/usr/bin/awk", "/usr/bin/curl", "/usr/bin/git", "/usr/bin/tar",
    "/usr/bin/gcc", "/usr/bin/find", "/usr/bin/ssh", "/usr/bin/wc",
    "/usr/bin/python3", "/usr/bin/node", "/bin/bash", "/usr/bin/sort",
    "/usr/bin/head", "/usr/bin/env", "/usr/bin/dash", "/usr/bin/rm",
]


def _process_hash(pid, timestamp, comm) -> str:
    """Canonical process_hash, matching graph/service.py's enrichment step
    and detection/features.py's process_hash_ok / R5 check. Kept as one
    function so generation, tampering and verification can never drift
    out of sync with each other."""
    return hashlib.sha256(f"{pid}:{timestamp}:{comm}".encode()).hexdigest()


def generate(rng: random.Random | None = None,
             n_events: int | None = None,
             uid: int | None = None) -> nx.DiGraph:
    """Build one synthetic provenance graph: a branching execve tree with
    realistic burst behaviour - a shell spawns a few children, some of
    which are themselves shells that spawn more, with short bursts of
    rapid execs separated by idle gaps."""
    rng = rng or random.Random()
    n_events = n_events or rng.randint(25, 70)
    uid = uid if uid is not None else rng.choice([1000, 1001, 1002])

    G = nx.DiGraph()

    root = f"P:root:uid{uid}"
    G.add_node(root, type="process", label=f"session uid {uid}", pid=-1,
               uid=uid, comm="session", filename="", timestamp=0,
               sequence=0, process_hash="", synthetic_root=True)

    ts = rng.randint(10 ** 12, 10 ** 13)
    seq = 0

    # (node_id, comm-as-seen-by-children)
    frontier: list[tuple[str, str]] = [(root, rng.choice(SHELLS))]

    for _ in range(n_events):
        seq += 1
        # bursts of fast execs, occasionally a long idle gap
        ts += rng.randint(200_000, 3_000_000) if rng.random() < 0.75 \
            else rng.randint(50_000_000, 900_000_000)

        parent_node, parent_comm = rng.choice(frontier)
        binary = rng.choice(BINARIES)
        pid = rng.randint(1000, 60000)

        node = f"P:{pid}:{seq}"
        G.add_node(node, type="process",
                   label=f"{binary.rsplit('/', 1)[-1]}\nPID {pid}",
                   pid=pid, uid=uid, comm=parent_comm, filename=binary,
                   timestamp=ts, sequence=seq,
                   process_hash=_process_hash(pid, ts, parent_comm),
                   synthetic_root=False)

        file_node = f"F:{binary}"
        G.add_node(file_node, type="file", label=binary.rsplit("/", 1)[-1],
                   path=binary, pid=-1, uid=uid, comm="", filename=binary,
                   timestamp=ts, sequence=seq, process_hash="",
                   synthetic_root=False)

        G.add_edge(node, file_node, relation="EXECUTES", seq=seq, ts=ts)
        G.add_edge(parent_node, node, relation="SPAWNS", seq=seq, ts=ts)

        # interpreters and shells become parents for later execs
        name = binary.rsplit("/", 1)[-1]
        if name in SHELLS or rng.random() < 0.2:
            frontier.append((node, name[:15]))
        if len(frontier) > 12:
            frontier.pop(rng.randrange(1, len(frontier)))

    G.graph["builder"] = "synthetic"
    G.graph["event_count"] = n_events
    return G


def windows(G: nx.DiGraph, size: int = 40, stride: int | None = None,
            min_edges: int = 12) -> list[nx.DiGraph]:
    """Slice a real captured graph into overlapping sequence windows.

    Each window is a genuine subgraph of real data, which is what makes
    the trained model fit *this* host's behaviour rather than only the
    synthetic distribution.

    NOTE: this walks edge attribute `seq` (set by generate()'s own edges
    and by crypto/integrity.py's EDGE_SEALED_ATTRS). graph/service.py's
    real builder currently stamps edges with `sequence` instead, not
    `seq` - so on a real captured graph every edge's `seq` reads as 0 and
    the whole graph collapses into a single window. That is a Phase 3 /
    Phase 4 schema mismatch to fix in graph/service.py, not something
    papered over here.
    """
    stride = stride or max(1, size // 2)

    seqs = sorted({int(d.get("seq") or 0) for _, _, d in G.edges(data=True)})
    if not seqs:
        return []

    out = []
    for start in range(0, len(seqs), stride):
        chunk = set(seqs[start: start + size])
        if not chunk:
            break
        edges = [(u, v) for u, v, d in G.edges(data=True)
                 if int(d.get("seq") or 0) in chunk]
        if len(edges) < min_edges:
            continue
        nodes = {n for e in edges for n in e}
        sub = G.subgraph(nodes).copy()
        sub.remove_edges_from(
            [(u, v) for u, v in sub.edges() if (u, v) not in set(edges)]
        )
        sub.remove_nodes_from([n for n in list(sub.nodes()) if sub.degree(n) == 0])
        if sub.number_of_edges() >= min_edges:
            out.append(sub)

    return out


# ===================================================================
# 2. Tampering strategies - the label source
# ===================================================================
#
# Ten deterministic rules (detection/detector.py) catch what they were
# written for; the GNN has to catch the rest, which means it needs
# examples of "the rest". These four strategies are what a root-level
# attacker realistically does to cover their tracks:
#
#   deletion   remove relations / whole process nodes from the record
#   reorder    swap sequence numbers and timestamps so the causal story
#              reads differently
#   forgery    insert a fabricated process that "explains" activity,
#              with attributes copied from a real node so it looks
#              plausible
#   timeshift  move a window of events so the attack falls outside the
#              investigated period
#
# `sophistication` (0.0 crude -> 1.0 expert) controls whether the
# attacker recomputes process_hash / keeps timestamps consistent after
# mutating the graph. Training with a mix of both forces the model to
# learn structural signals instead of latching onto one give-away
# attribute (a crude attacker leaves stale hashes, which is trivial to
# catch and would let the model skip learning anything harder).

STRATEGIES = ("deletion", "reorder", "forgery", "timeshift")


class TamperResult:
    """A tampered (or clean) graph plus a per-node 0/1 label map and a
    log of which strategies were applied, for reporting."""

    def __init__(self, graph, labels, applied):
        self.graph = graph
        self.labels = labels          # node_id -> 0/1
        self.applied = applied        # list of {strategy, targets, ...}

    @property
    def tampered(self) -> bool:
        return bool(self.applied)

    def positives(self):
        return [n for n, y in self.labels.items() if y == 1]


class TamperGenerator:

    def __init__(self, rng: random.Random | None = None,
                 sophistication: float | None = None):
        self.rng = rng or random.Random()
        self.sophistication = sophistication

    def _soph(self):
        if self.sophistication is not None:
            return self.sophistication
        return self.rng.random()

    def apply(self, G, strategies: list[str] | None = None,
              intensity: float = 0.08) -> TamperResult:
        """Return a tampered copy of G plus per-node labels."""

        H = G.copy()
        labels = {n: 0 for n in H.nodes()}
        applied = []

        chosen = strategies or [self.rng.choice(STRATEGIES)]
        soph = self._soph()

        for strategy in chosen:
            fn = getattr(self, f"_{strategy}")
            record = fn(H, labels, intensity, soph)
            if record:
                applied.append(record)

        # nodes removed during the attack cannot be labelled; keep the
        # label map aligned with the surviving graph
        labels = {n: labels.get(n, 0) for n in H.nodes()}
        return TamperResult(H, labels, applied)

    def clean(self, G) -> TamperResult:
        return TamperResult(G.copy(), {n: 0 for n in G.nodes()}, [])

    # -- deletion ----------------------------------------------------

    def _deletion(self, H, labels, intensity, soph):
        candidates = [
            (u, v) for u, v, d in H.edges(data=True)
            if not H.nodes[u].get("synthetic_root")
        ]
        if not candidates:
            return None

        k = max(1, int(len(candidates) * intensity))
        victims = self.rng.sample(candidates, min(k, len(candidates)))

        touched = set()
        for u, v in victims:
            if not H.has_edge(u, v):
                continue
            H.remove_edge(u, v)
            touched.update((u, v))

        # a crude attacker leaves the now-parentless node behind; an
        # expert also removes the orphan so nothing obviously dangles
        if soph > 0.5:
            for n in list(touched):
                if n in H and H.degree(n) == 0:
                    H.remove_node(n)
                    labels.pop(n, None)
                    touched.discard(n)

        for n in touched:
            if n in labels:
                labels[n] = 1

        return {"strategy": "deletion", "removed_edges": len(victims),
                "sophistication": round(soph, 2),
                "targets": sorted(touched)}

    # -- reorder -------------------------------------------------------

    def _reorder(self, H, labels, intensity, soph):
        edges = [(u, v, d) for u, v, d in H.edges(data=True)
                 if d.get("seq")]
        if len(edges) < 4:
            return None

        k = max(1, int(len(edges) * intensity))
        touched = set()

        for _ in range(k):
            (u1, v1, d1), (u2, v2, d2) = self.rng.sample(edges, 2)
            d1["seq"], d2["seq"] = d2.get("seq"), d1.get("seq")
            if soph < 0.5:
                # crude: timestamps left behind, creating an inversion
                pass
            else:
                d1["ts"], d2["ts"] = d2.get("ts"), d1.get("ts")
            touched.update((u1, v1, u2, v2))

        for n in touched:
            if n in labels:
                labels[n] = 1

        return {"strategy": "reorder", "swaps": k,
                "sophistication": round(soph, 2),
                "targets": sorted(touched)}

    # -- forgery -------------------------------------------------------

    def _forgery(self, H, labels, intensity, soph):
        real = [n for n, a in H.nodes(data=True)
                if a.get("type") == "process" and not a.get("synthetic_root")]
        if len(real) < 2:
            return None

        k = max(1, int(len(real) * intensity))
        created = []

        for i in range(k):
            template = H.nodes[self.rng.choice(real)]
            anchor = self.rng.choice(real)

            fake_pid = self.rng.randint(1000, 60000)
            fake_seq = int(template.get("sequence") or 0) + self.rng.randint(1, 5)
            fake_ts = int(template.get("timestamp") or 0) + self.rng.randint(
                1_000_000, 50_000_000
            )

            attrs = {
                "type": "process",
                "label": f"forged\nPID {fake_pid}",
                "pid": fake_pid,
                "uid": template.get("uid"),
                "comm": template.get("comm"),
                "filename": template.get("filename"),
                "timestamp": fake_ts,
                "sequence": fake_seq,
                "synthetic_root": False,
            }
            # expert attacker recomputes the integrity field; crude one
            # copies the victim's hash verbatim
            attrs["process_hash"] = (
                _process_hash(attrs["pid"], attrs["timestamp"], attrs["comm"])
                if soph > 0.5 else template.get("process_hash", "")
            )

            fake = f"P:{fake_pid}:{fake_seq}:X{i}"
            H.add_node(fake, **attrs)
            labels[fake] = 1
            created.append(fake)

            H.add_edge(anchor, fake, relation="SPAWNS",
                       seq=fake_seq, ts=fake_ts)
            labels[anchor] = 1

            files = [n for n, a in H.nodes(data=True) if a.get("type") == "file"]
            if files:
                target = self.rng.choice(files)
                H.add_edge(fake, target, relation="EXECUTES",
                           seq=fake_seq, ts=fake_ts)
                labels[target] = 1

        return {"strategy": "forgery", "inserted": len(created),
                "sophistication": round(soph, 2), "targets": created}

    # -- timeshift -------------------------------------------------------

    def _timeshift(self, H, labels, intensity, soph):
        nodes = [n for n, a in H.nodes(data=True)
                 if not a.get("synthetic_root") and a.get("timestamp")]
        if len(nodes) < 3:
            return None

        k = max(2, int(len(nodes) * max(intensity, 0.1)))
        start = self.rng.randrange(0, max(1, len(nodes) - k + 1))
        window = sorted(nodes, key=lambda n: H.nodes[n].get("sequence") or 0)[
            start: start + k
        ]

        shift = self.rng.choice([-1, 1]) * self.rng.randint(
            500_000_000, 5_000_000_000
        )

        for n in window:
            a = H.nodes[n]
            a["timestamp"] = int(a.get("timestamp") or 0) + shift
            if soph > 0.5 and a.get("type") == "process" and a.get("process_hash"):
                a["process_hash"] = _process_hash(a.get("pid"), a["timestamp"], a.get("comm"))
            for _, _, d in H.in_edges(n, data=True):
                d["ts"] = int(d.get("ts") or 0) + shift
            labels[n] = 1

        return {"strategy": "timeshift", "window": len(window),
                "shift_ns": shift, "sophistication": round(soph, 2),
                "targets": window}


# ===================================================================
# 3. Dataset assembly - graphs + tampering -> (X, A, y) samples
# ===================================================================
#
# One sample = one graph + one label per node. Half of all base graphs
# are left clean (all labels 0); the other half get 1-2 tampering
# strategies applied, with every touched node labelled 1.


class Sample:
    __slots__ = ("X", "A", "y", "nodes", "tampered", "applied", "source")

    def __init__(self, X, A, y, nodes, tampered, applied, source):
        self.X, self.A, self.y = X, A, y
        self.nodes = nodes
        self.tampered = tampered
        self.applied = applied
        self.source = source


def encode(G) -> tuple[np.ndarray, np.ndarray, list[str]]:
    X, nodes = features.extract(G)
    A = features.adjacency(G, nodes)
    return X, A, nodes


def build_base_graphs(real_graph=None, n_synthetic: int = 220,
                      window_size: int = 40,
                      seed: int = 13) -> list[tuple[str, object]]:
    """Mix overlapping windows of a real capture (if given) with freshly
    generated synthetic graphs, before any tampering is applied."""
    rng = random.Random(seed)
    bases: list[tuple[str, object]] = []

    if real_graph is not None and real_graph.number_of_edges() > 0:
        for w in windows(real_graph, size=window_size):
            bases.append(("real", w))

    for _ in range(n_synthetic):
        bases.append(("synthetic", generate(rng)))

    rng.shuffle(bases)
    return bases


def build_samples(bases, seed: int = 21, tamper_ratio: float = 0.5,
                  multi_strategy_prob: float = 0.3) -> list[Sample]:
    """Turn base graphs into labelled feature-matrix samples: each base
    graph is tampered with probability `tamper_ratio` (sometimes with two
    stacked strategies), then encoded via detection/features.py."""
    rng = random.Random(seed)
    gen = TamperGenerator(rng)
    samples: list[Sample] = []

    for source, G in bases:
        if rng.random() < tamper_ratio:
            strategies = [rng.choice(STRATEGIES)]
            if rng.random() < multi_strategy_prob:
                other = rng.choice([s for s in STRATEGIES if s != strategies[0]])
                strategies.append(other)
            result = gen.apply(G, strategies,
                               intensity=rng.uniform(0.05, 0.15))
        else:
            result = gen.clean(G)

        H = result.graph
        if H.number_of_nodes() < 4 or H.number_of_edges() < 3:
            continue

        X, A, nodes = encode(H)
        y = np.array([result.labels.get(n, 0) for n in nodes], dtype=np.float64)

        samples.append(
            Sample(X, A, y, nodes, result.tampered, result.applied, source)
        )

    return samples


def split(samples, train=0.7, val=0.15, seed: int = 5):
    """Split at the BASE-graph level (already done by the time samples
    exist) so a clean/tampered pair of the same window never crosses
    train/val/test boundaries."""
    rng = random.Random(seed)
    idx = list(range(len(samples)))
    rng.shuffle(idx)

    n = len(idx)
    a = int(n * train)
    b = int(n * (train + val))

    pick = lambda part: [samples[i] for i in part]  # noqa: E731
    return pick(idx[:a]), pick(idx[a:b]), pick(idx[b:])


def standardiser(samples) -> tuple[np.ndarray, np.ndarray]:
    """Feature mean/std over the training split only (never val/test, to
    avoid leaking their distribution into normalisation)."""
    stack = np.vstack([s.X for s in samples]) if samples else np.zeros((1, features.FEATURE_DIM))
    mean = stack.mean(axis=0)
    std = stack.std(axis=0)
    std[std < 1e-6] = 1.0
    return mean.astype(np.float64), std.astype(np.float64)


def apply_standardiser(samples, mean, std):
    for s in samples:
        s.X = (s.X - mean) / std
