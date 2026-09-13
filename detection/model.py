"""
GraphSAGE poisoning-detection model: architecture, optimiser, metrics, the
training loop, and the `python -m detection.model` CLI. Kept in one file
because the training loop only exists to produce this model, and neither
half is useful without the other.

    python -m detection.model                    # synthetic only
    python -m detection.model --graph graphs/provenance_graph.gpickle
    python -m detection.model --epochs 120 --hidden 96

Architecture
------------
Two-layer GraphSAGE with a mean aggregator, i.e. exactly `SAGEConv`
written out with explicit forward/backward passes:

    Z = X.W_self + (A_mean.X).W_neigh + b        H = ReLU(Z)

`A_mean` is the row-normalised SYMMETRIC adjacency (detection/features.py
`adjacency()`). Provenance edges are directed, but a forged node is only
visible in context - you need to see both what spawned it and what it
touched - so messages flow both ways. Two layers gives every node its
2-hop neighbourhood, which is the scale tampering patterns live at (a
deleted edge changes a node's neighbours' degrees, not just its own).

Why NumPy and not PyTorch Geometric: this is ~200 lines, trains hundreds
of graphs in seconds on a laptop CPU with no CUDA/torch-scatter build,
and every line is explainable in a viva. The backward pass is meant to be
checked against numerical gradients in a test suite (see the project's
known-limitations notes) so it should not be taken on faith.

Training
--------
Node-level binary labels (tampered / not) with a positive class weight,
since tampering only ever touches a small fraction of nodes. The decision
threshold is chosen on the VALIDATION split by maximising F1 - never on
test - and both threshold and feature standardiser are saved alongside
the weights so inference (detection/detector.py) is reproducible without
re-deriving them.
"""

from __future__ import annotations

import argparse
import json
import os
import pickle
import time

import numpy as np

from core import config
from detection import features, synthetic

# ===================================================================
# Numerics
# ===================================================================


def sigmoid(x):
    out = np.empty_like(x, dtype=np.float64)
    pos = x >= 0
    out[pos] = 1.0 / (1.0 + np.exp(-x[pos]))
    e = np.exp(x[~pos])
    out[~pos] = e / (1.0 + e)
    return out


def bce_with_logits(logits, y, weights):
    """Numerically stable weighted binary cross entropy."""
    z, t = logits.ravel(), y.ravel()
    loss = np.maximum(z, 0) - z * t + np.log1p(np.exp(-np.abs(z)))
    return float(np.sum(weights.ravel() * loss) / max(1, len(t)))


# ===================================================================
# Model
# ===================================================================


class GraphSAGE:

    def __init__(self, in_dim: int, hidden: int = 64, seed: int = 7):
        rng = np.random.default_rng(seed)

        def he(a, b):
            return rng.normal(0, np.sqrt(2.0 / a), size=(a, b)).astype(np.float64)

        self.in_dim = in_dim
        self.hidden = hidden

        self.p = {
            "Ws1": he(in_dim, hidden), "Wn1": he(in_dim, hidden),
            "b1": np.zeros(hidden),
            "Ws2": he(hidden, hidden), "Wn2": he(hidden, hidden),
            "b2": np.zeros(hidden),
            "Wo": he(hidden, 1), "bo": np.zeros(1),
        }

    def forward(self, X, A, cache=True):
        AX = A @ X
        Z1 = X @ self.p["Ws1"] + AX @ self.p["Wn1"] + self.p["b1"]
        H1 = np.maximum(Z1, 0.0)

        AH1 = A @ H1
        Z2 = H1 @ self.p["Ws2"] + AH1 @ self.p["Wn2"] + self.p["b2"]
        H2 = np.maximum(Z2, 0.0)

        logits = H2 @ self.p["Wo"] + self.p["bo"]

        if cache:
            self._cache = (X, A, AX, Z1, H1, AH1, Z2, H2)
        return logits

    def backward(self, logits, y, weights, l2: float = 0.0):
        X, A, AX, Z1, H1, AH1, Z2, H2 = self._cache
        n = max(1, len(y))

        p = sigmoid(logits)
        dlogits = (weights.reshape(-1, 1) * (p - y.reshape(-1, 1))) / n

        g = {}
        g["Wo"] = H2.T @ dlogits
        g["bo"] = dlogits.sum(axis=0)

        dH2 = dlogits @ self.p["Wo"].T
        dZ2 = dH2 * (Z2 > 0)

        g["Ws2"] = H1.T @ dZ2
        g["Wn2"] = AH1.T @ dZ2
        g["b2"] = dZ2.sum(axis=0)

        dH1 = dZ2 @ self.p["Ws2"].T + A.T @ (dZ2 @ self.p["Wn2"].T)
        dZ1 = dH1 * (Z1 > 0)

        g["Ws1"] = X.T @ dZ1
        g["Wn1"] = AX.T @ dZ1
        g["b1"] = dZ1.sum(axis=0)

        if l2:
            for k in ("Ws1", "Wn1", "Ws2", "Wn2", "Wo"):
                g[k] = g[k] + l2 * self.p[k]

        return g

    def predict(self, X, A):
        return sigmoid(self.forward(X, A, cache=False)).ravel()

    def save(self, path: str, meta: dict):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        np.savez(path, **self.p)
        with open(path.replace(".npz", ".meta.json"), "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)

    @classmethod
    def load(cls, path: str):
        blob = np.load(path)
        meta_path = path.replace(".npz", ".meta.json")
        with open(meta_path, "r", encoding="utf-8") as fh:
            meta = json.load(fh)

        model = cls(int(meta["in_dim"]), int(meta["hidden"]))
        for k in model.p:
            model.p[k] = blob[k]
        return model, meta


# ===================================================================
# Adam
# ===================================================================


class Adam:

    def __init__(self, params, lr=3e-3, beta1=0.9, beta2=0.999, eps=1e-8):
        self.lr, self.b1, self.b2, self.eps = lr, beta1, beta2, eps
        self.m = {k: np.zeros_like(v) for k, v in params.items()}
        self.v = {k: np.zeros_like(v) for k, v in params.items()}
        self.t = 0

    def step(self, params, grads):
        self.t += 1
        for k, g in grads.items():
            self.m[k] = self.b1 * self.m[k] + (1 - self.b1) * g
            self.v[k] = self.b2 * self.v[k] + (1 - self.b2) * (g * g)
            mh = self.m[k] / (1 - self.b1 ** self.t)
            vh = self.v[k] / (1 - self.b2 ** self.t)
            params[k] -= self.lr * mh / (np.sqrt(vh) + self.eps)


# ===================================================================
# Metrics
# ===================================================================


def roc_auc(y_true, scores) -> float:
    y = np.asarray(y_true).ravel()
    s = np.asarray(scores).ravel()
    pos, neg = (y == 1).sum(), (y == 0).sum()
    if pos == 0 or neg == 0:
        return float("nan")
    order = np.argsort(s, kind="mergesort")
    ranks = np.empty(len(s), dtype=np.float64)
    ranks[order] = np.arange(1, len(s) + 1)
    # average ranks for ties
    sorted_s = s[order]
    i = 0
    while i < len(sorted_s):
        j = i
        while j + 1 < len(sorted_s) and sorted_s[j + 1] == sorted_s[i]:
            j += 1
        if j > i:
            ranks[order[i:j + 1]] = (i + j + 2) / 2.0
        i = j + 1
    return float((ranks[y == 1].sum() - pos * (pos + 1) / 2) / (pos * neg))


def binary_metrics(y_true, scores, threshold: float) -> dict:
    y = np.asarray(y_true).ravel()
    pred = (np.asarray(scores).ravel() >= threshold).astype(int)

    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    return {
        "threshold": float(threshold),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round((tp + tn) / max(1, len(y)), 4),
    }


def best_threshold(y_true, scores, grid=None) -> tuple[float, dict]:
    """Pick the threshold maximising F1 on the given split (used only on
    validation - see the training-loop note above)."""
    grid = grid if grid is not None else np.linspace(0.05, 0.95, 91)
    best, best_m = 0.5, None
    for t in grid:
        m = binary_metrics(y_true, scores, float(t))
        if best_m is None or m["f1"] > best_m["f1"]:
            best, best_m = float(t), m
    return best, best_m


# ===================================================================
# Training loop
# ===================================================================


def _pos_weight(samples) -> float:
    """Weight positive (tampered) nodes up to `neg/pos`, capped at 20x,
    so the loss isn't dominated by the vast majority of untouched nodes."""
    pos = sum(float(s.y.sum()) for s in samples)
    total = sum(len(s.y) for s in samples)
    neg = total - pos
    if pos <= 0:
        return 1.0
    return float(np.clip(neg / pos, 1.0, 20.0))


def evaluate(model, samples, threshold=0.5):
    """Score every sample and report both node-level metrics (precision/
    recall/F1/AUC over individual nodes) and graph-level metrics (did we
    correctly call this whole graph tampered or clean)."""
    ys, ps = [], []
    graph_true, graph_pred = [], []

    for s in samples:
        score = model.predict(s.X, s.A)
        ys.append(s.y)
        ps.append(score)
        graph_true.append(1 if s.tampered else 0)
        flagged = int((score >= threshold).sum())
        graph_pred.append(1 if flagged >= config.GRAPH_ALERT_MIN_NODES else 0)

    y = np.concatenate(ys) if ys else np.zeros(0)
    p = np.concatenate(ps) if ps else np.zeros(0)

    node = binary_metrics(y, p, threshold)
    node["auc"] = round(roc_auc(y, p), 4)

    gt = np.array(graph_true)
    gp = np.array(graph_pred)
    tp = int(((gp == 1) & (gt == 1)).sum())
    fp = int(((gp == 1) & (gt == 0)).sum())
    fn = int(((gp == 0) & (gt == 1)).sum())
    tn = int(((gp == 0) & (gt == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0

    graph = {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0,
        "accuracy": round((tp + tn) / max(1, len(gt)), 4),
    }

    return {"node": node, "graph": graph, "y": y, "p": p}


def train(real_graph=None, epochs=100, hidden=64, lr=3e-3, l2=1e-5,
          n_synthetic=220, seed=7, verbose=True):
    """Build the mixed real+synthetic dataset (detection/synthetic.py),
    train GraphSAGE with Adam, keep the best-validation-F1 checkpoint
    (the model overfits after ~20 epochs), then pick a threshold and
    report final validation/test metrics."""

    bases = synthetic.build_base_graphs(real_graph, n_synthetic=n_synthetic)
    samples = synthetic.build_samples(bases)
    tr, va, te = synthetic.split(samples)

    if not tr or not va:
        raise RuntimeError("not enough training data - increase --synthetic")

    mean, std = synthetic.standardiser(tr)
    for part in (tr, va, te):
        synthetic.apply_standardiser(part, mean, std)

    pw = _pos_weight(tr)
    model = GraphSAGE(features.FEATURE_DIM, hidden, seed=seed)
    opt = Adam(model.p, lr=lr)

    if verbose:
        n_pos = sum(int(s.y.sum()) for s in tr)
        n_node = sum(len(s.y) for s in tr)
        print(f"[train] graphs  train={len(tr)} val={len(va)} test={len(te)}")
        print(f"[train] nodes   {n_node} ({n_pos} tampered, "
              f"pos_weight={pw:.2f})")
        print(f"[train] features {features.FEATURE_DIM}, hidden {hidden}")

    rng = np.random.default_rng(seed)
    best_f1, best_state, best_epoch = -1.0, None, 0
    history = []

    for epoch in range(1, epochs + 1):
        order = rng.permutation(len(tr))
        total = 0.0

        for i in order:
            s = tr[i]
            w = np.where(s.y == 1, pw, 1.0)
            logits = model.forward(s.X, s.A)
            total += bce_with_logits(logits, s.y, w)
            grads = model.backward(logits, s.y, w, l2=l2)
            opt.step(model.p, grads)

        val = evaluate(model, va, 0.5)
        thr, _ = best_threshold(val["y"], val["p"])
        val_at_thr = binary_metrics(val["y"], val["p"], thr)

        history.append({"epoch": epoch,
                        "loss": round(total / len(tr), 5),
                        "val_f1": val_at_thr["f1"],
                        "val_auc": val["node"]["auc"]})

        if val_at_thr["f1"] > best_f1:
            best_f1 = val_at_thr["f1"]
            best_state = {k: v.copy() for k, v in model.p.items()}
            best_epoch = epoch

        if verbose and (epoch % 10 == 0 or epoch == 1):
            print(f"  epoch {epoch:>3}  loss {total / len(tr):.5f}  "
                  f"val F1 {val_at_thr['f1']:.4f}  "
                  f"val AUC {val['node']['auc']:.4f}")

    if best_state:
        model.p = best_state

    val = evaluate(model, va, 0.5)
    threshold, _ = best_threshold(val["y"], val["p"])

    val_final = evaluate(model, va, threshold)
    test_final = evaluate(model, te, threshold) if te else None

    meta = {
        "in_dim": features.FEATURE_DIM,
        "hidden": hidden,
        "threshold": threshold,
        "pos_weight": pw,
        "feature_names": features.FEATURE_NAMES,
        "feature_mean": mean.tolist(),
        "feature_std": std.tolist(),
        "best_epoch": best_epoch,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "n_train_graphs": len(tr),
        "n_val_graphs": len(va),
        "n_test_graphs": len(te),
        "real_windows": sum(1 for s in samples if s.source == "real"),
        "validation": {"node": val_final["node"], "graph": val_final["graph"]},
        "test": ({"node": test_final["node"], "graph": test_final["graph"]}
                 if test_final else None),
        "history": history[-20:],
    }

    return model, meta


def main():
    ap = argparse.ArgumentParser(description="Train QuantumGuard GNN detector")
    ap.add_argument("--graph", default=config.GRAPH_PICKLE,
                    help="captured provenance graph (.gpickle) to mix in")
    ap.add_argument("--epochs", type=int, default=100)
    ap.add_argument("--hidden", type=int, default=64)
    ap.add_argument("--lr", type=float, default=3e-3)
    ap.add_argument("--synthetic", type=int, default=220)
    ap.add_argument("--out", default=config.MODEL_PATH)
    args = ap.parse_args()

    real = None
    if args.graph and os.path.exists(args.graph):
        with open(args.graph, "rb") as fh:
            real = pickle.load(fh)
        print(f"[train] real graph: {real.number_of_nodes()} nodes, "
              f"{real.number_of_edges()} edges")
    else:
        print("[train] no captured graph found - training on synthetic data "
              "only (run graph/main.py first for a host-tuned model)")

    model, meta = train(real, epochs=args.epochs, hidden=args.hidden,
                        lr=args.lr, n_synthetic=args.synthetic)

    model.save(args.out, meta)

    print("\n" + "=" * 58)
    print(f"  saved: {args.out}")
    print(f"  threshold (chosen on validation): {meta['threshold']:.3f}")
    print("  node-level  ", json.dumps(meta["validation"]["node"]))
    if meta["test"]:
        print("  test node   ", json.dumps(meta["test"]["node"]))
        print("  test graph  ", json.dumps(meta["test"]["graph"]))
    print("=" * 58)


if __name__ == "__main__":
    main()
