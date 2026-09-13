"""
Central, environment-overridable configuration for every phase.

Nothing that varies per machine or per deployment should be hard-coded
anywhere else in the project - if a module needs a path, URL, size or
threshold, it imports this module rather than defining its own copy.
(graph/service.py used to keep its own drifted copies of the database URL
and the parent-inference window; that duplication is what caused it to
silently disagree with this file. Fixed by having it import from here.)
"""

import os

# ==========================================================
# DATABASE
# ==========================================================

# Override with QG_DB_URL, e.g. for a different host/user/password.
# The default matches database/schema.sql's example CREATE USER statement.
DATABASE_URL = os.getenv(
    "QG_DB_URL",
    "postgresql+psycopg2://quantumguard:StrongPassword123@localhost/provenance",
)

STORE_BACKEND = os.getenv("QG_STORE", "auto")   # db | file | auto

# ==========================================================
# DIRECTORIES
# ==========================================================

GRAPH_DIR = "graphs"
MODEL_DIR = "models"
KEY_DIR = "keys"
EVIDENCE_DIR = "evidence"

GRAPH_PICKLE = f"{GRAPH_DIR}/provenance_graph.gpickle"
GRAPH_GRAPHML = f"{GRAPH_DIR}/provenance.graphml"

# ==========================================================
# GRAPH PARAMETERS  (graph/service.py)
# ==========================================================

# Two events on the same (pid, filename) inside this window are treated
# as one capture-side duplicate, not two real execs.
DEDUP_WINDOW_NS = 2_000_000

# How long after a process last exec'd an image we still accept a later
# event under the same (uid, comm) as its child. Generous on purpose:
# too short and ordinary human/command latency creates spurious
# "orphan_process" rule hits when a real parent is just slow to fork its
# next child.
PARENT_WINDOW_NS = 60_000_000_000

# ==========================================================
# GNN  (detection/model.py, detection/detector.py)
# ==========================================================

# Read by detection/detector.py (PoisoningDetector) and as the default
# --out for detection/model.py's training CLI. Must end in .npz:
# GraphSAGE.save() uses np.savez(), and .load() derives the sibling
# *.meta.json path from this name.
MODEL_PATH = f"{MODEL_DIR}/gnn_detector.npz"

# A graph is only called "tampered" by the GNN alone (no rule violation)
# once at least this many nodes score above the learned threshold - one
# noisy node should never flip the verdict. Override with QG_ALERT_MIN_NODES.
GRAPH_ALERT_MIN_NODES = int(os.getenv("QG_ALERT_MIN_NODES", "2"))

# ==========================================================
# CRYPTO  (crypto/integrity.py)
# ==========================================================

# Edges per Merkle partition. Override with QG_PARTITION_SIZE.
PARTITION_SIZE = int(os.getenv("QG_PARTITION_SIZE", "128"))

# Must match the file actually on disk - crypto.integrity.KeyStore falls
# back silently to creating a NEW store at this path if it's wrong,
# which is exactly what happened here before this filename was corrected
# to match keys/quantumguard.keystore.json.
KEYSTORE = f"{KEY_DIR}/quantumguard.keystore.json"

# Passphrase that decrypts the Ed25519/ML-DSA private keys at rest.
# CHANGE THIS before any non-classroom use - "quantumguard-dev" is
# printed in this project's own docs, so a keystore protected only by
# the default is protected by nothing.
KEYSTORE_PASSPHRASE = os.getenv(
    "QG_KEYSTORE_PASSPHRASE",
    "quantumguard-dev",
)

ED25519 = "Ed25519"
MLDSA = "ML-DSA-65"

# ==========================================================
# CREATE DIRECTORIES
# ==========================================================


def init_dirs():
    for d in (GRAPH_DIR, MODEL_DIR, KEY_DIR, EVIDENCE_DIR):
        os.makedirs(d, exist_ok=True)
