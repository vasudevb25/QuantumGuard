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

# Event timestamps are taken after the ring-buffer slot is reserved, so two
# events on different CPUs can land a few microseconds out of order with no
# tampering involved. Inversions smaller than this are not reported.
TEMPORAL_TOLERANCE_NS = 100_000

# Programs whose job is to run something as another user. Only these may link
# a process to a parent with a different uid, or change the uid seen under one
# pid. Names are cut to 15 characters to match the kernel's comm field.
PRIVILEGE_HELPERS = frozenset({
    "sudo", "sudoedit", "su", "doas", "pkexec", "runuser", "setpriv",
    "newgrp", "sg", "login", "sshd", "sshd-session", "cron", "crond",
})

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
# ANCHORING  (anchoring/)  - Phase 6
# ==========================================================

# Where the external anchor lives. "local" is the append-only, chained,
# dual-signed ledger in anchoring/ledger.py; "fabric" selects the
# Hyperledger Fabric adapter, which needs a running network and raises
# NotImplementedError without one. See anchoring/ledger.py for exactly
# what the local ledger does and does not guarantee.
LEDGER_BACKEND = os.getenv("QG_LEDGER", "local")

# The ledger file is deliberately NOT under EVIDENCE_DIR: an anchor that
# lives beside the evidence it protects is destroyed by the same `rm`.
LEDGER_DIR = "ledger"
LEDGER_PATH = f"{LEDGER_DIR}/anchor_ledger.json"

ANCHOR_REPORT = f"{EVIDENCE_DIR}/anchoring_report.json"

# Tier-2 partitions accumulate until this many are pending, then one
# second-order Merkle tree is built over their roots and a single
# transaction anchors the batch. Larger batches cost fewer transactions
# and delay the anchor for the earliest member; this default trades a
# short delay for an 8x reduction in ledger writes.
ANCHOR_BATCH_SIZE = int(os.getenv("QG_ANCHOR_BATCH_SIZE", "8"))

# ==========================================================
# EVALUATION  (evaluation/)  - Phase 7
# ==========================================================

EVALUATION_DIR = "evaluation"
EVALUATION_REPORT = f"{EVALUATION_DIR}/report.json"

# Weights of the five survivability measures inside the composite FSI.
# PIS and GRR carry the most weight because they answer the two
# questions an investigator asks first: how much evidence is left, and
# can the causal chain still be walked.
FSI_WEIGHTS = {"PIS": 0.30, "EPR": 0.20, "GRR": 0.25, "RA": 0.25}

# No blanket init_dirs() here on purpose: main.py used to call one before
# every subcommand, which meant `sudo python main.py capture` on a fresh
# checkout created graphs/, models/ and keys/ as root too - even though
# capture never touches them - and every later non-sudo command then hit
# PermissionError. Each consumer creates only the directory it actually
# needs, right when it needs it: FileStore.__init__ (core/store.py),
# ProvenanceGraphService.save (graph/service.py), GraphSAGE.save
# (detection/model.py), and KeyStore.load_or_create (crypto/integrity.py).
