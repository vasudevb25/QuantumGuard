# QuantumGuard

**QuantumGuard** is a host-based provenance security system for Linux. It
captures process-execution events at the kernel level with eBPF, verifies
that no events were silently lost (Capture Completeness Attestation),
reconstructs a causal provenance graph, detects provenance-poisoning
attacks with a rule engine and a GraphSAGE GNN, and finally seals the
graph with Merkle-tree partitions and hybrid Ed25519 + ML-DSA (post-quantum)
signatures.

> Research focus: making event loss _provable_ rather than assumed away,
> and treating the provenance record itself as an asset an attacker will
> try to falsify - so it gets the same tamper-evidence a ledger would.

---

## Architecture

```
 execve()
    |
    v
 eBPF probe (ebpf/probes.c)          kernel-side UID filter, ring buffer
    |
    v
 loader (ebpf/loader.c)              reads the ring buffer, emits JSON lines
    |
    v
 capture/collector.py                sequence numbers + CCA + userspace filters
    |
    v
 core/store.py                       PostgreSQL  <-- QG_STORE=auto|db|file -->  FileStore (JSON)
    |
    v
 graph/service.py (Phase 3)          dedupe -> validate -> enrich -> build DiGraph
    |
    +---> graphs/provenance_graph.gpickle, provenance.graphml
    |
    v
 detection/ (Phase 4)                RuleEngine (10 invariants) + GraphSAGE GNN
    |
    +---> evidence/detection_report.json
    |
    v
 crypto/integrity.py (Phase 5)       Merkle partitions, hash chain, Ed25519+ML-DSA
    |
    +---> evidence/sealed_graph.json
    |
    v
 evaluation/main.py (Phase 7)        controlled poisoning + recovery survivability metrics
```

Every stage after capture can also run **entirely offline**: set
`QG_STORE=file` and nothing here touches PostgreSQL, eBPF, or root - see
[Running without PostgreSQL or eBPF](#running-without-postgresql-or-ebpf).

---

## Repository structure

```
QuantumGuard/
├── ebpf/                    Phase 1 - kernel capture (C)
│   ├── probes.c                tracepoint/syscalls/sys_enter_execve, ring buffer
│   ├── loader.c                userspace loader, prints JSON events to stdout
│   ├── vmlinux.h               generated kernel type info (bpftool btf dump)
│   └── Makefile
│
├── capture/                 Phase 1/2 - collection, sequencing, completeness
│   ├── collector.py             orchestrates the loader subprocess -> store
│   ├── cca.py                   Capture Completeness Attestation
│   └── models.py                RawEvent
│
├── graph/                   Phase 3 - provenance graph construction
│   ├── service.py               dedupe / validate / enrich / build (the schema contract
│   │                             detection/ and crypto/ depend on - read its docstring)
│   ├── models.py                ProvenanceEvent
│   ├── main.py                  `python -m graph.main` CLI
│   └── visualize.py             matplotlib rendering -> graphs/provenance_graph.png
│
├── detection/                Phase 4 - poisoning detection
│   ├── features.py              38-dim node feature extraction (structural/temporal/attribute)
│   ├── synthetic.py             synthetic graphs, real-graph windowing, tampering
│   │                             strategies, and train/val/test dataset assembly
│   ├── model.py                 GraphSAGE (pure NumPy), Adam, metrics, training CLI
│   └── detector.py               RuleEngine (10 invariants) + GNN fusion, inference CLI
│
├── crypto/                   Phase 5 - integrity protection
│   └── integrity.py             Merkle tree, partitioning, KeyStore, hybrid
│                                 Ed25519/ML-DSA signing, verification, CLI
│
├── evaluation/                Phase 7 - forensic survivability
│   └── main.py                   controlled poisoning + recovery + PIS/EPR/GRR/RA/FSI
│
├── core/                      shared infrastructure
│   ├── config.py                 every environment-overridable setting
│   └── store.py                  PostgreSQLStore / FileStore behind one interface
│
├── database/
│   └── schema.sql                 raw_events, cca_attestation (Phase 1/2), graph_partitions,
│                                   detection_reports, capture_sessions (Phase 4/5) - one
│                                   file, every statement is CREATE ... IF NOT EXISTS
│
├── tests/                     offline unit tests (no Postgres/eBPF/root needed)
│   └── test_all.py                `python -m tests.test_all` - 27 tests, one file
│
├── main.py                    single CLI entry point for every phase
└── requirements.txt
```

---

## Setup

### 1. System dependencies (for real kernel capture)

```bash
sudo apt update
sudo apt install clang llvm bpftool libbpf-dev build-essential \
                  graphviz graphviz-dev postgresql postgresql-contrib
```

You only need this section for **live capture**. Graph construction,
detection, crypto, evaluation and the test suite all run without it - see
[Running without PostgreSQL or eBPF](#running-without-postgresql-or-ebpf).

### 2. Python environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Database (skip this for the offline/FileStore path)

```bash
sudo -u postgres createdb provenance
sudo -u postgres psql -d provenance -c \
  "CREATE USER quantumguard WITH PASSWORD 'StrongPassword123'; \
   GRANT ALL PRIVILEGES ON DATABASE provenance TO quantumguard;"

sudo -u postgres psql -d provenance -f database/schema.sql
sudo -u postgres psql -d provenance -c \
  "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO quantumguard; \
   GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO quantumguard;"
```

Using a different host, user, password or database name? Set `QG_DB_URL`
instead of editing `core/config.py` - see [Configuration](#configuration).

### 4. Build the eBPF probe

```bash
make -C ebpf
```

Produces `ebpf/loader`, `ebpf/probes.o`, `ebpf/probes.skel.h` (all
build output, gitignored). Re-run this after any change to `ebpf/probes.c`.

---

## Running the full pipeline

`main.py` is the single entry point for every phase:

```bash
python  main.py capture                  # Phase 1/2 - prompts for sudo itself; Ctrl+C to stop
python  main.py graph                    # Phase 3 - builds the provenance graph
python  main.py train --epochs 100       # Phase 4 - trains the GNN (mixes in the real graph)
python  main.py detect                   # Phase 4 - rules + GNN, writes a detection report
python  main.py seal                     # Phase 5 - Merkle-seals + signs the graph
python  main.py evaluate                 # Phase 7 - survivability metrics
python  main.py all                      # graph -> detect -> seal -> evaluate, one command
```

**Never run `capture` with an outer `sudo`.** `capture/collector.py` already invokes
`sudo ./ebpf/loader` internally for just the tiny C loader that needs
kernel privileges - the Python process itself, and everything it writes,
stays as your normal user. `sudo python main.py capture` instead elevates
the *whole* process, so every file/directory it touches (`graphs/`,
`models/`, `keys/`, `evidence/`) gets created root-owned, and every
later command fails with `PermissionError` until you `sudo chown -R
$(id -u):$(id -g) graphs models keys evidence` to undo it.

Each step's output:

| Command    | Produces                                                                 |
| ---------- | ------------------------------------------------------------------------ |
| `capture`  | rows in `raw_events` / `cca_attestation` (or `evidence/*.jsonl` offline) |
| `graph`    | `graphs/provenance_graph.gpickle`, `graphs/provenance.graphml`           |
| `train`    | `models/gnn_detector.npz`, `models/gnn_detector.meta.json`               |
| `detect`   | `evidence/detection_report.json` (rule violations, GNN scores, verdict)  |
| `seal`     | `evidence/sealed_graph.json` (Merkle roots, hash chain, dual signatures) |
| `evaluate` | `evaluation/report.json` (PIS / EPR / GRR / RA / FSI)                    |

Visualize the graph separately (needs `capture`/`graph` to have run first):

```bash
python -m graph.visualize            # -> graphs/provenance_graph.png
```

Each phase also has its own direct CLI, useful when you only want that
one piece:

```bash
python -m detection.model --epochs 120 --hidden 96 --synthetic 300
python -m crypto.integrity --graph graphs/provenance_graph.gpickle --partition-size 64
python -m evaluation.main --ratio 0.25 --seed 1
```

### Running without PostgreSQL or eBPF

Every phase after capture works identically against a JSON-file backend,
which makes the whole pipeline runnable on a laptop with no root, no
Postgres, and no kernel module:

```bash
export QG_STORE=file        # default is "auto": try Postgres, fall back to file
python main.py graph        # reads evidence/raw_events.jsonl instead of a table
python main.py detect
python main.py seal
python main.py evaluate
```

`capture/collector.py` still needs eBPF and root to produce _real_
`raw_events.jsonl`, but for detection/crypto/evaluation, training a model,
or just exploring the code, `detection.synthetic.generate()` produces
graphs with the identical schema, and that's exactly what
`detection/model.py`'s training pipeline and the test suite already run on.

### Tests

```bash
python -m tests.test_all
```

27 tests, no PostgreSQL, no eBPF, no root. Covers: Merkle tree/proof
correctness at several leaf counts, key-store round trip and
wrong-passphrase rejection, hybrid-signature verification with either
algorithm broken independently, seal/verify detecting a deleted edge and
an edited node attribute, the rule engine on clean and tampered graphs,
CCA-attested gaps not being reported as tampering, feature-extraction
determinism, an **analytic-vs-numerical gradient check on the GraphSAGE
backward pass**, every tampering strategy producing consistent labels,
FileStore round trips, and the Phase 3 execve-chain parent inference.

---

## Configuration

Everything that varies per machine or deployment is environment-overridable
(`core/config.py`) - nothing is hard-coded to one host.

| Variable                 | Default                                                                     | Meaning                                                           |
| ------------------------ | --------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| `QG_DB_URL`              | `postgresql+psycopg2://quantumguard:StrongPassword123@localhost/provenance` | Phase 1/2/3 database                                              |
| `QG_STORE`               | `auto`                                                                      | `db` \| `file` \| `auto` (try Postgres, fall back to `FileStore`) |
| `QG_PARTITION_SIZE`      | `128`                                                                       | edges per Merkle partition                                        |
| `QG_ALERT_MIN_NODES`     | `2`                                                                         | nodes the GNN alone must flag before calling a graph tampered     |
| `QG_KEYSTORE_PASSPHRASE` | `quantumguard-dev`                                                          | decrypts `keys/quantumguard.keystore.json` - **change this**      |

---

## Phase notes

### Phase 1/2 - capture and completeness

`ebpf/probes.c` hooks `sys_enter_execve` and filters to UID >= 1000 in the
kernel (the same threshold `capture/collector.py` re-applies in
userspace as defence in depth), so system/service accounts never reach
the ring buffer. `capture/cca.py`'s `CCA` class tracks the expected vs.
received sequence number per process and records any gap - that gap
record is what lets `detection/detector.py`'s `sequence_gap` rule tell
"an attacker deleted an event" apart from "the kernel legitimately
dropped one under load".

### Phase 3 - provenance graph (`graph/service.py`)

Canonical process id is `P:{pid}:{sequence}` (one identity per process,
not split across two nodes). Parent inference uses a real property of
execve: at `sys_enter_execve` the kernel has already forked, so `pid` is
the _new_ process but `comm` is still the name of the image being
replaced - the parent. An event `(pid=4321, comm="bash",
file="/usr/bin/ls")` means "something called bash exec'd ls", so it links
to the most recent earlier event, same uid, whose executed binary's
basename equals this event's `comm` (truncated to 15 chars -
`TASK_COMM_LEN` is 16 bytes including the NUL). Events with no match
attach to a per-uid session-root node instead of being left orphaned.
Dropped events (out-of-order sequence/timestamp) are recorded in
`service.dropped` rather than silently discarded.

**Schema contract.** Every node/edge attribute name this module writes -
`process_hash` (not `hash`), `synthetic_root` (not `synthetic`), `seq`
and `ts` on every edge (not just `sequence`) - is read by
`detection/features.py`, `detection/detector.py`, and
`crypto/integrity.py`. A real captured graph and a
`detection/synthetic.py`-generated graph must share this schema exactly,
or tamper detection and integrity sealing silently degrade instead of
failing loudly (this happened before it was fixed - see
`graph/service.py`'s module docstring for the full story, and
`tests/test_all.py`'s `GraphSchemaTest` for the regression tests that now guard it).

### Phase 4 - poisoning detection (`detection/`)

**The rule engine** (in `detection/detector.py`) encodes ten invariants a
correctly captured graph is guaranteed to satisfy, so a violation is
proof of tampering (or of a capture bug, equally worth surfacing) rather
than a guess:

| Rule                    | Severity | Catches                                            |
| ----------------------- | -------- | -------------------------------------------------- |
| `process_hash_mismatch` | critical | node attributes edited after capture               |
| `dangling_edge`         | critical | edge pointing at a node missing from the graph     |
| `duplicate_sequence`    | high     | injected events reusing a sequence number          |
| `temporal_inversion`    | high     | later sequence carrying an earlier timestamp       |
| `causal_inversion`      | high     | child timestamped before its parent                |
| `attribute_conflict`    | high     | one pid under conflicting uids                     |
| `sequence_gap`          | medium   | missing sequence numbers _with no CCA attestation_ |
| `self_loop`             | medium   | process spawning or executing itself               |
| `impossible_timestamp`  | medium   | negative timestamp                                 |
| `orphan_process`        | low      | process whose causal origin can't be reconstructed |

`sequence_gap` is where Phase 1's CCA and Phase 4's detector connect: a
gap the CCA layer already attested as capture loss is not reported as
tampering. `main.py detect` wires this automatically by loading
`store.load_missing_sequences()` before running the rules.

**The GNN** (`detection/model.py` + `features.py`) is a two-layer
GraphSAGE with a mean aggregator, implemented in ~250 lines of NumPy with
an explicit forward and backward pass (no PyTorch/CUDA dependency,
trains hundreds of graphs in seconds on a CPU, and every line is
explainable in a viva - the backward pass is checked against numerical
gradients in `tests/test_all.py`'s `GraphSAGEGradientCheckTest`). Training data has no public
source (nobody publishes labelled _poisoned provenance graphs_), so
`detection/synthetic.py` generates it: synthetic execve-tree graphs mixed
with overlapping windows of your own real capture, half left clean and
half hit with one of four tampering strategies (deletion, reorder,
forgery, timeshift) at a randomised sophistication level, so the model
learns structural signals rather than one give-away attribute.

**Fusion policy** (`detection/detector.py`): any critical/high rule
violation means tampered at confidence 1.0, regardless of what the GNN
says; the GNN can only ever _add_ detections. `main.py train` mixes your
real captured graph in automatically if `graphs/provenance_graph.gpickle`
exists - retrain after any real capture for a host-tuned model.

### Phase 5 - integrity protection (`crypto/integrity.py`)

```
partition 0 --.
partition 1 --+-- Merkle root over its relations
partition 2 --'   + hash of the PREVIOUS record         (chain)
                  + Ed25519 signature                   (classical)
                  + ML-DSA-65 signature                  (post-quantum)
```

Partitioning is deterministic (edges sorted by `seq, ts, relation, src,
dst`, chunked at `QG_PARTITION_SIZE`), so two parties building partitions
from the same graph get byte-identical results. Merkle leaves cover both
endpoint nodes' full sealed attributes as well as the edge, so editing a
node's timestamp changes the leaf even though no edge was touched.
Verification compares leaves as **sets**, not by position, so inserting
one relation doesn't make the whole archive look rewritten - insertions
are localised to the partition whose sequence range they fall in.
Signing is strict AND across Ed25519 and ML-DSA-65 (`dilithium-py`, or
`liboqs-python` if installed): an attacker has to break an elliptic-curve
problem _and_ a lattice problem, and the signed message is domain-separated
so a signature can never be replayed in a different context.

The key store (`crypto.integrity.KeyStore`) is a software-HSM simulation:
`passphrase --scrypt--> KEK --AES-256-GCM--> wrapped private keys`, never
written to disk in plaintext. Key material does enter host memory, which
a real HSM would prevent - state that limitation rather than letting
someone find it.

### Phase 7 - forensic survivability (`evaluation/main.py`)

Simulates a poisoning attack as controlled random edge removal, runs a
baseline recovery pass (drop isolated fragments), and reports five
metrics: **PIS** (structural survival), **EPR** (event preservation),
**GRR** (graph recovery rate), **RA** (recovery accuracy), and their
weighted composite **FSI**.

---

## Known limitations

State these before someone finds them.

1. **Sequence resets on collector restart.** `capture/collector.py`'s
   `SequenceManager` starts at 1 every run, so completeness is only
   provable _within_ one session. `database/schema.sql` already
   defines `capture_sessions` for per-run continuity; wiring a `run_id`
   through `capture/collector.py` and `graph/service.py` is a Phase 1/3
   change that hasn't been made.
2. **CCA is not yet cryptographically signed.** Gaps are logically
   detected and now feed the rule engine (see Phase 4 above), but the
   attestation itself isn't sealed the way graph partitions are -
   nothing yet stops an attacker who controls the database from deleting
   an inconvenient `cca_attestation` row outright.
3. **Software key store, not a real HSM.** Private keys enter host memory.
4. **Detector trained on self-generated tampering.** There is no public
   dataset of poisoned provenance graphs (DARPA TC/OpTC label attacks,
   not audit-record tampering), so labels come from
   `detection/synthetic.py`'s own `TamperGenerator`. Treat metrics in
   `models/gnn_detector.meta.json` as a demonstration on this
   distribution, not an external validation.
5. **Capture is execve-only.** No file or network provenance, so the
   graph is a process tree with file targets, not a full data-flow graph.
6. **`impossible_timestamp` only catches negative timestamps**, not
   far-future ones - event timestamps are boot-relative
   (`bpf_ktime_get_ns()`), so comparing against wall-clock "now" would
   flag every legitimate timestamp as "future" once reviewed after a
   reboot. See the comment in `detection/detector.py::_temporal_rules`.
7. **Phase 6 (risk-adaptive anchoring) is not built.** Hooks
   (`risk_tier_hint`, `MerkleTree` groundwork for a second-order root,
   `IntegrityService.inclusion_proof`) exist for it.

---

## Verification checklist

Everything below has been run and confirmed working, against both a live
PostgreSQL capture and the offline `QG_STORE=file` path:

- [x] `make -C ebpf` builds `loader` / `probes.o` / `probes.skel.h`
- [x] `python main.py graph` → `graphs/provenance_graph.gpickle` with
      `process_hash`, `synthetic_root`, and `seq`/`ts` on every edge
- [x] `python main.py train` → `models/gnn_detector.npz` + `.meta.json`
- [x] `python main.py detect` → rule engine + GNN fused verdict
- [x] `python main.py seal` → Merkle-sealed, dual-signed evidence,
      `Verified: True`
- [x] `python main.py evaluate` → PIS/EPR/GRR/RA/FSI report
- [x] `python -m tests.test_all` → 27/27 passing

---

## Resetting to a clean state

Everything the pipeline writes is regenerable output (`graphs/`,
`models/`, `evidence/`, `keys/`, and five Postgres tables) - safe to wipe
between demo runs, or before a fresh capture session. If you want to keep
a copy of a run's results first (e.g. to compare before/after a demo),
copy them out before deleting:

```bash
cp evidence/detection_report.json evidence/sealed_graph.json \
   evaluation/report.json models/gnn_detector.meta.json  ~/qg-demo-backup/
```

### Quick reset (keep the DB user/schema, wipe the data)

```bash
# empty every table but keep the schema and reset id/serial counters
sudo -u postgres psql -d provenance -c \
  "TRUNCATE TABLE raw_events, cca_attestation, graph_partitions, \
   detection_reports, capture_sessions RESTART IDENTITY;"

# delete every generated file - main.py recreates these dirs on next run
rm -rf graphs models evidence keys

# optional: also clear bytecode caches
find . -name "__pycache__" -exec rm -rf {} +
```

After this, `python main.py graph` (or `capture` first, for a live
demo) starts completely fresh - no old nodes, no stale detection report,
no keystore left over from the last run.

### Full reset (drop the database entirely)

Only if you want to remove the `provenance` database and `quantumguard`
role too, e.g. handing the machine to someone else:

```bash
sudo -u postgres dropdb provenance
sudo -u postgres psql -c "DROP ROLE IF EXISTS quantumguard;"
rm -rf graphs models evidence keys venv
```

Then repeat [Setup](#setup) from step 2 onward to rebuild.

### Offline (`QG_STORE=file`) reset

There's no database involved, so the quick reset is just:

```bash
rm -rf graphs models evidence keys
```
