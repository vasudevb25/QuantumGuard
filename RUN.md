# QuantumGuard — How to Run

Every command, in order. For design rationale see `README.md`; this file
is purely operational.

Two paths:

- **Offline** — 5 minutes, no PostgreSQL, no eBPF, no root. Start here.
- **Live capture** — needs PostgreSQL, Linux and root for the eBPF probe.

---

## 1. Install

```bash
cd QuantumGuard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

One command, no compile step, no CUDA, no liboqs build.

Confirm the post-quantum backend loaded (this also creates your key store):

```bash
python main.py keys
```

```json
{
  "path": "keys/quantumguard.keystore.json",
  "ed25519_public_key": "aaab8f71...",
  "mldsa_algorithm": "ML-DSA-65",
  "mldsa_backend": "dilithium-py"
}
```

**Before any real use, change the key store passphrase.** The default is
printed in this project's own documentation, so a store protected only
by it is protected by nothing:

```bash
export QG_KEYSTORE_PASSPHRASE='something-long-and-not-this'
rm -rf keys/
python main.py keys
```

---

## 2. Offline — run everything without a database

### 2.1 Tests

```bash
python -m tests.run_all
```

Expect `124 tests, 0 failed, 0 errors`.

### 2.2 The demonstration

Builds a graph, seals it, verifies it, anchors it by risk, lets an
attacker tamper with it, then shows every layer responding.

```bash
python main.py demo --partition-size 16
```

All four attack strategies:

```bash
python main.py demo --partition-size 16 --strategy forgery
python main.py demo --partition-size 16 --strategy deletion
python main.py demo --partition-size 16 --strategy reorder
python main.py demo --partition-size 16 --strategy timeshift
```

Crude attacker versus careful attacker — the careful one recomputes
`process_hash` and keeps timestamps consistent:

```bash
python main.py demo --strategy forgery --sophistication 0.0
python main.py demo --strategy forgery --sophistication 1.0
```

**Always pass `--partition-size 16` for demos.** The default of 128 puts
a small graph in one partition, so you never see the per-partition
localisation that makes the output worth looking at.

### 2.3 Measured results

```bash
python -m tests.benchmark
python -m tests.benchmark --quick                      # fewer trials
python -m tests.benchmark --json evidence/benchmark.json
```

Everything it prints is measured at run time, not quoted.

### 2.4 Train the detector

```bash
python -m detection.model --epochs 40 --synthetic 260
```

Under a minute on CPU. Writes `models/gnn_detector.npz` and its
`.meta.json` sidecar.

Detection works without a model — the rule engine runs alone and says
so — but be aware of what you lose. The rules miss about 30% of partial
**deletions**, which the GNN catches. Neither reliably catches an attacker who
keeps the graph self-consistent; the cryptographic verifier catches those.
`python main.py tamper test` measures all of this.

---

## 3. Live capture — database setup

### 3.1 Create the database

```bash
sudo -u postgres createdb provenance
sudo -u postgres psql -c "CREATE USER quantumguard WITH PASSWORD 'StrongPassword123';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE provenance TO quantumguard;"
```

### 3.2 Load the schema

Every statement is `IF NOT EXISTS`, so this is safe to re-run against a
database that already holds evidence.

```bash
sudo -u postgres psql -d provenance -f database/schema.sql
```

Then re-grant — new tables are owned by `postgres` and do not inherit
the earlier grant:

```bash
sudo -u postgres psql -d provenance -c \
  "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO quantumguard; \
   GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO quantumguard;"
```

Verify:

```bash
sudo -u postgres psql -d provenance -c "\dt"
```

You should see seven tables: `raw_events`, `cca_attestation`,
`capture_sessions`, `graph_partitions`, `detection_reports`,
`anchor_receipts`, `survivability_reports`.

If your connection differs from the default:

```bash
export QG_DB_URL='postgresql+psycopg2://user:pass@host/provenance'
```

---

## 4. Live capture — collect events

```bash
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r) bpftool
make -C ebpf
python main.py capture          # Ctrl-C to stop
```

Leave it running and **use the machine in a second terminal** — open
shells, run `git status`, `curl`, compile something, `ls` around. You
want several hundred events, not a handful.

On Ctrl-C the collector writes a **signed completeness certificate** to
`evidence/completeness_<run>.json`, stating exactly which sequence range
it captured and which sequences it lost.

Check what you captured:

```bash
sudo -u postgres psql -d provenance -c "SELECT count(*) FROM raw_events;"
sudo -u postgres psql -d provenance -c "SELECT * FROM capture_sessions;"
```

Restarting the collector resumes from the highest stored sequence and
records the downtime as a `SESSION_GAP` attestation, so completeness
holds across restarts rather than only within one session.

---

## 5. The pipeline

### 5.1 Everything at once

```bash
python main.py all
```

Runs: graph → detect → seal → anchor → evaluate, passing the run id from
`seal` into `anchor` so they operate on the same evidence.

### 5.2 Step by step

**Build the graph** (Phases 2–3):

```bash
python main.py graph
```

**Train on your own capture** — do this before any review; the shipped
model has never seen your host:

```bash
python main.py train --graph graphs/provenance_graph.gpickle --epochs 40
```

**Detect poisoning** (Phase 4):

```bash
python main.py detect
python main.py detect --persist
python main.py detect --output evidence/detection_report.json
```

**Seal the evidence** (Phase 5):

```bash
python main.py seal
python main.py seal --partition-size 16
python main.py seal --run-id my-run-2026-10
```

Note the run id it prints — you need it to verify that run later.

**Anchor by risk** (Phase 6):

```bash
python main.py anchor
python main.py anchor --batch-size 8
python main.py anchor --run-id my-run-2026-10
python main.py anchor --ledger local          # or: fabric
```

The ledger lives in `ledger/anchor_ledger.json`, deliberately **not**
under `evidence/` — an anchor stored beside the evidence it protects is
destroyed by the same `rm`.

**Measure survivability** (Phase 7):

```bash
python main.py evaluate
python main.py evaluate --ratio 0.3 --mode node
python main.py evaluate --mode mixed           # delete and fabricate
python -m evaluation.main --sweep              # across damage levels
```

Damage modes: `edge`, `node`, `window`, `insert`, `mixed`.

**Verify everything independently**:

```bash
python main.py verify
python main.py verify --no-graph               # signatures and chain only
python main.py verify --run-id my-run-2026-10
```

Checks sealed partitions, the anchor ledger, and every completeness
certificate. Exit code is `0` on PASS and `2` on FAIL, so it scripts:

```bash
python main.py verify && echo "evidence intact"
```

**Verify one certificate**:

```bash
python main.py certify evidence/completeness_a1b2c3d4.json
```

### 5.3 Visualise

```bash
python main.py visualize         # graphs/provenance_graph.png, one box per program
```

---

## 6. Demonstrating tamper detection on your own data

```bash
# 1. build and seal
python main.py graph
python main.py seal --partition-size 16 --run-id tamper-test

# 2. confirm it verifies clean
python main.py verify --partition-size 16 --run-id tamper-test

# 3. tamper with it
python - <<'EOF'
import pickle, random
from detection.synthetic import TamperGenerator

G = pickle.load(open("graphs/provenance_graph.gpickle", "rb"))
H = TamperGenerator(random.Random(1), sophistication=1.0).apply(
        G, ["forgery"], intensity=0.1).graph
pickle.dump(H, open("graphs/provenance_graph.gpickle", "wb"))
print("tampered:", G.number_of_edges(), "->", H.number_of_edges(), "relations")
EOF

# 4. every layer should now respond
python main.py detect
python main.py verify --partition-size 16 --run-id tamper-test
python main.py anchor --partition-size 16 --run-id tamper-test

# 5. restore
python main.py graph
```

Step 4 is the one to show: the detector names the suspicious nodes, the
verifier names the exact partitions and relations that changed, and the
anchoring layer escalates those partitions to immediate external
anchoring.

---

## 7. Configuration

Nothing is hard-coded to one machine. All read by `core/config.py`.

| Variable | Default | Meaning |
|---|---|---|
| `QG_DB_URL` | `postgresql+psycopg2://quantumguard:StrongPassword123@localhost/provenance` | database connection |
| `QG_STORE` | `auto` | `auto` \| `db` \| `file` |
| `QG_PARTITION_SIZE` | `128` | relations per sealed partition |
| `QG_KEYSTORE_PASSPHRASE` | `quantumguard-dev` | **change this** |
| `QG_ALERT_MIN_NODES` | `2` | flagged nodes needed for a GNN-only alert |
| `QG_LEDGER` | `local` | `local` \| `fabric` |
| `QG_ANCHOR_BATCH_SIZE` | `8` | Tier-2 partitions per batched transaction |

`QG_STORE=auto` tries PostgreSQL and falls back to JSON files under
`evidence/`. That is deliberate: a system about evidence surviving should
not lose evidence because a database is down.

```bash
QG_STORE=file python main.py seal
QG_STORE=db   python main.py seal
```

---

## 8. Command reference

```
python main.py --help
python main.py <command> --help

  keys       create / show the key store
  capture    eBPF capture with completeness attestation   (Phase 1)
  graph      normalise events and build the graph         (Phase 2/3)
  train      train the GraphSAGE detector                 (Phase 4)
  detect     rule + GNN poisoning detection               (Phase 4)
  seal       Merkle partitions, hash chain, dual signing  (Phase 5)
  anchor     risk scoring and tiered anchoring            (Phase 6)
  evaluate   forensic survivability                       (Phase 7)
  verify     verify evidence, anchors and certificates
  certify    verify one completeness certificate
  all        graph -> detect -> seal -> anchor -> evaluate
  demo       full offline demonstration
```

`--graph`, `--run-id` and `--partition-size` work either before or after
the subcommand:

```bash
python main.py seal --partition-size 16 --run-id r1     # both
python main.py --partition-size 16 --run-id r1 seal     # work
```

---

## 9. Troubleshooting

**`ModuleNotFoundError: No module named 'core'`**
Run from the repository root.

**`graph not found`**
Run `python main.py graph` first, or use `python main.py demo`, which
needs no graph.

**Detector says "rules only"**
No trained model. Run `python main.py train`. Detection still works, but
see §2.4 for what you lose.

**`ImportError: Install 'dilithium-py' or 'liboqs-python'`**
`pip install dilithium-py`.

**`the database schema is out of date`**
Seal format 2 added two columns. Re-apply `database/schema.sql` (see §3.2).

**`key store could not be unlocked`**
`QG_KEYSTORE_PASSPHRASE` differs from when the store was created. Set it
back, or `rm -rf keys/` and reseal — signatures made with the lost key
can no longer be verified.

**`permission denied for table graph_partitions`**
Re-run the `GRANT` in §3.2. New tables do not inherit the old grant.

**`[store] PostgreSQL unavailable ... using file evidence store`**
Not an error — the intended fallback. Set `QG_STORE=db` to fail loudly.

**Verify says PASS but you know you tampered**
You probably rebuilt the graph after sealing, or used different
`--partition-size` values for seal and verify. They must match.

**Verify reports a run you did not expect**
Multiple sealed runs are stored and no `--run-id` was given, so all of
them are checked against the current graph. An older run sealed a
different graph and correctly reports as altered. Pass `--run-id`.

**`NotImplementedError: FabricLedger requires a running ... network`**
Expected. The Fabric adapter is an interface, not a simulation — see
`anchoring/ledger.py` for why it refuses rather than returning a
fabricated transaction id. Use `--ledger local`.

---

## 10. Before a review — checklist

```bash
python -m tests.run_all                                   # 124/124
python main.py tamper test --trials 30                    # which layer sees what
export QG_KEYSTORE_PASSPHRASE='<your own>'                # not the default
python main.py capture                                    # 15+ min of real use
python main.py graph
python main.py train --graph graphs/provenance_graph.gpickle
python main.py all
python -m tests.benchmark --json evidence/benchmark.json
python main.py demo --partition-size 16
```

Three things worth saying before anyone asks:

1. The detector is trained on **self-generated** tampering. Validation
   against DARPA OpTC is the next milestone.
2. The key store is a **software simulation**, not an HSM. Private keys
   enter host memory.
3. The anchor ledger is **local**. It provides append-only, chained,
   signed anchoring, but not the distributed trust a real Fabric network
   would. `anchoring/ledger.py` states exactly what it does and does not
   guarantee.
