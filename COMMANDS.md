# QuantumGuard — All Commands

Flat copy-paste reference. Run everything from the repository root.
For explanation see `RUN.md`; for design see `README.md`.

---

## 0. Install

```bash
cd QuantumGuard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 1. Fastest check — no database, no eBPF, no root

```bash
python -m tests.run_all
python main.py demo --partition-size 16
```

Expect `144 tests, 0 failed, 0 errors`, then a full attack demonstration.

---

## 2. Keys

```bash
python main.py keys                       # create on first run, then show

export QG_KEYSTORE_PASSPHRASE='something-long-and-not-this'
rm -rf keys/
python main.py keys                       # regenerate under the new phrase
```

---

## 3. Tests and measured results

```bash
python -m tests.run_all                   # all 144
python -m tests.test_all                  # Phases 1-5   (27)
python -m tests.test_phase67              # Phases 6-7   (49)

python -m tests.benchmark                 # regenerate every published number
python -m tests.benchmark --quick
python -m tests.benchmark --trials 25
python -m tests.benchmark --json evidence/benchmark.json
```

---

## 4. Demo

```bash
python main.py demo --partition-size 16

python main.py demo --partition-size 16 --strategy forgery
python main.py demo --partition-size 16 --strategy deletion
python main.py demo --partition-size 16 --strategy reorder
python main.py demo --partition-size 16 --strategy timeshift

python main.py demo --strategy forgery --sophistication 0.0   # crude
python main.py demo --strategy forgery --sophistication 1.0   # careful

python main.py demo --events 300 --batch-size 4 --seed 7
```

Always pass `--partition-size 16` for demos — the default of 128 puts a
small graph in one partition and hides the per-partition localisation.

---

## 5. Training

```bash
python main.py train --epochs 40
python main.py train --graph graphs/provenance_graph.gpickle --epochs 40

python -m detection.model --help
python -m detection.model --epochs 40 --synthetic 260 \
    --graph graphs/provenance_graph.gpickle \
    --hidden 64 --lr 0.003 --out models/gnn_detector.npz
```

---

## 6. Database setup

```bash
sudo -u postgres createdb provenance
sudo -u postgres psql -c "CREATE USER quantumguard WITH PASSWORD 'StrongPassword123';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE provenance TO quantumguard;"

sudo -u postgres psql -d provenance -f database/schema.sql

sudo -u postgres psql -d provenance -c \
  "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO quantumguard; \
   GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO quantumguard;"
```

Inspect:

```bash
sudo -u postgres psql -d provenance -c "\dt"
sudo -u postgres psql -d provenance -c "SELECT count(*) FROM raw_events;"
sudo -u postgres psql -d provenance -c "SELECT * FROM capture_sessions;"
sudo -u postgres psql -d provenance -c "SELECT * FROM cca_attestation ORDER BY id DESC LIMIT 5;"
sudo -u postgres psql -d provenance -c "SELECT run_id, partition_index, seq_start, seq_end FROM graph_partitions;"
sudo -u postgres psql -d provenance -c "SELECT run_id, tampered, rule_violation_count FROM detection_reports;"
sudo -u postgres psql -d provenance -c "SELECT run_id, risk_tier, risk_score FROM anchor_receipts;"
```

---

## 7. Capture

```bash
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r) bpftool
make -C ebpf

python main.py capture                    # Ctrl-C to stop
python main.py capture --run-id my-session
```

On Ctrl-C a signed completeness certificate is written to
`evidence/completeness_<run>.json`.

---

## 8. Pipeline

```bash
python main.py all                        # graph -> detect -> seal -> anchor -> evaluate
python main.py all --partition-size 16
```

Step by step:

```bash
python main.py graph                      # Phase 2/3
python main.py detect                     # Phase 4
python main.py seal                       # Phase 5
python main.py anchor                     # Phase 6
python main.py evaluate                   # Phase 7
```

### Detect

```bash
python main.py detect
python main.py detect --persist
python main.py detect --output evidence/detection_report.json
```

### Seal

```bash
python main.py seal
python main.py seal --partition-size 16
python main.py seal --partition-size 64
python main.py seal --run-id my-run-2026-10
python main.py seal --output evidence/sealed_graph.json
```

Note the run id it prints — you need it to verify that run later.

### Anchor

```bash
python main.py anchor
python main.py anchor --run-id my-run-2026-10
python main.py anchor --batch-size 4
python main.py anchor --ledger local
python main.py anchor --ledger fabric     # refuses without a Fabric network
```

### Evaluate

```bash
python main.py evaluate
python main.py evaluate --ratio 0.30
python main.py evaluate --mode edge
python main.py evaluate --mode node
python main.py evaluate --mode window
python main.py evaluate --mode insert
python main.py evaluate --mode mixed
python main.py evaluate --seed 7 --output evaluation/report.json

python -m evaluation.main --sweep         # across damage levels
python -m evaluation.main --sweep --mode node
```

### Verify

```bash
python main.py verify
python main.py verify --no-graph          # signatures and chain only
python main.py verify --run-id my-run-2026-10
python main.py verify --partition-size 16

python main.py verify && echo "evidence intact"   # exit 0 = PASS, 2 = FAIL
```

### Certify

```bash
python main.py certify evidence/completeness_a1b2c3d4.json
```

### Visualise

```bash
python main.py visualize                  # graphs/provenance_graph.png, one box per program
```

---

## 9. Prove tamper detection on your own data

```bash
# 1. build and seal
python main.py graph
python main.py seal --partition-size 16 --run-id tamper-test

# 2. confirm clean
python main.py verify --partition-size 16 --run-id tamper-test

# 3. tamper
python - <<'EOF'
import pickle, random
from detection.synthetic import TamperGenerator

G = pickle.load(open("graphs/provenance_graph.gpickle", "rb"))
H = TamperGenerator(random.Random(1), sophistication=1.0).apply(
        G, ["forgery"], intensity=0.1).graph
pickle.dump(H, open("graphs/provenance_graph.gpickle", "wb"))
print("tampered:", G.number_of_edges(), "->", H.number_of_edges())
EOF

# 4. every layer responds
python main.py detect
python main.py verify --partition-size 16 --run-id tamper-test
python main.py anchor --partition-size 16 --run-id tamper-test

# 5. restore
python main.py graph
```

Swap `"forgery"` for `"deletion"`, `"reorder"` or `"timeshift"`.
`sophistication=0.0` is a crude attacker, `1.0` a careful one.

---

## 10. Help

```bash
python main.py --help
python main.py keys --help
python main.py capture --help
python main.py graph --help
python main.py train --help
python main.py detect --help
python main.py seal --help
python main.py anchor --help
python main.py evaluate --help
python main.py verify --help
python main.py certify --help
python main.py all --help
python main.py demo --help

python -m detection.model --help
python -m evaluation.main --help
python -m crypto.integrity --help
python -m tests.benchmark --help
```

`--graph`, `--run-id` and `--partition-size` work either side of the
subcommand:

```bash
python main.py seal --partition-size 16 --run-id r1
python main.py --partition-size 16 --run-id r1 seal
```

---

## 11. Environment variables

```bash
export QG_DB_URL='postgresql+psycopg2://quantumguard:StrongPassword123@localhost/provenance'
export QG_STORE=auto                      # auto | db | file
export QG_PARTITION_SIZE=128
export QG_KEYSTORE_PASSPHRASE='change-me'
export QG_ALERT_MIN_NODES=2
export QG_LEDGER=local                    # local | fabric
export QG_ANCHOR_BATCH_SIZE=8
```

Force a backend for one command:

```bash
QG_STORE=file python main.py seal
QG_STORE=db   python main.py seal
```

---

## 12. Reset

```bash
rm -rf graphs/ models/ evidence/ keys/ ledger/ evaluation/report.json
rm -rf __pycache__ */__pycache__

sudo -u postgres psql -d provenance -c \
  "DROP TABLE IF EXISTS graph_partitions, detection_reports,
   anchor_receipts, survivability_reports, capture_sessions;"
```

Deleting `keys/` is irreversible for verification — signatures made with
the old key can no longer be checked. Reseal after regenerating.

Deleting `ledger/` discards every external anchor.

---

## 12a. Tamper testing

`python main.py tamper` attacks copies of the evidence and scores each layer
separately. It uses a temporary key store and ledger, so it never changes the
real graph, evidence, keys or ledger.

```bash
python main.py tamper test --trials 30                    # full scorecard
python main.py tamper apply --attack adaptive_forgery     # one tampered copy
python main.py detect --graph graphs/tampered_adaptive_forgery.gpickle \
       --output evidence/tampered_detection.json          # does the detector see it?
python main.py verify --graph graphs/tampered_adaptive_forgery.gpickle   # does the seal?
```

Graph attacks come in two families: `deletion/reorder/forgery/timeshift` at
`_crude` and `_expert` levels, which the GNN trained on, and `adaptive_deletion`,
`tail_truncate`, `adaptive_reorder`, `adaptive_forgery`, `binary_swap`,
`uid_rewrite` and `flag_abuse`, which it never saw. Evidence attacks modify the
sealed records and the ledger instead. Results are saved to
`evaluation/tamper_report.json`, and the exit status is 2 if an evidence attack
goes undetected.

## 12b. Dashboard

```bash
python main.py dashboard          # then open http://127.0.0.1:8765
```

A local web console. It uses only the Python standard library and listens only
on 127.0.0.1.

- **Live views** (Command Center, Capture, Provenance Graph, Detection, Evidence
  Seal, Anchoring) read your real data and never write. Verification uses public
  keys, so no passphrase is needed.
- **Simulation views** (Attack Lab, Pipeline Simulator, Survivability, Tamper
  Scorecard) run the real project code on a copy, in a temporary directory with a
  throwaway key store and ledger, which is deleted afterwards.

Capture still starts from a terminal, because it needs your `sudo` password.

## 13. Full run, start to finish

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export QG_KEYSTORE_PASSPHRASE='<your own>'

sudo -u postgres psql -d provenance -f database/schema.sql
sudo -u postgres psql -d provenance -c \
  "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO quantumguard; \
   GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO quantumguard;"

make -C ebpf
python main.py capture                    # 15+ minutes of real use, then Ctrl-C

python -m tests.run_all
python main.py keys
python main.py graph
python main.py train --graph graphs/provenance_graph.gpickle --epochs 40
python main.py all
python main.py verify
python main.py tamper test --trials 30
python -m tests.benchmark --json evidence/benchmark.json
```
