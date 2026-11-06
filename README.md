# QuantumGuard

A host-based provenance security system for Linux. It captures
process-execution events in the kernel with eBPF, proves whether any
were lost, reconstructs a causal provenance graph, detects tampering
with that graph, seals it under hybrid classical and post-quantum
signatures, anchors the most valuable evidence outside the host, and
quantifies how much of it would survive a compromise.

> The premise: every graph-based forensic system assumes its input is
> an honest record. That assumption fails against the adversary who
> matters most — one who has obtained root, and therefore has the same
> privileges as the logging system itself. QuantumGuard treats the audit
> record as the thing under attack.

**Status: all seven phases implemented.** 144 tests pass with no
PostgreSQL, eBPF or root. Limitations are stated in
[Known limitations](#known-limitations) rather than left for a reader to
discover.

---

## Measured results

Everything below is produced by `python -m tests.benchmark`, 15 trials
per cell. These are not quoted from a previous run — regenerate them and
you get the same shape.

### Detection — can each layer see each attack?

| Attack | Attacker | Detected | By rules | By GNN |
|---|---|---|---|---|
| deletion | crude | 15/15 | 15/15 | 15/15 |
| deletion | sophisticated | 15/15 | 15/15 | 15/15 |
| reorder | crude | 15/15 | 15/15 | 15/15 |
| reorder | sophisticated | 15/15 | 15/15 | 15/15 |
| forgery | crude | 15/15 | 15/15 | 15/15 |
| forgery | sophisticated | 15/15 | 15/15 | 15/15 |
| timeshift | crude | 15/15 | 15/15 | 15/15 |
| timeshift | sophisticated | 15/15 | 15/15 | 15/15 |

"By rules" and "by GNN" here count any hit at all, including low-severity
rule hits. These are also the attacks the GNN trained on. See the tamper
scorecard below for what each layer does when it has to decide alone, and
against attacks it has never seen.

An earlier version of this table showed the rules catching 0/15 sophisticated
reorders. That attack swaps sequence and time on edges but not nodes, and a
one-line comparison of the two now catches it (`edge_node_mismatch`), so it is
no longer evidence for the learned component.

### Tamper scorecard: which layer notices what

`python main.py tamper test --trials 30`, on synthetic graphs the model did not
train on. "Trained" attacks are the ones in the model's training data.
"Held out" attacks were never in it, and keep the graph self-consistent. A layer
counts only if it would raise an alert by itself.

| Attack | Family | Rules | GNN | Reported verdict | Seal |
|---|---|---|---|---|---|
| clean graph (false alarms) | | 0% | 0% | 0% | 0% |
| deletion, crude | trained | 63% | 100% | 100% | 100% |
| deletion, expert | trained | 73% | 100% | 100% | 100% |
| reorder, crude / expert | trained | 100% | 100% | 100% | 100% |
| forgery, crude / expert | trained | 100% | 100% | 100% | 100% |
| timeshift, crude / expert | trained | 100% | 100% | 100% | 100% |
| adaptive deletion | held out | 0% | 3% | 3% | 100% |
| tail truncation | held out | 0% | 0% | 0% | 100% |
| adaptive reorder | held out | 7% | 13% | 13% | 100% |
| adaptive forgery | held out | 0% | 33% | 33% | 100% |
| binary swap | held out | 0% | 0% | 0% | 100% |
| uid rewrite | held out | 7% | 0% | 7% | 100% |
| flag abuse | held out | 100% | 97% | 100% | 100% |

The bottom half is the main result. **Against an attacker who keeps the graph
self-consistent, detection mostly fails and only the seal holds.** GNN figures
move by several points between training runs: adaptive forgery has measured
between 7% and 33%. The GNN adds real value on partial deletions the rules miss,
but it does not generalise well to attack types it has not seen.

**Real captures:** the GNN raises false alarms on real data even after retraining
on it. A clean 177-event capture was flagged, as were 2 of its 3 windows,
although clean synthetic graphs scored 0%. Real use looks unlike the synthetic
training data: most events there were PATH lookups by a program started before
the capture. False alarms also rise with size, reaching 33% of clean 800-event
synthetic graphs. A GNN-only result is therefore reported as SUSPICIOUS, never
TAMPERED, and warns above the 300-event training limit. Rules and the seal are
not affected by any of this. All 17 attacks on the sealed records and the ledger are
also caught. The seal depends on a trusted seal having been made before the
attack and on the signer's key being pinned.

### Integrity — what the cryptographic layer catches

| Attack | Crude | Sophisticated |
|---|---|---|
| deletion | 15/15 | 15/15 |
| reorder | 15/15 | 15/15 |
| forgery | 15/15 | 15/15 |
| timeshift | 15/15 | 15/15 |

**100%, with no training data and no distributional assumption.** This
is the guarantee the project rests on. If a sealed record changed, the
hash does not match — regardless of how sophisticated the attacker is,
and regardless of whether the GNN was right. The learned detector is a
second line on top of this, not a substitute for it.

### Risk scoring — separation between clean and tampered

```
clean captures    (15 runs): mean 0.008   max 0.018
tampered captures (15 runs): mean 0.430   min 0.268
```

| Threshold | Clean runs anchoring anything | Tampered runs anchored |
|---|---|---|
| 0.10 | 0/15 | 15/15 |
| 0.15 | 0/15 | 15/15 |
| **0.20** | **0/15** | **15/15** |
| 0.25 | 0/15 | 15/15 |
| 0.30 | 0/15 | 13/15 |

The Tier-2 threshold sits inside the gap between the highest clean score
(0.018) and the lowest tampered score (0.268). These tampered runs use the
trained attacks; a held-out attack the detector misses scores like a clean run
and is not anchored early.

### Anchoring cost — does cost follow risk?

| | Partitions | Externally anchored | Ledger transactions |
|---|---|---|---|
| 15 clean runs | 300 | 0 | **0** |
| 15 tampered runs | 304 | 250 | **16** |

A clean capture consumes nothing. A compromised one anchors 250
partitions in 16 transactions — **15.6× batching compression** — because
Tier-2 members share one second-order Merkle tree and each keeps an
inclusion proof into it.

### Survivability — evidence remaining after a compromise

| Damage | PIS | EPR | GRR | RA | FSI |
|---|---|---|---|---|---|
| 0% | 100.00 | 100.00 | 100.00 | 100.00 | 100.00 |
| 15% | 85.00 | 100.00 | 75.10 | 100.00 | 89.28 |
| 30% | 70.00 | 93.00 | 45.43 | 100.00 | 75.96 |
| 50% | 50.00 | 78.50 | 23.54 | 100.00 | 61.59 |
| 75% | 25.00 | 54.50 | 7.78 | 100.00 | 45.34 |

*(edge-removal mode; `node` and `window` modes are in the benchmark
output and behave comparably)*

### What sealing is worth, measured

The same attack — delete 25% and fabricate replacements — evaluated with
and without the Phase 5 sealed evidence available:

| | PIS | EPR | GRR | RA | FSI |
|---|---|---|---|---|---|
| with sealing | 75.75 | 98.50 | 64.55 | **100.00** | 83.56 |
| without sealing | 0.00 | 98.50 | 64.55 | **80.80** | 56.04 |

72 relations were fabricated. With sealed evidence the system rejected
every one of them; without it, it accepted them as authentic. **Recovery
Accuracy +19.20 points.** The sealed 100% is true by construction, since a
matching leaf hash is the original relation. The measurement is the unsealed
80.80%.

### GNN detector

Trained on 220 synthetic graphs of 25-300 events, some with normal sudo use,
plus the real capture, 40 epochs, CPU, under one minute. Figures are from one
training run on the project's 463-event capture and move between runs:

| Split | Precision | Recall | F1 | AUC |
|---|---|---|---|---|
| Validation — node | 0.820 | 0.790 | 0.805 | 0.961 |
| Test — node | 0.806 | 0.744 | 0.774 | 0.954 |
| Test — graph | 1.000 | 1.000 | 1.000 | — |

The threshold is raised until clean validation graphs rarely alert, because
choosing it by node F1 alone produced false alarms on 30% of clean graphs. These
splits contain only the trained attacks; see the tamper scorecard for the rest.

Node-level F1 is limited by the labels. The label marks
every node a corruption operator touched, including nodes at the
periphery of a deletion whose own features barely change — those are
genuinely ambiguous, and the ceiling is a property of the labelling
scheme rather than the architecture. The decision the system actually makes is
at graph level. Its test split held 35 graphs, and across training runs its
precision has measured between 0.88 and 1.00.

---

## Architecture

```
 execve()
    |
    v
 eBPF probe (ebpf/probes.c)        kernel-side filter, ring buffer
    |
    v
 capture/collector.py              Phase 1  sequence numbers, CCA,
 capture/cca.py                             session continuity,
    |                                       SIGNED completeness certificate
    v
 core/store.py                     PostgreSQL <-- QG_STORE --> JSON files
    |
    v
 graph/service.py                  Phase 2/3  dedupe -> validate ->
    |                                         execve-chain parent inference
    +---> graphs/provenance_graph.gpickle
    |
    v
 detection/                        Phase 4  10 deterministic rules
 detector.py, model.py,                     + 2-layer GraphSAGE
 features.py, synthetic.py
    |
    +---> evidence/detection_report.json
    |
    v
 crypto/integrity.py               Phase 5  Merkle partitions, hash chain,
    |                                       Ed25519 + ML-DSA-65 strict-AND
    +---> evidence/sealed_graph.json
    |
    v
 anchoring/                        Phase 6  risk scoring -> 3 tiers
 risk.py, ledger.py, service.py             -> external anchor
    |
    +---> ledger/anchor_ledger.json   (deliberately NOT under evidence/)
    +---> evidence/anchoring_report.json
    |
    v
 evaluation/main.py                Phase 7  PIS, EPR, GRR, RA, FSI
    |
    +---> evaluation/report.json
```

Every stage after capture runs **entirely offline** with
`QG_STORE=file` — no PostgreSQL, no eBPF, no root.

---

## The seven phases

### Phase 1 — Provenance capture with completeness attestation

An eBPF program on the `sys_enter_execve` tracepoint. In-kernel capture
matters adversarially: a user-space monitor is a process an attacker
with root can kill, trace or interpose; a kernel probe observes every
program launch before it can act.

Each event receives a monotonic sequence number, and any discontinuity
is recorded as an attestation. That is what makes the downstream
distinction decidable — a gap *with* an attestation is capture loss, a
gap *without* one is deletion. No reported system makes that
distinction.

Two properties beyond gap detection:

- **Continuity across restarts.** `SessionManager` resumes from the
  highest sequence already stored and records the downtime as an
  explicit `SESSION_GAP`. A counter that reset to 1 could only attest
  within one session and would collide with the primary key of events
  already captured.
- **Signature.** `CompletenessCertificate` covers a whole sequence
  range, names every gap inside it, and is signed with Ed25519 and
  ML-DSA. A third party with the public key can verify what the
  collector asserted and detect any later edit to that assertion. A gap
  record that is only checkable locally is a log entry, not an
  attestation.

### Phase 2/3 — Normalisation and graph construction

Deduplication, temporal validation with the reason for every discard
recorded, and parent-process inference.

The inference exploits a property of `execve`: at tracepoint invocation
the fork has already happened, so the process identifier belongs to the
new image while `comm` still holds the name of the image being replaced
— in practice the invoking shell. The parent's identity is carried in
the event itself and needs no guessing. An earlier version approximated
the parent as "the most recent process under the same uid", which is
invalid the moment two things run concurrently.

### Phase 4 — Poisoning detection

**Ten deterministic invariants** that a correctly captured graph must
satisfy: process-hash recomputation, temporal and causal inversion,
duplicate sequence, dangling edge, attribute conflict, orphan process,
self-loop, impossible timestamp, and the CCA-aware sequence gap. No
training data; no false positives on a well-formed graph.

**A two-layer GraphSAGE network** for what the rules were not written to
catch. 38 features per node across structural, temporal and attribute
families; mean aggregation over the symmetric adjacency, giving each
node a 2-hop receptive field matched to the perturbation radius of the
corruption operators.

GraphSAGE specifically because it is *inductive*: spectral methods like
GCN bind their filter to the training graph's Laplacian, and the
deployment requirement here is to score unseen graphs from unseen hosts
without retraining.

**Fusion is rule-priority.** Any critical or high violation forces a
tampered verdict; the network can only *add* detections, never overturn
a proven one.

Training labels come from controlled corruption — there is no public
corpus of poisoned provenance graphs, and DARPA OpTC labels intrusions
rather than record modification, which is a disjoint label space. A
`sophistication` parameter makes half the simulated attackers recompute
`process_hash`, maintain temporal consistency and clean up orphans,
which forces the model onto structural signals rather than a single
give-away attribute.

### Phase 5 — Integrity protection

Three layers, each catching what the others cannot:

| Layer | Catches |
|---|---|
| Merkle root per partition | any modified relation or node attribute |
| `prev_record_hash` chain | deletion or reordering of a whole partition |
| Ed25519 + ML-DSA-65, strict AND | forgery of the record itself, now and post-quantum |

The leaf hash covers the full sealed attributes of **both endpoint
nodes**, not just the edge — so editing a node's timestamp changes the
leaf even though no edge moved. Leaves and internal nodes use different
domain-separation prefixes, closing the second-preimage attack on naive
Merkle trees.

Verification is strict AND: forgery requires breaking an elliptic-curve
problem *and* a lattice problem simultaneously, and a future break of
either alone does not silently invalidate the archive.

Keys are held in a passphrase-protected store (scrypt → AES-256-GCM).

### Phase 6 — Risk-adaptive anchoring

Signing proves evidence was not *edited*. Anchoring is what survives
evidence being *destroyed* — an adversary at root can delete the entire
local archive, signatures included, and a hash chain that exists only on
the wiped machine proves nothing afterwards.

Anchoring everything is unaffordable; anchoring nothing is useless. This
is the cost Baseri et al. (2025) quantify and answer with risk-adaptive
anchoring — a proposal they never implemented. This phase is that
implementation.

**Risk scoring** is a weighted sum over six signals, each normalised to
[0,1] and each deliberately legible so an auditor can disagree with it:

| Signal | Weight |
|---|---|
| tamper alert present | 0.20 |
| rule violations in range | 0.25 |
| GNN suspicion | 0.25 |
| privilege activity (uid transitions, root execution) | 0.15 |
| unattested sequence gaps | 0.10 |
| rare executed images | 0.05 |

Plus two **hard escalation rules**, named explicitly rather than hidden
inside a scoring function: a tamper alert and a blocking rule violation
both force Tier 1 regardless of the arithmetic. Which rule fired is
recorded on every score.

**Three tiers:**

- **Tier 1 — immediate.** Anchored without delay. "Without delay" does
  not mean "alone": several urgent partitions produced in the same pass
  share one transaction, because holding none of them back costs nothing
  and paying N fees for simultaneous evidence is the waste the risk
  model exists to avoid.
- **Tier 2 — batched.** Held until the buffer fills, then a
  second-order Merkle tree is built over the members' *already-signed
  roots* and the single batch root is anchored. Each member keeps the
  sibling path proving its root sits under the anchored batch root, so
  batching costs no provability.
- **Tier 3 — local.** The Phase 5 hash chain only. No ledger
  transaction. `verify_anchor` reports Tier 3 as passing *with its
  limitation named* rather than silently.

### Phase 7 — Forensic survivability

Five measures answering what no reviewed system asks: how much evidence
is still usable, and how much of the attack path can still be walked?

| | Measure |
|---|---|
| **PIS** | fraction of sealed relations still present **and** verifying |
| **EPR** | fraction of originally captured events that survived |
| **GRR** | fraction of causal *reachability* retained |
| **RA** | accuracy of what the system asserts is authentic |
| **FSI** | weighted composite |

Two design points worth stating:

**GRR is measured over ancestor-descendant pairs, not edges.** An
investigator does not ask how many edges are left; they ask whether they
can still get from the phishing email to the exfiltration. A deleted
edge mid-chain destroys far more reachability than one at a leaf, and
counting edges misses that entirely.

**Recovery produces a classification, not restored bytes.** Deleted
evidence is gone. What sealing makes possible is establishing, for every
relation the archive attests to, whether it is `intact`, `missing`
(provable deletion) or `unsealed` (provable insertion). That is what
lets an investigator say "these 62 relations were deleted after capture"
rather than "some events seem to be missing".

Where a deleted process sat between two survivors, a bridge edge marked
`inferred=True` can be added, but finding those places needs the original
graph, and sealed evidence holds only hashes. A real investigator does not have
that, so GRR and FSI are computed without bridges. `GRR_bridged` is reported
separately as an upper bound.

---

## Dashboard

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

## Tamper testing

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

## Quick start

```bash
pip install -r requirements.txt
python -m tests.run_all                      # 144 tests
python main.py demo --partition-size 16      # full offline demonstration
python -m tests.benchmark                    # regenerate every number above
```

No PostgreSQL, no eBPF, no root required for any of those.

Full operational guide: **[RUN.md](RUN.md)**.

---

## Repository structure

```
capture/          Phase 1  eBPF collector, CCA, session continuity
  cca.py                   gap detection + signed completeness certificate
  collector.py             sequence assignment, session resume
graph/            Phase 2/3  normalisation and graph construction
detection/        Phase 4  rule engine + GraphSAGE
  detector.py              10 invariants, rule/GNN fusion
  features.py              38-dimensional node encoding
  model.py                 GraphSAGE, Adam, training loop
  synthetic.py             graph generation + tamper generator (labels)
crypto/           Phase 5  Merkle, hash chain, hybrid signing
anchoring/        Phase 6  risk scoring, ledger, tiered anchoring
  risk.py                  six-signal model + escalation rules
  ledger.py                append-only chained ledger; Fabric interface
  service.py               tier assignment, second-order batching
dashboard/                 web console and sandboxed simulations
evaluation/       Phase 7  attack simulation, recovery, five measures
                           tamper.py: attacks every layer and scores it
core/                      config and the storage boundary
tests/
  test_all.py              Phases 1-5            (27 tests)
  test_phase67.py          Phases 6-7 and CCA    (49 tests)
  test_tamper.py           bug regressions and tamper harness (48 tests)
  test_dashboard.py        dashboard and simulations (20 tests)
  run_all.py               all four              (144 tests)
  benchmark.py             reproducible measured results
```

---

## Known limitations

Stated here rather than left to be found.

**The detector is trained on self-generated tampering.** No public
corpus of poisoned provenance graphs exists, so the training
distribution is synthetic graphs plus windows of real capture, corrupted
by four operators we implemented. The reported figures are
in-distribution. They demonstrate the approach works against those four
strategies; they are not evidence of performance against an adversary
using a fifth we did not anticipate. Validation against DARPA OpTC is
the next milestone. *This limitation applies only to the learned
component — the cryptographic layer carries no distributional
dependency.*

**The key store is a software simulation, not an HSM.** Keys are
encrypted at rest with scrypt and AES-GCM, but key material does enter
host memory, which a hardware module would prevent. The interface is
shaped like PKCS#11 so SoftHSM can be substituted.

**The anchor ledger is local.** `LocalLedger` provides append-only,
hash-chained, dual-signed anchoring and verifies independently. It does
*not* provide the property a distributed ledger provides — that no
single party can rewrite history because no single party holds it. An
attacker with root and the passphrase could discard the file and forge a
replacement chain. `FabricLedger` implements the same interface and
closes that gap, but requires a running Fabric network; it raises rather
than returning fabricated transaction identifiers, because a simulated
receipt would be worse than an honest failure.

**Capture is execve-only.** We observe which programs ran and what
spawned them, not file reads or network connections. The graph is a
process tree with file targets, not a full data-flow graph. Extending to
`vfs_write` and `tcp_connect` probes is future work.

**An exploited root service can still go unseen.** Capture keeps anything run
by a user with uid >= 1000 or inside a login session, so `sudo`, `su` and a root
login are recorded. A system service has no login session, so an attacker who
gets root by exploiting one looks like every other service and is filtered out.
Removing the filter closes this but records all service activity.

**Parents are inferred, not observed.** A process's parent is the most recent
event whose binary name matches its `comm`. The probe could read the real parent
pid from the kernel, which would remove this guesswork.

**Attack reconstruction is not implemented**, despite appearing in the
project title. Reconstruction systems such as Kairos operate on a
provenance graph; this work ensures the graph they consume is complete
and untampered. We protect their input.

**No ablations or baselines.** We have not isolated the contribution of
individual feature families, compared against GCN/GAT/GIN, or tested
other depths. A venue submission would expect these.

---

## Novelty, assessed honestly

**Genuinely novel.** Treating provenance-graph poisoning as a
first-class detectable attack. Every graph-based forensic system in our
review — Kairos, MGDA, and the rest — begins from an assumption of input
fidelity. None detects deletion, reordering or forgery of the record
itself.

**Novel as a combination, not individually.** Hybrid Ed25519 + ML-DSA
signing is *not* novel on its own; it has been proposed and applied
elsewhere. Merkle batching over audit logs is decades old. What is
unbuilt is the pipeline: completeness attestation feeding poisoning
detection feeding cryptographically sealed, chained, dual-signed,
risk-anchored evidence, with survivability quantified at the end.

**Two smaller contributions worth naming.** The tamper alert is itself
sealed and anchored — an attacker can attempt to destroy the record
proving they were caught, but not quietly. And detection runs *before*
certification, so tampering is caught rather than inherited into the
signed archive.

---

## References

[1] R. Sekar, H. Kimm, R. Aich. *eAudit: A Fast, Scalable and Deployable
Audit Data Collection System.* IEEE S&P 2024, pp. 3571–3589.

[2] Y. Hu, K. Hooshmand, H. Kalidhindi, S. J. Yang, R. A. Popa.
*Merkle²: A Low-Latency Transparency Log System.* IEEE S&P 2021,
pp. 285–303.

[3] Y. Baseri, A. Hafid, Y. Shahsavari, D. Makrakis, H. Khodaiemehr.
*Blockchain Security Risk Assessment in Quantum Era, Migration
Strategies and Proactive Defense.* IEEE COMST, 2025.

[4] M. Cui, Z. Jiang, S. Li, C. Ma, K. Zhang, P. Yang, H. Feng. *MGDA: A
Provenance Graph-Based Framework for Threat Detection and Attack
Scenario Reconstruction.* Computer Networks, vol. 274, 2025.

[5] M. Zipperle, F. Gottwalt, E. Chang, T. Dillon. *Provenance-based
Intrusion Detection Systems: A Survey.* ACM Computing Surveys, vol. 55,
no. 7, 2022.

[6] Z. Cheng, Q. Lv, J. Liang, Y. Wang, D. Sun, T. Pasquier, X. Han.
*Kairos: Practical Intrusion Detection and Investigation using
Whole-system Provenance.* IEEE S&P 2024, pp. 3533–3551.

[7] NIST. *Module-Lattice-Based Digital Signature Standard.* FIPS 204,
2024.

[8] W. L. Hamilton, R. Ying, J. Leskovec. *Inductive Representation
Learning on Large Graphs.* NeurIPS 2017.
