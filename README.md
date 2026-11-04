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

**Status: all seven phases implemented.** 76 tests pass with no
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
| **reorder** | **sophisticated** | **15/15** | **0/15** | **15/15** |
| forgery | crude | 15/15 | 15/15 | 15/15 |
| forgery | sophisticated | 15/15 | 15/15 | 15/15 |
| timeshift | crude | 15/15 | 15/15 | 15/15 |
| timeshift | sophisticated | 15/15 | 15/15 | 15/15 |

The bold row is why the learned component exists. A sophisticated
reorder swaps sequence numbers *and* timestamps together, so every
deterministic invariant remains satisfied and the rule engine sees
nothing. The GNN catches it in all 15 trials on structural grounds. One
row of this table is the entire argument for not shipping rules alone.

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
clean captures    (15 runs): mean 0.021   max 0.075
tampered captures (15 runs): mean 0.364   min 0.228
```

| Threshold | Clean runs anchoring anything | Tampered runs anchored |
|---|---|---|
| 0.10 | 0/15 | 15/15 |
| 0.15 | 0/15 | 15/15 |
| **0.20** | **0/15** | **15/15** |
| 0.25 | 0/15 | 11/15 |
| 0.30 | 0/15 | 8/15 |

The Tier-2 threshold is **calibrated on this separation, not chosen**.
An earlier guessed value of 0.25 missed roughly a quarter of tampered
runs; 0.20 sits inside the gap between the highest clean score (0.075)
and the lowest tampered score (0.228).

### Anchoring cost — does cost follow risk?

| | Partitions | Externally anchored | Ledger transactions |
|---|---|---|---|
| 15 clean runs | 300 | 0 | **0** |
| 15 tampered runs | 304 | 189 | **16** |

A clean capture consumes nothing. A compromised one anchors 189
partitions in 16 transactions — **11.8× batching compression** — because
Tier-2 members share one second-order Merkle tree and each keeps an
inclusion proof into it.

### Survivability — evidence remaining after a compromise

| Damage | PIS | EPR | GRR | RA | FSI |
|---|---|---|---|---|---|
| 0% | 100.00 | 100.00 | 100.00 | 100.00 | 100.00 |
| 15% | 85.00 | 100.00 | 75.10 | 100.00 | 89.28 |
| 30% | 70.00 | 93.00 | 46.55 | 100.00 | 76.24 |
| 50% | 50.00 | 78.50 | 27.27 | 100.00 | 62.52 |
| 75% | 25.00 | 54.50 | 19.75 | 100.00 | 48.34 |

*(edge-removal mode; `node` and `window` modes are in the benchmark
output and behave comparably)*

### What sealing is worth, measured

The same attack — delete 25% and fabricate replacements — evaluated with
and without the Phase 5 sealed evidence available:

| | PIS | EPR | GRR | RA | FSI |
|---|---|---|---|---|---|
| with sealing | 75.75 | 98.50 | 64.93 | **100.00** | 83.66 |
| without sealing | 0.00 | 98.50 | 64.93 | **80.80** | 56.13 |

72 relations were fabricated. With sealed evidence the system rejected
every one of them; without it, it accepted them as authentic. **Recovery
Accuracy +19.20 points.** This quantifies what Phase 5 buys rather than
asserting it.

### GNN detector

Trained on 260 synthetic base graphs plus windows of real capture,
40 epochs, CPU, under one minute:

| Split | Precision | Recall | F1 | AUC |
|---|---|---|---|---|
| Validation — node | 0.751 | 0.717 | 0.733 | 0.946 |
| Test — node | 0.775 | 0.611 | 0.684 | 0.937 |
| Test — graph | 1.000 | 1.000 | 1.000 | — |

Node-level F1 in the high sixties is the honest number. The label marks
every node a corruption operator touched, including nodes at the
periphery of a deletion whose own features barely change — those are
genuinely ambiguous, and the ceiling is a property of the labelling
scheme rather than the architecture. Graph-level, which is the decision
the system actually makes, is 1.00.

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

Where a deleted process sat between two survivors, a bridge edge is
inserted marked `inferred=True`. Bridges count toward GRR — restoring
reachability is exactly what they do — and are excluded from RA, because
crediting them would let the system score itself on its own guesses.

---

## Quick start

```bash
pip install -r requirements.txt
python -m tests.run_all                      # 76 tests
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
evaluation/       Phase 7  attack simulation, recovery, five measures
core/                      config and the storage boundary
tests/
  test_all.py              Phases 1-5            (27 tests)
  test_phase67.py          Phases 6-7 and CCA    (46 tests)
  run_all.py               both                  (76 tests)
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
