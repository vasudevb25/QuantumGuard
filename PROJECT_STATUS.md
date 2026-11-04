# QuantumGuard — Project Status

Where every phase, objective and novelty claim actually stands. Written
to be checked against the code, not taken on trust.

---

## Phases

| Phase | Design specification | Status |
|---|---|---|
| **1. Provenance capture** | eBPF execve probe, ring buffer, sequence numbering, CCA | ✅ **Done** — plus cross-session continuity and signed completeness certificates |
| **2. Event normalisation** | dedup, temporal validation, enrichment | ✅ **Done** — execve-chain parent inference; discards logged with a reason |
| **3. Graph construction** | node/edge creation, consistency checking | ✅ **Done** — one canonical identity per process; schema contract enforced |
| **4. Poisoning detection** | rule-based + GNN detection of deletion/reorder/forgery | ✅ **Done** — 10 deterministic rules + 2-layer GraphSAGE, gradient-checked |
| **5. Integrity protection** | Merkle tree over partitions, hybrid Ed25519 + ML-DSA | ✅ **Done** — domain-separated Merkle, hash chain, strict-AND dual signing, inclusion proofs |
| **6. Risk-adaptive anchoring** | risk scoring, 3-tier anchoring (local / batched / Fabric) | ✅ **Done** — six-signal risk model, calibrated thresholds, second-order batching, append-only signed ledger. *Fabric adapter is an interface, not a simulation* |
| **7. Survivability evaluation** | PIS, EPR, GRR, RA, FSI | ✅ **Done** — five measures, five damage models, sealing-benefit experiment |

**All seven phases implemented.** 76 tests pass with no PostgreSQL, no
eBPF and no root.

---

## Objectives

| # | Objective | Status |
|---|---|---|
| O1 | Capture with a monotonic sequence so event loss is **provable** | ✅ **Done** — sequence continuity holds across restarts; completeness certificates are dual-signed and third-party verifiable |
| O2 | Causally correct graph with real process-tree reconstruction | ✅ **Done** |
| O3 | Detect poisoning: deletion, reorder, forgery, timeshift | ✅ **Done** — 100% detection across all four at both sophistication levels |
| O4 | Seal with Merkle-rooted, hash-chained partitions under hybrid signatures | ✅ **Done** — 100% tamper detection, no training data required |
| O5 | Risk-adaptive anchoring and quantified survivability | ✅ **Done** — with the ledger caveat below |

---

## Novelty claims

| Claim | Status | Honest assessment |
|---|---|---|
| **1. CCA — event loss provable, not assumed** | ✅ **Complete** | Was ~80%: session-scoped and unsigned. Now resumes across restarts, records downtime as an explicit `SESSION_GAP`, and issues signed certificates a third party can verify. |
| **2. Poisoning detection as a first-class attack** | ✅ **Complete** | **This is the genuinely novel contribution.** No reviewed system detects tampering with the record itself. |
| **3. Hybrid Ed25519 + ML-DSA over Merkle batches, risk-adaptively anchored** | ✅ **Complete** | Signing and Merkle batching were done; the *risk-adaptive anchoring* half — the part Baseri et al. proposed without building — is now implemented. Note the hybrid signing itself is not novel; the combination is. |
| **4. Forensic survivability analyser** | ✅ **Complete** | Five measures implemented, each verified to respond to damage. Two earlier measures were broken and are now fixed (see below). |

---

## What changed in this final build

### Phase 6 built from nothing

`anchoring/` did not exist. Three new modules:

- **`risk.py`** — six-signal weighted scoring with saturating curves, plus
  two explicit hard escalation rules (tamper alert, blocking violation).
  Violations are **localised** to the partition they belong to by node,
  edge, pid or sequence; an earlier approach that attributed
  unlocalisable violations to every partition escalated whole runs to
  Tier 1 and removed any adaptation from "risk-adaptive".
- **`ledger.py`** — append-only, hash-chained, dual-signed ledger stored
  outside the evidence directory. `FabricLedger` implements the same
  interface and raises rather than returning fabricated transaction ids.
- **`service.py`** — tier assignment, second-order Merkle batching, and
  independent verification of every anchor.

### Two Phase 7 measures were broken and are fixed

Both reported **100% at every damage level, including 80% destruction**.
Both were measurement errors, not results:

- **EPR** read `recovered.graph["event_count"]`, a graph attribute copied
  unchanged by `deepcopy`, so it reported the original event count no
  matter how much was destroyed. Now counted from the graph itself.
- **RA** compared surviving edges against the original edge set after a
  recovery step that only removed isolated nodes — so every surviving
  edge was original by construction and the ratio was 1.0 by definition.
  RA is only meaningful against an attacker who *inserts*, so `insert`
  and `mixed` damage modes were added, and RA now measures the accuracy
  of the system's authenticity claim.

`tests/test_phase67.py` pins both: every measure must fall monotonically
as damage rises.

### Both CCA gaps closed

- **Cross-session continuity.** `SessionManager` resumes from the highest
  stored sequence and records the downtime as a `SESSION_GAP`
  attestation. The `capture_sessions` table is now wired in.
- **Signing.** `CompletenessCertificate` covers a sequence range, names
  every gap, and is dual-signed. `verify_certificate()` detects any
  later edit to the body.

---

## Measured results

Regenerate with `python -m tests.benchmark`.

**Detection** — 100% across all four strategies at both sophistication
levels. The decisive row:

| Attack | Detected | By rules | By GNN |
|---|---|---|---|
| reorder, sophisticated | 15/15 | **0/15** | **15/15** |

A sophisticated reorder swaps sequence numbers and timestamps together,
satisfying every deterministic invariant. Only the learned component
sees it. That single row is the argument for not shipping rules alone.

**Integrity** — 100% tamper detection, all strategies, no training data
and no distributional assumption.

**Risk separation** — clean captures max 0.075; tampered captures min
0.228. At the configured threshold of 0.20: 0/15 clean runs anchor
anything, 15/15 tampered runs are anchored.

**Anchoring cost** — 15 clean runs: 300 partitions, **0 ledger
transactions**. 15 tampered runs: 189 partitions anchored in **16
transactions** (11.8× batching compression).

**Sealing benefit** — against a mixed delete-and-fabricate attack, 72
relations were fabricated. Recovery Accuracy **80.80% → 100.00%**
(+19.20 points) with sealed evidence available.

---

## Known limitations

Stated here, not left to be found.

1. **The detector is trained on self-generated tampering.** No public
   corpus of poisoned provenance graphs exists. The figures are
   in-distribution. DARPA OpTC validation is the next milestone. This
   applies *only* to the learned component — the cryptographic layer has
   no distributional dependency.

2. **The key store is a software simulation, not an HSM.** Keys are
   encrypted at rest (scrypt + AES-GCM) but enter host memory. The
   interface is shaped like PKCS#11 for later substitution.

3. **The anchor ledger is local.** It is append-only, chained, signed
   and independently verifiable — but it does not provide the
   distributed trust a real Fabric network would. An attacker with root
   and the passphrase could discard it and forge a replacement.
   `FabricLedger` closes this and refuses to fake a receipt without a
   real network.

4. **Capture is execve-only.** Program execution is observed; file reads
   and network connections are not. The graph is a process tree with
   file targets, not a data-flow graph.

5. **Attack reconstruction is not implemented**, despite the project
   title. Systems like Kairos do reconstruction; this work protects the
   graph they consume.

6. **No ablations or baselines.** No comparison against GCN/GAT/GIN, no
   feature-family ablation, no depth study. A venue submission would
   expect these.

---

## If asked "what is novel here?"

> Treating poisoning of the provenance record as a first-class
> detectable attack. Every graph-based forensic system we reviewed
> assumes its input is honest.
>
> To be precise: hybrid post-quantum signing is not ours — it has been
> proposed and applied elsewhere. What is unbuilt is the combination:
> completeness attestation feeding poisoning detection feeding
> cryptographically sealed, risk-anchored evidence, with survivability
> quantified at the end.

Lead with one claim, well defended. Four claims where three fall apart
under a search engine is a worse position than one that holds.
