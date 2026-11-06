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

**All seven phases implemented.** 124 tests pass with no PostgreSQL, no
eBPF and no root.

---

## Objectives

| # | Objective | Status |
|---|---|---|
| O1 | Capture with a monotonic sequence so event loss is **provable** | ✅ **Done** — captures root activity inside login sessions; sequence continuity holds across restarts; completeness certificates are dual-signed and third-party verifiable |
| O2 | Causally correct graph with real process-tree reconstruction | ✅ **Done** |
| O3 | Detect poisoning: deletion, reorder, forgery, timeshift | ⚠️ **Done for the trained attacks** — 100% on those; mostly low from rules and GNN on self-consistent attacks they have not seen, which only the seal catches. See the tamper scorecard |
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

**Detection** — on the four trained strategies, 100% at both sophistication
levels. On seven self-consistent attacks the model never trained on, the
reported verdict catches six at 0-33% and the seal catches all of them at 100%
(`python main.py tamper test`). The GNN's measured contribution is partial
deletion: 100% against the rules' 63-73%.

An earlier claim here, that only the GNN sees a sophisticated reorder, did not
hold up: comparing edge and node timestamps catches it in every run with no
false alarms, and is now rule `edge_node_mismatch`.

**Integrity** — 100% tamper detection, all strategies, no training data
and no distributional assumption.

**Risk separation** — clean captures max 0.018; tampered captures min
0.268, using trained attacks. At the configured threshold of 0.20: 0/15 clean runs anchor
anything, 15/15 tampered runs are anchored.

**Anchoring cost** — 15 clean runs: 300 partitions, **0 ledger
transactions**. 15 tampered runs: 250 partitions anchored in **16
transactions** (15.6× batching compression).

**Sealing benefit** — against a mixed delete-and-fabricate attack, 72
relations were fabricated. Recovery Accuracy **80.80% → 100.00%**
(+19.20 points) with sealed evidence available. The sealed 100% is true by
construction; the measurement is the unsealed 80.80%.

---

## Known limitations

Stated here, not left to be found.

0. **Detection does not generalise.** See the tamper scorecard: an attacker who
   keeps the graph self-consistent passes the rules and the GNN. The seal is
   what catches them. GNN thresholds also vary between training runs, and one
   real capture is too little to measure false alarms on real data with
   confidence: holding out half of it gave 0/3 and 3/3 false alarms on small
   windows across two seeds. False alarms also rise on captures larger than
   the 300-event training limit: a clean 463-event capture was flagged. Scoring
   in chunks was tried and made it worse (73-100% false alarms), because cutting
   the graph creates orphans. GNN-only results are therefore reported as
   SUSPICIOUS, with a warning when the capture is that large. False alarms also
   occur below that size: a clean 177-event capture was flagged even after
   retraining on it, so a GNN-only result on real data is not evidence by itself.

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

3a. **Commands typed in a terminal are mostly missing from captures, cause
    unknown.** Captures hold events from VS Code, its scripts and `claude`, but
    not `python main.py ...` commands run in a terminal during the capture,
    including with the original probe. A certificate saying "0 missing" only
    covers events that reached the collector. Until this is explained, do not
    claim every exec is captured.

4a. **An exploited root service can go unseen.** Capture keeps uid >= 1000 and
    anything inside a login session, so `sudo`, `su` and root logins are recorded.
    A service has no login session, so root gained by exploiting one is filtered
    out with all other service activity.

4b. **Parents are inferred from binary names**, not read from the kernel.

4c. **Login-uid capture is built but not yet load-tested.** It compiles and its
    field resolves against the running kernel's type data, but loading a probe
    needs root. Loss counting and wall-clock capture have run on a real kernel.

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
