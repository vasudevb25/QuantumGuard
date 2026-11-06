# QuantumGuard — Final Review Guide

**A host-based, post-quantum provenance security system for Linux**

> Every graph-based forensic system assumes its input is an honest record. That assumption fails
> against the adversary who matters most — one who has obtained root, and therefore holds the same
> privileges as the logging system itself. QuantumGuard treats the audit record as the thing under attack.

**Status:** all seven phases implemented · 124 tests pass · runs fully offline with no PostgreSQL,
no eBPF and no root · every number in this guide is reproducible with `python -m tests.benchmark`.

---

## Table of contents

1. [Introduction — background and motivation](#1-introduction--background-and-motivation)
2. [Problem definition](#2-problem-definition)
3. [Objectives](#3-objectives)
4. [Literature review](#4-literature-review)
5. [Research gap](#5-research-gap)
6. [Datasets, platforms and implementation tools](#6-datasets-platforms-and-implementation-tools)
7. [Proposed methodology — the pipeline architecture](#7-proposed-methodology--the-pipeline-architecture)
8. [Proposed approach — algorithm steps and hyperparameters](#8-proposed-approach--algorithm-steps-and-hyperparameters)
9. [Evaluation setup and criteria](#9-evaluation-setup-and-criteria)
10. [Results and analysis](#10-results-and-analysis)
11. [Discussion and limitations](#11-discussion-and-limitations)
12. [Conclusion — objective-wise status](#12-conclusion--objective-wise-status)
13. [Future work](#13-future-work)
14. [Operating guide — every command](#14-operating-guide--every-command)
15. [Repository structure](#15-repository-structure)
16. [References](#16-references)

---

## 1. Introduction — background and motivation

### 1.1 The easy-to-understand version

When attackers break into a Linux machine, the logs are what investigators use to work out
what happened. But an attacker with **root** can edit those same logs — delete their commands,
forge timestamps, rewrite history. Every existing forensic system assumes its logs are honest.
QuantumGuard does not. It treats the log itself as the thing under attack, and answers four
questions, in this order:

1. **Did we record everything?** — capture, with proof of what was lost
2. **Does the record look tampered with?** — rules + a graph neural network
3. **Can we *prove* it has not changed?** — hashing + two signatures, one quantum-safe
4. **How much evidence survives if it is damaged?** — measured survivability

### 1.2 The technical version

QuantumGuard is a host-based provenance system that:

- captures process-execution events **in the kernel** with eBPF, so a user-space attacker cannot
  avoid or kill the monitor;
- attaches a **monotonically numbered sequence** to every event and signs a **completeness
  certificate** covering every gap — making "capture loss" vs "deletion" *decidable*;
- reconstructs a causal **provenance graph** (who spawned what, who executed which file);
- detects **poisoning of the record itself** — deletion, reordering, forgery, timeshift — with
  ten deterministic invariants fused with a two-layer GraphSAGE network;
- **seals** the graph into Merkle partitions chained by hashes and dual-signed with
  **Ed25519 + ML-DSA-65** (classical + post-quantum, strict AND);
- **anchors** the most valuable evidence off-host through a risk-adaptive, three-tier ledger,
  so a root attacker cannot destroy what they cannot afford to leave;
- and **quantifies forensic survivability** — how much evidence, and how much of the attack
  path, remains usable after a compromise.

The novelty is not any single primitive (Merkle batching and hybrid signing exist elsewhere);
it is the **pipeline**: completeness attestation → poisoning detection → sealed, chained,
dual-signed, risk-anchored evidence → survivability quantified at the end.

---

## 2. Problem definition

> **Given an adversary with root privileges on a Linux host, produce a process-provenance record
> that (a) provably accounts for every captured and every lost event, (b) detects modification
> of the record itself, (c) carries cryptographic proof of integrity that survives both classical
> and quantum adversaries, (d) keeps the most valuable evidence recoverable even after a total
> host wipe, and (e) can quantify how much evidentiary value survives a given level of damage.**

Concretely, the record-level attacks to defeat are:

| Attack | What the attacker does |
|---|---|
| **Deletion** | removes events they caused |
| **Reordering** | swaps events in time to break causality |
| **Forgery** | inserts invented events |
| **Timeshift** | moves timestamps to create false alibis |
| **Truncation** | deletes the newest evidence wholesale |
| **Total destruction** | `rm -rf` of the entire local archive, signatures included |

And the key distinction no prior system makes decidable: **a gap in the sequence *with* an
attestation is capture loss; a gap *without* one is deletion.**

---

## 3. Objectives

| # | Objective |
|---|---|
| O1 | Capture every program launch in-kernel (eBPF) with sequence numbers and a **signed Capture Completeness Attestation (CCA)** that survives collector restarts |
| O2 | Normalise raw events without hiding evidence (dedup with remembered numbers, attested reboot handling) and build a causal **provenance graph** with parent inference |
| O3 | Detect record **poisoning** with deterministic invariants (zero training data, zero false positives on well-formed graphs) fused with a learned GraphSAGE detector for what rules miss |
| O4 | **Seal** the graph: Merkle partitions over full-relation leaves, a hash chain with signed length, and hybrid **Ed25519 + ML-DSA-65** signatures with pinned keys |
| O5 | **Anchor** evidence off-host by forensic risk: a legible six-signal risk score, hard escalation rules, and three protection tiers with second-order Merkle batching |
| O6 | Quantify **forensic survivability** (PIS, EPR, GRR, RA, FSI) under controlled damage, and measure what sealing is worth |
| O7 | Attack the finished system end-to-end (`tamper` module) and report honestly **which layer catches which attack** — including the attacks the learned layer was never shown |

---

## 4. Literature review

| Year | Work | Key contribution | Demerit | Dataset used | Evaluation metrics |
|---|---|---|---|---|---|
| 2017 | GraphSAGE (Hamilton et al., NeurIPS) | Inductive GNN — scores unseen graphs without retraining | Generic; not applied to record integrity | Citation graphs | Classification accuracy |
| 2021 | Merkle² (Hu et al., IEEE S&P) | Low-latency transparency logs with Merkle batching | Not a host-capture system; no provenance semantics | Certificate-transparency logs | Query latency, proof size |
| 2022 | Provenance-based IDS survey (Zipperle et al., ACM CSUR) | Taxonomy of the provenance-IDS field | Documents that no system protects the record itself | — (survey) | — |
| 2024 | eAudit (Sekar et al., IEEE S&P) | Fast, scalable, deployable audit data collection | Collection speed only; no completeness attestation, no tamper model | System audit logs | Throughput, overhead |
| 2024 | Kairos (Cheng et al., IEEE S&P) | Whole-system provenance intrusion detection & investigation | **Assumes input-graph fidelity — no poisoning detection** | DARPA Transparent Computing provenance | Detection precision / recall |
| 2025 | MGDA (Cui et al., Computer Networks) | Provenance-graph threat detection & attack-scenario reconstruction | Same input-fidelity assumption | Enterprise provenance data | Detection / reconstruction accuracy |
| 2025 | Baseri et al. (IEEE COMST) | Quantum-era blockchain migration; proposes **risk-adaptive anchoring** | A proposal only — **never implemented** | — | Cost analysis |
| 2024 | NIST FIPS 204 | Standardises ML-DSA-65 lattice signatures | — | — | — |

---

## 5. Research gap

Four gaps emerge from the review, in the order the pipeline closes them:

1. **No system detects poisoning of the provenance record itself.** Kairos, MGDA and every
   reviewed forensic system begin from an assumption of input fidelity. None detects deletion,
   reordering or forgery of the record. ← Phases 4–5.
2. **Capture loss and attacker deletion are not distinguished.** Prior collectors log gaps
   locally, if at all; a signed, third-party-verifiable completeness attestation does not exist. ← Phase 1.
3. **Integrity is classical-only.** A future quantum break of elliptic-curve signatures silently
   invalidates today's sealed archives; "harvest now, decrypt later" applies to signatures too. ← Phase 5.
4. **Risk-adaptive anchoring is proposed but unbuilt.** Baseri et al. quantify the anchoring-cost
   problem and answer it on paper; no implementation exists. ← Phase 6.
5. *(Bonus gap)* **No system asks what survives.** Detection asks "was there an attack?";
   no reviewed system measures how much evidence an investigator can still use afterwards. ← Phase 7.

---

## 6. Datasets, platforms and implementation tools

| Category | Choice | Why |
|---|---|---|
| **Primary dataset** | Self-generated synthetic provenance graphs — 220+ graphs of 25–300 events, some with normal `sudo` use, half corrupted by four tamper operators with a `sophistication` knob | **No public corpus of poisoned provenance graphs exists.** DARPA OpTC labels intrusions, not record modification — a disjoint label space |
| **Real capture** | The authors' own host (177→463-event execve captures via the eBPF probe) | End-to-end validation on genuine kernel data |
| **Evaluation benchmark** | `python -m tests.benchmark` — 15 trials per cell, fully reproducible | "Not quoted from a previous run — regenerate them and you get the same shape" |
| **Language / runtime** | Python 3 + C (eBPF loader) | Rapid iteration kernel-side and model-side |
| **Kernel capture** | eBPF: `sys_enter_execve` + `sys_enter_execveat` tracepoints, libbpf, 16 MB ring buffer | In-kernel capture is adversarially necessary: a user-space monitor is a process root can kill |
| **Storage** | PostgreSQL (`database/schema.sql`, 7 tables) with automatic JSON-file fallback (`QG_STORE=auto`) | A system about evidence surviving should not lose evidence because a database is down |
| **Graph library** | NetworkX (DiGraph, `.gpickle` + `.graphml`) | Standard provenance-graph representation |
| **ML** | Hand-written NumPy GraphSAGE (2 layers × 64 units), Adam optimiser, gradient-checked | Transparent, CPU-trained (<1 min), no framework dependency |
| **Classical crypto** | Ed25519 (64-byte signatures) | Fast, small, battle-tested |
| **Post-quantum crypto** | ML-DSA-65 (FIPS 204, via `dilithium-py`, 3309-byte signatures) | Quantum-resistant lattice signatures |
| **Key store** | scrypt-derived key + AES-256-GCM encrypted store; PKCS#11-shaped interface (SoftHSM-substitutable) | Software simulation of an HSM, honestly labelled as such |
| **Ledger** | `LocalLedger` (append-only, hash-chained, dual-signed) + `FabricLedger` Hyperledger adapter that *refuses to fake receipts* | Honest failure beats a fabricated transaction id |
| **Testing** | 124 tests across `tests/test_all.py`, `test_phase67.py`, `test_tamper.py` | Every layer, plus 17 evidence-level attacks |

**Hardware:** commodity CPU only — no GPU, no CUDA, no liboqs build required.

---

## 7. Proposed methodology — the pipeline architecture

### 7.1 The full pipeline, end to end

```
                        program starts (execve / execveat)
                                     │
   ┌─────────────────────────────────▼──────────────────────────────────┐
   │  PHASE 1 · CAPTURE                                    (kernel)     │
   │  ebpf/probes.c  →  eBPF probe on sys_enter_execve{,at}             │
   │    • in-kernel: cannot be avoided or killed by a root attacker     │
   │    • keeps login-session processes (survives sudo), skips services │
   │    • kernel COUNTS ring-buffer losses under load                   │
   │  ebpf/loader.c  →  escapes each event to JSON (16 MB ring buffer)  │
   │  capture/collector.py →  monotonic sequence numbers (resumes       │
   │    across restarts), Unix-time conversion, filter, dedup holes     │
   │  capture/cca.py →  every gap becomes an ATTESTATION; on exit a     │
   │    SIGNED completeness certificate names the range + every loss    │
   └─────────┬──────────────────────────────────────────────────────────┘
             │ raw_events + cca_attestation  (PostgreSQL or JSON files)
   ┌─────────▼──────────────────────────────────────────────────────────┐
   │  PHASE 2 · NORMALISE                        graph/service.py       │
   │    • dedupe: same (pid,file) within 2 ms = one event — and the     │
   │      removed sequence numbers are REMEMBERED (never "deletion")    │
   │    • validate: attested reboot → time shifted; any other backwards │
   │      jump stays in the graph for Phase 4 to judge — never hidden   │
   │    • enrich: process identity, process_hash(PID,time,name), parent │
   └─────────┬──────────────────────────────────────────────────────────┘
   ┌─────────▼──────────────────────────────────────────────────────────┐
   │  PHASE 3 · PROVENANCE GRAPH                 graph/service.py       │
   │                                                                    │
   │      P:ROOT:1000 (session root, adopts orphans)                    │
   │         │ SPAWNS                                                   │
   │         ▼                                                          │
   │      P:100:1  bash ──EXECUTES──▶ F:/usr/bin/python3                │
   │         │ SPAWNS                                                   │
   │         ▼                                                          │
   │      P:101:2  python3 ──EXECUTES──▶ F:/usr/bin/git                 │
   │                                                                    │
   │    each event ⇒ 1 SPAWNS + 1 EXECUTES edge, both stamped with      │
   │    the event's sequence number and time → graphs/*.gpickle         │
   └─────────┬──────────────────────────────────────────────────────────┘
             │ evidence/detection_report.json
   ┌─────────▼──────────────────────────────────────────────────────────┐
   │  PHASE 4 · POISONING DETECTOR               detection/             │
   │                                                                    │
   │   ┌──────────────────────┐    ┌────────────────────────────────┐  │
   │   │ RULE ENGINE           │    │ GraphSAGE GNN (NumPy)          │  │
   │   │ 10 invariants — any   │    │ 38 features/node → 64 → 64 →   │  │
   │   │ high/critical hit is  │    │ sigmoid suspicion 0–1          │  │
   │   │ PROOF → TAMPERED      │    │ alert if ≥2 nodes > threshold  │  │
   │   │                       │    │ (statistical guess → SUSPICIOUS)│ │
   │   └──────────┬───────────┘    └──────────────┬─────────────────┘  │
   │              └────────── FUSION: rule-priority ──┘                 │
   │        rules prove, GNN can only ADD detections, never overturn    │
   └─────────┬──────────────────────────────────────────────────────────┘
             │
   ┌─────────▼──────────────────────────────────────────────────────────┐
   │  PHASE 5 · SEAL                            crypto/integrity.py     │
   │                                                                    │
   │        root ◀── signed Ed25519 AND ML-DSA-65 (strict AND)          │
   │       /    \                                                       │
   │     h12     h34          ◀── prev_partition_hash (chain)           │
   │    /  \     /  \              + signed total partition count       │
   │   e1   e2  e3   e4   ◀── one hash per relation, BOTH endpoints     │
   │                          included, domain-separated prefixes       │
   │    keys: scrypt → AES-256-GCM store; public keys PINNED on verify  │
   └─────────┬──────────────────────────────────────────────────────────┘
             │ evidence/sealed_graph.json
   ┌─────────▼──────────────────────────────────────────────────────────┐
   │  PHASE 6 · RISK-ADAPTIVE ANCHORING          anchoring/             │
   │                                                                    │
   │   score = Σ wᵢ·sᵢ   (legible, auditable, deterministic)            │
   │    rule violations .25 │ GNN suspicion .25 │ tamper alert .20      │
   │    privilege activity .15 │ unattested gap .10 │ rare image .05    │
   │                                                                    │
   │   HARD ESCALATION (named, not hidden): tamper alert or high/crit   │
   │   rule ⇒ Tier 1 regardless of the arithmetic                       │
   │                                                                    │
   │   score ≥ 0.45 ──▶ TIER 1  anchored NOW (urgent ones share 1 tx)   │
   │   score ≥ 0.20 ──▶ TIER 2  batched: 8 roots under ONE second-order │
   │                            Merkle tree → 1 tx, proofs kept         │
   │   score <  0.20 ──▶ TIER 3  local hash chain only, zero cost       │
   │                                                                    │
   │   ledger/anchor_ledger.json  — deliberately NOT under evidence/    │
   │   (an anchor beside the evidence dies in the same rm)              │
   └─────────┬──────────────────────────────────────────────────────────┘
             │
   ┌─────────▼──────────────────────────────────────────────────────────┐
   │  PHASE 7 · FORENSIC SURVIVABILITY           evaluation/            │
   │   damage a COPY (edge/node/window/insert/mixed/edit) then measure: │
   │   PIS .30 · EPR .20 · GRR .25 · RA .25  →  FSI composite           │
   │   every relation classified: intact │ missing (provably deleted)   │
   │                             │ unsealed (provably inserted)         │
   └────────────────────────────────────────────────────────────────────┘
```

### 7.2 Where the novelty lives

| Component | Novel? |
|---|---|
| Poisoning of a provenance graph as a first-class detectable attack | **Genuinely novel** — no reviewed system does it |
| Signed completeness attestation making loss-vs-deletion decidable | Genuinely novel |
| Ed25519 + ML-DSA signing | Not alone (proposed elsewhere) — here it is *implemented and sealed* |
| Merkle batching over audit logs | Decades old |
| **The pipeline** — attestation → detection → sealed/chained/dual-signed/risk-anchored evidence → survivability quantified | **Novel as a combination** |
| Risk-adaptive anchoring | Baseri et al. proposed it; **this is the implementation** |

Two quieter design points worth stating aloud: the **tamper alert is itself sealed and anchored**
(an attacker cannot quietly destroy the record proving they were caught), and **detection runs
before certification** (tampering is caught, not inherited into the signed archive).

---

## 8. Proposed approach — algorithm steps and hyperparameters

### 8.1 Detector training steps

1. Generate 220+ synthetic provenance graphs (25–300 events), some containing normal `sudo` use.
2. Corrupt half with 4 operators — `deletion`, `reorder`, `forgery`, `timeshift` — at a
   `sophistication` parameter: "expert" attackers **recompute `process_hash`, maintain temporal
   consistency and clean up orphans**, forcing the model onto structural signals instead of one
   giveaway attribute.
3. Encode each node: **38 features** across structural, temporal and attribute families.
4. Train GraphSAGE: own features + mean over the symmetric adjacency → 64 units → ReLU →
   repeat (2-hop receptive field, matching the corruption operators' perturbation radius) →
   sigmoid node score. Loss re-weighted **toward rare tampered nodes**.
5. Calibrate the alert threshold upward until **< 5 % of clean validation graphs alert** —
   choosing it by node-F1 alone produced 30 % false alarms on clean graphs.
6. Fuse: any critical/high rule ⇒ TAMPERED (confidence 1.0). GNN-only alert (≥
   `QG_ALERT_MIN_NODES` = 2 flagged nodes) ⇒ SUSPICIOUS with mean flagged-node score as
   confidence. Neither ⇒ CLEAN.

### 8.2 Key hyperparameters (all in `core/config.py`, all env-overridable)

| Parameter | Value | Role |
|---|---|---|
| dedup window | 2 ms | duplicate merge window |
| parent inference window | 60 s | child↔parent match under the same (uid, comm) |
| temporal tolerance | 100 µs | cross-CPU ring-buffer jitter, not tampering |
| GraphSAGE | 38 → 64 → 64 → 1, ReLU, sigmoid | node suspicion |
| epochs / optimiser | 40 / Adam | < 1 minute on CPU |
| `QG_ALERT_MIN_NODES` | 2 | GNN-only alert needs ≥ 2 flagged nodes |
| partition size | 128 relations | Merkle partitions (demo: 16) |
| signatures | Ed25519 **AND** ML-DSA-65 | strict AND |
| tier thresholds | 0.45 / 0.20 | Tier 1 / Tier 2 boundaries |
| anchor batch size | 8 | Tier-2 batching → 8× fewer ledger writes |
| FSI weights | PIS .30, EPR .20, GRR .25, RA .25 | composite survivability |

### 8.3 Testing steps (the tamper harness)

- **Graph attacks** in two families: the 4 trained attacks at crude/expert levels, plus **7
  held-out attacks** the model never saw — `adaptive_deletion` (renumbers so no gap shows),
  `tail_truncate`, `adaptive_reorder` (consistent across nodes, edges *and* hashes),
  `adaptive_forgery` (correct numbers, hashes, parents), `binary_swap`, `uid_rewrite`, `flag_abuse`.
- **17 evidence attacks** on the sealed records and ledger: leaf/root/signed-field edits, forged
  signatures of either kind, partition deletion/swap/truncation, duplicate leaf, re-signing with
  an attacker's key, ML-DSA key replacement, fake batch proofs, ledger edit/rebuild/removal.
- Runs on copies with a throwaway key store; exit status 2 if any evidence attack goes undetected.

---

## 9. Evaluation setup and criteria

**Setup:** `QG_STORE=file`, temporary key stores and ledgers for destructive tests, 15 trials per
benchmark cell, seeds fixed for reproducibility.

**Metrics and formulas:**

| Metric | Definition |
|---|---|
| **Risk score** | `score = Σ wᵢ·sᵢ` over six signals, each normalised to [0,1]; deterministic so two auditors scoring the same evidence agree exactly |
| **PIS** — Provenance Integrity Score | fraction of sealed relations still present **and** hash-verifying |
| **EPR** — Evidence Preservation Ratio | fraction of originally captured events that survived |
| **GRR** — Graph Recovery Rate | fraction of causal **reachability** retained (ancestor–descendant pairs, *not* edges — a mid-chain deletion destroys far more reachability than a leaf one) |
| **RA** — Recovery Accuracy | of what the system asserts is authentic, how much really is |
| **FSI** — Forensic Survivability Index | `0.30·PIS + 0.20·EPR + 0.25·GRR + 0.25·RA` |
| Detection | node precision / recall / F1, ROC-AUC; graph-level precision / recall |
| Integrity | fraction of attacks where seal verification fails against a pre-attack seal |

**Baselines:** rules-only vs GNN-only vs fused detection vs the cryptographic seal — each scored
*alone* so no layer hides behind another. The "CLEAN (false alarms)" row is read first: a detector
that always says "tampered" would score 100 % everywhere else.

---

## 10. Results and analysis

### 10.1 Detection — trained attacks (synthetic, 15 trials)

| Attack | Detected | By rules | By GNN |
|---|---|---|---|
| deletion / reorder / forgery / timeshift (crude & sophisticated) | **15/15 each** | 15/15 | 15/15 |

### 10.2 The tamper scorecard — the main result

`python main.py tamper test --trials 30`. Trained attacks vs held-out attacks:

| Attack | Family | Rules | GNN | Verdict | **Seal** |
|---|---|---|---|---|---|
| clean graph (false alarms) | — | **0 %** | **0 %** | **0 %** | **0 %** |
| deletion crude / expert | trained | 63 / 73 % | 100 % | 100 % | **100 %** |
| reorder crude / expert | trained | 100 % | 100 % | 100 % | **100 %** |
| forgery crude / expert | trained | 100 % | 100 % | 100 % | **100 %** |
| timeshift crude / expert | trained | 100 % | 100 % | 100 % | **100 %** |
| adaptive deletion | **held out** | 0 % | 3 % | 3 % | **100 %** |
| tail truncation | **held out** | 0 % | 0 % | 0 % | **100 %** |
| adaptive reorder | **held out** | 7 % | 13 % | 13 % | **100 %** |
| adaptive forgery | **held out** | 0 % | 33 % | 33 % | **100 %** |
| binary swap | **held out** | 0 % | 0 % | 0 % | **100 %** |
| uid rewrite | **held out** | 7 % | 0 % | 7 % | **100 %** |
| flag abuse | **held out** | 100 % | 97 % | 100 % | **100 %** |

**Read the bottom half.** Against an attacker who keeps the graph self-consistent, learned and
rule-based detection mostly fail — and **only the seal holds, 100 %, with no training data and no
distributional assumption.** Detection catches careless attackers and sends the investigator to
the right place; the seal never asks whether the graph *looks* wrong, only whether it *changed*.

### 10.3 Integrity layer

All four attack classes (deletion, reorder, forgery, timeshift), crude and sophisticated:
**15/15 each — 100 %, both.**

### 10.4 Risk-score separation

```
clean captures    (15 runs): mean 0.008   max 0.018
tampered captures (15 runs): mean 0.430   min 0.268
```
The Tier-2 threshold (0.20) sits inside the gap → clean runs anchor **0/15**, tampered runs
**15/15** at thresholds 0.10–0.25. *(Figure: `image/fig_risk.png`.)*

### 10.5 Anchoring cost follows risk

| | Partitions | Externally anchored | Ledger transactions |
|---|---|---|---|
| 15 clean runs | 300 | 0 | **0** |
| 15 tampered runs | 304 | 250 | **16** |

A clean capture consumes nothing; a compromised one anchors 250 partitions in 16 transactions —
**15.6× batching compression** via the second-order Merkle tree.

### 10.6 Survivability (edge-removal mode)

| Damage | PIS | EPR | GRR | RA | FSI |
|---|---|---|---|---|---|
| 0 % | 100.00 | 100.00 | 100.00 | 100.00 | 100.00 |
| 15 % | 85.00 | 100.00 | 75.10 | 100.00 | 89.28 |
| 30 % | 70.00 | 93.00 | 45.43 | 100.00 | 75.96 |
| 50 % | 50.00 | 78.50 | 23.54 | 100.00 | 61.59 |
| 75 % | 25.00 | 54.50 | 7.78 | 100.00 | 45.34 |

*(Figure: `image/fig_survivability.png`; node and window modes behave comparably.)*

### 10.7 What sealing is worth, measured

Same attack — delete 25 % and fabricate replacements — with vs without sealed evidence:

| | PIS | EPR | GRR | **RA** | FSI |
|---|---|---|---|---|---|
| with sealing | 75.75 | 98.50 | 64.55 | **100.00** | 83.56 |
| without sealing | 0.00 | 98.50 | 64.55 | **80.80** | 56.04 |

72 fabricated relations: with the seal, all rejected; without it, all accepted as authentic.
**Recovery Accuracy +19.20 points** — that is what sealing is worth in one number.

### 10.8 GNN metrics (463-event capture, one training run)

| Split | Precision | Recall | F1 | AUC |
|---|---|---|---|---|
| Validation — node | 0.820 | 0.790 | 0.805 | 0.961 |
| Test — node | 0.806 | 0.744 | 0.774 | 0.954 |
| Test — graph | 0.88–1.00 across runs | 1.000 | — | — |

Node F1 is bounded by the labelling scheme (periphery nodes of a deletion barely change), not the
architecture. The decision the system acts on is graph-level.

### 10.9 Final end-to-end run (real capture, 6 Nov 2026)

| Stage | Observed |
|---|---|
| Graph | 203 nodes, 354 relations |
| Detection | SUSPICIOUS (gnn) — 4 nodes above 0.760, 0 rule violations *(the documented GNN false-alarm behaviour on real captures; SUSPICIOUS explicitly means "confirm with `verify`")* |
| Seal | 3 partitions, Ed25519 + ML-DSA-65, **PASS** |
| Risk | min 0.0375 / mean 0.2524 / max 0.4001 → Tier 1 ×2, Tier 3 ×1, **1 ledger transaction** *(Tier-1 escalation below 0.45 is the named hard-escalation rule, not a bug)* |
| Survivability (edge, 15 %) | PIS 85.03 · EPR 97.74 · GRR 87.20 · RA 100.00 · **FSI 91.86** · 53 relations provably deleted |
| Tamper test (real capture) | seal **100 %** on every attack; **17/17 evidence attacks caught** |

The PIS (85.03 vs 85.00) and RA (100) values reproduce the 15 % benchmark row almost exactly on a
real capture; GRR (87.20 vs 75.10) varies legitimately with graph topology.

---

## 11. Discussion and limitations

Stated here rather than left for a reader to discover:

1. **The detector is trained on self-generated tampering.** Figures are in-distribution; they are
   not evidence against a fifth, unanticipated strategy. Validation against DARPA OpTC is the next
   milestone. *This limitation applies only to the learned component — the cryptographic layer
   carries no distributional dependency.*
2. **The GNN is unreliable on real captures.** It false-alarms even after retraining on them, and
   above ~300 events (33 % of clean 800-event graphs). Hence SUSPICIOUS ≠ TAMPERED — a GNN-only
   result is a prompt to run `verify`, never a verdict.
3. **The key store is a software simulation, not an HSM.** Private keys enter host memory;
   the interface is PKCS#11-shaped for SoftHSM substitution.
4. **The anchor ledger is local.** Append-only, chained, dual-signed — but a root attacker with
   the passphrase could discard and forge a replacement chain. Only `FabricLedger` on a real
   Hyperledger network closes this; it refuses to fabricate receipts without one.
5. **Capture is execve-only.** A process tree with file targets, not a full data-flow graph —
   no file reads, no network connections yet.
6. **An exploited root *system service* can go unseen.** Login-session capture records `sudo`,
   `su` and root logins, but a service has no login session. Removing the filter records all
   service activity — the biggest remaining capture gap.
7. **Parents are inferred from `comm` matching, not observed.** The probe could read the real
   parent PID from the kernel.
8. **The seal only protects from the moment it is made.** Anything altered before `seal` runs is
   sealed as if true — seal soon after capture.
9. **Attack reconstruction is not implemented** despite the field's name. Kairos-class systems
   reconstruct; QuantumGuard guarantees the graph they consume is complete and untampered.
10. **No ablations or baselines** (GCN/GAT/GIN comparison, feature-family isolation) — expected
    for a venue submission.

---

## 12. Conclusion — objective-wise status

| Objective | Status |
|---|---|
| O1 In-kernel capture + signed completeness attestation | ✅ Achieved |
| O2 Normalisation + causal provenance graph | ✅ Achieved |
| O3 Rule + GraphSAGE poisoning detection with honest fusion | ✅ Achieved |
| O4 Merkle + hash-chain + hybrid post-quantum sealing | ✅ Achieved — 100 % integrity on every tested attack |
| O5 Risk-adaptive three-tier anchoring (Baseri et al., implemented) | ✅ Achieved — 15.6× batching compression, zero cost on clean runs |
| O6 Survivability quantification + measured value of sealing | ✅ Achieved — RA +19.20 points with sealing |
| O7 End-to-end adversarial evaluation with honest reporting | ✅ Achieved — 17/17 evidence attacks caught; detector limits published, not hidden |

**Conclusion.** QuantumGuard demonstrates that the audit record itself can be treated as the
thing under attack — and defended. The learned and rule-based layers catch careless attackers and
localise suspicion; the cryptographic seal catches *everything tested*, sophisticated or not,
because it never reasons about how the record looks — only whether it changed. Risk-adaptive
anchoring makes off-host protection affordable precisely when it matters, and survivability
measurement turns "some events seem to be missing" into "these 53 relations were deleted after
capture". 124 tests, a reproducible benchmark, and an end-to-end real-capture run support every claim.

---

## 13. Future work

1. **Validation against DARPA OpTC** — real intrusion corpus for the learned detector.
2. **Kernel-read parent PIDs** — remove parent inference entirely.
3. **Extend capture** to `vfs_write` and `tcp_connect` probes → full data-flow provenance.
4. **Hardened keys** — real HSM / PKCS#11 via SoftHSM.
5. **Deploy `FabricLedger`** on a running Hyperledger Fabric network for distributed trust.
6. **Close the service-capture gap** (optionally widen the filter with a cost note).
7. **GNN generalisation** — train on realistic and adaptive attacks; raise the size ceiling
   beyond 300 events.
8. **Ablations & baselines** — GCN/GAT/GIN comparison, feature-family isolation, depth study.
9. **Attack reconstruction** on the protected graph (e.g. Kairos-style) as the downstream consumer.
10. **Explain the unexplained capture gap** — typed terminal commands under-represented in
    captures; must be root-caused before claiming every exec is captured.

---

## 14. Operating guide — every command

### 14.1 Install

```bash
cd QuantumGuard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt      # one command, no compile, no CUDA, no liboqs

python main.py keys                  # confirms the ML-DSA backend + creates the key store
```

**Before any real use, change the key-store passphrase** (the default `quantumguard-dev` is
printed in this project's own docs, so a store protected only by it is protected by nothing):

```bash
export QG_KEYSTORE_PASSPHRASE='something-long-and-not-this'
rm -rf keys/ && python main.py keys
```

### 14.2 Offline path — 5 minutes, no PostgreSQL, no eBPF, no root

```bash
python -m tests.run_all                      # expect: 124 tests, 0 failed
python main.py demo --partition-size 16      # full end-to-end demonstration
python main.py demo --strategy forgery --sophistication 0.0   # crude attacker
python main.py demo --strategy forgery --sophistication 1.0   # careful attacker
python -m tests.benchmark                    # regenerate every number in §10
python -m detection.model --epochs 40 --synthetic 260          # train the GNN
```

Demo strategies: `forgery` `deletion` `reorder` `timeshift`. **Always pass `--partition-size 16`
for demos** — the default of 128 puts a small graph in one partition and hides the per-partition
localisation that makes the output worth reading.

### 14.3 Live capture — database + kernel

```bash
sudo -u postgres createdb provenance
sudo -u postgres psql -c "CREATE USER quantumguard WITH PASSWORD 'StrongPassword123';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE provenance TO quantumguard;"
sudo -u postgres psql -d provenance -f database/schema.sql        # idempotent
sudo -u postgres psql -d provenance -c "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO quantumguard; GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO quantumguard;"
```

```bash
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r) bpftool
make -C ebpf
python main.py capture          # Ctrl-C to stop → writes the signed completeness certificate
```

Leave it running and **use the machine in a second terminal** — you want several hundred events.
Restarting resumes from the highest stored sequence and records downtime as a `SESSION_GAP`.

### 14.4 The pipeline

```bash
python main.py all        # graph → detect → seal → anchor → evaluate (run id passed through)
```

or step by step:

```bash
python main.py graph                     # Phase 2/3 — build the graph
python main.py train --graph graphs/provenance_graph.gpickle --epochs 40   # train on YOUR capture
python main.py detect                    # Phase 4  [--persist writes to the store]
python main.py seal --partition-size 16 --run-id my-run-2026-10   # Phase 5 — note the run id
python main.py anchor --batch-size 8 --run-id my-run-2026-10      # Phase 6  [--ledger local|fabric]
python main.py evaluate --ratio 0.15 --mode edge   # Phase 7  [modes: edge node window insert mixed edit]
python main.py verify --run-id my-run-2026-10     # independent check — exit 0 PASS / 2 FAIL
python main.py certify evidence/completeness_<id>.json   # one certificate
python main.py visualize                 # graphs/provenance_graph.png — one box per program
```

### 14.5 Demonstrating tamper detection on your own data

```bash
python main.py graph
python main.py seal --partition-size 16 --run-id tamper-test
python main.py verify --partition-size 16 --run-id tamper-test

python main.py tamper apply --attack adaptive_forgery          # write a tampered copy
python main.py detect --graph graphs/tampered_adaptive_forgery.gpickle \
       --output evidence/tampered_detection.json               # does the detector see it?
python main.py verify --graph graphs/tampered_adaptive_forgery.gpickle   # does the seal?

python main.py tamper test --trials 30                         # the full scorecard
```

`tamper` never touches the real graph, evidence, keys or ledger; exit status 2 if any evidence
attack goes undetected.

### 14.6 Configuration (`core/config.py`, all env-overridable)

| Variable | Default | Meaning |
|---|---|---|
| `QG_DB_URL` | `postgresql+psycopg2://quantumguard:StrongPassword123@localhost/provenance` | database connection |
| `QG_STORE` | `auto` | `auto` \| `db` \| `file` |
| `QG_PARTITION_SIZE` | `128` | relations per sealed partition |
| `QG_KEYSTORE_PASSPHRASE` | `quantumguard-dev` | **change this** |
| `QG_ALERT_MIN_NODES` | `2` | flagged nodes needed for a GNN-only alert |
| `QG_LEDGER` | `local` | `local` \| `fabric` |
| `QG_ANCHOR_BATCH_SIZE` | `8` | Tier-2 partitions per batched transaction |

### 14.7 Command reference

```
python main.py <command> --help

  keys       create / show the key store            (--export-trust for off-host pinning)
  capture    eBPF capture with CCA                  (Phase 1)
  graph      normalise events and build the graph   (Phase 2/3)
  train      train the GraphSAGE detector           (Phase 4)
  detect     rule + GNN poisoning detection         (Phase 4)
  seal       Merkle partitions, dual signing        (Phase 5)
  anchor     risk scoring and tiered anchoring      (Phase 6)
  evaluate   forensic survivability                 (Phase 7)
  verify     verify evidence, anchors, certificates (--trust-file, --no-graph)
  certify    verify one completeness certificate
  all        graph -> detect -> seal -> anchor -> evaluate
  demo       full offline demonstration
  tamper     attack a copy of the evidence and score it
  visualize  draw the graph
```

`--graph`, `--run-id`, `--partition-size` work before or after the subcommand.

### 14.8 Pre-review checklist

```bash
python -m tests.run_all                                   # 124/124
python main.py tamper test --trials 30                    # which layer sees what
export QG_KEYSTORE_PASSPHRASE='<your own>'                # not the default
python main.py capture                                    # 15+ min of real use
python main.py graph
python main.py train --graph graphs/provenance_graph.gpickle
python main.py all
python main.py verify
python -m tests.benchmark --json evidence/benchmark.json
```

Three things to say before anyone asks: the detector trains on **self-generated** tampering
(OpTC is next); the key store is a **software simulation**, not an HSM; the ledger is **local**,
not distributed. All three are stated in the README and §11.

---

## 15. Repository structure

```
QuantumGuard/
├── main.py              CLI entry point — every command above
├── ebpf/                Phase 1  probes.c (kernel probe) + loader.c (C) + Makefile
├── capture/             Phase 1  collector.py (sequences, resume), cca.py (signed certificates)
├── graph/               Phase 2/3  service.py (normalise, build), visualize.py
├── detection/           Phase 4  detector.py (10 rules + fusion), features.py (38-dim),
│                                 model.py (NumPy GraphSAGE), synthetic.py (graphs + tamper ops)
├── crypto/              Phase 5  integrity.py (Merkle, chain, Ed25519+ML-DSA, key store, verifier)
├── anchoring/           Phase 6  risk.py (6 signals, tiers, escalation), service.py (batching),
│                                 ledger.py (LocalLedger / FabricLedger)
├── evaluation/          Phase 7  main.py (PIS/EPR/GRR/RA/FSI), tamper.py (the attack harness)
├── core/                config.py (all env-overridable settings), store.py (PostgreSQL ↔ files)
├── database/            schema.sql — 7 tables
├── tests/               test_all.py (27) + test_phase67.py (49) + test_tamper.py (48) = 124,
│                        benchmark.py — regenerates every published number
├── image/               figures: fig_risk, fig_sealing, fig_survivability + final-run screenshots
├── README.md            design rationale + measured results
├── RUN.md               purely operational guide
├── QuantumGuard Field Guide.html   per-phase walkthrough with real annotated outputs
└── FINAL_GUIDE.md       this document
```

---

## 16. References

1. R. Sekar, H. Kimm, R. Aich. *eAudit: A Fast, Scalable and Deployable Audit Data Collection
   System.* IEEE S&P 2024, pp. 3571–3589.
2. Y. Hu, K. Hooshmand, H. Kalidhindi, S. J. Yang, R. A. Popa. *Merkle²: A Low-Latency
   Transparency Log System.* IEEE S&P 2021, pp. 285–303.
3. Y. Baseri, A. Hafid, Y. Shahsavari, D. Makrakis, H. Khodaiemehr. *Blockchain Security Risk
   Assessment in Quantum Era, Migration Strategies and Proactive Defense.* IEEE COMST, 2025.
4. M. Cui, Z. Jiang, S. Li, C. Ma, K. Zhang, P. Yang, H. Feng. *MGDA: A Provenance Graph-Based
   Framework for Threat Detection and Attack Scenario Reconstruction.* Computer Networks, vol.
   274, 2025.
5. M. Zipperle, F. Gottwalt, E. Chang, T. Dillon. *Provenance-based Intrusion Detection Systems:
   A Survey.* ACM Computing Surveys, vol. 55, no. 7, 2022.
6. Z. Cheng, Q. Lv, J. Liang, Y. Wang, D. Sun, T. Pasquier, X. Han. *Kairos: Practical Intrusion
   Detection and Investigation using Whole-system Provenance.* IEEE S&P 2024, pp. 3533–3551.
7. NIST. *Module-Lattice-Based Digital Signature Standard.* FIPS 204, 2024.
8. W. L. Hamilton, R. Ying, J. Leskovec. *Inductive Representation Learning on Large Graphs.*
   NeurIPS 2017.
