# QuantumGuard — Final Review Guide

**QuantumGuard: Post-Quantum, Tamper-Evident Provenance Logging and Attack Reconstruction Using Risk-Adaptive Anchoring**

**Vasudev B** (AM.SC.U4CSE23267) · **Vighnesh B** (AM.SC.U4CSE23269)
Under the guidance of **Dr. Devi Rajeev**, Center for Cybersecurity Systems and Networks
Amrita School of Computing, Amrita Vishwa Vidyapeetham, Amritapuri · November 2026

> Every system that investigates host intrusions reads provenance records and treats them as
> truthful. An attacker who reaches administrative privilege can edit that record before an
> investigator ever opens it — so a conclusion drawn from a doctored record is confidently wrong,
> and evidence built on it fails the reliability test a court applies. QuantumGuard protects the
> **record itself**, not the analysis performed on it.

**Status:** all seven components implemented · every number reproducible via
`python -m tests.benchmark --trials 15` · runs fully offline with no PostgreSQL, no eBPF, no root.

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

When an organisation discovers one of its machines has been broken into, the first question is
*how did the intruder get in and what did they reach?* That question is answered from provenance
data: which process launched which other process, which binary each process executed, which files
were touched. Modern investigation systems turn this record into a directed graph and search it
for the chain of events that explains the compromise.

The problem: **an attacker holding administrative rights can open the audit log and remove the
lines describing their own activity**, and nothing in the investigation pipeline notices — every
component downstream was built to *read* the record, not to *question* it. QuantumGuard treats
the record itself as the thing under attack, and answers four questions in order:

1. **Did we record everything?** — capture, with proof of what was lost
2. **Does the record look tampered with?** — rules + a graph neural network
3. **Can we *prove* it has not changed?** — hashing + two signatures, one quantum-safe
4. **How much evidence survives if it is damaged?** — measured survivability

### 1.2 The technical version

QuantumGuard is a host-based provenance protection system that:

- captures process execution **in the kernel** with eBPF, so a user-space attacker cannot avoid
  or kill the monitor, with monotonically increasing sequence numbers and a **signed certificate
  declaring exactly which sequence numbers were observed**;
- cleans events into a directed **provenance graph**;
- detects **editing of the record itself** — deletion, reordering, fabrication, timestamp
  manipulation — with **ten deterministic structural rules** alongside a **two-layer GraphSAGE
  encoder trained through self-supervised corruption**;
- **seals** the graph into Merkle-rooted, hash-chained partitions signed twice — **Ed25519 and
  ML-DSA-65** (FIPS 204) — so detection never depends on a trained model;
- **anchors** the most valuable partitions to an external ledger through a **six-signal risk
  score**, so cost follows suspicion instead of volume;
- and **quantifies survivability** — how much trustworthy evidence remains after a compromise,
  stated as a number.

The contribution, stated narrowly so it can be defended: **poisoning of the provenance record is
treated as a first-class detectable attack**, composed with attested capture, cryptographic
sealing, risk-proportionate anchoring and measured survivability into one working path. The
individual techniques are not claimed as novel; **the composition is**, because each layer covers
a failure mode of the layer before it.

### 1.3 Sustainable Development Goal mapping

| SDG and target | Mapping to the project | Beneficiaries |
|---|---|---|
| **SDG 16**, target 16.6 — effective, accountable, transparent institutions | Records whose completeness is attested and whose contents are sealed, checkable by a third party without trusting the host that produced them | Incident response teams; internal and external auditors |
| **SDG 16**, target 16.3 — rule of law and equal access to justice | Verification produces a pass/fail result from the evidence file and a public key alone, reducing dependence on the credibility of whoever collected it | Judicial processes receiving digital evidence from an interested party |
| **SDG 9**, target 9.1 — reliable, resilient infrastructure | Survivability is quantified, not assumed — an operator can state how much trustworthy evidence remains after a host is compromised | Platform and security engineers operating Linux hosts |

---

## 2. Problem definition

### 2.1 Problem statement

Provenance-based investigation treats the provenance record as ground truth. The problem is that
**the record is itself an attackable object**, and no stage of the existing pipeline is responsible
for noticing when it has been attacked.

> Stated precisely: given a host provenance record **R** produced by a capture mechanism and later
> presented to an investigator as **R′**, determine whether **R′ = R**, and if not, determine
> **which parts of R′ can still be relied upon**. Existing systems answer neither question, because
> they are built to analyse R′ rather than to authenticate it.

**The adversary:** one who has obtained administrative privilege on the host and has an interest
in the investigation reaching the wrong conclusion. They can read and write the stored record and
can observe the system while doing so. Four capabilities follow:

| Attack | What it does |
|---|---|
| **Deletion** | removes records of chosen actions |
| **Reordering** | exchanges the apparent order of events, altering causal attribution without changing the event set |
| **Fabrication** | inserts records of activity that never occurred — can redirect an investigation toward an innocent account |
| **Timestamp manipulation** | shifts events across time windows, outside the period under examination |

A **careless** adversary performs one crudely and leaves structural inconsistencies. A **careful**
adversary adjusts every dependent field so the result remains internally consistent. All four
leave the record syntactically valid — a log file with lines removed is still a well-formed log file.

**Stakeholders:** the incident responder, whose conclusions depend on the record; the
organisation, whose accountability depends on those conclusions; and any external party — auditor,
regulator or court — that must assess evidence collected by a party with an interest in the outcome.

**Consequences of leaving it unaddressed:** an investigation attributes the intrusion to the wrong
account or process and the real entry point persists; an organisation reports an incident
inaccurately to a regulator; evidence in a legal proceeding is excluded or discounted because its
integrity cannot be demonstrated.

**Inputs / outputs of the system:** input is process-execution events observed at the kernel
boundary. Output is a provenance graph, a tamper determination with the specific violations found,
a set of sealed partitions with signatures and inclusion proofs, external anchor receipts for the
partitions whose risk warranted them, and a survivability report.

### 2.2 Existing system and limitations

Four families of existing work each solve a part and leave the rest:

1. **Provenance-based intrusion detection** (Kairos, MGDA, threaTrace, UNICORN): high reported
   accuracy, but each **takes the graph as given**. A deletion performed before Kairos runs simply
   removes the subgraph it would have found; UNICORN's normality model means an attacker who edits
   the record *towards normality* is rewarded rather than detected.
2. **Audit capture** (eAudit): reduces event loss (~4.5 % overhead) but **reducing loss is not
   proving its absence** — a gap remains ambiguous between a dropped event and a deleted one.
3. **Transparency logs** (Merkle², Certificate Transparency): built for entries that arrive as an
   independent stream; provenance is a *graph* with causal structure, and both use classical
   cryptography only.
4. **Post-quantum and risk-adaptive protection** (FIPS 204, Baseri et al.): ML-DSA is deployable;
   risk-adaptive anchoring is proposed as **policy analysis only — no implementation, no
   measurement of the cost saved by adaptivity**.

---

## 3. Objectives

Five objectives were defined (Table 1.2 of the report):

| No. | Objective | Evaluation method | Deliverable |
|---|---|---|---|
| **O1** | Capture process execution so that the loss of any event is **provable** rather than assumed | Sequence continuity across a simulated outage; an edited certificate must fail verification | Capture module; signed completeness certificate |
| **O2** | Build a provenance graph whose causal structure matches the real process tree | One identity per process instance; schema contract holds on every edge | Normalisation and graph modules |
| **O3** | Detect deliberate editing under four strategies at two levels of attacker care | Detection rate over 15 independent trials per condition | Rule engine; learned detector; detection report |
| **O4** | Seal the graph so modification is detectable by **cryptography alone, under quantum-resistant signatures** | Verification detection rate **with the trained model absent** | Sealing module; verification command |
| **O5** | Anchor evidence externally **in proportion to risk** and quantify surviving evidence | Ledger transactions consumed clean vs compromised; five measures over five damage models | Anchoring service; local ledger; evaluation report |

---

## 4. Literature review

Twelve works were reviewed (IEEE Xplore, ACM Digital Library, USENIX proceedings, NIST
publications; 2013–2025). All entries are primary sources; quoted values are the authors' own.

| # | Work (year) | Problem / contribution | Study context (dataset) | Evaluation criteria | Key findings | Limitation / gap |
|---|---|---|---|---|---|---|
| 1 | **Kairos** — Cheng et al., IEEE S&P 2024 | Detect intrusions and reconstruct the attack narrative from whole-system provenance; graph encoder/decoder emits analyst-readable summary graphs | DARPA TC engagements 3 & 5; OpTC | Precision; recall; detection latency | Competitive detection with readable summaries | **Input graph assumed complete and untampered** |
| 2 | **MGDA** — Cui et al., Computer Networks 2025 | Multi-view masked graph autoencoder matched against MITRE ATT&CK for labelled detection + scenario reconstruction | StreamSpot; Unicorn Wget; DARPA TC eng. 3 | Precision; recall; F1 | Precision 97.58 %; F1 98.03 % | Graph tampering outside scope; no integrity layer |
| 3 | **Provenance-IDS survey** — Zipperle et al., ACM CSUR 2022 | Taxonomy over collection, representation, detection, evaluation practice | Secondary study, peer-reviewed systems to 2022 | Qualitative | Field concentrates on accuracy and scale; **integrity rarely addressed** | Survey only; no implementation |
| 4 | **eAudit** — Sekar et al., IEEE S&P 2024 | eBPF collection with tunable event prioritisation at production rates | Linux hosts; seven stress benchmarks (Postmark, kernel build) | Overhead; event-loss rate; tampering window | **~4.5 % overhead**, loss substantially reduced | **No signed proof that zero events were dropped**; a gap stays ambiguous |
| 5 | **threaTrace** — Wang et al., IEEE TIFS 2022 | Node-level inductive GNN flags *which* nodes are anomalous, without attack labels | StreamSpot; Unicorn Wget; DARPA TC | Node-level P, R, F1; tracing coverage | High node recall at practical false-positive rates | Depends on training corpus matching deployment; integrity not considered |
| 6 | **UNICORN** — Han et al., 2020 | Streaming whole-graph sketch vs learned normality detects slow APT campaigns | StreamSpot; supply-chain dataset; DARPA TC | Precision; recall; accuracy; memory | Detects long campaigns at bounded memory | Normality model shiftable by a patient adversary; record assumed genuine |
| 7 | **ATLAS** — Alsaheel et al., USENIX Security 2021 | Causal paths → sequences; sequence learning recovers the attack narrative | Ten realistic attack scenarios on instrumented hosts | P/R of recovered attack steps; analyst effort | Accurate recovery from few labelled examples | **Bounded by audit-log completeness**; needs labelled sequences |
| 8 | **Merkle²** — Hu et al., IEEE S&P 2021 | Nested Merkle-of-Merkles removes the append/lookup latency trade-off | Synthetic transparency-log workloads | Append/lookup latency; proof size | Latency improved at comparable proof size | **Classical primitives only**; built for independent entries, not causal graphs |
| 9 | **Certificate Transparency** — Laurie, CACM 2014 | Publicly auditable append-only logs; inclusion and consistency proofs | Public web PKI | Analytical detection guarantees | Misissuance detectable by any monitor | Detects after the fact; depends on independent monitoring |
| 10 | **Baseri et al.** — IEEE COMST 2025 | STRIDE-based quantum risk assessment; **proposes risk-adaptive anchoring + selective PQ verification** | Bitcoin, Ethereum, Ripple, Litecoin, Zcash | Qualitative risk assessment | Prioritised migration actions | **Policy analysis only — no implementation; adaptivity never measured** |
| 11 | **FIPS 204** — Dang et al., NIST 2024 | Standardises ML-DSA module-lattice signatures in three parameter sets | NIST post-quantum standardisation | Public cryptanalysis; security categories | Signatures larger than elliptic curve | Lattice cryptanalysis less mature → **hybrid deployment recommended** |
| 12 | **GraphSAGE** — Hamilton et al., NeurIPS 2017 | Learned neighbourhood aggregation → representations for **unseen** nodes/graphs (inductive) | Citation, social, protein benchmarks | Classification on unseen nodes/graphs; cost | Large gains over transductive baselines | Sampling variance; depends on feature quality |

---

## 5. Research gap

Three consistent absences run through the twelve works:

1. **Provenance consumers do not authenticate their input.** Kairos, MGDA, threaTrace, UNICORN
   and ATLAS all improve what can be extracted from a provenance graph, and all five assume the
   graph is a faithful record. The survey confirms this holds across the field.
2. **Capture systems reduce event loss without proving its absence.** eAudit demonstrates fast,
   reliable collection, yet a gap in its output cannot be distinguished from a deletion —
   completeness is asserted by the operator, not demonstrated to a verifier.
3. **The integrity machinery exists but has never been brought to host provenance.** Merkle² and
   Certificate Transparency give append-only verifiable records; FIPS 204 gives signatures that
   survive quantum attack; GraphSAGE gives an inductive encoder for unseen graphs; Baseri et al.
   propose anchoring in proportion to risk — **without implementing or measuring it**.

**The gap addressed:** the absence of a path that runs from *attested capture*, through *detection
of deliberate editing*, into *cryptographically sealed and risk-anchored evidence*, with the
*survivability* of that evidence measured. The individual components are known; **the composition
is not** — and the composition is where the protection comes from, since each stage covers a
failure of the stage before it.

---

## 6. Datasets, platforms and implementation tools

### 6.1 The dataset position, stated plainly

**No public corpus of poisoned provenance graphs exists.** The datasets used by the reviewed
detection systems — DARPA Transparent Computing, OpTC, StreamSpot — contain attacks **against
hosts**, not attacks **against records**, and provide no ground truth for this problem.

Two data sources were used instead:

1. **Real provenance** captured from the authors' development machines via the eBPF probe
   (e.g. the 203-node / 354-relation capture used end-to-end).
2. **Generated graphs** from a configurable clean generator, with the project's **attack
   simulator** producing tampered counterparts under four strategies with a continuous
   sophistication parameter — yielding **exact node- and graph-level labels**, since the simulator
   knows exactly which nodes it modified.

Every evaluation figure was produced with a **fixed random seed and 15 independent trials per
condition** (30 trials per condition in the tamper scorecard). The consequence — that the learned
component's figures are in-distribution — is bounded in §11 rather than left to be inferred.

### 6.2 Platform, hardware and technology stack

| Category | Choice | Notes |
|---|---|---|
| **Hardware** | x86_64, 8 GB RAM, 10 GB disk; kernel ≥ 5.8 (ring buffer); root only to load the probe | **No GPU** — the learned component trains on CPU in under one minute |
| **Language** | Python 3.10+ (27 modules, 6,808 lines) + C for the eBPF loader | |
| **Kernel capture** | eBPF probe on `sys_enter_execve`; 16 MB ring buffer; no formatting/allocation in kernel context | `clang`, `llvm`, `libbpf-dev`, `bpftool` to build |
| **Graph** | NetworkX — directed graph; process node = (pid, creation time) so identifier reuse cannot merge processes; schema contract on every edge | |
| **ML** | NumPy GraphSAGE, 2 layers, mean aggregator, hand-derived gradients verified by finite difference | |
| **Crypto** | `cryptography` for Ed25519 + scrypt/AES-256-GCM key wrapping; module-lattice library for ML-DSA-65 | |
| **Storage** | PostgreSQL 14+ (7 tables) via SQLAlchemy/psycopg2, optional; automatic file-based fallback | Full test suite passes with none of DB/root/probe present |
| **Key properties (NFRs)** | Verification needs only evidence files + public key; sealing independent of any model; honest failure — the distributed-ledger adapter **raises rather than returns a fabricated receipt** | |

---

## 7. Proposed methodology — the pipeline architecture

### 7.1 The layering argument

Seven components, each stage covering a failure of the stage before it:

- **Sequence numbering** shows something is missing — but not whether its absence was deliberate.
- **Detection** distinguishes deliberate editing — but depends on training data of uncertain
  representativeness.
- **Sealing** is independent of training — but depends on the signing key.
- **Anchoring** limits the damage when the key is compromised.

The design is cumulative; **no single assumption carries the whole system.**

### 7.2 The full pipeline, end to end

```
                        program starts (execve)
                                     │
   ┌─────────────────────────────────▼──────────────────────────────────┐
   │  PHASE 1 · CAPTURE + COMPLETENESS ATTESTATION        (kernel)      │
   │  eBPF probe on sys_enter_execve — fires BEFORE the new process     │
   │    can run code; writes fixed-size records to a 16 MB ring buffer; │
   │    no formatting, no allocation in kernel context                  │
   │  User-space reader: assigns strictly increasing sequence numbers,  │
   │    resumes from the highest stored number across restarts          │
   │    1, 2, 4  ⇒  event 3 existed and is gone — the absence is a PROOF│
   │    buffer overflow / daemon stop  ⇒  ATTESTED gap (named + ranged) │
   │    any other gap                    ⇒  UNATTESTED = DELETION       │
   │  On shutdown: SIGNED completeness certificate — run id, sequence   │
   │    range, events observed, gaps attested, complete flag — hashed   │
   │    under its own domain separator, signed under BOTH schemes       │
   └─────────┬──────────────────────────────────────────────────────────┘
             │ raw events + attestations  (PostgreSQL or JSON files)
   ┌─────────▼──────────────────────────────────────────────────────────┐
   │  PHASE 2 · NORMALISE                                               │
   │    • remove ring-buffer re-read duplicates                         │
   │    • reject temporal-order violations                              │
   │    • infer parents from the execution chain                        │
   │    • EVERY discard recorded with its reason — the difference       │
   │      between events read and events retained is fully accounted    │
   └─────────┬──────────────────────────────────────────────────────────┘
   ┌─────────▼──────────────────────────────────────────────────────────┐
   │  PHASE 3 · PROVENANCE GRAPH                                        │
   │    process node = (pid, creation time) — no PID-reuse merging      │
   │                                                                    │
   │      P:ROOT:1000 (session root, adopts orphans)                    │
   │         │ SPAWNS                                                   │
   │         ▼                                                          │
   │      P:100:1  bash ──EXECUTES──▶ F:/usr/bin/python3                │
   │         │ SPAWNS                                                   │
   │         ▼                                                          │
   │      P:101:2  python3 ──EXECUTES──▶ F:/usr/bin/git                 │
   │    schema contract enforced on every edge                          │
   └─────────┬──────────────────────────────────────────────────────────┘
             │
   ┌─────────▼──────────────────────────────────────────────────────────┐
   │  PHASE 4 · DETECTION OF RECORD POISONING                           │
   │                                                                    │
   │   ┌────────────────────────┐  ┌──────────────────────────────────┐ │
   │   │ RULE ENGINE             │  │ GRAPHSAGE ENCODER (NumPy)        │ │
   │   │ 10 deterministic        │  │ 38 features/node (structural,    │ │
   │   │ invariants — sequence   │  │ temporal, identity, sequence)    │ │
   │   │ gap, causality, orphan, │  │   → 64 → 64 → sigmoid suspicion  │ │
   │   │ monotonicity, ...       │  │ 2 layers, mean aggregator =      │ │
   │   │ a violation is a PROOF  │  │ 2-hop receptive field            │ │
   │   │ → high/critical =       │  │ graph alert above threshold      │ │
   │   │   TAMPERED              │  │ → statistical = SUSPICIOUS       │ │
   │   └──────────┬─────────────┘  └───────────────┬──────────────────┘ │
   │              └───── fusion: rule-priority ─────┘                    │
   │   rules prove; the GNN catches what rules cannot express           │
   └─────────┬──────────────────────────────────────────────────────────┘
             │ detection report (violations carry their partition target)
   ┌─────────▼──────────────────────────────────────────────────────────┐
   │  PHASE 5 · SEALING — tamper evidence BY CONSTRUCTION               │
   │                                                                    │
   │        root ◀── signed Ed25519 AND ML-DSA-65 (both must pass)      │
   │       /    \                                                       │
   │     h12     h34        ◀── previous-partition hash (the CHAIN:     │
   │    /  \     /  \          removing a whole partition leaves each    │
   │   e1   e2  e3   e4        tree valid — only the chain reveals it)  │
   │                                                                    │
   │    leaves hashed under one domain separator, internal nodes        │
   │    under another (blocks second-preimage on naive Merkle)          │
   │    inclusion proof = sibling path (4 hashes for 16 relations)      │
   └─────────┬──────────────────────────────────────────────────────────┘
             │
   ┌─────────▼──────────────────────────────────────────────────────────┐
   │  PHASE 6 · RISK-ADAPTIVE ANCHORING                                 │
   │   score ∈ [0,1] per partition, six weighted signals:               │
   │    rule violations .25 │ learned suspicion .25 │ tamper alert .20  │
   │    privileged activity .15 │ unattested gap .10 │ rare image .05  │
   │   counted signals through a SATURATING curve (first violation      │
   │   moves the score most; more of the same contribute less)          │
   │   violations are ATTRIBUTED to their partition — unlocalisable     │
   │   ones are skipped, never spread over every partition              │
   │                                                                    │
   │   HARD ESCALATION overrides the score: tamper alert, or blocking   │
   │   rule violation ⇒ Tier 1 — "a weighted average should not be      │
   │   permitted to argue away a definite finding"                      │
   │                                                                    │
   │   score ≥ 0.45 ──▶ TIER 1  anchored without delay                  │
   │   score ≥ 0.20 ──▶ TIER 2  batched                                 │
   │   score <  0.20 ──▶ TIER 3  retained locally, zero transactions    │
   │   urgent partitions BATCHED: their roots become the leaves of a    │
   │   second-order Merkle tree (adapted from Merkle²) — one ledger     │
   │   write, each partition keeps an inclusion proof.                  │
   │   "Immediate" means without delay, not alone.                      │
   │                                                                    │
   │   ledger: local, append-only, hash-chained, dual-signed            │
   └─────────┬──────────────────────────────────────────────────────────┘
             │
   ┌─────────▼──────────────────────────────────────────────────────────┐
   │  PHASE 7 · SURVIVABILITY EVALUATION                                │
   │   five damage models: edge / node / contiguous-window removal,     │
   │   insertion of fabricated relations, mixed                         │
   │   each surviving relation classified against the seals:            │
   │     intact │ PROVABLY DELETED (seal exists, content gone)          │
   │     │ inserted-after-sealing (present, no seal)                    │
   │   bridges marked inferred, reported separately, never counted      │
   │   as authenticated evidence                                        │
   │   PIS · EPR · GRR · RA  →  FSI composite                           │
   └────────────────────────────────────────────────────────────────────┘
```

---

## 8. Proposed approach — algorithm steps and hyperparameters

### 8.1 Detection (report §5.2.3)

**Rule engine — ten deterministic structural conditions.** Four examples: the *sequence-gap* rule
reports any sequence number absent without a matching attestation; the *causality* rule reports a
child created before its parent; the *orphan* rule reports a process with no required spawn edge;
the *monotonicity* rule reports timestamp order contradicting sequence order. Each violation
carries a severity and names the node, edge, pid or sequence position — which is what allows it to
be attributed to a specific partition. **A violation is a proof.** The weakness: rules can only
express conditions that were anticipated — a careful attacker who adjusts sequence numbers *and*
timestamps satisfies every encoded invariant.

**Learned component — covers that weakness.** 38 features per node in four families: structural
(in/out-degree, local clustering), temporal (interval to parent, local event rate), identity (pid
locality, uid), sequence (local density, distance to nearest attested gap). GraphSAGE with two
layers and a mean aggregator; each layer mean-aggregates neighbours, concatenates with the node's
own representation, applies a learned linear map + non-linearity, and normalises. **Inductive is a
requirement, not a preference** — every capture produces a graph the model has never seen, so
transductive embeddings are inapplicable.

**Self-supervised training:** clean graph generated → attack simulator produces tampered
counterpart under a random strategy and sophistication → the touched nodes are the exact positive
labels. Gradients derived by hand, verified against numerical differentiation. Testing only on
graphs from a seed never used in training.

### 8.2 Configuration of the learned detector (report Table 5.1)

| Parameter | Value |
|---|---|
| Encoder | GraphSAGE, 2 layers |
| Aggregator | mean |
| Input features per node | 38 |
| Hidden dimension | 64 |
| Output dimension | 1 (node suspicion score) |
| Learning rate | 0.003 |
| Training epochs | 40 |
| Synthetic training graphs | 260 |
| Node decision threshold (training config) | 0.880, selected on a validation split, held fixed |
| Implementation | NumPy, hand-derived gradients |
| Gradient check | finite difference — passed |
| Threshold used in the Chapter 6 evaluation runs | 0.760, attack intensity 10 % |

### 8.3 Sealing (report §5.2.5)

Partitions of configurable size (default 128 relations; 16 in the demonstration). Each relation
canonically serialised and hashed into a leaf; leaves combined pairwise to a root. Leaves and
internal nodes hashed under **different domain separators** (an attacker cannot present an internal
node as a leaf to construct a second input with the same root). Each partition record incorporates
its predecessor's hash — removing an entire partition leaves the remaining trees individually
valid; **the broken chain is what reveals the removal**. Every root signed under **Ed25519 and
ML-DSA-65 (FIPS 204)**, both must verify: break Ed25519 with a quantum computer and the lattice
signature holds; find a weakness in the young lattice scheme and the elliptic curve holds. Any
sealed relation can be proved into its partition with the sibling path — four hashes for a
16-relation partition — without disclosing the rest.

### 8.4 Risk-adaptive anchoring (report §5.2.6)

Six weighted signals → score in [0,1]; counted signals mapped through a **saturating curve**
(the first violation moves the score substantially; further violations of the same kind contribute
progressively less). Violations are matched against each partition's sequence range and node set;
**unlocalisable violations are skipped rather than attributed everywhere** — an earlier version
counted them against every partition, which escalated entire runs to Tier 1 and destroyed
adaptivity (recorded as a defect with a regression test). Three tiers, two hard escalations, one
batching construction (second-order Merkle tree, adapted from Merkle²). The ledger implemented and
measured is **local** — append-only, hash-chained, dual-signed; the distributed adapter raises
rather than fabricate receipts, since a measurement from a simulated receipt would not be a
measurement.

### 8.5 Survivability evaluation (report §5.2.7)

Five damage models — edge, node, contiguous-window removal (the most realistic: an attacker erases
a *period*, not a scattering), insertion, mixed. Each surviving relation classified against the
seals: **intact** (present and verifying), **provably deleted** (seal exists, content gone — a
stronger statement than "missing"), **inserted after sealing** (present, no seal). Bridges across
provably deleted relations are marked `inferred` and reported separately, never counted as
authenticated evidence.

---

## 9. Evaluation setup and criteria

### 9.1 Setup

Two harnesses: `python main.py tamper test --trials 30` (the attack evaluation) and
`python main.py all` over a real development-machine capture. Linux x86_64, no database, no
compiled probe for the offline stages. Learned detector at **threshold 0.760, attack intensity
10 %**. Three populations: **30 generated graphs per condition** (synthetic), **3 real capture
graphs per condition** (real), each split into attacks seen in training and **seven held out
entirely** — so generalisation is measured, not assumed. A separate experiment attacks the sealed
evidence directly. Three safeguards: held-out attacks; the cryptographic column never consults the
detector; real captures reported separately because scores on generated data are optimistic when
the model trained on the same generator.

### 9.2 Criteria and formulas

- **Detection rate** — proportion of attacked runs in which a component reports tampering;
  reported separately for rules, learned detector, fusion, and the sealing layer.
- **False alarm rate** — proportion of clean runs flagged; the CLEAN row is as important as the
  detection rate (a detector that always says "tampered" scores 100 % everywhere else).
- **Node precision / recall / AUC** — how well the learned detector *localises* the attacker's edits.
- **Anchoring cost** — ledger transactions consumed vs partitions processed (cost should follow
  risk, not volume).
- **Survivability**, with P the sealed partitions and Pᵥ those verifying in full; E, Eₛ captured
  and surviving event counts; R, Rₛ ancestor→descendant reachability pairs in original and
  surviving graphs; A the relations asserted authentic, A_t of them in fact authentic:

```
PIS = |Pᵥ| / |P|     EPR = Eₛ / E     GRR = |Rₛ| / |R|     RA = |A_t| / |A|

FSI = fixed-weight combination of the four      (all reported as percentages)
```

---

## 10. Results and analysis

### 10.1 Attacks represented in training — synthetic, 30 trials per condition (report Table 6.1)

| Condition | Rules | GNN | Fusion | Seal | Node P | Node R | AUC |
|---|---|---|---|---|---|---|---|
| **clean (false alarms)** | **0 %** | 17 % | 17 % | **0 %** | – | – | – |
| deletion, crude | 63 % | 100 % | 100 % | 100 % | 0.79 | 0.66 | 0.91 |
| deletion, expert | 73 % | 100 % | 100 % | 100 % | 0.79 | 0.66 | 0.91 |
| reorder, crude | 100 % | 100 % | 100 % | 100 % | 0.66 | 0.59 | 0.75 |
| reorder, expert | 100 % | 100 % | 100 % | 100 % | 0.90 | 0.78 | 0.95 |
| forgery, crude | 100 % | 100 % | 100 % | 100 % | 0.94 | 0.96 | 1.00 |
| forgery, expert | 100 % | 100 % | 100 % | 100 % | 0.89 | 0.57 | 0.92 |
| timeshift, crude | 100 % | 100 % | 100 % | 100 % | 0.64 | 0.98 | 1.00 |
| timeshift, expert | 100 % | 100 % | 100 % | 100 % | 0.52 | 0.65 | 0.89 |

The GNN reaches 100 % everywhere; the rules are weaker on deletion (63–73 %) where removal
disturbs too little structure. Node recall (0.57–0.98) shows flagging the graph is not the same as
locating the edits.

### 10.2 Attacks **never seen** in training — the clearest result (report Table 6.2)

| Attack | Rules | GNN | Fusion | **Seal** | Node P | Node R | AUC |
|---|---|---|---|---|---|---|---|
| adaptive deletion | 0 % | 77 % | 77 % | **100 %** | 0.10 | 0.02 | 0.56 |
| tail truncate | 0 % | 13 % | 13 % | **100 %** | 0.00 | 0.00 | 0.66 |
| adaptive reorder | 7 % | 17 % | 17 % | **100 %** | 0.26 | 0.01 | 0.41 |
| adaptive forgery | 0 % | 53 % | 53 % | **100 %** | 0.68 | 0.04 | 0.78 |
| binary swap | 0 % | 7 % | 7 % | **100 %** | 0.00 | 0.00 | 0.60 |
| uid rewrite | 7 % | 20 % | 27 % | **100 %** | 0.21 | 0.02 | 0.54 |
| flag abuse | 100 % | 100 % | 100 % | **100 %** | 0.79 | 0.38 | 0.86 |

Against unseen attacks the learned detector falls from 100 % to **7–77 %** (binary swap: 7 % —
close to useless); the rules fall to zero on five of seven; node recall collapses to 0.00–0.04 on
six of seven — even when the graph is flagged, the detector cannot say *which* nodes were touched.
**The cryptographic layer catches all seven at 100 %.** The reason is structural: rules and the
GNN answer *"does this graph look edited?"* — which requires having seen similar edits. Sealing
answers *"does this content match the signed root?"* — an attack the designers never imagined still
changes the leaf, which changes the root, which breaks the signature. *(Figure:
`image/fig_risk.png` illustrates the risk-score separation behind the anchoring response.)*

### 10.3 Real captures — 3 graphs per condition (report Table 6.3)

| Condition | Rules | GNN | Fusion | Seal | Node P | Node R | AUC |
|---|---|---|---|---|---|---|---|
| **clean (false alarms)** | 0 % | **100 %** | 100 % | 0 % | – | – | – |
| deletion, crude / expert | 0 % / 0 % | 100 % | 100 % | 100 % | 0.35/0.33 | 0.56/0.59 | 0.68/0.65 |
| reorder, crude / expert | 100 % | 100 % | 100 % | 100 % | 0.38/0.59 | 0.26/0.71 | 0.49/0.74 |
| forgery, crude / expert | 100 % | 100 % | 100 % | 100 % | 0.58/0.40 | 0.88/0.54 | 0.91/0.74 |
| timeshift, crude / expert | 100 % | 100 % | 100 % | 100 % | 0.25/0.20 | 0.64/0.50 | 0.76/0.75 |
| adaptive deletion | 0 % | 67 % | 67 % | 100 % | 0.00 | 0.00 | 0.64 |
| tail truncate | 0 % | 67 % | 67 % | 100 % | 0.00 | 0.00 | 0.42 |
| adaptive reorder | 0 % | 67 % | 67 % | 100 % | 0.14 | 0.10 | 0.50 |
| adaptive forgery | 0 % | 33 % | 33 % | 100 % | 0.14 | 0.02 | 0.75 |
| binary swap | 0 % | 67 % | 67 % | 100 % | 0.10 | 0.03 | 0.56 |
| uid rewrite | 100 % | 100 % | 100 % | 100 % | 0.09 | 0.24 | 0.56 |
| flag abuse | 100 % | 100 % | 100 % | 100 % | 0.08 | 0.18 | 0.46 |

Two findings are worse than on generated data and reported because they are the honest ones: the
learned detector flagged **all three clean real captures** (real developer activity does not
resemble generated graphs — the system labels this SUSPICIOUS, a statistical suspicion, and
directs the user to `verify`); and the rule engine detects **no deletion at all** on real graphs
(real process trees are sparser, so removal breaks fewer invariants). **Sealing: 100 % on every
attacked condition, zero false alarms.**

### 10.4 Direct attacks on the sealed evidence and ledger — 17/17 caught (report Table 6.4)

| Layer | Attack | Caught |
|---|---|---|
| seal | edit a leaf hash / edit a Merkle root / edit a signed field | yes |
| seal | forge the Ed25519 signature / forge the ML-DSA signature | yes |
| seal | delete a middle partition / swap two partitions / truncate the newest partitions | yes |
| seal | add a duplicate leaf | yes |
| seal | **rewrite and re-sign with own key** — caught by key pinning | yes |
| seal | replace the ML-DSA key | yes |
| ledger | inclusion proof to a fake batch root | yes |
| ledger | sealed root differs from the anchored root | yes |
| ledger | edit a ledger block / rebuild the ledger with own key / remove a block / delete the anchored block entirely | yes |
| **Total** | | **17 / 17** |

### 10.5 End-to-end run on the real capture — risk scoring and anchoring (report Table 6.5)

203 nodes, 354 relations, 3 partitions:

| Quantity | Value |
|---|---|
| risk score — min / mean / max | 0.0375 / 0.2524 / 0.4001 |
| Tier 1 (anchored immediately) | 2 |
| Tier 2 (batched) | 0 |
| Tier 3 (retained locally) | 1 |
| **ledger transactions consumed** | **1** |
| anchors independently verified | PASS |

The two urgent partitions (0.400, 0.320) shared **one** ledger transaction via the second-order
Merkle tree; the third (0.0375) consumed nothing. **This is the adaptivity claim in miniature:
three partitions, one transaction, cost only where warranted.**

### 10.6 Survivability of the real capture — 15 % edge removal (report Table 6.6)

Graph fell 203 nodes / 354 relations → 197 / 301:

| Measure | Value |
|---|---|
| PIS — Provenance Integrity Score | 85.03 % |
| EPR — Evidence Preservation Ratio | 97.74 % |
| GRR — Graph Recovery Rate | 87.20 % |
| RA — Recovery Accuracy | 100.00 % |
| **FSI — Forensic Survivability Index** | **91.86 %** |
| sealed relations | 354 |
| verified intact | 301 |
| **provably deleted** | **53** |

The row that matters: **53 relations are not merely absent — they are provably deleted**, because
a valid seal covers each and the content is gone. Without sealing they would simply be missing,
and an investigator could say nothing about whether they had ever existed. RA stays 100 % because
edge removal inserts nothing; accuracy is the measure that responds to insertion.
*(Figure: `image/fig_survivability.png` — FSI under edge/node/window removal at 0–75 % destruction.)*

### 10.7 Comparative analysis — each layer against the prior art it corresponds to (report Table 6.7)

| Configuration | Attacks seen in training | Attacks never seen | False alarms (real) | Needs training data |
|---|---|---|---|---|
| Rule engine alone (= conventional log consistency checking) | 63–100 % | 0–100 % | 0 % | no |
| Learned detector alone (= the provenance-detection literature, aimed at records) | 100 % | **7–77 %** | **100 %** | yes |
| **Sealing alone** (= the transparency-log line of work) | **100 %** | **100 %** | **0 %** | **no** |
| Full system | 100 % | 100 % | see note | one layer only |

Sealing's gap: it gives no indication of *what* changed or *where* — the information an
investigator needs to act. Fusion inherits the detector's false-alarm behaviour; reducing it by
training on real captures is the first item of future work. Points of contact with the reviewed
work: eAudit reduces loss without proving completeness — QuantumGuard issues a signed certificate,
a *different guarantee* rather than a better loss rate; Kairos/MGDA figures are not comparable
(different questions); **Baseri et al. proposed risk-adaptive anchoring without implementing it —
Table 10.5 is the measurement their proposal lacked.**

Benchmark anchoring results (15 trials per condition): clean captures consumed **zero** external
transactions (300 clean partitions); compromised captures anchored **189 partitions in 16
transactions**.

### 10.8 What sealing is worth, measured

Against an attacker who both deleted and fabricated relations — **72 fabricated** — sealing raised
Recovery Accuracy from **80.80 % to 100.00 %** by rejecting every fabricated relation: **+19.20
points**. A fifth of the evidence an unsealed system would have presented was planted; the
integrity layer has a concrete value, not a theoretical one.

### 10.9 Measurement validity and corrections (report §6.5)

Two survivability measures were found computed incorrectly during development — both reported
100.00 % at every damage level, including one at which four-fifths of the evidence was destroyed.
A measure that does not move when its quantity changes is not reporting a favourable result; it is
not reporting anything. EPR read a stored event count carried unchanged across a deep copy (now
counted from the graph structure directly); RA compared survivors against the original set after a
recovery step that only removed isolated nodes (meaningful only against insertion — insertion and
mixed damage models were added). Three tests now assert every measure **decreases monotonically**
as damage rises, so a constant measure fails the suite rather than appearing in a report.

---

## 11. Discussion and limitations

Six limitations bound the results, stated here rather than left to be found:

1. **The learned detector is evaluated in-distribution.** Training labels come from the project's
   own attack simulator, because no public corpus of poisoned provenance graphs exists. The
   figures are an upper bound against an attacker whose methods differ. Validation against an
   independent corpus (DARPA OpTC is the realistic candidate) is the next milestone. **This
   applies to one layer only — the integrity result is unaffected.**
2. **The key store is a software component.** Keys encrypted at rest (scrypt + AES-256-GCM) but
   entering host memory during signing; an attacker with root and the passphrase can sign. The
   interface is shaped for HSM substitution; no HSM was used and no result depends on one.
3. **The anchoring ledger is local.** Append-only, hash-chained, signed, independently verifiable —
   but a root attacker with the passphrase could discard it and construct a replacement. The
   distributed adapter refuses fabricated receipts; measurements are of the local ledger only.
4. **Capture is limited to process execution.** No file reads/writes, no network connections — a
   process tree with execution targets, not a data-flow graph. An attack operating entirely through
   file content produces no record.
5. **Attack reconstruction is not implemented.** The system protects the record that
   reconstruction systems (Kairos, ATLAS) consume.
6. **No baselines or ablations against alternative encoders.** No GCN/GAT/GIN comparison, no
   feature-family ablation, no depth study — their absence limits the claim that GraphSAGE is the
   *right* encoder rather than a *sufficient* one.

**Interpretation highlights.** O1 is met with the noted boundary that completeness is attested
relative to what the probe observed (an attacker who suppresses the probe itself is outside the
threat model — the kernel is assumed uncompromised at capture). The rule engine's zero against a
careful reordering is the project's clearest empirical finding: consistency checking — the usual
defence — fails against an attacker who maintains consistency, which is why the learned component
exists. O4's 100 % with the model absent is the result that confines the training-data limitation
to a single layer. The threshold calibration finding: a threshold set by judgement would have
missed four of fifteen tampered runs — only measurement revealed it.

---

## 12. Conclusion — objective-wise status

| Objective | Status | Evidence |
|---|---|---|
| **O1** — loss is provable | ✅ Met | Sequence continuity across restarts; downtime as explicit session gap; edited certificate fails verification |
| **O2** — causally faithful graph | ✅ Met | One identity per process instance; schema contract on every edge |
| **O3** — detect editing, 4 strategies × 2 care levels | ✅ Met (100 %, all 8 conditions) | Careful reordering missed by rules 15/15, caught by the encoder 15/15 — the empirical basis for the two-layer design |
| **O4** — cryptographic-only verification, quantum-resistant | ✅ Met (100 %, model absent) | Confines the training-data limitation to one layer |
| **O5** — risk-proportionate anchoring + quantified survivability | ✅ Met | Zero transactions on 300 clean partitions vs 16 for 189 anchored; five measures over five damage models; sealing worth +19.20 points of RA |

All five objectives met. The contribution, stated narrowly: **poisoning of the provenance record
as a first-class detectable attack**, composed with attested capture, cryptographic sealing,
risk-proportionate anchoring and measured survivability into one working path. The most significant
limitation — in-distribution evaluation — is a consequence of the absence of a public dataset for
this problem, not a design decision.

---

## 13. Future work

1. **Validation against an independent corpus** — highest priority: an independently written
   tampering tool applied to DARPA OpTC provenance, converting in-distribution figures into a
   defensible out-of-distribution result.
2. **Baselines and ablations** — GCN / GAT / GIN under identical conditions; ablation over the
   four feature families; encoder-depth study. No new data required.
3. **Broadening capture** — file read/write and network connections → a data-flow graph. Main
   dependency: event volume; sampling and partitioning would need revision before sealing could
   keep pace.
4. **Connecting the distributed ledger** — the adapter interface exists and refuses fabricated
   receipts; a running Hyperledger Fabric network would remove the local-ledger limitation and let
   the anchoring-cost measurement be repeated against real transaction costs and latencies.
5. **Hardware-backed keys** — an HSM so private keys never enter host memory; validation by
   repeating the sealing and verification experiments with signing on the module.
6. **Operational trial** — continuous long-run capture to characterise the completeness
   certificate under real workloads, measure the genuine attested-gap rate, and establish the
   risk-score distribution on real activity.

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

**Before any real use, change the key-store passphrase** (the default is printed in the project's
own docs, so a store protected only by it is protected by nothing):

```bash
export QG_KEYSTORE_PASSPHRASE='something-long-and-not-this'
rm -rf keys/ && python main.py keys
```

### 14.2 Offline path — 5 minutes, no PostgreSQL, no eBPF, no root

```bash
python -m tests.run_all                      # run the full test suite; expect 0 failed
python main.py demo --partition-size 16      # full pipeline end to end, with an attack
python -m tests.benchmark --trials 15 --json evidence/benchmark.json   # regenerate every number
```

Demo strategies: `--strategy forgery | deletion | reorder | timeshift`, and
`--sophistication 0.0` (crude) vs `1.0` (careful attacker). **Always pass `--partition-size 16`
for demos** — the default of 128 puts a small graph in one partition and hides the per-partition
localisation.

### 14.3 Live capture — database + kernel

```bash
sudo -u postgres createdb provenance
sudo -u postgres psql -c "CREATE USER quantumguard WITH PASSWORD 'StrongPassword123';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE provenance TO quantumguard;"
sudo -u postgres psql -d provenance -f database/schema.sql        # idempotent (IF NOT EXISTS)
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

or stage by stage:

```bash
python main.py keys                   # create or display the key pair
python main.py graph                  # normalisation and graph construction
python main.py detect                 # rule engine and learned detector
python main.py seal                   # Merkle sealing and dual signing
python main.py anchor                 # risk scoring and external anchoring
python main.py evaluate               # survivability measurement
python main.py verify                 # exit status 0 for pass, 2 for fail
python main.py visualize              # graphs/provenance_graph.png — one box per program
```

Useful flags: `seal --partition-size 16 --run-id my-run`; `anchor --batch-size 8 --ledger local|fabric`;
`detect --output evidence/detection_report.json`; `evaluate --ratio 0.3 --mode node`
(modes: `edge node window insert mixed edit`); `verify --run-id ... --trust-file ...` (public keys
exported via `keys --export-trust`).

### 14.5 Tamper testing on your own data

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

`tamper` works on copies with a throwaway key store; exit status 2 if any evidence attack goes
undetected.

### 14.6 Configuration (`core/config.py`, env-overridable)

| Variable | Default | Meaning |
|---|---|---|
| `QG_DB_URL` | `postgresql+psycopg2://quantumguard:StrongPassword123@localhost/provenance` | database connection |
| `QG_STORE` | `auto` | `auto` \| `db` \| `file` |
| `QG_PARTITION_SIZE` | `128` | relations per sealed partition (demo: 16) |
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

---

## 15. Repository structure

```
QuantumGuard/
├── main.py              CLI entry point — every command above
├── ebpf/                probe source, loader and build file
├── capture/             collector, sequence manager, completeness attestation
├── graph/               normalisation, graph construction, visualisation
├── detection/           rule engine, features, GraphSAGE model, attack simulator
├── crypto/              Merkle tree, hash chain, dual signing, key store
├── anchoring/           risk scoring, ledger, anchoring service
├── evaluation/          damage models, recovery, survivability measures
├── core/                configuration and storage backends
├── database/            PostgreSQL schema, seven tables
├── tests/               test suite (capture→seal, phases 6–7, tamper) + benchmark harness
├── image/               figures: fig_risk, fig_sealing, fig_survivability + final-run screenshots
│                        + S7_Project_Report_Template_2026 (6).pdf (the project report)
│                        + final review PPT Template.pptx
├── README.md            design rationale + measured results
├── RUN.md               purely operational guide
├── QuantumGuard Field Guide.html   per-phase walkthrough with real annotated outputs
└── FINAL_GUIDE.md       this document
```

---

## 16. References

1. Z. Cheng, Q. Lv, J. Liang, Y. Wang, D. Sun, T. Pasquier, and X. Han, "Kairos: Practical
   intrusion detection and investigation using whole-system provenance," *2024 IEEE Symposium on
   Security and Privacy (SP)*, pp. 3533–3551, IEEE, 2024.
2. M. Cui, Z. Jiang, S. Li, C. Ma, K. Zhang, P. Yang, and H. Feng, "MGDA: A provenance graph-based
   framework for threat detection and attack scenario reconstruction," *Computer Networks*,
   p. 111806, 2025.
3. M. Zipperle, F. Gottwalt, E. Chang, and T. Dillon, "Provenance-based intrusion detection
   systems: A survey," *ACM Computing Surveys*, vol. 55, no. 7, pp. 1–36, 2022.
4. R. Sekar, H. Kimm, and R. Aich, "eAudit: A fast, scalable and deployable audit data collection
   system," *2024 IEEE Symposium on Security and Privacy (SP)*, pp. 3571–3589, IEEE, 2024.
5. Y. Hu, K. Hooshmand, H. Kalidhindi, S. J. Yang, and R. A. Popa, "Merkle²: A low-latency
   transparency log system," *2021 IEEE Symposium on Security and Privacy (SP)*, pp. 285–303,
   IEEE, 2021.
6. Y. Baseri, A. Hafid, Y. Shahsavari, D. Makrakis, and H. Khodaiemehr, "Blockchain security risk
   assessment in quantum era, migration strategies and proactive defense," *IEEE Communications
   Surveys & Tutorials*, 2025.
7. A. Alsaheel, Y. Nan, S. Ma, L. Yu, G. Walkup, Z. B. Celik, X. Zhang, and D. Xu, "ATLAS: A
   sequence-based learning approach for attack investigation," *30th USENIX Security Symposium*,
   pp. 3005–3022, 2021.
8. S. Wang, Z. Wang, T. Zhou, H. Sun, X. Yin, D. Han, H. Zhang, X. Shi, and J. Yang,
   "threaTrace: Detecting and tracing host-based threats in node level through provenance graph
   learning," *IEEE Transactions on Information Forensics and Security*, vol. 17,
   pp. 3972–3987, 2022.
9. X. Han, T. Pasquier, A. Bates, J. Mickens, and M. Seltzer, "UNICORN: Runtime provenance-based
   detector for advanced persistent threats," *arXiv preprint arXiv:2001.01525*, 2020.
10. B. Laurie, "Certificate transparency," *Communications of the ACM*, vol. 57, no. 10,
    pp. 40–46, 2014.
11. T. Dang, J. Lichtinger, Y.-K. Liu, C. Miller, D. Moody, R. Peralta, R. Perlner, A. Robinson,
    et al., "Module-lattice-based digital signature standard," NIST FIPS 204, 2024.
12. W. Hamilton, Z. Ying, and J. Leskovec, "Inductive representation learning on large graphs,"
    *Advances in Neural Information Processing Systems*, vol. 30, 2017.
