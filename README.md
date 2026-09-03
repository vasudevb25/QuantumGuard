
# QuantumGuard

**QuantumGuard** is an enhanced tamper-evident provenance logging framework that captures kernel-level system events, verifies capture completeness, constructs provenance graphs, and prepares forensic evidence for secure integrity verification.

> **Research Focus:** Building a next-generation provenance system with eBPF, Capture Completeness Attestation (CCA), provenance graph construction, post-quantum integrity, and forensic survivability evaluation.

---

## Overview

Traditional provenance systems assume that every system event is successfully captured. QuantumGuard removes that assumption by making **event loss provable** through Capture Completeness Attestation (CCA).

The current implementation includes:

- eBPF kernel-level provenance capture
- Capture Completeness Attestation (CCA)
- PostgreSQL evidence storage
- Event normalization pipeline
- Provenance graph generation using NetworkX
- Graph visualization for forensic analysis

Future phases will extend the system with Graph Neural Network poisoning detection, hybrid post-quantum signatures, Hyperledger Fabric anchoring, and forensic survivability metrics.

---

# System Architecture

```text
                    ┌─────────────────────────┐
                    │ User Processes          │
                    │ bash, python, code      │
                    └────────────┬────────────┘
                                 │ execve()
                                 ▼
                    ┌─────────────────────────┐
                    │ eBPF Kernel Probe       │
                    │ Tracepoint: execve      │
                    └────────────┬────────────┘
                                 │
                          Ring Buffer
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ Python Collector        │
                    │ JSON Event Parser       │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │ Capture Completeness    │
                    │ Attestation (CCA)       │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ PostgreSQL Evidence DB  │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ Graph Construction      │
                    │ Normalize • Validate    │
                    │ Enrich • Build DAG      │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ Provenance Graph        │
                    │ GraphML • PNG          │
                    └─────────────────────────┘
```

---

# Project Pipeline

| Stage                     | Description                                                                     |
| ------------------------- | ------------------------------------------------------------------------------- |
| **1. Capture**            | eBPF intercepts `execve()` system calls directly from the Linux kernel          |
| **2. Transport**          | Events are streamed through a ring buffer to user space                         |
| **3. Attestation**        | Every event receives a forensic sequence number and CCA verifies missing events |
| **4. Storage**            | Verified evidence is stored in PostgreSQL                                       |
| **5. Normalization**      | Duplicate events are removed and timestamps are validated                       |
| **6. Enrichment**         | Process metadata and causal relationships are added                             |
| **7. Graph Construction** | Events become a directed provenance graph (Process → File)                      |
| **8. Visualization**      | Human-readable forensic graph is generated                                      |

---

# Repository Structure

```text
quantumguard/
│
├── ebpf/
│   ├── probes.c
│   ├── loader.c
│   ├── Makefile
│   └── vmlinux.h
│
├── capture/
│   ├── collector.py
│   ├── database.py
│   ├── models.py
│   ├── sequence.py
│   └── cca.py
│
├── graph/
│   ├── service.py
│   ├── models.py
│   ├── main.py
│   └── visualize.py
│
├── database/
│   └── schema.sql
│
├── graphs/
│
└── README.md
```

---

# Technology Stack

| Component      | Technology       |
| -------------- | ---------------- |
| Kernel Capture | eBPF (Linux 6.x) |
| Loader         | C + libbpf       |
| Backend        | Python 3.12      |
| Database       | PostgreSQL       |
| Graph Engine   | NetworkX         |
| Visualization  | Matplotlib       |
| OS             | Ubuntu 24.04 LTS |

---

# Installation

## 1. Clone Repository

```bash
git clone https://github.com/yourusername/quantumguard.git

cd quantumguard
```

## 2. Install System Dependencies

```bash
sudo apt update

sudo apt install \
clang llvm bpftool libbpf-dev \
build-essential graphviz graphviz-dev \
postgresql postgresql-contrib
```

## 3. Create Python Environment

```bash
python3 -m venv venv

source venv/bin/activate

pip install \
sqlalchemy psycopg2-binary \
networkx matplotlib pygraphviz
```

---

# Database Initialization

## Create Database

```bash
sudo -u postgres createdb provenance
```

## Create User

```sql
CREATE USER quantumguard WITH PASSWORD 'StrongPassword123';

GRANT ALL PRIVILEGES ON DATABASE provenance TO quantumguard;
```

## Create Tables

```bash
sudo -u postgres psql -d provenance -f database/schema.sql
```

Grant permissions:

```sql
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO quantumguard;

GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO quantumguard;
```

---

# Build eBPF Program

Navigate into the eBPF directory:

```bash
cd ebpf

make clean

make
```

Generated files:

```text
loader
probes.o
probes.skel.h
```

---

# Running the Project

## Step 1. Start Provenance Collection

From project root:

```bash
python -m capture.collector
```

The collector automatically:

- launches the privileged eBPF loader
- captures kernel events
- performs Capture Completeness Attestation
- stores evidence into PostgreSQL

Example output:

```text
=== QuantumGuard eBPF Collector Started ===

[1] bash (PID 4211) → /usr/bin/python3

[2] python (PID 4214) → /usr/bin/docker

[3] code (PID 552922) → /usr/bin/bash
```

Press **Ctrl+C** to stop collection.

---

## Step 2. Construct Provenance Graph

```bash
python -m graph.main
```

Example:

```text
Raw events : 143

Nodes      : 67

Edges      : 81
```

Generated files:

```text
graphs/
├── provenance.graphml
└── provenance_graph.gpickle
```

---

## Step 3. Visualize Graph

```bash
python -m graph.visualize
```

Output:

```text
graphs/provenance_graph.png
```

The graph uses:

- 🔵 Blue nodes → Processes
- 🟢 Green nodes → Files
- Gray arrows → EXECUTES relation
- Red dashed arrows → SPAWNS relation

---

# Capture Completeness Attestation (CCA)

Unlike conventional provenance systems, QuantumGuard verifies whether events were silently lost.

Example:

```text
Sequence Received

1 ✓

2 ✓

3 ✓

7 ✗

Missing: 4,5,6
```

The missing sequences are recorded inside the `cca_attestation` table for forensic auditing.

---

# Provenance Graph Model

Each event becomes a directed edge.

```text
Process (bash)

│ EXECUTES

▼

File (python3)

│ SPAWNS

▼

Process (python)
```

This directed acyclic graph represents causal execution relationships rather than ordinary log entries.

---

# Output Artifacts

| File                       | Description                           |
| -------------------------- | ------------------------------------- |
| `raw_events`               | Kernel provenance evidence            |
| `cca_attestation`          | Missing event records                 |
| `provenance.graphml`       | Gephi/Cytoscape compatible graph      |
| `provenance_graph.gpickle` | Native NetworkX graph                 |
| `provenance_graph.png`     | Human-readable forensic visualization |

---

# Research Contributions

QuantumGuard introduces five major research components:

| Feature                            | Status         |
| ---------------------------------- | -------------- |
| eBPF Kernel Provenance Capture     | ✅ Implemented |
| Capture Completeness Attestation   | ✅ Implemented |
| Provenance Graph Construction      | ✅ Implemented |
| GNN Provenance Poisoning Detection | 🚧 Planned     |
| Hybrid Ed25519 + ML-DSA Integrity  | 🚧 Planned     |
| Risk-Adaptive Blockchain Anchoring | 🚧 Planned     |
| Forensic Survivability Evaluation  | 🚧 Planned     |

---

# Future Work

- GraphSAGE / GCN anomaly detection
- ML-DSA post-quantum signatures
- Hyperledger Fabric anchoring engine
- Merkle tree batching
- Provenance Integrity Score (PIS)
- Evidence Preservation Ratio (EPR)
- Graph Recovery Rate (GRR)
- Forensic Survivability Index (FSI)

---

# License

This project is developed for academic research and educational purposes as part of the **QuantumGuard Tamper-Evident Provenance Framework**.

