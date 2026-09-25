# 🛡️ ReconAI: AI-Assisted Digital Evidence Reconstruction & Recovery

> **AI-Assisted Intelligent Data Recovery and Digital Evidence Reconstruction tool**  
> Built for a 24-hour cybersecurity hackathon using a 100% free and open-source stack.

ReconAI ingests raw disk images (`.raw`, `.dd`, `.img`), preserves strict read-only chain of custody, performs dual recovery (filesystem metadata analysis + signature-based carving), reassembles split fragments with AI/heuristic confidence scoring, evaluates structural file integrity (0–100%), classifies evidence semantically into threat categories, renders interactive relationship graphs, and enables natural language evidence queries re-ranked by relevance and file integrity.

---

## ⚡ The 6 Core Features

1. **Dual Recovery (Filesystem + Signature Carving)**
   - Traverses deleted filesystem inodes (FAT16/FAT32 via `pytsk3` with an automated pure-Python sector undelete fallback) to recover files with intact metadata.
   - Carves raw unallocated sectors using magic byte signatures (JPEG, PNG, PDF, ZIP, TXT) when filesystem metadata is destroyed.
2. **AI Fragment Reconstruction + Confidence Score (0–100%)**
   - Discovers orphan header fragments and trailer chunks split across non-contiguous clusters.
   - Computes boundary entropy transitions, format syntax validation, and scores reassembly confidence (0–100%).
3. **Integrity & Quality Score (0–100%)**
   - Deep structural verification: tests whether recovered files actually open cleanly without format errors.
   - Utilizes Pillow for image decoding, `pypdf` for document structure/streams, and `zipfile` for CRC-32 testing.
   - Classifies artifacts as `INTACT` (80–100%), `PARTIAL` (40–79%), or `CORRUPTED` (0–39%).
4. **Semantic Classification & Investigator Prioritization**
   - Categorizes recovered evidence into investigative categories (`Financial & Invoices`, `Credentials & Secrets`, `Network & System Logs`, `Confidential Documents`, `Media`).
   - Prioritizes investigator workflow: $\text{Priority Score} = \text{Category Weight} \times (\text{Integrity} \times 0.7 + \text{Confidence} \times 0.3)$.
5. **Interactive Relationship Graph**
   - NetworkX + Pyvis graph visualizing fragment-to-file links (`REASSEMBLED_FROM`), recovery sources, and cross-evidence entities (crypto wallet addresses, forensic IPs).
6. **Natural Language Semantic Search**
   - Type conversational queries like *"unauthorized offshore wire transfer"* or *"leaked database credentials"*.
   - Multi-factor re-ranking: $\text{Rank Score} = \text{Relevance} \times \text{Integrity Multiplier}$.

---

## 🛠️ Free Technology Stack

| Layer | Technology | Rationale |
|---|---|---|
| **Frontend UI** | Streamlit | Pure Python, fast prototyping, dark cyber theme |
| **Disk Parsing** | `pytsk3` + Pure-Python FAT Sector Carver | Zero dependency lock-in, runs on macOS, Linux, Windows |
| **Fragment Reassembly** | Entropy gradient + Structural format validator | Fast, explainable 0–100% confidence scoring |
| **Integrity Testing** | Pillow, `pypdf`, `zipfile`, `hashlib` | Deep file format structure verification |
| **Graph Visualization** | NetworkX + Pyvis | Force-directed dark interactive physics graph |
| **Semantic Search** | `sentence-transformers` (all-MiniLM-L6-v2) + TF-IDF fallback | Neural search with instant zero-download fallback |
| **Database** | SQLite3 | Embedded persistent forensic case storage |

---

## 📂 Project Architecture

```
NOVA/
├── .vscode/
│   ├── settings.json               # Python environment & interpreter path
│   └── launch.json                 # 1-click VS Code run/debug profiles
├── data/
│   ├── demo_evidence.raw           # 64MB synthetic forensic disk image
│   ├── ground_truth.json           # Ground-truth verification manifest
│   └── reconai.db                  # SQLite database storing cases & artifacts
├── scripts/
│   └── make_test_image.py          # Synthetic disk generator with fragmentation & deleted files
├── reconai/
│   ├── ingest/
│   │   ├── hasher.py               # Read-only SHA-256 evidence seal & chain-of-custody
│   │   └── fs_reader.py            # pytsk3 + sector-level FAT undelete parser
│   ├── carve/
│   │   ├── signatures.py           # Magic bytes for JPEG, PNG, PDF, ZIP, TXT
│   │   └── carver.py               # Fast raw sector carver & orphan fragment collector
│   ├── reassemble/
│   │   └── fragment_matcher.py     # AI fragment reassembly & confidence scoring (0-100%)
│   ├── integrity/
│   │   └── validator.py            # Pillow, pypdf, zipfile integrity validator
│   ├── classify/
│   │   └── classifier.py           # Semantic threat categorization & priority ranking
│   ├── search/
│   │   └── semantic_search.py      # Natural language search with relevance × integrity
│   ├── graph/
│   │   └── graph_builder.py        # NetworkX + Pyvis dark forensic relationship graph
│   ├── db/
│   │   └── models.py               # SQLite storage for cases, items, and fragments
│   └── pipeline.py                 # Unified 6-stage forensic recovery orchestrator
├── tests/
│   └── test_pipeline.py            # Automated test suite for all 6 features
├── app.py                          # Streamlit application with custom dark cyber theme
├── requirements.txt                # Free open-source Python dependencies
└── README.md                       # Documentation & instructions
```

---

## 🚀 Quickstart Guide

### 1. Environment Setup
```bash
# Clone or navigate to the repository
cd /path/to/NOVA

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Generate Synthetic Test Disk (64MB)
```bash
python3 scripts/make_test_image.py
```
This generates:
- `data/demo_evidence.raw`: 64MB raw disk image containing deleted sensitive documents, fragmented passport photo, leaked credentials, unallocated bank logo, and corrupted archive.
- `data/ground_truth.json`: Ground truth manifest for automated scoring.

### 3. Launch the Streamlit Web Application
```bash
streamlit run app.py
```
Open [http://localhost:8501](http://localhost:8501) in your browser.

---

## 💻 Running in VS Code

This repository includes pre-configured VS Code debug targets:
1. Open this folder in VS Code (`code .`).
2. Press `Ctrl+Shift+D` (or `Cmd+Shift+D` on macOS) to open the **Run & Debug** pane.
3. Select any target from the dropdown:
   - **`ReconAI: Streamlit Web App`**: 1-click launch of the web interface with debugger attached.
   - **`ReconAI: Generate Test Image`**: Regenerates the 64MB demo disk image and ground truth.
   - **`ReconAI: Run Pipeline Tests`**: Runs the complete unit and integration test suite.
4. Press **F5** to start.

---

## 🧪 Automated Testing

Run the automated test suite verifying all 6 core features:
```bash
python3 -m unittest tests/test_pipeline.py
```

Expected output:
```
Ran 7 tests in 2.48s
OK
```

---

## 🛡️ Hackathon Demo Walkthrough

1. **Sidebar - Ingest & Seal:**
   - Select **"⚡ 64MB Demo Disk"**.
   - Notice the instant cryptographic **SHA-256 Chain-of-Custody seal**.
   - Click **"🚀 Run Recovery Pipeline"**.
2. **Tab 1: 📊 Executive Dashboard:**
   - View recovered file metrics, intact vs corrupted ratio, category distributions, and top priority items.
3. **Tab 2: 📁 Recovered Items:**
   - Filter by status (`INTACT`, `PARTIAL`, `CORRUPTED`) or category (`Credentials & Secrets`, `Financial & Invoices`).
   - Click any item to inspect its hex dump, decoded text stream, or render recovered images.
   - Download any reconstructed file with 1 click.
4. **Tab 3: 🕸️ Relationship Graph:**
   - Explore the force-directed interactive graph showing how fragments link to parent files and how entities like Crypto Wallets (`0x742d...`) and Forensic IPs (`198.51.100.23`) cross-link evidence.
5. **Tab 4: 🔍 Natural Language Search:**
   - Click demo buttons like *"💰 Offshore wire transfer"* or *"🔑 Leaked database secrets"*.
   - View results re-ranked by Relevance × Integrity.
6. **Tab 5: 📄 Forensic Report:**
   - Review the official DFIR case report and export to JSON or CSV.

