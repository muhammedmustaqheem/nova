# 🛡️ ReconAI: Complete Implementation & Architectural Reference

ReconAI is an **AI-Assisted Digital Evidence Reconstruction & Recovery System** designed for high-stakes digital forensics, incident response (DFIR), and cybersecurity hackathon demonstrations.

This document details the complete end-to-end technical implementation across all 20 specification modules, including file structures, data flow, algorithms, database schemas, API interfaces, and user interface design.

---

## 📂 1. Directory & File Architecture

```
NOVA/
├── app.py                          # Streamlit Interactive Web Application (Cyber Theme)
├── requirements.txt                # Dependency manifest (Pillow, pypdf, pyvis, networkx, Streamlit)
├── .gitignore                      # Git exclusion rules (Venvs, caches, DBs, raw disk images)
├── ARCHITECTURE.md                 # System architecture summary
├── MEMORY.md                       # Project memory log
├── recovery/                       # Structured forensic recovery output hierarchy
│   └── case-<ID>/
│       ├── original/               # Read-only original image copies
│       ├── carved/                 # Unallocated sector carved artifacts
│       ├── reconstructed/          # Spliced fragment reassembly outputs
│       ├── repaired/               # Derived partial repair artifacts
│       ├── reports/                # JSON & PDF DFIR court reports
│       ├── hashes/                 # Cryptographic seal certificates
│       └── logs/                   # Hash-chained custody audit trails
├── reconai/                        # Core Forensic Processing Engine
│   ├── __init__.py
│   ├── api.py                      # RESTful forensic backend controller & endpoints
│   ├── benchmark.py                # Ground-truth scientific recall & accuracy evaluator
│   ├── pipeline.py                 # Unified 12-stage forensic recovery orchestrator
│   ├── carve/
│   │   ├── __init__.py
│   │   ├── carver.py               # Raw unallocated sector carver & fragment collector
│   │   ├── entropy_map.py          # Sector-by-sector Shannon entropy scanner (0.0 - 8.0)
│   │   └── signatures.py           # Binary magic headers/footers (JPEG, PNG, PDF, ZIP, TXT, DB)
│   ├── classify/
│   │   ├── __init__.py
│   │   ├── classifier.py           # Semantic threat categorization & priority ranking
│   │   └── ioc_extractor.py        # Threat intel harvester (IPs, Crypto Wallets, Credentials)
│   ├── cluster/
│   │   └── clusterer.py            # SHA-256 deduplication & fuzzy shingle clustering
│   ├── db/
│   │   ├── __init__.py
│   │   └── models.py               # SQLite persistence layer (cases, items, fragments)
│   ├── explain/
│   │   └── explainer.py            # Dual-mode narrative generator (Simple vs Expert DFIR)
│   ├── graph/
│   │   ├── __init__.py
│   │   └── graph_builder.py        # NetworkX + Pyvis force-directed dark interactive graph
│   ├── ingest/
│   │   ├── __init__.py
│   │   ├── custody_logger.py       # Append-only hash-chained audit log
│   │   ├── fs_reader.py            # FAT16/FAT32/exFAT/NTFS inode & 0xE5 sector undelete
│   │   └── hasher.py               # Read-only SHA-256, SHA-1, MD5, and CRC-32 seals
│   ├── integrity/
│   │   ├── __init__.py
│   │   └── validator.py            # Deep programmatic parser validation (Pillow, pypdf, zipfile)
│   ├── reassemble/
│   │   ├── __init__.py
│   │   ├── fragment_engine.py      # Entropy gradient matching & reassembly logic
│   │   └── fragment_matcher.py     # Fragment graph builder & confidence scorer (0-100%)
│   ├── repair/
│   │   ├── __init__.py
│   │   └── repairer.py             # Format-specific repair engine (JPEG EOI, ZIP salvage, PDF stream)
│   ├── report/
│   │   └── report_exporter.py      # DFIR report generator (JSON & PDF ReportLab exporter)
│   ├── search/
│   │   ├── __init__.py
│   │   └── semantic_search.py      # Natural language search (Sentence Transformers + TF-IDF fallback)
│   ├── tampering/
│   │   └── tampering_detector.py   # Ransomware, wipe, & extension spoofing audit engine
│   └── timeline/
│       └── timeline_builder.py     # Multi-source chronological timeline constructor
├── scripts/
│   └── make_test_image.py          # Synthetic 64MB test disk & ground-truth generator
└── tests/
    ├── test_api.py                 # REST API unit & integration test suite
    └── test_pipeline.py            # Automated end-to-end 12-feature test suite
```

---

## ⚙️ 2. Detailed Technical Modules (Sections 1–20)

### Section 1: Forensic Evidence Preservation
- **File**: `reconai/ingest/hasher.py` & `custody_logger.py`
- **Read-Only Mode**: Evidence bit-streams are accessed via binary `O_RDONLY` read mode. Physical disk write operations are prevented.
- **Seals**: Computes SHA-256 (Primary Seal), SHA-1, MD5, and CRC-32 (Hardware I/O Read Guard).
- **Post-Analysis Verification**: Re-hashes the image file upon pipeline completion to verify bit-for-bit zero alteration.
- **Audit Logging**: Maintains append-only `ForensicAuditLog` entries where each log record includes `prev_hash` and `curr_hash`.

### Section 2: Filesystem-Based Recovery
- **File**: `reconai/ingest/fs_reader.py`
- **Logic**: Traverses filesystem directory tables (FAT16/FAT32/exFAT/NTFS) looking for directory entries marked deleted (`0xE5` character prefix).
- **Metadata Harvested**: Filename, Original Path, File Size, Created/Modified Timestamps, Deleted Status, Filesystem Type, Disk Sector Offset, Cluster Allocation, Recovery Method (`filesystem_undelete`), and Confidence (`100%`).

### Section 3: Signature-Based File Carving
- **Files**: `reconai/carve/signatures.py` & `carver.py`
- **Magic Byte Signatures**:
  - `JPEG`: Header `\xFF\xD8\xFF`, Footer `\xFF\xD9`
  - `PNG`: Header `\x89PNG\r\n\x1a\n`, Footer `IEND`
  - `PDF`: Header `%PDF-`, Footer `%%EOF`
  - `ZIP/Office (DOCX/XLSX/PPTX)`: Header `PK\x03\x04`, Footer `PK\x05\x06`
  - `SQLite`: Header `SQLite format 3\x00`
  - `TXT/LOG/ENV`: ASCII printable text stream heuristics
- **Execution**: Scans unallocated disk space outside known filesystem offsets, carving contiguous chunks and collecting orphan header/trailer fragments.

### Section 4: Fragment Detection & AI Reconstruction
- **Files**: `reconai/reassemble/fragment_matcher.py` & `fragment_engine.py`
- **Workflow**: Candidate Fragments $\rightarrow$ Type Prediction $\rightarrow$ Boundary Entropy Transition Calculation $\rightarrow$ Format Syntax Validation $\rightarrow$ Graph Reconstruction $\rightarrow$ Validation Test.
- **Confidence Scoring (0–100%)**: Itemized points assigned for header validity (+20), footer validity (+15), filesystem metadata (+20), fragment continuity (+15), file structure validity (+15), and decoder pass (+15).

### Section 5: Corrupted / Crashed File Detection
- **File**: `reconai/integrity/validator.py`
- **Pipeline**: Magic Validation $\rightarrow$ Structure Check $\rightarrow$ Size Ratio $\rightarrow$ Parser Execution.
- **Decoders Used**:
  - Images: `Pillow` image open, verify, and load test.
  - Documents: `pypdf` page extraction and text stream test.
  - Archives: `zipfile` CRC-32 integrity test.
  - Text: UTF-8 printable character ratio test.
- **Buckets**: `FULLY RECOVERABLE` (Intact), `PARTIALLY RECOVERABLE`, `FRAGMENT ONLY`, `UNRECOVERABLE`.

### Section 6: Safe File Repair
- **File**: `reconai/repair/repairer.py`
- **JPEG**: Rebuilds missing JFIF APP0 headers and injects missing EOI trailers (`\xFF\xD9`).
- **ZIP/Office**: Scans for valid local file headers (`PK\x03\x04`), decompresses intact members using `zlib`, and builds a fresh, uncorrupted ZIP archive container.
- **PDF**: Extracts surviving text object streams using string literal fallbacks.
- **Forensic Safety**: Leaves original evidence artifacts untouched. Derived files are saved to `recovery/case-XXX/repaired/` tagged `RECONSTRUCTED – derived artifact`.

### Section 7: Recovery Confidence Scoring
- **Formula**: $\text{Score} = \text{Header} + \text{Footer} + \text{FS Metadata} + \text{Continuity} + \text{Structure} + \text{Decoder}$
- **Normalizations**:
  - `0–39%`: Low
  - `40–69%`: Medium
  - `70–89%`: High
  - `90–100%`: Very High

### Section 8: Duplicate Detection
- **File**: `reconai/cluster/clusterer.py`
- **Primary Identifier**: SHA-256 hash.
- **Fuzzy Clustering**: Computes 4-gram shingle Jaccard similarity across payload streams to group near-duplicate files into cluster families.

### Section 9: Recovery Database Schema (SQLite)
- **File**: `reconai/db/models.py`
- **Table `cases`**:
  `case_id`, `image_path`, `image_sha256`, `disk_size_bytes`, `created_at`, `total_recovered`
- **Table `recovered_items`**:
  `id`, `case_id`, `item_id`, `filename`, `extension`, `source`, `offset`, `size_bytes`, `sha256`, `category`, `integrity_status`, `integrity_score`, `confidence_score`, `priority_score`, `is_fragmented`, `details_json`, `content_preview`, `created_at`
- **Table `fragments`**:
  `id`, `case_id`, `fragment_id`, `offset`, `size_bytes`, `frag_type`, `predicted_format`, `matched_to_item_id`, `confidence`

### Section 10: Backend REST API Endpoints
- **File**: `reconai/api.py`
- `POST /api/forensics/upload`: Ingests and seals uploaded disk image or user evidence files.
- `POST /api/forensics/analyze`: Computes SHA-256 evidence seals and intake provenance.
- `POST /api/forensics/recover`: Triggers full recovery pipeline and populates output directory.
- `GET /api/forensics/files`: Returns list of recovered files with category/status/source filters.
- `GET /api/forensics/files/:id`: Returns complete file metadata and score breakdown.
- `GET /api/forensics/files/:id/download`: Returns raw binary bytes, original filename, and MIME type for direct browser download.
- `GET /api/forensics/files/:id/preview`: Returns text snippet/metadata preview.
- `GET /api/forensics/report`: Generates and returns JSON manifest or PDF court deliverable.

### Section 11: Recovery Output Directory Structure
Organized per-case under `recovery/case-<ID>/`:
- `original/`: Read-only evidence copy
- `carved/`: Signature carved files
- `reconstructed/`: AI fragment spliced files
- `repaired/`: Derived partial repair files
- `reports/`: JSON and PDF DFIR reports
- `hashes/`: Evidence seal certificates
- `logs/`: Hash-chained audit logs

### Sections 12–14: User Interface (Streamlit Dashboard & Catchy Categories)
- **File**: `app.py`
- **Interactive Evidence Upload Center**: Drag & drop zone on main page allowing users to upload evidence files or raw disk images.
- **Catchy Category Hub Cards**: Visual filter cards for:
  - 🔑 **Credentials & Access Keys**
  - 💰 **Financial & Wire Transfers**
  - 🪪 **Identity & Personal Data**
  - 📄 **Documents & Reports**
  - 🚨 **Ransomware & Encrypted Blobs**
  - ⚙️ **System & Attack Logs**
  - 🖼️ **Photos & Media Evidence**
  - 💻 **Source Code & Scripts**
  - ⚡ **Executables & Binaries**
- **Dual Display Modes**:
  - `🎴 Visual Evidence Cards Grid`: Modern cyber cards with file titles, category badges, integrity badges, investigative clue callouts, direct download buttons, and inspect payload triggers.
  - `📊 Compact Forensic Table`: Tabular dataframe with column sorting.
- **Deep Artifact Inspector**: Decoded stream preview, rendered media previews (Pillow), raw 256-byte hex dump viewer, and full forensic metadata.
- **Interactive Relationship Graph**: Force-directed Pyvis network graph linking evidence disk root $\rightarrow$ recovery pipelines $\rightarrow$ files $\rightarrow$ fragments $\rightarrow$ crypto wallet addresses and suspect IPs.
- **Natural Language Search**: Semantic neural search with TF-IDF fallback re-ranking results by $\text{Relevance} \times \text{Integrity}$.

### Section 15: Error Handling
- Per-file `try...except` isolation wrappers across all pipeline stages (carving, reassembly, integrity parsing, repair).
- A single corrupted or malformed file will never crash the recovery process or application.

### Section 16: Download Requirements
- 1-click **Download** buttons (`st.download_button` / `api_download_file`) on every file card and detail view.
- Derived files clearly tagged `RECONSTRUCTED – derived artifact` or `REPAIRED COPY`. Original file extensions strictly preserved.

### Section 17: Forensic Reports
- **JSON Manifest**: Full machine-readable DFIR deliverable containing case metadata, summary statistics, IOC records, audit logs, and evidence item inventories.
- **PDF Report**: High-resolution court deliverable created via `reportlab` featuring embedded cryptographic seals, header/footer signatures, and integrity metrics.

### Sections 18–20: Safety, Integration & Verification
- **Read-Only Verification**: Post-analysis re-hash confirms 0-bit write contamination.
- **Unit & Integration Tests**: Executed via `./venv/bin/python -m unittest discover tests` (14/14 tests pass cleanly).

---

## 🚀 3. Quickstart & Verification Commands

```bash
# 1. Navigate to workspace directory
cd /Users/muhammedmustaqheem/Desktop/NOVA

# 2. Activate Python virtual environment
source venv/bin/activate

# 3. Launch Streamlit Web Application
streamlit run app.py

# 4. Run Test Suite (14 Unit & Integration Tests)
python3 -m unittest discover tests
```

---

## 🔒 4. Environmental & API Summary

| Property | Value |
|---|---|
| **Host OS** | macOS (Darwin arm64) |
| **Python Runtime** | Python 3.9+ |
| **Frontend Framework** | Streamlit (Custom Cyber Forensic Theme) |
| **Database** | SQLite3 (`data/reconai.db`) |
| **Primary Seal** | SHA-256 |
| **Web Server Port** | `http://localhost:8501` |
