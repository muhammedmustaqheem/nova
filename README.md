# 🛡️ ReconAI: Digital Forensic File Recovery & Reconstruction Platform

> **Specialized Digital Evidence Preservation, Recovery, Reconstruction, and Validation Engine**  
> Built for Cybersecurity & Digital Forensics Hackathons using a 100% free and open-source stack.

ReconAI solves a critical problem in digital investigations: recovering deleted, damaged, fragmented, and partially overwritten files from raw forensic disk images (`.raw`, `.dd`, `.img`) and user evidence packages while maintaining strict read-only chain of custody.

---

## ⚡ The 5-Stage Core Forensic Workflow

The application UI is structured around one clear, powerful forensic workflow:

```
📥 1. EVIDENCE        🔒 Case Creation, SHA-256 Intake Seal & Chain of Custody
        ↓
🔍 2. ANALYZE         📂 Filesystem Undelete, Magic Sector Carving & Shannon Entropy
        ↓
⚙️ 3. RECOVER         🧩 AI Fragment Reassembly, Safe Format Repair & Integrity Validation
        ↓
📁 4. ARTIFACTS        🎯 Catchy Threat Category Hub, Bounded Hex Inspector & Downloads
        ↓
📄 5. REPORTS          📜 Court-Ready DFIR Examination Report (JSON & PDF Exports)
```

---

## 🛠️ Key Capabilities & Problem Solved

1. **Forensic Preservation & Chain of Custody**:
   - Opens evidence bit-streams strictly in read-only mode (`O_RDONLY`).
   - Calculates pre-analysis and post-analysis cryptographic seals (**SHA-256**, **SHA-1**, **MD5**, **CRC-32**) to verify bit-for-bit zero alteration (`VERIFIED ✓`).
   - Appends audit trail logs tracking all intake, carving, and reassembly operations.

2. **Filesystem Recovery + Raw Signature Carving**:
   - Traverses deleted filesystem inodes (FAT16, FAT32, exFAT, NTFS) for `0xE5` deletion markers.
   - Carves raw unallocated sectors using magic numbers (`JPEG`, `PNG`, `PDF`, `ZIP`, `SQLite`, `TXT/LOG/ENV`).

3. **Fragment Detection & Reconstruction**:
   - Detects non-contiguous orphan cluster gaps using boundary byte entropy transition gradients.
   - Reconstructs split fragments into complete files with transparent 0–100% confidence scores and evidence rationale.

4. **Programmatic Corruption Detection & Safe Repair**:
   - Programmatically tests recovered files using real decoders (`Pillow` for images, `pypdf` for documents, `zipfile` for archives).
   - Classifies artifacts into 4 strict buckets: `VALID`, `PARTIALLY VALID`, `CORRUPTED`, `UNRECOVERABLE`.
   - Safely repairs truncated headers/trailers into derived files tagged `DERIVED ARTIFACT — REPAIRED/RECONSTRUCTED`. Original evidence is never modified!

5. **Catchy Category Explorer & Direct Artifact Downloads**:
   - Organizes evidence into catchy categories:
     - 🔑 **Credentials & Access Keys**
     - 💰 **Financial & Wire Transfers**
     - 🪪 **Identity & Personal Data**
     - 📄 **Documents & Reports**
     - 🚨 **Ransomware & Encrypted Blobs**
     - ⚙️ **System & Attack Logs**
     - 🖼️ **Photos & Media Evidence**
   - Provides a bounded 256-byte Hex Dump Inspector, payload previews, and direct 1-click **Download Artifact** buttons.

---

## 🚀 Quickstart Guide

### 1. Environment Setup
```bash
# Navigate to repository directory
cd /Users/muhammedmustaqheem/Desktop/NOVA

# Activate Python virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Launch Streamlit Forensic Web Platform
```bash
streamlit run app.py
```
Open [http://localhost:8501](http://localhost:8501) in your browser.

---

## 🧪 Automated Testing

Run the automated test suite verifying all forensic recovery capabilities:
```bash
python3 -m unittest discover tests
```

Expected output:
```text
Ran 14 tests in 8.66s
OK
```

---

## 🛡️ Hackathon Demonstration Workflow

1. **Step 1 — Upload Evidence (`📥 1. Evidence`):**
   - Drag & drop seized evidence files or raw disk images into the **Digital Evidence Upload Center**.
   - Review the instant SHA-256 seal and read-only custody status (`VERIFIED ✓`).
2. **Step 2 — Analyze (`🔍 2. Analyze`):**
   - Click **`🚀 Run Recovery Pipeline`**.
   - Observe real-time progress across filesystem undelete, raw sector carving, and Shannon sector entropy mapping.
3. **Step 3 — Review Recovery & Repair (`⚙️ 3. Recover`):**
   - Inspect reconstructed fragment chains, derived repaired artifacts, and itemized 0–100% confidence score explanations.
4. **Step 4 — Browse & Download Artifacts (`📁 4. Artifacts`):**
   - Click Catchy Category Hub Cards (`🔑 Credentials`, `💰 Financial`) or switch between **Visual Evidence Cards Grid** and **Detailed Forensic Table**.
   - Inspect raw 256-byte hex dumps and click **`⬇️ Download Artifact`**.
5. **Step 5 — Export Court Deliverable (`📄 5. Reports`):**
   - Review the official examination report and export signed **JSON Manifests** or **PDF Court Deliverables**.

---

## 🔒 Forensic Integrity Disclaimer

ReconAI strictly distinguishes between:
- **`ORIGINAL EVIDENCE`**: Unmodified raw bitstream copy.
- **`DERIVED / RECOVERED ARTIFACT`**: Rescued payload or carved artifact.
- **`RECONSTRUCTED / REPAIRED COPY`**: Derived file created via heuristic fragment matching or format repair.

Original evidence files are opened strictly in read-only mode and are never overwritten or altered.
