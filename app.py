"""
ReconAI - AI-Assisted Digital Evidence Reconstruction & Recovery
Streamlit forensic workbench: acquire & seal -> recover -> reconstruct -> assess -> report.
"""

import os
import io
import json
import hashlib
import platform
from datetime import datetime

import altair as alt
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from PIL import Image

from reconai.pipeline import run_recovery_pipeline
from reconai.search.semantic_search import search_recovered_items
from reconai.graph.graph_builder import build_forensic_graph, generate_interactive_pyvis_html
from reconai.ingest.hasher import compute_evidence_hash
from reconai.copilot.copilot_engine import query_investigator_copilot
from reconai.reassemble.whatif_simulator import simulate_whatif_chain

TOOL_VERSION = "ReconAI v1.4.0 (Intelligence Layer)"

st.set_page_config(
    page_title="ReconAI | Digital Evidence Reconstruction",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Forensic workbench styling (base colours come from .streamlit/config.toml dark theme)
st.markdown("""
<style>
    .mono { font-family: 'SF Mono', Menlo, Consolas, monospace; }

    .metric-card {
        background: linear-gradient(135deg, #131B2E 0%, #1A243B 100%);
        border: 1px solid #1E293B;
        border-radius: 10px;
        padding: 14px 18px;
        position: relative;
        height: 100%;
    }
    .metric-val { font-size: 28px; font-weight: 800; font-family: 'SF Mono', Monaco, monospace; }
    .metric-lbl { font-size: 12px; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.05em; }
    .metric-sub { font-size: 12px; color: #94A3B8; margin-top: 4px; line-height: 1.4; }

    .badge {
        display: inline-block; padding: 3px 9px; border-radius: 6px;
        font-size: 11px; font-weight: 700; letter-spacing: 0.04em;
        text-transform: uppercase; font-family: 'SF Mono', monospace;
    }
    .badge-intact { background-color: rgba(16,185,129,.2); color: #10B981; border: 1px solid #10B981; }
    .badge-partial { background-color: rgba(245,158,11,.2); color: #F59E0B; border: 1px solid #F59E0B; }
    .badge-corrupt { background-color: rgba(239,68,68,.2); color: #EF4444; border: 1px solid #EF4444; }
    .badge-reassembled { background-color: rgba(0,242,254,.2); color: #00F2FE; border: 1px solid #00F2FE; }
    .badge-fs { background-color: rgba(59,130,246,.2); color: #3B82F6; border: 1px solid #3B82F6; }
    .badge-carve { background-color: rgba(168,85,247,.2); color: #A855F7; border: 1px solid #A855F7; }
    .badge-derived { background-color: rgba(236,72,153,.2); color: #EC4899; border: 1px solid #EC4899; }

    .recon-tooltip { position: relative; display: inline-block; cursor: help; }
    .recon-tooltip .recon-tooltiptext {
        visibility: hidden; width: 260px; background-color: #0F172A; color: #F8FAFC;
        text-align: left; border-radius: 8px; padding: 10px 14px; position: absolute;
        z-index: 1000; bottom: 125%; left: 50%; margin-left: -130px; opacity: 0;
        transition: opacity 0.2s; border: 1px solid #00F2FE; font-size: 11px;
        line-height: 1.45; text-transform: none; letter-spacing: normal; font-weight: normal;
        box-shadow: 0 10px 20px -3px rgba(0,0,0,.6);
    }
    .recon-tooltip:hover .recon-tooltiptext { visibility: visible; opacity: 1; }

    .help-card {
        background-color: #131D33; border-left: 4px solid #00F2FE; border-radius: 8px;
        padding: 12px 16px; margin-bottom: 16px; font-size: 13px; color: #CBD5E1;
    }
    .alert-card {
        border-radius: 8px; padding: 12px 16px; margin-bottom: 10px;
        font-size: 13px; line-height: 1.5; color: #E2E8F0;
    }
    .step-num { font-size: 12px; color: #00F2FE; font-weight: 700; letter-spacing: .08em; }
</style>
""", unsafe_allow_html=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "data", "uploads")
CASE_FILES_DIR = os.path.join(UPLOAD_DIR, "case_files")
DEMO_RAW_PATH = os.path.join(BASE_DIR, "data", "demo_evidence.raw")
DEMO_GT_PATH = os.path.join(BASE_DIR, "data", "ground_truth.json")

BUCKETS = [
    ("FULLY RECOVERABLE", "fully_recoverable", "#10B981", "Opens cleanly; original content restorable."),
    ("PARTIALLY RECOVERABLE", "partially_recoverable", "#F59E0B", "Opens with gaps; salvageable content."),
    ("FRAGMENT ONLY", "fragment_only", "#F97316", "Only pieces survive; content is not openable."),
    ("UNRECOVERABLE", "unrecoverable", "#EF4444", "Structure destroyed; no usable content."),
]
BUCKET_COLORS = {b[0]: b[2] for b in BUCKETS}
SEVERITY_COLORS = {"CRITICAL": "#EF4444", "HIGH": "#F97316", "MEDIUM": "#F59E0B", "LOW": "#3B82F6", "INFO": "#64748B"}
SOURCE_LABELS = {
    "filesystem_undelete": "Filesystem undelete",
    "signature_carving": "Signature carving",
    "fragment_reassembly": "AI reassembly",
}

for key, default in [("recovery_results", None), ("current_image_path", None)]:
    if key not in st.session_state:
        st.session_state[key] = default


@st.cache_data(show_spinner="Computing acquisition hashes...")
def hash_evidence(path: str, mtime: float, size: int) -> dict:
    """Hashes are cached per (path, mtime, size) so reruns don't re-read a 64MB image."""
    return compute_evidence_hash(path)


def evidence_fingerprint(path: str):
    if os.path.isdir(path):
        entries = [os.path.join(path, f) for f in os.listdir(path)]
        return max((os.path.getmtime(e) for e in entries), default=0.0), sum(os.path.getsize(e) for e in entries)
    return os.path.getmtime(path), os.path.getsize(path)


def save_upload(uploaded, dest_dir: str) -> str:
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, os.path.basename(uploaded.name))
    with open(dest, "wb") as f:
        f.write(uploaded.getbuffer())
    return dest


def get_status_badge(status: str) -> str:
    s = (status or "").upper()
    cls = {"INTACT": "badge-intact", "PARTIAL": "badge-partial", "CORRUPTED": "badge-corrupt"}.get(s, "")
    tips = {
        "INTACT": "💡 NON-TECHNICAL: Opens perfectly! 🔬 TECHNICAL: Magic bytes & decoder structure verified.",
        "PARTIAL": "💡 NON-TECHNICAL: Opens partially; some content survived. 🔬 TECHNICAL: Valid header but truncated payload.",
        "CORRUPTED": "💡 NON-TECHNICAL: Damaged file; repair copy generated. 🔬 TECHNICAL: Invalid checksum or broken headers."
    }
    tip = tips.get(s, "Status verdict")
    return f'<span class="badge {cls}" title="{tip}">{s}</span>'


def get_bucket_badge(bucket: str) -> str:
    color = BUCKET_COLORS.get(bucket, "#64748B")
    tips = {
        "FULLY RECOVERABLE": "💡 NON-TECHNICAL: 100% usable file! 🔬 TECHNICAL: Full byte integrity & decoder verification.",
        "PARTIALLY RECOVERABLE": "💡 NON-TECHNICAL: Salvageable info present. 🔬 TECHNICAL: >50% structure intact.",
        "FRAGMENT ONLY": "💡 NON-TECHNICAL: Raw data piece. 🔬 TECHNICAL: Isolated orphan fragment without complete header.",
        "UNRECOVERABLE": "💡 NON-TECHNICAL: Unreadable data. 🔬 TECHNICAL: Overwritten or zero-filled cluster allocation."
    }
    tip = tips.get(bucket, "Recoverability classification")
    return (f'<span class="badge" title="{tip}" style="color:{color}; border:1px solid {color}; '
            f'background-color:{color}22;">{bucket}</span>')


def get_source_badge(source: str) -> str:
    cls = {"filesystem_undelete": "badge-fs", "signature_carving": "badge-carve",
           "fragment_reassembly": "badge-reassembled"}.get(source, "")
    tips = {
        "filesystem_undelete": "💡 NON-TECHNICAL: Restored from drive's file catalog. 🔬 TECHNICAL: FAT 0xE5 metadata undelete.",
        "signature_carving": "💡 NON-TECHNICAL: Found by scanning raw disk sectors. 🔬 TECHNICAL: Signature carved from unallocated clusters.",
        "fragment_reassembly": "💡 NON-TECHNICAL: Reconstructed by stitching matching pieces. 🔬 TECHNICAL: Cosine similarity & boundary continuity chain."
    }
    tip = tips.get(source, "Recovery method")
    return f'<span class="badge {cls}" title="{tip}">{SOURCE_LABELS.get(source, source)}</span>'


def get_priority_badge(prio: str) -> str:
    p = (prio or "P3 — LOW PRIORITY").upper()
    if "P1" in p:
        color = "#EF4444"
        tip = "💡 HIGH TECHNICAL RECOVERY PRIORITY: Complete or near-complete recoverable stream with strong confidence."
    elif "P2" in p:
        color = "#F59E0B"
        tip = "💡 MEDIUM TECHNICAL RECOVERY PRIORITY: Partial recoverable stream or medium confidence."
    else:
        color = "#3B82F6"
        tip = "💡 LOW TECHNICAL RECOVERY PRIORITY: Fragment only or severe corruption."
    return f'<span class="badge" title="{tip}" style="color:{color}; border:1px solid {color}; background-color:{color}22;">{p}</span>'


def get_state_badge(state: str) -> str:
    s = (state or "CARVED").upper()
    colors = {
        "INTACT": "#10B981", "DELETED": "#F59E0B", "CARVED": "#A855F7",
        "RECONSTRUCTED": "#00F2FE", "PARTIALLY_RECOVERED": "#F97316",
        "REPAIRED": "#EC4899", "CORRUPTED": "#EF4444", "UNRECOVERABLE": "#64748B"
    }
    color = colors.get(s, "#64748B")
    return f'<span class="badge" title="Primary Recovery State: {s}" style="color:{color}; border:1px solid {color}; background-color:{color}22;">{s}</span>'



def short_hash(h: str, n: int = 12) -> str:

    return f"{h[:n]}…" if h else ""


# --- SIDEBAR: CASE INTAKE, ACQUISITION SEAL & PIPELINE ---
with st.sidebar:
    st.markdown("## 🛡️ ReconAI")
    st.caption("AI-assisted digital evidence recovery & reconstruction")

    st.markdown("#### 1 · Case details")
    case_id_input = st.text_input("Case reference", placeholder="Auto: CASE-<hash prefix>",
                                  help="Your agency / incident reference. Left blank, one is derived from the evidence SHA-256.")
    examiner_input = st.text_input("Examiner name *", placeholder="e.g. J. Doe, DFIR Unit",
                                   help="Recorded in the hash-chained audit log and every exported report.")

    st.markdown("#### 2 · Evidence source")
    ingest_mode = st.radio(
        "Evidence source",
        ["Disk image (.raw / .dd / .img)", "Loose evidence files", "Synthetic test disk"],
        label_visibility="collapsed",
    )

    target_path = None
    if ingest_mode.startswith("Disk image"):
        up = st.file_uploader("Disk image", type=["raw", "dd", "img"], label_visibility="collapsed")
        if up is not None:
            target_path = save_upload(up, UPLOAD_DIR)
    elif ingest_mode.startswith("Loose"):
        ups = st.file_uploader("Evidence files", accept_multiple_files=True, label_visibility="collapsed",
                               help="Documents, images, logs, archives, databases — each is hashed, validated and classified.")
        if ups:
            os.makedirs(CASE_FILES_DIR, exist_ok=True)
            for old in os.listdir(CASE_FILES_DIR):
                old_fp = os.path.join(CASE_FILES_DIR, old)
                if os.path.isfile(old_fp):
                    os.remove(old_fp)
            for uf in ups:
                save_upload(uf, CASE_FILES_DIR)
            target_path = CASE_FILES_DIR
    else:
        st.caption("64 MB FAT image with deleted, fragmented, wiped and corrupted files plus a ground-truth manifest for scoring.")
        if st.button("Generate fresh test disk", use_container_width=True):
            from scripts.make_test_image import generate_evidence_disk
            generate_evidence_disk(DEMO_RAW_PATH, DEMO_GT_PATH)
            hash_evidence.clear()
        if os.path.exists(DEMO_RAW_PATH):
            target_path = DEMO_RAW_PATH

    if target_path and os.path.exists(target_path):
        evidence_info = hash_evidence(target_path, *evidence_fingerprint(target_path))
        if st.session_state.get("last_intake_target") != (target_path, evidence_info["sha256"]):
            st.session_state.intake_timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            st.session_state.last_intake_target = (target_path, evidence_info["sha256"])

        st.markdown("#### 3 · Acquisition seal")
        st.markdown(
            f"**{evidence_info['filename']}**  \n"
            f"{evidence_info['size_mb']} MB ({evidence_info['size_bytes']:,} bytes) · intake `{st.session_state.intake_timestamp}`"
        )
        st.caption("SHA-256 (primary seal)")
        st.code(evidence_info["sha256"], language="text")

        with st.expander("Secondary hashes & cross-verification"):
            st.caption("SHA-1 / MD5 — for matching legacy FTK, EnCase and Autopsy manifests")
            st.code(f"SHA-1  {evidence_info['sha1']}\nMD5    {evidence_info['md5']}\nCRC-32 {evidence_info['crc32']}", language="text")
            acq_input = st.text_input("Hash recorded at acquisition", placeholder="Paste SHA-256, SHA-1 or MD5")
            if acq_input:
                cand = acq_input.strip().lower()
                matched = next((name for name, key in [("SHA-256", "sha256"), ("SHA-1", "sha1"), ("MD5", "md5")]
                                if cand == evidence_info[key].lower()), None)
                if matched:
                    st.success(f"Match on {matched}: this is the same bit-stream that was acquired.")
                else:
                    st.error("No match: this copy differs from the acquired evidence. Do not proceed without re-acquisition.")

        examiner = examiner_input.strip()
        run_btn = st.button("🚀 Run recovery pipeline", type="primary", use_container_width=True,
                            disabled=not examiner,
                            help="Undelete, carve, reassemble fragments, validate integrity, repair, classify, detect tampering, build timeline.")
        if not examiner:
            st.caption("Enter the examiner name to start — required for chain of custody.")
        if run_btn:
            progress_bar = st.progress(0, text="Initializing recovery pipeline...")
            results = run_recovery_pipeline(
                target_path,
                case_id=case_id_input.strip() or None,
                examiner_name=examiner,
                progress_callback=lambda msg, p: progress_bar.progress(p, text=msg),
            )
            st.session_state.recovery_results = results
            st.session_state.current_image_path = target_path
            progress_bar.empty()
            st.rerun()

        res = st.session_state.recovery_results
        if res and res["case"]["image_sha256"] == evidence_info["sha256"]:
            if res.get("read_only_verified"):
                st.success("Post-analysis re-hash matches the acquisition seal — evidence unmodified.")
            else:
                st.error("Post-analysis re-hash does NOT match the acquisition seal.")

        custody_manifest = {
            "record_type": "Digital Evidence Chain-of-Custody & Verification Certificate",
            "case_id": (res or {}).get("case", {}).get("case_id") or case_id_input.strip() or f"CASE-{evidence_info['sha256'][:8].upper()}",
            "evidence_id": f"EV-{evidence_info['sha256'][:6].upper()}",
            "examiner": examiner or "UNSPECIFIED",
            "evidence_source": {
                "filename": evidence_info["filename"],
                "size_bytes": evidence_info["size_bytes"],
            },
            "timestamps": {
                "intake_utc": st.session_state.intake_timestamp,
                "verification_utc": (res or {}).get("case", {}).get("verification_timestamp", "Pending pipeline execution"),
            },
            "cryptographic_seals": {
                "primary_sha256": evidence_info["sha256"],
                "legacy_sha1": evidence_info["sha1"],
                "legacy_md5": evidence_info["md5"],
                "crc32": evidence_info["crc32"],
            },
            "post_analysis_verification": {
                "post_sha256": (res or {}).get("post_analysis_hash", {}).get("sha256", "Pending pipeline execution"),
                "read_only_verified": (res or {}).get("read_only_verified", False),
            },
            "provenance_environment": {
                "tool_version": TOOL_VERSION,
                "host_os": f"{platform.system()} {platform.release()} ({platform.machine()})",
                "python_version": platform.python_version(),
            },
        }
        custody_manifest["certificate_sha256_seal"] = hashlib.sha256(
            json.dumps(custody_manifest, sort_keys=True, indent=2).encode("utf-8")).hexdigest()
        st.download_button(
            "⬇️ Custody certificate (JSON)",
            data=json.dumps(custody_manifest, indent=2),
            file_name=f"custody_certificate_{custody_manifest['case_id']}.json",
            mime="application/json",
            use_container_width=True,
        )


# --- MAIN CONTENT AREA ---
if st.session_state.recovery_results is None:
    st.markdown("## 🛡️ ReconAI — Digital Evidence Reconstruction")
    st.markdown("Recover deleted, fragmented and damaged data, then find out **what can realistically be restored**, "
                "**how the pieces fit together**, and **whether someone tried to destroy it**.")
    st.info("👈 Start in the sidebar: enter case details, add a disk image or evidence files, then run the pipeline.")

    steps = [
        ("01 · ACQUIRE & SEAL", "Read-only intake. SHA-256 / SHA-1 / MD5 seal, genesis block of a hash-chained audit log."),
        ("02 · RECOVER", "FAT directory undelete (0xE5 entries) plus filesystem-independent signature carving of unallocated space."),
        ("03 · RECONSTRUCT", "Orphan fragments are scored pairwise (byte-histogram cosine similarity, boundary entropy continuity, format match) and chained into files."),
        ("04 · ASSESS & REPORT", "Decoder-verified integrity, four recoverability buckets, repair, anti-forensics detection, timeline and a sealed report."),
    ]
    cols = st.columns(4)
    for col, (title, body) in zip(cols, steps):
        col.markdown(f'<div class="metric-card"><div class="step-num">{title}</div>'
                     f'<div class="metric-sub" style="font-size:13px;">{body}</div></div>', unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### 📋 Synthetic test disk scenario")
    st.markdown("""
The generated 64 MB image simulates a drive seized from a financial-fraud suspect, with a ground-truth manifest so results can be scored:
- **Deleted PDF audit report** — offshore crypto transfers and wire logs
- **Deleted `.env` credentials** — cloud access keys and database passwords
- **Fragmented JPEG** — passport scan split across non-contiguous clusters
- **Carved PNG** — recovered from unallocated space with no filesystem metadata
- **Corrupted ZIP** — damaged central directory
- **Auth log** — SSH brute force and privilege escalation
- **Anti-forensics traces** — ransom note, wiped sectors, a spoofed file extension
""")

else:
    results = st.session_state.recovery_results
    stats = results["stats"]
    case_meta = results["case"]
    items = results["recovered_items"]
    fragments = results["fragments"]
    iocs = results.get("iocs", {"total_iocs_found": 0, "records": []})
    benchmark = results.get("benchmark", {})
    rec_summary = results.get("recoverability_summary", {})
    tampering = results.get("tampering", {"indicators": [], "total_indicators": 0})
    timeline = results.get("timeline", {"timeline_events": []})
    repaired = results.get("repaired_artifacts", [])
    clustering = results.get("clustering", {"clustered_items": [], "summary": {}})
    narratives = results.get("narratives", {})
    audit = results.get("audit_log", {})
    reports = results.get("reports", {})
    repaired_by_parent = {r["parent_item_id"]: r for r in repaired}

    head_c1, head_c2 = st.columns([4, 1])
    with head_c1:
        st.markdown(f"## 🛡️ Case `{case_meta['case_id']}`")
        custody_ok = results.get("read_only_verified")
        st.caption(
            f"Evidence `{case_meta['filename']}` · Examiner **{case_meta.get('examiner_name', 'N/A')}** · "
            f"SHA-256 `{short_hash(case_meta['image_sha256'], 16)}` · "
            + ("✅ custody verified (post-analysis hash match)" if custody_ok else "❌ custody hash mismatch")
        )
    with head_c2:
        if st.button("📁 Close case", use_container_width=True, help="Return to intake. Exports first — the session is not saved."):
            st.session_state.recovery_results = None
            st.rerun()

    with st.expander("💡 User Guide: How to Fetch Corrupted, Fragmented & Deleted Files (Click to expand)", expanded=False):
        st.markdown("""
        #### 📖 Step-by-Step Workflow for Technical & Non-Technical Users
        
        | Target File Type | What Happened on Disk | How to Find & Fetch it in ReconAI | Hover Tip |
        |---|---|---|---|
        | **🗑️ Deleted Files** | File was deleted, but index entry (`0xE5`) survived in filesystem tables. | Open **🗂️ Evidence** tab → Filter **Source: Filesystem undelete** → Click **⬇️ Original recovered bytes**. | 💡 *Original metadata intact!* |
        | **🔍 Carved Files** | Metadata was wiped; file found by scanning byte signatures (`FF D8 FF`, `%PDF`, `PK`). | Open **🗂️ Evidence** tab → Filter **Source: Signature carving** → Click **⬇️ Original recovered bytes**. | 💡 *Raw sector extraction.* |
        | **🛠️ Corrupted Files** | Damaged zip central directory, broken header, or missing terminator. | Open **🧩 Reconstruction** tab → Find **🛠️ Repaired (derived) artifacts** → Click **⬇️ Download**. | 💡 *Original untouched; safe copy generated!* |
        | **🧩 Fragmented Files** | File split across non-contiguous clusters; ReconAI stitched fragments together. | Open **🧩 Reconstruction** tab → Review **Fragment Map** → Download reassembled artifact in **🗂️ Evidence**. | 💡 *Entropy & boundary matched.* |
        """)

    tabs = st.tabs([
        "📊 Overview",
        "🗂️ Evidence & DNA",
        "🧩 Reconstruction & What-If",
        f"🚨 Threats & Story Timeline ({tampering.get('total_indicators', 0)})",
        "🕸️ Evidence Graph",
        "🤖 Investigator Copilot",
        "📄 Report & Custody",
    ])

    # ----------------------------------------------------
    # TAB: OVERVIEW — what can realistically be restored?
    # ----------------------------------------------------
    with tabs[0]:
        st.markdown("### What can realistically be restored?")
        rest_pct = rec_summary.get("realistic_restoration_pct", 0)
        bcols = st.columns([1.3, 1, 1, 1, 1])
        with bcols[0]:
            st.markdown(f"""
            <div class="metric-card" style="border-left: 4px solid #00F2FE;">
                <div class="metric-lbl">Realistic restoration</div>
                <div class="metric-val" style="color:#00F2FE;">{rest_pct}%</div>
                <div class="metric-sub">{stats['total_recovered']} artifacts recovered · fully + partially recoverable share</div>
            </div>""", unsafe_allow_html=True)
        for col, (label, key, color, desc) in zip(bcols[1:], BUCKETS):
            with col:
                st.markdown(f"""
                <div class="metric-card" style="border-left: 4px solid {color};">
                    <div class="metric-lbl">{label.title()}</div>
                    <div class="metric-val" style="color:{color};">{rec_summary.get(key, 0)}</div>
                    <div class="metric-sub">{desc}</div>
                </div>""", unsafe_allow_html=True)
        if rec_summary.get("restoration_verdict"):
            st.caption(rec_summary["restoration_verdict"])

        if tampering.get("tampering_detected"):
            crit = sum(1 for i in tampering["indicators"] if i.get("severity") == "CRITICAL")
            st.error(f"**Anti-forensics / tampering detected — {tampering['total_indicators']} indicator(s), {crit} critical.** "
                     f"See the Threats & Timeline tab.")

        st.markdown("<br>", unsafe_allow_html=True)
        src_cols = st.columns(4)
        src_cols[0].metric("Filesystem undelete", stats["filesystem_recovered"])
        src_cols[1].metric("Carved from unallocated", stats["signature_carved"])
        src_cols[2].metric("AI-reassembled files", stats["reassembled"], help=f"From {stats['orphan_fragments']} orphan fragments")
        src_cols[3].metric("Derived repairs", stats.get("derived_repairs", 0), help="Reconstructed copies — originals are never altered")

        prio_cols = st.columns(3)
        prio_cols[0].metric("P1 — High Priority", stats.get("p1_high_priority", 0), help="High technical recoverability & high confidence")
        prio_cols[1].metric("P2 — Medium Priority", stats.get("p2_medium_priority", 0), help="Partial recoverability or medium confidence")
        prio_cols[2].metric("P3 — Low Priority", stats.get("p3_low_priority", 0), help="Fragment only or severe corruption")

        with st.expander("🧠 Intelligence Engine & AI Reconstruction Architecture (Click for Details)", expanded=False):
            st.markdown("""
            #### 🔬 AI-Assisted Heuristic Reconstruction Pipeline
            ReconAI combines deterministic forensic carving with an **intelligent graph-based reassembly engine**:
            
            ```
            RAW DISK IMAGE
                  ↓
            1. FEATURE EXTRACTION  ──→ [Entropy, 256-Bin Byte Histogram, Boundary ΔH, Sector Proximity, Magic Signature]
                  ↓
            2. PAIRWISE GRAPH      ──→ [Pairwise Relationship Score: Hist Sim (40%) + Boundary (35%) + Format (25%)]
                  ↓
            3. PATH REASSEMBLY     ──→ [Greedy Best-Path Chaining from Header to Trailer Candidates]
                  ↓
            4. DECODER VALIDATION  ──→ [Pillow / PyPDF / ZipFile Structural Parser Checks]
                  ↓
            5. PRIORITY & VERDICT  ──→ [Technical Recovery Priority (P1/P2/P3) + 4 Recoverability Buckets]
            ```
            
            * **Pairwise Feature Vectors**: Calculates Shannon entropy transition ($\Delta H$), byte distribution cosine similarity, and cluster offset proximity.
            * **Explainable Reasoning**: Every reassembly decision produces a transparent feature score and evidence breakdown.
            * **Safety Guarantee**: Original evidence is accessed `O_RDONLY`. Derived repairs are saved separately with unique SHA-256 seals.
            """)


        st.markdown("---")
        nar_c1, nar_c2 = st.columns([3, 2])
        with nar_c1:
            mode = st.segmented_control("Case narrative", ["Plain English", "Examiner detail"], default="Plain English")
            st.markdown(narratives.get("expert_mode" if mode == "Examiner detail" else "simple_mode", "_No narrative generated._"))
        with nar_c2:
            st.markdown("##### 🚨 Highest-priority evidence")
            st.caption("Priority = content sensitivity × integrity score")
            for itm in items[:4]:
                st.markdown(f"""
                <div class="metric-card" style="margin-bottom:8px; border-left: 3px solid {BUCKET_COLORS.get(itm.get('recoverability_bucket'), '#64748B')};">
                    <div style="display:flex; justify-content:space-between; gap:8px;">
                        <strong style="font-size:13px;">{itm.get('friendly_title', itm['filename'])}</strong>
                        <span class="mono" style="color:#00F2FE; font-size:13px;">{itm['priority_score']}</span>
                    </div>
                    <div class="metric-sub"><span class="mono">{itm['filename']}</span> · {itm['category']}</div>
                </div>""", unsafe_allow_html=True)

        if benchmark.get("status") == "SUCCESS":
            st.markdown("---")
            st.markdown("##### 🎯 Accuracy against ground truth")
            st.caption("Only available for the synthetic test disk, which ships with a manifest of what was planted on it.")
            bm = st.columns(4)
            bm[0].metric("Recall", f"{benchmark.get('recall_score', 0)}%", help="Planted files that were recovered")
            bm[1].metric("Precision", f"{benchmark.get('precision_score', 0)}%", help="Recovered artifacts that match a planted file")
            bm[2].metric("Reassembly accuracy", f"{benchmark.get('reassembly_accuracy', 0)}%", help="Fragmented files rebuilt byte-for-byte")
            bm[3].metric("Integrity accuracy", f"{benchmark.get('integrity_classification_accuracy', 0)}%", help="Intact/damaged verdicts matching the manifest")
            if benchmark.get("missed"):
                st.warning(f"Missed: {', '.join(m.get('gt_filename', '?') for m in benchmark['missed'])}")

    # ----------------------------------------------------
    # TAB: EVIDENCE CATALOG + INSPECTOR
    # ----------------------------------------------------
    with tabs[1]:
        f1, f2, f3, f4 = st.columns([1.3, 1.2, 1.2, 1.6])
        with f1:
            tier = st.segmented_control("Tier", ["All", "User evidence", "System / OS"], default="All")
        with f2:
            sel_bucket = st.selectbox("Recoverability", ["ALL"] + [b[0] for b in BUCKETS])
        with f3:
            sel_cat = st.selectbox("Category", ["ALL"] + sorted({i.get("category", "") for i in items}))
        with f4:
            search_query = st.text_input("Filter", placeholder="Title, filename, SHA-256…")

        filtered = items
        if tier == "User evidence":
            filtered = [i for i in filtered if i.get("is_user_file")]
        elif tier == "System / OS":
            filtered = [i for i in filtered if not i.get("is_user_file")]
        if sel_bucket != "ALL":
            filtered = [i for i in filtered if i.get("recoverability_bucket") == sel_bucket]
        if sel_cat != "ALL":
            filtered = [i for i in filtered if i.get("category") == sel_cat]
        if search_query.strip():
            sq = search_query.strip().lower()
            filtered = [i for i in filtered if any(sq in str(i.get(k, "")).lower()
                                                   for k in ("friendly_title", "filename", "use_case", "sha256"))]

        st.caption(f"{len(filtered)} of {len(items)} artifacts · select a row to inspect it")
        df = pd.DataFrame([{
            "Tech Priority": i.get("technical_priority", "P3 — LOW PRIORITY"),
            "Title": i.get("friendly_title", i["filename"]),
            "Filename": i["filename"],
            "File Type": i.get("file_type_class", "UNKNOWN"),
            "Recovery State": i.get("recovery_state", "CARVED"),
            "Completeness": i.get("completeness_pct", "100%"),
            "Category": i["category"],
            "Integrity %": i["integrity_score"],
            "Confidence %": i.get("confidence_score", 100.0),
            "Source": SOURCE_LABELS.get(i["source"], i["source"]),
            "Offset": f"0x{i.get('offset', 0):08X}",
            "Size (B)": i.get("size_bytes", 0),
            "Repaired copy": "✔" if i["item_id"] in repaired_by_parent else "",
            "SHA-256": i.get("sha256", ""),
        } for i in filtered])

        inspected = None
        if filtered:
            selection = st.dataframe(
                df, use_container_width=True, hide_index=True, on_select="rerun", selection_mode="single-row",
                column_config={
                    "Integrity %": st.column_config.ProgressColumn("Integrity %", min_value=0, max_value=100, format="%.0f"),
                    "Confidence %": st.column_config.NumberColumn(format="%.1f"),
                    "SHA-256": st.column_config.TextColumn(width="small"),
                },
            )
            rows = selection.selection.rows if selection else []
            inspected = filtered[rows[0]] if rows else filtered[0]
        else:
            st.info("No artifacts match these filters.")

        if inspected:
            st.markdown("---")
            data = inspected.get("data", b"")
            st.markdown(f"""
            <div class="metric-card" style="border-left: 5px solid {BUCKET_COLORS.get(inspected.get('recoverability_bucket'), '#00F2FE')}; margin-bottom: 14px;">
                <div style="display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px; margin-bottom:6px;">
                    <span style="font-size:16px; font-weight:700;">🔬 {inspected.get('friendly_title', inspected['filename'])}</span>
                    <span>{get_priority_badge(inspected.get('technical_priority'))} {get_state_badge(inspected.get('recovery_state'))} {get_bucket_badge(inspected.get('recoverability_bucket'))} {get_status_badge(inspected['integrity_status'])} {get_source_badge(inspected['source'])}</span>
                </div>
                <div class="metric-sub"><span class="mono">{inspected['filename']}</span> · {inspected.get('use_case', '')}</div>
            </div>""", unsafe_allow_html=True)

            ins_c1, ins_c2 = st.columns([3, 2])
            with ins_c1:
                ext = inspected.get("extension", "").lower()
                if ext in (".jpg", ".jpeg", ".png") and data:
                    try:
                        img = Image.open(io.BytesIO(data))
                        st.image(img, caption=f"Rendered from recovered bytes ({img.size[0]}×{img.size[1]} px)", width=320)
                    except Exception as e:
                        st.warning(f"Image does not decode: {e}")
                st.markdown("**Decoded content**")
                st.code(inspected.get("content_preview") or "No printable text stream detected.", language="text")
                with st.expander("Hex view (first 512 bytes)"):
                    hex_lines = []
                    for i in range(0, min(512, len(data)), 16):
                        chunk = data[i:i + 16]
                        hex_str = " ".join(f"{b:02X}" for b in chunk)
                        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                        hex_lines.append(f"{inspected.get('offset', 0) + i:08X}  {hex_str:<48}  |{ascii_str}|")
                    st.code("\n".join(hex_lines) or "(empty)", language="text")
                expl = inspected.get("explanations", {})
                if expl:
                    with st.expander("Why this verdict? (plain English / examiner)"):
                        st.markdown(expl.get("simple", ""))
                        st.markdown("---")
                        st.markdown(expl.get("expert", ""))

            with ins_c2:
                imp_val = inspected.get("impact_score", 50)
                st.markdown(f"#### 📊 Evidence Impact Score: `{imp_val}/100`")
                imp_b = inspected.get("impact_breakdown", {})
                if imp_b:
                    for k, (pts, m_pts) in imp_b.items():
                        st.progress(min(pts / m_pts, 1.0), text=f"{k.replace('_', ' ').title()}: {pts}/{m_pts}")
                st.caption(inspected.get("impact_rationale", ""))

                with st.expander("🧬 Evidence DNA / Visual Fingerprint", expanded=True):
                    dna = inspected.get("evidence_dna", {})
                    st.markdown(f"""
| DNA Field | Fingerprint Value |
|---|---|
| Artifact ID | `{dna.get('artifact_id', inspected['item_id'])}` |
| File Type Class | `{dna.get('file_type_class', 'UNKNOWN')}` |
| Recovery State | `{dna.get('primary_recovery_state', 'CARVED')}` |
| Sector Range | `{dna.get('sector_range', 'Disk sector')}` |
| Hex Offset | `{dna.get('source_offset_hex', '0x00000000')}` |
| Tech Priority | `{dna.get('technical_priority', 'P3')}` |
| Completeness | `{dna.get('completeness', '100%')}` |
| Confidence | `{dna.get('recovery_confidence', '100%')}` |
""")
                    st.caption("Primary SHA-256 Seal")
                    st.code(inspected.get("sha256", ""), language="text")

                st.download_button("⬇️ Original recovered bytes", data=data, file_name=inspected["filename"],
                                   mime="application/octet-stream", use_container_width=True,
                                   key=f"dl_orig_{inspected['item_id']}")
                derived = repaired_by_parent.get(inspected["item_id"])
                if derived:
                    st.markdown(f'<span class="badge badge-derived">Derived artifact</span> '
                                f'<span class="metric-sub">{derived["repair_type"].replace("_", " ").title()}</span>',
                                unsafe_allow_html=True)
                    st.download_button("⬇️ Repaired copy (derived)", data=derived.get("data", b""),
                                       file_name=derived["derived_filename"], mime="application/octet-stream",
                                       use_container_width=True, key=f"dl_der_{inspected['item_id']}")

    # ----------------------------------------------------
    # TAB: FRAGMENT RECONSTRUCTION, REPAIR & DEDUPLICATION
    # ----------------------------------------------------
    with tabs[2]:
        reassembled = [i for i in items if i["source"] == "fragment_reassembly"]
        leftovers = results.get("leftover_orphans", [])
        dup_heads = [c for c in clustering.get("clustered_items", []) if c.get("duplicate_count", 1) > 1]

        m = st.columns(5)
        m[0].metric("Orphan fragments", stats["orphan_fragments"])
        m[1].metric("Chains reassembled", len(reassembled))
        m[2].metric("Unmatched fragments", len(leftovers))
        m[3].metric("Derived repairs", len(repaired))
        m[4].metric("Duplicate groups", len(dup_heads), help=clustering.get("summary", {}).get("cluster_message", ""))

        st.markdown("#### 🗺️ Fragment map")
        st.caption("Where each orphan fragment sits on disk and which reconstructed file it was chained into. "
                   "Hover for size and role.")
        frag_rows = []
        for r in reassembled:
            for f in r.get("fragments_linked", []):
                frag_rows.append({"file": r["filename"], "offset_kb": f["offset"] / 1024, "offset": f"0x{f['offset']:08X}",
                                  "role": f.get("type", "?"), "size": f.get("size", 0)})
        for f in leftovers:
            frag_rows.append({"file": "⟂ unmatched", "offset_kb": f["offset"] / 1024, "offset": f"0x{f['offset']:08X}",
                              "role": f.get("frag_type", "?"), "size": f.get("size_bytes", 0)})
        if frag_rows:
            fdf = pd.DataFrame(frag_rows)
            chart = alt.Chart(fdf).mark_circle(size=180, opacity=0.9).encode(
                x=alt.X("offset_kb:Q", title="Disk offset (KB)", scale=alt.Scale(zero=False, padding=20)),
                y=alt.Y("file:N", title=None),
                color=alt.Color("role:N", title="Fragment role"),
                tooltip=["file", "offset", "role", "size"],
            )
            lines = alt.Chart(fdf[fdf["file"] != "⟂ unmatched"]).mark_line(strokeDash=[4, 3], opacity=0.5).encode(
                x=alt.X("offset_kb:Q", scale=alt.Scale(zero=False, padding=20)), y="file:N", detail="file:N")
            st.altair_chart((lines + chart).properties(height=max(120, 60 * fdf["file"].nunique())), use_container_width=True)
        else:
            st.info("No orphan fragments were found — every recovered file was contiguous.")

        if reassembled:
            st.markdown("#### 🧩 Reassembled files — how the fragments were joined")
            for r in reassembled:
                with st.expander(f"{r['filename']} · confidence {r.get('confidence_score', 0)}% · {r.get('recoverability_bucket', '')}", expanded=True):
                    rc1, rc2 = st.columns([3, 2])
                    with rc1:
                        st.dataframe(pd.DataFrame([{
                            "Order": n + 1, "Fragment": f["fragment_id"], "Role": f.get("type"),
                            "Offset": f"0x{f['offset']:08X}", "Size (B)": f.get("size"),
                        } for n, f in enumerate(r.get("fragments_linked", []))]), hide_index=True, use_container_width=True)
                        gaps = [b["offset"] - (a["offset"] + a.get("size", 0))
                                for a, b in zip(r.get("fragments_linked", []), r.get("fragments_linked", [])[1:])]
                        if gaps:
                            st.caption("Gap between fragments: " + ", ".join(f"{g:,} bytes" for g in gaps))
                    with rc2:
                        st.markdown("**🧠 Explainable AI Relationship Analysis**")
                        st.markdown(f"**Overall Confidence: `{r.get('confidence_score', 0)}%`**")
                        st.markdown("""
                        | Feature Vector | Contribution |
                        |---|---|
                        | Byte Histogram Cosine Sim | `+40%` |
                        | Boundary Entropy Continuity | `+35%` |
                        | Format & Signature Match | `+25%` |
                        """)
                        for reason in r.get("join_reasons", []):
                            st.markdown(f"• {reason}")
                        st.caption(f"Post-join validation: {r.get('details', {}).get('details', '')}")

        with st.expander("🔮 Recovery What-If Reconstruction Simulator (Click to Simulate)", expanded=False):
            st.markdown("Simulate excluding a fragment or comparing candidate fragment chains to evaluate confidence and decoder validation changes.")
            all_frags_pool = fragments or []
            if all_frags_pool:
                sel_ids = st.multiselect("Select fragments for Candidate Chain A", [f["fragment_id"] for f in all_frags_pool], default=[f["fragment_id"] for f in all_frags_pool[:2]])
                chain_a = [f for f in all_frags_pool if f["fragment_id"] in sel_ids]
                if chain_a:
                    res_sim = simulate_whatif_chain(chain_a)
                    ca = res_sim["candidate_a"]
                    st.success(f"**Candidate Chain A Verdict**: Confidence **{ca['confidence']}%** · Decoder: `{ca['decoder_msg']}` · Payload: `{ca['bytes_len']} bytes`")
            else:
                st.caption("No orphan fragments available in this case to simulate.")

        if leftovers:
            st.markdown("#### ⟂ Unmatched fragments")
            st.caption("Pieces with no confident partner. Kept for manual review rather than force-joined.")
            st.dataframe(pd.DataFrame([{
                "Fragment": f["fragment_id"], "Predicted format": f.get("predicted_format"), "Role": f.get("frag_type"),
                "Offset": f"0x{f['offset']:08X}", "Size (B)": f.get("size_bytes"),
                "Entropy (bits/byte)": round(f.get("features", {}).get("entropy", 0), 2),
            } for f in leftovers]), hide_index=True, use_container_width=True)


        st.markdown("#### 🛠️ Repaired (derived) artifacts")
        st.caption("Repairs are written as new, separately hashed files. Original evidence bytes are never modified.")
        if repaired:
            for r in repaired:
                with st.container(border=True):
                    dc1, dc2 = st.columns([4, 1])
                    with dc1:
                        st.markdown(f"**{r['derived_filename']}** ← `{r['original_filename']}` · "
                                    f"{r['repair_type'].replace('_', ' ').title()}")
                        for act in r.get("repair_actions", []):
                            st.caption(f"• {act}")
                        st.caption(f"Original SHA-256 `{short_hash(r['original_sha256'], 20)}` → "
                                   f"repaired SHA-256 `{short_hash(r['repaired_sha256'], 20)}`")
                    with dc2:
                        st.download_button("⬇️ Download", data=r.get("data", b""), file_name=r["derived_filename"],
                                           key=f"dl_rep_{r['item_id']}", use_container_width=True)
        else:
            st.caption("No artifact needed or allowed repair.")

        if dup_heads:
            st.markdown("#### ♊ Duplicate & near-duplicate groups")
            st.caption(clustering.get("summary", {}).get("cluster_message", ""))
            for head in dup_heads:
                st.markdown(f"**{head['filename']}** — {head['duplicate_count']} copies")
                st.dataframe(pd.DataFrame([{
                    "Filename": m_["filename"], "Offset": f"0x{(m_.get('offset') or 0):08X}",
                    "Similarity %": m_["similarity"], "Match": m_["match_type"],
                } for m_ in head.get("cluster_members", [])]), hide_index=True, use_container_width=True)

        entropy_map = results.get("entropy_map", [])
        if entropy_map:
            st.markdown("#### 📈 Disk entropy profile")
            st.caption("~8 bits/byte = compressed or encrypted data; near 0 = zero-filled or wiped space.")
            st.line_chart(pd.DataFrame(entropy_map).set_index("offset_mb")["entropy"], color="#00F2FE", height=200)

    # ----------------------------------------------------
    # TAB: THREATS, IOCs & TIMELINE
    # ----------------------------------------------------
    with tabs[3]:
        st.markdown("### 🚨 Anti-forensics & tampering indicators")
        indicators = tampering.get("indicators", [])
        if indicators:
            for ind in sorted(indicators, key=lambda x: list(SEVERITY_COLORS).index(x.get("severity", "INFO")) if x.get("severity") in SEVERITY_COLORS else 99):
                color = SEVERITY_COLORS.get(ind.get("severity"), "#64748B")
                off = ind.get("offset")
                st.markdown(f"""
                <div class="alert-card" style="background-color:{color}14; border:1px solid {color}55; border-left:4px solid {color};">
                    <span class="badge" style="color:{color}; border:1px solid {color};">{ind.get('severity')}</span>
                    <strong style="margin-left:6px;">{ind.get('indicator_type', '').replace('_', ' ').title()}</strong>
                    <span class="mono metric-sub" style="margin-left:6px;">{ind.get('target_artifact', '')}{f' @ 0x{off:08X}' if isinstance(off, int) else ''}</span>
                    <div style="margin-top:6px;">{ind.get('plain_language_explanation', '')}</div>
                </div>""", unsafe_allow_html=True)
        else:
            st.success("No ransomware, wiping or extension-spoofing indicators found.")

        st.markdown("### 🎯 Indicators of compromise")
        if iocs.get("records"):
            st.dataframe(pd.DataFrame(iocs["records"]), use_container_width=True, hide_index=True)
        else:
            st.caption("No IOCs extracted from recovered text.")

        st.markdown("### 🕒 Reconstructed timeline")
        events = timeline.get("timeline_events", [])
        if events:
            st.caption(f"{timeline.get('summary', '')} Range: {timeline.get('earliest_timestamp')} → {timeline.get('latest_timestamp')}")
            tdf = pd.DataFrame(events)
            tdf["time"] = pd.to_datetime(tdf["timestamp"].str.replace(" UTC", "", regex=False), errors="coerce")
            plot_df = tdf.dropna(subset=["time"])
            if not plot_df.empty:
                sev_domain = [s for s in SEVERITY_COLORS if s in set(plot_df["severity"])] or list(SEVERITY_COLORS)
                st.altair_chart(alt.Chart(plot_df).mark_circle(size=140).encode(
                    x=alt.X("time:T", title="UTC"),
                    y=alt.Y("source_artifact:N", title=None),
                    color=alt.Color("severity:N", scale=alt.Scale(domain=sev_domain, range=[SEVERITY_COLORS[s] for s in sev_domain])),
                    tooltip=["timestamp", "event_type", "severity", "description"],
                ).properties(height=max(140, 40 * plot_df["source_artifact"].nunique())), use_container_width=True)
            st.dataframe(tdf.drop(columns=["time"]), use_container_width=True, hide_index=True)
        else:
            st.caption("No timestamps could be recovered from artifacts.")

    # ----------------------------------------------------
    # TAB: RELATIONSHIP GRAPH
    # ----------------------------------------------------
    with tabs[4]:
        st.caption("Evidence source → recovery method → artifacts → fragments, plus wallets and IPs shared between files. Drag to explore.")
        st.markdown("""
        <div class="metric-card" style="display:flex; flex-wrap:wrap; gap:16px; font-size:13px; margin-bottom:12px;">
            <span>⭐ <strong style="color:#F59E0B;">Evidence root</strong></span>
            <span>⬢ <strong style="color:#3B82F6;">Recovery method</strong></span>
            <span>● <strong style="color:#10B981;">Intact file</strong></span>
            <span>● <strong style="color:#F59E0B;">Damaged file</strong></span>
            <span>◆ <strong style="color:#00F2FE;">Fragment</strong></span>
            <span>■ <strong style="color:#A855F7;">Crypto wallet</strong></span>
            <span>▲ <strong style="color:#EC4899;">IP address</strong></span>
        </div>""", unsafe_allow_html=True)
        try:
            G = build_forensic_graph(case_meta, items, fragments)
            components.html(generate_interactive_pyvis_html(G, height="600px"), height=620, scrolling=False)
        except Exception as e:
            st.error(f"Error rendering graph: {e}")

    # ----------------------------------------------------
    # TAB: INVESTIGATOR COPILOT
    # ----------------------------------------------------
    with tabs[5]:
        st.markdown("### 🤖 Local Evidence-Grounded Investigator Copilot")
        st.caption("Ask questions about case evidence. Answers are computed strictly from indexed recovered case artifacts with citations and disclaimers.")
        
        c_examples = [
            "Which recovered files are connected to 198.51.100.23?",
            "Why is this artifact P1?",
            "Which fragments reconstructed this image?",
            "Show all evidence around file deletion events.",
            "Which recovered artifacts contain credentials?"
        ]
        picked_copilot = st.pills("Copilot Prompts", c_examples, label_visibility="collapsed")
        copilot_query = st.text_input("Investigator Question", value=picked_copilot or "", placeholder="Ask a question about the recovered evidence...")

        if copilot_query:
            with st.spinner("Querying indexed case evidence..."):
                cop_res = query_investigator_copilot(
                    copilot_query, items, case_meta,
                    timeline_events=timeline.get("timeline_events"),
                    tampering_indicators=tampering.get("indicators")
                )
            st.markdown(f"#### {cop_res['tag']} Evidence Answer")
            st.markdown(cop_res["answer"])
            if cop_res["citations"]:
                st.caption(f"Evidence Citations: {', '.join(f'`{c}`' for c in cop_res['citations'])}")


    # ----------------------------------------------------
    # TAB: REPORT, AUDIT TRAIL & EXPORTS
    # ----------------------------------------------------
    with tabs[6]:
        rep_c1, rep_c2 = st.columns([3, 2])
        with rep_c1:
            st.markdown("### 📄 Case record")
            st.markdown(f"""
| Field | Value |
|---|---|
| Case ID | `{case_meta['case_id']}` |
| Evidence ID | `{case_meta.get('evidence_id', '')}` |
| Examiner | `{case_meta.get('examiner_name', '')}` |
| Evidence | `{case_meta['filename']}` ({case_meta.get('disk_size_bytes', 0):,} bytes) |
| Intake (UTC) | `{case_meta.get('intake_timestamp', '')}` |
| Verification (UTC) | `{case_meta.get('verification_timestamp', 'N/A')}` |
| Acquisition SHA-256 | `{case_meta['image_sha256']}` |
| Post-analysis SHA-256 | `{case_meta.get('post_analysis_sha256', '')}` |
| Read-only verified | {'✅ Yes — hashes identical' if case_meta.get('read_only_verified') else '❌ No — hashes differ'} |
| SHA-1 / MD5 | `{case_meta.get('image_sha1', '')}` / `{case_meta.get('image_md5', '')}` |
| Tool / host | `{case_meta.get('tool_version', '')}` on `{case_meta.get('host_machine', '')}` |
""")
        with rep_c2:
            st.markdown("### ⬇️ Exports")
            if reports.get("pdf_bytes"):
                st.download_button("⬇️ Forensic report (PDF)", data=reports["pdf_bytes"],
                                   file_name=f"ReconAI_Report_{case_meta['case_id']}.pdf", mime="application/pdf",
                                   use_container_width=True, type="primary")
                st.caption(f"PDF SHA-256 `{short_hash(reports.get('pdf_sha256', ''), 24)}`")
            if reports.get("json_str"):
                st.download_button("⬇️ Sealed case manifest (JSON)", data=reports["json_str"],
                                   file_name=f"ReconAI_Report_{case_meta['case_id']}.json", mime="application/json",
                                   use_container_width=True)
                st.caption(f"Embedded seal `{short_hash(reports.get('json_sha256', ''), 24)}` — covers inventory, audit trail, IOCs, timeline, repairs")
            st.download_button("⬇️ Evidence inventory (CSV)", data=pd.DataFrame([{
                "Item_ID": i["item_id"], "Title": i.get("friendly_title", i["filename"]), "Filename": i["filename"],
                "Tier": "User evidence" if i.get("is_user_file") else "System/OS", "Category": i["category"],
                "Recoverability": i.get("recoverability_bucket"), "Integrity_Score": i.get("integrity_score"),
                "Confidence_Score": i.get("confidence_score"), "Priority_Score": i.get("priority_score"),
                "Source": i.get("source"), "Offset": f"0x{i.get('offset', 0):08X}", "Size_Bytes": i.get("size_bytes"),
                "SHA256": i.get("sha256"),
            } for i in items]).to_csv(index=False), file_name=f"ReconAI_Inventory_{case_meta['case_id']}.csv",
                mime="text/csv", use_container_width=True)
            st.download_button("⬇️ Audit trail (JSON)", data=json.dumps(audit, indent=2, default=str),
                               file_name=f"ReconAI_Audit_{case_meta['case_id']}.json", mime="application/json",
                               use_container_width=True)

        st.markdown("---")
        st.markdown("### 🔗 Hash-chained audit trail")
        chain_ok = audit.get("chain_integrity") == "VERIFIED_TAMPER_FREE"
        (st.success if chain_ok else st.error)(
            f"Chain integrity: **{audit.get('chain_integrity', 'UNKNOWN')}** · {audit.get('total_audit_events', 0)} events · "
            f"head block `{short_hash(audit.get('latest_block_hash', ''), 24)}`"
            + ("" if chain_ok else f" · {audit.get('integrity_error')}")
        )
        st.caption("Each entry embeds the hash of the previous one, so editing or deleting any step breaks every hash after it.")
        entries = audit.get("entries", [])
        if entries:
            st.dataframe(pd.DataFrame([{
                "Step": e["step"], "Action": e["action"], "UTC": e["timestamp"],
                "Prev hash": short_hash(e["prev_hash"], 16), "Entry hash": short_hash(e["entry_hash"], 16),
                "Details": json.dumps(e.get("details", {}), default=str),
            } for e in entries]), use_container_width=True, hide_index=True)
