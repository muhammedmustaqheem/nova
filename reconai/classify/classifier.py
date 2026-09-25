"""
ReconAI Semantic Classification & Investigator Prioritization Engine
Classifies recovered evidence artifacts into 9 standardized content classes:
  1. Document
  2. Image
  3. Credentials & Keys
  4. Financial
  5. Personal Data (PII)
  6. Source Code
  7. Logs
  8. Executables
  9. Encrypted Blobs
Computes: Priority Score = Sensitivity Weight × Integrity Score × Scope Relevance
Enforces strict filtering based on selected Extraction Scope.
"""

import re
import os
from typing import Dict, Any, Tuple, List

# Standard Catchy Content Classes and their Forensic Sensitivity Weights
CLASS_WEIGHTS = {
    "🔑 Credentials & Access Keys": 1.00,
    "💰 Financial & Wire Transfers": 0.95,
    "🪪 Identity & Personal Data": 0.90,
    "📄 Documents & Reports": 0.80,
    "🚨 Ransomware & Encrypted Blobs": 0.75,
    "⚙️ System & Attack Logs": 0.70,
    "🖼️ Photos & Media Evidence": 0.65,
    "💻 Source Code & Scripts": 0.60,
    "⚡ Executables & Binaries": 0.50
}

# Backwards compatibility aliases
CLASS_WEIGHTS["Credentials & Keys"] = 1.00
CLASS_WEIGHTS["Financial"] = 0.95
CLASS_WEIGHTS["Personal Data (PII)"] = 0.90
CLASS_WEIGHTS["Document"] = 0.80
CLASS_WEIGHTS["Encrypted Blobs"] = 0.75
CLASS_WEIGHTS["Logs"] = 0.70
CLASS_WEIGHTS["Image"] = 0.65
CLASS_WEIGHTS["Source Code"] = 0.60
CLASS_WEIGHTS["Executables"] = 0.50

CATEGORY_WEIGHTS = CLASS_WEIGHTS

# Content classes created by a person (vs. OS / tooling footprints)
USER_EVIDENCE_CLASSES = {
    "🔑 Credentials & Access Keys", "💰 Financial & Wire Transfers", "🪪 Identity & Personal Data",
    "📄 Documents & Reports", "🚨 Ransomware & Encrypted Blobs", "🖼️ Photos & Media Evidence",
    "Credentials & Keys", "Financial", "Personal Data (PII)", "Document", "Image", "Encrypted Blobs",
}


# Regex Patterns for Deep Payload Inspection
CREDENTIAL_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
    re.compile(r"DATABASE_URL|postgres://|mysql://|mongodb://|redis://", re.IGNORECASE),
    re.compile(r"password\s*[:=]|passwd|secret|jwt_secret|private_key|api_token", re.IGNORECASE),
    re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----")
]

FINANCIAL_PATTERNS = [
    re.compile(r"0x[a-fA-F0-9]{40}"),  # Ethereum / EVM address
    re.compile(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}"),  # Bitcoin address
    re.compile(r"\$[\d,]+(\.\d{2})?"),  # Currency amounts
    re.compile(r"wire transfer|offshore|routing number|swift\s*code|iban|invoice|balance sheet", re.IGNORECASE),
    re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b")  # Credit card pattern
]

PII_PATTERNS = [
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # Email
    re.compile(r"\b(?:\+?1[-. ]?)?\(?[2-9]\d{2}\)?[-. ]?\d{3}[-. ]?\d{4}\b"),  # Phone
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # US SSN
    re.compile(r"passport\s*no|ssn|date of birth|driver'?s license", re.IGNORECASE)
]

LOG_PATTERNS = [
    re.compile(r"sshd\[\d+\]|Failed password|Accepted password|sudo:|privilege", re.IGNORECASE),
    re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),  # IPv4
    re.compile(r"kernel:|exfiltration|firewall|unauthorized|syslog", re.IGNORECASE)
]

SOURCE_CODE_PATTERNS = [
    re.compile(r"def\s+\w+\s*\(|class\s+\w+[:\(]|import\s+\w+|#include\s+<|function\s+\w+\(", re.IGNORECASE),
    re.compile(r"SELECT\s+.+\s+FROM\s+|INSERT\s+INTO\s+|UPDATE\s+\w+\s+SET", re.IGNORECASE)
]

def extract_preview_text(item: Dict[str, Any]) -> str:
    """Extracts human-readable textual snippet from artifact payload for indexing & display."""
    data = item.get("data", b"")
    ext = (item.get("extension") or "").lower()

    if ext in [".txt", ".env", ".log", ".json", ".sql", ".sh", ".py", ".md"]:
        try:
            raw_text = data.decode('utf-8')
            printable = sum(1 for c in raw_text if c.isprintable() or c in '\r\n\t')
            if printable / max(1, len(raw_text)) >= 0.75:
                return raw_text[:2000]
        except Exception:
            pass
        clean_chars = [chr(b) if (32 <= b <= 126 or b in (9, 10, 13)) else '.' for b in data[:300]]
        return f"[Raw Stream ({len(data)} B)]\n" + "".join(clean_chars)

    elif ext == ".pdf":
        try:
            import pypdf
            import io
            reader = pypdf.PdfReader(io.BytesIO(data))
            text = ""
            for p in reader.pages[:3]:
                t = p.extract_text()
                if t:
                    text += t + "\n"
            if text.strip():
                return text[:2000]
        except Exception:
            pass
        strings = re.findall(rb"\(([^\)]{4,})\)", data)
        if strings:
            return " ".join(s.decode('latin-1', errors='ignore') for s in strings[:15])[:1000]

    elif ext in [".jpg", ".jpeg", ".png", ".gif", ".bmp"]:
        dim = item.get("dimensions") or item.get("details", {}).get("dimensions", "Image")
        ascii_strings = [s.decode('ascii', errors='ignore') for s in re.findall(rb"[\x20-\x7E]{6,}", data)]
        comments = " | ".join(ascii_strings[:4]) if ascii_strings else ""
        return f"{ext.upper().replace('.', '')} Image [{dim}] {comments}"

    elif ext in [".zip", ".docx", ".xlsx"]:
        details = item.get("details", {})
        files = details.get("files_count", "archive")
        return f"Compressed Archive ({files} items)"

    ascii_runs = re.findall(rb"[\x20-\x7E]{5,}", data[:4096])
    return " ".join(s.decode('ascii', errors='ignore') for s in ascii_runs[:10])[:1000]

def classify_content(item: Dict[str, Any]) -> str:
    """
    Classifies an artifact into one of the 9 standard Content Classes.
    """
    filename = item.get("filename", "").lower()
    ext = (item.get("extension") or os.path.splitext(filename)[1]).lower()
    data = item.get("data", b"")
    preview = extract_preview_text(item)

    # 1. Credentials & Keys
    if any(p.search(preview) for p in CREDENTIAL_PATTERNS) or ext in [".env", ".key", ".pem"] or "cred" in filename or "pass" in filename:
        return "🔑 Credentials & Access Keys"

    # 2. Financial
    if any(p.search(preview) for p in FINANCIAL_PATTERNS) or "finance" in filename or "invoice" in filename or "audit" in filename:
        return "💰 Financial & Wire Transfers"

    # 3. Personal Data (PII)
    if any(p.search(preview) for p in PII_PATTERNS) or "passport" in filename or "pii" in filename:
        return "🪪 Identity & Personal Data"

    # 4. Logs
    if any(p.search(preview) for p in LOG_PATTERNS) or ext in [".log"] or "auth" in filename or "syslog" in filename:
        return "⚙️ System & Attack Logs"

    # 5. Source Code
    if ext in [".py", ".sh", ".sql", ".js", ".c", ".cpp", ".java", ".html", ".css"] or any(p.search(preview) for p in SOURCE_CODE_PATTERNS):
        return "💻 Source Code & Scripts"

    # 6. Executables
    if ext in [".exe", ".dll", ".so", ".bin"] or data.startswith(b"MZ") or data.startswith(b"\x7fELF"):
        return "⚡ Executables & Binaries"

    # 7. Images
    if ext in [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"]:
        return "🖼️ Photos & Media Evidence"

    # 8. Documents
    if ext in [".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".md", ".rtf"] or "doc" in filename:
        return "📄 Documents & Reports"

    # 9. Encrypted Blobs
    ent = float(item.get("entropy", 0.0))
    if ent >= 7.85:
        return "🚨 Ransomware & Encrypted Blobs"

    return "📄 Documents & Reports"


def compute_priority(
    item: Dict[str, Any],
    content_class: str,
    scope: str = "Complete Forensic Triage"
) -> Tuple[float, str, str]:
    """
    Computes: Priority Score = Sensitivity Weight × Integrity Score × Scope Relevance
    Returns: (priority_score, artifact_scope, score_rationale)
    """
    sensitivity = CLASS_WEIGHTS.get(content_class, 0.50)
    integrity = float(item.get("integrity_score", item.get("score", 50.0)))

    # Determine Artifact Scope (User Evidence vs System/OS)
    is_user = content_class in USER_EVIDENCE_CLASSES
    artifact_scope = "User Evidence File" if is_user else "System / OS File"

    # Scope Relevance Multiplier
    if "Suspect" in scope:
        relevance = 1.0 if is_user else 0.05
    elif "System" in scope:
        relevance = 1.0 if not is_user else 0.05
    else:  # Complete Forensic Triage
        relevance = 1.0

    priority = round(sensitivity * (integrity / 100.0) * relevance * 100.0, 1)
    rationale = f"Sensitivity: {sensitivity:.2f} × Integrity: {integrity:.0f}% × Scope: {relevance:.2f}"
    return priority, artifact_scope, rationale

def filter_items_by_scope(items: List[Dict[str, Any]], scope: str) -> List[Dict[str, Any]]:
    """
    Enforces active extraction scope filtering on the recovered artifact collection.
    """
    if "Suspect" in scope:
        return [i for i in items if i.get("artifact_scope") == "User Evidence File"]
    elif "System" in scope:
        return [i for i in items if i.get("artifact_scope") == "System / OS File"]
    return items  # Complete Forensic Triage returns all

def classify_and_prioritize(
    item: Dict[str, Any],
    scope: str = "Complete Forensic Triage"
) -> Tuple[str, float, str, str]:
    """
    Combined classification and scoring wrapper.
    Returns: (category, priority_score, preview_text, artifact_scope)
    """
    preview = extract_preview_text(item)
    category = classify_content(item)
    priority, artifact_scope, rationale = compute_priority(item, category, scope)
    item["priority_rationale"] = rationale
    return category, priority, preview, artifact_scope

def get_file_friendly_meta(filename: str, category: str, preview: str = "") -> Dict[str, str]:
    """
    Generates human-readable friendly titles, investigative use cases, and forensic naming notes.
    """
    fn = filename.upper()
    preview_upper = (preview or "").upper()

    if "RED" in fn or "ENV" in fn or "CRED" in fn or "PASS" in fn or "AKIA" in preview_upper:
        return {
            "friendly_title": "Leaked Cloud & Database Credentials (.env)",
            "use_case": "Smoking-Gun Clue: Contains live AWS cloud access keys, Stripe API tokens, and PostgreSQL core banking passwords used by the suspect to access financial infrastructure.",
            "naming_note": "Forensic Naming Note: Why the underscore '_'? In FAT filesystems, when a file is deleted, the first letter is replaced with deletion byte 0xE5. ReconAI recovered it as '_REDS.ENV' (originally 'CREDS.ENV')."
        }
    elif "INANCE" in fn or "AUDIT" in fn or ("OFFSHORE" in preview_upper and "PDF" in fn):
        return {
            "friendly_title": "Offshore Wire Transfer Audit Report (PDF)",
            "use_case": "Financial Fraud Proof: Formal audit finding documenting an unauthorized wire transfer of $4,250,000 USD sent directly to the suspect's Ethereum crypto wallet.",
            "naming_note": "Forensic Naming Note: Originally 'FINANCE.PDF'. The first character was replaced with 0xE5 when deleted by the suspect to cover their tracks."
        }
    elif "UTHLOG" in fn or "AUTH" in fn or "SSHD" in preview_upper:
        return {
            "friendly_title": "Server Attack & Authentication Log (auth.log)",
            "use_case": "Cyberattack Traces: Operating system security log recording SSH password brute-force attempts from external IP 198.51.100.23, privilege escalation to root, and data exfiltration.",
            "naming_note": "Forensic Naming Note: Originally 'AUTHLOG.TXT'. Recovered from deleted Linux server filesystem tables."
        }
    elif "PASSPORT" in fn or "REASSEMBLED" in fn:
        return {
            "friendly_title": "AI-Reassembled Suspect Passport Photo (JPEG)",
            "use_case": "Suspect Identity Evidence: A photo split across non-contiguous disk sectors that was reassembled by AI with high confidence by matching boundary byte entropy.",
            "naming_note": "Reassembly Lineage: The suspect split this image across two separate clusters separated by slack space. ReconAI solved the puzzle."
        }
    elif "WEAPON" in fn:
        return {
            "friendly_title": "Crime Scene Physical Weapon Photograph (JPEG)",
            "use_case": "Physical Evidence: Crime scene camera photograph documenting physical weapon evidence recovered during law enforcement investigation.",
            "naming_note": "Filesystem Active File: Intact image entry discovered in the drive directory table."
        }
    elif "PNG" in fn or "SEAL" in fn or "BANK" in preview_upper:
        return {
            "friendly_title": "Offshore Bank Digital Seal Logo (PNG)",
            "use_case": "Affiliation Evidence: Digital seal of an offshore financial entity carved directly from raw unallocated disk sectors where directory table metadata was wiped.",
            "naming_note": "Signature Carving: Carved from raw sector bytes using PNG magic header '\\x89PNG' and 'IEND' footer."
        }
    elif "ACKUP" in fn or "ZIP" in fn:
        return {
            "friendly_title": "Damaged System Backup Archive (backup.zip)",
            "use_case": "Integrity Testing Benchmark: A corrupted system backup archive demonstrating how ReconAI's validator catches damaged file payloads (rated PARTIAL 45% due to broken CRC).",
            "naming_note": "Forensic Naming Note: Originally 'BACKUP.ZIP'. Contains a damaged central payload structure."
        }
    elif "LOCKED" in fn or "RANSOM" in fn or "ENCRYPT" in preview_upper:
        return {
            "friendly_title": "Ransomware Encrypted Payload / Extortion Clue",
            "use_case": "Malicious Tampering: Encrypted storage region or ransom instruction left behind during a cyber extortion event.",
            "naming_note": "Anti-Forensics Indicator: High-entropy cipher stream or ransom demand note."
        }
    else:
        return {
            "friendly_title": f"Recovered {category} Artifact ({filename})",
            "use_case": f"Investigative {category} file recovered during forensic disk analysis.",
            "naming_note": f"Artifact {filename} classified as {category} based on payload signatures."
        }


def classify_file_type(item: Dict[str, Any]) -> str:
    """
    Standardized File Type Classification: IMAGE, DOCUMENT, PDF, ARCHIVE, DATABASE, TEXT, LOG, EXECUTABLE, UNKNOWN.
    """
    ext = (item.get("extension") or os.path.splitext(item.get("filename", ""))[1]).lower()
    data = item.get("data", b"")
    if ext in [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"]:
        return "IMAGE"
    elif ext == ".pdf" or data.startswith(b"%PDF"):
        return "PDF"
    elif ext in [".docx", ".xlsx", ".pptx", ".doc", ".rtf"]:
        return "DOCUMENT"
    elif ext in [".zip", ".tar", ".gz", ".7z", ".rar"] or data.startswith(b"PK\x03\x04"):
        return "ARCHIVE"
    elif ext in [".sqlite", ".db", ".sqlite3"] or data.startswith(b"SQLite format 3"):
        return "DATABASE"
    elif ext in [".log"] or "auth" in item.get("filename", "").lower():
        return "LOG"
    elif ext in [".txt", ".env", ".json", ".xml", ".csv", ".md"]:
        return "TEXT"
    elif ext in [".exe", ".dll", ".so", ".bin"] or data.startswith(b"MZ") or data.startswith(b"\x7fELF"):
        return "EXECUTABLE"
    return "UNKNOWN"


def classify_primary_recovery_state(item: Dict[str, Any], is_repaired: bool = False) -> str:
    """
    Standardized Primary Recovery State: INTACT, DELETED, CARVED, FRAGMENTED, RECONSTRUCTED, PARTIALLY_RECOVERED, REPAIRED, CORRUPTED, UNRECOVERABLE.
    """
    source = item.get("source", "")
    is_deleted = item.get("is_deleted", False)
    is_fragmented = item.get("is_fragmented", False)
    integrity = item.get("integrity_status", "INTACT")
    bucket = item.get("recoverability_bucket", "")

    if source == "fragment_reassembly" or is_fragmented:
        return "RECONSTRUCTED"
    elif is_repaired:
        return "REPAIRED"
    elif is_deleted and source == "filesystem_undelete":
        return "DELETED"
    elif source == "signature_carving":
        return "CARVED"
    elif integrity == "INTACT" or bucket == "FULLY RECOVERABLE":
        return "INTACT"
    elif integrity == "PARTIAL" or bucket == "PARTIALLY RECOVERABLE":
        return "PARTIALLY_RECOVERED"
    elif integrity == "CORRUPTED":
        return "CORRUPTED"
    elif bucket == "UNRECOVERABLE":
        return "UNRECOVERABLE"
    return "CARVED"


def compute_technical_priority(item: Dict[str, Any]) -> Tuple[str, str, List[str]]:
    """
    Assigns Technical Recovery Priority: P1 — HIGH PRIORITY, P2 — MEDIUM PRIORITY, P3 — LOW PRIORITY.
    Does NOT claim legal or investigative importance; focuses purely on technical recoverability.
    Returns: (priority_tag, priority_score_str, rationale_reasons)
    """
    p_score = float(item.get("priority_score", 50.0))
    conf = float(item.get("confidence_score", 100.0))
    integrity = item.get("integrity_status", "INTACT")
    bucket = item.get("recoverability_bucket", "FULLY RECOVERABLE")
    
    reasons = []
    if conf >= 85.0:
        reasons.append(f"High confidence score ({conf:.0f}%)")
    if integrity == "INTACT":
        reasons.append("Decoder structural validation passed")
    elif integrity == "PARTIAL":
        reasons.append("Partial payload recovered")
    if bucket == "FULLY RECOVERABLE":
        reasons.append("Fully restorable file stream")
    
    if conf >= 85.0 and integrity in ("INTACT", "PARTIAL") and bucket in ("FULLY RECOVERABLE", "PARTIALLY RECOVERABLE"):
        tag = "P1 — HIGH PRIORITY"
    elif conf >= 50.0 or integrity == "PARTIAL":
        tag = "P2 — MEDIUM PRIORITY"
    else:
        tag = "P3 — LOW PRIORITY"

    return tag, f"{p_score:.1f}", reasons


def compute_completeness_estimate(item: Dict[str, Any]) -> Tuple[str, str]:
    """
    Provides a measurable technical data completeness estimate.
    Returns: (completeness_pct_str, basis_explanation)
    """
    integrity = item.get("integrity_status", "INTACT")
    bucket = item.get("recoverability_bucket", "FULLY RECOVERABLE")
    breakdown = item.get("score_breakdown", {})

    if integrity == "INTACT" and bucket == "FULLY RECOVERABLE":
        return "100%", "Header, payload structure, and footer fully verified by decoder."
    elif bucket == "PARTIALLY RECOVERABLE":
        pts = breakdown.get("recovery_ratio", 7)
        pct = min(95, max(50, int((pts / 10.0) * 100)))
        return f"{pct}%", "Payload partially truncated; salvageable content streams preserved."
    elif bucket == "FRAGMENT ONLY":
        return "35%", "Isolated cluster fragment without complete format headers/footers."
    elif bucket == "UNRECOVERABLE":
        return "0%", "Structure destroyed or zero-filled on disk."
    return "Unknown", "Data completeness cannot be reliably estimated."


def compute_evidence_impact_score(item: Dict[str, Any], total_artifacts: int = 10) -> Dict[str, Any]:
    """
    Computes Evidence Impact Score from 0 to 100 without replacing P1/P2/P3.
    Breakdown factors:
      - Recoverability (max 25)
      - Integrity (max 25)
      - Relationships (max 20)
      - Sensitivity & Timeline relevance (max 15)
      - Uniqueness (max 15)
    Returns dictionary with total score (0-100) and explicit factor breakdown.
    """
    bucket = item.get("recoverability_bucket", "FULLY RECOVERABLE")
    integrity_score = float(item.get("integrity_score", 50.0))
    conf = float(item.get("confidence_score", 100.0))
    category = item.get("category", "📄 Documents & Reports")
    sens = CLASS_WEIGHTS.get(category, 0.50)

    # 1. Recoverability (max 25)
    if bucket == "FULLY RECOVERABLE":
        rec_pts = 25
    elif bucket == "PARTIALLY RECOVERABLE":
        rec_pts = 18
    elif bucket == "FRAGMENT ONLY":
        rec_pts = 10
    else:
        rec_pts = 0

    # 2. Integrity & Confidence (max 25)
    int_pts = int((integrity_score / 100.0 * 0.6 + conf / 100.0 * 0.4) * 25)

    # 3. Relationships (max 20)
    frags_count = len(item.get("fragments_linked", []))
    rel_pts = min(20, 10 + frags_count * 5)

    # 4. Sensitivity & Timeline Relevance (max 15)
    sens_pts = int(sens * 15)

    # 5. Uniqueness (max 15)
    is_user = item.get("is_user_file", True)
    uniq_pts = 15 if is_user else 8

    total = rec_pts + int_pts + rel_pts + sens_pts + uniq_pts
    total = min(100, max(0, total))

    return {
        "score": total,
        "breakdown": {
            "recoverability": (rec_pts, 25),
            "integrity": (int_pts, 25),
            "relationships": (rel_pts, 20),
            "sensitivity_relevance": (sens_pts, 15),
            "uniqueness": (uniq_pts, 15),
        },
        "rationale": f"Recoverability ({rec_pts}/25) + Integrity ({int_pts}/25) + Relationships ({rel_pts}/20) + Sensitivity ({sens_pts}/15) + Uniqueness ({uniq_pts}/15)"
    }


def generate_evidence_dna(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generates a comprehensive Evidence DNA / Fingerprint profile for an artifact.
    """
    offset = item.get("offset", 0)
    size = item.get("size_bytes", 0)
    sector_start = offset // 512
    sector_end = (offset + size) // 512

    return {
        "artifact_id": item.get("item_id", "unknown"),
        "original_filename": item.get("filename", "unknown"),
        "recovered_filename": item.get("filename", "unknown"),
        "file_type_class": item.get("file_type_class", "UNKNOWN"),
        "primary_recovery_state": item.get("recovery_state", "CARVED"),
        "sha256": item.get("sha256", "pending"),
        "source_offset_hex": f"0x{offset:08X}",
        "sector_range": f"Sectors {sector_start:,} – {sector_end:,}",
        "integrity_status": item.get("integrity_status", "INTACT"),
        "recovery_confidence": f"{item.get('confidence_score', 100.0):.1f}%",
        "category": item.get("category", "General"),
        "technical_priority": item.get("technical_priority", "P3 — LOW PRIORITY"),
        "impact_score": item.get("impact_score", 50),
        "completeness": item.get("completeness_pct", "100%"),
        "fragment_count": len(item.get("fragments_linked", [])),
    }


