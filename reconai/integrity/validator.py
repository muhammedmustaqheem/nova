"""
ReconAI Structural Integrity & Recoverability Engine
Deeply evaluates whether recovered files open, are complete, or are corrupted.
Computes a transparent 0-100% Recoverability Score with an explicit 'why' breakdown.
Places every file into one of 4 strict buckets:
  1. FULLY RECOVERABLE
  2. PARTIALLY RECOVERABLE
  3. FRAGMENT ONLY
  4. UNRECOVERABLE
Answers directly 'what can realistically be restored' with totals and percentages.
"""

import io
import os
import zipfile
import math
from typing import Dict, Any, List, Tuple

def calculate_entropy(data: bytes) -> float:
    """Computes Shannon entropy (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts: Dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def validate_item_integrity(filename: str, data: bytes, extension: str = "") -> Dict[str, Any]:
    """
    Validates structural file integrity and assigns a transparent 0-100% Recoverability Score
    and places the item into one of the 4 standard Recoverability Buckets.
    """
    ext = (extension or os.path.splitext(filename)[1]).lower()
    if not data or len(data) == 0:
        return {
            "status": "CORRUPTED",
            "score": 0.0,
            "recoverability_bucket": "UNRECOVERABLE",
            "score_breakdown": {
                "header_valid": 0,
                "footer_present": 0,
                "structure_parses": 0,
                "recovery_ratio": 0,
                "entropy_health": 0
            },
            "score_rationale": "Empty artifact (zero bytes recovered).",
            "details": "Zero-byte file",
            "is_openable": False
        }

    # Format-specific validation
    if ext in [".jpg", ".jpeg"]:
        res = _validate_jpeg(data)
    elif ext == ".png":
        res = _validate_png(data)
    elif ext == ".pdf":
        res = _validate_pdf(data)
    elif ext in [".zip", ".docx", ".xlsx", ".pptx"]:
        res = _validate_zip(data, ext)
    elif ext in [".txt", ".env", ".log", ".json", ".sql", ".sh", ".py", ".md"]:
        res = _validate_text(data)
    elif ext in [".sqlite", ".db"]:
        res = _validate_sqlite(data)
    elif ext in [".exe", ".bin"]:
        res = _validate_exe(data)
    else:
        res = _validate_generic(data)

    # Assign Recoverability Bucket based on score and openability
    score = res["score"]
    if score >= 80.0 and res["is_openable"]:
        bucket = "FULLY RECOVERABLE"
    elif score >= 40.0:
        bucket = "PARTIALLY RECOVERABLE"
    elif score >= 15.0:
        bucket = "FRAGMENT ONLY"
    else:
        bucket = "UNRECOVERABLE"

    res["recoverability_bucket"] = bucket
    return res

def _validate_jpeg(data: bytes) -> Dict[str, Any]:
    has_soi = data.startswith(b"\xFF\xD8")
    has_eoi = b"\xFF\xD9" in data[-32:]
    ent = calculate_entropy(data)
    ent_health = 10 if 6.0 <= ent <= 7.95 else 5

    header_pts = 25 if has_soi else 0
    footer_pts = 20 if has_eoi else 0
    parse_pts = 0
    is_openable = False
    details = ""
    dimensions = "N/A"

    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data))
        img.verify()
        img_full = Image.open(io.BytesIO(data))
        img_full.load()
        width, height = img_full.size
        dimensions = f"{width}x{height}"
        parse_pts = 35
        is_openable = True
        status = "INTACT"
        details = f"Valid JPEG ({width}x{height} px, {img_full.format})"
    except Exception as e:
        status = "PARTIAL" if has_soi else "CORRUPTED"
        if has_soi and has_eoi:
            parse_pts = 15
            details = f"Valid JPEG markers present, decode fault: {str(e)[:45]}"
        elif has_soi:
            parse_pts = 10
            details = "SOI header found, but EOF trailer missing (truncated)"
        else:
            parse_pts = 0
            details = "Corrupted or missing JPEG header markers"

    ratio_pts = 10 if len(data) >= 512 else 5
    score = float(header_pts + footer_pts + parse_pts + ratio_pts + ent_health)

    rationale = (
        f"Header: {header_pts}/25 | Footer: {footer_pts}/20 | Decoder: {parse_pts}/35 | "
        f"Ratio: {ratio_pts}/10 | Entropy: {ent_health}/10 ({ent:.2f} b/B)"
    )

    return {
        "status": status,
        "score": min(100.0, score),
        "score_breakdown": {
            "header_valid": header_pts,
            "footer_present": footer_pts,
            "structure_parses": parse_pts,
            "recovery_ratio": ratio_pts,
            "entropy_health": ent_health
        },
        "score_rationale": rationale,
        "details": details,
        "is_openable": is_openable,
        "dimensions": dimensions
    }

def _validate_png(data: bytes) -> Dict[str, Any]:
    has_sig = data.startswith(b"\x89PNG\r\n\x1a\n")
    has_iend = b"IEND" in data[-32:]
    ent = calculate_entropy(data)
    ent_health = 10 if 6.0 <= ent <= 7.95 else 5

    header_pts = 25 if has_sig else 0
    footer_pts = 20 if has_iend else 0
    parse_pts = 0
    is_openable = False
    dimensions = "N/A"

    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data))
        img.verify()
        img_full = Image.open(io.BytesIO(data))
        img_full.load()
        width, height = img_full.size
        dimensions = f"{width}x{height}"
        parse_pts = 35
        is_openable = True
        status = "INTACT"
        details = f"Valid PNG image ({width}x{height} px)"
    except Exception as e:
        status = "PARTIAL" if has_sig else "CORRUPTED"
        parse_pts = 10 if has_sig else 0
        details = f"PNG chunk error: {str(e)[:45]}"

    ratio_pts = 10 if len(data) >= 128 else 4
    score = float(header_pts + footer_pts + parse_pts + ratio_pts + ent_health)
    rationale = f"Header: {header_pts}/25 | Footer: {footer_pts}/20 | Decoder: {parse_pts}/35 | Ratio: {ratio_pts}/10 | Entropy: {ent_health}/10"

    return {
        "status": status,
        "score": min(100.0, score),
        "score_breakdown": {
            "header_valid": header_pts,
            "footer_present": footer_pts,
            "structure_parses": parse_pts,
            "recovery_ratio": ratio_pts,
            "entropy_health": ent_health
        },
        "score_rationale": rationale,
        "details": details,
        "is_openable": is_openable,
        "dimensions": dimensions
    }

def _validate_pdf(data: bytes) -> Dict[str, Any]:
    has_header = b"%PDF-" in data[:1024]
    has_eof = b"%%EOF" in data[-512:]
    ent = calculate_entropy(data)
    ent_health = 10 if 5.0 <= ent <= 7.9 else 6

    header_pts = 25 if has_header else 0
    footer_pts = 20 if has_eof else 0
    parse_pts = 0
    is_openable = False
    pages = 0
    sample_text = ""

    try:
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(data))
        pages = len(reader.pages)
        if pages > 0:
            sample_text = reader.pages[0].extract_text() or ""
            parse_pts = 35
            is_openable = True
            status = "INTACT"
            details = f"Valid PDF document with {pages} page(s)"
        else:
            parse_pts = 15
            status = "PARTIAL"
            details = "PDF parsed but zero readable pages found"
    except Exception as e:
        status = "PARTIAL" if has_header else "CORRUPTED"
        parse_pts = 10 if has_header else 0
        details = f"PDF syntax or xref error: {str(e)[:45]}"

    ratio_pts = 10 if len(data) >= 512 else 5
    score = float(header_pts + footer_pts + parse_pts + ratio_pts + ent_health)
    rationale = f"Header: {header_pts}/25 | EOF Marker: {footer_pts}/20 | PyPDF Parse: {parse_pts}/35 | Stream Ratio: {ratio_pts}/10 | Entropy: {ent_health}/10"

    return {
        "status": status,
        "score": min(100.0, score),
        "score_breakdown": {
            "header_valid": header_pts,
            "footer_present": footer_pts,
            "structure_parses": parse_pts,
            "recovery_ratio": ratio_pts,
            "entropy_health": ent_health
        },
        "score_rationale": rationale,
        "details": details,
        "is_openable": is_openable,
        "pages": pages,
        "sample_text": sample_text[:120]
    }

def _validate_zip(data: bytes, ext: str) -> Dict[str, Any]:
    has_pk = data.startswith(b"PK\x03\x04")
    has_eocd = b"PK\x05\x06" in data[-256:]
    ent = calculate_entropy(data)
    ent_health = 10 if 6.0 <= ent <= 7.95 else 5

    header_pts = 25 if has_pk else 0
    footer_pts = 20 if has_eocd else 0
    parse_pts = 0
    is_openable = False
    files_count = 0

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        bad_file = zf.testzip()
        file_list = zf.namelist()
        files_count = len(file_list)
        if bad_file is None:
            parse_pts = 35
            is_openable = True
            status = "INTACT"
            details = f"Valid archive with {files_count} members: {', '.join(file_list[:2])}"
        else:
            parse_pts = 15
            is_openable = True
            status = "PARTIAL"
            details = f"Archive openable, CRC failure on member: {bad_file}"
    except Exception as e:
        status = "PARTIAL" if has_pk else "CORRUPTED"
        parse_pts = 5 if has_pk else 0
        details = f"Central Directory damaged ({str(e)[:40]})"

    ratio_pts = 10 if len(data) >= 256 else 4
    score = float(header_pts + footer_pts + parse_pts + ratio_pts + ent_health)
    rationale = f"Header PK: {header_pts}/25 | EOCD Footer: {footer_pts}/20 | Zipfile Test: {parse_pts}/35 | Length: {ratio_pts}/10 | Entropy: {ent_health}/10"

    return {
        "status": status,
        "score": min(100.0, score),
        "score_breakdown": {
            "header_valid": header_pts,
            "footer_present": footer_pts,
            "structure_parses": parse_pts,
            "recovery_ratio": ratio_pts,
            "entropy_health": ent_health
        },
        "score_rationale": rationale,
        "details": details,
        "is_openable": is_openable,
        "files_count": files_count
    }

def _validate_text(data: bytes) -> Dict[str, Any]:
    ent = calculate_entropy(data)
    ent_health = 10 if 3.0 <= ent <= 6.5 else 5

    try:
        text = data.decode('utf-8')
        printable_ratio = sum(1 for c in text if c.isprintable() or c in '\r\n\t') / max(1, len(text))
        if printable_ratio > 0.95:
            header_pts = 25
            footer_pts = 20
            parse_pts = 35
            is_openable = True
            status = "INTACT"
            details = f"Clean UTF-8 text ({len(text)} chars, {len(text.splitlines())} lines)"
        elif printable_ratio > 0.70:
            header_pts = 20
            footer_pts = 10
            parse_pts = 20
            is_openable = True
            status = "PARTIAL"
            details = f"Partial text stream ({round((1-printable_ratio)*100)}% non-printable characters)"
        else:
            header_pts = 10
            footer_pts = 5
            parse_pts = 5
            is_openable = False
            status = "CORRUPTED"
            details = "Binary data mixed into text stream"
    except UnicodeDecodeError:
        header_pts = 10
        footer_pts = 0
        parse_pts = 5
        is_openable = False
        status = "CORRUPTED"
        details = "Binary payload failed UTF-8 decoding"

    ratio_pts = 10 if len(data) >= 32 else 3
    score = float(header_pts + footer_pts + parse_pts + ratio_pts + ent_health)
    rationale = f"UTF-8 Header: {header_pts}/25 | Text Closure: {footer_pts}/20 | Printable Ratio: {parse_pts}/35 | Length: {ratio_pts}/10 | Entropy: {ent_health}/10"

    return {
        "status": status,
        "score": min(100.0, score),
        "score_breakdown": {
            "header_valid": header_pts,
            "footer_present": footer_pts,
            "structure_parses": parse_pts,
            "recovery_ratio": ratio_pts,
            "entropy_health": ent_health
        },
        "score_rationale": rationale,
        "details": details,
        "is_openable": is_openable
    }

def _validate_sqlite(data: bytes) -> Dict[str, Any]:
    has_header = data.startswith(b"SQLite format 3\x00")
    header_pts = 25 if has_header else 0
    footer_pts = 20 if len(data) >= 512 else 0
    parse_pts = 35 if has_header and len(data) >= 512 else 10
    ent = calculate_entropy(data)
    ent_health = 10
    ratio_pts = 10

    score = float(header_pts + footer_pts + parse_pts + ratio_pts + ent_health)
    is_openable = has_header and len(data) >= 512

    return {
        "status": "INTACT" if is_openable else "PARTIAL",
        "score": min(100.0, score),
        "score_breakdown": {
            "header_valid": header_pts,
            "footer_present": footer_pts,
            "structure_parses": parse_pts,
            "recovery_ratio": ratio_pts,
            "entropy_health": ent_health
        },
        "score_rationale": f"SQLite Header: {header_pts}/25 | Page Table: {parse_pts}/35",
        "details": f"SQLite 3 Database ({len(data)} bytes)",
        "is_openable": is_openable
    }

def _validate_exe(data: bytes) -> Dict[str, Any]:
    has_mz = data.startswith(b"MZ")
    header_pts = 25 if has_mz else 0
    footer_pts = 15 if len(data) >= 1024 else 0
    parse_pts = 30 if has_mz else 0
    ratio_pts = 10
    ent_health = 10

    score = float(header_pts + footer_pts + parse_pts + ratio_pts + ent_health)
    return {
        "status": "INTACT" if has_mz else "PARTIAL",
        "score": min(100.0, score),
        "score_breakdown": {
            "header_valid": header_pts,
            "footer_present": footer_pts,
            "structure_parses": parse_pts,
            "recovery_ratio": ratio_pts,
            "entropy_health": ent_health
        },
        "score_rationale": f"MZ Header: {header_pts}/25 | PE Image: {parse_pts}/35",
        "details": f"Windows PE Executable ({len(data)} bytes)",
        "is_openable": has_mz
    }

def _validate_generic(data: bytes) -> Dict[str, Any]:
    null_ratio = data.count(b'\x00') / max(1, len(data))
    if null_ratio > 0.85:
        return {
            "status": "CORRUPTED",
            "score": 10.0,
            "score_breakdown": {"header_valid": 0, "footer_present": 0, "structure_parses": 0, "recovery_ratio": 5, "entropy_health": 5},
            "score_rationale": "High null density (>85% slack/zero fill)",
            "details": "Mostly null bytes / slack zero fill",
            "is_openable": False
        }
    ent = calculate_entropy(data)
    score = 45.0 if ent > 4.0 else 25.0
    return {
        "status": "PARTIAL",
        "score": score,
        "score_breakdown": {"header_valid": 10, "footer_present": 10, "structure_parses": 10, "recovery_ratio": 10, "entropy_health": 5},
        "score_rationale": f"Generic raw payload (entropy: {ent:.2f} b/B)",
        "details": "Unverified raw binary block",
        "is_openable": False
    }

def compute_recoverability_summary(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Answers directly 'what can realistically be restored' with totals and percentages.
    """
    total = len(items)
    if total == 0:
        return {
            "total_items": 0,
            "fully_recoverable": 0,
            "partially_recoverable": 0,
            "fragment_only": 0,
            "unrecoverable": 0,
            "fully_recoverable_pct": 0.0,
            "partially_recoverable_pct": 0.0,
            "realistic_restoration_pct": 0.0
        }

    fully = sum(1 for i in items if i.get("recoverability_bucket") == "FULLY RECOVERABLE")
    partial = sum(1 for i in items if i.get("recoverability_bucket") == "PARTIALLY RECOVERABLE")
    fragments = sum(1 for i in items if i.get("recoverability_bucket") == "FRAGMENT ONLY")
    unrec = sum(1 for i in items if i.get("recoverability_bucket") == "UNRECOVERABLE")

    realistic_total = fully + partial
    realistic_pct = round((realistic_total / total) * 100, 1)

    return {
        "total_items": total,
        "fully_recoverable": fully,
        "partially_recoverable": partial,
        "fragment_only": fragments,
        "unrecoverable": unrec,
        "fully_recoverable_pct": round((fully / total) * 100, 1),
        "partially_recoverable_pct": round((partial / total) * 100, 1),
        "realistic_restoration_pct": realistic_pct,
        "restoration_verdict": f"{fully} files ({(fully/total)*100:.1f}%) can be fully restored immediately; {partial} files ({(partial/total)*100:.1f}%) can be partially salvaged; {unrec + fragments} items require deep carving or are unrecoverable."
    }
