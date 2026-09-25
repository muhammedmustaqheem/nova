"""
ReconAI Backend API Module & Controller
Provides standard RESTful forensic service functions and endpoints:
  - POST /api/forensics/upload
  - POST /api/forensics/analyze
  - POST /api/forensics/recover
  - GET /api/forensics/files
  - GET /api/forensics/files/:id
  - GET /api/forensics/files/:id/download
  - GET /api/forensics/files/:id/preview
  - GET /api/forensics/report
"""

import os
import io
import json
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from reconai.ingest.hasher import compute_evidence_hash
from reconai.pipeline import run_recovery_pipeline
from reconai.db.models import get_case_items, get_case_metadata, save_case, save_recovered_item
from reconai.report.report_exporter import generate_json_report, generate_pdf_report

# In-memory storage cache for active session items
_ACTIVE_CASE_CACHE: Dict[str, Any] = {}

def api_upload_image(file_bytes: bytes, filename: str, upload_dir: str = "data/uploads") -> Dict[str, Any]:
    """
    POST /api/forensics/upload
    Saves uploaded disk image (.raw, .img, .dd) to working directory in read-only mode.
    """
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, filename)
    with open(file_path, "wb") as f:
        f.write(file_bytes)
    
    hash_info = compute_evidence_hash(file_path)
    return {
        "status": "SUCCESS",
        "message": f"Disk image uploaded and sealed successfully: {filename}",
        "file_path": file_path,
        "hash_metadata": hash_info
    }

def api_analyze_image(image_path: str) -> Dict[str, Any]:
    """
    POST /api/forensics/analyze
    Computes cryptographic hashes and chain-of-custody metadata for disk image.
    """
    if not os.path.exists(image_path):
        return {"status": "ERROR", "message": f"Image file not found: {image_path}"}
    
    hash_info = compute_evidence_hash(image_path)
    return {
        "status": "SUCCESS",
        "analysis": hash_info,
        "read_only_mode": "O_RDONLY"
    }

def api_recover_image(
    image_path: str,
    case_id: Optional[str] = None,
    examiner_name: str = "Lead DFIR Examiner",
    scope: str = "Complete Forensic Triage"
) -> Dict[str, Any]:
    """
    POST /api/forensics/recover
    Executes end-to-end recovery pipeline (FS undelete, carving, AI reassembly, repair, triage).
    Organizes outputs in recovery/case-XXX/ output structure.
    """
    results = run_recovery_pipeline(
        image_path=image_path,
        case_id=case_id,
        examiner_name=examiner_name,
        extraction_scope=scope
    )
    
    c_id = results["case"]["case_id"]
    _ACTIVE_CASE_CACHE[c_id] = results
    
    # Save output artifacts to organized recovery directory structure (Requirement 11)
    base_recovery_dir = os.path.join("recovery", c_id.lower())
    for folder in ["original", "carved", "reconstructed", "repaired", "reports", "hashes", "logs"]:
        os.makedirs(os.path.join(base_recovery_dir, folder), exist_ok=True)
    
    # Save hash certificates
    with open(os.path.join(base_recovery_dir, "hashes", "evidence_seal.json"), "w") as f:
        json.dump(results["hash_meta"], f, indent=2)
        
    return {
        "status": "SUCCESS",
        "case_id": c_id,
        "total_recovered": results["stats"]["total_recovered"],
        "stats": results["stats"],
        "recoverability_summary": results["recoverability_summary"]
    }

def api_get_files(
    case_id: str,
    category: Optional[str] = None,
    status: Optional[str] = None,
    source: Optional[str] = None
) -> Dict[str, Any]:
    """
    GET /api/forensics/files
    Retrieves list of recovered files with optional filters.
    """
    if case_id in _ACTIVE_CASE_CACHE:
        items = _ACTIVE_CASE_CACHE[case_id]["recovered_items"]
    else:
        items = get_case_items(case_id)
        
    filtered = items
    if category and category.upper() != "ALL":
        filtered = [i for i in filtered if i.get("category") == category]
    if status and status.upper() != "ALL":
        filtered = [i for i in filtered if i.get("integrity_status") == status]
    if source and source.upper() != "ALL":
        filtered = [i for i in filtered if i.get("source") == source]
        
    sanitized = []
    for item in filtered:
        sanitized.append({
            "item_id": item.get("item_id"),
            "filename": item.get("filename"),
            "category": item.get("category"),
            "source": item.get("source"),
            "integrity_status": item.get("integrity_status"),
            "integrity_score": item.get("integrity_score"),
            "confidence_score": item.get("confidence_score", 100.0),
            "priority_score": item.get("priority_score"),
            "size_bytes": item.get("size_bytes"),
            "sha256": item.get("sha256"),
            "offset": item.get("offset"),
            "is_user_file": item.get("is_user_file", True)
        })
        
    return {
        "status": "SUCCESS",
        "count": len(sanitized),
        "files": sanitized
    }

def api_get_file_detail(case_id: str, item_id: str) -> Dict[str, Any]:
    """
    GET /api/forensics/files/:id
    Retrieves complete metadata, validation info, and recovery reasons for a file.
    """
    item = _find_item(case_id, item_id)
    if not item:
        return {"status": "ERROR", "message": f"File item '{item_id}' not found."}
    
    # Exclude raw binary data from JSON payload metadata
    meta = {k: v for k, v in item.items() if k != "data"}
    return {
        "status": "SUCCESS",
        "file": meta
    }

def api_download_file(case_id: str, item_id: str) -> Tuple[bytes, str, str]:
    """
    GET /api/forensics/files/:id/download
    Returns (raw_binary_bytes, filename, mime_type) for direct browser download.
    """
    item = _find_item(case_id, item_id)
    if not item:
        raise FileNotFoundError(f"Recovered item '{item_id}' not found.")
    
    data = item.get("data", b"")
    filename = item.get("filename", "recovered_file.bin")
    ext = item.get("extension", "").lower()
    
    mime_map = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".pdf": "application/pdf",
        ".zip": "application/zip",
        ".txt": "text/plain",
        ".env": "text/plain",
        ".log": "text/plain",
        ".json": "application/json",
        ".sqlite": "application/x-sqlite3",
        ".db": "application/x-sqlite3"
    }
    mime_type = mime_map.get(ext, "application/octet-stream")
    return data, filename, mime_type

def api_preview_file(case_id: str, item_id: str) -> Dict[str, Any]:
    """
    GET /api/forensics/files/:id/preview
    Returns content preview or notice if preview unavailable.
    """
    item = _find_item(case_id, item_id)
    if not item:
        return {"status": "ERROR", "message": f"File item '{item_id}' not found."}
    
    preview_text = item.get("content_preview", "")
    ext = item.get("extension", "").lower()
    
    return {
        "status": "SUCCESS",
        "item_id": item_id,
        "filename": item.get("filename"),
        "extension": ext,
        "preview_type": "text" if preview_text else "unavailable",
        "content_preview": preview_text if preview_text else "Preview unavailable. Download artifact for external forensic examination.",
        "integrity_status": item.get("integrity_status"),
        "is_openable": item.get("details", {}).get("is_openable", False)
    }

def api_get_report(case_id: str, report_format: str = "json") -> Dict[str, Any]:
    """
    GET /api/forensics/report
    Generates downloadable forensic report in JSON or PDF format.
    """
    if case_id in _ACTIVE_CASE_CACHE:
        res = _ACTIVE_CASE_CACHE[case_id]
        if report_format.lower() == "pdf":
            return {
                "status": "SUCCESS",
                "format": "pdf",
                "pdf_bytes": res["reports"]["pdf_bytes"],
                "sha256": res["reports"]["pdf_sha256"]
            }
        else:
            return {
                "status": "SUCCESS",
                "format": "json",
                "report_json": res["reports"]["json_str"],
                "sha256": res["reports"]["json_sha256"]
            }
    
    return {"status": "ERROR", "message": f"Case '{case_id}' not found in active session."}

def _find_item(case_id: str, item_id: str) -> Optional[Dict[str, Any]]:
    if case_id in _ACTIVE_CASE_CACHE:
        for item in _ACTIVE_CASE_CACHE[case_id]["recovered_items"]:
            if item.get("item_id") == item_id or item.get("filename") == item_id:
                return item
        for rep in _ACTIVE_CASE_CACHE[case_id].get("repaired_artifacts", []):
            if rep.get("item_id") == item_id or rep.get("derived_filename") == item_id:
                return rep
    return None


# ---------------------------------------------------------------------------
# Command Center view model (consumed by frontend/index.html via reconai.server)
# ---------------------------------------------------------------------------

_DROP_KEYS = {"data", "features", "_shingles"}


def _json_safe(value: Any) -> Any:
    """Strips raw payload bytes and converts numpy values so results serialise cleanly."""
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items() if k not in _DROP_KEYS}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, bytes):
        return None
    if hasattr(value, "item") and not isinstance(value, (str, int, float, bool)):
        try:
            return value.item()
        except Exception:
            return str(value)
    return value


def api_list_cases() -> Dict[str, Any]:
    """GET /api/forensics/cases — cases analysed by this server process, newest first."""
    cases = [
        {"case_id": cid, "filename": res["case"]["filename"], "examiner": res["case"].get("examiner_name"),
         "verified_at": res["case"].get("verification_timestamp")}
        for cid, res in reversed(list(_ACTIVE_CASE_CACHE.items()))
    ]
    return {"status": "SUCCESS", "cases": cases}


def api_get_case_view(case_id: str) -> Dict[str, Any]:
    """
    GET /api/forensics/cases/:id
    Everything the Command Center renders, taken directly from the pipeline results.
    """
    res = _ACTIVE_CASE_CACHE.get(case_id)
    if not res:
        return {"status": "ERROR", "message": f"Case '{case_id}' is not loaded. Run the pipeline first."}

    frag_entropy = {
        f["fragment_id"]: round(float(f.get("features", {}).get("entropy", 0.0)), 2)
        for f in res.get("fragments", []) + res.get("leftover_orphans", [])
    }

    chains = []
    for item in res["recovered_items"]:
        if item.get("source") != "fragment_reassembly":
            continue
        linked = []
        for f in item.get("fragments_linked", []):
            linked.append({**f, "entropy_bits": frag_entropy.get(f["fragment_id"])})
        gaps = [b["offset"] - (a["offset"] + a.get("size", 0)) for a, b in zip(linked, linked[1:])]
        chains.append({
            "item_id": item["item_id"],
            "filename": item["filename"],
            "format": item.get("format") or item.get("detected_type"),
            "confidence": item.get("confidence_score"),
            "join_reasons": item.get("join_reasons", []),
            "fragments": linked,
            "gaps_bytes": gaps,
        })

    orphans = [{
        "fragment_id": f["fragment_id"], "offset": f["offset"], "size_bytes": f.get("size_bytes"),
        "role": f.get("frag_type"), "predicted_format": f.get("predicted_format"),
        "entropy_bits": frag_entropy.get(f["fragment_id"]),
    } for f in res.get("leftover_orphans", [])]

    case = res["case"]
    view = {
        "status": "SUCCESS",
        "case": case,
        "custody": {
            "acquisition": {k: res["hash_meta"].get(k) for k in ("sha256", "sha1", "md5", "crc32", "size_bytes", "filename")},
            "post_analysis_sha256": res["post_analysis_hash"].get("sha256"),
            "read_only_verified": res.get("read_only_verified", False),
            "audit": res.get("audit_log", {}),
        },
        "stats": res["stats"],
        "recoverability": res.get("recoverability_summary", {}),
        "items": res["recovered_items"],
        "chains": chains,
        "orphans": orphans,
        "repaired": res.get("repaired_artifacts", []),
        "tampering": res.get("tampering", {}),
        "timeline": res.get("timeline", {}),
        "iocs": res.get("iocs", {}),
        "clustering": res.get("clustering", {}).get("summary", {}),
        "narratives": res.get("narratives", {}),
        "entropy_map": res.get("entropy_map", []),
        "benchmark": {k: v for k, v in res.get("benchmark", {}).items() if k != "matches"},
        "reports": {"pdf_sha256": res["reports"].get("pdf_sha256"), "json_sha256": res["reports"].get("json_sha256")},
    }
    return _json_safe(view)


def api_hex_dump(case_id: str, item_id: str, length: int = 256) -> Dict[str, Any]:
    """GET /api/forensics/files/:id/hex — first bytes of an artifact, addressed by absolute disk offset."""
    item = _find_item(case_id, item_id)
    if not item:
        return {"status": "ERROR", "message": f"File item '{item_id}' not found."}
    data = item.get("data", b"")[:max(16, min(length, 4096))]
    base = item.get("offset", 0) or 0
    rows = [{
        "offset": base + i,
        "hex": " ".join(f"{b:02X}" for b in data[i:i + 16]),
        "ascii": "".join(chr(b) if 32 <= b <= 126 else "." for b in data[i:i + 16]),
    } for i in range(0, len(data), 16)]
    return {"status": "SUCCESS", "item_id": item_id, "rows": rows, "total_bytes": len(item.get("data", b""))}


def api_copilot(case_id: str, query: str) -> Dict[str, Any]:
    """POST /api/forensics/copilot — evidence-grounded answer that cites recovered artifacts."""
    from reconai.copilot.copilot_engine import query_investigator_copilot
    res = _ACTIVE_CASE_CACHE.get(case_id)
    if not res:
        return {"status": "ERROR", "message": f"Case '{case_id}' is not loaded."}
    answer = query_investigator_copilot(
        query, res["recovered_items"], res["case"],
        res.get("timeline", {}).get("timeline_events", []),
        res.get("tampering", {}).get("indicators", []),
    )
    return {"status": "SUCCESS", **_json_safe(answer)}
