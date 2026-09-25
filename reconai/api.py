"""
ReconAI Backend API Module & Controller
Provides standard RESTful forensic service functions and endpoints:
  - GET  /api/forensics/cases
  - GET  /api/forensics/cases/:id
  - POST /api/forensics/upload
  - POST /api/forensics/analyze
  - POST /api/forensics/recover
  - GET  /api/forensics/files
  - GET  /api/forensics/files/:id
  - GET  /api/forensics/files/:id/download
  - GET  /api/forensics/files/:id/preview
  - GET  /api/forensics/files/:id/hex
  - POST /api/forensics/copilot
  - GET  /api/forensics/report
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
from reconai.copilot.service import ask_copilot

# In-memory storage cache for active session items
_ACTIVE_CASE_CACHE: Dict[str, Any] = {}

def _ensure_active_case() -> Dict[str, Any]:
    """Ensures at least one active case (e.g. demo case) is loaded into cache.
    Only used when the caller didn't ask for a specific case_id — never as a
    substitute for a case_id that was requested but not found."""
    if _ACTIVE_CASE_CACHE:
        first_key = list(_ACTIVE_CASE_CACHE.keys())[0]
        return _ACTIVE_CASE_CACHE[first_key]

    demo_raw = os.path.join("data", "demo_evidence.raw")
    if not os.path.exists(demo_raw):
        os.makedirs("data", exist_ok=True)
        try:
            from scripts.make_test_image import generate_evidence_disk
            generate_evidence_disk(demo_raw, os.path.join("data", "ground_truth.json"))
        except Exception:
            pass

    if os.path.exists(demo_raw):
        results = run_recovery_pipeline(
            image_path=demo_raw,
            examiner_name="Demo Examiner (auto-generated case)",
            extraction_scope="Complete Forensic Triage"
        )
        c_id = results["case"]["case_id"]
        _ACTIVE_CASE_CACHE[c_id] = results
        return results

    return {}

def _resolve_case(case_id: Optional[str]) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    Resolves a case_id to (resolved_id, case_data).
    - No case_id given: bootstraps/returns whatever case is active (zero-config demo entry).
    - A specific case_id given: returns it only if it actually exists — never silently
      substitutes a different case, so a stale or mistyped case_id fails loudly instead
      of returning someone else's evidence.
    """
    if not case_id:
        data = _ensure_active_case()
        resolved_id = data.get("case", {}).get("case_id") if data else None
        return resolved_id, (data or None)

    if case_id not in _ACTIVE_CASE_CACHE and not _ACTIVE_CASE_CACHE:
        _ensure_active_case()  # cold start: populate cache, then check again below

    return case_id, _ACTIVE_CASE_CACHE.get(case_id)

def api_list_cases() -> List[Dict[str, Any]]:
    """
    GET /api/forensics/cases
    Returns list of all active or cached cases.
    """
    _ensure_active_case()
    case_list = []
    for c_id, data in _ACTIVE_CASE_CACHE.items():
        case_meta = data.get("case", {})
        hash_meta = data.get("hash_meta", {})
        stats = data.get("stats", {})
        case_list.append({
            "case_id": c_id,
            "evidence_id": case_meta.get("evidence_id", c_id),
            "examiner_name": case_meta.get("examiner_name", "Lead Examiner"),
            "evidence_filename": hash_meta.get("filename", "demo_evidence.raw"),
            "disk_size_bytes": hash_meta.get("size_bytes", 67108864),
            "sha256": hash_meta.get("sha256", ""),
            "created_at": case_meta.get("created_at", datetime.utcnow().isoformat()),
            "total_recovered": stats.get("total_recovered", len(data.get("recovered_items", [])))
        })
    return case_list

def api_get_case_view(case_id: str) -> Dict[str, Any]:
    """
    GET /api/forensics/cases/:id
    Returns complete sanitized case metadata, recoverability stats, tampering indicators, and timeline.
    """
    case_id, data = _resolve_case(case_id)
    if not data:
        return {"status": "ERROR", "message": f"Case '{case_id}' not found."}

    # Sanitize recovered items so heavy bytes aren't serialized in metadata JSON
    sanitized_items = []
    for item in data.get("recovered_items", []):
        sanitized_items.append({
            "item_id": item.get("item_id"),
            "friendly_title": item.get("friendly_title", item.get("filename")),
            "filename": item.get("filename"),
            "category": item.get("category"),
            "source": item.get("source"),
            "integrity_status": item.get("integrity_status"),
            "integrity_score": item.get("integrity_score"),
            "confidence_score": item.get("confidence_score", 100.0),
            "recoverability_bucket": item.get("recoverability_bucket"),
            "technical_priority": item.get("technical_priority"),
            "file_type_class": item.get("file_type_class"),
            "recovery_state": item.get("recovery_state"),
            "completeness_pct": item.get("completeness_pct"),
            "impact_score": item.get("impact_score"),
            "evidence_dna": item.get("evidence_dna"),
            "priority_score": item.get("priority_score"),
            "size_bytes": item.get("size_bytes"),
            "sha256": item.get("sha256"),
            "offset": item.get("offset"),
            "is_user_file": item.get("is_user_file", True),
            "use_case": item.get("use_case", ""),
            "join_reasons": item.get("join_reasons", []),
            "fragments_linked": item.get("fragments_linked", []),
            "is_fragmented": item.get("is_fragmented", False)
        })

    audit = data.get("audit_log", {})
    return {
        "status": "SUCCESS",
        "case_id": case_id,
        "case": data.get("case", {}),
        "hash_meta": data.get("hash_meta", {}),
        "stats": data.get("stats", {}),
        "recoverability_summary": data.get("recoverability_summary", {}),
        # The pipeline's key is "tampering" — kept as "tampering_summary" here too since
        # the frontend already reads that name.
        "tampering_summary": data.get("tampering", {}),
        "timeline": data.get("timeline", {}),
        "custody": {
            "read_only_verified": data.get("read_only_verified", False),
            "acquisition_sha256": data.get("hash_meta", {}).get("sha256"),
            "post_analysis_sha256": data.get("post_analysis_hash", {}).get("sha256"),
            "chain_integrity": audit.get("chain_integrity"),
            "total_audit_events": audit.get("total_audit_events"),
            "examiner_name": data.get("case", {}).get("examiner_name"),
        },
        "iocs": data.get("iocs", {}),
        "narratives": data.get("narratives", {}),
        "benchmark": data.get("benchmark", {}),
        "recovered_items": sanitized_items
    }

ALLOWED_EVIDENCE_EXTENSIONS = {".raw", ".img", ".dd", ".bin", ".mem", ".dmp"}

def api_upload_image(file_bytes: bytes, filename: str, upload_dir: str = "data/uploads") -> Dict[str, Any]:
    """
    POST /api/forensics/upload
    Saves uploaded disk image (.raw, .img, .dd, .bin, .mem, .dmp) to working directory in read-only mode.
    """
    # Strip any directory components from a client-supplied filename before it touches
    # the filesystem — otherwise "../../reconai/api.py" would overwrite files outside
    # upload_dir. Only recognised evidence extensions are accepted.
    safe_name = os.path.basename((filename or "").strip().replace("\\", "/"))
    ext = os.path.splitext(safe_name)[1].lower()
    if not safe_name or ext not in ALLOWED_EVIDENCE_EXTENSIONS:
        return {"status": "ERROR", "message": f"Upload a disk image with one of these extensions: {', '.join(sorted(ALLOWED_EVIDENCE_EXTENSIONS))}"}

    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, safe_name)
    with open(file_path, "wb") as f:
        f.write(file_bytes)
    
    hash_info = compute_evidence_hash(file_path)
    return {
        "status": "SUCCESS",
        "message": f"Disk image uploaded and sealed successfully: {safe_name}",
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
    examiner_name: Optional[str] = None,
    scope: str = "Complete Forensic Triage"
) -> Dict[str, Any]:
    """
    POST /api/forensics/recover
    Executes end-to-end recovery pipeline (FS undelete, carving, AI reassembly, repair, triage).
    The examiner name is written into the chain-of-custody record and every exported
    report, so it must be supplied by the caller rather than defaulting to a fabricated
    identity — a made-up examiner on a custody record is a real forensic-integrity problem.
    """
    examiner_name = (examiner_name or "").strip()
    if not examiner_name:
        return {"status": "ERROR", "message": "Examiner name is required for chain of custody."}

    results = run_recovery_pipeline(
        image_path=image_path,
        case_id=case_id,
        examiner_name=examiner_name,
        extraction_scope=scope
    )
    
    c_id = results["case"]["case_id"]
    _ACTIVE_CASE_CACHE[c_id] = results
    
    base_recovery_dir = os.path.join("recovery", c_id.lower())
    for folder in ["original", "carved", "reconstructed", "repaired", "reports", "hashes", "logs"]:
        os.makedirs(os.path.join(base_recovery_dir, folder), exist_ok=True)
    
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
    _, data = _resolve_case(case_id)
    if not data:
        return {"status": "ERROR", "message": f"Case '{case_id}' not found.", "count": 0, "files": []}
    items = data.get("recovered_items", [])

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
            "friendly_title": item.get("friendly_title", item.get("filename")),
            "filename": item.get("filename"),
            "category": item.get("category"),
            "source": item.get("source"),
            "integrity_status": item.get("integrity_status"),
            "integrity_score": item.get("integrity_score"),
            "confidence_score": item.get("confidence_score", 100.0),
            "recoverability_bucket": item.get("recoverability_bucket"),
            "technical_priority": item.get("technical_priority"),
            "file_type_class": item.get("file_type_class"),
            "recovery_state": item.get("recovery_state"),
            "completeness_pct": item.get("completeness_pct"),
            "impact_score": item.get("impact_score"),
            "priority_score": item.get("priority_score"),
            "size_bytes": item.get("size_bytes"),
            "sha256": item.get("sha256"),
            "offset": item.get("offset"),
            "is_user_file": item.get("is_user_file", True),
            "join_reasons": item.get("join_reasons", []),
            "fragments_linked": item.get("fragments_linked", []),
            "is_fragmented": item.get("is_fragmented", False)
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
    
    meta = {k: v for k, v in item.items() if k != "data"}
    return {
        "status": "SUCCESS",
        "file": meta
    }

def api_hex_dump(case_id: str, item_id: str, length: int = 512) -> Dict[str, Any]:
    """
    GET /api/forensics/files/:id/hex
    Returns formatted hex dump snippet for file.
    """
    item = _find_item(case_id, item_id)
    if not item:
        return {"status": "ERROR", "message": f"Item '{item_id}' not found."}

    data = item.get("data", b"")
    hex_lines = []
    base_offset = item.get("offset", 0)
    for i in range(0, min(length, len(data)), 16):
        chunk = data[i:i + 16]
        hex_str = " ".join(f"{b:02X}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        hex_lines.append(f"{base_offset + i:08X}  {hex_str:<48}  |{ascii_str}|")

    return {
        "status": "SUCCESS",
        "item_id": item_id,
        "filename": item.get("filename"),
        "hex_lines": hex_lines
    }

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

def api_copilot_ask(case_id: str, prompt: str) -> Dict[str, Any]:
    """
    POST /api/copilot/ask or POST /api/forensics/copilot
    Executes evidence-grounded query using AI Provider abstraction and retrieval layer.
    """
    _, c_data = _resolve_case(case_id)
    if not c_data:
        return {"success": False, "answer": f"Case '{case_id}' not found. Run recovery on it first.",
                "citations": [], "evidence_count": 0, "grounded": False}

    return ask_copilot(question=prompt, case_data=c_data)

def api_get_report(case_id: str, report_format: str = "json") -> Dict[str, Any]:
    """
    GET /api/forensics/report
    Generates downloadable forensic report in JSON or PDF format.
    """
    _, res = _resolve_case(case_id)
    if not res:
        return {"status": "ERROR", "message": f"Case '{case_id}' not found."}
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

def _find_item(case_id: str, item_id: str) -> Optional[Dict[str, Any]]:
    _, c_data = _resolve_case(case_id)
    if not c_data:
        return None
    for item in c_data.get("recovered_items", []):
        if item.get("item_id") == item_id or item.get("filename") == item_id:
            return item
    for rep in c_data.get("repaired_artifacts", []):
        if rep.get("item_id") == item_id or rep.get("derived_filename") == item_id:
            return rep
    return None
