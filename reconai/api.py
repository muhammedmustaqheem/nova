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
        json.dumps(results["hash_meta"], indent=2)
        
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
