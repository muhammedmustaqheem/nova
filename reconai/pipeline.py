"""
ReconAI Unified Forensic Recovery & Intelligence Pipeline Orchestrator
Integrates all 12 advanced hackathon capabilities into an automated, strictly read-only workflow:
 1. Chain of Custody & Hash-Chained Audit Trail (ForensicAuditLog)
 2. Filesystem-Independent Signature Carving (JPEG, PNG, PDF, ZIP, SQLITE, EXE, MP4, TXT)
 3. AI Fragment Reconstruction Engine (Histogram Cosine Sim + Boundary Continuity + Graph Pathfinding)
 4. Structural Integrity & 4 Recoverability Buckets (Fully / Partially / Fragment / Unrecoverable)
 5. Automatic Partial Repair Engine (Reconstructed Derived Artifacts)
 6. 9-Class Content Classification & Scope-Aware Prioritization
 7. Ransomware & Anti-Forensics Tampering Detector (High Entropy Ciphers, Wipes, Extension Spoofs)
 8. Exact Duplicate & Near-Duplicate Fuzzy Clustering
 9. Multi-Source Timeline Reconstruction (EXIF, PDF, Office XML, Syslog, FS Tables)
10. Dual-Mode Plain-English Narrative Explainer (Simple vs Expert)
11. Comprehensive Court-Ready Report Generation (JSON & PDF with embedded seals)
12. Ground-Truth Benchmarking & SQLite Case Persistence
"""

import os
import hashlib
import logging
import platform
from datetime import datetime
from typing import Dict, Any, List, Callable, Optional

# Core Modules
from reconai.ingest.hasher import compute_evidence_hash
from reconai.ingest.custody_logger import ForensicAuditLog
from reconai.ingest.fs_reader import recover_filesystem
from reconai.carve.carver import carve_raw_image
from reconai.reassemble.fragment_engine import reassemble_fragments
from reconai.integrity.validator import validate_item_integrity, compute_recoverability_summary
from reconai.repair.repairer import repair_artifact
from reconai.classify.classifier import (
    classify_and_prioritize, get_file_friendly_meta, filter_items_by_scope,
    classify_file_type, classify_primary_recovery_state,
    compute_technical_priority, compute_completeness_estimate
)
from reconai.classify.ioc_extractor import aggregate_case_iocs
from reconai.tampering.tampering_detector import detect_tampering_indicators
from reconai.cluster.clusterer import cluster_evidence_items
from reconai.timeline.timeline_builder import build_forensic_timeline
from reconai.explain.explainer import generate_case_narrative, generate_item_explanation
from reconai.report.report_exporter import generate_json_report, generate_pdf_report
from reconai.benchmark import evaluate_ground_truth
from reconai.carve.entropy_map import generate_disk_entropy_map
from reconai.db.models import init_db, save_case, save_recovered_item, save_fragment

# pypdf logs every malformed xref it meets; damaged PDFs are expected input here
logging.getLogger("pypdf").setLevel(logging.ERROR)

def run_recovery_pipeline(
    image_path: str,
    case_id: Optional[str] = None,
    examiner_name: str = "Lead DFIR Examiner",
    extraction_scope: str = "Complete Forensic Triage",
    progress_callback: Optional[Callable[[str, float], None]] = None
) -> Dict[str, Any]:
    """
    Executes the complete forensic recovery & reconstruction pipeline.
    Supports both raw disk images (.raw, .img, .dd) and directories of user-uploaded evidence files.
    Strictly read-only evidence handling.
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Evidence target path not found: {image_path}")

    def update_progress(msg: str, progress: float):
        if progress_callback:
            progress_callback(msg, progress)

    # Initialize Local Database
    init_db()

    is_directory = os.path.isdir(image_path)

    # --- 1. INGESTION, PRIMARY SEAL & AUDIT LOG ---
    update_progress("Step 1/10: Ingesting evidence & initializing hash-chained audit log...", 0.08)
    
    hash_meta = compute_evidence_hash(image_path)

    if not case_id:
        case_id = f"CASE-{hash_meta['sha256'][:8].upper()}"
    evidence_id = f"EV-{hash_meta['sha256'][:6].upper()}"

    audit_log = ForensicAuditLog(
        case_id=case_id,
        evidence_id=evidence_id,
        examiner_name=examiner_name,
        initial_evidence_sha256=hash_meta["sha256"]
    )
    audit_log.log_action("EVIDENCE_INGEST_AND_INITIAL_SEAL", {
        "filename": hash_meta["filename"],
        "size_bytes": hash_meta["size_bytes"],
        "primary_sha256": hash_meta["sha256"],
        "read_only_flag": "O_RDONLY"
    })

    case_record = {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "examiner_name": examiner_name,
        "image_path": hash_meta["image_path"],
        "filename": hash_meta["filename"],
        "image_sha256": hash_meta["sha256"],
        "image_sha1": hash_meta.get("sha1", ""),
        "image_md5": hash_meta.get("md5", ""),
        "image_crc32": hash_meta.get("crc32", ""),
        "disk_size_bytes": hash_meta["size_bytes"],
        "intake_timestamp": hash_meta.get("timestamp_utc", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")),
        "created_at": datetime.utcnow().isoformat() + "Z",
        "tool_version": "ReconAI v1.2.0 (Forensic Engine)",
        "host_machine": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python_version": platform.python_version()
    }

    fs_items = []
    unique_carved = []
    orphan_fragments = []
    reassembled_files = []
    leftover_orphans = []

    if is_directory:
        # Direct User Evidence Directory Processing
        update_progress("Step 2/10: Processing uploaded evidence files & calculating SHA-256 seals...", 0.20)
        dir_files = [os.path.join(image_path, f) for f in sorted(os.listdir(image_path)) if not f.startswith('.')]
        for idx, fp in enumerate(dir_files):
            if os.path.isfile(fp):
                fn = os.path.basename(fp)
                with open(fp, 'rb') as f:
                    f_data = f.read()
                f_hash = hashlib.sha256(f_data).hexdigest()
                ext = os.path.splitext(fn)[1].lower()
                
                fs_items.append({
                    "item_id": f"upload_{idx+1:04d}",
                    "filename": fn,
                    "extension": ext,
                    "source": "filesystem_undelete",
                    "offset": 0,
                    "size_bytes": len(f_data),
                    "sha256": f_hash,
                    "data": f_data,
                    "is_deleted": False,
                    "is_fragmented": False
                })
    else:
        # --- 2. FILESYSTEM UNDELETE ---
        update_progress("Step 2/10: Parsing directory tables for deleted inodes (0xE5 markers)...", 0.18)
        fs_items = recover_filesystem(image_path)
        known_offsets = [item["offset"] for item in fs_items]
        known_hashes = {item["sha256"]: item for item in fs_items}
        audit_log.log_action("FILESYSTEM_UNDELETE_SCAN", {
            "recovered_inodes": len(fs_items),
            "target_offsets": known_offsets
        })

        # --- 3. FILESYSTEM-INDEPENDENT SIGNATURE CARVING ---
        update_progress("Step 3/10: Scanning raw unallocated bitstream for file signatures & orphan fragments...", 0.30)
        carved_items, orphan_fragments = carve_raw_image(image_path, known_offsets)

        # De-duplicate carved items against filesystem items
        for c in carved_items:
            c_hash = c["sha256"]
            if c_hash in known_hashes:
                known_hashes[c_hash]["dual_verified"] = True
            else:
                unique_carved.append(c)

        audit_log.log_action("SIGNATURE_CARVE_SCAN", {
            "total_carved": len(carved_items),
            "unique_unallocated": len(unique_carved),
            "orphan_fragments_captured": len(orphan_fragments)
        })

        # --- 4. AI FRAGMENT RECONSTRUCTION ENGINE ---
        update_progress("Step 4/10: AI Fragment Engine: evaluating byte histogram cosine similarity & graph reassembly...", 0.42)
        reassembled_files, leftover_orphans = reassemble_fragments(orphan_fragments)

        audit_log.log_action("AI_FRAGMENT_REASSEMBLY", {
            "fragments_processed": len(orphan_fragments),
            "chains_reassembled": len(reassembled_files),
            "leftover_orphans": len(leftover_orphans)
        })


    # Combine all recovered candidate artifacts
    all_artifacts = []
    for item in fs_items:
        item["confidence_score"] = 100.0
        all_artifacts.append(item)

    for item in unique_carved:
        item["confidence_score"] = 95.0
        all_artifacts.append(item)

    for item in reassembled_files:
        all_artifacts.append(item)

    # --- 5. INTEGRITY & 4 RECOVERABILITY BUCKETS ---
    update_progress("Step 5/10: Structural parser deep verification: assigning 4 Recoverability Buckets...", 0.54)
    for item in all_artifacts:
        val = validate_item_integrity(item["filename"], item["data"], item.get("extension", ""))
        item["integrity_status"] = val["status"]
        item["integrity_score"] = val["score"]
        item["recoverability_bucket"] = val["recoverability_bucket"]
        item["score_rationale"] = val.get("score_rationale", "")
        item["score_breakdown"] = val.get("score_breakdown", {})
        item["details"] = val

    recoverability_summary = compute_recoverability_summary(all_artifacts)
    audit_log.log_action("RECOVERABILITY_BUCKETING", {
        "fully_recoverable": recoverability_summary["fully_recoverable"],
        "partially_recoverable": recoverability_summary["partially_recoverable"],
        "fragment_only": recoverability_summary["fragment_only"],
        "unrecoverable": recoverability_summary["unrecoverable"],
        "restoration_pct": recoverability_summary["realistic_restoration_pct"]
    })

    # --- 6. AUTOMATED PARTIAL REPAIR ENGINE ---
    update_progress("Step 6/10: Automated partial repair: salvaging JPEG headers, broken ZIP members & PDF streams...", 0.65)
    repaired_artifacts = []
    for item in all_artifacts:
        repaired = repair_artifact(item)
        if repaired:
            repaired_artifacts.append(repaired)

    audit_log.log_action("AUTOMATED_PARTIAL_REPAIR", {
        "derived_artifacts_created": len(repaired_artifacts),
        "repair_types": list(set(r["repair_type"] for r in repaired_artifacts))
    })

    # --- 7. CLASSIFICATION & SCOPE PRIORITIZATION (9 CLASSES + P1/P2/P3 PRIORITY) ---
    update_progress("Step 7/10: Classifying 9 content categories & computing P1/P2/P3 priority scores...", 0.74)
    repaired_parent_ids = {r["parent_item_id"] for r in repaired_artifacts}
    for item in all_artifacts:
        cat, prio, preview, scope = classify_and_prioritize(item, scope=extraction_scope)
        f_meta = get_file_friendly_meta(item["filename"], cat, preview)
        item["category"] = cat
        item["priority_score"] = prio
        item["content_preview"] = preview
        item["artifact_scope"] = scope
        item["is_user_file"] = (scope == "User Evidence File")
        item["friendly_title"] = f_meta["friendly_title"]
        item["use_case"] = f_meta["use_case"]
        item["naming_note"] = f_meta["naming_note"]
        item["case_id"] = case_id
        item["created_at"] = datetime.utcnow().isoformat() + "Z"

        # CALMSTACKS Gap Fields
        item["file_type_class"] = classify_file_type(item)
        item["recovery_state"] = classify_primary_recovery_state(item, is_repaired=(item["item_id"] in repaired_parent_ids))
        tech_prio, p_score_str, tech_reasons = compute_technical_priority(item)
        item["technical_priority"] = tech_prio
        item["technical_priority_reasons"] = tech_reasons
        comp_pct, comp_basis = compute_completeness_estimate(item)
        item["completeness_pct"] = comp_pct
        item["completeness_basis"] = comp_basis

        # Item-level Dual Explanation
        item["explanations"] = generate_item_explanation(item)


    all_artifacts.sort(key=lambda x: x["priority_score"], reverse=True)
    user_evidence_files = [a for a in all_artifacts if a.get("artifact_scope") == "User Evidence File"]
    system_files = [a for a in all_artifacts if a.get("artifact_scope") == "System / OS File"]

    # Active Scope Filtered Collection
    scoped_artifacts = filter_items_by_scope(all_artifacts, extraction_scope)

    audit_log.log_action("SEMANTIC_CLASSIFICATION_AND_TRIAGE", {
        "scope_selected": extraction_scope,
        "user_evidence_count": len(user_evidence_files),
        "system_files_count": len(system_files),
        "scoped_results_count": len(scoped_artifacts)
    })

    # --- 8. RANSOMWARE & ANTI-FORENSICS DETECTION ---
    update_progress("Step 8/10: Scanning for evidence tampering: high-entropy ciphers, wipes & spoofed extensions...", 0.82)
    tampering_results = detect_tampering_indicators(image_path, all_artifacts)
    audit_log.log_action("TAMPERING_AND_ANTI_FORENSICS_AUDIT", {
        "tampering_detected": tampering_results["tampering_detected"],
        "total_indicators": tampering_results["total_indicators"]
    })

    # --- 9. DEDUPLICATION & NEAR-DUPLICATE CLUSTERING ---
    update_progress("Step 9/10: Clustering exact duplicates and near-duplicate fuzzy shingles...", 0.89)
    clustering_results = cluster_evidence_items(all_artifacts)
    audit_log.log_action("DEDUPLICATION_CLUSTERING", clustering_results["summary"])

    # --- 10. TIMELINE RECONSTRUCTION & EXPLANATIONS ---
    update_progress("Step 10/10: Building unified timeline & generating dual-mode explanations...", 0.94)
    timeline_results = build_forensic_timeline(all_artifacts, case_record)
    ioc_results = aggregate_case_iocs(all_artifacts)

    # Compile executive summary stats
    intact_count = sum(1 for a in all_artifacts if a["integrity_status"] == "INTACT")
    partial_count = sum(1 for a in all_artifacts if a["integrity_status"] == "PARTIAL")
    corrupt_count = sum(1 for a in all_artifacts if a["integrity_status"] == "CORRUPTED")

    p1_count = sum(1 for a in all_artifacts if "P1" in a.get("technical_priority", ""))
    p2_count = sum(1 for a in all_artifacts if "P2" in a.get("technical_priority", ""))
    p3_count = sum(1 for a in all_artifacts if "P3" in a.get("technical_priority", ""))

    stats = {
        "total_recovered": len(all_artifacts),
        "user_evidence_count": len(user_evidence_files),
        "system_files_count": len(system_files),
        "scoped_count": len(scoped_artifacts),
        "filesystem_recovered": len(fs_items),
        "signature_carved": len(unique_carved),
        "reassembled": len(reassembled_files),
        "intact": intact_count,
        "partial": partial_count,
        "corrupted": corrupt_count,
        "p1_high_priority": p1_count,
        "p2_medium_priority": p2_count,
        "p3_low_priority": p3_count,
        "orphan_fragments": len(orphan_fragments),
        "derived_repairs": len(repaired_artifacts),
        "tampering_alerts": tampering_results["total_indicators"],
        "unique_clusters": clustering_results["summary"]["unique_clusters"],
        "timeline_events": timeline_results["total_events"],
        "iocs_found": ioc_results["total_iocs_found"]
    }

    # Case-level Dual Mode Narrative
    narratives = generate_case_narrative(
        case_record, stats, recoverability_summary, tampering_results, all_artifacts
    )

    # --- POST-ANALYSIS VERIFICATION: PROVE STRICT READ-ONLY INTEGRITY ---
    post_hash_meta = compute_evidence_hash(image_path)
    is_read_only_verified = (post_hash_meta["sha256"].lower() == hash_meta["sha256"].lower())
    case_record["post_analysis_sha256"] = post_hash_meta["sha256"]
    case_record["read_only_verified"] = is_read_only_verified
    case_record["verification_timestamp"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    audit_log.log_action("POST_ANALYSIS_READ_ONLY_VERIFICATION", {
        "post_sha256": post_hash_meta["sha256"],
        "is_match": is_read_only_verified,
        "status": "MATCH" if is_read_only_verified else "MISMATCH"
    })

    audit_summary = audit_log.get_summary()

    # Ground-Truth Benchmarking
    gt_path = os.path.join(os.path.dirname(image_path), "ground_truth.json")
    benchmark_metrics = evaluate_ground_truth(all_artifacts, gt_path)

    # Sector Entropy Map
    entropy_map = generate_disk_entropy_map(image_path)

    # Save to SQLite Database
    case_record["total_recovered"] = len(all_artifacts)
    save_case(case_record)
    for item in all_artifacts:
        save_recovered_item(item)
    for frag in orphan_fragments:
        frag["case_id"] = case_id
        save_fragment(frag)

    # Generate Reports
    json_report_str, report_sha = generate_json_report(
        case_record, stats, recoverability_summary, tampering_results,
        timeline_results, audit_summary["entries"], all_artifacts,
        extra_sections={
            "extracted_iocs": ioc_results,
            "derived_artifacts": [
                {k: v for k, v in r.items() if k != "data"} for r in repaired_artifacts
            ],
            "deduplication": clustering_results["summary"],
            "ground_truth_benchmark": {k: v for k, v in benchmark_metrics.items() if k != "matches"},
        }
    )
    pdf_report_bytes, pdf_sha = generate_pdf_report(
        case_record, stats, recoverability_summary, tampering_results,
        timeline_results, all_artifacts
    )

    update_progress("Forensic reconstruction complete!", 1.0)

    return {
        "case": case_record,
        "hash_meta": hash_meta,
        "post_analysis_hash": post_hash_meta,
        "read_only_verified": is_read_only_verified,
        "audit_log": audit_summary,
        "recovered_items": all_artifacts,
        "scoped_items": scoped_artifacts,
        "user_evidence_items": user_evidence_files,
        "system_file_items": system_files,
        "repaired_artifacts": repaired_artifacts,
        "recoverability_summary": recoverability_summary,
        "tampering": tampering_results,
        "clustering": clustering_results,
        "timeline": timeline_results,
        "narratives": narratives,
        "reports": {
            "json_str": json_report_str,
            "json_sha256": report_sha,
            "pdf_bytes": pdf_report_bytes,
            "pdf_sha256": pdf_sha
        },
        "fragments": orphan_fragments,
        "leftover_orphans": leftover_orphans,
        "iocs": ioc_results,
        "benchmark": benchmark_metrics,
        "entropy_map": entropy_map,
        "stats": stats
    }
