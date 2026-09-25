"""
ReconAI Ground-Truth Benchmarking Engine
Evaluates recovery performance against ground_truth.json:
Computes Recall, Precision, Fragment Reassembly Accuracy, and Integrity Classification Accuracy.
"""

import os
import json
from typing import Dict, Any, List

def evaluate_ground_truth(recovered_items: List[Dict[str, Any]], ground_truth_path: str) -> Dict[str, Any]:
    """
    Evaluates pipeline recovery results against the ground truth manifest.
    Returns quantitative precision, recall, and reassembly scores.
    """
    if not os.path.exists(ground_truth_path):
        return {"status": "NO_GROUND_TRUTH", "message": "Ground truth manifest not found."}

    with open(ground_truth_path, 'r') as f:
        gt_data = json.load(f)

    gt_files = gt_data.get("files", [])
    if not gt_files:
        return {"status": "EMPTY_GROUND_TRUTH"}

    recovered_hashes = {item["sha256"].lower(): item for item in recovered_items if item.get("sha256")}
    recovered_names = {item["filename"].lower(): item for item in recovered_items}

    matched_gt = []
    unmatched_gt = []
    reassembly_matches = 0
    reassembly_total = 0
    integrity_matches = 0

    for gf in gt_files:
        expected_sha = gf.get("sha256", "").lower()
        fn = gf.get("filename", "").lower()
        is_frag = gf.get("is_fragmented", False)
        expected_intact = gf.get("expected_integrity", "INTACT")

        if is_frag:
            reassembly_total += 1

        # Check for hash match or filename match
        match = recovered_hashes.get(expected_sha)
        if not match:
            # Check filename without leading underscore
            clean_fn = fn.lstrip('_')
            for r_fn, r_item in recovered_names.items():
                if clean_fn in r_fn or r_fn.lstrip('_') == clean_fn:
                    match = r_item
                    break

        if match:
            matched_gt.append({
                "gt_filename": gf.get("filename"),
                "gt_category": gf.get("category"),
                "expected_integrity": expected_intact,
                "recovered_filename": match.get("filename"),
                "recovered_sha256": match.get("sha256"),
                "recovered_status": match.get("integrity_status"),
                "recovered_score": match.get("integrity_score"),
                "source": match.get("source")
            })
            if is_frag and match.get("sha256", "").lower() == expected_sha:
                reassembly_matches += 1
            if match.get("integrity_status") == expected_intact:
                integrity_matches += 1
        else:
            unmatched_gt.append(gf)

    total_gt = len(gt_files)
    recall_pct = round((len(matched_gt) / total_gt) * 100, 1) if total_gt > 0 else 0.0
    precision_pct = round((len(matched_gt) / len(recovered_items)) * 100, 1) if recovered_items else 0.0
    reassembly_acc = round((reassembly_matches / reassembly_total) * 100, 1) if reassembly_total > 0 else 100.0
    integrity_acc = round((integrity_matches / len(matched_gt)) * 100, 1) if matched_gt else 0.0

    return {
        "status": "SUCCESS",
        "case_id": gt_data.get("case_id", "RECONAI-BENCHMARK"),
        "total_ground_truth": total_gt,
        "total_recovered": len(recovered_items),
        "ground_truth_recovered": len(matched_gt),
        "recall_score": recall_pct,
        "precision_score": precision_pct,
        "reassembly_accuracy": reassembly_acc,
        "integrity_classification_accuracy": integrity_acc,
        "matches": matched_gt,
        "missed": unmatched_gt
    }
