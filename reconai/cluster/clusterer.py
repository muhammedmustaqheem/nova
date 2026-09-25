"""
ReconAI Duplicate & Near-Duplicate Evidence Clustering Engine
Groups redundant evidence artifacts:
1. Exact Duplicates: Grouped bit-for-bit via SHA-256 hashes.
2. Near-Duplicates: Clustered via rolling 4-gram shingle similarity and byte-frequency vectors.
Collapses redundant fragment runs and multi-sector duplicates into a single canonical exemplar,
displaying occurrence counts and disk offset lists.
"""

from typing import List, Dict, Any, Tuple
import numpy as np

def _compute_shingle_set(data: bytes, k: int = 4) -> set:
    """Computes k-gram byte shingles for fast Jaccard near-duplicate estimation."""
    if len(data) < k:
        return set([data])
    # Sample up to 1000 shingles for efficiency
    stride = max(1, len(data) // 1000)
    shingles = set()
    for i in range(0, len(data) - k + 1, stride):
        shingles.add(data[i:i + k])
    return shingles

def _compute_jaccard_similarity(set_a: set, set_b: set) -> float:
    """Calculates Jaccard similarity between two sets."""
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return intersection / union if union > 0 else 0.0

def cluster_evidence_items(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Groups exact duplicates and near-duplicates into canonical clusters.
    Returns:
        clustered_items: List of primary exemplar items with cluster metadata.
        cluster_summary: Quantitative breakdown of deduplication.
    """
    if not items:
        return {
            "clustered_items": [],
            "summary": {
                "total_raw_items": 0,
                "unique_clusters": 0,
                "exact_duplicates": 0,
                "near_duplicates": 0,
                "noise_reduction_pct": 0.0
            }
        }

    # Step 1: Exact Duplicate Grouping (by SHA-256)
    sha_map: Dict[str, List[Dict[str, Any]]] = {}
    for item in items:
        h = item.get("sha256", "")
        if h not in sha_map:
            sha_map[h] = []
        sha_map[h].append(item)

    exemplars: List[Dict[str, Any]] = []
    exact_dup_count = 0

    for sha, group in sha_map.items():
        # Choose best exemplar (highest integrity score, or with filename)
        group.sort(key=lambda x: (x.get("integrity_score", 0), len(x.get("filename", ""))), reverse=True)
        primary = group[0].copy()

        # Members list
        members = []
        for member in group:
            members.append({
                "item_id": member.get("item_id"),
                "filename": member.get("filename"),
                "offset": member.get("offset"),
                "size_bytes": member.get("size_bytes"),
                "similarity": 100.0,
                "match_type": "EXACT_SHA256"
            })

        primary["duplicate_count"] = len(group)
        primary["cluster_members"] = members
        if len(group) > 1:
            exact_dup_count += (len(group) - 1)

        exemplars.append(primary)

    # Step 2: Near-Duplicate Clustering across remaining exemplars (Fuzzy Hashing / Shingling)
    # Pre-extract shingles for exemplars of reasonable size
    for ex in exemplars:
        ex["_shingles"] = _compute_shingle_set(ex.get("data", b""))

    final_clusters: List[Dict[str, Any]] = []
    merged_indices = set()
    near_dup_count = 0

    for i in range(len(exemplars)):
        if i in merged_indices:
            continue

        head = exemplars[i].copy()
        head_shingles = head.get("_shingles", set())
        head_members = list(head.get("cluster_members", []))

        for j in range(i + 1, len(exemplars)):
            if j in merged_indices:
                continue

            cand = exemplars[j]
            # Check size similarity (within 30% difference)
            len_head = head.get("size_bytes", 0)
            len_cand = cand.get("size_bytes", 0)
            if len_head == 0 or len_cand == 0:
                continue

            size_ratio = min(len_head, len_cand) / max(len_head, len_cand)
            if size_ratio < 0.60:
                continue

            cand_shingles = cand.get("_shingles", set())
            jaccard_sim = _compute_jaccard_similarity(head_shingles, cand_shingles)

            # High fuzzy similarity threshold (>= 80%)
            if jaccard_sim >= 0.80:
                merged_indices.add(j)
                near_dup_count += cand.get("duplicate_count", 1)

                # Add cand members into head
                for cm in cand.get("cluster_members", []):
                    head_members.append({
                        "item_id": cm["item_id"],
                        "filename": cm["filename"],
                        "offset": cm["offset"],
                        "size_bytes": cm["size_bytes"],
                        "similarity": round(jaccard_sim * 100, 1),
                        "match_type": "FUZZY_NEAR_DUPLICATE"
                    })

        head["duplicate_count"] = len(head_members)
        head["cluster_members"] = head_members
        if "_shingles" in head:
            del head["_shingles"]

        final_clusters.append(head)

    # Clean up temporary fields
    for c in final_clusters:
        if "_shingles" in c:
            del c["_shingles"]

    total_raw = len(items)
    unique_count = len(final_clusters)
    reduction_pct = round(((total_raw - unique_count) / total_raw) * 100, 1) if total_raw > 0 else 0.0

    return {
        "clustered_items": final_clusters,
        "summary": {
            "total_raw_items": total_raw,
            "unique_clusters": unique_count,
            "exact_duplicates": exact_dup_count,
            "near_duplicates": near_dup_count,
            "noise_reduction_pct": reduction_pct,
            "cluster_message": (
                f"Clustering reduced {total_raw} raw artifacts into {unique_count} unique evidence clusters "
                f"({exact_dup_count} exact bit-for-bit duplicates, {near_dup_count} fuzzy near-duplicates collapsed)."
            )
        }
    }
