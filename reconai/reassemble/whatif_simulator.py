"""
ReconAI Recovery What-If Reconstruction Simulator
Allows investigators to simulate excluding/including fragments or comparing candidate fragment chains.
Calculates confidence, integrity, and decoder validation changes dynamically.
"""

from typing import Dict, Any, List, Tuple
from reconai.reassemble.fragment_engine import score_fragment_pair, _verify_chain_structure, compute_fragment_features

def simulate_whatif_chain(
    candidate_a_fragments: List[Dict[str, Any]],
    candidate_b_fragments: List[Dict[str, Any]] = None,
    target_format: str = "JPEG"
) -> Dict[str, Any]:
    """
    Simulates and compares two candidate fragment reconstruction chains.
    """
    def evaluate_chain(frags: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not frags:
            return {"confidence": 0.0, "valid": False, "msg": "No fragments in chain", "bytes_len": 0}

        combined_bytes = b"".join(f.get("data", b"") for f in frags)
        pair_scores = []
        all_reasons = []

        for f1, f2 in zip(frags, frags[1:]):
            if "features" not in f1:
                f1["features"] = compute_fragment_features(f1.get("data", b""))
            if "features" not in f2:
                f2["features"] = compute_fragment_features(f2.get("data", b""))
            score, reasons = score_fragment_pair(f1, f2)
            pair_scores.append(score)
            all_reasons.extend(reasons)

        avg_pair_score = sum(pair_scores) / max(1, len(pair_scores))
        is_valid, struct_score, struct_msg = _verify_chain_structure(target_format, combined_bytes)

        total_conf = round(((0.50 * struct_score) + (0.50 * avg_pair_score)) * 100, 1)

        return {
            "confidence": total_conf,
            "decoder_valid": is_valid,
            "decoder_msg": struct_msg,
            "pair_score_pct": round(avg_pair_score * 100, 1),
            "bytes_len": len(combined_bytes),
            "reasons": all_reasons
        }

    eval_a = evaluate_chain(candidate_a_fragments)
    eval_b = evaluate_chain(candidate_b_fragments) if candidate_b_fragments else None

    comparison = {
        "candidate_a": eval_a,
        "candidate_b": eval_b,
        "recommendation": "Candidate A is supported by stronger decoder evidence." if (not eval_b or eval_a["confidence"] >= eval_b["confidence"]) else "Candidate B achieves higher structural verification."
    }
    return comparison
