"""
ReconAI AI Fragment Reconstruction - Compatibility Wrapper
Routes all reassembly requests through the enhanced graph-based fragment_engine.
"""

from reconai.reassemble.fragment_engine import (
    calculate_entropy,
    compute_fragment_features,
    score_fragment_pair,
    reassemble_fragments
)

__all__ = [
    "calculate_entropy",
    "compute_fragment_features",
    "score_fragment_pair",
    "reassemble_fragments"
]
