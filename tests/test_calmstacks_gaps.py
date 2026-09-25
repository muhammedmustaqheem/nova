"""
ReconAI CALMSTACKS Gap Audit Unit Tests
Verifies the implementation of missing requirements from the official CALMSTACKS 24H Hackathon problem statement.
"""

import unittest
import numpy as np
from reconai.classify.classifier import (
    classify_file_type, classify_primary_recovery_state,
    compute_technical_priority, compute_completeness_estimate
)
from reconai.reassemble.fragment_engine import (
    compute_fragment_features, score_fragment_pair, calculate_entropy
)

class TestCALMSTACKSGaps(unittest.TestCase):

    def test_fragment_relationship_scoring(self):
        """Verify feature extraction and pairwise relationship scoring."""
        frag_a = {
            "fragment_id": "frag_001",
            "offset": 1024,
            "data": b"\xFF\xD8\xFF\xE0\x00\x10JFIF" + b"\x41" * 500,
            "predicted_format": "JPEG"
        }
        frag_b = {
            "fragment_id": "frag_002",
            "offset": 2048,
            "data": b"\x41" * 500 + b"\xFF\xD9",
            "predicted_format": "JPEG"
        }
        
        score, reasons = score_fragment_pair(frag_a, frag_b)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)
        self.assertGreater(len(reasons), 0)
        # Reasons must contain transparent feature evidence
        self.assertTrue(any("similarity" in r.lower() or "continuity" in r.lower() or "compatibility" in r.lower() for r in reasons))

    def test_fragment_classification(self):
        """Verify 2-tier file type class & primary recovery state assignment."""
        item_pdf = {
            "filename": "document.pdf",
            "extension": ".pdf",
            "data": b"%PDF-1.4 header text",
            "source": "filesystem_undelete",
            "is_deleted": True,
            "integrity_status": "INTACT",
            "recoverability_bucket": "FULLY RECOVERABLE"
        }
        self.assertEqual(classify_file_type(item_pdf), "PDF")
        self.assertEqual(classify_primary_recovery_state(item_pdf), "DELETED")

        item_reconstructed = {
            "filename": "reassembled_jpeg_1024.jpg",
            "extension": ".jpg",
            "data": b"\xFF\xD8\xFF\xE0" + b"\x00" * 100 + b"\xFF\xD9",
            "source": "fragment_reassembly",
            "is_fragmented": True
        }
        self.assertEqual(classify_file_type(item_reconstructed), "IMAGE")
        self.assertEqual(classify_primary_recovery_state(item_reconstructed), "RECONSTRUCTED")

    def test_recovery_priority(self):
        """Verify Technical Recovery Priority assignment (P1, P2, P3)."""
        high_item = {
            "priority_score": 92.5,
            "confidence_score": 95.0,
            "integrity_status": "INTACT",
            "recoverability_bucket": "FULLY RECOVERABLE"
        }
        tag, score_str, reasons = compute_technical_priority(high_item)
        self.assertIn("P1", tag)
        self.assertGreater(len(reasons), 0)

        low_item = {
            "priority_score": 25.0,
            "confidence_score": 30.0,
            "integrity_status": "CORRUPTED",
            "recoverability_bucket": "UNRECOVERABLE"
        }
        tag_low, score_str_low, reasons_low = compute_technical_priority(low_item)
        self.assertIn("P3", tag_low)

    def test_data_completeness(self):
        """Verify technical data completeness calculation."""
        full_item = {
            "integrity_status": "INTACT",
            "recoverability_bucket": "FULLY RECOVERABLE"
        }
        pct, basis = compute_completeness_estimate(full_item)
        self.assertEqual(pct, "100%")
        self.assertIn("verified", basis.lower())

        part_item = {
            "integrity_status": "PARTIAL",
            "recoverability_bucket": "PARTIALLY RECOVERABLE",
            "score_breakdown": {"recovery_ratio": 7}
        }
        pct_p, basis_p = compute_completeness_estimate(part_item)
        self.assertIn("%", pct_p)
        self.assertIn("truncated", basis_p.lower())

    def test_entropy_computation(self):
        """Verify Shannon entropy calculation on byte sequences."""
        zero_data = b"\x00" * 100
        self.assertEqual(calculate_entropy(zero_data), 0.0)

        high_entropy_data = bytes(range(256))
        self.assertAlmostEqual(calculate_entropy(high_entropy_data), 8.0, delta=0.1)

if __name__ == "__main__":
    unittest.main()
