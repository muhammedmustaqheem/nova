"""
ReconAI Forensic Intelligence Layer Unit Tests
Tests:
 - Investigator Copilot Engine
 - What-If Reconstruction Simulator
 - Evidence Impact Score (0-100)
 - Evidence DNA Fingerprint Profile
"""

import unittest
from reconai.classify.classifier import compute_evidence_impact_score, generate_evidence_dna
from reconai.copilot.copilot_engine import query_investigator_copilot
from reconai.reassemble.whatif_simulator import simulate_whatif_chain

class TestIntelligenceLayer(unittest.TestCase):

    def setUp(self):
        self.mock_items = [
            {
                "item_id": "upload_0001",
                "filename": "_creds.env",
                "category": "🔑 Credentials & Access Keys",
                "integrity_status": "INTACT",
                "integrity_score": 100.0,
                "confidence_score": 100.0,
                "priority_score": 95.0,
                "technical_priority": "P1 — HIGH PRIORITY",
                "recoverability_bucket": "FULLY RECOVERABLE",
                "content_preview": "AKIA1234567890123456 DB_PASS=secret",
                "offset": 2048,
                "size_bytes": 128,
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "is_deleted": True,
                "is_user_file": True
            },
            {
                "item_id": "upload_0002",
                "filename": "auth.log",
                "category": "⚙️ System & Attack Logs",
                "integrity_status": "INTACT",
                "integrity_score": 100.0,
                "confidence_score": 100.0,
                "priority_score": 80.0,
                "technical_priority": "P1 — HIGH PRIORITY",
                "recoverability_bucket": "FULLY RECOVERABLE",
                "content_preview": "Failed password for root from 198.51.100.23 port 22",
                "offset": 4096,
                "size_bytes": 512,
                "sha256": "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2",
                "is_deleted": False,
                "is_user_file": False
            }
        ]

    def test_evidence_impact_score(self):
        item = self.mock_items[0]
        res = compute_evidence_impact_score(item)
        self.assertIn("score", res)
        self.assertGreaterEqual(res["score"], 0)
        self.assertLessEqual(res["score"], 100)
        self.assertIn("breakdown", res)

    def test_evidence_dna_generation(self):
        item = self.mock_items[0]
        dna = generate_evidence_dna(item)
        self.assertEqual(dna["artifact_id"], "upload_0001")
        self.assertEqual(dna["source_offset_hex"], "0x00000800")
        self.assertEqual(dna["technical_priority"], "P1 — HIGH PRIORITY")

    def test_investigator_copilot_ip_query(self):
        res = query_investigator_copilot("198.51.100.23", self.mock_items, {"case_id": "CASE-TEST"})
        self.assertIn("[OBSERVED]", res["answer"])
        self.assertIn("upload_0002", res["citations"])

    def test_investigator_copilot_priority_query(self):
        res = query_investigator_copilot("Why is this artifact P1?", self.mock_items, {"case_id": "CASE-TEST"})
        self.assertIn("[DERIVED]", res["answer"])
        self.assertIn("upload_0001", res["citations"])

    def test_whatif_reconstruction_simulator(self):
        frag1 = {"fragment_id": "f1", "offset": 1024, "data": b"\xFF\xD8\xFF\xE0" + b"A"*100, "predicted_format": "JPEG"}
        frag2 = {"fragment_id": "f2", "offset": 2048, "data": b"A"*100 + b"\xFF\xD9", "predicted_format": "JPEG"}
        sim = simulate_whatif_chain([frag1, frag2])
        self.assertIn("candidate_a", sim)
        self.assertGreaterEqual(sim["candidate_a"]["confidence"], 0.0)

if __name__ == "__main__":
    unittest.main()
