"""
ReconAI - End-to-End Automated Pipeline Test Suite
Tests all 12 advanced hackathon capabilities against ground-truth synthetic evidence.
"""

import os
import unittest
import hashlib

from reconai.pipeline import run_recovery_pipeline
from reconai.search.semantic_search import search_recovered_items
from reconai.graph.graph_builder import build_forensic_graph, generate_interactive_pyvis_html
from reconai.ingest.hasher import compute_evidence_hash, verify_evidence_integrity
from scripts.make_test_image import generate_evidence_disk

class TestReconAIPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cls.raw_path = os.path.join(cls.base_dir, "data", "demo_evidence.raw")
        cls.gt_path = os.path.join(cls.base_dir, "data", "ground_truth.json")

        # Generate fresh demo disk
        generate_evidence_disk(cls.raw_path, cls.gt_path)

        # Execute recovery pipeline once for test suite
        cls.results = run_recovery_pipeline(cls.raw_path)
        cls.items = cls.results["recovered_items"]
        cls.stats = cls.results["stats"]
        cls.case = cls.results["case"]

    def test_feature1_read_only_hashing(self):
        """Feature 1: Read-only evidence ingest & SHA-256 seal verification."""
        hash_info = compute_evidence_hash(self.raw_path)
        self.assertEqual(hash_info["size_bytes"], 64 * 1024 * 1024)
        self.assertTrue(len(hash_info["sha256"]) == 64)
        self.assertTrue(verify_evidence_integrity(self.raw_path, hash_info["sha256"]))

    def test_feature1_hash_chained_audit_log(self):
        """Feature 1: Append-only hash-chained forensic audit trail."""
        self.assertIn("audit_log", self.results)
        audit = self.results["audit_log"]
        self.assertEqual(audit["chain_integrity"], "VERIFIED_TAMPER_FREE")
        self.assertGreater(audit["total_audit_events"], 5)
        # Check genesis block
        self.assertEqual(audit["entries"][0]["step"], 0)
        self.assertEqual(audit["entries"][0]["prev_hash"], "0" * 64)

    def test_feature2_dual_recovery(self):
        """Feature 2: Dual recovery discovers filesystem deleted files + raw signature carved files."""
        fs_files = [i for i in self.items if i["source"] == "filesystem_undelete"]
        carved_files = [i for i in self.items if i["source"] == "signature_carving"]

        self.assertGreater(len(fs_files), 0, "Filesystem undelete should recover deleted entries")
        self.assertGreater(len(carved_files), 0, "Signature carver should recover unallocated entries")

        # Check deleted env file recovered
        env_files = [i for i in self.items if "env" in i["filename"].lower() or "cred" in i["filename"].lower()]
        self.assertGreater(len(env_files), 0, "Deleted credentials file must be recovered")

    def test_feature3_fragment_reconstruction(self):
        """Feature 3: AI Fragment Reconstruction reassembles non-contiguous chunks with confidence score and reasons."""
        reassembled = [i for i in self.items if i["source"] == "fragment_reassembly"]
        self.assertGreater(len(reassembled), 0, "Fragment reassembler must recover split fragments")

        target = reassembled[0]
        self.assertIn("confidence_score", target)
        self.assertGreaterEqual(target["confidence_score"], 60.0)
        self.assertEqual(target["integrity_status"], "INTACT")
        self.assertIn("join_reasons", target)
        self.assertGreater(len(target["join_reasons"]), 0)

    def test_feature4_integrity_and_recoverability_buckets(self):
        """Feature 4: Structural file integrity and 4 Recoverability Buckets."""
        self.assertIn("recoverability_summary", self.results)
        rec_summary = self.results["recoverability_summary"]
        self.assertIn("FULLY RECOVERABLE", [i.get("recoverability_bucket") for i in self.items])
        self.assertIn("PARTIALLY RECOVERABLE", [i.get("recoverability_bucket") for i in self.items])
        self.assertGreater(rec_summary["realistic_restoration_pct"], 0.0)

    def test_feature5_automatic_partial_repair(self):
        """Feature 5: Automated partial repair creates derived artifacts."""
        self.assertIn("repaired_artifacts", self.results)
        rep_list = self.results["repaired_artifacts"]
        for rep in rep_list:
            self.assertTrue(rep["is_derived_artifact"])
            self.assertEqual(rep["artifact_label"], "RECONSTRUCTED – derived artifact")
            self.assertIn("repaired_sha256", rep)

    def test_feature6_semantic_classification_and_scoping(self):
        """Feature 6: Categorizes items into 9 content classes and prioritizes."""
        categories = set(i["category"] for i in self.items)
        self.assertTrue(len(categories) >= 3)

        # Priority scores should be sorted descending
        scores = [i["priority_score"] for i in self.items]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_feature7_tampering_and_ransomware_detection(self):
        """Feature 7: Detects evidence tampering, ransomware ciphers, and wipes."""
        self.assertIn("tampering", self.results)
        tamp = self.results["tampering"]
        self.assertTrue(tamp["tampering_detected"])
        self.assertGreater(tamp["total_indicators"], 0)

        types = [ind["indicator_type"] for ind in tamp["indicators"]]
        self.assertTrue(any("RANSOM" in t or "WIP" in t or "SPOOF" in t or "CIPHER" in t for t in types))

    def test_feature8_clustering_deduplication(self):
        """Feature 8: Deduplication and near-duplicate fuzzy clustering."""
        self.assertIn("clustering", self.results)
        clust = self.results["clustering"]
        self.assertIn("clustered_items", clust)
        self.assertGreater(clust["summary"]["unique_clusters"], 0)

    def test_feature9_timeline_reconstruction(self):
        """Feature 9: Unified chronological forensic timeline."""
        self.assertIn("timeline", self.results)
        tl = self.results["timeline"]
        self.assertGreater(tl["total_events"], 0)
        # Verify chronological order
        timestamps = [e["timestamp"] for e in tl["timeline_events"]]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_feature10_dual_mode_explanations(self):
        """Feature 10: Simple and Expert explanations for cases and items."""
        self.assertIn("narratives", self.results)
        narr = self.results["narratives"]
        self.assertIn("simple_mode", narr)
        self.assertIn("expert_mode", narr)
        self.assertIn("Executive Summary", narr["simple_mode"])
        self.assertIn("DFIR Technical", narr["expert_mode"])

    def test_feature11_report_exports_and_self_hashes(self):
        """Feature 11: Machine-readable JSON and PDF report exports with self-hashes."""
        self.assertIn("reports", self.results)
        reps = self.results["reports"]
        self.assertTrue(len(reps["json_str"]) > 0)
        self.assertTrue(len(reps["json_sha256"]) == 64)
        self.assertTrue(len(reps["pdf_bytes"]) > 0)
        self.assertTrue(len(reps["pdf_sha256"]) == 64)
        self.assertTrue(reps["pdf_bytes"].startswith(b"%PDF-1.4"))

    def test_feature12_read_only_verification_match(self):
        """Feature 12: Post-analysis cryptographic re-hash confirms bit-for-bit read-only MATCH."""
        self.assertTrue(self.results["read_only_verified"])
        intake_sha = self.results["hash_meta"]["sha256"]
        post_sha = self.results["post_analysis_hash"]["sha256"]
        self.assertEqual(intake_sha, post_sha)

if __name__ == "__main__":
    unittest.main()
