"""
ReconAI API Endpoint Integration Tests
Validates all backend API service endpoints:
  - api_upload_image
  - api_analyze_image
  - api_recover_image
  - api_get_files
  - api_get_file_detail
  - api_download_file
  - api_preview_file
  - api_get_report
"""

import os
import unittest
from reconai.api import (
    api_upload_image,
    api_analyze_image,
    api_recover_image,
    api_get_files,
    api_get_file_detail,
    api_download_file,
    api_preview_file,
    api_get_report
)

class TestReconAIAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cls.raw_path = os.path.join(cls.base_dir, "data", "demo_evidence.raw")
        if not os.path.exists(cls.raw_path):
            from scripts.make_test_image import generate_evidence_disk
            generate_evidence_disk(cls.raw_path, os.path.join(cls.base_dir, "data", "ground_truth.json"))

    def test_api_workflow(self):
        # 1. Analyze
        res_analyze = api_analyze_image(self.raw_path)
        self.assertEqual(res_analyze["status"], "SUCCESS")
        self.assertEqual(res_analyze["read_only_mode"], "O_RDONLY")

        # 2. Recover
        # examiner_name is required for chain of custody — api_recover_image no longer
        # falls back to a fabricated examiner identity when it is omitted.
        res_recover = api_recover_image(self.raw_path, examiner_name="QA Test Examiner")
        self.assertEqual(res_recover["status"], "SUCCESS")
        case_id = res_recover["case_id"]
        self.assertIsNotNone(case_id)

        # 3. Get Files
        res_files = api_get_files(case_id)
        self.assertEqual(res_files["status"], "SUCCESS")
        self.assertGreater(res_files["count"], 0)
        first_file = res_files["files"][0]
        item_id = first_file["item_id"]

        # 4. Get File Detail
        res_detail = api_get_file_detail(case_id, item_id)
        self.assertEqual(res_detail["status"], "SUCCESS")
        self.assertEqual(res_detail["file"]["item_id"], item_id)

        # 5. Download File
        data, filename, mime_type = api_download_file(case_id, item_id)
        self.assertTrue(isinstance(data, bytes))
        self.assertIsNotNone(filename)
        self.assertIsNotNone(mime_type)

        # 6. Preview File
        res_preview = api_preview_file(case_id, item_id)
        self.assertEqual(res_preview["status"], "SUCCESS")
        self.assertIn("content_preview", res_preview)

        # 7. Get Report (JSON & PDF)
        rep_json = api_get_report(case_id, "json")
        self.assertEqual(rep_json["status"], "SUCCESS")
        self.assertEqual(len(rep_json["sha256"]), 64)

        rep_pdf = api_get_report(case_id, "pdf")
        self.assertEqual(rep_pdf["status"], "SUCCESS")
        self.assertTrue(rep_pdf["pdf_bytes"].startswith(b"%PDF-1.4"))

if __name__ == "__main__":
    unittest.main()
