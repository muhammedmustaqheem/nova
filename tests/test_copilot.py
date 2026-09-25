"""
Unit Test Suite for ReconAI Evidence-Grounded Investigator Copilot
"""

import os
import unittest
from reconai import api
from reconai.copilot.service import ask_copilot
from reconai.copilot.provider import get_configured_ai_provider, LocalGroundedRAGProvider

class TestCopilotModule(unittest.TestCase):

    def setUp(self):
        # The demo disk's content embeds a wall-clock timestamp, so its SHA-256 (and
        # therefore its derived case_id) is not stable across runs — resolve whatever
        # case is actually active rather than hardcoding a case_id string. (A hardcoded
        # id here previously passed only by riding a since-fixed bug where an unknown
        # case_id silently fell back to whatever case was already cached, instead of
        # correctly reporting "not found".)
        self.case_data = api._ensure_active_case()
        self.case_id = self.case_data["case"]["case_id"]
        self.case_view = api.api_get_case_view(self.case_id)

    def test_provider_fallback(self):
        """Test AIProvider abstraction falls back safely when no API keys are present."""
        os.environ.pop("OPENAI_API_KEY", None)
        os.environ.pop("GEMINI_API_KEY", None)
        os.environ.pop("ANTHROPIC_API_KEY", None)
        provider, name = get_configured_ai_provider()
        self.assertIsInstance(provider, LocalGroundedRAGProvider)
        self.assertIn("Local Evidence-Grounded Engine", name)

    def test_credential_query(self):
        """Test credential query retrieves credential artifacts and citations."""
        res = ask_copilot("Which recovered files contain credentials?", self.case_data)
        self.assertTrue(res["success"])
        self.assertTrue(res["grounded"])
        self.assertGreater(res["evidence_count"], 0)
        self.assertTrue(len(res["citations"]) > 0)
        self.assertIn("[OBSERVED]", res["answer"])

    def test_reconstruction_query(self):
        """Test fragment reconstruction query."""
        res = ask_copilot("Which fragments were reconstructed?", self.case_data)
        self.assertTrue(res["success"])
        self.assertTrue(res["grounded"])
        self.assertIn("[DERIVED]", res["answer"])

    def test_timeline_query(self):
        """Test timeline query retrieves events around specific time."""
        res = ask_copilot("What happened around 03:12?", self.case_data)
        self.assertTrue(res["success"])
        self.assertTrue(res["grounded"])

    def test_empty_query(self):
        """Test empty query handling."""
        res = ask_copilot("", self.case_data)
        self.assertFalse(res["success"])
        self.assertFalse(res["grounded"])

    def test_api_copilot_endpoint(self):
        """Test API endpoint api_copilot_ask."""
        res = api.api_copilot_ask(self.case_id, "Which files are P1 priority?")
        self.assertTrue(res["success"])
        self.assertTrue(res["grounded"])
        self.assertGreater(res["evidence_count"], 0)

if __name__ == "__main__":
    unittest.main()
