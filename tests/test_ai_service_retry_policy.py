"""Bounded HTTP retry policy for OpenAI-compatible provider requests."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from backend.services.ai_service import _get_client


class AIServiceRetryPolicyTests(unittest.TestCase):
    def test_client_defaults_to_one_bounded_provider_retry(self):
        with patch.dict(os.environ, {"LLM_PROVIDER_ALLOWLIST": "ai.sumopod.com"}, clear=True), \
                patch("backend.services.ai_service.AsyncOpenAI") as client:
            _get_client(base_url="https://ai.sumopod.com/v1", api_key="test-key")

        self.assertEqual(client.call_args.kwargs["max_retries"], 1)
        self.assertEqual(client.call_args.kwargs["timeout"], 180.0)

    def test_explicit_zero_retries_remains_supported(self):
        with patch.dict(os.environ, {
            "LLM_PROVIDER_ALLOWLIST": "ai.sumopod.com",
            "LLM_MAX_RETRIES": "0",
            "LLM_TIMEOUT_SECONDS": "30",
        }, clear=True), patch("backend.services.ai_service.AsyncOpenAI") as client:
            _get_client(base_url="https://ai.sumopod.com/v1", api_key="test-key")

        self.assertEqual(client.call_args.kwargs["max_retries"], 0)
        self.assertEqual(client.call_args.kwargs["timeout"], 30.0)


if __name__ == "__main__":
    unittest.main()
