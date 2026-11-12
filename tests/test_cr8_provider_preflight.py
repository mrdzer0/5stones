"""Safe preflight contract tests; never make provider network requests."""
from __future__ import annotations

import asyncio
import unittest

from backend.services.ai_service import StructuredJSONResult
from tools.cr8_provider_preflight import check_provider


class AuthenticationError(Exception):
    status_code = 401


class ProviderPreflightTests(unittest.TestCase):
    def test_valid_minimal_response_records_observed_model(self):
        async def complete_json(**_kwargs):
            return StructuredJSONResult({"ok": True}, {
                "response_model": "deepseek-v4-flash",
                "provider_attempts": 1,
            })

        result = asyncio.run(check_provider(
            "sumopod",
            {"base_url": "https://ai.sumopod.com/v1", "api_key": "test-only"},
            "deepseek-v4-flash",
            complete_json=complete_json,
        ))
        self.assertEqual(result["status"], "qualified")
        self.assertEqual(result["response_model"], "deepseek-v4-flash")
        self.assertEqual(result["endpoint_hostname"], "ai.sumopod.com")
        self.assertNotIn("api_key", result)

    def test_authentication_failure_is_redacted_to_exception_type_and_status(self):
        async def complete_json(**_kwargs):
            raise AuthenticationError("secret-token-must-not-escape")

        result = asyncio.run(check_provider(
            "sumopod",
            {"base_url": "https://ai.sumopod.com/v1", "api_key": "test-only"},
            "deepseek-v4-flash",
            complete_json=complete_json,
        ))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_type"], "AuthenticationError")
        self.assertEqual(result["http_status"], 401)
        self.assertNotIn("secret-token-must-not-escape", str(result))
        self.assertNotIn("test-only", str(result))

    def test_missing_or_mismatched_model_provenance_fails(self):
        async def complete_json(**_kwargs):
            return StructuredJSONResult({"ok": True}, {"response_model": "another-model"})

        result = asyncio.run(check_provider(
            "sumopod",
            {"base_url": "https://ai.sumopod.com/v1", "api_key": "test-only"},
            "deepseek-v4-flash",
            complete_json=complete_json,
        ))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reasons"], ["response_model_mismatch"])


if __name__ == "__main__":
    unittest.main()
