import os
import unittest
from unittest.mock import patch

from backend.services.ai_service import get_active_provider_config
from backend.services.provider_policy import (
    ProviderPolicyError,
    normalize_max_tokens,
    normalize_max_retries,
    normalize_timeout_seconds,
    validate_provider_url,
)


class ProviderPolicyTests(unittest.TestCase):
    def test_known_cloud_endpoint_is_allowed(self):
        result = validate_provider_url("https://api.openai.com/v1")
        self.assertFalse(result["is_local"])
        self.assertEqual(result["hostname"], "api.openai.com")

    def test_custom_endpoint_requires_explicit_allowlist(self):
        with self.assertRaisesRegex(ProviderPolicyError, "not allowlisted"):
            validate_provider_url("https://llm.example.test/v1")
        with patch.dict(os.environ, {"LLM_PROVIDER_ALLOWLIST": "llm.example.test"}, clear=False):
            self.assertFalse(validate_provider_url("https://llm.example.test/v1")["is_local"])

    def test_local_only_rejects_cloud_and_accepts_localhost(self):
        with self.assertRaisesRegex(ProviderPolicyError, "local_only"):
            validate_provider_url("https://api.openai.com/v1", data_policy="local_only")
        self.assertTrue(validate_provider_url("http://127.0.0.1:11434/v1", data_policy="local_only")["is_local"])

    def test_token_budget_has_explicit_bounds(self):
        self.assertEqual(normalize_max_tokens("1024"), 1024)
        with self.assertRaisesRegex(ProviderPolicyError, "between"):
            normalize_max_tokens(128)

    def test_timeout_and_retry_limits_are_bounded(self):
        self.assertEqual(normalize_timeout_seconds("30"), 30)
        self.assertEqual(normalize_max_retries("2"), 2)
        with self.assertRaisesRegex(ProviderPolicyError, "timeout"):
            normalize_timeout_seconds(0)
        with self.assertRaisesRegex(ProviderPolicyError, "retries"):
            normalize_max_retries(4)

    def test_local_only_provider_selection_does_not_use_active_cloud_provider(self):
        settings = {
            "active_provider_id": "cloud",
            "providers": [{
                "provider_id": "cloud",
                "base_url": "https://api.openai.com/v1",
                "model": "gpt-test",
                "_api_key": "key",
                "is_local": False,
            }],
            "local_llm_endpoint": "http://127.0.0.1:11434/v1",
            "local_llm_model": "llama-test",
        }
        with patch("backend.utils.storage.get_settings", return_value=settings):
            config = get_active_provider_config("local_only")
        self.assertTrue(config["is_local"])
        self.assertEqual(config["model"], "llama-test")


if __name__ == "__main__":
    unittest.main()
