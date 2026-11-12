from __future__ import annotations

from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

from backend.services.ai_service import ChatCompletionResult, StructuredJSONResult, chat_complete
from backend.services.threat_batch_service import _safe_response_metadata, run_threat_batches


class ProviderResponseModelProvenanceTests(IsolatedAsyncioTestCase):
    async def _complete(self, response_model):
        async def create(**_kwargs):
            choice = SimpleNamespace(
                finish_reason="stop",
                message=SimpleNamespace(content="{}", model_extra={}),
            )
            return SimpleNamespace(model=response_model, choices=[choice], usage=None)

        client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
        with patch("backend.services.ai_service._get_client", return_value=client):
            return await chat_complete(
                system_prompt="Return a JSON object.",
                user_prompt="Return {}.",
                model="deepseek-v4-flash",
                base_url="https://ai.sumopod.com/v1",
                api_key="test-only-not-used",
                use_json_format=True,
                return_metadata=True,
            )

    async def test_provider_echo_is_distinguished_from_requested_model(self):
        result = await self._complete("deepseek-v4-flash")

        self.assertIsInstance(result, ChatCompletionResult)
        self.assertEqual(result.metadata["configured_model"], "deepseek-v4-flash")
        self.assertEqual(result.metadata["response_model"], "deepseek-v4-flash")
        self.assertEqual(result.metadata["model"], "deepseek-v4-flash")
        self.assertEqual(result.metadata["model_source"], "provider_response")

    async def test_requested_model_fallback_is_not_reported_as_provider_echo(self):
        result = await self._complete(None)

        self.assertIsInstance(result, ChatCompletionResult)
        self.assertEqual(result.metadata["configured_model"], "deepseek-v4-flash")
        self.assertIsNone(result.metadata["response_model"])
        self.assertEqual(result.metadata["model"], "deepseek-v4-flash")
        self.assertEqual(result.metadata["model_source"], "configured_fallback")

    def test_batch_metadata_sanitizer_preserves_provenance_without_response_content(self):
        safe = _safe_response_metadata({
            "model": "deepseek-v4-flash",
            "configured_model": "deepseek-v4-flash",
            "response_model": "deepseek-v4-flash",
            "model_source": "provider_response",
            "content": "private model response must not be persisted",
        })

        self.assertEqual(safe, {
            "model": "deepseek-v4-flash",
            "configured_model": "deepseek-v4-flash",
            "response_model": "deepseek-v4-flash",
            "model_source": "provider_response",
        })

    async def test_batch_manifest_retains_provider_response_model_provenance(self):
        async def complete(**_kwargs):
            return StructuredJSONResult(
                payload={"threats": [], "coverage": []},
                metadata={
                    "model": "deepseek-v4-flash",
                    "configured_model": "deepseek-v4-flash",
                    "response_model": "deepseek-v4-flash",
                    "model_source": "provider_response",
                    "content": "must not be retained",
                },
            )

        result = await run_threat_batches(
            framework="STRIDE",
            batches=[{
                "batch_id": "batch-1",
                "scope_refs": ["flow-1"],
                "flow_refs": ["flow-1"],
                "context": "{}",
            }],
            deferred_refs=[],
            system_prompt="system",
            prompt_prefix="prefix",
            prompt_suffix="suffix",
            provider={"model": "deepseek-v4-flash", "max_tokens": 2048},
            chat_complete_json=complete,
        )

        batch_metadata = result.response_metadata["generation_manifest"]["batches"][0]["response_metadata"]
        self.assertEqual(batch_metadata["configured_model"], "deepseek-v4-flash")
        self.assertEqual(batch_metadata["response_model"], "deepseek-v4-flash")
        self.assertEqual(batch_metadata["model_source"], "provider_response")
        self.assertNotIn("content", batch_metadata)


if __name__ == "__main__":
    import unittest

    unittest.main()
