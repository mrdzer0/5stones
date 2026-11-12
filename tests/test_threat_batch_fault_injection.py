"""Offline provider fault injection for bounded threat-batch generation."""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from backend.services.ai_service import AnalysisResponseError
from backend.services.threat_batch_service import (
    ThreatGenerationProviderError,
    FLOWS_PER_BATCH,
    build_threat_batches,
    run_threat_batches,
)
from backend.services.threat_validation_service import validate_generated_threats


def batch(batch_id: str, flow_id: str) -> dict:
    return {
        "batch_id": batch_id,
        "scope_refs": [flow_id],
        "flow_refs": [flow_id],
        "context": f"synthetic DFD interaction {flow_id}",
    }


def valid_payload(flow_id: str = "flow-valid") -> dict:
    return {
        "threats": [{
            "threat_category": "Tampering",
            "threat_description": "A request value could be altered before validation.",
            "primary_interaction_ref": flow_id,
            "affected_refs": [flow_id],
        }],
        "coverage": [{"element_ref": flow_id, "category": "Tampering", "status": "candidate_identified"}],
    }


class RateLimitError(Exception):
    status_code = 429


class ThreatBatchFaultInjectionTests(unittest.TestCase):
    def run_stage(self, callback, batches, *, framework="STRIDE"):
        return asyncio.run(run_threat_batches(
            framework=framework,
            batches=batches,
            deferred_refs=[],
            system_prompt="synthetic system prompt",
            prompt_prefix="synthetic threat review",
            prompt_suffix="use evidence only",
            provider={"base_url": "https://provider.invalid/v1", "api_key": "fixture-key", "model": "fault-fixture"},
            chat_complete_json=callback,
        ))

    def test_batch_planner_covers_all_46_flows_instead_of_truncating_after_eight_batches(self):
        flows = [
            {"id": f"flow-{index:02d}", "source_id": "source", "target_id": "target", "name": f"Flow {index}"}
            for index in range(46)
        ]
        batches, deferred = build_threat_batches({
            "flows": flows,
            "primary_interaction_ids": [item["id"] for item in flows],
            "nodes": [], "data_objects": [], "zones": [], "boundaries": [],
        })

        planned = [ref for item in batches for ref in item["flow_refs"]]
        self.assertEqual(len(batches), 16)
        self.assertTrue(all(len(item["flow_refs"]) <= FLOWS_PER_BATCH for item in batches))
        self.assertEqual(planned, [item["id"] for item in flows])
        self.assertEqual(deferred, [])

    def test_batch_planner_keeps_work_bounded_and_marks_overflow_deferred(self):
        flows = [
            {"id": f"flow-{index:02d}", "source_id": "source", "target_id": "target"}
            for index in range(200)
        ]
        batches, deferred = build_threat_batches({
            "flows": flows,
            "primary_interaction_ids": [item["id"] for item in flows],
            "nodes": [], "data_objects": [], "zones": [], "boundaries": [],
        })

        planned = [ref for item in batches for ref in item["flow_refs"]]
        self.assertEqual(len(batches), 32)
        self.assertEqual(len(planned), 32 * FLOWS_PER_BATCH)
        self.assertEqual(deferred, sorted(f"flow-{index}" for index in range(96, 200)))

    def test_stride_prompt_requires_every_category_for_each_batch_flow(self):
        prompts = []

        async def provider(*, user_prompt, **_kwargs):
            prompts.append(user_prompt)
            return {"threats": [], "coverage": []}

        self.run_stage(provider, [{
            "batch_id": "batch-1",
            "scope_refs": ["flow-1", "flow-2"],
            "flow_refs": ["flow-1", "flow-2"],
            "context": "synthetic DFD interactions flow-1 and flow-2",
        }])
        self.assertIn("12 coverage rows", prompts[0])
        self.assertIn("Spoofing", prompts[0])
        self.assertIn("Elevation of Privilege", prompts[0])
        self.assertIn("Never omit a flow/category pair", prompts[0])

    def test_linddun_prompt_requires_all_seven_categories_for_each_batch_flow(self):
        prompts = []

        async def provider(*, user_prompt, **_kwargs):
            prompts.append(user_prompt)
            return {"threats": [], "coverage": []}

        self.run_stage(
            provider,
            [{
                "batch_id": "batch-1",
                "scope_refs": ["flow-1", "flow-2"],
                "flow_refs": ["flow-1", "flow-2"],
                "context": "synthetic DFD interactions flow-1 and flow-2",
            }],
            framework="LINDDUN",
        )
        self.assertIn("14 coverage rows", prompts[0])
        self.assertIn("Unawareness & Unintervenability", prompts[0])
        self.assertIn("Non-compliance", prompts[0])
        self.assertIn("Never omit a flow/category pair", prompts[0])

    def test_mixed_valid_and_rate_limited_batches_preserve_valid_and_defer_failed_flow(self):
        attempts = {"batch-1": 0, "batch-2": 0}

        async def provider(*, user_prompt, **_kwargs):
            batch_id = "batch-1" if "batch-1" in user_prompt else "batch-2"
            attempts[batch_id] += 1
            if batch_id == "batch-2":
                raise RateLimitError("synthetic 429")
            return {"threats": [
                {"threat_category": "Tampering", "threat_description": "A request value may be changed.", "affected_refs": ["flow-1"]}
            ], "coverage": []}

        result = self.run_stage(provider, [batch("batch-1", "flow-1"), batch("batch-2", "flow-2")])
        manifest = result.response_metadata["generation_manifest"]
        records = {item["batch_id"]: item for item in manifest["batches"]}

        self.assertEqual(result.assessment_status, "partial")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["generation_scope_flow_refs"], ["flow-1"])
        self.assertEqual(manifest["deferred_refs"], ["flow-2"])
        self.assertEqual(records["batch-1"]["status"], "valid")
        self.assertEqual(records["batch-2"]["status"], "unavailable")
        self.assertEqual(records["batch-2"]["error_kind"], "rate_limited")
        self.assertEqual(records["batch-2"]["attempt_count"], 2)
        self.assertEqual(attempts, {"batch-1": 1, "batch-2": 2})
        self.assertNotIn("fallback", str(manifest).casefold())

    def test_provider_down_keeps_all_interactions_deferred_and_never_falls_back(self):
        async def provider(**_kwargs):
            raise ConnectionError("synthetic provider outage")

        with self.assertRaises(ThreatGenerationProviderError) as raised:
            self.run_stage(provider, [batch("batch-1", "flow-1")])

        manifest = raised.exception.response_metadata["generation_manifest"]
        self.assertEqual(raised.exception.code, "provider_unavailable")
        self.assertEqual(manifest["completed_count"], 0)
        self.assertEqual(manifest["deferred_refs"], ["flow-1"])
        self.assertEqual(manifest["batches"][0]["status"], "unavailable")
        self.assertEqual(manifest["batches"][0]["attempt_count"], 2)
        self.assertEqual(manifest["batches"][0]["retry_count"], 1)
        self.assertNotIn("validated_output", manifest["batches"][0])

    def test_batch_timeout_retries_once_then_returns_deferred_failure(self):
        async def provider(**_kwargs):
            await asyncio.sleep(0.05)
            return {"threats": [], "coverage": []}

        with patch("backend.services.threat_batch_service.MAX_BATCH_SECONDS", 0.005), \
                patch("backend.services.threat_batch_service.MAX_STAGE_SECONDS", 0.2):
            with self.assertRaises(ThreatGenerationProviderError) as raised:
                self.run_stage(provider, [batch("batch-1", "flow-1")])

        manifest = raised.exception.response_metadata["generation_manifest"]
        record = manifest["batches"][0]
        self.assertEqual(record["status"], "timed_out")
        self.assertEqual(record["error_kind"], "application_deadline")
        self.assertEqual(record["attempt_count"], 2)
        self.assertEqual(manifest["deferred_refs"], ["flow-1"])

    def test_truncated_response_retries_once_and_remains_invalid(self):
        async def provider(**_kwargs):
            raise AnalysisResponseError(
                "synthetic truncated response",
                code="truncated_json",
                metadata={"finish_reason": "length", "truncation_suspected": True},
            )

        with self.assertRaises(AnalysisResponseError) as raised:
            self.run_stage(provider, [batch("batch-1", "flow-1")])

        manifest = raised.exception.response_metadata["generation_manifest"]
        record = manifest["batches"][0]
        self.assertEqual(record["status"], "invalid")
        self.assertEqual(record["error_kind"], "truncated")
        self.assertEqual(record["attempt_count"], 2)
        self.assertEqual(manifest["deferred_refs"], ["flow-1"])
        self.assertNotIn("validated_output", record)

    def test_semantically_invalid_candidate_is_rejected_by_trusted_validator(self):
        async def provider(**_kwargs):
            return {
                "threats": [{
                    "threat_category": "Invented STRIDE category",
                    "threat_description": "A synthetic but unsupported category claim.",
                    "primary_interaction_ref": "flow-1",
                    "affected_refs": ["flow-1"],
                }],
                "coverage": [],
            }

        generated = self.run_stage(provider, [batch("batch-1", "flow-1")])
        accepted, warnings = validate_generated_threats(
            generated, "STRIDE", {"flows": [{"id": "flow-1"}], "nodes": [], "data_objects": [], "boundaries": []}
        )

        self.assertEqual(generated.assessment_status, "complete")
        self.assertEqual(accepted, [])
        self.assertTrue(any("unsupported category" in warning for warning in warnings))


if __name__ == "__main__":
    unittest.main()
