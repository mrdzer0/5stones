import asyncio
import unittest

from backend.services.ai_service import StructuredJSONResult
from backend.services.posture_service import normalize_deferred_interaction_manifests
from backend.services.threat_batch_service import build_threat_batches, run_threat_batches


class InteractionDeferredRefTests(unittest.TestCase):
    def test_isolated_context_is_not_retryable_generation_work(self):
        model = {
            "nodes": [
                {"id": "node-a", "name": "A", "zone_ids": ["zone-app"]},
                {"id": "node-b", "name": "B", "zone_ids": ["zone-app"]},
                {"id": "node-isolated", "name": "Isolated", "zone_ids": ["zone-data"]},
            ],
            "flows": [{"id": "flow-ab", "source_id": "node-a", "target_id": "node-b", "data_object_ids": ["data-used"]}],
            "data_objects": [{"id": "data-used"}, {"id": "data-unused"}],
            "zones": [{"id": "zone-app"}, {"id": "zone-data"}],
            "boundaries": [],
        }

        batches, deferred = build_threat_batches(model)

        self.assertEqual(deferred, [])
        self.assertEqual(batches[0]["flow_refs"], ["flow-ab"])
        self.assertEqual(set(batches[0]["context_gap_refs"]), {"node-isolated", "data-unused", "zone-data"})

    def test_context_gaps_do_not_make_successful_assessment_partial(self):
        batches, deferred = build_threat_batches({
            "nodes": [{"id": "node-a"}, {"id": "node-b"}, {"id": "node-isolated"}],
            "flows": [{"id": "flow-ab", "source_id": "node-a", "target_id": "node-b"}],
        })

        async def provider(**kwargs):
            return StructuredJSONResult({"threats": [], "coverage": []}, {"finish_reason": "stop"})

        result = asyncio.run(run_threat_batches(
            framework="STRIDE", batches=batches, deferred_refs=deferred,
            system_prompt="system", prompt_prefix="analyze", prompt_suffix="json",
            provider={}, chat_complete_json=provider,
        ))

        manifest = result.response_metadata["generation_manifest"]
        self.assertEqual(result.assessment_status, "valid_empty")
        self.assertEqual(manifest["deferred_refs"], [])
        self.assertEqual(manifest["non_interaction_refs"], ["node-isolated"])

    def test_no_flow_skips_provider_without_retry_loop(self):
        batches, deferred = build_threat_batches({
            "nodes": [{"id": "node-isolated"}], "flows": [], "data_objects": [{"id": "data-unused"}],
        })
        called = False

        async def provider(**kwargs):
            nonlocal called
            called = True
            raise AssertionError("Provider must not be called without a canonical interaction")

        result = asyncio.run(run_threat_batches(
            framework="LINDDUN", batches=batches, deferred_refs=deferred,
            system_prompt="system", prompt_prefix="analyze", prompt_suffix="json",
            provider={}, chat_complete_json=provider,
        ))

        self.assertFalse(called)
        self.assertEqual(result.assessment_status, "valid_empty")
        self.assertEqual(result.response_metadata["generation_manifest"]["deferred_refs"], [])
        self.assertEqual(
            set(result.response_metadata["generation_manifest"]["non_interaction_refs"]),
            {"node-isolated", "data-unused"},
        )

    def test_legacy_data_only_deferred_refs_are_reclassified_on_read(self):
        report = {
            "dfd_model": {"flows": [{"id": "flow-ab"}]},
            "threats": [{"framework": "STRIDE", "analysis_state": "current"}],
            "ai_status": {"stride": {
                "ok": False,
                "engine": "AI",
                "assessment_status": "partial",
                "validation_warnings": ["10 canonical references were deferred for retry"],
                "response_metadata": {"generation_manifest": {
                    "deferred_refs": ["data-1", "data-2"],
                    "batches": [{"batch_id": "batch-1", "scope_refs": ["flow-ab"], "status": "complete"}],
                }},
            }},
            "analysis_run": {
                "requested_types": ["stride"], "retryable": True, "warning_stages": ["stride"],
            },
        }

        normalized = normalize_deferred_interaction_manifests(report)
        stage = normalized["ai_status"]["stride"]

        self.assertTrue(stage["ok"])
        self.assertEqual(stage["assessment_status"], "complete")
        self.assertEqual(stage["response_metadata"]["generation_manifest"]["deferred_refs"], [])
        self.assertEqual(stage["response_metadata"]["generation_manifest"]["non_interaction_refs"], ["data-1", "data-2"])
        self.assertFalse(normalized["analysis_run"]["retryable"])
        self.assertEqual(normalized["analysis_run"]["warning_stages"], [])

    def test_legacy_failed_flow_remains_retryable(self):
        report = {
            "dfd_model": {"flows": [{"id": "flow-ab"}]},
            "threats": [],
            "ai_status": {"stride": {
                "ok": False,
                "engine": "AI",
                "assessment_status": "partial",
                "response_metadata": {"generation_manifest": {
                    "deferred_refs": ["flow-ab", "data-1"],
                    "batches": [{"batch_id": "batch-1", "scope_refs": ["flow-ab", "data-1"], "status": "invalid"}],
                }},
            }},
        }

        normalized = normalize_deferred_interaction_manifests(report)
        stage = normalized["ai_status"]["stride"]

        self.assertFalse(stage["ok"])
        self.assertEqual(stage["assessment_status"], "partial")
        self.assertEqual(stage["response_metadata"]["generation_manifest"]["deferred_refs"], ["flow-ab"])
        self.assertEqual(stage["response_metadata"]["generation_manifest"]["non_interaction_refs"], ["data-1"])

    def test_incomplete_current_coverage_cannot_be_reclassified_as_complete(self):
        report = {
            "dfd_model": {"flows": [{"id": "flow-ab"}]},
            "threats": [{"framework": "STRIDE", "analysis_state": "current"}],
            "ai_status": {"stride": {
                "ok": False,
                "engine": "AI",
                "assessment_status": "partial",
                "response_metadata": {"generation_manifest": {
                    "deferred_refs": ["data-1"],
                    "batches": [{"batch_id": "batch-1", "scope_refs": ["flow-ab"], "status": "complete"}],
                }},
            }},
            "analysis_coverage_summary": {"STRIDE": {"complete": False, "deferred": 5}},
            "analysis_coverage_manifest": {"STRIDE": {"summary": {"complete": False, "deferred": 5}}},
            "analysis_run": {
                "requested_types": ["stride"], "retryable": True, "warning_stages": ["stride"],
            },
        }

        normalized = normalize_deferred_interaction_manifests(report)
        stage = normalized["ai_status"]["stride"]

        self.assertFalse(stage["ok"])
        self.assertEqual(stage["assessment_status"], "partial")
        self.assertTrue(stage["coverage_partial"])
        self.assertNotIn("legacy_deferred_reclassified", stage)
        self.assertTrue(any("coverage is incomplete" in warning for warning in stage["validation_warnings"]))
        self.assertEqual(stage["response_metadata"]["generation_manifest"]["deferred_refs"], [])

    def test_complete_current_coverage_allows_legacy_context_ref_reclassification(self):
        report = {
            "dfd_model": {"flows": [{"id": "flow-ab"}]},
            "threats": [{"framework": "STRIDE", "analysis_state": "current"}],
            "ai_status": {"stride": {
                "ok": False,
                "engine": "AI",
                "assessment_status": "partial",
                "response_metadata": {"generation_manifest": {
                    "deferred_refs": ["data-1"],
                    "batches": [{"batch_id": "batch-1", "scope_refs": ["flow-ab"], "status": "complete"}],
                }},
            }},
            "analysis_coverage_summary": {"STRIDE": {"complete": True}},
            "analysis_coverage_manifest": {"STRIDE": {"summary": {"complete": True}}},
        }

        normalized = normalize_deferred_interaction_manifests(report)

        self.assertTrue(normalized["ai_status"]["stride"]["ok"])
        self.assertEqual(normalized["ai_status"]["stride"]["assessment_status"], "complete")


if __name__ == "__main__":
    unittest.main()
