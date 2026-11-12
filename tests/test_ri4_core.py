import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.routers.analysis import _apply_recovery_snapshot
from backend.services.ai_service import StructuredJSONResult
from backend.services.control_service import _catalog_fallback
from backend.services.test_service import generate_test_scenarios
from backend.services.threat_batch_service import (
    MAX_BATCHES, FLOWS_PER_BATCH, MAX_BATCH_OUTPUT_TOKENS,
    build_threat_batches, run_threat_batches,
)
from backend.utils.storage import get_controls_catalog


class Ri4CoreTests(unittest.TestCase):
    def test_batch_packing_covers_flows_with_fewer_provider_calls(self):
        flows = [{"id": f"flow-{i}", "source_id": f"node-{i}", "target_id": f"node-{i + 1}"} for i in range(8)]
        nodes = [{"id": f"node-{i}", "name": f"Node {i}"} for i in range(9)]
        batches, deferred = build_threat_batches({"flows": flows, "nodes": nodes})
        self.assertEqual(len(batches), (len(flows) + FLOWS_PER_BATCH - 1) // FLOWS_PER_BATCH)
        self.assertLessEqual(len(batches), MAX_BATCHES)
        self.assertEqual(deferred, [])
        self.assertEqual({ref for batch in batches for ref in batch["scope_refs"] if ref.startswith("flow-")},
                         {flow["id"] for flow in flows})

    def test_timeout_keeps_successful_batch_and_marks_only_failed_refs_deferred(self):
        batches = [
            {"batch_id": "batch-1", "scope_refs": ["flow-1"], "context": "{}"},
            {"batch_id": "batch-2", "scope_refs": ["flow-2"], "context": "{}"},
        ]
        async def provider(**kwargs):
            if "batch-2" in kwargs["user_prompt"]:
                await asyncio.sleep(0.2)
            return StructuredJSONResult({"threats": [{"threat_category": "Tampering",
                "threat_description": "Request data can be changed", "affected_refs": ["flow-1"]}],
                "coverage": []}, {"finish_reason": "stop"})

        with patch("backend.services.threat_batch_service.MAX_STAGE_SECONDS", 0.05), \
             patch("backend.services.threat_batch_service.MAX_BATCH_SECONDS", 0.04):
            result = asyncio.run(run_threat_batches(
                framework="STRIDE", batches=batches, deferred_refs=[], system_prompt="STRIDE",
                prompt_prefix="Analyze", prompt_suffix="JSON only", provider={}, chat_complete_json=provider))
        manifest = result.response_metadata["generation_manifest"]
        self.assertEqual(result.assessment_status, "partial")
        self.assertEqual(len(result), 1)
        self.assertEqual(manifest["deferred_refs"], ["flow-2"])
        self.assertEqual(manifest["batches"][1]["error_code"], "stage_timeout")
        self.assertEqual(manifest["batches"][0]["max_tokens"], MAX_BATCH_OUTPUT_TOKENS)

    def test_catalog_is_available_with_isolated_data_directory(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch("backend.utils.storage.DATA_DIR", Path(directory)):
            catalog = get_controls_catalog()
        self.assertTrue(any(item.get("id") == "ctrl-010" for item in catalog))

    def test_catalog_requires_domain_applicability_not_category_alone(self):
        threats = [
            {"threat_id": "t1", "framework": "STRIDE", "threat_category": "Tampering",
             "threat_description": "An attacker changes a registration request before the API validates it.",
             "recommended_control": "Server-side input validation"},
            {"threat_id": "t2", "framework": "LINDDUN", "threat_category": "Data Disclosure",
             "threat_description": "A registration flow exposes customer email beyond the intended recipient.",
             "recommended_control": "Data minimization"},
        ]
        controls = _catalog_fallback(threats, get_controls_catalog())
        names = {item["name"] for item in controls}
        self.assertIn("Input Validation and Sanitization", names)
        self.assertIn("PII Data Minimization and Masking", names)
        self.assertFalse(any("Webhook" in name or "Amount/Value" in name or "Nonce" in name for name in names))

    def test_template_scenario_links_control_and_canonical_target(self):
        threat = {"threat_id": "t1", "framework": "STRIDE", "threat_category": "Tampering",
                  "target_refs": [{"type": "data_flow", "id": "flow-1"}], "affected_refs": ["flow-1"]}
        control = {"control_id": "CAT-ctrl-010", "name": "Input Validation and Sanitization",
                   "threat_ids": ["t1"], "mapping_status": "mapped"}
        model = {"revision": 3, "semantic_hash": "hash-3", "flows": [{"id": "flow-1", "name": "Registration request"}]}
        result = asyncio.run(generate_test_scenarios([threat], {}, force_fallback=True,
                                                     controls=[control], dfd_model=model))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["related_control_id"], control["control_id"])
        self.assertIn("Registration request", result[0]["scenario_name"])
        self.assertEqual(result[0]["target_refs"][0]["id"], "flow-1")

    def test_warning_only_completed_framework_does_not_erase_current_results(self):
        snapshot = {"snapshot_id": "old", "threats": [{"threat_id": "old", "framework": "STRIDE"}]}
        report = {"threats": [{"threat_id": "new", "framework": "STRIDE"}],
                  "ai_status": {"stride": {"ok": False, "engine": "AI", "assessment_status": "complete",
                                           "validation_warnings": ["Unknown evidence reference removed"]}}}
        self.assertEqual(_apply_recovery_snapshot(report, snapshot, ["stride"]), {})
        self.assertEqual(report["threats"][0]["threat_id"], "new")
