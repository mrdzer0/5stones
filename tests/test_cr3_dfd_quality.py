import json
import unittest
from pathlib import Path

from backend.services.dfd_model_service import build_dfd_model, validate_dfd_model
from backend.services.dfd_quality_service import evaluate_expected_dfd
from backend.services.threat_batch_service import build_threat_batches
from backend.services.trust_boundary_service import build_trust_model


class Cr3DfdQualityTests(unittest.TestCase):
    def setUp(self):
        self.project = {
            "project_id": "cr3-registration",
            "name": "Registration",
            "actors": ["Customer"],
            "components": ["Registration API", "Customer Database"],
            "external_systems": ["Email Provider"],
            "manual_context": {
                "actors": ["Customer"],
                "components": ["Registration API", "Customer Database"],
                "external_systems": ["Email Provider"],
            },
            "artifact_sources": [{"artifact_id": "prd-1", "filename": "registration.md", "active": True}],
            "extracted_data_flows": [
                {"flow_id": "submit", "source": "Customer", "destination": "Registration API", "source_entity_type": "actor", "destination_entity_type": "component", "data": ["email"], "evidence_refs": ["artifact:prd-1"], "evidence_type": "direct"},
                {"flow_id": "store", "source": "Registration API", "destination": "Customer Database", "source_entity_type": "component", "destination_entity_type": "data_store", "data": ["customer record"], "evidence_refs": ["artifact:prd-1"], "evidence_type": "direct"},
            ],
        }

    def test_quality_snapshot_has_metrics_primary_set_and_traceable_aliases(self):
        model = build_dfd_model(self.project, build_trust_model(self.project))
        quality = model.semantic_quality

        self.assertIsNotNone(quality)
        self.assertEqual(quality.version, "dfd-quality-v2")
        self.assertEqual(quality.counts["valid_endpoints"], len(model.flows))
        self.assertIn("data_store_external_classification_rate", quality.metrics)
        self.assertEqual(set(quality.primary_interaction_ids), {flow.id for flow in model.flows})
        self.assertTrue(any(item.alias == "Customer" for item in quality.alias_mappings))
        self.assertEqual(validate_dfd_model(model)["semantic_quality"]["version"], "dfd-quality-v2")

    def test_missing_endpoint_is_deferred_and_never_enters_primary_batches(self):
        project = {**self.project, "extracted_data_flows": [{"flow_id": "missing", "source": "Customer", "data": ["email"]}]}
        trust = build_trust_model(project)
        model = build_dfd_model(project, trust)

        self.assertEqual(model.flows, [])
        self.assertEqual(len(model.deferred_interactions), 1)
        self.assertFalse(model.primary_interaction_ids)
        batches, deferred = build_threat_batches(model.model_dump())
        self.assertEqual(deferred, [])
        self.assertTrue(batches)
        self.assertEqual(batches[0]["flow_count"], 0)

    def test_evidence_free_candidate_is_visible_but_not_framework_input(self):
        project = {**self.project, "extracted_data_flows": [{**self.project["extracted_data_flows"][0], "evidence_refs": []}]}
        model = build_dfd_model(project, build_trust_model(project))
        candidate = next(flow for flow in model.flows if flow.id == "submit")

        self.assertEqual(candidate.grounding_status, "candidate")
        self.assertNotIn(candidate.id, model.primary_interaction_ids)
        batches, deferred = build_threat_batches(model.model_dump())
        self.assertIn(candidate.id, deferred)
        self.assertEqual(sum(item["flow_count"] for item in batches), 0)
        self.assertTrue(any(item.code == "unsupported_inferred_relationship" for item in model.semantic_quality.issues))

    def test_same_label_with_different_context_is_not_semantically_merged(self):
        project = {
            **self.project,
            "components": ["Notification API"],
            "external_systems": ["Payments API"],
            "manual_context": {"components": ["Notification API"]},
            "extracted_data_flows": [
                {"flow_id": "prod", "source": "Notification API", "destination": "Payments API (prod)", "destination_entity_type": "external_system", "destination_environment": "prod", "destination_control_party": "Acme Pay", "data": ["charge"], "evidence_refs": ["artifact:prd-1"], "evidence_type": "direct"},
                {"flow_id": "sandbox", "source": "Notification API", "destination": "Payments API (sandbox)", "destination_entity_type": "external_system", "destination_environment": "sandbox", "destination_control_party": "Acme Pay", "data": ["test charge"], "evidence_refs": ["artifact:prd-1"], "evidence_type": "direct"},
            ],
        }
        trust = build_trust_model(project)
        external = [item for item in trust["entities"] if item["entity_type"] == "external_system"]

        self.assertEqual(len(external), 2)
        self.assertEqual({item["environment"] for item in external}, {"prod", "sandbox"})
        model = build_dfd_model(project, trust)
        self.assertTrue(any(item.decision == "kept_separate" for item in model.semantic_quality.alias_mappings))

    def test_expected_contract_returns_explicit_counts_not_percentage_only(self):
        contract = json.loads((Path(__file__).parents[1] / "tests" / "prd_corpus" / "dfd_quality_contract.json").read_text())
        expected = contract["calibration_cases"][1]
        model = build_dfd_model(self.project, build_trust_model(self.project))
        result = evaluate_expected_dfd(model, expected)

        self.assertIn("numerator", result["entity_recall"])
        self.assertIn("denominator", result["precision"])
        self.assertIn("valid_endpoint", result)
        self.assertIsInstance(result["unsupported_ids"], list)


if __name__ == "__main__":
    unittest.main()
