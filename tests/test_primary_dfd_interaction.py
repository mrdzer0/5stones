import asyncio
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from backend.routers.analysis import update_threat_review
from backend.services.posture_service import (
    build_project_evidence_catalog,
    enrich_threats,
    normalize_report_evidence,
)
from backend.services.threat_validation_service import validate_generated_threats
from backend.services.trust_boundary_service import attach_target_refs


def canonical_model():
    return {
        "revision": 7,
        "semantic_hash": "semantic-7",
        "nodes": [
            {"id": "node-user", "name": "Customer", "type": "entity"},
            {"id": "node-api", "name": "Checkout API", "type": "process"},
            {"id": "node-store", "name": "Orders", "type": "data_store"},
        ],
        "flows": [
            {"id": "flow-submit", "name": "Submit order", "source_id": "node-user", "target_id": "node-api"},
            {"id": "flow-write", "name": "Write order", "source_id": "node-api", "target_id": "node-store"},
        ],
        "data_objects": [{"id": "data-order", "name": "Order"}],
        "boundaries": [{"id": "boundary-public", "name": "Public boundary"}],
    }


def evidence_project():
    return {
        "project_id": "project-primary",
        "name": "Primary interaction fixture",
        "artifact_sources": [{
            "artifact_id": "artifact-1",
            "filename": "prd.md",
            "artifact_type": "prd",
            "active": True,
            "revision": 1,
            "content_hash": "hash-1",
            "evidence_items": [{
                "locator": "Checkout",
                "snippet": "Customers submit an order to the Checkout API.",
                "topics": ["checkout", "order"],
            }],
        }],
    }


def candidate(**overrides):
    value = {
        "threat_category": "Tampering",
        "threat_description": "An attacker may alter an order during checkout.",
        "affected_refs": ["flow-submit", "node-api", "data-order"],
        "primary_interaction_ref": "flow-submit",
    }
    value.update(overrides)
    return value


class PrimaryDfdInteractionTests(unittest.TestCase):
    def test_node_only_candidate_is_rejected_without_primary_flow(self):
        accepted, warnings = validate_generated_threats([
            candidate(primary_interaction_ref=None, affected_refs=["node-api"])
        ], "STRIDE", canonical_model())

        self.assertEqual(accepted, [])
        self.assertTrue(any("no canonical DFD flow" in warning for warning in warnings))

    def test_multiple_flows_require_explicit_primary_interaction(self):
        accepted, warnings = validate_generated_threats([
            candidate(primary_interaction_ref=None, affected_refs=["flow-submit", "flow-write"])
        ], "STRIDE", canonical_model())

        self.assertEqual(accepted, [])
        self.assertTrue(any("multiple DFD flows" in warning for warning in warnings))

    def test_primary_flow_is_required_to_be_inside_generation_batch(self):
        accepted, warnings = validate_generated_threats([
            candidate(generation_scope_flow_refs=["flow-write"])
        ], "STRIDE", canonical_model())

        self.assertEqual(accepted, [])
        self.assertTrue(any("outside its generation batch" in warning for warning in warnings))

    def test_primary_flow_and_dfd_context_are_separate(self):
        accepted, warnings = validate_generated_threats([
            candidate(dfd_context_refs=["node-api", "data-order"])
        ], "STRIDE", canonical_model())

        self.assertEqual(warnings, [])
        self.assertEqual(accepted[0]["primary_interaction_ref"], "flow-submit")
        self.assertEqual(accepted[0]["interaction_mapping_status"], "mapped")
        self.assertEqual(accepted[0]["dfd_context_refs"], ["node-api", "data-order"])
        self.assertEqual(accepted[0]["affected_refs"][0], "flow-submit")

    def test_context_evidence_does_not_become_scenario_evidence(self):
        project = evidence_project()
        evidence_id = build_project_evidence_catalog(project)[0]["evidence_id"]
        accepted, warnings = validate_generated_threats([
            candidate(
                scenario_evidence_refs=[],
                evidence_refs=[],
                context_evidence_refs=[evidence_id],
            )
        ], "STRIDE", canonical_model(), {evidence_id})

        self.assertEqual(warnings, [])
        self.assertEqual(accepted[0]["scenario_evidence_refs"], [])
        self.assertEqual(accepted[0]["evidence_refs"], [])
        self.assertEqual(accepted[0]["context_evidence_refs"], [evidence_id])

    def test_auto_retrieved_context_cannot_ground_a_scenario(self):
        project = evidence_project()
        threat = {
            **candidate(),
            "framework": "STRIDE",
            "interaction_mapping_status": "mapped",
            "scenario_evidence_refs": [],
            "evidence_refs": [],
            "confidence": "High",
            "risk_level": "High",
        }

        finding = enrich_threats([threat], project, "STRIDE")[0]

        self.assertEqual(finding["finding_state"], "hypothesis")
        self.assertEqual(finding["scenario_evidence_refs"], [])
        self.assertEqual(finding["evidence_refs"], [])
        self.assertTrue(finding["context_evidence_refs"])
        self.assertEqual(finding["evidence_role"], "context")

    def test_legacy_single_flow_is_migrated_but_generic_refs_stay_context(self):
        project = evidence_project()
        evidence_id = build_project_evidence_catalog(project)[0]["evidence_id"]
        report = {
            "dfd_model": canonical_model(),
            "threats": [{
                **candidate(primary_interaction_ref=None),
                "threat_id": "legacy-one",
                "framework": "STRIDE",
                "evidence_refs": [evidence_id],
                "evidence_type": "direct",
                "evidence_source": "prd.md",
                "evidence_locator": "Checkout",
                "evidence_snippet": "Customers submit an order to the Checkout API.",
                "risk_level": "High",
            }],
        }

        finding = normalize_report_evidence(report, project)["threats"][0]

        self.assertEqual(finding["primary_interaction_ref"], "flow-submit")
        self.assertEqual(finding["interaction_mapping_status"], "mapped")
        self.assertEqual(finding["scenario_evidence_refs"], [])
        self.assertEqual(finding["context_evidence_refs"], [evidence_id])
        self.assertEqual(finding["finding_state"], "hypothesis")

    def test_legacy_multiple_flows_is_deferred_as_ambiguous(self):
        report = {
            "dfd_model": canonical_model(),
            "threats": [{
                **candidate(primary_interaction_ref=None, affected_refs=["flow-submit", "flow-write"]),
                "threat_id": "legacy-many",
                "framework": "STRIDE",
                "risk_level": "High",
            }],
        }

        finding = normalize_report_evidence(report, evidence_project())["threats"][0]

        self.assertIsNone(finding["primary_interaction_ref"])
        self.assertEqual(finding["interaction_mapping_status"], "ambiguous")
        self.assertEqual(finding["finding_state"], "needs_context")
        self.assertEqual(finding["risk_level"], "Unknown")
        self.assertTrue(finding["primary_interaction_guarded"])

    def test_typed_primary_target_is_first_and_controls_mapping_status(self):
        threat = {
            "threat_id": "mapped",
            **candidate(),
        }

        attach_target_refs([threat], [], {}, canonical_model())

        self.assertEqual(threat["mapping_status"], "mapped")
        self.assertEqual(threat["target_refs"][0]["id"], "flow-submit")
        self.assertTrue(threat["target_refs"][0]["is_primary_interaction"])

    def test_review_api_rejects_a_node_as_primary_interaction(self):
        report = {
            "dfd_model": canonical_model(),
            "threats": [{"threat_id": "review-1", "framework": "STRIDE", **candidate()}],
            "controls": [],
            "test_scenarios": [],
        }
        with patch("backend.routers.analysis.get_project", return_value=evidence_project()), patch(
            "backend.routers.analysis.get_report", return_value=report
        ):
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(update_threat_review(
                    "project-primary", "review-1", {"primary_interaction_ref": "node-api"}
                ))

        self.assertEqual(raised.exception.status_code, 422)
        self.assertIn("canonical DFD flow", raised.exception.detail)

    def test_review_api_can_remediate_an_ambiguous_primary_interaction(self):
        report = {
            "dfd_model": canonical_model(),
            "threats": [{
                "threat_id": "review-2",
                "framework": "STRIDE",
                **candidate(primary_interaction_ref=None, affected_refs=["flow-submit", "flow-write"]),
                "risk_level": "High",
                "status": "Open",
            }],
            "controls": [],
            "test_scenarios": [],
            "trust_boundaries": [],
            "trust_model": {"views": {}},
        }
        with patch("backend.routers.analysis.get_project", return_value=evidence_project()), patch(
            "backend.routers.analysis.get_report", return_value=report
        ), patch("backend.routers.analysis.save_report"), patch("backend.routers.analysis.log_event"):
            response = asyncio.run(update_threat_review(
                "project-primary", "review-2", {"primary_interaction_ref": "flow-write"}
            ))

        self.assertEqual(response["threat"]["primary_interaction_ref"], "flow-write")
        self.assertEqual(response["threat"]["interaction_mapping_status"], "mapped")
        self.assertEqual(response["threat"]["target_refs"][0]["id"], "flow-write")


if __name__ == "__main__":
    unittest.main()
