import asyncio
import csv
import io
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from backend.routers.analysis import update_threat_review
from backend.routers.export import _to_csv, _to_markdown
from backend.services.posture_service import enrich_controls, summarize_threat_findings
from backend.services.risk_service import (
    RISK_METHODOLOGY_VERSION,
    align_test_risk_priorities,
    assess_threat_risk,
)


def canonical_model():
    return {
        "revision": 4,
        "semantic_hash": "risk-model-4",
        "nodes": [
            {"id": "actor", "name": "Internet user", "type": "entity", "exposure": "internet_facing", "scope": "external_dependency"},
            {"id": "api", "name": "Checkout API", "type": "process", "exposure": "private", "scope": "in_scope"},
        ],
        "data_objects": [{"id": "payment", "name": "Payment details", "classification": "Financial"}],
        "flows": [{
            "id": "flow-checkout", "source_id": "actor", "target_id": "api", "name": "Submit payment",
            "data_object_ids": ["payment"], "boundary_crossings": ["boundary-public"], "authn": "OIDC",
        }],
        "boundaries": [{"id": "boundary-public", "name": "Public to application"}],
    }


def grounded_threat(**overrides):
    item = {
        "threat_id": "threat-risk",
        "framework": "STRIDE",
        "threat_category": "Tampering",
        "threat_description": "A payment request may be altered in transit.",
        "data_classification": "Public",
        "primary_interaction_ref": "flow-checkout",
        "interaction_mapping_status": "mapped",
        "finding_state": "grounded",
        "status": "Open",
        "risk_level": "Low",
    }
    item.update(overrides)
    return item


class DeterministicRiskMethodologyTests(unittest.TestCase):
    def test_same_facts_produce_same_result_and_provider_severity_is_advisory(self):
        low_provider = assess_threat_risk(grounded_threat(risk_level="Low"), canonical_model())
        critical_provider = assess_threat_risk(grounded_threat(risk_level="Critical"), canonical_model())

        self.assertEqual(low_provider["risk_level"], "High")
        self.assertEqual(low_provider["risk_score"], 16)
        self.assertEqual(low_provider["risk_assessment_fingerprint"], critical_provider["risk_assessment_fingerprint"])
        self.assertEqual(critical_provider["risk_level"], "High")
        self.assertEqual(low_provider["provider_risk_level"], "Low")
        self.assertEqual(critical_provider["provider_risk_level"], "Critical")

    def test_calculation_records_matrix_factors_provenance_and_revision(self):
        result = assess_threat_risk(grounded_threat(), canonical_model())
        calculation = result["risk_calculation"]

        self.assertEqual(result["risk_methodology_version"], RISK_METHODOLOGY_VERSION)
        self.assertEqual(calculation["matrix"], "inherent-risk-5x5")
        self.assertEqual(calculation["impact"]["score"], 4)
        self.assertEqual(calculation["likelihood"]["score"], 4)
        self.assertEqual(calculation["dfd_revision"], 4)
        self.assertEqual(calculation["dfd_semantic_hash"], "risk-model-4")
        self.assertTrue(any(factor["source"] == "dfd.data_object:payment" for factor in calculation["impact"]["factors"]))

    def test_hypothesis_has_scenario_estimate_but_no_final_risk(self):
        result = assess_threat_risk(grounded_threat(finding_state="hypothesis"), canonical_model())

        self.assertEqual(result["scenario_risk_level"], "High")
        self.assertEqual(result["risk_level"], "Unknown")
        self.assertEqual(result["risk_status"], "scenario_only")
        summary = summarize_threat_findings([result])
        self.assertEqual(summary["scored_total"], 0)
        self.assertEqual(summary["scenario_only_total"], 1)

    def test_missing_primary_flow_defers_risk(self):
        result = assess_threat_risk(
            grounded_threat(primary_interaction_ref="flow-stale"), canonical_model()
        )

        self.assertEqual(result["risk_level"], "Unknown")
        self.assertEqual(result["risk_status"], "deferred")
        self.assertIsNone(result["risk_score"])
        self.assertIn("absent from the current canonical DFD revision", result["risk_rationale"])

    def test_review_override_keeps_inherent_result_visible(self):
        result = assess_threat_risk(grounded_threat(
            risk_override_level="Medium",
            risk_override_reason="Compensating transaction signing is runtime verified.",
            risk_override_by="security-reviewer",
            risk_override_at="2026-09-22T00:00:00+00:00",
        ), canonical_model())

        self.assertEqual(result["risk_level"], "Medium")
        self.assertEqual(result["risk_source"], "reviewer_override")
        self.assertEqual(result["risk_calculation"]["inherent_level"], "High")
        self.assertEqual(result["risk_calculation"]["override"]["reviewer"], "security-reviewer")

    def test_control_and_test_priorities_ignore_provider_priority(self):
        threat = assess_threat_risk(grounded_threat(), canonical_model())
        controls = enrich_controls([{
            "control_id": "control-1", "name": "Transaction signing", "threat_ids": ["threat-risk"],
            "priority": "Low", "mapping_status": "mapped",
        }], [threat], {}, canonical_model())
        tests = align_test_risk_priorities([{
            "test_id": "test-1", "threat_id": "threat-risk", "priority": "Low",
        }], [threat])

        self.assertEqual(controls[0]["priority"], "High")
        self.assertEqual(controls[0]["provider_priority"], "Low")
        self.assertEqual(tests[0]["priority"], "High")
        self.assertEqual(tests[0]["provider_priority"], "Low")

    def test_exports_include_auditable_methodology_fields(self):
        threat = assess_threat_risk(grounded_threat(), canonical_model())
        report = {"threats": [threat], "risk_summary": summarize_threat_findings([threat])}

        markdown = _to_markdown({"name": "Risk fixture"}, report)
        csv_rows = list(csv.DictReader(io.StringIO(_to_csv(report))))

        self.assertIn("dfd-risk-v1.0", markdown)
        self.assertIn("Risk Input Fingerprint", markdown)
        self.assertEqual(csv_rows[0]["Risk Methodology"], "dfd-risk-v1.0")
        self.assertEqual(csv_rows[0]["Risk Score"], "16")

    def test_override_api_rejects_missing_reason(self):
        project = {"project_id": "project-risk", "name": "Risk fixture"}
        report = {"dfd_model": canonical_model(), "threats": [grounded_threat()], "controls": [], "test_scenarios": []}
        with patch("backend.routers.analysis.get_project", return_value=project), patch(
            "backend.routers.analysis.get_report", return_value=report
        ):
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(update_threat_review(
                    "project-risk", "threat-risk", {"risk_override_level": "Low", "risk_override_reason": "short"}
                ))

        self.assertEqual(raised.exception.status_code, 422)
        self.assertIn("reason", raised.exception.detail)

    def test_override_api_records_server_owned_history(self):
        project = {"project_id": "project-risk", "name": "Risk fixture"}
        threat = assess_threat_risk(grounded_threat(
            status="Reviewed", reviewed_at="2026-09-22T00:00:00+00:00"
        ), canonical_model())
        report = {"dfd_model": canonical_model(), "threats": [threat], "controls": [], "test_scenarios": []}
        with patch("backend.routers.analysis.get_project", return_value=project), patch(
            "backend.routers.analysis.get_report", return_value=report
        ), patch("backend.routers.analysis.save_report"), patch("backend.routers.analysis.log_event"):
            response = asyncio.run(update_threat_review(
                "project-risk", "threat-risk", {
                    "risk_override_level": "Medium",
                    "risk_override_reason": "Runtime compensating control reduces practical likelihood.",
                    "risk_override_by": "spoofed-client-value",
                    "risk_override_history": [{"spoofed": True}],
                }
            ))

        updated = response["threat"]
        self.assertEqual(updated["risk_level"], "Medium")
        self.assertEqual(updated["risk_source"], "reviewer_override")
        self.assertEqual(updated["risk_override_by"], "local-developer")
        self.assertEqual(updated["risk_override_history"][0]["reviewer"], "local-developer")
        self.assertEqual(len(updated["risk_override_history"]), 1)
        self.assertNotIn("spoofed", updated["risk_override_history"][0])


if __name__ == "__main__":
    unittest.main()
