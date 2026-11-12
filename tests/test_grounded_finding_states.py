import asyncio
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from backend.routers.analysis import update_threat_review
from backend.services.posture_service import (
    build_project_evidence_catalog,
    enrich_threats,
    normalize_report_evidence,
    summarize_threat_findings,
)
from backend.services.threat_validation_service import validate_generated_threats


def evidence_project(snippet="Login requests are processed by the authentication service."):
    return {
        "project_id": "project-1",
        "name": "Grounding fixture",
        "artifact_sources": [{
            "artifact_id": "artifact-1",
            "filename": "prd.md",
            "artifact_type": "prd",
            "active": True,
            "revision": 1,
            "content_hash": "hash-1",
            "evidence_items": [{"locator": "Security", "snippet": snippet, "topics": ["login"]}],
        }],
    }


def base_threat(evidence_ref=None):
    return {
        "threat_id": "threat-1",
        "framework": "STRIDE",
        "threat_category": "Spoofing",
        "threat_description": "No rate limiting is evidenced on login, enabling credential stuffing.",
        "component": "Login API",
        "source": "Internet user",
        "destination": "Login API",
        "affected_refs": ["flow-login"],
        "primary_interaction_ref": "flow-login",
        "interaction_mapping_status": "mapped",
        "evidence_refs": [evidence_ref] if evidence_ref else [],
        "confidence": "High",
        "risk_level": "High",
        "status": "Open",
    }


class GroundedFindingStateTests(unittest.TestCase):
    def test_provider_cannot_self_assign_verified_finding(self):
        raw = base_threat("EV-1")
        raw.update({"status": "Verified", "finding_state": "verified", "vulnerability_status": "verified"})
        model = {
            "revision": 3,
            "semantic_hash": "hash",
            "nodes": [{"id": "node-login"}],
            "flows": [{"id": "flow-login"}],
        }

        accepted, warnings = validate_generated_threats([raw], "STRIDE", model, {"EV-1"})

        self.assertEqual(warnings, [])
        self.assertEqual(accepted[0]["status"], "Open")
        self.assertEqual(accepted[0]["finding_state"], "hypothesis")
        self.assertEqual(accepted[0]["vulnerability_status"], "not_verified")
        self.assertTrue(accepted[0]["needs_human_review"])

    def test_document_omission_becomes_needs_context_not_vulnerability(self):
        project = evidence_project()
        evidence_id = build_project_evidence_catalog(project)[0]["evidence_id"]
        threat = base_threat(evidence_id)

        finding = normalize_report_evidence({
            "threats": enrich_threats([threat], project, "STRIDE"),
            "dfd_model": {"flows": [{"id": "flow-login"}], "nodes": [], "data_objects": [], "boundaries": []},
        }, project)["threats"][0]

        self.assertEqual(finding["finding_state"], "needs_context")
        self.assertEqual(finding["status"], "Needs Info")
        self.assertEqual(finding["risk_level"], "Unknown")
        self.assertEqual(finding["scenario_risk_level"], "Medium")
        self.assertEqual(finding["provider_risk_level"], "High")
        self.assertEqual(finding["risk_status"], "deferred")
        self.assertEqual(finding["vulnerability_status"], "not_verified")
        self.assertTrue(finding["absence_of_evidence_guarded"])
        self.assertIn("Hypothesis requiring evidence", finding["threat_description"])
        self.assertIn("explicit implementation or runtime evidence", finding["missing_info"])

    def test_explicit_direct_control_gap_can_ground_scenario(self):
        project = evidence_project("Rate limiting is disabled on the login endpoint.")
        evidence_id = build_project_evidence_catalog(project)[0]["evidence_id"]
        threat = base_threat(evidence_id)
        threat["control_gap_evidence_refs"] = [evidence_id]

        finding = normalize_report_evidence({
            "threats": enrich_threats([threat], project, "STRIDE"),
            "dfd_model": {"flows": [{"id": "flow-login"}], "nodes": [], "data_objects": [], "boundaries": []},
        }, project)["threats"][0]

        self.assertEqual(finding["finding_state"], "grounded")
        self.assertEqual(finding["risk_level"], "Medium")
        self.assertEqual(finding["provider_risk_level"], "High")
        self.assertEqual(finding["risk_methodology_version"], "dfd-risk-v1.0")
        self.assertEqual(finding["control_gap_evidence_refs"], [evidence_id])
        self.assertFalse(finding.get("absence_of_evidence_guarded", False))
        self.assertEqual(finding["vulnerability_status"], "not_verified")

    def test_documented_omission_is_not_explicit_control_gap_evidence(self):
        project = evidence_project("Rate limiting is not documented for the login endpoint.")
        evidence_id = build_project_evidence_catalog(project)[0]["evidence_id"]
        threat = base_threat(evidence_id)
        threat["control_gap_evidence_refs"] = [evidence_id]

        finding = enrich_threats([threat], project, "STRIDE")[0]

        self.assertEqual(finding["finding_state"], "needs_context")
        self.assertEqual(finding["control_gap_evidence_refs"], [])

    def test_summary_does_not_score_needs_context_as_high_vulnerability(self):
        threats = [
            {**base_threat(), "finding_state": "needs_context", "risk_level": "Unknown", "scenario_risk_level": "High"},
            {**base_threat(), "threat_id": "threat-2", "finding_state": "grounded", "risk_level": "High"},
        ]

        summary = summarize_threat_findings(threats)

        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["high"], 1)
        self.assertEqual(summary["scored_total"], 1)
        self.assertEqual(summary["needs_context_total"], 1)
        self.assertEqual(summary["verified_vulnerability_total"], 0)

    def test_legacy_report_is_guarded_on_read_without_rerun(self):
        project = evidence_project()
        evidence_id = build_project_evidence_catalog(project)[0]["evidence_id"]
        report = {"threats": [base_threat(evidence_id)], "risk_summary": {"high": 1, "total": 1}}

        normalized = normalize_report_evidence(report, project)

        self.assertEqual(normalized["threats"][0]["finding_state"], "needs_context")
        self.assertEqual(normalized["risk_summary"]["high"], 0)
        self.assertEqual(normalized["risk_summary"]["needs_context_total"], 1)

    def test_verified_review_status_requires_verification_evidence(self):
        project = evidence_project()
        report = {"threats": [base_threat()], "controls": [], "test_scenarios": []}
        with patch("backend.routers.analysis.get_project", return_value=project), patch(
            "backend.routers.analysis.get_report", return_value=report
        ):
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(update_threat_review("project-1", "threat-1", {"status": "Verified"}))

        self.assertEqual(raised.exception.status_code, 422)
        self.assertIn("verification_evidence_refs", raised.exception.detail)

    def test_verified_vulnerability_requires_confirmed_verification_contract(self):
        project = evidence_project("Runtime test reproduced credential replay on the login endpoint.")
        evidence_id = build_project_evidence_catalog(project)[0]["evidence_id"]
        threat = base_threat(evidence_id)
        threat.update({
            "threat_description": "Credential replay permits account takeover on the login endpoint.",
            "status": "Verified",
            "reviewed_at": "2026-09-21T00:00:00Z",
            "verification_evidence_refs": [evidence_id],
            "verification_method": "runtime_test",
            "verification_result": "confirmed",
        })

        finding = normalize_report_evidence({
            "threats": [threat],
            "dfd_model": {"flows": [{"id": "flow-login"}], "nodes": [], "data_objects": [], "boundaries": []},
        }, project)["threats"][0]

        self.assertEqual(finding["finding_state"], "verified")
        self.assertEqual(finding["vulnerability_status"], "verified")
        self.assertEqual(finding["risk_status"], "assessed")

    def test_legacy_verified_label_is_downgraded_without_verification_contract(self):
        project = evidence_project()
        evidence_id = build_project_evidence_catalog(project)[0]["evidence_id"]
        threat = base_threat(evidence_id)
        threat.update({"status": "Verified", "reviewed_at": "2026-09-21T00:00:00Z"})

        finding = normalize_report_evidence({
            "threats": [threat],
            "dfd_model": {"flows": [{"id": "flow-login"}], "nodes": [], "data_objects": [], "boundaries": []},
        }, project)["threats"][0]

        self.assertEqual(finding["status"], "Reviewed")
        self.assertEqual(finding["reported_status"], "Verified")
        self.assertEqual(finding["verification_state"], "insufficient_evidence")
        self.assertEqual(finding["vulnerability_status"], "not_verified")


if __name__ == "__main__":
    unittest.main()
