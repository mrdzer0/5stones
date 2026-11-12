import asyncio
import copy
import unittest
from unittest.mock import patch

from backend.routers.analysis import (
    _has_valid_empty_threat_assessment,
    _refresh_quality_gate,
    get_project_report,
)
from backend.routers.projects import _enrich_project_readiness
from backend.services.posture_service import compute_signoff_readiness


def ready_report():
    return {
        "completeness": {"score": 100, "level": "Ready", "blockers": []},
        "dfd_validation": {
            "readiness": {"status": "ready", "blocking_reasons": []},
        },
        "dfd_model": {
            "questions": [{"id": "q-1", "status": "resolved"}],
        },
        "trust_boundaries": [{"boundary_id": "b-1", "status": "Confirmed"}],
        "ai_status": {
            stage: {"ok": True, "assessment_status": "complete", "baseline_used": False}
            for stage in ("stride", "linddun", "controls", "tests")
        },
        "analysis_coverage_summary": {
            framework: {
                "complete": True,
                "insufficient_information": 0,
                "unknown_applicability": 0,
            }
            for framework in ("STRIDE", "LINDDUN")
        },
        "threats": [{
            "threat_id": "threat-1",
            "status": "Mitigation Planned",
            "framework": "STRIDE",
        }],
        "controls": [{
            "control_id": "control-1",
            "mapping_status": "mapped",
            "threat_ids": ["threat-1"],
        }],
        "test_scenarios": [{
            "test_id": "test-1",
            "threat_id": "threat-1",
            "applicability_status": "applicable",
            "steps": ["Exercise the affected interaction"],
            "expected_result": "The mitigation prevents the threat",
            "evidence_needed": ["Request and response capture"],
        }],
    }


class UnifiedReadinessTests(unittest.TestCase):
    def test_all_quality_components_must_pass_for_signoff(self):
        gate = compute_signoff_readiness(ready_report())

        self.assertTrue(gate["signoff_ready"])
        self.assertEqual(gate["status"], "ready")
        self.assertFalse(gate["review_required"])
        self.assertTrue(all(value["status"] == "ready" for value in gate["components"].values()))

    def test_high_context_score_cannot_override_unready_dfd(self):
        report = ready_report()
        report["completeness"] = {"score": 97, "level": "Ready", "blockers": []}
        report["dfd_validation"]["readiness"] = {
            "status": "not_ready",
            "blocking_reasons": ["Data Store zone has no evidenced flow"],
        }

        gate = compute_signoff_readiness(report)

        self.assertTrue(gate["components"]["input_context"]["status"] == "ready")
        self.assertEqual(gate["components"]["dfd"]["status"], "not_ready")
        self.assertFalse(gate["signoff_ready"])
        self.assertIn("Data Store zone has no evidenced flow", gate["blocking_reasons"])

    def test_open_questions_and_boundary_candidates_block_signoff(self):
        report = ready_report()
        report["dfd_model"]["questions"][0]["status"] = "open"
        report["trust_boundaries"][0]["status"] = "Candidate"

        gate = compute_signoff_readiness(report)

        reasons = gate["components"]["dfd"]["reasons"]
        self.assertTrue(any("question" in reason for reason in reasons))
        self.assertTrue(any("trust-boundary" in reason for reason in reasons))
        self.assertFalse(gate["signoff_ready"])

    def test_partial_or_preserved_analysis_result_blocks_signoff(self):
        report = ready_report()
        report["ai_status"]["linddun"].update({
            "ok": False,
            "assessment_status": "partial",
            "previous_results_preserved": True,
        })

        gate = compute_signoff_readiness(report)

        self.assertEqual(gate["components"]["analysis"]["status"], "not_ready")
        self.assertTrue(any("LINDDUN" in reason for reason in gate["blocking_reasons"]))

    def test_reviewed_without_disposition_is_not_signoff_ready(self):
        report = ready_report()
        report["threats"][0]["status"] = "Reviewed"

        gate = compute_signoff_readiness(report)

        self.assertEqual(gate["components"]["threat_review"]["status"], "ready")
        self.assertEqual(gate["components"]["control_disposition"]["status"], "not_ready")
        self.assertFalse(gate["signoff_ready"])

    def test_accepted_risk_does_not_require_control_or_test(self):
        report = ready_report()
        report["threats"][0]["status"] = "Accepted"
        report["controls"] = []
        report["test_scenarios"] = []

        gate = compute_signoff_readiness(report)

        self.assertTrue(gate["signoff_ready"])

    def test_valid_empty_framework_result_does_not_require_controls_or_tests(self):
        report = ready_report()
        report["threats"] = []
        report["controls"] = []
        report["test_scenarios"] = []
        for stage in ("stride", "linddun", "controls", "tests"):
            report["ai_status"][stage]["assessment_status"] = "valid_empty"

        self.assertTrue(_has_valid_empty_threat_assessment(report))
        self.assertTrue(compute_signoff_readiness(report)["signoff_ready"])

    def test_missing_framework_result_is_not_valid_empty(self):
        report = ready_report()
        report["threats"] = []
        report["ai_status"]["linddun"]["ok"] = False
        report["ai_status"]["linddun"]["assessment_status"] = "invalid"

        self.assertFalse(_has_valid_empty_threat_assessment(report))

    def test_blocked_or_incomplete_test_is_not_a_verification_plan(self):
        report = ready_report()
        report["test_scenarios"][0].update({
            "applicability_status": "blocked",
            "steps": [],
            "expected_result": "",
            "evidence_needed": [],
        })

        gate = compute_signoff_readiness(report)

        self.assertEqual(gate["components"]["verification_plan"]["status"], "not_ready")
        self.assertFalse(gate["signoff_ready"])

    def test_gate_result_is_deterministic_and_does_not_mutate_report(self):
        report = ready_report()
        original = copy.deepcopy(report)

        first = compute_signoff_readiness(report)
        second = compute_signoff_readiness(report)

        self.assertEqual(first, second)
        self.assertEqual(report, original)

    def test_report_and_analysis_run_share_the_same_gate(self):
        report = ready_report()
        report["analysis_run"] = {"status": "completed"}

        gate = _refresh_quality_gate(report)

        self.assertEqual(report["quality_gate"], gate)
        self.assertEqual(report["analysis_run"]["quality_gate"], gate)
        self.assertFalse(report["analysis_run"]["review_required"])

    def test_project_read_uses_current_context_with_saved_report(self):
        project = {"project_id": "project-1"}
        current_context = {
            "score": 25,
            "level": "Insufficient context",
            "blockers": [{"area": "Architecture"}],
        }
        with patch("backend.routers.projects.get_report", return_value=ready_report()), patch(
            "backend.routers.projects.compute_completeness", return_value=current_context
        ):
            _enrich_project_readiness(project)

        self.assertTrue(project["has_report"])
        self.assertFalse(project["signoff_ready"])
        self.assertEqual(project["quality_gate"]["components"]["input_context"]["score"], 25)

    def test_report_read_recomputes_gate_with_current_project_context(self):
        current_context = {
            "score": 25,
            "level": "Insufficient context",
            "blockers": [{"area": "Architecture"}],
        }
        report = ready_report()
        with patch("backend.routers.analysis.get_project", return_value={"project_id": "project-1"}), patch(
            "backend.routers.analysis.get_report", return_value=report
        ), patch(
            "backend.routers.analysis.normalize_report_evidence", side_effect=lambda value, _project: value
        ), patch(
            "backend.routers.analysis.compute_completeness", return_value=current_context
        ), patch("backend.routers.analysis.get_dfd_model", return_value=None):
            response = asyncio.run(get_project_report("project-1"))

        self.assertEqual(response["completeness"]["score"], 25)
        self.assertFalse(response["quality_gate"]["signoff_ready"])


if __name__ == "__main__":
    unittest.main()
