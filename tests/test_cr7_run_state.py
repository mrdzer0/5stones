import asyncio
import csv
import io
import unittest
from unittest.mock import patch

from backend.routers.analysis import get_project_report
from backend.routers.export import _to_csv, _to_markdown
from backend.routers.projects import _enrich_project_readiness
from backend.services.formal_report_service import build_formal_report_metadata
from backend.services.run_state_service import build_analysis_state


class Cr7RunStateTests(unittest.TestCase):
    def test_new_project_is_typed_not_started_with_run_action(self):
        state = build_analysis_state({})

        self.assertEqual(state["schema_version"], "analysis-state-v1")
        self.assertEqual(state["result_state"], "not_started")
        self.assertEqual(state["status_label"], "Not started")
        self.assertEqual(state["next_actions"][0]["id"], "run_analysis")
        self.assertFalse(state["signoff_ready"])

    def test_progress_is_authoritative_for_active_stage(self):
        report = {
            "analysis_run": {"run_id": "run-1", "status": "running", "requested_types": ["trust_boundary", "stride"]},
            "ai_status": {
                "trust_boundary": {"ok": True, "assessment_status": "complete"},
                "stride": {"ok": False, "assessment_status": "not_run"},
            },
        }
        progress = {
            "run_id": "run-1",
            "status": "running",
            "requested_types": ["trust_boundary", "stride"],
            "active_stage": "stride",
            "stages": {
                "trust_boundary": {"state": "completed", "duration_seconds": 1.2},
                "stride": {"state": "active", "started_at": "2026-09-25T00:00:00Z"},
            },
        }

        state = build_analysis_state(report, progress=progress)

        self.assertEqual(state["status"], "running")
        self.assertEqual(state["active_stage"], "stride")
        stages = {item["id"]: item for item in state["stages"]}
        self.assertEqual(stages["trust_boundary"]["state"], "completed")
        self.assertEqual(stages["stride"]["status"], "running")
        self.assertEqual(state["next_actions"][0]["id"], "monitor_analysis")

    def test_fallback_and_partial_are_not_completed_or_clean(self):
        report = {
            "analysis_run": {"run_id": "run-2", "status": "completed_with_warnings", "requested_types": ["stride"]},
            "ai_status": {
                "stride": {
                    "ok": False,
                    "engine": "fallback",
                    "baseline_used": True,
                    "assessment_status": "fallback",
                },
            },
            "risk_summary": {"total": 0, "scored_total": 0},
            "quality_gate": {"signoff_ready": False, "components": {"analysis": {"status": "not_ready", "reasons": ["STRIDE fallback"]}}},
        }

        state = build_analysis_state(report)

        self.assertEqual(state["result_state"], "fallback")
        self.assertEqual(state["status_label"], "Fallback")
        self.assertIn("stride", state["baseline_stages"])
        self.assertTrue(any(item["id"] == "retry_stride" for item in state["next_actions"]))

    def test_stale_and_preserved_results_remain_explicit(self):
        report = {
            "analysis_run": {"run_id": "run-3", "status": "completed_with_warnings", "requested_types": ["stride"]},
            "analysis_recovery": {
                "state": "previous_results_preserved",
                "retryable": True,
                "message": "Previous validated results remain available.",
            },
            "analysis_stale": {"stages": ["stride"]},
            "ai_status": {
                "stride": {
                    "ok": False,
                    "assessment_status": "partial",
                    "previous_results_preserved": True,
                },
            },
            "threats": [{"threat_id": "old-1", "analysis_state": "historical"}],
        }

        state = build_analysis_state(report)

        self.assertEqual(state["result_state"], "partial")
        self.assertEqual(state["preserved_stages"], ["stride"])
        self.assertEqual(state["stale_stages"], ["stride"])
        self.assertEqual(state["trusted_result_scope"]["historical_finding_count"], 1)
        self.assertTrue(any(item["code"] == "analysis_recovery" for item in state["blockers"]))

    def test_project_readiness_exposes_same_state_without_report(self):
        project = {"project_id": "new-project"}
        completeness = {"score": 0, "level": "Not scored", "blockers": []}
        with patch("backend.routers.projects.get_report", return_value=None), patch(
            "backend.routers.projects.compute_completeness", return_value=completeness
        ):
            _enrich_project_readiness(project)

        self.assertEqual(project["analysis_state"]["result_state"], "not_started")
        self.assertFalse(project["signoff_ready"])

    def test_report_endpoint_returns_not_started_projection_instead_of_404(self):
        project = {"project_id": "new-project", "name": "New project"}
        with patch("backend.routers.analysis.get_project", return_value=project), patch(
            "backend.routers.analysis.get_report", return_value=None
        ), patch("backend.routers.analysis.get_dfd_model", return_value=None), patch(
            "backend.routers.analysis.normalize_report_evidence", side_effect=lambda value, _project: value
        ):
            response = asyncio.run(get_project_report("new-project"))

        self.assertEqual(response["analysis_status"], "not_started")
        self.assertEqual(response["analysis_state"]["result_state"], "not_started")
        self.assertFalse(response["quality_gate"]["signoff_ready"])

    def test_formal_metadata_and_exports_carry_state_and_provenance(self):
        report = {
            "analysis_status": "completed_with_warnings",
            "analysis_run": {
                "run_id": "run-export",
                "status": "completed_with_warnings",
                "requested_types": ["stride"],
                "warning_stages": ["stride"],
                "provider": {"source": "byok", "provider_name": "Fixture", "model": "fixture-model", "base_url": "https://llm.example/v1"},
            },
            "ai_status": {"stride": {"engine": "fallback", "baseline_used": True, "assessment_status": "fallback"}},
            "analysis_coverage_summary": {"STRIDE": {"assessed": 1, "deferred": 2, "failed": 0, "unprocessed": 0, "complete": False}},
            "quality_gate": {"signoff_ready": False, "blocking_reasons": ["STRIDE fallback"]},
            "risk_summary": {"total": 0, "scored_total": 0, "needs_context_total": 2},
            "threats": [],
        }
        project = {"project_id": "export-project", "name": "Export project", "artifact_sources": []}
        report["formal_report"] = build_formal_report_metadata(project, report)
        state = build_analysis_state(report)
        report["analysis_state"] = state

        csv_text = _to_csv(report)
        rows = list(csv.reader(io.StringIO(csv_text)))
        markdown = _to_markdown(project, report)

        self.assertEqual(rows[0][0], "Analysis Status")
        self.assertEqual(rows[1][0], "Fallback")
        self.assertIn("Provider: Fixture", markdown)
        self.assertIn("Fallback active", markdown)
        self.assertIn("Framework Coverage", markdown)
        self.assertIn("not a clean bill of health", markdown)


if __name__ == "__main__":
    unittest.main()
