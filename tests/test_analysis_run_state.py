import asyncio
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from backend.routers.analysis import _valid_completed_stages, run_full_analysis


class AnalysisRunStateTests(unittest.TestCase):
    def setUp(self):
        self.project = {
            "project_id": "project-run-state",
            "name": "Run state fixture",
            "analysis_status": "completed",
        }
        self.old_report = {
            "report_id": "report-old",
            "project_id": self.project["project_id"],
            "analysis_run": {
                "run_id": "run-old",
                "status": "completed",
                "requested_types": ["trust_boundary"],
            },
            "dfd_model": {"revision": 4},
        }

    def test_pipeline_failure_persists_retryable_state_and_preserves_old_report(self):
        saved_reports = []

        def save_report(_, report):
            saved_reports.append(report.copy())
            return report

        with patch("backend.routers.analysis.get_project", return_value=self.project.copy()), \
             patch("backend.routers.analysis.get_report", return_value=self.old_report.copy()), \
             patch("backend.routers.analysis.save_report", side_effect=save_report), \
             patch("backend.routers.analysis.save_project"), \
             patch("backend.routers.analysis._run_analysis_pipeline", side_effect=RuntimeError("provider timeout")):
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(run_full_analysis(self.project["project_id"], {"analysis_types": ["stride"]}))

        self.assertEqual(raised.exception.status_code, 500)
        failed = saved_reports[-1]
        self.assertEqual(failed["analysis_run"]["status"], "failed")
        self.assertTrue(failed["analysis_run"]["retryable"])
        self.assertEqual(failed["dfd_model"]["revision"], 4)

    def test_success_with_fallback_is_persisted_as_warning(self):
        saved_reports = []

        def save_report(_, report):
            saved_reports.append(report.copy())
            return report

        result = {
            **self.old_report,
            "ai_status": {"stride": {"ok": False, "engine": "fallback", "error": "provider unavailable"}},
            "risk_summary": {"total": 1},
        }
        with patch("backend.routers.analysis.get_project", return_value=self.project.copy()), \
             patch("backend.routers.analysis.get_report", return_value=self.old_report.copy()), \
             patch("backend.routers.analysis.save_report", side_effect=save_report), \
             patch("backend.routers.analysis.save_project"), \
             patch("backend.routers.analysis._run_analysis_pipeline", return_value=result):
            completed = asyncio.run(run_full_analysis(self.project["project_id"], {"analysis_types": ["stride"]}))

        self.assertEqual(completed["analysis_run"]["status"], "completed_with_warnings")
        self.assertEqual(completed["analysis_run"]["warning_stages"], ["stride"])
        self.assertTrue(completed["analysis_run"]["retryable"])

    def test_stale_stages_clear_only_after_current_valid_results(self):
        report = {
            "dfd_model": {"revision": 9},
            "assumptions": [],
            "ai_status": {
                "trust_boundary": {"ok": True},
                "dfd_model": {"ok": True},
                "stride": {"ok": True, "assessment_status": "complete"},
                "controls": {"ok": False, "engine": "fallback"},
                "tests": {"ok": False, "engine": "fallback"},
                "missing_info": {"ok": True},
            },
        }

        completed = _valid_completed_stages(
            report,
            ["trust_boundary", "stride", "controls", "tests", "missing_info", "assumptions"],
        )

        self.assertEqual(completed, ["trust_boundary", "stride", "missing_info", "assumptions"])

    def test_f08_snapshot_and_dependency_gate_stale_clearing(self):
        snapshot = {"dfd_revision": 12, "dfd_semantic_hash": "hash-12"}
        current = {
            "run_id": "run-current",
            "ok": True,
            "assessment_status": "complete",
            "analysis_snapshot": snapshot,
        }
        stale = {
            "run_id": "run-old",
            "ok": True,
            "assessment_status": "complete",
            "analysis_snapshot": {"dfd_revision": 11, "dfd_semantic_hash": "hash-11"},
        }
        report = {
            "dfd_model": {"revision": 12, "semantic_hash": "hash-12"},
            "assumptions": [],
            "ai_status": {
                "trust_boundary": current,
                "dfd_model": current,
                "stride": current,
                "linddun": stale,
                "controls": current,
                "tests": current,
                "assumptions": current,
            },
        }

        completed = _valid_completed_stages(
            report,
            ["trust_boundary", "stride", "linddun", "controls", "tests", "assumptions"],
            run_id="run-current",
            snapshot=snapshot,
        )

        self.assertEqual(completed, ["trust_boundary", "stride"])

    def test_f08_failed_or_unrequested_stage_cannot_be_reported_as_run_warning(self):
        saved_reports = []
        result = {
            **self.old_report,
            "ai_status": {
                "stride": {"ok": False, "engine": "fallback"},
                "controls": {"ok": False, "engine": "fallback"},
            },
            "risk_summary": {"total": 1},
        }
        with patch("backend.routers.analysis.get_project", return_value=self.project.copy()), \
             patch("backend.routers.analysis.get_report", return_value=self.old_report.copy()), \
             patch("backend.routers.analysis.save_report", side_effect=lambda _, report: saved_reports.append(report.copy())), \
             patch("backend.routers.analysis.save_project"), \
             patch("backend.routers.analysis._run_analysis_pipeline", return_value=result):
            completed = asyncio.run(run_full_analysis(self.project["project_id"], {"analysis_types": ["stride"]}))

        self.assertEqual(completed["analysis_run"]["warning_stages"], ["stride"])

    def test_f08_run_manifest_is_promoted_to_persisted_analysis_run(self):
        result = {
            **self.old_report,
            "ai_status": {"stride": {"ok": True, "assessment_status": "complete"}},
            "risk_summary": {"total": 1},
            "analysis_run_manifest": {
                "final_snapshot": {"dfd_revision": 4, "dfd_semantic_hash": "hash-4"},
                "completed_stages": ["stride"],
                "stage_timings": {"stride": 1.25},
            },
        }
        with patch("backend.routers.analysis.get_project", return_value=self.project.copy()), \
             patch("backend.routers.analysis.get_report", return_value=self.old_report.copy()), \
             patch("backend.routers.analysis.save_report"), \
             patch("backend.routers.analysis.save_project"), \
             patch("backend.routers.analysis._run_analysis_pipeline", return_value=result):
            completed = asyncio.run(run_full_analysis(self.project["project_id"], {"analysis_types": ["stride"]}))

        self.assertEqual(completed["analysis_run"]["final_snapshot"]["dfd_revision"], 4)
        self.assertEqual(completed["analysis_run"]["completed_stages"], ["stride"])
        self.assertEqual(completed["analysis_run"]["stage_timings"]["stride"], 1.25)


if __name__ == "__main__":
    unittest.main()
