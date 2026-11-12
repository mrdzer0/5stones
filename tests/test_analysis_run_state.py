import asyncio
import unittest
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from fastapi import HTTPException

from backend.routers.analysis import (
    AnalysisRunAdmission,
    _ANALYSIS_RUN_ADMISSION,
    _valid_completed_stages,
    run_full_analysis,
)


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
        self.assertFalse(_ANALYSIS_RUN_ADMISSION.is_active(self.project["project_id"]))
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


class AnalysisRunAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.project = {"project_id": "admission-project", "name": "Admission fixture"}

    def test_capacity_is_atomic_and_preserves_per_project_conflict(self):
        admission = AnalysisRunAdmission(capacity=2)

        self.assertIsNone(admission.reserve("project-a"))
        self.assertEqual(admission.reserve("project-a"), "duplicate")
        self.assertIsNone(admission.reserve("project-b"))
        self.assertEqual(admission.reserve("project-c"), "capacity")
        self.assertTrue(admission.is_active("project-a"))
        admission.release("project-a")
        self.assertIsNone(admission.reserve("project-c"))

    def test_concurrent_distinct_reservations_never_exceed_capacity(self):
        capacity = 4
        admission = AnalysisRunAdmission(capacity=capacity)
        barrier = threading.Barrier(16)

        def reserve(index):
            barrier.wait()
            return admission.reserve(f"project-{index}")

        with ThreadPoolExecutor(max_workers=16) as pool:
            outcomes = list(pool.map(reserve, range(16)))

        self.assertEqual(outcomes.count(None), capacity)

    def test_route_returns_429_with_retry_after_when_capacity_is_full(self):
        admission = AnalysisRunAdmission(capacity=1)
        self.assertIsNone(admission.reserve("other-project"))
        with patch("backend.routers.analysis._ANALYSIS_RUN_ADMISSION", admission), \
             patch("backend.routers.analysis.get_project", return_value=self.project):
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(run_full_analysis(self.project["project_id"], {"analysis_types": ["stride"]}))

        self.assertEqual(raised.exception.status_code, 429)
        self.assertEqual(raised.exception.headers["Retry-After"], "30")
        admission.release("other-project")

    def test_route_preserves_409_for_a_project_that_already_has_a_run(self):
        admission = AnalysisRunAdmission(capacity=2)
        self.assertIsNone(admission.reserve(self.project["project_id"]))
        with patch("backend.routers.analysis._ANALYSIS_RUN_ADMISSION", admission), \
             patch("backend.routers.analysis.get_project", return_value=self.project):
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(run_full_analysis(self.project["project_id"], {"analysis_types": ["stride"]}))

        self.assertEqual(raised.exception.status_code, 409)
        admission.release(self.project["project_id"])

    def test_slot_is_released_when_setup_fails_before_pipeline(self):
        admission = AnalysisRunAdmission(capacity=1)
        with patch("backend.routers.analysis._ANALYSIS_RUN_ADMISSION", admission), \
             patch("backend.routers.analysis.get_project", return_value=self.project), \
             patch("backend.routers.analysis.get_report", side_effect=RuntimeError("storage unavailable")):
            with self.assertRaisesRegex(RuntimeError, "storage unavailable"):
                asyncio.run(run_full_analysis(self.project["project_id"], {"analysis_types": ["stride"]}))

        self.assertFalse(admission.is_active(self.project["project_id"]))


if __name__ == "__main__":
    unittest.main()
