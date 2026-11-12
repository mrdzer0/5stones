import asyncio
import copy
import unittest
from unittest.mock import patch

from backend.routers.analysis import (
    AnalysisPublishConflict,
    _apply_recovery_snapshot,
    _assert_analysis_publish_safe,
    run_full_analysis,
)


class Ri0RecoveryTests(unittest.TestCase):
    def test_validated_result_with_warnings_does_not_restore_old_snapshot(self):
        snapshot = {"snapshot_id": "old", "threats": [{"threat_id": "old", "framework": "STRIDE"}]}
        report = {"threats": [{"threat_id": "new", "framework": "STRIDE"}],
                  "ai_status": {"stride": {"ok": False, "engine": "AI", "assessment_status": "complete",
                                           "validation_warnings": ["One dangling reference was removed"]}}}
        recovery = _apply_recovery_snapshot(report, snapshot, ["stride"])
        self.assertEqual(recovery, {})
        self.assertEqual([item["threat_id"] for item in report["threats"]], ["new"])

    def test_validated_partial_result_keeps_current_candidates(self):
        snapshot = {"snapshot_id": "old", "threats": [{"threat_id": "old", "framework": "LINDDUN"}]}
        report = {"threats": [{"threat_id": "new", "framework": "LINDDUN"}],
                  "ai_status": {"linddun": {"ok": False, "engine": "AI", "assessment_status": "partial"}}}
        self.assertEqual(_apply_recovery_snapshot(report, snapshot, ["linddun"]), {})
        self.assertEqual([item["threat_id"] for item in report["threats"]], ["new"])

    def test_failed_frameworks_restore_only_the_prior_snapshot_as_historical(self):
        snapshot = {
            "snapshot_id": "recovery-fixture",
            "threats": [
                {"threat_id": "stride-old", "framework": "STRIDE", "status": "Open"},
                {"threat_id": "linddun-old", "framework": "LINDDUN", "status": "Reviewed"},
            ],
            "controls": [{"control_id": "control-old", "name": "Encrypt data"}],
            "test_scenarios": [{"test_id": "test-old", "scenario_name": "Attempt disclosure"}],
        }
        report = {
            "threats": [],
            "controls": [],
            "test_scenarios": [],
            "ai_status": {
                "stride": {"ok": False, "engine": "AI", "assessment_status": "invalid"},
                "linddun": {"ok": False, "engine": "AI", "assessment_status": "invalid"},
                "controls": {"ok": False, "engine": "blocked", "assessment_status": "blocked"},
                "tests": {"ok": False, "engine": "blocked", "assessment_status": "blocked"},
            },
        }

        recovery = _apply_recovery_snapshot(
            report,
            snapshot,
            ["stride", "linddun", "controls", "tests"],
        )

        self.assertEqual(recovery["state"], "previous_results_preserved")
        self.assertFalse(recovery["baseline_used"])
        self.assertEqual(
            {item["threat_id"] for item in report["threats"]},
            {"stride-old", "linddun-old"},
        )
        self.assertTrue(all(item["analysis_state"] == "historical" for item in report["threats"]))
        self.assertEqual(report["controls"][0]["analysis_state"], "historical")
        self.assertEqual(report["test_scenarios"][0]["analysis_state"], "historical")
        self.assertTrue(report["ai_status"]["stride"]["previous_results_preserved"])
        self.assertTrue(report["ai_status"]["controls"]["previous_results_preserved"])

    def test_invalid_stage_without_prior_result_is_not_reported_as_baseline(self):
        report = {
            "ai_status": {
                "stride": {"ok": False, "engine": "AI", "assessment_status": "invalid"},
            },
        }

        recovery = _apply_recovery_snapshot(report, None, ["stride"])

        self.assertEqual(recovery["state"], "analysis_unavailable")
        self.assertFalse(recovery["baseline_used"])
        self.assertFalse(report["ai_status"]["stride"]["baseline_used"])

    def test_final_publish_merges_latest_project_before_updating_analysis_fields(self):
        project_id = "ri0-project"
        initial = {
            "project_id": project_id,
            "name": "RI0 fixture",
            "analysis_status": "completed",
        }
        latest = {
            **copy.deepcopy(initial),
            "artifact_sources": [{"artifact_id": "new-artifact", "active": True}],
            "updated_at": "newer-than-run-input",
        }
        result = {
            "project_id": project_id,
            "ai_status": {"stride": {"ok": True, "assessment_status": "complete"}},
            "risk_summary": {"total": 3, "current_total": 3},
            "completeness": {"score": 82, "level": "Usable with gaps"},
        }
        saved_projects = []

        with (
            patch(
                "backend.routers.analysis.get_project",
                side_effect=[copy.deepcopy(initial), copy.deepcopy(latest), copy.deepcopy(latest)],
            ),
            patch("backend.routers.analysis.get_report", return_value={"project_id": project_id}),
            patch("backend.routers.analysis.save_report"),
            patch("backend.routers.analysis.save_project", side_effect=lambda project: saved_projects.append(copy.deepcopy(project))),
            patch("backend.routers.analysis._run_analysis_pipeline", return_value=result),
        ):
            completed = asyncio.run(run_full_analysis(project_id, {"analysis_types": ["stride"]}))

        published = saved_projects[-1]
        self.assertEqual(published["artifact_sources"][0]["artifact_id"], "new-artifact")
        self.assertEqual(published["risk_summary"]["total"], 3)
        self.assertEqual(published["completeness_score"], 82)
        self.assertEqual(published["analysis_status"], completed["analysis_status"])
        self.assertTrue(published.get("analysis_run_id"))

    def test_publish_rejects_a_newer_canonical_dfd_revision(self):
        report = {
            "dfd_model": {"revision": 4, "semantic_hash": "hash-4"},
            "analysis_run_manifest": {"base_report_revision": 7},
            "threats": [],
        }
        latest_report = {"report_revision": 8, "dfd_model": {"revision": 5, "semantic_hash": "hash-5"}}

        with patch("backend.routers.analysis.get_report", return_value=latest_report), \
             patch("backend.routers.analysis.get_dfd_model", return_value=latest_report["dfd_model"]):
            with self.assertRaises(AnalysisPublishConflict):
                _assert_analysis_publish_safe(report, "ri0-project")


if __name__ == "__main__":
    unittest.main()
