import copy
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from backend.utils import storage


class ProjectRevisionCasTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.patches = [
            patch.object(storage, "DATA_DIR", root),
            patch.object(storage, "PROJECTS_DIR", root / "projects"),
            patch.object(storage, "REPORTS_DIR", root / "reports"),
            patch.object(storage, "DFD_MODELS_DIR", root / "dfd_models"),
        ]
        for item in self.patches:
            item.start()
        storage.PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
        storage.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        storage.DFD_MODELS_DIR.mkdir(parents=True, exist_ok=True)
        self.project_id = "cas-test-project"

    def _seed_project(self):
        storage.save_project({"project_id": self.project_id, "name": "CAS fixture"})

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp_dir.cleanup()

    def test_stale_report_revision_is_rejected(self):
        self._seed_project()
        storage.save_report(self.project_id, {"report_revision": 0, "value": "first"})
        stale = storage.get_report(self.project_id)
        storage.save_report(self.project_id, {"report_revision": 1, "value": "second"})

        with self.assertRaises(storage.RevisionConflict) as caught:
            storage.save_report(self.project_id, stale)

        self.assertEqual(caught.exception.expected_revision, 1)
        self.assertEqual(caught.exception.current_revision, 2)
        self.assertEqual(storage.get_report(self.project_id)["value"], "second")

    def test_parallel_report_and_dfd_updates_have_one_winner(self):
        self._seed_project()
        storage.save_report(self.project_id, {"report_revision": 0, "value": "base"})
        storage.save_dfd_model(self.project_id, {"revision": 1, "marker": "base"}, expected_revision=0)
        base_report, base_dfd = storage.get_project_report_and_dfd(self.project_id)
        barrier = threading.Barrier(2)

        def update(marker):
            report = copy.deepcopy(base_report)
            dfd_model = {"revision": 2, "marker": marker}
            report["value"] = marker
            barrier.wait()
            try:
                storage.save_report_and_dfd(
                    self.project_id,
                    report,
                    dfd_model,
                    expected_report_revision=base_report["report_revision"],
                    expected_dfd_revision=base_dfd["revision"],
                )
                return "saved"
            except (storage.RevisionConflict, storage.DfdRevisionConflict):
                return "conflict"

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(update, ("reviewer-a", "reviewer-b")))

        self.assertCountEqual(results, ["saved", "conflict"])
        report, dfd_model = storage.get_project_report_and_dfd(self.project_id)
        self.assertEqual(report["report_revision"], 2)
        self.assertEqual(dfd_model["revision"], 2)
        self.assertEqual(report["value"], dfd_model["marker"])

    def test_pair_write_rejects_a_dfd_snapshot_older_than_canonical(self):
        self._seed_project()
        storage.save_report(self.project_id, {"report_revision": 0, "value": "current"})
        storage.save_dfd_model(self.project_id, {"revision": 2, "marker": "canonical"}, expected_revision=0)
        report = storage.get_report(self.project_id)
        report["value"] = "stale-analysis"

        with self.assertRaises(storage.DfdRevisionConflict) as caught:
            storage.save_report_and_dfd(
                self.project_id,
                report,
                {"revision": 1, "marker": "stale-analysis"},
                expected_report_revision=report["report_revision"],
                expected_dfd_revision=2,
            )

        self.assertEqual(caught.exception.expected_revision, 1)
        self.assertEqual(caught.exception.current_revision, 2)
        self.assertEqual(storage.get_dfd_model(self.project_id)["marker"], "canonical")

    def test_project_deletion_prevents_late_report_or_dfd_recreation(self):
        self._seed_project()
        report = storage.save_report(self.project_id, {"report_revision": 0, "value": "existing"})
        project = storage.get_project(self.project_id)
        self.assertTrue(storage.delete_project(self.project_id, expected_revision=project["project_revision"]))

        with self.assertRaises(storage.ProjectNotFoundError):
            storage.save_report(self.project_id, report)
        with self.assertRaises(storage.ProjectNotFoundError):
            storage.save_dfd_model(self.project_id, {"revision": 1})

        self.assertIsNone(storage.get_report(self.project_id))
        self.assertIsNone(storage.get_dfd_model(self.project_id))

    def test_parallel_project_edits_have_one_winner_and_preserve_revision(self):
        storage.save_project({"project_id": self.project_id, "name": "base"})
        base = storage.get_project(self.project_id)
        barrier = threading.Barrier(2)

        def update(name):
            project = copy.deepcopy(base)
            project["name"] = name
            barrier.wait()
            try:
                storage.save_project(project)
                return "saved"
            except storage.ProjectRevisionConflict:
                return "conflict"

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(update, ("analyst-a", "analyst-b")))

        self.assertCountEqual(results, ["saved", "conflict"])
        current = storage.get_project(self.project_id)
        self.assertEqual(current["project_revision"], 2)
        self.assertIn(current["name"], {"analyst-a", "analyst-b"})

    def test_stale_project_cannot_overwrite_or_recreate_deleted_project(self):
        storage.save_project({"project_id": self.project_id, "name": "before"})
        stale = storage.get_project(self.project_id)
        storage.save_project({**stale, "name": "newer"})

        with self.assertRaises(storage.ProjectRevisionConflict):
            storage.save_project(stale)
        current = storage.get_project(self.project_id)
        self.assertTrue(storage.delete_project(self.project_id, expected_revision=current["project_revision"]))

        with self.assertRaises(storage.ProjectRevisionConflict):
            storage.save_project(stale)
        self.assertIsNone(storage.get_project(self.project_id))

    def test_project_ids_cannot_escape_storage_directories(self):
        traversal_id = "../reports/cas-test-project"

        self.assertIsNone(storage.get_project(traversal_id))
        self.assertIsNone(storage.get_report(traversal_id))
        self.assertIsNone(storage.get_dfd_model(traversal_id))
        self.assertFalse(storage.delete_project(traversal_id))
        with self.assertRaises(ValueError):
            storage.save_project({"project_id": traversal_id, "name": "must not write"})


if __name__ == "__main__":
    unittest.main()
