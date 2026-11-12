import asyncio
import copy
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from backend.routers.analysis import update_trust_boundary_review


class TrustBoundaryReviewTests(unittest.TestCase):
    def setUp(self):
        self.report = {
            "trust_boundaries": [{
                "boundary_id": "boundary-1",
                "model_fingerprint": "topology-1",
                "source": "User",
                "destination": "API Gateway",
                "status": "Candidate",
            }],
            "trust_model": {},
            "risk_summary": {},
        }

    def test_confirm_persists_review_and_clears_visibility_only_staleness(self):
        report = copy.deepcopy(self.report)
        report["analysis_stale"] = {
            "stages": ["stride", "linddun"],
            "reason": "A trust-boundary review decision changed. Refresh dependent analysis stages.",
        }
        with (
            patch("backend.routers.analysis.get_report", return_value=report),
            patch("backend.routers.analysis.save_report") as save_report,
            patch("backend.routers.analysis.log_event"),
        ):
            response = asyncio.run(update_trust_boundary_review(
                "project-1",
                "boundary-1",
                {"status": "Confirmed", "review_note": "Validated with API owner"},
            ))

        self.assertTrue(response["success"])
        self.assertEqual(report["trust_boundaries"][0]["status"], "Confirmed")
        self.assertEqual(report["trust_boundary_reviews"]["boundary-1"]["model_fingerprint"], "topology-1")
        self.assertNotIn("analysis_stale", report)
        save_report.assert_called_once_with("project-1", report)

    def test_invalid_review_status_is_rejected(self):
        with patch("backend.routers.analysis.get_report", return_value=copy.deepcopy(self.report)):
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(update_trust_boundary_review(
                    "project-1", "boundary-1", {"status": "Accepted"}
                ))
        self.assertEqual(raised.exception.status_code, 422)


if __name__ == "__main__":
    unittest.main()
