import copy
import unittest

from backend.routers.artifacts import _verified_evidence_items
from backend.services.parser_service import _basic_evidence_items
from backend.services.posture_service import (
    build_evidence_context,
    build_project_evidence_catalog,
    enrich_threats,
    normalize_report_evidence,
)


class EvidenceTraceabilityTests(unittest.TestCase):
    def setUp(self):
        self.project = {
            "name": "Story Portal",
            "description": "A public story API backed by PostGIS.",
            "components": ["Public Stories API", "PostGIS Database"],
            "entry_points": ["GET /api/stories"],
            "data_involved": ["location data", "image links"],
            "actors": ["External developer"],
            "external_systems": ["Caption model API"],
            "critical_actions": [],
            "existing_controls": [],
            "auth_method": "API key",
            "artifact_summary": "The portal returns geospatial stories through a public API.",
            "artifact_sources": [{"filename": "prd.pdf", "artifact_type": "prd"}],
            "extracted_data_flows": [
                {
                    "source": "External developer",
                    "destination": "Public Stories API",
                    "protocol": "HTTPS",
                    "data": ["query filters"],
                },
                {
                    "source": "Public Stories API",
                    "destination": "PostGIS Database",
                    "protocol": "PostgreSQL",
                    "data": ["location data"],
                },
            ],
        }

    def test_catalog_distinguishes_direct_evidence_from_context(self):
        project = copy.deepcopy(self.project)
        project["artifact_evidence"] = [{
            "filename": "prd.pdf",
            "artifact_type": "prd",
            "snippet": "The public API supports bounding-box and date filters.",
            "locator": "Public API",
            "topics": ["GET /api/stories"],
        }]

        catalog = build_project_evidence_catalog(project)
        self.assertTrue(any(item["evidence_type"] == "direct" for item in catalog))
        self.assertTrue(any(item["evidence_type"] == "context" for item in catalog))
        prompt_context = build_evidence_context(project)
        self.assertIn("DIRECT · prd.pdf · Public API", prompt_context)
        self.assertIn("EV-", prompt_context)

    def test_threats_receive_relevant_non_identical_context(self):
        threats = [
            {
                "framework": "STRIDE",
                "threat_category": "Denial of Service",
                "component": "Public Stories API",
                "source": "External developer",
                "destination": "Public Stories API",
                "asset": "API availability",
                "confidence": "Medium",
            },
            {
                "framework": "STRIDE",
                "threat_category": "Tampering",
                "component": "PostGIS Database",
                "source": "Public Stories API",
                "destination": "PostGIS Database",
                "asset": "location data",
                "confidence": "Medium",
            },
        ]

        enriched = enrich_threats(threats, self.project, "STRIDE")
        self.assertEqual([item["evidence_type"] for item in enriched], ["context", "context"])
        self.assertNotEqual(enriched[0]["evidence_snippet"], enriched[1]["evidence_snippet"])
        self.assertIn("External developer", enriched[0]["evidence_snippet"])
        self.assertIn("PostGIS Database", enriched[1]["evidence_snippet"])
        self.assertIn("External developer → Public Stories API", enriched[0]["evidence_snippet"])
        self.assertIn("Public Stories API → PostGIS Database", enriched[1]["evidence_snippet"])

    def test_legacy_summary_is_upgraded_without_changing_review_fields(self):
        report = {
            "threats": [{
                "threat_id": "T-1",
                "framework": "STRIDE",
                "threat_category": "Tampering",
                "component": "PostGIS Database",
                "source": "Public Stories API",
                "destination": "PostGIS Database",
                "asset": "location data",
                "confidence": "Medium",
                "status": "Reviewed",
                "review_notes": "Confirmed by the backend team",
                "evidence_source": "artifact",
                "evidence_snippet": self.project["artifact_summary"],
            }]
        }

        normalized = normalize_report_evidence(report, self.project)
        threat = normalized["threats"][0]
        self.assertEqual(threat["status"], "Reviewed")
        self.assertEqual(threat["review_notes"], "Confirmed by the backend team")
        self.assertEqual(threat["evidence_type"], "context")
        self.assertNotEqual(threat["evidence_snippet"], self.project["artifact_summary"])

    def test_missing_project_context_is_labeled_as_inference(self):
        threat = {
            "framework": "LINDDUN",
            "threat_category": "Unawareness",
            "component": "Unknown integration",
            "confidence": "Low",
        }
        enriched = enrich_threats([threat], {}, "LINDDUN")[0]
        self.assertEqual(enriched["evidence_type"], "inference")
        self.assertIn("Framework inference", enriched["evidence_snippet"])

    def test_only_verbatim_upload_snippets_become_direct_evidence(self):
        content = "The public API supports bounding-box filters. Authentication uses an API key."
        items = [
            {"snippet": "The public API supports bounding-box filters.", "locator": "API", "topics": ["API"]},
            {"snippet": "The API uses OAuth and MFA.", "locator": "Security", "topics": ["auth"]},
        ]
        verified = _verified_evidence_items(items, content, "prd.md", "prd")
        self.assertEqual(len(verified), 1)
        self.assertEqual(verified[0]["snippet"], items[0]["snippet"])

    def test_basic_parser_evidence_is_verbatim(self):
        content = "Overview\nThe public API stores location data in the database for map filtering.\nShort line"
        items = _basic_evidence_items(content)
        self.assertEqual(len(items), 1)
        self.assertIn(items[0]["snippet"], content)


if __name__ == "__main__":
    unittest.main()
