import copy
import json
import unittest
from pathlib import Path

from backend.models.dfd import DfdModel
from backend.services.dfd_model_service import recalculate_boundary_crossings
from backend.services.dfd_model_service import format_dfd_analysis_context
from backend.services.privacy_service import (
    assess_privacy_metadata,
    annotate_privacy_threats,
    privacy_context_for_refs,
)


class PrivacyServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_path = Path(__file__).parents[1] / "fixtures" / "customer_registration_dfd.json"
        cls.model = DfdModel.model_validate(json.loads(fixture_path.read_text(encoding="utf-8")))
        recalculate_boundary_crossings(cls.model)

    def test_assessment_keeps_unknown_lifecycle_and_privacy_metadata_explicit(self):
        assessment = assess_privacy_metadata(self.model.model_dump())
        self.assertEqual(assessment["model_revision"], self.model.revision)
        self.assertIn(assessment["status"], {"partial", "unknown"})
        data_record = next(item for item in assessment["data_objects"] if item["element_id"] == "DO3")
        self.assertIn("linkability", data_record["missing_fields"])
        self.assertIn("store.retention", data_record["missing_fields"])
        self.assertGreater(assessment["unknown_field_count"], 0)

    def test_flow_context_resolves_to_data_object_and_store_questions(self):
        context = privacy_context_for_refs(self.model.model_dump(), [{"type": "data_flow", "id": "F5"}])
        self.assertEqual(context["status"], "partial")
        self.assertIn("DO5", context["data_object_ids"])
        self.assertTrue(context["missing_fields"])

    def test_non_data_reference_is_not_invented_as_personal_data(self):
        context = privacy_context_for_refs(self.model.model_dump(), [{"type": "process", "id": "P1"}])
        self.assertEqual(context["status"], "not_applicable")
        self.assertEqual(context["data_object_ids"], [])

    def test_privacy_candidate_is_needs_info_without_erasing_candidate(self):
        threat = {
            "threat_id": "L-1",
            "framework": "LINDDUN",
            "threat_category": "Data Disclosure",
            "threat_description": "Recipient may receive excessive registration data.",
            "affected_refs": ["F5"],
            "status": "Open",
        }
        annotated = annotate_privacy_threats([threat], self.model.model_dump())[0]
        self.assertEqual(annotated["privacy_context_status"], "partial")
        self.assertEqual(annotated["status"], "Needs Info")
        self.assertEqual(annotated["finding_status"], "needs_context")
        self.assertIn("linkability", annotated["missing_info"])

    def test_documented_metadata_can_be_analyzed_without_forced_needs_info(self):
        model = copy.deepcopy(self.model.model_dump())
        data = next(item for item in model["data_objects"] if item["id"] == "DO3")
        data.update({
            "data_subjects": ["Customer"],
            "identifiers": ["email"],
            "direct_identifiers": ["email"],
            "indirect_identifiers": [],
            "sensitivity": "sensitive",
            "purpose": "customer account",
            "recipients": ["Organization"],
            "linkability": "bounded to customer account",
            "notice": "Registration notice",
            "individual_control": "Account deletion request",
            "legal_basis": "Documented service contract",
        })
        store = model["stores"]["D1"]
        store.update({"retention": "Until account deletion", "deletion": "On account deletion", "backup": "Encrypted backup, 30 days"})
        assessment = assess_privacy_metadata(model)
        record = next(item for item in assessment["data_objects"] if item["element_id"] == "DO3")
        self.assertEqual(record["status"], "documented")
        self.assertNotIn("store.retention", record["missing_fields"])
        threat = {
            "threat_id": "L-2",
            "framework": "LINDDUN",
            "threat_category": "Linking",
            "threat_description": "Records may be linked across contexts.",
            "affected_refs": ["DO3"],
            "status": "Open",
        }
        annotated = annotate_privacy_threats([threat], model)[0]
        self.assertEqual(annotated["privacy_context_status"], "documented")
        self.assertEqual(annotated["status"], "Open")

    def test_linddun_context_contains_lifecycle_and_legal_basis_fields(self):
        context = format_dfd_analysis_context(self.model.model_dump())
        self.assertIn("STORES AND DATA LIFECYCLE", context)
        self.assertIn("retention=unknown", context)
        self.assertIn("legal_basis=unknown", context)
        self.assertIn("OPEN QUESTIONS", context)
        self.assertIn("retention and deletion", context)


if __name__ == "__main__":
    unittest.main()
