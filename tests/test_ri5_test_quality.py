import asyncio
import unittest

from backend.services.control_service import _catalog_fallback
from backend.services.test_service import generate_test_scenarios, normalize_test_scenarios
from backend.utils.storage import get_controls_catalog


class Ri5TestQualityTests(unittest.TestCase):
    def test_catalog_covers_specific_ai_location_and_identifier_risks(self):
        threats = [
            {"threat_id": "ai-egress", "framework": "STRIDE", "threat_category": "Information Disclosure",
             "threat_description": "An external AI provider receives sensitive story content and location.",
             "recommended_control": "Redact outbound fields before sending to the AI provider."},
            {"threat_id": "map-link", "framework": "LINDDUN", "threat_category": "Linking",
             "threat_description": "Precise locations on a map allow viewers to correlate records.",
             "recommended_control": "Fuzz location precision for public views."},
            {"threat_id": "id-link", "framework": "LINDDUN", "threat_category": "Linking",
             "threat_description": "Identifiers stored with generated content permit cross-context joins.",
             "recommended_control": "Separate identifiers and restrict join keys."},
        ]
        controls = _catalog_fallback(threats, get_controls_catalog())
        by_threat = {threat["threat_id"]: {item["catalog_id"] for item in controls
                                            if threat["threat_id"] in item["threat_ids"] and item["mapping_status"] == "mapped"}
                     for threat in threats}
        self.assertIn("ctrl-017", by_threat["ai-egress"])
        self.assertIn("ctrl-018", by_threat["map-link"])
        self.assertIn("ctrl-019", by_threat["id-link"])
        self.assertFalse(any(item["mapping_status"] == "unassigned" for item in controls))

    def test_catalog_does_not_map_external_payment_provider_to_ai_control(self):
        threat = {"threat_id": "payment", "framework": "STRIDE", "threat_category": "Information Disclosure",
                  "threat_description": "An external payment provider receives a billing response."}
        controls = _catalog_fallback([threat], get_controls_catalog())
        self.assertFalse(any(item.get("catalog_id") == "ctrl-017" for item in controls))

    def test_same_dfd_target_produces_distinct_executable_disclosure_steps(self):
        model = {"revision": 2, "semantic_hash": "revision-2", "nodes": [{"id": "portal", "name": "Web portal"}]}
        common = {"framework": "LINDDUN", "threat_category": "Data Disclosure",
                  "target_refs": [{"type": "process", "id": "portal"}]}
        threats = [
            {**common, "threat_id": "recipient", "asset": "customer email",
             "threat_description": "Customer email is exposed to an unintended recipient.",
             "source": "Web portal", "destination": "Customer browser"},
            {**common, "threat_id": "provider", "asset": "precise location and story content",
             "threat_description": "External AI provider receives unnecessary story and location data.",
             "recommended_control": "Redact data sent to external AI provider.",
             "source": "Web portal", "destination": "External AI provider"},
        ]
        controls = [
            {"control_id": "CAT-ctrl-004", "name": "PII Data Minimization and Masking",
             "threat_ids": ["recipient"], "mapping_status": "mapped"},
            {"control_id": "CAT-ctrl-017", "name": "External AI Data Egress Minimization",
             "threat_ids": ["provider"], "mapping_status": "mapped"},
        ]
        scenarios = asyncio.run(generate_test_scenarios(threats, {}, force_fallback=True, controls=controls, dfd_model=model))
        self.assertEqual(len(scenarios), 2)
        self.assertEqual({item["applicability_status"] for item in scenarios}, {"applicable"})
        self.assertNotEqual(scenarios[0]["steps"], scenarios[1]["steps"])
        self.assertIn("customer email", " ".join(scenarios[0]["steps"]))
        self.assertIn("provider-bound", " ".join(scenarios[1]["steps"]))
        self.assertEqual({item["related_control_id"] for item in scenarios}, {"CAT-ctrl-004", "CAT-ctrl-017"})
        self.assertTrue(all("Web portal" in item["scenario_name"] for item in scenarios))

    def test_unassigned_threat_cannot_borrow_another_threats_control(self):
        threat = {"threat_id": "needs-review", "framework": "LINDDUN", "threat_category": "Data Disclosure",
                  "asset": "customer email", "threat_description": "Customer email leaks to the wrong recipient."}
        controls = [
            {"control_id": "CAT-ctrl-004", "name": "PII Data Minimization and Masking",
             "threat_ids": ["someone-else"], "mapping_status": "mapped"},
            {"control_id": "UNASSIGNED-needs-review", "name": "Control mapping requires review",
             "threat_ids": ["needs-review"], "mapping_status": "unassigned"},
        ]
        generated = asyncio.run(generate_test_scenarios([threat], {}, force_fallback=True, controls=controls))
        self.assertEqual(generated[0]["applicability_status"], "blocked")
        self.assertEqual(generated[0]["execution_status"], "Blocked")
        self.assertNotIn("related_control_id", generated[0])
        self.assertIsNone(generated[0]["related_control"])
        forged = {**generated[0], "related_control_id": "CAT-ctrl-004", "related_control": "PII Data Minimization and Masking",
                  "applicability_status": "applicable", "execution_status": "Not Run"}
        checked = normalize_test_scenarios([forged], [threat], controls)
        self.assertEqual(checked[0]["applicability_status"], "blocked")
        self.assertNotIn("related_control_id", checked[0])

    def test_unknown_disclosure_mechanism_requires_review(self):
        threat = {"threat_id": "vague", "framework": "LINDDUN", "threat_category": "Data Disclosure",
                  "threat_description": "Something might be unsafe."}
        control = {"control_id": "c", "name": "PII Data Minimization and Masking", "threat_ids": ["vague"], "mapping_status": "mapped"}
        scenario = asyncio.run(generate_test_scenarios([threat], {}, force_fallback=True, controls=[control]))[0]
        self.assertEqual(scenario["applicability_status"], "blocked")
        self.assertIn("not specific enough", scenario["applicability_reason"])


if __name__ == "__main__":
    unittest.main()
