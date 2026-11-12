import unittest

from backend.routers.analysis import _eligible_downstream_threats
from backend.services.action_quality_service import validate_test_scenarios
from backend.services.control_service import _catalog_fallback
from backend.services.posture_service import enrich_controls, validate_control_patch
from backend.utils.storage import get_controls_catalog


def action_dfd():
    return {
        "revision": 4,
        "semantic_hash": "dfd-cr6",
        "nodes": [{"id": "web-api", "name": "Web API"}],
        "flows": [{"id": "flow-login", "source_id": "web-api", "target_id": "web-api"}],
        "data_objects": [],
        "boundaries": [],
    }


def action_threat(threat_id="threat-1", description="Server recalculates a tampered amount before state change."):
    return {
        "threat_id": threat_id,
        "framework": "STRIDE",
        "threat_category": "Tampering",
        "threat_description": description,
        "mechanism": "tampered amount input",
        "primary_interaction_ref": "flow-login",
        "target_refs": [{"type": "data_flow", "id": "flow-login"}],
        "finding_state": "hypothesis",
    }


class Cr6ActionQualityTests(unittest.TestCase):
    def test_fallback_invalid_and_stale_findings_are_not_downstream_current_actions(self):
        report = {
            "ai_status": {
                "stride": {"engine": "AI", "assessment_status": "complete"},
                "linddun": {"engine": "fallback", "assessment_status": "fallback"},
            },
            "threats": [
                action_threat("stride-current"),
                {**action_threat("linddun-baseline"), "framework": "LINDDUN"},
                {**action_threat("stride-stale"), "analysis_state": "stale"},
            ],
        }

        eligible = _eligible_downstream_threats(report)

        self.assertEqual([item["threat_id"] for item in eligible], ["stride-current"])
        baseline = report["threats"][1]
        self.assertFalse(baseline["downstream_eligible"])
        self.assertEqual(baseline["downstream_state"], "baseline_suggestion")
        self.assertIn("baseline", baseline["downstream_exclusion_reason"])
        self.assertFalse(report["threats"][2]["downstream_eligible"])

    def test_control_package_contains_mechanism_rationale_and_primary_flow_trace(self):
        threat = action_threat()
        controls = _catalog_fallback([threat], get_controls_catalog())
        enriched = enrich_controls(controls, [threat], {"entry_points": ["Web API"]}, dfd_model=action_dfd())

        self.assertTrue(enriched)
        control = enriched[0]
        self.assertEqual(control["linked_finding_ids"], ["threat-1"])
        self.assertEqual(control["target_refs"], [{"type": "data_flow", "id": "flow-login"}])
        self.assertEqual(control["location_ref"]["id"], "flow-login")
        self.assertTrue(control["mitigated_mechanism"])
        self.assertTrue(control["applicability_rationale"])
        self.assertTrue(control["verification_method"])
        self.assertTrue(control["implementation_evidence_requested"])
        self.assertEqual(control["recommendation_status"], "recommended")

    def test_mapped_control_lifecycle_requires_evidence_and_supports_decision_states(self):
        with self.assertRaises(ValueError):
            validate_control_patch({"mapping_status": "mapped"}, existing_control={"threat_ids": []})
        self.assertEqual(
            validate_control_patch({"recommendation_status": "Accepted Risk"})["recommendation_status"],
            "accepted_risk",
        )

    def test_duplicate_semantic_scenario_is_blocked_across_different_finding_ids(self):
        first = action_threat("threat-1")
        second = action_threat("threat-2")
        controls = [
            {"control_id": "control-1", "name": "Amount validation", "threat_ids": ["threat-1"], "mapping_status": "mapped"},
            {"control_id": "control-2", "name": "Amount validation", "threat_ids": ["threat-2"], "mapping_status": "mapped"},
        ]
        common = {
            "preconditions": "A sandbox order and a request capture with a server-side amount source.",
            "steps": ["Create a sandbox order", "Send a tampered amount", "Observe server-side calculation", "Verify the stored amount remains server derived"],
            "expected_result": "The server rejects the tampered amount and keeps the authoritative value unchanged.",
            "evidence_needed": ["Request-response capture", "Stored state comparison"],
            "target_refs": [{"type": "data_flow", "id": "flow-login"}],
            "applicability_status": "applicable",
        }
        scenarios, warnings = validate_test_scenarios([
            {**common, "test_id": "test-1", "threat_id": "threat-1", "related_control_id": "control-1"},
            {**common, "test_id": "test-2", "threat_id": "threat-2", "related_control_id": "control-2"},
        ], [first, second], controls, action_dfd())

        self.assertEqual(scenarios[0]["quality_status"], "executable")
        self.assertEqual(scenarios[1]["applicability_status"], "blocked")
        self.assertIn("duplicate_semantic_test", scenarios[1]["applicability_reason"])
        self.assertTrue(any("quality gate" in warning for warning in warnings))

    def test_generic_disclosure_sequence_is_blocked_with_explicit_reason(self):
        threat = {
            **action_threat("disclosure", "Customer email is exposed to an unintended recipient."),
            "threat_category": "Data Disclosure",
            "asset": "customer email",
        }
        control = {"control_id": "control-disclosure", "name": "PII minimization", "threat_ids": ["disclosure"], "mapping_status": "mapped"}
        scenarios, _warnings = validate_test_scenarios([{
            "test_id": "generic-disclosure",
            "threat_id": "disclosure",
            "related_control_id": "control-disclosure",
            "scenario_name": "Data disclosure review",
            "preconditions": "A representative response and an authorized test recipient are available.",
            "steps": [
                "Locate the canonical DFD target Web API",
                "Capture the sender-to-receiver payload",
                "Compare fields with purpose and recipient scope",
                "Verify unnecessary fields are removed or masked",
            ],
            "expected_result": "Only the necessary fields are returned to the intended recipient.",
            "evidence_needed": ["Payload capture"],
            "target_refs": [{"type": "data_flow", "id": "flow-login"}],
            "applicability_status": "applicable",
        }], [threat], [control], action_dfd())

        self.assertEqual(scenarios[0]["quality_status"], "blocked")
        self.assertEqual(scenarios[0]["execution_status"], "Blocked")
        self.assertIn("generic_disclosure_sequence", scenarios[0]["applicability_reason"])


if __name__ == "__main__":
    unittest.main()
