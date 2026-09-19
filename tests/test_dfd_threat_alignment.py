import unittest

from backend.services.dfd_model_service import build_dfd_model
from backend.services.linddun_service import _fallback_linddun
from backend.services.stride_service import _fallback_stride
from backend.services.threat_validation_service import (
    complete_graph_coverage,
    parse_generation_payload,
    quarantine_report_threats,
    validate_coverage,
    validate_generated_threats,
)
from backend.services.trust_boundary_service import attach_target_refs, build_trust_model
from backend.services.posture_service import enrich_controls, replace_framework_threats
from backend.utils.redaction import redact_text


class DfdThreatAlignmentTests(unittest.TestCase):
    def setUp(self):
        self.project = {
            "project_id": "project-1",
            "name": "Registration",
            "description": "Customer registration",
            "actors": ["Customer"],
            "components": ["Registration API", "Customer Database"],
            "entry_points": ["Web App"],
            "data_involved": ["email"],
            "external_systems": [],
            "manual_context": {"actors": ["Customer"], "components": ["Registration API", "Customer Database"]},
            "artifact_sources": [],
            "canonical_operations": [],
            "extracted_data_flows": [{
                "flow_id": "flow-1",
                "source": "Customer",
                "destination": "Registration API",
                "source_entity_type": "actor",
                "destination_entity_type": "component",
                "protocol": "HTTPS",
                "data": ["email"],
                "evidence_refs": ["manual:flow[0]"],
                "evidence_type": "direct",
            }],
        }
        self.trust_model = build_trust_model(self.project)
        self.dfd_model = build_dfd_model(self.project, self.trust_model).model_dump()

    def test_generated_output_normalizes_linddun_alias_and_invalid_refs(self):
        threats, warnings = validate_generated_threats([{
            "threat_category": "Linkability",
            "threat_description": "Persistent identifier links sessions.",
            "affected_refs": [self.dfd_model["flows"][0]["id"], "not-in-model"],
        }], "LINDDUN", self.dfd_model)

        self.assertEqual(threats[0]["threat_category"], "Linking")
        self.assertEqual(threats[0]["affected_refs"], [self.dfd_model["flows"][0]["id"]])
        self.assertTrue(any("unknown DFD IDs" in warning for warning in warnings))

    def test_invalid_ai_list_shape_is_dropped_at_schema_boundary(self):
        threats, warnings = validate_generated_threats([{
            "threat_category": "Tampering",
            "threat_description": "Input can be modified.",
            "affected_refs": "flow-should-be-a-list",
        }], "STRIDE", self.dfd_model)

        self.assertEqual(threats, [])
        self.assertTrue(any("schema validation failed" in warning for warning in warnings))

    def test_threat_contract_pins_revision_and_does_not_assert_non_compliance(self):
        threats, warnings = validate_generated_threats([{
            "threat_category": "Non-compliance",
            "threat_description": "Retention obligation cannot be assessed from the available model.",
            "affected_refs": [self.dfd_model["flows"][0]["id"]],
            "evidence_refs": [],
        }], "LINDDUN", self.dfd_model, set())

        self.assertEqual(threats[0]["taxonomy_version"], "linddun-v1")
        self.assertEqual(threats[0]["analysis_revision"], self.dfd_model["revision"])
        self.assertEqual(threats[0]["finding_status"], "needs_context")
        self.assertEqual(threats[0]["status"], "Needs Info")
        self.assertTrue(any("non-compliance requires" in warning for warning in warnings))

    def test_empty_provider_assessment_is_valid_and_does_not_become_fallback(self):
        result = parse_generation_payload({"threats": [], "coverage": []}, "STRIDE")

        self.assertEqual(list(result), [])
        self.assertEqual(result.assessment_status, "valid_empty")
        self.assertEqual(result.response_shape, "object")

    def test_linddun_non_compliance_requires_each_claim_side_independently(self):
        base = {
            "threat_category": "Non-compliance",
            "threat_description": "A retention obligation may not be met.",
            "affected_refs": [self.dfd_model["flows"][0]["id"]],
        }
        with_obligation, warnings = validate_generated_threats(
            [{**base, "obligation": "Documented retention policy", "evidence_refs": []}],
            "LINDDUN",
            self.dfd_model,
            set(),
        )
        with_evidence, _ = validate_generated_threats(
            [{**base, "obligation": "", "evidence_refs": ["EV-1"]}],
            "LINDDUN",
            self.dfd_model,
            {"EV-1"},
        )

        self.assertEqual(with_obligation[0]["status"], "Needs Info")
        self.assertEqual(with_obligation[0]["finding_status"], "needs_context")
        self.assertEqual(with_evidence[0]["status"], "Needs Info")
        self.assertTrue(any("both an obligation" in warning for warning in warnings))

    def test_linddun_missing_classification_is_unknown_not_pii(self):
        threats, _ = validate_generated_threats([{
            "threat_category": "Data Disclosure",
            "threat_description": "The recipient may receive excessive data.",
            "affected_refs": [self.dfd_model["flows"][0]["id"]],
        }], "LINDDUN", self.dfd_model)

        self.assertEqual(threats[0]["data_classification"], "Unknown")

    def test_stale_or_unpinned_report_threats_are_quarantined(self):
        flow_id = self.dfd_model["flows"][0]["id"]
        current = {
            "threat_id": "current",
            "framework": "STRIDE",
            "threat_category": "Tampering",
            "threat_description": "Current finding.",
            "affected_refs": [flow_id],
            "analysis_revision": self.dfd_model["revision"],
        }
        stale = {**current, "threat_id": "stale", "analysis_revision": "old-revision"}
        active, quarantined = quarantine_report_threats([current, stale], self.dfd_model)

        self.assertEqual([item["threat_id"] for item in active], ["current"])
        self.assertEqual(quarantined[0]["item"]["threat_id"], "stale")
        self.assertIn("stale_analysis_revision", quarantined[0]["reasons"])

    def test_framework_rerun_preserves_matching_reviewer_decision(self):
        flow_id = self.dfd_model["flows"][0]["id"]
        old = {
            "threat_id": "reviewed-threat",
            "framework": "STRIDE",
            "threat_category": "Tampering",
            "threat_description": "Input can be altered.",
            "affected_refs": [flow_id],
            "status": "Confirmed",
            "review_notes": "Keep this risk visible.",
            "reviewed_at": "2026-09-19T00:00:00Z",
        }
        new = {**old, "threat_id": "new-provider-id", "status": "Open", "review_notes": ""}
        merged, _ = replace_framework_threats([old], [new], "STRIDE")

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["threat_id"], "reviewed-threat")
        self.assertEqual(merged[0]["status"], "Confirmed")
        self.assertEqual(merged[0]["review_notes"], "Keep this risk visible.")

    def test_affected_refs_become_semantic_target_refs(self):
        flow_id = self.dfd_model["flows"][0]["id"]
        source_id = self.dfd_model["flows"][0]["source_id"]
        threat = {
            "threat_id": "threat-1",
            "affected_refs": [flow_id, source_id],
            "component": "unrelated narrative",
        }

        attach_target_refs(
            [threat],
            self.trust_model["boundaries"],
            self.trust_model["views"],
            self.dfd_model,
        )

        refs = {(item["type"], item["id"]) for item in threat["target_refs"]}
        self.assertIn(("data_flow", flow_id), refs)
        self.assertIn(("entity", source_id), refs)
        self.assertEqual(threat["mapping_status"], "mapped")

    def test_coverage_validator_keeps_only_current_model_ids(self):
        flow_id = self.dfd_model["flows"][0]["id"]
        coverage, warnings = validate_coverage([
            {"element_ref": flow_id, "status": "candidate_identified", "reason": "candidate"},
            {"element_ref": "missing", "status": "reviewed_no_candidate"},
        ], self.dfd_model)

        self.assertEqual([item["element_ref"] for item in coverage], [flow_id])
        self.assertTrue(warnings)

    def test_fallbacks_are_reviewable_candidates_tied_to_the_dfd(self):
        stride = _fallback_stride(self.project, self.trust_model["boundaries"], self.dfd_model)
        linddun = _fallback_linddun(self.project, self.dfd_model)

        self.assertEqual(len(stride), 1)
        self.assertEqual(len(linddun), 1)
        self.assertEqual(stride[0]["status"], "Needs Info")
        self.assertEqual(linddun[0]["status"], "Needs Info")
        self.assertTrue(stride[0]["affected_refs"])
        self.assertTrue(linddun[0]["affected_refs"])

    def test_graph_coverage_makes_missing_analysis_explicit(self):
        flow_id = self.dfd_model["flows"][0]["id"]
        node_id = self.dfd_model["flows"][0]["target_id"]
        threats = [{
            "framework": "STRIDE",
            "threat_category": "Tampering",
            "target_refs": [{"type": "data_flow", "id": flow_id}],
        }]

        coverage, summary = complete_graph_coverage(
            [{
                "element_ref": node_id,
                "category": "Spoofing",
                "status": "reviewed_no_candidate",
                "reason": "Identity control reviewed.",
            }],
            threats,
            self.dfd_model,
            "STRIDE",
        )

        flow_tampering = next(item for item in coverage if item["element_ref"] == flow_id and item["category"] == "Tampering")
        node_spoofing = next(item for item in coverage if item["element_ref"] == node_id and item["category"] == "Spoofing")
        node_tampering = next(item for item in coverage if item["element_ref"] == node_id and item["category"] == "Tampering")
        self.assertEqual(flow_tampering["status"], "candidate_identified")
        self.assertEqual(flow_tampering["coverage_origin"], "validated_threat_reference")
        self.assertEqual(node_spoofing["status"], "reviewed_no_candidate")
        self.assertEqual(node_tampering["status"], "insufficient_information")
        self.assertGreater(summary["insufficient_information"], 0)
        self.assertFalse(summary["complete"])

    def test_control_location_and_target_refs_follow_validated_threat_targets(self):
        flow_id = self.dfd_model["flows"][0]["id"]
        threat = {
            "threat_id": "threat-control-1",
            "threat_category": "Tampering",
            "threat_description": "Input can be altered.",
            "target_refs": [{"type": "data_flow", "id": flow_id}],
            "risk_level": "High",
        }
        controls = enrich_controls(
            [{
                "name": "Validate input",
                "threat_ids": ["threat-control-1", "not-a-threat"],
                "target_refs": [{"type": "data_flow", "id": flow_id}, {"type": "flow", "id": "missing"}],
                "verification_evidence_refs": ["missing-evidence"],
            }],
            [threat],
            self.project,
            dfd_model=self.dfd_model,
            evidence_ids={"EV-1"},
        )

        self.assertEqual(controls[0]["threat_ids"], ["threat-control-1"])
        self.assertEqual(controls[0]["target_refs"], [{"type": "data_flow", "id": flow_id}])
        self.assertEqual(controls[0]["location_ref"]["id"], flow_id)
        self.assertEqual(controls[0]["verification_evidence_refs"], [])

    def test_redaction_protects_structured_and_plain_text_secrets(self):
        content = '{"api_key":"secret-value","raw":"{\\"password\\":\\"pw\\"}","name":"safe"}'
        redacted = redact_text(content)
        self.assertNotIn("secret-value", redacted)
        self.assertNotIn('\\"pw\\"', redacted)
        self.assertIn("[REDACTED]", redacted)

        plain = redact_text("password=secret token: abc123")
        self.assertNotIn("secret", plain)
        self.assertNotIn("abc123", plain)


if __name__ == "__main__":
    unittest.main()
