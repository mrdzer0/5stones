import asyncio
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from backend.services.dfd_model_service import build_dfd_model
from backend.services.linddun_service import _fallback_linddun
from backend.services.stride_service import _fallback_stride
from backend.services.control_service import _catalog_fallback
from backend.services.control_service import map_controls
from backend.services.ai_service import AnalysisResponseError, chat_complete_json
from backend.services.test_service import _fallback_scenarios, normalize_test_scenarios
from backend.services.test_service import generate_test_scenarios
from backend.services.threat_validation_service import (
    complete_graph_coverage,
    normalize_generation_result,
    parse_generation_payload,
    quarantine_report_threats,
    ThreatGenerationContractError,
    ThreatGenerationResult,
    validate_coverage,
    validate_generated_threats,
)
from backend.services.trust_boundary_service import attach_target_refs, build_trust_model, propagate_target_refs
from backend.services.posture_service import (
    enrich_controls,
    reconcile_controls,
    reconcile_test_scenarios,
    replace_framework_threats,
    validate_control_patch,
    _related_threats_by_text,
)
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
        self.assertEqual(threats[0]["dfd_semantic_hash"], self.dfd_model["semantic_hash"])
        self.assertEqual(threats[0]["finding_status"], "needs_context")
        self.assertEqual(threats[0]["status"], "Needs Info")
        self.assertTrue(any("non-compliance requires" in warning for warning in warnings))

    def test_empty_provider_assessment_is_valid_and_does_not_become_fallback(self):
        result = parse_generation_payload({"threats": [], "coverage": []}, "STRIDE")

        self.assertEqual(list(result), [])
        self.assertEqual(result.assessment_status, "valid_empty")
        self.assertEqual(result.response_shape, "object")

    def test_empty_list_compatible_result_is_normalized_to_valid_empty(self):
        result = normalize_generation_result([], "LINDDUN")

        self.assertEqual(list(result), [])
        self.assertEqual(result.assessment_status, "valid_empty")
        self.assertEqual(result.response_shape, "legacy_list")

    def test_invalid_provider_envelope_is_a_contract_error(self):
        with self.assertRaises(ThreatGenerationContractError):
            parse_generation_payload({"coverage": []}, "LINDDUN")

        contradictory = normalize_generation_result(
            ThreatGenerationResult([], [], assessment_status="provider_success"),
            "STRIDE",
        )
        self.assertEqual(contradictory.assessment_status, "invalid")
        self.assertTrue(contradictory.generation_warnings)

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
            "analyzed_revision": self.dfd_model["revision"],
            "taxonomy_version": "stride-v1",
            "dfd_semantic_hash": self.dfd_model["semantic_hash"],
        }
        stale = {**current, "threat_id": "stale", "analysis_revision": "old-revision"}
        active, quarantined = quarantine_report_threats([current, stale], self.dfd_model)

        self.assertEqual([item["threat_id"] for item in active], ["current"])
        self.assertEqual(quarantined[0]["item"]["threat_id"], "stale")
        self.assertIn("stale_analysis_revision", quarantined[0]["reasons"])

    def test_legacy_malformed_threats_are_quarantined_before_downstream_use(self):
        flow_id = self.dfd_model["flows"][0]["id"]
        legacy = {
            "threat_id": "legacy-stride",
            "framework": "STRIDE",
            "threat_category": "Tampering",
            "threat_description": "Legacy finding without provenance.",
            "affected_refs": [flow_id],
        }
        malformed = {
            "threat_id": "malformed-linddun",
            "framework": "LINDDUN",
            "threat_category": "Data Disclosure",
            "threat_description": "Mismatched revisions must not reach controls.",
            "affected_refs": [flow_id],
            "analysis_revision": self.dfd_model["revision"],
            "analyzed_revision": "different-revision",
            "taxonomy_version": "linddun-v1",
            "dfd_semantic_hash": self.dfd_model["semantic_hash"],
        }

        active, quarantined = quarantine_report_threats([legacy, malformed], self.dfd_model)

        self.assertEqual(active, [])
        self.assertEqual({item["item"]["threat_id"] for item in quarantined}, {"legacy-stride", "malformed-linddun"})
        self.assertTrue(any("missing_or_unsupported_taxonomy_version" in item["reasons"] for item in quarantined))
        self.assertTrue(any("analysis_revision_mismatch" in item["reasons"] for item in quarantined))

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

    def test_framework_rerun_preserves_unmatched_reviewed_finding(self):
        flow_id = self.dfd_model["flows"][0]["id"]
        old = {
            "threat_id": "reviewed-threat",
            "framework": "LINDDUN",
            "threat_category": "Linking",
            "threat_description": "Persistent identifier links sessions.",
            "affected_refs": [flow_id],
            "status": "Reviewed",
            "review_notes": "Keep this privacy risk visible.",
            "reviewed_at": "2026-09-19T00:00:00Z",
        }

        merged, _ = replace_framework_threats([old], [], "LINDDUN")

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["threat_id"], "reviewed-threat")
        self.assertEqual(merged[0]["assessment_status"], "review_preserved")

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

    def test_controls_receive_the_same_canonical_dfd_snapshot_as_threats(self):
        flow_id = self.dfd_model["flows"][0]["id"]
        threat = {
            "threat_id": "control-context-threat",
            "framework": "STRIDE",
            "threat_category": "Tampering",
            "threat_description": "Input can be altered before validation.",
            "target_refs": [{"type": "data_flow", "id": flow_id}],
            "analysis_revision": self.dfd_model["revision"],
            "evidence_refs": ["EV-1"],
        }
        with (
            patch("backend.services.control_service.get_active_provider_config", return_value={"base_url": "http://localhost", "model": "test", "api_key": "test"}),
            patch("backend.services.control_service.chat_complete_json", new=AsyncMock(return_value={"controls": [{"name": "Input validation", "threat_ids": ["control-context-threat"]}]})) as provider,
        ):
            controls = asyncio.run(map_controls([threat], dfd_model=self.dfd_model))

        self.assertEqual(controls[0]["analysis_revision"], self.dfd_model["revision"])
        self.assertEqual(controls[0]["dfd_semantic_hash"], self.dfd_model["semantic_hash"])
        prompt = provider.await_args.kwargs["user_prompt"]
        self.assertIn("CANONICAL DFD SNAPSHOT", prompt)
        self.assertIn(f"revision: {self.dfd_model['revision']}", prompt)
        self.assertIn(f"semantic_hash: {self.dfd_model['semantic_hash']}", prompt)
        self.assertIn("data_object_ids=", prompt)
        self.assertIn("authn=", prompt)
        self.assertIn("PROCESS METADATA", prompt)
        self.assertIn("source_zones=", prompt)

    def test_tests_receive_dfd_and_mapped_control_context(self):
        flow_id = self.dfd_model["flows"][0]["id"]
        threat = {
            "threat_id": "test-context-threat",
            "framework": "LINDDUN",
            "threat_category": "Data Disclosure",
            "threat_description": "The response may expose unnecessary data.",
            "target_refs": [{"type": "data_flow", "id": flow_id}],
        }
        controls = [{
            "control_id": "control-context-1",
            "name": "Data minimization",
            "threat_ids": ["test-context-threat"],
            "target_refs": [{"type": "data_flow", "id": flow_id}],
            "analysis_revision": self.dfd_model["revision"],
        }]
        scenario = {
            "scenario_name": "Verify data minimization",
            "preconditions": "Representative response payload",
            "steps": ["Capture the response", "Compare fields with purpose"],
            "expected_result": "Only necessary data is returned",
            "threat_id": "test-context-threat",
            "related_control_id": "control-context-1",
            "target_refs": [{"type": "data_flow", "id": flow_id}],
        }
        with (
            patch("backend.services.test_service.get_active_provider_config", return_value={"base_url": "http://localhost", "model": "test", "api_key": "test"}),
            patch("backend.services.test_service.chat_complete_json", new=AsyncMock(return_value={"scenarios": [scenario]})) as provider,
        ):
            result = asyncio.run(generate_test_scenarios([threat], self.project, controls=controls, dfd_model=self.dfd_model))

        self.assertEqual(result[0]["related_control_id"], "control-context-1")
        self.assertEqual(result[0]["analysis_revision"], self.dfd_model["revision"])
        self.assertEqual(result[0]["dfd_semantic_hash"], self.dfd_model["semantic_hash"])
        prompt = provider.await_args.kwargs["user_prompt"]
        self.assertIn("MAPPED CONTROLS:", prompt)
        self.assertIn("control-context-1", prompt)
        self.assertIn("CANONICAL DFD SNAPSHOT", prompt)
        self.assertIn(f"semantic_hash: {self.dfd_model['semantic_hash']}", prompt)
        self.assertIn("authz=", prompt)

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

    def test_control_status_cannot_claim_implementation_without_evidence(self):
        flow_id = self.dfd_model["flows"][0]["id"]
        threat = {
            "threat_id": "threat-status-1",
            "framework": "STRIDE",
            "threat_category": "Tampering",
            "threat_description": "Input can be altered.",
            "target_refs": [{"type": "data_flow", "id": flow_id}],
            "risk_level": "High",
        }
        controls = enrich_controls([{
            "control_id": "control-status-1",
            "name": "Input validation",
            "threat_ids": ["threat-status-1"],
            "status": "Implemented",
            "implementation_status": "Implemented",
            "target_refs": [{"type": "data_flow", "id": flow_id}],
        }], [threat], self.project, dfd_model=self.dfd_model, evidence_ids=set())

        self.assertEqual(controls[0]["implementation_status"], "Unknown")
        self.assertEqual(controls[0]["verification_status"], "unverified")
        self.assertEqual(controls[0]["mapping_status"], "mapped")
        self.assertEqual(controls[0]["analysis_revision"], self.dfd_model["revision"])

    def test_control_lifecycle_separates_documented_and_runtime_verified_evidence(self):
        flow_id = self.dfd_model["flows"][0]["id"]
        threat = {
            "threat_id": "threat-lifecycle-1",
            "framework": "STRIDE",
            "threat_category": "Tampering",
            "threat_description": "Input can be altered.",
            "target_refs": [{"type": "data_flow", "id": flow_id}],
        }
        documented = enrich_controls([{
            "control_id": "control-documented",
            "name": "Input validation",
            "threat_ids": ["threat-lifecycle-1"],
            "implementation_status": "Implemented",
            "implementation_evidence_refs": ["EV-CODE"],
            "verification_evidence_refs": ["EV-TEST"],
        }], [threat], self.project, dfd_model=self.dfd_model, evidence_ids={"EV-CODE", "EV-TEST"})[0]
        self.assertEqual(documented["implementation_status"], "Implemented")
        self.assertEqual(documented["implementation_state"], "documented")
        self.assertEqual(documented["verification_status"], "evidenced")
        self.assertIn("runtime effectiveness is not verified", documented["implementation_status_reason"])

        runtime = enrich_controls([{
            "control_id": "control-runtime",
            "name": "Input validation",
            "threat_ids": ["threat-lifecycle-1"],
            "implementation_status": "Implemented",
            "implementation_evidence_refs": ["EV-CODE"],
            "runtime_verification_refs": ["EV-RUNTIME"],
        }], [threat], self.project, dfd_model=self.dfd_model, evidence_ids={"EV-CODE", "EV-RUNTIME"})[0]
        self.assertEqual(runtime["implementation_state"], "runtime_verified")
        self.assertEqual(runtime["verification_status"], "evidenced")

        review_only = enrich_controls([{
            "control_id": "control-review-only",
            "name": "Input validation",
            "threat_ids": ["threat-lifecycle-1"],
            "implementation_status": "Implemented",
            "verification_evidence_refs": ["EV-TEST"],
        }], [threat], self.project, dfd_model=self.dfd_model, evidence_ids={"EV-TEST"})[0]
        self.assertEqual(review_only["implementation_status"], "Unknown")
        self.assertEqual(review_only["implementation_state"], "unknown")
        self.assertEqual(review_only["verification_status"], "evidenced")

    def test_control_status_patch_requires_evidence_and_validates_lifecycle_state(self):
        with self.assertRaises(ValueError):
            validate_control_patch({"implementation_status": "Implemented"}, evidence_ids={"EV-1"})
        with self.assertRaises(ValueError):
            validate_control_patch({"implementation_state": "runtime_verified"}, evidence_ids={"EV-1"})

        patch = validate_control_patch(
            {
                "implementation_status": "Implemented",
                "implementation_state": "runtime_verified",
                "runtime_verification_refs": ["EV-1"],
            },
            evidence_ids={"EV-1"},
        )
        self.assertEqual(patch["implementation_state"], "runtime_verified")

    def test_control_catalog_separates_consent_notice_and_tls_scope(self):
        catalog = __import__("backend.utils.storage", fromlist=["get_controls_catalog"]).get_controls_catalog()
        by_id = {item["id"]: item for item in catalog}
        self.assertNotIn("Linkability", by_id["ctrl-012"]["mitigates"])
        self.assertNotEqual(by_id["ctrl-015"]["name"], by_id["ctrl-016"]["name"])
        self.assertIn("consent", by_id["ctrl-015"]["tags"])
        self.assertIn("notice", by_id["ctrl-016"]["tags"])
        self.assertTrue(by_id["ctrl-015"]["evidence_requirements"])
        self.assertTrue(by_id["ctrl-016"]["evidence_requirements"])

    def test_fallback_controls_map_per_threat_without_first_three_fanout(self):
        threats = [
            {"threat_id": "t1", "threat_category": "Denial of Service", "threat_description": "The endpoint can be flooded."},
            {"threat_id": "t2", "threat_category": "Tampering", "threat_description": "A critical value can be changed."},
            {"threat_id": "t3", "threat_category": "Repudiation", "threat_description": "Critical actions may lack audit records."},
            {"threat_id": "t4", "framework": "LINDDUN", "threat_category": "Data Disclosure", "threat_description": "The response may disclose unnecessary personal data."},
        ]
        controls = _catalog_fallback(threats, __import__("backend.utils.storage", fromlist=["get_controls_catalog"]).get_controls_catalog())

        self.assertTrue(controls)
        self.assertTrue(all(set(control["threat_ids"]).issubset({"t1", "t2", "t3", "t4"}) for control in controls))
        self.assertFalse(any(set(control["threat_ids"]).issuperset({"t1", "t2", "t3"}) for control in controls))
        self.assertTrue(all(control["control_id"].startswith("CAT-") for control in controls))

    def test_fallback_controls_keep_unsupported_threats_explicitly_unassigned(self):
        threats = [{
            "threat_id": "unsupported-threat",
            "threat_category": "Unknown Category",
            "threat_description": "The attacker can rotate a color palette.",
        }]
        catalog = __import__("backend.utils.storage", fromlist=["get_controls_catalog"]).get_controls_catalog()
        controls = _catalog_fallback(threats, catalog)

        self.assertEqual(len(controls), 1)
        self.assertEqual(controls[0]["mapping_status"], "unassigned")
        self.assertEqual(controls[0]["mapping_basis"], "no_catalog_applicability_match")
        self.assertEqual(controls[0]["threat_ids"], ["unsupported-threat"])
        self.assertEqual(controls[0]["threat_mappings"][0]["match_type"], "unassigned")

        enriched = enrich_controls(controls, threats, self.project, dfd_model=self.dfd_model)
        self.assertEqual(enriched[0]["mapping_status"], "unassigned")
        self.assertEqual(enriched[0]["mapping_basis"], "no_catalog_applicability_match")

    def test_text_mapping_requires_specific_nonempty_signals(self):
        threats = [
            {"threat_id": "t-empty", "threat_category": "", "recommended_control": ""},
            {"threat_id": "t-weak", "threat_category": "Tampering", "threat_description": "The response may be affected."},
            {"threat_id": "t-specific", "threat_category": "Tampering", "threat_description": "Validate tampered amount input."},
        ]
        self.assertEqual(_related_threats_by_text({"name": "", "description": ""}, threats), [])
        related = _related_threats_by_text({"name": "Amount validation", "description": "Reject tampered amount input."}, threats)
        self.assertEqual([item["threat_id"] for item in related], ["t-specific"])

    def test_test_scenarios_cover_all_frameworks_and_validate_foreign_keys(self):
        flow_id = self.dfd_model["flows"][0]["id"]
        threats = [
            {
                "threat_id": f"threat-{index}",
                "framework": "STRIDE" if index % 2 else "LINDDUN",
                "threat_category": "Tampering" if index % 2 else "Data Disclosure",
                "threat_description": ("A registration field may be changed before validation." if index % 2
                                       else "Customer email may be disclosed beyond its intended recipient."),
                "target_refs": [{"type": "data_flow", "id": flow_id}],
            }
            for index in range(16)
        ]
        controls = [
            {"control_id": "control-1", "name": "PII Data Minimization and Masking",
             "threat_ids": [item["threat_id"] for item in threats if item["framework"] == "LINDDUN"], "mapping_status": "mapped"},
            {"control_id": "control-2", "name": "Input Validation and Sanitization",
             "threat_ids": [item["threat_id"] for item in threats if item["framework"] == "STRIDE"], "mapping_status": "mapped"},
        ]
        raw = _fallback_scenarios(threats, controls)
        raw.append({"scenario_name": "dangling", "threat_id": "missing", "preconditions": "x", "steps": ["x"], "expected_result": "x"})
        scenarios = normalize_test_scenarios(raw, threats, controls, self.dfd_model)

        self.assertEqual(len(scenarios), 16)
        self.assertTrue(any(item["threat_id"] == "threat-0" for item in scenarios))
        self.assertTrue(all(item["target_refs"] for item in scenarios))
        self.assertTrue(all(item["execution_status"] == "Not Run" for item in scenarios))
        self.assertEqual(len({item["test_id"] for item in scenarios}), 16)

    def test_f07_legacy_and_provider_omissions_are_explicit_blocked_items(self):
        flow_id = self.dfd_model["flows"][0]["id"]
        threats = [
            {"threat_id": "legacy-missing-category", "framework": "STRIDE", "threat_description": "Legacy record without category.", "target_refs": [{"type": "data_flow", "id": flow_id}]},
            {"threat_id": "provider-omitted", "framework": "LINDDUN", "threat_category": "Linking", "threat_description": "Identifiers may be correlated.", "target_refs": [{"type": "data_flow", "id": flow_id}]},
            None,
            {"framework": "STRIDE", "threat_category": "Tampering"},
        ]
        scenarios = normalize_test_scenarios([], threats, dfd_model=self.dfd_model)

        self.assertEqual({item["threat_id"] for item in scenarios}, {"legacy-missing-category", "provider-omitted"})
        self.assertTrue(all(item["execution_status"] == "Blocked" for item in scenarios))
        self.assertTrue(all(item["applicability_status"] == "blocked" for item in scenarios))
        self.assertTrue(all(item["applicability_reason"] for item in scenarios))

    def test_f07_spoofing_template_requires_webhook_evidence(self):
        generic = {
            "threat_id": "spoof-generic",
            "framework": "STRIDE",
            "threat_category": "Spoofing",
            "threat_description": "An attacker may impersonate a normal API caller.",
        }
        webhook = {
            **generic,
            "threat_id": "spoof-webhook",
            "threat_description": "An attacker may forge a payment webhook callback.",
        }
        generic_scenario = _fallback_scenarios([generic])[0]
        webhook_scenario = _fallback_scenarios([webhook])[0]

        self.assertNotIn("Webhook", generic_scenario["scenario_name"])
        self.assertIn("Webhook", webhook_scenario["scenario_name"])

    def test_f07_fallback_has_all_canonical_linddun_templates(self):
        categories = ["Linking", "Identifying", "Non-repudiation", "Detecting", "Data Disclosure", "Unawareness & Unintervenability", "Non-compliance"]
        threats = [{
            "threat_id": f"privacy-{index}",
            "framework": "LINDDUN",
            "threat_category": category,
            "threat_description": f"Privacy finding for {category}.",
        } for index, category in enumerate(categories)]

        scenarios = _fallback_scenarios(threats)

        self.assertEqual(len(scenarios), len(categories))
        self.assertTrue(all(item["steps"] and item["evidence_needed"] for item in scenarios))
        self.assertEqual({item["threat_id"] for item in scenarios}, {item["threat_id"] for item in threats})

    def test_control_and_test_reruns_preserve_stable_review_and_execution_state(self):
        old_control = {
            "control_id": "control-stable",
            "name": "Server-side validation",
            "threat_ids": ["threat-stable"],
            "review_status": "Verified",
            "implementation_status": "Implemented",
            "verification_evidence_refs": ["EV-1"],
        }
        new_control = {**old_control, "control_id": "provider-control", "review_status": "Open", "implementation_status": "Unknown"}
        controls = reconcile_controls([old_control], [new_control], self.dfd_model["revision"])
        old_test = {
            "test_id": "test-stable",
            "scenario_name": "Validate input",
            "threat_id": "threat-stable",
            "related_control_id": "control-stable",
            "preconditions": "setup",
            "steps": ["run"],
            "expected_result": "blocked",
            "execution_status": "Passed",
            "actual_result": "blocked",
        }
        new_test = {**old_test, "test_id": "provider-test", "execution_status": "Not Run"}
        tests = reconcile_test_scenarios([old_test], [new_test], self.dfd_model["revision"])

        self.assertEqual(controls[0]["control_id"], "control-stable")
        self.assertEqual(controls[0]["review_status"], "Verified")
        self.assertEqual(tests[0]["test_id"], "test-stable")
        self.assertEqual(tests[0]["execution_status"], "Passed")

    def test_projection_preserves_explicit_control_and_test_targets(self):
        flow_id = self.dfd_model["flows"][0]["id"]
        node_id = self.dfd_model["flows"][0]["target_id"]
        report = {
            "threats": [{
                "threat_id": "threat-projection",
                "target_refs": [{"type": "data_flow", "id": flow_id}],
            }],
            "controls": [{
                "threat_ids": ["threat-projection"],
                "target_refs": [{"type": "process", "id": node_id}],
            }],
            "test_scenarios": [{
                "threat_id": "threat-projection",
                "target_refs": [{"type": "process", "id": node_id}],
            }],
        }

        propagate_target_refs(report)

        self.assertEqual(
            {(ref["type"], ref["id"]) for ref in report["controls"][0]["target_refs"]},
            {("process", node_id), ("data_flow", flow_id)},
        )
        self.assertEqual(
            {(ref["type"], ref["id"]) for ref in report["test_scenarios"][0]["target_refs"]},
            {("process", node_id), ("data_flow", flow_id)},
        )

    def test_redaction_protects_structured_and_plain_text_secrets(self):
        content = '{"api_key":"secret-value","raw":"{\\"password\\":\\"pw\\"}","name":"safe"}'
        redacted = redact_text(content)
        self.assertNotIn("secret-value", redacted)
        self.assertNotIn('\\"pw\\"', redacted)
        self.assertIn("[REDACTED]", redacted)

        plain = redact_text("password=secret token: abc123")
        self.assertNotIn("secret", plain)
        self.assertNotIn("abc123", plain)

    def test_control_contract_drops_invalid_items_and_records_refs_and_metadata(self):
        flow_id = self.dfd_model["flows"][0]["id"]
        threat = {
            "threat_id": "f04-threat",
            "threat_category": "Tampering",
            "threat_description": "Input may be changed.",
        }
        payload = {
            "controls": [
                {
                    "name": "Validate input",
                    "status": "Unknown",
                    "threat_ids": ["f04-threat", "missing-threat"],
                    "target_refs": [
                        {"type": "flow", "id": flow_id},
                        {"type": "process", "id": "missing-dfd-id"},
                    ],
                    "verification_evidence_refs": ["EV-1", "EV-missing"],
                },
                {"name": "", "status": "not-a-control-status"},
            ]
        }
        with (
            patch("backend.services.control_service.get_active_provider_config", return_value={"base_url": "http://localhost", "model": "test", "api_key": "test", "max_tokens": 512}),
            patch("backend.services.control_service.chat_complete_json", new=AsyncMock(return_value=payload)),
        ):
            controls = asyncio.run(map_controls([threat], dfd_model=self.dfd_model, evidence_ids={"EV-1"}))

        self.assertEqual(len(controls), 1)
        self.assertEqual(controls.assessment_status, "partial")
        self.assertTrue(controls.generation_warnings)
        self.assertEqual(controls[0]["threat_ids"], ["f04-threat"])
        self.assertEqual(controls[0]["target_refs"], [{"type": "data_flow", "id": flow_id}])
        self.assertEqual(controls[0]["verification_evidence_refs"], ["EV-1"])

    def test_test_contract_rejects_invalid_foreign_key_items_but_keeps_valid_item(self):
        flow_id = self.dfd_model["flows"][0]["id"]
        threat = {"threat_id": "f04-test-threat", "threat_category": "Data Disclosure", "threat_description": "Data is over-shared."}
        valid = {
            "scenario_name": "Verify minimization",
            "preconditions": "Representative response",
            "steps": ["Capture response", "Compare fields"],
            "expected_result": "Only necessary data is returned",
            "threat_id": "f04-test-threat",
            "target_refs": [{"type": "flow", "id": flow_id}, {"type": "process", "id": "unknown"}],
            "execution_status": "Not Run",
        }
        payload = {"scenarios": [valid, {**valid, "scenario_name": "Bad", "priority": "Urgent", "threat_id": "missing"}]}
        with (
            patch("backend.services.test_service.get_active_provider_config", return_value={"base_url": "http://localhost", "model": "test", "api_key": "test", "max_tokens": 512}),
            patch("backend.services.test_service.chat_complete_json", new=AsyncMock(return_value=payload)),
        ):
            scenarios = asyncio.run(generate_test_scenarios([threat], self.project, dfd_model=self.dfd_model))

        self.assertEqual(len(scenarios), 1)
        self.assertEqual(scenarios.assessment_status, "partial")
        self.assertTrue(scenarios.generation_warnings)
        self.assertEqual(scenarios[0]["target_refs"], [{"type": "data_flow", "id": flow_id}])

    def test_structured_response_records_finish_reason_usage_and_retry_classification(self):
        response = SimpleNamespace(
            model="test-model",
            usage=SimpleNamespace(prompt_tokens=11, completion_tokens=7, total_tokens=18),
            choices=[SimpleNamespace(
                finish_reason="stop",
                message=SimpleNamespace(content='{"controls": []}', model_extra={}),
            )],
        )
        client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=AsyncMock(return_value=response))))
        with patch("backend.services.ai_service._get_client", return_value=client):
            result = asyncio.run(chat_complete_json("system", "user", base_url="http://localhost", return_metadata=True))

        self.assertEqual(result.metadata["finish_reason"], "stop")
        self.assertEqual(result.metadata["usage"]["total_tokens"], 18)
        self.assertEqual(result.metadata["parse_status"], "valid")

    def test_truncated_structured_response_is_not_accepted_after_repair(self):
        response = SimpleNamespace(
            model="test-model",
            usage=None,
            choices=[SimpleNamespace(
                finish_reason="length",
                message=SimpleNamespace(content='{"controls": [{"name": "partial"', model_extra={}),
            )],
        )
        client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=AsyncMock(return_value=response))))
        with patch("backend.services.ai_service._get_client", return_value=client):
            with self.assertRaises(AnalysisResponseError) as raised:
                asyncio.run(chat_complete_json("system", "user", base_url="http://localhost", return_metadata=True))

        self.assertEqual(raised.exception.code, "truncated_json")
        self.assertIn("truncated_json", raised.exception.response_metadata["retry_reasons"])
        # With 3 attempts (range(3)), the final attempt index is 2.
        self.assertEqual(raised.exception.response_metadata["format_retry_count"], 2)


if __name__ == "__main__":
    unittest.main()
