import json
import unittest
from pathlib import Path

from backend.services.finding_quality_service import (
    FINDING_QUALITY_VERSION,
    build_applicability_manifest,
    finding_quality_fingerprint,
    validate_and_dedupe_findings,
)


def quality_model():
    return {
        "revision": 7,
        "semantic_hash": "quality-model-7",
        "primary_interaction_ids": ["flow-primary"],
        "nodes": [
            {"id": "actor", "type": "entity"},
            {"id": "api", "type": "process"},
        ],
        "data_objects": [{"id": "data", "classification": "PII"}],
        "flows": [
            {
                "id": "flow-primary",
                "source_id": "actor",
                "target_id": "api",
                "data_object_ids": ["data"],
                "grounding_status": "grounded",
            },
            {
                "id": "flow-deferred",
                "source_id": "actor",
                "target_id": "api",
                "grounding_status": "deferred",
                "grounding_reason": "Source locator is missing.",
            },
        ],
        "boundaries": [{"id": "boundary-public"}],
    }


class Cr4FindingQualityTests(unittest.TestCase):
    def test_fingerprint_uses_mechanism_not_title_or_description_wording(self):
        first = {
            "framework": "STRIDE",
            "threat_category": "Tampering",
            "primary_interaction_ref": "flow-primary",
            "asset": "Registration fields",
            "title": "Altered registration payload",
            "abuse_case": "attacker changes unexpected fields before validation",
        }
        second = {
            **first,
            "title": "Input integrity issue",
            "threat_description": "A different provider wording.",
        }
        self.assertEqual(finding_quality_fingerprint(first), finding_quality_fingerprint(second))

    def test_manifest_distinguishes_assessed_unprocessed_and_context_only(self):
        manifest = build_applicability_manifest(
            [{
                "element_ref": "flow-primary",
                "category": "Tampering",
                "status": "candidate_identified",
                "reason": "Provider found an integrity scenario.",
                "applicability": "applicable",
            }],
            [],
            quality_model(),
            "STRIDE",
        )
        summary = manifest["summary"]
        self.assertEqual(summary["primary_interaction_count"], 1)
        self.assertEqual(summary["assessed"], 1)
        self.assertGreater(summary["unprocessed"], 0)
        self.assertGreater(summary["context_only"], 0)
        self.assertFalse(summary["complete"])
        self.assertEqual(manifest["scope"]["unprocessed_flow_ids"], ["flow-primary"])
        self.assertEqual(manifest["model_revision"], 7)

    def test_missing_primary_is_reviewable_but_blocked_from_downstream(self):
        findings, warnings, quarantine = validate_and_dedupe_findings(
            [{
                "threat_id": "missing-primary",
                "framework": "STRIDE",
                "threat_category": "Spoofing",
                "threat_description": "A caller may impersonate a principal.",
                "affected_refs": ["api"],
            }],
            quality_model(),
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_state"], "needs_context")
        self.assertFalse(findings[0]["downstream_eligible"])
        self.assertEqual(findings[0]["risk_status"], "deferred")
        self.assertTrue(any("missing_primary_interaction" in item for item in warnings))
        self.assertEqual(quarantine, [])

    def test_direct_evidence_and_semantic_duplicate_are_enforced(self):
        base = {
            "threat_id": "finding-1",
            "framework": "STRIDE",
            "threat_category": "Tampering",
            "threat_description": "The request can be altered before validation.",
            "abuse_case": "attacker changes unexpected fields before validation",
            "asset": "Registration fields",
            "primary_interaction_ref": "flow-primary",
            "finding_state": "grounded",
            "scenario_evidence_refs": ["EV-1"],
        }
        duplicate = {**base, "threat_id": "finding-2", "title": "Another provider title"}
        findings, warnings, quarantine = validate_and_dedupe_findings(
            [base, duplicate],
            quality_model(),
            {"EV-1"},
            [{"evidence_id": "EV-1", "evidence_type": "direct", "snippet": "Validation is bypassed."}],
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["quality_schema_version"], FINDING_QUALITY_VERSION)
        self.assertEqual(findings[0]["finding_state"], "grounded")
        self.assertEqual(findings[0]["evidence_sufficiency"], "direct")
        self.assertTrue(any("duplicate" in warning for warning in warnings))
        self.assertEqual(quarantine[0]["reasons"], ["duplicate_finding_fingerprint"])

    def test_domain_slice_fixture_covers_cr4_sampling_domains_and_topics(self):
        path = Path(__file__).parent / "prd_corpus" / "cr4_domain_slices.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        required_domains = {
            "identity", "payment", "healthcare", "saas_multi_tenant",
            "public_service_biometric", "wallet", "ai_agent_tool_use", "webhook_event",
        }
        self.assertTrue(required_domains.issubset({item["domain"] for item in payload["slices"]}))
        self.assertTrue({
            "credential_theft_fraud_auditability",
            "consent_video_privacy",
            "inventory_race",
            "shared_link_malware_admin_abuse",
            "role_escalation",
            "provider_impersonation_threshold_auditability",
            "transaction_integrity",
            "agent_overtrust",
            "queue_poisoning",
        }.issubset(set(payload["expected_topics"])))


if __name__ == "__main__":
    unittest.main()
