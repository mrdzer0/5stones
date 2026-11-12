import asyncio
import copy
import unittest
from unittest.mock import patch

from backend.services.deferred_decision_service import (
    DECISION_STATES,
    apply_decision_update,
    decision_fingerprint,
    normalize_decision_state,
    reconcile_deferred_decisions,
)
from backend.services.posture_service import compute_signoff_readiness
from backend.routers.analysis import update_deferred_decision


def cr5_report():
    return {
        "missing_info": [{
            "missing_id": "gap-auth-1",
            "area": "Authentication",
            "question_to_ask": "What authentication mechanism is used for login requests?",
            "owner": "Security",
            "next_action": "Add the authentication design or runtime evidence.",
            "linked_refs": [{"type": "data_flow", "id": "flow-login"}, {"type": "threat", "id": "threat-auth"}],
        }],
        "assumptions": [{
            "assumption_id": "assumption-auth-1",
            "area": "Authentication",
            "assumption": "JWT is used for the login session.",
            "verification_question": "What authentication mechanism is used for login requests?",
            "related_threat_id": "threat-auth",
            "target_refs": [{"type": "data_flow", "id": "flow-login"}],
        }],
        "dfd_model": {
            "flows": [{"id": "flow-login", "source": "internet", "destination": "web-api"}],
        },
        "threats": [
            {
                "threat_id": "threat-auth",
                "framework": "STRIDE",
                "finding_state": "grounded",
                "status": "Open",
                "risk_level": "High",
                "primary_interaction_ref": "flow-login",
                "affected_refs": ["flow-login"],
            },
            {
                "threat_id": "threat-unrelated",
                "framework": "STRIDE",
                "finding_state": "grounded",
                "status": "Open",
                "risk_level": "Medium",
                "primary_interaction_ref": "flow-profile",
                "affected_refs": ["flow-profile"],
            },
        ],
        "controls": [
            {"control_id": "control-auth", "threat_ids": ["threat-auth"], "mapping_status": "mapped"},
            {"control_id": "control-unrelated", "threat_ids": ["threat-unrelated"], "mapping_status": "mapped"},
        ],
        "test_scenarios": [
            {"test_id": "test-auth", "threat_id": "threat-auth", "steps": ["Exercise login"]},
            {"test_id": "test-unrelated", "threat_id": "threat-unrelated", "steps": ["Exercise profile"]},
        ],
    }


class DeferredDecisionTests(unittest.TestCase):
    def test_state_contract_accepts_reviewer_lifecycle_and_legacy_aliases(self):
        self.assertEqual(set(DECISION_STATES), {
            "open", "assigned", "answered", "accepted_assumption", "deferred", "obsolete",
        })
        self.assertEqual(normalize_decision_state("Resolved"), "answered")
        self.assertEqual(normalize_decision_state("Accepted assumption"), "accepted_assumption")
        self.assertEqual(normalize_decision_state("closed"), "obsolete")

    def test_semantic_duplicates_merge_sources_and_dependencies(self):
        report = cr5_report()
        reconcile_deferred_decisions(report)

        decisions = report["deferred_decisions"]
        auth = next(item for item in decisions if item["decision_fingerprint"] == decision_fingerprint(
            "What authentication mechanism is used for login requests?", "Authentication"
        ))

        self.assertEqual(len([item for item in decisions if item["decision_fingerprint"] == auth["decision_fingerprint"]]), 1)
        self.assertEqual({ref["type"] for ref in auth["source_refs"]}, {"missing_info", "assumption"})
        self.assertIn("threat-auth", auth["dependency_refs"]["threat_ids"])
        self.assertIn("flow-login", auth["dependency_refs"]["dfd_refs"])
        self.assertEqual(auth["owner"], "Security")
        self.assertTrue(auth["next_action"])
        self.assertEqual(report["decision_summary"]["unresolved"], report["decision_summary"]["total"])

    def test_deferred_topic_rules_are_actionable_and_project_aware(self):
        report = {"dfd_model": {"flows": [{"id": "flow-webhook"}]}}
        project = {
            "name": "Multi-tenant AI payment webhook",
            "description": "AI provider handles payment webhooks for tenant workspaces and queues.",
            "data_involved": ["personal data", "payment transaction"],
            "external_systems": ["LLM provider"],
        }
        reconcile_deferred_decisions(report, project)
        areas = {item["area"] for item in report["deferred_decisions"]}

        self.assertIn("Key Certificate Rotation", areas)
        self.assertIn("Deletion Propagation", areas)
        self.assertIn("Idempotency Replay", areas)
        self.assertIn("Provider Terms", areas)
        self.assertIn("Tenant Isolation", areas)
        self.assertIn("Dlq Schema Ownership", areas)
        self.assertTrue(all(item["owner"] and item["next_action"] for item in report["deferred_decisions"]))

    def test_answer_selectively_stales_only_linked_consumers_and_preserves_history(self):
        report = cr5_report()
        reconcile_deferred_decisions(report)
        decision = next(item for item in report["deferred_decisions"] if "threat-auth" in item["dependency_refs"]["threat_ids"])

        updated, impact = apply_decision_update(report, decision["decision_id"], {
            "state": "answered",
            "answer": "The API uses short-lived OIDC tokens with issuer validation.",
            "evidence_refs": ["EV-auth-design"],
        }, actor="appsec-reviewer")

        self.assertEqual(updated["state"], "answered")
        self.assertEqual(updated["status"], "Answered")
        self.assertEqual(updated["history"][-1]["actor"], "appsec-reviewer")
        self.assertEqual(updated["evidence_refs"], ["EV-auth-design"])
        self.assertEqual(report["missing_info"][0]["state"], "answered")
        self.assertEqual(report["assumptions"][0]["status"], "Answered")
        self.assertEqual(report["missing_info"][0]["decision_id"], decision["decision_id"])
        self.assertEqual(set(impact["impacted"]["threats"]), {"threat-auth"})
        self.assertEqual(set(impact["impacted"]["controls"]), {"control-auth"})
        self.assertEqual(set(impact["impacted"]["tests"]), {"test-auth"})
        self.assertTrue(impact["selective_invalidation"])
        self.assertEqual(report["threats"][0]["analysis_state"], "stale")
        self.assertNotIn("analysis_state", report["threats"][1])
        self.assertEqual(report["controls"][0]["analysis_state"], "stale")
        self.assertNotIn("analysis_state", report["controls"][1])
        self.assertEqual(report["test_scenarios"][0]["analysis_state"], "stale")
        self.assertNotIn("analysis_state", report["test_scenarios"][1])
        self.assertIn("stride", report["analysis_stale"]["stages"])
        self.assertIn("controls", report["analysis_stale"]["stages"])

    def test_dfd_only_dependency_can_stale_direct_control_and_test_refs(self):
        report = {
            "missing_info": [{
                "missing_id": "gap-flow",
                "area": "Transport security",
                "question": "Is the login flow protected by TLS?",
                "linked_refs": [{"type": "data_flow", "id": "flow-login"}],
            }],
            "dfd_model": {"flows": [{"id": "flow-login"}]},
            "controls": [{"control_id": "control-flow", "primary_interaction_ref": "flow-login"}],
            "test_scenarios": [{"test_id": "test-flow", "primary_interaction_ref": "flow-login"}],
        }
        reconcile_deferred_decisions(report)
        decision = report["deferred_decisions"][0]

        _, impact = apply_decision_update(report, decision["decision_id"], {"state": "deferred"})

        self.assertEqual(impact["impacted"]["controls"], ["control-flow"])
        self.assertEqual(impact["impacted"]["tests"], ["test-flow"])
        self.assertEqual(report["controls"][0]["analysis_state"], "stale")
        self.assertEqual(report["test_scenarios"][0]["analysis_state"], "stale")

    def test_unresolved_decision_blocks_signoff_without_mutating_source_report(self):
        report = cr5_report()
        original = copy.deepcopy(report)
        gate = compute_signoff_readiness(report)

        self.assertEqual(gate["components"]["deferred_decisions"]["status"], "not_ready")
        self.assertFalse(gate["signoff_ready"])
        self.assertEqual(report, original)

    def test_decision_api_persists_canonical_update_and_returns_impact(self):
        report = cr5_report()
        reconcile_deferred_decisions(report)
        decision_id = report["deferred_decisions"][0]["decision_id"]
        project = {"project_id": "project-1", "name": "CR5 fixture"}

        with patch("backend.routers.analysis.get_project", return_value=project), patch(
            "backend.routers.analysis.get_report", return_value=report
        ), patch("backend.routers.analysis.save_report"), patch("backend.routers.analysis.log_event"):
            response = asyncio.run(update_deferred_decision(
                "project-1", decision_id, {"status": "Accepted assumption", "answer": "Reviewed by owner."}
            ))

        self.assertTrue(response["success"])
        self.assertEqual(response["decision"]["state"], "accepted_assumption")
        self.assertTrue(response["impact"]["selective_invalidation"])
        self.assertEqual(report["deferred_decisions"][0]["answer"], "Reviewed by owner.")


if __name__ == "__main__":
    unittest.main()
