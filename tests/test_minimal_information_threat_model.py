import asyncio
import unittest

from backend.services.control_service import _catalog_fallback
from backend.services.dfd_model_service import build_dfd_model, validate_dfd_model
from backend.services.test_service import generate_test_scenarios
from backend.services.trust_boundary_service import build_grounded_data_flows, build_trust_model
from backend.utils.storage import get_controls_catalog


class MinimalInformationThreatModelTests(unittest.TestCase):
    def setUp(self):
        self.project = {
            "project_id": "minimal-commerce",
            "name": "Minimal Commerce",
            "actors": ["Buyer"],
            "components": ["Backend", "Database Relasional"],
            "external_systems": ["Payment Gateway"],
            "extracted_data_flows": [
                {"source": "Buyer", "destination": "Sistem", "data": ["email"], "protocol": "HTTPS"},
                {"source": "Sistem", "destination": "Payment Gateway", "data": ["payment token"], "protocol": "HTTPS"},
            ],
            "artifact_sources": [{"filename": "legacy-prd.pdf", "active": True}],
        }

    def test_legacy_extraction_is_visible_but_never_promoted_to_documented(self):
        trust = build_trust_model(self.project)
        model = build_dfd_model(self.project, trust)
        validation = validate_dfd_model(model)
        self.assertEqual(len(trust["data_flows"]), 2)
        self.assertEqual(len(model.flows), 2)
        self.assertEqual(len(model.boundaries), 2)
        self.assertTrue(validation["valid"])
        self.assertEqual(validation["readiness"]["knowledge_completeness"]["status"], "partial")
        self.assertFalse(validation["semantic_ready"])
        self.assertTrue(all(flow.knowledge_status == "inferred" for flow in model.flows))
        self.assertTrue(all(boundary.status == "candidate" for boundary in model.boundaries))
        self.assertEqual({item.evidence_type for item in model.evidence if item.id.startswith("legacy-flow:")}, {"inference"})
        self.assertIn("question-legacy-flow-evidence", {item.id for item in model.questions})
        self.assertTrue(any(node.name == "Sistem" and node.type == "process" for node in model.nodes))
        self.assertFalse(any(node.name == "Sistem" and "Backend" in node.identity_aliases for node in model.nodes))

    def test_empty_or_malformed_legacy_flow_does_not_create_an_edge(self):
        self.project["extracted_data_flows"] = [{"source": "Buyer", "data": ["email"]}]
        self.assertEqual(build_grounded_data_flows(self.project), [])

    def test_payment_linkability_uses_payment_control_and_executable_scenario(self):
        threat = {
            "threat_id": "payment-link",
            "framework": "LINDDUN",
            "threat_category": "Linking",
            "threat_description": "The payment gateway may correlate transactions across merchants.",
            "asset": "Payment card and customer ID",
            "recommended_control": "Tokenize payment fields sent to the gateway.",
            "source": "Sistem",
            "destination": "Payment Gateway",
        }
        controls = _catalog_fallback([threat], get_controls_catalog())
        ids = {item.get("catalog_id") for item in controls if item.get("mapping_status") == "mapped"}
        self.assertIn("ctrl-020", ids)
        self.assertNotIn("ctrl-008", ids)
        self.assertNotIn("ctrl-018", ids)
        scenarios = asyncio.run(generate_test_scenarios([threat], {}, force_fallback=True, controls=controls))
        self.assertEqual(len(scenarios), 1)
        self.assertEqual(scenarios[0]["applicability_status"], "applicable")
        self.assertEqual(scenarios[0]["related_control_id"], "CAT-ctrl-020")
        self.assertIn("cross-merchant", " ".join(scenarios[0]["steps"]).lower())

    def test_context_words_do_not_create_unrelated_specialist_controls(self):
        threats = [
            {"threat_id": "tracking", "threat_category": "Linking",
             "threat_description": "Tracking numbers link buyer orders.",
             "abuse_case": "An insider maps buying patterns and locations from shipment records.",
             "recommended_control": "Scope tracking identifiers per order."},
            {"threat_id": "audit", "threat_category": "Repudiation",
             "threat_description": "Order status changes lack immutable audit logging.",
             "recommended_control": "Record actor and timestamp."},
            {"threat_id": "notice", "threat_category": "Unawareness & Unintervenability",
             "threat_description": "Users are not informed that payment data reaches external providers.",
             "recommended_control": "Provide a privacy notice at checkout."},
        ]
        controls = _catalog_fallback(threats, get_controls_catalog())
        by_threat = {
            threat["threat_id"]: {item.get("catalog_id") for item in controls
                                  if threat["threat_id"] in item.get("threat_ids", [])}
            for threat in threats
        }
        self.assertNotIn("ctrl-018", by_threat["tracking"])
        self.assertNotIn("ctrl-008", by_threat["audit"])
        self.assertNotIn("ctrl-020", by_threat["notice"])


if __name__ == "__main__":
    unittest.main()
