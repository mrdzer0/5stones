import unittest

from backend.routers.artifacts import _verified_use_cases
from backend.services.artifact_reconciliation_service import rebuild_project_from_artifacts
from backend.services.trust_boundary_service import attach_target_refs, build_trust_model


class PrdScenarioModelingTests(unittest.TestCase):
    def test_reconciliation_keeps_prd_use_cases_separate_from_api_operations(self):
        project = {
            "actors": [], "components": [], "entry_points": [], "data_involved": [],
            "external_systems": [], "critical_actions": [], "existing_controls": [],
            "artifact_sources": [{
                "artifact_id": "prd-1", "artifact_type": "prd", "filename": "checkout.md", "active": True,
                "contribution": {"use_cases": [{
                    "name": "Create order", "actor": "Customer",
                    "steps": [{"type": "action", "label": "Submit order"}],
                    "evidence_locator": "Order flow", "evidence_snippet": "Customer submits an order.",
                }]},
            }],
        }

        rebuild_project_from_artifacts(project)

        self.assertEqual(project["canonical_operations"], [])
        self.assertEqual(len(project["business_scenarios"]), 1)
        self.assertEqual(project["artifact_inventory"]["business_scenario_count"], 1)
        self.assertEqual(project["business_scenarios"][0]["evidence_ref"], "artifact:prd-1:Order flow")

    def test_use_case_requires_exact_evidence_and_preserves_activity_types(self):
        content = "Customer submits an order. The application validates stock and stores the order in Order Database."
        items = [{
            "name": "Create order",
            "actor": "Customer",
            "steps": [
                {"type": "action", "label": "Submit order", "target": "Application"},
                {"type": "decision", "label": "Stock available?"},
                {"type": "data_store", "label": "Store order", "target": "Order Database"},
            ],
            "data": ["order"],
            "evidence_snippet": content,
            "evidence_locator": "Order flow",
        }]

        verified = _verified_use_cases(items, content, "checkout-prd.md", "prd")

        self.assertEqual(len(verified), 1)
        self.assertEqual([step["type"] for step in verified[0]["steps"]], ["action", "decision", "data_store"])
        self.assertEqual(verified[0]["status"], "Candidate")

        items[0]["evidence_snippet"] = "This sentence does not exist in the source artifact."
        self.assertEqual(_verified_use_cases(items, content, "checkout-prd.md", "prd"), [])

    def test_prd_business_scenario_builds_activity_flow_with_distinct_elements(self):
        project = {
            "name": "Checkout",
            "actors": ["Customer"],
            "components": ["Application", "Order Database"],
            "entry_points": ["Web"],
            "manual_context": {
                "actors": ["Customer"], "components": [], "entry_points": ["Web"], "external_systems": []
            },
            "canonical_operations": [],
            "extracted_data_flows": [],
            "business_scenarios": [{
                "name": "Create order",
                "actor": "Customer",
                "steps": [
                    {"type": "action", "label": "Submit order", "target": "Application", "data": ["order"]},
                    {"type": "decision", "label": "Stock available?"},
                    {"type": "data_store", "label": "Store order", "target": "Order Database", "data": ["order"]},
                ],
                "evidence_ref": "artifact:prd-1:Order flow",
                "evidence_snippet": "Customer submits an order and the application stores it.",
            }],
        }

        model = build_trust_model(project)
        scenario = model["views"]["scenarios"]["business_items"][0]

        self.assertEqual(scenario["scenario_kind"], "business_flow")
        self.assertEqual(
            [step["element_type"] for step in scenario["steps"]],
            ["actor", "action", "decision", "data_store"],
        )
        self.assertEqual(model["views"]["services"]["readiness"]["state"], "insufficient")
        self.assertEqual(model["views"]["services"]["nodes"], [])

        threat = {"threat_id": "order-threat", "component": "Application", "threat_description": "An attacker can abuse Create order to submit a forged order."}
        attach_target_refs([threat], model["boundaries"], model["views"])
        self.assertIn(
            scenario["scenario_id"],
            {ref["id"] for ref in threat["target_refs"] if ref["type"] == "scenario"},
        )

    def test_prd_internal_flow_is_candidate_service_architecture(self):
        project = {
            "name": "Checkout",
            "actors": ["Customer"],
            "components": ["Order Service", "Order Database"],
            "entry_points": [],
            "manual_context": {"actors": ["Customer"], "components": [], "entry_points": [], "external_systems": []},
            "canonical_operations": [],
            "business_scenarios": [],
            "extracted_data_flows": [{
                "source": "Order Service",
                "destination": "Order Database",
                "protocol": "SQL",
                "data": ["order"],
                "artifact_ids": ["prd-1"],
            }],
        }

        model = build_trust_model(project)
        service_view = model["views"]["services"]

        self.assertEqual(service_view["readiness"]["state"], "candidate")
        self.assertEqual({node["element_type"] for node in service_view["nodes"]}, {"process", "data_store"})
        self.assertEqual(len(service_view["flows"]), 1)


if __name__ == "__main__":
    unittest.main()
