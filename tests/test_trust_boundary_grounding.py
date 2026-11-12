import unittest

from backend.services.trust_boundary_service import (
    active_trust_boundaries,
    apply_boundary_reviews,
    attach_boundary_refs,
    attach_target_refs,
    build_entity_registry,
    build_trust_model,
    validate_boundary_candidates,
)


class TrustBoundaryGroundingTests(unittest.TestCase):
    def setUp(self):
        self.project = {
            "name": "crAPI testing",
            "actors": ["user"],
            "components": ["Identity API", "Community API", "Workshop API", ".Well Known API", "Api API"],
            "entry_points": ["API gateway", "POST /identity/api/auth/login"],
            "external_systems": [],
            "manual_context": {
                "actors": ["user"],
                "components": [],
                "entry_points": ["API gateway"],
                "external_systems": [],
            },
            "canonical_operations": [
                {"key": "POST /identity/api/auth/login", "service": "Identity API"},
                {"key": "GET /.well-known/jwks.json", "service": ".Well Known API"},
                {"key": "GET /api/v2/search", "service": "Api API"},
            ],
            "extracted_data_flows": [
                {
                    "source": "External API client",
                    "destination": "Identity API",
                    "protocol": "HTTPS",
                    "data": ["email", "password"],
                    "artifact_ids": ["openapi-1", "postman-1"],
                }
            ],
        }

    def test_crapi_topology_collapses_to_one_grounded_ingress_boundary(self):
        model = build_trust_model(self.project)

        self.assertEqual(len(model["boundaries"]), 1)
        boundary = model["boundaries"][0]
        self.assertEqual((boundary["source"], boundary["destination"]), ("User", "API Gateway"))
        self.assertEqual((boundary["source_zone_id"], boundary["destination_zone_id"]), ("external", "application"))
        self.assertEqual(boundary["status"], "Candidate")
        self.assertEqual(boundary["confidence"], "Medium")
        self.assertTrue(boundary["evidence_refs"])
        self.assertEqual(boundary["generation_method"], "deterministic")

        entity_names = {entity["name"] for entity in model["entities"]}
        self.assertNotIn(".Well Known API", entity_names)
        self.assertNotIn("Api API", entity_names)
        self.assertIn("Application API", entity_names)
        self.assertNotIn("User Database", entity_names)
        self.assertNotIn("External Payment Gateway", entity_names)
        self.assertEqual(model["data_flows"][0]["operation_count"], 3)

    def test_validator_rejects_unknown_and_same_zone_entities(self):
        flows = [{
            "flow_id": "flow-1",
            "source": "Identity API",
            "destination": "Community API",
            "source_entity_type": "component",
            "destination_entity_type": "component",
            "confidence": "Medium",
            "evidence_refs": ["artifact:openapi-1"],
        }]
        registry = build_entity_registry(self.project, flows)
        candidates = [
            {
                "source": "Identity API",
                "destination": "Community API",
                "crossing_flow_ids": ["flow-1"],
                "evidence_refs": ["artifact:openapi-1"],
            },
            {
                "source": "Workshop API",
                "destination": "External Payment Gateway",
                "crossing_flow_ids": ["flow-1"],
                "evidence_refs": ["artifact:openapi-1"],
            },
        ]

        accepted, warnings = validate_boundary_candidates(candidates, registry, flows)
        self.assertEqual(accepted, [])
        self.assertTrue(any("same-zone" in warning for warning in warnings))
        self.assertTrue(any("unknown entity" in warning for warning in warnings))

    def test_no_topology_claim_when_cross_zone_flow_is_missing(self):
        project = {
            "name": "Unspecified service",
            "actors": ["User"],
            "components": ["Backend API"],
            "entry_points": [],
            "external_systems": ["Email provider"],
            "manual_context": {
                "actors": ["User"],
                "components": ["Backend API"],
                "entry_points": [],
                "external_systems": ["Email provider"],
            },
            "canonical_operations": [],
            "extracted_data_flows": [],
        }
        model = build_trust_model(project)
        self.assertEqual(model["boundaries"], [])
        self.assertTrue(any("no evidenced data flow" in warning.lower() for warning in model["warnings"]))

    def test_human_review_is_applied_only_to_the_same_model_fingerprint(self):
        boundary = build_trust_model(self.project)["boundaries"][0]
        reviews = {
            boundary["boundary_id"]: {
                "status": "Confirmed",
                "review_note": "Confirmed with the API owner.",
                "reviewed_at": "2026-08-06T10:00:00",
                "model_fingerprint": boundary["model_fingerprint"],
            }
        }

        reviewed, warnings = apply_boundary_reviews([boundary], reviews)
        self.assertEqual(reviewed[0]["status"], "Confirmed")
        self.assertEqual(reviewed[0]["review_note"], "Confirmed with the API owner.")
        self.assertEqual(warnings, [])

        changed = {**boundary, "model_fingerprint": "topology-changed"}
        stale, warnings = apply_boundary_reviews([changed], reviews)
        self.assertEqual(stale[0]["status"], "Candidate")
        self.assertTrue(stale[0]["review_stale"])
        self.assertTrue(any("stale" in warning.lower() for warning in warnings))

        removed, warnings = apply_boundary_reviews([], reviews)
        self.assertEqual(removed, [])
        self.assertTrue(any("no longer exists" in warning.lower() for warning in warnings))

    def test_rejected_boundary_is_excluded_from_active_analysis(self):
        boundary = build_trust_model(self.project)["boundaries"][0]
        self.assertEqual(active_trust_boundaries([{**boundary, "status": "Rejected"}]), [])
        self.assertEqual(len(active_trust_boundaries([{**boundary, "status": "Confirmed"}])), 1)

    def test_findings_receive_stable_boundary_references(self):
        model = build_trust_model(self.project)
        boundary = model["boundaries"][0]
        threats = [{
            "threat_id": "threat-1",
            "trust_boundary": "User → API Gateway",
            "source": "External attacker",
            "destination": "Identity API",
        }]

        attach_boundary_refs(threats, [boundary])

        self.assertEqual(threats[0]["trust_boundary_ids"], [boundary["boundary_id"]])

    def test_hierarchical_views_separate_grounded_topology_from_logical_services(self):
        model = build_trust_model(self.project)
        views = model["views"]

        self.assertEqual({item["label"] for item in views["context"]["nodes"]}, {"User", "API Gateway"})
        logical_services = {
            item["label"] for item in views["services"]["nodes"]
            if item.get("role") == "logical_service"
        }
        self.assertEqual(logical_services, {"Application API", "Identity API"})
        self.assertTrue(all(item["topology_status"] == "logical" for item in views["services"]["flows"]))
        self.assertEqual(len(views["scenarios"]["items"]), 3)

    def test_typed_targets_map_findings_to_process_flow_boundary_and_scenario(self):
        model = build_trust_model(self.project)
        threat = {
            "threat_id": "threat-login",
            "component": "Identity API",
            "asset": "password",
            "trust_boundary": "User → API Gateway",
            "threat_description": "Credential attack against POST /identity/api/auth/login",
        }

        attach_target_refs([threat], model["boundaries"], model["views"])

        target_types = {item["type"] for item in threat["target_refs"]}
        self.assertTrue({"process", "data_flow", "trust_boundary", "scenario", "data_asset"}.issubset(target_types))
        self.assertEqual(threat["mapping_status"], "unmapped")
        self.assertIsNone(threat.get("primary_interaction_ref"))


if __name__ == "__main__":
    unittest.main()
