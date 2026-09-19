import unittest

from backend.services.dfd_model_service import build_dfd_model, validate_dfd_model
from backend.services.trust_boundary_service import attach_target_refs, build_trust_model
from backend.models.dfd import DfdFlow, DfdModel, DfdNode, DfdZone


class DfdSemanticModelTests(unittest.TestCase):
    def setUp(self):
        self.project = {
            "project_id": "project-1",
            "name": "Registration",
            "description": "Customer registration flow",
            "actors": ["Customer"],
            "components": ["Registration API", "Customer Database"],
            "entry_points": ["Web App"],
            "data_involved": ["email", "activation token"],
            "external_systems": ["Email Provider"],
            "manual_context": {
                "actors": ["Customer"],
                "components": ["Registration API", "Customer Database"],
                "entry_points": ["Web App"],
                "external_systems": ["Email Provider"],
            },
            "artifact_sources": [{
                "artifact_id": "artifact-1",
                "active": True,
            }],
            "canonical_operations": [],
            "extracted_data_flows": [
                {
                    "flow_id": "flow-1",
                    "source": "Customer",
                    "destination": "Registration API",
                    "source_entity_type": "actor",
                    "destination_entity_type": "component",
                    "protocol": "HTTPS",
                    "data": ["email"],
                    "evidence_refs": ["artifact:artifact-1"],
                    "evidence_type": "direct",
                },
                {
                    "flow_id": "flow-2",
                    "source": "Registration API",
                    "destination": "Customer Database",
                    "source_entity_type": "component",
                    "destination_entity_type": "data_store",
                    "protocol": "SQL",
                    "data": ["email"],
                    "evidence_refs": ["artifact:artifact-1"],
                    "evidence_type": "direct",
                },
            ],
        }

    def test_builds_canonical_model_with_stable_typed_refs(self):
        trust_model = build_trust_model(self.project)
        model = build_dfd_model(self.project, trust_model)
        validation = validate_dfd_model(model)

        self.assertTrue(validation["valid"], validation)
        self.assertEqual(model.schema_version, "dfd-v1")
        self.assertEqual({node.type for node in model.nodes}, {"entity", "process", "data_store"})
        self.assertTrue(all(flow.source_id in {node.id for node in model.nodes} for flow in model.flows))
        self.assertTrue(all(flow.target_id in {node.id for node in model.nodes} for flow in model.flows))
        self.assertTrue(model.source_refs)
        self.assertTrue(model.questions)

    def test_validator_reports_dangling_refs_and_zone_cycles(self):
        model = DfdModel(
            id="model-1",
            project_id="project-1",
            title="Invalid model",
            nodes=[DfdNode(id="p-1", display_id="P1", type="process", name="Process")],
            zones=[
                DfdZone(id="z-1", display_id="Z1", name="One", parent_zone_id="z-2"),
                DfdZone(id="z-2", display_id="Z2", name="Two", parent_zone_id="z-1"),
            ],
            flows=[DfdFlow(
                id="f-1",
                display_id="F1",
                source_id="p-1",
                target_id="missing-node",
                name="Data",
            )],
        )

        validation = validate_dfd_model(model)

        self.assertFalse(validation["valid"])
        self.assertTrue(any("dangling" in error for error in validation["errors"]))
        self.assertTrue(any("cycle" in error for error in validation["errors"]))

    def test_unmapped_threat_does_not_fan_out_to_all_boundaries(self):
        model = build_trust_model(self.project)
        boundaries = model["boundaries"]
        extra = {
            **boundaries[0],
            "boundary_id": "boundary-2",
            "source": "Other Customer",
            "destination": "Other API",
            "boundary_label": "Other boundary",
        }
        threat = {
            "threat_id": "threat-1",
            "component": "Unrelated process",
            "source": "Unrelated actor",
            "destination": "Unrelated process",
            "threat_description": "No model element is named here.",
        }

        attach_target_refs([threat], [boundaries[0], extra], model["views"])

        self.assertEqual(threat["trust_boundary_ids"], [])
        self.assertFalse(any(ref["type"] == "trust_boundary" for ref in threat["target_refs"]))
        self.assertEqual(threat["mapping_status"], "unmapped")


if __name__ == "__main__":
    unittest.main()

