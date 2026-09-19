import json
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from backend.models.dfd import DfdBoundary
from backend.routers.dfd import apply_dfd_regeneration_proposal, export_dfd, import_dfd, save_dfd, resolve_dfd_regeneration_proposal
from backend.services.dfd_model_service import (
    build_dfd_model,
    preview_dfd_delete_impact,
    recalculate_boundary_crossings,
    reconcile_generated_dfd,
    refresh_attribute_assertions,
    validate_dfd_model,
)
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
        evidence_ids = {item.id for item in model.evidence}
        self.assertTrue(all(ref in evidence_ids for node in model.nodes for ref in node.evidence_refs))
        self.assertTrue(all(ref in evidence_ids for flow in model.flows for ref in flow.evidence_refs))
        self.assertTrue(model.questions)
        feature_views = [view for view in model.views if view.kind == "feature" and view.parent_process_id]
        self.assertTrue(feature_views)
        self.assertTrue(all(view.port_mappings.get("input") == view.input_flow_ids for view in feature_views))
        self.assertTrue(all(view.port_mappings.get("output") == view.output_flow_ids for view in feature_views))
        self.assertTrue(any(question.id == "question-data-privacy-context" for question in model.questions))

    def test_canonical_operations_split_request_and_response_flows(self):
        project = {
            **self.project,
            "canonical_operations": [{
                "key": "POST /register",
                "method": "POST",
                "path": "/register",
                "service": "Registration API",
                "security_status": "secured",
                "request_fields": ["email", "password"],
                "response_fields": ["status", "activation_token"],
            }],
        }
        trust_model = build_trust_model(project)
        model = build_dfd_model(project, trust_model)
        validation = validate_dfd_model(model)

        self.assertTrue(validation["valid"], validation)
        self.assertEqual({flow.interaction_kind for flow in model.flows}, {"request", "response"})
        self.assertEqual(len(model.flows), 2)
        request = next(flow for flow in model.flows if flow.interaction_kind == "request")
        response = next(flow for flow in model.flows if flow.interaction_kind == "response")
        self.assertEqual((request.source_id, request.target_id), (response.target_id, response.source_id))
        self.assertTrue(request.authz)

    def test_postman_only_projection_does_not_invent_database_or_internal_topology(self):
        project = {
            "project_id": "postman-only",
            "name": "Postman-only API",
            "description": "Only an API collection is available.",
            "actors": [],
            "components": [],
            "entry_points": [],
            "data_involved": [],
            "external_systems": [],
            "manual_context": {"actors": [], "components": [], "entry_points": [], "external_systems": []},
            "artifact_sources": [{"artifact_id": "postman-1", "artifact_type": "postman", "active": True}],
            "canonical_operations": [{
                "key": "POST /register",
                "method": "POST",
                "path": "/register",
                "service": "Registration API",
                "security_status": "unknown",
                "request_fields": ["email"],
                "response_fields": [],
            }],
            "extracted_data_flows": [{
                "source": "External API client",
                "destination": "Registration API",
                "protocol": "HTTPS",
                "data": ["email"],
                "artifact_ids": ["postman-1"],
            }],
        }
        trust_model = build_trust_model(project)
        model = build_dfd_model(project, trust_model)

        self.assertFalse(any(node.type == "data_store" for node in model.nodes))
        self.assertFalse(any("database" in node.name.casefold() for node in model.nodes))
        self.assertTrue(any(question.id == "question-response-semantics" for question in model.questions))

    def test_conflicting_artifact_assertions_remain_conflicting(self):
        project = {
            **self.project,
            "artifact_conflicts": [{
                "operation_key": "POST /register",
                "field": "security_status",
                "values": [
                    {"artifact_id": "openapi-1", "security_status": "secured"},
                    {"artifact_id": "postman-1", "security_status": "public"},
                ],
                "message": "Artifacts disagree about authentication.",
            }],
        }
        model = build_dfd_model(project, build_trust_model(project))

        self.assertTrue(any(assertion.status == "conflicting" for assertion in model.assertions))
        self.assertTrue(any(question.id == "question-conflicting-sources" for question in model.questions))

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

    def test_validator_reports_duplicate_display_ids(self):
        model = DfdModel(
            id="model-display-duplicate",
            project_id="project-1",
            title="Duplicate display IDs",
            nodes=[
                DfdNode(id="p-1", display_id="P1", type="process", name="One"),
                DfdNode(id="p-2", display_id="P1", type="process", name="Two"),
            ],
        )

        validation = validate_dfd_model(model)

        self.assertFalse(validation["valid"])
        self.assertTrue(any("Duplicate node display ID" in error for error in validation["errors"]))

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

    def test_synthetic_customer_registration_covers_nested_and_logical_crossings(self):
        fixture_path = Path(__file__).parents[1] / "fixtures" / "customer_registration_dfd.json"
        payload = json.loads(fixture_path.read_text(encoding="utf-8"))
        from backend.models.dfd import DfdModel
        model = DfdModel.model_validate(payload)
        recalculate_boundary_crossings(model)
        validation = validate_dfd_model(model)

        self.assertTrue(validation["valid"], validation)
        flows = {flow.id: flow for flow in model.flows}
        self.assertEqual(flows["F4"].boundary_crossings, ["TB3"])
        self.assertIn("TB4", flows["F5"].boundary_crossings)
        self.assertIn("TB4", flows["F6"].boundary_crossings)
        self.assertEqual(flows["F4"].crossing_origins["TB3"], "reviewer")

        # A boundary on the common organization ancestor is not a crossing for
        # an application-to-application flow.
        model.boundaries.append(DfdBoundary(
            id="TB-COMMON",
            display_id="TB5",
            name="Organization common ancestor",
            types=["organization"],
            source_zone_ids=["zone-organization"],
            target_zone_ids=["zone-organization"],
            transition_scope="zone",
            status="confirmed",
            derived=True,
        ))
        recalculate_boundary_crossings(model)
        self.assertNotIn("TB-COMMON", flows["F4"].boundary_crossings)

    def test_unknown_membership_is_reviewable_and_not_no_crossing(self):
        from backend.models.dfd import DfdModel
        fixture_path = Path(__file__).parents[1] / "fixtures" / "customer_registration_dfd.json"
        model = DfdModel.model_validate(json.loads(fixture_path.read_text(encoding="utf-8")))
        model.nodes[1].zone_ids = []
        recalculate_boundary_crossings(model)
        validation = validate_dfd_model(model)

        self.assertEqual(next(flow for flow in model.flows if flow.id == "F4").crossing_status, "unresolved")
        self.assertTrue(any("unresolved zone membership" in warning for warning in validation["warnings"]))

    def test_reviewer_can_represent_logical_boundary_on_same_zone_flow(self):
        fixture_path = Path(__file__).parents[1] / "fixtures" / "customer_registration_dfd.json"
        model = DfdModel.model_validate(json.loads(fixture_path.read_text(encoding="utf-8")))
        boundary = next(item for item in model.boundaries if item.id == "TB3")
        boundary.transition_scope = "logical"
        flow = next(item for item in model.flows if item.id == "F4")
        flow.boundary_crossings = ["TB3"]
        flow.crossing_origins = {"TB3": "reviewer"}
        flow.crossing_rationales = {"TB3": "The notification process changes privilege context before dispatch."}
        recalculate_boundary_crossings(model)
        validation = validate_dfd_model(model)

        self.assertIn("TB3", flow.boundary_crossings)
        self.assertEqual(flow.crossing_status, "resolved")
        self.assertIn("F4", boundary.crossing_flow_ids)
        self.assertTrue(validation["valid"])
        self.assertFalse(any("requires reviewer confirmation" in warning for warning in validation["warnings"]))

    def test_human_metadata_without_evidence_is_inferred_not_documented(self):
        fixture_path = Path(__file__).parents[1] / "fixtures" / "customer_registration_dfd.json"
        model = DfdModel.model_validate(json.loads(fixture_path.read_text(encoding="utf-8")))
        data_object = next(item for item in model.data_objects if item.id == "DO5")
        data_object.recipients = ["Vendor email service"]
        data_object.legal_basis = "Documented service purpose"
        refresh_attribute_assertions(model)
        recipient_assertion = next(item for item in data_object.assertions if item.field_path == "recipients")
        legal_basis_assertion = next(item for item in data_object.assertions if item.field_path == "legal_basis")
        missing_assertion = next(item for item in data_object.assertions if item.field_path == "linkability")

        self.assertEqual(recipient_assertion.status, "inferred")
        self.assertEqual(legal_basis_assertion.status, "inferred")
        self.assertEqual(missing_assertion.status, "unknown")

    def test_feature_port_mapping_mismatch_is_blocking(self):
        fixture_path = Path(__file__).parents[1] / "fixtures" / "customer_registration_dfd.json"
        model = DfdModel.model_validate(json.loads(fixture_path.read_text(encoding="utf-8")))
        feature = next(view for view in model.views if view.kind == "feature")
        feature.input_flow_ids = ["F2"]
        feature.port_mappings["input"] = ["F2"]
        validation = validate_dfd_model(model)

        self.assertFalse(validation["valid"])
        self.assertTrue(any("input port flow F2" in error for error in validation["errors"]))

    def test_missing_canonical_evidence_reference_is_blocking(self):
        fixture_path = Path(__file__).parents[1] / "fixtures" / "customer_registration_dfd.json"
        model = DfdModel.model_validate(json.loads(fixture_path.read_text(encoding="utf-8")))
        model.flows[0].evidence_refs = ["EV-MISSING"]
        validation = validate_dfd_model(model)

        self.assertFalse(validation["valid"])
        self.assertTrue(any("missing evidence EV-MISSING" in error for error in validation["errors"]))

    def test_layout_only_save_does_not_increment_semantic_revision(self):
        from backend.models.dfd import DfdModel
        fixture_path = Path(__file__).parents[1] / "fixtures" / "customer_registration_dfd.json"
        model = DfdModel.model_validate(json.loads(fixture_path.read_text(encoding="utf-8")))
        recalculate_boundary_crossings(model)
        report = {"dfd_model": model.model_dump(), "dfd_validation": validate_dfd_model(model)}
        edited = model.model_dump()
        edited["views"][0]["positions"] = {"P1": {"x": 120, "y": 80}}

        with (
            patch("backend.routers.dfd.get_project", return_value={"project_id": "fixture-customer-registration"}),
            patch("backend.routers.dfd.get_report", return_value=report),
            patch("backend.routers.dfd.save_report"),
            patch("backend.routers.dfd.log_event"),
        ):
            response = __import__("asyncio").run(save_dfd(
                "fixture-customer-registration",
                {"model": edited, "expected_revision": 1},
            ))

        self.assertFalse(response["semantic_changed"])
        self.assertEqual(response["model"]["revision"], 1)
        self.assertEqual(response["model"]["layout_revision"], 2)

    def test_semantic_save_increments_revision_and_marks_downstream_analysis_stale(self):
        from backend.models.dfd import DfdModel
        fixture_path = Path(__file__).parents[1] / "fixtures" / "customer_registration_dfd.json"
        model = DfdModel.model_validate(json.loads(fixture_path.read_text(encoding="utf-8")))
        recalculate_boundary_crossings(model)
        report = {"dfd_model": model.model_dump(), "dfd_validation": validate_dfd_model(model)}
        edited = model.model_dump()
        edited["nodes"][1]["ownership"] = "shared"

        with (
            patch("backend.routers.dfd.get_project", return_value={"project_id": "fixture-customer-registration"}),
            patch("backend.routers.dfd.get_report", return_value=report),
            patch("backend.routers.dfd.save_report"),
            patch("backend.routers.dfd.log_event"),
        ):
            response = __import__("asyncio").run(save_dfd(
                "fixture-customer-registration",
                {"model": edited, "expected_revision": 1},
            ))

        self.assertTrue(response["semantic_changed"])
        self.assertEqual(response["model"]["revision"], 2)
        # The route mutates the same report object used by the storage mock.
        self.assertEqual(set(report["analysis_stale"]["stages"]), {
            "stride", "linddun", "controls", "tests", "missing_info", "assumptions",
        })

    def test_semantic_save_accepts_a_user_added_node(self):
        fixture_path = Path(__file__).parents[1] / "fixtures" / "customer_registration_dfd.json"
        model = DfdModel.model_validate(json.loads(fixture_path.read_text(encoding="utf-8")))
        recalculate_boundary_crossings(model)
        current = model.model_copy(deep=True)
        model.nodes.append(DfdNode(
            id="E3",
            display_id="E3",
            type="entity",
            name="Support operator",
            scope="unknown",
            ownership="organization",
            exposure="private",
            zone_ids=["zone-organization"],
        ))
        report = {"dfd_model": current.model_dump(), "dfd_validation": validate_dfd_model(current)}

        with (
            patch("backend.routers.dfd.get_project", return_value={"project_id": "fixture-customer-registration"}),
            patch("backend.routers.dfd.get_report", return_value=report),
            patch("backend.routers.dfd.save_report"),
            patch("backend.routers.dfd.log_event"),
        ):
            response = __import__("asyncio").run(save_dfd(
                "fixture-customer-registration",
                {"model": model.model_dump(), "expected_revision": current.revision},
            ))

        self.assertTrue(response["success"])
        self.assertIn("E3", {node["id"] for node in response["model"]["nodes"]})
        self.assertTrue(response["semantic_changed"])

    def test_dfd_save_rejects_revision_conflict(self):
        from backend.models.dfd import DfdModel
        fixture_path = Path(__file__).parents[1] / "fixtures" / "customer_registration_dfd.json"
        model = DfdModel.model_validate(json.loads(fixture_path.read_text(encoding="utf-8")))
        recalculate_boundary_crossings(model)
        report = {"dfd_model": model.model_dump(), "dfd_validation": validate_dfd_model(model)}

        with (
            patch("backend.routers.dfd.get_project", return_value={"project_id": "fixture-customer-registration"}),
            patch("backend.routers.dfd.get_report", return_value=report),
        ):
            with self.assertRaises(HTTPException) as raised:
                __import__("asyncio").run(save_dfd(
                    "fixture-customer-registration",
                    {"model": model.model_dump(), "expected_revision": 99},
                ))

        self.assertEqual(raised.exception.status_code, 409)

    def test_source_change_preserves_human_dfd_and_returns_regeneration_proposal(self):
        fixture_path = Path(__file__).parents[1] / "fixtures" / "customer_registration_dfd.json"
        previous = DfdModel.model_validate(json.loads(fixture_path.read_text(encoding="utf-8")))
        recalculate_boundary_crossings(previous)
        previous.nodes[0].ownership = "customer"
        previous.human_edit_revision = 1
        previous.source_semantic_hash = previous.semantic_hash

        generated = DfdModel.model_validate(previous.model_dump())
        generated.nodes[0].ownership = "unknown"
        generated.human_edit_revision = 0
        generated.source_semantic_hash = None
        recalculate_boundary_crossings(generated)

        selected, proposal, protected = reconcile_generated_dfd(
            generated,
            previous.model_dump(),
        )

        self.assertTrue(protected)
        self.assertEqual(selected.nodes[0].ownership, "customer")
        self.assertIsNotNone(proposal)
        self.assertIn("nodes", proposal["sections"])
        self.assertIn(previous.nodes[0].id, proposal["sections"]["nodes"]["changed"])

    def test_reviewed_regeneration_proposal_can_be_applied_without_resetting_layout(self):
        fixture_path = Path(__file__).parents[1] / "fixtures" / "customer_registration_dfd.json"
        current = DfdModel.model_validate(json.loads(fixture_path.read_text(encoding="utf-8")))
        recalculate_boundary_crossings(current)
        context_view = next(view for view in current.views if view.kind == "context")
        context_view.positions = {"P1": {"x": 240, "y": 180}}
        candidate = current.model_copy(deep=True)
        candidate.nodes[0].name = "Registered customer"
        recalculate_boundary_crossings(candidate)
        report = {
            "dfd_model": current.model_dump(),
            "dfd_validation": validate_dfd_model(current),
            "dfd_proposal": {"candidate_model": candidate.model_dump()},
        }

        with (
            patch("backend.routers.dfd.get_project", return_value={"project_id": "fixture-customer-registration"}),
            patch("backend.routers.dfd.get_report", return_value=report),
            patch("backend.routers.dfd.save_report"),
            patch("backend.routers.dfd.log_event"),
        ):
            response = __import__("asyncio").run(apply_dfd_regeneration_proposal(
                "fixture-customer-registration",
                {"expected_revision": current.revision, "accept_all": True},
            ))

        self.assertTrue(response["success"])
        self.assertEqual(response["model"]["nodes"][0]["name"], "Registered customer")
        self.assertEqual(response["model"]["views"][0]["positions"]["P1"], {"x": 240, "y": 180})
        self.assertIsNone(response["proposal"])
        self.assertEqual(response["model"]["revision"], current.revision + 1)
        self.assertTrue(report["analysis_stale"]["stages"])

    def test_regeneration_proposal_can_be_dismissed_without_mutating_model(self):
        fixture_path = Path(__file__).parents[1] / "fixtures" / "customer_registration_dfd.json"
        current = DfdModel.model_validate(json.loads(fixture_path.read_text(encoding="utf-8")))
        recalculate_boundary_crossings(current)
        candidate = current.model_copy(deep=True)
        candidate.nodes[0].name = "Candidate renamed customer"
        recalculate_boundary_crossings(candidate)
        report = {
            "dfd_model": current.model_dump(),
            "dfd_validation": validate_dfd_model(current),
            "dfd_proposal": {
                "base_revision": current.revision,
                "candidate_revision": candidate.revision,
                "sections": {"nodes": {"changed": ["E1"], "added": [], "removed": []}},
                "candidate_model": candidate.model_dump(),
            },
            "analysis_stale": {
                "stages": ["stride"],
                "reason": "Source context changed while a human-edited DFD exists. Review the regeneration proposal before applying it.",
            },
        }

        with (
            patch("backend.routers.dfd.get_project", return_value={"project_id": "fixture-customer-registration"}),
            patch("backend.routers.dfd.get_report", return_value=report),
            patch("backend.routers.dfd.save_report"),
            patch("backend.routers.dfd.log_event"),
        ):
            response = __import__("asyncio").run(resolve_dfd_regeneration_proposal(
                "fixture-customer-registration",
                {"expected_revision": current.revision, "action": "dismiss"},
            ))

        self.assertTrue(response["success"])
        self.assertEqual(response["resolution"]["resolution"], "dismissed")
        self.assertIsNone(report.get("dfd_proposal"))
        self.assertNotIn("analysis_stale", report)
        self.assertEqual(report["dfd_model"]["nodes"][0]["name"], current.nodes[0].name)

    def test_svg_export_is_escaped_and_contains_canonical_elements(self):
        from backend.models.dfd import DfdModel
        fixture_path = Path(__file__).parents[1] / "fixtures" / "customer_registration_dfd.json"
        model = DfdModel.model_validate(json.loads(fixture_path.read_text(encoding="utf-8")))
        recalculate_boundary_crossings(model)
        report = {"dfd_model": model.model_dump(), "dfd_validation": validate_dfd_model(model)}

        with (
            patch("backend.routers.dfd.get_project", return_value={"project_id": "fixture-customer-registration"}),
            patch("backend.routers.dfd.get_report", return_value=report),
        ):
            response = __import__("asyncio").run(export_dfd("fixture-customer-registration", "svg"))

        content = response.body.decode("utf-8")
        self.assertEqual(response.media_type, "image/svg+xml")
        self.assertIn("F1", content)
        self.assertIn("P1 Memproses registrasi", content)
        self.assertIn("Z2 · Organization", content)
        self.assertIn("Z5 · Vendor", content)
        self.assertIn("stroke-dasharray=\"8 6\"", content)
        self.assertNotIn("<script", content.lower())

    def test_svg_export_hydrates_legacy_evidence_refs(self):
        fixture_path = Path(__file__).parents[1] / "fixtures" / "customer_registration_dfd.json"
        model = DfdModel.model_validate(json.loads(fixture_path.read_text(encoding="utf-8")))
        model.evidence = []
        report = {"dfd_model": model.model_dump()}

        with (
            patch("backend.routers.dfd.get_project", return_value={"project_id": "fixture-customer-registration"}),
            patch("backend.routers.dfd.get_report", return_value=report),
        ):
            response = __import__("asyncio").run(export_dfd("fixture-customer-registration", "svg"))

        self.assertEqual(response.status_code, 200)
        self.assertIn("Z2 · Organization", response.body.decode("utf-8"))

    def test_json_export_and_import_round_trip_preserve_canonical_contract(self):
        fixture_path = Path(__file__).parents[1] / "fixtures" / "customer_registration_dfd.json"
        model = DfdModel.model_validate(json.loads(fixture_path.read_text(encoding="utf-8")))
        recalculate_boundary_crossings(model)
        report = {"dfd_model": model.model_dump(), "dfd_validation": validate_dfd_model(model)}

        with (
            patch("backend.routers.dfd.get_project", return_value={"project_id": "fixture-customer-registration"}),
            patch("backend.routers.dfd.get_report", return_value=report),
            patch("backend.routers.dfd.save_report"),
            patch("backend.routers.dfd.log_event"),
        ):
            exported = __import__("asyncio").run(export_dfd("fixture-customer-registration", "json"))
            exported_model = json.loads(exported.body)
            self.assertEqual(exported_model["schema_version"], "dfd-v1")
            exported_model["nodes"][0]["description"] = "Reviewed in JSON round trip"
            imported = __import__("asyncio").run(import_dfd(
                "fixture-customer-registration",
                {"model": exported_model, "expected_revision": model.revision},
            ))

        self.assertTrue(imported["success"])
        self.assertEqual(imported["model"]["nodes"][0]["description"], "Reviewed in JSON round trip")
        self.assertEqual(imported["model"]["schema_version"], "dfd-v1")

    def test_delete_impact_preview_surfaces_semantic_dependents(self):
        fixture_path = Path(__file__).parents[1] / "fixtures" / "customer_registration_dfd.json"
        model = DfdModel.model_validate(json.loads(fixture_path.read_text(encoding="utf-8")))
        recalculate_boundary_crossings(model)
        threats = [{
            "threat_id": "threat-node-p1",
            "target_refs": [{"type": "process", "id": "P1"}],
        }]

        node_impact = preview_dfd_delete_impact(model, "node", "P1", threats)
        self.assertFalse(node_impact["safe_to_delete"])
        self.assertIn("F1", node_impact["dependent_flows"])
        self.assertIn("view-system", node_impact["dependent_views"])
        self.assertIn("threat-node-p1", node_impact["dependent_threats"])

        zone_impact = preview_dfd_delete_impact(model, "zone", "zone-organization", threats)
        self.assertFalse(zone_impact["safe_to_delete"])
        self.assertEqual(set(zone_impact["dependent_nodes"]), {"P1", "P2", "D1"})
        self.assertIn("zone-restricted-data", zone_impact["dependent_zones"])


if __name__ == "__main__":
    unittest.main()
