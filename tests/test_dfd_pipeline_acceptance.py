import asyncio
import copy
import unittest
from unittest.mock import AsyncMock, patch

from backend.services.threat_validation_service import ThreatGenerationResult
from backend.services.trust_boundary_service import build_trust_model
from backend.services.dfd_model_service import build_dfd_model
from backend.routers.analysis import run_full_analysis


class DfdPipelineAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.project = {
            "project_id": "acceptance-registration",
            "name": "Acceptance registration",
            "description": "Customer registration and notification.",
            "actors": ["Customer"],
            "components": ["Registration process", "Notification process", "Customer database"],
            "entry_points": ["Registration UI"],
            "data_involved": ["email", "activation token"],
            "external_systems": ["Vendor email"],
            "critical_actions": ["register customer"],
            "existing_controls": [],
            "auth_method": "unknown",
            "artifact_sources": [{"artifact_id": "artifact-registration", "filename": "registration.md", "artifact_type": "prd", "active": True}],
            "manual_context": {
                "actors": ["Customer"],
                "components": ["Registration process", "Notification process", "Customer database"],
                "entry_points": ["Registration UI"],
                "external_systems": ["Vendor email"],
            },
            "extracted_data_flows": [
                {"flow_id": "flow-register", "source": "Customer", "destination": "Registration process", "source_entity_type": "actor", "destination_entity_type": "component", "protocol": "HTTPS", "data": ["email"], "evidence_refs": ["artifact:artifact-registration"], "evidence_type": "direct"},
                {"flow_id": "flow-store", "source": "Registration process", "destination": "Customer database", "source_entity_type": "component", "destination_entity_type": "data_store", "protocol": "SQL", "data": ["customer record"], "evidence_refs": ["artifact:artifact-registration"], "evidence_type": "direct"},
                {"flow_id": "flow-notify", "source": "Notification process", "destination": "Vendor email", "source_entity_type": "component", "destination_entity_type": "external_system", "protocol": "HTTPS", "data": ["activation message"], "evidence_refs": ["artifact:artifact-registration"], "evidence_type": "direct"},
            ],
        }

    def test_generate_persist_analyze_and_retain_unknowns(self):
        trust_model = build_trust_model(self.project)
        model = build_dfd_model(self.project, trust_model)
        flow_id = model.flows[0].id
        node_id = model.flows[0].target_id
        stride = ThreatGenerationResult([{
            "threat_id": "T-STRIDE-1",
            "framework": "STRIDE",
            "threat_category": "Tampering",
            "threat_description": "Registration input can be altered before validation.",
            "affected_refs": [flow_id, node_id],
            "status": "Open",
            "confidence": "Medium",
        }], [{"element_ref": flow_id, "category": "Tampering", "status": "candidate_identified", "reason": "Input flow reviewed."}])
        linddun = ThreatGenerationResult([{
            "threat_id": "T-LINDDUN-1",
            "framework": "LINDDUN",
            "threat_category": "Data Disclosure",
            "threat_description": "Activation data may be shared beyond the intended recipient.",
            "affected_refs": [flow_id],
            "status": "Open",
            "confidence": "Low",
        }], [])
        saved_reports = []
        saved_projects = []

        async def assumptions(project, threats):
            return []

        with (
            patch("backend.routers.analysis.get_project", return_value=copy.deepcopy(self.project)),
            patch("backend.routers.analysis.get_report", return_value=None),
            patch("backend.routers.analysis.save_report", side_effect=lambda project_id, report: saved_reports.append(copy.deepcopy(report))),
            patch("backend.routers.analysis.save_project", side_effect=lambda project: saved_projects.append(copy.deepcopy(project))),
            patch("backend.routers.analysis.generate_stride_threats", new=AsyncMock(return_value=stride)),
            patch("backend.routers.analysis.generate_linddun_threats", new=AsyncMock(return_value=linddun)),
            patch("backend.routers.analysis.map_controls", new=AsyncMock(return_value=[])),
            patch("backend.routers.analysis.generate_test_scenarios", new=AsyncMock(return_value=[])),
            patch("backend.routers.analysis.generate_missing_info", new=AsyncMock(return_value=[])),
            patch("backend.routers.analysis.generate_assumptions", new=assumptions),
        ):
            result = asyncio.run(run_full_analysis(self.project["project_id"], {
                "analysis_types": ["trust_boundary", "stride", "linddun", "controls", "tests", "missing_info", "assumptions"],
            }))

        self.assertEqual(result["analysis_run"]["status"], "completed")
        self.assertTrue(result["dfd_model"]["nodes"])
        self.assertTrue(result["dfd_validation"]["valid"])
        self.assertIn("privacy_assessment", result)
        self.assertTrue(result["privacy_assessment"]["unresolved_count"])
        self.assertTrue(result["analysis_coverage"]["STRIDE"])
        self.assertTrue(result["analysis_coverage"]["LINDDUN"])
        self.assertTrue(any(item.get("framework") == "STRIDE" for item in result["threats"]))
        linddun_result = next(item for item in result["threats"] if item.get("framework") == "LINDDUN")
        self.assertEqual(linddun_result["status"], "Needs Info")
        self.assertTrue(linddun_result["target_refs"])
        self.assertGreaterEqual(len(saved_reports), 2)  # running state and completed state
        self.assertEqual(saved_reports[-1]["analysis_run"]["status"], "completed")
        self.assertEqual(saved_projects[-1]["analysis_status"], "completed")


if __name__ == "__main__":
    unittest.main()
