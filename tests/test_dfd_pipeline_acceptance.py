import asyncio
import copy
import unittest
from unittest.mock import AsyncMock, patch

from backend.services.threat_validation_service import ThreatGenerationResult
from backend.services.threat_validation_service import ThreatGenerationContractError
from backend.services.threat_batch_service import ThreatGenerationProviderError
from backend.services.trust_boundary_service import build_trust_model
from backend.services.dfd_model_service import build_dfd_model
from backend.services.ai_service import AnalysisResponseError
from backend.routers.analysis import _run_analysis_pipeline, run_full_analysis


class DfdPipelineAcceptanceTests(unittest.TestCase):
    @staticmethod
    def _capture_atomic_save(saved_reports):
        def save(_project_id, report, dfd_model, *, expected_report_revision, **_kwargs):
            report["report_revision"] = expected_report_revision + 1
            saved_reports.append(copy.deepcopy(report))
            return report, dfd_model
        return save

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
            patch("backend.routers.analysis.get_dfd_model", return_value=None),
            patch("backend.routers.analysis.save_report", side_effect=lambda project_id, report: saved_reports.append(copy.deepcopy(report))),
            patch("backend.routers.analysis.save_report_and_dfd", side_effect=self._capture_atomic_save(saved_reports)),
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

        self.assertEqual(result["analysis_run"]["status"], "completed_with_warnings")
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
        self.assertEqual(saved_reports[-1]["analysis_run"]["status"], "completed_with_warnings")
        self.assertEqual(saved_projects[-1]["analysis_status"], "completed_with_warnings")

    def test_valid_empty_assessment_is_persisted_without_fallback(self):
        empty_stride = ThreatGenerationResult([], [])
        empty_linddun = ThreatGenerationResult([], [])
        saved_reports = []
        saved_projects = []

        async def assumptions(project, threats):
            return []

        with (
            patch("backend.routers.analysis.get_project", return_value=copy.deepcopy(self.project)),
            patch("backend.routers.analysis.get_report", return_value=None),
            patch("backend.routers.analysis.get_dfd_model", return_value=None),
            patch("backend.routers.analysis.save_report", side_effect=lambda project_id, report: saved_reports.append(copy.deepcopy(report))),
            patch("backend.routers.analysis.save_report_and_dfd", side_effect=self._capture_atomic_save(saved_reports)),
            patch("backend.routers.analysis.save_project", side_effect=lambda project: saved_projects.append(copy.deepcopy(project))),
            patch("backend.routers.analysis.generate_stride_threats", new=AsyncMock(return_value=empty_stride)),
            patch("backend.routers.analysis.generate_linddun_threats", new=AsyncMock(return_value=empty_linddun)),
            patch("backend.routers.analysis.generate_assumptions", new=assumptions),
        ):
            result = asyncio.run(run_full_analysis(self.project["project_id"], {
                "analysis_types": ["trust_boundary", "stride", "linddun", "assumptions"],
            }))

        self.assertEqual(result["analysis_run"]["status"], "completed_with_warnings")
        self.assertTrue(result["analysis_run"]["review_required"])
        self.assertFalse(result["analysis_run"]["quality_gate"]["signoff_ready"])
        self.assertFalse(result["analysis_run"]["retryable"])
        self.assertTrue(result["ai_status"]["stride"]["ok"])
        self.assertEqual(result["ai_status"]["stride"]["assessment_status"], "valid_empty")
        self.assertTrue(result["ai_status"]["linddun"]["ok"])
        self.assertEqual(result["ai_status"]["linddun"]["assessment_status"], "valid_empty")
        self.assertEqual(result["threats"], [])
        self.assertFalse(any(item.get("is_fallback") for item in result["threats"]))

    def test_provider_contract_failure_is_invalid_not_fallback_for_both_frameworks(self):
        saved_reports = []
        saved_projects = []

        async def assumptions(project, threats):
            return []

        with (
            patch("backend.routers.analysis.get_project", return_value=copy.deepcopy(self.project)),
            patch("backend.routers.analysis.get_report", return_value=None),
            patch("backend.routers.analysis.get_dfd_model", return_value=None),
            patch("backend.routers.analysis.save_report", side_effect=lambda project_id, report: saved_reports.append(copy.deepcopy(report))),
            patch("backend.routers.analysis.save_report_and_dfd", side_effect=self._capture_atomic_save(saved_reports)),
            patch("backend.routers.analysis.save_project", side_effect=lambda project: saved_projects.append(copy.deepcopy(project))),
            patch(
                "backend.routers.analysis.generate_stride_threats",
                new=AsyncMock(side_effect=AnalysisResponseError("Analysis engine returned unstructured response")),
            ),
            patch(
                "backend.routers.analysis.generate_linddun_threats",
                new=AsyncMock(side_effect=ThreatGenerationContractError("LINDDUN response must contain a threats array")),
            ),
            patch("backend.routers.analysis.generate_assumptions", new=assumptions),
        ):
            result = asyncio.run(run_full_analysis(self.project["project_id"], {
                "analysis_types": ["trust_boundary", "stride", "linddun", "assumptions"],
            }))

        self.assertEqual(result["analysis_run"]["status"], "completed_with_warnings")
        for framework in ("stride", "linddun"):
            self.assertFalse(result["ai_status"][framework]["ok"])
            self.assertEqual(result["ai_status"][framework]["engine"], "AI")
            self.assertEqual(result["ai_status"][framework]["assessment_status"], "invalid")
            self.assertNotEqual(result["ai_status"][framework]["engine"], "fallback")
        self.assertEqual(result["threats"], [])
        self.assertTrue(any(
            "provider_contract_invalid" in item.get("reasons", [])
            for item in result["analysis_quarantine"]
        ))

    def test_provider_outage_fallback_is_visible_but_never_validated_or_signoff_ready(self):
        saved_reports = []
        saved_projects = []
        fallback_result = ThreatGenerationResult(
            [], [], assessment_status="fallback", warnings=["provider unavailable"]
        )
        empty_linddun = ThreatGenerationResult([], [], assessment_status="valid_empty")

        async def stride(_project, _boundaries, *, force_fallback=False, **_kwargs):
            if force_fallback:
                return fallback_result
            raise ThreatGenerationProviderError(
                "Synthetic provider outage",
                code="provider_unavailable",
                metadata={"generation_manifest": {"deferred_refs": ["flow-register"]}},
            )

        async def assumptions(project, threats):
            return []

        with (
            patch("backend.routers.analysis.get_project", return_value=copy.deepcopy(self.project)),
            patch("backend.routers.analysis.get_report", return_value=None),
            patch("backend.routers.analysis.get_dfd_model", return_value=None),
            patch("backend.routers.analysis.save_report", side_effect=lambda project_id, report: saved_reports.append(copy.deepcopy(report))),
            patch("backend.routers.analysis.save_report_and_dfd", side_effect=self._capture_atomic_save(saved_reports)),
            patch("backend.routers.analysis.save_project", side_effect=lambda project: saved_projects.append(copy.deepcopy(project))),
            patch("backend.routers.analysis.generate_stride_threats", new=AsyncMock(side_effect=stride)),
            patch("backend.routers.analysis.generate_linddun_threats", new=AsyncMock(return_value=empty_linddun)),
            patch("backend.routers.analysis.generate_assumptions", new=assumptions),
        ):
            result = asyncio.run(run_full_analysis(self.project["project_id"], {
                "analysis_types": ["trust_boundary", "stride", "linddun", "assumptions"],
            }))

        self.assertEqual(result["analysis_run"]["status"], "completed_with_warnings")
        self.assertEqual(result["ai_status"]["stride"]["engine"], "fallback")
        self.assertEqual(result["ai_status"]["stride"]["assessment_status"], "fallback")
        self.assertFalse(result["ai_status"]["stride"]["ok"])
        self.assertFalse(result["analysis_run"]["quality_gate"]["signoff_ready"])
        self.assertEqual(result["threats"], [])
        self.assertFalse(any(item.get("is_fallback") for item in result["threats"]))

    def test_malformed_candidate_is_quarantined_and_not_sent_downstream(self):
        malformed = ThreatGenerationResult([{
            "threat_id": "malformed-stride",
            "framework": "STRIDE",
            "threat_category": "Tampering",
            "threat_description": "The provider referenced a non-canonical element.",
            "affected_refs": ["not-a-dfd-id"],
        }], [])
        empty_linddun = ThreatGenerationResult([], [])
        saved_reports = []
        saved_projects = []

        async def assumptions(project, threats):
            return []

        with (
            patch("backend.routers.analysis.get_project", return_value=copy.deepcopy(self.project)),
            patch("backend.routers.analysis.get_report", return_value=None),
            patch("backend.routers.analysis.get_dfd_model", return_value=None),
            patch("backend.routers.analysis.save_report", side_effect=lambda project_id, report: saved_reports.append(copy.deepcopy(report))),
            patch("backend.routers.analysis.save_report_and_dfd", side_effect=self._capture_atomic_save(saved_reports)),
            patch("backend.routers.analysis.save_project", side_effect=lambda project: saved_projects.append(copy.deepcopy(project))),
            patch("backend.routers.analysis.generate_stride_threats", new=AsyncMock(return_value=malformed)),
            patch("backend.routers.analysis.generate_linddun_threats", new=AsyncMock(return_value=empty_linddun)),
            patch("backend.routers.analysis.generate_assumptions", new=assumptions),
        ):
            result = asyncio.run(run_full_analysis(self.project["project_id"], {
                "analysis_types": ["trust_boundary", "stride", "linddun", "assumptions"],
            }))

        self.assertEqual(result["analysis_run"]["status"], "completed_with_warnings")
        self.assertFalse(result["ai_status"]["stride"]["ok"])
        self.assertEqual(result["ai_status"]["stride"]["assessment_status"], "invalid")
        self.assertEqual(result["threats"], [])
        self.assertTrue(any("invalid_generated_output" in item.get("reasons", []) for item in result["analysis_quarantine"]))

    def test_legacy_stride_is_quarantined_and_reviewed_linddun_survives_fallback(self):
        trust_model = build_trust_model(self.project)
        model = build_dfd_model(self.project, trust_model)
        flow_id = model.flows[0].id
        prior_report = {
            "project_id": self.project["project_id"],
            "dfd_model": model.model_dump(),
            "trust_boundaries": trust_model["boundaries"],
            "trust_model": trust_model,
            "threats": [
                {
                    "threat_id": "legacy-stride",
                    "framework": "STRIDE",
                    "threat_category": "Tampering",
                    "threat_description": "Old unpinned finding.",
                    "affected_refs": [flow_id],
                },
                {
                    "threat_id": "reviewed-linddun",
                    "framework": "LINDDUN",
                    "threat_category": "Data Disclosure",
                    "threat_description": "Reviewed privacy finding must remain visible.",
                    "affected_refs": [flow_id],
                    "analysis_revision": model.revision,
                    "analyzed_revision": model.revision,
                    "taxonomy_version": "linddun-v1",
                    "dfd_semantic_hash": model.semantic_hash,
                    "status": "Reviewed",
                    "review_notes": "Privacy review decision is authoritative until a valid replacement exists.",
                    "reviewed_at": "2026-09-19T00:00:00Z",
                },
            ],
        }
        fallback_stride = ThreatGenerationResult([], [], assessment_status="fallback", warnings=["provider unavailable"])
        fallback_linddun = ThreatGenerationResult([], [], assessment_status="fallback", warnings=["provider unavailable"])
        saved_reports = []
        saved_projects = []

        with (
            patch("backend.routers.analysis.get_project", return_value=copy.deepcopy(self.project)),
            patch("backend.routers.analysis.get_report", return_value=copy.deepcopy(prior_report)),
            patch("backend.routers.analysis.get_dfd_model", return_value=None),
            patch("backend.routers.analysis.save_report", side_effect=lambda project_id, report: saved_reports.append(copy.deepcopy(report))),
            patch("backend.routers.analysis.save_report_and_dfd", side_effect=self._capture_atomic_save(saved_reports)),
            patch("backend.routers.analysis.save_project", side_effect=lambda project: saved_projects.append(copy.deepcopy(project))),
            patch("backend.routers.analysis.generate_stride_threats", new=AsyncMock(return_value=fallback_stride)),
            patch("backend.routers.analysis.generate_linddun_threats", new=AsyncMock(return_value=fallback_linddun)),
        ):
            result = asyncio.run(_run_analysis_pipeline(self.project["project_id"], {
                "analysis_types": ["stride", "linddun"],
            }))

        active_ids = {item.get("threat_id") for item in result["threats"]}
        self.assertNotIn("legacy-stride", active_ids)
        self.assertIn("reviewed-linddun", active_ids)
        preserved = next(item for item in result["threats"] if item.get("threat_id") == "reviewed-linddun")
        self.assertEqual(preserved["status"], "Reviewed")
        self.assertTrue(any(
            item.get("item", {}).get("threat_id") == "legacy-stride"
            and "missing_or_unsupported_taxonomy_version" in item.get("reasons", [])
            for item in result["analysis_quarantine"]
        ))
        self.assertTrue(any(
            item.get("framework") == "LINDDUN"
            and "fallback_result_preserved_prior_snapshot" in item.get("reasons", [])
            for item in result["analysis_quarantine"]
        ))


if __name__ == "__main__":
    unittest.main()
