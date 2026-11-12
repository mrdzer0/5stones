import asyncio
import hashlib
import io
import json
import unittest
from unittest.mock import AsyncMock, patch

from fastapi import UploadFile

from backend.routers.artifacts import upload_artifact
from backend.routers.export import _apply_visibility_filter, _to_markdown, _to_csv, export_report
from backend.models.schemas import ArtifactUpload
from backend.services.artifact_file_service import read_validated_artifact_file
from backend.services.parser_service import PARSER_VERSION, parse_artifact
from backend.services.artifact_reconciliation_service import project_client_view


class RI3IntegrationTests(unittest.TestCase):
    def test_text_cap_is_partial_with_exact_unread_locator(self):
        content = "# Policy\nThe application retains audit records for thirty days.\n" + "x" * 120000
        file = UploadFile(filename="policy.md", file=io.BytesIO(content.encode()))
        extracted = asyncio.run(read_validated_artifact_file("markdown", file))
        changed_tail = content[:-1] + "y"
        alternate = asyncio.run(read_validated_artifact_file("markdown", UploadFile(
            filename="policy.md", file=io.BytesIO(changed_tail.encode()))))
        self.assertEqual(alternate["content"], extracted["content"])
        self.assertNotEqual(alternate["source_hash"], extracted["source_hash"])
        self.assertTrue(extracted["truncated"])
        self.assertEqual(extracted["source_hash"], hashlib.sha256(content.encode()).hexdigest())
        self.assertEqual(extracted["extraction_omissions"][0]["locator"],
                         f"characters 120001-{len(content)}")

        async def provider(**kwargs):
            return {"evidence_items": [{"snippet": "The application retains audit records for thirty days."}]}

        with patch("backend.services.parser_service.get_active_provider_config", return_value={}), \
             patch("backend.services.parser_service.chat_complete_json", new=AsyncMock(side_effect=provider)):
            parsed = asyncio.run(parse_artifact("markdown", extracted["content"],
                source_truncated=extracted["truncated"], truncated_chars=extracted["truncated_chars"],
                extraction_omissions=extracted["extraction_omissions"]))
        coverage = parsed["coverage_manifest"]
        self.assertEqual(coverage["status"], "partial")
        self.assertIn(extracted["extraction_omissions"][0]["locator"],
                      [item["locator"] for item in coverage["unread_sections"]])

    def test_docx_table_limit_has_structured_omission(self):
        from docx import Document
        document = Document()
        document.add_paragraph("The service stores audit events.")
        for number in range(21):
            table = document.add_table(rows=1, cols=1)
            table.cell(0, 0).text = f"Table {number + 1}"
        buffer = io.BytesIO()
        document.save(buffer)
        file = UploadFile(filename="requirements.docx", file=io.BytesIO(buffer.getvalue()))
        extracted = asyncio.run(read_validated_artifact_file("prd", file))
        self.assertEqual(extracted["extraction_omissions"][0]["locator"], "tables 21-21")
        self.assertTrue(extracted["truncated"])

    def test_pdf_page_limit_has_structured_omission(self):
        class Page:
            def extract_text(self):
                return "The application stores audit records."

        class Reader:
            is_encrypted = False
            pages = [Page() for _ in range(81)]

        file = UploadFile(filename="requirements.pdf", file=io.BytesIO(b"fixture-pdf"))
        with patch("pypdf.PdfReader", return_value=Reader()):
            extracted = asyncio.run(read_validated_artifact_file("prd", file))
        self.assertEqual(extracted["extraction_omissions"][0]["locator"], "pages 81-81")
        self.assertTrue(extracted["truncated"])

    def test_har_tail_is_not_silently_removed_before_character_cap(self):
        content = json.dumps({"entries": [{"id": number} for number in range(510)]})
        file = UploadFile(filename="traffic.har", file=io.BytesIO(content.encode()))
        extracted = asyncio.run(read_validated_artifact_file("har", file))
        self.assertIn('"id": 509', extracted["content"])
        self.assertFalse(extracted["truncated"])

    def test_structured_api_gets_complete_deterministic_manifest(self):
        content = json.dumps({"openapi": "3.0.0", "info": {"title": "Example", "version": "1"},
                              "paths": {"/health": {"get": {"responses": {"200": {"description": "OK"}}}}}})
        parsed = asyncio.run(parse_artifact("openapi", content))
        self.assertEqual(parsed["coverage_manifest"]["status"], "complete")
        self.assertEqual(parsed["coverage_manifest"]["processed_chunk_count"], 1)

    def test_resume_only_verified_matching_chunks(self):
        content = "# One\nThe gateway validates customer access tokens.\n# Two\nThe audit store retains events for thirty days.\n"
        calls = []

        async def provider(**kwargs):
            calls.append(kwargs["user_prompt"])
            if "SOURCE LOCATOR: One" in kwargs["user_prompt"]:
                return {"evidence_items": [{"snippet": "The gateway validates customer access tokens."}]}
            return {}

        with patch("backend.services.parser_service.get_active_provider_config", return_value={}), \
             patch("backend.services.parser_service.chat_complete_json", new=AsyncMock(side_effect=provider)):
            first = asyncio.run(parse_artifact("markdown", content, max_ai_chunks=1))
            second = asyncio.run(parse_artifact("markdown", content, max_ai_chunks=1,
                resume_chunks=first["coverage_manifest"]["checkpoints"]))
        self.assertEqual(len(calls), 2)
        self.assertEqual(second["coverage_manifest"]["processed_chunk_count"], 1)
        self.assertEqual(second["coverage_manifest"]["empty_chunk_count"], 1)

    def test_legacy_missing_manifest_reparses_with_distinct_revision_id(self):
        content = "# Policy\nThe service stores audit events."
        digest = hashlib.sha256(content.encode()).hexdigest()
        previous = {"artifact_id": f"artifact-{digest[:16]}", "artifact_type": "markdown",
                    "filename": "policy.md", "content_hash": digest, "revision": 1,
                    "active": True, "parser": {"version": PARSER_VERSION}, "contribution": {}}
        project = {"id": "fixture", "name": "Fixture", "artifact_sources": [previous]}
        parsed = {"parser": {"version": PARSER_VERSION}, "coverage_manifest": {"status": "complete"},
                  "evidence_items": [], "warnings": [], "stats": {}}
        with patch("backend.routers.artifacts.get_authorized_project", return_value=project), \
             patch("backend.routers.artifacts.parse_artifact", new=AsyncMock(return_value=parsed)) as parser, \
             patch("backend.routers.artifacts.capture_manual_context"), \
             patch("backend.routers.artifacts.rebuild_project_from_artifacts"), \
             patch("backend.routers.artifacts.compute_completeness", return_value={"score": 0, "level": "Low"}), \
             patch("backend.routers.artifacts.project_client_view", return_value={}), \
             patch("backend.routers.artifacts.save_project"):
            result = asyncio.run(upload_artifact("fixture", ArtifactUpload(
                artifact_type="markdown", filename="policy.md", content=content)))
        parser.assert_awaited_once()
        self.assertFalse(result["duplicate"])
        self.assertFalse(previous["active"])
        self.assertEqual(project["artifact_sources"][-1]["revision"], 2)
        self.assertNotEqual(project["artifact_sources"][-1]["artifact_id"], previous["artifact_id"])

    def test_resume_checkpoint_stays_internal_to_project_storage(self):
        checkpoint = {"chunk-001": {"result": {"evidence_items": [{"snippet": "private working copy"}]}}}
        project = {"artifact_sources": [{"coverage_manifest": {"status": "partial", "checkpoints": checkpoint}}]}
        view = project_client_view(project)
        self.assertNotIn("checkpoints", view["artifact_sources"][0]["coverage_manifest"])
        self.assertIn("checkpoints", project["artifact_sources"][0]["coverage_manifest"])

    def test_export_projection_keeps_same_zone_and_recounts_summary(self):
        report = {"trust_boundaries": [{"boundary_id": "b", "source": "API", "destination": "DB",
                                        "boundary_label": "Internal", "status": "Rejected"}],
                  "threats": [
                      {"threat_id": "same", "framework": "STRIDE", "risk_level": "High",
                       "source": "API", "destination": "DB", "trust_boundary": "Internal"},
                      {"threat_id": "cross", "framework": "LINDDUN", "risk_level": "Critical",
                       "trust_boundary_ids": ["b"]}],
                  "controls": [{"name": "same control", "threat_ids": ["same"]}],
                  "test_scenarios": [{"test_id": "same test", "threat_id": "same"}],
                  "missing_info": [{"area": "Deployment"}],
                  "risk_summary": {"total": 2, "critical": 1, "high": 1}}
        visible = _apply_visibility_filter(report)
        self.assertEqual([item["threat_id"] for item in visible["threats"]], ["same"])
        self.assertEqual(visible["risk_summary"]["total"], 1)
        self.assertEqual(visible["risk_summary"]["critical"], 0)
        self.assertEqual(len(visible["missing_info"]), 1)
        self.assertIn("| Total | 1 |", _to_markdown({"name": "Fixture"}, visible))
        self.assertIn("STRIDE", _to_csv(visible))
        self.assertNotIn("LINDDUN", _to_csv(visible))
        with patch("backend.routers.export.get_authorized_project", return_value={"name": "Fixture"}), \
             patch("backend.routers.export.get_report", return_value=report), \
             patch("backend.routers.export.normalize_report_evidence", side_effect=lambda value, _: value):
            default_json = asyncio.run(export_report("fixture", format="json"))
            raw_json = asyncio.run(export_report("fixture", format="json", scope="all"))
        self.assertEqual(default_json["risk_summary"]["total"], 1)
        self.assertEqual(raw_json["risk_summary"]["total"], 2)
