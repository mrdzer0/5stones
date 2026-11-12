import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from backend.routers.artifacts import _verified_evidence_items
from backend.services.parser_service import (
    _document_chunks,
    parse_artifact,
    PARSER_VERSION,
    MAX_AI_CHUNKS_PER_RUN,
)


class IngestionCoverageTests(unittest.TestCase):
    def test_chunk_ranges_cover_the_document_and_reach_tail_after_8000(self):
        content = ("Introductory architecture notes.\n" + ("x" * 8100) +
                   "\n# Tail requirement\nThe retention decision is seven days.")

        chunks = _document_chunks(content)

        self.assertGreater(len(content), 8000)
        self.assertEqual(chunks[0]["start_char"], 0)
        self.assertEqual(chunks[-1]["end_char"], len(content))
        self.assertTrue(all(
            left["end_char"] == right["start_char"]
            for left, right in zip(chunks, chunks[1:])
        ))
        self.assertIn("Tail requirement", chunks[-1]["content"])

    def test_heading_only_sections_are_structural_and_do_not_create_unread_gaps(self):
        content = "# Overview\nThe application has a documented request flow.\n\n## User journeys\n\n## Data flow\nThe browser sends a request to the API over HTTPS.\n"

        async def provider(**kwargs):
            chunk = str(kwargs["user_prompt"]).split("ARTIFACT CONTENT CHUNK:", 1)[-1]
            snippet = next((line.strip() for line in chunk.splitlines() if len(line.strip()) >= 20), "")
            return {
                "summary": "Section extracted.",
                "evidence_items": [{
                    "snippet": snippet,
                    "locator": "Data flow",
                    "topics": ["flow"],
                }] if snippet else [],
            }

        with patch("backend.services.parser_service.get_active_provider_config", return_value={}), \
             patch("backend.services.parser_service.chat_complete_json", new=AsyncMock(side_effect=provider)):
            result = asyncio.run(parse_artifact("markdown", content))

        coverage = result["coverage_manifest"]
        structural = [item for item in coverage["chunks"] if item.get("structural_only")]
        self.assertEqual(len(structural), 1)
        self.assertEqual(structural[0]["status"], "processed_deterministic")
        self.assertEqual(coverage["processed_chunk_count"], coverage["chunk_count"])
        self.assertEqual(coverage["unread_sections"], [])
        self.assertEqual(coverage["status"], "complete")

    def test_generic_parser_extracts_tail_chunk_instead_of_prefix_only(self):
        tail = "Tail requirement: retention is seven days and deletion is audited."
        content = "# Overview\n" + ("background architecture notes.\n" * 500) + f"\n# Tail\n{tail}\n"
        self.assertGreater(len(content), 8000)

        async def provider(**kwargs):
            if tail in kwargs["user_prompt"]:
                return {
                    "summary": "Tail section extracted.",
                    "evidence_items": [{
                        "snippet": tail,
                        "locator": "Tail requirement",
                        "topics": ["retention"],
                    }],
                }
            return {"summary": "Earlier section extracted.", "evidence_items": []}

        with patch("backend.services.parser_service.get_active_provider_config", return_value={}), \
             patch("backend.services.parser_service.chat_complete_json", new=AsyncMock(side_effect=provider)):
            result = asyncio.run(parse_artifact("markdown", content))

        self.assertTrue(any(item["snippet"] == tail for item in result["evidence_items"]))
        coverage = result["coverage_manifest"]
        self.assertIn(coverage["status"], ("complete", "partial"))
        self.assertGreaterEqual(coverage["chunk_count"], 2)

    def test_unread_tail_is_explicit_when_ai_and_deterministic_extraction_have_no_signal(self):
        content = "# Overview\n" + ("background architecture notes.\n" * 500) + (
            "\n# Tail\nImportant business decision: archive after seven days.\n"
        )

        async def unavailable(**kwargs):
            raise RuntimeError("provider unavailable")

        with patch("backend.services.parser_service.get_active_provider_config", return_value={}), \
             patch("backend.services.parser_service.chat_complete_json", new=AsyncMock(side_effect=unavailable)):
            result = asyncio.run(parse_artifact("markdown", content))

        coverage = result["coverage_manifest"]
        self.assertEqual(coverage["status"], "deferred")
        self.assertGreater(coverage["deferred_chunk_count"], 0)
        self.assertTrue(any("Tail" in item["locator"] for item in coverage["unread_sections"]))

    def test_evidence_deduplicates_by_source_revision_and_hash(self):
        content = "The API retains audit records for seven days."
        items = [
            {"snippet": content, "locator": "Section A", "chunk_id": "chunk-001"},
            {"snippet": content, "locator": "Section B", "chunk_id": "chunk-002"},
        ]

        same_revision = _verified_evidence_items(
            items, content, "policy.md", "markdown",
            artifact_id="artifact-a", source_revision=1, source_hash="hash-a",
        )
        next_revision = _verified_evidence_items(
            items[:1], content, "policy.md", "markdown",
            artifact_id="artifact-b", source_revision=2, source_hash="hash-b",
        )

        self.assertEqual(len(same_revision), 1)
        self.assertEqual(same_revision[0]["document_revision"], 1)
        self.assertEqual(same_revision[0]["document_hash"], "hash-a")
        self.assertEqual(len(next_revision), 1)
        self.assertNotEqual(same_revision[0]["document_hash"], next_revision[0]["document_hash"])

    # ── RG10: Coverage manifest honesty ─────────────────────────────────────────

    def test_empty_ai_response_not_counted_as_processed(self):
        """RG10: {} from provider must be processed_empty, not processed."""
        content = "# Security Policy\nThe application uses HTTPS for all API calls."

        async def empty_provider(**kwargs):
            # Return an empty dict — all fields absent
            return {}

        with patch("backend.services.parser_service.get_active_provider_config", return_value={}), \
             patch("backend.services.parser_service.chat_complete_json", new=AsyncMock(side_effect=empty_provider)):
            result = asyncio.run(parse_artifact("markdown", content))

        coverage = result["coverage_manifest"]
        # At least one chunk should be processed_empty, not processed
        chunk_statuses = [c["status"] for c in coverage.get("chunks", [])]
        self.assertIn("processed_empty", chunk_statuses,
                      "Empty AI response should produce processed_empty, not processed")
        self.assertNotIn("processed", chunk_statuses,
                         "Empty AI response must not be counted as fully processed")
        # Coverage should not be 'complete' if all chunks are processed_empty
        self.assertNotEqual(coverage.get("status"), "complete",
                            "Coverage cannot be complete when AI returned empty responses")
        # empty_chunk_count must be reported
        self.assertGreater(coverage.get("empty_chunk_count", 0), 0)

    def test_fallback_single_pii_signal_is_deferred(self):
        """RG10: Fallback with only has_pii=True (no evidence_items/endpoints) → deferred."""
        content = "# Sensitive Data Policy\nUsers provide their names and emails."

        async def unavailable(**kwargs):
            raise RuntimeError("provider unavailable")

        with patch("backend.services.parser_service.get_active_provider_config", return_value={}), \
             patch("backend.services.parser_service.chat_complete_json", new=AsyncMock(side_effect=unavailable)):
            # Override _basic_extract to return only has_pii=True (no evidence_items or endpoints)
            with patch("backend.services.parser_service._basic_extract",
                       return_value={"has_pii": True, "evidence_items": [], "endpoints": []}):
                result = asyncio.run(parse_artifact("markdown", content))

        coverage = result["coverage_manifest"]
        chunk_statuses = [c["status"] for c in coverage.get("chunks", [])]
        self.assertIn("deferred", chunk_statuses,
                      "has_pii=True alone without evidence_items/endpoints must be deferred")
        self.assertNotIn("processed_fallback", chunk_statuses,
                         "has_pii alone must not count as processed_fallback")

    def test_chunk_budget_exhausted_deferred(self):
        """RG11: Chunks beyond max_ai_chunks budget are deferred, not silently skipped."""
        # Build a document with many sections to exceed budget
        sections = "\n".join(f"# Section {i}\nContent for section {i}.\n" for i in range(1, 60))
        chunks = _document_chunks(sections)
        self.assertGreater(len(chunks), 5, "Need more chunks than the test budget")

        call_count = 0

        async def counting_provider(**kwargs):
            nonlocal call_count
            call_count += 1
            return {"summary": "extracted", "evidence_items": []}

        test_budget = 3
        with patch("backend.services.parser_service.get_active_provider_config", return_value={}), \
             patch("backend.services.parser_service.chat_complete_json", new=AsyncMock(side_effect=counting_provider)):
            result = asyncio.run(parse_artifact("markdown", sections, max_ai_chunks=test_budget))

        # Provider must not be called more than the budget
        self.assertLessEqual(call_count, test_budget,
                             f"AI calls ({call_count}) exceeded budget ({test_budget})")
        coverage = result["coverage_manifest"]
        # Remaining chunks must be in deferred with budget reason
        deferred = [c for c in coverage.get("chunks", []) if c["status"] == "deferred"]
        self.assertGreater(len(deferred), 0, "Chunks beyond budget must be deferred")
        budget_deferred = [c for c in deferred if "budget" in (c.get("reason") or "").lower()]
        self.assertGreater(len(budget_deferred), 0,
                           "Budget-exhausted chunks must have a reason mentioning budget")
        # Manifest should report budget_exhausted=True
        self.assertTrue(coverage.get("budget_exhausted"),
                        "coverage_manifest must report budget_exhausted=True")
        self.assertEqual(coverage.get("budget_limit"), test_budget)

    def test_truncated_source_reflected_in_manifest(self):
        """RG10: source_truncated=True from file extraction is reflected in coverage manifest."""
        content = "# Policy\nThe system retains logs for 30 days."

        async def simple_provider(**kwargs):
            return {"summary": "extracted", "evidence_items": []}

        with patch("backend.services.parser_service.get_active_provider_config", return_value={}), \
             patch("backend.services.parser_service.chat_complete_json", new=AsyncMock(side_effect=simple_provider)):
            result = asyncio.run(
                parse_artifact("markdown", content, source_truncated=True, truncated_chars=15000)
            )

        coverage = result["coverage_manifest"]
        self.assertTrue(coverage.get("source_truncated"),
                        "coverage_manifest must report source_truncated=True")
        self.assertEqual(coverage.get("unread_chars_estimate"), 15000)
        # Warning about truncation must appear
        warnings = result.get("warnings", [])
        self.assertTrue(any("truncated" in w.lower() for w in warnings),
                        "A warning about source truncation must be present")

    def test_reparse_triggered_by_parser_version_upgrade(self):
        """RG11: Source with old parser version should be reparsed, not returned as duplicate."""
        from backend.routers.artifacts import upload_artifact
        from unittest.mock import MagicMock, AsyncMock as AsyncMockClass
        import asyncio

        old_parser_version = "structured-api-v1"
        content_hash = "abc123"
        content = "# API Docs\nUser authentication via JWT token."

        # Simulate an existing source with old parser version and complete coverage
        existing_source = {
            "artifact_id": f"artifact-{content_hash[:16]}",
            "artifact_type": "markdown",
            "filename": "api_docs.md",
            "content_hash": content_hash,
            "revision": 1,
            "active": True,
            "parser": {"version": old_parser_version, "kind": "ai_enrichment", "chunked": True},
            "coverage_manifest": {"status": "complete"},
        }
        project = {
            "id": "test-project-ri3",
            "name": "RI3 Reparse Test",
            "artifact_sources": [existing_source],
        }

        from backend.models.schemas import ArtifactUpload
        payload = ArtifactUpload(
            artifact_type="markdown",
            content=content,
            filename="api_docs.md",
        )

        reparse_triggered = []

        async def mock_parse_artifact(artifact_type, content_arg, data_policy=None, **kwargs):
            reparse_triggered.append(True)
            return {
                "summary": "reparsed",
                "evidence_items": [],
                "coverage_manifest": {"status": "complete"},
                "parser": {"version": PARSER_VERSION, "kind": "ai_enrichment", "chunked": True},
                "stats": {},
                "warnings": [],
            }

        import hashlib
        actual_hash = hashlib.sha256(content.encode()).hexdigest()
        existing_source["content_hash"] = actual_hash

        with patch("backend.routers.artifacts.parse_artifact", new=mock_parse_artifact), \
             patch("backend.routers.artifacts.get_authorized_project", return_value=project), \
             patch("backend.routers.artifacts.save_project"), \
             patch("backend.routers.artifacts.rebuild_project_from_artifacts"), \
             patch("backend.routers.artifacts.compute_completeness",
                   return_value={"score": 50, "level": "Medium"}), \
             patch("backend.routers.artifacts.capture_manual_context"), \
             patch("backend.routers.artifacts.project_client_view", return_value={}):
            result = asyncio.run(upload_artifact("test-project-ri3", payload, request=None))

        self.assertTrue(reparse_triggered,
                        "parse_artifact must be called when parser version differs (RG11 reparse)")
        self.assertFalse(result.get("duplicate", True),
                         "Response must not claim duplicate when reparse is needed")

    def test_direct_flow_gets_artifact_provenance_after_upload_revision_is_known(self):
        from backend.routers.artifacts import upload_artifact
        from backend.models.schemas import ArtifactUpload

        content = "# Flow\nEmployee sends a leave request to the HR API."
        project = {"id": "project-direct-flow", "name": "Direct flow provenance", "artifact_sources": []}
        payload = ArtifactUpload(artifact_type="markdown", content=content, filename="flow.md")

        async def mock_parse_artifact(artifact_type, content_arg, data_policy=None, **kwargs):
            return {
                "summary": "direct flow",
                "data_flows": [{
                    "source": "Employee",
                    "destination": "HR API",
                    "data": ["Leave request"],
                    "evidence_type": "direct",
                    "evidence_locator": "Flow",
                }],
                "evidence_items": [],
                "coverage_manifest": {"status": "complete"},
                "parser": {"version": PARSER_VERSION, "kind": "ai_enrichment", "chunked": True},
                "stats": {},
                "warnings": [],
            }

        with patch("backend.routers.artifacts.parse_artifact", new=mock_parse_artifact), \
             patch("backend.routers.artifacts.get_authorized_project", return_value=project), \
             patch("backend.routers.artifacts.save_project"), \
             patch("backend.routers.artifacts.rebuild_project_from_artifacts"), \
             patch("backend.routers.artifacts.compute_completeness", return_value={"score": 50, "level": "Medium"}), \
             patch("backend.routers.artifacts.capture_manual_context"), \
             patch("backend.routers.artifacts.project_client_view", return_value={}):
            asyncio.run(upload_artifact("project-direct-flow", payload, request=None))

        flow = project["artifact_sources"][0]["contribution"]["data_flows"][0]
        self.assertEqual(flow["evidence_type"], "direct")
        self.assertEqual(flow["evidence_refs"], [f"artifact:{project['artifact_sources'][0]['artifact_id']}"])


if __name__ == "__main__":
    unittest.main()
