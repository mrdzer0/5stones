import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from backend.routers.artifacts import _verified_evidence_items
from backend.services.parser_service import _document_chunks, parse_artifact


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
        self.assertEqual(coverage["status"], "complete")
        self.assertGreaterEqual(coverage["chunk_count"], 2)
        self.assertEqual(coverage["deferred_chunk_count"], 0)

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


if __name__ == "__main__":
    unittest.main()
