import asyncio
import json
import pathlib
import unittest
from unittest.mock import AsyncMock, patch

from backend.services.parser_service import parse_artifact
from backend.services.posture_service import compute_completeness, enrich_missing_info


ROOT = pathlib.Path(__file__).resolve().parents[1]


class Cr2CompletenessTests(unittest.TestCase):
    def test_calibration_ordering_does_not_use_band_as_runtime_input(self):
        fixture = json.loads((ROOT / "tests/prd_corpus/completeness_calibration.json").read_text())
        scores = {
            case["band"]: compute_completeness(case["project"])["score"]
            for case in fixture["cases"]
        }

        self.assertGreater(scores["complete"], scores["half"])
        self.assertGreater(scores["half"], scores["incomplete"])
        self.assertNotEqual(scores["complete"], scores["half"])
        self.assertNotEqual(scores["half"], scores["incomplete"])

    def test_dimensions_have_evidence_refs_and_actionable_gap_contract(self):
        result = compute_completeness({"actors": ["User"]})

        self.assertEqual(result["schema_version"], "completeness-v2")
        self.assertEqual(len(result["dimensions"]), 10)
        self.assertTrue(all("evidence_refs" in item and "locators" in item for item in result["dimensions"]))
        self.assertTrue(all(
            item.get("owner") and item.get("linked_object") and item.get("next_action")
            for item in result["blockers"]
        ))
        self.assertTrue(any(item["dimension"] == "authentication_authorization" for item in result["gaps"]))

    def test_unknown_placeholder_does_not_earn_completeness_credit(self):
        result = compute_completeness({
            "auth_method": "Unknown",
            "data_classification": ["N/A"],
            "retention": "Not specified",
        })
        by_key = {item["key"]: item for item in result["dimensions"]}

        self.assertEqual(by_key["authentication_authorization"]["earned"], 0)
        self.assertEqual(by_key["assets_data_classification"]["earned"], 0)
        self.assertEqual(by_key["lifecycle_retention_deletion"]["earned"], 0)

    def test_product_signal_creates_specific_deferred_topic_not_generic_question(self):
        result = compute_completeness({
            "actors": ["Partner system"],
            "entry_points": ["Webhook callback"],
            "external_systems": ["Partner platform"],
            "extracted_data_flows": [{"source": "Partner", "destination": "Webhook gateway", "data": ["Order status"]}],
        })
        topics = {item["area"] for item in result["candidate_deferred_topics"]}

        self.assertIn("Webhook signature rotation", topics)
        self.assertIn("Webhook replay window", topics)
        self.assertTrue(all(item["linked_object"] and item["next_action"] for item in result["candidate_deferred_topics"]))

    def test_unread_section_has_locator_state_owner_link_and_next_action(self):
        project = {
            "artifact_sources": [{
                "artifact_id": "artifact-1", "artifact_type": "prd", "filename": "prd.md",
                "active": True, "revision": 2, "content_hash": "hash-2",
                "coverage_manifest": {
                    "status": "partial", "total_characters": 100,
                    "chunks": [{"chunk_id": "chunk-1", "section": "Retention", "locator": "Retention · characters 81-100", "char_count": 20, "status": "deferred", "reason": "Chunk budget exhausted"}],
                    "extraction_omissions": [],
                },
            }],
        }
        coverage = compute_completeness(project)["ingestion_coverage"]
        item = coverage["unread_sections"][0]

        self.assertEqual(item["locator"], "Retention · characters 81-100")
        self.assertEqual(item["state"], "deferred")
        self.assertTrue(item["owner"])
        self.assertTrue(item["linked_object"])
        self.assertTrue(item["next_action"])

    def test_deterministic_fallback_never_claims_complete_coverage(self):
        async def unavailable(**kwargs):
            raise RuntimeError("provider unavailable")

        with patch("backend.services.parser_service.get_active_provider_config", return_value={}), \
             patch("backend.services.parser_service.chat_complete_json", new=AsyncMock(side_effect=unavailable)):
            result = asyncio.run(parse_artifact("markdown", "# Security\nGET /health is public."))

        coverage = result["coverage_manifest"]
        self.assertEqual(coverage["status"], "partial")
        self.assertEqual(coverage["fallback_chunk_count"], 1)
        self.assertTrue(any(item["state"] == "unverified" for item in coverage["unread_sections"]))
        self.assertTrue(any("fallback" in warning.lower() for warning in result["warnings"]))

    def test_changed_source_reuses_unchanged_checkpoint_by_content_hash(self):
        calls = []

        async def provider(**kwargs):
            calls.append(kwargs["user_prompt"])
            chunk = kwargs["user_prompt"].split("ARTIFACT CONTENT CHUNK:\n", 1)[1].split("\n\nReturn at most", 1)[0]
            snippet = next((line.strip() for line in chunk.splitlines() if line.strip().startswith("Decision:")), "Decision: no decision")
            return {"summary": "Extracted", "evidence_items": [{"snippet": snippet, "locator": "section"}]}

        first_content = "# Existing\nDecision: retain audit logs for seven days.\n"
        second_content = "# New context\nDecision: use a partner queue.\n\n" + first_content
        with patch("backend.services.parser_service.get_active_provider_config", return_value={}), \
             patch("backend.services.parser_service.chat_complete_json", new=AsyncMock(side_effect=provider)):
            first = asyncio.run(parse_artifact("markdown", first_content))
            first_calls = len(calls)
            second = asyncio.run(parse_artifact(
                "markdown", second_content,
                resume_chunks=first["coverage_manifest"]["checkpoints"],
                resume_source_revision=1,
                resume_source_hash="hash-1",
            ))

        self.assertEqual(first_calls, 1)
        self.assertEqual(len(calls), 2)
        self.assertEqual(second["coverage_manifest"]["reused_chunk_count"], 1)
        self.assertEqual(second["coverage_manifest"]["reparse_source_revision"], 1)

    def test_enriched_missing_info_preserves_owner_link_and_next_action(self):
        item = enrich_missing_info([], {"actors": []})[0]

        self.assertTrue(item["owner"])
        self.assertTrue(item["linked_object"])
        self.assertTrue(item["next_action"])
        self.assertTrue(item["effect_on_analysis"])


if __name__ == "__main__":
    unittest.main()
