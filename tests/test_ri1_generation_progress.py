import asyncio
import copy
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from fastapi import HTTPException

from backend.routers.analysis import get_analysis_run_progress, run_full_analysis
from backend.services.ai_service import AnalysisResponseError, StructuredJSONResult, chat_complete_json
from backend.services.deterministic_threat_provider import DeterministicThreatProvider
from backend.services.threat_batch_service import (
    build_threat_batches, run_threat_batches, MAX_BATCHES, FLOWS_PER_BATCH,
    MAX_BATCH_OUTPUT_TOKENS, MAX_BATCH_CONTEXT_CHARS, MAX_CONCURRENT_BATCHES,
)
from backend.services.threat_validation_service import ThreatGenerationResult


class Ri1GenerationTests(unittest.TestCase):
    def test_adaptive_batching_isolates_a_complex_flow(self):
        flows = [
            {"id": "flow-large", "source_id": "node-1", "target_id": "node-2", "name": "x" * (MAX_BATCH_CONTEXT_CHARS + 1)},
            {"id": "flow-small-1", "source_id": "node-2", "target_id": "node-3", "name": "small"},
            {"id": "flow-small-2", "source_id": "node-3", "target_id": "node-4", "name": "small"},
        ]
        batches, deferred = build_threat_batches({"nodes": [], "flows": flows})

        self.assertEqual([batch["flow_refs"] for batch in batches], [
            ["flow-large"], ["flow-small-1", "flow-small-2"],
        ])
        self.assertEqual(deferred, [])
        self.assertEqual(batches[0]["flow_count"], 1)

    def test_manifest_records_attempt_budget_and_safe_provider_metadata(self):
        async def provider(**kwargs):
            return StructuredJSONResult(
                {"threats": [], "coverage": []},
                {
                    "model": "fixture-model",
                    "finish_reason": "stop",
                    "usage": {"total_tokens": 42},
                    "parse_status": "valid",
                },
            )

        result = asyncio.run(run_threat_batches(
            framework="STRIDE",
            batches=[{"batch_id": "batch-1", "scope_refs": ["flow-1"], "context": "{}"}],
            deferred_refs=[], system_prompt="system", prompt_prefix="Analyze",
            prompt_suffix="JSON only", provider={}, chat_complete_json=provider,
        ))
        manifest = result.response_metadata["generation_manifest"]
        record = manifest["batches"][0]

        self.assertEqual(record["status"], "valid_empty")
        self.assertEqual(record["assessment_status"], "valid_empty")
        self.assertEqual(record["attempt_count"], 1)
        self.assertEqual(record["retry_count"], 0)
        self.assertGreater(record["estimated_input_tokens"], 0)
        self.assertEqual(record["attempts"][0]["response_metadata"]["usage"]["total_tokens"], 42)
        self.assertEqual(manifest["concurrency"], MAX_CONCURRENT_BATCHES)
        self.assertEqual(manifest["max_batch_retries"], 1)

    def test_retry_repeats_only_failed_batch_and_keeps_successful_batch(self):
        calls = []
        attempts = {"batch-2": 0}

        async def provider(**kwargs):
            batch_id = "batch-2" if "batch-2" in kwargs["user_prompt"] else "batch-1"
            calls.append(batch_id)
            if batch_id == "batch-2" and attempts[batch_id] == 0:
                attempts[batch_id] += 1
                raise ConnectionError("temporary provider failure")
            return StructuredJSONResult({"threats": [], "coverage": []}, {"finish_reason": "stop"})

        result = asyncio.run(run_threat_batches(
            framework="STRIDE",
            batches=[
                {"batch_id": "batch-1", "scope_refs": ["flow-1"], "context": "{}"},
                {"batch_id": "batch-2", "scope_refs": ["flow-2"], "context": "{}"},
            ],
            deferred_refs=[], system_prompt="system", prompt_prefix="Analyze",
            prompt_suffix="JSON only", provider={}, chat_complete_json=provider,
        ))
        manifest = result.response_metadata["generation_manifest"]
        by_id = {item["batch_id"]: item for item in manifest["batches"]}

        self.assertEqual(result.assessment_status, "valid_empty")
        self.assertEqual(calls.count("batch-1"), 1)
        self.assertEqual(calls.count("batch-2"), 2)
        self.assertEqual(by_id["batch-1"]["attempt_count"], 1)
        self.assertEqual(by_id["batch-2"]["attempt_count"], 2)
        self.assertEqual(manifest["deferred_refs"], [])

    def test_cached_successful_batch_is_not_recalled_on_stage_retry(self):
        calls = []

        async def first_provider(**kwargs):
            calls.append("first")
            return StructuredJSONResult(
                {"threats": [], "coverage": []},
                {"model": "fixture-model", "finish_reason": "stop"},
            )

        batch = {"batch_id": "batch-1", "scope_refs": ["flow-1"], "context": "{}"}
        first = asyncio.run(run_threat_batches(
            framework="STRIDE", batches=[batch], deferred_refs=[], system_prompt="system",
            prompt_prefix="Analyze", prompt_suffix="JSON only", provider={"model": "fixture-model"},
            chat_complete_json=first_provider,
        ))
        prior_manifest = first.response_metadata["generation_manifest"]

        async def retry_provider(**kwargs):
            calls.append("retry")
            raise AssertionError("a successful batch must be served from the retry cache")

        retried = asyncio.run(run_threat_batches(
            framework="STRIDE", batches=[batch], deferred_refs=[], system_prompt="system",
            prompt_prefix="Analyze", prompt_suffix="JSON only", provider={"model": "fixture-model"},
            chat_complete_json=retry_provider, prior_manifest=prior_manifest,
        ))
        record = retried.response_metadata["generation_manifest"]["batches"][0]

        self.assertEqual(calls, ["first"])
        self.assertTrue(record["cache_hit"])
        self.assertEqual(retried.assessment_status, "valid_empty")
        self.assertEqual(retried.response_metadata["generation_manifest"]["cache_hits"], 1)

    def test_deterministic_mixed_fixture_preserves_success_and_defers_failure(self):
        provider = DeterministicThreatProvider("mixed", delay_seconds=0)
        batches = [
            {"batch_id": "batch-1", "scope_refs": ["flow-1"], "context": '{"id":"flow-1"}'},
            {"batch_id": "batch-2", "scope_refs": ["flow-2"], "context": '{"id":"flow-2"}'},
        ]

        result = asyncio.run(run_threat_batches(
            framework="STRIDE", batches=batches, deferred_refs=[], system_prompt="system",
            prompt_prefix="Analyze", prompt_suffix="JSON only", provider={},
            chat_complete_json=provider,
        ))

        manifest = result.response_metadata["generation_manifest"]
        self.assertEqual(result.assessment_status, "partial")
        self.assertEqual(len(result), 1)
        self.assertEqual(manifest["deferred_refs"], ["flow-2"])
        self.assertEqual(manifest["batches"][1]["error_kind"], "truncated")

    def test_deterministic_valid_empty_fixture_is_a_valid_assessment(self):
        provider = DeterministicThreatProvider("valid_empty")
        result = asyncio.run(run_threat_batches(
            framework="LINDDUN",
            batches=[{"batch_id": "batch-1", "scope_refs": ["flow-1"], "context": "{}"}],
            deferred_refs=[], system_prompt="system", prompt_prefix="Analyze LINDDUN",
            prompt_suffix="JSON only", provider={}, chat_complete_json=provider,
        ))

        self.assertEqual(result.assessment_status, "valid_empty")
        self.assertEqual(result.response_metadata["generation_manifest"]["batches"][0]["status"], "valid_empty")

    def test_deterministic_failure_fixture_codes_are_not_collapsed(self):
        batch = [{"batch_id": "batch-1", "scope_refs": ["flow-1"], "context": "{}"}]
        for mode, expected_code in (("truncated", "truncated_json"), ("malformed", "non_json_response"), ("rate_limited", "rate_limited")):
            with self.subTest(mode=mode), self.assertRaises(AnalysisResponseError) as raised:
                asyncio.run(run_threat_batches(
                    framework="STRIDE", batches=batch, deferred_refs=[], system_prompt="system",
                    prompt_prefix="Analyze", prompt_suffix="JSON only", provider={},
                    chat_complete_json=DeterministicThreatProvider(mode),
                ))
            self.assertEqual(raised.exception.code, expected_code)

    def test_deterministic_timeout_fixture_exposes_terminal_stage_timeout(self):
        provider = DeterministicThreatProvider("timeout", delay_seconds=0.05)
        batch = [{"batch_id": "batch-1", "scope_refs": ["flow-1"], "context": "{}"}]
        with (
            patch("backend.services.threat_batch_service.MAX_BATCH_SECONDS", 0.01),
            patch("backend.services.threat_batch_service.MAX_STAGE_SECONDS", 0.02),
            self.assertRaises(RuntimeError) as raised,
        ):
            asyncio.run(run_threat_batches(
                framework="STRIDE", batches=batch, deferred_refs=[], system_prompt="system",
                prompt_prefix="Analyze", prompt_suffix="JSON only", provider={},
                chat_complete_json=provider,
            ))
        self.assertEqual(raised.exception.code, "stage_timeout")
        self.assertEqual(
            raised.exception.response_metadata["generation_manifest"]["batches"][0]["status"],
            "timed_out",
        )

    def test_batch_cap_exposes_deferred_graph_references(self):
        nodes = [{"id": f"node-{index}", "name": f"Process {index}", "type": "process"} for index in range(201)]
        flows = [
            {"id": f"flow-{index}", "source_id": f"node-{index}", "target_id": f"node-{index + 1}"}
            for index in range(200)
        ]
        batches, deferred = build_threat_batches({"revision": 2, "semantic_hash": "hash-2", "nodes": nodes, "flows": flows})

        # The fixed request cap covers 96 interactions in groups of three; the rest remain deferred.
        self.assertEqual(len(batches), MAX_BATCHES)
        self.assertIn("flow-199", deferred)
        self.assertTrue(all(len(batch["context"]) < 14000 for batch in batches))
        self.assertEqual(len({ref for batch in batches for ref in batch["scope_refs"] if ref.startswith("flow-")}),
                         MAX_BATCHES * FLOWS_PER_BATCH)
        self.assertEqual(len(deferred), 200 - MAX_BATCHES * FLOWS_PER_BATCH)

    def test_partial_batches_keep_valid_findings_and_defer_failed_scope(self):
        batches = [
            {"batch_id": "batch-1", "scope_refs": ["flow-1"], "context": "{}"},
            {"batch_id": "batch-2", "scope_refs": ["flow-2"], "context": "{}"},
        ]
        calls = []

        async def provider(**kwargs):
            calls.append(kwargs)
            if "batch-2" in kwargs["user_prompt"]:
                raise AnalysisResponseError("Provider output incomplete", code="truncated_json", metadata={"finish_reason": "length", "parse_status": "truncated_json"})
            return StructuredJSONResult({"threats": [{"threat_category": "Tampering", "threat_description": "A valid candidate", "affected_refs": ["flow-1"]}], "coverage": []}, {"finish_reason": "stop", "usage": {"total_tokens": 42}})

        result = asyncio.run(run_threat_batches(
            framework="STRIDE", batches=batches, deferred_refs=[], system_prompt="system",
            prompt_prefix="Analyze", prompt_suffix="JSON only", provider={}, chat_complete_json=provider,
        ))

        self.assertEqual(result.assessment_status, "partial")
        self.assertEqual(len(result), 1)
        manifest = result.response_metadata["generation_manifest"]
        self.assertEqual(manifest["deferred_refs"], ["flow-2"])
        self.assertEqual(manifest["batches"][0]["response_metadata"]["usage"]["total_tokens"], 42)
        self.assertEqual(manifest["batches"][1]["error_code"], "truncated_json")
        self.assertEqual(manifest["batches"][1]["status"], "invalid")
        self.assertEqual(manifest["batches"][1]["error_kind"], "truncated")
        self.assertTrue(all(call["max_tokens"] == MAX_BATCH_OUTPUT_TOKENS and call["return_metadata"] for call in calls))

    def test_shared_references_are_not_marked_deferred_when_another_batch_completed(self):
        batches = [
            {"batch_id": "batch-1", "scope_refs": ["node-shared", "flow-1"], "context": "{}"},
            {"batch_id": "batch-2", "scope_refs": ["node-shared", "flow-2"], "context": "{}"},
        ]

        async def provider(**kwargs):
            if "batch-2" in kwargs["user_prompt"]:
                raise AnalysisResponseError("truncated", code="truncated_json")
            return StructuredJSONResult({"threats": [], "coverage": []}, {"finish_reason": "stop"})

        result = asyncio.run(run_threat_batches(
            framework="STRIDE", batches=batches, deferred_refs=[], system_prompt="system",
            prompt_prefix="Analyze", prompt_suffix="JSON only", provider={}, chat_complete_json=provider,
        ))
        self.assertEqual(result.response_metadata["generation_manifest"]["deferred_refs"], ["flow-2"])

    def test_provider_unavailable_keeps_batch_manifest(self):
        batch = [{"batch_id": "batch-1", "scope_refs": ["flow-1"], "context": "{}"}]

        async def provider(**kwargs):
            raise ConnectionError("provider offline")

        with self.assertRaises(RuntimeError) as raised:
            asyncio.run(run_threat_batches(
                framework="STRIDE", batches=batch, deferred_refs=[], system_prompt="system",
                prompt_prefix="Analyze", prompt_suffix="JSON only", provider={}, chat_complete_json=provider,
            ))
        self.assertEqual(raised.exception.code, "provider_unavailable")
        self.assertEqual(raised.exception.response_metadata["generation_manifest"]["deferred_refs"], ["flow-1"])

    def test_valid_empty_batch_is_not_provider_failure(self):
        batch = [{"batch_id": "batch-1", "scope_refs": ["flow-1"], "context": "{}"}]

        async def provider(**kwargs):
            return StructuredJSONResult({"threats": [], "coverage": []}, {"finish_reason": "stop"})

        result = asyncio.run(run_threat_batches(
            framework="STRIDE", batches=batch, deferred_refs=[], system_prompt="system",
            prompt_prefix="Analyze", prompt_suffix="JSON only", provider={}, chat_complete_json=provider,
        ))
        self.assertEqual(result.assessment_status, "valid_empty")
        self.assertEqual(result.response_metadata["generation_manifest"]["deferred_refs"], [])

    def test_output_limit_rejects_even_syntactically_complete_json(self):
        response = SimpleNamespace(
            model="test-model", usage=None,
            choices=[SimpleNamespace(finish_reason="length", message=SimpleNamespace(content='{"threats": [], "coverage": []}', model_extra={}))],
        )
        client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=AsyncMock(return_value=response))))
        with patch("backend.services.ai_service._get_client", return_value=client):
            with self.assertRaises(AnalysisResponseError) as raised:
                asyncio.run(chat_complete_json("system", "user", base_url="http://localhost", return_metadata=True))
        self.assertEqual(raised.exception.code, "truncated_response")
        self.assertEqual(raised.exception.response_metadata["finish_reason"], "length")

    def test_output_limit_retry_requests_shorter_complete_response(self):
        first = SimpleNamespace(model="test-model", usage=None, choices=[SimpleNamespace(
            finish_reason="length", message=SimpleNamespace(content='{"threats": [', model_extra={}),
        )])
        second = SimpleNamespace(model="test-model", usage=None, choices=[SimpleNamespace(
            finish_reason="stop", message=SimpleNamespace(content='{"threats": [], "coverage": []}', model_extra={}),
        )])
        create = AsyncMock(side_effect=[first, second])
        client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
        with patch("backend.services.ai_service._get_client", return_value=client):
            result = asyncio.run(chat_complete_json("system", "user", base_url="http://localhost", return_metadata=True))
        self.assertEqual(result.metadata["format_retry_count"], 1)
        self.assertIn("output limit", create.call_args_list[1].kwargs["messages"][0]["content"])

    def test_empty_prose_and_truncated_failures_keep_distinct_codes(self):
        batch = [{"batch_id": "batch-1", "scope_refs": ["flow-1"], "context": "{}"}]
        for code in ("empty_response", "non_json_response", "truncated_json"):
            async def provider(**kwargs):
                raise AnalysisResponseError(code, code=code, metadata={"parse_status": code, "finish_reason": "length" if code == "truncated_json" else "stop"})

            with self.subTest(code=code), self.assertRaises(AnalysisResponseError) as raised:
                asyncio.run(run_threat_batches(
                    framework="STRIDE", batches=batch, deferred_refs=[], system_prompt="system",
                    prompt_prefix="Analyze", prompt_suffix="JSON only", provider={}, chat_complete_json=provider,
                ))
            self.assertEqual(raised.exception.code, code)
            self.assertEqual(raised.exception.response_metadata["generation_manifest"]["batches"][0]["error_code"], code)


class Ri1ProgressTests(unittest.TestCase):
    def test_dfd_edit_during_provider_wait_supersedes_analysis_without_overwrite(self):
        project = {
            "project_id": "ri1-dfd-race", "name": "DFD race fixture", "description": "Registration API",
            "actors": ["Customer"], "components": ["Registration API"],
            "entry_points": ["Registration endpoint"], "data_involved": ["email"],
            "extracted_data_flows": [{"source": "Customer", "destination": "Registration API", "data": ["email"]}],
        }
        state = {"project": copy.deepcopy(project), "report": None, "dfd": None}

        async def scenario():
            entered = asyncio.Event()
            release = asyncio.Event()

            async def stride(*args, **kwargs):
                entered.set()
                await release.wait()
                return ThreatGenerationResult([], [], assessment_status="valid_empty")

            def save_report(_project_id, report):
                state["report"] = copy.deepcopy(report)
                return report

            with (
                patch("backend.routers.analysis.get_project", side_effect=lambda *_: copy.deepcopy(state["project"])),
                patch("backend.routers.analysis.save_project", side_effect=lambda value: state.__setitem__("project", copy.deepcopy(value))),
                patch("backend.routers.analysis.get_report", side_effect=lambda *_: copy.deepcopy(state["report"])),
                patch("backend.routers.analysis.save_report", side_effect=save_report),
                patch("backend.routers.analysis.get_dfd_model", side_effect=lambda *_: copy.deepcopy(state["dfd"])),
                patch("backend.routers.analysis.save_report_and_dfd", side_effect=AssertionError("stale run must not publish")),
                patch("backend.routers.analysis.generate_stride_threats", side_effect=stride),
                patch("backend.routers.analysis.generate_linddun_threats", new=AsyncMock(return_value=ThreatGenerationResult([], [], assessment_status="valid_empty"))),
            ):
                task = asyncio.create_task(run_full_analysis(project["project_id"], {"analysis_types": ["trust_boundary", "stride", "linddun"]}))
                await asyncio.wait_for(entered.wait(), 3)
                edited_dfd = {"revision": 2, "semantic_hash": "human-reviewed-edit", "nodes": [], "flows": []}
                state["dfd"] = copy.deepcopy(edited_dfd)
                state["report"]["report_revision"] = 1
                state["report"]["dfd_model"] = copy.deepcopy(edited_dfd)
                release.set()
                with self.assertRaises(HTTPException) as caught:
                    await task

            self.assertEqual(caught.exception.status_code, 409)
            self.assertEqual(state["report"]["analysis_status"], "superseded")
            self.assertEqual(state["report"]["dfd_model"]["semantic_hash"], "human-reviewed-edit")
            self.assertEqual(state["project"]["analysis_status"], "superseded")

        asyncio.run(scenario())

    def test_held_stride_keeps_only_stride_active_and_later_phases_queued(self):
        project = {
            "project_id": "ri1-progress", "name": "Progress fixture", "description": "Registration API",
            "actors": ["Customer"], "components": ["Registration API"],
            "entry_points": ["Registration endpoint"], "data_involved": ["email"],
            "extracted_data_flows": [{"source": "Customer", "destination": "Registration API", "data": ["email"]}],
        }
        state = {"project": copy.deepcopy(project), "report": None, "progress": None}

        async def scenario():
            entered = asyncio.Event()
            release = asyncio.Event()

            async def stride(*args, **kwargs):
                entered.set()
                await release.wait()
                return ThreatGenerationResult([], [], assessment_status="valid_empty")

            with (
                patch("backend.routers.analysis.get_authorized_project", side_effect=lambda *_: copy.deepcopy(state["project"])),
                patch("backend.routers.analysis.get_project", side_effect=lambda *_: copy.deepcopy(state["project"])),
                patch("backend.routers.analysis.save_project", side_effect=lambda value: state.__setitem__("project", copy.deepcopy(value))),
                patch("backend.routers.analysis.get_report", side_effect=lambda *_: copy.deepcopy(state["report"])),
                patch("backend.routers.analysis.save_report", side_effect=lambda _, value: state.__setitem__("report", copy.deepcopy(value))),
                patch("backend.routers.analysis.save_report_and_dfd"),
                patch("backend.routers.analysis.get_dfd_model", return_value=None),
                patch("backend.routers.analysis.get_analysis_progress", side_effect=lambda *_: copy.deepcopy(state["progress"])),
                patch("backend.routers.analysis.save_analysis_progress", side_effect=lambda _, value: state.__setitem__("progress", copy.deepcopy(value))),
                patch("backend.routers.analysis.generate_stride_threats", side_effect=stride),
                patch("backend.routers.analysis.generate_linddun_threats", new=AsyncMock(return_value=ThreatGenerationResult([], [], assessment_status="valid_empty"))),
            ):
                task = asyncio.create_task(run_full_analysis(project["project_id"], {"analysis_types": ["trust_boundary", "stride", "linddun"]}, request=object()))
                await asyncio.wait_for(entered.wait(), 3)
                progress = await get_analysis_run_progress(project["project_id"], request=object())
                self.assertEqual(progress["active_stage"], "stride")
                self.assertEqual(progress["stages"]["trust_boundary"]["state"], "completed")
                self.assertEqual(progress["stages"]["stride"]["state"], "active")
                self.assertEqual(progress["stages"]["linddun"]["state"], "queued")
                release.set()
                await task
                self.assertEqual(state["progress"]["status"], "completed_with_warnings")
                self.assertFalse(state["report"]["analysis_run"]["quality_gate"]["signoff_ready"])

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
