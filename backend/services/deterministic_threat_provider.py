"""Deterministic provider fixture for local threat-generation contract tests.

This module is intentionally opt-in. It is never selected as the application
provider; tests pass an instance to ``run_threat_batches`` so timeout,
truncation, malformed, and mixed-batch behavior can be reproduced offline.
"""
from __future__ import annotations

import asyncio
import json
import re

from backend.services.ai_service import AnalysisResponseError, StructuredJSONResult


class DeterministicThreatProvider:
    """Small OpenAI-compatible callable with named, repeatable failure modes."""

    MODES = {
        "success",
        "partial",
        "timeout",
        "truncated",
        "malformed",
        "valid_empty",
        "mixed",
        "rate_limited",
    }

    def __init__(self, mode: str = "success", *, delay_seconds: float = 0.1):
        if mode not in self.MODES:
            raise ValueError(f"Unsupported deterministic provider mode: {mode}")
        self.mode = mode
        self.delay_seconds = delay_seconds
        self.calls: list[dict] = []

    async def __call__(self, **kwargs):
        prompt = str(kwargs.get("user_prompt") or "")
        batch_match = re.search(r"CANONICAL DFD INTERACTION (batch-[A-Za-z0-9_-]+)", prompt)
        batch_id = batch_match.group(1) if batch_match else "batch-unknown"
        self.calls.append({"batch_id": batch_id, "max_tokens": kwargs.get("max_tokens")})

        if self.mode == "timeout" or (self.mode in {"partial", "mixed"} and batch_id == "batch-2"):
            await asyncio.sleep(self.delay_seconds)
            if self.mode == "timeout":
                await asyncio.sleep(self.delay_seconds)
            else:
                raise AnalysisResponseError(
                    "Deterministic partial fixture response was truncated",
                    code="truncated_json",
                    metadata={"finish_reason": "length", "parse_status": "truncated_json"},
                )
        if self.mode == "truncated":
            raise AnalysisResponseError(
                "Deterministic truncated fixture response",
                code="truncated_json",
                metadata={"finish_reason": "length", "parse_status": "truncated_json"},
            )
        if self.mode == "malformed":
            raise AnalysisResponseError(
                "Deterministic malformed fixture response",
                code="non_json_response",
                metadata={"finish_reason": "stop", "parse_status": "non_json_response"},
            )
        if self.mode == "rate_limited":
            error = AnalysisResponseError(
                "Deterministic rate limit fixture response",
                code="rate_limited",
                metadata={"http_status": 429, "parse_status": "provider_error"},
            )
            error.status_code = 429
            raise error

        if self.mode == "valid_empty":
            payload = {"threats": [], "coverage": []}
        else:
            flow_match = re.search(r'"id":"(flow-[A-Za-z0-9_-]+)"', prompt)
            flow_id = flow_match.group(1) if flow_match else "flow-fixture"
            framework = "LINDDUN" if "LINDDUN" in prompt.upper() else "STRIDE"
            payload = {
                "threats": [{
                    "framework": framework,
                    "threat_category": "Data Disclosure" if framework == "LINDDUN" else "Tampering",
                    "threat_description": f"Deterministic candidate for {flow_id}",
                    "primary_interaction_ref": flow_id,
                    "affected_refs": [flow_id],
                }],
                "coverage": [{
                    "element_ref": flow_id,
                    "category": "Data Disclosure" if framework == "LINDDUN" else "Tampering",
                    "status": "candidate_identified",
                    "reason": "Deterministic fixture candidate",
                    "applicability": "applicable",
                    "applicability_rationale": "Fixture mode",
                    "mapping_refs": [flow_id],
                }],
            }
        return StructuredJSONResult(payload, {
            "model": "deterministic-threat-fixture",
            "finish_reason": "stop",
            "parse_status": "valid",
            "usage": {"total_tokens": len(json.dumps(payload))},
        })
