"""Bounded graph slices for STRIDE/LINDDUN provider calls."""
from __future__ import annotations

import asyncio
import hashlib
import json
import time

from backend.services.ai_service import AnalysisResponseError, StructuredJSONResult
from backend.services.threat_validation_service import ThreatGenerationResult, parse_generation_payload
from backend.utils.redaction import redact_text

MAX_BATCHES = 32
FLOWS_PER_BATCH = 3
MAX_BATCH_OUTPUT_TOKENS = 4096
MAX_STAGE_SECONDS = 360
MAX_BATCH_SECONDS = 60
MAX_BATCH_RETRIES = 1
MAX_CONCURRENT_BATCHES = 2
MAX_BATCH_CONTEXT_CHARS = 10000
MAX_CANDIDATES_PER_BATCH = 3
COVERAGE_CATEGORIES = {
    "STRIDE": (
        "Spoofing", "Tampering", "Repudiation", "Information Disclosure",
        "Denial of Service", "Elevation of Privilege",
    ),
    "LINDDUN": (
        "Linking", "Identifying", "Non-repudiation", "Detecting",
        "Data Disclosure", "Unawareness & Unintervenability", "Non-compliance",
    ),
}


class ThreatGenerationProviderError(RuntimeError):
    """Provider failure with the batch manifest needed to explain the retry."""

    def __init__(self, message: str, *, metadata: dict, code: str = "provider_unavailable"):
        super().__init__(message)
        self.code = code
        self.response_metadata = metadata


class StageBudgetError(TimeoutError):
    code = "stage_timeout"


def _fields(item: dict, names: tuple[str, ...]) -> dict:
    return {name: item[name] for name in names if item.get(name) not in (None, "", [], {})}


NODE_FIELDS = ("id", "name", "type", "scope", "ownership", "exposure", "zone_ids", "parent_process_id", "knowledge_status", "identity_key", "operator_control_party", "process_metadata", "evidence_refs")
FLOW_FIELDS = ("id", "source_id", "target_id", "name", "data_object_ids", "protocol", "interaction_kind", "authn", "authz", "boundary_crossings", "crossing_status", "grounding_status", "grounding_reason", "endpoint_classification", "evidence_refs")
DATA_FIELDS = ("id", "name", "fields", "classification", "sensitivity", "purpose", "data_subjects", "identifiers", "direct_identifiers", "indirect_identifiers", "recipients", "linkability", "notice", "individual_control", "legal_basis", "evidence_refs")
ZONE_FIELDS = ("id", "name", "parent_zone_id", "ownership_group_id", "trust_assumptions", "knowledge_status", "evidence_refs")
BOUNDARY_FIELDS = ("id", "name", "types", "source_zone_ids", "target_zone_ids", "crossing_flow_ids", "status", "rationale", "evidence_refs")


def _bounded(value):
    if isinstance(value, str):
        return value[:200]
    if isinstance(value, list):
        return [_bounded(item) for item in value[:8]]
    if isinstance(value, dict):
        return {str(key): _bounded(item) for key, item in list(value.items())[:18]}
    return value


def _flow_context_size(flow: dict) -> int:
    """Estimate serialized flow cost before adding related DFD context."""
    return len(json.dumps(flow, ensure_ascii=False, separators=(",", ":")))


def _adaptive_flow_groups(flows: list[dict]) -> list[list[dict]]:
    """Pack bounded groups of simple flows and isolate oversized interactions.

    Each batch can cover up to ``FLOWS_PER_BATCH`` interactions. A complex flow
    is reduced to a smaller batch so its context does not crowd out adjacent
    interactions or exceed the prompt budget.
    """
    groups: list[list[dict]] = []
    index = 0
    while index < len(flows):
        current = []
        estimated = 0
        while index < len(flows) and len(current) < FLOWS_PER_BATCH:
            next_size = _flow_context_size(flows[index])
            if current and estimated + next_size > MAX_BATCH_CONTEXT_CHARS:
                break
            current.append(flows[index])
            estimated += next_size
            index += 1
        groups.append(current)
    return groups


def _error_details(exc: Exception) -> tuple[str, str, bool]:
    """Return stable state, diagnostic kind, and whether one retry is safe."""
    code = str(getattr(exc, "code", "") or "").casefold()
    exception_name = type(exc).__name__.casefold()
    status_code = getattr(exc, "status_code", None)
    if code in {"connect_timeout", "connection_timeout"} or "connecttimeout" in exception_name:
        return "timed_out", "connect_timeout", True
    if code in {"read_timeout", "response_timeout"} or "readtimeout" in exception_name:
        return "timed_out", "read_timeout", True
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)) or code in {"stage_timeout", "timeout"}:
        return "timed_out", "application_deadline", True
    if status_code == 429 or code in {"rate_limit", "rate_limited", "too_many_requests"}:
        return "unavailable", "rate_limited", True
    if code in {"truncated_json", "truncated_response"}:
        return "invalid", "truncated", True
    if code in {"malformed_json", "non_json_response", "empty_response", "empty_choices"}:
        return "invalid", "malformed", True
    if code in {"provider_contract_invalid", "structured_output_invalid"}:
        return "invalid", "schema_invalid", False
    if isinstance(exc, (ConnectionError, OSError)):
        return "unavailable", "provider_unavailable", True
    if isinstance(exc, ValueError):
        return "invalid", "schema_invalid", False
    return "unavailable", "provider_unavailable", True


def _safe_response_metadata(value: object) -> dict:
    """Keep provider audit fields without persisting raw response content."""
    if not isinstance(value, dict):
        return {}
    safe = {}
    for key in (
        "provider_attempts", "format_retry_count", "retry_reasons", "finish_reason",
        "usage", "parse_status", "response_shape", "truncation_suspected",
        "error_code", "latency_ms", "http_status", "model", "configured_model",
        "response_model", "model_source", "redacted_response_hash",
    ):
        if key not in value:
            continue
        item = value[key]
        if key == "usage" and isinstance(item, dict):
            safe[key] = {
                str(name): number for name, number in item.items()
                if isinstance(number, (int, float))
            }
        elif key == "retry_reasons" and isinstance(item, list):
            safe[key] = [str(reason)[:80] for reason in item[:10]]
        elif isinstance(item, (str, int, float, bool)) or item is None:
            safe[key] = str(item)[:240] if isinstance(item, str) else item
    return safe


def _batch_input_fingerprint(
    *,
    framework: str,
    system_prompt: str,
    prompt: str,
    batch: dict,
    provider: dict,
    output_budget: int,
) -> str:
    """Hash the effective batch input without storing prompt/source text."""
    payload = {
        "framework": framework,
        "system_prompt": system_prompt,
        "prompt": prompt,
        "batch_id": batch.get("batch_id"),
        "scope_refs": sorted(str(ref) for ref in (batch.get("scope_refs") or [])),
        "flow_refs": sorted(str(ref) for ref in (batch.get("flow_refs") or [])),
        "context": str(batch.get("context") or ""),
        "model": provider.get("model"),
        "base_url": provider.get("base_url"),
        "output_budget": output_budget,
    }
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_threat_batches(dfd_model: dict | None) -> tuple[list[dict], list[str]]:
    """Cover canonical interactions without retrying isolated graph context.

    Threat candidates require one primary flow. Nodes, data objects, zones, or
    boundaries that are not attached to a flow are DFD completeness gaps; they
    are not provider work and must never create a perpetual partial/retry loop.
    """
    model = dfd_model if isinstance(dfd_model, dict) else {}
    all_flows = [item for item in (model.get("flows") or []) if isinstance(item, dict) and item.get("id")]
    primary_ids = {
        str(value) for value in (model.get("primary_interaction_ids") or []) if value
    }
    primary_scope_declared = "primary_interaction_ids" in model
    flows = [
        item for item in all_flows
        if item.get("grounding_status", "grounded") != "deferred"
        and (not primary_scope_declared or str(item.get("id")) in primary_ids)
    ]
    nodes = [item for item in (model.get("nodes") or []) if isinstance(item, dict) and item.get("id")]
    data_objects = [item for item in (model.get("data_objects") or []) if isinstance(item, dict) and item.get("id")]
    zones = [item for item in (model.get("zones") or []) if isinstance(item, dict) and item.get("id")]
    boundaries = [item for item in (model.get("boundaries") or []) if isinstance(item, dict) and item.get("id")]
    groups = _adaptive_flow_groups(flows)
    if not groups:
        groups = [[]]
    included_groups = groups[:MAX_BATCHES]
    batches = []
    visited_refs: set[str] = set()
    for index, group in enumerate(included_groups):
        group_flows = [item for item in group if item in flows]
        node_ids = {str(value) for flow in group_flows for value in (flow.get("source_id"), flow.get("target_id")) if value}
        selected_nodes = [item for item in nodes if str(item["id"]) in node_ids]
        data_ids = {str(value) for flow in group_flows for value in (flow.get("data_object_ids") or [])}
        selected_data = [item for item in data_objects if str(item["id"]) in data_ids]
        zone_ids = {str(value) for node in selected_nodes for value in (node.get("zone_ids") or [])}
        selected_zones = [item for item in zones if str(item["id"]) in zone_ids]
        flow_ids = {str(item["id"]) for item in group_flows}
        boundary_ids = {str(value) for flow in group_flows for value in (flow.get("boundary_crossings") or [])}
        selected_boundaries = [item for item in boundaries if str(item["id"]) in boundary_ids or flow_ids.intersection(item.get("crossing_flow_ids") or [])]
        refs = sorted({*flow_ids, *node_ids, *data_ids, *zone_ids, *(str(item["id"]) for item in selected_boundaries)})
        visited_refs.update(refs)
        context = {
            "model_id": model.get("id"),
            "revision": model.get("revision"),
            "semantic_hash": model.get("semantic_hash"),
            "batch": index + 1,
            "batch_count": min(len(groups), MAX_BATCHES),
            "nodes": [_bounded(_fields(item, NODE_FIELDS)) for item in selected_nodes],
            "flows": [_bounded(_fields(item, FLOW_FIELDS)) for item in group_flows],
            "data_objects": [_bounded(_fields(item, DATA_FIELDS)) for item in selected_data],
            "zones": [_bounded(_fields(item, ZONE_FIELDS)) for item in selected_zones],
            "boundaries": [_bounded(_fields(item, BOUNDARY_FIELDS)) for item in selected_boundaries],
            "stores": {key: _bounded(value) for key, value in (model.get("stores") or {}).items() if key in node_ids},
        }
        batches.append({"batch_id": f"batch-{index + 1}", "scope_refs": refs,
                        "flow_refs": sorted(flow_ids),
                        "flow_count": len(group_flows),
                        "estimated_context_chars": len(json.dumps(context, ensure_ascii=False, separators=(",", ":"))),
                        "context": json.dumps(context, ensure_ascii=False, separators=(",", ":"))})

    all_refs = {str(item["id"]) for collection in (flows, nodes, data_objects, zones, boundaries) for item in collection}
    all_flow_refs = {str(item["id"]) for item in all_flows}
    visited_flow_refs = {ref for ref in visited_refs if ref in all_flow_refs}
    interaction_context_refs: set[str] = set(all_flow_refs)
    node_by_id = {str(item["id"]): item for item in nodes}
    for flow in all_flows:
        flow_id = str(flow["id"])
        endpoint_ids = {
            str(value) for value in (flow.get("source_id"), flow.get("target_id")) if value
        }
        interaction_context_refs.update(endpoint_ids)
        interaction_context_refs.update(str(value) for value in (flow.get("data_object_ids") or []))
        for node_id in endpoint_ids:
            interaction_context_refs.update(str(value) for value in (node_by_id.get(node_id, {}).get("zone_ids") or []))
        interaction_context_refs.update(str(value) for value in (flow.get("boundary_crossings") or []))
        interaction_context_refs.update(
            str(boundary["id"])
            for boundary in boundaries
            if flow_id in {str(value) for value in (boundary.get("crossing_flow_ids") or [])}
        )
    context_gap_refs = sorted(all_refs - interaction_context_refs)
    if batches:
        batches[0]["context_gap_refs"] = context_gap_refs
    # Only grounded primary flow IDs are retryable generation work. Deferred or
    # inventory-only interactions remain visible through the DFD quality gate.
    deferred_primary = sorted(
        str(item["id"]) for item in all_flows
        if item.get("grounding_status", "grounded") == "deferred"
        or (primary_scope_declared and str(item["id"]) not in primary_ids)
    )
    return batches, sorted(set(all_flow_refs - visited_flow_refs) | set(deferred_primary))


async def run_threat_batches(*, framework: str, batches: list[dict], deferred_refs: list[str],
                             system_prompt: str, prompt_prefix: str, prompt_suffix: str,
                             provider: dict, chat_complete_json,
                             prior_manifest: dict | None = None) -> ThreatGenerationResult:
    """Run each bounded interaction and retain status/metadata for every call."""
    threats, coverage, records, warnings = [], [], [], []
    completed_refs: set[str] = set()
    first_error = None
    success_count = 0
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_BATCHES)
    output_budget = min(MAX_BATCH_OUTPUT_TOKENS, int(provider.get("max_tokens") or MAX_BATCH_OUTPUT_TOKENS))
    stage_started = time.monotonic()
    cached_batches = {}
    if isinstance(prior_manifest, dict) and prior_manifest.get("framework") == framework:
        cached_batches = {
            str(item.get("batch_id")): item
            for item in (prior_manifest.get("batches") or [])
            if isinstance(item, dict)
            and item.get("status") in {"valid", "valid_empty"}
            and isinstance(item.get("validated_output"), dict)
            and isinstance(item["validated_output"].get("threats"), list)
            and isinstance(item["validated_output"].get("coverage"), list)
        }

    async def analyze_batch(batch: dict):
        batch_flow_refs = list(batch.get("flow_refs") or [
            ref for ref in (batch.get("scope_refs") or []) if str(ref).startswith("flow-")
        ])
        categories = COVERAGE_CATEGORIES.get(framework, ())
        required_coverage_count = len(batch_flow_refs) * len(categories)
        category_list = ", ".join(categories)
        prompt = (f"{prompt_prefix}\nCANONICAL DFD INTERACTION {batch['batch_id']}:\n{batch['context']}\n"
                  f"Return at most {MAX_CANDIDATES_PER_BATCH} high-priority threats and exactly "
                  f"{required_coverage_count} coverage rows: one row for every listed flow and every framework "
                  f"category ({category_list}). Never omit a flow/category pair. Mark a pair "
                  "reviewed_no_candidate only after considering it; use insufficient_information when evidence "
                  "does not support a decision. Canonical flows are applicable assessment targets. Keep each "
                  "coverage reason/rationale concise and free-text fields brief. Consider every listed flow and "
                  "distribute findings across distinct supported flows before duplicating one flow. "
                  f"{prompt_suffix}")
        input_fingerprint = _batch_input_fingerprint(
            framework=framework, system_prompt=system_prompt, prompt=prompt,
            batch={**batch, "flow_refs": batch_flow_refs}, provider=provider,
            output_budget=output_budget,
        )
        record = {"batch_id": batch["batch_id"], "scope_refs": batch["scope_refs"],
                  "flow_refs": batch_flow_refs,
                  "flow_count": len(batch_flow_refs),
                  "prompt_chars": len(prompt),
                  "estimated_input_tokens": (len(system_prompt) + len(prompt) + 3) // 4,
                  "max_tokens": output_budget,
                  "max_batch_retries": MAX_BATCH_RETRIES,
                  "input_fingerprint": input_fingerprint,
                  "idempotency_key": input_fingerprint,
                  "cache_hit": False,
                  "attempts": []}
        started = time.monotonic()
        try:
            if not record["flow_refs"]:
                record.update({"status": "valid_empty", "assessment_status": "valid_empty", "response_metadata": {"provider_call": "skipped_no_interactions"},
                               "threat_count": 0, "coverage_count": 0, "prompt_chars": 0})
                return record, [], [], None
            cached = cached_batches.get(str(batch.get("batch_id")))
            if cached and cached.get("input_fingerprint") == record["input_fingerprint"]:
                cached_output = cached["validated_output"]
                cached_metadata = _safe_response_metadata(cached.get("response_metadata"))
                cached_metadata["cache_hit"] = True
                cached_attempts = [
                    dict(item) for item in (cached.get("attempts") or []) if isinstance(item, dict)
                ]
                cached_threats = [
                    dict(item) for item in cached_output.get("threats", []) if isinstance(item, dict)
                ]
                cached_coverage = [
                    dict(item) for item in cached_output.get("coverage", []) if isinstance(item, dict)
                ]
                record.update({
                    "status": cached.get("status"),
                    "assessment_status": cached.get("assessment_status") or (
                        "valid_empty" if not cached_threats else "complete"
                    ),
                    "response_metadata": cached_metadata,
                    "threat_count": len(cached_threats),
                    "coverage_count": len(cached_coverage),
                    "attempt_count": cached.get("attempt_count", len(cached_attempts)),
                    "retry_count": cached.get("retry_count", 0),
                    "attempts": cached_attempts,
                    "cache_hit": True,
                    "cached_from_batch_id": cached.get("batch_id"),
                    "validated_output": {
                        "threats": cached_threats,
                        "coverage": cached_coverage,
                    },
                })
                return record, cached_threats, cached_coverage, None
            last_error = None
            for attempt in range(MAX_BATCH_RETRIES + 1):
                attempt_started = time.monotonic()
                try:
                    remaining = MAX_STAGE_SECONDS - (time.monotonic() - stage_started)
                    if remaining <= 0:
                        raise StageBudgetError("Threat stage exceeded its total budget")
                    async with semaphore:
                        response = await asyncio.wait_for(chat_complete_json(
                            system_prompt=system_prompt, user_prompt=prompt,
                            base_url=provider.get("base_url"), api_key=provider.get("api_key"),
                            model=provider.get("model"), max_tokens=output_budget,
                            return_metadata=True, max_format_retries=1,
                        ), timeout=min(MAX_BATCH_SECONDS, remaining))
                    metadata = _safe_response_metadata(
                        response.metadata if isinstance(response, StructuredJSONResult) else {}
                    )
                    payload = response.payload if isinstance(response, StructuredJSONResult) else response
                    parsed = parse_generation_payload(payload, framework)
                    batch_threats = []
                    for raw in parsed:
                        candidate = dict(raw)
                        # Trusted application metadata lets the validator reject
                        # a primary interaction invented outside this graph slice.
                        candidate["generation_scope_flow_refs"] = list(record["flow_refs"])
                        batch_threats.append(candidate)
                    record.update({
                        "status": "valid_empty" if not parsed else "valid",
                        "assessment_status": "valid_empty" if not parsed else "complete",
                        "response_metadata": metadata,
                        "threat_count": len(parsed),
                        "coverage_count": len(parsed.coverage),
                        "attempt_count": attempt + 1,
                        "retry_count": attempt,
                    })
                    record["attempts"].append({
                        "attempt": attempt + 1,
                        "status": record["status"],
                        "duration_seconds": round(time.monotonic() - attempt_started, 3),
                        "response_metadata": metadata,
                    })
                    record["validated_output"] = {
                        "threats": batch_threats,
                        "coverage": list(parsed.coverage),
                    }
                    return record, batch_threats, list(parsed.coverage), None
                except Exception as raw_error:
                    exc = raw_error
                    if isinstance(exc, asyncio.TimeoutError):
                        exc = StageBudgetError(f"Threat batch exceeded {MAX_BATCH_SECONDS}s provider budget")
                    state, error_kind, retryable = _error_details(exc)
                    error_code = getattr(exc, "code", None) or error_kind
                    error_metadata = _safe_response_metadata(getattr(exc, "response_metadata", {}))
                    record["attempts"].append({
                        "attempt": attempt + 1,
                        "status": state,
                        "error_kind": error_kind,
                        "error_code": error_code,
                        "duration_seconds": round(time.monotonic() - attempt_started, 3),
                        "response_metadata": error_metadata,
                    })
                    last_error = exc
                    if not retryable or attempt >= MAX_BATCH_RETRIES:
                        record.update({
                            "status": state,
                            "error_kind": error_kind,
                            "error_code": error_code,
                            "error": redact_text(str(exc))[:240],
                            "response_metadata": error_metadata,
                            "attempt_count": attempt + 1,
                            "retry_count": attempt,
                        })
                        return record, [], [], exc
            return record, [], [], last_error
        finally:
            record["duration_seconds"] = round(time.monotonic() - started, 3)

    tasks = [asyncio.create_task(analyze_batch(batch)) for batch in batches]
    done, pending = await asyncio.wait(tasks, timeout=MAX_STAGE_SECONDS)
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    results = []
    for batch, task in zip(batches, tasks):
        if task in done:
            results.append(task.result())
        else:
            exc = StageBudgetError(f"Threat stage exceeded {MAX_STAGE_SECONDS}s total budget")
            results.append(({
                "batch_id": batch["batch_id"], "scope_refs": batch["scope_refs"],
                "flow_refs": list(batch.get("flow_refs") or [
                    ref for ref in (batch.get("scope_refs") or []) if str(ref).startswith("flow-")
                ]),
                "status": "timed_out", "assessment_status": "partial",
                "error_kind": "application_deadline", "error_code": exc.code, "error": str(exc),
                "prompt_chars": 0, "max_tokens": output_budget,
                "max_batch_retries": MAX_BATCH_RETRIES,
                "attempt_count": 0, "retry_count": 0, "attempts": [],
                "duration_seconds": MAX_STAGE_SECONDS,
            }, [], [], exc))
    context_gap_refs = sorted({
        str(ref) for batch in batches for ref in (batch.get("context_gap_refs") or [])
    })
    for record, batch_threats, batch_coverage, error in results:
        records.append(record)
        retryable_refs = list(record.get("flow_refs") or [
            ref for ref in (record.get("scope_refs") or []) if str(ref).startswith("flow-")
        ])
        if error is None:
            success_count += 1
            completed_refs.update(retryable_refs)
            threats.extend(batch_threats)
            coverage.extend(batch_coverage)
        else:
            if first_error is None:
                first_error = error
            warnings.append(f"{record['batch_id']}: {record['error_code']}")
            deferred_refs.extend(retryable_refs)
    deferred_refs = sorted(set(deferred_refs) - completed_refs)
    manifest = {"framework": framework, "batch_count": len(records), "completed_count": success_count,
                "max_batches": MAX_BATCHES, "flows_per_batch": FLOWS_PER_BATCH,
                "concurrency": MAX_CONCURRENT_BATCHES, "max_batch_retries": MAX_BATCH_RETRIES,
                "stage_budget_seconds": MAX_STAGE_SECONDS, "batch_budget_seconds": MAX_BATCH_SECONDS,
                "output_budget_tokens": output_budget,
                "cache_hits": sum(1 for record in records if record.get("cache_hit")),
                "deferred_refs": deferred_refs, "non_interaction_refs": context_gap_refs,
                "batches": records}
    if not success_count:
        if first_error is not None and not isinstance(first_error, ValueError):
            raise ThreatGenerationProviderError(
                redact_text(str(first_error))[:240] or "Analysis provider was unavailable",
                metadata={"generation_manifest": manifest},
                code=getattr(first_error, "code", "provider_unavailable"),
            ) from first_error
        raise AnalysisResponseError(
            "No threat batch produced a validated structured assessment.",
            code=getattr(first_error, "code", "provider_contract_invalid"), metadata={"generation_manifest": manifest},
        )
    if deferred_refs:
        warnings.append(f"{len(deferred_refs)} canonical DFD interactions were deferred for retry")
    if context_gap_refs:
        warnings.append(
            f"{len(context_gap_refs)} non-interaction DFD references remain graph completeness gaps; "
            "they are not provider retry work"
        )
    status = "partial" if deferred_refs or success_count != len(records) else ("valid_empty" if not threats else "complete")
    return ThreatGenerationResult(threats, coverage, assessment_status=status,
                                  response_shape="batched_object", warnings=warnings,
                                  response_metadata={"generation_manifest": manifest})
