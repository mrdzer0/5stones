"""Bounded graph slices for STRIDE/LINDDUN provider calls."""
from __future__ import annotations

import asyncio
import json

from backend.services.ai_service import AnalysisResponseError, StructuredJSONResult
from backend.services.threat_validation_service import ThreatGenerationResult, parse_generation_payload
from backend.utils.redaction import redact_text

MAX_BATCHES = 8
FLOWS_PER_BATCH = 2
MAX_BATCH_OUTPUT_TOKENS = 2200


class ThreatGenerationProviderError(RuntimeError):
    """Provider failure with the batch manifest needed to explain the retry."""

    def __init__(self, message: str, *, metadata: dict):
        super().__init__(message)
        self.code = "provider_unavailable"
        self.response_metadata = metadata


def _fields(item: dict, names: tuple[str, ...]) -> dict:
    return {name: item[name] for name in names if item.get(name) not in (None, "", [], {})}


NODE_FIELDS = ("id", "name", "type", "scope", "ownership", "exposure", "zone_ids", "parent_process_id", "knowledge_status", "identity_key", "operator_control_party", "process_metadata", "evidence_refs")
FLOW_FIELDS = ("id", "source_id", "target_id", "name", "data_object_ids", "protocol", "interaction_kind", "authn", "authz", "boundary_crossings", "crossing_status", "evidence_refs")
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


def build_threat_batches(dfd_model: dict | None) -> tuple[list[dict], list[str]]:
    """Cover each flow once and report nodes not included within the call cap."""
    model = dfd_model if isinstance(dfd_model, dict) else {}
    flows = [item for item in (model.get("flows") or []) if isinstance(item, dict) and item.get("id")]
    nodes = [item for item in (model.get("nodes") or []) if isinstance(item, dict) and item.get("id")]
    data_objects = [item for item in (model.get("data_objects") or []) if isinstance(item, dict) and item.get("id")]
    zones = [item for item in (model.get("zones") or []) if isinstance(item, dict) and item.get("id")]
    boundaries = [item for item in (model.get("boundaries") or []) if isinstance(item, dict) and item.get("id")]
    groups = [flows[index:index + FLOWS_PER_BATCH] for index in range(0, len(flows), FLOWS_PER_BATCH)]
    connected_ids = {str(value) for flow in flows for value in (flow.get("source_id"), flow.get("target_id")) if value}
    orphans = [node for node in nodes if str(node["id"]) not in connected_ids]
    groups.extend([orphans[index:index + 4] for index in range(0, len(orphans), 4)])
    if not groups:
        groups = [[]]
    included_groups = groups[:MAX_BATCHES]
    batches = []
    visited_refs: set[str] = set()
    for index, group in enumerate(included_groups):
        group_flows = [item for item in group if item in flows]
        group_orphans = [item for item in group if item in orphans]
        node_ids = {str(value) for flow in group_flows for value in (flow.get("source_id"), flow.get("target_id")) if value}
        node_ids.update(str(item["id"]) for item in group_orphans)
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
                        "context": json.dumps(context, ensure_ascii=False, separators=(",", ":"))})

    all_refs = {str(item["id"]) for collection in (flows, nodes, data_objects, zones, boundaries) for item in collection}
    return batches, sorted(all_refs - visited_refs)


async def run_threat_batches(*, framework: str, batches: list[dict], deferred_refs: list[str],
                             system_prompt: str, prompt_prefix: str, prompt_suffix: str,
                             provider: dict, chat_complete_json) -> ThreatGenerationResult:
    """Run each bounded interaction and retain status/metadata for every call."""
    threats, coverage, records, warnings = [], [], [], []
    completed_refs: set[str] = set()
    first_error = None
    success_count = 0
    semaphore = asyncio.Semaphore(2)

    async def analyze_batch(batch: dict):
        prompt = f"{prompt_prefix}\nCANONICAL DFD INTERACTION {batch['batch_id']}:\n{batch['context']}\n{prompt_suffix}"
        record = {"batch_id": batch["batch_id"], "scope_refs": batch["scope_refs"],
                  "prompt_chars": len(prompt), "max_tokens": MAX_BATCH_OUTPUT_TOKENS}
        try:
            async with semaphore:
                response = await chat_complete_json(
                    system_prompt=system_prompt, user_prompt=prompt,
                    base_url=provider.get("base_url"), api_key=provider.get("api_key"),
                    model=provider.get("model"), max_tokens=MAX_BATCH_OUTPUT_TOKENS,
                    return_metadata=True,
                )
            metadata = response.metadata if isinstance(response, StructuredJSONResult) else {}
            payload = response.payload if isinstance(response, StructuredJSONResult) else response
            parsed = parse_generation_payload(payload, framework)
            record.update({"status": "valid_empty" if not parsed else "complete", "response_metadata": metadata,
                           "threat_count": len(parsed), "coverage_count": len(parsed.coverage)})
            return record, list(parsed), list(parsed.coverage), None
        except Exception as exc:
            record.update({"status": "invalid" if isinstance(exc, ValueError) else "unavailable",
                           "error_code": getattr(exc, "code", "provider_contract_invalid" if isinstance(exc, ValueError) else "provider_unavailable"),
                           "error": redact_text(str(exc))[:240], "response_metadata": getattr(exc, "response_metadata", {})})
            return record, [], [], exc

    for record, batch_threats, batch_coverage, error in await asyncio.gather(
        *(analyze_batch(batch) for batch in batches)
    ):
        records.append(record)
        if error is None:
            success_count += 1
            completed_refs.update(record["scope_refs"])
            threats.extend(batch_threats)
            coverage.extend(batch_coverage)
        else:
            if first_error is None:
                first_error = error
            warnings.append(f"{record['batch_id']}: {record['error_code']}")
            deferred_refs.extend(record["scope_refs"])
    deferred_refs = sorted(set(deferred_refs) - completed_refs)
    manifest = {"batch_count": len(records), "completed_count": success_count,
                "deferred_refs": deferred_refs, "batches": records}
    if not success_count:
        if first_error is not None and not isinstance(first_error, ValueError):
            raise ThreatGenerationProviderError(
                redact_text(str(first_error))[:240] or "Analysis provider was unavailable",
                metadata={"generation_manifest": manifest},
            ) from first_error
        raise AnalysisResponseError(
            "No threat batch produced a validated structured assessment.",
            code=getattr(first_error, "code", "provider_contract_invalid"), metadata={"generation_manifest": manifest},
        )
    if deferred_refs:
        warnings.append(f"{len(deferred_refs)} canonical references were deferred for retry")
    status = "partial" if deferred_refs or success_count != len(records) else ("valid_empty" if not threats else "complete")
    return ThreatGenerationResult(threats, coverage, assessment_status=status,
                                  response_shape="batched_object", warnings=warnings,
                                  response_metadata={"generation_manifest": manifest})
