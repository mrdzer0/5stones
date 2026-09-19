"""Order-independent reconciliation of facts extracted from multiple artifacts."""
from __future__ import annotations

import copy
import re
from collections import defaultdict
from typing import Any


LIST_CONTEXT_FIELDS = (
    "actors",
    "components",
    "entry_points",
    "data_involved",
    "external_systems",
    "critical_actions",
    "existing_controls",
)

SOURCE_PRIORITY = {"openapi": 0, "postman": 1, "har": 2}


def project_client_view(project: dict) -> dict:
    """Return project data without repeating bulky internal parser contributions."""
    view = copy.deepcopy(project)
    for source in view.get("artifact_sources") or []:
        if isinstance(source, dict):
            source.pop("contribution", None)
    view["canonical_operations"] = [
        {
            key: operation.get(key)
            for key in ("key", "method", "path", "service", "security_status", "coverage", "sources")
        }
        for operation in (view.get("canonical_operations") or [])
        if isinstance(operation, dict)
    ]
    return view


def unique_strings(values) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        text = " ".join(str(value or "").split())
        if not text or text.casefold() in seen:
            continue
        seen.add(text.casefold())
        result.append(text)
    return result


def canonical_auth_methods(values) -> list[str]:
    normalized = []
    for value in values or []:
        text = " ".join(str(value or "").split())
        key = text.casefold().replace("_", "").replace("-", "").replace(" ", "")
        if "bearer" in key or key == "jwt":
            normalized.append("Bearer token")
        elif "oauth2" in key or key == "oauth":
            normalized.append("OAuth 2.0")
        elif "apikey" in key:
            normalized.append("API key")
        elif text:
            normalized.append(text)
    return unique_strings(normalized)


def capture_manual_context(project: dict, *, legacy: bool = False) -> dict:
    """Snapshot user-entered facts so artifact recomputation never overwrites them."""
    existing = project.get("manual_context")
    if isinstance(existing, dict):
        return existing

    context = {field: list(project.get(field) or []) for field in LIST_CONTEXT_FIELDS}
    context["auth_method"] = str(project.get("auth_method") or "").strip()
    context["has_pii"] = bool(project.get("has_pii", False))
    if legacy and project.get("artifact_sources"):
        # Older builds mixed generated endpoints into manual input. Retain human-facing
        # surfaces such as "Web App", but discard machine-looking legacy API strings.
        context["entry_points"] = [
            value for value in context["entry_points"]
            if not _looks_like_generated_endpoint(value)
        ]
    project["manual_context"] = context
    return context


def _looks_like_generated_endpoint(value: Any) -> bool:
    text = str(value or "").strip()
    return (
        text.casefold() == "api"
        or bool(re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+/", text, re.I))
        or text.startswith("/")
        or text.startswith("{{")
    )


def active_artifact_sources(project: dict) -> list[dict]:
    return [
        source for source in (project.get("artifact_sources") or [])
        if isinstance(source, dict) and source.get("active", True) and isinstance(source.get("contribution"), dict)
    ]


def rebuild_project_from_artifacts(project: dict) -> dict:
    """Recompute all derived fields from active sources; upload order cannot change output."""
    manual = capture_manual_context(project, legacy=True)
    sources = sorted(
        active_artifact_sources(project),
        key=lambda source: (
            SOURCE_PRIORITY.get(source.get("artifact_type"), 9),
            str(source.get("filename") or "").casefold(),
            str(source.get("content_hash") or ""),
        ),
    )
    operations, conflicts = _merge_operations(sources)
    business_scenarios = _merge_business_scenarios(sources)

    contribution_fields = {
        "actors": "actors",
        "components": "components",
        "data_involved": "data_fields",
        "external_systems": "external_systems",
        "critical_actions": "critical_actions",
        "existing_controls": "existing_controls",
    }
    for project_field, parsed_field in contribution_fields.items():
        extracted = [
            value
            for source in sources
            for value in source["contribution"].get(parsed_field, [])
        ]
        project[project_field] = unique_strings([*(manual.get(project_field) or []), *extracted])

    project["entry_points"] = unique_strings([
        *(manual.get("entry_points") or []),
        *(operation["key"] for operation in operations),
    ])
    project["canonical_operations"] = operations
    project["business_scenarios"] = business_scenarios
    project["artifact_conflicts"] = conflicts
    project["extracted_data_flows"] = _merge_flows(sources)
    project["has_pii"] = bool(manual.get("has_pii")) or any(
        source["contribution"].get("has_pii") for source in sources
    )

    parsed_auth = canonical_auth_methods(
        method
        for source in sources
        for method in source["contribution"].get("auth_methods", [])
    )
    project["auth_method"] = manual.get("auth_method") or ", ".join(parsed_auth)
    project["artifact_summary"] = " ".join(
        source["contribution"].get("summary", "") for source in sources if source["contribution"].get("summary")
    )[:2000]
    project["artifacts"] = unique_strings(source.get("filename") for source in sources)
    project["artifact_evidence"] = [
        evidence
        for source in sources
        for evidence in (source.get("evidence_items") or [])
    ][-48:]

    source_types_by_operation = [set(assertion["artifact_type"] for assertion in op["sources"]) for op in operations]
    overlap_count = sum(1 for types in source_types_by_operation if {"openapi", "postman"}.issubset(types))
    project["artifact_inventory"] = {
        "artifact_count": len(sources),
        "operation_count": len(operations),
        "overlap_count": overlap_count,
        "conflict_count": len(conflicts),
        "scenario_count": sum(len(operation.get("scenarios") or []) for operation in operations),
        "business_scenario_count": len(business_scenarios),
        "source_types": sorted({source.get("artifact_type") for source in sources if source.get("artifact_type")}),
        "source_operation_counts": {
            source.get("artifact_type", "unknown"): sum(
                len(item["contribution"].get("operations") or [])
                for item in sources if item.get("artifact_type") == source.get("artifact_type")
            )
            for source in sources
        },
    }
    return project


def _merge_business_scenarios(sources: list[dict]) -> list[dict]:
    """Merge evidence-backed PRD use cases without turning them into API operations."""
    result = []
    seen = set()
    for source in sources:
        for item in source["contribution"].get("use_cases") or []:
            if not isinstance(item, dict):
                continue
            name = " ".join(str(item.get("name") or "").split())
            actor = " ".join(str(item.get("actor") or "").split())
            key = (name.casefold(), actor.casefold())
            if not name or not actor or key in seen:
                continue
            seen.add(key)
            result.append({
                **copy.deepcopy(item),
                "artifact_id": source.get("artifact_id"),
                "artifact_type": source.get("artifact_type"),
                "filename": source.get("filename"),
                "evidence_ref": f"artifact:{source.get('artifact_id')}:{item.get('evidence_locator') or 'use-case'}",
            })
    result.sort(key=lambda item: (str(item.get("actor") or "").casefold(), str(item.get("name") or "").casefold()))
    return result


def _merge_operations(sources: list[dict]) -> tuple[list[dict], list[dict]]:
    grouped: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
    for source in sources:
        for operation in source["contribution"].get("operations") or []:
            if isinstance(operation, dict) and operation.get("match_key"):
                grouped[operation["match_key"]].append((source, operation))

    merged_operations: list[dict] = []
    conflicts: list[dict] = []
    for match_key in sorted(grouped):
        assertions = sorted(
            grouped[match_key],
            key=lambda pair: (
                SOURCE_PRIORITY.get(pair[0].get("artifact_type"), 9),
                str(pair[0].get("filename") or "").casefold(),
            ),
        )
        preferred_source, preferred = assertions[0]
        source_records = []
        statuses = []
        for source, operation in assertions:
            status = operation.get("security_status") or "unknown"
            statuses.append(status)
            source_records.append({
                "artifact_id": source.get("artifact_id"),
                "artifact_type": source.get("artifact_type"),
                "filename": source.get("filename"),
                "locator": operation.get("locator"),
                "security_status": status,
            })

        explicit_statuses = unique_strings(status for status in statuses if status not in {"", "unknown"})
        security_status = explicit_statuses[0] if len(explicit_statuses) == 1 else (
            "conflict" if len(explicit_statuses) > 1 else "unknown"
        )
        if security_status == "conflict":
            conflicts.append({
                "operation_key": preferred.get("key"),
                "field": "security_status",
                "values": source_records,
                "message": "Artifacts disagree about whether this operation requires authentication.",
            })

        source_types = {record["artifact_type"] for record in source_records}
        if {"openapi", "postman"}.issubset(source_types):
            coverage = "contract_and_collection"
        elif "openapi" in source_types:
            coverage = "contract_only"
        elif "postman" in source_types:
            coverage = "collection_only"
        else:
            coverage = "single_source"

        merged_operations.append({
            "key": preferred.get("key"),
            "match_key": match_key,
            "method": preferred.get("method"),
            "path": preferred.get("path"),
            "service": preferred.get("service"),
            "operation_id": next((op.get("operation_id") for _, op in assertions if op.get("operation_id")), None),
            "summary": next((op.get("summary") for _, op in assertions if op.get("summary")), ""),
            "tags": unique_strings(tag for _, op in assertions for tag in (op.get("tags") or [])),
            "security_status": security_status,
            "auth_methods": canonical_auth_methods(method for _, op in assertions for method in (op.get("auth_methods") or [])),
            "auth_sources": unique_strings(
                source
                for _, op in assertions
                for source in (op.get("auth_sources") or [])
            ),
            "parameters": _unique_dicts(item for _, op in assertions for item in (op.get("parameters") or [])),
            "request_fields": unique_strings(field for _, op in assertions for field in (op.get("request_fields") or [])),
            "response_fields": unique_strings(field for _, op in assertions for field in (op.get("response_fields") or [])),
            "saved_response_examples": _unique_dicts(
                example
                for _, op in assertions
                for example in (op.get("saved_response_examples") or [])
            ),
            "unresolved_variable_refs": unique_strings(
                value
                for _, op in assertions
                for value in (op.get("unresolved_variable_refs") or [])
            ),
            "content_types": unique_strings(value for _, op in assertions for value in (op.get("content_types") or [])),
            "scenarios": _scenarios_with_sources(assertions),
            "coverage": coverage,
            "sources": source_records,
        })

    merged_operations.sort(key=lambda operation: (operation.get("service") or "", operation.get("path") or "", operation.get("method") or ""))
    return merged_operations, conflicts


def _unique_dicts(values) -> list[dict]:
    result = []
    seen = set()
    for value in values:
        if not isinstance(value, dict):
            continue
        key = tuple(sorted((str(k), str(v)) for k, v in value.items()))
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def _scenarios_with_sources(assertions: list[tuple[dict, dict]]) -> list[dict]:
    result = []
    for source, operation in assertions:
        for scenario_index, scenario in enumerate(operation.get("scenarios") or [], start=1):
            if not isinstance(scenario, dict):
                continue
            # Identically named requests can still represent separate positive/negative
            # cases. Preserve them and give each a stable source-local ordinal.
            item = {
                **scenario,
                "scenario_index": scenario_index,
                "artifact_id": source.get("artifact_id"),
                "filename": source.get("filename"),
            }
            result.append(item)
    return result


def _merge_flows(sources: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str, str], dict] = {}
    for source in sources:
        for flow in source["contribution"].get("data_flows") or []:
            if not isinstance(flow, dict):
                continue
            key = (
                str(flow.get("source") or "Unknown source"),
                str(flow.get("destination") or "Unknown destination"),
                str(flow.get("protocol") or "HTTPS"),
            )
            existing = grouped.setdefault(key, {
                "source": key[0],
                "destination": key[1],
                "protocol": key[2],
                "data": [],
                "artifact_ids": [],
                "evidence_type": "derived",
                "basis": flow.get("basis") or "Derived from active artifact operations.",
                "confidence": flow.get("confidence") or "Medium",
            })
            existing["data"] = unique_strings([*existing["data"], *(flow.get("data") or [])])[:24]
            existing["artifact_ids"] = unique_strings([*existing["artifact_ids"], source.get("artifact_id")])
    return [grouped[key] for key in sorted(grouped)]
