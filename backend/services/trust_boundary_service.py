"""Grounded trust-zone and boundary modeling.

Topology is built deterministically from declared actors, ingress points, and
evidenced flows. AI is intentionally not allowed to invent entities or edges.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any


TRUST_MODEL_VERSION = "grounded-v2"
TRUST_BOUNDARY_REVIEW_STATUSES = {"Candidate", "Confirmed", "Rejected"}
BOUNDARY_TYPES = {"network", "identity", "privilege", "tenant", "organization", "unknown"}
ENTITY_SCOPES = {"in_scope", "external_dependency", "unknown"}
ENTITY_OWNERSHIPS = {"organization", "customer", "vendor", "shared", "unknown"}
ENTITY_EXPOSURES = {"internet_facing", "private", "local", "unknown"}


def _unique_strings(values) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        text = " ".join(str(value or "").split())
        if not text or text.casefold() in seen:
            continue
        seen.add(text.casefold())
        result.append(text)
    return result


def _stable_id(prefix: str, *values: Any) -> str:
    raw = "|".join(str(value or "").strip().casefold() for value in values)
    return f"{prefix}-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]}"


def _is_operation_entrypoint(value: Any) -> bool:
    return bool(re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+/", str(value or "").strip(), re.I))


def _display_label(value: Any) -> str:
    text = " ".join(str(value or "").split())
    if text.casefold() == "api gateway":
        return "API Gateway"
    if text.casefold() == "user":
        return "User"
    return text


def _logical_component_label(value: Any) -> str:
    display = _display_label(value)
    if display.casefold() in {".well known api", ".well-known api", "api api"}:
        return "Application API"
    return display


def _entity_zone(entity_type: str, label: str) -> tuple[str, str]:
    lowered = label.casefold()
    if entity_type == "actor":
        if "admin" in lowered:
            return "external-privileged", "Privileged External"
        if any(token in lowered for token in ("anonymous", "unauthenticated", "public", "attacker")):
            return "external", "Untrusted"
        return "external", "Low Trust"
    if entity_type == "external_system":
        return "external-dependency", "External Dependency"
    if entity_type == "data_store":
        return "data", "Sensitive Internal Store"
    return "application", "Internal Trusted"


def _entity_type(label: str, declared_type: str = "") -> str:
    if declared_type:
        return declared_type
    lowered = label.casefold()
    if any(token in lowered for token in ("database", " db", "storage", "data store")):
        return "data_store"
    return "component"


def _identity_tokens(label: str) -> tuple[str, ...]:
    """Compare explicit names without treating a shared technology as identity."""
    ignored = {"database", "db", "with", "python"}
    return tuple(sorted(token for token in re.findall(r"[a-z0-9]+", label.casefold()) if token not in ignored))


def _same_entity_name(left: str, right: str) -> bool:
    if left.casefold() == right.casefold():
        return True
    left_tokens, right_tokens = _identity_tokens(left), _identity_tokens(right)
    if len(left_tokens) >= 2 and left_tokens == right_tokens:
        return True
    # A parenthesized technology list may elaborate a declared component.
    # Require the same base name and the same first technology when both have
    # details; mere token overlap (e.g. two services using React) is not enough.
    left_base, _, left_detail = left.partition("(")
    right_base, _, right_detail = right.partition("(")
    base = _identity_tokens(left_base)
    if len(base) < 2 or base != _identity_tokens(right_base):
        return False
    left_first = _identity_tokens(left_detail.split(",", 1)[0])
    right_first = _identity_tokens(right_detail.split(",", 1)[0])
    return not left_first or not right_first or left_first == right_first


def _entity_metadata_index(project: dict) -> dict[str, dict]:
    """Read explicit entity classifications without deriving security facts from labels."""
    manual = project.get("manual_context") if isinstance(project.get("manual_context"), dict) else {}
    raw = project.get("entity_metadata") or manual.get("entity_metadata") or {}
    entries = raw.items() if isinstance(raw, dict) else (
        (item.get("name") or item.get("label"), item)
        for item in (raw or []) if isinstance(item, dict)
    )
    result = {}
    for label, metadata in entries:
        if label and isinstance(metadata, dict):
            result[str(label).casefold()] = metadata
    return result


def _zone_metadata_index(project: dict) -> dict[str, dict]:
    """Normalize optional nested-zone metadata to stable unprefixed zone keys."""
    raw = project.get("zone_metadata") or project.get("trust_zones") or []
    if isinstance(raw, dict):
        entries = [dict(value, id=key) if isinstance(value, dict) else {"id": key} for key, value in raw.items()]
    else:
        entries = [item for item in raw if isinstance(item, dict)]
    result = {}
    for item in entries:
        zone_id = str(item.get("id") or item.get("zone_id") or "").strip()
        if not zone_id:
            continue
        key = zone_id.removeprefix("zone-")
        normalized = dict(item)
        normalized["id"] = key
        parent = str(normalized.get("parent_zone_id") or normalized.get("parentZoneId") or "").strip()
        normalized["parent_zone_id"] = parent.removeprefix("zone-") if parent else None
        result[key] = normalized
    return result


def _effective_zone_ids(zone_id: str, zone_metadata: dict[str, dict]) -> set[str]:
    members = set()
    current = str(zone_id or "").removeprefix("zone-")
    visited = set()
    while current and current not in visited:
        visited.add(current)
        members.add(current)
        current = str(zone_metadata.get(current, {}).get("parent_zone_id") or "").removeprefix("zone-")
    return members


def _is_zone_transition(source_zone: str, destination_zone: str, zone_metadata: dict[str, dict]) -> bool:
    source_members = _effective_zone_ids(source_zone, zone_metadata)
    destination_members = _effective_zone_ids(destination_zone, zone_metadata)
    shared = source_members & destination_members
    return bool((source_members - shared) and (destination_members - shared))


def _explicit_boundary_types(*sources: dict | None) -> list[str]:
    values = []
    for source in sources:
        if not isinstance(source, dict):
            continue
        raw = source.get("boundary_types") or source.get("boundaryTypes") or source.get("boundary_type")
        if isinstance(raw, str):
            raw = [raw]
        values.extend(str(value).strip().casefold() for value in (raw or []))
    normalized = _unique_strings(values)
    typed = [value for value in normalized if value in BOUNDARY_TYPES and value != "unknown"]
    return typed or ["unknown"]


def _boundary_metadata_for_flow(project: dict, flow: dict) -> list[dict]:
    raw = project.get("boundary_metadata") or []
    if isinstance(raw, dict):
        raw = [dict(value, boundary_id=key) if isinstance(value, dict) else {"boundary_id": key} for key, value in raw.items()]
    source = str(flow.get("source") or "").casefold()
    destination = str(flow.get("destination") or "").casefold()
    flow_id = str(flow.get("flow_id") or "")
    matched = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        flow_ids = {str(value) for value in (item.get("flow_ids") or item.get("crossing_flow_ids") or [])}
        item_source = str(item.get("source") or "").casefold()
        item_destination = str(item.get("destination") or "").casefold()
        if (
            flow_id in flow_ids
            or (item_source and item_destination and item_source == source and item_destination == destination)
        ):
            matched.append(item)
    return matched


def _composite_external_endpoint(label: str, external_systems: list[str]) -> bool:
    base, separator, detail = label.partition("(")
    if not separator or not re.search(r"\b(?:apis?|providers?)\b", base, re.I):
        return False
    detail_tokens = set(_identity_tokens(detail))
    return any(set(_identity_tokens(external)) <= detail_tokens for external in external_systems if _identity_tokens(external))


def build_entity_registry(project: dict, flows: list[dict] | None = None) -> dict[str, dict]:
    """Build the allowlist of entities that boundary results may reference."""
    manual = project.get("manual_context") if isinstance(project.get("manual_context"), dict) else {}
    metadata_index = _entity_metadata_index(project)
    zone_metadata = _zone_metadata_index(project)
    registry: dict[str, dict] = {}
    external_systems = [str(value) for value in (project.get("external_systems") or []) if value]
    type_rank = {"component": 0, "ingress": 1, "actor": 2, "data_store": 3, "external_system": 3}

    def add(label: Any, entity_type: str, source: str, locator: str, confidence: str):
        display = _display_label(label)
        if not display:
            return
        matches = [key for key, item in registry.items() if _same_entity_name(display, item["name"])]
        key = matches[0] if len(matches) == 1 else display.casefold()
        if entity_type == "component" and _composite_external_endpoint(display, external_systems):
            entity_type = "external_system"
        metadata = metadata_index.get(display.casefold(), {})
        if not metadata:
            metadata = next(
                (value for label, value in metadata_index.items() if _same_entity_name(display, label)),
                {},
            )
        inferred_zone_id, trust_level = _entity_zone(entity_type, display)
        explicit_zone_id = str(metadata.get("zone_id") or metadata.get("trust_zone_id") or "").strip().removeprefix("zone-")
        zone_id = explicit_zone_id or inferred_zone_id
        explicit_evidence_refs = _unique_strings(metadata.get("evidence_refs") or metadata.get("evidence") or [])
        record = registry.setdefault(key, {
            "entity_id": _stable_id("entity", display),
            "name": display,
            "entity_type": entity_type,
            "zone_id": zone_id,
            "trust_level": trust_level,
            "scope": "unknown",
            "ownership": "unknown",
            "exposure": "unknown",
            "operator_control_party": None,
            "zone_parent_id": zone_metadata.get(zone_id, {}).get("parent_zone_id"),
            "zone_metadata_source": "explicit" if explicit_zone_id or zone_id in zone_metadata else "inferred",
            "confidence": confidence,
            "evidence_refs": explicit_evidence_refs,
        })
        record["evidence_refs"] = _unique_strings([*record["evidence_refs"], f"{source}:{locator}"])
        if type_rank.get(entity_type, 0) > type_rank.get(record["entity_type"], 0):
            record.update(entity_type=entity_type, zone_id=zone_id, trust_level=trust_level)
        if source != "flow" and record["name"] != display and type_rank.get(entity_type, 0) >= type_rank.get(record["entity_type"], 0):
            record["name"] = display
            record["entity_id"] = _stable_id("entity", display)
        for field, allowed in (
            ("scope", ENTITY_SCOPES),
            ("ownership", ENTITY_OWNERSHIPS),
            ("exposure", ENTITY_EXPOSURES),
        ):
            value = str(metadata.get(field) or "").strip().casefold()
            if value in allowed:
                record[field] = value
        operator = str(metadata.get("operator_control_party") or metadata.get("operatorControlParty") or "").strip()
        if operator:
            record["operator_control_party"] = operator
        if explicit_zone_id or zone_id in zone_metadata:
            record["zone_parent_id"] = zone_metadata.get(zone_id, {}).get("parent_zone_id")
            record["zone_metadata_source"] = "explicit"
            record["evidence_refs"] = _unique_strings([*record["evidence_refs"], *explicit_evidence_refs])
        if confidence == "High":
            record["confidence"] = "High"

    actors = manual.get("actors") or project.get("actors") or []
    for index, actor in enumerate(actors):
        add(actor, "actor", "manual", f"actors[{index}]", "High" if manual.get("actors") else "Medium")

    entry_points = manual.get("entry_points") or []
    for index, entry_point in enumerate(entry_points):
        if not _is_operation_entrypoint(entry_point):
            add(entry_point, "ingress", "manual", f"entry_points[{index}]", "High")

    manual_components = {str(value).casefold() for value in (manual.get("components") or [])}
    for index, component in enumerate(project.get("components") or []):
        source = "manual" if str(component).casefold() in manual_components else "derived"
        confidence = "High" if source == "manual" else "Medium"
        label = component if source == "manual" else _logical_component_label(component)
        add(label, _entity_type(str(label)), source, f"components[{index}]", confidence)

    manual_external = {str(value).casefold() for value in (manual.get("external_systems") or [])}
    for index, external in enumerate(project.get("external_systems") or []):
        confidence = "High" if str(external).casefold() in manual_external else "Medium"
        add(external, "external_system", "manual" if confidence == "High" else "derived", f"external_systems[{index}]", confidence)

    for flow in flows or []:
        source_type = flow.get("source_entity_type") or "actor"
        destination_type = flow.get("destination_entity_type") or "ingress"
        add(flow.get("source"), source_type, "flow", flow.get("flow_id", "unknown"), flow.get("confidence", "Low"))
        add(flow.get("destination"), destination_type, "flow", flow.get("flow_id", "unknown"), flow.get("confidence", "Low"))
    return {item["name"].casefold(): item for item in registry.values()}


def build_grounded_data_flows(project: dict) -> list[dict]:
    """Create data flows without asserting undocumented deployment topology."""
    manual = project.get("manual_context") if isinstance(project.get("manual_context"), dict) else {}
    canonical_operations = project.get("canonical_operations") or []
    extracted_flows = [flow for flow in (project.get("extracted_data_flows") or []) if isinstance(flow, dict)]

    if canonical_operations:
        actors = manual.get("actors") or project.get("actors") or ["External API client"]
        manual_surfaces = [
            value for value in (manual.get("entry_points") or [])
            if value and not _is_operation_entrypoint(value)
        ]
        source = _display_label(actors[0] if actors else "External API client")
        destination = _display_label(manual_surfaces[0] if manual_surfaces else f"{project.get('name') or 'Application'} API")
        artifact_ids = _unique_strings(
            artifact_id
            for flow in extracted_flows
            for artifact_id in (flow.get("artifact_ids") or [])
        )
        data = _unique_strings(
            field for flow in extracted_flows for field in (flow.get("data") or [])
        )[:24]
        evidence_refs = [
            *(f"artifact:{artifact_id}" for artifact_id in artifact_ids),
            *(f"manual:actors[{index}]" for index, _ in enumerate(actors[:1])),
        ]
        if manual_surfaces:
            evidence_refs.append("manual:entry_points[0]")
        confidence = "Medium" if manual_surfaces else "Low"
        flow_id = _stable_id("flow", source, destination, "api-ingress")
        return [{
            "flow_id": flow_id,
            "source": source,
            "destination": destination,
            "source_entity_type": "actor",
            "destination_entity_type": "ingress",
            "protocol": "HTTP(S)",
            "data": data or ["API request and response data"],
            "operation_count": len(canonical_operations),
            "logical_destinations": _unique_strings(
                _logical_component_label(operation.get("service"))
                for operation in canonical_operations if isinstance(operation, dict)
            ),
            "evidence_type": "derived",
            "evidence_refs": _unique_strings(evidence_refs),
            "basis": "Actor and ingress come from manual intake; operation coverage is derived from active API artifacts."
                if manual_surfaces else "Ingress is derived from canonical API operations and requires architecture confirmation.",
            "confidence": confidence,
            "status": "Candidate",
        }]

    grounded = []
    for index, flow in enumerate(extracted_flows):
        source = _display_label(flow.get("source"))
        destination = _display_label(flow.get("destination"))
        evidence_refs = _unique_strings([
            *(flow.get("evidence_refs") or []),
            *(f"artifact:{artifact_id}" for artifact_id in (flow.get("artifact_ids") or [])),
        ])
        if not source or not destination or not evidence_refs:
            continue
        evidence_type = flow.get("evidence_type") or "derived"
        grounded.append({
            **flow,
            "flow_id": flow.get("flow_id") or _stable_id("flow", source, destination, index),
            "source": source,
            "destination": destination,
            "source_entity_type": flow.get("source_entity_type") or "component",
            "destination_entity_type": flow.get("destination_entity_type") or "component",
            "evidence_type": evidence_type,
            "evidence_refs": evidence_refs,
            "basis": flow.get("basis") or "Flow extracted from an artifact and retained as a candidate until architecture review.",
            "confidence": flow.get("confidence") or ("High" if evidence_type == "direct" else "Medium"),
            "status": "Confirmed" if evidence_type == "direct" else "Candidate",
        })
    return grounded


def validate_boundary_candidates(boundaries: list[dict], registry: dict[str, dict], flows: list[dict]) -> tuple[list[dict], list[str]]:
    """Reject ungrounded entities, non-crossing edges, and evidence-free claims."""
    accepted: list[dict] = []
    warnings: list[str] = []
    flows_by_id = {flow.get("flow_id"): flow for flow in flows if flow.get("flow_id")}
    zone_metadata = {
        str(item.get("zone_id")): {"parent_zone_id": item.get("zone_parent_id")}
        for item in registry.values()
        if item.get("zone_id")
    }
    seen: set[tuple[str, str, str, str]] = set()

    for boundary in boundaries:
        source_key = str(boundary.get("source") or "").casefold()
        destination_key = str(boundary.get("destination") or "").casefold()
        source_entity = registry.get(source_key)
        destination_entity = registry.get(destination_key)
        if not source_entity or not destination_entity:
            warnings.append(f"Rejected boundary with unknown entity: {boundary.get('source')} → {boundary.get('destination')}")
            continue

        crossing_ids = [flow_id for flow_id in (boundary.get("crossing_flow_ids") or []) if flow_id in flows_by_id]
        matching_flows = [
            flows_by_id[flow_id] for flow_id in crossing_ids
            if str(flows_by_id[flow_id].get("source") or "").casefold() == source_key
            and str(flows_by_id[flow_id].get("destination") or "").casefold() == destination_key
        ]
        if not matching_flows:
            warnings.append(f"Rejected boundary without a matching data flow: {boundary.get('source')} → {boundary.get('destination')}")
            continue
        if not _is_zone_transition(source_entity["zone_id"], destination_entity["zone_id"], zone_metadata):
            warnings.append(f"Rejected same-zone relationship: {boundary.get('source')} → {boundary.get('destination')}")
            continue

        evidence_refs = _unique_strings([
            *(boundary.get("evidence_refs") or []),
            *(ref for flow in matching_flows for ref in (flow.get("evidence_refs") or [])),
        ])
        if not evidence_refs:
            warnings.append(f"Rejected evidence-free boundary: {boundary.get('source')} → {boundary.get('destination')}")
            continue

        dedupe_key = (source_key, destination_key, source_entity["zone_id"], destination_entity["zone_id"])
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        accepted.append({
            **boundary,
            "boundary_id": boundary.get("boundary_id") or _stable_id("boundary", *dedupe_key),
            "model_fingerprint": _stable_id(
                "topology",
                *dedupe_key,
                *(sorted(evidence_refs)),
                *(sorted(flow["flow_id"] for flow in matching_flows)),
                boundary.get("basis"),
            ),
            "source": source_entity["name"],
            "destination": destination_entity["name"],
            "source_zone_id": source_entity["zone_id"],
            "destination_zone_id": destination_entity["zone_id"],
            "source_trust_level": source_entity["trust_level"],
            "destination_trust_level": destination_entity["trust_level"],
            "boundary_types": _explicit_boundary_types(boundary, *(matching_flows[:1] or [{}])),
            "evidence_refs": evidence_refs,
            "crossing_flow_ids": [flow["flow_id"] for flow in matching_flows],
            "generation_method": "deterministic",
        })
    return accepted, warnings


def apply_boundary_reviews(boundaries: list[dict], reviews: dict | None) -> tuple[list[dict], list[str]]:
    """Apply human decisions only while the reviewed model fingerprint matches."""
    reviewed: list[dict] = []
    warnings: list[str] = []
    review_map = reviews if isinstance(reviews, dict) else {}
    current_boundary_ids: set[str] = set()
    for boundary in boundaries:
        item = dict(boundary)
        boundary_id = str(item.get("boundary_id") or "")
        current_boundary_ids.add(boundary_id)
        review = review_map.get(boundary_id)
        if not isinstance(review, dict):
            reviewed.append(item)
            continue
        if review.get("model_fingerprint") != item.get("model_fingerprint"):
            warnings.append(
                f"Previous review is stale for {item.get('source')} → {item.get('destination')}; evidence or topology changed."
            )
            item["status"] = "Candidate"
            item["review_stale"] = True
            reviewed.append(item)
            continue
        status = review.get("status")
        if status not in TRUST_BOUNDARY_REVIEW_STATUSES:
            reviewed.append(item)
            continue
        item.update({
            "status": status,
            "review_note": str(review.get("review_note") or "").strip(),
            "reviewed_at": review.get("reviewed_at"),
            "review_stale": False,
        })
        reviewed.append(item)
    for boundary_id, review in review_map.items():
        if boundary_id not in current_boundary_ids and isinstance(review, dict):
            warnings.append(
                f"Reviewed boundary {boundary_id} no longer exists in the grounded topology; its decision was not applied."
            )
    return reviewed, _unique_strings(warnings)


def active_trust_boundaries(boundaries: list[dict] | None) -> list[dict]:
    """Return relationships that remain eligible for diagrams and analysis."""
    return [
        boundary for boundary in (boundaries or [])
        if isinstance(boundary, dict) and boundary.get("status") != "Rejected"
    ]


def _group_zone_boundaries(boundaries: list[dict]) -> list[dict]:
    """A trust boundary separates zones; several evidenced flows may cross it."""
    grouped: dict[tuple[str, str], list[dict]] = {}
    for boundary in boundaries:
        key = tuple(sorted((boundary["source_zone_id"], boundary["destination_zone_id"])))
        grouped.setdefault(key, []).append(boundary)
    result = []
    for zone_pair, members in grouped.items():
        if len(members) == 1:
            result.append(members[0])
            continue
        first = dict(members[0])
        evidence_refs = _unique_strings(ref for item in members for ref in item.get("evidence_refs", []))
        flow_ids = _unique_strings(flow_id for item in members for flow_id in item.get("crossing_flow_ids", []))
        boundary_types = _explicit_boundary_types(*(
            {"boundary_types": item.get("boundary_types") or []}
            for item in members
        ))
        first.update({
            "boundary_id": _stable_id("boundary", *zone_pair),
            "boundary_label": f"{zone_pair[0].replace('-', ' ').title()} ↔ {zone_pair[1].replace('-', ' ').title()}",
            "basis": "Evidenced flows cross this trust-zone transition; review the controls for each flow.",
            "evidence_refs": evidence_refs,
            "boundary_types": boundary_types,
            "crossing_flow_ids": flow_ids,
            "status": "Candidate" if any(item.get("status") != "Confirmed" for item in members) else "Confirmed",
            "model_fingerprint": _stable_id("topology", *zone_pair, *sorted(evidence_refs), *sorted(flow_ids)),
        })
        result.append(first)
    return result


def build_hierarchical_views(
    project: dict,
    registry: dict[str, dict],
    flows: list[dict],
    boundaries: list[dict],
) -> dict:
    """Build evidence-aware L0 context, L1 service, and L2 scenario views."""
    context_labels = _unique_strings(
        value
        for flow in flows
        for value in (flow.get("source"), flow.get("destination"))
    )
    context_nodes = []
    for label in context_labels:
        entity = registry.get(label.casefold())
        if not entity:
            continue
        element_type = {
            "actor": "external_entity",
            "data_store": "data_store",
            "external_system": "external_system",
        }.get(entity["entity_type"], "process")
        context_nodes.append({
            "element_id": entity["entity_id"],
            "label": entity["name"],
            "element_type": element_type,
            "trust_zone_id": entity["zone_id"],
            "trust_level": entity["trust_level"],
            "confidence": entity["confidence"],
            "evidence_refs": entity["evidence_refs"],
            "topology_status": "grounded",
            "model_level": "context",
        })
    context_node_by_label = {item["label"].casefold(): item for item in context_nodes}
    context_flows = [{
        "element_id": flow["flow_id"],
        "flow_id": flow["flow_id"],
        "label": f"{flow.get('source')} → {flow.get('destination')}",
        "element_type": "data_flow",
        "source_id": context_node_by_label.get(str(flow.get("source") or "").casefold(), {}).get("element_id"),
        "destination_id": context_node_by_label.get(str(flow.get("destination") or "").casefold(), {}).get("element_id"),
        "source": flow.get("source"),
        "destination": flow.get("destination"),
        "protocol": flow.get("protocol"),
        "data": flow.get("data", []),
        "confidence": flow.get("confidence", "Low"),
        "evidence_refs": flow.get("evidence_refs", []),
        "topology_status": "grounded",
        "model_level": "context",
    } for flow in flows]

    operations = [item for item in (project.get("canonical_operations") or []) if isinstance(item, dict)]
    grouped_operations: dict[str, list[dict]] = {}
    for operation in operations:
        service = _logical_component_label(operation.get("service") or "Application API")
        grouped_operations.setdefault(service, []).append(operation)

    ingress = next(
        (item for item in context_nodes if item["element_type"] == "process"),
        context_nodes[-1] if context_nodes else None,
    )
    service_nodes = []
    service_flows = []
    scenarios = []
    if ingress and grouped_operations:
        service_nodes.append({**ingress, "model_level": "service", "role": "ingress"})
    for service, service_operations in sorted(grouped_operations.items(), key=lambda item: item[0].casefold()):
        service_id = _stable_id("process", service, "logical-service")
        evidence_refs = _unique_strings(
            f"artifact:{source.get('artifact_id')}"
            for operation in service_operations
            for source in (operation.get("sources") or [])
            if isinstance(source, dict) and source.get("artifact_id")
        )
        service_nodes.append({
            "element_id": service_id,
            "label": service,
            "element_type": "process",
            "trust_zone_id": ingress.get("trust_zone_id", "application") if ingress else "application",
            "trust_level": ingress.get("trust_level", "Internal Trusted") if ingress else "Internal Trusted",
            "confidence": "Medium",
            "evidence_refs": evidence_refs,
            "topology_status": "logical",
            "model_level": "service",
            "role": "logical_service",
            "operation_count": len(service_operations),
        })
        if ingress:
            service_flow_id = _stable_id("logical-flow", ingress["element_id"], service_id)
            service_flows.append({
                "element_id": service_flow_id,
                "flow_id": service_flow_id,
                "label": f"{ingress['label']} → {service}",
                "element_type": "data_flow",
                "source_id": ingress["element_id"],
                "destination_id": service_id,
                "source": ingress["label"],
                "destination": service,
                "protocol": "Logical API routing",
                "data": _unique_strings(
                    field
                    for operation in service_operations
                    for field in [*(operation.get("request_fields") or []), *(operation.get("response_fields") or [])]
                )[:16],
                "confidence": "Medium",
                "evidence_refs": evidence_refs,
                "topology_status": "logical",
                "model_level": "service",
                "operation_count": len(service_operations),
                "is_trust_crossing": False,
            })

        for operation in service_operations:
            operation_key = str(operation.get("key") or "").strip()
            key_parts = operation_key.split(maxsplit=1)
            method = str(operation.get("method") or (key_parts[0] if len(key_parts) == 2 else "")).upper()
            path = str(operation.get("path") or (key_parts[1] if len(key_parts) == 2 else operation_key))
            scenario_id = _stable_id("scenario", method, path)
            operation_evidence = _unique_strings(
                f"artifact:{source.get('artifact_id')}:{source.get('locator', '')}"
                for source in (operation.get("sources") or [])
                if isinstance(source, dict) and source.get("artifact_id")
            )
            scenarios.append({
                "element_id": scenario_id,
                "scenario_id": scenario_id,
                "label": operation.get("summary") or f"{method} {path}",
                "element_type": "scenario",
                "service_id": service_id,
                "service": service,
                "method": method,
                "path": path,
                "security_status": operation.get("security_status", "unknown"),
                "coverage": operation.get("coverage", "unknown"),
                "request_fields": operation.get("request_fields", []),
                "response_fields": operation.get("response_fields", []),
                "scenario_count": len(operation.get("scenarios") or []),
                "evidence_refs": operation_evidence,
                "topology_status": "logical",
                "model_level": "scenario",
                "scenario_kind": "api_operation",
            })

    service_readiness = {
        "state": "logical" if grouped_operations else "insufficient",
        "label": "Logical service map" if grouped_operations else "Insufficient architecture evidence",
        "message": "Service groups are derived from canonical API operations and do not assert deployment boundaries."
            if grouped_operations else "At least two internal elements and one evidenced internal flow are required for a service-level model.",
    }
    if not grouped_operations:
        node_by_id = {item.get("element_id"): item for item in context_nodes}
        candidate_flows = [
            item for item in context_flows
            if node_by_id.get(item.get("source_id"), {}).get("element_type") != "external_entity"
            and node_by_id.get(item.get("destination_id"), {}).get("element_type") != "external_entity"
        ]
        candidate_ids = {
            value for flow in candidate_flows for value in (flow.get("source_id"), flow.get("destination_id")) if value
        }
        if candidate_flows and len(candidate_ids) >= 2:
            service_nodes = [
                {**node_by_id[element_id], "model_level": "service", "role": "architecture_candidate", "topology_status": "candidate"}
                for element_id in sorted(candidate_ids) if element_id in node_by_id
            ]
            service_flows = [
                {**item, "model_level": "service", "topology_status": "candidate"}
                for item in candidate_flows
            ]
            service_readiness = {
                "state": "candidate",
                "label": "Architecture candidates",
                "message": "Internal relationships were extracted from narrative evidence and require architecture review.",
            }

    business_scenarios = []
    for item in (project.get("business_scenarios") or []):
        if not isinstance(item, dict) or not item.get("name") or not item.get("actor"):
            continue
        scenario_id = _stable_id("business-scenario", item.get("actor"), item.get("name"), item.get("evidence_ref"))
        steps = []
        actor_element_id = _stable_id("activity-actor", scenario_id, item.get("actor"))
        steps.append({
            "element_id": actor_element_id,
            "element_type": "actor",
            "label": item.get("actor"),
            "sequence": 0,
        })
        for index, step in enumerate(item.get("steps") or [], start=1):
            if not isinstance(step, dict) or not step.get("label"):
                continue
            step_type = str(step.get("type") or "action")
            steps.append({
                "element_id": _stable_id("activity", scenario_id, index, step_type, step.get("label")),
                "element_type": step_type,
                "label": step.get("label"),
                "target": step.get("target"),
                "data": step.get("data") or [],
                "sequence": index,
            })
        if len(steps) < 2:
            continue
        business_scenarios.append({
            "element_id": scenario_id,
            "scenario_id": scenario_id,
            "label": item.get("name"),
            "element_type": "scenario",
            "scenario_kind": "business_flow",
            "actor": item.get("actor"),
            "trigger": item.get("trigger"),
            "preconditions": item.get("preconditions") or [],
            "steps": steps,
            "data": item.get("data") or [],
            "status": item.get("status", "Candidate"),
            "confidence": item.get("confidence", "Medium"),
            "evidence_refs": _unique_strings([item.get("evidence_ref")]),
            "evidence_snippet": item.get("evidence_snippet"),
            "evidence_locator": item.get("evidence_locator"),
            "model_level": "scenario",
            "topology_status": "candidate",
        })

    boundary_elements = [{
        "element_id": item["boundary_id"],
        "label": item.get("boundary_label") or f"{item.get('source')} → {item.get('destination')}",
        "element_type": "trust_boundary",
        "source": item.get("source"),
        "destination": item.get("destination"),
        "status": item.get("status", "Candidate"),
        "evidence_refs": item.get("evidence_refs", []),
        "model_level": "context",
    } for item in boundaries]
    asset_fields = _unique_strings([
        *(field for flow in flows for field in (flow.get("data") or [])),
        *(field for scenario in scenarios for field in [
            *(scenario.get("request_fields") or []), *(scenario.get("response_fields") or [])
        ]),
        *(field for scenario in business_scenarios for field in (scenario.get("data") or [])),
        *(field for scenario in business_scenarios for step in (scenario.get("steps") or []) for field in (step.get("data") or [])),
    ])
    data_assets = []
    for field in asset_fields:
        normalized = str(field).casefold().replace("_", " ").replace(".", " ")
        if re.search(r"password|token|otp|secret|pincode", normalized):
            classification = "Secret"
        elif re.search(r"email|phone|number|name|vehicle|vin|location|address|video|image", normalized):
            classification = "Personal"
        elif re.search(r"amount|price|credit|coupon|order", normalized):
            classification = "Financial"
        else:
            classification = "Business"
        data_assets.append({
            "element_id": _stable_id("data-asset", field),
            "label": field,
            "element_type": "data_asset",
            "classification": classification,
            "model_level": "asset",
            "topology_status": "derived",
        })
    return {
        "context": {
            "label": "Context DFD",
            "description": "Grounded deployment scope and trust-zone crossings.",
            "nodes": context_nodes,
            "flows": context_flows,
            "boundaries": boundary_elements,
        },
        "services": {
            "label": service_readiness["label"],
            "description": service_readiness["message"],
            "readiness": service_readiness,
            "nodes": service_nodes,
            "flows": service_flows,
        },
        "scenarios": {
            "label": "Scenario flows and operation catalog",
            "description": "Evidence-backed business activities are kept separate from canonical API operations.",
            "readiness": {
                "state": "ready" if business_scenarios or scenarios else "insufficient",
                "business_flow_count": len(business_scenarios),
                "operation_count": len(scenarios),
            },
            "business_items": business_scenarios,
            "operation_items": scenarios,
            "items": [*business_scenarios, *scenarios],
        },
        "assets": {
            "label": "Data asset catalog",
            "description": "Request and response fields derived from canonical operations and grounded flows.",
            "items": data_assets,
        },
        "summary": {
            "context_nodes": len(context_nodes),
            "grounded_flows": len(context_flows),
            "logical_services": len(grouped_operations),
            "scenarios": len(scenarios),
            "business_scenarios": len(business_scenarios),
            "data_assets": len(data_assets),
        },
    }


def attach_target_refs(
    threats: list[dict] | None,
    boundaries: list[dict] | None,
    views: dict | None,
    dfd_model: dict | None = None,
) -> list[dict]:
    """Attach typed model targets to findings using IDs and deterministic labels."""
    candidates = [item for item in (boundaries or []) if isinstance(item, dict) and item.get("boundary_id")]
    view_data = views if isinstance(views, dict) else {}
    context = view_data.get("context") if isinstance(view_data.get("context"), dict) else {}
    services = view_data.get("services") if isinstance(view_data.get("services"), dict) else {}
    scenarios_view = view_data.get("scenarios") if isinstance(view_data.get("scenarios"), dict) else {}
    assets_view = view_data.get("assets") if isinstance(view_data.get("assets"), dict) else {}
    context_nodes = context.get("nodes") or []
    context_flows = context.get("flows") or []
    service_nodes = [
        item for item in (services.get("nodes") or [])
        if item.get("role") in {"logical_service", "architecture_candidate"}
    ]
    scenarios = scenarios_view.get("items") or []
    data_assets = assets_view.get("items") or []

    # AI output may point directly at stable canonical DFD IDs. Resolve these
    # before heuristic label matching so a precise reference is not diluted by
    # a broad narrative match. Unknown IDs are expected to be removed by the
    # threat-output validator; this second check keeps the mapper defensive.
    canonical_targets = {}
    if isinstance(dfd_model, dict):
        collections = (
            ("nodes", None),
            ("data_objects", "data_object"),
            ("flows", "data_flow"),
            ("boundaries", "trust_boundary"),
            ("zones", "zone"),
            ("questions", "question"),
        )
        for collection, fixed_type in collections:
            for item in dfd_model.get(collection, []) or []:
                if not isinstance(item, dict) or not item.get("id"):
                    continue
                target_type = item.get("type") if collection == "nodes" else fixed_type
                if collection == "nodes" and target_type not in {"entity", "process", "data_store"}:
                    target_type = None
                if target_type:
                    canonical_targets[str(item["id"])] = (target_type, item)

    def relation_text(item: dict) -> str:
        values = [item.get(field) for field in (
            "trust_boundary", "source", "destination", "component", "asset",
            "threat_description", "abuse_case", "evidence_locator", "evidence_snippet",
        )]
        values.extend(item.get("evidence") or [])
        return " ".join(str(value or "") for value in values).casefold()

    def node_text(item: dict) -> str:
        # Node ownership must come from explicit component/endpoint fields.
        # Narrative/evidence text often mentions users or web controls and would
        # otherwise map nearly every finding to generic context nodes.
        return " ".join(str(item.get(field) or "") for field in (
            "component", "source", "destination", "trust_boundary",
        )).casefold()

    def phrase_present(text: str, phrase: str) -> bool:
        normalized = " ".join(str(phrase or "").casefold().split())
        if not normalized:
            return False
        return bool(re.search(rf"(?<![a-z0-9]){re.escape(normalized)}(?![a-z0-9])", text))

    def scenario_text(item: dict) -> str:
        # Do not use the broad evidence list here. A report may retain secondary
        # references from another operation; those are useful for review but are
        # not authoritative enough to create an element-level target link.
        return " ".join(str(item.get(field) or "") for field in (
            "component", "threat_description", "abuse_case", "test_scenario",
            "evidence_locator", "evidence_snippet",
        )).casefold()

    def ref(element_type: str, element: dict, model_level: str, match_basis: str) -> dict:
        return {
            "type": element_type,
            "id": element.get("element_id") or element.get("boundary_id") or element.get("flow_id") or element.get("scenario_id"),
            "label": element.get("label") or f"{element.get('source')} → {element.get('destination')}",
            "model_level": model_level,
            "match_basis": match_basis,
        }

    for threat in threats or []:
        if not isinstance(threat, dict):
            continue
        target_refs: list[dict] = []
        known_ids = {
            str(value) for value in (threat.get("trust_boundary_ids") or []) if value
        }
        explicit_refs = {
            str(value) for value in (threat.get("affected_refs") or []) if value
        }
        available_ids = {str(item["boundary_id"]) for item in candidates}
        retained = sorted(known_ids.intersection(available_ids))
        retained.extend(sorted(
            ref_id for ref_id in explicit_refs
            if ref_id in canonical_targets and canonical_targets[ref_id][0] == "trust_boundary"
            and ref_id not in retained
        ))
        text = relation_text(threat)
        explicit_node_text = node_text(threat)
        explicit_scenario_text = scenario_text(threat)
        if not retained:
            matched = []
            for boundary in candidates:
                source = str(boundary.get("source") or "").casefold()
                destination = str(boundary.get("destination") or "").casefold()
                label = str(boundary.get("boundary_label") or "").casefold()
                if (
                    source and destination and phrase_present(text, source) and phrase_present(text, destination)
                ) or (label and phrase_present(text, label)):
                    matched.append(str(boundary["boundary_id"]))
            # An unmapped finding must remain unmapped. Falling back to every
            # boundary creates false cross-boundary coverage and can hide a
            # finding when one of several boundaries is rejected.
            retained = sorted(matched)
        threat["trust_boundary_ids"] = retained
        for ref_id in sorted(explicit_refs):
            target = canonical_targets.get(ref_id)
            if not target:
                continue
            element_type, element = target
            target_refs.append({
                "type": element_type,
                "id": ref_id,
                "label": element.get("name") or element.get("id"),
                "model_level": "semantic",
                "match_basis": "AI-provided DFD reference",
            })
        for boundary in candidates:
            if str(boundary["boundary_id"]) not in retained:
                continue
            target_refs.append(ref("trust_boundary", {
                **boundary,
                "element_id": boundary["boundary_id"],
                "label": boundary.get("boundary_label") or f"{boundary.get('source')} → {boundary.get('destination')}",
            }, "context", "boundary relationship"))
            for flow_id in boundary.get("crossing_flow_ids") or []:
                flow = next((item for item in context_flows if item.get("flow_id") == flow_id), None)
                if flow:
                    target_refs.append(ref("data_flow", flow, "context", "boundary crossing flow"))

        component_text = str(threat.get("component") or "").casefold()
        for node in [*context_nodes, *service_nodes]:
            label = str(node.get("label") or "").casefold()
            if not label:
                continue
            exact_component = component_text and (component_text == label or component_text in label or label in component_text)
            mentioned = label in explicit_node_text
            if exact_component or mentioned:
                target_refs.append(ref(node.get("element_type", "process"), node, node.get("model_level", "service"), "component label"))

        for scenario in scenarios:
            if scenario.get("scenario_kind") == "business_flow":
                scenario_label = str(scenario.get("label") or "").casefold()
                action_labels = [
                    str(step.get("label") or "").casefold()
                    for step in (scenario.get("steps") or [])
                    if step.get("element_type") == "action" and len(str(step.get("label") or "")) >= 8
                ]
                if (scenario_label and scenario_label in explicit_scenario_text) or any(label in explicit_scenario_text for label in action_labels):
                    target_refs.append(ref("scenario", scenario, "scenario", "business use case"))
                continue
            method_path = f"{scenario.get('method', '')} {scenario.get('path', '')}".strip().casefold()
            path = str(scenario.get("path") or "").casefold()
            if (method_path and method_path in explicit_scenario_text) or (path and path in explicit_scenario_text):
                target_refs.append(ref("scenario", scenario, "scenario", "operation path"))

        asset_text = " ".join(str(threat.get(field) or "") for field in (
            "asset", "data_classification", "threat_description", "abuse_case",
        )).casefold().replace("_", " ").replace(".", " ")
        for asset in data_assets:
            label = str(asset.get("label") or "").casefold()
            normalized_label = label.replace("_", " ").replace(".", " ")
            # Short/common schema keys such as id, name, kind, and limit are
            # too ambiguous to become finding targets on their own.
            if len(normalized_label) < 4 or normalized_label in {
                "name", "kind", "query", "limit", "offset", "content", "title",
                "user", "data", "status", "type", "message", "code", "value",
                "result", "success", "error", "url", "description",
            }:
                continue
            if re.search(rf"(?<![a-z0-9]){re.escape(normalized_label)}(?![a-z0-9])", asset_text):
                target_refs.append(ref("data_asset", asset, "asset", "data field mention"))

        deduped = []
        seen_refs = set()
        for item in target_refs:
            key = (item.get("type"), item.get("id"))
            if not item.get("id") or key in seen_refs:
                continue
            seen_refs.add(key)
            deduped.append(item)
        threat["target_refs"] = deduped
        threat["mapping_status"] = "mapped" if deduped else "unmapped"
    return threats or []


def attach_boundary_refs(threats: list[dict] | None, boundaries: list[dict] | None) -> list[dict]:
    """Backward-compatible boundary-only target linking."""
    return attach_target_refs(threats, boundaries, {})


def propagate_target_refs(report: dict) -> dict:
    """Copy threat targets to controls, tests, and assumptions through threat IDs."""
    threat_by_id = {str(item.get("threat_id")): item for item in (report.get("threats") or []) if item.get("threat_id")}

    def merged_refs(threat_ids, existing=None) -> list[dict]:
        refs = []
        seen = set()
        for item in [*(existing or []), *[ref for threat_id in (threat_ids or []) for ref in threat_by_id.get(str(threat_id), {}).get("target_refs") or []]]:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            key = (item.get("type"), item.get("id"))
            if key in seen:
                continue
            seen.add(key)
            refs.append(item)
        return refs

    for control in report.get("controls") or []:
        control["target_refs"] = merged_refs(control.get("threat_ids") or [], control.get("target_refs"))
    for scenario in report.get("test_scenarios") or []:
        scenario["target_refs"] = merged_refs([scenario.get("threat_id")], scenario.get("target_refs"))
    for assumption in report.get("assumptions") or []:
        assumption["target_refs"] = merged_refs([assumption.get("related_threat_id")], assumption.get("target_refs"))
    return report


def build_trust_model(project: dict) -> dict:
    flows = build_grounded_data_flows(project)
    registry = build_entity_registry(project, flows)
    zone_metadata = _zone_metadata_index(project)
    normalized_flows = []
    for flow in flows:
        normalized = dict(flow)
        for endpoint, type_field in (("source", "source_entity_type"), ("destination", "destination_entity_type")):
            matches = [item for item in registry.values() if _same_entity_name(str(flow.get(endpoint) or ""), item["name"])]
            if len(matches) == 1:
                normalized[endpoint] = matches[0]["name"]
                normalized[type_field] = matches[0]["entity_type"]
        normalized_flows.append(normalized)
    flows = normalized_flows
    candidates = []
    for flow in flows:
        source = registry.get(str(flow.get("source") or "").casefold())
        destination = registry.get(str(flow.get("destination") or "").casefold())
        if not source or not destination or not _is_zone_transition(source["zone_id"], destination["zone_id"], zone_metadata):
            continue
        boundary_metadata = _boundary_metadata_for_flow(project, flow)
        metadata_evidence = _unique_strings(
            ref
            for item in boundary_metadata
            for ref in (item.get("evidence_refs") or item.get("evidenceRefs") or [])
        )
        candidates.append({
            "source": source["name"],
            "destination": destination["name"],
            "boundary_label": f"{source['zone_id'].replace('-', ' ').title()} → {destination['zone_id'].replace('-', ' ').title()}",
            "risk_note": "Data enters a different trust zone. Validate identity, authorization, input constraints, and abuse resistance at this ingress.",
            "basis": next(
                (item.get("rationale") or item.get("basis") for item in boundary_metadata if item.get("rationale") or item.get("basis")),
                flow.get("basis"),
            ),
            "boundary_types": _explicit_boundary_types(flow, *boundary_metadata),
            "confidence": flow.get("confidence", "Low"),
            "status": flow.get("status", "Candidate"),
            "evidence_refs": _unique_strings([*(flow.get("evidence_refs") or []), *metadata_evidence]),
            "crossing_flow_ids": [flow["flow_id"]],
        })

    boundaries, warnings = validate_boundary_candidates(candidates, registry, flows)
    boundaries = _group_zone_boundaries(boundaries)
    views = build_hierarchical_views(project, registry, flows, boundaries)
    declared_external = {_display_label(value).casefold() for value in (project.get("external_systems") or []) if value}
    connected_entities = {
        str(flow.get(field) or "").casefold()
        for flow in flows
        for field in ("source", "destination")
    }
    if declared_external and not declared_external.intersection(connected_entities):
        warnings.append("External systems are declared but no evidenced data flow connects them.")
    if not boundaries:
        warnings.append("No grounded cross-zone data flow is available; add or confirm architecture relationships.")
    return {
        "version": TRUST_MODEL_VERSION,
        "generation_method": "deterministic",
        "entities": sorted(registry.values(), key=lambda item: (item["zone_id"], item["name"].casefold())),
        "data_flows": flows,
        "boundaries": boundaries,
        "views": views,
        "warnings": _unique_strings(warnings),
    }


async def detect_trust_boundaries(project: dict, force_fallback: bool = False) -> list[dict]:
    """Compatibility entry point used by callers that only need boundaries."""
    return build_trust_model(project)["boundaries"]
