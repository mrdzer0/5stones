"""Build and validate the canonical DFD model from the grounded topology."""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict

from backend.models.dfd import (
    DfdBoundary,
    DfdDataObject,
    DfdFlow,
    DfdModel,
    DfdNode,
    DfdQuestion,
    DfdView,
    DfdZone,
)


DFD_SCHEMA_VERSION = "dfd-v1"


def _stable_id(prefix: str, *values: object) -> str:
    raw = "|".join(str(value or "").strip().casefold() for value in values)
    return f"{prefix}-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]}"


def _unique(values) -> list[str]:
    result = []
    seen = set()
    for value in values or []:
        text = str(value or "").strip()
        if text and text.casefold() not in seen:
            seen.add(text.casefold())
            result.append(text)
    return result


def _display_ids(items: list[dict], prefix: str) -> dict[str, str]:
    return {
        str(item["id"]): f"{prefix}{index}"
        for index, item in enumerate(sorted(items, key=lambda value: str(value.get("name") or "").casefold()), start=1)
    }


def _zone_label(zone_id: str) -> str:
    labels = {
        "external": "External",
        "external-privileged": "Privileged External",
        "external-dependency": "External Dependency",
        "application": "Application",
        "data": "Data Store",
    }
    return labels.get(zone_id, zone_id.replace("-", " ").title())


def _node_type(entity_type: str) -> str:
    if entity_type == "data_store":
        return "data_store"
    if entity_type in {"actor", "external_system"}:
        return "entity"
    return "process"


def _source_refs(project: dict) -> list[str]:
    refs = [f"artifact:{source.get('artifact_id')}" for source in project.get("artifact_sources", []) or [] if isinstance(source, dict) and source.get("artifact_id") and source.get("active", True)]
    if project.get("manual_context"):
        refs.append("manual:context")
    return _unique(refs)


def build_dfd_model(project: dict, trust_model: dict, previous: dict | None = None) -> DfdModel:
    """Project grounded topology into the canonical semantic contract.

    This adapter deliberately preserves unknown classification values. It does
    not promote the current heuristic trust labels into ownership or exposure
    facts.
    """
    entities = [item for item in trust_model.get("entities", []) if isinstance(item, dict) and item.get("entity_id") and item.get("name")]
    flows = [item for item in trust_model.get("data_flows", []) if isinstance(item, dict) and item.get("flow_id")]
    boundaries = [item for item in trust_model.get("boundaries", []) if isinstance(item, dict) and item.get("boundary_id")]
    entity_by_name = {str(item.get("name")).casefold(): item for item in entities}

    raw_nodes = [{
        "id": item["entity_id"],
        "name": item["name"],
        "type": _node_type(item.get("entity_type", "component")),
    } for item in entities]
    display_by_node = {}
    for node_type, prefix in (("entity", "E"), ("process", "P"), ("data_store", "D")):
        display_by_node.update(_display_ids([item for item in raw_nodes if item["type"] == node_type], prefix))

    zone_ids = sorted({str(item.get("zone_id")) for item in entities if item.get("zone_id")})
    zone_display = {zone_id: f"Z{index}" for index, zone_id in enumerate(zone_ids, start=1)}
    zones = [DfdZone(
        id=f"zone-{zone_id}",
        display_id=zone_display[zone_id],
        name=_zone_label(zone_id),
        description="Derived from grounded topology; ownership and exposure require review.",
        trust_assumptions=[],
        knowledge_status="inferred",
    ) for zone_id in zone_ids]
    zone_ref = {zone_id: f"zone-{zone_id}" for zone_id in zone_ids}

    nodes = []
    for item in entities:
        node_id = item["entity_id"]
        raw_type = _node_type(item.get("entity_type", "component"))
        nodes.append(DfdNode(
            id=node_id,
            display_id=display_by_node[node_id],
            type=raw_type,
            name=item["name"],
            scope="unknown",
            ownership="unknown",
            exposure="unknown",
            zone_ids=[zone_ref[item["zone_id"]]] if item.get("zone_id") in zone_ref else [],
            knowledge_status="inferred" if item.get("confidence") != "High" else "documented",
            evidence_refs=_unique(item.get("evidence_refs", [])),
        ))

    data_objects = []
    data_object_by_name = {}
    for value in _unique(field for flow in flows for field in (flow.get("data") or [])):
        object_id = _stable_id("data-object", value)
        data_object_by_name[value.casefold()] = object_id
        data_objects.append(DfdDataObject(
            id=object_id,
            display_id=f"DO{len(data_objects) + 1}",
            name=value,
            knowledge_status="inferred",
        ))

    dfd_flows = []
    for index, flow in enumerate(flows, start=1):
        source = entity_by_name.get(str(flow.get("source") or "").casefold())
        target = entity_by_name.get(str(flow.get("destination") or "").casefold())
        if not source or not target:
            continue
        data_ids = [data_object_by_name[str(value).casefold()] for value in flow.get("data") or [] if str(value).casefold() in data_object_by_name]
        dfd_flows.append(DfdFlow(
            id=flow["flow_id"],
            display_id=f"F{index}",
            source_id=source["entity_id"],
            target_id=target["entity_id"],
            name=(flow.get("data") or ["Unknown data flow"])[0],
            data_object_ids=data_ids,
            protocol=flow.get("protocol"),
            interaction_kind="unknown",
            boundary_crossings=[],
            crossing_status="resolved",
            evidence_refs=_unique(flow.get("evidence_refs", [])),
            knowledge_status="documented" if flow.get("evidence_type") == "direct" else "inferred",
        ))

    dfd_flow_by_id = {item.id: item for item in dfd_flows}
    dfd_boundaries = []
    boundary_display = {}
    for index, boundary in enumerate(boundaries, start=1):
        boundary_id = boundary["boundary_id"]
        boundary_display[boundary_id] = f"TB{index}"
        source_entity = entity_by_name.get(str(boundary.get("source") or "").casefold())
        target_entity = entity_by_name.get(str(boundary.get("destination") or "").casefold())
        source_zone = source_entity.get("zone_id") if source_entity else None
        target_zone = target_entity.get("zone_id") if target_entity else None
        crossing_flow_ids = [flow_id for flow_id in boundary.get("crossing_flow_ids", []) if flow_id in dfd_flow_by_id]
        for flow_id in crossing_flow_ids:
            dfd_flow_by_id[flow_id].boundary_crossings.append(boundary_id)
        dfd_boundaries.append(DfdBoundary(
            id=boundary_id,
            display_id=boundary_display[boundary_id],
            name=boundary.get("boundary_label") or f"{boundary.get('source')} → {boundary.get('destination')}",
            types=["unknown"],
            rationale=boundary.get("basis"),
            source_zone_ids=[zone_ref[source_zone]] if source_zone in zone_ref else [],
            target_zone_ids=[zone_ref[target_zone]] if target_zone in zone_ref else [],
            crossing_flow_ids=crossing_flow_ids,
            status={"Candidate": "candidate", "Confirmed": "confirmed", "Rejected": "rejected"}.get(boundary.get("status"), "unresolved"),
            derived=True,
            evidence_refs=_unique(boundary.get("evidence_refs", [])),
        ))

    for flow in dfd_flows:
        flow.boundary_crossings = _unique(flow.boundary_crossings)

    all_element_ids = [item.id for item in nodes] + [item.id for item in dfd_flows] + [item.id for item in dfd_boundaries] + [item.id for item in data_objects]
    views = [
        DfdView(
            id="view-context",
            kind="context",
            element_refs=all_element_ids,
            projection_mappings={item.id: [item.id] for item in nodes},
        ),
        DfdView(
            id="view-system",
            kind="system",
            element_refs=all_element_ids,
            projection_mappings={item.id: [item.id] for item in nodes},
        ),
    ]

    questions = []
    unknown_nodes = [item.id for item in nodes if item.scope == "unknown" or item.ownership == "unknown" or item.exposure == "unknown"]
    if unknown_nodes:
        questions.append(DfdQuestion(
            id="question-classification",
            affected_refs=unknown_nodes,
            question="Which scope, ownership, and exposure apply to each DFD element?",
            reason="These dimensions are required to calculate trust boundaries without treating internal as trusted.",
            source_refs=_source_refs(project),
        ))
    if any(flow.interaction_kind == "unknown" for flow in dfd_flows):
        questions.append(DfdQuestion(
            id="question-interaction-kind",
            affected_refs=[flow.id for flow in dfd_flows if flow.interaction_kind == "unknown"],
            question="Are these flows requests, responses, events, reads, writes, or replication?",
            reason="The current artifact model does not reliably distinguish interaction direction/semantics.",
            source_refs=_source_refs(project),
        ))

    semantic_payload = {
        "nodes": [item.model_dump() for item in nodes],
        "data_objects": [item.model_dump() for item in data_objects],
        "flows": [item.model_dump() for item in dfd_flows],
        "boundaries": [item.model_dump() for item in dfd_boundaries],
        "zones": [item.model_dump() for item in zones],
    }
    semantic_hash = hashlib.sha256(json.dumps(semantic_payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    previous_hash = previous.get("semantic_hash") if isinstance(previous, dict) else None
    previous_revision = int(previous.get("revision", 0)) if isinstance(previous, dict) else 0
    revision = previous_revision + 1 if previous_hash and previous_hash != semantic_hash else max(previous_revision, 1)

    return DfdModel(
        id=(previous or {}).get("id") or _stable_id("dfd-model", project.get("project_id"), project.get("name")),
        project_id=str(project.get("project_id") or ""),
        schema_version=DFD_SCHEMA_VERSION,
        revision=revision,
        semantic_hash=semantic_hash,
        title=str(project.get("name") or "Threat Model"),
        scope_description=project.get("description"),
        source_refs=_source_refs(project),
        nodes=nodes,
        data_objects=data_objects,
        flows=dfd_flows,
        stores={},
        zones=zones,
        boundaries=dfd_boundaries,
        views=views,
        questions=questions,
    )


def validate_dfd_model(model: DfdModel) -> dict:
    """Return blocking graph errors separately from reviewable warnings."""
    errors: list[str] = []
    warnings: list[str] = []
    node_ids = [item.id for item in model.nodes]
    data_ids = [item.id for item in model.data_objects]
    zone_ids = [item.id for item in model.zones]
    boundary_ids = [item.id for item in model.boundaries]
    flow_ids = [item.id for item in model.flows]
    all_ids = node_ids + data_ids + zone_ids + boundary_ids + flow_ids

    def duplicates(values: list[str], label: str):
        seen = set()
        for value in values:
            if value in seen:
                errors.append(f"Duplicate {label} ID: {value}")
            seen.add(value)

    duplicates(node_ids, "node")
    duplicates(data_ids, "data object")
    duplicates(zone_ids, "zone")
    duplicates(boundary_ids, "boundary")
    duplicates(flow_ids, "flow")
    duplicates(all_ids, "model element")

    node_by_id = {item.id: item for item in model.nodes}
    data_set = set(data_ids)
    zone_set = set(zone_ids)
    boundary_set = set(boundary_ids)
    flow_set = set(flow_ids)

    for zone in model.zones:
        if zone.parent_zone_id and zone.parent_zone_id not in zone_set:
            errors.append(f"Zone {zone.id} references missing parent zone {zone.parent_zone_id}")
    for zone in model.zones:
        seen = set()
        current = zone
        while current.parent_zone_id:
            if current.id in seen:
                errors.append(f"Zone cycle detected at {current.id}")
                break
            seen.add(current.id)
            parent = next((item for item in model.zones if item.id == current.parent_zone_id), None)
            if not parent:
                break
            current = parent

    for node in model.nodes:
        for zone_id in node.zone_ids:
            if zone_id not in zone_set:
                errors.append(f"Node {node.id} references missing zone {zone_id}")
        if node.parent_process_id and node.parent_process_id not in node_by_id:
            errors.append(f"Node {node.id} references missing parent process {node.parent_process_id}")
        elif node.parent_process_id and node_by_id[node.parent_process_id].type != "process":
            errors.append(f"Node {node.id} parent {node.parent_process_id} is not a process")

    for flow in model.flows:
        if flow.source_id not in node_by_id or flow.target_id not in node_by_id:
            errors.append(f"Flow {flow.id} has a dangling source/target reference")
        for data_id in flow.data_object_ids:
            if data_id not in data_set:
                errors.append(f"Flow {flow.id} references missing data object {data_id}")
        for boundary_id in flow.boundary_crossings:
            if boundary_id not in boundary_set:
                errors.append(f"Flow {flow.id} references missing boundary {boundary_id}")
        if flow.source_id in node_by_id and flow.target_id in node_by_id:
            source_type = node_by_id[flow.source_id].type
            target_type = node_by_id[flow.target_id].type
            if source_type != "process" and target_type != "process":
                warnings.append(f"Flow {flow.id} does not touch a process and requires review")

    for boundary in model.boundaries:
        for zone_id in [*boundary.source_zone_ids, *boundary.target_zone_ids]:
            if zone_id not in zone_set:
                errors.append(f"Boundary {boundary.id} references missing zone {zone_id}")
        for flow_id in boundary.crossing_flow_ids:
            if flow_id not in flow_set:
                errors.append(f"Boundary {boundary.id} references missing flow {flow_id}")

    for view in model.views:
        for element_id in view.element_refs:
            if element_id not in set(all_ids):
                errors.append(f"View {view.id} references missing element {element_id}")
        if view.parent_process_id and view.parent_process_id not in node_by_id:
            errors.append(f"View {view.id} references missing parent process {view.parent_process_id}")

    for flow in model.flows:
        if len(flow.boundary_crossings) != len(set(flow.boundary_crossings)):
            errors.append(f"Flow {flow.id} contains duplicate boundary crossings")

    return {
        "valid": not errors,
        "errors": _unique(errors),
        "warnings": _unique(warnings),
        "counts": {
            "nodes": len(model.nodes),
            "data_objects": len(model.data_objects),
            "flows": len(model.flows),
            "zones": len(model.zones),
            "boundaries": len(model.boundaries),
            "questions": len(model.questions),
        },
    }


def format_dfd_analysis_context(dfd_model: dict | None) -> str:
    """Format stable DFD IDs for analysis adapters without exposing raw artifacts."""
    if not isinstance(dfd_model, dict):
        return "No canonical DFD model is available. Keep affected references empty and explain the information gap."

    lines = [
        f"DFD model id: {dfd_model.get('id', 'unknown')}",
        f"DFD schema: {dfd_model.get('schema_version', 'unknown')} · revision: {dfd_model.get('revision', 'unknown')}",
        "NODES:",
    ]
    for node in dfd_model.get("nodes", []) or []:
        lines.append(
            f"- {node.get('id')} ({node.get('display_id')}) · {node.get('type')} · {node.get('name')} · "
            f"scope={node.get('scope')} ownership={node.get('ownership')} exposure={node.get('exposure')}"
        )
    lines.append("DATA OBJECTS:")
    for item in dfd_model.get("data_objects", []) or []:
        lines.append(f"- {item.get('id')} ({item.get('display_id')}) · {item.get('name')} · status={item.get('knowledge_status')}")
    lines.append("FLOWS:")
    for flow in dfd_model.get("flows", []) or []:
        lines.append(
            f"- {flow.get('id')} ({flow.get('display_id')}) · {flow.get('source_id')} → {flow.get('target_id')} · "
            f"data={flow.get('name')} · interaction={flow.get('interaction_kind')} · boundaries={flow.get('boundary_crossings') or []}"
        )
    lines.append("BOUNDARIES:")
    for boundary in dfd_model.get("boundaries", []) or []:
        lines.append(
            f"- {boundary.get('id')} ({boundary.get('display_id')}) · {boundary.get('name')} · "
            f"types={boundary.get('types') or []} · flows={boundary.get('crossing_flow_ids') or []} · status={boundary.get('status')}"
        )
    if dfd_model.get("questions"):
        lines.append("OPEN QUESTIONS:")
        for question in dfd_model.get("questions", []) or []:
            lines.append(f"- {question.get('id')} · {question.get('question')} · affected={question.get('affected_refs') or []}")
    return "\n".join(lines)
