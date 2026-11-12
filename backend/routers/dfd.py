"""Canonical DFD persistence and revision-safe editing endpoints."""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape
import json
from math import ceil, sqrt

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError

from backend.models.dfd import DfdModel
from backend.services.dfd_model_service import (
    PROPOSAL_SECTIONS,
    apply_dfd_proposal,
    diff_dfd_models,
    preview_dfd_delete_impact,
    recalculate_boundary_crossings,
    refresh_attribute_assertions,
    _model_evidence,
    load_dfd_model,
    sync_dfd_views,
    validate_dfd_model,
)
from backend.services.posture_service import compute_signoff_readiness
from backend.utils.audit import log_event
from backend.utils.storage import (
    get_project,
    get_project_report_and_dfd,
    save_dfd_model,
    save_report,
    save_report_and_dfd,
)
from backend.utils.access_control import get_authorized_project, require_roles, workspace_access_dependency


router = APIRouter(
    prefix="/api/projects",
    tags=["dfd"],
    dependencies=[workspace_access_dependency, require_roles("analyst", "reviewer", "admin")],
)
DOWNSTREAM_STAGES = ["stride", "linddun", "controls", "tests", "missing_info", "assumptions"]


def _refresh_quality_gate(report: dict) -> dict:
    gate = compute_signoff_readiness(report)
    report["quality_gate"] = gate
    if isinstance(report.get("analysis_run"), dict):
        report["analysis_run"]["quality_gate"] = gate.copy()
        report["analysis_run"]["review_required"] = gate["review_required"]
    return gate


def _auto_layout_dfd(model: DfdModel) -> tuple[dict[str, dict[str, float]], int, int]:
    """Provide a readable zone-lane fallback for SVG exports without mutating the model."""
    context_view = next((view for view in model.views if view.kind == "context"), None)
    saved = context_view.positions if context_view else {}
    if model.nodes and all(node.id in saved for node in model.nodes):
        positions = {
            node.id: {"x": float(saved[node.id].get("x", 0)), "y": float(saved[node.id].get("y", 0))}
            for node in model.nodes
        }
        max_x = max((point["x"] for point in positions.values()), default=0)
        max_y = max((point["y"] for point in positions.values()), default=0)
        min_x = min((point["x"] for point in positions.values()), default=0)
        min_y = min((point["y"] for point in positions.values()), default=0)
        return positions, max(1200, ceil(max_x - min_x + 300)), max(760, ceil(max_y - min_y + 220))

    zones_by_id = {str(zone.id): zone for zone in model.zones}
    degree = {node.id: 0 for node in model.nodes}
    for flow in model.flows:
        degree[flow.source_id] = degree.get(flow.source_id, 0) + 1
        degree[flow.target_id] = degree.get(flow.target_id, 0) + 1

    def top_zone(zone_id: str) -> str:
        current = zones_by_id.get(str(zone_id))
        visited: set[str] = set()
        while current and current.parent_zone_id and str(current.parent_zone_id) in zones_by_id and str(current.id) not in visited:
            visited.add(str(current.id))
            current = zones_by_id[str(current.parent_zone_id)]
        return str(current.id) if current else "__unknown__"

    groups: dict[str, dict[str, list]] = {}
    for node in model.nodes:
        direct_zone = str(node.zone_ids[0]) if node.zone_ids else "__unknown__"
        groups.setdefault(top_zone(direct_zone), {}).setdefault(direct_zone, []).append(node)

    positions: dict[str, dict[str, float]] = {}
    lane_top = 95
    max_width = 1200
    ordered_top_zones = [str(zone.id) for zone in model.zones if str(zone.id) in groups]
    ordered_top_zones.extend(zone_id for zone_id in groups if zone_id not in ordered_top_zones)
    for top_zone_id in ordered_top_zones:
        lane_height = 0
        lane_width = 0
        for group_index, nodes in enumerate(groups[top_zone_id].values()):
            nodes.sort(key=lambda node: (-degree.get(node.id, 0), node.display_id, node.name))
            columns = min(5, max(1, ceil(sqrt(len(nodes)))) )
            rows = max(1, ceil(len(nodes) / columns))
            group_left = 155 + group_index * 270
            for index, node in enumerate(nodes):
                positions[node.id] = {
                    "x": group_left + (index % columns) * 220,
                    "y": lane_top + 100 + (index // columns) * 112,
                }
            lane_width = max(lane_width, group_left + max(0, columns - 1) * 220 + 220)
            lane_height = max(lane_height, rows * 112 + 155)
        max_width = max(max_width, lane_width)
        lane_top += lane_height + 70
    return positions, max_width, max(760, lane_top + 80)


def _resolve_dfd_view(model: DfdModel, selector: str | None):
    if not selector:
        return None
    normalized = str(selector).strip()
    view = next((item for item in model.views if item.id == normalized), None)
    if view:
        return view
    if normalized in {"context", "system"}:
        return next((item for item in model.views if item.kind == normalized), None)
    if normalized.startswith("feature:"):
        parent_id = normalized.split(":", 1)[1]
        return next((item for item in model.views if item.kind == "feature" and item.parent_process_id == parent_id), None)
    return None


def _projection_payload(model: DfdModel, view, validation: dict) -> dict:
    canonical_ids = {
        canonical_id for node in view.projection_nodes for canonical_id in node.canonical_node_ids
    }
    individually_visible = {
        node.id for node in view.projection_nodes
        if node.id in {item.id for item in model.nodes} and node.canonical_node_ids == [node.id]
    }
    hidden_internal = sum(
        1 for node in model.nodes
        if node.scope == "in_scope" and node.id not in individually_visible
    )
    validation_status = "blocked" if not validation.get("valid") else "ready" if validation.get("semantic_ready") else "review"
    level = {"context": "L0", "system": "L1", "feature": "L2"}[view.kind]
    return {
        "view_id": view.id,
        "level": level,
        "kind": view.kind,
        "parent_process_id": view.parent_process_id,
        "revision": model.revision,
        "layout_revision": model.layout_revision,
        "semantic_hash": model.semantic_hash,
        "projection_version": "dfd-projection-v1",
        "validation_status": validation_status,
        "decomposition_status": view.decomposition_status,
        "projection_issues": list(view.projection_issues),
        "counts": {
            "nodes": len(view.projection_nodes),
            "flows": len(view.projection_flows),
            "canonical_nodes_mapped": len(canonical_ids),
            "canonical_flows_mapped": len({ref for flow in view.projection_flows for ref in flow.canonical_flow_ids}),
            "hidden_internal_node_details": hidden_internal,
        },
        "warning": "This is a partial view of the canonical DFD; review validation status and projection issues before sign-off.",
        "view": view.model_dump(),
    }


def _render_projection_svg(model: DfdModel, view, validation: dict) -> str:
    payload = _projection_payload(model, view, validation)
    nodes = list(view.projection_nodes)
    flows = list(view.projection_flows)
    node_by_id = {item.id: item for item in nodes}
    indegree = {item.id: 0 for item in nodes}
    outgoing: dict[str, list[str]] = {item.id: [] for item in nodes}
    for flow in flows:
        if flow.source_id in outgoing and flow.target_id in indegree:
            outgoing[flow.source_id].append(flow.target_id)
            indegree[flow.target_id] += 1
    queue = sorted((node_id for node_id, degree in indegree.items() if degree == 0))
    ranks = {node_id: 0 for node_id in node_by_id}
    visited = set()
    while queue:
        source = queue.pop(0)
        if source in visited:
            continue
        visited.add(source)
        for target in sorted(outgoing.get(source, [])):
            ranks[target] = max(ranks[target], ranks[source] + 1)
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
                queue.sort()
    max_rank = max(ranks.values(), default=0)
    by_rank: dict[int, list] = {}
    for node in nodes:
        rank = ranks[node.id] if node.id in visited else max_rank + 1
        by_rank.setdefault(rank, []).append(node)
    positions = {}
    for rank, items in sorted(by_rank.items()):
        items.sort(key=lambda item: (item.type != "entity", item.type != "system", item.display_id, item.id))
        for index, item in enumerate(items):
            positions[item.id] = {"x": 165 + rank * 280, "y": 130 + index * 142}
    width = max(900, 320 + (max(by_rank.keys(), default=0) + 1) * 280)
    height = max(560, 210 + max((len(items) for items in by_rank.values()), default=1) * 142 + 90)
    esc = lambda value: escape(str(value or ""), quote=True)
    status = payload["validation_status"]
    warning_text = "; ".join(view.projection_issues) or payload["warning"]
    metadata = escape(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" role="img" aria-labelledby="dfd-title dfd-desc" data-view-id="{esc(view.id)}" data-view-kind="{esc(view.kind)}" data-revision="{model.revision}" data-semantic-hash="{esc(model.semantic_hash)}" data-validation-status="{status}" data-decomposition-status="{view.decomposition_status}">',
        f'<title id="dfd-title">{esc(model.title)} — {payload["level"]} {esc(view.id)} revision {model.revision}</title>',
        f'<desc id="dfd-desc">{esc(payload["level"])} projection with {len(nodes)} nodes and {len(flows)} flows. Status: {status}. {esc(warning_text)}</desc>',
        '<metadata id="dfd-projection-metadata">' + metadata + '</metadata>',
        '<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#526777"/></marker></defs>',
        f'<rect width="{width}" height="{height}" fill="#FFFFFF"/>',
    ]
    zone_by_id = {zone.id: zone for zone in model.zones}
    for zone_id in sorted({zone_id for node in nodes for zone_id in node.zone_ids}):
        zone_nodes = [node for node in nodes if zone_id in node.zone_ids]
        points = [positions[node.id] for node in zone_nodes]
        if not points:
            continue
        left = min(point["x"] for point in points) - 98
        top = min(point["y"] for point in points) - 53
        right = max(point["x"] for point in points) + 98
        bottom = max(point["y"] for point in points) + 50
        zone = zone_by_id.get(zone_id)
        lines.append(f'<rect data-zone-id="{esc(zone_id)}" x="{max(4, left)}" y="{max(4, top)}" width="{max(190, right-left)}" height="{max(108, bottom-top)}" rx="16" fill="#EFF6FF" fill-opacity="0.3" stroke="#457B9D" stroke-width="2" stroke-dasharray="8 6"/>')
        lines.append(f'<text x="{max(16,left+12)}" y="{max(24,top+23)}" font-size="12" font-family="monospace" fill="#315B73">{esc((zone.display_id + " · " if zone else "") + (zone.name if zone else zone_id))}</text>')
    for flow in flows:
        start, end = positions[flow.source_id], positions[flow.target_id]
        dash = ' stroke-dasharray="9 6"' if flow.boundary_crossings or flow.crossing_status == "unresolved" else ""
        canonical_ids = ",".join(flow.canonical_flow_ids)
        lines.append(f'<g data-projection-flow-id="{esc(flow.id)}" data-canonical-flow-ids="{esc(canonical_ids)}"><line x1="{start["x"]}" y1="{start["y"]}" x2="{end["x"]}" y2="{end["y"]}" stroke="#6C91AA" stroke-width="2"{dash} marker-end="url(#arrow)"/>')
        label = ", ".join(next((item.name for item in model.data_objects if item.id == data_id), data_id) for data_id in flow.data_object_ids) or flow.name
        lines.append(f'<text x="{(start["x"]+end["x"])/2}" y="{(start["y"]+end["y"])/2-8}" text-anchor="middle" font-size="11" font-family="monospace" fill="#344E5C">{esc(flow.display_id)} · {esc(label)}</text></g>')
    for node in nodes:
        point = positions[node.id]
        x, y = point["x"], point["y"]
        canonical_ids = ",".join(node.canonical_node_ids)
        if node.type == "entity":
            shape = f'<ellipse cx="{x}" cy="{y}" rx="78" ry="34" fill="#EFF6FF" stroke="#2563EB" stroke-width="2"/>'
        elif node.type == "data_store":
            shape = f'<path d="M{x-76},{y-30}h152v60h-152z" fill="#F5F3FF" stroke="#6D28D9" stroke-width="2"/><path d="M{x-76},{y-30}q76,18 152,0" fill="none" stroke="#6D28D9" stroke-width="2"/>'
        elif node.type == "system":
            shape = f'<rect x="{x-87}" y="{y-36}" width="174" height="72" rx="18" fill="#ECFDF5" stroke="#15803D" stroke-width="3"/>'
        else:
            shape = f'<rect x="{x-82}" y="{y-32}" width="164" height="64" rx="12" fill="#F8FAFC" stroke="#64748B" stroke-width="2"/>'
        label = f"{node.display_id} {node.name}"
        lines.append(f'<g data-projection-node-id="{esc(node.id)}" data-canonical-node-ids="{esc(canonical_ids)}">{shape}<text x="{x}" y="{y+4}" text-anchor="middle" font-size="12" fill="#1F2937">{esc(label[:72])}</text></g>')
    footer = f'{payload["level"]} · revision {model.revision} · validation {status} · {payload["counts"]["hidden_internal_node_details"]} internal details aggregated'
    lines.append(f'<text x="20" y="{height-25}" font-size="11" fill="#526777">{esc(footer)}</text>')
    lines.append('</svg>')
    return "".join(lines)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _semantic_delta(previous: DfdModel, current: DfdModel) -> dict:
    def changed_ids(old_items, new_items, field_names):
        old_by_id = {item.id: item for item in old_items}
        new_by_id = {item.id: item for item in new_items}
        changed = []
        for item_id in sorted(set(old_by_id) | set(new_by_id)):
            old, new = old_by_id.get(item_id), new_by_id.get(item_id)
            if old is None or new is None or any(getattr(old, field) != getattr(new, field) for field in field_names):
                changed.append(item_id)
        return changed

    old_views = {view.id: view.projection_mappings for view in previous.views}
    new_views = {view.id: view.projection_mappings for view in current.views}
    return {
        "scope_changed_node_ids": changed_ids(previous.nodes, current.nodes, ["scope"]),
        "parent_child_changed_node_ids": changed_ids(previous.nodes, current.nodes, ["parent_process_id"]),
        "flow_mapping_changed_ids": changed_ids(previous.flows, current.flows, [
            "source_id", "target_id", "data_object_ids", "boundary_crossings", "grounding_status",
        ]),
        "boundary_review_changed_ids": changed_ids(previous.boundaries, current.boundaries, ["status", "transition_scope"]),
        "projection_mapping_changed_view_ids": sorted(
            view_id for view_id in set(old_views) | set(new_views) if old_views.get(view_id) != new_views.get(view_id)
        ),
    }


def _stale(report: dict, reason: str):
    current = report.get("analysis_stale") if isinstance(report.get("analysis_stale"), dict) else {}
    report["analysis_stale"] = {
        "stages": sorted(set([*(current.get("stages") or []), *DOWNSTREAM_STAGES])),
        "reason": reason,
        "changed_at": _utc_now(),
    }


def _hydrate_model_evidence(model: DfdModel, project: dict | None) -> DfdModel:
    """Backfill evidence envelopes for legacy reports without changing semantics."""
    refs: list[str] = []

    def collect(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "evidence_refs" and isinstance(item, list):
                    refs.extend(str(ref) for ref in item if ref)
                else:
                    collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    collect(model.model_dump(exclude={"evidence"}))
    known = {evidence.id for evidence in model.evidence}
    generated = _model_evidence(project or {}, [ref for ref in refs if ref not in known])
    model.evidence = [*model.evidence, *(item for item in generated if item.id not in known)]
    return model


def _load_model(project_id: str) -> tuple[dict, DfdModel]:
    report, stored_payload = get_project_report_and_dfd(project_id)
    report = report if isinstance(report, dict) else {}
    report_payload = report.get("dfd_model") if isinstance(report, dict) else None
    if not report and not stored_payload:
        raise HTTPException(status_code=404, detail="No canonical DFD model yet — run analysis first")
    if stored_payload and (
        not isinstance(report_payload, dict)
        or int(stored_payload.get("revision", 0) or 0) >= int(report_payload.get("revision", 0) or 0)
    ):
        payload = stored_payload
    else:
        payload = report_payload
    if not isinstance(payload, dict):
        raise HTTPException(status_code=404, detail="No canonical DFD model yet — run analysis first")
    # load_dfd_model rebuilds deterministic projections while normalizing the
    # model, so detect the pre-migration payload before that enrichment occurs.
    legacy_hierarchy = bool(payload.get("nodes")) and any(
        not isinstance(view, dict) or not view.get("projection_nodes")
        for view in (payload.get("views") or [])
    )
    try:
        model, migrated = load_dfd_model(payload, project_id=project_id)
    except (ValidationError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=500, detail="Stored canonical DFD model is invalid") from exc
    model = _hydrate_model_evidence(model, get_project(project_id))
    sync_dfd_views(model)
    recalculate_boundary_crossings(model)
    hydrated_payload = model.model_dump()
    expected_dfd_revision = int((stored_payload or report_payload or {}).get("revision", 0) or 0)
    hierarchy_semantic_changed = legacy_hierarchy
    if hierarchy_semantic_changed:
        model.revision = max(model.revision, expected_dfd_revision) + 1
        hydrated_payload = model.model_dump()
        report["dfd_model"] = hydrated_payload
        report["dfd_validation"] = validate_dfd_model(model)
        _stale(report, "DFD hierarchy projections were migrated; rerun dependent analysis and review the new level mappings.")
        _refresh_quality_gate(report)
        save_report_and_dfd(
            project_id,
            report,
            hydrated_payload,
            expected_report_revision=int(report.get("report_revision", 0) or 0),
            expected_dfd_revision=expected_dfd_revision,
        )
        log_event("dfd.hierarchy_migrated", details={
            "project_id": project_id,
            "from_revision": expected_dfd_revision,
            "to_revision": model.revision,
            "validation_status": "valid" if validate_dfd_model(model)["valid"] else "review",
        })
    elif migrated or not stored_payload or payload is report_payload or hydrated_payload != payload:
        save_dfd_model(project_id, hydrated_payload, expected_revision=expected_dfd_revision)
    return report or {}, model


def _project_for_request(project_id: str, request: Request = None) -> dict | None:
    # Keep direct service-style calls used by the existing unit tests
    # patchable, while HTTP requests go through the workspace guard.
    return get_project(project_id) if request is None else get_authorized_project(project_id, request)


@router.get("/{project_id}/dfd")
async def get_dfd(project_id: str, request: Request = None, view_id: str | None = None):
    if not _project_for_request(project_id, request):
        raise HTTPException(status_code=404, detail="Project not found")
    report, model = _load_model(project_id)
    response = {
        "model": model.model_dump(),
        "validation": validate_dfd_model(model),
    }
    if view_id:
        view = _resolve_dfd_view(model, view_id)
        if not view:
            raise HTTPException(status_code=404, detail=f"Unknown DFD view: {view_id}")
        response["projection"] = _projection_payload(model, view, response["validation"])
    return response


@router.put("/{project_id}/dfd", dependencies=[require_roles("analyst", "admin")])
async def save_dfd(project_id: str, body: dict, request: Request = None):
    """Persist a validated semantic model without overwriting newer edits."""
    if not _project_for_request(project_id, request):
        raise HTTPException(status_code=404, detail="Project not found")
    if not isinstance(body, dict) or not isinstance(body.get("model"), dict):
        raise HTTPException(status_code=422, detail="Request must contain a model object")

    report, current = _load_model(project_id)
    expected_revision = body.get("expected_revision")
    try:
        expected_revision_value = int(expected_revision) if expected_revision is not None else None
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="expected_revision must be an integer") from exc
    if expected_revision_value is not None and expected_revision_value != current.revision:
        raise HTTPException(
            status_code=409,
            detail={"message": "DFD revision conflict", "current_revision": current.revision},
        )
    try:
        model, _migrated = load_dfd_model(body["model"], project_id=project_id)
    except (ValidationError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Canonical DFD schema validation failed") from exc
    _hydrate_model_evidence(model, get_project(project_id))
    sync_dfd_views(model)

    if model.project_id != project_id or model.id != current.id:
        raise HTTPException(status_code=422, detail="DFD project_id or model id cannot be changed")

    recalculate_boundary_crossings(model)
    submitted_semantic_changed = model.semantic_hash != current.semantic_hash
    if submitted_semantic_changed:
        refresh_attribute_assertions(model)
        recalculate_boundary_crossings(model)
    validation = validate_dfd_model(model)
    if not validation["valid"]:
        raise HTTPException(status_code=422, detail={"message": "DFD graph validation failed", **validation})

    semantic_changed = model.semantic_hash != current.semantic_hash
    model.revision = current.revision + 1 if semantic_changed else current.revision
    model.layout_revision = max(current.layout_revision, model.layout_revision) + 1
    model.human_edit_revision = current.human_edit_revision + (1 if semantic_changed else 0)
    model.source_semantic_hash = current.source_semantic_hash or current.semantic_hash
    model_payload = model.model_dump()
    report["dfd_model"] = model_payload
    report["dfd_validation"] = validation
    if semantic_changed:
        _stale(report, "Canonical DFD semantic model edited. Refresh dependent analysis stages.")
    quality_gate = _refresh_quality_gate(report)
    save_report_and_dfd(
        project_id,
        report,
        model_payload,
        expected_report_revision=int(report.get("report_revision", 0) or 0),
        expected_dfd_revision=current.revision,
    )
    log_event("dfd.saved", details={
        "project_id": project_id,
        "revision": model.revision,
        "layout_revision": model.layout_revision,
        "semantic_changed": semantic_changed,
        "semantic_delta": _semantic_delta(current, model) if semantic_changed else {},
    })
    return {
        "success": True,
        "model": model.model_dump(),
        "validation": validation,
        "semantic_changed": semantic_changed,
        "quality_gate": quality_gate,
    }


@router.post("/{project_id}/dfd/proposal/apply", dependencies=[require_roles("analyst", "admin")])
async def apply_dfd_regeneration_proposal(project_id: str, body: dict, request: Request = None):
    """Apply only an explicitly reviewed source-regeneration proposal."""
    if not _project_for_request(project_id, request):
        raise HTTPException(status_code=404, detail="Project not found")
    report, current = _load_model(project_id)
    proposal = report.get("dfd_proposal")
    if not isinstance(proposal, dict) or not isinstance(proposal.get("candidate_model"), dict):
        raise HTTPException(status_code=404, detail="No reviewable DFD regeneration proposal")
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="Request body is required")
    try:
        expected_revision = int(body.get("expected_revision"))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="expected_revision must be an integer") from exc
    if expected_revision != current.revision:
        raise HTTPException(
            status_code=409,
            detail={"message": "DFD revision conflict", "current_revision": current.revision},
        )

    try:
        candidate, _migrated = load_dfd_model(proposal["candidate_model"], project_id=project_id)
    except (ValidationError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Stored DFD proposal candidate is invalid") from exc
    _hydrate_model_evidence(candidate, get_project(project_id))
    sync_dfd_views(candidate)
    if candidate.project_id != project_id or candidate.id != current.id:
        raise HTTPException(status_code=422, detail="DFD proposal identity does not match the project model")

    # Normalize both sides before a partial apply so legacy models without
    # per-attribute assertions do not appear as unrelated changes in every
    # proposal section.
    refresh_attribute_assertions(current)
    sync_dfd_views(current)
    recalculate_boundary_crossings(current)
    refresh_attribute_assertions(candidate)
    sync_dfd_views(candidate)
    recalculate_boundary_crossings(candidate)

    if body.get("accept_all"):
        selected_sections = list(PROPOSAL_SECTIONS)
    else:
        selected_sections = body.get("sections")
        if not isinstance(selected_sections, list) or not selected_sections:
            raise HTTPException(
                status_code=422,
                detail={"message": "Select proposal sections or set accept_all=true", "sections": list(PROPOSAL_SECTIONS)},
            )
        if any(section not in PROPOSAL_SECTIONS for section in selected_sections):
            raise HTTPException(status_code=422, detail={"message": "Unsupported proposal section", "sections": list(PROPOSAL_SECTIONS)})

    try:
        model = apply_dfd_proposal(current, candidate, selected_sections)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    refresh_attribute_assertions(model)
    validation = validate_dfd_model(model)
    if not validation["valid"]:
        raise HTTPException(status_code=422, detail={"message": "Applied DFD proposal is invalid", **validation})

    model.revision = current.revision + 1
    model.layout_revision = max(current.layout_revision, model.layout_revision) + 1
    model.human_edit_revision = current.human_edit_revision + 1
    remaining = diff_dfd_models(model, candidate)
    has_remaining = any(
        section.get("added") or section.get("removed") or section.get("changed")
        for section in remaining["sections"].values()
    )
    if has_remaining:
        model.source_semantic_hash = current.source_semantic_hash or current.semantic_hash
        report["dfd_proposal"] = {
            **remaining,
            "candidate_model": candidate.model_dump(),
            "selected_sections": selected_sections,
        }
    else:
        model.source_semantic_hash = candidate.semantic_hash
        report.pop("dfd_proposal", None)
    model_payload = model.model_dump()
    report["dfd_model"] = model_payload
    report["dfd_validation"] = validation
    _stale(report, "A reviewed DFD regeneration proposal changed the canonical semantic model. Refresh dependent analysis stages.")
    quality_gate = _refresh_quality_gate(report)
    save_report_and_dfd(
        project_id,
        report,
        model_payload,
        expected_report_revision=int(report.get("report_revision", 0) or 0),
        expected_dfd_revision=current.revision,
    )
    log_event("dfd.proposal_applied", details={
        "project_id": project_id,
        "revision": model.revision,
        "sections": selected_sections,
        "remaining": has_remaining,
    })
    return {
        "success": True,
        "model": model.model_dump(),
        "validation": validation,
        "proposal": report.get("dfd_proposal"),
        "semantic_changed": True,
        "quality_gate": quality_gate,
    }


@router.get("/{project_id}/dfd/export")
async def export_dfd(
    project_id: str,
    format: str = "svg",
    request: Request = None,
    view_id: str | None = None,
    level: str | None = None,
):
    """Export the canonical model or one mapped DFD level as JSON/SVG."""
    normalized_format = format.lower()
    if normalized_format not in {"svg", "json", "projection-json"}:
        raise HTTPException(status_code=400, detail="Unsupported DFD export format. Use: json, projection-json, or svg")
    if not _project_for_request(project_id, request):
        raise HTTPException(status_code=404, detail="Project not found")
    _, model = _load_model(project_id)
    validation = validate_dfd_model(model)
    if not validation["valid"]:
        raise HTTPException(status_code=422, detail={"message": "Cannot export invalid DFD", **validation})
    selector = view_id or level
    if selector and selector.lower() in {"l0", "l1", "l2"}:
        selector = {"l0": "context", "l1": "system"}.get(selector.lower())
        if selector is None:
            raise HTTPException(status_code=400, detail="L2 has multiple feature projections; provide view_id=feature:<parent_process_id>")
    selected_view = _resolve_dfd_view(model, selector) if selector else None
    if selector and not selected_view:
        raise HTTPException(status_code=404, detail=f"Unknown DFD view or level: {selector}")
    if normalized_format == "projection-json":
        if not selected_view:
            raise HTTPException(status_code=400, detail="projection-json requires view_id or level")
        projection = _projection_payload(model, selected_view, validation)
        log_event("dfd.projection_exported", details={
            "project_id": project_id,
            "format": "projection-json",
            "view_id": selected_view.id,
            "revision": model.revision,
        })
        return JSONResponse(
            content=projection,
            headers={"Content-Disposition": f"attachment; filename=dfd-{project_id}-{selected_view.id}.json"},
        )
    if normalized_format == "json":
        if selector:
            raise HTTPException(status_code=400, detail="Use format=projection-json for a selected DFD view; json always exports the full canonical model")
        log_event("dfd.exported", details={"project_id": project_id, "format": "json", "revision": model.revision})
        return JSONResponse(
            content=model.model_dump(),
            headers={"Content-Disposition": f"attachment; filename=dfd-{project_id}.json"},
        )

    if selected_view:
        svg_content = _render_projection_svg(model, selected_view, validation)
        log_event("dfd.projection_exported", details={
            "project_id": project_id,
            "format": "svg",
            "view_id": selected_view.id,
            "revision": model.revision,
        })
        return Response(
            content=svg_content,
            media_type="image/svg+xml",
            headers={"Content-Disposition": f"attachment; filename=dfd-{project_id}-{selected_view.id}.svg"},
        )

    node_by_id = {node.id: node for node in model.nodes}
    positions, canvas_width, canvas_height = _auto_layout_dfd(model)

    def text(value) -> str:
        return escape(str(value or ""), quote=True)

    def node_shape(node, x: float, y: float) -> str:
        label = f"{node.display_id} {node.name}"
        if node.type == "data_store":
            return f'<path d="M{x-72},{y-28} h144 v56 h-144 z" fill="#F5F3FF" stroke="#6D28D9" stroke-width="2"/><path d="M{x-72},{y-28} q72,18 144,0" fill="none" stroke="#6D28D9" stroke-width="2"/>'
        if node.type == "entity":
            return f'<ellipse cx="{x}" cy="{y}" rx="76" ry="32" fill="#EFF6FF" stroke="#2563EB" stroke-width="2"/>'
        return f'<rect x="{x-82}" y="{y-32}" width="164" height="64" rx="14" fill="#F8FAFC" stroke="#64748B" stroke-width="2"/>'

    def wrap_label(value: str, max_chars: int = 27) -> list[str]:
        words = str(value).split()
        lines: list[str] = []
        current = ""
        for word in words:
            candidate = f"{current} {word}".strip()
            if current and len(candidate) > max_chars:
                lines.append(current)
                current = word
            else:
                current = candidate
        if current:
            lines.append(current)
        return lines or [""]

    def node_text(node, x: float, y: float) -> str:
        lines = wrap_label(f"{node.display_id} {node.name}")[:3]
        start_y = y - (len(lines) - 1) * 7
        return "".join(
            f'<text x="{x}" y="{start_y + index * 14}" text-anchor="middle" font-size="12" fill="#1F2937">{text(line)}</text>'
            for index, line in enumerate(lines)
        )

    def zone_depth(zone_id: str) -> int:
        depth = 0
        current = next((zone for zone in model.zones if zone.id == zone_id), None)
        visited: set[str] = set()
        while current and current.parent_zone_id and current.parent_zone_id not in visited:
            visited.add(current.id)
            depth += 1
            current = next((zone for zone in model.zones if zone.id == current.parent_zone_id), None)
        return depth

    def descendants(zone_id: str) -> set[str]:
        result = {zone_id}
        changed = True
        while changed:
            changed = False
            for zone in model.zones:
                if zone.parent_zone_id in result and zone.id not in result:
                    result.add(zone.id)
                    changed = True
        return result

    zone_palette = [
        ("#457B9D", "#EFF6FF"),
        ("#6D28D9", "#F5F3FF"),
        ("#D97706", "#FFF7ED"),
        ("#DC2626", "#FEF2F4"),
    ]
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {canvas_width} {canvas_height}" role="img" aria-labelledby="dfd-title dfd-desc">',
        f'<title id="dfd-title">{text(model.title)} — canonical DFD revision {model.revision}</title>',
        '<desc id="dfd-desc">Canonical semantic DFD export with zone containers, directed data flows, and evidence-reviewable boundary crossings. Dashed arrows indicate boundary crossings or unresolved membership.</desc>',
        '<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#526777"/></marker></defs>',
        f'<rect width="{canvas_width}" height="{canvas_height}" fill="#FFFFFF"/>',
    ]

    for zone in sorted(model.zones, key=zone_depth):
        zone_ids = descendants(zone.id)
        zone_nodes = [
            node for node in model.nodes
            if any(zone_id in zone_ids for zone_id in node.zone_ids)
        ]
        points = [positions[node.id] for node in zone_nodes if node.id in positions]
        if not points:
            continue
        accent, fill = zone_palette[min(zone_depth(zone.id), len(zone_palette) - 1)]
        left = min(point["x"] for point in points) - 105
        top = min(point["y"] for point in points) - 58
        right = max(point["x"] for point in points) + 105
        bottom = max(point["y"] for point in points) + 55
        lines.append(
            f'<rect x="{max(4, left)}" y="{max(4, top)}" width="{max(150, right - left)}" height="{max(110, bottom - top)}" '
            f'rx="18" fill="{fill}" fill-opacity="0.55" stroke="{accent}" stroke-width="2" stroke-dasharray="8 6"/>'
        )
        lines.append(
            f'<text x="{max(16, left + 14)}" y="{max(24, top + 25)}" font-size="12" font-family="monospace" font-weight="600" fill="{accent}">{text(f"{zone.display_id} · {zone.name}")}</text>'
        )

    for index, flow in enumerate(model.flows):
        source = node_by_id.get(flow.source_id)
        target = node_by_id.get(flow.target_id)
        if not source or not target:
            continue
        start = positions[source.id]
        end = positions[target.id]
        crossing = bool(flow.boundary_crossings) or flow.crossing_status == "unresolved"
        dash = ' stroke-dasharray="10 7"' if crossing else ""
        lines.append(
            f'<line id="flow-{index}" x1="{float(start.get("x", 0))}" y1="{float(start.get("y", 0))}" '
            f'x2="{float(end.get("x", 0))}" y2="{float(end.get("y", 0))}" stroke="#6C91AA" stroke-width="2"{dash} marker-end="url(#arrow)"/>'
        )
        data_label = ", ".join(
            next((item.name for item in model.data_objects if item.id == data_id), data_id)
            for data_id in flow.data_object_ids
        ) or flow.name
        mid_x = (float(start.get("x", 0)) + float(end.get("x", 0))) / 2
        mid_y = (float(start.get("y", 0)) + float(end.get("y", 0))) / 2 - 8
        lines.append(f'<text x="{mid_x}" y="{mid_y}" text-anchor="middle" font-size="12" font-family="monospace" fill="#344E5C">{text(flow.display_id)} · {text(data_label)}</text>')
    for node in model.nodes:
        position = positions[node.id]
        x = float(position.get("x", 0))
        y = float(position.get("y", 0))
        lines.append(node_shape(node, x, y))
        lines.append(node_text(node, x, y))
    lines.append('</svg>')
    return Response(
        content="".join(lines),
        media_type="image/svg+xml",
        headers={"Content-Disposition": f"attachment; filename=dfd-{project_id}.svg"},
    )


@router.post("/{project_id}/dfd/proposal/resolve", dependencies=[require_roles("reviewer", "admin")])
async def resolve_dfd_regeneration_proposal(project_id: str, body: dict, request: Request = None):
    """Resolve a pending regeneration proposal without silently changing the model."""
    if not _project_for_request(project_id, request):
        raise HTTPException(status_code=404, detail="Project not found")
    report, current = _load_model(project_id)
    proposal = report.get("dfd_proposal")
    if not isinstance(proposal, dict) or not isinstance(proposal.get("candidate_model"), dict):
        raise HTTPException(status_code=404, detail="No reviewable DFD regeneration proposal")
    if not isinstance(body, dict) or body.get("action") != "dismiss":
        raise HTTPException(status_code=422, detail="Only explicit dismiss action is supported")
    try:
        expected_revision = int(body.get("expected_revision"))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="expected_revision must be an integer") from exc
    if expected_revision != current.revision:
        raise HTTPException(
            status_code=409,
            detail={"message": "DFD revision conflict", "current_revision": current.revision},
        )
    resolved_at = _utc_now()
    history_item = {
        "resolved_at": resolved_at,
        "resolution": "dismissed",
        "base_revision": proposal.get("base_revision", current.revision),
        "candidate_revision": proposal.get("candidate_revision"),
        "sections": proposal.get("sections") or {},
    }
    history = report.setdefault("dfd_proposal_history", [])
    history.append(history_item)
    report["dfd_proposal_history"] = history[-20:]
    report["dfd_proposal_resolution"] = {
        "resolution": "dismissed",
        "resolved_at": resolved_at,
        "base_revision": current.revision,
        "reason": str(body.get("reason") or "Source proposal was dismissed; the reviewed canonical model remains authoritative.")[:1000],
    }
    report.pop("dfd_proposal", None)
    stale = report.get("analysis_stale")
    if isinstance(stale, dict) and str(stale.get("reason") or "").startswith("Source context changed while a human-edited DFD exists"):
        report.pop("analysis_stale", None)
    quality_gate = _refresh_quality_gate(report)
    save_report(project_id, report)
    log_event("dfd.proposal_dismissed", details={"project_id": project_id, "revision": current.revision})
    return {
        "success": True,
        "resolution": report["dfd_proposal_resolution"],
        "model": current.model_dump(),
        "proposal": None,
        "quality_gate": quality_gate,
    }


@router.post("/{project_id}/dfd/import", dependencies=[require_roles("analyst", "admin")])
async def import_dfd(project_id: str, body: dict, request: Request = None):
    """Import a schema-validated canonical DFD through the normal save path."""
    if not isinstance(body, dict) or not isinstance(body.get("model"), dict):
        raise HTTPException(status_code=422, detail="Request must contain an exported model object")
    return await save_dfd(project_id, body, request=request)


@router.post("/{project_id}/dfd/impact-preview", dependencies=[require_roles("analyst", "reviewer", "admin")])
async def dfd_impact_preview(project_id: str, body: dict, request: Request = None):
    """Return deletion dependencies without mutating the canonical model."""
    if not _project_for_request(project_id, request):
        raise HTTPException(status_code=404, detail="Project not found")
    report, model = _load_model(project_id)
    if not isinstance(body, dict) or not body.get("element_type") or not body.get("element_id"):
        raise HTTPException(status_code=422, detail="element_type and element_id are required")
    try:
        return preview_dfd_delete_impact(
            model,
            str(body["element_type"]),
            str(body["element_id"]),
            report.get("threats") or [],
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="DFD element not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
