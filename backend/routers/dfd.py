"""Canonical DFD persistence and revision-safe editing endpoints."""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError

from backend.models.dfd import DfdModel
from backend.services.dfd_model_service import (
    PROPOSAL_SECTIONS,
    apply_dfd_proposal,
    diff_dfd_models,
    preview_dfd_delete_impact,
    recalculate_boundary_crossings,
    validate_dfd_model,
)
from backend.utils.audit import log_event
from backend.utils.storage import get_project, get_report, save_report


router = APIRouter(prefix="/api/projects", tags=["dfd"])
DOWNSTREAM_STAGES = ["stride", "linddun", "controls", "tests", "missing_info", "assumptions"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _stale(report: dict, reason: str):
    current = report.get("analysis_stale") if isinstance(report.get("analysis_stale"), dict) else {}
    report["analysis_stale"] = {
        "stages": sorted(set([*(current.get("stages") or []), *DOWNSTREAM_STAGES])),
        "reason": reason,
        "changed_at": _utc_now(),
    }


def _load_model(project_id: str) -> tuple[dict, DfdModel]:
    report = get_report(project_id)
    if not report or not report.get("dfd_model"):
        raise HTTPException(status_code=404, detail="No canonical DFD model yet — run analysis first")
    try:
        model = DfdModel.model_validate(report["dfd_model"])
    except ValidationError as exc:
        raise HTTPException(status_code=500, detail="Stored canonical DFD model is invalid") from exc
    return report, model


@router.get("/{project_id}/dfd")
async def get_dfd(project_id: str):
    if not get_project(project_id):
        raise HTTPException(status_code=404, detail="Project not found")
    report, model = _load_model(project_id)
    return {
        "model": model.model_dump(),
        "validation": report.get("dfd_validation") or validate_dfd_model(model),
    }


@router.put("/{project_id}/dfd")
async def save_dfd(project_id: str, body: dict):
    """Persist a validated semantic model without overwriting newer edits."""
    if not get_project(project_id):
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
        model = DfdModel.model_validate(body["model"])
    except (ValidationError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Canonical DFD schema validation failed") from exc

    if model.project_id != project_id or model.id != current.id:
        raise HTTPException(status_code=422, detail="DFD project_id or model id cannot be changed")

    recalculate_boundary_crossings(model)
    validation = validate_dfd_model(model)
    if not validation["valid"]:
        raise HTTPException(status_code=422, detail={"message": "DFD graph validation failed", **validation})

    semantic_changed = model.semantic_hash != current.semantic_hash
    model.revision = current.revision + 1 if semantic_changed else current.revision
    model.layout_revision = max(current.layout_revision, model.layout_revision) + 1
    model.human_edit_revision = current.human_edit_revision + (1 if semantic_changed else 0)
    model.source_semantic_hash = current.source_semantic_hash or current.semantic_hash
    report["dfd_model"] = model.model_dump()
    report["dfd_validation"] = validation
    if semantic_changed:
        _stale(report, "Canonical DFD semantic model edited. Refresh dependent analysis stages.")
    save_report(project_id, report)
    log_event("dfd.saved", details={
        "project_id": project_id,
        "revision": model.revision,
        "layout_revision": model.layout_revision,
        "semantic_changed": semantic_changed,
    })
    return {
        "success": True,
        "model": model.model_dump(),
        "validation": validation,
        "semantic_changed": semantic_changed,
    }


@router.post("/{project_id}/dfd/proposal/apply")
async def apply_dfd_regeneration_proposal(project_id: str, body: dict):
    """Apply only an explicitly reviewed source-regeneration proposal."""
    if not get_project(project_id):
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
        candidate = DfdModel.model_validate(proposal["candidate_model"])
    except (ValidationError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Stored DFD proposal candidate is invalid") from exc
    if candidate.project_id != project_id or candidate.id != current.id:
        raise HTTPException(status_code=422, detail="DFD proposal identity does not match the project model")

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
    report["dfd_model"] = model.model_dump()
    report["dfd_validation"] = validation
    _stale(report, "A reviewed DFD regeneration proposal changed the canonical semantic model. Refresh dependent analysis stages.")
    save_report(project_id, report)
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
    }


@router.get("/{project_id}/dfd/export")
async def export_dfd(project_id: str, format: str = "svg"):
    """Export the canonical model as schema-versioned JSON or escaped SVG."""
    normalized_format = format.lower()
    if normalized_format not in {"svg", "json"}:
        raise HTTPException(status_code=400, detail="Unsupported DFD export format. Use: json or svg")
    if not get_project(project_id):
        raise HTTPException(status_code=404, detail="Project not found")
    _, model = _load_model(project_id)
    validation = validate_dfd_model(model)
    if not validation["valid"]:
        raise HTTPException(status_code=422, detail={"message": "Cannot export invalid DFD", **validation})
    if normalized_format == "json":
        log_event("dfd.exported", details={"project_id": project_id, "format": "json", "revision": model.revision})
        return JSONResponse(
            content=model.model_dump(),
            headers={"Content-Disposition": f"attachment; filename=dfd-{project_id}.json"},
        )

    context_view = next((view for view in model.views if view.kind == "context"), None)
    positions = context_view.positions if context_view else {}
    node_by_id = {node.id: node for node in model.nodes}
    positions = {
        node.id: positions.get(node.id) or {
            "x": 160 + (index % 4) * 240,
            "y": 120 + (index // 4) * 180,
        }
        for index, node in enumerate(model.nodes)
    }

    def text(value) -> str:
        return escape(str(value or ""), quote=True)

    def node_shape(node, x: float, y: float) -> str:
        label = f"{node.display_id} {node.name}"
        if node.type == "data_store":
            return f'<path d="M{x-72},{y-28} h144 v56 h-144 z" fill="#F5F3FF" stroke="#6D28D9" stroke-width="2"/><path d="M{x-72},{y-28} q72,18 144,0" fill="none" stroke="#6D28D9" stroke-width="2"/>'
        if node.type == "entity":
            return f'<ellipse cx="{x}" cy="{y}" rx="76" ry="32" fill="#EFF6FF" stroke="#2563EB" stroke-width="2"/>'
        return f'<rect x="{x-82}" y="{y-32}" width="164" height="64" rx="14" fill="#F8FAFC" stroke="#64748B" stroke-width="2"/>'

    lines = [
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 760" role="img" aria-labelledby="dfd-title dfd-desc">',
        f'<title id="dfd-title">{text(model.title)} — canonical DFD revision {model.revision}</title>',
        '<desc id="dfd-desc">Escaped semantic DFD export. Dashed arrows indicate boundary crossings or unresolved membership.</desc>',
        '<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#526777"/></marker></defs>',
        '<rect width="1200" height="760" fill="#FFFFFF"/>',
    ]
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
            f'x2="{float(end.get("x", 0))}" y2="{float(end.get("y", 0))}" stroke="#D06B55" stroke-width="2"{dash} marker-end="url(#arrow)"/>'
        )
        data_label = ", ".join(
            next((item.name for item in model.data_objects if item.id == data_id), data_id)
            for data_id in flow.data_object_ids
        ) or flow.name
        mid_x = (float(start.get("x", 0)) + float(end.get("x", 0))) / 2
        mid_y = (float(start.get("y", 0)) + float(end.get("y", 0))) / 2 - 8
        lines.append(f'<text x="{mid_x}" y="{mid_y}" font-size="12" fill="#526777">{text(flow.display_id)} · {text(data_label)}</text>')
    for node in model.nodes:
        position = positions[node.id]
        x = float(position.get("x", 0))
        y = float(position.get("y", 0))
        lines.append(node_shape(node, x, y))
        lines.append(f'<text x="{x}" y="{y+4}" text-anchor="middle" font-size="13" fill="#1F2937">{text(f"{node.display_id} {node.name}")}</text>')
    lines.append('</svg>')
    return Response(
        content="".join(lines),
        media_type="image/svg+xml",
        headers={"Content-Disposition": f"attachment; filename=dfd-{project_id}.svg"},
    )


@router.post("/{project_id}/dfd/import")
async def import_dfd(project_id: str, body: dict):
    """Import a schema-validated canonical DFD through the normal save path."""
    if not isinstance(body, dict) or not isinstance(body.get("model"), dict):
        raise HTTPException(status_code=422, detail="Request must contain an exported model object")
    return await save_dfd(project_id, body)


@router.post("/{project_id}/dfd/impact-preview")
async def dfd_impact_preview(project_id: str, body: dict):
    """Return deletion dependencies without mutating the canonical model."""
    if not get_project(project_id):
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
