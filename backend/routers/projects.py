"""FastAPI routers — Projects CRUD."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from datetime import datetime
from backend.models.schemas import ProjectCreate, Project
from backend.utils.storage import save_project, get_project, list_projects, delete_project, REPORTS_DIR
from backend.utils.audit import log_event
from backend.services.posture_service import compute_completeness
from backend.services.artifact_reconciliation_service import (
    LIST_CONTEXT_FIELDS,
    capture_manual_context,
    project_client_view,
    rebuild_project_from_artifacts,
)

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.get("")
async def get_projects():
    projects = list_projects()
    # Enrich with stats
    for p in projects:
        report_path = REPORTS_DIR / f"{p['project_id']}.json"
        p["has_report"] = report_path.exists()
        completeness = compute_completeness(p)
        p["completeness_score"] = completeness["score"]
        p["completeness_level"] = completeness["level"]
    return [project_client_view(project) for project in projects]


@router.post("")
async def create_project(data: ProjectCreate):
    project = Project(**data.model_dump())
    payload = project.model_dump()
    capture_manual_context(payload)
    completeness = compute_completeness(payload)
    payload["completeness_score"] = completeness["score"]
    payload["completeness_level"] = completeness["level"]
    saved = save_project(payload)
    log_event("project.created", details={"project_id": saved["project_id"], "name": saved["name"]})
    return project_client_view(saved)


@router.get("/{project_id}")
async def get_project_detail(project_id: str):
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    completeness = compute_completeness(project)
    project["completeness_score"] = completeness["score"]
    project["completeness_level"] = completeness["level"]
    project["completeness"] = completeness
    return project_client_view(project)


@router.put("/{project_id}")
async def update_project(project_id: str, data: dict):
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    manual_context = capture_manual_context(project, legacy=bool(project.get("artifact_sources")))
    for field in LIST_CONTEXT_FIELDS:
        if field in data and isinstance(data[field], list):
            manual_context[field] = list(data[field])
    if "auth_method" in data:
        manual_context["auth_method"] = str(data.get("auth_method") or "").strip()
    if "has_pii" in data:
        manual_context["has_pii"] = bool(data.get("has_pii"))
    project.update(data)
    project["manual_context"] = manual_context
    if project.get("artifact_sources"):
        rebuild_project_from_artifacts(project)
    project["updated_at"] = datetime.utcnow().isoformat()
    completeness = compute_completeness(project)
    project["completeness_score"] = completeness["score"]
    project["completeness_level"] = completeness["level"]
    saved = save_project(project)
    log_event("project.updated", details={"project_id": project_id})
    return project_client_view(saved)


@router.delete("/{project_id}")
async def remove_project(project_id: str):
    if not delete_project(project_id):
        raise HTTPException(status_code=404, detail="Project not found")
    log_event("project.deleted", details={"project_id": project_id})
    return {"success": True, "message": "Project deleted"}
