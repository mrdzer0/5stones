"""FastAPI routers — Projects CRUD."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from datetime import datetime
from backend.models.schemas import ProjectCreate, Project
from backend.utils.storage import save_project, get_project, list_projects, delete_project, REPORTS_DIR
from backend.utils.audit import log_event
from backend.services.posture_service import compute_completeness

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
    return projects


@router.post("")
async def create_project(data: ProjectCreate):
    project = Project(**data.model_dump())
    payload = project.model_dump()
    completeness = compute_completeness(payload)
    payload["completeness_score"] = completeness["score"]
    payload["completeness_level"] = completeness["level"]
    saved = save_project(payload)
    log_event("project.created", details={"project_id": saved["project_id"], "name": saved["name"]})
    return saved


@router.get("/{project_id}")
async def get_project_detail(project_id: str):
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    completeness = compute_completeness(project)
    project["completeness_score"] = completeness["score"]
    project["completeness_level"] = completeness["level"]
    project["completeness"] = completeness
    return project


@router.put("/{project_id}")
async def update_project(project_id: str, data: dict):
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    project.update(data)
    project["updated_at"] = datetime.utcnow().isoformat()
    completeness = compute_completeness(project)
    project["completeness_score"] = completeness["score"]
    project["completeness_level"] = completeness["level"]
    saved = save_project(project)
    log_event("project.updated", details={"project_id": project_id})
    return saved


@router.delete("/{project_id}")
async def remove_project(project_id: str):
    if not delete_project(project_id):
        raise HTTPException(status_code=404, detail="Project not found")
    log_event("project.deleted", details={"project_id": project_id})
    return {"success": True, "message": "Project deleted"}
