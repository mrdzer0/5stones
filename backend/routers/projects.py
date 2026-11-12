"""FastAPI routers — Projects CRUD."""
from __future__ import annotations
from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import Response
from pydantic import ValidationError
from datetime import datetime
from backend.models.schemas import ProjectCreate, Project
from backend.services import local_auth_service
from backend.services.project_archive_service import (
    MAX_ARCHIVE_BYTES,
    ProjectArchiveError,
    ProjectArchiveTooLargeError,
    build_project_archive,
    parse_project_archive,
)
from backend.utils import storage
from backend.utils.storage import (
    ProjectAlreadyExistsError,
    save_project,
    list_projects,
    list_unscoped_projects,
    claim_legacy_project,
    delete_project,
    get_report,
    get_analysis_progress,
)
from backend.utils.audit import log_event
from backend.services.posture_service import (
    compute_completeness,
    compute_signoff_readiness,
    normalize_report_evidence,
)
from backend.services.artifact_reconciliation_service import (
    LIST_CONTEXT_FIELDS,
    capture_manual_context,
    project_client_view,
    rebuild_project_from_artifacts,
)
from backend.services.run_state_service import attach_analysis_state
from backend.utils.access_control import (
    get_authorized_project,
    auth_mode,
    workspace_access_dependency,
    workspace_id_for_request,
    require_roles,
)

router = APIRouter(
    prefix="/api/projects",
    tags=["projects"],
    dependencies=[workspace_access_dependency, require_roles("analyst", "reviewer", "admin")],
)

_PROJECT_EDITABLE_FIELDS = set(ProjectCreate.model_fields) | {"components", "has_pii"}


def _enrich_project_readiness(project: dict) -> dict:
    """Attach current input and sign-off readiness to a project response."""
    completeness = compute_completeness(project)
    project["completeness_score"] = completeness["score"]
    project["completeness_level"] = completeness["level"]

    report = get_report(str(project.get("project_id") or ""))
    project["has_report"] = isinstance(report, dict)
    if isinstance(report, dict):
        report = normalize_report_evidence(report, project)
        # Context can be edited independently after a report is generated. Use
        # the current project assessment so the dashboard cannot expose a stale
        # sign-off decision from the previous analysis run.
        report["completeness"] = completeness
        gate = compute_signoff_readiness(report)
        project["signoff_ready"] = gate["signoff_ready"]
        project["signoff_status"] = gate["status"]
        project["quality_gate"] = gate
        project["risk_summary"] = report.get("risk_summary") or {}
        progress = get_analysis_progress(str(project.get("project_id") or ""))
        projected = attach_analysis_state(
            report,
            project,
            progress if isinstance(progress, dict) and progress.get("run_id") == (report.get("analysis_run") or {}).get("run_id") else None,
        )
        project["analysis_state"] = projected.get("analysis_state")
    else:
        project["signoff_ready"] = False
        project["signoff_status"] = "not_ready"
        project.pop("quality_gate", None)
        project["analysis_state"] = attach_analysis_state({}, project).get("analysis_state")
    return completeness


@router.get("")
async def get_projects(request: Request = None):
    projects = list_projects()
    workspace_id = workspace_id_for_request(request)
    if workspace_id:
        projects = [project for project in projects if project.get("workspace_id") == workspace_id]
    # Enrich with current stats and the same gate used by report/run views.
    for p in projects:
        _enrich_project_readiness(p)
    return [project_client_view(project) for project in projects]


@router.post("", dependencies=[require_roles("analyst", "admin")])
async def create_project(data: ProjectCreate, request: Request = None):
    project = Project(**data.model_dump())
    payload = project.model_dump()
    workspace_id = workspace_id_for_request(request)
    if workspace_id:
        payload["workspace_id"] = workspace_id
    capture_manual_context(payload)
    completeness = compute_completeness(payload)
    payload["completeness_score"] = completeness["score"]
    payload["completeness_level"] = completeness["level"]
    # New Project models carry a schema default timestamp. Storage uses the
    # absence of updated_at to distinguish a new row from a stale deleted copy.
    payload.pop("updated_at", None)
    saved = save_project(payload)
    log_event("project.created", details={"project_id": saved["project_id"], "name": saved["name"]})
    return project_client_view(saved)


@router.get("/legacy-import/status", dependencies=[require_roles("admin")])
async def legacy_import_status(request: Request):
    """Expose legacy recovery only to the sole local administrator account."""
    user = getattr(request.state, "local_auth_user", None)
    if auth_mode() != "local_users" or not isinstance(user, dict):
        return {"available": False, "legacy_project_count": 0}
    if not local_auth_service.is_sole_admin_user(str(user.get("user_id") or "")):
        return {"available": False, "legacy_project_count": 0}
    count = len(list_unscoped_projects())
    return {"available": count > 0, "legacy_project_count": count}


@router.post("/legacy-import", dependencies=[require_roles("admin")])
async def import_legacy_projects(request: Request):
    """Explicitly assign unowned pre-auth projects to the sole local account."""
    user = getattr(request.state, "local_auth_user", None)
    workspace_id = workspace_id_for_request(request)
    if (
        auth_mode() != "local_users"
        or not isinstance(user, dict)
        or not workspace_id
        or not local_auth_service.is_sole_admin_user(str(user.get("user_id") or ""))
    ):
        raise HTTPException(status_code=409, detail="Previous local data can only be recovered by the sole local administrator account.")

    legacy_projects = list_unscoped_projects()
    claimed = []
    for project in legacy_projects:
        recovered = claim_legacy_project(str(project.get("project_id") or ""), workspace_id)
        if recovered:
            claimed.append(recovered)
    log_event("project.legacy_import", details={"project_count": len(claimed)})
    return {
        "success": True,
        "imported_count": len(claimed),
        "projects": [project_client_view(project) for project in claimed],
    }


@router.post("/import-archive", dependencies=[require_roles("analyst", "admin")])
async def import_project_archive(file: UploadFile = File(...), request: Request = None):
    """Import one project archive into the caller's account-owned workspace."""
    try:
        content = await file.read(MAX_ARCHIVE_BYTES + 1)
    finally:
        await file.close()
    if len(content) > MAX_ARCHIVE_BYTES:
        raise HTTPException(status_code=413, detail="Project archive exceeds the 5 MiB upload limit")
    try:
        snapshot = parse_project_archive(content)
    except ProjectArchiveTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except ProjectArchiveError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    workspace_id = workspace_id_for_request(request)
    if not workspace_id:
        raise HTTPException(status_code=403, detail="Project archive import requires an account-scoped workspace")
    try:
        imported = storage.import_project_archive_snapshot(snapshot, workspace_id)
    except ProjectAlreadyExistsError as exc:
        # Do not reveal whether an inaccessible project ID belongs to another account.
        raise HTTPException(status_code=409, detail="A project with this ID already exists, so this archive was not imported.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    _enrich_project_readiness(imported)
    log_event("project.archive_imported", details={"project_id": imported["project_id"]})
    return {"success": True, "project": project_client_view(imported)}


@router.get("/{project_id}")
async def get_project_detail(project_id: str, request: Request = None):
    project = get_authorized_project(project_id, request)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    completeness = _enrich_project_readiness(project)
    project["completeness"] = completeness
    return project_client_view(project)


@router.put("/{project_id}", dependencies=[require_roles("analyst", "admin")])
async def update_project(project_id: str, data: dict, request: Request = None):
    project = get_authorized_project(project_id, request)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    unsupported_fields = set(data) - _PROJECT_EDITABLE_FIELDS
    if unsupported_fields:
        raise HTTPException(
            status_code=422,
            detail={"unsupported_fields": sorted(unsupported_fields)},
        )

    # Validate editable values through the create schema so dict updates cannot
    # bypass enum/type constraints. Keep server-owned identifiers, workspace,
    # timestamps, and revision out of the request merge entirely.
    project_fields = set(ProjectCreate.model_fields)
    current_fields = {field: project.get(field) for field in project_fields}
    submitted_fields = {field: data[field] for field in data if field in project_fields}
    try:
        validated = ProjectCreate.model_validate({**current_fields, **submitted_fields}).model_dump()
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc
    if "components" in data and not isinstance(data["components"], list):
        raise HTTPException(status_code=422, detail="components must be a list")
    if "has_pii" in data and not isinstance(data["has_pii"], bool):
        raise HTTPException(status_code=422, detail="has_pii must be a boolean")

    expected_revision = int(project.get("project_revision", 0) or 0)
    manual_context = capture_manual_context(project, legacy=bool(project.get("artifact_sources")))
    for field in LIST_CONTEXT_FIELDS:
        if field in data:
            value = data[field] if field == "components" else validated[field]
            manual_context[field] = list(value)
    if "auth_method" in data:
        manual_context["auth_method"] = str(validated.get("auth_method") or "").strip()
    if "has_pii" in data:
        manual_context["has_pii"] = data["has_pii"]
    for field in submitted_fields:
        project[field] = validated[field]
    if "components" in data:
        project["components"] = list(data["components"])
    if "has_pii" in data:
        project["has_pii"] = data["has_pii"]
    project["manual_context"] = manual_context
    if project.get("artifact_sources"):
        rebuild_project_from_artifacts(project)
    project["updated_at"] = datetime.utcnow().isoformat()
    _enrich_project_readiness(project)
    saved = save_project(project, expected_revision=expected_revision)
    log_event("project.updated", details={"project_id": project_id})
    return project_client_view(saved)


@router.delete("/{project_id}", dependencies=[require_roles("admin")])
async def remove_project(project_id: str, request: Request = None):
    project = get_authorized_project(project_id, request)
    if not project or not delete_project(project_id, expected_revision=int(project.get("project_revision", 0) or 0)):
        raise HTTPException(status_code=404, detail="Project not found")
    log_event("project.deleted", details={"project_id": project_id})
    return {"success": True, "message": "Project deleted"}


@router.get("/{project_id}/archive")
async def export_project_archive(project_id: str, request: Request = None):
    """Export one authorized project together with its analysis history."""
    project = get_authorized_project(project_id, request)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    snapshot = storage.get_project_archive_snapshot(project_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail="Project not found")
    try:
        content = build_project_archive(snapshot)
    except ProjectArchiveTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except ProjectArchiveError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    log_event("project.archive_exported", details={"project_id": project_id})
    return Response(
        content=content,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="5stones-project-{project_id}.zip"',
            "Cache-Control": "no-store",
        },
    )
