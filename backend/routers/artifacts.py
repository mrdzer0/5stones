"""Artifact upload and parsing router."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from datetime import datetime
from backend.models.schemas import ArtifactUpload
from backend.utils.storage import get_project, save_project
from backend.services.artifact_file_service import allowed_file_policy, read_validated_artifact_file
from backend.services.parser_service import parse_artifact
from backend.services.posture_service import compute_completeness
from backend.utils.audit import log_event

router = APIRouter(prefix="/api/projects", tags=["artifacts"])


@router.get("/artifact/policy")
async def get_artifact_policy():
    """Return artifact upload limits and allowlisted file extensions."""
    return allowed_file_policy()


@router.post("/{project_id}/artifact")
async def upload_artifact(project_id: str, data: ArtifactUpload, upload_meta: dict = None):
    """Upload and parse an artifact for a project."""
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    log_event("artifact.upload", details={
        "project_id": project_id,
        "artifact_type": data.artifact_type,
        "filename": data.filename
    })

    # Parse the artifact
    parsed = await parse_artifact(data.artifact_type, data.content)
    parsed["artifact_type"] = data.artifact_type
    parsed["filename"] = data.filename or f"{data.artifact_type}_artifact"
    parsed["raw_content"] = data.content[:500]  # truncate for storage

    # Merge extracted entities into project
    for field in ["actors", "components", "entry_points", "data_involved",
                  "external_systems", "critical_actions", "existing_controls"]:
        src_key = {
            "entry_points": "endpoints",
            "data_involved": "data_fields",
            "components": "components",
        }.get(field, field.replace("_involved", "_fields").replace("entry_points", "endpoints"))
        extracted = parsed.get(src_key, parsed.get(field.replace("_", "_"), []))
        existing = project.get(field, [])
        merged = list(dict.fromkeys(existing + extracted))  # deduplicate preserving order
        project[field] = merged

    project["has_pii"] = parsed.get("has_pii", project.get("has_pii", False))
    project["artifact_summary"] = parsed.get("summary", "")
    project["extracted_data_flows"] = parsed.get("data_flows", [])

    # Track artifacts
    artifacts = project.get("artifacts", [])
    artifacts.append(parsed.get("filename", data.artifact_type))
    project["artifacts"] = artifacts
    artifact_sources = project.get("artifact_sources", [])
    artifact_sources.append({
        "artifact_type": data.artifact_type,
        "filename": parsed.get("filename", data.artifact_type),
        "source_kind": "file_upload" if upload_meta else "api_payload",
        "size_bytes": (upload_meta or {}).get("size_bytes"),
        "truncated": (upload_meta or {}).get("truncated", False),
        "parsed_at": datetime.utcnow().isoformat(),
    })
    project["artifact_sources"] = artifact_sources
    completeness = compute_completeness(project)
    project["completeness_score"] = completeness["score"]
    project["completeness_level"] = completeness["level"]

    save_project(project)
    return {"success": True, "parsed": parsed, "project": project, "completeness": completeness}


@router.post("/{project_id}/artifact/file")
async def upload_artifact_file(
    project_id: str,
    artifact_type: str = Form(...),
    file: UploadFile = File(...)
):
    """Upload a file and parse it."""
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    extracted = await read_validated_artifact_file(artifact_type, file)

    payload = ArtifactUpload(
        artifact_type=artifact_type,
        content=extracted["content"],
        filename=extracted["filename"]
    )
    upload_meta = {
        "filename": extracted["filename"],
        "size_bytes": extracted["size_bytes"],
        "truncated": extracted["truncated"],
    }
    result = await upload_artifact(project_id, payload, upload_meta=upload_meta)
    result["upload"] = upload_meta
    return result
