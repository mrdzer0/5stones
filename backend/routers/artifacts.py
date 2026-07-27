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


def clean_and_merge_similar_strings(items: list[str]) -> list[str]:
    """Normalize and deduplicate similar strings (e.g. plurals, capitalization differences) case-insensitively while preserving order."""
    if not items:
        return []
    normalized_map = {}
    for item in items:
        if not item or not isinstance(item, str):
            continue
        orig = item.strip()
        if not orig:
            continue
        # Normalize: lowercase, strip 's' at the end for plurals, hyphens to spaces
        norm = orig.lower().replace('_', ' ').replace('-', ' ').strip()
        if norm.endswith('s') and len(norm) > 3:
            norm = norm[:-1]
        
        if norm not in normalized_map:
            normalized_map[norm] = orig
        else:
            existing = normalized_map[norm]
            if len(orig) < len(existing) and existing.lower().startswith(orig.lower()):
                normalized_map[norm] = orig
            elif existing.islower() and not orig.islower():
                normalized_map[norm] = orig
                
    result = []
    seen = set()
    for item in items:
        if not item or not isinstance(item, str):
            continue
        orig = item.strip()
        norm = orig.lower().replace('_', ' ').replace('-', ' ').strip()
        if norm.endswith('s') and len(norm) > 3:
            norm = norm[:-1]
        best = normalized_map.get(norm, orig)
        if best.lower() not in seen:
            seen.add(best.lower())
            result.append(best)
    return result


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
        merged = clean_and_merge_similar_strings(existing + extracted)
        project[field] = merged

    # Merge auth_methods if project.auth_method is empty or '-'
    if parsed.get("auth_methods"):
        clean_methods = clean_and_merge_similar_strings(parsed["auth_methods"])
        if clean_methods and (not project.get("auth_method") or project.get("auth_method").strip() in ("", "-", "Unknown")):
            project["auth_method"] = ", ".join(clean_methods)

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
