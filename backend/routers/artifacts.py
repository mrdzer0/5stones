"""Artifact upload and parsing router."""
from __future__ import annotations
import hashlib
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Request
from datetime import datetime
from backend.models.schemas import ArtifactUpload
from backend.utils.storage import save_project
from backend.services.artifact_file_service import allowed_file_policy, read_validated_artifact_file
from backend.services.parser_service import parse_artifact
from backend.services.artifact_reconciliation_service import (
    capture_manual_context,
    project_client_view,
    rebuild_project_from_artifacts,
)
from backend.services.posture_service import compute_completeness
from backend.utils.redaction import redact_text
from backend.utils.audit import log_event
from backend.utils.access_control import get_authorized_project, workspace_access_dependency

router = APIRouter(
    prefix="/api/projects",
    tags=["artifacts"],
    dependencies=[workspace_access_dependency],
)


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


def _verified_evidence_items(items: list, content: str, filename: str, artifact_type: str) -> list[dict]:
    """Keep only short snippets that can be found verbatim in the uploaded artifact."""
    normalized_content = " ".join(str(content or "").split()).lower()
    verified = []
    seen = set()
    for item in items or []:
        if not isinstance(item, dict):
            continue
        snippet = " ".join(str(item.get("snippet") or "").split())[:320]
        if len(snippet) < 20 or snippet.lower() not in normalized_content:
            continue
        key = snippet.lower()
        if key in seen:
            continue
        seen.add(key)
        verified.append({
            "artifact_type": artifact_type,
            "filename": filename,
            "snippet": snippet,
            "locator": " ".join(str(item.get("locator") or "Artifact content").split())[:160],
            "topics": [str(topic)[:80] for topic in (item.get("topics") or [])[:8] if topic],
        })
    return verified[:12]


def _verified_use_cases(items: list, content: str, filename: str, artifact_type: str) -> list[dict]:
    """Retain only PRD use cases backed by an exact excerpt from the artifact."""
    normalized_content = " ".join(str(content or "").split()).casefold()
    allowed_step_types = {"action", "decision", "data_store", "external_system"}
    verified = []
    seen = set()
    def values(value):
        return value if isinstance(value, list) else ([value] if value else [])
    for item in items or []:
        if not isinstance(item, dict):
            continue
        name = " ".join(str(item.get("name") or "").split())[:160]
        actor = " ".join(str(item.get("actor") or "").split())[:120]
        snippet = " ".join(str(item.get("evidence_snippet") or "").split())[:320]
        if not name or not actor or len(snippet) < 20 or snippet.casefold() not in normalized_content:
            continue
        key = (name.casefold(), actor.casefold())
        if key in seen:
            continue
        steps = []
        for step in (item.get("steps") or [])[:16]:
            if not isinstance(step, dict):
                continue
            step_type = str(step.get("type") or "action").strip().casefold()
            label = " ".join(str(step.get("label") or "").split())[:180]
            if step_type not in allowed_step_types or not label:
                continue
            steps.append({
                "type": step_type,
                "label": label,
                "target": " ".join(str(step.get("target") or "").split())[:120],
                "data": clean_and_merge_similar_strings(values(step.get("data")))[:12],
            })
        if not steps:
            continue
        seen.add(key)
        verified.append({
            "name": name,
            "actor": actor,
            "trigger": " ".join(str(item.get("trigger") or "").split())[:240],
            "preconditions": clean_and_merge_similar_strings(values(item.get("preconditions")))[:12],
            "steps": steps,
            "data": clean_and_merge_similar_strings(values(item.get("data")))[:24],
            "evidence_snippet": snippet,
            "evidence_locator": " ".join(str(item.get("evidence_locator") or "Artifact content").split())[:160],
            "filename": filename,
            "artifact_type": artifact_type,
            "confidence": "Medium",
            "status": "Candidate",
        })
    return verified[:24]


@router.post("/{project_id}/artifact")
async def upload_artifact(
    project_id: str,
    data: ArtifactUpload,
    upload_meta: dict = None,
    request: Request = None,
):
    """Upload and parse an artifact for a project."""
    project = get_authorized_project(project_id, request)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    log_event("artifact.upload", details={
        "project_id": project_id,
        "artifact_type": data.artifact_type,
        "filename": data.filename
    })

    content_hash = hashlib.sha256(data.content.encode("utf-8")).hexdigest()
    filename = data.filename or f"{data.artifact_type}_artifact"
    existing_sources = [source for source in (project.get("artifact_sources") or []) if isinstance(source, dict)]
    duplicate = next((
        source for source in existing_sources
        if source.get("active", True)
        and source.get("artifact_type") == data.artifact_type
        and source.get("content_hash") == content_hash
    ), None)
    if duplicate:
        rebuild_project_from_artifacts(project)
        completeness = compute_completeness(project)
        project["completeness_score"] = completeness["score"]
        project["completeness_level"] = completeness["level"]
        save_project(project)
        return {
            "success": True,
            "duplicate": True,
            "message": f"{filename} is already included; no duplicate context was added.",
            "parsed": duplicate.get("contribution", {}),
            "project": project_client_view(project),
            "completeness": completeness,
            "reconciliation": project.get("artifact_inventory", {}),
        }

    # Preserve user-entered context before adding the first structured source.
    capture_manual_context(project, legacy=bool(existing_sources))
    try:
        parsed = await parse_artifact(data.artifact_type, data.content, project.get("data_policy"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    parsed["artifact_type"] = data.artifact_type
    parsed["filename"] = filename
    # Verify excerpts against the same redacted representation that was parsed
    # and may be sent to an AI provider. The original content hash remains the
    # source identity, but secrets never become evidence excerpts.
    verified_evidence = _verified_evidence_items(
        parsed.get("evidence_items", []), redact_text(data.content), filename, data.artifact_type
    )
    parsed["evidence_items"] = verified_evidence
    parsed["use_cases"] = _verified_use_cases(
        parsed.get("use_cases", []), redact_text(data.content), filename, data.artifact_type
    )

    artifact_id = f"artifact-{content_hash[:16]}"
    for evidence in verified_evidence:
        evidence["artifact_id"] = artifact_id
    revision = 1 + max((
        int(source.get("revision", 1)) for source in existing_sources
        if source.get("filename") == filename and source.get("artifact_type") == data.artifact_type
    ), default=0)
    replaced_count = 0
    for source in existing_sources:
        if (
            source.get("active", True)
            and source.get("filename") == filename
            and source.get("artifact_type") == data.artifact_type
        ):
            source["active"] = False
            source["superseded_by"] = artifact_id
            replaced_count += 1

    contribution_keys = {
        "actors", "components", "data_flows", "endpoints", "data_fields", "external_systems",
        "auth_methods", "critical_actions", "existing_controls", "has_pii", "summary",
        "operations", "use_cases", "warnings", "stats", "parser",
    }
    contribution = {key: parsed.get(key) for key in contribution_keys if key in parsed}
    existing_sources.append({
        "artifact_id": artifact_id,
        "artifact_type": data.artifact_type,
        "filename": filename,
        "content_hash": content_hash,
        "revision": revision,
        "active": True,
        "source_kind": "file_upload" if upload_meta else "api_payload",
        "size_bytes": (upload_meta or {}).get("size_bytes"),
        "truncated": (upload_meta or {}).get("truncated", False),
        "structured": (upload_meta or {}).get("structured", data.artifact_type in {"openapi", "postman"}),
        "parser": parsed.get("parser", {}),
        "stats": parsed.get("stats", {}),
        "warnings": parsed.get("warnings", []),
        "evidence_items": verified_evidence,
        "contribution": contribution,
        "parsed_at": datetime.utcnow().isoformat(),
    })
    project["artifact_sources"] = existing_sources
    rebuild_project_from_artifacts(project)
    completeness = compute_completeness(project)
    project["completeness_score"] = completeness["score"]
    project["completeness_level"] = completeness["level"]

    save_project(project)
    return {
        "success": True,
        "duplicate": False,
        "message": f"{filename} parsed and reconciled successfully.",
        "parsed": parsed,
        "project": project_client_view(project),
        "completeness": completeness,
        "reconciliation": project.get("artifact_inventory", {}),
        "conflicts": project.get("artifact_conflicts", []),
        "replaced_revisions": replaced_count,
    }


@router.post("/{project_id}/artifact/file")
async def upload_artifact_file(
    project_id: str,
    artifact_type: str = Form(...),
    file: UploadFile = File(...),
    request: Request = None,
):
    """Upload a file and parse it."""
    project = get_authorized_project(project_id, request)
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
        "structured": extracted.get("structured", False),
    }
    result = await upload_artifact(project_id, payload, upload_meta=upload_meta, request=request)
    result["upload"] = upload_meta
    return result
