"""Artifact upload and parsing router."""
from __future__ import annotations
import hashlib
import copy
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Request
from datetime import datetime
from backend.models.schemas import ArtifactUpload
from backend.utils.storage import save_project
from backend.services.artifact_file_service import allowed_file_policy, read_validated_artifact_file
from backend.services.parser_service import parse_artifact, PARSER_VERSION
from backend.services.artifact_reconciliation_service import (
    capture_manual_context,
    project_client_view,
    rebuild_project_from_artifacts,
)
from backend.services.posture_service import compute_completeness
from backend.utils.redaction import redact_text
from backend.utils.audit import log_event
from backend.utils.access_control import get_authorized_project, require_roles, workspace_access_dependency

router = APIRouter(
    prefix="/api/projects",
    tags=["artifacts"],
    dependencies=[workspace_access_dependency, require_roles("analyst", "reviewer", "admin")],
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


def _verified_evidence_items(
    items: list,
    content: str,
    filename: str,
    artifact_type: str,
    *,
    artifact_id: str | None = None,
    source_revision: int | None = None,
    source_hash: str | None = None,
) -> list[dict]:
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
        key = (source_hash or "", source_revision or 0, snippet.casefold())
        if key in seen:
            continue
        seen.add(key)
        evidence = {
            "artifact_type": artifact_type,
            "filename": filename,
            "snippet": snippet,
            "locator": " ".join(str(item.get("locator") or "Artifact content").split())[:160],
            "topics": [str(topic)[:80] for topic in (item.get("topics") or [])[:8] if topic],
            "chunk_id": str(item.get("chunk_id") or "")[:80] or None,
            "chunk_locator": " ".join(str(item.get("chunk_locator") or "").split())[:180] or None,
            "document_revision": source_revision,
            "document_hash": source_hash,
        }
        if artifact_id:
            evidence["artifact_id"] = artifact_id
        verified.append(evidence)
    return verified


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


def _public_parsed(parsed: dict) -> dict:
    """Return coverage diagnostics without exposing resumable provider payloads."""
    view = copy.deepcopy(parsed)
    if isinstance(view.get("coverage_manifest"), dict):
        view["coverage_manifest"].pop("checkpoints", None)
    return view


def _resume_source_for_revision(
    sources: list[dict],
    *,
    filename: str,
    artifact_type: str,
    parser_version: str,
) -> dict | None:
    """Find the newest same-parser source whose successful chunks can be reused."""
    candidates = [
        source for source in sources
        if isinstance(source, dict)
        and source.get("filename") == filename
        and source.get("artifact_type") == artifact_type
        and (source.get("parser") or {}).get("version") == parser_version
        and isinstance((source.get("coverage_manifest") or {}).get("checkpoints"), dict)
        and (source.get("coverage_manifest") or {}).get("checkpoints")
    ]
    return max(candidates, key=lambda source: int(source.get("revision") or 0), default=None)


@router.post("/{project_id}/artifact", dependencies=[require_roles("analyst", "admin")])
async def upload_artifact(
    project_id: str,
    data: ArtifactUpload,
    request: Request = None,
):
    """Upload and parse JSON artifact content; metadata remains server-owned."""
    return await _process_artifact_upload(project_id, data, upload_meta=None, request=request)


async def _process_artifact_upload(
    project_id: str,
    data: ArtifactUpload,
    *,
    upload_meta: dict | None,
    request: Request = None,
):
    """Parse an artifact using metadata produced by the trusted file reader."""
    project = get_authorized_project(project_id, request)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    log_event("artifact.upload", details={
        "project_id": project_id,
        "artifact_type": data.artifact_type,
        "filename": data.filename
    })

    content_hash = (upload_meta or {}).get("source_hash") or hashlib.sha256(data.content.encode("utf-8")).hexdigest()
    filename = data.filename or f"{data.artifact_type}_artifact"
    existing_sources = [source for source in (project.get("artifact_sources") or []) if isinstance(source, dict)]
    duplicate = next((
        source for source in existing_sources
        if source.get("active", True)
        and source.get("artifact_type") == data.artifact_type
        and source.get("content_hash") == content_hash
    ), None)
    if duplicate:
        # RG11: Only skip reparse if the same content was already processed by the
        # current parser version AND coverage is complete. If the parser was upgraded
        # or the previous run produced incomplete coverage, reparse the source so it
        # can benefit from improved extraction without requiring a different file.
        existing_parser_version = (duplicate.get("parser") or {}).get("version", "")
        existing_coverage_status = (duplicate.get("coverage_manifest") or {}).get("status", "")
        needs_reparse = (
            existing_parser_version != PARSER_VERSION
            or existing_coverage_status != "complete"
        )
        if not needs_reparse:
            rebuild_project_from_artifacts(project)
            completeness = compute_completeness(project)
            project["completeness_score"] = completeness["score"]
            project["completeness_level"] = completeness["level"]
            save_project(project)
            return {
                "success": True,
                "duplicate": True,
                "message": f"{filename} is already included; no duplicate context was added.",
                "parsed": _public_parsed(duplicate.get("contribution") or {}),
                "project": project_client_view(project),
                "completeness": completeness,
                "reconciliation": project.get("artifact_inventory", {}),
            }
        # Fall through to reparse — mark the reparse reason for audit.
        reparse_reason = (
            f"parser_version_upgrade ({existing_parser_version!r} → {PARSER_VERSION!r})"
            if existing_parser_version != PARSER_VERSION
            else f"incomplete_coverage ({existing_coverage_status!r})"
        )
    else:
        reparse_reason = None

    resume_source = _resume_source_for_revision(
        existing_sources,
        filename=filename,
        artifact_type=data.artifact_type,
        parser_version=PARSER_VERSION,
    )
    if resume_source and not duplicate:
        reparse_reason = (
            f"source_revision_changed ({resume_source.get('revision')} → next); "
            "unchanged validated sections will be reused by content hash"
        )

    # Preserve user-entered context before adding the first structured source.
    capture_manual_context(project, legacy=bool(existing_sources))
    # Pass truncation metadata to parse_artifact so the coverage manifest can
    # report that the source was cut short before reaching the provider (RG10).
    file_truncated = bool((upload_meta or {}).get("truncated"))
    # Use the truncated_chars value from the file service when available (accurate
    # char-level measurement). Fall back to byte-level estimate only when not provided.
    truncated_chars = (upload_meta or {}).get("truncated_chars", 0) if file_truncated else 0
    try:
        parsed = await parse_artifact(
            data.artifact_type, data.content, project.get("data_policy"),
            workspace_id=project.get("workspace_id"),
            source_truncated=file_truncated,
            truncated_chars=truncated_chars,
            extraction_omissions=(upload_meta or {}).get("extraction_omissions"),
            resume_chunks=(resume_source.get("coverage_manifest") or {}).get("checkpoints")
                if resume_source else None,
            resume_source_revision=resume_source.get("revision") if resume_source else None,
            resume_source_hash=resume_source.get("content_hash") if resume_source else None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    parsed["artifact_type"] = data.artifact_type
    parsed["filename"] = filename
    base_artifact_id = f"artifact-{content_hash[:16]}"
    revision = 1 + max((
        int(source.get("revision", 1)) for source in existing_sources
        if source.get("filename") == filename and source.get("artifact_type") == data.artifact_type
    ), default=0)
    artifact_id = (f"{base_artifact_id}-r{revision}"
                   if any(source.get("artifact_id") == base_artifact_id for source in existing_sources)
                   else base_artifact_id)
    coverage_manifest = parsed.get("coverage_manifest")
    if isinstance(coverage_manifest, dict):
        coverage_manifest.update({
            "source_artifact_id": artifact_id,
            "source_revision": revision,
            "document_hash": content_hash,
        })
    # Verify excerpts against the same redacted representation that was parsed
    # and may be sent to an AI provider. The original content hash remains the
    # source identity, but secrets never become evidence excerpts.
    verified_evidence = _verified_evidence_items(
        parsed.get("evidence_items", []), redact_text(data.content), filename, data.artifact_type,
        artifact_id=artifact_id, source_revision=revision, source_hash=content_hash,
    )
    parsed["evidence_items"] = verified_evidence
    parsed["use_cases"] = _verified_use_cases(
        parsed.get("use_cases", []), redact_text(data.content), filename, data.artifact_type
    )

    # Preserve flow-level provenance from the parser into the reconciled
    # project. The artifact identity is only known after upload metadata is
    # finalized; without this bridge a direct parser flow is reclassified as a
    # legacy/inference claim by build_grounded_data_flows.
    enriched_flows = []
    for raw_flow in parsed.get("data_flows", []) or []:
        if not isinstance(raw_flow, dict):
            continue
        flow = dict(raw_flow)
        flow["evidence_refs"] = list(dict.fromkeys([
            *(str(ref) for ref in (flow.get("evidence_refs") or []) if ref),
            *([f"artifact:{artifact_id}"] if flow.get("evidence_type") == "direct" else []),
        ]))
        enriched_flows.append(flow)
    parsed["data_flows"] = enriched_flows

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
        "coverage_manifest",
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
        "coverage_manifest": coverage_manifest or {},
        "stats": parsed.get("stats", {}),
        "warnings": parsed.get("warnings", []),
        "evidence_items": verified_evidence,
        "contribution": contribution,
        "parsed_at": datetime.utcnow().isoformat(),
        **({"reparse_reason": reparse_reason} if reparse_reason else {}),
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
        "parsed": _public_parsed(parsed),
        "project": project_client_view(project),
        "completeness": completeness,
        "reconciliation": project.get("artifact_inventory", {}),
        "conflicts": project.get("artifact_conflicts", []),
        "replaced_revisions": replaced_count,
    }


@router.post("/{project_id}/artifact/file", dependencies=[require_roles("analyst", "admin")])
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
        "truncated_chars": extracted.get("truncated_chars", 0),
        "source_hash": extracted.get("source_hash"),
        "extraction_omissions": extracted.get("extraction_omissions", []),
        "structured": extracted.get("structured", False),
    }
    result = await _process_artifact_upload(project_id, payload, upload_meta=upload_meta, request=request)
    result["upload"] = upload_meta
    return result
