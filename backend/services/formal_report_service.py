"""Formal report metadata and provenance helpers."""
from __future__ import annotations

import hashlib
import json
import copy
from datetime import datetime, timezone

from backend.utils.storage import get_settings


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


PROJECT_CONTEXT_FIELDS = (
    "name", "description", "environment", "data_policy", "actors", "entry_points",
    "data_involved", "auth_method", "external_systems", "critical_actions",
    "existing_controls", "entity_metadata", "zone_metadata", "boundary_metadata",
    "manual_context",
)


def project_context_fingerprint(project: dict | None) -> str:
    project = project or {}
    context = {field: project.get(field) for field in PROJECT_CONTEXT_FIELDS}
    rendered = json.dumps(context, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def report_snapshot_fingerprint(snapshot: dict) -> str:
    payload = copy.deepcopy(snapshot)
    payload.pop("snapshot_sha256", None)
    rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def source_manifest(project: dict | None) -> list[dict]:
    result = []
    for source in (project or {}).get("artifact_sources") or []:
        if not isinstance(source, dict):
            continue
        coverage = source.get("coverage_manifest") if isinstance(source.get("coverage_manifest"), dict) else {}
        stats = source.get("stats") if isinstance(source.get("stats"), dict) else {}
        result.append({
            "artifact_id": source.get("artifact_id"),
            "filename": source.get("filename"),
            "artifact_type": source.get("artifact_type"),
            "active": source.get("active", True),
            "revision": source.get("revision"),
            "content_hash": source.get("content_hash") or source.get("document_hash"),
            "size_bytes": source.get("size_bytes"),
            "coverage_status": coverage.get("status"),
            "chunk_count": coverage.get("chunk_count") or stats.get("chunk_count", 0),
            "processed_chunk_count": coverage.get("processed_chunk_count") or stats.get("processed_chunk_count", 0),
            "unread_section_count": len(coverage.get("unread_sections") or []),
        })
    return result


def provider_configuration_snapshot(project: dict | None = None) -> dict:
    """Return non-secret provider/config provenance suitable for a report.

    API keys and encrypted values are intentionally never included. Reading
    settings is best-effort because a malformed/custom endpoint must not make
    a saved report unreadable.
    """
    project = project or {}
    settings = get_settings(project.get("workspace_id"))
    policy = project.get("data_policy") or settings.get("default_data_policy")
    active_id = settings.get("active_provider_id")
    provider = next((item for item in settings.get("providers", [])
                     if isinstance(item, dict) and item.get("provider_id") == active_id), None)
    if isinstance(provider, dict):
        return {
            "source": "byok",
            "provider_id": provider.get("provider_id"),
            "provider_name": provider.get("name"),
            "provider_type": provider.get("provider_type"),
            "base_url": provider.get("base_url"),
            "model": provider.get("model"),
            "max_tokens": provider.get("max_tokens"),
            "is_local": bool(provider.get("is_local") or provider.get("provider_type") == "local"),
            "data_policy": policy,
        }
    if settings.get("local_llm_endpoint") or settings.get("local_llm_model"):
        return {
            "source": "local",
            "provider_name": "Local LLM",
            "base_url": settings.get("local_llm_endpoint"),
            "model": settings.get("local_llm_model"),
            "max_tokens": None,
            "is_local": True,
            "data_policy": policy,
        }
    return {
        "source": "environment",
        "provider_name": "Environment-configured provider",
        "base_url": None,
        "model": None,
        "max_tokens": None,
        "is_local": False,
        "data_policy": policy,
    }


def _provider_provenance(project: dict, report: dict, run: dict) -> dict:
    configured = run.get("provider") if isinstance(run.get("provider"), dict) else provider_configuration_snapshot(project)
    configured = {key: value for key, value in configured.items() if key not in {"api_key", "_api_key"}}
    observed_models = []
    engines = {}
    for stage, status in (report.get("ai_status") or {}).items():
        if not isinstance(status, dict):
            continue
        engine = status.get("engine")
        if engine:
            engines[stage] = engine
        metadata = status.get("response_metadata") if isinstance(status.get("response_metadata"), dict) else {}
        if metadata.get("model"):
            observed_models.append(str(metadata["model"]))
    configured["observed_models"] = list(dict.fromkeys(observed_models))
    configured["stage_engines"] = engines
    return configured


def build_formal_report_metadata(project: dict | None, report: dict | None, *, status: str | None = None,
                                 revision: int | None = None, signed_by: str | None = None,
                                 signed_at: str | None = None, approval_history: list[dict] | None = None,
                                 signed_deployment_profile: str | None = None,
                                 signed_identity_mode: str | None = None) -> dict:
    project = project or {}
    report = report or {}
    model = report.get("dfd_model") if isinstance(report.get("dfd_model"), dict) else {}
    risk_summary = report.get("risk_summary") if isinstance(report.get("risk_summary"), dict) else {}
    previous = report.get("formal_report") if isinstance(report.get("formal_report"), dict) else {}
    report_revision = int(revision if revision is not None else (report.get("report_revision") or 0))
    current_status = status or previous.get("status") or "draft"
    history = approval_history if approval_history is not None else list(previous.get("approval_history") or [])
    run = report.get("analysis_run") if isinstance(report.get("analysis_run"), dict) else {}
    quality_gate = report.get("quality_gate") if isinstance(report.get("quality_gate"), dict) else run.get("quality_gate") or {}
    coverage_summary = report.get("analysis_coverage_summary") if isinstance(report.get("analysis_coverage_summary"), dict) else {}
    methodology_versions = sorted({
        str(item.get("risk_methodology_version"))
        for item in (report.get("threats") or [])
        if isinstance(item, dict) and item.get("risk_methodology_version")
    })
    if risk_summary.get("risk_methodology_version") and str(risk_summary["risk_methodology_version"]) not in methodology_versions:
        methodology_versions.append(str(risk_summary["risk_methodology_version"]))
    deferred_total = len({
        str(item.get("threat_id") or index)
        for index, item in enumerate(report.get("threats") or [])
        if isinstance(item, dict)
        and item.get("analysis_state") != "historical"
        and (item.get("finding_state") == "needs_context" or item.get("risk_status") == "deferred")
    })
    return {
        "schema_version": "formal-report-v1",
        "status": current_status,
        "revision": report_revision,
        "created_at": previous.get("created_at") or report.get("report_updated_at") or _now(),
        "updated_at": _now(),
        "signed_at": signed_at or previous.get("signed_at"),
        "signed_by": signed_by or previous.get("signed_by"),
        "signed_deployment_profile": signed_deployment_profile or previous.get("signed_deployment_profile"),
        "signed_identity_mode": signed_identity_mode or previous.get("signed_identity_mode"),
        "dfd_revision": model.get("revision"),
        "dfd_layout_revision": model.get("layout_revision"),
        "dfd_semantic_hash": model.get("semantic_hash"),
        "project_context_sha256": project_context_fingerprint(project),
        "analysis_run_id": (report.get("analysis_run") or {}).get("run_id") or report.get("analysis_run_id"),
        "analysis_completed_at": (report.get("analysis_run") or {}).get("completed_at") or report.get("generated_at"),
        "analysis_status": report.get("analysis_status") or run.get("status") or "not_started",
        "methodology": {
            "risk_methodology_versions": methodology_versions,
            "frameworks": ["STRIDE", "LINDDUN"],
            "dfd_schema_version": model.get("schema_version"),
            "grounding_policy": "Canonical DFD primary interaction plus explicit deferred/context state",
            "provider_severity": "advisory_only",
        },
        "source_manifest": source_manifest(project),
        "approval_history": history,
        "provenance": {
            "provider": _provider_provenance(project, report, run),
            "run_config": {
                "requested_types": list(run.get("requested_types") or []),
                "stage_dependencies": run.get("stage_dependencies") or {},
                "retryable": bool(run.get("retryable")),
                "warning_stages": list(run.get("warning_stages") or []),
            },
            "fallback_used": any(
                isinstance(item, dict) and (item.get("baseline_used") or item.get("engine") == "fallback")
                for item in (report.get("ai_status") or {}).values()
            ),
            "preserved_result_used": any(
                isinstance(item, dict) and item.get("previous_results_preserved")
                for item in (report.get("ai_status") or {}).values()
            ),
        },
        "coverage": {
            "frameworks": coverage_summary,
            "denominator": {
                framework: {
                    "assessed": int((summary or {}).get("assessed", 0) or 0),
                    "deferred": int((summary or {}).get("deferred", 0) or 0),
                    "failed": int((summary or {}).get("failed", 0) or 0),
                    "unprocessed": int((summary or {}).get("unprocessed", 0) or 0),
                    "complete": bool((summary or {}).get("complete")),
                }
                for framework, summary in coverage_summary.items()
                if isinstance(summary, dict)
            },
        },
        "unresolved_blockers": list(quality_gate.get("blocking_reasons") or []),
        "risk_disposition": {
            "scored": int(risk_summary.get("scored_total", 0) or 0),
            "deferred": max(deferred_total, int(risk_summary.get("needs_context_total", 0) or 0), int(risk_summary.get("risk_deferred_total", 0) or 0)),
            "total": int(risk_summary.get("total", 0) or 0),
        },
    }


def revision_summary(snapshot: dict) -> dict:
    metadata = snapshot.get("formal_report") if isinstance(snapshot.get("formal_report"), dict) else {}
    report = snapshot.get("report") if isinstance(snapshot.get("report"), dict) else snapshot
    return {
        "revision_id": snapshot.get("revision_id"),
        "revision": metadata.get("revision") or report.get("report_revision"),
        "status": snapshot.get("status") or metadata.get("status") or "draft",
        "created_at": snapshot.get("created_at") or metadata.get("created_at"),
        "signed_at": metadata.get("signed_at"),
        "signed_by": metadata.get("signed_by"),
        "dfd_revision": metadata.get("dfd_revision"),
        "analysis_run_id": metadata.get("analysis_run_id"),
        "snapshot_sha256": snapshot.get("snapshot_sha256"),
    }
