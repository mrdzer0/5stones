"""Analysis router — runs threat modeling pipeline."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException, Request
from backend.utils.storage import get_project, save_dfd_model, save_project, save_report, get_report
from backend.utils.audit import log_event
from backend.utils.access_control import get_authorized_project, workspace_access_dependency
from backend.utils.redaction import redact_text
from backend.services.trust_boundary_service import (
    TRUST_BOUNDARY_REVIEW_STATUSES,
    active_trust_boundaries,
    apply_boundary_reviews,
    attach_target_refs,
    build_trust_model,
    propagate_target_refs,
)
from backend.services.dfd_model_service import build_dfd_model, reconcile_generated_dfd, validate_dfd_model
from backend.services.stride_service import generate_stride_threats
from backend.services.linddun_service import generate_linddun_threats
from backend.services.privacy_service import assess_privacy_metadata, annotate_privacy_threats
from backend.services.threat_validation_service import (
    complete_graph_coverage,
    quarantine_report_threats,
    validate_coverage,
    validate_generated_threats,
)
from backend.services.control_service import map_controls
from backend.services.test_service import (
    generate_test_scenarios,
    generate_missing_info,
    generate_assumptions,
)
from backend.services.posture_service import (
    compute_completeness,
    enrich_controls,
    enrich_missing_info,
    enrich_assumptions,
    enrich_threats,
    merge_deduped_threats,
    replace_framework_threats,
    reconcile_controls,
    reconcile_test_scenarios,
    threat_fingerprint,
    normalize_report_evidence,
    build_project_evidence_catalog,
    update_item_by_id,
    validate_control_patch,
)
import uuid
import time
from datetime import datetime, timezone

router = APIRouter(
    prefix="/api/projects",
    tags=["analysis"],
    dependencies=[workspace_access_dependency],
)

BOUNDARY_DOWNSTREAM_STAGES = ["stride", "linddun", "controls", "tests", "missing_info", "assumptions"]
_ACTIVE_ANALYSIS_RUNS: set[str] = set()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _active_topology_signature(boundaries: list[dict] | None) -> tuple[str, ...]:
    return tuple(sorted(
        f"{boundary.get('model_fingerprint', '')}:{boundary.get('status', 'Candidate')}"
        for boundary in active_trust_boundaries(boundaries)
    ))


def _mark_analysis_stale(report: dict, stages: list[str], reason: str):
    current = report.get("analysis_stale") if isinstance(report.get("analysis_stale"), dict) else {}
    report["analysis_stale"] = {
        "stages": sorted(set([*(current.get("stages") or []), *stages])),
        "reason": reason,
        "changed_at": _utc_now(),
    }


def _clear_completed_stale_stages(report: dict, completed: list[str]):
    stale = report.get("analysis_stale")
    if not isinstance(stale, dict):
        return
    remaining = [stage for stage in (stale.get("stages") or []) if stage not in completed]
    if remaining:
        stale["stages"] = remaining
    else:
        report.pop("analysis_stale", None)


def _clear_review_visibility_stale(report: dict):
    stale = report.get("analysis_stale")
    if isinstance(stale, dict) and str(stale.get("reason") or "").startswith("A trust-boundary review decision changed"):
        report.pop("analysis_stale", None)


def _valid_completed_stages(report: dict, requested: list[str]) -> list[str]:
    """Return only stages that produced current, validated results."""
    statuses = report.get("ai_status") if isinstance(report.get("ai_status"), dict) else {}
    completed = []
    for stage in requested:
        if stage == "trust_boundary":
            dfd_status = statuses.get("dfd_model") or {}
            boundary_status = statuses.get("trust_boundary") or {}
            if dfd_status.get("ok") and boundary_status.get("ok"):
                completed.append(stage)
            continue
        if stage == "assumptions":
            # Assumptions are deterministic, but only count as complete after
            # the pipeline has materialized the stage output.
            if isinstance(report.get("assumptions"), list):
                completed.append(stage)
            continue
        status = statuses.get(stage)
        if isinstance(status, dict) and status.get("ok") is True:
            completed.append(stage)
    return completed


def _append_analysis_quarantine(report: dict, records: list[dict]):
    """Persist safe recovery metadata for invalid/stale analysis output."""
    if not records:
        return
    bucket = report.setdefault("analysis_quarantine", [])
    existing_keys = {
        (item.get("framework"), tuple(item.get("reasons") or []), item.get("item", {}).get("threat_id"))
        for item in bucket
        if isinstance(item, dict)
    }
    for record in records:
        key = (record.get("framework"), tuple(record.get("reasons") or []), record.get("item", {}).get("threat_id"))
        if key not in existing_keys:
            bucket.append(record)
            existing_keys.add(key)
    report["analysis_quarantine"] = bucket[-100:]


def _append_invalid_generation_quarantine(report: dict, framework: str, revision: str | None, raw_items: list):
    records = []
    for index, item in enumerate(raw_items):
        summary = {}
        if isinstance(item, dict):
            for key in ("threat_id", "threat_category", "title", "threat_description"):
                if item.get(key):
                    summary[key] = str(item[key])[:240]
        else:
            summary["raw_type"] = type(item).__name__
        records.append({
            "quarantine_id": f"generated-{framework.lower()}-{index}-{uuid.uuid4().hex[:8]}",
            "captured_at": _utc_now(),
            "framework": framework,
            "model_revision": revision,
            "reasons": ["invalid_generated_output"],
            "item": summary,
        })
    _append_analysis_quarantine(report, records)


def _quarantine_superseded_framework_items(
    report: dict,
    incoming: list[dict],
    framework: str,
    revision: str | None,
):
    """Keep omitted prior findings recoverable when a framework snapshot reruns."""
    incoming_keys = {
        item.get("fingerprint") or threat_fingerprint(item)
        for item in incoming or []
        if isinstance(item, dict)
    }
    records = []
    for item in report.get("threats", []) or []:
        if not isinstance(item, dict) or item.get("framework") != framework:
            continue
        key = item.get("fingerprint") or threat_fingerprint(item)
        if key in incoming_keys:
            continue
        records.append({
            "quarantine_id": f"superseded-{framework.lower()}-{item.get('threat_id') or uuid.uuid4().hex[:8]}",
            "captured_at": _utc_now(),
            "framework": framework,
            "model_revision": revision,
            "reasons": ["superseded_by_new_framework_snapshot"],
            "item": dict(item),
        })
    _append_analysis_quarantine(report, records)


def _empty_report(project: dict) -> dict:
    return {
        "report_id": str(uuid.uuid4()),
        "project_id": project["project_id"],
        "project_name": project.get("name", ""),
        "generated_at": datetime.utcnow().isoformat(),
        "data_flows": [],
        "trust_boundaries": [],
        "threats": [],
        "controls": [],
        "test_scenarios": [],
        "assumptions": [],
        "missing_info": [],
        "completeness": {},
        "risk_summary": {},
    }


def _requested_analysis_types(body: dict | None) -> list[str]:
    requested = (body or {}).get("analysis_types")
    if not isinstance(requested, list) or not requested:
        return ["trust_boundary", "stride", "linddun", "controls", "tests", "missing_info", "assumptions"]
    return [str(item) for item in requested if str(item).strip()]


@router.post("/{project_id}/analyze")
async def run_full_analysis(project_id: str, body: dict = None, request: Request = None):
    """Run analysis with a persisted run state and retry-safe failure boundary."""
    project = get_project(project_id) if request is None else get_authorized_project(project_id, request)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    types = _requested_analysis_types(body)
    if project_id in _ACTIVE_ANALYSIS_RUNS:
        raise HTTPException(status_code=409, detail="Analysis is already running")
    _ACTIVE_ANALYSIS_RUNS.add(project_id)
    previous_report = get_report(project_id) or _empty_report(project)
    previous_run = previous_report.get("analysis_run") if isinstance(previous_report.get("analysis_run"), dict) else {}
    run_state = {
        "run_id": str(uuid.uuid4()),
        "status": "running",
        "requested_types": types,
        "started_at": _utc_now(),
        "previous_successful_run_id": previous_run.get("run_id") if previous_run.get("status") in {"completed", "completed_with_warnings"} else None,
        "retryable": False,
    }
    previous_report["analysis_run"] = run_state
    previous_report["analysis_status"] = "running"
    save_report(project_id, previous_report)
    project["analysis_status"] = "running"
    save_project(project)

    try:
        result = await _run_analysis_pipeline(project_id, body, request=request)
    except Exception as exc:
        safe_error = redact_text(str(exc))[:1000] or "Analysis pipeline failed"
        failed_report = get_report(project_id) or previous_report
        failed_report["analysis_run"] = {
            **run_state,
            "status": "failed",
            "failed_at": _utc_now(),
            "error": safe_error,
            "retryable": True,
        }
        failed_report["analysis_status"] = "failed"
        save_report(project_id, failed_report)
        project["analysis_status"] = "failed"
        save_project(project)
        log_event("analysis.failed", details={"project_id": project_id, "run_id": run_state["run_id"], "error": safe_error})
        raise HTTPException(status_code=500, detail="Analysis failed; the previous saved model remains available and can be retried.") from exc
    finally:
        _ACTIVE_ANALYSIS_RUNS.discard(project_id)

    statuses = result.get("ai_status") if isinstance(result.get("ai_status"), dict) else {}
    warning_stages = sorted(
        stage for stage, status in statuses.items()
        if isinstance(status, dict) and status.get("ok") is False
    )
    result["analysis_run"] = {
        **run_state,
        "status": "completed_with_warnings" if warning_stages else "completed",
        "completed_at": _utc_now(),
        "warning_stages": warning_stages,
        "retryable": bool(warning_stages),
    }
    result["analysis_status"] = result["analysis_run"]["status"]
    save_report(project_id, result)
    project["analysis_status"] = result["analysis_status"]
    save_project(project)
    return result


@router.post("/{project_id}/analyze/retry")
async def retry_analysis(project_id: str, request: Request = None):
    """Retry the last persisted analysis request without discarding its report."""
    project = get_project(project_id) if request is None else get_authorized_project(project_id, request)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    report = get_report(project_id)
    run_state = report.get("analysis_run") if isinstance(report, dict) else None
    if not isinstance(run_state, dict) or not run_state.get("requested_types"):
        raise HTTPException(status_code=404, detail="No previous analysis run is available to retry")
    if run_state.get("status") == "running" and project_id in _ACTIVE_ANALYSIS_RUNS:
        raise HTTPException(status_code=409, detail="Analysis is already running")
    return await run_full_analysis(
        project_id,
        {"analysis_types": run_state["requested_types"]},
        request=request,
    )


async def _run_analysis_pipeline(project_id: str, body: dict = None, request: Request = None):
    """Run full threat modeling pipeline for a project."""
    project = get_project(project_id) if request is None else get_authorized_project(project_id, request)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    types = _requested_analysis_types(body)
    stage_started_at = time.perf_counter()
    log_event("analysis.started", details={"project_id": project_id, "analysis_types": types})

    report = get_report(project_id)
    if report:
        report = normalize_report_evidence(report, project)
    else:
        report = _empty_report(project)

    report["completeness"] = compute_completeness(project)
    evidence_ids = {
        str(item.get("evidence_id"))
        for item in build_project_evidence_catalog(project)
        if item.get("evidence_id")
    }
    report.setdefault("ai_status", {})
    _clear_review_visibility_stale(report)

    # 1. Trust Boundaries
    if "trust_boundary" in types:
        previous_signature = _active_topology_signature(report.get("trust_boundaries"))
        previous_dfd_hash = (report.get("dfd_model") or {}).get("semantic_hash")
        try:
            trust_model = build_trust_model(project)
            reviewed_boundaries, review_warnings = apply_boundary_reviews(
                trust_model["boundaries"], report.get("trust_boundary_reviews")
            )
            boundary_status = {item["boundary_id"]: item.get("status", "Candidate") for item in reviewed_boundaries}
            for item in trust_model["views"].get("context", {}).get("boundaries", []):
                item["status"] = boundary_status.get(item.get("element_id"), item.get("status", "Candidate"))
            trust_boundaries = active_trust_boundaries(reviewed_boundaries)
            report["data_flows"] = trust_model["data_flows"]
            generated_dfd_model = build_dfd_model(project, trust_model, previous=report.get("dfd_model"))
            dfd_model, dfd_proposal, _human_edit_protected = reconcile_generated_dfd(
                generated_dfd_model, report.get("dfd_model")
            )
            if dfd_proposal:
                dfd_proposal["candidate_model"] = generated_dfd_model.model_dump()
                report["dfd_proposal"] = dfd_proposal
                _mark_analysis_stale(
                    report,
                    BOUNDARY_DOWNSTREAM_STAGES,
                    "Source context changed while a human-edited DFD exists. Review the regeneration proposal before applying it.",
                )
            else:
                report.pop("dfd_proposal", None)
            dfd_validation = validate_dfd_model(dfd_model)
            report["dfd_model"] = dfd_model.model_dump()
            report["dfd_validation"] = dfd_validation
            save_dfd_model(project_id, report["dfd_model"])
            report["trust_model"] = {
                "version": trust_model["version"],
                "generation_method": trust_model["generation_method"],
                "entities": trust_model["entities"],
                "warnings": [*trust_model["warnings"], *review_warnings],
                "review_summary": {
                    "candidate": sum(item.get("status") == "Candidate" for item in reviewed_boundaries),
                    "confirmed": sum(item.get("status") == "Confirmed" for item in reviewed_boundaries),
                    "rejected": sum(item.get("status") == "Rejected" for item in reviewed_boundaries),
                },
                "views": trust_model["views"],
            }
            report["ai_status"]["trust_boundary"] = {
                "ok": True,
                "engine": "deterministic",
                "warnings": [*trust_model["warnings"], *review_warnings],
            }
            report["trust_boundaries"] = reviewed_boundaries
            attach_target_refs(report.get("threats"), reviewed_boundaries, trust_model["views"], report.get("dfd_model"))
            current_signature = _active_topology_signature(reviewed_boundaries)
            if previous_signature and current_signature != previous_signature:
                _mark_analysis_stale(
                    report,
                    BOUNDARY_DOWNSTREAM_STAGES,
                    "Trust-boundary topology or review state changed. Refresh dependent analysis stages.",
                )
            if previous_dfd_hash and previous_dfd_hash != dfd_model.semantic_hash:
                _mark_analysis_stale(
                    report,
                    BOUNDARY_DOWNSTREAM_STAGES,
                    "Canonical DFD semantic model changed. Refresh dependent analysis stages.",
                )
            report["ai_status"]["dfd_model"] = {
                "ok": dfd_validation["valid"],
                "engine": "deterministic",
                "errors": dfd_validation["errors"],
                "warnings": dfd_validation["warnings"],
                "revision": dfd_model.revision,
            }
        except Exception as exc:
            # Fail closed: an unavailable grounded model must never fall back to
            # guessed topology or re-run the same failing builder.
            trust_boundaries = []
            report["data_flows"] = []
            report["trust_model"] = {"version": "unavailable", "entities": [], "warnings": [str(exc)]}
            report["ai_status"]["trust_boundary"] = {"ok": False, "error": str(exc), "engine": "deterministic"}
            report["ai_status"]["dfd_model"] = {"ok": False, "error": str(exc), "engine": "deterministic"}
            report["trust_boundaries"] = []
    else:
        trust_boundaries = active_trust_boundaries(report.get("trust_boundaries", []))

    # Keep privacy/lifecycle readiness derived from the same canonical model
    # revision that feeds LINDDUN. Missing metadata remains review context; it
    # never becomes a safe default or a legal conclusion.
    report["privacy_assessment"] = assess_privacy_metadata(report.get("dfd_model"))

    # Never send legacy or stale findings to controls/tests. Keep a recoverable
    # copy with explicit reasons instead of silently promoting it to the active
    # revision.
    active_threats, quarantined_threats = quarantine_report_threats(
        report.get("threats", []), report.get("dfd_model")
    )
    report["threats"] = active_threats
    _append_analysis_quarantine(report, quarantined_threats)

    # 2. STRIDE
    stride_threats = []
    if "stride" in types:
        stride_generation_status = "complete"
        try:
            stride_threats = await generate_stride_threats(
                project,
                trust_boundaries,
                force_fallback=False,
                dfd_model=report.get("dfd_model"),
            )
            stride_engine = "AI"
        except Exception as exc:
            stride_threats = await generate_stride_threats(
                project,
                trust_boundaries,
                force_fallback=True,
                dfd_model=report.get("dfd_model"),
            )
            stride_engine = "fallback"
            stride_generation_error = str(exc)
        raw_stride_threats = list(stride_threats or [])
        stride_generation_status = getattr(stride_threats, "assessment_status", "complete")
        stride_generation_warnings = list(getattr(stride_threats, "generation_warnings", []))
        stride_response_shape = getattr(stride_threats, "response_shape", "unknown")
        stride_coverage = getattr(stride_threats, "coverage", [])
        valid_stride_coverage, coverage_warnings = validate_coverage(
            stride_coverage, report.get("dfd_model"), "STRIDE"
        )
        stride_threats, stride_warnings = validate_generated_threats(
            stride_threats, "STRIDE", report.get("dfd_model"), evidence_ids
        )
        if raw_stride_threats and not stride_threats:
            stride_generation_status = "invalid"
            _append_invalid_generation_quarantine(
                report, "STRIDE", (report.get("dfd_model") or {}).get("revision"), raw_stride_threats
            )
        elif len(stride_threats) < len(raw_stride_threats) and stride_generation_status == "complete":
            stride_generation_status = "partial"
        stride_warnings = [*stride_generation_warnings, *stride_warnings]
        report["ai_status"]["stride"] = {
            "ok": stride_engine == "AI" and stride_generation_status in {"complete", "valid_empty"} and not stride_warnings,
            "engine": stride_engine,
            "assessment_status": stride_generation_status,
            "response_shape": stride_response_shape,
            "validation_warnings": [*coverage_warnings, *stride_warnings],
            **({"error": stride_generation_error} if stride_engine == "fallback" else {}),
        }
        stride_threats = enrich_threats(stride_threats, project, "STRIDE")
        attach_target_refs(
            stride_threats,
            report.get("trust_boundaries", trust_boundaries),
            report.get("trust_model", {}).get("views"),
            report.get("dfd_model"),
        )
        completed_coverage, coverage_summary = complete_graph_coverage(
            valid_stride_coverage,
            stride_threats,
            report.get("dfd_model"),
            "STRIDE",
        )
        report.setdefault("analysis_coverage", {})["STRIDE"] = completed_coverage
        report.setdefault("analysis_coverage_summary", {})["STRIDE"] = coverage_summary
        if stride_generation_status != "invalid":
            _quarantine_superseded_framework_items(
                report,
                stride_threats,
                "STRIDE",
                (report.get("dfd_model") or {}).get("revision"),
            )
            report["threats"], stride_deduped = replace_framework_threats(
                report.get("threats", []), stride_threats, "STRIDE"
            )
        else:
            stride_deduped = 0

    # 3. LINDDUN
    linddun_threats = []
    if "linddun" in types:
        linddun_generation_status = "complete"
        try:
            linddun_threats = await generate_linddun_threats(
                project,
                trust_boundaries,
                force_fallback=False,
                dfd_model=report.get("dfd_model"),
            )
            linddun_engine = "AI"
        except Exception as exc:
            linddun_threats = await generate_linddun_threats(
                project,
                trust_boundaries,
                force_fallback=True,
                dfd_model=report.get("dfd_model"),
            )
            linddun_engine = "fallback"
            linddun_generation_error = str(exc)
        raw_linddun_threats = list(linddun_threats or [])
        linddun_generation_status = getattr(linddun_threats, "assessment_status", "complete")
        linddun_generation_warnings = list(getattr(linddun_threats, "generation_warnings", []))
        linddun_response_shape = getattr(linddun_threats, "response_shape", "unknown")
        linddun_coverage = getattr(linddun_threats, "coverage", [])
        valid_linddun_coverage, coverage_warnings = validate_coverage(
            linddun_coverage, report.get("dfd_model"), "LINDDUN"
        )
        linddun_threats, linddun_warnings = validate_generated_threats(
            linddun_threats, "LINDDUN", report.get("dfd_model"), evidence_ids
        )
        if raw_linddun_threats and not linddun_threats:
            linddun_generation_status = "invalid"
            _append_invalid_generation_quarantine(
                report, "LINDDUN", (report.get("dfd_model") or {}).get("revision"), raw_linddun_threats
            )
        elif len(linddun_threats) < len(raw_linddun_threats) and linddun_generation_status == "complete":
            linddun_generation_status = "partial"
        linddun_warnings = [*linddun_generation_warnings, *linddun_warnings]
        report["ai_status"]["linddun"] = {
            "ok": linddun_engine == "AI" and linddun_generation_status in {"complete", "valid_empty"} and not linddun_warnings,
            "engine": linddun_engine,
            "assessment_status": linddun_generation_status,
            "response_shape": linddun_response_shape,
            "validation_warnings": [*coverage_warnings, *linddun_warnings],
            **({"error": linddun_generation_error} if linddun_engine == "fallback" else {}),
        }
        linddun_threats = enrich_threats(linddun_threats, project, "LINDDUN")
        attach_target_refs(
            linddun_threats,
            report.get("trust_boundaries", trust_boundaries),
            report.get("trust_model", {}).get("views"),
            report.get("dfd_model"),
        )
        linddun_threats = annotate_privacy_threats(linddun_threats, report.get("dfd_model"))
        completed_coverage, coverage_summary = complete_graph_coverage(
            valid_linddun_coverage,
            linddun_threats,
            report.get("dfd_model"),
            "LINDDUN",
        )
        report.setdefault("analysis_coverage", {})["LINDDUN"] = completed_coverage
        report.setdefault("analysis_coverage_summary", {})["LINDDUN"] = coverage_summary
        if linddun_generation_status != "invalid":
            _quarantine_superseded_framework_items(
                report,
                linddun_threats,
                "LINDDUN",
                (report.get("dfd_model") or {}).get("revision"),
            )
            report["threats"], linddun_deduped = replace_framework_threats(
                report.get("threats", []), linddun_threats, "LINDDUN"
            )
        else:
            linddun_deduped = 0

    # Framework replacement above already reconciles each active snapshot. A
    # final empty-seed merge only removes duplicate records from legacy reports
    # without reintroducing stale framework findings.
    report["threats"], final_deduped = merge_deduped_threats([], report.get("threats", []))
    deduped_count = final_deduped + locals().get("stride_deduped", 0) + locals().get("linddun_deduped", 0)

    # 4. Controls
    if "controls" in types and report.get("threats"):
        try:
            controls = await map_controls(
                report["threats"],
                force_fallback=False,
                data_policy=project.get("data_policy"),
                dfd_model=report.get("dfd_model"),
            )
            report["ai_status"]["controls"] = {"ok": True, "engine": "AI"}
        except Exception as exc:
            controls = await map_controls(
                report["threats"],
                force_fallback=True,
                data_policy=project.get("data_policy"),
                dfd_model=report.get("dfd_model"),
            )
            report["ai_status"]["controls"] = {"ok": False, "error": str(exc), "engine": "fallback"}
        mapped_controls = enrich_controls(
            controls,
            report["threats"],
            project,
            dfd_model=report.get("dfd_model"),
            evidence_ids=evidence_ids,
        )
        report["controls"] = reconcile_controls(
            report.get("controls", []),
            mapped_controls,
            (report.get("dfd_model") or {}).get("revision"),
        )

    # 5. Test Scenarios
    if "tests" in types and report.get("threats"):
        try:
            tests = await generate_test_scenarios(
                report["threats"],
                project,
                force_fallback=False,
                controls=report.get("controls", []),
                dfd_model=report.get("dfd_model"),
                evidence_ids=evidence_ids,
            )
            report["ai_status"]["tests"] = {"ok": True, "engine": "AI"}
        except Exception as exc:
            tests = await generate_test_scenarios(
                report["threats"],
                project,
                force_fallback=True,
                controls=report.get("controls", []),
                dfd_model=report.get("dfd_model"),
                evidence_ids=evidence_ids,
            )
            report["ai_status"]["tests"] = {"ok": False, "error": str(exc), "engine": "fallback"}
        report["test_scenarios"] = reconcile_test_scenarios(
            report.get("test_scenarios", []),
            tests,
            (report.get("dfd_model") or {}).get("revision"),
        )

    # 6. Missing Info
    if "missing_info" in types:
        try:
            missing = await generate_missing_info(project, report.get("threats", []), force_fallback=False)
            report["ai_status"]["missing_info"] = {"ok": True, "engine": "AI"}
        except Exception as exc:
            missing = await generate_missing_info(project, report.get("threats", []), force_fallback=True)
            report["ai_status"]["missing_info"] = {"ok": False, "error": str(exc), "engine": "fallback"}
        report["missing_info"] = enrich_missing_info(missing, project)

    # 7. Assumptions
    if "assumptions" in types:
        assumptions = await generate_assumptions(project, report.get("threats", []))
        report["assumptions"] = enrich_assumptions(assumptions, report.get("threats", []), project)

    # Risk summary
    threats = report.get("threats", [])
    report["risk_summary"] = {
        "critical": sum(1 for t in threats if t.get("risk_level") == "Critical"),
        "high": sum(1 for t in threats if t.get("risk_level") == "High"),
        "medium": sum(1 for t in threats if t.get("risk_level") == "Medium"),
        "low": sum(1 for t in threats if t.get("risk_level") == "Low"),
        "total": len(threats),
        "stride_count": sum(1 for t in threats if t.get("framework") == "STRIDE"),
        "linddun_count": sum(1 for t in threats if t.get("framework") == "LINDDUN"),
        "needs_review": sum(1 for t in threats if t.get("needs_human_review")),
        "needs_info": sum(1 for t in threats if t.get("status") == "Needs Info"),
        "deduped_on_last_run": deduped_count,
        "completeness_score": report["completeness"].get("score", 0),
        "boundary_candidates": sum(item.get("status") == "Candidate" for item in report.get("trust_boundaries", [])),
        "boundary_confirmed": sum(item.get("status") == "Confirmed" for item in report.get("trust_boundaries", [])),
    }
    report["generated_at"] = datetime.utcnow().isoformat()
    propagate_target_refs(report)

    # A source change with a human-edited DFD leaves a proposal pending. Keep
    # downstream stages stale until the reviewer applies or resolves it.
    _clear_completed_stale_stages(
        report,
        [] if report.get("dfd_proposal") else _valid_completed_stages(report, types),
    )

    stage_duration = round(time.perf_counter() - stage_started_at, 2)
    stage_metrics = report.setdefault("stage_metrics", {})
    completed_at = datetime.utcnow().isoformat()
    for analysis_type in types:
        stage_metrics[analysis_type] = {
            "duration_seconds": stage_duration,
            "completed_at": completed_at,
        }

    save_report(project_id, report)

    # Update project status
    project["analysis_status"] = "completed"
    project["risk_summary"] = report["risk_summary"]
    project["completeness_score"] = report["completeness"].get("score", 0)
    project["completeness_level"] = report["completeness"].get("level", "")
    save_project(project)

    log_event("analysis.completed", details={
        "project_id": project_id,
        "threats": len(threats),
        "controls": len(report.get("controls", [])),
        "tests": len(report.get("test_scenarios", [])),
        "deduped": deduped_count,
        "analysis_types": types,
        "duration_seconds": stage_duration,
    })

    return report


@router.get("/{project_id}/report")
async def get_project_report(project_id: str, request: Request = None):
    """Get the threat model report for a project."""
    project = get_project(project_id) if request is None else get_authorized_project(project_id, request)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    report = get_report(project_id)
    if not report:
        raise HTTPException(status_code=404, detail="No report yet — run analysis first")

    return normalize_report_evidence(report, project)


@router.patch("/{project_id}/threats/{threat_id}")
async def update_threat_review(project_id: str, threat_id: str, data: dict, request: Request = None):
    """Update review workflow fields for a generated threat."""
    if request is not None and not get_authorized_project(project_id, request):
        raise HTTPException(status_code=404, detail="Project not found")
    report = get_report(project_id)
    if not report:
        raise HTTPException(status_code=404, detail="No report yet — run analysis first")

    if not update_item_by_id(report.get("threats", []), "threat_id", threat_id, data):
        raise HTTPException(status_code=404, detail="Threat not found")

    save_report(project_id, report)
    log_event("threat.review_updated", details={"project_id": project_id, "threat_id": threat_id})
    return {"success": True}


@router.patch("/{project_id}/trust-boundaries/{boundary_id}")
async def update_trust_boundary_review(project_id: str, boundary_id: str, data: dict, request: Request = None):
    """Confirm, reject, or reset a grounded trust-boundary candidate."""
    if request is not None and not get_authorized_project(project_id, request):
        raise HTTPException(status_code=404, detail="Project not found")
    report = get_report(project_id)
    if not report:
        raise HTTPException(status_code=404, detail="No report yet — run analysis first")

    boundary = next(
        (item for item in report.get("trust_boundaries", []) if item.get("boundary_id") == boundary_id),
        None,
    )
    if not boundary:
        raise HTTPException(status_code=404, detail="Trust boundary not found")

    status = str(data.get("status") or "").strip()
    if status not in TRUST_BOUNDARY_REVIEW_STATUSES:
        raise HTTPException(status_code=422, detail="Status must be Candidate, Confirmed, or Rejected")
    review_note = str(data.get("review_note") or "").strip()[:1000]
    reviewed_at = _utc_now()
    review = {
        "status": status,
        "review_note": review_note,
        "reviewed_at": reviewed_at,
        "model_fingerprint": boundary.get("model_fingerprint"),
    }
    report.setdefault("trust_boundary_reviews", {})[boundary_id] = review
    boundary.update({**review, "review_stale": False})

    summary = report.setdefault("trust_model", {}).setdefault("review_summary", {})
    summary.update({
        "candidate": sum(item.get("status") == "Candidate" for item in report.get("trust_boundaries", [])),
        "confirmed": sum(item.get("status") == "Confirmed" for item in report.get("trust_boundaries", [])),
        "rejected": sum(item.get("status") == "Rejected" for item in report.get("trust_boundaries", [])),
    })
    report.setdefault("risk_summary", {}).update({
        "boundary_candidates": summary["candidate"],
        "boundary_confirmed": summary["confirmed"],
    })
    # Review status only gates visibility. The stored findings remain intact so
    # Candidate/Confirmed can restore them without an expensive regeneration.
    _clear_review_visibility_stale(report)
    save_report(project_id, report)
    log_event("trust_boundary.review_updated", details={
        "project_id": project_id,
        "boundary_id": boundary_id,
        "status": status,
    })
    return {
        "success": True,
        "boundary": boundary,
        "analysis_stale": report.get("analysis_stale"),
    }


@router.patch("/{project_id}/controls/{control_id}")
async def update_control_review(project_id: str, control_id: str, data: dict, request: Request = None):
    """Update checklist/review workflow fields for a mapped control."""
    project = get_project(project_id) if request is None else get_authorized_project(project_id, request)
    if request is not None and not project:
        raise HTTPException(status_code=404, detail="Project not found")
    project = project or {}
    report = get_report(project_id)
    if not report:
        raise HTTPException(status_code=404, detail="No report yet — run analysis first")

    try:
        data = validate_control_patch(
            data,
            dfd_model=report.get("dfd_model"),
            evidence_ids={
                str(item.get("evidence_id"))
                for item in build_project_evidence_catalog(project)
                if item.get("evidence_id")
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if not update_item_by_id(report.get("controls", []), "control_id", control_id, data):
        raise HTTPException(status_code=404, detail="Control not found")

    save_report(project_id, report)
    log_event("control.review_updated", details={"project_id": project_id, "control_id": control_id})
    return {"success": True}


@router.post("/{project_id}/analyze/stride")
async def run_stride_only(project_id: str, request: Request = None):
    return await run_full_analysis(
        project_id,
        {"analysis_types": ["trust_boundary", "stride", "controls", "tests"]},
        request=request,
    )


@router.post("/{project_id}/analyze/linddun")
async def run_linddun_only(project_id: str, request: Request = None):
    return await run_full_analysis(
        project_id,
        {"analysis_types": ["trust_boundary", "linddun", "controls", "tests"]},
        request=request,
    )
