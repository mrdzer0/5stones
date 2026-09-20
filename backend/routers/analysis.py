"""Analysis router — runs threat modeling pipeline."""
from __future__ import annotations
import copy
from fastapi import APIRouter, HTTPException, Request
from backend.utils.storage import (
    get_project, save_dfd_model, save_project, save_report, get_report, get_dfd_model,
    get_analysis_progress, save_analysis_progress,
)
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
from backend.services.dfd_model_service import (
    build_dfd_model,
    load_dfd_model,
    recalculate_boundary_crossings,
    reconcile_generated_dfd,
    validate_dfd_model,
)
from backend.services.stride_service import generate_stride_threats
from backend.services.linddun_service import generate_linddun_threats
from backend.services.privacy_service import assess_privacy_metadata, annotate_privacy_threats
from backend.services.threat_validation_service import (
    complete_graph_coverage,
    normalize_generation_result,
    quarantine_report_threats,
    ThreatGenerationResult,
    ThreatGenerationContractError,
    validate_coverage,
    validate_generated_threats,
)
from backend.services.ai_service import AnalysisResponseError
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
ANALYSIS_STAGE_DEPENDENCIES = {
    "trust_boundary": [],
    "stride": ["trust_boundary"],
    "linddun": ["trust_boundary"],
    "controls": ["stride", "linddun"],
    "tests": ["controls"],
    "missing_info": ["stride", "linddun"],
    "assumptions": ["stride", "linddun"],
}
_ACTIVE_ANALYSIS_RUNS: set[str] = set()


class AnalysisPublishConflict(RuntimeError):
    """Raised when a run would publish over a newer canonical/report state."""


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


def _analysis_snapshot(report: dict, project: dict | None = None) -> dict:
    dfd_model = report.get("dfd_model") if isinstance(report, dict) else {}
    dfd_model = dfd_model if isinstance(dfd_model, dict) else {}
    return {
        "dfd_revision": dfd_model.get("revision"),
        "dfd_semantic_hash": dfd_model.get("semantic_hash"),
        "project_updated_at": (project or {}).get("updated_at"),
    }


def _stage_matches_snapshot(status: dict, snapshot: dict | None, run_id: str | None = None) -> bool:
    if not isinstance(status, dict) or status.get("ok") is not True:
        return False
    if run_id and status.get("run_id") != run_id:
        return False
    if snapshot is None:
        return True
    recorded = status.get("analysis_snapshot")
    if not isinstance(recorded, dict):
        return False
    return all(recorded.get(key) == snapshot.get(key) for key in ("dfd_revision", "dfd_semantic_hash"))


def _valid_completed_stages(
    report: dict,
    requested: list[str],
    *,
    run_id: str | None = None,
    snapshot: dict | None = None,
) -> list[str]:
    """Return only stages that produced current, validated results."""
    statuses = report.get("ai_status") if isinstance(report.get("ai_status"), dict) else {}
    def is_valid(stage: str, seen: set[str] | None = None, require_run_id: bool = True) -> bool:
        seen = set(seen or set())
        if stage in seen:
            return False
        seen.add(stage)
        status = statuses.get(stage)
        if stage == "assumptions" and snapshot is None:
            return isinstance(report.get("assumptions"), list)
        if not _stage_matches_snapshot(status, snapshot, run_id if require_run_id else None):
            return False
        if stage == "trust_boundary":
            dfd_status = statuses.get("dfd_model") or {}
            boundary_status = statuses.get("trust_boundary") or {}
            dependency_run_id = run_id if require_run_id else None
            return _stage_matches_snapshot(dfd_status, snapshot, dependency_run_id) and _stage_matches_snapshot(boundary_status, snapshot, dependency_run_id)
        if stage == "assumptions":
            # Assumptions are deterministic, but only count as complete after
            # the pipeline has materialized the stage output.
            return isinstance(report.get("assumptions"), list) and (
                snapshot is None or all(is_valid(dependency, seen, False) for dependency in ANALYSIS_STAGE_DEPENDENCIES.get(stage, []))
            )
        if snapshot is None:
            return True
        return all(is_valid(dependency, seen, False) for dependency in ANALYSIS_STAGE_DEPENDENCIES.get(stage, []))

    return [stage for stage in requested if is_valid(stage)]


def _stage_status_template(run_id: str, snapshot: dict, stage: str) -> dict:
    return {
        "ok": False,
        "engine": "pending",
        "assessment_status": "not_run",
        "run_id": run_id,
        "analysis_snapshot": dict(snapshot),
        "dependencies": list(ANALYSIS_STAGE_DEPENDENCIES.get(stage, [])),
    }


def _stamp_stage_results(
    report: dict,
    requested: list[str],
    run_id: str,
    snapshot: dict,
    stage_timings: dict[str, float],
):
    statuses = report.setdefault("ai_status", {})
    completed_at = _utc_now()
    for stage in requested:
        status = statuses.get(stage)
        if not isinstance(status, dict):
            status = _stage_status_template(run_id, snapshot, stage)
            statuses[stage] = status
        status["run_id"] = run_id
        status["analysis_snapshot"] = dict(snapshot)
        status["dependencies"] = list(ANALYSIS_STAGE_DEPENDENCIES.get(stage, []))
        status["duration_seconds"] = round(float(stage_timings.get(stage, 0.0)), 3)
        status["completed_at"] = completed_at


def _stage_timer(stage_timings: dict[str, float], stage: str):
    started = time.perf_counter()

    def finish():
        stage_timings[stage] = time.perf_counter() - started

    return finish


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


def _append_generation_contract_quarantine(
    report: dict,
    framework: str,
    revision: str | None,
    error: str,
):
    """Record a provider contract failure without treating it as a fallback result."""
    _append_analysis_quarantine(report, [{
        "quarantine_id": f"contract-{framework.lower()}-{uuid.uuid4().hex[:8]}",
        "captured_at": _utc_now(),
        "framework": framework,
        "model_revision": revision,
        "reasons": ["provider_contract_invalid"],
        "item": {"error": str(error or "Invalid provider response")[:240]},
    }])


def _append_preserved_framework_result(
    report: dict,
    framework: str,
    revision: str | None,
    status: str,
    raw_items: list,
):
    """Record provider output that was intentionally not allowed to replace a valid snapshot."""
    records = []
    items = list(raw_items or [])
    if not items:
        items = [{"raw_count": 0}]
    for index, item in enumerate(items):
        summary = {}
        if isinstance(item, dict):
            for key in ("threat_id", "threat_category", "title", "threat_description"):
                if item.get(key):
                    summary[key] = str(item[key])[:240]
            if "raw_count" in item:
                summary["raw_count"] = item["raw_count"]
        else:
            summary["raw_type"] = type(item).__name__
        records.append({
            "quarantine_id": f"preserved-{framework.lower()}-{index}-{uuid.uuid4().hex[:8]}",
            "captured_at": _utc_now(),
            "framework": framework,
            "model_revision": revision,
            "reasons": [f"{status}_result_preserved_prior_snapshot"],
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
        reviewed = bool(
            item.get("reviewed_at")
            or item.get("review_notes")
            or item.get("status") in {"Reviewed", "Accepted", "Mitigated", "Verified"}
        )
        if reviewed:
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


def _capture_recovery_snapshot(report: dict) -> dict | None:
    """Capture the last persisted result before a run can quarantine it.

    A failed or contract-invalid rerun must not turn a previously useful
    report into an empty report.  The snapshot is kept in memory during the
    run; the resulting report stores the recovered items plus a compact audit
    record, so a later retry has an explicit provenance trail.
    """
    if not isinstance(report, dict):
        return None
    collections = {
        key: copy.deepcopy(report.get(key) or [])
        for key in (
            "threats", "controls", "test_scenarios", "missing_info",
            "assumptions", "trust_boundaries", "data_flows",
        )
    }
    dfd_model = copy.deepcopy(report.get("dfd_model")) if isinstance(report.get("dfd_model"), dict) else None
    # Only a finding that still satisfies the canonical DFD contract is a
    # recoverable baseline. Legacy/stale items remain quarantine evidence and
    # must not be promoted into the visible report during recovery.
    if collections["threats"] and dfd_model:
        validated_threats, _ = quarantine_report_threats(collections["threats"], dfd_model)
        collections["threats"] = copy.deepcopy(validated_threats)
    if not any(collections.values()) and not dfd_model:
        return None
    snapshot_id = f"recovery-{uuid.uuid4().hex[:12]}"
    snapshot = {
        "snapshot_id": snapshot_id,
        "captured_at": _utc_now(),
        **collections,
        "dfd_model": dfd_model,
        "dfd_validation": copy.deepcopy(report.get("dfd_validation") or {}),
        "trust_model": copy.deepcopy(report.get("trust_model") or {}),
        "risk_summary": copy.deepcopy(report.get("risk_summary") or {}),
    }
    history = report.setdefault("analysis_history", [])
    if isinstance(history, list):
        history.append({
            "snapshot_id": snapshot_id,
            "captured_at": snapshot["captured_at"],
            "dfd_revision": (dfd_model or {}).get("revision"),
            "dfd_semantic_hash": (dfd_model or {}).get("semantic_hash"),
            "threat_count": len(collections["threats"]),
            "control_count": len(collections["controls"]),
            "test_count": len(collections["test_scenarios"]),
        })
        report["analysis_history"] = history[-10:]
    return snapshot


def _mark_historical_items(items: list, snapshot_id: str, reason: str) -> list:
    marked = []
    for raw in items or []:
        if not isinstance(raw, dict):
            continue
        item = copy.deepcopy(raw)
        item["analysis_state"] = "historical"
        item["historical_reason"] = reason
        item["recovery_snapshot_id"] = snapshot_id
        item["needs_human_review"] = True
        marked.append(item)
    return marked


def _apply_recovery_snapshot(
    report: dict,
    snapshot: dict | None,
    requested_types: list[str],
) -> dict:
    """Restore collections whose replacement was not validated.

    The active report remains usable, but every recovered item is explicitly
    marked historical so downstream consumers cannot mistake it for a fresh
    assessment of the current DFD revision.
    """
    statuses = report.get("ai_status") if isinstance(report.get("ai_status"), dict) else {}
    failed_stages = []
    preserved_stages = []
    preserved_frameworks = []
    preserved_collections = []
    baseline_used = False

    def failed(stage: str) -> bool:
        status = statuses.get(stage)
        return isinstance(status, dict) and status.get("ok") is not True

    def preserve_status(stage: str, preserved: bool):
        status = statuses.get(stage)
        if not isinstance(status, dict):
            return
        status["previous_results_preserved"] = bool(preserved)
        # A deterministic fallback is only a baseline when no verified prior
        # snapshot was available.  This keeps the UI from claiming baseline
        # output when it is actually showing historical results.
        status["baseline_used"] = bool(status.get("engine") == "fallback" and not preserved)

    if not snapshot:
        for stage in requested_types:
            if failed(stage):
                failed_stages.append(stage)
                preserve_status(stage, False)
                status = statuses.get(stage) or {}
                baseline_used = baseline_used or bool(status.get("engine") == "fallback")
        if failed_stages:
            recovery = {
                "state": "baseline_used" if baseline_used else "analysis_unavailable",
                "retryable": True,
                "baseline_used": baseline_used,
                "previous_results_preserved": False,
                "failed_stages": sorted(set(failed_stages)),
                "preserved_frameworks": [],
                "preserved_collections": [],
                "message": "No validated replacement was produced for one or more requested stages.",
                "updated_at": _utc_now(),
            }
            report["analysis_recovery"] = recovery
            return recovery
        report.pop("analysis_recovery", None)
        return {}

    snapshot_id = snapshot["snapshot_id"]
    prior_threats = snapshot.get("threats") or []
    for framework, stage in (("STRIDE", "stride"), ("LINDDUN", "linddun")):
        if stage not in requested_types or not failed(stage):
            continue
        failed_stages.append(stage)
        prior_items = [item for item in prior_threats if isinstance(item, dict) and item.get("framework") == framework]
        status = statuses.get(stage) or {}
        if prior_items:
            current = [
                item for item in (report.get("threats") or [])
                if not isinstance(item, dict) or item.get("framework") != framework
            ]
            recovered = _mark_historical_items(
                prior_items,
                snapshot_id,
                f"{framework} replacement was not validated for the current analysis run",
            )
            report["threats"] = [*current, *recovered]
            preserved_frameworks.append(framework)
            preserved_stages.append(stage)
            preserve_status(stage, True)
        else:
            preserve_status(stage, False)
            baseline_used = baseline_used or bool(status.get("engine") == "fallback")

    for stage, collection_key in (("controls", "controls"), ("tests", "test_scenarios"), ("missing_info", "missing_info"), ("assumptions", "assumptions")):
        if stage not in requested_types or not failed(stage):
            continue
        failed_stages.append(stage)
        prior_items = snapshot.get(collection_key) or []
        if prior_items:
            report[collection_key] = _mark_historical_items(
                prior_items,
                snapshot_id,
                f"{stage} replacement was not validated for the current analysis run",
            )
            preserved_collections.append(collection_key)
            preserved_stages.append(stage)
            preserve_status(stage, True)
        else:
            status = statuses.get(stage) or {}
            preserve_status(stage, False)
            baseline_used = baseline_used or bool(status.get("engine") == "fallback")

    # A deterministic DFD/trust-boundary failure should leave the last
    # canonical topology available for review instead of exposing an empty
    # diagram that looks like a valid empty system.
    if "trust_boundary" in requested_types and failed("trust_boundary"):
        failed_stages.append("trust_boundary")
        if snapshot.get("dfd_model"):
            report["dfd_model"] = copy.deepcopy(snapshot["dfd_model"])
            report["dfd_validation"] = copy.deepcopy(snapshot.get("dfd_validation") or {})
            report["trust_model"] = copy.deepcopy(snapshot.get("trust_model") or {})
            report["trust_boundaries"] = copy.deepcopy(snapshot.get("trust_boundaries") or [])
            report["data_flows"] = copy.deepcopy(snapshot.get("data_flows") or [])
            preserved_collections.append("dfd_model")
            preserved_stages.append("trust_boundary")
            preserve_status("trust_boundary", True)

    if not failed_stages:
        report.pop("analysis_recovery", None)
        return {}

    previous_preserved = bool(preserved_stages or preserved_frameworks or preserved_collections)
    recovery = {
        "state": "previous_results_preserved" if previous_preserved else ("baseline_used" if baseline_used else "analysis_unavailable"),
        "retryable": True,
        "baseline_used": bool(baseline_used and not previous_preserved),
        "previous_results_preserved": previous_preserved,
        "snapshot_id": snapshot_id,
        "failed_stages": sorted(set(failed_stages)),
        "preserved_stages": sorted(set(preserved_stages)),
        "preserved_frameworks": sorted(set(preserved_frameworks)),
        "preserved_collections": sorted(set(preserved_collections)),
        "message": "The last validated results remain available while the failed stages are retried.",
        "updated_at": _utc_now(),
    }
    report["analysis_recovery"] = recovery
    return recovery


def _publish_project_analysis_state(
    project_id: str,
    run_id: str,
    status: str,
    report: dict | None = None,
    fallback_project: dict | None = None,
) -> bool:
    """Merge analysis fields into the latest project snapshot.

    The pipeline is async and project context can change while it is running.
    Reloading immediately before publishing prevents a stale project object
    from erasing newer risk/completeness or artifact fields.
    """
    latest = get_project(project_id) or copy.deepcopy(fallback_project or {})
    latest_run_id = latest.get("analysis_run_id")
    if latest_run_id and latest_run_id != run_id and latest.get("analysis_status") == "running":
        return False
    latest["analysis_status"] = status
    latest["analysis_run_id"] = run_id
    if isinstance(report, dict):
        if isinstance(report.get("risk_summary"), dict):
            latest["risk_summary"] = copy.deepcopy(report["risk_summary"])
        completeness = report.get("completeness") if isinstance(report.get("completeness"), dict) else {}
        latest["completeness_score"] = completeness.get("score", latest.get("completeness_score", 0))
        latest["completeness_level"] = completeness.get("level", latest.get("completeness_level", ""))
    save_project(latest)
    return True


def _project_run_is_current(project_id: str, run_id: str) -> bool:
    latest = get_project(project_id)
    latest_run_id = latest.get("analysis_run_id") if isinstance(latest, dict) else None
    return not latest_run_id or latest_run_id == run_id


def _merge_latest_review_state(result: dict, latest: dict) -> None:
    """Carry reviewer edits made while the provider was running into result."""
    review_fields = (
        "status", "owner", "review_notes", "reviewed_at", "needs_human_review",
        "review_status", "implementation_status", "implementation_state",
        "verification_evidence_refs", "implementation_evidence_refs",
        "execution_status", "actual_result", "execution_evidence_refs",
    )
    for collection, identity in (
        ("threats", "threat_id"),
        ("controls", "control_id"),
        ("test_scenarios", "test_id"),
    ):
        latest_items = {
            str(item.get(identity)): item
            for item in (latest.get(collection) or [])
            if isinstance(item, dict) and item.get(identity)
        }
        for item in result.get(collection) or []:
            if not isinstance(item, dict) or not item.get(identity):
                continue
            current = latest_items.get(str(item.get(identity)))
            if not current:
                continue
            for field in review_fields:
                if field in current and current.get(field) not in (None, [], ""):
                    item[field] = copy.deepcopy(current[field])


def _assert_analysis_publish_safe(report: dict, project_id: str) -> None:
    """Reject a publish that targets a newer report or canonical DFD revision."""
    manifest = report.get("analysis_run_manifest") if isinstance(report, dict) else {}
    base_revision = manifest.get("base_report_revision") if isinstance(manifest, dict) else None
    latest = get_report(project_id)
    if not isinstance(latest, dict) or base_revision is None:
        return
    try:
        latest_revision = int(latest.get("report_revision", 0) or 0)
        base_revision = int(base_revision or 0)
    except (TypeError, ValueError):
        return
    if latest_revision == base_revision:
        return
    latest_dfd = get_dfd_model(project_id) or latest.get("dfd_model") or {}
    result_dfd = report.get("dfd_model") or {}
    if (
        latest_dfd.get("revision") != result_dfd.get("revision")
        or latest_dfd.get("semantic_hash") != result_dfd.get("semantic_hash")
    ):
        raise AnalysisPublishConflict(
            "The canonical DFD changed while analysis was running. The run was not published; retry against the latest revision."
        )
    _merge_latest_review_state(report, latest)


def _requested_analysis_types(body: dict | None) -> list[str]:
    requested = (body or {}).get("analysis_types")
    if not isinstance(requested, list) or not requested:
        return ["trust_boundary", "stride", "linddun", "controls", "tests", "missing_info", "assumptions"]
    return [str(item) for item in requested if str(item).strip()]


def _write_analysis_progress(project_id: str, run_id: str, *, stage: str | None = None,
                             state: str | None = None, status: dict | None = None,
                             run_status: str | None = None):
    progress = get_analysis_progress(project_id)
    if not isinstance(progress, dict) or progress.get("run_id") != run_id:
        return
    if stage and stage in progress.get("stages", {}):
        record = progress["stages"][stage]
        record["state"] = state or record.get("state", "queued")
        if state == "active":
            record["started_at"] = _utc_now()
            progress["active_stage"] = stage
        else:
            record["completed_at"] = _utc_now()
            record["assessment_status"] = (status or {}).get("assessment_status") or ("complete" if (status or {}).get("ok") else "invalid")
            record["error_code"] = (status or {}).get("error_code")
            record["error"] = redact_text(str((status or {}).get("error") or ""))[:240]
            record["duration_seconds"] = (status or {}).get("duration_seconds")
            if progress.get("active_stage") == stage:
                progress["active_stage"] = None
    if run_status:
        progress["status"] = run_status
        if run_status == "failed":
            for record in progress.get("stages", {}).values():
                if record.get("state") == "active":
                    record["state"] = "warning"
                    record["assessment_status"] = "failed"
                    record["completed_at"] = _utc_now()
                elif record.get("state") == "queued":
                    record["state"] = "skipped"
        progress["active_stage"] = None
        if run_status != "running":
            progress["completed_at"] = _utc_now()
    progress["updated_at"] = _utc_now()
    save_analysis_progress(project_id, progress)


def _initial_analysis_progress(run_id: str, types: list[str]) -> dict:
    return {
        "run_id": run_id,
        "status": "running",
        "requested_types": list(types),
        "stage_order": list(types),
        "stages": {stage: {"state": "queued"} for stage in types},
        "active_stage": None,
        "started_at": _utc_now(),
        "updated_at": _utc_now(),
    }


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
    input_snapshot = _analysis_snapshot(previous_report, project)
    run_state = {
        "run_id": str(uuid.uuid4()),
        "status": "running",
        "requested_types": types,
        "started_at": _utc_now(),
        "input_snapshot": input_snapshot,
        "stage_dependencies": {stage: ANALYSIS_STAGE_DEPENDENCIES.get(stage, []) for stage in types},
        "previous_successful_run_id": previous_run.get("run_id") if previous_run.get("status") in {"completed", "completed_with_warnings"} else None,
        "retryable": False,
    }
    previous_report["analysis_run"] = run_state
    previous_report["analysis_status"] = "running"
    save_report(project_id, previous_report)
    project["analysis_status"] = "running"
    project["analysis_run_id"] = run_state["run_id"]
    save_project(project)
    publish_progress = request is not None
    if publish_progress:
        save_analysis_progress(project_id, _initial_analysis_progress(run_state["run_id"], types))

    try:
        result = await _run_analysis_pipeline(
            project_id,
            body,
            request=request,
            run_id=run_state["run_id"],
            input_snapshot=input_snapshot,
            publish_progress=publish_progress,
        )
    except Exception as exc:
        safe_error = redact_text(str(exc))[:1000] or "Analysis pipeline failed"
        latest_project = get_project(project_id)
        if isinstance(latest_project, dict) and latest_project.get("analysis_run_id") not in (None, run_state["run_id"]):
            log_event("analysis.superseded", details={"project_id": project_id, "run_id": run_state["run_id"]})
            raise HTTPException(status_code=409, detail="A newer analysis run owns this project; the older result was not published.") from exc
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
        if publish_progress:
            _write_analysis_progress(project_id, run_state["run_id"], run_status="failed")
        _publish_project_analysis_state(
            project_id,
            run_state["run_id"],
            "failed",
            report=failed_report,
            fallback_project=project,
        )
        log_event("analysis.failed", details={"project_id": project_id, "run_id": run_state["run_id"], "error": safe_error})
        raise HTTPException(status_code=500, detail="Analysis failed; the previous saved model remains available and can be retried.") from exc
    finally:
        _ACTIVE_ANALYSIS_RUNS.discard(project_id)

    statuses = result.get("ai_status") if isinstance(result.get("ai_status"), dict) else {}
    warning_stages = sorted(
        stage for stage in {*types, *(set(["dfd_model"]) if "trust_boundary" in types else set())}
        if isinstance(statuses.get(stage), dict) and statuses[stage].get("ok") is False
    )
    pipeline_manifest = result.pop("analysis_run_manifest", {}) if isinstance(result, dict) else {}
    result["analysis_run"] = {
        **run_state,
        **pipeline_manifest,
        "status": "completed_with_warnings" if warning_stages else "completed",
        "completed_at": _utc_now(),
        "warning_stages": warning_stages,
        "retryable": bool(warning_stages),
    }
    result["analysis_status"] = result["analysis_run"]["status"]
    if not _project_run_is_current(project_id, run_state["run_id"]):
        return get_report(project_id) or result
    save_report(project_id, result)
    if publish_progress:
        _write_analysis_progress(project_id, run_state["run_id"], run_status=result["analysis_status"])
    _publish_project_analysis_state(
        project_id,
        run_state["run_id"],
        result["analysis_status"],
        report=result,
        fallback_project=project,
    )
    return result


@router.get("/{project_id}/analyze/progress")
async def get_analysis_run_progress(project_id: str, request: Request = None):
    project = get_project(project_id) if request is None else get_authorized_project(project_id, request)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    progress = get_analysis_progress(project_id)
    report = get_report(project_id) or {}
    run = report.get("analysis_run") or {}
    if isinstance(progress, dict) and progress.get("run_id") == run.get("run_id"):
        return progress
    return {"run_id": run.get("run_id"), "status": run.get("status", "not_run"),
            "requested_types": run.get("requested_types") or [], "stages": {}, "active_stage": None}


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


async def _run_analysis_pipeline(
    project_id: str,
    body: dict = None,
    request: Request = None,
    run_id: str | None = None,
    input_snapshot: dict | None = None,
    publish_progress: bool = False,
):
    """Run full threat modeling pipeline for a project."""
    project = get_project(project_id) if request is None else get_authorized_project(project_id, request)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    types = _requested_analysis_types(body)
    run_id = run_id or str(uuid.uuid4())
    stage_started_at = time.perf_counter()
    stage_timings: dict[str, float] = {}
    log_event("analysis.started", details={"project_id": project_id, "analysis_types": types})

    report = get_report(project_id)
    if report:
        report = normalize_report_evidence(report, project)
    else:
        report = _empty_report(project)

    recovery_snapshot = _capture_recovery_snapshot(report)
    # A new run starts with a clean recovery marker. If this run cannot
    # replace a stage, _apply_recovery_snapshot will add a new, truthful one.
    report.pop("analysis_recovery", None)

    report["completeness"] = compute_completeness(project)
    evidence_catalog = build_project_evidence_catalog(project)
    evidence_ids = {
        str(item.get("evidence_id"))
        for item in evidence_catalog
        if item.get("evidence_id")
    }
    report.setdefault("ai_status", {})
    input_snapshot = dict(input_snapshot or _analysis_snapshot(report, project))
    for stage in types:
        # Keep previous output collections for recovery, but mark their status
        # as not-run until this run produces a validated replacement.
        report["ai_status"][stage] = _stage_status_template(run_id, input_snapshot, stage)
    report["analysis_run_manifest"] = {
        "run_id": run_id,
        "requested_types": list(types),
        "input_snapshot": dict(input_snapshot),
        "base_report_revision": report.get("report_revision", 0),
        "stage_dependencies": {stage: ANALYSIS_STAGE_DEPENDENCIES.get(stage, []) for stage in types},
    }

    def start_stage(stage: str):
        if publish_progress:
            _write_analysis_progress(project_id, run_id, stage=stage, state="active")

    def end_stage(stage: str):
        if publish_progress:
            stage_status = report.get("ai_status", {}).get(stage) or {}
            stage_state = "completed" if stage_status.get("ok") else (
                "blocked" if stage_status.get("assessment_status") == "blocked" else "warning"
            )
            _write_analysis_progress(project_id, run_id, stage=stage, state=stage_state,
                                     status={**stage_status, "duration_seconds": stage_timings.get(stage)})

    # 1. Trust Boundaries
    if "trust_boundary" in types:
        start_stage("trust_boundary")
    finish_trust_boundary = _stage_timer(stage_timings, "trust_boundary") if "trust_boundary" in types else None
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
            report["ai_status"]["trust_boundary"]["ok"] = bool(dfd_validation["valid"])
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
    if finish_trust_boundary:
        finish_trust_boundary()
        end_stage("trust_boundary")

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
    if "stride" in types:
        start_stage("stride")
    stride_threats = []
    finish_stride = _stage_timer(stage_timings, "stride") if "stride" in types else None
    if "stride" in types:
        prior_stride_threats = [
            dict(item) for item in (report.get("threats") or [])
            if isinstance(item, dict) and item.get("framework") == "STRIDE"
        ]
        stride_generation_status = "complete"
        stride_generation_error = None
        stride_error_code = None
        stride_response_metadata = {}
        try:
            stride_threats = await generate_stride_threats(
                project,
                trust_boundaries,
                force_fallback=False,
                dfd_model=report.get("dfd_model"),
            )
            stride_engine = "AI"
        except (AnalysisResponseError, ThreatGenerationContractError) as exc:
            # A provider response that cannot satisfy the structured contract
            # is an invalid assessment, not a deterministic fallback.
            stride_threats = ThreatGenerationResult(
                [],
                [],
                assessment_status="invalid",
                response_shape="invalid",
                warnings=[str(exc)],
                response_metadata=getattr(exc, "response_metadata", {}),
            )
            stride_engine = "AI"
            stride_generation_error = str(exc)
            stride_error_code = getattr(exc, "code", "provider_contract_invalid")
            stride_response_metadata = getattr(exc, "response_metadata", {})
            _append_generation_contract_quarantine(
                report,
                "STRIDE",
                (report.get("dfd_model") or {}).get("revision"),
                str(exc),
            )
        except Exception as exc:
            stride_threats = await generate_stride_threats(
                project,
                trust_boundaries,
                force_fallback=True,
                dfd_model=report.get("dfd_model"),
            )
            stride_engine = "fallback"
            stride_generation_error = str(exc)
            stride_error_code = getattr(exc, "code", "provider_unavailable")
            stride_response_metadata = getattr(exc, "response_metadata", {})
        stride_threats = normalize_generation_result(stride_threats, "STRIDE")
        raw_stride_threats = list(stride_threats or [])
        stride_generation_status = getattr(stride_threats, "assessment_status", "complete")
        stride_generation_warnings = list(getattr(stride_threats, "generation_warnings", []))
        stride_response_shape = getattr(stride_threats, "response_shape", "unknown")
        stride_response_metadata = getattr(stride_threats, "response_metadata", stride_response_metadata)
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
            "response_metadata": stride_response_metadata,
            **({"error_code": stride_error_code} if stride_error_code else {}),
            "validation_warnings": [*coverage_warnings, *stride_warnings],
            "baseline_used": False,
            "previous_results_preserved": False,
            **({"error": stride_generation_error} if stride_generation_error else {}),
        }
        stride_threats = enrich_threats(stride_threats, project, "STRIDE")
        attach_target_refs(
            stride_threats,
            report.get("trust_boundaries", trust_boundaries),
            report.get("trust_model", {}).get("views"),
            report.get("dfd_model"),
        )
        preserve_prior_stride = stride_generation_status in {"fallback", "partial"} and bool(prior_stride_threats)
        coverage_threats = prior_stride_threats if preserve_prior_stride else stride_threats
        completed_coverage, coverage_summary = complete_graph_coverage(
            valid_stride_coverage,
            coverage_threats,
            report.get("dfd_model"),
            "STRIDE",
        )
        report.setdefault("analysis_coverage", {})["STRIDE"] = completed_coverage
        report.setdefault("analysis_coverage_summary", {})["STRIDE"] = coverage_summary
        if preserve_prior_stride:
            _append_preserved_framework_result(
                report,
                "STRIDE",
                (report.get("dfd_model") or {}).get("revision"),
                stride_generation_status,
                raw_stride_threats,
            )
            stride_deduped = 0
        elif stride_generation_status != "invalid":
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
    if finish_stride:
        finish_stride()
        end_stage("stride")

    # 3. LINDDUN
    if "linddun" in types:
        start_stage("linddun")
    linddun_threats = []
    finish_linddun = _stage_timer(stage_timings, "linddun") if "linddun" in types else None
    if "linddun" in types:
        prior_linddun_threats = [
            dict(item) for item in (report.get("threats") or [])
            if isinstance(item, dict) and item.get("framework") == "LINDDUN"
        ]
        linddun_generation_status = "complete"
        linddun_generation_error = None
        linddun_error_code = None
        linddun_response_metadata = {}
        try:
            linddun_threats = await generate_linddun_threats(
                project,
                trust_boundaries,
                force_fallback=False,
                dfd_model=report.get("dfd_model"),
            )
            linddun_engine = "AI"
        except (AnalysisResponseError, ThreatGenerationContractError) as exc:
            # Keep schema/contract failures distinguishable from availability
            # failures that legitimately use the deterministic fallback.
            linddun_threats = ThreatGenerationResult(
                [],
                [],
                assessment_status="invalid",
                response_shape="invalid",
                warnings=[str(exc)],
                response_metadata=getattr(exc, "response_metadata", {}),
            )
            linddun_engine = "AI"
            linddun_generation_error = str(exc)
            linddun_error_code = getattr(exc, "code", "provider_contract_invalid")
            linddun_response_metadata = getattr(exc, "response_metadata", {})
            _append_generation_contract_quarantine(
                report,
                "LINDDUN",
                (report.get("dfd_model") or {}).get("revision"),
                str(exc),
            )
        except Exception as exc:
            linddun_threats = await generate_linddun_threats(
                project,
                trust_boundaries,
                force_fallback=True,
                dfd_model=report.get("dfd_model"),
            )
            linddun_engine = "fallback"
            linddun_generation_error = str(exc)
            linddun_error_code = getattr(exc, "code", "provider_unavailable")
            linddun_response_metadata = getattr(exc, "response_metadata", {})
        linddun_threats = normalize_generation_result(linddun_threats, "LINDDUN")
        raw_linddun_threats = list(linddun_threats or [])
        linddun_generation_status = getattr(linddun_threats, "assessment_status", "complete")
        linddun_generation_warnings = list(getattr(linddun_threats, "generation_warnings", []))
        linddun_response_shape = getattr(linddun_threats, "response_shape", "unknown")
        linddun_response_metadata = getattr(linddun_threats, "response_metadata", linddun_response_metadata)
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
            "response_metadata": linddun_response_metadata,
            **({"error_code": linddun_error_code} if linddun_error_code else {}),
            "validation_warnings": [*coverage_warnings, *linddun_warnings],
            "baseline_used": False,
            "previous_results_preserved": False,
            **({"error": linddun_generation_error} if linddun_generation_error else {}),
        }
        linddun_threats = enrich_threats(linddun_threats, project, "LINDDUN")
        attach_target_refs(
            linddun_threats,
            report.get("trust_boundaries", trust_boundaries),
            report.get("trust_model", {}).get("views"),
            report.get("dfd_model"),
        )
        linddun_threats = annotate_privacy_threats(linddun_threats, report.get("dfd_model"))
        preserve_prior_linddun = linddun_generation_status in {"fallback", "partial"} and bool(prior_linddun_threats)
        coverage_threats = prior_linddun_threats if preserve_prior_linddun else linddun_threats
        completed_coverage, coverage_summary = complete_graph_coverage(
            valid_linddun_coverage,
            coverage_threats,
            report.get("dfd_model"),
            "LINDDUN",
        )
        report.setdefault("analysis_coverage", {})["LINDDUN"] = completed_coverage
        report.setdefault("analysis_coverage_summary", {})["LINDDUN"] = coverage_summary
        if preserve_prior_linddun:
            _append_preserved_framework_result(
                report,
                "LINDDUN",
                (report.get("dfd_model") or {}).get("revision"),
                linddun_generation_status,
                raw_linddun_threats,
            )
            linddun_deduped = 0
        elif linddun_generation_status != "invalid":
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
    if finish_linddun:
        finish_linddun()
        end_stage("linddun")

    # Framework replacement above already reconciles each active snapshot. A
    # final empty-seed merge only removes duplicate records from legacy reports
    # without reintroducing stale framework findings.
    report["threats"], final_deduped = merge_deduped_threats([], report.get("threats", []))
    deduped_count = final_deduped + locals().get("stride_deduped", 0) + locals().get("linddun_deduped", 0)

    # 4. Controls
    if "controls" in types:
        start_stage("controls")
    finish_controls = _stage_timer(stage_timings, "controls") if "controls" in types else None
    if "controls" in types and report.get("threats"):
        try:
            controls = await map_controls(
                report["threats"],
                force_fallback=False,
                data_policy=project.get("data_policy"),
                dfd_model=report.get("dfd_model"),
                evidence_ids=evidence_ids,
                evidence_catalog=evidence_catalog,
            )
            controls_status = getattr(controls, "assessment_status", "complete")
            report["ai_status"]["controls"] = {
                "ok": controls_status == "complete",
                "engine": "AI",
                "assessment_status": controls_status,
                "baseline_used": False,
                "previous_results_preserved": False,
                "response_shape": getattr(controls, "response_shape", "unknown"),
                "warnings": getattr(controls, "generation_warnings", []),
                "response_metadata": getattr(controls, "response_metadata", {}),
            }
        except Exception as exc:
            controls = await map_controls(
                report["threats"],
                force_fallback=True,
                data_policy=project.get("data_policy"),
                dfd_model=report.get("dfd_model"),
                evidence_ids=evidence_ids,
                evidence_catalog=evidence_catalog,
            )
            report["ai_status"]["controls"] = {
                "ok": False,
                "error": str(exc),
                "error_code": getattr(exc, "code", "stage_generation_error"),
                "engine": "fallback",
                "assessment_status": "fallback",
                "baseline_used": True,
                "previous_results_preserved": False,
                "response_shape": getattr(controls, "response_shape", "deterministic_fallback"),
                "warnings": getattr(controls, "generation_warnings", []),
                "response_metadata": getattr(exc, "response_metadata", {}),
            }
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
    elif "controls" in types:
        report["ai_status"]["controls"] = {
            **report["ai_status"].get("controls", {}),
            "ok": False,
            "engine": "blocked",
            "assessment_status": "blocked",
            "blocked_by": ["stride", "linddun"],
            "error": "Controls were not generated because no validated threat findings were available.",
            "baseline_used": False,
            "previous_results_preserved": False,
        }
    if finish_controls:
        finish_controls()
        end_stage("controls")

    # 5. Test Scenarios
    if "tests" in types:
        start_stage("tests")
    finish_tests = _stage_timer(stage_timings, "tests") if "tests" in types else None
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
            tests_status = getattr(tests, "assessment_status", "complete")
            report["ai_status"]["tests"] = {
                "ok": tests_status == "complete",
                "engine": "AI",
                "assessment_status": tests_status,
                "baseline_used": False,
                "previous_results_preserved": False,
                "response_shape": getattr(tests, "response_shape", "unknown"),
                "warnings": getattr(tests, "generation_warnings", []),
                "response_metadata": getattr(tests, "response_metadata", {}),
            }
        except Exception as exc:
            tests = await generate_test_scenarios(
                report["threats"],
                project,
                force_fallback=True,
                controls=report.get("controls", []),
                dfd_model=report.get("dfd_model"),
                evidence_ids=evidence_ids,
            )
            report["ai_status"]["tests"] = {
                "ok": False,
                "error": str(exc),
                "error_code": getattr(exc, "code", "stage_generation_error"),
                "engine": "fallback",
                "assessment_status": "fallback",
                "baseline_used": True,
                "previous_results_preserved": False,
                "response_shape": getattr(tests, "response_shape", "deterministic_fallback"),
                "warnings": getattr(tests, "generation_warnings", []),
                "response_metadata": getattr(exc, "response_metadata", {}),
            }
        report["test_scenarios"] = reconcile_test_scenarios(
            report.get("test_scenarios", []),
            tests,
            (report.get("dfd_model") or {}).get("revision"),
        )
    elif "tests" in types:
        report["ai_status"]["tests"] = {
            **report["ai_status"].get("tests", {}),
            "ok": False,
            "engine": "blocked",
            "assessment_status": "blocked",
            "blocked_by": ["controls"],
            "error": "Test scenarios were not generated because no validated threat findings were available.",
            "baseline_used": False,
            "previous_results_preserved": False,
        }
    if finish_tests:
        finish_tests()
        end_stage("tests")

    # 6. Missing Info
    if "missing_info" in types:
        start_stage("missing_info")
    finish_missing_info = _stage_timer(stage_timings, "missing_info") if "missing_info" in types else None
    if "missing_info" in types:
        try:
            missing = await generate_missing_info(project, report.get("threats", []), force_fallback=False)
            report["ai_status"]["missing_info"] = {"ok": True, "engine": "AI"}
        except Exception as exc:
            missing = await generate_missing_info(project, report.get("threats", []), force_fallback=True)
            report["ai_status"]["missing_info"] = {"ok": False, "error": str(exc), "engine": "fallback"}
        report["missing_info"] = enrich_missing_info(missing, project)
    if finish_missing_info:
        finish_missing_info()
        end_stage("missing_info")

    # 7. Assumptions
    if "assumptions" in types:
        start_stage("assumptions")
    finish_assumptions = _stage_timer(stage_timings, "assumptions") if "assumptions" in types else None
    if "assumptions" in types:
        assumptions = await generate_assumptions(project, report.get("threats", []))
        report["assumptions"] = enrich_assumptions(assumptions, report.get("threats", []), project)
        report["ai_status"]["assumptions"] = {"ok": True, "engine": "deterministic", "assessment_status": "complete"}
    if finish_assumptions:
        finish_assumptions()
        end_stage("assumptions")

    recovery = _apply_recovery_snapshot(report, recovery_snapshot, types)

    # Risk summary
    threats = report.get("threats", [])
    historical_count = sum(1 for item in threats if item.get("analysis_state") == "historical")
    report["risk_summary"] = {
        "critical": sum(1 for t in threats if t.get("risk_level") == "Critical"),
        "high": sum(1 for t in threats if t.get("risk_level") == "High"),
        "medium": sum(1 for t in threats if t.get("risk_level") == "Medium"),
        "low": sum(1 for t in threats if t.get("risk_level") == "Low"),
        "total": len(threats),
        "current_total": len(threats) - historical_count,
        "historical_total": historical_count,
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

    final_snapshot = _analysis_snapshot(report, project)
    stamp_types = [*types, *(["dfd_model"] if "trust_boundary" in types else [])]
    _stamp_stage_results(report, stamp_types, run_id, final_snapshot, stage_timings)

    # A source change with a human-edited DFD leaves a proposal pending. Keep
    # downstream stages stale until the reviewer applies or resolves it. A
    # stage can clear staleness only when its own validated result and every
    # dependency point at this exact canonical snapshot and run.
    completed_stages = [] if report.get("dfd_proposal") else _valid_completed_stages(
        report,
        types,
        run_id=run_id,
        snapshot=final_snapshot,
    )
    _clear_completed_stale_stages(report, completed_stages)

    stage_duration = round(time.perf_counter() - stage_started_at, 2)
    stage_metrics = report.setdefault("stage_metrics", {})
    completed_at = datetime.utcnow().isoformat()
    for analysis_type in types:
        stage_metrics[analysis_type] = {
            "duration_seconds": round(float(stage_timings.get(analysis_type, 0.0)), 3),
            "completed_at": completed_at,
            "run_id": run_id,
            "analysis_snapshot": dict(final_snapshot),
        }

    report["analysis_run_manifest"] = {
        **(report.get("analysis_run_manifest") or {}),
        "final_snapshot": dict(final_snapshot),
        "completed_stages": completed_stages,
        "stage_timings": {stage: round(float(value), 3) for stage, value in stage_timings.items()},
        "recovery": copy.deepcopy(recovery),
    }

    if not _project_run_is_current(project_id, run_id):
        raise AnalysisPublishConflict(
            "A newer analysis run owns this project. The current run was not published; retry against the latest run state."
        )
    _assert_analysis_publish_safe(report, project_id)
    save_report(project_id, report)

    # Update only the latest project snapshot so an artifact edit made while
    # this async run was in flight is not overwritten by the stale input copy.
    _publish_project_analysis_state(
        project_id,
        run_id,
        "completed",
        report=report,
        fallback_project=project,
    )

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

    report = normalize_report_evidence(report, project)

    # Reports created before the readiness contract was expanded may still
    # contain a legacy flat ``dfd_validation`` object. Recompute the
    # validation from the canonical persisted model on read so the Analysis
    # page never presents an old green readiness result or stale topology
    # warning. This is intentionally read-only; persistence remains owned by
    # the DFD/analysis write paths.
    dfd_payload = get_dfd_model(project_id) or report.get("dfd_model")
    if isinstance(dfd_payload, dict):
        try:
            dfd_model, _migrated = load_dfd_model(dfd_payload, project_id=project_id)
            recalculate_boundary_crossings(dfd_model)
            report["dfd_model"] = dfd_model.model_dump()
            report["dfd_validation"] = validate_dfd_model(dfd_model)
        except (TypeError, ValueError):
            # Preserve the existing report response; the dedicated /dfd
            # endpoint will surface a malformed canonical payload explicitly.
            pass

    return report


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
            existing_control=next(
                (
                    item for item in (report.get("controls") or [])
                    if isinstance(item, dict) and str(item.get("control_id")) == str(control_id)
                ),
                None,
            ),
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
