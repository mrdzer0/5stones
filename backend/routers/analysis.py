"""Analysis router — runs threat modeling pipeline."""
from __future__ import annotations
import copy
import os
import threading
from fastapi import APIRouter, HTTPException, Request
from backend.utils.storage import (
    DfdRevisionConflict, ProjectRevisionConflict, RevisionConflict,
    get_project, save_project, save_report, save_report_and_dfd, get_report, get_dfd_model,
    get_analysis_progress, save_analysis_progress, save_report_revision,
    list_report_revisions, get_report_revision,
)
from backend.utils.audit import log_event
from backend.utils.access_control import (
    get_authorized_project,
    principal_for_request,
    release_authority_context,
    require_roles,
    workspace_access_dependency,
)
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
from backend.services.finding_quality_service import (
    build_applicability_manifest,
    validate_and_dedupe_findings,
)
from backend.services.deferred_decision_service import (
    apply_decision_update,
    reconcile_deferred_decisions,
)
from backend.services.ai_service import AnalysisResponseError
from backend.services.threat_batch_service import ThreatGenerationProviderError
from backend.services.control_service import map_controls
from backend.services.test_service import (
    generate_test_scenarios,
    generate_missing_info,
    generate_assumptions,
)
from backend.services.posture_service import (
    compute_completeness,
    compute_signoff_readiness,
    enrich_controls,
    ground_threat_findings,
    enrich_missing_info,
    enrich_assumptions,
    enrich_threats,
    merge_deduped_threats,
    replace_framework_threats,
    reconcile_controls,
    reconcile_test_scenarios,
    threat_fingerprint,
    normalize_report_evidence,
    summarize_threat_findings,
    build_project_evidence_catalog,
    update_item_by_id,
    validate_control_patch,
)
from backend.services.formal_report_service import (
    build_formal_report_metadata,
    provider_configuration_snapshot,
    report_snapshot_fingerprint,
    revision_summary,
)
from backend.services.release_decision_service import build_release_decision
from backend.services.run_state_service import attach_analysis_state, build_analysis_state
import uuid
import time
from datetime import datetime, timezone

router = APIRouter(
    prefix="/api/projects",
    tags=["analysis"],
    dependencies=[workspace_access_dependency, require_roles("analyst", "reviewer", "admin")],
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
def _analysis_run_capacity() -> int:
    raw = os.environ.get("ANALYSIS_MAX_CONCURRENT_RUNS", "2")
    try:
        capacity = int(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("ANALYSIS_MAX_CONCURRENT_RUNS must be a positive integer") from exc
    if capacity < 1:
        raise RuntimeError("ANALYSIS_MAX_CONCURRENT_RUNS must be a positive integer")
    return capacity


class AnalysisRunAdmission:
    """Atomic process-local admission for analysis runs.

    Multi-worker and multi-host deployments still need a shared admission
    control at the gateway or in a distributed store.
    """

    def __init__(self, capacity: int):
        if capacity < 1:
            raise ValueError("Analysis run capacity must be positive")
        self.capacity = capacity
        self._active_projects: set[str] = set()
        self._lock = threading.Lock()

    def reserve(self, project_id: str) -> str | None:
        with self._lock:
            if project_id in self._active_projects:
                return "duplicate"
            if len(self._active_projects) >= self.capacity:
                return "capacity"
            self._active_projects.add(project_id)
            return None

    def release(self, project_id: str) -> None:
        with self._lock:
            self._active_projects.discard(project_id)

    def is_active(self, project_id: str) -> bool:
        with self._lock:
            return project_id in self._active_projects


_ANALYSIS_RUN_ADMISSION = AnalysisRunAdmission(_analysis_run_capacity())


class AnalysisPublishConflict(RuntimeError):
    """Raised when a run would publish over a newer canonical/report state."""


def _refresh_quality_gate(report: dict) -> dict:
    """Keep the report-level and run-level sign-off decision identical."""
    gate = compute_signoff_readiness(report)
    report["quality_gate"] = gate
    run = report.get("analysis_run")
    if isinstance(run, dict):
        run["quality_gate"] = copy.deepcopy(gate)
        run["review_required"] = gate["review_required"]
    return gate


def _has_valid_empty_threat_assessment(report: dict) -> bool:
    """True only when both frameworks completed and legitimately found nothing."""
    if report.get("threats"):
        return False
    statuses = report.get("ai_status") if isinstance(report.get("ai_status"), dict) else {}
    for stage in ("stride", "linddun"):
        status = statuses.get(stage) if isinstance(statuses.get(stage), dict) else {}
        if status.get("ok") is not True:
            return False
        if str(status.get("assessment_status") or "").casefold() not in {"complete", "valid_empty"}:
            return False
        if status.get("baseline_used") or status.get("previous_results_preserved"):
            return False
        manifest = (report.get("analysis_coverage_manifest") or {}).get(stage.upper())
        if isinstance(manifest, dict) and not (manifest.get("summary") or {}).get("complete"):
            return False
    return True


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


def _prior_generation_manifest(report: dict, framework: str, snapshot: dict) -> dict | None:
    """Return a reusable AI batch manifest only for the same DFD snapshot.

    Batch fingerprints provide the final protection against changed prompts or
    evidence. This outer check prevents a retry from even considering a cache
    created for a stale canonical model or a deterministic fallback run.
    """
    statuses = report.get("ai_status") if isinstance(report.get("ai_status"), dict) else {}
    stage = statuses.get(framework.casefold())
    if not isinstance(stage, dict) or stage.get("engine") != "AI":
        return None
    if stage.get("assessment_status") not in {"complete", "valid_empty", "partial"}:
        return None
    recorded = stage.get("analysis_snapshot")
    if not isinstance(recorded, dict):
        return None
    if any(recorded.get(key) != snapshot.get(key) for key in ("dfd_revision", "dfd_semantic_hash")):
        return None
    metadata = stage.get("response_metadata")
    manifest = metadata.get("generation_manifest") if isinstance(metadata, dict) else None
    return manifest if isinstance(manifest, dict) else None


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


def _append_quality_quarantine(report: dict, records: list[dict], framework: str, revision: str | None):
    """Persist CR4 duplicate/grounding audit records without exposing raw AI text."""
    normalized = []
    for index, record in enumerate(records or []):
        item = record.get("item") if isinstance(record, dict) else {}
        normalized.append({
            "quarantine_id": f"quality-{framework.lower()}-{index}-{uuid.uuid4().hex[:8]}",
            "captured_at": _utc_now(),
            "framework": framework,
            "model_revision": revision,
            "reasons": list(record.get("reasons") or ["finding_quality_gate"]),
            "item": dict(item) if isinstance(item, dict) else {},
        })
    _append_analysis_quarantine(report, normalized)


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
        "analysis_status": "not_started",
        "analysis_run": {
            "run_id": None,
            "status": "not_started",
            "requested_types": [],
            "warning_stages": [],
            "retryable": False,
            "review_required": True,
        },
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
        if not isinstance(status, dict):
            return False
        assessment = status.get("assessment_status")
        # `ok` also reflects warnings. A validated complete/partial result must
        # remain current even when some candidates or coverage rows need review.
        if assessment in {"complete", "valid_empty", "partial"}:
            return False
        if assessment in {"invalid", "blocked", "fallback"}:
            return True
        return status.get("ok") is not True

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
) -> bool:
    """Merge analysis fields into the latest project snapshot.

    The pipeline is async and project context can change while it is running.
    Reloading immediately before publishing prevents a stale project object
    from erasing newer risk/completeness or artifact fields.
    """
    for _attempt in range(5):
        latest = get_project(project_id)
        if not isinstance(latest, dict):
            return False
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
            quality_gate = report.get("quality_gate") if isinstance(report.get("quality_gate"), dict) else {}
            latest["signoff_ready"] = quality_gate.get("signoff_ready", False)
            latest["signoff_status"] = quality_gate.get("status", "not_ready")
            latest["quality_gate"] = copy.deepcopy(quality_gate)
        try:
            save_project(latest)
            return True
        except ProjectRevisionConflict:
            continue
    return False


def _mark_analysis_run_superseded(project_id: str, run_id: str, *, update_project: bool = True) -> None:
    """Close a run whose captured report/DFD state was replaced while it ran."""
    latest_report = get_report(project_id)
    if not isinstance(latest_report, dict):
        return
    latest_run = latest_report.get("analysis_run")
    if isinstance(latest_run, dict) and latest_run.get("run_id") == run_id:
        latest_report["analysis_run"] = {
            **latest_run,
            "status": "superseded",
            "completed_at": _utc_now(),
            "retryable": True,
            "superseded_reason": "Project state changed while this analysis was running.",
        }
        latest_report["analysis_status"] = "superseded"
        try:
            save_report(project_id, latest_report)
        except RevisionConflict:
            # A newer write won while we recorded the superseded state.
            latest_report = get_report(project_id) or latest_report
    if update_project:
        _publish_project_analysis_state(
            project_id,
            run_id,
            "superseded",
            report=latest_report,
        )


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
    report["report_revision"] = latest_revision


def _requested_analysis_types(body: dict | None) -> list[str]:
    requested = (body or {}).get("analysis_types")
    if not isinstance(requested, list) or not requested:
        return ["trust_boundary", "stride", "linddun", "controls", "tests", "missing_info", "assumptions"]
    return [str(item) for item in requested if str(item).strip()]


def _eligible_downstream_threats(report: dict) -> list[dict]:
    """Return only current framework findings safe for controls and tests.

    Fallback, invalid, preserved, historical, stale, and ungrounded-primary
    records remain visible as review/baseline context, but they are not allowed
    to create current remediation actions or executable test claims.
    """
    statuses = report.get("ai_status") if isinstance(report.get("ai_status"), dict) else {}
    eligible: list[dict] = []
    blocked_assessments = {"invalid", "blocked", "fallback", "timed_out", "failed", "not_run"}
    for item in report.get("threats") or []:
        if not isinstance(item, dict):
            continue
        framework = str(item.get("framework") or "").casefold()
        stage = statuses.get(framework) if isinstance(statuses.get(framework), dict) else {}
        reason = None
        state = str(item.get("analysis_state") or "").casefold()
        if state in {"historical", "stale"}:
            reason = f"Finding is {state}; rerun the dependent framework before generating current actions."
        elif item.get("downstream_eligible", True) is False:
            reason = item.get("grounding_reason") or item.get("downstream_exclusion_reason") or "Finding is not eligible for downstream actions."
        elif stage.get("engine") == "fallback" or stage.get("baseline_used"):
            reason = "Framework output is a baseline/fallback suggestion, not a validated current assessment."
        elif stage.get("previous_results_preserved"):
            reason = "Framework output was preserved from a previous run and is not current for downstream actions."
        elif str(stage.get("assessment_status") or "not_run").casefold() in blocked_assessments:
            reason = f"Framework assessment is {stage.get('assessment_status') or 'not validated'}."
        elif framework not in {"stride", "linddun"}:
            reason = "Finding framework is not supported by the downstream action contract."
        if reason:
            item["downstream_eligible"] = False
            item["downstream_exclusion_reason"] = str(reason)
            item["downstream_state"] = "baseline_suggestion" if stage.get("engine") == "fallback" else "review_only"
            continue
        eligible.append(item)
    return eligible


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


@router.post("/{project_id}/analyze", dependencies=[require_roles("analyst", "admin")])
async def run_full_analysis(project_id: str, body: dict = None, request: Request = None):
    """Run analysis with a persisted run state and retry-safe failure boundary."""
    project = get_project(project_id) if request is None else get_authorized_project(project_id, request)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    admission = _ANALYSIS_RUN_ADMISSION.reserve(project_id)
    if admission == "duplicate":
        raise HTTPException(status_code=409, detail="Analysis is already running")
    if admission == "capacity":
        raise HTTPException(
            status_code=429,
            detail="Analysis capacity is full; retry after an active run completes.",
            headers={"Retry-After": "30"},
        )

    try:
        return await _run_full_analysis_reserved(project_id, project=project, body=body, request=request)
    finally:
        _ANALYSIS_RUN_ADMISSION.release(project_id)


async def _run_full_analysis_reserved(
    project_id: str,
    project: dict,
    body: dict = None,
    request: Request = None,
):
    """Execute a run after the caller has reserved its process-local slot."""
    types = _requested_analysis_types(body)
    previous_report = get_report(project_id) or _empty_report(project)
    previous_run = previous_report.get("analysis_run") if isinstance(previous_report.get("analysis_run"), dict) else {}
    input_snapshot = _analysis_snapshot(previous_report, project)
    canonical_dfd = get_dfd_model(project_id) or previous_report.get("dfd_model") or {}
    if isinstance(canonical_dfd, dict):
        input_snapshot["dfd_revision"] = canonical_dfd.get("revision")
        input_snapshot["dfd_semantic_hash"] = canonical_dfd.get("semantic_hash")
    run_state = {
        "run_id": str(uuid.uuid4()),
        "status": "running",
        "requested_types": types,
        "started_at": _utc_now(),
        "input_snapshot": input_snapshot,
        "stage_dependencies": {stage: ANALYSIS_STAGE_DEPENDENCIES.get(stage, []) for stage in types},
        "previous_successful_run_id": previous_run.get("run_id") if previous_run.get("status") in {"completed", "completed_with_warnings"} else None,
        "retryable": False,
        "provider": provider_configuration_snapshot(project),
    }
    previous_report["analysis_run"] = run_state
    previous_report["analysis_status"] = "running"
    try:
        save_report(project_id, previous_report)
    except RevisionConflict as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Project report changed before analysis started; reload the current state and retry.",
                "resource": "report",
                "expected_revision": exc.expected_revision,
                "current_revision": exc.current_revision,
            },
        ) from exc
    project["analysis_status"] = "running"
    project["analysis_run_id"] = run_state["run_id"]
    try:
        save_project(project)
    except ProjectRevisionConflict as exc:
        _mark_analysis_run_superseded(project_id, run_state["run_id"], update_project=False)
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Project changed before analysis started; reload the current state and retry.",
                "resource": "project",
                "expected_revision": exc.expected_revision,
                "current_revision": exc.current_revision,
            },
        ) from exc
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
    except AnalysisPublishConflict as exc:
        _mark_analysis_run_superseded(project_id, run_state["run_id"])
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (RevisionConflict, DfdRevisionConflict) as exc:
        _mark_analysis_run_superseded(project_id, run_state["run_id"])
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Project state changed while analysis was running; reload the current state and retry.",
                "resource": "dfd" if isinstance(exc, DfdRevisionConflict) else "report",
                "expected_revision": exc.expected_revision,
                "current_revision": exc.current_revision,
            },
        ) from exc
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
        )
        log_event("analysis.failed", details={"project_id": project_id, "run_id": run_state["run_id"], "error": safe_error})
        raise HTTPException(status_code=500, detail="Analysis failed; the previous saved model remains available and can be retried.") from exc
    statuses = result.get("ai_status") if isinstance(result.get("ai_status"), dict) else {}
    warning_stages = sorted(
        stage for stage in {*types, *(set(["dfd_model"]) if "trust_boundary" in types else set())}
        if isinstance(statuses.get(stage), dict) and statuses[stage].get("ok") is False
    )
    dfd_readiness = ((result.get("dfd_validation") or {}).get("readiness") or {})
    quality_gate = compute_signoff_readiness(result)
    review_required = quality_gate["review_required"]
    if dfd_readiness.get("status") == "not_ready" and "dfd_model" not in warning_stages:
        warning_stages.append("dfd_model")
        warning_stages.sort()
    retryable = any(
        isinstance(statuses.get(stage), dict) and statuses[stage].get("ok") is False
        for stage in {*types, *(set(["dfd_model"]) if "trust_boundary" in types else set())}
    )
    pipeline_manifest = result.pop("analysis_run_manifest", {}) if isinstance(result, dict) else {}
    result["analysis_run"] = {
        **run_state,
        **pipeline_manifest,
        "status": "completed_with_warnings" if warning_stages or review_required else "completed",
        "completed_at": _utc_now(),
        "warning_stages": warning_stages,
        "retryable": retryable,
        "review_required": review_required,
        "quality_gate": quality_gate,
    }
    result["quality_gate"] = copy.deepcopy(quality_gate)
    result["analysis_status"] = result["analysis_run"]["status"]
    result["analysis_state"] = build_analysis_state(result, project)
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
    if not (isinstance(progress, dict) and progress.get("run_id") == run.get("run_id")):
        progress = {
            "run_id": run.get("run_id"),
            "status": run.get("status", "not_started"),
            "requested_types": run.get("requested_types") or [],
            "stages": {},
            "active_stage": None,
        }
    response = copy.deepcopy(progress)
    response["analysis_state"] = build_analysis_state(report, project, response)
    return response


@router.post("/{project_id}/analyze/retry", dependencies=[require_roles("analyst", "admin")])
async def retry_analysis(project_id: str, request: Request = None):
    """Retry the last persisted analysis request without discarding its report."""
    project = get_project(project_id) if request is None else get_authorized_project(project_id, request)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    report = get_report(project_id)
    run_state = report.get("analysis_run") if isinstance(report, dict) else None
    if not isinstance(run_state, dict) or not run_state.get("requested_types"):
        raise HTTPException(status_code=404, detail="No previous analysis run is available to retry")
    if run_state.get("status") == "running" and _ANALYSIS_RUN_ADMISSION.is_active(project_id):
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
    prior_generation_manifests = {
        framework: _prior_generation_manifest(report, framework, input_snapshot)
        for framework in ("STRIDE", "LINDDUN")
    }
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
                prior_generation_manifest=prior_generation_manifests.get("STRIDE"),
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
        except ThreatGenerationProviderError as exc:
            if getattr(exc, "code", "") == "stage_timeout":
                stride_threats = ThreatGenerationResult(
                    [], [], assessment_status="timed_out", response_shape="invalid",
                    warnings=[str(exc)], response_metadata=getattr(exc, "response_metadata", {}),
                )
                stride_engine = "AI"
                stride_generation_error = str(exc)
                stride_error_code = exc.code
                stride_response_metadata = getattr(exc, "response_metadata", {})
            else:
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
            "ok": stride_engine == "AI" and stride_generation_status in {"complete", "valid_empty"},
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
        stride_threats = ground_threat_findings(
            stride_threats, project, report.get("dfd_model")
        )
        stride_threats, quality_warnings, quality_quarantine = validate_and_dedupe_findings(
            stride_threats,
            report.get("dfd_model"),
            evidence_ids,
            evidence_catalog,
        )
        stride_warnings = [*stride_warnings, *quality_warnings]
        report["ai_status"]["stride"]["validation_warnings"] = [
            *report["ai_status"]["stride"].get("validation_warnings", []),
            *quality_warnings,
        ]
        _append_quality_quarantine(
            report,
            quality_quarantine,
            "STRIDE",
            (report.get("dfd_model") or {}).get("revision"),
        )
        preserve_prior_stride = stride_generation_status == "fallback" and bool(prior_stride_threats)
        coverage_threats = prior_stride_threats if preserve_prior_stride else stride_threats
        completed_coverage, coverage_summary = complete_graph_coverage(
            valid_stride_coverage,
            coverage_threats,
            report.get("dfd_model"),
            "STRIDE",
        )
        report.setdefault("analysis_coverage", {})["STRIDE"] = completed_coverage
        report.setdefault("analysis_coverage_summary", {})["STRIDE"] = coverage_summary
        stride_manifest = build_applicability_manifest(
            completed_coverage,
            coverage_threats,
            report.get("dfd_model"),
            "STRIDE",
        )
        report.setdefault("analysis_coverage_manifest", {})["STRIDE"] = stride_manifest
        manifest_summary = stride_manifest["summary"]
        coverage_summary.update({
            "schema_version": manifest_summary["schema_version"],
            "assessed": manifest_summary["assessed"],
            "deferred": manifest_summary["deferred"],
            "failed": manifest_summary["failed"],
            "unprocessed": manifest_summary["unprocessed"],
            "insufficient_information": manifest_summary["deferred"] + manifest_summary["unprocessed"] + manifest_summary["failed"],
            "complete": manifest_summary["complete"],
            "primary_interaction_count": manifest_summary["primary_interaction_count"],
        })
        report.setdefault("analysis_coverage_summary", {})["STRIDE"] = coverage_summary
        if stride_generation_status == "complete" and not manifest_summary["complete"]:
            stride_generation_status = "partial"
            report["ai_status"]["stride"]["assessment_status"] = "partial"
            report["ai_status"]["stride"]["ok"] = False
            report["ai_status"]["stride"]["validation_warnings"] = [
                *report["ai_status"]["stride"].get("validation_warnings", []),
                "CR4 coverage manifest contains deferred, failed, or unprocessed primary interaction/category pairs.",
            ]
        elif stride_generation_status == "valid_empty" and not manifest_summary["complete"]:
            report["ai_status"]["stride"]["validation_warnings"] = [
                *report["ai_status"]["stride"].get("validation_warnings", []),
                "CR4 coverage is not complete; an empty framework result is not sign-off evidence.",
            ]
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
                prior_generation_manifest=prior_generation_manifests.get("LINDDUN"),
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
        except ThreatGenerationProviderError as exc:
            if getattr(exc, "code", "") == "stage_timeout":
                linddun_threats = ThreatGenerationResult(
                    [], [], assessment_status="timed_out", response_shape="invalid",
                    warnings=[str(exc)], response_metadata=getattr(exc, "response_metadata", {}),
                )
                linddun_engine = "AI"
                linddun_generation_error = str(exc)
                linddun_error_code = exc.code
                linddun_response_metadata = getattr(exc, "response_metadata", {})
            else:
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
            "ok": linddun_engine == "AI" and linddun_generation_status in {"complete", "valid_empty"},
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
        linddun_threats = ground_threat_findings(
            linddun_threats, project, report.get("dfd_model")
        )
        linddun_threats, quality_warnings, quality_quarantine = validate_and_dedupe_findings(
            linddun_threats,
            report.get("dfd_model"),
            evidence_ids,
            evidence_catalog,
        )
        linddun_warnings = [*linddun_warnings, *quality_warnings]
        report["ai_status"]["linddun"]["validation_warnings"] = [
            *report["ai_status"]["linddun"].get("validation_warnings", []),
            *quality_warnings,
        ]
        _append_quality_quarantine(
            report,
            quality_quarantine,
            "LINDDUN",
            (report.get("dfd_model") or {}).get("revision"),
        )
        preserve_prior_linddun = linddun_generation_status == "fallback" and bool(prior_linddun_threats)
        coverage_threats = prior_linddun_threats if preserve_prior_linddun else linddun_threats
        completed_coverage, coverage_summary = complete_graph_coverage(
            valid_linddun_coverage,
            coverage_threats,
            report.get("dfd_model"),
            "LINDDUN",
        )
        report.setdefault("analysis_coverage", {})["LINDDUN"] = completed_coverage
        report.setdefault("analysis_coverage_summary", {})["LINDDUN"] = coverage_summary
        linddun_manifest = build_applicability_manifest(
            completed_coverage,
            coverage_threats,
            report.get("dfd_model"),
            "LINDDUN",
        )
        report.setdefault("analysis_coverage_manifest", {})["LINDDUN"] = linddun_manifest
        manifest_summary = linddun_manifest["summary"]
        coverage_summary.update({
            "schema_version": manifest_summary["schema_version"],
            "assessed": manifest_summary["assessed"],
            "deferred": manifest_summary["deferred"],
            "failed": manifest_summary["failed"],
            "unprocessed": manifest_summary["unprocessed"],
            "insufficient_information": manifest_summary["deferred"] + manifest_summary["unprocessed"] + manifest_summary["failed"],
            "complete": manifest_summary["complete"],
            "primary_interaction_count": manifest_summary["primary_interaction_count"],
        })
        report.setdefault("analysis_coverage_summary", {})["LINDDUN"] = coverage_summary
        if linddun_generation_status == "complete" and not manifest_summary["complete"]:
            linddun_generation_status = "partial"
            report["ai_status"]["linddun"]["assessment_status"] = "partial"
            report["ai_status"]["linddun"]["ok"] = False
            report["ai_status"]["linddun"]["validation_warnings"] = [
                *report["ai_status"]["linddun"].get("validation_warnings", []),
                "CR4 coverage manifest contains deferred, failed, or unprocessed primary interaction/category pairs.",
            ]
        elif linddun_generation_status == "valid_empty" and not manifest_summary["complete"]:
            report["ai_status"]["linddun"]["validation_warnings"] = [
                *report["ai_status"]["linddun"].get("validation_warnings", []),
                "CR4 coverage is not complete; an empty framework result is not sign-off evidence.",
            ]
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
    downstream_threats = _eligible_downstream_threats(report)
    if "controls" in types:
        start_stage("controls")
    finish_controls = _stage_timer(stage_timings, "controls") if "controls" in types else None
    if "controls" in types and downstream_threats:
        try:
            # Catalog mapping is deterministic, threat-linked, and bounded. A
            # single AI response for the full DFD/threat catalog previously
            # exceeded 87k prompt tokens and repeatedly truncated.
            controls = await map_controls(
                downstream_threats,
                force_fallback=True,
                data_policy=project.get("data_policy"),
                workspace_id=project.get("workspace_id"),
                dfd_model=report.get("dfd_model"),
                evidence_ids=evidence_ids,
                evidence_catalog=evidence_catalog,
            )
            controls_status = "complete" if controls and all(
                item.get("mapping_status") != "unassigned" for item in controls if isinstance(item, dict)
            ) else "partial"
            report["ai_status"]["controls"] = {
                "ok": controls_status == "complete",
                "engine": "catalog",
                "assessment_status": controls_status,
                "baseline_used": False,
                "previous_results_preserved": False,
                "response_shape": "deterministic_catalog",
                "warnings": (["Some threats have no applicable catalog control; review their unassigned mapping."]
                             if controls_status == "partial" else []),
                "response_metadata": {"control_count": len(controls)},
            }
        except Exception as exc:
            controls = []
            report["ai_status"]["controls"] = {
                "ok": False,
                "error": str(exc),
                "error_code": getattr(exc, "code", "stage_generation_error"),
                "engine": "catalog",
                "assessment_status": "invalid",
                "baseline_used": False,
                "previous_results_preserved": False,
                "response_shape": "deterministic_catalog",
                "warnings": [],
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
        valid_empty = _has_valid_empty_threat_assessment(report)
        report["ai_status"]["controls"] = {
            **report["ai_status"].get("controls", {}),
            "ok": valid_empty,
            "engine": "catalog" if valid_empty else "blocked",
            "assessment_status": "valid_empty" if valid_empty else "blocked",
            "blocked_by": [] if valid_empty else ["stride", "linddun"],
            "error": None if valid_empty else "Controls were not generated because no validated threat findings were available.",
            "baseline_used": False,
            "previous_results_preserved": False,
            "response_metadata": {"control_count": 0},
        }
    if finish_controls:
        finish_controls()
        end_stage("controls")

    # 5. Test Scenarios
    if "tests" in types:
        start_stage("tests")
    finish_tests = _stage_timer(stage_timings, "tests") if "tests" in types else None
    if "tests" in types and downstream_threats:
        try:
            # Each active threat gets an executable or explicitly blocked
            # scenario from the reviewed template catalog. No huge AI prompt.
            tests = await generate_test_scenarios(
                downstream_threats,
                project,
                force_fallback=True,
                controls=report.get("controls", []),
                dfd_model=report.get("dfd_model"),
                evidence_ids=evidence_ids,
            )
            tests_status = "complete" if tests and all(
                item.get("applicability_status") == "applicable" for item in tests if isinstance(item, dict)
            ) else "partial"
            report["ai_status"]["tests"] = {
                "ok": tests_status == "complete",
                "engine": "templates",
                "assessment_status": tests_status,
                "baseline_used": False,
                "previous_results_preserved": False,
                "response_shape": "deterministic_templates",
                "warnings": (["Some scenarios are blocked pending threat/category review."]
                             if tests_status == "partial" else []),
                "response_metadata": {"scenario_count": len(tests)},
            }
        except Exception as exc:
            tests = []
            report["ai_status"]["tests"] = {
                "ok": False,
                "error": str(exc),
                "error_code": getattr(exc, "code", "stage_generation_error"),
                "engine": "templates",
                "assessment_status": "invalid",
                "baseline_used": False,
                "previous_results_preserved": False,
                "response_shape": "deterministic_templates",
                "warnings": [],
                "response_metadata": getattr(exc, "response_metadata", {}),
            }
        report["test_scenarios"] = reconcile_test_scenarios(
            report.get("test_scenarios", []),
            tests,
            (report.get("dfd_model") or {}).get("revision"),
        )
    elif "tests" in types:
        valid_empty = _has_valid_empty_threat_assessment(report)
        report["ai_status"]["tests"] = {
            **report["ai_status"].get("tests", {}),
            "ok": valid_empty,
            "engine": "templates" if valid_empty else "blocked",
            "assessment_status": "valid_empty" if valid_empty else "blocked",
            "blocked_by": [] if valid_empty else ["controls"],
            "error": None if valid_empty else "Test scenarios were not generated because no validated threat findings were available.",
            "baseline_used": False,
            "previous_results_preserved": False,
            "response_metadata": {"scenario_count": 0},
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
    # Re-derive finding states after snapshot reconciliation so preserved
    # reviewer data or legacy evidence cannot bypass the grounding guard.
    report = normalize_report_evidence(report, project)
    attach_target_refs(
        report.get("threats"),
        report.get("trust_boundaries") or [],
        (report.get("trust_model") or {}).get("views"),
        report.get("dfd_model"),
    )
    propagate_target_refs(report)

    # Risk summary
    threats = report.get("threats", [])
    report["risk_summary"] = {
        **summarize_threat_findings(threats, report.get("risk_summary")),
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
    stale = report.get("analysis_stale")
    if isinstance(stale, dict):
        attempted_unvalidated = [
            stage for stage in (stale.get("stages") or [])
            if stage in types and stage not in completed_stages
        ]
        if attempted_unvalidated and not report.get("dfd_proposal"):
            descriptions = [
                f"{stage} ({(report.get('ai_status', {}).get(stage) or {}).get('assessment_status') or 'not validated'})"
                for stage in attempted_unvalidated
            ]
            stale["reason"] = (
                "The latest run did not validate these stages against the current DFD: "
                + ", ".join(descriptions) + ". Review or retry them."
            )
            stale["last_attempt_at"] = _utc_now()

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
    canonical_dfd = report.get("dfd_model") if isinstance(report.get("dfd_model"), dict) else None
    if canonical_dfd is not None:
        save_report_and_dfd(
            project_id,
            report,
            canonical_dfd,
            expected_report_revision=int(report.get("report_revision", 0) or 0),
            expected_dfd_revision=int(input_snapshot.get("dfd_revision") or 0),
        )
    else:
        save_report(project_id, report)

    # Update only the latest project snapshot so an artifact edit made while
    # this async run was in flight is not overwritten by the stale input copy.
    _publish_project_analysis_state(
        project_id,
        run_id,
        "completed",
        report=report,
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
    report_exists = isinstance(report, dict) and bool(report)
    # A new project is a valid workflow state. Returning a typed empty
    # projection prevents an expected first-load 404 from becoming a browser
    # error and gives every workspace the same not_started contract.
    if not report:
        report = _empty_report(project)

    report = normalize_report_evidence(report, project)
    # Project context can be edited after the last analysis. Sign-off must use
    # the current input assessment, not the completeness snapshot from that run.
    report["completeness"] = compute_completeness(project)

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

    # Primary-interaction validity must be evaluated against the canonical DFD
    # revision loaded above, not only the model snapshot embedded in an older
    # report payload.
    report = normalize_report_evidence(report, project)
    _refresh_quality_gate(report)
    stored_formal = report.get("formal_report") if isinstance(report.get("formal_report"), dict) else {}
    report["formal_report"] = build_formal_report_metadata(
        project,
        report,
        status=stored_formal.get("status") or "draft",
    )
    formal_revision = stored_formal.get("revision")
    signed_snapshot = get_report_revision(project_id, f"report-r{formal_revision}-signed") if formal_revision is not None else None
    release_decision = build_release_decision(
        project,
        report,
        dfd_payload if isinstance(dfd_payload, dict) else {},
        signed_snapshot,
        report.get("quality_gate") or {},
        signed_metadata=stored_formal,
        report_exists=report_exists,
    )
    report["release_decision"] = release_decision
    if release_decision["status"] == "superseded":
        report["formal_report"] = {
            **stored_formal,
            "status": "superseded",
            "release_decision_status": "superseded",
            "signed_snapshot_sha256": release_decision.get("signed_snapshot_sha256"),
        }
    else:
        report["formal_report"]["release_decision_status"] = release_decision["status"]
        report["formal_report"]["signed_snapshot_sha256"] = release_decision.get("signed_snapshot_sha256")
    progress = get_analysis_progress(project_id)
    return attach_analysis_state(report, project, progress if isinstance(progress, dict) and progress.get("run_id") == (report.get("analysis_run") or {}).get("run_id") else None)


@router.get("/{project_id}/release-decision")
async def get_project_release_decision(project_id: str, request: Request = None):
    """Return the current signed/not-ready/superseded decision for consumer CI."""
    project = get_authorized_project(project_id, request)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    report = get_report(project_id)
    report_exists = isinstance(report, dict) and bool(report)
    if not isinstance(report, dict):
        report = {}
    stored_formal = report.get("formal_report") if isinstance(report.get("formal_report"), dict) else {}
    report = normalize_report_evidence(report, project)
    report["completeness"] = compute_completeness(project)
    gate = compute_signoff_readiness(report)
    canonical_dfd = get_dfd_model(project_id) or report.get("dfd_model") or {}
    revision = stored_formal.get("revision")
    signed_snapshot = get_report_revision(project_id, f"report-r{revision}-signed") if revision is not None else None
    return build_release_decision(
        project,
        report,
        canonical_dfd,
        signed_snapshot,
        gate,
        signed_metadata=stored_formal,
        report_exists=report_exists,
    )


@router.get("/{project_id}/report/revisions")
async def list_project_report_revisions(project_id: str, request: Request = None):
    """List immutable formal snapshots and the current draft metadata."""
    project = get_project(project_id) if request is None else get_authorized_project(project_id, request)
    report = get_report(project_id)
    if not project or not report:
        raise HTTPException(status_code=404, detail="Project or report not found")
    current = build_formal_report_metadata(project, report)
    return {
        "current": current,
        "revisions": [revision_summary(item) for item in list_report_revisions(project_id)],
    }


@router.get("/{project_id}/report/revisions/{revision_id}")
async def get_project_report_revision(project_id: str, revision_id: str, request: Request = None):
    """Return an immutable report snapshot for audit or reproducibility checks."""
    project = get_project(project_id) if request is None else get_authorized_project(project_id, request)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    snapshot = get_report_revision(project_id, revision_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail="Report revision not found")
    return snapshot


@router.post("/{project_id}/report/revisions", dependencies=[require_roles("analyst", "reviewer", "admin")])
async def create_project_report_revision(project_id: str, data: dict | None = None, request: Request = None):
    """Materialize the current report as a read-only draft snapshot."""
    project = get_project(project_id) if request is None else get_authorized_project(project_id, request)
    report = get_report(project_id)
    if not project or not report:
        raise HTTPException(status_code=404, detail="Project or report not found")
    metadata = build_formal_report_metadata(project, report, status="draft")
    revision = int(metadata.get("revision") or report.get("report_revision") or 0)
    revision_id = f"report-r{revision}-draft"
    snapshot = {
        "revision_id": revision_id,
        "status": "draft",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "formal_report": metadata,
        "report": copy.deepcopy(report),
    }
    saved = save_report_revision(project_id, snapshot)
    log_event("report.draft_snapshot_created", details={"project_id": project_id, "revision_id": revision_id})
    return {"success": True, "revision": revision_summary(saved), "formal_report": metadata}


@router.post("/{project_id}/report/signoff", dependencies=[require_roles("reviewer")])
async def sign_project_report(project_id: str, data: dict | None = None, request: Request = None):
    """Sign the current quality-gated report and persist an immutable snapshot."""
    project = get_project(project_id) if request is None else get_authorized_project(project_id, request)
    report = get_report(project_id)
    if not project or not report:
        raise HTTPException(status_code=404, detail="Project or report not found")
    previous_formal = report.get("formal_report") if isinstance(report.get("formal_report"), dict) else {}
    if previous_formal.get("status") == "signed" and int(previous_formal.get("revision") or 0) == int(report.get("report_revision") or 0):
        raise HTTPException(status_code=409, detail="This report revision is already signed and immutable")

    report = normalize_report_evidence(report, project)
    canonical_dfd = get_dfd_model(project_id) or report.get("dfd_model") or {}
    report_dfd = report.get("dfd_model") if isinstance(report.get("dfd_model"), dict) else {}
    canonical_revision = canonical_dfd.get("revision")
    if canonical_revision is not None and report_dfd.get("revision") is not None and str(canonical_revision) != str(report_dfd.get("revision")):
        raise HTTPException(status_code=409, detail="Canonical DFD changed after this report was generated; refresh analysis before sign-off")
    dfd_mismatch = [
        str(item.get("threat_id"))
        for item in (report.get("threats") or [])
        if isinstance(item, dict)
        and item.get("analysis_state") != "historical"
        and canonical_revision is not None
        and item.get("primary_interaction_ref")
        and str(item.get("dfd_revision") or item.get("analysis_revision") or "") != str(canonical_revision)
    ]
    if dfd_mismatch:
        raise HTTPException(status_code=409, detail={
            "message": "Active findings do not reference the current canonical DFD revision",
            "dfd_revision": canonical_revision,
            "finding_ids": dfd_mismatch[:20],
        })
    gate = _refresh_quality_gate(report)
    if not gate.get("signoff_ready"):
        raise HTTPException(status_code=409, detail={
            "message": "Report is not ready for sign-off",
            "blocking_reasons": gate.get("blocking_reasons") or [],
        })
    payload = data if isinstance(data, dict) else {}
    principal = principal_for_request(request)
    # Actor identity is server-owned. In the unauthenticated local profile we
    # record the fixed development principal rather than a caller-supplied name.
    reviewer = principal.subject if principal else "local-developer"
    note = str(payload.get("note") or "").strip()[:1000]
    next_revision = int(report.get("report_revision") or 0) + 1
    signed_at = datetime.now(timezone.utc).isoformat()
    approval_history = list(previous_formal.get("approval_history") or [])
    approval_history.append({
        "action": "signed",
        "actor": reviewer,
        "note": note or "Formal report approved for sign-off.",
        "recorded_at": signed_at,
        "revision": next_revision,
    })
    signer_deployment_profile, signer_identity_mode = release_authority_context()
    metadata = build_formal_report_metadata(
        project, report, status="signed", revision=next_revision,
        signed_by=reviewer, signed_at=signed_at, approval_history=approval_history,
        signed_deployment_profile=signer_deployment_profile,
        signed_identity_mode=signer_identity_mode,
    )
    report["formal_report"] = metadata
    saved = save_report(project_id, report)
    actual_revision = int(saved.get("report_revision") or next_revision)
    metadata["revision"] = actual_revision
    revision_id = f"report-r{actual_revision}-signed"
    snapshot = {
        "revision_id": revision_id,
        "status": "signed",
        "created_at": signed_at,
        "formal_report": copy.deepcopy(metadata),
        "report": copy.deepcopy(saved),
    }
    snapshot["snapshot_sha256"] = report_snapshot_fingerprint(snapshot)
    saved_snapshot = save_report_revision(project_id, snapshot)
    log_event("report.signed", details={"project_id": project_id, "revision_id": revision_id, "reviewer": reviewer})
    return {"success": True, "revision": revision_summary(saved_snapshot), "formal_report": metadata}


@router.patch("/{project_id}/threats/{threat_id}", dependencies=[require_roles("analyst", "reviewer", "admin")])
async def update_threat_review(project_id: str, threat_id: str, data: dict, request: Request = None):
    """Update review workflow fields for a generated threat."""
    project = get_project(project_id) if request is None else get_authorized_project(project_id, request)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    report = get_report(project_id)
    if not report:
        raise HTTPException(status_code=404, detail="No report yet — run analysis first")

    evidence_ids = {
        str(item.get("evidence_id"))
        for item in build_project_evidence_catalog(project)
        if item.get("evidence_id")
    }
    dfd_model = report.get("dfd_model") if isinstance(report.get("dfd_model"), dict) else {}
    flow_ids = {
        str(item.get("id"))
        for item in (dfd_model.get("flows") or [])
        if isinstance(item, dict) and item.get("id")
    }
    dfd_ids = {
        str(item.get("id"))
        for collection in ("nodes", "data_objects", "flows", "boundaries")
        for item in (dfd_model.get(collection) or [])
        if isinstance(item, dict) and item.get("id")
    }
    if "primary_interaction_ref" in data:
        primary_ref = str(data.get("primary_interaction_ref") or "").strip()
        if primary_ref not in flow_ids:
            raise HTTPException(status_code=422, detail="primary_interaction_ref must identify a canonical DFD flow")
        data["primary_interaction_ref"] = primary_ref
    if "dfd_context_refs" in data:
        context_refs = data.get("dfd_context_refs")
        if not isinstance(context_refs, list):
            raise HTTPException(status_code=422, detail="dfd_context_refs must be a list")
        invalid = [str(ref) for ref in context_refs if str(ref) not in dfd_ids]
        if invalid:
            raise HTTPException(status_code=422, detail=f"Unknown DFD context refs: {', '.join(invalid)}")
        data["dfd_context_refs"] = list(dict.fromkeys(str(ref) for ref in context_refs))
    if "verification_evidence_refs" in data:
        refs = data.get("verification_evidence_refs")
        if not isinstance(refs, list):
            raise HTTPException(status_code=422, detail="verification_evidence_refs must be a list")
        invalid = [str(ref) for ref in refs if str(ref) not in evidence_ids]
        if invalid:
            raise HTTPException(status_code=422, detail=f"Unknown verification evidence refs: {', '.join(invalid)}")
    existing = next(
        (item for item in (report.get("threats") or []) if str(item.get("threat_id")) == str(threat_id)),
        None,
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Threat not found")

    # Severity is derived by the versioned matrix. A reviewer may override the
    # final result only with an explicit reason; audit fields/history are
    # server-owned and cannot be injected by the client.
    for field in ("risk_override_by", "risk_override_at", "risk_override_history"):
        data.pop(field, None)
    override_requested = "risk_override_level" in data or "risk_override_reason" in data
    principal = principal_for_request(request)
    if override_requested and principal and principal.auth_mode != "disabled" and not principal.roles.intersection({"reviewer", "admin"}):
        raise HTTPException(status_code=403, detail="Risk overrides require the Reviewer role")
    if str(data.get("status") or "").strip().casefold() in {"accepted", "verified"} and principal and principal.auth_mode != "disabled" and not principal.roles.intersection({"reviewer", "admin"}):
        raise HTTPException(status_code=403, detail="Accepting or verifying a threat requires the Reviewer role")
    if override_requested:
        level = data.get("risk_override_level")
        reason = str(data.get("risk_override_reason") or "").strip()
        clearing = level in (None, "") and not reason
        if not clearing:
            if level not in {"Critical", "High", "Medium", "Low"}:
                raise HTTPException(status_code=422, detail="risk_override_level must be Critical, High, Medium, or Low")
            if len(reason) < 10:
                raise HTTPException(status_code=422, detail="A risk override requires a reason of at least 10 characters")
            if existing.get("finding_state") not in {"grounded", "reviewed", "verified"}:
                raise HTTPException(status_code=422, detail="Risk can be overridden only after the scenario is grounded or reviewed")
        now = datetime.now(timezone.utc).isoformat()
        reviewer = principal.subject if principal else "local-developer"
        history = [dict(entry) for entry in (existing.get("risk_override_history") or []) if isinstance(entry, dict)]
        history.append({
            "action": "cleared" if clearing else "set",
            "level": None if clearing else level,
            "reason": reason or "Reviewer cleared the risk override.",
            "reviewer": reviewer,
            "recorded_at": now,
            "previous_level": existing.get("risk_override_level"),
        })
        data.update({
            "risk_override_level": None if clearing else level,
            "risk_override_reason": None if clearing else reason,
            "risk_override_by": reviewer,
            "risk_override_at": now,
            "risk_override_history": history,
        })
    future_verification_refs = data.get("verification_evidence_refs", (existing or {}).get("verification_evidence_refs") or [])
    future_method = data.get("verification_method", (existing or {}).get("verification_method"))
    future_result = data.get("verification_result", (existing or {}).get("verification_result"))
    future_primary = str(data.get("primary_interaction_ref", (existing or {}).get("primary_interaction_ref") or ""))
    if data.get("status") == "Verified" and (
        not future_verification_refs
        or future_method not in {"runtime_test", "code_review", "configuration_review"}
        or future_result != "confirmed"
        or future_primary not in flow_ids
    ):
        raise HTTPException(
            status_code=422,
            detail="Verified status requires a primary DFD interaction, verification_evidence_refs, a verification_method, and verification_result=confirmed",
        )

    update_item_by_id(report.get("threats", []), "threat_id", threat_id, data)

    report = normalize_report_evidence(report, project)
    attach_target_refs(
        report.get("threats"),
        report.get("trust_boundaries") or [],
        (report.get("trust_model") or {}).get("views"),
        report.get("dfd_model"),
    )
    propagate_target_refs(report)
    quality_gate = _refresh_quality_gate(report)
    save_report(project_id, report)
    log_event("threat.review_updated", details={
        "project_id": project_id,
        "threat_id": threat_id,
        "risk_override_changed": override_requested,
        "risk_override_level": data.get("risk_override_level") if override_requested else None,
    })
    updated = next(
        (item for item in (report.get("threats") or []) if str(item.get("threat_id")) == str(threat_id)),
        None,
    )
    return {
        "success": True,
        "threat": updated,
        "risk_summary": report.get("risk_summary") or {},
        "quality_gate": quality_gate,
    }


@router.patch("/{project_id}/trust-boundaries/{boundary_id}", dependencies=[require_roles("reviewer", "admin")])
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
    quality_gate = _refresh_quality_gate(report)
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
        "quality_gate": quality_gate,
    }


@router.patch("/{project_id}/controls/{control_id}", dependencies=[require_roles("analyst", "reviewer", "admin")])
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

    quality_gate = _refresh_quality_gate(report)
    save_report(project_id, report)
    log_event("control.review_updated", details={"project_id": project_id, "control_id": control_id})
    return {"success": True, "quality_gate": quality_gate}


@router.patch("/{project_id}/evidence-items/{item_type}/{item_id}", dependencies=[require_roles("analyst", "reviewer", "admin")])
async def update_evidence_item(project_id: str, item_type: str, item_id: str, data: dict, request: Request = None):
    """Update the human-review state of a missing-info or assumption item."""
    project = get_project(project_id) if request is None else get_authorized_project(project_id, request)
    if request is not None and not project:
        raise HTTPException(status_code=404, detail="Project not found")
    report = get_report(project_id)
    if not report:
        raise HTTPException(status_code=404, detail="No report yet — run analysis first")

    collection_key = {"gap": "missing_info", "missing_info": "missing_info", "assumption": "assumptions"}.get(str(item_type).strip().lower())
    if not collection_key:
        raise HTTPException(status_code=422, detail="item_type must be gap or assumption")
    identity = "missing_id" if collection_key == "missing_info" else "assumption_id"
    item = next((entry for entry in (report.get(collection_key) or []) if str(entry.get(identity)) == str(item_id)), None)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence item not found")

    allowed_statuses = {"Open", "Assigned", "Answered", "Resolved", "Accepted assumption", "Deferred", "Obsolete"}
    if "status" in data and data["status"] not in allowed_statuses:
        raise HTTPException(status_code=422, detail="Unsupported evidence item status")
    principal = principal_for_request(request)
    if str(data.get("status") or "").strip().casefold() == "accepted assumption" and principal and principal.auth_mode != "disabled" and not principal.roles.intersection({"reviewer", "admin"}):
        raise HTTPException(status_code=403, detail="Accepting an assumption requires the Reviewer role")
    allowed_fields = {"status", "state", "answer", "resolution", "owner", "target_team", "next_action", "linked_object", "notes", "related_threat_id", "target_refs", "evidence_refs", "follow_up_date", "due_at"}
    for field in allowed_fields:
        if field not in data:
            continue
        value = data[field]
        if field == "target_refs":
            if not isinstance(value, list):
                raise HTTPException(status_code=422, detail="target_refs must be a list")
            value = [ref for ref in value if isinstance(ref, dict) and ref.get("id")]
        elif field == "evidence_refs":
            if not isinstance(value, list):
                raise HTTPException(status_code=422, detail="evidence_refs must be a list")
            value = [str(ref or "").strip()[:1000] for ref in value if str(ref or "").strip()][:20]
        elif field in {"owner", "target_team", "next_action", "linked_object", "notes", "related_threat_id", "answer", "resolution", "due_at"}:
            value = str(value or "").strip()[:1000] or None
        elif field == "follow_up_date":
            value = str(value or "").strip()[:80] or None
        item[field] = value
    item["reviewed_at"] = datetime.now(timezone.utc).isoformat()
    reconcile_deferred_decisions(report, project)
    source_type = "missing_info" if collection_key == "missing_info" else "assumption"
    decision = next(
        (
            entry for entry in (report.get("deferred_decisions") or [])
            if any(
                str(ref.get("type")) == source_type and str(ref.get("id")) == str(item_id)
                for ref in (entry.get("source_refs") or [])
                if isinstance(ref, dict)
            )
        ),
        None,
    )
    decision_impact = None
    if decision:
        decision_patch = dict(data)
        if "state" not in decision_patch and "status" not in decision_patch:
            decision_patch["state"] = item.get("state") or item.get("status")
        decision_patch.setdefault("evidence_refs", item.get("evidence_refs") or [])
        try:
            _, decision_impact = apply_decision_update(report, decision["decision_id"], decision_patch, project=project)
        except KeyError:
            decision_impact = None
    quality_gate = _refresh_quality_gate(report)
    save_report(project_id, report)
    log_event("evidence.item_updated", details={"project_id": project_id, "item_type": collection_key, "item_id": item_id})
    return {"success": True, "item": item, "decision_impact": decision_impact, "quality_gate": quality_gate}


@router.patch("/{project_id}/decisions/{decision_id}", dependencies=[require_roles("analyst", "reviewer", "admin")])
async def update_deferred_decision(project_id: str, decision_id: str, data: dict, request: Request = None):
    """Apply one canonical CR5 decision and selectively invalidate dependents."""
    project = get_project(project_id) if request is None else get_authorized_project(project_id, request)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    report = get_report(project_id)
    if not report:
        raise HTTPException(status_code=404, detail="No report yet — run analysis first")
    reconcile_deferred_decisions(report, project)
    allowed = {"state", "status", "owner", "due_at", "follow_up_date", "next_action", "answer", "resolution", "notes", "evidence_refs"}
    unknown = sorted(set(data or {}) - allowed)
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unsupported decision fields: {', '.join(unknown)}")
    if "evidence_refs" in data and not isinstance(data["evidence_refs"], list):
        raise HTTPException(status_code=422, detail="evidence_refs must be a list")
    if "state" in data or "status" in data:
        state_value = data.get("state", data.get("status"))
        allowed_states = {"open", "assigned", "answered", "accepted_assumption", "deferred", "obsolete", "Open", "Assigned", "Answered", "Resolved", "Accepted assumption", "Deferred", "Obsolete"}
        if state_value not in allowed_states:
            raise HTTPException(status_code=422, detail="Unsupported decision state")
        principal = principal_for_request(request)
        if str(state_value).strip().casefold() in {"accepted_assumption", "accepted assumption", "obsolete"} and principal and principal.auth_mode != "disabled" and not principal.roles.intersection({"reviewer", "admin"}):
            raise HTTPException(status_code=403, detail="Accepting or closing a deferred decision requires the Reviewer role")
    cleaned = dict(data or {})
    if "follow_up_date" in cleaned and "due_at" not in cleaned:
        cleaned["due_at"] = cleaned.pop("follow_up_date")
    if "evidence_refs" in cleaned:
        valid_evidence = {
            str(item.get("evidence_id")) for item in build_project_evidence_catalog(project)
            if item.get("evidence_id")
        }
        invalid = [str(ref) for ref in cleaned["evidence_refs"] if str(ref) not in valid_evidence]
        if invalid:
            raise HTTPException(status_code=422, detail=f"Unknown evidence refs: {', '.join(invalid)}")
        cleaned["evidence_refs"] = [str(ref) for ref in cleaned["evidence_refs"]]
    try:
        item, impact = apply_decision_update(report, decision_id, cleaned, project=project)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Deferred decision not found") from exc
    quality_gate = _refresh_quality_gate(report)
    save_report(project_id, report)
    log_event("deferred_decision.updated", details={
        "project_id": project_id,
        "decision_id": decision_id,
        "state": item.get("state"),
        "selective_invalidation": True,
    })
    return {"success": True, "decision": item, "impact": impact, "quality_gate": quality_gate}


@router.post("/{project_id}/analyze/stride", dependencies=[require_roles("analyst", "admin")])
async def run_stride_only(project_id: str, request: Request = None):
    return await run_full_analysis(
        project_id,
        {"analysis_types": ["trust_boundary", "stride", "controls", "tests"]},
        request=request,
    )


@router.post("/{project_id}/analyze/linddun", dependencies=[require_roles("analyst", "admin")])
async def run_linddun_only(project_id: str, request: Request = None):
    return await run_full_analysis(
        project_id,
        {"analysis_types": ["trust_boundary", "linddun", "controls", "tests"]},
        request=request,
    )
