"""Canonical, read-only analysis run state projection.

The analysis pipeline persists detailed stage records in a report and, while a
run is active, in the progress store.  Consumers used to infer status from
different subsets of those records.  This module is the single projection
used by project/workspace/report/export responses; it never mutates the source
report or progress document.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any


ANALYSIS_STATE_SCHEMA_VERSION = "analysis-state-v1"
STAGE_ORDER = (
    "trust_boundary",
    "stride",
    "linddun",
    "controls",
    "tests",
    "missing_info",
    "assumptions",
)
STAGE_LABELS = {
    "trust_boundary": "DFD and trust boundaries",
    "stride": "STRIDE findings",
    "linddun": "LINDDUN privacy findings",
    "controls": "Control mapping",
    "tests": "Verification scenarios",
    "missing_info": "Evidence gaps",
    "assumptions": "Assumptions",
}
STAGE_PHASES = {
    "trust_boundary": "model",
    "stride": "findings",
    "linddun": "findings",
    "controls": "action-plan",
    "tests": "action-plan",
    "missing_info": "evidence",
    "assumptions": "evidence",
}
TERMINAL_PROGRESS_STATES = {"completed", "warning", "blocked", "skipped"}
VALID_ASSESSMENTS = {"complete", "valid_empty"}
PROBLEM_ASSESSMENTS = {"partial", "invalid", "blocked", "fallback", "timed_out", "failed", "not_run"}


def _text(value: Any, default: str = "") -> str:
    value = default if value is None else value
    return " ".join(str(value).split())


def _unique(values: list[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = _text(value)
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _assessment(status: dict | None) -> str:
    if not isinstance(status, dict):
        return "not_started"
    return _text(status.get("assessment_status") or "not_run").casefold()


def _stage_projection(stage: str, status: dict | None, progress_record: dict | None,
                      run_status: str, stale_stages: set[str]) -> dict:
    status = status if isinstance(status, dict) else {}
    progress_record = progress_record if isinstance(progress_record, dict) else {}
    assessment = _assessment(status)
    progress_state = _text(progress_record.get("state")).casefold()
    state = progress_state or ""
    if stage in stale_stages:
        state = "stale"
    elif not state:
        if run_status == "not_started" and not status:
            state = "not_started"
        elif assessment in {"complete", "valid_empty"} and status.get("ok") is not False:
            state = "completed"
        elif assessment == "blocked":
            state = "blocked"
        elif assessment in PROBLEM_ASSESSMENTS:
            state = "warning"
        elif status.get("ok") is True:
            state = "completed"
        elif run_status == "running":
            state = "queued"
        else:
            state = "not_started"

    baseline = bool(status.get("baseline_used") or status.get("engine") == "fallback")
    preserved = bool(status.get("previous_results_preserved"))
    if baseline:
        display_status = "fallback"
    elif assessment == "partial" or state == "stale":
        display_status = "partial"
    elif assessment in {"invalid", "failed", "timed_out"}:
        display_status = "failed"
    elif assessment == "blocked" or state == "blocked":
        display_status = "blocked"
    elif state == "not_started":
        display_status = "not_started"
    elif state == "queued":
        display_status = "queued"
    elif state == "active":
        display_status = "running"
    else:
        display_status = "completed"

    warnings = status.get("validation_warnings") or status.get("warnings") or []
    if not isinstance(warnings, list):
        warnings = [warnings]
    error = _text(status.get("error"))
    return {
        "id": stage,
        "label": STAGE_LABELS.get(stage, stage.replace("_", " ").title()),
        "phase": STAGE_PHASES.get(stage, stage),
        "state": state,
        "status": display_status,
        "assessment_status": assessment,
        "ok": status.get("ok") is True and assessment in VALID_ASSESSMENTS and not baseline and not preserved,
        "baseline_used": baseline,
        "previous_results_preserved": preserved,
        "retryable": bool(status.get("retryable", False) or display_status in {"fallback", "partial", "failed", "blocked", "stale"}),
        "run_id": status.get("run_id") or progress_record.get("run_id"),
        "started_at": progress_record.get("started_at") or status.get("started_at"),
        "completed_at": progress_record.get("completed_at") or status.get("completed_at"),
        "duration_seconds": status.get("duration_seconds") or progress_record.get("duration_seconds"),
        "error_code": status.get("error_code") or progress_record.get("error_code"),
        "error": error,
        "warnings": _unique(warnings)[:8],
    }


def _stage_issue_detail(record: dict) -> str:
    if record.get("error"):
        return _text(record["error"])
    if record.get("warnings"):
        return _text(record["warnings"][0])
    if record.get("status") == "fallback":
        return "A baseline suggestion is visible for review; it is not a validated current assessment."
    if record.get("status") == "partial":
        return "Some scope remains deferred and must be reviewed or retried."
    if record.get("status") == "blocked":
        return "This stage was blocked by an upstream dependency or missing information."
    if record.get("status") == "stale":
        return "The current DFD or project context changed after this result was produced."
    return "This stage needs review before the result can support sign-off."


def _add_action(actions: list[dict], action_id: str, title: str, detail: str,
                phase: str, priority: str = "normal") -> None:
    if any(item.get("id") == action_id for item in actions):
        return
    actions.append({
        "id": action_id,
        "title": _text(title),
        "detail": _text(detail),
        "phase": phase,
        "priority": priority,
    })


def _build_actions_and_blockers(report: dict, run_status: str, stages: list[dict],
                                stale_stages: set[str], quality_gate: dict,
                                recovery: dict) -> tuple[list[dict], list[dict]]:
    actions: list[dict] = []
    blockers: list[dict] = []

    def blocker(code: str, title: str, detail: str, action_id: str | None = None,
                phase: str = "analysis", severity: str = "warning") -> None:
        if any(item.get("code") == code for item in blockers):
            return
        item = {
            "code": code,
            "title": _text(title),
            "detail": _text(detail),
            "phase": phase,
            "severity": severity,
        }
        blockers.append(item)
        if action_id:
            _add_action(actions, action_id, title, detail, phase, "high" if severity == "error" else "normal")

    if run_status == "not_started":
        _add_action(actions, "run_analysis", "Run the threat model", "Build the DFD, framework assessments, controls, tests, and evidence queue.", "analysis", "high")
    elif run_status == "running":
        _add_action(actions, "monitor_analysis", "Monitor the active analysis", "The server is processing one stage at a time; reload safely to recover the persisted state.", "analysis", "normal")
    elif run_status == "failed":
        blocker("analysis_failed", "Analysis failed", _text((report.get("analysis_run") or {}).get("error"), "No validated replacement was produced."), "retry_analysis", "analysis", "error")

    for record in stages:
        if record["status"] in {"fallback", "partial", "failed", "blocked", "stale"}:
            action_id = f"retry_{record['id']}" if record.get("retryable") else f"review_{record['id']}"
            title = f"{record['label']} needs review"
            if record["status"] == "stale":
                title = f"Refresh {record['label'].lower()}"
            blocker(
                f"stage_{record['id']}_{record['status']}",
                title,
                _stage_issue_detail(record),
                action_id,
                record["phase"],
                "error" if record["status"] in {"failed", "blocked"} else "warning",
            )
    if stale_stages:
        blocker(
            "analysis_stale",
            "Current results are out of date",
            f"The following stages must be refreshed: {', '.join(sorted(stale_stages))}.",
            "retry_analysis",
            "analysis",
            "warning",
        )
    if recovery.get("state") in {"previous_results_preserved", "baseline_used", "analysis_unavailable"}:
        blocker(
            "analysis_recovery",
            "Recovery state requires review",
            _text(recovery.get("message"), "Previous or baseline results are visible but are not equivalent to a validated current run."),
            "retry_analysis",
            "analysis",
            "warning",
        )

    components = quality_gate.get("components") if isinstance(quality_gate, dict) else {}
    if not isinstance(components, dict):
        components = {}
    component_actions = {
        "input_context": ("review_context", "Complete project context", "Resolve missing input context before relying on the assessment.", "evidence"),
        "dfd": ("review_dfd", "Review the canonical DFD", "Resolve DFD questions, isolated zones, and trust-boundary decisions.", "model"),
        "analysis": ("retry_analysis", "Review analysis coverage", "Framework results are not fully validated for the current model.", "findings"),
        "framework_coverage": ("review_findings", "Review deferred framework coverage", "Some STRIDE or LINDDUN interaction/category checks remain unresolved.", "findings"),
        "deferred_decisions": ("review_evidence", "Resolve deferred decisions", "Assign an owner, answer, accept the assumption, or explicitly defer each decision.", "evidence"),
        "threat_review": ("review_findings", "Triage threat findings", "Active findings still need a reviewer disposition.", "findings"),
        "control_disposition": ("review_controls", "Review control applicability", "Map each applicable finding or record an explicit applicability decision.", "action-plan"),
        "verification_plan": ("review_tests", "Review verification scenarios", "Ensure each applicable threat has an executable test or justified disposition.", "action-plan"),
    }
    for name, component in components.items():
        if not isinstance(component, dict) or component.get("status") == "ready":
            continue
        action_id, title, detail, phase = component_actions.get(
            name, (f"review_{name}", f"Review {name.replace('_', ' ')}", "This quality gate is not ready.", "analysis")
        )
        reasons = component.get("reasons") or []
        blocker(f"gate_{name}", title, reasons[0] if reasons else detail, action_id, phase, "warning")

    if quality_gate.get("signoff_ready") is True and run_status == "completed":
        _add_action(actions, "open_report", "Review and sign the report", "All automated readiness components are ready; confirm provenance and approval history.", "signoff", "normal")
    elif run_status not in {"not_started", "running"} and not actions:
        _add_action(actions, "review_report", "Review report provenance", "Confirm the DFD revision, source coverage, methodology, and approval history.", "signoff", "normal")

    return actions, blockers


def build_analysis_state(report: dict | None = None, project: dict | None = None,
                         progress: dict | None = None) -> dict:
    """Build the canonical public run/readiness state without mutating input."""
    report = report if isinstance(report, dict) else {}
    project = project if isinstance(project, dict) else {}
    progress = progress if isinstance(progress, dict) else {}
    run = report.get("analysis_run") if isinstance(report.get("analysis_run"), dict) else {}
    progress_run_id = _text(progress.get("run_id"))
    run_id = _text(run.get("run_id") or progress_run_id) or None
    raw_status = _text(progress.get("status") or run.get("status") or report.get("analysis_status")).casefold()
    if not raw_status:
        raw_status = "not_started"
    if raw_status in {"complete", "success"}:
        raw_status = "completed"
    if raw_status == "completed_with_warnings":
        normalized_run_status = "completed_with_warnings"
    elif raw_status in {"running", "failed", "completed"}:
        normalized_run_status = raw_status
    elif raw_status in {"queued", "pending"}:
        normalized_run_status = "running"
    elif not run_id and not progress_run_id:
        normalized_run_status = "not_started"
    else:
        normalized_run_status = raw_status or "not_started"

    requested = progress.get("requested_types") or run.get("requested_types") or []
    if not isinstance(requested, list):
        requested = []
    requested = [stage for stage in requested if stage in STAGE_ORDER]
    if not requested and run_id:
        requested = list(STAGE_ORDER)
    stale_values = report.get("analysis_stale") if isinstance(report.get("analysis_stale"), dict) else {}
    stale_stages = {stage for stage in (stale_values.get("stages") or []) if stage in STAGE_ORDER}
    ai_status = report.get("ai_status") if isinstance(report.get("ai_status"), dict) else {}
    progress_stages = progress.get("stages") if isinstance(progress.get("stages"), dict) else {}
    stages = []
    for stage in STAGE_ORDER:
        if stage not in requested and stage not in ai_status and stage not in progress_stages:
            continue
        stages.append(_stage_projection(stage, ai_status.get(stage), progress_stages.get(stage), normalized_run_status, stale_stages))

    quality_gate = report.get("quality_gate") if isinstance(report.get("quality_gate"), dict) else run.get("quality_gate")
    quality_gate = deepcopy(quality_gate) if isinstance(quality_gate, dict) else {}
    recovery = report.get("analysis_recovery") if isinstance(report.get("analysis_recovery"), dict) else {}
    recovery = deepcopy(recovery)
    if not quality_gate and normalized_run_status == "not_started":
        quality_gate = {
            "schema_version": "signoff-gate-v1",
            "status": "not_ready",
            "signoff_ready": False,
            "review_required": True,
            "summary": "Run analysis before sign-off can be evaluated.",
            "blocking_reasons": ["Analysis has not started"],
            "components": {},
        }

    result_state = "completed"
    stage_statuses = {item["status"] for item in stages}
    if normalized_run_status == "not_started":
        result_state = "not_started"
    elif normalized_run_status == "running":
        result_state = "running"
    elif normalized_run_status == "failed":
        result_state = "failed"
    elif "fallback" in stage_statuses or recovery.get("state") == "baseline_used":
        result_state = "fallback"
    elif "partial" in stage_statuses or normalized_run_status == "completed_with_warnings" or recovery.get("state"):
        result_state = "partial"
    elif quality_gate.get("signoff_ready") is False:
        result_state = "needs_review"

    status_label = {
        "not_started": "Not started",
        "running": "Running",
        "failed": "Failed",
        "fallback": "Fallback",
        "partial": "Partial",
        "needs_review": "Needs review",
        "completed": "Completed",
    }[result_state]
    actions, blockers = _build_actions_and_blockers(
        report, normalized_run_status, stages, stale_stages, quality_gate, recovery,
    )
    current_stages = [item["id"] for item in stages if item["ok"] and item["id"] not in stale_stages]
    baseline_stages = [item["id"] for item in stages if item["baseline_used"]]
    preserved_stages = [item["id"] for item in stages if item["previous_results_preserved"]]
    return {
        "schema_version": ANALYSIS_STATE_SCHEMA_VERSION,
        "status": normalized_run_status,
        "result_state": result_state,
        "status_label": status_label,
        "run_id": run_id,
        "requested_types": requested,
        "stage_order": [stage for stage in STAGE_ORDER if stage in requested or any(item["id"] == stage for item in stages)],
        "active_stage": progress.get("active_stage") if normalized_run_status == "running" else None,
        "stages": stages,
        "completed_stages": current_stages,
        "warning_stages": [item["id"] for item in stages if item["status"] in {"fallback", "partial", "failed", "blocked", "stale"}],
        "baseline_stages": baseline_stages,
        "preserved_stages": preserved_stages,
        "stale_stages": sorted(stale_stages),
        "trusted_result_scope": {
            "current_stages": current_stages,
            "historical_finding_count": sum(1 for item in report.get("threats") or [] if isinstance(item, dict) and item.get("analysis_state") == "historical"),
            "current_finding_count": sum(1 for item in report.get("threats") or [] if isinstance(item, dict) and item.get("analysis_state") != "historical"),
            "baseline_stages": baseline_stages,
            "preserved_stages": preserved_stages,
        },
        "quality_gate": quality_gate,
        "recovery": recovery,
        "blockers": blockers,
        "next_actions": actions[:8],
        "signoff_ready": quality_gate.get("signoff_ready") is True,
        "review_required": quality_gate.get("signoff_ready") is not True,
        "updated_at": progress.get("updated_at") or run.get("completed_at") or run.get("started_at"),
    }


def attach_analysis_state(report: dict | None, project: dict | None = None,
                          progress: dict | None = None) -> dict:
    """Return a copied report with the canonical state attached."""
    result = deepcopy(report) if isinstance(report, dict) else {}
    result["analysis_state"] = build_analysis_state(result, project, progress)
    return result
