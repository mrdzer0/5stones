"""Export router — export reports to Markdown, CSV, JSON."""
from __future__ import annotations
import copy
import csv
import io
import json
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse, StreamingResponse
from backend.utils.storage import get_dfd_model, get_report, get_analysis_progress
from backend.utils.storage import get_report_revision
from backend.utils.audit import log_event
from backend.services.dfd_model_service import (
    load_dfd_model,
    recalculate_boundary_crossings,
    validate_dfd_model,
)
from backend.services.posture_service import (
    compute_completeness,
    compute_signoff_readiness,
    normalize_report_evidence,
    summarize_threat_findings,
)
from backend.services.formal_report_service import build_formal_report_metadata
from backend.services.release_decision_service import build_release_decision
from backend.services.run_state_service import attach_analysis_state
from backend.utils.access_control import get_authorized_project, require_roles, workspace_access_dependency

router = APIRouter(
    prefix="/api/projects",
    tags=["export"],
    dependencies=[workspace_access_dependency, require_roles("analyst", "reviewer", "admin")],
)


def _apply_visibility_filter(report: dict) -> dict:
    """Mirror the analysisVisibility() JS logic for consistent export projection.

    Threats without any boundary dependency are always visible.
    Threats with explicit boundary links are hidden only if all linked boundaries
    are Rejected (i.e. allRejected=True). This prevents same-zone findings from
    being silently omitted from exports when boundaries are rejected.
    """
    boundaries = [
        b for b in (report.get("trust_boundaries") or [])
        if b and b.get("boundary_id")
    ]
    active_ids: set[str] = {
        str(b["boundary_id"])
        for b in boundaries
        if b.get("status") != "Rejected"
    }
    boundary_ids = {str(b["boundary_id"]) for b in boundaries}
    def threat_visible(threat: dict) -> bool:
        if not boundaries:
            return True
        linked = [str(bid) for bid in (threat.get("trust_boundary_ids") or []) if bid]
        # No boundary dependency → always visible (same-zone finding)
        if not linked:
            return True
        if not any(bid in boundary_ids for bid in linked):
            return True
        return any(bid in active_ids for bid in linked)

    visible_threats = [t for t in (report.get("threats") or []) if threat_visible(t)]
    visible_threat_ids: set[str] = {
        str(t["threat_id"]) for t in visible_threats if t.get("threat_id")
    }

    def linked_item_visible(ids) -> bool:
        links = [str(i) for i in (ids or []) if i]
        return not links or any(lid in visible_threat_ids for lid in links)

    visible_controls = [
        c for c in (report.get("controls") or [])
        if linked_item_visible(c.get("threat_ids"))
    ]
    visible_tests = [
        s for s in (report.get("test_scenarios") or [])
        if linked_item_visible([s.get("threat_id")])
    ]
    visible_assumptions = [
        a for a in (report.get("assumptions") or [])
        if linked_item_visible([a.get("related_threat_id")])
    ]
    visible_missing_info = [
        item for item in (report.get("missing_info") or [])
        if linked_item_visible([item.get("related_threat_id")])
    ]

    summary = summarize_threat_findings(visible_threats, report.get("risk_summary"))

    return {
        **report,
        "threats": visible_threats,
        "controls": visible_controls,
        "test_scenarios": visible_tests,
        "assumptions": visible_assumptions,
        "missing_info": visible_missing_info,
        "risk_summary": summary,
        "visibility": {
            "projection": "boundary_review",
            "hidden": {
                "threats": len(report.get("threats") or []) - len(visible_threats),
                "controls": len(report.get("controls") or []) - len(visible_controls),
                "tests": len(report.get("test_scenarios") or []) - len(visible_tests),
                "assumptions": len(report.get("assumptions") or []) - len(visible_assumptions),
                "missing_info": len(report.get("missing_info") or []) - len(visible_missing_info),
            },
        },
    }


@router.get("/{project_id}/export", dependencies=[require_roles("analyst", "reviewer", "admin")])
async def export_report(project_id: str, format: str = "json", scope: str = "visible", revision_id: str | None = None, request: Request = None):
    project = get_authorized_project(project_id, request)
    snapshot = get_report_revision(project_id, revision_id) if revision_id else None
    if revision_id and not snapshot:
        raise HTTPException(status_code=404, detail="Report revision not found")
    current_report = get_report(project_id)
    report_exists = isinstance(current_report, dict) and bool(current_report)
    report = copy.deepcopy(snapshot.get("report") if snapshot else current_report)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not report:
        # Keep export machine-readable for a new project. Markdown/CSV still
        # carry an explicit not_started record rather than implying a clean
        # or empty threat assessment.
        report = {
            "project_id": project_id,
            "project_name": project.get("name", ""),
            "generated_at": None,
            "threats": [], "controls": [], "test_scenarios": [],
            "trust_boundaries": [], "missing_info": [], "assumptions": [],
            "risk_summary": {}, "analysis_status": "not_started",
            "analysis_run": {"status": "not_started", "requested_types": []},
        }
    if snapshot:
        # A revision export must use the immutable metadata captured with that
        # snapshot. Rebuilding formal metadata here could silently point the
        # appendix at the current DFD or source manifest.
        report["formal_report"] = copy.deepcopy(snapshot.get("formal_report") or report.get("formal_report") or {})
        report["report_revision"] = report["formal_report"].get("revision", report.get("report_revision"))
    report = normalize_report_evidence(report, project)
    if not report.get("completeness"):
        report["completeness"] = compute_completeness(project)
    canonical_dfd = get_dfd_model(project_id)
    dfd_payload = report.get("dfd_model") or canonical_dfd
    if isinstance(dfd_payload, dict):
        try:
            dfd_model, _migrated = load_dfd_model(dfd_payload, project_id=project_id)
            recalculate_boundary_crossings(dfd_model)
            report["dfd_model"] = dfd_model.model_dump()
            report["dfd_validation"] = validate_dfd_model(dfd_model)
        except (TypeError, ValueError):
            # Export remains available, but the unified gate will explicitly
            # block sign-off using the last readable validation state.
            pass
    report = normalize_report_evidence(report, project)
    report["quality_gate"] = compute_signoff_readiness(report)
    if not snapshot:
        report["formal_report"] = build_formal_report_metadata(project, report)
    formal = report.get("formal_report") if isinstance(report.get("formal_report"), dict) else {}
    formal_revision = formal.get("revision")
    signed_snapshot = None
    if snapshot and snapshot.get("status") == "signed":
        signed_snapshot = snapshot
    elif formal_revision is not None:
        signed_snapshot = get_report_revision(project_id, f"report-r{formal_revision}-signed")
    report["release_decision"] = build_release_decision(
        project,
        report,
        canonical_dfd if isinstance(canonical_dfd, dict) else (dfd_payload if isinstance(dfd_payload, dict) else {}),
        signed_snapshot,
        report["quality_gate"],
        signed_metadata=formal,
        report_exists=report_exists,
    )
    # Preserve the formal status as historical workflow metadata and expose the
    # current enterprise release verdict as a separate projection.
    report["formal_report"] = {
        **formal,
        "release_decision_status": report["release_decision"]["status"],
        "signed_snapshot_sha256": report["release_decision"].get("signed_snapshot_sha256"),
    }
    progress = None if snapshot else get_analysis_progress(project_id)
    report = attach_analysis_state(
        report,
        project,
        progress if isinstance(progress, dict) and progress.get("run_id") == (report.get("analysis_run") or {}).get("run_id") else None,
    )

    log_event("report.exported", details={"project_id": project_id, "format": format, "revision_id": revision_id})

    if scope not in {"visible", "all"}:
        raise HTTPException(status_code=400, detail="Unsupported scope. Use: visible, all")
    projected = _apply_visibility_filter(report) if scope == "visible" else report

    if format == "json":
        return projected

    if format == "markdown":
        md = _to_markdown(project, projected)
        return PlainTextResponse(content=md, media_type="text/markdown",
                                  headers={"Content-Disposition": f"attachment; filename=threat-model-{project_id}.md"})

    if format == "csv":
        csv_content = _to_csv(projected)
        return StreamingResponse(
            io.StringIO(csv_content),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=threats-{project_id}.csv"}
        )

    raise HTTPException(status_code=400, detail="Unsupported format. Use: json, markdown, csv")


def _to_markdown(project: dict, report: dict) -> str:
    name = project.get("name", "Threat Model")
    lines = [
        f"# Threat Model Report — {name}",
        f"",
        f"> Generated: {report.get('generated_at', 'N/A')}  ",
        f"> ⚠️ This report contains security-sensitive information. Handle with care.",
        f"",
        f"## Summary",
        f"",
    ]

    rs = report.get("risk_summary", {})
    completeness = report.get("completeness", {})
    quality_gate = report.get("quality_gate", {})
    analysis_state = report.get("analysis_state") if isinstance(report.get("analysis_state"), dict) else {}
    formal = report.get("formal_report") if isinstance(report.get("formal_report"), dict) else {}
    gate_reasons = quality_gate.get("blocking_reasons") or []
    lines += [
        f"**Analysis status:** {analysis_state.get('status_label') or analysis_state.get('result_state') or report.get('analysis_status', 'Not started')} — run `{analysis_state.get('run_id') or formal.get('analysis_run_id') or 'none'}`",
        f"**Input Context Completeness:** {completeness.get('score', 0)}/100 — {completeness.get('level', 'N/A')}",
        f"**Sign-off Readiness:** {'Ready' if quality_gate.get('signoff_ready') else 'Not ready'} — {quality_gate.get('summary', 'Quality gate not evaluated')}",
        f"**Formal Report Status:** {formal.get('status', 'draft')}",
        f"**Enterprise Release Decision:** {str((report.get('release_decision') or {}).get('status', 'not_ready')).upper()}",
        f"**Risk Methodology:** {rs.get('risk_methodology_version', 'not evaluated')} — deterministic 5×5 inherent-risk matrix; provider severity is advisory only",
        f"**Risk disposition:** {(report.get('formal_report') or {}).get('risk_disposition', {}).get('scored', rs.get('scored_total', 0))} scored scenario(s); {(report.get('formal_report') or {}).get('risk_disposition', {}).get('deferred', rs.get('needs_context_total', 0))} deferred / needs context; total {rs.get('total', 0)}. A deferred scenario is not evidence that no risk exists.",
        f"**DFD revision:** {formal.get('dfd_revision', 'unknown')} · semantic hash: {formal.get('dfd_semantic_hash', 'unknown')}",
        f"**Analysis run:** {formal.get('analysis_run_id', 'unknown')}",
        f"**Fallback active:** {'yes' if (formal.get('provenance') or {}).get('fallback_used') else 'no'} · **Preserved result:** {'yes' if (formal.get('provenance') or {}).get('preserved_result_used') else 'no'}",
        f"",
        f"| Risk Level | Count |",
        f"|------------|-------|",
        f"| 🔴 Critical | {rs.get('critical', 0)} |",
        f"| 🟠 High | {rs.get('high', 0)} |",
        f"| 🟡 Medium | {rs.get('medium', 0)} |",
        f"| 🟢 Low | {rs.get('low', 0)} |",
        f"| Scored scenarios | {rs.get('scored_total', 0)} |",
        f"| Risk deferred / needs context | {rs.get('needs_context_total', 0)} |",
        f"| Total | {rs.get('total', 0)} |",
        f"",
        f"## Trust Boundaries",
        f"",
    ]
    if rs.get("scored_total", 0) == 0 and (report.get('formal_report') or {}).get('risk_disposition', {}).get('deferred', rs.get('needs_context_total', 0)):
        lines += ["⚠️ **No scenarios received a final scored risk. This is a deferred assessment, not a clean bill of health.**", ""]
    manifest = (report.get("formal_report") or {}).get("source_manifest") or []
    if manifest:
        lines += ["## Source Manifest", "", "| File | Type | Revision | Hash | Coverage |", "|---|---|---:|---|---|"]
        for source in manifest:
            lines.append(
                f"| {source.get('filename') or 'Unknown'} | {source.get('artifact_type') or 'Unknown'} | "
                f"{source.get('revision') or '—'} | {str(source.get('content_hash') or '—')[:16]} | "
                f"{source.get('coverage_status') or 'unknown'} |")
        lines.append("")
    if gate_reasons:
        lines += ["### Sign-off blockers", "", *[f"- {reason}" for reason in gate_reasons], ""]
    release_blockers = (report.get("release_decision") or {}).get("blockers") or []
    if release_blockers:
        lines += ["### Enterprise release blockers", "", *[
            f"- `{item.get('code', 'unknown')}`: {item.get('message', '')}"
            for item in release_blockers
        ], ""]
    coverage = formal.get("coverage", {}).get("denominator", {}) if isinstance(formal.get("coverage"), dict) else {}
    if coverage:
        lines += ["## Framework Coverage", "", "| Framework | Assessed | Deferred | Failed | Unprocessed | Complete |", "|---|---:|---:|---:|---:|---|"]
        for framework, item in coverage.items():
            lines.append(
                f"| {framework} | {item.get('assessed', 0)} | {item.get('deferred', 0)} | "
                f"{item.get('failed', 0)} | {item.get('unprocessed', 0)} | "
                f"{'yes' if item.get('complete') else 'no'} |"
            )
        lines.append("")
    provider = (formal.get("provenance") or {}).get("provider") or {}
    lines += [
        "## Run Provenance", "",
        f"- Provider: {provider.get('provider_name') or provider.get('source') or 'Unknown'}",
        f"- Model: {provider.get('model') or ', '.join(provider.get('observed_models') or []) or 'Unknown'}",
        f"- Endpoint: {provider.get('base_url') or 'Not recorded'}",
        f"- Approval history entries: {len(formal.get('approval_history') or [])}", "",
    ]

    for b in report.get("trust_boundaries", []):
        lines.append(
            f"- **[{b.get('status', 'Candidate')}] {b.get('source')}** → **{b.get('destination')}**: "
            f"{b.get('boundary_label')} ({b.get('source_trust_level')} → {b.get('destination_trust_level')})"
        )
        if b.get("review_note"):
            lines.append(f"  - Review note: {b.get('review_note')}")
        if b.get("basis"):
            lines.append(f"  - Basis: {b.get('basis')}")

    lines += [f"", f"## STRIDE Threat Scenarios", f""]
    stride = [t for t in report.get("threats", []) if t.get("framework") == "STRIDE"]
    for t in stride:
        lines += [
            f"### [{t.get('risk_level')}] {t.get('threat_category')} — {t.get('threat_description', '')[:80]}",
            f"- **Asset**: {t.get('asset', 'N/A')}",
            f"- **Abuse Case**: {t.get('abuse_case', 'N/A')}",
            f"- **Control**: {t.get('recommended_control', 'N/A')}",
            f"- **Confidence**: {t.get('confidence')} | **Status**: {t.get('status')}",
            f"- **Finding State**: {t.get('finding_state', 'hypothesis')} | **Vulnerability Status**: {t.get('vulnerability_status', 'not_verified')}",
            f"- **Primary DFD Interaction**: {t.get('primary_interaction_ref') or 'Not mapped'} ({t.get('interaction_mapping_status', 'missing')})",
            f"- **DFD Context Refs**: {', '.join(t.get('dfd_context_refs') or []) or 'None'}",
            f"- **Risk Status**: {t.get('risk_status', 'scenario_only')} | **Scenario Impact**: {t.get('scenario_risk_level') or t.get('risk_level', 'Unknown')}",
            f"- **Risk Calculation**: impact {(t.get('risk_calculation') or {}).get('impact', {}).get('score', 'N/A')}/5 × likelihood {(t.get('risk_calculation') or {}).get('likelihood', {}).get('score', 'N/A')}/5 = {t.get('risk_score', 'N/A')}/25 · {t.get('risk_methodology_version', 'legacy/unversioned')}",
            f"- **Risk Rationale**: {t.get('risk_rationale', 'N/A')}",
            f"- **Provider Estimate**: {t.get('provider_risk_level') or 'Not supplied'} (advisory only)",
            f"- **Risk Override**: {t.get('risk_override_level') or 'None'}{(' — ' + str(t.get('risk_override_reason'))) if t.get('risk_override_reason') else ''}",
            f"- **Risk Input Fingerprint**: {t.get('risk_assessment_fingerprint', 'N/A')}",
            f"- **Grounding**: {t.get('grounding_reason', 'Requires review')}",
            f"- **Evidence Type**: {t.get('evidence_type', 'inference').title()}",
            f"- **Evidence**: {t.get('evidence_source', 'N/A')} · {t.get('evidence_locator', 'N/A')} — {t.get('evidence_snippet', 'N/A')}",
            f"- **Scenario Evidence Refs**: {', '.join(t.get('scenario_evidence_refs') or []) or 'None cited'}",
            f"- **Context-only Evidence Refs**: {', '.join(t.get('context_evidence_refs') or []) or 'None'}",
            f"- **Confidence Reason**: {t.get('confidence_reason', 'N/A')}",
            f"- **Assumption**: {t.get('assumption', 'N/A')}",
            f"",
        ]

    lines += [f"## LINDDUN Privacy Threat Scenarios", f""]
    linddun = [t for t in report.get("threats", []) if t.get("framework") == "LINDDUN"]
    for t in linddun:
        lines += [
            f"### [{t.get('risk_level')}] {t.get('threat_category')} — {t.get('threat_description', '')[:80]}",
            f"- **Asset**: {t.get('asset', 'N/A')}",
            f"- **Control**: {t.get('recommended_control', 'N/A')}",
            f"- **Confidence**: {t.get('confidence')} | **Status**: {t.get('status')}",
            f"- **Finding State**: {t.get('finding_state', 'hypothesis')} | **Vulnerability Status**: {t.get('vulnerability_status', 'not_verified')}",
            f"- **Primary DFD Interaction**: {t.get('primary_interaction_ref') or 'Not mapped'} ({t.get('interaction_mapping_status', 'missing')})",
            f"- **DFD Context Refs**: {', '.join(t.get('dfd_context_refs') or []) or 'None'}",
            f"- **Risk Status**: {t.get('risk_status', 'scenario_only')} | **Scenario Impact**: {t.get('scenario_risk_level') or t.get('risk_level', 'Unknown')}",
            f"- **Risk Calculation**: impact {(t.get('risk_calculation') or {}).get('impact', {}).get('score', 'N/A')}/5 × likelihood {(t.get('risk_calculation') or {}).get('likelihood', {}).get('score', 'N/A')}/5 = {t.get('risk_score', 'N/A')}/25 · {t.get('risk_methodology_version', 'legacy/unversioned')}",
            f"- **Risk Rationale**: {t.get('risk_rationale', 'N/A')}",
            f"- **Provider Estimate**: {t.get('provider_risk_level') or 'Not supplied'} (advisory only)",
            f"- **Risk Override**: {t.get('risk_override_level') or 'None'}{(' — ' + str(t.get('risk_override_reason'))) if t.get('risk_override_reason') else ''}",
            f"- **Risk Input Fingerprint**: {t.get('risk_assessment_fingerprint', 'N/A')}",
            f"- **Grounding**: {t.get('grounding_reason', 'Requires review')}",
            f"- **Evidence Type**: {t.get('evidence_type', 'inference').title()}",
            f"- **Evidence**: {t.get('evidence_source', 'N/A')} · {t.get('evidence_locator', 'N/A')} — {t.get('evidence_snippet', 'N/A')}",
            f"- **Scenario Evidence Refs**: {', '.join(t.get('scenario_evidence_refs') or []) or 'None cited'}",
            f"- **Context-only Evidence Refs**: {', '.join(t.get('context_evidence_refs') or []) or 'None'}",
            f"",
        ]

    lines += [f"## Control Checklist", f"", f"| Control | Status | Owner |", f"|---------|--------|-------|"]
    for c in report.get("controls", []):
        lines.append(f"| {c.get('name')} | {c.get('review_status', c.get('status'))} | {c.get('owner', 'N/A')} |")
        for item in c.get("checklist_items", []):
            lines.append(f"| ↳ {item} | {c.get('review_status', 'Open')} | {c.get('owner', 'N/A')} |")

    lines += [f"", f"## Security Test Backlog", f"", f"| Test ID | Scenario | Priority | Owner | Applicability |", f"|---------|----------|----------|-------|--------------|"]
    for s in report.get("test_scenarios", []):
        lines.append(f"| {s.get('test_id', 'N/A')} | {s.get('scenario_name', '')[:60]} | {s.get('priority')} | {s.get('owner', 'N/A')} | {s.get('applicability_status', 'applicable')} |")

    lines += [f"", f"## Missing Information", f"", f"| Priority | Team | Area | Question | Why It Matters |", f"|----------|------|------|----------|----------------|"]
    for m in report.get("missing_info", []):
        lines.append(f"| {m.get('priority', 'Medium')} | {m.get('target_team', 'Dev/Tech Lead')} | {m.get('area')} | {m.get('question_to_ask') or m.get('question', '')} | {m.get('why_it_matters', '')} |")

    lines += [f"", f"## Assumption Register", f"", f"| Area | Assumption | Evidence | Impact If Wrong | Verification Question | Confidence |", f"|------|------------|----------|-----------------|-----------------------|------------|"]
    for a in report.get("assumptions", []):
        lines.append(f"| {a.get('area')} | {a.get('assumption', '')} | {a.get('evidence', '')} | {a.get('impact_if_wrong', '')} | {a.get('verification_question', '')} | {a.get('confidence')} |")

    return "\n".join(lines)


def _to_csv(report: dict) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    state = report.get("analysis_state") if isinstance(report.get("analysis_state"), dict) else {}
    formal = report.get("formal_report") if isinstance(report.get("formal_report"), dict) else {}
    provenance = formal.get("provenance") if isinstance(formal.get("provenance"), dict) else {}
    provider = provenance.get("provider") if isinstance(provenance.get("provider"), dict) else {}
    coverage = formal.get("coverage", {}).get("denominator", {}) if isinstance(formal.get("coverage"), dict) else {}
    metadata = [
        state.get("status_label") or state.get("result_state") or report.get("analysis_status", "Not started"),
        state.get("run_id") or formal.get("analysis_run_id") or "",
        formal.get("dfd_revision", ""),
        formal.get("dfd_semantic_hash", ""),
        "Ready" if (report.get("quality_gate") or {}).get("signoff_ready") else "Not ready",
        formal.get("status", "draft"),
        (report.get("release_decision") or {}).get("status", "not_ready"),
        "; ".join(item.get("code", "unknown") for item in ((report.get("release_decision") or {}).get("blockers") or [])),
        "yes" if provenance.get("fallback_used") else "no",
        json.dumps(coverage, ensure_ascii=False, sort_keys=True),
        "; ".join((report.get("quality_gate") or {}).get("blocking_reasons") or []),
        provider.get("provider_name") or provider.get("source") or "",
        provider.get("model") or "; ".join(provider.get("observed_models") or []),
        "; ".join((formal.get("methodology") or {}).get("risk_methodology_versions") or []),
        str(len(formal.get("approval_history") or [])),
    ]

    # Header
    writer.writerow([
        "Analysis Status", "Analysis Run ID", "DFD Revision", "DFD Semantic Hash",
        "Sign-off Status", "Formal Report Status", "Enterprise Release Decision", "Release Blocker Codes",
        "Fallback Active", "Coverage Denominator", "Unresolved Blockers",
        "Provider", "Model", "Risk Methodology", "Approval History Entries",
        "Framework", "Threat Category", "Component", "Source", "Destination",
        "Trust Boundary", "Asset", "Data Classification", "Threat Description",
        "Abuse Case", "Recommended Control", "Confidence", "Risk Level",
        "Finding State", "Vulnerability Status", "Risk Status", "Scenario Risk Level",
        "Provider Risk Estimate", "Risk Methodology", "Risk Score", "Impact Score", "Likelihood Score",
        "Risk Source", "Risk Rationale", "Risk Input Fingerprint", "Risk Override Level", "Risk Override Reason",
        "Primary DFD Interaction", "Interaction Mapping Status", "DFD Context Refs",
        "Status", "Assumption", "Missing Info", "Owner", "Evidence Type", "Evidence Source",
        "Evidence Locator", "Evidence Snippet", "Scenario Evidence Refs", "Context Evidence Refs",
        "Confidence Reason", "Needs Human Review", "Fingerprint"
    ])

    for t in report.get("threats", []):
        writer.writerow([
            *metadata,
            t.get("framework", ""),
            t.get("threat_category", ""),
            t.get("component", ""),
            t.get("source", ""),
            t.get("destination", ""),
            t.get("trust_boundary", ""),
            t.get("asset", ""),
            t.get("data_classification", ""),
            t.get("threat_description", ""),
            t.get("abuse_case", ""),
            t.get("recommended_control", ""),
            t.get("confidence", ""),
            t.get("risk_level", ""),
            t.get("finding_state", "hypothesis"),
            t.get("vulnerability_status", "not_verified"),
            t.get("risk_status", "scenario_only"),
            t.get("scenario_risk_level", ""),
            t.get("provider_risk_level", ""),
            t.get("risk_methodology_version", ""),
            t.get("risk_score", ""),
            (t.get("risk_calculation") or {}).get("impact", {}).get("score", ""),
            (t.get("risk_calculation") or {}).get("likelihood", {}).get("score", ""),
            t.get("risk_source", ""),
            t.get("risk_rationale", ""),
            t.get("risk_assessment_fingerprint", ""),
            t.get("risk_override_level", ""),
            t.get("risk_override_reason", ""),
            t.get("primary_interaction_ref", ""),
            t.get("interaction_mapping_status", "missing"),
            "; ".join(t.get("dfd_context_refs") or []),
            t.get("status", ""),
            t.get("assumption", ""),
            t.get("missing_info", ""),
            t.get("owner", ""),
            t.get("evidence_type", ""),
            t.get("evidence_source", ""),
            t.get("evidence_locator", ""),
            t.get("evidence_snippet", ""),
            "; ".join(t.get("scenario_evidence_refs") or []),
            "; ".join(t.get("context_evidence_refs") or []),
            t.get("confidence_reason", ""),
            t.get("needs_human_review", ""),
            t.get("fingerprint", ""),
        ])

    if not (report.get("threats") or []):
        writer.writerow([*metadata] + [""] * 43)

    return output.getvalue()
