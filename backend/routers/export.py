"""Export router — export reports to Markdown, CSV, JSON."""
from __future__ import annotations
import csv
import io
import json
from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse, StreamingResponse
from backend.utils.storage import get_project, get_report
from backend.utils.audit import log_event

router = APIRouter(prefix="/api/projects", tags=["export"])


@router.get("/{project_id}/export")
async def export_report(project_id: str, format: str = "json"):
    project = get_project(project_id)
    report = get_report(project_id)
    if not project or not report:
        raise HTTPException(status_code=404, detail="Project or report not found")

    log_event("report.exported", details={"project_id": project_id, "format": format})

    if format == "json":
        return report

    if format == "markdown":
        md = _to_markdown(project, report)
        return PlainTextResponse(content=md, media_type="text/markdown",
                                  headers={"Content-Disposition": f"attachment; filename=threat-model-{project_id}.md"})

    if format == "csv":
        csv_content = _to_csv(report)
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
    lines += [
        f"**Threat Model Readiness:** {completeness.get('score', 0)}/100 — {completeness.get('level', 'N/A')}",
        f"",
        f"| Risk Level | Count |",
        f"|------------|-------|",
        f"| 🔴 Critical | {rs.get('critical', 0)} |",
        f"| 🟠 High | {rs.get('high', 0)} |",
        f"| 🟡 Medium | {rs.get('medium', 0)} |",
        f"| 🟢 Low | {rs.get('low', 0)} |",
        f"| Total | {rs.get('total', 0)} |",
        f"",
        f"## Trust Boundaries",
        f"",
    ]

    for b in report.get("trust_boundaries", []):
        lines.append(f"- **{b.get('source')}** → **{b.get('destination')}**: {b.get('boundary_label')} ({b.get('source_trust_level')} → {b.get('destination_trust_level')})")

    lines += [f"", f"## STRIDE Threats", f""]
    stride = [t for t in report.get("threats", []) if t.get("framework") == "STRIDE"]
    for t in stride:
        lines += [
            f"### [{t.get('risk_level')}] {t.get('threat_category')} — {t.get('threat_description', '')[:80]}",
            f"- **Asset**: {t.get('asset', 'N/A')}",
            f"- **Abuse Case**: {t.get('abuse_case', 'N/A')}",
            f"- **Control**: {t.get('recommended_control', 'N/A')}",
            f"- **Confidence**: {t.get('confidence')} | **Status**: {t.get('status')}",
            f"- **Evidence**: {t.get('evidence_source', 'N/A')} — {t.get('evidence_snippet', 'N/A')}",
            f"- **Confidence Reason**: {t.get('confidence_reason', 'N/A')}",
            f"- **Assumption**: {t.get('assumption', 'N/A')}",
            f"",
        ]

    lines += [f"## LINDDUN Privacy Threats", f""]
    linddun = [t for t in report.get("threats", []) if t.get("framework") == "LINDDUN"]
    for t in linddun:
        lines += [
            f"### [{t.get('risk_level')}] {t.get('threat_category')} — {t.get('threat_description', '')[:80]}",
            f"- **Asset**: {t.get('asset', 'N/A')}",
            f"- **Control**: {t.get('recommended_control', 'N/A')}",
            f"- **Confidence**: {t.get('confidence')}",
            f"- **Evidence**: {t.get('evidence_source', 'N/A')} — {t.get('evidence_snippet', 'N/A')}",
            f"",
        ]

    lines += [f"## Control Checklist", f"", f"| Control | Status | Owner |", f"|---------|--------|-------|"]
    for c in report.get("controls", []):
        lines.append(f"| {c.get('name')} | {c.get('review_status', c.get('status'))} | {c.get('owner', 'N/A')} |")
        for item in c.get("checklist_items", []):
            lines.append(f"| ↳ {item} | {c.get('review_status', 'Open')} | {c.get('owner', 'N/A')} |")

    lines += [f"", f"## Security Test Backlog", f"", f"| Test ID | Scenario | Priority | Owner |", f"|---------|----------|----------|-------|"]
    for s in report.get("test_scenarios", []):
        lines.append(f"| {s.get('test_id', 'N/A')} | {s.get('scenario_name', '')[:60]} | {s.get('priority')} | {s.get('owner', 'N/A')} |")

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

    # Header
    writer.writerow([
        "Framework", "Threat Category", "Component", "Source", "Destination",
        "Trust Boundary", "Asset", "Data Classification", "Threat Description",
        "Abuse Case", "Recommended Control", "Confidence", "Risk Level",
        "Status", "Assumption", "Missing Info", "Owner", "Evidence Source",
        "Evidence Snippet", "Confidence Reason", "Needs Human Review", "Fingerprint"
    ])

    for t in report.get("threats", []):
        writer.writerow([
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
            t.get("status", ""),
            t.get("assumption", ""),
            t.get("missing_info", ""),
            t.get("owner", ""),
            t.get("evidence_source", ""),
            t.get("evidence_snippet", ""),
            t.get("confidence_reason", ""),
            t.get("needs_human_review", ""),
            t.get("fingerprint", ""),
        ])

    return output.getvalue()
