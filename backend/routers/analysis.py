"""Analysis router — runs threat modeling pipeline."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from backend.utils.storage import get_project, save_project, save_report, get_report
from backend.utils.audit import log_event
from backend.services.trust_boundary_service import detect_trust_boundaries
from backend.services.stride_service import generate_stride_threats
from backend.services.linddun_service import generate_linddun_threats
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
    update_item_by_id,
)
import uuid
from datetime import datetime

router = APIRouter(prefix="/api/projects", tags=["analysis"])


@router.post("/{project_id}/analyze")
async def run_full_analysis(project_id: str, body: dict = None):
    """Run full threat modeling pipeline for a project."""
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    log_event("analysis.started", details={"project_id": project_id})

    types = (body or {}).get("analysis_types", [
        "trust_boundary", "stride", "linddun", "controls", "tests", "missing_info", "assumptions"
    ])

    report = get_report(project_id) or {
        "report_id": str(uuid.uuid4()),
        "project_id": project_id,
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

    report["completeness"] = compute_completeness(project)

    # 1. Trust Boundaries
    if "trust_boundary" in types:
        trust_boundaries = await detect_trust_boundaries(project)
        report["trust_boundaries"] = trust_boundaries
    else:
        trust_boundaries = report.get("trust_boundaries", [])

    # 2. STRIDE
    stride_threats = []
    if "stride" in types:
        stride_threats = await generate_stride_threats(project, trust_boundaries)
        stride_threats = enrich_threats(stride_threats, project, "STRIDE")

    # 3. LINDDUN
    linddun_threats = []
    if "linddun" in types and project.get("has_pii", True):
        linddun_threats = await generate_linddun_threats(project, trust_boundaries)
        linddun_threats = enrich_threats(linddun_threats, project, "LINDDUN")

    all_threats = stride_threats + linddun_threats
    if all_threats:
        report["threats"], deduped_count = merge_deduped_threats(report.get("threats", []), all_threats)
    else:
        deduped_count = 0

    # 4. Controls
    if "controls" in types and report.get("threats"):
        controls = await map_controls(report["threats"])
        report["controls"] = enrich_controls(controls, report["threats"], project)

    # 5. Test Scenarios
    if "tests" in types and report.get("threats"):
        tests = await generate_test_scenarios(report["threats"], project)
        report["test_scenarios"] = tests

    # 6. Missing Info
    if "missing_info" in types:
        missing = await generate_missing_info(project, report.get("threats", []))
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
    }
    report["generated_at"] = datetime.utcnow().isoformat()

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
    })

    return report


@router.get("/{project_id}/report")
async def get_project_report(project_id: str):
    """Get the threat model report for a project."""
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    report = get_report(project_id)
    if not report:
        raise HTTPException(status_code=404, detail="No report yet — run analysis first")

    return report


@router.patch("/{project_id}/threats/{threat_id}")
async def update_threat_review(project_id: str, threat_id: str, data: dict):
    """Update review workflow fields for a generated threat."""
    report = get_report(project_id)
    if not report:
        raise HTTPException(status_code=404, detail="No report yet — run analysis first")

    if not update_item_by_id(report.get("threats", []), "threat_id", threat_id, data):
        raise HTTPException(status_code=404, detail="Threat not found")

    save_report(project_id, report)
    log_event("threat.review_updated", details={"project_id": project_id, "threat_id": threat_id})
    return {"success": True}


@router.patch("/{project_id}/controls/{control_id}")
async def update_control_review(project_id: str, control_id: str, data: dict):
    """Update checklist/review workflow fields for a mapped control."""
    report = get_report(project_id)
    if not report:
        raise HTTPException(status_code=404, detail="No report yet — run analysis first")

    if not update_item_by_id(report.get("controls", []), "control_id", control_id, data):
        raise HTTPException(status_code=404, detail="Control not found")

    save_report(project_id, report)
    log_event("control.review_updated", details={"project_id": project_id, "control_id": control_id})
    return {"success": True}


@router.post("/{project_id}/analyze/stride")
async def run_stride_only(project_id: str):
    return await run_full_analysis(project_id, {"analysis_types": ["trust_boundary", "stride", "controls", "tests"]})


@router.post("/{project_id}/analyze/linddun")
async def run_linddun_only(project_id: str):
    return await run_full_analysis(project_id, {"analysis_types": ["trust_boundary", "linddun", "controls", "tests"]})
