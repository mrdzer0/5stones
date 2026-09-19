"""STRIDE threat generation service."""
from __future__ import annotations
import uuid
from typing import List
from backend.services.ai_service import chat_complete_json, get_active_provider_config
from backend.services.posture_service import build_evidence_context
from backend.services.dfd_model_service import format_dfd_analysis_context
from backend.services.threat_validation_service import ThreatGenerationResult

STRIDE_SYSTEM_PROMPT = """You are a senior AppSec engineer performing STRIDE threat modeling.
Generate realistic, specific threats based on the context. Each threat must be actionable and evidence-based.
Only cite evidence IDs provided in the evidence catalog. Never invent evidence, quotes, source names, or IDs.
If the catalog does not support a finding, leave evidence_refs empty and explain the assumption.
Return one strict JSON object. Never fabricate controls that are confirmed without evidence."""

STRIDE_CATEGORIES = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege"
]


async def generate_stride_threats(
    project: dict,
    trust_boundaries: List[dict],
    force_fallback: bool = False,
    dfd_model: dict | None = None,
) -> List[dict]:
    """Generate STRIDE threats from project context and trust boundaries."""
    if force_fallback:
        return ThreatGenerationResult(_fallback_stride(project, trust_boundaries, dfd_model), [])

    cfg = get_active_provider_config(project.get("data_policy"))

    context = _build_context(project)
    evidence_context = build_evidence_context(project)
    boundaries_text = "\n".join([
        f"- {b.get('source')} → {b.get('destination')}: {b.get('boundary_label')}"
        for b in trust_boundaries[:10]
    ])
    dfd_context = format_dfd_analysis_context(dfd_model)

    user_prompt = f"""Perform STRIDE threat analysis for this system.

PROJECT CONTEXT:
{context}

TRUST BOUNDARIES:
{boundaries_text}

CANONICAL DFD MODEL:
{dfd_context}

EVIDENCE CATALOG:
{evidence_context}

    Generate only high-value candidate threats supported by the model. Do not create one
    finding for every STRIDE category or every element. Return one JSON object with a
    "threats" array and a separate "coverage" array:
{{
  "coverage": [{{"element_ref": "valid DFD id", "category": "STRIDE category", "status": "reviewed_no_candidate|candidate_identified|insufficient_information", "reason": "..."}}],
  "threats": [
    {{
    "framework": "STRIDE",
    "taxonomy_version": "stride-v1",
    "title": "short threat title",
    "scenario": "specific source-flow-destination attack scenario",
    "threat_category": "Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege",
    "component": "affected component",
    "source": "where attack originates",
    "destination": "target component",
    "trust_boundary": "boundary name if applicable",
    "affected_refs": ["valid DFD node/flow/boundary/data-object IDs only"],
    "asset": "what asset is at risk",
    "data_classification": "Public|Internal|PII|Financial|Secret",
    "threat_description": "specific threat description",
    "abuse_case": "how an attacker would execute this",
    "recommended_control": "primary recommended control",
    "known_controls": ["controls explicitly evidenced by the project context"],
    "recommended_mitigations": ["actionable mitigation steps"],
    "evidence_refs": ["one or more exact EV-... IDs from the catalog, or an empty array"],
    "assumption": "what assumption was made if evidence is missing",
    "missing_info": "what information would change this analysis",
    "preconditions": ["conditions required for the scenario"],
    "impact": "system impact",
    "validation_steps": ["Developer/QA validation step"],
    "confidence": "High|Medium|Low",
    "risk_level": "Critical|High|Medium|Low",
    "owner": "Dev|QA|Security|DevOps"
    }}
  ]
}}"""

    result = await chat_complete_json(
        system_prompt=STRIDE_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        base_url=cfg.get("base_url"),
        api_key=cfg.get("api_key"),
        model=cfg.get("model"),
        max_tokens=4000,
    )
    coverage = [] if isinstance(result, list) else result.get("coverage", [])
    threats = result if isinstance(result, list) else result.get("threats", [])
    if not threats:
        raise ValueError("Analysis engine returned an empty or invalid STRIDE threat list")

    for t in threats:
        t["threat_id"] = t.get("threat_id") or str(uuid.uuid4())
        t["framework"] = "STRIDE"
        t.setdefault("status", "Open")

    return ThreatGenerationResult(threats, coverage)


def _build_context(project: dict) -> str:
    return f"""Name: {project.get('name')}
Description: {project.get('description', 'N/A')}
Actors: {', '.join(project.get('actors', []))}
Entry Points: {', '.join(project.get('entry_points', []))}
Data Involved: {', '.join(project.get('data_involved', []))}
Auth Method: {project.get('auth_method', 'Unknown')}
External Systems: {', '.join(project.get('external_systems', []))}
Critical Actions: {', '.join(project.get('critical_actions', []))}
Existing Controls: {', '.join(project.get('existing_controls', []))}
Components: {', '.join(project.get('components', []))}
Artifact Summary: {project.get('artifact_summary', 'N/A')}
Environment: {project.get('environment', 'Unknown')}"""


def _fallback_stride(project: dict, trust_boundaries: list, dfd_model: dict | None = None) -> list:
    """Return an explicitly reviewable candidate when AI is unavailable."""
    actors = project.get("actors", ["User"])
    entry_points = project.get("entry_points", ["API"])
    data = project.get("data_involved", ["user data"])
    critical = project.get("critical_actions", ["create", "update"])
    flow = (dfd_model or {}).get("flows", [])[:1]
    flow = flow[0] if flow else {}
    refs = [value for value in [flow.get("id"), flow.get("source_id"), flow.get("target_id")] if value]
    refs.extend(flow.get("data_object_ids") or [])
    component = flow.get("target_id") or (entry_points[0] if entry_points else "API")
    return [{
        "threat_id": str(uuid.uuid4()),
        "framework": "STRIDE",
        "threat_category": "Tampering",
        "threat_description": f"Candidate: {data[0] if data else 'request data'} may be modified before {component} processes it.",
        "abuse_case": f"An actor alters the request or input flow before {critical[0] if critical else 'the critical action'}.",
        "recommended_control": "Validate input server-side and verify integrity at the receiving process.",
        "component": component,
        "source": actors[0] if actors else "User",
        "destination": component,
        "trust_boundary": "",
        "affected_refs": refs,
        "asset": data[0] if data else "Application Data",
        "data_classification": "Internal",
        "assumption": "AI provider unavailable; candidate is derived from the first canonical flow and requires review.",
        "missing_info": "Confirm request semantics, authentication, authorization, and integrity controls.",
        "preconditions": ["An attacker can send or alter the relevant input flow."],
        "impact": "Integrity impact is unknown until the receiving process and controls are verified.",
        "validation_steps": ["Review the receiving process validation and authorization tests."],
        "risk_level": "Medium",
        "confidence": "Low",
        "owner": "Security",
        "status": "Needs Info",
        "is_fallback": True,
        "candidate_only": True,
    }]
