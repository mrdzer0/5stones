"""STRIDE threat generation service."""
from __future__ import annotations
import uuid
from typing import List
from backend.services.ai_service import chat_complete_json, get_active_provider_config
from backend.services.posture_service import build_evidence_context
from backend.services.dfd_model_service import format_dfd_analysis_context

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
        return _fallback_stride(project, trust_boundaries)

    cfg = get_active_provider_config()

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
    "taxonomy_version": "adapter-version",
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
    threats = result if isinstance(result, list) else result.get("threats", [])
    if not threats:
        raise ValueError("Analysis engine returned an empty or invalid STRIDE threat list")

    for t in threats:
        t["threat_id"] = t.get("threat_id") or str(uuid.uuid4())
        t["framework"] = "STRIDE"
        t.setdefault("status", "Open")

    return threats


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


def _fallback_stride(project: dict, trust_boundaries: list) -> list:
    threats = []
    actors = project.get("actors", ["User"])
    entry_points = project.get("entry_points", ["API"])
    data = project.get("data_involved", ["user data"])
    external = project.get("external_systems", [])
    critical = project.get("critical_actions", ["create", "update"])

    templates = [
        {
            "threat_category": "Spoofing",
            "threat_description": f"Attacker impersonates a legitimate {actors[0] if actors else 'user'} to gain unauthorized access",
            "abuse_case": f"Forge authentication token or session to access {entry_points[0] if entry_points else 'API'}",
            "recommended_control": "Secure token validation, MFA for sensitive actions",
            "risk_level": "High", "confidence": "Medium",
        },
        {
            "threat_category": "Tampering",
            "threat_description": f"User manipulates {data[0] if data else 'request data'} in transit or at rest",
            "abuse_case": "Intercept HTTP request and modify parameter values before server processing",
            "recommended_control": "Server-side validation, input sanitization, integrity checks",
            "risk_level": "High", "confidence": "Medium",
        },
        {
            "threat_category": "Repudiation",
            "threat_description": f"User performs {critical[0] if critical else 'critical action'} without an audit trail",
            "abuse_case": "Perform sensitive action and deny it was done due to missing logs",
            "recommended_control": "Immutable audit logging for all critical actions",
            "risk_level": "Medium", "confidence": "Medium",
        },
        {
            "threat_category": "Information Disclosure",
            "threat_description": "User accesses another user's data through IDOR vulnerability",
            "abuse_case": f"Replace own resource ID with another user's ID in {entry_points[0] if entry_points else 'API'} request",
            "recommended_control": "Object ownership validation on every resource endpoint",
            "risk_level": "High", "confidence": "Medium",
        },
        {
            "threat_category": "Denial of Service",
            "threat_description": f"Public endpoint {entry_points[0] if entry_points else 'API'} abused without rate limiting",
            "abuse_case": "Flood endpoint with automated requests causing service degradation",
            "recommended_control": "Rate limiting, IP throttling, CAPTCHA for sensitive flows",
            "risk_level": "Medium", "confidence": "Medium",
        },
        {
            "threat_category": "Elevation of Privilege",
            "threat_description": "Low-privilege user accesses admin or privileged function",
            "abuse_case": "Modify role claim in JWT or manipulate role parameter to escalate privilege",
            "recommended_control": "Server-side RBAC, role validation from authoritative source only",
            "risk_level": "Critical", "confidence": "Medium",
        },
    ]

    for i, t in enumerate(templates):
        t["threat_id"] = str(uuid.uuid4())
        t["framework"] = "STRIDE"
        t["is_fallback"] = True
        t.setdefault("component", entry_points[0] if entry_points else "API")
        t.setdefault("source", actors[0] if actors else "User")
        t.setdefault("destination", entry_points[0] if entry_points else "API")
        t.setdefault("trust_boundary", "Public → Internal")
        t.setdefault("asset", data[0] if data else "Application Data")
        t.setdefault("data_classification", "Internal")
        t.setdefault("assumption", "Based on common pattern — verify with code review")
        t.setdefault("missing_info", "Need code review to confirm control status")
        t.setdefault("owner", "Backend")
        t.setdefault("status", "Open")
        threats.append(t)

    return threats
