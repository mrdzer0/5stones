"""LINDDUN privacy threat generation service."""
from __future__ import annotations
import uuid
from typing import List
from backend.services.ai_service import chat_complete_json, get_active_provider_config
from backend.services.posture_service import build_evidence_context
from backend.services.dfd_model_service import format_dfd_analysis_context

LINDDUN_SYSTEM_PROMPT = """You are a privacy engineer performing LINDDUN privacy threat modeling.
Evaluate direct PII and indirect privacy signals such as identifiers, geolocation, images,
behavioral data, inferred attributes, public-data aggregation, external processors, user
awareness, retention, and re-identification. A project can have privacy threats even when
its has_pii flag is false.
Only cite evidence IDs provided in the evidence catalog. Never invent evidence, quotes,
source names, or IDs. Leave evidence_refs empty when a finding is framework inference.
Return one strict JSON object. Be specific and actionable."""

LINDDUN_CATEGORIES = [
    "Linkability",
    "Identifiability",
    "Non-repudiation",
    "Detectability",
    "Disclosure of Information",
    "Unawareness",
    "Non-compliance"
]


async def generate_linddun_threats(
    project: dict,
    trust_boundaries: List[dict],
    force_fallback: bool = False,
    dfd_model: dict | None = None,
) -> List[dict]:
    """Generate LINDDUN privacy threats from project context."""
    if force_fallback:
        return _fallback_linddun(project)

    cfg = get_active_provider_config()

    context = _build_privacy_context(project)
    evidence_context = build_evidence_context(project)
    boundaries_text = "\n".join([
        f"- {b.get('source')} → {b.get('destination')}: {b.get('boundary_label')}"
        for b in trust_boundaries[:8]
    ])
    dfd_context = format_dfd_analysis_context(dfd_model)

    user_prompt = f"""Perform LINDDUN privacy threat analysis for this system.

PROJECT CONTEXT:
{context}

TRUST BOUNDARIES:
{boundaries_text}

CANONICAL DFD MODEL:
{dfd_context}

EVIDENCE CATALOG:
{evidence_context}

    Generate only specific candidate privacy threats grounded in sender, flow, receiver, and
    data lifecycle. Do not create a finding for every category. Do not treat has_pii=false as proof that no
privacy risk exists. Evaluate location and image metadata, linkability across records,
third-party model processing, inferred content, public API aggregation, retention, user
awareness, and compliance where relevant.
    Return one JSON object with a "threats" array and a separate "coverage" array:
{{
  "coverage": [{{"element_ref": "valid DFD id", "category": "LINDDUN category", "status": "reviewed_no_candidate|candidate_identified|insufficient_information", "reason": "..."}}],
  "threats": [
    {{
    "framework": "LINDDUN",
    "taxonomy_version": "adapter-version",
    "threat_category": "Linkability|Identifiability|Non-repudiation|Detectability|Disclosure of Information|Unawareness|Non-compliance",
    "component": "affected component",
    "source": "data origin",
    "destination": "data destination",
    "trust_boundary": "boundary crossed",
    "affected_refs": ["valid DFD node/flow/boundary/data-object IDs only"],
    "asset": "personal data at risk",
    "data_classification": "PII",
    "threat_description": "specific privacy threat description",
    "abuse_case": "how this privacy risk materializes",
    "recommended_control": "privacy control recommendation",
    "evidence_refs": ["one or more exact EV-... IDs from the catalog, or an empty array"],
    "assumption": "assumption made",
    "missing_info": "clarification needed",
    "preconditions": ["conditions required for the scenario"],
    "impact": "impact on individuals or privacy expectations",
    "validation_steps": ["Developer/QA/Product validation step"],
    "confidence": "High|Medium|Low",
    "risk_level": "Critical|High|Medium|Low",
    "owner": "Backend|Product|Legal|DevOps"
    }}
  ]
}}"""

    result = await chat_complete_json(
        system_prompt=LINDDUN_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        base_url=cfg.get("base_url"),
        api_key=cfg.get("api_key"),
        model=cfg.get("model"),
        max_tokens=3000,
    )
    threats = result if isinstance(result, list) else result.get("threats", [])
    if not threats:
        raise ValueError("Analysis engine returned an empty or invalid LINDDUN threat list")

    for t in threats:
        t["threat_id"] = t.get("threat_id") or str(uuid.uuid4())
        t["framework"] = "LINDDUN"
        t.setdefault("status", "Open")
        t.setdefault("data_classification", "PII")

    return threats


def _build_privacy_context(project: dict) -> str:
    return f"""Name: {project.get('name')}
Description: {project.get('description', 'N/A')}
Actors: {', '.join(project.get('actors', []))}
Data Involved: {', '.join(project.get('data_involved', []))}
External Systems: {', '.join(project.get('external_systems', []))}
Critical Actions: {', '.join(project.get('critical_actions', []))}
Existing Controls: {', '.join(project.get('existing_controls', []))}
Components: {', '.join(project.get('components', []))}
Entry Points: {', '.join(project.get('entry_points', []))}
Artifact Summary: {project.get('artifact_summary', 'N/A')}
Has PII: {project.get('has_pii', True)}"""


def _fallback_linddun(project: dict) -> list:
    data = project.get("data_involved", ["user data"])
    external = project.get("external_systems", ["third-party service"])
    actors = project.get("actors", ["User"])

    templates = [
        {
            "threat_category": "Disclosure of Information",
            "threat_description": f"Personal data ({data[0] if data else 'PII'}) exposed to unauthorized party through API response",
            "abuse_case": "API response includes sensitive fields not needed by the caller",
            "recommended_control": "Data minimization — remove unnecessary PII from API responses",
            "risk_level": "High", "confidence": "High",
            "asset": data[0] if data else "PII",
        },
        {
            "threat_category": "Linkability",
            "threat_description": f"User activity across multiple sessions can be linked using persistent identifiers",
            "abuse_case": "Track user behavior across sessions using device ID, transaction IDs, or cookies",
            "recommended_control": "Use ephemeral identifiers, implement identifier rotation",
            "risk_level": "Medium", "confidence": "Medium",
            "asset": "User identifiers",
        },
        {
            "threat_category": "Identifiability",
            "threat_description": f"Combination of data fields uniquely identifies individuals even without direct PII",
            "abuse_case": f"Combine {data[0] if data else 'user data'} with behavioral data to re-identify users",
            "recommended_control": "Evaluate data combinations for re-identification risk, apply aggregation",
            "risk_level": "Medium", "confidence": "Medium",
            "asset": "User profile data",
        },
        {
            "threat_category": "Unawareness",
            "threat_description": f"Users are not informed that their data is shared with {external[0] if external else 'third parties'}",
            "abuse_case": "Data sharing happens without user consent or transparent disclosure",
            "recommended_control": "Add clear privacy notice, obtain explicit consent for data sharing",
            "risk_level": "High", "confidence": "Medium",
            "asset": "Personal data shared externally",
        },
        {
            "threat_category": "Non-compliance",
            "threat_description": "Personal data retention period not defined or enforced — potential UU PDP/GDPR violation",
            "abuse_case": "Personal data retained indefinitely without legal basis or user consent",
            "recommended_control": "Define retention policy, implement automated data deletion, document legal basis",
            "risk_level": "High", "confidence": "Low",
            "asset": "All personal data",
        },
    ]

    threats = []
    for t in templates:
        t["threat_id"] = str(uuid.uuid4())
        t["framework"] = "LINDDUN"
        t["is_fallback"] = True
        t.setdefault("component", "API / Data Store")
        t.setdefault("source", actors[0] if actors else "User")
        t.setdefault("destination", "Data Store")
        t.setdefault("trust_boundary", "Internal Service → Sensitive Data Store")
        t.setdefault("data_classification", "PII")
        t.setdefault("assumption", "Based on common privacy pattern")
        t.setdefault("missing_info", "Need data flow diagram and privacy policy to confirm")
        t.setdefault("owner", "Backend")
        t.setdefault("status", "Open")
        threats.append(t)

    return threats
