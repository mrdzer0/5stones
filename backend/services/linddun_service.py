"""LINDDUN privacy threat generation service."""
from __future__ import annotations
import json
import uuid
from typing import List
from backend.services.ai_service import chat_complete_json, get_active_provider_config
from backend.services.posture_service import build_evidence_context
from backend.services.privacy_service import assess_privacy_metadata
from backend.services.threat_validation_service import ThreatGenerationResult
from backend.services.threat_batch_service import build_threat_batches, run_threat_batches

LINDDUN_SYSTEM_PROMPT = """You are a privacy engineer performing LINDDUN privacy threat modeling.
Evaluate direct PII and indirect privacy signals such as identifiers, geolocation, images,
behavioral data, inferred attributes, public-data aggregation, external processors, user
awareness, retention, and re-identification. A project can have privacy threats even when
its has_pii flag is false.
Only cite evidence IDs provided in the evidence catalog. Never invent evidence, quotes,
source names, or IDs. Leave evidence_refs empty when a finding is framework inference.
Return one strict JSON object. Be specific and actionable."""

LINDDUN_CATEGORIES = [
    "Linking",
    "Identifying",
    "Non-repudiation",
    "Detecting",
    "Data Disclosure",
    "Unawareness & Unintervenability",
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
        return ThreatGenerationResult(
            _fallback_linddun(project, dfd_model),
            [],
            assessment_status="fallback",
            response_shape="deterministic_fallback",
        )

    cfg = get_active_provider_config(project.get("data_policy"))

    context = _build_privacy_context(project)[:1800]
    evidence_context = build_evidence_context(project, limit=10)
    boundaries_text = "\n".join([
        f"- {b.get('source')} → {b.get('destination')}: {b.get('boundary_label')}"
        for b in trust_boundaries[:8]
    ])
    batches, deferred_refs = build_threat_batches(dfd_model)
    privacy_assessment = assess_privacy_metadata(dfd_model)

    user_prompt = f"""Perform LINDDUN privacy threat analysis for this system.

PROJECT CONTEXT:
{context}

TRUST BOUNDARIES:
{boundaries_text}

CANONICAL DFD MODEL:
The current interaction batch is provided after the response contract. Analyze only its listed canonical references.

PRIVACY METADATA READINESS:
{json.dumps({key: privacy_assessment.get(key) for key in ('status', 'unresolved_count', 'missing_fields')}, ensure_ascii=False)[:1200]}

EVIDENCE CATALOG:
{evidence_context}

    Generate only specific candidate privacy threats grounded in sender, flow, receiver, and
    data lifecycle. Do not create a finding for every category. Do not treat has_pii=false as proof that no
privacy risk exists. Evaluate location and image metadata, linkability across records,
third-party model processing, inferred content, public API aggregation, retention, user
awareness, and compliance where relevant. Missing purpose, recipient, lifecycle, notice,
individual-control, linkability, or legal-basis metadata must be reported as insufficient
information or a candidate requiring review; it is not proof of safety and is not by itself
evidence of legal non-compliance. A documented lawful basis does not remove other privacy
risks such as excessive disclosure, linking, or unawareness.
    Return one JSON object with a "threats" array and a separate "coverage" array:
{{
  "coverage": [{{"element_ref": "valid DFD id", "category": "LINDDUN category", "status": "reviewed_no_candidate|candidate_identified|insufficient_information", "reason": "...", "applicability": "applicable|not_applicable|unknown", "applicability_rationale": "...", "mapping_refs": ["related DFD/data lifecycle IDs"]}}],
  "threats": [
    {{
    "framework": "LINDDUN",
    "taxonomy_version": "linddun-v1",
    "title": "short privacy threat title",
    "scenario": "specific sender-flow-receiver privacy scenario",
    "threat_category": "Linking|Identifying|Non-repudiation|Detecting|Data Disclosure|Unawareness & Unintervenability|Non-compliance",
    "component": "affected component",
    "source": "data origin",
    "destination": "data destination",
    "trust_boundary": "boundary crossed",
    "affected_refs": ["valid DFD node/flow/boundary/data-object IDs only"],
    "analysis_revision": "current canonical DFD revision",
    "dfd_semantic_hash": "current canonical DFD semantic hash",
    "asset": "personal data at risk",
    "data_classification": "PII|Public|Internal|Financial|Secret|Unknown",
    "threat_description": "specific privacy threat description",
    "abuse_case": "how this privacy risk materializes",
    "recommended_control": "privacy control recommendation",
    "known_controls": ["controls explicitly evidenced by the project context"],
    "recommended_mitigations": ["actionable privacy mitigation steps"],
    "obligation": "documented obligation only when relevant; otherwise leave empty",
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

    parsed = await run_threat_batches(
        framework="LINDDUN", batches=batches, deferred_refs=deferred_refs,
        system_prompt=LINDDUN_SYSTEM_PROMPT, prompt_prefix=user_prompt, prompt_suffix="Return coverage and privacy candidates only for this batch. An omitted pair is insufficient information, never a reviewed negative.",
        provider=cfg, chat_complete_json=chat_complete_json,
    )
    threats = list(parsed)

    for t in threats:
        t["threat_id"] = t.get("threat_id") or str(uuid.uuid4())
        t["framework"] = "LINDDUN"
        t.setdefault("status", "Open")
        # Do not turn an omitted privacy classification into a PII assertion.
        t.setdefault("data_classification", "Unknown")

    return ThreatGenerationResult(
        threats,
        parsed.coverage,
        assessment_status=parsed.assessment_status,
        response_shape=parsed.response_shape,
        warnings=parsed.generation_warnings,
        response_metadata=parsed.response_metadata,
    )


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


def _fallback_linddun(project: dict, dfd_model: dict | None = None) -> list:
    data = project.get("data_involved", ["user data"])
    actors = project.get("actors", ["User"])
    flow = (dfd_model or {}).get("flows", [])[:1]
    flow = flow[0] if flow else {}
    refs = [value for value in [flow.get("id"), flow.get("source_id"), flow.get("target_id")] if value]
    refs.extend(flow.get("data_object_ids") or [])
    component = flow.get("target_id") or "Data Store"
    return [{
        "threat_id": str(uuid.uuid4()),
        "framework": "LINDDUN",
        "threat_category": "Data Disclosure",
        "threat_description": f"Candidate: {data[0] if data else 'personal data'} may be disclosed beyond the intended recipient.",
        "abuse_case": "A response or downstream data sharing includes more personal data than the purpose requires.",
        "recommended_control": "Confirm purpose limitation, recipient scope, minimization, and response field filtering.",
        "component": component,
        "source": actors[0] if actors else "User",
        "destination": component,
        "trust_boundary": "",
        "affected_refs": refs,
        "asset": data[0] if data else "Personal data",
        "data_classification": "PII",
        "assumption": "AI provider unavailable; candidate is derived from the first canonical flow and requires privacy review.",
        "missing_info": "Confirm purpose, recipient, retention, notice, and individual control for this flow.",
        "preconditions": ["The flow carries personal or linkable data."],
        "impact": "Privacy impact is unknown until purpose, recipient, and data minimization are verified.",
        "validation_steps": ["Review data inventory, response schema, recipient agreement, and retention policy."],
        "risk_level": "Medium",
        "confidence": "Low",
        "owner": "Product",
        "status": "Needs Info",
        "is_fallback": True,
        "candidate_only": True,
    }]
