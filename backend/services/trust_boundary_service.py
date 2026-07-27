"""Trust boundary detection service."""
from __future__ import annotations
import uuid
from typing import List, Dict
from backend.services.ai_service import chat_complete_json, get_active_provider_config

TRUST_LEVELS = {
    "anonymous user": "Untrusted",
    "unauthenticated": "Untrusted",
    "public": "Untrusted",
    "logged-in": "Low Trust",
    "customer": "Low Trust",
    "user": "Low Trust",
    "merchant": "External Trusted",
    "partner": "External Dependency",
    "third-party": "External Dependency",
    "external": "External Dependency",
    "internal service": "Internal Trusted",
    "backend": "Internal Trusted",
    "api": "Internal Trusted",
    "service": "Internal Trusted",
    "admin": "Privileged",
    "administrator": "Privileged",
    "database": "Highly Trusted",
    "db": "Highly Trusted",
    "log": "Sensitive Internal Store",
    "storage": "Sensitive Internal Store",
}


def _infer_trust(entity: str) -> str:
    el = entity.lower()
    for key, level in TRUST_LEVELS.items():
        if key in el:
            return level
    return "Internal Trusted"


async def detect_trust_boundaries(project: dict) -> List[dict]:
    """Generate trust boundaries from project context using AI."""
    cfg = get_active_provider_config()

    actors = project.get("actors", [])
    components = project.get("components", [])
    entry_points = project.get("entry_points", [])
    data_flows = project.get("extracted_data_flows", [])
    artifacts_summary = project.get("artifact_summary", "")

    # Format data flows for AI context
    flows_text = ""
    if data_flows:
        flows_text = "Data Flows:\n" + "\n".join([
            f"- {f.get('source')} → {f.get('destination')} (Data: {', '.join(f.get('data', []))})"
            for f in data_flows
        ])

    context = f"""
Project: {project.get('name')}
Description: {project.get('description', '')}
Actors: {', '.join(actors)}
Entry Points: {', '.join(entry_points)}
External Systems: {', '.join(project.get('external_systems', []))}
Components: {', '.join(components)}
{flows_text}
Artifact Summary: {artifacts_summary[:2000]}
"""

    system_prompt = """You are a security architect identifying trust boundaries for threat modeling.
Return strict JSON. Be precise and avoid duplicates."""

    user_prompt = f"""Based on this project context, identify all trust boundaries where data crosses between different trust zones.

{context}

Return a JSON array of trust boundary objects:
[
  {{
    "source": "entity name",
    "destination": "entity name",
    "source_trust_level": "Untrusted|Low Trust|External Trusted|External Dependency|Internal Trusted|Privileged|Highly Trusted|Sensitive Internal Store",
    "destination_trust_level": "same options",
    "boundary_label": "short description like 'Public Internet → Internal Backend'",
    "risk_note": "why this boundary is security-relevant"
  }}
]

Include boundaries for: user→frontend, frontend→API, API→database, API→external services, admin→system, etc."""

    boundaries = []
    try:
        result = await chat_complete_json(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            base_url=cfg.get("base_url"),
            api_key=cfg.get("api_key"),
            model=cfg.get("model"),
        )
        boundaries = result if isinstance(result, list) else result.get("boundaries", [])
    except Exception:
        pass

    if not boundaries:
        boundaries = _fallback_boundaries(project)

    # Add IDs
    for b in boundaries:
        if "boundary_id" not in b:
            b["boundary_id"] = str(uuid.uuid4())

    return boundaries


def _fallback_boundaries(project: dict) -> list:
    actors = project.get("actors", ["User"])
    entry_points = project.get("entry_points", ["API"])
    external = project.get("external_systems", [])
    data_flows = project.get("extracted_data_flows", [])

    boundaries = []

    # If we have extracted data flows from the artifact, use them to build boundaries!
    if data_flows:
        seen = set()
        for flow in data_flows:
            src = flow.get("source")
            dst = flow.get("destination")
            if not src or not dst:
                continue
            key = (src.lower(), dst.lower())
            if key in seen:
                continue
            seen.add(key)

            src_trust = _infer_trust(src)
            dst_trust = _infer_trust(dst)

            boundaries.append({
                "boundary_id": str(uuid.uuid4()),
                "source": src,
                "destination": dst,
                "source_trust_level": src_trust,
                "destination_trust_level": dst_trust,
                "boundary_label": f"{src_trust} → {dst_trust}",
                "risk_note": f"Data flow between {src} ({src_trust}) and {dst} ({dst_trust}). Requires authentication & input validation."
            })
        if boundaries:
            return boundaries

    # Otherwise, use old generic fallback based on actors and entry points
    for actor in actors[:3]:
        for ep in entry_points[:2]:
            boundaries.append({
                "boundary_id": str(uuid.uuid4()),
                "source": actor,
                "destination": ep,
                "source_trust_level": _infer_trust(actor),
                "destination_trust_level": "Internal Trusted",
                "boundary_label": f"{actor} → {ep}",
                "risk_note": "Cross-trust boundary requiring authentication and input validation."
            })
    for ext in external[:2]:
        boundaries.append({
            "boundary_id": str(uuid.uuid4()),
            "source": ext,
            "destination": "Internal API",
            "source_trust_level": "External Dependency",
            "destination_trust_level": "Internal Trusted",
            "boundary_label": f"External {ext} → Internal",
            "risk_note": "External dependency — validate all inbound data."
        })
    return boundaries

