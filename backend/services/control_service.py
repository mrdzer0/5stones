"""Control mapping service — maps threats to recommended controls from catalog."""
from __future__ import annotations
import uuid
from typing import List
from backend.utils.storage import get_controls_catalog
from backend.services.ai_service import chat_complete_json, get_active_provider_config


async def map_controls(threats: List[dict], force_fallback: bool = False) -> List[dict]:
    """Map recommended controls from catalog or generate them using AI."""
    if not threats:
        return []

    catalog = get_controls_catalog()
    if force_fallback:
        return _catalog_fallback(threats, catalog)

    cfg = get_active_provider_config()

    catalog_summary = "\n".join([
        f"- {c.get('name')}: {c.get('description')}" for c in catalog[:15]
    ])

    threats_summary = "\n".join([
        f"- Threat: {t.get('threat_category')} - {t.get('threat_description')} (Component: {t.get('component')}) (ID: {t.get('threat_id')})"
        for t in threats
    ])

    system_prompt = """You are a senior security engineer mapping threat mitigations (controls).
Map controls to specific threat IDs. Return one strict JSON object."""

    user_prompt = f"""Select or generate controls for the following threats, using the reference control catalog where applicable.

CONTROL CATALOG:
{catalog_summary}

THREATS:
{threats_summary}

Return one JSON object with a "controls" array:
{{
  "controls": [
    {{
    "name": "control name",
    "description": "what this control does",
    "implementation_guidance": "specific how-to guidance",
    "status": "Unknown|Partial|Implemented|Missing",
    "evidence": "what evidence is needed to confirm status",
    "owner": "Backend|DevOps|QA|Security|Product",
    "threat_ids": ["list of threat_ids this control addresses"]
    }}
  ]
}}

Deduplicate: one control can address multiple threats."""

    result = await chat_complete_json(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        base_url=cfg.get("base_url"),
        api_key=cfg.get("api_key"),
        model=cfg.get("model"),
        max_tokens=3000,
    )
    controls = result if isinstance(result, list) else result.get("controls", [])
    
    if not controls:
        raise ValueError("Analysis engine returned an empty or invalid controls list")

    for c in controls:
        c["control_id"] = c.get("control_id") or str(uuid.uuid4())

    return controls


def _catalog_fallback(threats: list, catalog: list) -> list:
    """Simple keyword-based control matching."""
    threat_text = " ".join([
        f"{t.get('threat_category','')} {t.get('threat_description','')}"
        for t in threats
    ]).lower()

    matched = []
    used_ids = set()

    for ctrl in catalog:
        keywords = ctrl.get("tags", []) + [m.lower() for m in ctrl.get("mitigates", [])]
        if any(k in threat_text for k in keywords):
            if ctrl["id"] not in used_ids:
                used_ids.add(ctrl["id"])
                matched.append({
                    "control_id": str(uuid.uuid4()),
                    "name": ctrl["name"],
                    "description": ctrl["description"],
                    "implementation_guidance": ctrl.get("implementation_guidance", ""),
                    "status": "Unknown",
                    "evidence": "Need code review to confirm status",
                    "owner": ctrl.get("owner", "Backend"),
                    "threat_ids": [t.get("threat_id", "") for t in threats[:3]],
                })

    if not matched:
        # Return first 3 controls as generic fallback
        for ctrl in catalog[:3]:
            matched.append({
                "control_id": str(uuid.uuid4()),
                "name": ctrl["name"],
                "description": ctrl["description"],
                "implementation_guidance": ctrl.get("implementation_guidance", ""),
                "status": "Unknown",
                "evidence": "Confirm via code review",
                "owner": ctrl.get("owner", "Backend"),
                "threat_ids": [],
            })

    return matched
