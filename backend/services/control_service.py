"""Control mapping service — maps threats to recommended controls from catalog."""
from __future__ import annotations
import uuid
from typing import List
from backend.utils.storage import get_controls_catalog
from backend.services.ai_service import chat_complete_json, get_active_provider_config


async def map_controls(threats: List[dict]) -> List[dict]:
    """Map a list of threats to recommended controls."""
    catalog = get_controls_catalog()
    cfg = get_active_provider_config()

    # Build a dict for fast lookup
    catalog_summary = "\n".join([
        f"- {c['id']}: {c['name']} (mitigates: {', '.join(c.get('mitigates', []))})"
        for c in catalog
    ])

    threats_summary = "\n".join([
        f"- {t.get('threat_id', 'unknown')}: [{t.get('framework')}:{t.get('threat_category')}] {t.get('threat_description', '')}"
        for t in threats[:20]
    ])

    system_prompt = """You are a security control advisor. Map each threat to the most relevant controls from the catalog.
Return strict JSON."""

    user_prompt = f"""Map each threat to relevant controls from our catalog. You may also suggest additional controls not in the catalog.

CONTROL CATALOG:
{catalog_summary}

THREATS:
{threats_summary}

Return a JSON array of control objects:
[
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

Deduplicate: one control can address multiple threats."""

    try:
        result = await chat_complete_json(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            base_url=cfg.get("base_url"),
            api_key=cfg.get("api_key"),
            model=cfg.get("model"),
            max_tokens=4096,
        )
        controls = result if isinstance(result, list) else result.get("controls", [])
    except Exception:
        controls = _catalog_fallback(threats, catalog)

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
