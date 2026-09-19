"""Control mapping service — maps threats to recommended controls from catalog."""
from __future__ import annotations
import uuid
import re
from typing import List
from backend.utils.storage import get_controls_catalog
from backend.services.ai_service import chat_complete_json, get_active_provider_config


CONTROL_CATEGORY_ALIASES = {
    "Linking": ["Linkability"],
    "Identifying": ["Identifiability"],
    "Detecting": ["Detectability"],
    "Data Disclosure": ["Disclosure of Information", "Information Disclosure"],
    "Unawareness & Unintervenability": ["Unawareness"],
}


async def map_controls(
    threats: List[dict],
    force_fallback: bool = False,
    data_policy: str | None = None,
    dfd_model: dict | None = None,
) -> List[dict]:
    """Map recommended controls from catalog or generate them using AI."""
    if not threats:
        return []

    catalog = get_controls_catalog()
    if force_fallback:
        return _catalog_fallback(threats, catalog)

    cfg = get_active_provider_config(data_policy)

    catalog_summary = "\n".join([
        f"- {c.get('name')}: {c.get('description')}" for c in catalog[:15]
    ])

    threats_summary = "\n".join([
        f"- Threat: {t.get('threat_category')} - {t.get('threat_description')} (Component: {t.get('component')}) (ID: {t.get('threat_id')}) (DFD targets: {t.get('target_refs') or t.get('affected_refs') or []})"
        for t in threats
    ])
    valid_dfd_ids = [
        str(item.get("id"))
        for collection in ("nodes", "data_objects", "flows", "boundaries")
        for item in ((dfd_model or {}).get(collection) or [])
        if isinstance(item, dict) and item.get("id")
    ]

    system_prompt = """You are a senior security engineer mapping threat mitigations (controls).
Map controls to specific threat IDs. Return one strict JSON object."""

    user_prompt = f"""Select or generate controls for the following threats, using the reference control catalog where applicable.

CONTROL CATALOG:
{catalog_summary}

THREATS:
{threats_summary}

VALID CANONICAL DFD IDS (use only these in target_refs/location_ref):
{valid_dfd_ids}

Return one JSON object with a "controls" array:
{{
  "controls": [
    {{
    "name": "control name",
    "description": "what this control does",
    "implementation_guidance": "specific how-to guidance",
    "status": "Unknown|Partial|Implemented|Missing",
    "implementation_status": "Unknown|Partial|Implemented|Missing",
    "evidence": "what evidence is needed to confirm status",
    "verification_evidence_refs": ["valid evidence IDs only; leave empty unless implementation evidence exists"],
    "target_refs": [{{"type": "data_flow|process|data_store|entity|boundary|data_object", "id": "valid DFD element ID"}}],
    "location_ref": {{"type": "data_flow|process|data_store|entity|boundary|data_object", "id": "primary DFD element ID"}},
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
    if not isinstance(controls, list):
        raise ValueError("Analysis engine returned a controls field that is not an array")

    controls = [
        item for item in controls
        if isinstance(item, dict) and str(item.get("name") or "").strip()
    ]
    if not controls:
        raise ValueError("Analysis engine returned an empty or invalid controls list")

    for c in controls:
        c["control_id"] = c.get("control_id") or str(uuid.uuid4())
        c["control_origin"] = c.get("control_origin") or "recommended"
        c["recommendation_status"] = c.get("recommendation_status") or "recommended"

    return controls


def _catalog_fallback(threats: list, catalog: list) -> list:
    """Match catalog controls per threat without fan-out or generic guessing."""
    grouped: dict[str, dict] = {}

    def tokens(value: object) -> set[str]:
        stopwords = {
            "the", "and", "for", "with", "may", "can", "from", "this", "that",
            "before", "after", "into", "when", "where", "user", "data", "system",
            "critical", "endpoint", "request", "response",
        }
        return {
            token for token in re.findall(r"[a-z0-9-]+", str(value or "").lower())
            if len(token) >= 3 and token not in stopwords
        }

    for threat in threats or []:
        if not isinstance(threat, dict) or not threat.get("threat_id"):
            continue
        category = str(threat.get("threat_category") or "")
        aliases = [category, *CONTROL_CATEGORY_ALIASES.get(category, [])]
        threat_tokens = tokens(" ".join([
            category,
            *aliases,
            str(threat.get("threat_description") or ""),
            str(threat.get("recommended_control") or ""),
        ]))
        ranked = []
        for ctrl in catalog or []:
            ctrl_tokens = tokens(" ".join([
                str(ctrl.get("name") or ""),
                str(ctrl.get("description") or ""),
                " ".join(str(value) for value in (ctrl.get("tags") or [])),
                " ".join(str(value) for value in (ctrl.get("mitigates") or [])),
            ]))
            score = len(threat_tokens.intersection(ctrl_tokens))
            category_match = any(
                str(value).strip().casefold() in {
                    str(item).strip().casefold() for item in (ctrl.get("mitigates") or [])
                }
                for value in aliases
                if str(value).strip()
            )
            if category_match:
                score += 5
            if score:
                ranked.append((score, ctrl))
        for _, ctrl in sorted(ranked, key=lambda pair: (-pair[0], str(pair[1].get("id"))))[:3]:
            key = str(ctrl.get("id") or ctrl.get("name"))
            item = grouped.setdefault(key, {
                "control_id": f"CAT-{key}",
                "catalog_id": key,
                "name": ctrl["name"],
                "description": ctrl["description"],
                "implementation_guidance": ctrl.get("implementation_guidance", ""),
                "status": "Unknown",
                "implementation_status": "Unknown",
                "evidence": "Implementation evidence is required before status can be confirmed.",
                "owner": ctrl.get("owner", "Backend"),
                "threat_ids": [],
                "control_origin": "recommended",
                "recommendation_status": "recommended",
                "mapping_basis": "catalog_category_and_keyword_match",
            })
            if threat["threat_id"] not in item["threat_ids"]:
                item["threat_ids"].append(threat["threat_id"])

    return list(grouped.values())
