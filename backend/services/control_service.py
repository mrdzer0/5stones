"""Control mapping service — maps threats to recommended controls from catalog."""
from __future__ import annotations
import uuid
import re
from typing import List
from pydantic import ValidationError
from backend.utils.storage import get_controls_catalog
from backend.services.ai_service import (
    StageGenerationResult,
    StructuredJSONResult,
    chat_complete_json,
    get_active_provider_config,
)
from backend.services.dfd_model_service import format_dfd_analysis_context
from backend.services.generation_contracts import (
    ControlGenerationItem,
    GenerationContractError,
    model_ids,
)


CONTROL_CATEGORY_ALIASES = {
    "Linking": ["Linkability"],
    "Linkability": ["Linking"],
    "Identifying": ["Identifiability"],
    "Identifiability": ["Identifying"],
    "Detecting": ["Detectability"],
    "Detectability": ["Detecting"],
    "Data Disclosure": ["Disclosure of Information", "Information Disclosure"],
    "Disclosure of Information": ["Data Disclosure", "Information Disclosure"],
    "Unawareness & Unintervenability": ["Unawareness"],
    "Unawareness": ["Unawareness & Unintervenability"],
}

_MATCH_STOPWORDS = {
    "the", "and", "for", "with", "may", "can", "from", "this", "that",
    "before", "after", "into", "when", "where", "user", "data", "system",
    "critical", "endpoint", "request", "response", "application", "service",
    "ensure", "every", "using", "required", "sensitive", "all", "use",
}


async def map_controls(
    threats: List[dict],
    force_fallback: bool = False,
    data_policy: str | None = None,
    dfd_model: dict | None = None,
    evidence_ids: set[str] | None = None,
) -> List[dict]:
    """Map recommended controls from catalog or generate them using AI."""
    if not threats:
        return []

    catalog = get_controls_catalog()
    if force_fallback:
        controls = _catalog_fallback(threats, catalog)
        for control in controls:
            if isinstance(dfd_model, dict):
                control["analysis_revision"] = dfd_model.get("revision")
                control["dfd_revision"] = dfd_model.get("revision")
                control["dfd_semantic_hash"] = dfd_model.get("semantic_hash")
        return StageGenerationResult(
            controls,
            assessment_status="fallback",
            response_shape="deterministic_fallback",
            warnings=["AI control generation was bypassed; catalog candidates require review."],
            response_metadata={"engine": "fallback"},
        )

    cfg = get_active_provider_config(data_policy)

    catalog_summary = "\n".join([
        f"- {c.get('name')}: {c.get('description')}" for c in catalog[:15]
    ])

    threats_summary = "\n".join([
        f"- Threat: {t.get('threat_category')} - {t.get('threat_description')} (Component: {t.get('component')}) "
        f"(ID: {t.get('threat_id')}) (framework: {t.get('framework')}) "
        f"(analysis_revision: {t.get('analysis_revision') or t.get('analyzed_revision') or 'unknown'}) "
        f"(DFD targets: {t.get('target_refs') or t.get('affected_refs') or []}) "
        f"(evidence: {t.get('evidence_refs') or []})"
        for t in threats
    ])
    dfd_context = format_dfd_analysis_context(dfd_model)
    dfd_revision = (dfd_model or {}).get("revision", "unknown")
    dfd_hash = (dfd_model or {}).get("semantic_hash", "unknown")
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

CANONICAL DFD SNAPSHOT (the same semantic revision used by threat analysis):
{dfd_context}

ANALYSIS SNAPSHOT PROVENANCE:
- dfd_revision: {dfd_revision}
- dfd_semantic_hash: {dfd_hash}

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
    "analysis_revision": "current canonical DFD revision",
    "dfd_revision": "current canonical DFD revision",
    "dfd_semantic_hash": "current canonical DFD semantic hash",
    "owner": "Backend|DevOps|QA|Security|Product",
    "threat_ids": ["list of threat_ids this control addresses"]
    }}
  ]
}}

Deduplicate: one control can address multiple threats."""

    stage_budget = min(int(cfg.get("max_tokens") or 3000), 3000)
    result = await chat_complete_json(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        base_url=cfg.get("base_url"),
        api_key=cfg.get("api_key"),
        model=cfg.get("model"),
        max_tokens=stage_budget,
        return_metadata=True,
    )
    payload, response_metadata = _unpack_structured_result(result)
    response_shape = str(response_metadata.get("response_shape") or "unknown")
    if not isinstance(payload, dict) or "controls" not in payload:
        raise GenerationContractError(
            "Controls response must contain a controls array envelope",
            code="controls_envelope_invalid",
            metadata=response_metadata,
        )
    if not isinstance(payload["controls"], list):
        raise GenerationContractError(
            "Controls response field 'controls' must be an array",
            code="controls_envelope_schema_invalid",
            metadata=response_metadata,
        )
    if not payload["controls"]:
        raise GenerationContractError(
            "Analysis engine returned an empty controls list",
            code="controls_empty",
            metadata=response_metadata,
        )

    valid_threat_ids = {str(item.get("threat_id")) for item in threats if item.get("threat_id")}
    valid_dfd_ids = model_ids(dfd_model)
    warnings = []
    controls = []
    for index, raw_item in enumerate(payload["controls"]):
        try:
            model = ControlGenerationItem.model_validate(raw_item)
        except ValidationError:
            warnings.append(f"Control {index} failed item schema validation and was dropped.")
            continue
        item = model.model_dump(exclude_none=True)
        raw_threat_ids = list(item.get("threat_ids") or [])
        item["threat_ids"] = [tid for tid in raw_threat_ids if str(tid) in valid_threat_ids]
        if len(item["threat_ids"]) != len(raw_threat_ids):
            warnings.append(f"Control {index} contained unknown threat IDs; they were removed.")
        for field in ("target_refs",):
            refs = item.get(field) or []
            valid_refs = [ref for ref in refs if not valid_dfd_ids or str(ref.get("id")) in valid_dfd_ids]
            if len(valid_refs) != len(refs):
                warnings.append(f"Control {index} contained dangling DFD refs; they were removed.")
            item[field] = valid_refs
        if item.get("location_ref") and valid_dfd_ids and str(item["location_ref"].get("id")) not in valid_dfd_ids:
            item["location_ref"] = None
            warnings.append(f"Control {index} contained a dangling location_ref; it was removed.")
        for field in ("verification_evidence_refs", "implementation_evidence_refs"):
            refs = [str(ref) for ref in (item.get(field) or [])]
            if evidence_ids is not None:
                filtered = [ref for ref in refs if ref in evidence_ids]
                if len(filtered) != len(refs):
                    warnings.append(f"Control {index} contained unknown {field}; they were removed.")
                refs = filtered
            item[field] = refs
        controls.append(item)

    for c in controls:
        c["control_id"] = c.get("control_id") or str(uuid.uuid4())
        c["control_origin"] = c.get("control_origin") or "recommended"
        c["recommendation_status"] = c.get("recommendation_status") or "recommended"
        if isinstance(dfd_model, dict):
            c["analysis_revision"] = dfd_model.get("revision")
            c["dfd_revision"] = dfd_model.get("revision")
            c["dfd_semantic_hash"] = dfd_model.get("semantic_hash")

    if not controls:
        raise GenerationContractError(
            "Analysis engine returned no schema-valid controls",
            code="controls_items_invalid",
            metadata=response_metadata,
        )

    response_metadata["validation_status"] = "partial" if warnings else "complete"
    return StageGenerationResult(
        controls,
        assessment_status="partial" if warnings else "complete",
        response_shape=response_shape,
        warnings=warnings,
        response_metadata=response_metadata,
    )


def _unpack_structured_result(result) -> tuple[object, dict]:
    """Support instrumented responses and old test/provider adapters."""
    if isinstance(result, StructuredJSONResult):
        return result.payload, dict(result.metadata)
    return result, {"instrumentation_status": "legacy_uninstrumented"}


def _catalog_fallback(threats: list, catalog: list) -> list:
    """Match catalog controls per threat with explicit applicability evidence.

    A control is eligible through an exact category/alias match, or through at
    least two meaningful keyword signals. A single generic word is not enough.
    Threats without an eligible catalog control receive an explicit unassigned
    review record instead of being silently connected to an unrelated control.
    """
    grouped: dict[str, dict] = {}

    def tokens(value: object) -> set[str]:
        return {
            token for token in re.findall(r"[a-z0-9-]+", str(value or "").lower())
            if len(token) >= 3 and token not in _MATCH_STOPWORDS
        }

    for threat in threats or []:
        if not isinstance(threat, dict) or not threat.get("threat_id"):
            continue
        threat_id = str(threat["threat_id"])
        category = str(threat.get("threat_category") or "")
        aliases = [category, *CONTROL_CATEGORY_ALIASES.get(category, [])]
        threat_tokens = tokens(" ".join([
            str(threat.get("threat_description") or ""),
            str(threat.get("recommended_control") or ""),
            str(threat.get("asset") or ""),
            str(threat.get("component") or ""),
        ]))
        ranked = []
        for ctrl in catalog or []:
            ctrl_id = str(ctrl.get("id") or ctrl.get("name") or "")
            ctrl_tokens = tokens(" ".join([
                str(ctrl.get("name") or ""),
                str(ctrl.get("description") or ""),
                str(ctrl.get("implementation_guidance") or ""),
                " ".join(str(value) for value in (ctrl.get("tags") or [])),
                " ".join(str(value) for value in (ctrl.get("mitigates") or [])),
            ]))
            mitigates = {
                str(value).strip().casefold()
                for value in (ctrl.get("mitigates") or [])
                if str(value).strip()
            }
            category_hits = [
                alias for alias in aliases
                if str(alias).strip() and str(alias).strip().casefold() in mitigates
            ]
            keyword_hits = sorted(threat_tokens.intersection(ctrl_tokens))
            if category_hits:
                match_type = "category_applicability"
                score = 100 + len(keyword_hits)
                signals = category_hits + keyword_hits
            elif len(keyword_hits) >= 2:
                match_type = "keyword_applicability"
                score = len(keyword_hits)
                signals = keyword_hits
            else:
                continue
            ranked.append((score, ctrl_id, ctrl, match_type, signals))

        if not ranked:
            key = f"UNASSIGNED-{threat_id}"
            grouped[key] = {
                "control_id": key,
                "catalog_id": None,
                "name": "Control mapping requires review",
                "description": "No catalog control met the applicability threshold for this threat.",
                "implementation_guidance": "Review the threat and define or add an applicable control.",
                "status": "Unknown",
                "implementation_status": "Unknown",
                "evidence": "Threat-specific control applicability review is required.",
                "owner": "Security",
                "threat_ids": [threat_id],
                "control_origin": "inferred",
                "recommendation_status": "needs_review",
                "mapping_status": "unassigned",
                "mapping_basis": "no_catalog_applicability_match",
                "mapping_rationale": "No exact category/alias match or two-signal keyword match was found.",
                "threat_mappings": [{
                    "threat_id": threat_id,
                    "match_type": "unassigned",
                    "score": 0,
                    "matched_signals": [],
                    "rationale": "No catalog control met the applicability threshold.",
                }],
            }
            continue

        for score, _, ctrl, match_type, signals in sorted(ranked, key=lambda pair: (-pair[0], pair[1]))[:3]:
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
                "mapping_status": "mapped",
                "mapping_basis": match_type,
                "mapping_rationale": "",
                "threat_mappings": [],
            })
            if threat_id not in item["threat_ids"]:
                item["threat_ids"].append(threat_id)
            if match_type != item.get("mapping_basis"):
                item["mapping_basis"] = "category_and_keyword_applicability"
            rationale = f"{match_type.replace('_', ' ')} matched: {', '.join(signals)}."
            item["threat_mappings"].append({
                "threat_id": threat_id,
                "match_type": match_type,
                "score": score,
                "matched_signals": signals,
                "rationale": rationale,
            })
            item["mapping_rationale"] = " ".join(
                mapping["rationale"] for mapping in item["threat_mappings"]
            )

    return list(grouped.values())
