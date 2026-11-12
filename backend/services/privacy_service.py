"""Deterministic privacy metadata readiness for the canonical DFD.

This module does not decide legal compliance.  It makes the information that
LINDDUN needs explicit, and keeps missing metadata as reviewable context rather
than silently treating it as safe or as a confirmed violation.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable


DATA_PRIVACY_FIELDS = (
    "purpose",
    "recipients",
    "data_subjects",
    "identifiers",
    "sensitivity",
    "linkability",
    "notice",
    "individual_control",
    "legal_basis",
)

STORE_LIFECYCLE_FIELDS = ("retention", "deletion", "backup")


def _missing(value: object) -> bool:
    """Distinguish absent/unknown metadata from explicit false or none-like text."""
    return value is None or value == "" or value == [] or value == "unknown"


def _status(missing_fields: list[str], total_fields: int) -> str:
    if not missing_fields:
        return "documented"
    if len(missing_fields) >= total_fields:
        return "unknown"
    return "partial"


def _unique(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        text = str(value or "").strip()
        if text and text.casefold() not in seen:
            seen.add(text.casefold())
            result.append(text)
    return result


def assess_privacy_metadata(dfd_model: dict | None) -> dict:
    """Return a reviewable privacy/lifecycle assessment for a DFD revision.

    The result is deliberately a derived assessment.  The canonical model and
    its assertions remain authoritative; this summary is safe to recompute on
    every report load and is suitable for prompts, coverage explanations, and
    UI badges.
    """
    model = dfd_model if isinstance(dfd_model, dict) else {}
    data_objects = [item for item in model.get("data_objects") or [] if isinstance(item, dict) and item.get("id")]
    stores = {
        str(store_id): store
        for store_id, store in (model.get("stores") or {}).items()
        if isinstance(store, dict)
    }
    nodes = {
        str(node.get("id")): node
        for node in model.get("nodes") or []
        if isinstance(node, dict) and node.get("id")
    }
    flows = [item for item in model.get("flows") or [] if isinstance(item, dict) and item.get("id")]
    questions = [item for item in model.get("questions") or [] if isinstance(item, dict) and item.get("id")]

    data_to_stores: dict[str, set[str]] = defaultdict(set)
    for store_id, store in stores.items():
        for data_id in store.get("data_object_ids") or []:
            data_to_stores[str(data_id)].add(store_id)

    data_to_flows: dict[str, set[str]] = defaultdict(set)
    for flow in flows:
        for data_id in flow.get("data_object_ids") or []:
            data_to_flows[str(data_id)].add(str(flow["id"]))

    question_by_ref: dict[str, set[str]] = defaultdict(set)
    for question in questions:
        for ref in question.get("affected_refs") or []:
            question_by_ref[str(ref)].add(str(question["id"]))

    data_records: list[dict] = []
    for item in data_objects:
        missing_fields = [field for field in DATA_PRIVACY_FIELDS if _missing(item.get(field))]
        store_ids = sorted(data_to_stores.get(str(item["id"]), set()))
        lifecycle_missing = [
            f"store.{field}"
            for store_id in store_ids
            for field in STORE_LIFECYCLE_FIELDS
            if _missing(stores.get(store_id, {}).get(field))
        ]
        missing = _unique([*missing_fields, *lifecycle_missing])
        affected_refs = {str(item["id"]), *store_ids, *data_to_flows.get(str(item["id"]), set())}
        question_ids = sorted({question_id for ref in affected_refs for question_id in question_by_ref.get(ref, set())})
        evidence_refs = _unique(item.get("evidence_refs") or [])
        for store_id in store_ids:
            evidence_refs.extend(stores.get(store_id, {}).get("evidence_refs") or [])
        data_records.append({
            "element_id": str(item["id"]),
            "display_id": item.get("display_id"),
            "name": item.get("name"),
            "status": _status(missing, len(DATA_PRIVACY_FIELDS) + len(lifecycle_missing)),
            "missing_fields": missing,
            "known_fields": [field for field in DATA_PRIVACY_FIELDS if field not in missing_fields],
            "store_ids": store_ids,
            "flow_ids": sorted(data_to_flows.get(str(item["id"]), set())),
            "question_ids": question_ids,
            "evidence_refs": _unique(evidence_refs),
        })

    store_records: list[dict] = []
    for store_id, store in sorted(stores.items()):
        missing_fields = [field for field in STORE_LIFECYCLE_FIELDS if _missing(store.get(field))]
        affected_refs = {store_id, *(str(value) for value in store.get("data_object_ids") or [])}
        question_ids = sorted({question_id for ref in affected_refs for question_id in question_by_ref.get(ref, set())})
        store_records.append({
            "element_id": store_id,
            "status": _status(missing_fields, len(STORE_LIFECYCLE_FIELDS)),
            "missing_fields": missing_fields,
            "known_fields": [field for field in STORE_LIFECYCLE_FIELDS if field not in missing_fields],
            "data_object_ids": [str(value) for value in store.get("data_object_ids") or []],
            "question_ids": question_ids,
            "evidence_refs": _unique(store.get("evidence_refs") or []),
        })

    unresolved = [
        *[record for record in data_records if record["missing_fields"]],
        *[record for record in store_records if record["missing_fields"]],
    ]
    status = "documented"
    if unresolved:
        status = "unknown" if all(record["status"] == "unknown" for record in unresolved) else "partial"
    return {
        "schema_version": "privacy-assessment-v1",
        "model_revision": model.get("revision"),
        "status": status,
        "data_objects": data_records,
        "stores": store_records,
        "unresolved_count": len(unresolved),
        "unknown_field_count": sum(len(record["missing_fields"]) for record in unresolved),
        "decision_note": "Missing privacy or lifecycle metadata is insufficient information; it is not evidence of safety or legal non-compliance.",
    }


def privacy_context_for_refs(dfd_model: dict | None, refs: Iterable[object]) -> dict:
    """Resolve privacy readiness for threat references without inventing data scope."""
    assessment = assess_privacy_metadata(dfd_model)
    model = dfd_model if isinstance(dfd_model, dict) else {}
    data_ids = {str(item.get("element_id")) for item in assessment["data_objects"]}
    store_ids = {str(item.get("element_id")) for item in assessment["stores"]}
    flow_to_data: dict[str, set[str]] = defaultdict(set)
    for flow in model.get("flows") or []:
        if isinstance(flow, dict) and flow.get("id"):
            flow_to_data[str(flow["id"])].update(str(value) for value in flow.get("data_object_ids") or [])
    store_to_data = {
        str(record["element_id"]): {str(value) for value in record.get("data_object_ids") or []}
        for record in assessment["stores"]
    }
    target_data_ids: set[str] = set()
    for raw_ref in refs or []:
        ref_id = str(raw_ref.get("id")) if isinstance(raw_ref, dict) and raw_ref.get("id") else str(raw_ref or "")
        if ref_id in data_ids:
            target_data_ids.add(ref_id)
        elif ref_id in flow_to_data:
            target_data_ids.update(flow_to_data[ref_id])
        elif ref_id in store_ids:
            target_data_ids.update(store_to_data.get(ref_id, set()))

    if not target_data_ids:
        return {
            "status": "not_applicable",
            "missing_fields": [],
            "data_object_ids": [],
            "question_ids": [],
            "evidence_refs": [],
        }
    records = [record for record in assessment["data_objects"] if record["element_id"] in target_data_ids]
    missing_fields = _unique(field for record in records for field in record.get("missing_fields") or [])
    question_ids = _unique(question_id for record in records for question_id in record.get("question_ids") or [])
    evidence_refs = _unique(ref for record in records for ref in record.get("evidence_refs") or [])
    statuses = {record.get("status") for record in records}
    status = "documented" if statuses == {"documented"} and not missing_fields else "unknown" if statuses == {"unknown"} else "partial"
    return {
        "status": status,
        "missing_fields": missing_fields,
        "data_object_ids": sorted(target_data_ids),
        "question_ids": question_ids,
        "evidence_refs": evidence_refs,
    }


def annotate_privacy_threats(threats: Iterable[dict], dfd_model: dict | None) -> list[dict]:
    """Attach privacy readiness to LINDDUN candidates while preserving candidates."""
    annotated: list[dict] = []
    for raw in threats or []:
        threat = dict(raw)
        refs = threat.get("target_refs") or [
            {"id": value} for value in (threat.get("affected_refs") or [])
        ]
        context = privacy_context_for_refs(dfd_model, refs)
        threat["privacy_context_status"] = context["status"]
        threat["privacy_context_missing"] = context["missing_fields"]
        threat["privacy_data_object_refs"] = context["data_object_ids"]
        if context["question_ids"]:
            threat["privacy_question_refs"] = context["question_ids"]
        if context["status"] in {"unknown", "partial"}:
            threat["finding_status"] = "needs_context"
            threat["finding_state"] = "needs_context"
            threat["finding_kind"] = "threat_scenario"
            threat["vulnerability_status"] = "not_verified"
            threat["risk_status"] = "deferred"
            risk_level = threat.get("risk_level")
            if risk_level in {"Critical", "High", "Medium", "Low"}:
                threat["scenario_risk_level"] = risk_level
                threat["risk_level"] = "Unknown"
            if threat.get("status") in (None, "Open", "Candidate"):
                threat["status"] = "Needs Info"
            missing_text = ", ".join(context["missing_fields"][:6]) or "documented privacy context"
            existing = str(threat.get("missing_info") or "").strip()
            suffix = f"Resolve privacy metadata: {missing_text}."
            threat["missing_info"] = f"{existing} {suffix}".strip()
            threat["assumption"] = str(threat.get("assumption") or "").strip() or "Privacy context is incomplete; this candidate requires human review."
        annotated.append(threat)
    return annotated
