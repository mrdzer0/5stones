"""CR4 quality gates for DFD-grounded STRIDE/LINDDUN findings.

This module is deliberately deterministic.  The provider may propose a
scenario, but the application owns the scope, applicability, grounding state,
duplicate identity, and coverage manifest that downstream stages consume.
"""
from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from typing import Iterable

from backend.services.threat_validation_service import (
    LINDDUN_CATEGORY_ALIASES,
    LINDDUN_CATEGORIES,
    STRIDE_CATEGORIES,
)


FINDING_QUALITY_VERSION = "cr4-grounded-finding-v1"
APPLICABILITY_SCHEMA_VERSION = "cr4-applicability-v1"
FINDING_STATES = {"grounded", "hypothesis", "needs_context", "reviewed", "verified"}
_NON_SEMANTIC_WORDS = {
    "a", "an", "the", "this", "that", "may", "might", "could", "can", "be", "is",
    "are", "to", "of", "in", "on", "for", "from", "with", "and", "or", "when",
    "before", "after", "possible", "potential", "threat", "risk", "candidate",
}


def _text(value: object) -> str:
    return " ".join(str(value or "").split()).strip()


def _canonical_category(value: object, framework: str) -> str:
    category = _text(value)
    return LINDDUN_CATEGORY_ALIASES.get(category, category) if framework == "LINDDUN" else category


def _unique(values: Iterable[object]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        item = _text(value)
        if item and item.casefold() not in seen:
            result.append(item)
            seen.add(item.casefold())
    return result


def _mechanism(value: object) -> str:
    text = _text(value).casefold()
    tokens = [token for token in re.findall(r"[a-z0-9][a-z0-9_-]*", text) if token not in _NON_SEMANTIC_WORDS]
    return " ".join(tokens[:80])


def finding_quality_fingerprint(threat: dict) -> str:
    """Return the CR4 duplicate identity.

    Titles are intentionally excluded.  Two provider phrasings represent one
    scenario when they share framework/category, primary interaction,
    mechanism, and affected asset.
    """
    framework = _text(threat.get("framework")).upper()
    category = _canonical_category(threat.get("threat_category"), framework)
    mechanism = (
        threat.get("mechanism")
        or threat.get("attack_mechanism")
        or threat.get("abuse_case")
        or threat.get("scenario")
        or threat.get("threat_description")
    )
    affected_asset = (
        threat.get("affected_asset")
        or threat.get("asset")
        or threat.get("data_asset")
        or threat.get("component")
        or "|".join(_unique(threat.get("affected_refs") or []))
    )
    payload = {
        "framework": framework,
        "category": category,
        "primary_interaction_ref": _text(threat.get("primary_interaction_ref")),
        "mechanism": _mechanism(mechanism),
        "affected_asset": _mechanism(affected_asset),
    }
    rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()[:32]


def _inventory(model: dict | None) -> dict[str, tuple[str, dict]]:
    result: dict[str, tuple[str, dict]] = {}
    if not isinstance(model, dict):
        return result
    for collection in ("nodes", "data_objects", "flows", "boundaries"):
        element_type = collection[:-1] if collection.endswith("s") else collection
        for item in model.get(collection) or []:
            if isinstance(item, dict) and item.get("id"):
                result[str(item["id"])] = (element_type, item)
    return result


def _primary_flow_ids(model: dict | None) -> set[str]:
    if not isinstance(model, dict):
        return set()
    flows = {
        str(item.get("id"))
        for item in (model.get("flows") or [])
        if isinstance(item, dict) and item.get("id")
    }
    if "primary_interaction_ids" not in model:
        return flows
    return flows.intersection({str(value) for value in model.get("primary_interaction_ids") or [] if value})


def _coverage_key(item: dict) -> tuple[str, str]:
    return _text(item.get("element_ref")), _text(item.get("category"))


def _element_applicability(element_type: str, category: str, framework: str, *, linked: bool) -> tuple[str, str]:
    """Return deterministic applicability for graph context elements.

    Flows are handled separately because they are the only provider assessment
    scope.  Nodes, stores, and boundaries remain visible as context so their
    lack of a provider row is never mistaken for a reviewed negative.
    """
    if element_type == "flow":
        return "applicable", "A canonical interaction is the assessment unit."
    if element_type == "boundary":
        return "not_applicable", "A trust boundary is context for an interaction, not an independent provider target."
    if framework == "STRIDE" and element_type == "data_object":
        if category in {"Tampering", "Repudiation", "Information Disclosure"}:
            return "applicable", "The data object can be modified, attributed, or disclosed through a canonical interaction."
        return "not_applicable", f"{category} is assessed on the canonical flow or endpoint, not the data object itself."
    if framework == "LINDDUN" and element_type == "data_object":
        return ("applicable", "The data object is attached to at least one canonical interaction.") if linked else (
            "not_applicable", "The data object is not attached to a canonical interaction."
        )
    return "context_only", "The element is retained as DFD context; provider coverage is evaluated on its canonical flow."


def build_applicability_manifest(
    coverage: Iterable[dict],
    threats: Iterable[dict],
    dfd_model: dict | None,
    framework: str,
) -> dict:
    """Build an auditable per-element/category coverage manifest."""
    framework = _text(framework).upper()
    categories = tuple(sorted(STRIDE_CATEGORIES)) if framework == "STRIDE" else tuple(LINDDUN_CATEGORIES)
    model = dfd_model if isinstance(dfd_model, dict) else {}
    inventory = _inventory(model)
    primary_ids = _primary_flow_ids(model)
    deferred_flow_ids = {
        str(item.get("id"))
        for item in (model.get("flows") or [])
        if isinstance(item, dict) and item.get("id") and item.get("grounding_status") == "deferred"
    }
    coverage_by_key: dict[tuple[str, str], dict] = {}
    for raw in coverage or []:
        if not isinstance(raw, dict):
            continue
        element_ref = _text(raw.get("element_ref"))
        category = _canonical_category(raw.get("category"), framework)
        if element_ref and category in categories:
            coverage_by_key[(element_ref, category)] = raw

    linked_data_ids = {
        str(value)
        for flow in (model.get("flows") or [])
        if isinstance(flow, dict) and str(flow.get("id")) in primary_ids
        for value in (flow.get("data_object_ids") or [])
        if value
    }
    entries: list[dict] = []
    for element_ref, (element_type, element) in sorted(inventory.items()):
        for category in categories:
            applicability, applicability_rationale = _element_applicability(
                element_type, category, framework, linked=element_ref in linked_data_ids
            )
            raw = coverage_by_key.get((element_ref, category))
            is_primary_flow = element_type == "flow" and element_ref in primary_ids
            if element_type == "flow" and is_primary_flow:
                if element_ref in deferred_flow_ids:
                    status = "deferred"
                    reason = _text(element.get("grounding_reason")) or "Canonical interaction evidence is incomplete."
                elif raw is None:
                    status = "unprocessed"
                    reason = "No provider coverage row was returned for this primary interaction/category pair."
                else:
                    raw_status = _text(raw.get("status"))
                    if raw_status in {"reviewed_no_candidate", "candidate_identified", "assessed"}:
                        status = "assessed"
                    elif raw_status in {"not_applicable"} or _text(raw.get("applicability")).casefold() == "not_applicable":
                        status = "not_applicable"
                    elif raw_status in {"failed"}:
                        status = "failed"
                    elif raw_status in {"deferred", "insufficient_information"}:
                        status = "deferred"
                    elif raw_status in {"unprocessed"}:
                        status = "unprocessed"
                    else:
                        status = "unprocessed"
                    reason = _text(raw.get("reason")) or {
                        "assessed": "Provider assessed this canonical interaction/category pair.",
                        "not_applicable": _text(raw.get("applicability_rationale")) or applicability_rationale,
                        "deferred": "Material context is unresolved; absence is not evidence of no threat.",
                        "failed": "The analysis engine failed to return a validated assessment for this pair.",
                        "unprocessed": "The analysis engine did not process this pair.",
                    }.get(status, "Coverage state requires review.")
            elif element_type == "flow":
                status = "unprocessed"
                reason = "Flow is outside the current primary interaction set and is deferred from framework generation."
            else:
                status = "context_only"
                reason = applicability_rationale
            entries.append({
                "element_ref": element_ref,
                "element_type": element_type,
                "category": category,
                "assessment_scope": "primary_interaction" if is_primary_flow else "dfd_context",
                "status": status,
                "applicability": applicability,
                "applicability_rationale": applicability_rationale,
                "reason": reason,
                "mapping_refs": _unique((raw or {}).get("mapping_refs") if raw else []),
                "data_lifecycle": _text(
                    element.get("lifecycle")
                    or element.get("lifecycle_stage")
                    or element.get("data_lifecycle")
                    or "unknown"
                ),
                "model_revision": model.get("revision"),
                "dfd_semantic_hash": model.get("semantic_hash"),
                "coverage_key": f"{element_ref}:{category}",
            })

    scoped = [item for item in entries if item["assessment_scope"] == "primary_interaction"]
    summary = {
        "schema_version": APPLICABILITY_SCHEMA_VERSION,
        "framework": framework,
        "model_revision": model.get("revision"),
        "dfd_semantic_hash": model.get("semantic_hash"),
        "primary_interaction_count": len(primary_ids),
        "total": len(entries),
        "scoped_total": len(scoped),
        "assessed": sum(item["status"] == "assessed" for item in scoped),
        "not_applicable": sum(item["status"] == "not_applicable" for item in scoped),
        "deferred": sum(item["status"] == "deferred" for item in scoped),
        "failed": sum(item["status"] == "failed" for item in scoped),
        "unprocessed": sum(item["status"] == "unprocessed" for item in scoped),
        "context_only": sum(item["status"] == "context_only" for item in entries),
    }
    summary["complete"] = bool(scoped) and not any(
        summary[key] for key in ("deferred", "failed", "unprocessed")
    )
    return {
        "schema_version": APPLICABILITY_SCHEMA_VERSION,
        "framework": framework,
        "model_revision": model.get("revision"),
        "dfd_semantic_hash": model.get("semantic_hash"),
        "entries": entries,
        "applicability_matrix": entries,
        "summary": summary,
        "scope": {
            "primary_interaction_ids": sorted(primary_ids),
            "deferred_flow_ids": sorted(deferred_flow_ids),
            "unprocessed_flow_ids": sorted(
                {item["element_ref"] for item in scoped if item["status"] == "unprocessed"}
            ),
        },
    }


def validate_and_dedupe_findings(
    threats: Iterable[dict],
    dfd_model: dict | None,
    evidence_ids: set[str] | None = None,
    evidence_catalog: Iterable[dict] | None = None,
) -> tuple[list[dict], list[str], list[dict]]:
    """Apply CR4 grounding rules and remove semantic duplicates.

    Findings without a current primary interaction remain visible as
    ``needs_context`` review items, but are marked ineligible for controls and
    tests.  This keeps the evidence gap discoverable without turning it into a
    vulnerability or downstream foreign key.
    """
    model = dfd_model if isinstance(dfd_model, dict) else {}
    inventory = _inventory(model)
    flow_ids = {ref for ref, (kind, _) in inventory.items() if kind == "flow"}
    primary_ids = _primary_flow_ids(model)
    deferred_ids = {
        ref for ref in primary_ids
        if inventory.get(ref, ("", {}))[1].get("grounding_status") == "deferred"
    }
    catalog = {
        str(item.get("evidence_id")): item
        for item in (evidence_catalog or [])
        if isinstance(item, dict) and item.get("evidence_id")
    }
    warnings: list[str] = []
    quarantined: list[dict] = []
    unique: dict[str, dict] = {}
    output: list[dict] = []
    for index, raw in enumerate(threats or []):
        if not isinstance(raw, dict):
            continue
        item = deepcopy(raw)
        framework = _text(item.get("framework")).upper()
        item["quality_schema_version"] = FINDING_QUALITY_VERSION
        item["finding_fingerprint"] = finding_quality_fingerprint(item)
        item["fingerprint"] = item["finding_fingerprint"]
        item["quality_model_revision"] = model.get("revision")
        item["quality_dfd_semantic_hash"] = model.get("semantic_hash")
        item["quality_validation"] = {
            "model_revision": model.get("revision"),
            "dfd_semantic_hash": model.get("semantic_hash"),
            "validated_at_scope": "application",
        }
        field_checks = {
            "category": bool(_text(item.get("threat_category"))),
            "affected_refs": bool(_unique(item.get("affected_refs") or [])),
            "mechanism": bool(_text(
                item.get("mechanism") or item.get("attack_mechanism")
                or item.get("abuse_case") or item.get("scenario")
                or item.get("threat_description")
            )),
            "preconditions": bool(item.get("preconditions")),
            "impact": bool(_text(item.get("impact"))),
            "uncertainty": bool(_text(
                item.get("uncertainty") or item.get("confidence")
                or item.get("assumption") or item.get("missing_info")
            )),
            "analysis_revision": item.get("analysis_revision") == model.get("revision"),
            "dfd_semantic_hash": item.get("dfd_semantic_hash") == model.get("semantic_hash"),
        }
        item["quality_validation"]["field_checks"] = field_checks
        item["quality_validation"]["advisory_gaps"] = [
            key for key, valid in field_checks.items()
            if not valid and key not in {"category", "affected_refs", "analysis_revision", "dfd_semantic_hash"}
        ]
        refs = _unique(item.get("scenario_evidence_refs") or item.get("evidence_refs") or [])
        gap_refs = _unique(item.get("control_gap_evidence_refs") or [])
        if evidence_ids is not None:
            refs = [ref for ref in refs if ref in evidence_ids]
            gap_refs = [ref for ref in gap_refs if ref in evidence_ids]
        direct_refs = [
            ref for ref in [*refs, *gap_refs]
            if not catalog or str(catalog.get(ref, {}).get("evidence_type") or "").casefold() == "direct"
        ]
        item["scenario_evidence_refs"] = refs
        item["evidence_refs"] = list(refs)
        item["control_gap_evidence_refs"] = gap_refs
        item["grounding_evidence_refs"] = _unique(direct_refs)
        item["evidence_sufficiency"] = "direct" if direct_refs else ("cited" if refs or gap_refs else "missing")

        primary = _text(item.get("primary_interaction_ref"))
        primary_issue = None
        if not primary:
            primary_issue = "missing_primary_interaction"
        elif primary not in flow_ids:
            primary_issue = "primary_interaction_not_canonical"
        elif primary not in primary_ids:
            primary_issue = "primary_interaction_not_in_assessment_scope"
        elif primary in deferred_ids:
            primary_issue = "primary_interaction_deferred"
        if primary_issue:
            item["finding_state"] = "needs_context"
            item["finding_status"] = "needs_context"
            item["status"] = "Needs Info"
            item["vulnerability_status"] = "not_verified"
            item["risk_status"] = "deferred"
            item["risk_level"] = "Unknown"
            item["risk_score"] = None
            item["downstream_eligible"] = False
            item["grounding_reason"] = (
                "Framework output is retained for review, but it cannot enter downstream controls/tests until "
                f"the primary DFD interaction is resolved ({primary_issue})."
            )
            item["missing_info"] = _unique([
                item.get("missing_info"),
                "Select one current, grounded primary DFD interaction before mapping controls or tests.",
            ])[-1]
            warnings.append(f"{framework} finding {item.get('threat_id') or index}: {primary_issue}")
        else:
            item["downstream_eligible"] = True
            item["primary_interaction_validated"] = True
            state = _text(item.get("finding_state") or "hypothesis").casefold()
            if state not in FINDING_STATES:
                state = "hypothesis"
            if state in {"grounded", "verified"} and not direct_refs:
                # A cited context/inference item can support review, but not a
                # scored finding or a verified vulnerability.
                state = "hypothesis"
                item["grounding_reason"] = "The scenario has no direct evidence; it remains a hypothesis until evidence is supplied."
            item["finding_state"] = state
            item["finding_status"] = state
            if state == "reviewed" and not direct_refs:
                item["risk_status"] = "scenario_only"
                item["risk_level"] = "Unknown"
                item["risk_score"] = None
                item["grounding_reason"] = "Reviewer disposition is preserved, but final risk remains deferred without direct evidence."
            elif state in {"hypothesis", "needs_context"}:
                item["risk_status"] = "scenario_only" if state == "hypothesis" else "deferred"
                item["risk_level"] = "Unknown"
                item["risk_score"] = None
                item["vulnerability_status"] = "not_verified"

        key = item["finding_fingerprint"]
        if key in unique:
            winner = unique[key]
            for field in ("status", "owner", "review_notes", "reviewed_at", "risk_override_level", "risk_override_reason"):
                if winner.get(field):
                    item[field] = winner[field]
            item["duplicate_of"] = winner.get("threat_id")
            quarantined.append({
                "framework": framework,
                "reasons": ["duplicate_finding_fingerprint"],
                "item": {"threat_id": item.get("threat_id"), "duplicate_of": winner.get("threat_id"), "finding_fingerprint": key},
            })
            warnings.append(f"{framework} duplicate finding {item.get('threat_id') or index} was removed from the active snapshot")
            continue
        unique[key] = item
        output.append(item)
    return output, warnings, quarantined
