"""Deterministic and auditable DFD-based threat risk assessment.

The analysis provider may describe impact and attack scenarios, but it does not
own the final severity decision.  This module applies one versioned 5x5 matrix
to canonical DFD facts and preserves the provider severity only as an advisory
input for audit comparison.
"""
from __future__ import annotations

import hashlib
import json
from typing import Iterable


RISK_METHODOLOGY_VERSION = "dfd-risk-v1.0"
RISK_MATRIX_NAME = "inherent-risk-5x5"
RISK_LEVELS = {"Critical", "High", "Medium", "Low"}

_CLASSIFICATION_IMPACT = {
    "public": 1,
    "internal": 2,
    "unknown": 2,
    "pii": 4,
    "financial": 4,
    "secret": 5,
}

_CATEGORY_IMPACT = {
    "spoofing": 3,
    "tampering": 3,
    "repudiation": 2,
    "information disclosure": 4,
    "denial of service": 3,
    "elevation of privilege": 4,
    "linking": 3,
    "linkability": 3,
    "identifying": 4,
    "identifiability": 4,
    "non-repudiation": 3,
    "detecting": 2,
    "detectability": 2,
    "data disclosure": 4,
    "disclosure of information": 4,
    "unawareness & unintervenability": 3,
    "unawareness": 3,
    "non-compliance": 3,
}


def risk_level_for_score(score: int) -> str:
    """Map a 1..25 matrix score to the versioned severity bands."""
    if score >= 20:
        return "Critical"
    if score >= 12:
        return "High"
    if score >= 6:
        return "Medium"
    return "Low"


def _classification(value: object) -> str:
    normalized = str(value or "Unknown").strip().casefold()
    return normalized if normalized in _CLASSIFICATION_IMPACT else "unknown"


def _factor(name: str, value: object, score: int, source: str) -> dict:
    return {"name": name, "value": value, "score": score, "source": source}


def _canonical_json_hash(value: object) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _provider_level(item: dict) -> str | None:
    existing = str(item.get("provider_risk_level") or "").strip()
    if existing in RISK_LEVELS:
        return existing
    # Capture a legacy/generated value once.  On subsequent normalization the
    # deterministic result must never be mistaken for a provider input.
    if not item.get("risk_methodology_version"):
        candidate = str(item.get("scenario_risk_level") or item.get("risk_level") or "").strip()
        if candidate in RISK_LEVELS:
            return candidate
    return None


def _flow_context(item: dict, dfd_model: dict | None) -> tuple[dict | None, dict, dict, list[dict]]:
    model = dfd_model if isinstance(dfd_model, dict) else {}
    primary = str(item.get("primary_interaction_ref") or "")
    flow = next(
        (record for record in (model.get("flows") or []) if isinstance(record, dict) and str(record.get("id")) == primary),
        None,
    )
    nodes = {
        str(record.get("id")): record
        for record in (model.get("nodes") or [])
        if isinstance(record, dict) and record.get("id")
    }
    data_objects = {
        str(record.get("id")): record
        for record in (model.get("data_objects") or [])
        if isinstance(record, dict) and record.get("id")
    }
    source = nodes.get(str((flow or {}).get("source_id")), {})
    target = nodes.get(str((flow or {}).get("target_id")), {})
    attached_data = [
        data_objects[ref]
        for ref in (flow or {}).get("data_object_ids") or []
        if str(ref) in data_objects
    ]
    return flow, source, target, attached_data


def _impact_assessment(item: dict, attached_data: list[dict]) -> tuple[int, list[dict], list[str]]:
    category = str(item.get("threat_category") or "unknown").strip()
    category_score = _CATEGORY_IMPACT.get(category.casefold(), 2)
    factors = [_factor("threat_category", category or "unknown", category_score, "methodology.category")]
    uncertainties: list[str] = []

    classifications = [
        (_classification(record.get("classification")), f"dfd.data_object:{record.get('id')}")
        for record in attached_data
    ]
    if classifications:
        classification, source = max(classifications, key=lambda pair: _CLASSIFICATION_IMPACT[pair[0]])
    else:
        classification = _classification(item.get("data_classification"))
        source = "finding.data_classification"
        uncertainties.append("No classified data object is attached to the primary flow; finding classification was used.")
    classification_score = _CLASSIFICATION_IMPACT[classification]
    factors.append(_factor("data_classification", classification.title(), classification_score, source))
    if classification == "unknown":
        uncertainties.append("Data classification is unknown; the conservative baseline impact score is 2.")
    return max(category_score, classification_score), factors, uncertainties


def _likelihood_assessment(
    item: dict,
    flow: dict,
    source: dict,
    target: dict,
) -> tuple[int, list[dict], list[str]]:
    uncertainties: list[str] = []
    endpoint_scores = []
    for role, node in (("source", source), ("target", target)):
        exposure = str(node.get("exposure") or "unknown").casefold()
        scope = str(node.get("scope") or "unknown").casefold()
        if exposure == "internet_facing" or scope == "external_dependency":
            score = 4
        elif exposure == "local":
            score = 1
        elif exposure == "private":
            score = 2
        else:
            score = 2
            uncertainties.append(f"{role.title()} endpoint exposure is unknown; likelihood baseline 2 was used.")
        endpoint_scores.append(score)
    exposure_score = max(endpoint_scores or [2])
    factors = [_factor(
        "endpoint_exposure",
        f"{source.get('exposure') or 'unknown'} → {target.get('exposure') or 'unknown'}",
        exposure_score,
        f"dfd.flow:{flow.get('id')}",
    )]

    crossing_ids = [str(ref) for ref in (flow.get("boundary_crossings") or []) if ref]
    crossing_score = 3 if crossing_ids else 2
    factors.append(_factor(
        "trust_boundary_crossing",
        crossing_ids or "none documented",
        crossing_score,
        f"dfd.flow:{flow.get('id')}",
    ))
    likelihood = max(exposure_score, crossing_score)

    authn = str(flow.get("authn") or "unknown").strip()
    authn_normalized = authn.casefold()
    unauthenticated = authn_normalized in {"none", "no", "public", "anonymous", "unauthenticated", "not required"}
    authn_score = 4 if unauthenticated else 2
    factors.append(_factor("authentication_context", authn, authn_score, f"dfd.flow:{flow.get('id')}"))
    if authn_normalized == "unknown":
        uncertainties.append("Authentication context is unknown; no risk reduction was assumed.")
    if unauthenticated:
        likelihood = max(likelihood, 4)

    if item.get("control_gap_evidence_refs"):
        likelihood = min(5, likelihood + 1)
        factors.append(_factor(
            "evidenced_control_condition",
            list(item.get("control_gap_evidence_refs") or []),
            likelihood,
            "finding.control_gap_evidence_refs",
        ))
    if (
        item.get("finding_state") == "verified"
        and item.get("verification_result") == "confirmed"
        and item.get("verification_evidence_refs")
    ):
        likelihood = 5
        factors.append(_factor(
            "confirmed_verification",
            list(item.get("verification_evidence_refs") or []),
            5,
            "finding.verification_evidence_refs",
        ))
    return likelihood, factors, uncertainties


def assess_threat_risk(threat: dict, dfd_model: dict | None = None) -> dict:
    """Return a threat with deterministic scenario and final risk fields.

    Hypotheses retain a scenario-only matrix result but are not counted as an
    assessed finding.  Needs-context and unmapped records are explicitly
    deferred.  A reviewer override is applied only to an otherwise assessed
    finding and must carry an audit reason.
    """
    item = dict(threat or {})
    provider_level = _provider_level(item)
    item["provider_risk_level"] = provider_level
    item["risk_methodology_version"] = RISK_METHODOLOGY_VERSION

    flow, source, target, attached_data = _flow_context(item, dfd_model)
    mapped = bool(item.get("interaction_mapping_status") == "mapped" and item.get("primary_interaction_ref"))
    if not mapped or flow is None:
        reason = (
            "Risk is deferred until one primary canonical DFD flow is mapped."
            if not mapped else
            "Risk is deferred because the mapped primary flow is absent from the current canonical DFD revision."
        )
        item.update({
            "risk_level": "Unknown",
            "scenario_risk_level": None,
            "risk_score": None,
            "risk_status": "deferred",
            "risk_source": "deferred",
            "risk_rationale": reason,
            "risk_calculation": {
                "methodology_version": RISK_METHODOLOGY_VERSION,
                "matrix": RISK_MATRIX_NAME,
                "status": "deferred",
                "reason": reason,
                "primary_interaction_ref": item.get("primary_interaction_ref"),
                "dfd_revision": (dfd_model or {}).get("revision") if isinstance(dfd_model, dict) else None,
                "dfd_semantic_hash": (dfd_model or {}).get("semantic_hash") if isinstance(dfd_model, dict) else None,
            },
        })
        item["risk_assessment_fingerprint"] = _canonical_json_hash(item["risk_calculation"])
        return item

    impact, impact_factors, impact_uncertainties = _impact_assessment(item, attached_data)
    likelihood, likelihood_factors, likelihood_uncertainties = _likelihood_assessment(item, flow, source, target)
    score = impact * likelihood
    inherent_level = risk_level_for_score(score)
    state = str(item.get("finding_state") or "hypothesis")
    assessed = state in {"grounded", "reviewed", "verified"}
    deferred = state == "needs_context"
    override_level = str(item.get("risk_override_level") or "").strip()
    override_reason = str(item.get("risk_override_reason") or "").strip()
    override_valid = assessed and override_level in RISK_LEVELS and bool(override_reason)
    final_level = override_level if override_valid else inherent_level
    calculation = {
        "methodology_version": RISK_METHODOLOGY_VERSION,
        "matrix": RISK_MATRIX_NAME,
        "matrix_bands": {"Low": "1-5", "Medium": "6-11", "High": "12-19", "Critical": "20-25"},
        "status": "assessed" if assessed else ("deferred" if deferred else "scenario_only"),
        "impact": {"score": impact, "factors": impact_factors},
        "likelihood": {"score": likelihood, "factors": likelihood_factors},
        "score": score,
        "inherent_level": inherent_level,
        "final_level": final_level if assessed else None,
        "uncertainties": [*impact_uncertainties, *likelihood_uncertainties],
        "primary_interaction_ref": item.get("primary_interaction_ref"),
        "dfd_revision": (dfd_model or {}).get("revision") if isinstance(dfd_model, dict) else None,
        "dfd_semantic_hash": (dfd_model or {}).get("semantic_hash") if isinstance(dfd_model, dict) else None,
    }
    if override_valid:
        calculation["override"] = {
            "level": override_level,
            "reason": override_reason,
            "reviewer": item.get("risk_override_by") or "reviewer",
            "recorded_at": item.get("risk_override_at"),
        }
    calculation["input_fingerprint"] = _canonical_json_hash({
        "methodology_version": RISK_METHODOLOGY_VERSION,
        "primary_interaction_ref": item.get("primary_interaction_ref"),
        "finding_state": state,
        "impact": impact_factors,
        "likelihood": likelihood_factors,
        "override": calculation.get("override"),
        "dfd_revision": calculation["dfd_revision"],
        "dfd_semantic_hash": calculation["dfd_semantic_hash"],
    })
    item["risk_calculation"] = calculation
    item["risk_assessment_fingerprint"] = calculation["input_fingerprint"]
    item["risk_score"] = score
    item["scenario_risk_level"] = inherent_level
    if assessed:
        item["risk_level"] = final_level
        item["risk_status"] = "assessed"
        item["risk_source"] = "reviewer_override" if override_valid else "deterministic"
        suffix = f" Reviewer override applied: {override_reason}" if override_valid else ""
        item["risk_rationale"] = (
            f"{RISK_MATRIX_NAME}: impact {impact}/5 × likelihood {likelihood}/5 = {score}/25 "
            f"({inherent_level} inherent).{suffix}"
        ).strip()
    else:
        item["risk_level"] = "Unknown"
        item["risk_status"] = "deferred" if deferred else "scenario_only"
        item["risk_source"] = "deferred"
        item["risk_rationale"] = (
            f"Scenario estimate is {inherent_level} ({impact}×{likelihood}={score}/25), but final risk is "
            f"{'deferred while material context is unresolved' if deferred else 'not assigned until the hypothesis is grounded or reviewed'}."
        )
    return item


def threat_priority_level(threat: dict) -> str:
    """Return the deterministic level inherited by a control or test backlog."""
    if threat.get("risk_status") == "assessed" and threat.get("risk_level") in RISK_LEVELS:
        return str(threat["risk_level"])
    if threat.get("scenario_risk_level") in RISK_LEVELS:
        return str(threat["scenario_risk_level"])
    return "Medium"


def highest_risk_level(levels: Iterable[str]) -> str:
    order = ("Critical", "High", "Medium", "Low")
    values = set(levels)
    return next((level for level in order if level in values), "Medium")


def align_test_risk_priorities(scenarios: Iterable[dict], threats: Iterable[dict]) -> list[dict]:
    """Project deterministic threat risk into an existing verification backlog."""
    threat_by_id = {
        str(item.get("threat_id")): item
        for item in threats or []
        if isinstance(item, dict) and item.get("threat_id")
    }
    aligned = []
    for raw in scenarios or []:
        if not isinstance(raw, dict):
            continue
        item = dict(raw)
        threat = threat_by_id.get(str(item.get("threat_id") or ""))
        if threat:
            if item.get("priority_source") != "deterministic_threat_risk":
                item["provider_priority"] = item.get("provider_priority") or item.get("priority")
            item["priority"] = threat_priority_level(threat)
            item["priority_source"] = "deterministic_threat_risk"
            item["risk_methodology_version"] = RISK_METHODOLOGY_VERSION
        aligned.append(item)
    return aligned
