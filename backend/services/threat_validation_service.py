"""Validation and normalization for AI-generated threat candidates."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable
from pydantic import BaseModel, ConfigDict, Field, ValidationError


class _ThreatEnvelope(BaseModel):
    """Small strict boundary for the fields that drive graph traceability."""

    model_config = ConfigDict(extra="allow")

    threat_category: str
    threat_description: str
    affected_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    validation_steps: list[str] = Field(default_factory=list)
    known_controls: list[str] = Field(default_factory=list)
    recommended_mitigations: list[str] = Field(default_factory=list)


class ThreatGenerationResult(list):
    """List-compatible AI result that preserves the separate coverage array."""

    def __init__(
        self,
        threats=None,
        coverage=None,
        *,
        assessment_status: str | None = None,
        response_shape: str = "object",
        warnings: list[str] | None = None,
    ):
        super().__init__(threats or [])
        self.coverage = coverage if isinstance(coverage, list) else []
        self.assessment_status = assessment_status or ("valid_empty" if not self else "complete")
        self.response_shape = response_shape
        self.generation_warnings = list(warnings or [])


class ThreatGenerationContractError(ValueError):
    """Raised when a provider response cannot satisfy the threat envelope."""


VALID_ASSESSMENT_STATUSES = {
    "complete",
    "valid_empty",
    "partial",
    "fallback",
    "invalid",
}


def normalize_generation_result(result: object, framework: str) -> ThreatGenerationResult:
    """Normalize provider/service output before the pipeline classifies it.

    Empty list-compatible results are a valid no-finding assessment. Unknown
    result shapes or contradictory status metadata are contract failures and
    must not be silently presented as a successful or fallback assessment.
    """
    if isinstance(result, ThreatGenerationResult):
        threats = list(result)
        coverage = result.coverage
        status = result.assessment_status
        response_shape = result.response_shape
        warnings = list(result.generation_warnings)
    elif isinstance(result, list):
        threats = list(result)
        coverage = []
        status = "valid_empty" if not threats else "complete"
        response_shape = "legacy_list"
        warnings = []
    else:
        return ThreatGenerationResult(
            [],
            [],
            assessment_status="invalid",
            response_shape="invalid",
            warnings=[f"{framework} result must be a list-compatible threat result"],
        )

    if status not in VALID_ASSESSMENT_STATUSES:
        warnings.append(f"{framework} result used unsupported assessment status: {status}")
        status = "invalid"
    elif not threats and status == "complete":
        status = "valid_empty"
    elif threats and status == "valid_empty":
        warnings.append(f"{framework} result marked valid_empty but contained threats")
        status = "invalid"

    return ThreatGenerationResult(
        threats,
        coverage,
        assessment_status=status,
        response_shape=response_shape,
        warnings=warnings,
    )


STRIDE_CATEGORIES = {
    "Spoofing", "Tampering", "Repudiation", "Information Disclosure",
    "Denial of Service", "Elevation of Privilege",
}
STRIDE_TAXONOMY_VERSION = "stride-v1"
LINDDUN_TAXONOMY_VERSION = "linddun-v1"

LINDDUN_CATEGORY_ALIASES = {
    "Linkability": "Linking",
    "Identifiability": "Identifying",
    "Non-repudiation": "Non-repudiation",
    "Detectability": "Detecting",
    "Disclosure of Information": "Data Disclosure",
    "Unawareness": "Unawareness & Unintervenability",
    "Linking": "Linking",
    "Identifying": "Identifying",
    "Detecting": "Detecting",
    "Data Disclosure": "Data Disclosure",
    "Unawareness & Unintervenability": "Unawareness & Unintervenability",
    "Non-compliance": "Non-compliance",
}

LINDDUN_CATEGORIES = (
    "Linking",
    "Identifying",
    "Non-repudiation",
    "Detecting",
    "Data Disclosure",
    "Unawareness & Unintervenability",
    "Non-compliance",
)


def _unique(values: Iterable[str]) -> list[str]:
    result = []
    seen = set()
    for value in values or []:
        text = str(value or "").strip()
        if text and text.casefold() not in seen:
            seen.add(text.casefold())
            result.append(text)
    return result


def parse_generation_payload(payload: object, framework: str) -> ThreatGenerationResult:
    """Validate the provider envelope without treating a valid empty review as failure.

    A provider may return the legacy array shape for compatibility, but new
    assessments should use the object envelope so coverage remains explicit.
    Missing or incorrectly typed envelope fields are provider-contract errors;
    an explicitly empty ``threats`` array is a valid assessment outcome.
    """
    if isinstance(payload, list):
        threats = payload
        coverage = []
        response_shape = "legacy_list"
    elif isinstance(payload, dict) and "threats" in payload:
        threats = payload.get("threats")
        coverage = payload.get("coverage", [])
        response_shape = "object"
        if not isinstance(threats, list):
            raise ThreatGenerationContractError(f"{framework} response field 'threats' must be an array")
        if not isinstance(coverage, list):
            raise ThreatGenerationContractError(f"{framework} response field 'coverage' must be an array")
    else:
        raise ThreatGenerationContractError(f"{framework} response must contain a threats array")

    return ThreatGenerationResult(
        threats,
        coverage,
        assessment_status="valid_empty" if not threats else "complete",
        response_shape=response_shape,
    )


def _model_ids(dfd_model: dict | None, *, include_review_elements: bool = False) -> set[str]:
    if not isinstance(dfd_model, dict):
        return set()
    ids = set()
    collections = ("nodes", "data_objects", "flows", "boundaries")
    if include_review_elements:
        collections = (*collections, "zones", "views", "questions")
    for collection in collections:
        ids.update(str(item.get("id")) for item in (dfd_model.get(collection) or []) if isinstance(item, dict) and item.get("id"))
    return ids


def validate_generated_threats(
    threats: Iterable[dict],
    framework: str,
    dfd_model: dict | None = None,
    evidence_ids: set[str] | None = None,
) -> tuple[list[dict], list[str]]:
    """Drop structurally invalid candidates and strip invalid model references.

    Incomplete information remains a valid candidate. A dangling reference is
    not silently accepted as a real DFD target.
    """
    valid_ids = _model_ids(dfd_model)
    accepted = []
    warnings = []
    allowed_categories = STRIDE_CATEGORIES if framework == "STRIDE" else set(LINDDUN_CATEGORY_ALIASES)

    for index, raw in enumerate(threats or []):
        if not isinstance(raw, dict):
            warnings.append(f"Dropped {framework} candidate {index}: result was not an object")
            continue
        try:
            item = _ThreatEnvelope.model_validate(raw).model_dump()
        except ValidationError:
            warnings.append(f"Dropped {framework} candidate {index}: schema validation failed")
            continue
        category = item["threat_category"].strip()
        description = item["threat_description"].strip()
        if category not in allowed_categories:
            warnings.append(f"Dropped {framework} candidate {index}: unsupported category {category or '(missing)'}")
            continue
        if not description:
            warnings.append(f"Dropped {framework} candidate {index}: missing threat description")
            continue
        if framework == "LINDDUN":
            item["threat_category"] = LINDDUN_CATEGORY_ALIASES.get(category, category)
        item["framework"] = framework
        item["taxonomy_version"] = str(
            item.get("taxonomy_version")
            or (STRIDE_TAXONOMY_VERSION if framework == "STRIDE" else LINDDUN_TAXONOMY_VERSION)
        )
        item["title"] = str(item.get("title") or description[:140]).strip()
        item["scenario"] = str(item.get("scenario") or item.get("abuse_case") or description).strip()
        item["finding_status"] = str(item.get("finding_status") or "candidate")
        item["known_controls"] = _unique(item.get("known_controls") or [])
        item["recommended_mitigations"] = _unique(
            item.get("recommended_mitigations")
            or ([item.get("recommended_control")] if item.get("recommended_control") else [])
        )
        item["affected_refs"] = _unique(item.get("affected_refs") or [])
        if valid_ids:
            invalid_refs = [ref for ref in item["affected_refs"] if ref not in valid_ids]
            if invalid_refs:
                warnings.append(
                    f"{framework} candidate {index} referenced unknown DFD IDs: {', '.join(invalid_refs)}"
                )
                item["affected_refs"] = [ref for ref in item["affected_refs"] if ref in valid_ids]
            if not item["affected_refs"]:
                warnings.append(
                    f"Dropped {framework} candidate {index}: no valid canonical DFD target remained"
                )
                continue
        item["mapping_refs"] = _unique(item.get("mapping_refs") or item.get("interaction_refs") or [])
        if valid_ids and item["mapping_refs"]:
            invalid_mapping = [ref for ref in item["mapping_refs"] if ref not in valid_ids]
            if invalid_mapping:
                warnings.append(
                    f"{framework} candidate {index} referenced unknown mapping IDs: {', '.join(invalid_mapping)}"
                )
                item["mapping_refs"] = [ref for ref in item["mapping_refs"] if ref in valid_ids]
        item["evidence_refs"] = _unique(item.get("evidence_refs") or [])
        if evidence_ids is not None:
            invalid_evidence = [ref for ref in item["evidence_refs"] if ref not in evidence_ids]
            if invalid_evidence:
                warnings.append(
                    f"{framework} candidate {index} referenced unknown evidence IDs: {', '.join(invalid_evidence)}"
                )
                item["evidence_refs"] = [ref for ref in item["evidence_refs"] if ref in evidence_ids]
        if framework == "LINDDUN" and item["threat_category"] == "Non-compliance":
            # Both an explicit obligation and relevant evidence are required
            # before a non-compliance claim can be treated as a finding.  If
            # either side is missing, the item is still useful as review
            # context, but must not read as a legal conclusion.
            if not str(item.get("obligation") or "").strip() or not item["evidence_refs"]:
                warnings.append(
                    f"LINDDUN candidate {index}: non-compliance requires both an obligation and relevant evidence"
                )
                item["finding_status"] = "needs_context"
                item["status"] = "Needs Info"
                item["non_compliance_assertion"] = "unsubstantiated"
        if framework == "LINDDUN":
            # Missing classification is uncertainty, not proof that the data
            # is PII. Keep an explicit value for downstream consumers without
            # promoting a privacy/security assumption to fact.
            item["data_classification"] = str(item.get("data_classification") or "Unknown").strip() or "Unknown"
        item["preconditions"] = item.get("preconditions") or []
        item["validation_steps"] = item.get("validation_steps") or []
        if isinstance(dfd_model, dict):
            item["analyzed_revision"] = dfd_model.get("revision")
            item["analysis_revision"] = dfd_model.get("revision")
            item["dfd_semantic_hash"] = dfd_model.get("semantic_hash")
        accepted.append(item)
    return accepted, warnings


def validate_coverage(
    coverage: Iterable[dict],
    dfd_model: dict | None = None,
    framework: str | None = None,
) -> tuple[list[dict], list[str]]:
    """Keep only coverage entries that refer to the current canonical model."""
    valid_ids = _model_ids(dfd_model, include_review_elements=True)
    accepted = []
    warnings = []
    statuses = {"reviewed_no_candidate", "candidate_identified", "insufficient_information"}
    allowed_categories = STRIDE_CATEGORIES if framework == "STRIDE" else set(LINDDUN_CATEGORY_ALIASES)
    for index, raw in enumerate(coverage or []):
        if not isinstance(raw, dict):
            warnings.append(f"Dropped coverage item {index}: result was not an object")
            continue
        element_ref = str(raw.get("element_ref") or "").strip()
        status = str(raw.get("status") or "").strip()
        if valid_ids and element_ref not in valid_ids:
            warnings.append(f"Dropped coverage item {index}: unknown DFD ID {element_ref or '(missing)'}")
            continue
        if status not in statuses:
            warnings.append(f"Dropped coverage item {index}: unsupported status {status or '(missing)'}")
            continue
        category = str(raw.get("category") or "").strip()
        if framework and category not in allowed_categories:
            warnings.append(f"Dropped coverage item {index}: unsupported category {category or '(missing)'}")
            continue
        if framework == "LINDDUN":
            category = LINDDUN_CATEGORY_ALIASES.get(category, category)
        applicability = str(raw.get("applicability") or "unknown").strip().lower()
        if applicability not in {"applicable", "not_applicable", "unknown"}:
            warnings.append(f"Dropped coverage item {index}: unsupported applicability {applicability}")
            continue
        rationale = str(raw.get("applicability_rationale") or raw.get("rationale") or "").strip()
        if applicability == "not_applicable" and not rationale:
            warnings.append(f"Dropped coverage item {index}: not_applicable requires a rationale")
            continue
        mapping_refs = _unique(raw.get("mapping_refs") or raw.get("interaction_refs") or [])
        if valid_ids and mapping_refs:
            invalid_mapping = [ref for ref in mapping_refs if ref not in valid_ids]
            if invalid_mapping:
                warnings.append(f"Dropped unknown mapping IDs from coverage item {index}: {', '.join(invalid_mapping)}")
                mapping_refs = [ref for ref in mapping_refs if ref in valid_ids]
        accepted.append({
            "element_ref": element_ref,
            "category": category,
            "status": status,
            "reason": str(raw.get("reason") or "").strip(),
            "applicability": applicability,
            "applicability_rationale": rationale,
            "mapping_refs": mapping_refs,
        })
    return accepted, warnings


def complete_graph_coverage(
    coverage: Iterable[dict],
    threats: Iterable[dict],
    dfd_model: dict | None,
    framework: str,
) -> tuple[list[dict], dict]:
    """Make coverage explicit for every canonical element/category pair.

    Missing AI coverage is represented as ``insufficient_information`` rather
    than silently treated as a reviewed negative. A validated threat reference
    can promote only its own element/category pair to ``candidate_identified``;
    it never creates a threat finding by itself.
    """
    categories = tuple(sorted(STRIDE_CATEGORIES)) if framework == "STRIDE" else LINDDUN_CATEGORIES
    model = dfd_model if isinstance(dfd_model, dict) else {}
    element_items = []
    for collection in ("nodes", "data_objects", "flows", "boundaries"):
        for item in model.get(collection) or []:
            if isinstance(item, dict) and item.get("id"):
                element_items.append((str(item["id"]), collection[:-1] if collection.endswith("s") else collection))

    target_categories: dict[str, set[str]] = {}
    for threat in threats or []:
        if not isinstance(threat, dict) or str(threat.get("framework") or framework) != framework:
            continue
        category = str(threat.get("threat_category") or "").strip()
        if framework == "LINDDUN":
            category = LINDDUN_CATEGORY_ALIASES.get(category, category)
        if category not in categories:
            continue
        refs = threat.get("target_refs") or []
        if not refs:
            refs = [{"id": value} for value in (threat.get("affected_refs") or [])]
        for ref in refs:
            if isinstance(ref, dict) and ref.get("id"):
                target_categories.setdefault(str(ref["id"]), set()).add(category)

    accepted: dict[tuple[str, str], dict] = {}
    for item in coverage or []:
        if not isinstance(item, dict):
            continue
        element_ref = str(item.get("element_ref") or "").strip()
        category = str(item.get("category") or "").strip()
        if framework == "LINDDUN":
            category = LINDDUN_CATEGORY_ALIASES.get(category, category)
        if element_ref and category in categories:
            accepted[(element_ref, category)] = {
                "element_ref": element_ref,
                "category": category,
                "status": item.get("status") or "insufficient_information",
                "reason": str(item.get("reason") or "").strip(),
                "coverage_origin": "analysis_engine",
                "applicability": item.get("applicability") or "unknown",
                "applicability_rationale": item.get("applicability_rationale") or "",
                "mapping_refs": _unique(item.get("mapping_refs") or item.get("interaction_refs") or []),
            }

    for element_ref, element_type in element_items:
        for category in categories:
            key = (element_ref, category)
            targeted = category in target_categories.get(element_ref, set())
            current = accepted.get(key)
            if targeted:
                accepted[key] = {
                    **(current or {}),
                    "element_ref": element_ref,
                    "category": category,
                    "status": "candidate_identified",
                    "reason": (current or {}).get("reason") or "A validated threat candidate references this canonical element.",
                    "coverage_origin": "validated_threat_reference",
                    "applicability": (current or {}).get("applicability") or "applicable",
                    "applicability_rationale": (current or {}).get("applicability_rationale") or "A validated candidate demonstrates applicability to this element.",
                    "mapping_refs": (current or {}).get("mapping_refs") or [],
                }
            elif current:
                current["coverage_origin"] = current.get("coverage_origin") or "analysis_engine"
            else:
                accepted[key] = {
                    "element_ref": element_ref,
                    "category": category,
                    "status": "insufficient_information",
                    "reason": "No validated coverage entry was returned for this canonical element/category; absence is not evidence of no threat.",
                    "coverage_origin": "graph_completeness_gap",
                    "applicability": (current or {}).get("applicability") or "unknown",
                    "applicability_rationale": (current or {}).get("applicability_rationale") or "Applicability was not established by the analysis engine.",
                    "mapping_refs": (current or {}).get("mapping_refs") or [],
                }

    items = sorted(accepted.values(), key=lambda item: (item["element_ref"], categories.index(item["category"])))
    summary = {
        "framework": framework,
        "model_revision": model.get("revision"),
        "total": len(items),
        "reviewed_no_candidate": sum(item["status"] == "reviewed_no_candidate" for item in items),
        "candidate_identified": sum(item["status"] == "candidate_identified" for item in items),
        "insufficient_information": sum(item["status"] == "insufficient_information" for item in items),
        "applicable": sum(item.get("applicability") == "applicable" for item in items),
        "not_applicable": sum(item.get("applicability") == "not_applicable" for item in items),
        "unknown_applicability": sum(item.get("applicability") == "unknown" for item in items),
        "complete": bool(items) and all(item["status"] != "insufficient_information" for item in items),
        "element_types": {element_id: element_type for element_id, element_type in element_items},
    }
    return items, summary


def quarantine_report_threats(
    threats: Iterable[dict],
    dfd_model: dict | None,
) -> tuple[list[dict], list[dict]]:
    """Separate legacy, malformed, and stale findings before downstream use.

    The quarantined copy is intentionally retained for reviewer/audit recovery,
    while only current, revision-pinned findings remain active.  A missing
    revision is not silently upgraded to the current DFD revision.
    """
    model_revision = (dfd_model or {}).get("revision") if isinstance(dfd_model, dict) else None
    model_semantic_hash = (dfd_model or {}).get("semantic_hash") if isinstance(dfd_model, dict) else None
    valid_ids = _model_ids(dfd_model)
    active: list[dict] = []
    quarantined: list[dict] = []
    allowed_frameworks = {"STRIDE", "LINDDUN"}
    allowed_statuses = {"Open", "Needs Info", "Reviewed", "Accepted", "Mitigation Planned", "Mitigated", "Verified"}
    canonical_target_types = {
        "entity", "external_entity", "external_system", "process", "data_store",
        "data_flow", "flow", "boundary", "trust_boundary", "data_object",
    }
    seen_threat_ids: set[str] = set()

    for index, raw in enumerate(threats or []):
        reasons: list[str] = []
        item = dict(raw) if isinstance(raw, dict) else {"raw_type": type(raw).__name__}
        framework = str(item.get("framework") or "").strip().upper()
        threat_id = str(item.get("threat_id") or "").strip()
        if not threat_id:
            reasons.append("missing_threat_id")
        elif threat_id in seen_threat_ids:
            reasons.append("duplicate_threat_id")
        else:
            seen_threat_ids.add(threat_id)
        if framework not in allowed_frameworks:
            reasons.append("unsupported_framework")
        else:
            item["framework"] = framework
        if not str(item.get("threat_category") or "").strip():
            reasons.append("missing_threat_category")
        elif framework in allowed_frameworks:
            allowed_categories = STRIDE_CATEGORIES if framework == "STRIDE" else set(LINDDUN_CATEGORY_ALIASES)
            if item.get("threat_category") not in allowed_categories:
                reasons.append("unsupported_threat_category")
            elif framework == "LINDDUN":
                item["threat_category"] = LINDDUN_CATEGORY_ALIASES[item["threat_category"]]
        if not str(item.get("threat_description") or "").strip():
            reasons.append("missing_threat_description")
        affected_refs = item.get("affected_refs")
        if affected_refs is not None and not isinstance(affected_refs, list):
            reasons.append("malformed_affected_refs")
            affected_refs = []
        if isinstance(affected_refs, list) and any(not isinstance(ref, (str, int)) or not str(ref).strip() for ref in affected_refs):
            reasons.append("malformed_affected_refs")
        typed_refs = item.get("target_refs")
        if typed_refs is not None and not isinstance(typed_refs, list):
            reasons.append("malformed_target_refs")
            typed_refs = []
        if isinstance(typed_refs, list) and any(
            not isinstance(ref, dict) or not ref.get("id") or not ref.get("type")
            for ref in typed_refs
        ):
            reasons.append("malformed_target_refs")
        analysis_revision = item.get("analysis_revision")
        analyzed_revision = item.get("analyzed_revision")
        revision = analysis_revision if analysis_revision is not None else analyzed_revision
        if analysis_revision is None or analyzed_revision is None:
            reasons.append("missing_analysis_provenance")
        if model_revision and revision != model_revision:
            reasons.append("missing_or_stale_analysis_revision" if not revision else "stale_analysis_revision")
        if analysis_revision is not None and analyzed_revision is not None and analysis_revision != analyzed_revision:
            reasons.append("analysis_revision_mismatch")
        dfd_semantic_hash = item.get("dfd_semantic_hash")
        if model_semantic_hash and dfd_semantic_hash != model_semantic_hash:
            reasons.append("missing_or_stale_dfd_semantic_hash" if not dfd_semantic_hash else "stale_dfd_semantic_hash")
        expected_taxonomy = "stride-v1" if framework == "STRIDE" else "linddun-v1"
        if framework in allowed_frameworks and item.get("taxonomy_version") != expected_taxonomy:
            reasons.append("missing_or_unsupported_taxonomy_version")
        if item.get("status") and item.get("status") not in allowed_statuses:
            reasons.append("unsupported_threat_status")
        refs = affected_refs or []
        typed_refs = typed_refs or []
        canonical_typed_refs = {
            str(ref.get("id")) for ref in typed_refs
            if isinstance(ref, dict) and ref.get("id") and str(ref.get("type") or "") in canonical_target_types
        }
        ref_ids = {str(ref) for ref in refs if ref}
        unknown_refs = [ref_id for ref_id in ref_ids.union(canonical_typed_refs) if ref_id not in valid_ids]
        if valid_ids and unknown_refs:
            reasons.append("dangling_dfd_refs")
        if valid_ids and not ref_ids and not (canonical_typed_refs & valid_ids):
            reasons.append("missing_dfd_refs")
        if reasons:
            quarantined.append({
                "quarantine_id": f"threat-{index}-{str(item.get('threat_id') or 'unknown')}",
                "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "framework": framework or "unknown",
                "model_revision": model_revision,
                "reasons": reasons,
                "item": item,
            })
        else:
            active.append(item)
    return active, quarantined
