"""Validation and normalization for AI-generated threat candidates."""
from __future__ import annotations

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

    def __init__(self, threats=None, coverage=None):
        super().__init__(threats or [])
        self.coverage = coverage if isinstance(coverage, list) else []


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
        item["evidence_refs"] = _unique(item.get("evidence_refs") or [])
        if evidence_ids is not None:
            invalid_evidence = [ref for ref in item["evidence_refs"] if ref not in evidence_ids]
            if invalid_evidence:
                warnings.append(
                    f"{framework} candidate {index} referenced unknown evidence IDs: {', '.join(invalid_evidence)}"
                )
                item["evidence_refs"] = [ref for ref in item["evidence_refs"] if ref in evidence_ids]
        if framework == "LINDDUN" and item["threat_category"] == "Non-compliance":
            if not item.get("obligation") and not item["evidence_refs"]:
                warnings.append(
                    f"LINDDUN candidate {index}: non-compliance requires an obligation and relevant evidence"
                )
                item["finding_status"] = "needs_context"
                item["status"] = "Needs Info"
        item["preconditions"] = item.get("preconditions") or []
        item["validation_steps"] = item.get("validation_steps") or []
        if isinstance(dfd_model, dict):
            item["analyzed_revision"] = dfd_model.get("revision")
            item["analysis_revision"] = dfd_model.get("revision")
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
        accepted.append({
            "element_ref": element_ref,
            "category": category,
            "status": status,
            "reason": str(raw.get("reason") or "").strip(),
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
                }

    items = sorted(accepted.values(), key=lambda item: (item["element_ref"], categories.index(item["category"])))
    summary = {
        "framework": framework,
        "model_revision": model.get("revision"),
        "total": len(items),
        "reviewed_no_candidate": sum(item["status"] == "reviewed_no_candidate" for item in items),
        "candidate_identified": sum(item["status"] == "candidate_identified" for item in items),
        "insufficient_information": sum(item["status"] == "insufficient_information" for item in items),
        "complete": bool(items) and all(item["status"] != "insufficient_information" for item in items),
        "element_types": {element_id: element_type for element_id, element_type in element_items},
    }
    return items, summary
