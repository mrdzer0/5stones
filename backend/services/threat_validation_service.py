"""Validation and normalization for AI-generated threat candidates."""
from __future__ import annotations

from typing import Iterable


class ThreatGenerationResult(list):
    """List-compatible AI result that preserves the separate coverage array."""

    def __init__(self, threats=None, coverage=None):
        super().__init__(threats or [])
        self.coverage = coverage if isinstance(coverage, list) else []


STRIDE_CATEGORIES = {
    "Spoofing", "Tampering", "Repudiation", "Information Disclosure",
    "Denial of Service", "Elevation of Privilege",
}

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


def _unique(values: Iterable[str]) -> list[str]:
    result = []
    seen = set()
    for value in values or []:
        text = str(value or "").strip()
        if text and text.casefold() not in seen:
            seen.add(text.casefold())
            result.append(text)
    return result


def _model_ids(dfd_model: dict | None) -> set[str]:
    if not isinstance(dfd_model, dict):
        return set()
    ids = set()
    for collection in ("nodes", "data_objects", "flows", "boundaries", "zones", "views", "questions"):
        ids.update(str(item.get("id")) for item in (dfd_model.get(collection) or []) if isinstance(item, dict) and item.get("id"))
    return ids


def validate_generated_threats(
    threats: Iterable[dict],
    framework: str,
    dfd_model: dict | None = None,
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
        item = dict(raw)
        category = str(item.get("threat_category") or "").strip()
        description = str(item.get("threat_description") or "").strip()
        if category not in allowed_categories:
            warnings.append(f"Dropped {framework} candidate {index}: unsupported category {category or '(missing)'}")
            continue
        if not description:
            warnings.append(f"Dropped {framework} candidate {index}: missing threat description")
            continue
        if framework == "LINDDUN":
            item["threat_category"] = LINDDUN_CATEGORY_ALIASES.get(category, category)
        item["framework"] = framework
        item["taxonomy_version"] = str(item.get("taxonomy_version") or "unversioned")
        item["affected_refs"] = _unique(item.get("affected_refs") or [])
        if valid_ids:
            invalid_refs = [ref for ref in item["affected_refs"] if ref not in valid_ids]
            if invalid_refs:
                warnings.append(
                    f"{framework} candidate {index} referenced unknown DFD IDs: {', '.join(invalid_refs)}"
                )
                item["affected_refs"] = [ref for ref in item["affected_refs"] if ref in valid_ids]
        item["preconditions"] = item.get("preconditions") or []
        item["validation_steps"] = item.get("validation_steps") or []
        accepted.append(item)
    return accepted, warnings


def validate_coverage(coverage: Iterable[dict], dfd_model: dict | None = None) -> tuple[list[dict], list[str]]:
    """Keep only coverage entries that refer to the current canonical model."""
    valid_ids = _model_ids(dfd_model)
    accepted = []
    warnings = []
    statuses = {"reviewed_no_candidate", "candidate_identified", "insufficient_information"}
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
        accepted.append({
            "element_ref": element_ref,
            "category": str(raw.get("category") or ""),
            "status": status,
            "reason": str(raw.get("reason") or "").strip(),
        })
    return accepted, warnings
