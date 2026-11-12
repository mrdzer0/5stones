"""Deterministic CR6 quality gates for controls and verification scenarios.

The provider or template may propose an action, but the application owns
foreign-key integrity, DFD traceability, executable-test quality, and the
distinction between an actionable recommendation and verified effectiveness.
"""
from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from typing import Iterable


ACTION_QUALITY_SCHEMA_VERSION = "cr6-action-quality-v1"
_PLACEHOLDER_PATTERNS = (
    "setup test environment",
    "execute attack scenario",
    "verify defense",
    "test as appropriate",
    "check the system",
    "tbd",
)
_ASSERTION_TERMS = {
    "reject", "deny", "prevent", "only", "cannot", "absent", "masked",
    "restricted", "blocked", "unchanged", "recorded", "removed", "scoped",
    "returns", "status", "error", "fails",
}
_GENERIC_DISCLOSURE_TERMS = {"capture payload", "capture the payload", "compare fields"}
_STOPWORDS = {
    "the", "and", "for", "with", "from", "this", "that", "into", "when", "where",
    "user", "data", "system", "request", "response", "test", "verify", "check",
    "record", "field", "fields", "purpose", "recipient", "affected", "canonical",
}


def _text(value: object) -> str:
    return " ".join(str(value or "").split()).strip()


def _normalized(value: object) -> str:
    return _text(value).casefold()


def _tokens(value: object) -> set[str]:
    return {
        token for token in re.findall(r"[a-z0-9][a-z0-9_-]*", _normalized(value))
        if len(token) > 2 and token not in _STOPWORDS
    }


def _target_ids(item: dict) -> list[str]:
    return sorted({
        str(ref.get("id"))
        for ref in (item.get("target_refs") or [])
        if isinstance(ref, dict) and ref.get("id")
    })


def _threat_context(threat: dict | None) -> str:
    threat = threat if isinstance(threat, dict) else {}
    return " ".join(str(threat.get(field) or "") for field in (
        "threat_category", "mechanism", "attack_mechanism", "abuse_case", "scenario",
        "threat_description", "asset", "component", "source", "destination",
    ))


def test_quality_fingerprint(item: dict, threat: dict | None = None) -> str:
    """Stable semantic identity that intentionally excludes ``threat_id``.

    A provider often gives each finding a different ID while copying the same
    test. Target, mechanism, steps, and oracle are the meaningful identity.
    """
    payload = "|".join([
        ";".join(_target_ids(item)),
        " ".join(sorted(_tokens(_threat_context(threat)))),
        "|".join(_normalized(step) for step in (item.get("steps") or [])),
        _normalized(item.get("expected_result")),
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def _control_for_test(item: dict, controls_by_id: dict[str, dict], threat_id: str) -> dict | None:
    control_id = _text(item.get("related_control_id"))
    control = controls_by_id.get(control_id) if control_id else None
    if not control and _text(item.get("related_control")):
        wanted = _normalized(item.get("related_control"))
        control = next(
            (candidate for candidate in controls_by_id.values()
             if _normalized(candidate.get("name")) == wanted),
            None,
        )
    if not control or str(threat_id) not in {str(value) for value in (control.get("threat_ids") or [])}:
        return None
    if str(control.get("mapping_status") or "mapped").casefold() == "unassigned":
        return None
    return control


def validate_test_scenarios(
    scenarios: Iterable[dict],
    threats: Iterable[dict],
    controls: Iterable[dict] | None = None,
    dfd_model: dict | None = None,
) -> tuple[list[dict], list[str]]:
    """Mark every scenario executable or explicitly blocked with reasons."""
    threat_by_id = {
        str(item.get("threat_id")): item
        for item in (threats or [])
        if isinstance(item, dict) and item.get("threat_id")
    }
    controls_by_id = {
        str(item.get("control_id")): item
        for item in (controls or [])
        if isinstance(item, dict) and item.get("control_id")
    }
    valid_dfd_ids = {
        str(item.get("id"))
        for collection in ("nodes", "data_objects", "flows", "boundaries")
        for item in ((dfd_model or {}).get(collection) or [])
        if isinstance(item, dict) and item.get("id")
    }
    result: list[dict] = []
    warnings: list[str] = []
    seen_quality: dict[str, str] = {}
    for index, raw in enumerate(scenarios or []):
        if not isinstance(raw, dict):
            continue
        item = deepcopy(raw)
        threat_id = _text(item.get("threat_id"))
        threat = threat_by_id.get(threat_id)
        issues: list[str] = []
        applicability = _normalized(item.get("applicability_status") or "applicable")
        if applicability not in {"applicable", "not_applicable", "blocked"}:
            applicability = "applicable"
        steps = [_text(step) for step in (item.get("steps") or []) if _text(step)]
        item["steps"] = steps
        item["quality_schema_version"] = ACTION_QUALITY_SCHEMA_VERSION
        item["quality_fingerprint"] = test_quality_fingerprint(item, threat)

        if applicability == "applicable":
            if len(_text(item.get("preconditions"))) < 20:
                issues.append("preconditions_not_actionable")
            if len(steps) < 3:
                issues.append("too_few_steps")
            if len({_normalized(step) for step in steps}) != len(steps):
                issues.append("duplicate_steps")
            combined = _normalized(" ".join(str(value or "") for value in [
                item.get("scenario_name"), *steps, item.get("expected_result"), _threat_context(threat),
            ]))
            if any(pattern in combined for pattern in _PLACEHOLDER_PATTERNS):
                issues.append("generic_placeholder_steps")
            expected = _text(item.get("expected_result"))
            expected_norm = _normalized(expected)
            assertion_patterns = (*_ASSERTION_TERMS, "reject", "den", "prevent", "remain", "never", "must")
            if len(expected) < 24 or not any(term in expected_norm for term in assertion_patterns):
                issues.append("expected_result_not_assertive")
            if not [_text(value) for value in (item.get("evidence_needed") or []) if _text(value)]:
                issues.append("execution_evidence_not_defined")
            if not threat:
                issues.append("threat_reference_missing")
            else:
                primary = _text(threat.get("primary_interaction_ref"))
                target_ids = set(_target_ids(item))
                if primary and valid_dfd_ids and primary not in valid_dfd_ids:
                    issues.append("primary_flow_invalid")
                elif primary and primary not in target_ids:
                    issues.append("primary_flow_target_missing")
                elif valid_dfd_ids and not primary and not target_ids:
                    issues.append("dfd_target_missing")
                if not _control_for_test(item, controls_by_id, threat_id) and controls is not None:
                    issues.append("mapped_control_missing")
            step_text = " ".join(_normalized(step) for step in steps)
            has_capture = "capture" in step_text and ("payload" in step_text or "request" in step_text)
            has_compare = "compare" in step_text and ("field" in step_text or "purpose" in step_text or "scope" in step_text)
            if has_capture and has_compare:
                specificity = _tokens(" ".join([
                    item.get("scenario_name"), item.get("expected_result"), _threat_context(threat),
                ]))
                if len(specificity.intersection(_tokens(" ".join(steps)))) < 2:
                    issues.append("generic_disclosure_sequence")

            fingerprint = item["quality_fingerprint"]
            if fingerprint in seen_quality:
                issues.append(f"duplicate_semantic_test:{seen_quality[fingerprint]}")
            else:
                seen_quality[fingerprint] = _text(item.get("test_id")) or f"scenario-{index}"
        elif applicability == "blocked":
            if len(_text(item.get("applicability_reason"))) < 12:
                issues.append("blocked_reason_missing")
        else:
            if len(_text(item.get("applicability_reason"))) < 12:
                issues.append("not_applicable_reason_missing")

        item["quality_issues"] = issues
        if applicability == "applicable" and issues:
            item["applicability_status"] = "blocked"
            item["execution_status"] = "Blocked"
            item["applicability_reason"] = (
                "CR6 quality gate blocked execution: " + ", ".join(issues)
            )
            item["quality_status"] = "blocked"
            warnings.append(f"Test {item.get('test_id') or index} blocked by quality gate: {', '.join(issues)}")
        elif applicability == "blocked":
            item["execution_status"] = "Blocked"
            item["quality_status"] = "blocked"
        elif applicability == "not_applicable":
            item["execution_status"] = "Blocked"
            item["quality_status"] = "not_applicable"
        else:
            item["quality_status"] = "executable"
        result.append(item)
    return result, warnings
