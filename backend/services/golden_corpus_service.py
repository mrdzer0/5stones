"""Offline golden-corpus evaluation for threat-model quality.

The evaluator is intentionally provider-independent.  It can score bundled
deterministic candidates for CI or externally generated report snapshots for
model/provider qualification without changing production project data.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Iterable

from backend.services.control_service import _catalog_fallback
from backend.services.test_service import generate_test_scenarios
from backend.utils.storage import get_controls_catalog


GOLDEN_CORPUS_SCHEMA_VERSION = "threat-model-golden-v1"
EVALUATOR_VERSION = "golden-evaluator-v1.0"
DEFAULT_CORPUS_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "threat_model_golden_corpus.json"

_FRAMEWORKS = {"STRIDE", "LINDDUN"}
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
}


class GoldenCorpusError(ValueError):
    """Raised when a corpus or candidate snapshot violates the eval contract."""


def _normalized(value: object) -> str:
    return " ".join(str(value or "").casefold().split())


def _tokens(value: object) -> set[str]:
    return {
        token for token in re.findall(r"[a-z0-9]+", _normalized(value))
        if len(token) > 2
    }


def _safe_ratio(numerator: int, denominator: int, *, empty: float = 0.0) -> float:
    return round(numerator / denominator, 4) if denominator else empty


def _content_hash(value: object) -> str:
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _active(items: Iterable[dict]) -> list[dict]:
    return [
        item for item in items or []
        if isinstance(item, dict) and item.get("analysis_state") != "historical"
    ]


def _control_key(control: dict) -> str:
    catalog_id = str(control.get("catalog_id") or "").strip()
    if catalog_id:
        return catalog_id
    control_id = str(control.get("control_id") or "").strip()
    if control_id.startswith("CAT-"):
        return control_id[4:]
    return _normalized(control.get("name"))


def load_golden_corpus(path: str | Path = DEFAULT_CORPUS_PATH) -> dict:
    corpus_path = Path(path)
    try:
        payload = json.loads(corpus_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GoldenCorpusError(f"Cannot load golden corpus: {corpus_path}") from exc
    validate_golden_corpus(payload)
    return payload


def validate_golden_corpus(corpus: dict) -> None:
    if not isinstance(corpus, dict) or corpus.get("schema_version") != GOLDEN_CORPUS_SCHEMA_VERSION:
        raise GoldenCorpusError(f"schema_version must be {GOLDEN_CORPUS_SCHEMA_VERSION}")
    cases = corpus.get("cases")
    if not isinstance(cases, list) or not cases:
        raise GoldenCorpusError("Golden corpus must contain at least one case")
    thresholds = corpus.get("thresholds")
    required_thresholds = {
        "max_unsupported_finding_rate", "min_finding_precision", "min_finding_recall",
        "min_mapping_precision", "min_mapping_recall", "min_test_executability_rate",
        "min_blocked_test_accuracy",
    }
    if not isinstance(thresholds, dict) or not required_thresholds.issubset(thresholds):
        raise GoldenCorpusError("Golden corpus thresholds are incomplete")
    if any(not isinstance(thresholds[key], (int, float)) or not 0 <= thresholds[key] <= 1 for key in required_thresholds):
        raise GoldenCorpusError("Every golden corpus threshold must be between 0 and 1")

    case_ids: set[str] = set()
    positive_findings = 0
    negative_cases = 0
    for case in cases:
        if not isinstance(case, dict) or not str(case.get("case_id") or "").strip():
            raise GoldenCorpusError("Every case requires case_id")
        case_id = str(case["case_id"])
        if case_id in case_ids:
            raise GoldenCorpusError(f"Duplicate case_id: {case_id}")
        case_ids.add(case_id)
        expected = case.get("expected")
        if not isinstance(expected, dict):
            raise GoldenCorpusError(f"{case_id}: expected labels are required")
        findings = expected.get("findings")
        if not isinstance(findings, list):
            raise GoldenCorpusError(f"{case_id}: expected.findings must be a list")
        positive_findings += len(findings)
        negative_cases += int(not findings)
        golden_ids = set()
        flow_ids = {
            str(item.get("id"))
            for item in ((case.get("dfd_model") or {}).get("flows") or [])
            if isinstance(item, dict) and item.get("id")
        }
        for finding in findings:
            golden_id = str(finding.get("golden_id") or "")
            if not golden_id or golden_id in golden_ids:
                raise GoldenCorpusError(f"{case_id}: findings require unique golden_id values")
            golden_ids.add(golden_id)
            if finding.get("framework") not in _FRAMEWORKS:
                raise GoldenCorpusError(f"{case_id}/{golden_id}: unsupported framework")
            if not str(finding.get("category") or "").strip() or not finding.get("match_terms"):
                raise GoldenCorpusError(f"{case_id}/{golden_id}: category and match_terms are required")
            if str(finding.get("primary_interaction_ref") or "") not in flow_ids:
                raise GoldenCorpusError(f"{case_id}/{golden_id}: primary interaction is not a corpus DFD flow")
        for mapping in expected.get("control_mappings") or []:
            if not mapping.get("control_key") or not set(mapping.get("golden_finding_ids") or []).issubset(golden_ids):
                raise GoldenCorpusError(f"{case_id}: invalid expected control mapping")
        for test in expected.get("tests") or []:
            if test.get("golden_finding_id") not in golden_ids:
                raise GoldenCorpusError(f"{case_id}: expected test references an unknown golden finding")
            if test.get("applicability") not in {"applicable", "blocked"}:
                raise GoldenCorpusError(f"{case_id}: expected test applicability must be applicable or blocked")
    if positive_findings < 3 or negative_cases < 1:
        raise GoldenCorpusError("Corpus must include at least three positive findings and one no-finding negative case")


def _finding_text(item: dict) -> str:
    values = [item.get(field) for field in (
        "title", "threat_description", "scenario", "abuse_case", "asset",
        "component", "source", "destination",
    )]
    return _normalized(" ".join(str(value or "") for value in values))


def _match_findings(expected: list[dict], actual: list[dict]) -> tuple[dict[str, dict], dict[str, str], list[dict]]:
    remaining = {str(item.get("threat_id") or f"actual-{index}"): item for index, item in enumerate(actual)}
    by_golden: dict[str, dict] = {}
    actual_to_golden: dict[str, str] = {}
    for label in expected:
        terms = [_normalized(term) for term in label.get("match_terms") or [] if _normalized(term)]
        candidates = []
        for threat_id, item in remaining.items():
            if item.get("framework") != label.get("framework"):
                continue
            if _normalized(item.get("threat_category")) != _normalized(label.get("category")):
                continue
            text = _finding_text(item)
            if not all(term in text for term in terms):
                continue
            overlap = len(_tokens(text).intersection(_tokens(" ".join(terms))))
            candidates.append((overlap, threat_id, item))
        if not candidates:
            continue
        _, threat_id, item = sorted(candidates, key=lambda value: (-value[0], value[1]))[0]
        golden_id = str(label["golden_id"])
        by_golden[golden_id] = item
        actual_to_golden[threat_id] = golden_id
        remaining.pop(threat_id, None)
    return by_golden, actual_to_golden, list(remaining.values())


def _expected_control_edges(expected: dict) -> set[tuple[str, str, str]]:
    return {
        ("control_to_finding", str(mapping["control_key"]), str(golden_id))
        for mapping in expected.get("control_mappings") or []
        for golden_id in mapping.get("golden_finding_ids") or []
    }


def _test_quality(test: dict, threat: dict, controls_by_id: dict[str, dict], label: dict) -> tuple[bool, list[str]]:
    reasons = []
    applicability = str(test.get("applicability_status") or "applicable").casefold()
    expected_applicability = label.get("applicability")
    if expected_applicability == "blocked":
        if applicability != "blocked" or test.get("execution_status") != "Blocked":
            reasons.append("expected_blocked_state_missing")
        if len(str(test.get("applicability_reason") or "").strip()) < 12:
            reasons.append("blocked_reason_missing")
        return not reasons, reasons

    if applicability != "applicable" or test.get("execution_status") == "Blocked":
        reasons.append("test_not_applicable")
    preconditions = str(test.get("preconditions") or "").strip()
    if len(preconditions) < 20:
        reasons.append("preconditions_not_actionable")
    steps = [str(step).strip() for step in (test.get("steps") or []) if str(step).strip()]
    if len(steps) < int(label.get("min_steps") or 3):
        reasons.append("too_few_steps")
    if len({_normalized(step) for step in steps}) != len(steps):
        reasons.append("duplicate_steps")
    joined = _normalized(" ".join([test.get("scenario_name") or "", *steps, test.get("expected_result") or ""]))
    if any(pattern in joined for pattern in _PLACEHOLDER_PATTERNS):
        reasons.append("generic_placeholder_steps")
    mechanism_terms = [_normalized(term) for term in label.get("mechanism_terms_any") or [] if _normalized(term)]
    if mechanism_terms and not any(term in joined for term in mechanism_terms):
        reasons.append("expected_mechanism_missing")
    expected_result = str(test.get("expected_result") or "").strip()
    if len(expected_result) < 24 or not any(term in _normalized(expected_result) for term in _ASSERTION_TERMS):
        reasons.append("expected_result_not_assertive")
    if not [value for value in (test.get("evidence_needed") or []) if str(value).strip()]:
        reasons.append("execution_evidence_not_defined")
    target_ids = {
        str(ref.get("id")) for ref in (test.get("target_refs") or [])
        if isinstance(ref, dict) and ref.get("id")
    }
    if str(threat.get("primary_interaction_ref") or "") not in target_ids:
        reasons.append("primary_flow_target_missing")
    control_id = str(test.get("related_control_id") or "")
    control = controls_by_id.get(control_id)
    if not control or str(threat.get("threat_id")) not in {str(value) for value in control.get("threat_ids") or []}:
        reasons.append("mapped_control_missing")
    return not reasons, reasons


def evaluate_golden_case(case: dict, report: dict) -> dict:
    expected = case["expected"]
    threats = _active(report.get("threats") or [])
    controls = _active(report.get("controls") or [])
    tests = _active(report.get("test_scenarios") or [])
    matched, actual_to_golden, unsupported = _match_findings(expected.get("findings") or [], threats)

    expected_findings = len(expected.get("findings") or [])
    predicted_findings = len(threats)
    matched_findings = len(matched)
    unsupported_asserted = sum(
        item.get("finding_state") in {"grounded", "reviewed", "verified"}
        or item.get("risk_status") == "assessed"
        for item in unsupported
    )

    expected_threat_edges = {
        ("finding_to_flow", str(label["golden_id"]), str(label["primary_interaction_ref"]))
        for label in expected.get("findings") or []
    }
    actual_threat_edges = {
        (
            "finding_to_flow",
            actual_to_golden.get(str(item.get("threat_id") or ""), "__unsupported__"),
            str(item.get("primary_interaction_ref") or "__missing__"),
        )
        for item in threats
    }
    expected_control_edges = _expected_control_edges(expected)
    actual_control_edges = set()
    for control in controls:
        if control.get("mapping_status") == "unassigned":
            continue
        key = _control_key(control)
        for threat_id in control.get("threat_ids") or []:
            actual_control_edges.add((
                "control_to_finding", key,
                actual_to_golden.get(str(threat_id), "__unsupported__"),
            ))

    expected_test_edges = {
        (
            "test_to_finding",
            str(label["golden_finding_id"]),
            str(label.get("applicability") or "applicable"),
        )
        for label in expected.get("tests") or []
    }
    actual_test_edges = {
        (
            "test_to_finding",
            actual_to_golden.get(str(item.get("threat_id") or ""), "__unsupported__"),
            "blocked" if item.get("applicability_status") == "blocked" else "applicable",
        )
        for item in tests
    }
    expected_mapping_edges = expected_threat_edges | expected_control_edges | expected_test_edges
    actual_mapping_edges = actual_threat_edges | actual_control_edges | actual_test_edges
    correct_mapping_edges = expected_mapping_edges.intersection(actual_mapping_edges)

    controls_by_id = {
        str(item.get("control_id")): item for item in controls if item.get("control_id")
    }
    test_results = []
    used_test_ids: set[str] = set()
    for label in expected.get("tests") or []:
        golden_id = str(label["golden_finding_id"])
        threat = matched.get(golden_id)
        candidates = [
            item for item in tests
            if threat and str(item.get("threat_id")) == str(threat.get("threat_id"))
            and str(item.get("test_id") or id(item)) not in used_test_ids
        ]
        selected = candidates[0] if candidates else None
        if selected:
            used_test_ids.add(str(selected.get("test_id") or id(selected)))
            passed, reasons = _test_quality(selected, threat, controls_by_id, label)
        else:
            passed, reasons = False, ["expected_test_missing"]
        test_results.append({
            "golden_finding_id": golden_id,
            "expected_applicability": label.get("applicability"),
            "test_id": selected.get("test_id") if selected else None,
            "passed": passed,
            "reasons": reasons,
        })

    applicable_results = [item for item in test_results if item["expected_applicability"] == "applicable"]
    blocked_results = [item for item in test_results if item["expected_applicability"] == "blocked"]
    counters = {
        "expected_findings": expected_findings,
        "predicted_findings": predicted_findings,
        "matched_findings": matched_findings,
        "unsupported_findings": len(unsupported),
        "unsupported_asserted_findings": unsupported_asserted,
        "expected_mapping_edges": len(expected_mapping_edges),
        "predicted_mapping_edges": len(actual_mapping_edges),
        "correct_mapping_edges": len(correct_mapping_edges),
        "expected_applicable_tests": len(applicable_results),
        "executable_tests": sum(item["passed"] for item in applicable_results),
        "expected_blocked_tests": len(blocked_results),
        "correctly_blocked_tests": sum(item["passed"] for item in blocked_results),
    }
    return {
        "case_id": case["case_id"],
        "title": case.get("title") or case["case_id"],
        "counters": counters,
        "metrics": _metrics_from_counters(counters),
        "matched_findings": sorted(matched),
        "missing_findings": sorted(
            str(item["golden_id"]) for item in expected.get("findings") or []
            if str(item["golden_id"]) not in matched
        ),
        "unsupported_findings": [
            {
                "threat_id": item.get("threat_id"),
                "framework": item.get("framework"),
                "category": item.get("threat_category"),
                "state": item.get("finding_state"),
                "primary_interaction_ref": item.get("primary_interaction_ref"),
            }
            for item in unsupported
        ],
        "mapping_false_positives": sorted([list(edge) for edge in actual_mapping_edges - expected_mapping_edges]),
        "mapping_false_negatives": sorted([list(edge) for edge in expected_mapping_edges - actual_mapping_edges]),
        "test_results": test_results,
    }


def _metrics_from_counters(counters: dict) -> dict:
    return {
        "unsupported_finding_rate": _safe_ratio(
            counters["unsupported_findings"], counters["predicted_findings"], empty=0.0
        ),
        "finding_precision": _safe_ratio(
            counters["matched_findings"], counters["predicted_findings"],
            empty=1.0 if counters["expected_findings"] == 0 else 0.0,
        ),
        "finding_recall": _safe_ratio(
            counters["matched_findings"], counters["expected_findings"],
            empty=1.0 if counters["predicted_findings"] == 0 else 0.0,
        ),
        "mapping_precision": _safe_ratio(
            counters["correct_mapping_edges"], counters["predicted_mapping_edges"],
            empty=1.0 if counters["expected_mapping_edges"] == 0 else 0.0,
        ),
        "mapping_recall": _safe_ratio(
            counters["correct_mapping_edges"], counters["expected_mapping_edges"], empty=1.0
        ),
        "test_executability_rate": _safe_ratio(
            counters["executable_tests"], counters["expected_applicable_tests"], empty=1.0
        ),
        "blocked_test_accuracy": _safe_ratio(
            counters["correctly_blocked_tests"], counters["expected_blocked_tests"], empty=1.0
        ),
    }


def _gate(metrics: dict, thresholds: dict) -> dict:
    checks = {
        "unsupported_finding_rate": {
            "passed": metrics["unsupported_finding_rate"] <= thresholds["max_unsupported_finding_rate"],
            "actual": metrics["unsupported_finding_rate"],
            "operator": "<=",
            "threshold": thresholds["max_unsupported_finding_rate"],
        },
        "finding_precision": {
            "passed": metrics["finding_precision"] >= thresholds["min_finding_precision"],
            "actual": metrics["finding_precision"],
            "operator": ">=",
            "threshold": thresholds["min_finding_precision"],
        },
        "finding_recall": {
            "passed": metrics["finding_recall"] >= thresholds["min_finding_recall"],
            "actual": metrics["finding_recall"],
            "operator": ">=",
            "threshold": thresholds["min_finding_recall"],
        },
        "mapping_precision": {
            "passed": metrics["mapping_precision"] >= thresholds["min_mapping_precision"],
            "actual": metrics["mapping_precision"],
            "operator": ">=",
            "threshold": thresholds["min_mapping_precision"],
        },
        "mapping_recall": {
            "passed": metrics["mapping_recall"] >= thresholds["min_mapping_recall"],
            "actual": metrics["mapping_recall"],
            "operator": ">=",
            "threshold": thresholds["min_mapping_recall"],
        },
        "test_executability_rate": {
            "passed": metrics["test_executability_rate"] >= thresholds["min_test_executability_rate"],
            "actual": metrics["test_executability_rate"],
            "operator": ">=",
            "threshold": thresholds["min_test_executability_rate"],
        },
        "blocked_test_accuracy": {
            "passed": metrics["blocked_test_accuracy"] >= thresholds["min_blocked_test_accuracy"],
            "actual": metrics["blocked_test_accuracy"],
            "operator": ">=",
            "threshold": thresholds["min_blocked_test_accuracy"],
        },
    }
    return {"passed": all(item["passed"] for item in checks.values()), "checks": checks}


def evaluate_golden_corpus(corpus: dict, reports_by_case: dict[str, dict]) -> dict:
    validate_golden_corpus(corpus)
    missing_reports = [case["case_id"] for case in corpus["cases"] if case["case_id"] not in reports_by_case]
    if missing_reports:
        raise GoldenCorpusError(f"Missing candidate reports for: {', '.join(missing_reports)}")
    case_results = [
        evaluate_golden_case(case, reports_by_case[case["case_id"]])
        for case in corpus["cases"]
    ]
    aggregate = {
        key: sum(result["counters"][key] for result in case_results)
        for key in case_results[0]["counters"]
    }
    metrics = _metrics_from_counters(aggregate)
    gate = _gate(metrics, corpus["thresholds"])
    slices = {}
    for slice_name in ("STRIDE", "LINDDUN", "negative"):
        selected = [
            result for result, case in zip(case_results, corpus["cases"])
            if slice_name in (case.get("tags") or [])
        ]
        if not selected:
            continue
        counters = {
            key: sum(result["counters"][key] for result in selected)
            for key in selected[0]["counters"]
        }
        slices[slice_name] = {"case_count": len(selected), "counters": counters, "metrics": _metrics_from_counters(counters)}
    corpus_for_hash = {key: value for key, value in corpus.items() if not key.startswith("_")}
    corpus_hash = _content_hash(corpus_for_hash)
    candidate_hash = _content_hash(reports_by_case)
    return {
        "schema_version": GOLDEN_CORPUS_SCHEMA_VERSION,
        "evaluator_version": EVALUATOR_VERSION,
        "corpus_id": corpus.get("corpus_id"),
        "corpus_revision": corpus.get("revision"),
        "corpus_hash": corpus_hash,
        "candidate_hash": candidate_hash,
        "evaluation_fingerprint": _content_hash({
            "evaluator_version": EVALUATOR_VERSION,
            "corpus_hash": corpus_hash,
            "candidate_hash": candidate_hash,
        }),
        "case_count": len(case_results),
        "candidate_source": "external_snapshots" if corpus.get("_external_reports") else "bundled_offline_pipeline",
        "counters": aggregate,
        "metrics": metrics,
        "thresholds": deepcopy(corpus["thresholds"]),
        "gate": gate,
        "slices": slices,
        "cases": case_results,
    }


async def materialize_offline_reports(corpus: dict) -> dict[str, dict]:
    """Run current deterministic control/test logic over labelled threat candidates."""
    reports = {}
    catalog = get_controls_catalog()
    for case in corpus["cases"]:
        threats = deepcopy(case.get("candidate_threats") or [])
        controls = _catalog_fallback(threats, catalog)
        tests = await generate_test_scenarios(
            threats,
            case.get("project") or {},
            force_fallback=True,
            controls=controls,
            dfd_model=case.get("dfd_model") or {},
        )
        reports[case["case_id"]] = {
            "threats": threats,
            "controls": list(controls),
            "test_scenarios": list(tests),
        }
    return reports


def _load_external_reports(path: str | Path) -> dict[str, dict]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GoldenCorpusError(f"Cannot load candidate reports: {path}") from exc
    if not isinstance(payload, dict):
        raise GoldenCorpusError("Candidate report snapshot must be an object keyed by case_id")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate threat-model output against the versioned golden corpus")
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS_PATH))
    parser.add_argument("--reports", help="JSON object keyed by case_id; omit to run bundled offline candidates")
    parser.add_argument("--output", help="Optional JSON result path")
    parser.add_argument("--no-fail", action="store_true", help="Always exit zero while retaining gate status")
    args = parser.parse_args(argv)
    try:
        corpus = load_golden_corpus(args.corpus)
        if args.reports:
            reports = _load_external_reports(args.reports)
            corpus["_external_reports"] = True
        else:
            reports = asyncio.run(materialize_offline_reports(corpus))
        result = evaluate_golden_corpus(corpus, reports)
    except GoldenCorpusError as exc:
        print(json.dumps({"gate": {"passed": False}, "error": str(exc)}, indent=2))
        return 2
    rendered = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
    print(rendered)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    return 0 if result["gate"]["passed"] or args.no_fail else 1


if __name__ == "__main__":
    raise SystemExit(main())
