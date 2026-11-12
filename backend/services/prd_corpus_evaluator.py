"""Fail-closed quality evaluation for PRD corpus E2E results.

The golden-corpus evaluator covers deterministic finding/control/test logic.
This evaluator covers provenance, ingestion, DFD quality, framework validity,
and release readiness for the broader PRD corpus journey.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


EVALUATOR_VERSION = "prd-corpus-evaluator-v1.2"
RESULT_EVALUATION_SCHEMA_VERSION = "prd-corpus-evaluation-v1"
TARGET_RESULT_SCHEMA_VERSION = "prd-corpus-e2e-v2"
LEGACY_RESULT_SCHEMA_VERSION = "prd-corpus-e2e-v1"
CONTRACT_SCHEMA_VERSION = "prd-corpus-metrics-v1"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RESULTS_PATH = PROJECT_ROOT / "tests" / "prd_corpus" / "e2e_results.json"
DEFAULT_MANIFEST_PATH = PROJECT_ROOT / "tests" / "prd_corpus" / "manifest.json"
DEFAULT_CONTRACT_PATH = PROJECT_ROOT / "tests" / "prd_corpus" / "metric_contract.json"

REQUIRED_METRICS = (
    "ingestion_coverage",
    "dfd_entity_recall",
    "dfd_precision",
    "duplicate_rate",
    "topology_validity",
    "framework_validation",
    "finding_precision",
    "finding_recall",
    "deferred_recall",
    "control_mapping_precision",
    "control_mapping_recall",
    "test_executability",
)
PROVENANCE_FIELDS = (
    "application_commit",
    "provider",
    "model",
    "timeout_seconds",
    "retry_config",
    "batch_config",
    "source_revision",
    "source_hash",
    "dfd_revision",
    "dfd_semantic_hash",
    "run_id",
)
SAFE_PROVIDER_METADATA = {
    "provider_attempts",
    "format_retry_count",
    "retry_reasons",
    "finish_reason",
    "usage",
    "parse_status",
    "response_shape",
    "truncation_suspected",
    "error_code",
    "latency_ms",
    "http_status",
    "batch_id",
    "flow_refs",
    "status",
    "redacted_response_hash",
}


class PRDCorpusEvaluationError(ValueError):
    """Raised when the PRD corpus contract cannot be evaluated safely."""


def _read_json(path: str | Path) -> dict:
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PRDCorpusEvaluationError(f"Cannot load JSON artifact: {source}") from exc
    if not isinstance(payload, dict):
        raise PRDCorpusEvaluationError(f"JSON artifact must be an object: {source}")
    return payload


def _canonical_hash_value(value: Any) -> Any:
    """Normalize integral floats so JS and Python fingerprint the same JSON number."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, list):
        return [_canonical_hash_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _canonical_hash_value(item) for key, item in value.items()}
    return value


def _content_hash(value: Any) -> str:
    rendered = json.dumps(_canonical_hash_value(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _file_hash(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator > 0 else None


def _relative_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def validate_metric_contract(contract: dict) -> None:
    if contract.get("schema_version") != CONTRACT_SCHEMA_VERSION:
        raise PRDCorpusEvaluationError(
            f"metric contract schema_version must be {CONTRACT_SCHEMA_VERSION}"
        )
    if not str(contract.get("contract_id") or "").strip():
        raise PRDCorpusEvaluationError("metric contract requires contract_id")
    if contract.get("corpus_result_schema_version") != TARGET_RESULT_SCHEMA_VERSION:
        raise PRDCorpusEvaluationError("metric contract has an unsupported result schema version")
    legacy_versions = contract.get("accepted_legacy_result_schema_versions")
    if not isinstance(legacy_versions, list) or LEGACY_RESULT_SCHEMA_VERSION not in legacy_versions:
        raise PRDCorpusEvaluationError("metric contract must explicitly declare the legacy result schema")
    if contract.get("evaluator_version") != EVALUATOR_VERSION:
        raise PRDCorpusEvaluationError("metric contract evaluator_version does not match implementation")
    provenance = contract.get("required_provenance")
    if not isinstance(provenance, list) or set(PROVENANCE_FIELDS) - set(provenance):
        raise PRDCorpusEvaluationError("metric contract is missing required provenance fields")
    definitions = contract.get("metrics")
    if not isinstance(definitions, list):
        raise PRDCorpusEvaluationError("metric contract metrics must be a list")
    names = [str(item.get("name") or "") for item in definitions if isinstance(item, dict)]
    if set(REQUIRED_METRICS) != set(names) or len(names) != len(set(names)):
        raise PRDCorpusEvaluationError("metric contract must define every required metric exactly once")
    thresholds = contract.get("thresholds")
    if not isinstance(thresholds, dict) or not thresholds:
        raise PRDCorpusEvaluationError("metric contract thresholds are required")
    if any(not isinstance(value, (int, float)) or not 0 <= value <= 1 for value in thresholds.values()):
        raise PRDCorpusEvaluationError("metric contract thresholds must be ratios between 0 and 1")


def validate_result_payload(results: dict) -> None:
    schema_version = results.get("schema_version")
    if schema_version not in {TARGET_RESULT_SCHEMA_VERSION, LEGACY_RESULT_SCHEMA_VERSION}:
        raise PRDCorpusEvaluationError(
            f"result schema_version must be {TARGET_RESULT_SCHEMA_VERSION} or {LEGACY_RESULT_SCHEMA_VERSION}"
        )
    if schema_version == TARGET_RESULT_SCHEMA_VERSION:
        root_provenance = results.get("provenance")
        if not isinstance(root_provenance, dict):
            raise PRDCorpusEvaluationError("v2 result requires root provenance")
        missing_root = [
            field for field in PROVENANCE_FIELDS[:7]
            if root_provenance.get(field) in (None, "", {})
        ]
        if missing_root:
            raise PRDCorpusEvaluationError(
                f"v2 result is missing root provenance: {', '.join(missing_root)}"
            )
    cases = results.get("cases")
    if not isinstance(cases, list) or not cases:
        raise PRDCorpusEvaluationError("PRD corpus result must contain cases")
    case_ids: set[str] = set()
    percentage_fields = (
        "coverage_pct", "dfd_entities_pct", "threat_topic_pct",
        "deferred_topic_pct", "framework_validation_pct", "overall_pct",
    )
    for case in cases:
        if not isinstance(case, dict) or not str(case.get("case_id") or "").strip():
            raise PRDCorpusEvaluationError("Every E2E result case requires case_id")
        case_id = str(case["case_id"])
        if case_id in case_ids:
            raise PRDCorpusEvaluationError(f"Duplicate result case_id: {case_id}")
        case_ids.add(case_id)
        for field in percentage_fields:
            if field in case and (
                not isinstance(case[field], (int, float)) or not 0 <= case[field] <= 100
            ):
                raise PRDCorpusEvaluationError(
                    f"{case_id}: {field} must be a percentage between 0 and 100"
                )
        if "signoff_ready" in case and not isinstance(case["signoff_ready"], bool):
            raise PRDCorpusEvaluationError(f"{case_id}: signoff_ready must be boolean")
        if schema_version == TARGET_RESULT_SCHEMA_VERSION:
            case_provenance = case.get("provenance")
            if not isinstance(case_provenance, dict):
                raise PRDCorpusEvaluationError(f"{case_id}: v2 result requires case provenance")
            missing_case = [
                field for field in ("source_revision", "source_hash", "dfd_revision", "dfd_semantic_hash", "run_id")
                if case_provenance.get(field) in (None, "", {})
            ]
            if missing_case:
                raise PRDCorpusEvaluationError(
                    f"{case_id}: v2 result is missing provenance: {', '.join(missing_case)}"
                )
            case_metrics = case.get("metrics")
            if not isinstance(case_metrics, dict):
                raise PRDCorpusEvaluationError(f"{case_id}: v2 result requires explicit metric counts")
            missing_metrics = [name for name in REQUIRED_METRICS if name not in case_metrics]
            if missing_metrics:
                raise PRDCorpusEvaluationError(
                    f"{case_id}: v2 result is missing metric counts: {', '.join(missing_metrics)}"
                )
    aggregate = results.get("aggregate")
    if aggregate is not None and (
        not isinstance(aggregate, dict) or aggregate.get("cases") not in {None, len(cases)}
    ):
        raise PRDCorpusEvaluationError("aggregate.cases does not match result cases")


def validate_manifest(manifest: dict, results: dict) -> None:
    manifest_cases = manifest.get("cases")
    if not isinstance(manifest_cases, list) or not manifest_cases:
        raise PRDCorpusEvaluationError("PRD manifest must contain cases")
    manifest_ids = {
        str(item.get("id") or "") for item in manifest_cases if isinstance(item, dict)
    }
    result_ids = {str(item.get("case_id") or "") for item in results["cases"]}
    missing = sorted(manifest_ids - result_ids)
    if missing:
        raise PRDCorpusEvaluationError(
            f"Missing E2E results for manifest cases: {', '.join(missing)}"
        )
    extra = sorted(result_ids - manifest_ids)
    if extra:
        raise PRDCorpusEvaluationError(
            f"E2E result contains cases absent from manifest: {', '.join(extra)}"
        )


def _safe_provider_metadata(value: Any) -> dict:
    if not isinstance(value, dict):
        return {}
    safe: dict[str, Any] = {}
    for key in SAFE_PROVIDER_METADATA:
        if key not in value:
            continue
        item = value[key]
        if key == "usage" and isinstance(item, dict):
            safe[key] = {
                str(name): number for name, number in item.items()
                if isinstance(number, (int, float))
            }
        elif key == "retry_reasons" and isinstance(item, list):
            safe[key] = [str(reason)[:80] for reason in item[:10]]
        elif key == "flow_refs" and isinstance(item, list):
            safe[key] = [str(ref)[:160] for ref in item[:100]]
        elif isinstance(item, (str, int, float, bool)) or item is None:
            safe[key] = str(item)[:240] if isinstance(item, str) else item
    return safe


def _explicit_metric(case: dict, name: str) -> dict | None:
    metrics = case.get("metrics")
    if not isinstance(metrics, dict) or name not in metrics:
        return None
    observation = metrics[name]
    if not isinstance(observation, dict):
        return {
            "name": name, "status": "invalid", "numerator": None,
            "denominator": None, "value": None, "eligible_for_gate": False,
            "reason": "Metric observation must be an object.",
            "source": f"case.metrics.{name}",
        }
    numerator = observation.get("numerator")
    denominator = observation.get("denominator")
    if (
        not isinstance(numerator, int)
        or not isinstance(denominator, int)
        or denominator < 0
        or numerator < 0
        or numerator > denominator
    ):
        return {
            "name": name, "status": "invalid", "numerator": numerator,
            "denominator": denominator, "value": None, "eligible_for_gate": False,
            "reason": "Metric requires integer numerator and denominator with numerator <= denominator.",
            "source": f"case.metrics.{name}",
        }
    if observation.get("eligible_for_gate") is False or denominator == 0:
        return {
            "name": name, "status": "not_measured", "numerator": numerator,
            "denominator": denominator, "value": None, "eligible_for_gate": False,
            "reason": observation.get("reason") or "Metric is diagnostic only and is not eligible for a release gate.",
            "source": f"case.metrics.{name}",
        }
    return {
        "name": name, "status": "measured", "numerator": numerator,
        "denominator": denominator, "value": _ratio(numerator, denominator),
        "eligible_for_gate": True,
        "reason": observation.get("reason") or "Measured from explicit numerator and denominator.",
        "source": f"case.metrics.{name}",
    }


def _aggregate_explicit_metric(cases: list[dict], name: str) -> dict | None:
    observations = [_explicit_metric(case, name) for case in cases]
    if not any(observations):
        return None
    if any(item is None or item["status"] != "measured" for item in observations):
        unavailable = next((item for item in observations if item is not None and item["status"] != "measured"), None)
        return {
            "name": name, "status": "not_measured" if unavailable and unavailable["status"] == "not_measured" else "invalid", "numerator": None,
            "denominator": None, "value": None, "eligible_for_gate": False,
            "reason": (unavailable or {}).get("reason") or "At least one case is missing or has an invalid explicit metric.",
            "source": f"cases[].metrics.{name}",
        }
    numerator = sum(int(item["numerator"]) for item in observations if item)
    denominator = sum(int(item["denominator"]) for item in observations if item)
    return {
        "name": name, "status": "measured", "numerator": numerator,
        "denominator": denominator, "value": _ratio(numerator, denominator),
        "eligible_for_gate": True,
        "reason": "Aggregated from explicit case-level counts.",
        "source": f"cases[].metrics.{name}",
    }


def _legacy_context_metric(cases: list[dict], name: str, field: str, reason: str) -> dict:
    values = [case.get(field) for case in cases if isinstance(case.get(field), (int, float))]
    return {
        "name": name, "status": "legacy_reported_only", "numerator": None,
        "denominator": None, "value": None,
        "legacy_reported_percent": round(sum(values) / len(values), 2) if values else None,
        "eligible_for_gate": False, "reason": reason, "source": f"cases[].{field}",
    }


def _unmeasured(name: str, reason: str) -> dict:
    return {
        "name": name, "status": "not_measured", "numerator": None,
        "denominator": None, "value": None, "eligible_for_gate": False,
        "reason": reason, "source": "missing",
    }


def _framework_metric(cases: list[dict]) -> dict:
    explicit = _aggregate_explicit_metric(cases, "framework_validation")
    if explicit:
        return explicit
    denominator = len(cases)
    validated_cases = sum(
        1 for case in cases if case.get("framework_validation_pct") == 100
    )
    return {
        "name": "framework_validation", "status": "legacy_derived",
        "numerator": validated_cases, "denominator": denominator,
        "value": _ratio(validated_cases, denominator),
        "legacy_reported_percent": 0 if not validated_cases else None,
        "eligible_for_gate": False,
        "reason": "Legacy result has no explicit validated/valid-empty framework outcome per case; derived count is diagnostic only.",
        "source": "cases[].framework_validation_pct",
    }


def _build_metrics(cases: list[dict]) -> dict[str, dict]:
    metrics: dict[str, dict] = {
        "ingestion_coverage": _legacy_context_metric(
            cases, "ingestion_coverage", "coverage_pct",
            "Legacy coverage percentage has no processed/total section counts.",
        ),
        "dfd_entity_recall": _legacy_context_metric(
            cases, "dfd_entity_recall", "dfd_entities_pct",
            "Legacy entity percentage has no expected/found entity counts.",
        ),
        "dfd_precision": _unmeasured(
            "dfd_precision",
            "Baseline stores entity presence only; it has no labelled canonical precision counts.",
        ),
        "duplicate_rate": _unmeasured(
            "duplicate_rate",
            "Baseline does not persist semantic duplicate-node/flow counts.",
        ),
        "topology_validity": _unmeasured(
            "topology_validity",
            "Baseline does not persist valid endpoint, crossing, boundary, and isolation counts.",
        ),
        "framework_validation": _framework_metric(cases),
        "finding_precision": _unmeasured(
            "finding_precision",
            "Baseline has topic presence but no labelled supported/generated finding counts.",
        ),
        "finding_recall": _unmeasured(
            "finding_recall",
            "Baseline does not map generated findings to independent expected finding labels.",
        ),
        "deferred_recall": _unmeasured(
            "deferred_recall",
            "Baseline stores missed topics but not expected/surfaced deferred topic counts.",
        ),
        "control_mapping_precision": _unmeasured(
            "control_mapping_precision",
            "Baseline has control counts but no expected and generated edge counts.",
        ),
        "control_mapping_recall": _unmeasured(
            "control_mapping_recall",
            "Baseline has no labelled finding-to-control edge counts.",
        ),
        "test_executability": _unmeasured(
            "test_executability",
            "Baseline has test counts but no executable/blocked test counts or assertion evidence.",
        ),
    }
    for name in REQUIRED_METRICS:
        explicit = _aggregate_explicit_metric(cases, name)
        if explicit:
            metrics[name] = explicit
    return metrics


def _case_provenance(
    case: dict,
    manifest_case: dict | None,
    manifest_dir: Path,
    default_timeout_seconds: int | float | None = None,
) -> dict:
    provenance = case.get("provenance")
    provenance = provenance if isinstance(provenance, dict) else {}
    source_file = str((manifest_case or {}).get("file") or case.get("file") or "")
    source_path = manifest_dir / source_file if source_file else None
    source_hash = provenance.get("source_hash") or _file_hash(source_path)
    values = {
        "application_commit": provenance.get("application_commit"),
        "provider": provenance.get("provider"),
        "model": provenance.get("model"),
        "timeout_seconds": provenance.get(
            "timeout_seconds", case.get("provider_timeout_seconds", default_timeout_seconds)
        ),
        "retry_config": provenance.get("retry_config"),
        "batch_config": provenance.get("batch_config"),
        "source_revision": provenance.get("source_revision"),
        "source_hash": source_hash,
        "dfd_revision": provenance.get("dfd_revision"),
        "dfd_semantic_hash": provenance.get("dfd_semantic_hash"),
        "run_id": provenance.get("run_id") or case.get("run_id"),
    }
    missing_fields = [
        field for field in PROVENANCE_FIELDS if values.get(field) in (None, "", {})
    ]
    safe_metadata = _safe_provider_metadata(
        case.get("provider_metadata") or provenance.get("provider_metadata")
    )
    return {
        "case_id": case.get("case_id"),
        "project_id": case.get("project_id"),
        "source_file": source_file,
        "source_file_exists": bool(source_path and source_path.is_file()),
        "source_artifact_hash": source_hash,
        "values": values,
        "missing_fields": missing_fields,
        "provider_metadata": safe_metadata,
        "provider_metadata_present": bool(safe_metadata),
    }


def _provenance_summary(
    cases: list[dict],
    manifest_by_id: dict[str, dict],
    manifest_dir: Path,
    results: dict,
) -> dict:
    case_items = [
        _case_provenance(
            case,
            manifest_by_id.get(str(case.get("case_id"))),
            manifest_dir,
            results.get("provider_timeout_seconds"),
        )
        for case in cases
    ]
    global_values = {
        "application_commit": results.get("application_commit"),
        "provider": results.get("provider"),
        "model": results.get("model"),
        "timeout_seconds": results.get("provider_timeout_seconds"),
        "retry_config": results.get("retry_config"),
        "batch_config": results.get("batch_config"),
    }
    missing_global = [
        field for field in (
            "application_commit", "provider", "model", "timeout_seconds",
            "retry_config", "batch_config",
        )
        if global_values.get(field) in (None, "", {})
    ]
    return {
        "global": global_values,
        "missing_global_fields": missing_global,
        "cases": case_items,
        "cases_with_provider_metadata": sum(
            item["provider_metadata_present"] for item in case_items
        ),
        "cases_with_complete_required_case_provenance": sum(
            not item["missing_fields"] for item in case_items
        ),
        "required_case_fields": [
            "source_revision", "source_hash", "dfd_revision",
            "dfd_semantic_hash", "run_id",
        ],
    }


def _gate(metrics: dict[str, dict], contract: dict) -> dict:
    threshold_names = {
        "ingestion_coverage": ("min_ingestion_coverage", ">="),
        "dfd_entity_recall": ("min_dfd_entity_recall", ">="),
        "dfd_precision": ("min_dfd_precision", ">="),
        "duplicate_rate": ("max_duplicate_rate", "<="),
        "topology_validity": ("min_topology_validity", ">="),
        "framework_validation": ("min_framework_validation", ">="),
        "finding_precision": ("min_finding_precision", ">="),
        "finding_recall": ("min_finding_recall", ">="),
        "deferred_recall": ("min_deferred_recall", ">="),
        "control_mapping_precision": ("min_control_mapping_precision", ">="),
        "control_mapping_recall": ("min_control_mapping_recall", ">="),
        "test_executability": ("min_test_executability", ">="),
    }
    checks: dict[str, dict] = {}
    thresholds = contract["thresholds"]
    for name, (threshold_name, operator) in threshold_names.items():
        observation = metrics[name]
        threshold = thresholds[threshold_name]
        measured = (
            observation.get("status") == "measured"
            and observation.get("value") is not None
            and observation.get("eligible_for_gate") is True
        )
        if not measured:
            passed = False
            reason = observation.get("reason") or "Required metric is not measured."
        elif operator == "<=":
            passed = observation["value"] <= threshold
            reason = "Measured value is within threshold." if passed else "Measured value exceeds threshold."
        else:
            passed = observation["value"] >= threshold
            reason = "Measured value is within threshold." if passed else "Measured value is below threshold."
        checks[name] = {
            "passed": passed,
            "status": observation.get("status"),
            "actual": observation.get("value"),
            "numerator": observation.get("numerator"),
            "denominator": observation.get("denominator"),
            "operator": operator,
            "threshold": threshold,
            "reason": reason,
        }
    return {"passed": all(item["passed"] for item in checks.values()), "checks": checks, "fail_closed": True}


def evaluate_prd_corpus(
    results: dict,
    manifest: dict,
    contract: dict,
    *,
    results_path: str | Path = DEFAULT_RESULTS_PATH,
    manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
) -> dict:
    validate_metric_contract(contract)
    validate_result_payload(results)
    validate_manifest(manifest, results)
    cases = list(results["cases"])
    manifest_by_id = {str(item.get("id")): item for item in manifest["cases"]}
    metrics = _build_metrics(cases)
    provenance = _provenance_summary(
        cases, manifest_by_id, Path(manifest_path).resolve().parent, results
    )
    signoff_cases = sum(bool(case.get("signoff_ready")) for case in cases)
    warnings = []
    if any(case.get("run_status") == "completed_with_warnings" for case in cases):
        warnings.append("At least one case completed with warnings; completion is not a validated assessment.")
    if metrics["framework_validation"]["value"] == 0:
        warnings.append("No case has a validated or legitimate valid-empty framework outcome in the baseline.")
    if any(item["missing_fields"] for item in provenance["cases"]):
        warnings.append("Case-level run/DFD/source provenance is incomplete; missing fields are listed per case.")
    results_for_hash = {
        key: value for key, value in results.items()
        if key not in {"evaluated_at", "output_path"}
    }
    manifest_hash = _content_hash(manifest)
    contract_hash = _content_hash(contract)
    results_hash = _content_hash(results_for_hash)
    fingerprint = _content_hash({
        "evaluator_version": EVALUATOR_VERSION,
        "contract_hash": contract_hash,
        "manifest_hash": manifest_hash,
        "results_hash": results_hash,
        "metrics": metrics,
    })
    gate = _gate(metrics, contract)
    gate["checks"]["no_false_signoff"] = {
        "passed": signoff_cases == 0 or metrics["framework_validation"]["value"] == 1.0,
        "status": "measured",
        "actual": signoff_cases,
        "numerator": signoff_cases,
        "denominator": len(cases),
        "operator": "consistent-with-framework-state",
        "threshold": 0,
        "reason": (
            "Sign-off is absent while framework validation is unavailable."
            if signoff_cases == 0
            else "Sign-off cannot be true before all framework cases are validated."
        ),
    }
    gate["passed"] = all(item["passed"] for item in gate["checks"].values())
    case_summary = []
    for case in cases:
        provenance_case = next(
            item for item in provenance["cases"] if item["case_id"] == case.get("case_id")
        )
        case_summary.append({
            "case_id": case.get("case_id"),
            "completeness": case.get("completeness"),
            "run_status": case.get("run_status"),
            "framework_validation_pct_legacy": case.get("framework_validation_pct"),
            "signoff_ready": case.get("signoff_ready"),
            "missing_fields": provenance_case["missing_fields"],
        })
    return {
        "schema_version": RESULT_EVALUATION_SCHEMA_VERSION,
        "evaluator_version": EVALUATOR_VERSION,
        "contract_id": contract.get("contract_id"),
        "contract_schema_version": contract.get("schema_version"),
        "corpus_result_schema_version": results.get("schema_version"),
        "target_result_schema_version": TARGET_RESULT_SCHEMA_VERSION,
        "legacy_input": results.get("schema_version") == LEGACY_RESULT_SCHEMA_VERSION,
        "corpus_revision": manifest.get("version"),
        "captured_at": results.get("captured_at"),
        "source_artifacts": {
            "results_hash": results_hash,
            "manifest_hash": manifest_hash,
            "contract_hash": contract_hash,
            "results_path": _relative_path(Path(results_path)),
            "manifest_path": _relative_path(Path(manifest_path)),
        },
        "evaluation_fingerprint": fingerprint,
        "provenance": provenance,
        "metrics": metrics,
        "case_count": len(cases),
        "signoff_ready_cases": signoff_cases,
        "warnings": warnings,
        "gate": gate,
        "cases": case_summary,
    }


def _display_metric(observation: dict) -> str:
    if observation.get("numerator") is not None and observation.get("denominator") is not None:
        value = observation.get("value")
        percent = f" ({value * 100:.2f}%)" if value is not None else ""
        return f"{observation['numerator']}/{observation['denominator']}{percent}"
    legacy = observation.get("legacy_reported_percent")
    if legacy is not None:
        return f"legacy {legacy:.2f}% (no counts)"
    return "not measured"


def render_markdown(evaluation: dict) -> str:
    gate = evaluation["gate"]
    lines = [
        "# PRD Corpus CR0 Evaluation",
        "",
        f"- Verdict: {'PASS' if gate['passed'] else 'FAIL'} (fail-closed)",
        f"- Evaluator: {evaluation['evaluator_version']}",
        f"- Contract: {evaluation['contract_id']}",
        f"- Cases: {evaluation['case_count']}",
        f"- Evaluation fingerprint: {evaluation['evaluation_fingerprint']}",
        "",
        "## Gate checks",
        "",
        "| Metric | Status | Actual | Threshold | Reason |",
        "|---|---|---:|---:|---|",
    ]
    for name, check in gate["checks"].items():
        actual = "n/a" if check.get("actual") is None else str(check["actual"])
        lines.append(
            f"| {name} | {'PASS' if check['passed'] else 'FAIL'} | {actual} | "
            f"{check.get('operator')} {check.get('threshold')} | {check.get('reason')} |"
        )
    lines.extend([
        "", "## Metric observations", "",
        "| Metric | Status | Count | Eligible for gate | Reason |",
        "|---|---|---:|---|---|",
    ])
    for name in REQUIRED_METRICS:
        observation = evaluation["metrics"][name]
        lines.append(
            f"| {name} | {observation['status']} | {_display_metric(observation)} | "
            f"{'yes' if observation.get('eligible_for_gate') else 'no'} | {observation.get('reason')} |"
        )
    lines.extend([
        "", "## Provenance", "",
        f"- Results hash: {evaluation['source_artifacts']['results_hash']}",
        f"- Manifest hash: {evaluation['source_artifacts']['manifest_hash']}",
        f"- Contract hash: {evaluation['source_artifacts']['contract_hash']}",
        f"- Cases with provider metadata: {evaluation['provenance']['cases_with_provider_metadata']}/{evaluation['case_count']}",
        "",
    ])
    if evaluation["warnings"]:
        lines.extend(["## Warnings", ""])
        lines.extend(f"- {warning}" for warning in evaluation["warnings"])
        lines.append("")
    lines.extend([
        "## Case summary", "",
        "| Case | Completeness | Run status | Legacy framework % | Sign-off | Missing provenance |",
        "|---|---|---|---:|---|---|",
    ])
    for case in evaluation["cases"]:
        missing = ", ".join(case["missing_fields"]) or "none"
        lines.append(
            f"| {case['case_id']} | {case.get('completeness') or 'unknown'} | "
            f"{case.get('run_status') or 'unknown'} | "
            f"{case.get('framework_validation_pct_legacy', 'n/a')} | "
            f"{case.get('signoff_ready', False)} | {missing} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate PRD corpus E2E output using the CR0 fail-closed contract"
    )
    parser.add_argument("--results", default=str(DEFAULT_RESULTS_PATH))
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST_PATH))
    parser.add_argument("--contract", default=str(DEFAULT_CONTRACT_PATH))
    parser.add_argument("--output", help="Optional JSON evaluation output path")
    parser.add_argument("--markdown-output", help="Optional Markdown evaluation output path")
    parser.add_argument("--no-fail", action="store_true", help="Print verdict but always exit zero")
    args = parser.parse_args(argv)
    try:
        results = _read_json(args.results)
        manifest = _read_json(args.manifest)
        contract = _read_json(args.contract)
        evaluation = evaluate_prd_corpus(
            results, manifest, contract,
            results_path=args.results, manifest_path=args.manifest,
        )
    except PRDCorpusEvaluationError as exc:
        rendered = json.dumps({
            "schema_version": RESULT_EVALUATION_SCHEMA_VERSION,
            "gate": {"passed": False, "fail_closed": True},
            "error": str(exc),
        }, ensure_ascii=False, indent=2)
        print(rendered)
        return 0 if args.no_fail else 2
    rendered = json.dumps(evaluation, ensure_ascii=False, indent=2, sort_keys=True)
    print(rendered)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    if args.markdown_output:
        Path(args.markdown_output).write_text(render_markdown(evaluation), encoding="utf-8")
    return 0 if evaluation["gate"]["passed"] or args.no_fail else 1


if __name__ == "__main__":
    raise SystemExit(main())
