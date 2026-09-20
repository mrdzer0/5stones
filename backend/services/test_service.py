"""Test scenario generation service."""
from __future__ import annotations
import hashlib
import uuid
from typing import List
from pydantic import ValidationError
from backend.services.ai_service import (
    StageGenerationResult,
    StructuredJSONResult,
    chat_complete_json,
    get_active_provider_config,
)
from backend.services.dfd_model_service import format_dfd_analysis_context
from backend.services.generation_contracts import (
    GenerationContractError,
    TestScenarioGenerationItem,
    model_ids,
)
from backend.services.threat_validation_service import LINDDUN_CATEGORY_ALIASES

SYSTEM_PROMPT = """You are a security test engineer creating security test scenarios for QA and Security teams.
Each scenario must be actionable, specific, and executable. Return one strict JSON object."""

_LINDDUN_TEST_CATEGORIES = {
    "Linking", "Identifying", "Non-repudiation", "Detecting", "Data Disclosure",
    "Unawareness & Unintervenability", "Non-compliance",
}
_STRIDE_TEST_CATEGORIES = {
    "Spoofing", "Tampering", "Repudiation", "Information Disclosure",
    "Denial of Service", "Elevation of Privilege",
}


async def generate_test_scenarios(
    threats: List[dict],
    project: dict,
    force_fallback: bool = False,
    controls: List[dict] | None = None,
    dfd_model: dict | None = None,
    evidence_ids: set[str] | None = None,
) -> List[dict]:
    """Generate test scenarios mapped to generated threats."""
    if force_fallback:
        fallback_warnings = _threat_quality_warnings(threats)
        return StageGenerationResult(
            normalize_test_scenarios(_fallback_scenarios(threats, controls), threats, controls, dfd_model, evidence_ids),
            assessment_status="fallback",
            response_shape="deterministic_fallback",
            warnings=["AI test generation was bypassed; generated scenarios require review.", *fallback_warnings],
            response_metadata={"engine": "fallback"},
        )

    cfg = get_active_provider_config(project.get("data_policy"))

    active_threats = _active_threat_records(threats)
    threats_summary = "\n".join([
        f"- ID: {t.get('threat_id')}\n  Framework: {t.get('framework', 'unknown')}\n  Category: {t.get('threat_category', 'unknown')}\n  Description: {t.get('threat_description', '')}\n  Recommended Control: {t.get('recommended_control','')}\n  DFD targets: {t.get('target_refs') or []}"
        for t in active_threats
    ])
    controls_summary = "\n".join([
        f"- ID: {control.get('control_id')} · {control.get('name')} · status={control.get('implementation_status') or control.get('status') or 'Unknown'} · "
        f"threat_ids={control.get('threat_ids') or []} · target_refs={control.get('target_refs') or []} · "
        f"location_ref={control.get('location_ref') or None} · analysis_revision={control.get('analysis_revision') or control.get('dfd_revision') or 'unknown'}"
        for control in (controls or [])
        if isinstance(control, dict) and control.get("control_id")
    ]) or "No mapped controls are available; make the missing mapping explicit in the scenario."
    dfd_context = format_dfd_analysis_context(dfd_model)
    dfd_revision = (dfd_model or {}).get("revision", "unknown")
    dfd_hash = (dfd_model or {}).get("semantic_hash", "unknown")

    user_prompt = f"""Generate security test scenarios mapped to the following threat catalog.

PROJECT ENVIRONMENT:
{project.get('environment', 'production')}

THREATS:
{threats_summary}

MAPPED CONTROLS:
{controls_summary}

CANONICAL DFD SNAPSHOT (the same semantic revision used by threat analysis and controls):
{dfd_context}

ANALYSIS SNAPSHOT PROVENANCE:
- dfd_revision: {dfd_revision}
- dfd_semantic_hash: {dfd_hash}

Return one JSON object with a "scenarios" array:
{{
  "scenarios": [
    {{
    "scenario_name": "descriptive test name",
    "preconditions": "test setup requirements",
    "steps": ["step 1", "step 2", "step 3"],
    "expected_result": "what should happen if control is working",
    "evidence_needed": ["screenshot", "request-response log", etc],
    "related_control": "control name for display",
    "related_control_id": "stable control_id when a mapped control exists",
    "priority": "Critical|High|Medium|Low",
    "owner": "QA|Security|QA/Security",
    "threat_id": "the threat_id this test covers",
    "target_refs": [{{"type": "data_flow|process|data_store|entity|boundary|data_object", "id": "canonical DFD element ID"}}],
    "analysis_revision": "current canonical DFD revision",
    "dfd_revision": "current canonical DFD revision",
    "dfd_semantic_hash": "current canonical DFD semantic hash",
    "execution_status": "Not Run|Passed|Failed|Blocked",
    "actual_result": "leave empty until executed",
    "execution_evidence_refs": ["valid evidence IDs after execution"],
    "applicability_status": "applicable|not_applicable|blocked",
    "applicability_reason": "required when not_applicable or blocked"
    }}
  ]
}}"""

    stage_budget = min(int(cfg.get("max_tokens") or 3500), 3500)
    result = await chat_complete_json(
        system_prompt=SYSTEM_PROMPT,
        user_prompt=user_prompt,
        base_url=cfg.get("base_url"),
        api_key=cfg.get("api_key"),
        model=cfg.get("model"),
        max_tokens=stage_budget,
        return_metadata=True,
    )
    payload, response_metadata = _unpack_structured_result(result)
    response_shape = str(response_metadata.get("response_shape") or "unknown")
    if not isinstance(payload, dict) or "scenarios" not in payload:
        raise GenerationContractError(
            "Test-scenario response must contain a scenarios array envelope",
            code="test_scenarios_envelope_invalid",
            metadata=response_metadata,
        )
    if not isinstance(payload["scenarios"], list):
        raise GenerationContractError(
            "Test-scenario response field 'scenarios' must be an array",
            code="test_scenarios_envelope_schema_invalid",
            metadata=response_metadata,
        )
    active_threats = _active_threat_records(threats)
    if not payload["scenarios"] and not active_threats:
        raise GenerationContractError(
            "Analysis engine returned an empty test-scenario list",
            code="test_scenarios_empty",
            metadata=response_metadata,
        )

    valid_threat_ids = {str(item.get("threat_id")) for item in active_threats}
    valid_control_ids = {
        str(item.get("control_id")) for item in (controls or [])
        if isinstance(item, dict) and item.get("control_id")
    }
    valid_dfd_ids = model_ids(dfd_model)
    warnings = []
    scenarios = []
    for index, raw_item in enumerate(payload["scenarios"]):
        try:
            model = TestScenarioGenerationItem.model_validate(raw_item)
        except ValidationError:
            warnings.append(f"Scenario {index} failed item schema validation and was dropped.")
            continue
        item = model.model_dump(exclude_none=True)
        if item.get("threat_id") not in valid_threat_ids:
            warnings.append(f"Scenario {index} references an unknown threat_id and was dropped.")
            continue
        if item.get("related_control_id") and valid_control_ids and item["related_control_id"] not in valid_control_ids:
            warnings.append(f"Scenario {index} references an unknown related_control_id; it was removed.")
            item.pop("related_control_id", None)
        refs = item.get("target_refs") or []
        valid_refs = [ref for ref in refs if not valid_dfd_ids or str(ref.get("id")) in valid_dfd_ids]
        if len(valid_refs) != len(refs):
            warnings.append(f"Scenario {index} contained dangling DFD refs; they were removed.")
        item["target_refs"] = valid_refs
        refs = [str(ref) for ref in (item.get("execution_evidence_refs") or [])]
        if evidence_ids is not None:
            filtered = [ref for ref in refs if ref in evidence_ids]
            if len(filtered) != len(refs):
                warnings.append(f"Scenario {index} contained unknown execution evidence refs; they were removed.")
            refs = filtered
        item["execution_evidence_refs"] = refs
        scenarios.append(item)

    if not scenarios and active_threats:
        warnings.append("Provider returned no valid scenarios; uncovered threats were retained as blocked review items.")
    elif not scenarios:
        raise GenerationContractError(
            "Analysis engine returned no scenarios linked to active threats",
            code="test_scenarios_foreign_key_invalid",
            metadata=response_metadata,
        )

    normalized = normalize_test_scenarios(scenarios, threats, controls, dfd_model, evidence_ids)
    if not normalized:
        raise GenerationContractError(
            "Analysis engine returned no scenarios after normalization",
            code="test_scenarios_normalization_empty",
            metadata=response_metadata,
        )
    partial = bool(warnings) or any(item.get("applicability_status") != "applicable" for item in normalized)
    response_metadata["validation_status"] = "partial" if partial else "complete"
    return StageGenerationResult(
        normalized,
        assessment_status="partial" if partial else "complete",
        response_shape=response_shape,
        warnings=warnings,
        response_metadata=response_metadata,
    )


def _unpack_structured_result(result) -> tuple[object, dict]:
    if isinstance(result, StructuredJSONResult):
        return result.payload, dict(result.metadata)
    return result, {"instrumentation_status": "legacy_uninstrumented"}


def _fallback_scenarios(threats: list, controls: list | None = None) -> list:
    templates = {
        "Information Disclosure": {
            "scenario_name": "IDOR — Access Another User's Resource",
            "preconditions": "Two accounts (User A, User B) with separate resources",
            "steps": [
                "Login as User A, note resource ID",
                "Login as User B",
                "Attempt to access User A's resource ID via API",
                "Observe response code and body"
            ],
            "expected_result": "API returns 403 Forbidden or 404 Not Found",
            "evidence_needed": ["HTTP request/response", "Server logs"],
            "related_control": "Object Ownership Validation",
            "priority": "High",
            "owner": "QA/Security"
        },
        "Tampering": {
            "scenario_name": "Parameter Tampering — Modify Critical Value",
            "preconditions": "Authenticated session, intercepting proxy (Burp Suite)",
            "steps": [
                "Login and initiate normal request",
                "Intercept request with proxy",
                "Modify critical parameter (amount, status, role)",
                "Forward modified request"
            ],
            "expected_result": "Server rejects tampered value or recalculates server-side",
            "evidence_needed": ["Intercepted request", "Server response", "DB state before/after"],
            "related_control": "Server-Side Validation",
            "priority": "High",
            "owner": "Security"
        },
        "Spoofing": {
            "scenario_name": "Caller Identity Spoofing — Impersonate a Trusted Principal",
            "preconditions": "A test account, a normal authenticated request, and a representative protected endpoint",
            "steps": [
                "Capture a valid request from the test account",
                "Alter the caller identity, token claims, API key, or equivalent authentication material",
                "Replay the altered request against the protected endpoint",
                "Observe authorization response and any state change"
            ],
            "expected_result": "Server rejects the impersonated identity with 401/403 and does not change protected state",
            "evidence_needed": ["Original and altered request-response logs", "Server audit log", "State comparison"],
            "related_control": "Authentication and Caller Identity Validation",
            "priority": "Critical",
            "owner": "Security"
        },
        "Elevation of Privilege": {
            "scenario_name": "Privilege Escalation — Access Admin Function as Regular User",
            "preconditions": "Regular user account",
            "steps": [
                "Login as regular user",
                "Identify admin API endpoints from documentation or enumeration",
                "Call admin endpoint with regular user token",
                "Attempt to modify role in JWT payload (if not signed)"
            ],
            "expected_result": "Server returns 403 Forbidden for all admin endpoints",
            "evidence_needed": ["Request-response", "Server logs showing role check"],
            "related_control": "Server-Side RBAC",
            "priority": "Critical",
            "owner": "QA/Security"
        },
        "Denial of Service": {
            "scenario_name": "Rate Limit Test — Flood Public Endpoint",
            "preconditions": "Access to public endpoint",
            "steps": [
                "Send 100 requests in 10 seconds to endpoint",
                "Observe response codes",
                "Check for 429 Too Many Requests response",
                "Verify Retry-After header is present"
            ],
            "expected_result": "Rate limiting kicks in, returns 429 with Retry-After header",
            "evidence_needed": ["Response codes", "Response times", "Server metrics"],
            "related_control": "Rate Limiting",
            "priority": "Medium",
            "owner": "QA/Security"
        },
        "Repudiation": {
            "scenario_name": "Audit Trail — Verify Critical Action Logging",
            "preconditions": "Access to audit logs, authenticated session",
            "steps": [
                "Perform critical action (e.g., update, delete, payment)",
                "Access audit log",
                "Verify action is recorded with user ID, timestamp, action, resource"
            ],
            "expected_result": "Audit log contains complete record of the action",
            "evidence_needed": ["Audit log entry", "Action timestamp correlation"],
            "related_control": "Immutable Audit Log",
            "priority": "Medium",
            "owner": "QA"
        },
        "Disclosure of Information": {
            "scenario_name": "PII in API Response — Verify Data Minimization",
            "preconditions": "Authenticated session",
            "steps": [
                "Call API endpoints that return user/transaction data",
                "Review all response fields",
                "Identify PII fields not needed by caller",
                "Check if sensitive fields are masked"
            ],
            "expected_result": "No unnecessary PII exposed, sensitive fields masked (e.g. phone: +628****1234)",
            "evidence_needed": ["API response body", "Field-by-field review"],
            "related_control": "Data Minimization and Masking",
            "priority": "Medium",
            "owner": "QA"
        },
        "Data Disclosure": {
            "scenario_name": "Privacy Data Minimization — Verify Recipient Scope",
            "preconditions": "Representative personal-data response and documented purpose",
            "steps": ["Capture the sender-to-receiver payload", "Compare fields with purpose and recipient scope", "Verify unnecessary fields are removed or masked"],
            "expected_result": "Only data necessary for the documented purpose reaches the intended recipient.",
            "evidence_needed": ["Request-response capture", "Field-level data inventory"],
            "related_control": "PII Data Minimization and Masking",
            "priority": "High",
            "owner": "QA/Security"
        },
        "Non-repudiation": {
            "scenario_name": "Privacy Auditability — Attribute Sensitive Actions",
            "preconditions": "A test account, an auditable personal-data action, and access to the privacy-relevant audit trail",
            "steps": ["Perform a sensitive read, export, change, or deletion action", "Locate the corresponding audit record", "Verify actor, action, timestamp, target, and outcome are attributable without exposing unnecessary personal data"],
            "expected_result": "The privacy-relevant action is attributable and reviewable while audit records minimize personal data exposure.",
            "evidence_needed": ["Action request-response", "Audit record", "Audit-data minimization review"],
            "related_control": "Privacy-Aware Audit Logging",
            "priority": "Medium",
            "owner": "QA/Security"
        },
        "Detecting": {
            "scenario_name": "Privacy Observability — Detect Sensitive Data Access",
            "preconditions": "A test personal-data record, an authorized and unauthorized access path, and monitoring access",
            "steps": ["Access the personal-data record through the expected path", "Attempt an unauthorized or anomalous access pattern", "Check monitoring and audit signals for both events", "Verify alerts do not include unnecessary personal-data values"],
            "expected_result": "Relevant access is detectable and alertable with minimized telemetry content.",
            "evidence_needed": ["Access logs", "Alert or detection event", "Telemetry redaction review"],
            "related_control": "Privacy-Aware Audit Logging",
            "priority": "Medium",
            "owner": "QA/Security"
        },
        "Linking": {
            "scenario_name": "Linkability — Correlate Identifiers Across Flows",
            "preconditions": "Two records or sessions that should not be linkable without a documented purpose",
            "steps": ["Collect identifiers emitted by relevant flows", "Attempt cross-context correlation", "Verify identifiers are minimized, scoped, or rotated"],
            "expected_result": "Unnecessary cross-context correlation is prevented or explicitly controlled.",
            "evidence_needed": ["Captured identifiers", "Privacy metadata", "Correlation result"],
            "related_control": "PII Data Minimization and Masking",
            "priority": "Medium",
            "owner": "QA/Security"
        },
        "Identifying": {
            "scenario_name": "Identifiability — Re-identification Check",
            "preconditions": "Representative dataset and documented direct/indirect identifiers",
            "steps": ["Review direct and indirect identifiers", "Attempt re-identification from available combinations", "Verify masking, minimization, and access controls"],
            "expected_result": "Individuals cannot be identified beyond the documented purpose and access scope.",
            "evidence_needed": ["Data inventory", "Re-identification result"],
            "related_control": "PII Data Minimization and Masking",
            "priority": "High",
            "owner": "QA/Security"
        },
        "Unawareness & Unintervenability": {
            "scenario_name": "Privacy Notice and Individual Control Check",
            "preconditions": "Test user and documented notice, deletion, or opt-out behavior",
            "steps": ["Observe notice before or during collection", "Exercise access, deletion, or opt-out controls", "Verify downstream processing reflects the request"],
            "expected_result": "Notice and individual controls are available, understandable, and effective.",
            "evidence_needed": ["UI/API capture", "Deletion or opt-out record"],
            "related_control": "Consent and Transparency Mechanism",
            "priority": "High",
            "owner": "Product/Legal"
        },
        "Non-compliance": {
            "scenario_name": "Privacy Obligation Evidence Verification",
            "preconditions": "Documented obligation and relevant implementation evidence",
            "steps": ["Identify the obligation and affected flow", "Execute retention, notice, or deletion behavior", "Compare implementation evidence with the obligation"],
            "expected_result": "The implementation behavior is supported by evidence and matches the documented obligation.",
            "evidence_needed": ["Policy or obligation", "Implementation evidence", "Execution record"],
            "related_control": "Data Retention and Deletion Policy",
            "priority": "High",
            "owner": "Product/Legal"
        },
    }

    scenarios = []
    control_by_name = {
        str(control.get("name") or "").casefold(): control
        for control in (controls or [])
        if isinstance(control, dict) and control.get("name")
    }
    for i, threat in enumerate(threats or []):
        if not isinstance(threat, dict) or not threat.get("threat_id"):
            continue
        category = str(threat.get("threat_category") or "").strip()
        canonical_category = LINDDUN_CATEGORY_ALIASES.get(category, category)
        if not category:
            scenarios.append(_blocked_scenario_for_threat(
                threat,
                "Threat record has no canonical threat_category; execution is blocked until the legacy finding is reviewed.",
                controls,
            ))
            continue
        if canonical_category not in _STRIDE_TEST_CATEGORIES and canonical_category not in _LINDDUN_TEST_CATEGORIES:
            scenarios.append(_blocked_scenario_for_threat(
                threat,
                f"Threat category '{category}' is not supported by the canonical test catalog.",
                controls,
            ))
            continue
        if canonical_category == "Spoofing" and _has_webhook_evidence(threat, controls):
            template = {
                "scenario_name": "Webhook Spoofing — Send Callback Without Valid Signature",
                "preconditions": "Evidence-backed webhook or signed callback endpoint and a test provider secret",
                "steps": ["Craft a callback payload mimicking the trusted provider", "Send it without a signature", "Send it with an invalid signature and stale timestamp", "Observe response, audit event, and state change"],
                "expected_result": "The endpoint rejects unsigned, invalid, or replayed callbacks before changing application state.",
                "evidence_needed": ["Request-response logs", "Signature verification log", "State comparison"],
                "related_control": "Webhook Signature Verification",
                "priority": "Critical",
                "owner": "Security",
            }
        else:
            template = templates.get(canonical_category, {
                "scenario_name": f"Security Test — {category}",
                "preconditions": "Authenticated session with test data",
                "steps": ["Setup test environment", "Execute attack scenario", "Verify defense"],
                "expected_result": "Attack is blocked or logged appropriately",
                "evidence_needed": ["Request-response log"],
                "related_control": threat.get("recommended_control", "N/A"),
                "priority": "Medium",
                "owner": "Security"
            })
        s = dict(template)
        s["threat_id"] = threat.get("threat_id", "")
        control = control_by_name.get(str(s.get("related_control") or "").casefold())
        if control:
            s["related_control_id"] = control.get("control_id")
        s["target_refs"] = list(threat.get("target_refs") or [])
        scenarios.append(s)

    return scenarios


def _active_threat_records(threats: list | None) -> list[dict]:
    """Return only threat records safe to use as downstream foreign keys."""
    return [
        item for item in (threats or [])
        if isinstance(item, dict) and str(item.get("threat_id") or "").strip()
    ]


def _threat_quality_warnings(threats: list | None) -> list[str]:
    dropped = sum(1 for item in (threats or []) if not isinstance(item, dict) or not str(item.get("threat_id") or "").strip())
    return [f"Skipped {dropped} threat record(s) without a usable threat_id; they cannot be linked to a test scenario."] if dropped else []


def _has_webhook_evidence(threat: dict, controls: list | None = None) -> bool:
    """Require explicit callback/webhook evidence before using a webhook test."""
    values = [
        threat.get("threat_category"), threat.get("threat_description"), threat.get("scenario"),
        threat.get("abuse_case"), threat.get("recommended_control"), threat.get("asset"),
        threat.get("component"), threat.get("source"), threat.get("destination"),
    ]
    for control in controls or []:
        if isinstance(control, dict) and str(threat.get("threat_id")) in {str(item) for item in (control.get("threat_ids") or [])}:
            values.extend([control.get("name"), control.get("description"), control.get("implementation_guidance")])
    text = " ".join(str(value or "") for value in values).casefold()
    return any(signal in text for signal in ("webhook", "callback", "signed callback", "hmac"))


def _blocked_scenario_for_threat(threat: dict, reason: str, controls: list | None = None) -> dict:
    control = next((item for item in (controls or []) if isinstance(item, dict) and str(threat.get("threat_id")) in {str(ref) for ref in (item.get("threat_ids") or [])}), None)
    return {
        "scenario_name": "Verification blocked — review threat record",
        "preconditions": "Threat record and canonical DFD context must be reviewed before execution",
        "steps": ["Review the threat category and supporting evidence", "Confirm the applicable interaction and control", "Replace this blocked scenario with an executable verification case"],
        "expected_result": "A reviewed, evidence-backed test scenario is defined before execution.",
        "evidence_needed": ["Threat review decision", "DFD target evidence", "Applicable control evidence"],
        "related_control": control.get("name") if control else threat.get("recommended_control"),
        "related_control_id": control.get("control_id") if control else None,
        "priority": "High",
        "owner": "Security",
        "threat_id": str(threat.get("threat_id")),
        "target_refs": list(threat.get("target_refs") or []),
        "execution_status": "Blocked",
        "applicability_status": "blocked",
        "applicability_reason": reason,
    }


def normalize_test_scenarios(
    scenarios: list,
    threats: list,
    controls: list | None = None,
    dfd_model: dict | None = None,
    evidence_ids: set[str] | None = None,
) -> list:
    """Validate scenario foreign keys and pin each test to the active DFD."""
    threat_by_id = {
        str(item.get("threat_id")): item
        for item in threats or []
        if isinstance(item, dict) and item.get("threat_id")
    }
    control_by_id = {
        str(item.get("control_id")): item
        for item in (controls or [])
        if isinstance(item, dict) and item.get("control_id")
    }
    control_by_name = {
        str(item.get("name") or "").casefold(): item
        for item in (controls or [])
        if isinstance(item, dict) and item.get("name")
    }
    valid_dfd_ids = {
        str(item.get("id"))
        for collection in ("nodes", "data_objects", "flows", "boundaries")
        for item in ((dfd_model or {}).get(collection) or [])
        if isinstance(item, dict) and item.get("id")
    }
    normalized = []
    normalized_threat_ids = set()
    for raw in scenarios or []:
        if not isinstance(raw, dict):
            continue
        threat_id = str(raw.get("threat_id") or "")
        threat = threat_by_id.get(threat_id)
        if not threat:
            continue
        category = str(threat.get("threat_category") or "").strip()
        if not category:
            item = _blocked_scenario_for_threat(
                threat,
                "Threat record has no canonical threat_category; execution is blocked until the legacy finding is reviewed.",
                controls,
            )
            item["target_refs"] = list(threat.get("target_refs") or [])
            raw = {**item, **{key: value for key, value in raw.items() if key not in {"scenario_name", "preconditions", "steps", "expected_result", "execution_status", "applicability_status", "applicability_reason"}}}
        name = str(raw.get("scenario_name") or "").strip()
        preconditions = str(raw.get("preconditions") or "").strip()
        expected = str(raw.get("expected_result") or "").strip()
        steps = raw.get("steps")
        if not name or not preconditions or not expected or not isinstance(steps, list) or not steps:
            continue
        item = dict(raw)
        item["threat_id"] = threat_id
        item["preconditions"] = preconditions
        item["expected_result"] = expected
        item["steps"] = [str(step).strip() for step in steps if str(step).strip()]
        if not item["steps"]:
            continue
        related_id = str(item.get("related_control_id") or "")
        related_control = control_by_id.get(related_id)
        if not related_control:
            related_control = control_by_name.get(str(item.get("related_control") or "").casefold())
        if related_control:
            item["related_control_id"] = related_control.get("control_id")
            item["related_control"] = related_control.get("name")
        else:
            item.pop("related_control_id", None)
            item["related_control"] = item.get("related_control") or None
        raw_refs = item.get("target_refs") if isinstance(item.get("target_refs"), list) else []
        refs = [
            {"type": str(ref.get("type") or "dfd_element"), "id": str(ref["id"])}
            for ref in raw_refs
            if isinstance(ref, dict) and ref.get("id") and (not valid_dfd_ids or str(ref["id"]) in valid_dfd_ids)
        ]
        item["target_refs"] = refs or list(threat.get("target_refs") or [])
        applicability_status = str(item.get("applicability_status") or "applicable").strip().casefold()
        if applicability_status not in {"applicable", "not_applicable", "blocked"}:
            applicability_status = "applicable"
        item["applicability_status"] = applicability_status
        item["applicability_reason"] = str(item.get("applicability_reason") or "").strip()
        if applicability_status in {"not_applicable", "blocked"}:
            item["execution_status"] = "Blocked"
            if not item["applicability_reason"]:
                item["applicability_reason"] = "Scenario is not executable until applicability is reviewed."
        else:
            item["execution_status"] = item.get("execution_status") or "Not Run"
        item["actual_result"] = item.get("actual_result") or ""
        item["execution_evidence_refs"] = [
            str(ref) for ref in (item.get("execution_evidence_refs") or [])
            if evidence_ids is None or str(ref) in evidence_ids
        ]
        if isinstance(dfd_model, dict):
            item["analysis_revision"] = dfd_model.get("revision")
            item["dfd_revision"] = dfd_model.get("revision")
            item["dfd_semantic_hash"] = dfd_model.get("semantic_hash")
        item["verification_status"] = "not_executed" if item["execution_status"] in {"Not Run", "Blocked"} else "executed"
        item["test_fingerprint"] = _scenario_fingerprint(item)
        item["test_id"] = item.get("test_id") or f"TM-{item['test_fingerprint'][:10].upper()}"
        normalized.append(item)
        normalized_threat_ids.add(threat_id)

    # Preserve denominator and reviewability: a provider omission becomes an
    # explicit blocked item instead of silently reducing test coverage.
    for threat in _active_threat_records(threats):
        threat_id = str(threat.get("threat_id"))
        if threat_id in normalized_threat_ids:
            continue
        category = str(threat.get("threat_category") or "").strip()
        reason = (
            "Threat record has no canonical threat_category; execution is blocked until the legacy finding is reviewed."
            if not category else
            "No valid provider scenario was returned for this active threat; manual test design is required before execution."
        )
        blocked = _blocked_scenario_for_threat(threat, reason, controls)
        normalized.extend(normalize_test_scenarios([blocked], [threat], controls, dfd_model, evidence_ids))
    return normalized


def _scenario_fingerprint(item: dict) -> str:
    raw = "|".join([
        str(item.get("scenario_name") or "").strip().casefold(),
        str(item.get("threat_id") or ""),
        str(item.get("related_control_id") or item.get("related_control") or "").strip().casefold(),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


async def generate_missing_info(project: dict, threats: List[dict], force_fallback: bool = False) -> List[dict]:
    """Generate list of missing information needed for better threat modeling."""
    if force_fallback:
        return _fallback_missing_info(project)

    cfg = get_active_provider_config(project.get("data_policy"))

    context = f"""Project: {project.get('name')}
Description: {project.get('description', '')}
Actors: {', '.join(project.get('actors', []))}
Auth: {project.get('auth_method', 'Unknown')}
Entry Points: {', '.join(project.get('entry_points', []))}
Data: {', '.join(project.get('data_involved', []))}
External: {', '.join(project.get('external_systems', []))}
Existing Controls: {', '.join(project.get('existing_controls', []))}"""

    low_confidence = [t for t in threats if t.get("confidence") in ("Low", "Medium")][:10]
    open_questions = "\n".join([
        f"- {t.get('missing_info', '')}" for t in low_confidence if t.get("missing_info")
    ])

    user_prompt = f"""Based on this incomplete context, identify critical missing information needed for complete threat modeling.

PROJECT CONTEXT:
{context}

OPEN QUESTIONS FROM THREAT ANALYSIS:
{open_questions}

Return one JSON object with an "items" array:
{{
  "items": [
    {{
    "area": "area of concern (e.g., Webhook, Authorization, PII, Logging)",
    "question": "specific question to ask the dev/product team",
    "why_it_matters": "security/privacy impact if not clarified",
    "priority": "Critical|High|Medium|Low",
    "target_team": "Dev/Tech Lead|QA|Security|Product/Legal|DevOps",
    "question_to_ask": "ready-to-send concise question"
    }}
  ]
}}

Generate 5-8 questions covering the most critical gaps. Phrase questions so they can be pasted directly into Jira, Slack, or a review comment."""

    result = await chat_complete_json(
        system_prompt="You are a security analyst identifying information gaps for threat modeling. Return strict JSON.",
        user_prompt=user_prompt,
        base_url=cfg.get("base_url"),
        api_key=cfg.get("api_key"),
        model=cfg.get("model"),
        max_tokens=2500,
    )
    items = result if isinstance(result, list) else result.get("items", [])
    if not items:
        raise ValueError("Analysis engine returned an empty or invalid evidence-gap list")

    for item in items:
        item["missing_id"] = str(uuid.uuid4())

    return items


def _fallback_missing_info(project: dict) -> list:
    items = []
    if not project.get("auth_method"):
        items.append({"area": "Authentication", "question": "What authentication mechanism is used (JWT, session, API key)?", "why_it_matters": "Determines spoofing and session hijacking risk surface."})
    if not project.get("existing_controls"):
        items.append({"area": "Existing Controls", "question": "What security controls are already in place (WAF, rate limit, RBAC)?", "why_it_matters": "Avoids recommending controls that are already implemented."})
    items.extend([
        {"area": "Webhook", "question": "Does the webhook callback endpoint verify signature?", "why_it_matters": "Without signature verification, attacker can send fake callbacks to manipulate payment status."},
        {"area": "Authorization", "question": "Is there object ownership check on every resource endpoint?", "why_it_matters": "Missing check leads to IDOR — users accessing other users' data."},
        {"area": "Logging", "question": "Does the application log request bodies? Are PII fields filtered from logs?", "why_it_matters": "PII in logs is a privacy violation and compliance risk."},
        {"area": "Data Retention", "question": "What is the data retention period for personal data?", "why_it_matters": "Required for UU PDP / GDPR compliance."},
        {"area": "Rate Limiting", "question": "Are critical endpoints (login, payment) protected by rate limiting?", "why_it_matters": "Without rate limiting, endpoints are vulnerable to brute force and DoS."},
    ])
    return items[:8]


async def generate_assumptions(project: dict, threats: List[dict]) -> List[dict]:
    """Generate assumption register from threat analysis."""
    assumptions = []

    for i, threat in enumerate(threats):
        if threat.get("assumption"):
            assumptions.append({
                "assumption_id": str(uuid.uuid4()),
                "area": threat.get("threat_category", "General"),
                "assumption": threat.get("assumption"),
                "confidence": threat.get("confidence", "Medium"),
            })

    if not assumptions:
        # Generic fallback assumptions
        assumptions = [
            {"assumption_id": str(uuid.uuid4()), "area": "Authentication", "assumption": "Authentication is JWT-based unless documented otherwise", "confidence": "Medium"},
            {"assumption_id": str(uuid.uuid4()), "area": "Transport", "assumption": "All endpoints use HTTPS in production", "confidence": "High"},
            {"assumption_id": str(uuid.uuid4()), "area": "Authorization", "assumption": "Resource IDs are used as references in API endpoints (potential IDOR surface)", "confidence": "Medium"},
            {"assumption_id": str(uuid.uuid4()), "area": "Logging", "assumption": "Request logs may contain user-submitted data unless filtered", "confidence": "Low"},
        ]

    return assumptions
