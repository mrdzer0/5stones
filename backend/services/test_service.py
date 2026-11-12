"""Test scenario generation service."""
from __future__ import annotations
import asyncio
import hashlib
import re
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
from backend.services.risk_service import RISK_METHODOLOGY_VERSION, threat_priority_level
from backend.services.action_quality_service import validate_test_scenarios

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
        scenarios = _fallback_scenarios(threats, controls)
        label_by_id = {
            str(item.get("id")): str(item.get("name") or item.get("id"))
            for collection in ("nodes", "flows", "data_objects", "boundaries")
            for item in ((dfd_model or {}).get(collection) or [])
            if isinstance(item, dict) and item.get("id")
        }
        threat_by_id = {str(item.get("threat_id")): item for item in threats if isinstance(item, dict) and item.get("threat_id")}
        for scenario in scenarios:
            threat = threat_by_id.get(str(scenario.get("threat_id"))) or {}
            target = _test_target_label(threat, label_by_id)
            if target and scenario.get("applicability_status") != "blocked":
                scenario["scenario_name"] = f"{scenario['scenario_name']} — {target}"[:180]
                scenario["steps"] = [f"Identify the canonical DFD target '{target}' and its authorized baseline",
                                     *(scenario.get("steps") or [])]
            source = str(threat.get("source") or "").strip()
            destination = str(threat.get("destination") or "").strip()
            asset = _test_data_label(threat)
            if source and destination and scenario.get("applicability_status") != "blocked":
                subject = f"synthetic {asset}" if asset else "representative synthetic data"
                setup = f"Prepare {subject} for the reported {source} → {destination} path in the test environment"
                scenario["steps"] = [setup, *(scenario.get("steps") or [])]
                scenario["scenario_name"] = f"{scenario['scenario_name']} · {source} → {destination}"[:180]
        normalized = normalize_test_scenarios(scenarios, threats, controls, dfd_model, evidence_ids)
        normalized, quality_warnings = validate_test_scenarios(normalized, threats, controls, dfd_model)
        return StageGenerationResult(
            normalized,
            assessment_status="fallback",
            response_shape="deterministic_fallback",
            warnings=["AI test generation was bypassed; generated scenarios require review.", *fallback_warnings, *quality_warnings],
            response_metadata={"engine": "fallback"},
        )

    cfg = get_active_provider_config(project.get("data_policy"), project.get("workspace_id"))

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
    "priority": "Critical|High|Medium|Low (advisory only; application derives final priority from threat risk)",
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

    # Test scenarios per threat have 10+ fields. 5000 tokens could not fit a full
    # response for projects with >6 threats, causing truncated_json.
    stage_budget = min(int(cfg.get("max_tokens") or 8000), 8000)
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
    normalized, quality_warnings = validate_test_scenarios(normalized, threats, controls, dfd_model)
    if not normalized:
        raise GenerationContractError(
            "Analysis engine returned no scenarios after normalization",
            code="test_scenarios_normalization_empty",
            metadata=response_metadata,
        )
    warnings.extend(quality_warnings)
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


def _linked_controls(controls: list | None, threat_id: str) -> list[dict]:
    return [
        control for control in (controls or [])
        if isinstance(control, dict)
        and control.get("mapping_status") != "unassigned"
        and threat_id in {str(ref) for ref in (control.get("threat_ids") or [])}
    ]


def _test_target_label(threat: dict, label_by_id: dict[str, str]) -> str | None:
    refs = [ref for ref in (threat.get("target_refs") or []) if isinstance(ref, dict) and str(ref.get("id")) in label_by_id]
    primary_ref = str(threat.get("primary_interaction_ref") or "")
    if primary_ref in label_by_id:
        return label_by_id[primary_ref]
    source = str(threat.get("source") or "").casefold()
    destination = str(threat.get("destination") or "").casefold()
    for ref in refs:
        label = label_by_id[str(ref["id"])]
        if ref.get("type") == "data_flow" and source and destination and source in label.casefold() and destination in label.casefold():
            return label
    for ref in refs:
        if ref.get("model_level") == "semantic" and ref.get("type") != "trust_boundary":
            return label_by_id[str(ref["id"])]
    for ref in refs:
        if ref.get("type") != "trust_boundary":
            return label_by_id[str(ref["id"])]
    return label_by_id[str(refs[0]["id"])] if refs else None


def _test_data_label(threat: dict) -> str | None:
    asset = str(threat.get("asset") or "").strip()
    if asset:
        return asset[:120]
    for ref in (threat.get("target_refs") or []):
        if isinstance(ref, dict) and ref.get("type") in {"data_object", "data_asset"} and ref.get("label"):
            return str(ref["label"])[:120]
    context = " ".join(str(threat.get(field) or "") for field in ("threat_description", "recommended_control")).casefold()
    for pattern, label in (
        (r"\bemail\b", "email addresses"), (r"\bphone\b", "phone numbers"),
        (r"\b(?:location|coordinates?|geolocat\w*)\b", "location data"),
        (r"\b(?:identifier|user id|account id)\b", "identifiers"),
        (r"\b(?:token|api key|secret)\b", "credentials or tokens"),
    ):
        if re.search(pattern, context):
            return label
    return None


def _tailor_privacy_scenario(scenario: dict, threat: dict, category: str) -> None:
    """Use a testable failure mechanism; leave unsupported cases blocked for design review."""
    context = " ".join(str(threat.get(field) or "") for field in (
        "threat_description", "recommended_control", "asset", "scenario", "abuse_case", "component",
    )).casefold()
    data = _test_data_label(threat) or "the affected data"
    source, destination = (str(threat.get(field) or "").strip() for field in ("source", "destination"))
    path = f"{source} → {destination}" if source and destination else "the affected DFD interaction"
    if category in {"Data Disclosure", "Information Disclosure"}:
        if re.search(r"\b(?:external|third[- ]party|vendor|provider)\b", context) and re.search(r"\b(?:ai|llm|gpt|gemini|language model)\b", context):
            scenario.update({
                "scenario_name": "External AI egress — verify field allowlist and redaction",
                "preconditions": f"Isolated AI integration, tagged synthetic {data}, and an approved outbound field allowlist",
                "steps": [f"Seed tagged synthetic {data} on {path} in the test environment",
                          "Capture the provider-bound request before it leaves the application boundary",
                          "Compare every outbound field with the documented AI-processing purpose and allowlist",
                          "Verify unnecessary identifiers/content are removed or redacted; inspect integration logs and provider retention settings"],
                "expected_result": "Only approved fields reach the external AI provider; unnecessary sensitive values are absent from outbound payloads and logs.",
                "evidence_needed": ["Redacted provider-bound request", "Outbound field allowlist", "Integration log and retention configuration"],
            })
        elif re.search(r"\b(?:logs?|telemetry|traces?)\b", context):
            scenario.update({
                "scenario_name": "Sensitive logging — verify redaction at collection",
                "preconditions": f"Test logging access and tagged synthetic {data}",
                "steps": [f"Submit tagged synthetic {data} through {path}",
                          "Capture application logs, traces, and error telemetry for the transaction",
                          "Search for the raw tagged values and compare with the approved logging schema",
                          "Verify sensitive fields are absent or masked before storage and forwarding"],
                "expected_result": "Raw sensitive values are not persisted or forwarded in logs or telemetry.",
                "evidence_needed": ["Tagged test request", "Redacted log/trace capture", "Logging schema"],
            })
        elif _test_data_label(threat) or re.search(r"\b(?:recipient|response|expos|disclos|read)\b", context):
            scenario.update({
                "scenario_name": f"Recipient-scope disclosure — verify {data}"[:180],
                "preconditions": f"Tagged synthetic {data}, documented purpose and intended recipients for {path}",
                "steps": [f"Seed tagged synthetic {data} and exercise {path} under an authorized test identity",
                          "Capture the response or outbound payload and list the fields visible to the intended recipient",
                          "Repeat with a recipient outside the documented scope, when that access path exists",
                          f"Verify {data} is absent, masked, or access-denied outside the authorized purpose"],
                "expected_result": f"Only intended recipients receive the minimum necessary {data}; out-of-scope access is denied or redacted.",
                "evidence_needed": ["Authorized and out-of-scope captures", "Purpose/recipient matrix", "Field-level comparison"],
            })
        else:
            scenario["applicability_status"] = "blocked"
            scenario["applicability_reason"] = "Disclosure channel and affected data fields are not specific enough to design an executable test."
    elif category == "Linking":
        if re.search(r"\b(?:payment|transaction|billing|card)\b", context) and re.search(r"\b(?:gateway|provider|merchant|third[- ]party)\b", context):
            scenario.update({
                "scenario_name": "Payment-gateway linkability — test merchant isolation",
                "preconditions": "Two isolated synthetic merchant contexts, test payment records, provider-bound field inventory, and approved payment-purpose policy",
                "steps": [f"Create separate synthetic payment transactions for two merchant contexts on {path}",
                          "Capture provider-bound payloads and merchant-visible transaction records for each context",
                          "Compare customer, card/token, order, and transaction identifiers against the approved purpose and recipient scope",
                          "Attempt cross-merchant correlation using only identifiers exposed to the lower-privilege merchant or provider integration",
                          "Verify unrelated fields are omitted and identifiers or tokens are purpose/merchant scoped as documented"],
                "expected_result": "A merchant cannot correlate another merchant's payment records beyond the documented purpose; provider-bound data is minimized.",
                "evidence_needed": ["Redacted provider-bound payloads", "Merchant-scope records", "Payment field inventory and purpose policy", "Cross-merchant correlation result"],
            })
        elif re.search(r"\b(?:separat\w* identifiers?|join keys?|pseudonym\w*|anonymiz\w*|cross[- ]context)\b", context):
            scenario.update({
                "scenario_name": "Cross-context linkage — verify identifier separation",
                "preconditions": f"Two synthetic records with distinguishable {data} across separate processing contexts",
                "steps": [f"Create two synthetic records on {path} with distinct purpose-scoped identifiers",
                          "Capture the exposed identifiers and metadata available to a lower-privilege actor",
                          "Attempt to join the records using only those exposed fields",
                          "Verify join keys and direct identifiers remain separated or inaccessible outside the approved purpose"],
                "expected_result": "An unauthorized actor cannot correlate the synthetic records across contexts using exposed identifiers or metadata.",
                "evidence_needed": ["Synthetic record inventory", "Captured identifier fields", "Cross-context join result"],
            })
        elif re.search(r"\b(?:location|geolocat\w*|coordinates?|map|fuzz\w*|precision)\b", context):
            scenario.update({
                "scenario_name": "Location linkability — verify precision and audience",
                "preconditions": "Two synthetic records with known precise coordinates and documented public/privileged views",
                "steps": [f"Create synthetic location records on {path} with distinguishable precise coordinates",
                          "Capture public and authorized views of the same records",
                          "Compare exposed precision and attempt to correlate records across views",
                          "Verify public output is aggregated/fuzzed and detailed coordinates require the documented authorization"],
                "expected_result": "Public location precision does not enable unintended linkage; detailed coordinates are restricted to authorized viewers.",
                "evidence_needed": ["Synthetic coordinates", "Public and authorized view captures", "Precision and access policy"],
            })
        elif re.search(r"\b(?:identifier|correlat\w*|linkab\w*)\b", context):
            scenario.update({
                "scenario_name": "Identifier linkability — test cross-flow correlation",
                "preconditions": f"Two synthetic records containing {data} and a documented separation policy",
                "steps": [f"Create records in separate contexts associated with {path}",
                          "Capture identifiers visible in each context to the same unprivileged actor",
                          "Attempt cross-flow correlation using the captured identifiers",
                          "Verify identifiers are scoped, rotated, or hidden as required by the separation policy"],
                "expected_result": "Exposed identifiers do not permit correlation beyond the documented purpose.",
                "evidence_needed": ["Identifier inventory", "Cross-flow captures", "Correlation result"],
            })
        else:
            scenario["applicability_status"] = "blocked"
            scenario["applicability_reason"] = "Linkability mechanism and identifiers are not specific enough to design an executable test."


def _fallback_scenarios(threats: list, controls: list | None = None) -> list:
    templates = {
        "Information Disclosure": {
            "scenario_name": "Sensitive Data Exposure — Verify Response and Recipient Scope",
            "preconditions": "Representative test data, a documented recipient/purpose, and the affected read path",
            "steps": [
                "Capture the normal response on the affected path using test data",
                "Compare returned fields and recipients with the documented purpose and caller permissions",
                "Attempt an unauthorized read using a lower-privilege test account where applicable",
                "Check responses and logs for unnecessary sensitive values"
            ],
            "expected_result": "Unauthorized reads are rejected and responses contain only necessary data for the intended recipient",
            "evidence_needed": ["Authorized and unauthorized request-response captures", "Data inventory", "Relevant audit logs"],
            "related_control": "PII Data Minimization and Masking",
            "priority": "High",
            "owner": "QA/Security"
        },
        "Tampering": {
            "scenario_name": "Request Tampering — Modify a Security-Relevant Field",
            "preconditions": "A controlled test account, representative request, and expected server-side validation rules",
            "steps": [
                "Capture a normal request on the affected flow",
                "Modify a field or state transition relevant to the threat without changing unrelated fields",
                "Replay the altered request in the test environment",
                "Compare the response, stored state, and audit event with the expected behavior"
            ],
            "expected_result": "Server rejects or safely validates the altered value and does not commit an unauthorized state change",
            "evidence_needed": ["Altered request", "Server response", "Relevant state before/after"],
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
            "scenario_name": "Rate Limit Test — Controlled Request Burst",
            "preconditions": "Approved test environment, documented rate threshold, and monitoring access",
            "steps": [
                "Agree a safe test limit and observe baseline latency",
                "Send a bounded burst just above the configured threshold",
                "Observe response codes, retry guidance, and service health",
                "Stop the test if error rate or latency exceeds the agreed safety limit"
            ],
            "expected_result": "The configured throttle activates without degrading service; clients receive the documented retry behavior",
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
        linked = _linked_controls(controls, str(threat["threat_id"]))
        control = next((item for item in linked if str(item.get("name") or "").casefold() == str(s.get("related_control") or "").casefold()), None)
        control = control or (linked[0] if linked else None)
        if control:
            s["related_control_id"] = control.get("control_id")
            s["related_control"] = control.get("name")
        elif controls is not None:
            s["related_control"] = None
            s["applicability_status"] = "blocked"
            s["applicability_reason"] = "No mapped control is linked to this threat; review control applicability before execution."
        _tailor_privacy_scenario(s, threat, canonical_category)
        if s.get("scenario_name") == "Payment-gateway linkability — test merchant isolation":
            payment_control = next(
                (item for item in linked if item.get("catalog_id") == "ctrl-020"
                 or item.get("control_id") == "CAT-ctrl-020"), None
            )
            if payment_control:
                s["related_control_id"] = payment_control.get("control_id")
                s["related_control"] = payment_control.get("name")
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
    control = next(iter(_linked_controls(controls, str(threat.get("threat_id")))), None)
    return {
        "scenario_name": "Verification blocked — review threat record",
        "preconditions": "Threat record and canonical DFD context must be reviewed before execution",
        "steps": ["Review the threat category and supporting evidence", "Confirm the applicable interaction and control", "Replace this blocked scenario with an executable verification case"],
        "expected_result": "A reviewed, evidence-backed test scenario is defined before execution.",
        "evidence_needed": ["Threat review decision", "DFD target evidence", "Applicable control evidence"],
        "related_control": control.get("name") if control else None,
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
        item["provider_priority"] = item.get("provider_priority") or item.get("priority")
        item["priority"] = threat_priority_level(threat)
        item["priority_source"] = "deterministic_threat_risk"
        item["risk_methodology_version"] = RISK_METHODOLOGY_VERSION
        item["preconditions"] = preconditions
        item["expected_result"] = expected
        item["steps"] = [str(step).strip() for step in steps if str(step).strip()]
        if not item["steps"]:
            continue
        linked = _linked_controls(controls, threat_id)
        related_id = str(item.get("related_control_id") or "")
        related_name = str(item.get("related_control") or "").casefold()
        related_control = next((control for control in linked if related_id and str(control.get("control_id")) == related_id), None)
        if not related_control:
            related_control = next((control for control in linked if related_name and str(control.get("name") or "").casefold() == related_name), None)
        if related_control:
            item["related_control_id"] = related_control.get("control_id")
            item["related_control"] = related_control.get("name")
        else:
            item.pop("related_control_id", None)
            item["related_control"] = None
        raw_refs = item.get("target_refs") if isinstance(item.get("target_refs"), list) else []
        refs = [
            {"type": str(ref.get("type") or "dfd_element"), "id": str(ref["id"])}
            for ref in raw_refs
            if isinstance(ref, dict) and ref.get("id") and (not valid_dfd_ids or str(ref["id"]) in valid_dfd_ids)
        ]
        item["target_refs"] = refs or list(threat.get("target_refs") or [])
        primary_ref = str(threat.get("primary_interaction_ref") or "")
        if primary_ref and (not valid_dfd_ids or primary_ref in valid_dfd_ids) and not any(
            str(ref.get("id")) == primary_ref for ref in item["target_refs"] if isinstance(ref, dict)
        ):
            item["target_refs"].append({"type": "data_flow", "id": primary_ref})
        applicability_status = str(item.get("applicability_status") or "applicable").strip().casefold()
        if applicability_status not in {"applicable", "not_applicable", "blocked"}:
            applicability_status = "applicable"
        if controls is not None and not related_control and applicability_status == "applicable":
            applicability_status = "blocked"
            item["applicability_reason"] = "No mapped control linked to this threat was verified for this scenario."
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

    cfg = get_active_provider_config(project.get("data_policy"), project.get("workspace_id"))

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

    result = await asyncio.wait_for(chat_complete_json(
        system_prompt="You are a security analyst identifying information gaps for threat modeling. Return strict JSON.",
        user_prompt=user_prompt,
        base_url=cfg.get("base_url"),
        api_key=cfg.get("api_key"),
        model=cfg.get("model"),
        max_tokens=1500,
        max_format_retries=1,
    ), timeout=20)
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
