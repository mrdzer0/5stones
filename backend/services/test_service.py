"""Test scenario generation service."""
from __future__ import annotations
import hashlib
import uuid
from typing import List
from backend.services.ai_service import chat_complete_json, get_active_provider_config

SYSTEM_PROMPT = """You are a security test engineer creating security test scenarios for QA and Security teams.
Each scenario must be actionable, specific, and executable. Return one strict JSON object."""


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
        return normalize_test_scenarios(_fallback_scenarios(threats, controls), threats, controls, dfd_model, evidence_ids)

    cfg = get_active_provider_config(project.get("data_policy"))

    threats_summary = "\n".join([
        f"- ID: {t.get('threat_id')}\n  Framework: {t.get('framework', 'unknown')}\n  Category: {t.get('threat_category', 'unknown')}\n  Description: {t.get('threat_description', '')}\n  Recommended Control: {t.get('recommended_control','')}\n  DFD targets: {t.get('target_refs') or []}"
        for t in threats
        if isinstance(t, dict) and t.get("threat_id")
    ])

    user_prompt = f"""Generate security test scenarios mapped to the following threat catalog.

PROJECT ENVIRONMENT:
{project.get('environment', 'production')}

THREATS:
{threats_summary}

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
    "execution_status": "Not Run|Passed|Failed|Blocked",
    "actual_result": "leave empty until executed",
    "execution_evidence_refs": ["valid evidence IDs after execution"]
    }}
  ]
}}"""

    result = await chat_complete_json(
        system_prompt=SYSTEM_PROMPT,
        user_prompt=user_prompt,
        base_url=cfg.get("base_url"),
        api_key=cfg.get("api_key"),
        model=cfg.get("model"),
        max_tokens=3500,
    )
    scenarios = result if isinstance(result, list) else result.get("scenarios", [])
    if not isinstance(scenarios, list):
        raise ValueError("Analysis engine returned a scenarios field that is not an array")
    if not scenarios:
        raise ValueError("Analysis engine returned an empty or invalid test-scenario list")

    normalized = normalize_test_scenarios(scenarios, threats, controls, dfd_model, evidence_ids)
    if not normalized:
        raise ValueError("Analysis engine returned no scenarios linked to active threats")
    return normalized


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
            "scenario_name": "Webhook Spoofing — Send Callback Without Valid Signature",
            "preconditions": "Access to webhook endpoint URL",
            "steps": [
                "Craft webhook payload mimicking legitimate provider",
                "Send POST without signature header",
                "Send POST with invalid signature",
                "Observe server response and state change"
            ],
            "expected_result": "Server rejects unsigned/invalid requests with 400/401",
            "evidence_needed": ["Request-response log", "Server audit log"],
            "related_control": "HMAC Signature Verification",
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
        category = threat.get("threat_category", "")
        template = templates.get(category, {
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
    for raw in scenarios or []:
        if not isinstance(raw, dict):
            continue
        threat_id = str(raw.get("threat_id") or "")
        threat = threat_by_id.get(threat_id)
        name = str(raw.get("scenario_name") or "").strip()
        preconditions = str(raw.get("preconditions") or "").strip()
        expected = str(raw.get("expected_result") or "").strip()
        steps = raw.get("steps")
        if not threat or not name or not preconditions or not expected or not isinstance(steps, list) or not steps:
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
        item["execution_status"] = item.get("execution_status") or "Not Run"
        item["actual_result"] = item.get("actual_result") or ""
        item["execution_evidence_refs"] = [
            str(ref) for ref in (item.get("execution_evidence_refs") or [])
            if evidence_ids is None or str(ref) in evidence_ids
        ]
        item["verification_status"] = "not_executed" if item["execution_status"] == "Not Run" else "executed"
        item["test_fingerprint"] = _scenario_fingerprint(item)
        item["test_id"] = item.get("test_id") or f"TM-{item['test_fingerprint'][:10].upper()}"
        normalized.append(item)
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
