"""Test scenario generation service."""
from __future__ import annotations
import uuid
from typing import List
from backend.services.ai_service import chat_complete_json, get_active_provider_config

SYSTEM_PROMPT = """You are a security test engineer creating security test scenarios for QA and Security teams.
Each scenario must be actionable, specific, and executable. Return one strict JSON object."""


async def generate_test_scenarios(threats: List[dict], project: dict, force_fallback: bool = False) -> List[dict]:
    """Generate test scenarios mapped to generated threats."""
    if force_fallback:
        return _fallback_scenarios(threats)

    cfg = get_active_provider_config()

    threats_summary = "\n".join([
        f"- ID: {t['threat_id']}\n  Category: {t['threat_category']}\n  Description: {t['threat_description']}\n  Recommended Control: {t.get('recommended_control','')}"
        for t in threats[:15]
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
    "related_control": "control being tested",
    "priority": "Critical|High|Medium|Low",
    "owner": "QA|Security|QA/Security",
    "threat_id": "the threat_id this test covers"
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
    if not scenarios:
        raise ValueError("Analysis engine returned an empty or invalid test-scenario list")

    for s in scenarios:
        s["test_id"] = s.get("test_id") or f"TM-{str(uuid.uuid4())[:6].upper()}"

    return scenarios


def _fallback_scenarios(threats: list) -> list:
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
    }

    scenarios = []
    for i, threat in enumerate(threats[:10]):
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
        s["test_id"] = f"TM-{(i+1):03d}"
        s["threat_id"] = threat.get("threat_id", "")
        s["scenario_name"] = f"TM-{(i+1):03d}: {s['scenario_name']}"
        scenarios.append(s)

    return scenarios


async def generate_missing_info(project: dict, threats: List[dict], force_fallback: bool = False) -> List[dict]:
    """Generate list of missing information needed for better threat modeling."""
    if force_fallback:
        return _fallback_missing_info(project)

    cfg = get_active_provider_config()

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
