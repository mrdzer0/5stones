"""Posture helpers for evidence, dedupe, review workflow, and readiness scoring."""
from __future__ import annotations
import hashlib
import re
import uuid
from datetime import datetime
from typing import Iterable


EVIDENCE_TYPES = {"direct", "context", "inference"}
_EVIDENCE_STOPWORDS = {
    "about", "after", "against", "also", "from", "into", "through", "using", "with",
    "data", "system", "service", "application", "component", "project", "threat", "user",
    "yang", "dari", "dengan", "untuk", "pada", "dalam", "atau", "dan", "the", "this",
}
_PROJECT_SIGNAL_FIELDS = (
    ("components", "Components", "Documented component"),
    ("entry_points", "Entry points", "Documented entry point"),
    ("data_involved", "Data involved", "Documented data"),
    ("external_systems", "External systems", "Documented external system"),
    ("actors", "Actors", "Documented actor"),
    ("critical_actions", "Critical actions", "Documented critical action"),
    ("existing_controls", "Existing controls", "Documented control"),
)


REQUIRED_CONTEXT = [
    {
        "key": "actors",
        "label": "Actors",
        "weight": 10,
        "question": "Who can interact with this feature, including admins, partners, systems, and anonymous users?",
    },
    {
        "key": "entry_points",
        "label": "Entry Points",
        "weight": 12,
        "question": "Which UI screens, API endpoints, webhook callbacks, jobs, or integrations can receive input?",
    },
    {
        "key": "data_involved",
        "label": "Data Classification",
        "weight": 12,
        "question": "What data fields are processed, and which fields are PII, financial, secret, or business critical?",
    },
    {
        "key": "auth_method",
        "label": "Authentication",
        "weight": 10,
        "question": "What authentication method is used, and how are sessions, tokens, or service credentials validated?",
    },
    {
        "key": "critical_actions",
        "label": "Critical Actions",
        "weight": 10,
        "question": "Which actions can change money, permissions, user data, business state, or compliance records?",
    },
    {
        "key": "external_systems",
        "label": "External Systems",
        "weight": 8,
        "question": "Which third-party, partner, internal platform, or downstream systems exchange data with this feature?",
    },
    {
        "key": "existing_controls",
        "label": "Existing Controls",
        "weight": 8,
        "question": "Which controls already exist, such as RBAC, rate limiting, webhook signatures, audit logs, masking, or WAF?",
    },
    {
        "key": "artifact_sources",
        "label": "Artifact Evidence",
        "weight": 30,
        "question": "Upload PRD, OpenAPI/Swagger, Postman collection, database schema, HAR, or endpoint inventory evidence.",
    },
]


def compute_completeness(project: dict) -> dict:
    """Score whether the project has enough context for a useful threat model."""
    total = sum(item["weight"] for item in REQUIRED_CONTEXT)
    earned = 0
    areas = []
    blockers = []

    for item in REQUIRED_CONTEXT:
        if item["key"] == "artifact_sources":
            artifact_score, artifact_details = _artifact_readiness_score(project, item["weight"])
            present = artifact_score > 0
            earned += artifact_score
            if not present:
                blockers.append({
                    "area": item["label"],
                    "question": item["question"],
                    "priority": "High",
                })
            areas.append({
                "area": item["label"],
                "present": present,
                "weight": item["weight"],
                "earned": artifact_score,
                "question": item["question"],
                **artifact_details,
            })
            continue

        value = project.get(item["key"])
        present = bool(value) if not isinstance(value, list) else len(value) > 0
        if present:
            earned += item["weight"]
        else:
            blockers.append({
                "area": item["label"],
                "question": item["question"],
                "priority": "High" if item["weight"] >= 12 else "Medium",
            })
        areas.append({
            "area": item["label"],
            "present": present,
            "weight": item["weight"],
            "earned": item["weight"] if present else 0,
            "question": item["question"],
        })

    score = round((earned / total) * 100) if total else 0
    if score >= 85:
        level = "Ready"
    elif score >= 65:
        level = "Usable with gaps"
    elif score >= 40:
        level = "High assumption load"
    else:
        level = "Insufficient context"

    return {
        "score": score,
        "level": level,
        "areas": areas,
        "artifact_count": _artifact_count(project),
        "artifact_types": sorted(_artifact_types(project)),
        "blockers": blockers[:6],
        "updated_at": datetime.utcnow().isoformat(),
    }


def _artifact_readiness_score(project: dict, weight: int) -> tuple[int, dict]:
    count = _artifact_count(project)
    types = _artifact_types(project)
    if count == 0:
        return 0, {"uploaded_count": 0, "source_types": []}

    score = 0
    score += min(count, 4) * 4
    score += min(len(types), 4) * 3
    if project.get("artifact_summary"):
        score += 4
    if project.get("extracted_data_flows"):
        score += 4
    if any(t in types for t in {"openapi", "postman", "har"}):
        score += 3
    if any(t in types for t in {"prd", "markdown"}):
        score += 2
    if any(t in types for t in {"database_schema", "csv"}):
        score += 1

    return min(weight, score), {
        "uploaded_count": count,
        "source_types": sorted(types),
    }


def _artifact_count(project: dict) -> int:
    sources = project.get("artifact_sources")
    if isinstance(sources, list) and sources:
        return sum(1 for source in sources if not isinstance(source, dict) or source.get("active", True))
    artifacts = project.get("artifacts")
    if isinstance(artifacts, list):
        return len(artifacts)
    return 0


def _artifact_types(project: dict) -> set[str]:
    types = set()
    for source in project.get("artifact_sources", []) or []:
        if isinstance(source, dict) and source.get("active", True) and source.get("artifact_type"):
            types.add(source["artifact_type"])
    return types


def threat_fingerprint(threat: dict) -> str:
    """Create a stable semantic key so reruns do not duplicate the same threat."""
    parts = [
        threat.get("framework", ""),
        threat.get("threat_category", ""),
        threat.get("component", ""),
        threat.get("source", ""),
        threat.get("destination", ""),
        threat.get("asset", ""),
        threat.get("trust_boundary", ""),
        _normalize(threat.get("threat_description", ""))[:180],
    ]
    raw = "|".join(_normalize(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def build_project_evidence_catalog(project: dict) -> list[dict]:
    """Build a bounded catalog of evidence and context signals that findings may cite."""
    candidates = []
    seen = set()

    def add(evidence_type: str, source: str, locator: str, snippet: str, topics=None, metadata=None):
        clean_snippet = " ".join(str(snippet or "").split())[:360]
        if not clean_snippet:
            return
        key = (evidence_type, source, locator, clean_snippet.lower())
        if key in seen:
            return
        seen.add(key)
        digest = hashlib.sha256("|".join(map(str, key)).encode("utf-8")).hexdigest()[:8].upper()
        candidate = {
            "evidence_id": f"EV-{digest}",
            "evidence_type": evidence_type,
            "source": source,
            "locator": locator,
            "snippet": clean_snippet,
            "topics": [str(topic)[:80] for topic in (topics or []) if topic],
        }
        candidate.update(metadata or {})
        candidates.append(candidate)

    # Only snippets verified during upload are treated as direct artifact evidence.
    for item in project.get("artifact_evidence", []) or []:
        if not isinstance(item, dict):
            continue
        filename = item.get("filename") or item.get("artifact_type") or "Uploaded artifact"
        add("direct", filename, item.get("locator") or "Artifact content", item.get("snippet"), item.get("topics"))

    for source in project.get("artifact_sources", []) or []:
        if not isinstance(source, dict) or not source.get("active", True):
            continue
        filename = source.get("filename") or source.get("artifact_type") or "Uploaded artifact"
        for item in source.get("evidence_items", []) or []:
            if isinstance(item, dict):
                add("direct", filename, item.get("locator") or "Artifact content", item.get("snippet"), item.get("topics"))

    for field, label, prefix in _PROJECT_SIGNAL_FIELDS:
        for value in project.get(field, []) or []:
            add("context", "Project context", label, f"{prefix}: {value}", [value, label])

    auth_method = project.get("auth_method")
    if auth_method and str(auth_method).strip() not in {"-", "Unknown"}:
        add("context", "Project context", "Authentication", f"Documented authentication: {auth_method}", [auth_method])

    for flow in project.get("extracted_data_flows", []) or []:
        if not isinstance(flow, dict):
            continue
        source = flow.get("source") or "Unknown source"
        destination = flow.get("destination") or "Unknown destination"
        flow_data = ", ".join(map(str, flow.get("data", []) or []))
        protocol = flow.get("protocol") or "unspecified protocol"
        evidence_type = str(flow.get("evidence_type") or "derived").lower()
        flow_label = "Documented flow" if evidence_type == "direct" else "Derived flow candidate"
        snippet = f"{flow_label}: {source} → {destination} via {protocol}"
        if flow_data:
            snippet += f" carrying {flow_data}"
        add(
            "context", "Project context", "Extracted data flow", snippet,
            [source, destination, flow_data],
            {"flow_source": source, "flow_destination": destination},
        )

    artifact_summary = project.get("artifact_summary")
    if artifact_summary:
        source_name = _primary_artifact_name(project)
        add("context", source_name, "Artifact summary", artifact_summary, [project.get("name")])

    description = project.get("description")
    if description:
        add("context", "Project intake", "Description", f"Project description: {description}", [description])

    return candidates


def build_evidence_context(project: dict, limit: int = 28) -> str:
    """Format the evidence catalog for an analysis prompt without exposing raw artifacts."""
    catalog = build_project_evidence_catalog(project)[:limit]
    if not catalog:
        return "No direct evidence or structured context is available. Use assumptions and cite no evidence IDs."
    return "\n".join(
        f"[{item['evidence_id']}] {item['evidence_type'].upper()} · {item['source']} · "
        f"{item['locator']}: {item['snippet']}"
        for item in catalog
    )


def enrich_threats(threats: Iterable[dict], project: dict, source: str) -> list:
    enriched = []
    catalog = build_project_evidence_catalog(project)

    for threat in threats:
        t = dict(threat)
        t["fingerprint"] = t.get("fingerprint") or threat_fingerprint(t)
        selected, supporting = _select_threat_evidence(t, catalog, source)
        t["evidence_type"] = selected["evidence_type"]
        t["evidence_source"] = selected["source"]
        t["evidence_locator"] = selected["locator"]
        t["evidence_snippet"] = selected["snippet"]
        t["evidence_refs"] = [item["evidence_id"] for item in supporting if item.get("evidence_id")]
        t["evidence"] = [_format_evidence_signal(item) for item in supporting]
        t["confidence_reason"] = _confidence_reason(t, selected)
        t["needs_human_review"] = t.get("needs_human_review", _needs_review(t))
        t["status"] = t.get("status") or ("Needs Info" if t["needs_human_review"] else "Open")
        enriched.append(t)

    return enriched


def normalize_report_evidence(report: dict, project: dict) -> dict:
    """Upgrade legacy generic evidence at read time while preserving reviewed findings."""
    threats = []
    for threat in report.get("threats", []) or []:
        if _needs_evidence_upgrade(threat, project):
            upgraded = enrich_threats([threat], project, threat.get("framework") or "framework")
            threats.append(upgraded[0])
        else:
            threats.append(threat)
    report["threats"] = threats
    return report


def merge_deduped_threats(existing: list, incoming: list) -> tuple[list, int]:
    """Merge incoming generated threats while preserving human review fields."""
    merged = []
    by_key = {}
    deduped = 0

    for threat in existing:
        t = dict(threat)
        t["fingerprint"] = t.get("fingerprint") or threat_fingerprint(t)
        by_key[t["fingerprint"]] = t
        merged.append(t)

    for threat in incoming:
        t = dict(threat)
        key = t.get("fingerprint") or threat_fingerprint(t)
        if key in by_key:
            existing_threat = by_key[key]
            for field in ["status", "owner", "review_notes", "reviewed_at"]:
                if existing_threat.get(field):
                    t[field] = existing_threat[field]
            t["threat_id"] = existing_threat.get("threat_id", t.get("threat_id"))
            index = merged.index(existing_threat)
            merged[index] = {**existing_threat, **t}
            by_key[key] = merged[index]
            deduped += 1
        else:
            by_key[key] = t
            merged.append(t)

    return merged, deduped


def enrich_controls(controls: Iterable[dict], threats: list, project: dict) -> list:
    threat_by_id = {t.get("threat_id"): t for t in threats}
    enriched = []

    for control in controls:
        c = dict(control)
        related = [threat_by_id[tid] for tid in c.get("threat_ids", []) if tid in threat_by_id]
        if not related:
            related = _related_threats_by_text(c, threats)

        components = _unique(t.get("component") or t.get("destination") or t.get("asset") for t in related)
        priorities = [t.get("risk_level", "Medium") for t in related]
        c["affected_components"] = c.get("affected_components") or components
        c["priority"] = c.get("priority") or _highest_priority(priorities)
        c["review_status"] = c.get("review_status") or "Open"
        c["checklist_items"] = c.get("checklist_items") or _control_checklist(c, related, project)
        c["verification_method"] = c.get("verification_method") or _verification_method(c)
        c["control_id"] = c.get("control_id") or str(uuid.uuid4())
        enriched.append(c)

    return enriched


def enrich_missing_info(items: Iterable[dict], project: dict) -> list:
    enriched = []
    for item in items:
        m = dict(item)
        area = (m.get("area") or "").lower()
        m["missing_id"] = m.get("missing_id") or str(uuid.uuid4())
        m["priority"] = m.get("priority") or _missing_priority(area)
        m["target_team"] = m.get("target_team") or _target_team(area)
        m["status"] = m.get("status") or "Open"
        m["question_to_ask"] = m.get("question_to_ask") or _question_to_ask(m)
        enriched.append(m)

    completeness = compute_completeness(project)
    known_questions = {(_normalize(i.get("question", "")), i.get("area")) for i in enriched}
    for blocker in completeness.get("blockers", []):
        key = (_normalize(blocker["question"]), blocker["area"])
        if key in known_questions:
            continue
        enriched.append({
            "missing_id": str(uuid.uuid4()),
            "area": blocker["area"],
            "question": blocker["question"],
            "question_to_ask": blocker["question"],
            "why_it_matters": "Threat quality and control recommendations depend on this context.",
            "priority": blocker["priority"],
            "target_team": _target_team(blocker["area"].lower()),
            "status": "Open",
        })

    return enriched[:10]


def enrich_assumptions(items: Iterable[dict], threats: list, project: dict) -> list:
    """Turn terse threat assumptions into reviewable assumption records."""
    enriched = []
    threat_by_area = {}
    for threat in threats:
        threat_by_area.setdefault(threat.get("threat_category", "General"), []).append(threat)

    for item in items:
        assumption = dict(item)
        area = assumption.get("area", "General")
        related = threat_by_area.get(area, [])
        if not related:
            related = _related_threats_by_text({"name": area, "description": assumption.get("assumption", "")}, threats)
        primary = related[0] if related else {}

        assumption["source"] = assumption.get("source") or _assumption_source(primary, project)
        assumption["evidence"] = assumption.get("evidence") or _assumption_evidence(primary, project)
        assumption["impact_if_wrong"] = assumption.get("impact_if_wrong") or _assumption_impact(area, primary)
        assumption["verification_question"] = assumption.get("verification_question") or _assumption_question(area, primary)
        assumption["recommended_validation"] = assumption.get("recommended_validation") or _assumption_validation(area, primary)
        assumption["related_threat_id"] = assumption.get("related_threat_id") or primary.get("threat_id")
        assumption["related_threat"] = assumption.get("related_threat") or primary.get("threat_description")
        assumption["owner"] = assumption.get("owner") or _target_team(area.lower())
        assumption["status"] = assumption.get("status") or "Open"
        enriched.append(assumption)

    return enriched


def update_item_by_id(items: list, id_field: str, item_id: str, patch: dict) -> bool:
    allowed = {"status", "owner", "review_notes", "review_status", "evidence", "priority"}
    for item in items:
        if item.get(id_field) == item_id:
            for key, value in patch.items():
                if key in allowed:
                    item[key] = value
            item["reviewed_at"] = datetime.utcnow().isoformat()
            return True
    return False


def _normalize(value: str) -> str:
    return " ".join(str(value or "").lower().strip().split())


def _unique(values: Iterable[str | None]) -> list:
    seen = []
    for value in values:
        if value and value not in seen:
            seen.append(value)
    return seen


def _primary_artifact_name(project: dict) -> str:
    sources = [
        source for source in (project.get("artifact_sources", []) or [])
        if isinstance(source, dict) and source.get("active", True)
    ]
    if sources and isinstance(sources[-1], dict):
        return sources[-1].get("filename") or sources[-1].get("artifact_type") or "Uploaded artifact"
    artifacts = project.get("artifacts", []) or []
    return str(artifacts[-1]) if artifacts else "Uploaded artifact"


def _tokenize_evidence(value: str) -> set[str]:
    return {
        token for token in re.findall(r"[a-z0-9_./-]+", str(value or "").lower())
        if len(token) >= 3 and token not in _EVIDENCE_STOPWORDS
    }


def _threat_evidence_text(threat: dict) -> str:
    fields = (
        "threat_category", "component", "source", "destination", "asset",
        "trust_boundary", "threat_description", "abuse_case", "recommended_control",
    )
    return " ".join(str(threat.get(field) or "") for field in fields)


def _candidate_score(candidate: dict, threat: dict, requested_refs: set[str]) -> int:
    threat_text = _threat_evidence_text(threat).lower()
    candidate_text = " ".join([
        candidate.get("snippet", ""), candidate.get("locator", ""),
        " ".join(candidate.get("topics", [])),
    ]).lower()
    overlap = _tokenize_evidence(threat_text) & _tokenize_evidence(candidate_text)
    score = len(overlap) * 3
    if candidate.get("evidence_type") == "direct":
        score += 1
    if candidate.get("locator") == "Extracted data flow":
        score += 2
    if candidate.get("locator") == "Artifact summary":
        score -= 4
    if candidate.get("evidence_id") in requested_refs:
        score += 7
    field_weights = {"component": 6, "asset": 5}
    for field, weight in field_weights.items():
        value = str(threat.get(field) or "").lower().strip()
        if len(value) >= 3 and (value in candidate_text or candidate_text in value):
            score += weight
    flow_source = str(candidate.get("flow_source") or "").lower().strip()
    flow_destination = str(candidate.get("flow_destination") or "").lower().strip()
    threat_source = str(threat.get("source") or "").lower().strip()
    threat_destination = str(threat.get("destination") or "").lower().strip()
    if flow_source or flow_destination:
        source_matches = _text_matches(threat_source, flow_source)
        destination_matches = _text_matches(threat_destination, flow_destination)
        reverse_source = _text_matches(threat_source, flow_destination)
        reverse_destination = _text_matches(threat_destination, flow_source)
        if source_matches:
            score += 10
        if destination_matches:
            score += 14
        if reverse_source and reverse_destination:
            score -= 14
    else:
        if threat_source and threat_source in candidate_text:
            score += 5
        if threat_destination and threat_destination in candidate_text:
            score += 7
    return score


def _text_matches(left: str, right: str) -> bool:
    if len(left) < 3 or len(right) < 3:
        return False
    return left in right or right in left


def _select_threat_evidence(threat: dict, catalog: list[dict], framework: str) -> tuple[dict, list[dict]]:
    requested_refs = {
        str(ref) for ref in (threat.get("evidence_refs") or [])
        if isinstance(ref, (str, int))
    }
    ranked = sorted(
        ((max(0, _candidate_score(item, threat, requested_refs)), item) for item in catalog),
        key=lambda pair: (pair[0], pair[1].get("evidence_type") == "direct"),
        reverse=True,
    )
    relevant = [item for score, item in ranked if score >= 3][:3]
    if relevant:
        return relevant[0], relevant

    component = threat.get("component") or threat.get("destination") or "the affected component"
    category = threat.get("threat_category") or "threat pattern"
    boundary = threat.get("trust_boundary")
    detail = f"Framework inference: {category} pattern applied to {component}"
    if boundary:
        detail += f" across {boundary}"
    inferred = {
        "evidence_id": None,
        "evidence_type": "inference",
        "source": f"{framework} framework analysis",
        "locator": category,
        "snippet": detail + ".",
        "topics": [],
    }
    return inferred, [inferred]


def _format_evidence_signal(item: dict) -> str:
    return f"{item.get('source')} · {item.get('locator')}: {item.get('snippet')}"


def _needs_evidence_upgrade(threat: dict, project: dict) -> bool:
    evidence_type = threat.get("evidence_type")
    if evidence_type not in EVIDENCE_TYPES:
        return True
    source = str(threat.get("evidence_source") or "").lower()
    if source in {"artifact", "manual_intake"}:
        return True
    summary = " ".join(str(project.get("artifact_summary") or "").split())
    snippet = " ".join(str(threat.get("evidence_snippet") or "").split())
    return bool(summary and snippet and (snippet == summary or snippet == summary[:420]))


def _confidence_reason(threat: dict, evidence: dict) -> str:
    confidence = threat.get("confidence", "Medium")
    evidence_type = evidence.get("evidence_type")
    locator = evidence.get("locator") or "available context"
    if evidence_type == "direct":
        return f"{confidence} confidence: supported by a direct artifact excerpt at {locator}; implementation still requires review."
    if evidence_type == "context":
        return f"{confidence} confidence: supported by the project context at {locator}, not yet by implementation evidence."
    return f"{confidence} confidence: inferred from the {threat.get('threat_category', 'framework')} pattern; validate with implementation evidence."


def _needs_review(threat: dict) -> bool:
    return bool(
        threat.get("confidence") in ("Low", "Medium")
        or threat.get("assumption")
        or threat.get("missing_info")
    )


def _related_threats_by_text(control: dict, threats: list) -> list:
    text = _normalize(" ".join([control.get("name", ""), control.get("description", ""), control.get("implementation_guidance", "")]))
    return [t for t in threats if _normalize(t.get("threat_category", "")) in text or _normalize(t.get("recommended_control", "")) in text][:5]


def _highest_priority(levels: Iterable[str]) -> str:
    order = ["Critical", "High", "Medium", "Low"]
    found = set(levels)
    for level in order:
        if level in found:
            return level
    return "Medium"


def _control_checklist(control: dict, related: list, project: dict) -> list:
    name = _normalize(control.get("name", ""))
    if "webhook" in name or "signature" in name:
        return [
            "Validate HMAC/signature before any state change.",
            "Reject stale timestamp and replayed nonce.",
            "Log rejected webhook attempts without storing sensitive payloads.",
        ]
    if "ownership" in name or "rbac" in name or "access" in name:
        return [
            "Enforce authorization server-side for every affected endpoint.",
            "Use authenticated subject from token/session, not client-submitted user identifiers.",
            "Add negative tests for cross-user and low-privilege access.",
        ]
    if "pii" in name or "mask" in name or "privacy" in name:
        return [
            "Remove unnecessary PII from responses and logs.",
            "Mask sensitive fields consistently in UI, API, and observability tooling.",
            "Document retention and deletion behavior for personal data.",
        ]
    if "rate" in name or "dos" in name:
        return [
            "Apply per-user and per-IP throttling to public or critical endpoints.",
            "Return 429 with a clear retry policy.",
            "Monitor rate-limit hits and alert on abuse patterns.",
        ]
    if control.get("implementation_guidance"):
        return [control["implementation_guidance"]]

    components = ", ".join(_unique(t.get("component") for t in related)[:3]) or ", ".join(project.get("entry_points", [])[:3])
    return [f"Implement this control for affected components: {components or 'project critical paths'}."]


def _verification_method(control: dict) -> str:
    name = _normalize(control.get("name", ""))
    if "audit" in name:
        return "Perform the critical action and verify append-only audit evidence includes actor, action, resource, and timestamp."
    if "rate" in name:
        return "Run burst requests and confirm 429 responses plus server-side telemetry."
    if "webhook" in name or "signature" in name:
        return "Send unsigned, invalid, stale, and replayed callbacks and confirm all are rejected before state mutation."
    if "ownership" in name or "rbac" in name or "access" in name:
        return "Run positive and negative authorization tests across user roles and resource owners."
    return "Attach request/response evidence, code reference, or automated test result showing the control works."


def _missing_priority(area: str) -> str:
    if any(key in area for key in ["authorization", "authentication", "webhook", "pii", "data", "critical"]):
        return "High"
    if any(key in area for key in ["logging", "retention", "controls"]):
        return "Medium"
    return "Low"


def _target_team(area: str) -> str:
    if any(key in area for key in ["privacy", "retention", "consent", "compliance"]):
        return "Product/Legal"
    if any(key in area for key in ["test", "qa"]):
        return "QA"
    if any(key in area for key in ["rate", "waf", "tls", "infra"]):
        return "DevOps"
    return "Dev/Tech Lead"


def _question_to_ask(item: dict) -> str:
    area = item.get("area", "General")
    question = item.get("question", "")
    return f"[{area}] {question}"


def _assumption_source(threat: dict, project: dict) -> str:
    if threat.get("evidence_source"):
        return threat["evidence_source"]
    if project.get("artifact_sources"):
        return "uploaded_artifact"
    return "manual_intake_or_common_pattern"


def _assumption_evidence(threat: dict, project: dict) -> str:
    if threat.get("evidence_snippet"):
        return threat["evidence_snippet"]
    evidence = threat.get("evidence") or []
    if evidence:
        return "; ".join(evidence[:3])
    if project.get("description"):
        return project["description"][:300]
    return "No direct evidence captured. Validate with implementation or developer confirmation."


def _assumption_impact(area: str, threat: dict) -> str:
    category = (area or "").lower()
    if "spoof" in category or "auth" in category:
        return "If false, attackers may impersonate users or services and bypass authentication controls."
    if "tamper" in category:
        return "If false, client or integration data may be modified to create unauthorized state changes."
    if "information" in category or "disclosure" in category or "pii" in category:
        return "If false, sensitive data may be exposed through API responses, logs, or cross-user access."
    if "elevation" in category or "privilege" in category:
        return "If false, low-privilege users may access privileged actions or data."
    if "repudiation" in category or "logging" in category:
        return "If false, critical actions may not be attributable during incident response or audit."
    if "denial" in category or "dos" in category:
        return "If false, public or critical endpoints may be vulnerable to abuse and availability degradation."
    return "If false, the generated threat and recommended control may be incomplete or incorrectly prioritized."


def _assumption_question(area: str, threat: dict) -> str:
    component = threat.get("component") or threat.get("destination") or "the affected component"
    category = (area or "").lower()
    if "spoof" in category or "auth" in category:
        return f"How does {component} validate identity, token signature, issuer/audience, expiry, and service credentials?"
    if "tamper" in category:
        return f"Which server-side validations prevent tampering for {component}, especially for critical fields or state changes?"
    if "information" in category or "disclosure" in category:
        return f"Which authorization and data minimization checks prevent sensitive data exposure in {component}?"
    if "elevation" in category or "privilege" in category:
        return f"Which server-side RBAC/ABAC checks protect privileged operations in {component}?"
    if "repudiation" in category:
        return f"Which immutable audit events are recorded for critical actions in {component}?"
    if "denial" in category:
        return f"Which rate limits, quotas, or circuit breakers protect {component} from abuse?"
    return f"What implementation evidence confirms this assumption for {component}?"


def _assumption_validation(area: str, threat: dict) -> str:
    category = (area or "").lower()
    if "spoof" in category or "auth" in category:
        return "Review auth middleware/config and run negative token tests."
    if "tamper" in category:
        return "Review server-side validation and execute parameter tampering tests."
    if "information" in category or "disclosure" in category:
        return "Review authorization checks and inspect API responses/logs for unnecessary sensitive fields."
    if "elevation" in category or "privilege" in category:
        return "Run cross-role access tests against privileged endpoints."
    if "repudiation" in category:
        return "Perform a critical action and verify audit log completeness and immutability."
    if "denial" in category:
        return "Run controlled rate-limit tests and inspect gateway/application telemetry."
    return "Confirm with code reference, config evidence, or automated test result."
