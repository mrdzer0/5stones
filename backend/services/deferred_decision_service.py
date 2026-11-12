"""Canonical deferred-gap and reviewer-decision workflow for CR5.

The analysis pipeline can have several producers for the same unanswered
question: completeness, STRIDE, LINDDUN, controls, tests, and DFD review.
This service gives those producers one stable decision identity and records
the selective dependency impact of a reviewer decision.
"""
from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from datetime import datetime, timezone
from typing import Iterable


DECISION_SCHEMA_VERSION = "cr5-deferred-decision-v1"
DECISION_STATES = {
    "open", "assigned", "answered", "accepted_assumption", "deferred", "obsolete",
}
DECISION_STATUS_LABELS = {
    "open": "Open",
    "assigned": "Assigned",
    "answered": "Answered",
    "accepted_assumption": "Accepted assumption",
    "deferred": "Deferred",
    "obsolete": "Obsolete",
}
_STATE_ALIASES = {
    "": "open", "open": "open", "candidate": "open", "needs info": "open",
    "assigned": "assigned", "in progress": "assigned",
    "answered": "answered", "resolved": "answered", "complete": "answered",
    "accepted": "accepted_assumption", "accepted assumption": "accepted_assumption",
    "accepted_assumption": "accepted_assumption", "deferred": "deferred",
    "obsolete": "obsolete", "closed": "obsolete",
}
_STOPWORDS = {
    "a", "an", "the", "is", "are", "be", "to", "of", "in", "on", "for", "and", "or",
    "what", "which", "how", "who", "does", "do", "can", "will", "should", "please",
    "documented", "document", "confirm", "provide", "define", "specify", "exact", "details",
}


def _text(value: object) -> str:
    return " ".join(str(value or "").split()).strip()


def _unique(values: Iterable[object]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        text = _text(value)
        if text and text.casefold() not in seen:
            result.append(text)
            seen.add(text.casefold())
    return result


def normalize_decision_state(value: object) -> str:
    text = _text(value).casefold().replace("-", "_")
    text = text.replace("_", " ")
    return _STATE_ALIASES.get(text, "open")


def decision_status(state: object) -> str:
    return DECISION_STATUS_LABELS[normalize_decision_state(state)]


def _topic_key(text: object) -> str:
    value = _text(text).casefold()
    patterns = (
        ("authentication_authorization", r"\b(authenticat|authorization|authorize|rbac|role|permission|access control|mfa|jwt|session|identity)"),
        ("key_certificate_rotation", r"\b(key|certificate|credential).{0,40}\b(rotat|revok|expiry|expire)\b|\b(rotat|revok).{0,40}\b(key|certificate|credential)"),
        ("tenant_isolation", r"\b(tenant|workspace).{0,50}\b(isolat|cross[- ]tenant|scope|boundary)\b|\b(isolat|cross[- ]tenant).{0,50}\b(tenant|workspace)"),
        ("deletion_propagation", r"\b(delete|deletion|purge|erasure|offboard).{0,60}\b(propagat|backup|index|processor|store)"),
        ("idempotency_replay", r"\b(idempot|replay|duplicate event|duplicate transaction|nonce|timestamp)"),
        ("provider_terms", r"\b(provider|vendor|third[- ]party|llm|model).{0,60}\b(retention|training|processing|region|terms|agreement)"),
        ("human_approval", r"\b(human approval|manual approval|break[- ]glass|override|operator approval|autonomous)"),
        ("dlq_schema_ownership", r"\b(dead[- ]letter|dlq|queue poisoning|schema|payload version|retry ownership)"),
        ("consent_privacy", r"\b(consent|notice|legal basis|privacy|personal data|pii|phi|biometric)"),
        ("retention", r"\b(retention|retain|storage duration|lifecycle)"),
        ("operational_owner", r"\b(owner|on[- ]call|incident response|responsible team)"),
    )
    for key, pattern in patterns:
        if re.search(pattern, value):
            return key
    tokens = [token for token in re.findall(r"[a-z0-9][a-z0-9_-]*", value) if token not in _STOPWORDS]
    return "generic:" + " ".join(tokens[:10])


def decision_fingerprint(question: object, area: object = "") -> str:
    """Semantic identity that merges equivalent questions across producers."""
    payload = f"{_topic_key(question)}|{_topic_key(area)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def _typed_ref(ref: object, default_type: str = "dfd_element") -> dict | None:
    if isinstance(ref, dict) and ref.get("id"):
        return {"type": _text(ref.get("type")) or default_type, "id": _text(ref.get("id"))}
    if ref:
        return {"type": default_type, "id": _text(ref)}
    return None


def _refs_from_raw(raw: dict) -> list[dict]:
    refs: list[dict] = []
    for ref in raw.get("target_refs") or []:
        typed = _typed_ref(ref)
        if typed:
            refs.append(typed)
    for ref in raw.get("linked_refs") or []:
        typed = _typed_ref(ref)
        if typed:
            refs.append(typed)
    for key, ref_type in (("primary_interaction_ref", "data_flow"), ("related_threat_id", "threat"), ("related_control_id", "control"), ("threat_id", "threat")):
        typed = _typed_ref(raw.get(key), ref_type)
        if typed:
            refs.append(typed)
    return _dedupe_refs(refs)


def _dedupe_refs(refs: Iterable[dict]) -> list[dict]:
    result = []
    seen = set()
    for ref in refs or []:
        if not isinstance(ref, dict) or not ref.get("id"):
            continue
        key = (str(ref.get("type") or "dfd_element"), str(ref.get("id")))
        if key not in seen:
            seen.add(key)
            result.append({"type": key[0], "id": key[1]})
    return result


def _dependency_refs(raw: dict, source_type: str) -> dict:
    refs = _refs_from_raw(raw)
    dfd = [ref["id"] for ref in refs if ref["type"] in {"data_flow", "flow", "dfd_element", "process", "entity", "data_store", "data_object", "boundary"}]
    threats = _unique([
        raw.get("related_threat_id"), raw.get("threat_id"),
        *(raw.get("threat_ids") or []),
    ])
    controls = _unique([raw.get("related_control_id"), *(raw.get("control_ids") or [])])
    tests = _unique([raw.get("test_id"), *(raw.get("test_ids") or [])])
    for ref in refs:
        if ref["type"] == "threat":
            threats.append(ref["id"])
        elif ref["type"] == "control":
            controls.append(ref["id"])
        elif ref["type"] in {"test", "test_scenario"}:
            tests.append(ref["id"])
    return {
        "dfd_refs": _unique(dfd),
        "threat_ids": _unique(threats),
        "control_ids": _unique(controls),
        "test_ids": _unique(tests),
        "source_type": source_type,
    }


def _candidate(
    raw: dict,
    source_type: str,
    source_id: str,
    *,
    question: str,
    area: str,
    effect: str,
    owner: str,
    next_action: str,
    priority: str = "Medium",
) -> dict:
    question = _text(question) or "What evidence or decision is required to complete this assessment?"
    area = _text(area) or "Analysis context"
    state = normalize_decision_state(raw.get("state") or raw.get("status"))
    refs = _refs_from_raw(raw)
    linked_object = _text(raw.get("linked_object"))
    if linked_object and not any(ref["id"] == linked_object for ref in refs):
        refs.append({"type": "linked_object", "id": linked_object})
    fingerprint = decision_fingerprint(question, area)
    return {
        "decision_id": f"decision-{fingerprint}",
        "decision_fingerprint": fingerprint,
        "decision_schema_version": DECISION_SCHEMA_VERSION,
        "decision_type": source_type,
        "area": area,
        "question": question,
        "question_to_ask": question,
        "effect_on_analysis": _text(effect) or "A dependent analysis decision remains unresolved.",
        "effect_on_signoff": "Blocks sign-off until this decision is answered, explicitly accepted, or marked obsolete.",
        "priority": _text(raw.get("priority")) or priority,
        "owner": _text(raw.get("owner") or raw.get("target_team")) or owner,
        "next_action": _text(raw.get("next_action")) or next_action,
        "state": state,
        "status": decision_status(state),
        "linked_refs": refs,
        "linked_object": linked_object or (refs[0]["id"] if refs else f"decision:{fingerprint}"),
        "evidence_refs": _unique(raw.get("evidence_refs") or raw.get("source_refs") or []),
        "source_refs": [{"type": source_type, "id": source_id}],
        "dependency_refs": _dependency_refs(raw, source_type),
        "answer": _text(raw.get("answer") or raw.get("resolution")),
        "notes": _text(raw.get("notes")),
        "due_at": _text(raw.get("due_at") or raw.get("follow_up_date")),
        "history": [entry for entry in (raw.get("history") or []) if isinstance(entry, dict)],
        "source_present": True,
    }


def _flow_refs(model: dict) -> list[dict]:
    flows = [item for item in (model.get("flows") or []) if isinstance(item, dict) and item.get("id")]
    if not flows:
        return []
    return [{"type": "data_flow", "id": str(item["id"])} for item in flows[:3]]


def _rule_topic_candidates(project: dict, dfd_model: dict | None) -> list[dict]:
    """Targeted CR5-A05 questions missed by generic completeness scoring."""
    model = dfd_model if isinstance(dfd_model, dict) else {}
    text = " ".join(
        _text(project.get(key)) for key in (
            "name", "description", "actors", "components", "data_involved",
            "external_systems", "critical_actions", "extracted_data_flows", "artifact_summary",
        )
    ).casefold()
    rules = [
        ("key_certificate_rotation", ("provider", "external", "webhook", "certificate", "token", "credential"), "What is the key or certificate rotation, overlap, revocation, and emergency-owner procedure?", "Security / Platform", "Key lifecycle and provider impersonation cannot be verified."),
        ("break_glass_owner", ("medical", "health", "clinical", "sensitive", "emergency"), "Who approves, monitors, and reviews break-glass access, and what evidence is retained?", "Security / Operations", "Emergency privilege escalation and auditability remain unresolved."),
        ("deletion_propagation", ("data", "tenant", "workspace", "personal", "record", "offboard"), "How does deletion or offboarding propagate to stores, indexes, backups, queues, and downstream processors?", "Data owner / Engineering", "Stale-data exposure and privacy deletion cannot be tested end-to-end."),
        ("idempotency_replay", ("payment", "wallet", "transaction", "webhook", "event", "queue"), "What idempotency key, replay window, duplicate handling, and recovery behavior protect state-changing interactions?", "Engineering / Operations", "Replay and duplicate side effects cannot be verified."),
        ("provider_terms", ("provider", "vendor", "third", "llm", "ai", "model"), "What provider processing, retention, training-use, region, and contractual terms apply to exchanged data?", "Product / Legal", "External-provider privacy and retention analysis lacks a documented basis."),
        ("human_approval", ("ai", "assistant", "agent", "automation", "critical", "approval"), "Which actions require human approval, and what tool permissions and escalation boundary are enforced?", "Product / Security", "Agent over-trust and unauthorized automation lack a precise boundary."),
        ("tenant_isolation", ("tenant", "workspace", "organization", "multi"), "Where is tenant or workspace isolation enforced for APIs, search, storage, exports, and background jobs?", "Platform Security", "Cross-tenant disclosure cannot be assessed end-to-end."),
        ("dlq_schema_ownership", ("webhook", "event", "queue", "delivery", "retry"), "Who owns dead-letter recovery and payload schema/version compatibility for failed or retried events?", "Event platform owner", "Queue poisoning and schema-drift recovery lack accountable ownership."),
    ]
    candidates = []
    flow_refs = _flow_refs(model)
    for topic, keywords, question, owner, effect in rules:
        if not any(keyword in text for keyword in keywords):
            continue
        candidates.append({
            "area": topic.replace("_", " ").title(),
            "question": question,
            "question_to_ask": question,
            "why_it_matters": effect,
            "effect_on_analysis": effect,
            "owner": owner,
            "target_team": owner,
            "next_action": f"Assign {owner} and add evidence answering this decision.",
            "priority": "High",
            "linked_refs": flow_refs,
            "linked_object": flow_refs[0]["id"] if flow_refs else "project:context",
            "evidence_refs": [],
        })
    return candidates


def _merge_candidates(candidates: Iterable[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    for candidate in candidates or []:
        key = candidate["decision_fingerprint"]
        current = merged.get(key)
        if not current:
            merged[key] = deepcopy(candidate)
            continue
        current["source_refs"] = _merge_source_refs(current.get("source_refs"), candidate.get("source_refs"))
        current["linked_refs"] = _dedupe_refs([*(current.get("linked_refs") or []), *(candidate.get("linked_refs") or [])])
        current["evidence_refs"] = _unique([*(current.get("evidence_refs") or []), *(candidate.get("evidence_refs") or [])])
        current["dependency_refs"] = _merge_dependencies(current.get("dependency_refs") or {}, candidate.get("dependency_refs") or {})
        if current.get("state") == "open" and candidate.get("state") != "open":
            current["state"] = candidate["state"]
            current["status"] = decision_status(candidate["state"])
        if len(str(candidate.get("effect_on_analysis") or "")) > len(str(current.get("effect_on_analysis") or "")):
            current["effect_on_analysis"] = candidate["effect_on_analysis"]
    return list(merged.values())


def _merge_source_refs(left: Iterable[dict] | None, right: Iterable[dict] | None) -> list[dict]:
    result = []
    seen = set()
    for ref in [*(left or []), *(right or [])]:
        if not isinstance(ref, dict) or not ref.get("id"):
            continue
        key = (str(ref.get("type")), str(ref.get("id")))
        if key not in seen:
            seen.add(key)
            result.append({"type": key[0], "id": key[1]})
    return result


def _merge_dependencies(left: dict, right: dict) -> dict:
    result = {}
    for key in {*(left or {}).keys(), *(right or {}).keys()}:
        if key == "source_type":
            result[key] = left.get(key) or right.get(key)
        else:
            result[key] = _unique([*(left.get(key) or []), *(right.get(key) or [])])
    return result


def _raw_candidates(report: dict) -> list[dict]:
    result: list[dict] = []
    for raw in report.get("missing_info") or []:
        if isinstance(raw, dict):
            result.append(_candidate(
                raw, "missing_info", str(raw.get("missing_id") or raw.get("gap_id") or "missing-info"),
                question=raw.get("question_to_ask") or raw.get("question"), area=raw.get("area"),
                effect=raw.get("effect_on_analysis") or raw.get("why_it_matters"),
                owner=raw.get("owner") or raw.get("target_team") or "Security review",
                next_action=raw.get("next_action") or raw.get("question_to_ask") or raw.get("question"),
                priority=raw.get("priority") or "High",
            ))
    for raw in report.get("assumptions") or []:
        if isinstance(raw, dict):
            assumption = raw.get("assumption") or raw.get("verification_question")
            result.append(_candidate(
                raw, "assumption", str(raw.get("assumption_id") or "assumption"),
                question=raw.get("verification_question") or f"Validate assumption: {assumption}", area=raw.get("area"),
                effect=raw.get("impact_if_wrong") or raw.get("evidence"), owner=raw.get("owner") or "Security review",
                next_action=raw.get("recommended_validation") or raw.get("verification_question") or f"Validate: {assumption}",
                priority=raw.get("priority") or "Medium",
            ))
    completeness = report.get("completeness") if isinstance(report.get("completeness"), dict) else {}
    for raw in completeness.get("gaps") or []:
        if isinstance(raw, dict):
            result.append(_candidate(
                raw, "completeness", str(raw.get("gap_id") or raw.get("key") or "completeness"),
                question=raw.get("question"), area=raw.get("area") or raw.get("label"),
                effect=raw.get("effect_on_analysis") or raw.get("why_it_matters"), owner=raw.get("owner") or "Security review",
                next_action=raw.get("next_action") or raw.get("question"), priority=raw.get("priority") or "High",
            ))
    model = report.get("dfd_model") if isinstance(report.get("dfd_model"), dict) else {}
    for raw in model.get("questions") or []:
        if isinstance(raw, dict):
            result.append(_candidate(
                raw, "dfd_question", str(raw.get("id") or "dfd-question"), question=raw.get("question"),
                area="DFD model", effect=raw.get("reason"), owner="Architecture / Security",
                next_action="Resolve the DFD question and review affected interactions.",
            ))
    for raw in (model.get("deferred_interactions") or []):
        if isinstance(raw, dict) and raw.get("status", "deferred") != "resolved":
            result.append(_candidate(
                raw, "dfd_interaction", str(raw.get("id") or "deferred-interaction"),
                question=raw.get("next_action") or f"Resolve deferred interaction {raw.get('id')}",
                area="DFD interaction", effect=raw.get("reason"), owner=raw.get("owner") or "Product / Architecture",
                next_action=raw.get("next_action") or "Add endpoint, direction, and evidence for this interaction.",
                priority="High",
            ))
    quality = model.get("semantic_quality") if isinstance(model.get("semantic_quality"), dict) else {}
    for raw in quality.get("issues") or []:
        if isinstance(raw, dict) and str(raw.get("status") or "open").casefold() in {"open", "deferred"}:
            result.append(_candidate(
                raw, "dfd_quality", str(raw.get("id") or raw.get("code") or "dfd-quality"),
                question=raw.get("next_action") or raw.get("message"), area=raw.get("code") or "DFD quality",
                effect=raw.get("reason") or raw.get("message"), owner=raw.get("owner") or "Architecture / Security",
                next_action=raw.get("next_action") or "Resolve the DFD semantic issue before sign-off.", priority="High",
            ))
    for raw in report.get("threats") or []:
        if isinstance(raw, dict) and raw.get("finding_state") == "needs_context":
            question = raw.get("missing_info") or raw.get("grounding_reason")
            if question:
                result.append(_candidate(
                    raw, "finding_context", str(raw.get("threat_id") or "finding"), question=question,
                    area=raw.get("threat_category") or "Finding context", effect=raw.get("grounding_reason"),
                    owner=raw.get("owner") or "Security review", next_action=question, priority=raw.get("risk_level") or "High",
                ))
    for raw in report.get("controls") or []:
        if isinstance(raw, dict) and raw.get("mapping_status") == "unassigned":
            result.append(_candidate(
                raw, "control_applicability", str(raw.get("control_id") or "control"),
                question=raw.get("mapping_rationale") or "Which control is applicable to this threat and interaction?",
                area=raw.get("name") or "Control applicability", effect=raw.get("description"),
                owner=raw.get("owner") or "Security", next_action="Assign an applicable control or record not-applicable rationale.", priority="High",
            ))
    for raw in report.get("test_scenarios") or []:
        if isinstance(raw, dict) and str(raw.get("applicability_status") or "").casefold() == "blocked":
            result.append(_candidate(
                raw, "test_blocker", str(raw.get("test_id") or raw.get("threat_id") or "test"),
                question=raw.get("applicability_reason") or "What evidence or decision is required to make this test executable?",
                area="Test applicability", effect=raw.get("applicability_reason"), owner=raw.get("owner") or "QA / Security",
                next_action="Resolve applicability and define the executable test oracle.", priority="High",
            ))
    return result


def reconcile_deferred_decisions(report: dict, project: dict | None = None) -> dict:
    """Materialize one deduped decision register and preserve reviewer history."""
    report = report if isinstance(report, dict) else {}
    candidates = _raw_candidates(report)
    project_context = project if isinstance(project, dict) else (report.get("project") or {})
    candidates.extend(
        _candidate(raw, "rule_topic", str(raw.get("area") or "rule"), question=raw.get("question"), area=raw.get("area"),
                   effect=raw.get("effect_on_analysis") or raw.get("why_it_matters"), owner=raw.get("owner") or "Security review",
                   next_action=raw.get("next_action") or raw.get("question"), priority=raw.get("priority") or "High")
        for raw in _rule_topic_candidates(project_context, report.get("dfd_model"))
    )
    merged = _merge_candidates(candidates)
    previous = {
        str(item.get("decision_fingerprint")): item
        for item in (report.get("deferred_decisions") or [])
        if isinstance(item, dict) and item.get("decision_fingerprint")
    }
    result = []
    for item in merged:
        old = previous.get(item["decision_fingerprint"])
        if old:
            for field in ("state", "status", "owner", "due_at", "next_action", "answer", "notes", "history"):
                if field in old and old.get(field) not in (None, "", []):
                    item[field] = deepcopy(old[field])
            item["reviewer_decision_preserved"] = True
        item["state"] = normalize_decision_state(item.get("state"))
        item["status"] = decision_status(item["state"])
        item["effect_on_signoff"] = (
            "No sign-off blocker from this item; retain the decision in approval history."
            if item["state"] in {"answered", "accepted_assumption", "obsolete"}
            else "Blocks sign-off until this decision is answered, explicitly accepted, or marked obsolete."
        )
        result.append(item)
    # Keep previously reviewed items even if a partial rerun did not emit the
    # same source row.  They remain visible and auditable rather than vanishing.
    current_keys = {item["decision_fingerprint"] for item in result}
    for old in previous.values():
        if old["decision_fingerprint"] in current_keys:
            continue
        preserved = deepcopy(old)
        preserved["source_present"] = False
        preserved["decision_state_note"] = "Source was not emitted by the latest partial snapshot; reviewer history is preserved."
        result.append(preserved)
    result.sort(key=lambda item: ({"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(item.get("priority"), 2), item.get("area", "")))
    report["deferred_decisions"] = result
    report["decision_summary"] = {
        "schema_version": DECISION_SCHEMA_VERSION,
        "total": len(result),
        "open": sum(item.get("state") == "open" for item in result),
        "assigned": sum(item.get("state") == "assigned" for item in result),
        "answered": sum(item.get("state") == "answered" for item in result),
        "accepted_assumption": sum(item.get("state") == "accepted_assumption" for item in result),
        "deferred": sum(item.get("state") == "deferred" for item in result),
        "obsolete": sum(item.get("state") == "obsolete" for item in result),
        "unresolved": sum(item.get("state") in {"open", "assigned", "deferred"} for item in result),
    }
    return report


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _decision_depends_on(item: dict, ref_type: str, ref_id: str) -> bool:
    deps = item.get("dependency_refs") if isinstance(item.get("dependency_refs"), dict) else {}
    if ref_id in {str(value) for value in (deps.get(f"{ref_type}_ids") or [])}:
        return True
    if ref_type == "dfd" and ref_id in {str(value) for value in (deps.get("dfd_refs") or [])}:
        return True
    return any(str(ref.get("id")) == ref_id for ref in (item.get("linked_refs") or []) if isinstance(ref, dict))


def apply_decision_update(
    report: dict,
    decision_id: str,
    patch: dict,
    *,
    actor: str = "reviewer",
    project: dict | None = None,
) -> tuple[dict, dict]:
    """Apply a reviewer decision and selectively stale dependent consumers."""
    reconcile_deferred_decisions(report, project)
    item = next((entry for entry in report.get("deferred_decisions") or [] if str(entry.get("decision_id")) == str(decision_id)), None)
    if not item:
        raise KeyError(decision_id)
    before = item.get("state")
    requested = patch.get("state", patch.get("status", before))
    state = normalize_decision_state(requested)
    now = _now()
    history = [deepcopy(entry) for entry in (item.get("history") or []) if isinstance(entry, dict)]
    history.append({
        "from_state": before,
        "to_state": state,
        "actor": _text(actor) or "reviewer",
        "at": now,
        "answer": _text(patch.get("answer") or patch.get("resolution")),
        "evidence_refs": _unique(patch.get("evidence_refs") or []),
    })
    item["state"] = state
    item["status"] = decision_status(state)
    item["history"] = history[-30:]
    for field in ("owner", "due_at", "next_action", "answer", "notes"):
        if field in patch:
            item[field] = _text(patch.get(field))
    if "evidence_refs" in patch:
        item["evidence_refs"] = _unique(patch.get("evidence_refs") or [])
    item["reviewed_at"] = now
    item["last_decision_actor"] = _text(actor) or "reviewer"
    item["effect_on_signoff"] = (
        "No sign-off blocker from this item; retain the decision in approval history."
        if state in {"answered", "accepted_assumption", "obsolete"}
        else "Blocks sign-off until this decision is answered, explicitly accepted, or marked obsolete."
    )

    # Keep the legacy producer rows readable for report/export consumers that
    # have not migrated to the canonical decision register yet.  The decision
    # remains the source of truth; these fields are a compatibility projection.
    source_field_by_type = {
        "missing_info": ("missing_info", "missing_id"),
        "assumption": ("assumptions", "assumption_id"),
        "completeness": ("completeness", "gap_id"),
    }
    for source_ref in item.get("source_refs") or []:
        if not isinstance(source_ref, dict):
            continue
        collection = source_field_by_type.get(source_ref.get("type"))
        if not collection:
            continue
        rows = report.get(collection[0]) if collection[0] != "completeness" else (report.get("completeness") or {}).get("gaps")
        if not isinstance(rows, list):
            continue
        source_row = next((row for row in rows if str(row.get(collection[1])) == str(source_ref.get("id"))), None)
        if not isinstance(source_row, dict):
            continue
        source_row["state"] = state
        source_row["status"] = decision_status(state)
        source_row["reviewed_at"] = now
        for field in ("owner", "next_action", "answer", "notes", "due_at"):
            if field in patch:
                source_row[field] = item.get(field)
        if "evidence_refs" in patch:
            source_row["evidence_refs"] = list(item.get("evidence_refs") or [])
        source_row["decision_id"] = item["decision_id"]

    dependency = item.get("dependency_refs") if isinstance(item.get("dependency_refs"), dict) else {}
    threat_ids = {str(value) for value in (dependency.get("threat_ids") or [])}
    control_ids = {str(value) for value in (dependency.get("control_ids") or [])}
    test_ids = {str(value) for value in (dependency.get("test_ids") or [])}
    dfd_refs = {str(value) for value in (dependency.get("dfd_refs") or [])}
    impacted = {"threats": [], "controls": [], "tests": [], "stages": set()}
    for threat in report.get("threats") or []:
        if not isinstance(threat, dict):
            continue
        refs = {str(threat.get("threat_id") or ""), str(threat.get("primary_interaction_ref") or "")}
        refs.update(str(ref) for ref in (threat.get("affected_refs") or []))
        if refs.intersection(threat_ids | dfd_refs):
            threat["analysis_state"] = "stale"
            threat["stale_decision_id"] = item["decision_id"]
            threat["stale_reason"] = "A linked evidence decision changed; rerun this dependent framework assessment."
            threat["needs_human_review"] = True
            impacted["threats"].append(str(threat.get("threat_id")))
            if state not in {"answered", "accepted_assumption", "obsolete"}:
                threat["finding_state"] = "needs_context"
                threat["risk_status"] = "deferred"
                threat["risk_level"] = "Unknown"
                threat["risk_score"] = None
            impacted["stages"].update({str(threat.get("framework") or "").casefold()})
    for control in report.get("controls") or []:
        if not isinstance(control, dict):
            continue
        refs = {str(control.get("control_id") or ""), *(str(value) for value in (control.get("threat_ids") or []))}
        refs.update(str(control.get(key)) for key in ("primary_interaction_ref", "flow_id") if control.get(key))
        for key in ("affected_refs", "linked_refs", "target_refs", "dfd_refs"):
            values = control.get(key) or []
            if isinstance(values, list):
                refs.update(str(value.get("id")) if isinstance(value, dict) else str(value) for value in values if value)
        if refs.intersection(control_ids | set(impacted["threats"]) | threat_ids | dfd_refs):
            control["analysis_state"] = "stale"
            control["stale_decision_id"] = item["decision_id"]
            impacted["controls"].append(str(control.get("control_id")))
    for scenario in report.get("test_scenarios") or []:
        if not isinstance(scenario, dict):
            continue
        refs = {str(scenario.get("test_id") or ""), str(scenario.get("threat_id") or "")}
        refs.update(str(scenario.get(key)) for key in ("primary_interaction_ref", "flow_id") if scenario.get(key))
        for key in ("affected_refs", "linked_refs", "target_refs", "dfd_refs"):
            values = scenario.get(key) or []
            if isinstance(values, list):
                refs.update(str(value.get("id")) if isinstance(value, dict) else str(value) for value in values if value)
        if refs.intersection(test_ids | set(impacted["threats"]) | threat_ids | dfd_refs):
            scenario["analysis_state"] = "stale"
            scenario["stale_decision_id"] = item["decision_id"]
            impacted["tests"].append(str(scenario.get("test_id")))
    stages = {stage for stage in impacted["stages"] if stage in {"stride", "linddun"}}
    if impacted["controls"] or impacted["tests"] or impacted["threats"]:
        stages.update({"controls", "tests"})
    stale = report.get("analysis_stale") if isinstance(report.get("analysis_stale"), dict) else {}
    stale["stages"] = sorted(set(stale.get("stages") or []).union(stages))
    stale["reason"] = f"Decision {item['decision_id']} changed; only linked analysis dependencies require refresh."
    stale["changed_at"] = now
    report["analysis_stale"] = stale
    report["decision_summary"] = {
        **(report.get("decision_summary") or {}),
        "unresolved": sum(entry.get("state") in {"open", "assigned", "deferred"} for entry in (report.get("deferred_decisions") or [])),
    }
    return item, {
        "decision_id": item["decision_id"],
        "changed_from": before,
        "changed_to": state,
        "impacted": {**impacted, "stages": sorted(stages)},
        "selective_invalidation": True,
    }
