"""Evidence-grounded input completeness and ingestion coverage contract."""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone


COMPLETENESS_SCHEMA_VERSION = "completeness-v2"


REQUIRED_INFORMATION_DIMENSIONS = (
    {
        "key": "actors_roles",
        "label": "Actors and roles",
        "weight": 10,
        "field_groups": (("actors",), ("roles", "user_roles", "personas")),
        "keywords": ("actor", "role", "admin", "operator", "partner", "anonymous"),
        "question": "Which actors, roles, service identities, and anonymous users can use or administer this feature?",
        "owner": "Product / Security",
        "effect": "Threat sources, authorization scope, and abuse paths cannot be assessed precisely.",
    },
    {
        "key": "assets_data_classification",
        "label": "Assets and data classification",
        "weight": 12,
        "field_groups": (("data_involved", "data_fields", "assets"), ("data_classification", "data_classifications", "sensitivity")),
        "keywords": ("pii", "personal", "financial", "secret", "sensitive", "classification", "data field", "identifier"),
        "question": "What assets and data fields are processed, and which are Public, Internal, PII, Financial, or Secret?",
        "owner": "Product / Data owner",
        "effect": "Impact, privacy applicability, minimization, and disclosure scope remain uncertain.",
    },
    {
        "key": "primary_flows",
        "label": "Primary flows and entry points",
        "weight": 12,
        "field_groups": (("extracted_data_flows", "data_flows", "canonical_operations", "business_scenarios"), ("entry_points", "endpoints")),
        "keywords": ("request", "response", "endpoint", "webhook", "job", "flow", "send", "receive"),
        "question": "Which primary user, API, webhook, job, and system-to-system interactions carry the important data?",
        "owner": "Engineering",
        "effect": "DFD-grounded STRIDE/LINDDUN coverage and primary interaction mapping cannot be complete.",
    },
    {
        "key": "trust_zones_external_parties",
        "label": "Trust zones and external parties",
        "weight": 10,
        "field_groups": (("zone_metadata", "zones", "trust_zones", "boundary_metadata", "trust_boundaries"), ("external_systems", "external_parties", "third_party_systems")),
        "keywords": ("trust boundary", "zone", "external", "third-party", "partner", "provider", "internet"),
        "question": "Which components belong to each trust zone, and which external parties or providers receive data?",
        "owner": "Architecture / Security",
        "effect": "Boundary crossings, provider trust, and cross-zone threat paths may be deferred.",
    },
    {
        "key": "authentication_authorization",
        "label": "Authentication and authorization",
        "weight": 12,
        "field_groups": (("auth_method", "authentication", "authn", "identity_provider"), ("authorization_model", "authorization", "authz", "access_control", "permissions", "rbac")),
        "keywords": ("authentication", "authorization", "oauth", "jwt", "session", "rbac", "permission", "access control", "mfa"),
        "question": "How are identities authenticated and how is authorization enforced for each role, tenant, and critical action?",
        "owner": "Engineering / Security",
        "effect": "Spoofing and elevation-of-privilege analysis cannot be grounded to an access decision.",
    },
    {
        "key": "lifecycle_retention_deletion",
        "label": "Lifecycle, retention, and deletion",
        "weight": 10,
        "field_groups": (("lifecycle", "data_lifecycle", "retention", "retention_policy", "storage_duration"), ("deletion", "deletion_policy", "purge", "offboarding", "erasure")),
        "keywords": ("retention", "retain", "delete", "deletion", "purge", "archive", "offboard", "erasure", "lifecycle"),
        "question": "Where is data retained, for how long, and how does deletion or offboarding propagate to stores and processors?",
        "owner": "Data owner / Legal",
        "effect": "Privacy lifecycle, stale-data exposure, and deletion verification remain unresolved.",
    },
    {
        "key": "failure_abuse_behavior",
        "label": "Failure and abuse behavior",
        "weight": 10,
        "field_groups": (("failure_modes", "failure_behavior", "error_handling", "incident_response"), ("abuse_cases", "abuse_paths", "fraud_controls", "critical_actions")),
        "keywords": ("failure", "error", "retry", "timeout", "fraud", "abuse", "rate limit", "replay", "idempot", "incident"),
        "question": "What happens on failure, replay, retry, abuse, fraud, queue poisoning, or provider unavailability?",
        "owner": "Engineering / Operations",
        "effect": "DoS, tampering, replay, fraud, and recovery controls cannot be tested against defined behavior.",
    },
    {
        "key": "operational_owner",
        "label": "Operational owner",
        "weight": 8,
        "field_groups": (("owner", "owners", "operational_owner", "service_owner", "operator_control_party", "target_team"),),
        "keywords": ("owner", "operations", "on-call", "responsible", "team", "operator"),
        "question": "Who owns the service, boundary, incident response, key rotation, retention, and verification decisions?",
        "owner": "Engineering manager / Operations",
        "effect": "Open gaps cannot be assigned or verified and operational controls may remain theoretical.",
    },
    {
        "key": "regulatory_constraints",
        "label": "Regulatory and jurisdiction constraints",
        "weight": 8,
        "field_groups": (("regulatory_constraints", "regulations", "compliance", "jurisdiction", "legal_basis", "obligations"),),
        "keywords": ("gdpr", "hipaa", "pci", "regulation", "compliance", "jurisdiction", "legal basis", "consent"),
        "question": "Which regulatory, contractual, jurisdiction, consent, or data-residency constraints apply?",
        "owner": "Product / Legal",
        "effect": "LINDDUN obligations and data-handling requirements cannot be evaluated as applicable or not applicable.",
    },
    {
        "key": "verification_evidence",
        "label": "Verification evidence",
        "weight": 8,
        "field_groups": (("artifact_sources", "artifact_evidence", "evidence_items", "verification_evidence", "test_evidence"),),
        "keywords": ("evidence", "verification", "test", "audit", "log", "observed", "screenshot", "specification"),
        "question": "Which source, runtime observation, test, log, or specification verifies the important claims?",
        "owner": "QA / Security",
        "effect": "Claims remain hypotheses and absence of documentation cannot be promoted to a vulnerability.",
    },
)


def _as_values(value) -> list[str]:
    if isinstance(value, dict):
        values = []
        for key, nested in value.items():
            values.append(str(key))
            values.extend(_as_values(nested))
        return values
    if isinstance(value, (list, tuple, set)):
        return [item for nested in value for item in _as_values(nested)]
    if value in (None, "", False):
        return []
    text = str(value).strip()
    if text.casefold() in {"unknown", "n/a", "na", "none", "not specified", "not documented", "tbd", "-"}:
        return []
    return [text]


def _text(value) -> str:
    return " ".join(_as_values(value)).strip()


def _tokens(value: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9][a-z0-9_-]{2,}", value.casefold())}


def _evidence_text(item: dict) -> str:
    return " ".join(str(item.get(key) or "") for key in ("snippet", "locator", "source", "topics")).casefold()


def _stable_ref(prefix: str, value: str) -> str:
    return f"{prefix}:{hashlib.sha256(value.encode('utf-8')).hexdigest()[:12]}"


def _coverage_manifest(project: dict) -> dict:
    sources = []
    unread_sections = []
    total_chars = 0
    read_chars = 0
    validated_chars = 0
    total_chunks = processed_chunks = fallback_chunks = unverified_chunks = deferred_chunks = 0
    for source in (project.get("artifact_sources") or []):
        if not isinstance(source, dict) or source.get("active", True) is False:
            continue
        manifest = source.get("coverage_manifest") if isinstance(source.get("coverage_manifest"), dict) else {}
        chunks = [item for item in (manifest.get("chunks") or []) if isinstance(item, dict)]
        source_total = int(manifest.get("total_characters") or sum(int(item.get("char_count") or 0) for item in chunks))
        omitted_chars = int(manifest.get("unread_chars_estimate") or 0)
        if omitted_chars:
            source_total += omitted_chars
        source_read = 0
        source_validated = 0
        for chunk in chunks:
            char_count = int(chunk.get("char_count") or max(0, int(chunk.get("end_char") or 0) - int(chunk.get("start_char") or 0)))
            status = str(chunk.get("status") or "deferred")
            total_chunks += 1
            total_chars += char_count
            if status in {"processed", "processed_fallback", "processed_deterministic", "reused"}:
                source_read += char_count
                read_chars += char_count
            if status in {"processed", "processed_deterministic", "reused"}:
                source_validated += char_count
                validated_chars += char_count
            if status in {"processed", "processed_deterministic", "reused"}:
                processed_chunks += 1
            elif status == "processed_fallback":
                fallback_chunks += 1
            elif status == "processed_unverified":
                unverified_chunks += 1
            elif status in {"deferred", "processed_empty"}:
                deferred_chunks += 1
            if status not in {"processed", "processed_deterministic", "reused"}:
                unread_sections.append({
                    "artifact_id": source.get("artifact_id"),
                    "filename": source.get("filename"),
                    "artifact_type": source.get("artifact_type"),
                    "revision": source.get("revision"),
                    "document_hash": source.get("content_hash") or manifest.get("document_hash"),
                    "chunk_id": chunk.get("chunk_id"),
                    "locator": chunk.get("locator") or chunk.get("section") or "Unknown section",
                    "section": chunk.get("section"),
                    "state": "unverified" if status in {"processed_fallback", "processed_unverified"} else "deferred",
                    "status": status,
                    "reason": chunk.get("reason") or "Section has not produced validated evidence.",
                    "owner": "Ingestion owner",
                    "linked_object": f"artifact:{source.get('artifact_id')}",
                    "next_action": "Retry or add evidence for this section before relying on its claims.",
                })
        for omission in (manifest.get("extraction_omissions") or []):
            if not isinstance(omission, dict):
                continue
            unread_sections.append({
                "artifact_id": source.get("artifact_id"),
                "filename": source.get("filename"),
                "artifact_type": source.get("artifact_type"),
                "revision": source.get("revision"),
                "document_hash": source.get("content_hash") or manifest.get("document_hash"),
                "locator": omission.get("locator") or "Unspecified omitted source range",
                "section": omission.get("section"),
                "state": "omitted",
                "status": "omitted",
                "reason": omission.get("reason") or "Source extraction omitted this range.",
                "owner": "Ingestion owner",
                "linked_object": f"artifact:{source.get('artifact_id')}",
                "next_action": "Upload a complete source or reparse the omitted range.",
            })
        if not chunks and str(manifest.get("status") or "").casefold() != "complete":
            for unread in (manifest.get("unread_sections") or []):
                if not isinstance(unread, dict):
                    continue
                unread_sections.append({
                    "artifact_id": source.get("artifact_id"),
                    "filename": source.get("filename"),
                    "artifact_type": source.get("artifact_type"),
                    "revision": source.get("revision"),
                    "document_hash": source.get("content_hash") or manifest.get("document_hash"),
                    "chunk_id": unread.get("chunk_id"),
                    "locator": unread.get("locator") or unread.get("section") or "Unknown section",
                    "section": unread.get("section"),
                    "state": unread.get("state") or "deferred",
                    "status": unread.get("status") or "deferred",
                    "reason": unread.get("reason") or "The source section was not validated.",
                    "owner": "Ingestion owner",
                    "linked_object": f"artifact:{source.get('artifact_id')}",
                    "next_action": "Retry or add evidence for this section before relying on its claims.",
                })
            if not any(item.get("artifact_id") == source.get("artifact_id") for item in unread_sections):
                unread_sections.append({
                    "artifact_id": source.get("artifact_id"),
                    "filename": source.get("filename"),
                    "artifact_type": source.get("artifact_type"),
                    "revision": source.get("revision"),
                    "document_hash": source.get("content_hash") or manifest.get("document_hash"),
                    "locator": "Source coverage manifest",
                    "state": "deferred",
                    "status": manifest.get("status") or "deferred",
                    "reason": "The source has no validated chunk coverage.",
                    "owner": "Ingestion owner",
                    "linked_object": f"artifact:{source.get('artifact_id')}",
                    "next_action": "Reparse the source and review its coverage manifest.",
                })
        source_total = max(source_total, 0)
        source_read = min(source_read, source_total) if source_total else source_read
        sources.append({
            "artifact_id": source.get("artifact_id"),
            "filename": source.get("filename"),
            "artifact_type": source.get("artifact_type"),
            "revision": source.get("revision"),
            "document_hash": source.get("content_hash") or manifest.get("document_hash"),
            "parser_version": (source.get("parser") or {}).get("version"),
            "status": manifest.get("status") or "unknown",
            "total_characters": source_total,
            "read_characters": source_read,
            "validated_characters": source_validated,
            "coverage_percent": round((source_read / source_total) * 100, 2) if source_total else 0,
            "validated_percent": round((source_validated / source_total) * 100, 2) if source_total else 0,
            "unread_sections": [item for item in unread_sections if item.get("artifact_id") == source.get("artifact_id")],
            "reused_chunk_count": int(manifest.get("reused_chunk_count") or 0),
            "reparse_source_revision": manifest.get("reparse_source_revision"),
        })
    conflict_items = [
        {
            "state": "conflicting",
            "status": "conflicting",
            "reason": item.get("message") or "Active artifact assertions conflict.",
            "owner": "Product / Engineering",
            "linked_object": f"operation:{item.get('operation_key') or 'unknown'}",
            "next_action": "Resolve the conflicting source assertion before sign-off.",
            **{key: item.get(key) for key in ("operation_key", "field", "values") if item.get(key) is not None},
        }
        for item in (project.get("artifact_conflicts") or [])
        if isinstance(item, dict)
    ]
    unread_sections.extend(conflict_items)
    all_source_manifests_complete = bool(sources) and all(
        str(item.get("status") or "").casefold() == "complete" for item in sources
    )
    return {
        "status": "complete" if not unread_sections and sources and processed_chunks == total_chunks and all_source_manifests_complete else ("partial" if sources else "not_available"),
        "source_count": len(sources),
        "sources": sources,
        "total_chunks": total_chunks,
        "processed_chunk_count": processed_chunks,
        "fallback_chunk_count": fallback_chunks,
        "unverified_chunk_count": unverified_chunks,
        "deferred_chunk_count": deferred_chunks,
        "total_characters": total_chars,
        "read_characters": read_chars,
        "validated_characters": validated_chars,
        "coverage_percent": round((read_chars / total_chars) * 100, 2) if total_chars else 0,
        "validated_percent": round((validated_chars / total_chars) * 100, 2) if total_chars else 0,
        "unread_sections": unread_sections,
        "conflicts": conflict_items,
    }


def _group_values(project: dict, group: tuple[str, ...]) -> list[str]:
    values = []
    for field in group:
        if field == "artifact_sources":
            for source in (project.get(field) or []):
                if isinstance(source, dict):
                    values.append(" ".join(str(source.get(key) or "") for key in (
                        "artifact_type", "filename", "revision", "content_hash",
                    )))
            continue
        values.extend(_as_values(project.get(field)))
    return [value for value in values if value.strip()]


def _matching_evidence(project: dict, catalog: list[dict], values: list[str], keywords: tuple[str, ...], key: str) -> tuple[list[str], list[str]]:
    refs = []
    locators = []
    value_tokens = set()
    for value in values:
        value_tokens.update(_tokens(value))
    for item in catalog:
        if not isinstance(item, dict):
            continue
        text = _evidence_text(item)
        keyword_match = any(keyword.casefold() in text for keyword in keywords)
        value_match = bool(value_tokens and len(value_tokens.intersection(_tokens(text))) >= 1)
        if keyword_match or value_match:
            ref = str(item.get("evidence_id") or _stable_ref("evidence", text))
            if ref not in refs:
                refs.append(ref)
            locator = str(item.get("locator") or item.get("source") or "Project context")
            if locator not in locators:
                locators.append(locator)
    if values and not refs:
        refs.append(f"manual:{key}")
        locators.append("Project context input")
    return refs[:8], locators[:8]


def _make_gap(dimension: dict, *, state: str, evidence_refs: list[str], locators: list[str], missing_groups: list[int], source_coverage: dict) -> dict:
    gap_id = f"gap-{dimension['key']}"
    return {
        "gap_id": gap_id,
        "area": dimension["label"],
        "dimension": dimension["key"],
        "state": "open" if state in {"unknown", "partial", "conflicting", "deferred"} else state,
        "status": "Open" if state != "resolved" else "Resolved",
        "question": dimension["question"],
        "question_to_ask": dimension["question"],
        "why_it_matters": dimension["effect"],
        "reason": f"Missing or unresolved evidence for {dimension['label']}.",
        "missing_signals": [f"Required evidence group {index + 1}" for index in missing_groups],
        "evidence_refs": evidence_refs,
        "locators": locators,
        "owner": dimension["owner"],
        "target_team": dimension["owner"],
        "next_action": f"Add source evidence or answer: {dimension['question']}",
        "effect_on_analysis": dimension["effect"],
        "linked_object": f"completeness:{dimension['key']}",
        "source_coverage_status": source_coverage.get("status"),
        "priority": "High" if dimension["weight"] >= 10 else "Medium",
    }


def _topic_is_documented(topic_keywords: tuple[str, ...], project_text: str, catalog: list[dict]) -> bool:
    searchable = project_text.casefold()
    if any(keyword.casefold() in searchable for keyword in topic_keywords):
        return True
    return any(
        any(keyword.casefold() in _evidence_text(item) for keyword in topic_keywords)
        for item in catalog if isinstance(item, dict)
    )


def _candidate_deferred_topics(project: dict, catalog: list[dict]) -> list[dict]:
    """Create targeted review questions from documented product signals.

    These are evidence-gap candidates, never vulnerabilities. They are based
    on the observed product vocabulary/flows and remain open until a source or
    reviewer decision resolves them.
    """
    project_text = " ".join([
        _text(project.get("name")), _text(project.get("description")),
        _text(project.get("actors")), _text(project.get("components")),
        _text(project.get("data_involved")), _text(project.get("entry_points")),
        _text(project.get("external_systems")), _text(project.get("critical_actions")),
        _text(project.get("extracted_data_flows")), _text(project.get("artifact_summary")),
    ])
    flows = [item for item in (project.get("extracted_data_flows") or []) if isinstance(item, dict)]
    flow_ref = next((str(item.get("flow_id") or item.get("id")) for item in flows if item.get("flow_id") or item.get("id")), None)
    candidates = []

    def add(topic: str, keywords: tuple[str, ...], question: str, owner: str, effect: str, linked: str | None = None):
        if _topic_is_documented(keywords, project_text, catalog):
            return
        linked_object = linked or (f"flow:{flow_ref}" if flow_ref else "project:context")
        candidates.append({
            "gap_id": f"topic-{hashlib.sha256(topic.encode('utf-8')).hexdigest()[:12]}",
            "type": "deferred_topic",
            "area": topic,
            "dimension": "failure_abuse_behavior",
            "state": "open",
            "status": "Open",
            "question": question,
            "question_to_ask": question,
            "why_it_matters": effect,
            "reason": "The product signal is present, but the decision needed for a grounded assessment is not documented.",
            "evidence_refs": [],
            "locators": [],
            "owner": owner,
            "target_team": owner,
            "linked_object": linked_object,
            "next_action": f"Assign {owner} and add evidence answering this question.",
            "effect_on_analysis": effect,
            "priority": "High",
        })

    if _topic_is_documented(("webhook", "callback", "event delivery"), project_text, catalog):
        add("Webhook signature rotation", ("signature rotation", "rotate signing", "key rotation"),
            "What is the webhook signing-key rotation process, overlap window, and revocation owner?",
            "Integration owner / Security", "Signature lifecycle and partner offboarding cannot be verified.")
        add("Webhook replay window", ("replay window", "replay protection", "nonce", "timestamp validation"),
            "What replay window, nonce/idempotency key, and duplicate-event behavior does the webhook accept?",
            "Integration owner", "Replay and duplicate side effects cannot be tested precisely.")
        add("Dead-letter and schema ownership", ("dead-letter", "dlq", "schema version", "payload version"),
            "Who owns dead-letter recovery and payload schema/version compatibility for failed webhook events?",
            "Event platform owner", "Queue poisoning and recovery tests lack an accountable decision.")

    if _topic_is_documented(("payment", "wallet", "transaction", "financial"), project_text, catalog):
        add("Token rotation interval", ("token rotation", "rotation interval", "credential rotation"),
            "What is the exact token/credential rotation interval, overlap window, and emergency revocation procedure?",
            "Identity / Security owner", "Credential lifecycle and replay exposure cannot be verified.")
        add("Transaction idempotency and fraud review", ("idempotency", "fraud review", "duplicate transaction", "exactly once"),
            "Which idempotency key, replay handling, refund authorization, and fraud-review owner protect financial state changes?",
            "Payments / Fraud owner", "Payment integrity and duplicate side effects cannot be verified.")
        add("Payment network incident response owner", ("provider incident", "payment incident", "network incident", "incident response owner"),
            "Who owns payment-network incidents, reconciliation, and customer-impact decisions?",
            "Payments / Operations", "Failure recovery and auditability remain operationally undefined.")
        add("Refund authorization", ("refund authorization", "refund approval", "refund permission"),
            "Which role may approve refunds, and how are refund decisions authenticated and audited?",
            "Payments / Operations", "Refund abuse and authorization boundaries remain unresolved.")

    if _topic_is_documented(("tenant", "workspace", "multi-tenant"), project_text, catalog):
        add("Tenant isolation enforcement", ("tenant isolation", "tenant boundary", "cross-tenant", "row-level security"),
            "Where is tenant isolation enforced for API, search, object storage, exports, and background jobs?",
            "Platform Security", "Cross-tenant disclosure cannot be assessed or tested end-to-end.")
        add("Tenant deletion propagation", ("deletion propagation", "tenant offboarding", "workspace deletion"),
            "How does tenant/workspace deletion propagate to indexes, backups, attachments, and processors?",
            "Platform / Data owner", "Stale data and offboarding privacy risks remain deferred.")
        add("Search-index authorization", ("search-index authorization", "search authorization", "index access control"),
            "How does search authorization enforce tenant and object scope before indexed results are returned?",
            "Platform Security", "Search results may not be traceable to the canonical tenant authorization boundary.")
        add("Tenant keying strategy", ("tenant key", "tenant encryption key", "per-tenant key"),
            "How are tenant encryption keys isolated, rotated, and recovered without cross-tenant access?",
            "Platform Security", "Cryptographic tenant isolation and recovery remain unspecified.")

    if _topic_is_documented(("ai", "llm", "model", "assistant"), project_text, catalog):
        add("AI provider processing terms", ("provider terms", "data processing agreement", "model retention"),
            "What provider data-processing, retention, training-use, and region terms apply to prompts and transcripts?",
            "Product / Legal", "LINDDUN provider disclosure and retention analysis lacks a documented basis.")
        add("AI tool permission and human approval boundary", ("tool permission", "human approval", "agent action", "autonomous action"),
            "Which tools may the assistant call, what scopes are allowed, and where is human approval mandatory?",
            "Product / Security", "Prompt injection and over-trust scenarios lack a precise execution boundary.")

    if _topic_is_documented(("medical", "telemedicine", "clinician", "patient", "health"), project_text, catalog):
        add("Jurisdictional medical retention period", ("jurisdictional retention", "medical retention period", "health record retention"),
            "What jurisdiction-specific retention period applies to medical records, consultation notes, and video artifacts?",
            "Privacy / Legal", "LINDDUN retention and deletion analysis lacks a jurisdictional basis.")
        add("Break-glass access owner", ("break-glass", "emergency access", "override access"),
            "Who approves, monitors, and reviews break-glass access to sensitive clinical records?",
            "Clinical Security", "Emergency privilege escalation and auditability remain unresolved.")

    if _topic_is_documented(("wallet", "top-up", "top up"), project_text, catalog):
        add("Ledger ownership", ("ledger owner", "balance ledger", "ledger database"),
            "Which system is authoritative for wallet balance and how are reconciliation and dispute decisions owned?",
            "Payments / Finance owner", "Transfer integrity cannot be tied to an authoritative ledger.")
        add("Top-up provider", ("top-up provider", "top up provider", "funding provider"),
            "Which provider funds top-ups, and what authentication, callback, reconciliation, and incident contract applies?",
            "Payments / Operations", "Top-up trust boundary and provider failure behavior remain unknown.")

    if _topic_is_documented(("biometric", "face image", "face recognition", "government identifier"), project_text, catalog):
        add("Biometric deletion schedule", ("biometric deletion", "face image deletion", "biometric retention"),
            "When are biometric images and derived match artifacts deleted, and who verifies deletion?",
            "Privacy / Data owner", "Privacy lifecycle and deletion verification remain unresolved.")
        add("Provider certificate rotation owner", ("certificate rotation", "provider certificate", "mTLS"),
            "Who owns provider certificate rotation, trust-store updates, and emergency revocation?",
            "Platform Security", "Provider impersonation and outage recovery controls cannot be verified.")

    return candidates


def assess_completeness(project: dict, *, evidence_catalog: list[dict] | None = None) -> dict:
    """Score required information only when a source or explicit context supports it."""
    project = project if isinstance(project, dict) else {}
    catalog = evidence_catalog if isinstance(evidence_catalog, list) else []
    source_coverage = _coverage_manifest(project)
    dimensions = []
    gaps = []
    earned_total = 0.0
    total_weight = sum(item["weight"] for item in REQUIRED_INFORMATION_DIMENSIONS)

    for dimension in REQUIRED_INFORMATION_DIMENSIONS:
        group_evidence = []
        group_locators = []
        satisfied_groups = []
        missing_groups = []
        for index, group in enumerate(dimension["field_groups"]):
            values = _group_values(project, group)
            refs, locators = _matching_evidence(project, catalog, values, dimension["keywords"], dimension["key"])
            # Keyword evidence may support a dimension even when no normalized
            # project field was populated, but it remains partial until every
            # required group has a source-backed signal.
            if not values and refs:
                satisfied_groups.append(index)
            elif values:
                satisfied_groups.append(index)
            else:
                missing_groups.append(index)
            group_evidence.extend(refs)
            group_locators.extend(locators)
        satisfied_groups = sorted(set(satisfied_groups))
        group_count = len(dimension["field_groups"])
        ratio = len(satisfied_groups) / group_count if group_count else 0
        if dimension["key"] == "verification_evidence":
            direct_count = sum(1 for item in catalog if isinstance(item, dict) and item.get("evidence_type") == "direct")
            ratio = 1.0 if direct_count and not source_coverage.get("unread_sections") else (0.5 if direct_count else 0)
            if not direct_count and source_coverage.get("source_count"):
                missing_groups = [0]
        if source_coverage.get("conflicts") and dimension["key"] in {"primary_flows", "authentication_authorization"}:
            if ratio:
                ratio = min(ratio, 0.5)
            state = "conflicting"
        elif ratio >= 1:
            state = "evidenced"
        elif ratio > 0:
            state = "partial"
        else:
            state = "deferred" if source_coverage.get("unread_sections") else "unknown"
        earned = round(dimension["weight"] * ratio, 2)
        earned_total += earned
        refs = list(dict.fromkeys(group_evidence))[:12]
        locators = list(dict.fromkeys(group_locators))[:12]
        record = {
            "key": dimension["key"],
            "dimension": dimension["key"],
            "area": dimension["label"],
            "label": dimension["label"],
            "state": state,
            "status": state,
            "present": ratio > 0,
            "weight": dimension["weight"],
            "earned": earned,
            "score": round(ratio * 100),
            "evidence_refs": refs,
            "locators": locators,
            "question": dimension["question"],
            "owner": dimension["owner"],
            "effect_on_analysis": dimension["effect"],
            "missing_signals": [f"Required evidence group {index + 1}" for index in missing_groups],
            "source_coverage_status": source_coverage.get("status"),
        }
        dimensions.append(record)
        if state != "evidenced":
            gaps.append(_make_gap(
                dimension, state=state, evidence_refs=refs, locators=locators,
                missing_groups=missing_groups, source_coverage=source_coverage,
            ))

    deferred_topics = _candidate_deferred_topics(project, catalog)
    gaps.extend(deferred_topics)

    score = round((earned_total / total_weight) * 100) if total_weight else 0
    if score >= 85 and not source_coverage.get("unread_sections") and not gaps:
        level = "Ready"
    elif score >= 65:
        level = "Usable with gaps"
    elif score >= 40:
        level = "High assumption load"
    else:
        level = "Insufficient context"
    blockers = [
        {
            "area": gap["area"],
            "dimension": gap["dimension"],
            "question": gap["question"],
            "priority": gap["priority"],
            "state": gap["state"],
            "owner": gap["owner"],
            "linked_object": gap["linked_object"],
            "next_action": gap["next_action"],
            "effect_on_analysis": gap["effect_on_analysis"],
            "evidence_refs": gap["evidence_refs"],
        }
        for gap in gaps
    ]
    return {
        "schema_version": COMPLETENESS_SCHEMA_VERSION,
        "score": score,
        "earned": round(earned_total, 2),
        "max_score": total_weight,
        "level": level,
        "dimensions": dimensions,
        "areas": dimensions,
        "gaps": gaps,
        "candidate_deferred_topics": deferred_topics,
        "blockers": blockers,
        "blocker_count": len(blockers),
        "artifact_count": source_coverage.get("source_count", 0),
        "artifact_types": sorted({str(item.get("artifact_type")) for item in source_coverage.get("sources", []) if item.get("artifact_type")}),
        "ingestion_coverage": source_coverage,
        "source_manifest": source_coverage.get("sources", []),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
