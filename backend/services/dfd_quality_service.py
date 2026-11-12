"""Deterministic semantic-quality checks for the canonical DFD.

This module is intentionally independent from provider output.  It turns the
canonical graph into an auditable quality projection that can be consumed by
the API, model workspace, threat batcher, and PRD corpus evaluator.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any

from backend.models.dfd import (
    DfdAliasMapping,
    DfdModel,
    DfdSemanticIssue,
    DfdSemanticQuality,
)


QUALITY_VERSION = "dfd-quality-v2"
PRIMARY_FLOWS_PER_FEATURE = 6
MAX_GLOBAL_PRIMARY_FLOWS = 48


def _stable_id(prefix: str, *values: object) -> str:
    raw = "|".join(str(value or "").strip().casefold() for value in values)
    return f"{prefix}-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]}"


def normalize_semantic_label(value: object) -> str:
    """Normalize presentation-only differences without deleting identity context."""
    text = " ".join(str(value or "").replace("_", " ").replace("-", " ").split()).casefold()
    text = re.sub(r"[^a-z0-9 ]+", " ", text)
    return " ".join(text.split())


def _context_signature(item: dict) -> tuple[str, ...]:
    return tuple(
        normalize_semantic_label(item.get(field))
        for field in ("environment", "tenant_id", "operator_control_party", "ownership")
    )


def _node_signature(node: dict) -> tuple[str, ...]:
    # Canonical name is the merge key; aliases explain why a node was merged
    # but must not make an otherwise identical duplicate look unique.
    return (
        str(node.get("type") or "unknown"),
        normalize_semantic_label(node.get("name")),
        *_context_signature(node),
    )


def _base_node_signature(node: dict) -> tuple[str, str]:
    aliases = [node.get("name"), *(node.get("identity_aliases") or [])]
    normalized = sorted({normalize_semantic_label(alias) for alias in aliases if alias})
    return str(node.get("type") or "unknown"), normalized[0] if normalized else ""


def _flow_signature(flow: dict) -> tuple[str, ...]:
    return (
        str(flow.get("source_id") or ""),
        str(flow.get("target_id") or ""),
        str(flow.get("interaction_kind") or "unknown"),
        normalize_semantic_label(flow.get("protocol")),
        *(sorted(str(value) for value in (flow.get("data_object_ids") or []))),
    )


def _has_evidence(model: DfdModel, refs: list[str]) -> bool:
    known = {item.id: item for item in model.evidence}
    for ref in refs or []:
        evidence = known.get(str(ref))
        if evidence and (evidence.source or evidence.document_id or evidence.locator):
            return True
    return False


def _issue(
    code: str,
    message: str,
    next_action: str,
    *,
    affected_refs: list[str] | None = None,
    evidence_refs: list[str] | None = None,
    severity: str = "warning",
    reason: str | None = None,
    owner: str = "Product / Architecture",
) -> DfdSemanticIssue:
    return DfdSemanticIssue(
        id=_stable_id("dfd-issue", code, message, *(affected_refs or [])),
        code=code,
        severity=severity,
        message=message,
        reason=reason,
        next_action=next_action,
        owner=owner,
        affected_refs=list(dict.fromkeys(str(ref) for ref in (affected_refs or []) if ref)),
        evidence_refs=list(dict.fromkeys(str(ref) for ref in (evidence_refs or []) if ref)),
    )


def _primary_interactions(model: DfdModel) -> tuple[list[str], dict[str, list[str]], list[str]]:
    """Select a bounded, deterministic interaction set per feature/process.

    Every selected interaction remains a canonical flow.  A flow is not made
    primary merely because it is visible in an inventory: endpoints must exist,
    and explicitly deferred flows are excluded from framework work.
    """
    nodes = {node.id: node for node in model.nodes}
    eligible = [
        flow for flow in model.flows
        if flow.source_id in nodes
        and flow.target_id in nodes
        and flow.grounding_status == "grounded"
    ]

    def rank(flow) -> tuple[int, int, int, str]:
        direct = int(flow.knowledge_status == "documented" and bool(flow.evidence_refs))
        crossing = int(bool(flow.boundary_crossings))
        data = int(bool(flow.data_object_ids))
        return (-direct, -crossing, -data, str(flow.id))

    by_feature: dict[str, list] = defaultdict(list)
    process_ids = {node.id for node in model.nodes if node.type == "process"}
    for flow in eligible:
        features = [node_id for node_id in (flow.source_id, flow.target_id) if node_id in process_ids]
        by_feature[features[0] if features else "model"].append(flow)

    selected_by_feature: dict[str, list[str]] = {}
    for feature_id, flows in sorted(by_feature.items()):
        selected_by_feature[feature_id] = [flow.id for flow in sorted(flows, key=rank)[:PRIMARY_FLOWS_PER_FEATURE]]

    selected: list[str] = []
    for refs in selected_by_feature.values():
        for ref in refs:
            if ref not in selected and len(selected) < MAX_GLOBAL_PRIMARY_FLOWS:
                selected.append(ref)
    all_ids = {flow.id for flow in model.flows}
    deferred = sorted(all_ids - set(selected))
    return selected, selected_by_feature, deferred


def build_dfd_quality(model: DfdModel) -> DfdSemanticQuality:
    """Return the semantic quality projection without mutating ``model``."""
    nodes = [item.model_dump() for item in model.nodes]
    flows = [item.model_dump() for item in model.flows]
    zones = [item.model_dump() for item in model.zones]
    boundaries = [item.model_dump() for item in model.boundaries]
    node_by_id = {str(item["id"]): item for item in nodes}
    zone_by_id = {str(item["id"]): item for item in zones}
    flow_by_id = {str(item["id"]): item for item in flows}
    boundary_by_id = {str(item["id"]): item for item in boundaries}

    def effective_zones(zone_ids: list[str] | None) -> set[str]:
        result: set[str] = set()
        for raw_zone_id in zone_ids or []:
            current = str(raw_zone_id)
            visited: set[str] = set()
            while current and current not in visited and current in zone_by_id:
                visited.add(current)
                result.add(current)
                current = str(zone_by_id[current].get("parent_zone_id") or "")
        return result

    issues: list[DfdSemanticIssue] = []
    aliases: list[DfdAliasMapping] = []
    semantic_node_groups: dict[tuple[str, ...], list[dict]] = defaultdict(list)
    base_node_groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for node in nodes:
        semantic_node_groups[_node_signature(node)].append(node)
        base_node_groups[_base_node_signature(node)].append(node)
        identity_context = {
            key: str(node.get(key) or "")
            for key in ("environment", "tenant_id", "operator_control_party", "ownership")
            if node.get(key)
        }
        for alias in dict.fromkeys([node.get("name"), *(node.get("identity_aliases") or [])]):
            if not alias:
                continue
            aliases.append(DfdAliasMapping(
                canonical_id=str(node["id"]),
                canonical_label=str(node["name"]),
                alias=str(alias),
                entity_type=str(node.get("type") or "unknown"),
                decision="merged" if normalize_semantic_label(alias) != normalize_semantic_label(node["name"]) else "merged",
                reason="Alias resolves to the same canonical type and identity context.",
                identity_context=identity_context,
                evidence_refs=list(node.get("evidence_refs") or []),
            ))

    duplicate_node_count = 0
    for group in semantic_node_groups.values():
        if len(group) > 1:
            duplicate_node_count += len(group) - 1
            refs = [str(item["id"]) for item in group]
            issues.append(_issue(
                "duplicate_semantic_node",
                f"{len(group)} nodes share the same canonical type, label, and identity context.",
                "Merge the nodes after confirming their evidence locators, or record why they are separate.",
                affected_refs=refs,
                severity="blocking",
                reason="Duplicate nodes inflate the graph and can duplicate downstream scenarios.",
            ))
    for group in base_node_groups.values():
        contexts = {tuple(_context_signature(item)) for item in group}
        if len(group) > 1 and len(contexts) > 1:
            for item in group:
                aliases.append(DfdAliasMapping(
                    canonical_id=str(item["id"]),
                    canonical_label=str(item["name"]),
                    alias=str(item["name"]),
                    entity_type=str(item.get("type") or "unknown"),
                    decision="kept_separate",
                    reason="Same semantic label has incompatible environment, tenant, owner, or control-party context.",
                    identity_context={
                        key: str(item.get(key) or "")
                        for key in ("environment", "tenant_id", "operator_control_party", "ownership")
                        if item.get(key)
                    },
                    evidence_refs=list(item.get("evidence_refs") or []),
                ))
            issues.append(_issue(
                "alias_context_split",
                "Entities with the same label were kept separate because identity context differs.",
                "Confirm each environment, tenant, owner, and control-party locator before merging.",
                affected_refs=[str(item["id"]) for item in group],
                severity="info",
                reason="A semantic merge across incompatible contexts would hide a real boundary.",
            ))

    semantic_flow_groups: dict[tuple[str, ...], list[dict]] = defaultdict(list)
    for flow in flows:
        semantic_flow_groups[_flow_signature(flow)].append(flow)
    duplicate_flow_count = 0
    for group in semantic_flow_groups.values():
        if len(group) > 1:
            duplicate_flow_count += len(group) - 1
            issues.append(_issue(
                "duplicate_semantic_flow",
                f"{len(group)} flows describe the same directed interaction and payload.",
                "Merge the flow records and retain all distinct evidence locators on the canonical flow.",
                affected_refs=[str(item["id"]) for item in group],
                severity="blocking",
                reason="Duplicate edges can cause repeated STRIDE/LINDDUN coverage and misleading counts.",
            ))

    valid_endpoint_count = 0
    direction_count = 0
    evidenced_flow_count = 0
    classified_endpoint_count = 0
    cross_zone_flow_ids: set[str] = set()
    boundary_checked_flow_ids: set[str] = set()
    valid_boundary_flow_ids: set[str] = set()
    endpoint_class_counts: dict[str, int] = defaultdict(int)
    for flow in flows:
        source = node_by_id.get(str(flow.get("source_id")))
        target = node_by_id.get(str(flow.get("target_id")))
        if source and target and source["id"] != target["id"]:
            valid_endpoint_count += 1
            direction_count += 1
            endpoint_classes = {
                str(value) for value in (flow.get("endpoint_classification") or {}).values()
                if value
            }
            for endpoint_class in endpoint_classes:
                endpoint_class_counts[endpoint_class] += 1
            if endpoint_classes and endpoint_classes.issubset({
                "actor", "component", "process", "ingress", "data_store", "external_system"
            }):
                classified_endpoint_count += 1
        if flow.get("evidence_refs") and _has_evidence(model, flow.get("evidence_refs") or []):
            evidenced_flow_count += 1
        source_zones = effective_zones(source.get("zone_ids")) if source else set()
        target_zones = effective_zones(target.get("zone_ids")) if target else set()
        if source and target and source_zones != target_zones:
            cross_zone_flow_ids.add(str(flow["id"]))
            boundary_checked_flow_ids.add(str(flow["id"]))
            crossing_ids = {str(value) for value in (flow.get("boundary_crossings") or [])}
            if crossing_ids and all(
                boundary_by_id.get(value)
                and str(flow["id"]) in {str(ref) for ref in (boundary_by_id[value].get("crossing_flow_ids") or [])}
                for value in crossing_ids
            ):
                valid_boundary_flow_ids.add(str(flow["id"]))
        if source is None or target is None:
            issues.append(_issue(
                "invalid_flow_endpoint",
                f"Flow {flow.get('id')} does not resolve to two canonical endpoint nodes.",
                "Resolve both endpoint aliases from evidence before making this flow canonical.",
                affected_refs=[str(flow.get("id") or "")],
                evidence_refs=list(flow.get("evidence_refs") or []),
                severity="blocking",
                reason="A flow without canonical endpoints cannot be analyzed as a DFD interaction.",
            ))
        if not flow.get("data_object_ids"):
            issues.append(_issue(
                "missing_data_object",
                f"Flow {flow.get('id')} has no canonical data object.",
                "Name the payload or explicitly defer the data semantics with an owner and source locator.",
                affected_refs=[str(flow.get("id") or "")],
                evidence_refs=list(flow.get("evidence_refs") or []),
                severity="warning",
                reason="A directed edge without data semantics is too weak for useful STRIDE/LINDDUN scope.",
            ))
        if flow.get("grounding_status") != "grounded":
            issues.append(_issue(
                "unsupported_inferred_relationship",
                f"Flow {flow.get('id')} is a {flow.get('grounding_status')} relationship, not a grounded fact.",
                "Add a document locator or runtime observation, then promote the candidate after review.",
                affected_refs=[str(flow.get("id") or "")],
                evidence_refs=list(flow.get("evidence_refs") or []),
                severity="warning",
                reason=flow.get("grounding_reason") or "The endpoint or flow claim lacks direct source evidence.",
            ))

    zone_members = {zone_id: set() for zone_id in zone_by_id}
    for node in nodes:
        for zone_id in effective_zones(node.get("zone_ids")):
            if zone_id in zone_members:
                zone_members[zone_id].add(str(node["id"]))
    connected_nodes = {
        str(value)
        for flow in flows
        if str(flow.get("source_id")) in node_by_id and str(flow.get("target_id")) in node_by_id
        for value in (flow.get("source_id"), flow.get("target_id"))
    }
    for node in nodes:
        if str(node["id"]) not in connected_nodes:
            issues.append(_issue(
                "isolated_node",
                f"Node {node.get('name')} has no evidenced canonical flow.",
                "Add a sourced interaction or defer the node with a concrete owner and next action.",
                affected_refs=[str(node["id"])],
                evidence_refs=list(node.get("evidence_refs") or []),
                severity="blocking",
                reason="An isolated node cannot contribute a trustworthy interaction-level assessment.",
            ))
    for zone_id, members in zone_members.items():
        if not members:
            issues.append(_issue(
                "isolated_zone",
                f"Zone {zone_by_id[zone_id].get('name')} has no canonical nodes.",
                "Attach an evidenced node, remove the obsolete zone, or defer the zone decision.",
                affected_refs=[zone_id],
                evidence_refs=list(zone_by_id[zone_id].get("evidence_refs") or []),
                severity="warning",
                reason="An empty zone can make boundary coverage appear complete while hiding missing topology.",
            ))
    for flow_id in sorted(cross_zone_flow_ids):
        flow = flow_by_id[flow_id]
        if not flow.get("boundary_crossings"):
            issues.append(_issue(
                "missing_cross_zone_boundary",
                f"Cross-zone flow {flow.get('display_id') or flow_id} has no trust boundary link.",
                "Create or review the boundary that this interaction crosses; do not infer it from canvas geometry.",
                affected_refs=[flow_id],
                evidence_refs=list(flow.get("evidence_refs") or []),
                severity="blocking",
                reason="Cross-zone interaction without a boundary is not analyzable for boundary controls.",
            ))
    for boundary in boundaries:
        crossing_ids = [str(value) for value in (boundary.get("crossing_flow_ids") or [])]
        if not crossing_ids:
            issues.append(_issue(
                "boundary_without_interaction",
                f"Boundary {boundary.get('name')} has no linked crossing interaction.",
                "Link an evidenced flow, or defer/remove the boundary candidate.",
                affected_refs=[str(boundary["id"])],
                evidence_refs=list(boundary.get("evidence_refs") or []),
                severity="warning",
                reason="A boundary without an interaction cannot drive a concrete threat scope.",
            ))

    if not nodes and not flows:
        issues.append(_issue(
            "empty_canonical_graph",
            "Canonical DFD has no grounded nodes or flows.",
            "Add architecture evidence or keep the analysis explicitly deferred until a primary interaction is documented.",
            severity="blocking",
            reason="An empty graph cannot support interaction-level threat analysis.",
        ))
    for deferred in model.deferred_interactions:
        issues.append(_issue(
            "deferred_interaction",
            f"Interaction {deferred.source or '(unknown)'} → {deferred.destination or '(unknown)'} is deferred.",
            deferred.next_action,
            affected_refs=[str(deferred.id)],
            evidence_refs=list(deferred.evidence_refs),
            severity="warning",
            reason=deferred.reason,
            owner=deferred.owner,
        ))

    primary_ids, primary_by_feature, deferred_ids = _primary_interactions(model)
    deferred_ids = sorted({*deferred_ids, *(item.id for item in model.deferred_interactions)})
    if deferred_ids:
        issues.append(_issue(
            "primary_interaction_cap",
            f"{len(deferred_ids)} eligible flows are outside the bounded primary interaction set.",
            "Review deferred interactions and add them to a feature-specific analysis scope when required.",
            affected_refs=deferred_ids,
            severity="warning",
            reason="Framework work is intentionally bounded; inventory entities are not automatically analyzed.",
        ))

    total_nodes = len(nodes)
    total_flows = len(flows)
    metrics: dict[str, float | int | None] = {
        "node_uniqueness_rate": round((total_nodes - duplicate_node_count) / total_nodes, 4) if total_nodes else None,
        "flow_uniqueness_rate": round((total_flows - duplicate_flow_count) / total_flows, 4) if total_flows else None,
        "duplicate_semantic_node_rate": round(duplicate_node_count / total_nodes, 4) if total_nodes else 0.0,
        "duplicate_semantic_flow_rate": round(duplicate_flow_count / total_flows, 4) if total_flows else 0.0,
        "isolated_node_rate": round(sum(str(node["id"]) not in connected_nodes for node in nodes) / total_nodes, 4) if total_nodes else 0.0,
        "isolated_zone_rate": round(sum(not members for members in zone_members.values()) / len(zone_members), 4) if zone_members else 0.0,
        "unresolved_alias_rate": round(sum(not node.get("identity_key") for node in nodes) / total_nodes, 4) if total_nodes else 0.0,
        "valid_endpoint_rate": round(valid_endpoint_count / total_flows, 4) if total_flows else 0.0,
        "direction_rate": round(direction_count / total_flows, 4) if total_flows else 0.0,
        "evidence_rate": round(evidenced_flow_count / total_flows, 4) if total_flows else 0.0,
        "endpoint_classification_rate": round(classified_endpoint_count / total_flows, 4) if total_flows else 0.0,
        "data_store_external_classification_rate": round(
            (endpoint_class_counts.get("data_store", 0) + endpoint_class_counts.get("external_system", 0))
            / max(1, sum(endpoint_class_counts.values())), 4
        ) if endpoint_class_counts else 0.0,
        "boundary_crossing_accuracy": round(len(valid_boundary_flow_ids) / len(boundary_checked_flow_ids), 4) if boundary_checked_flow_ids else 1.0,
        "primary_interaction_coverage": round(len(primary_ids) / len({str(flow["id"]) for flow in flows}), 4) if flows else 0.0,
    }
    counts = {
        "nodes": total_nodes,
        "flows": total_flows,
        "zones": len(zones),
        "boundaries": len(boundaries),
        "duplicate_nodes": duplicate_node_count,
        "duplicate_flows": duplicate_flow_count,
        "isolated_nodes": sum(str(node["id"]) not in connected_nodes for node in nodes),
        "isolated_zones": sum(not members for members in zone_members.values()),
        "valid_endpoints": valid_endpoint_count,
        "evidenced_flows": evidenced_flow_count,
        "cross_zone_flows": len(cross_zone_flow_ids),
        "valid_crossing_flows": len(valid_boundary_flow_ids),
        "data_store_endpoints": endpoint_class_counts.get("data_store", 0),
        "external_system_endpoints": endpoint_class_counts.get("external_system", 0),
        "unknown_endpoint_classes": endpoint_class_counts.get("unknown", 0),
        "primary_interactions": len(primary_ids),
        "deferred_interactions": len(deferred_ids),
        "deferred_claims": len(model.deferred_interactions),
    }
    status = "blocked" if any(item.severity == "blocking" for item in issues) else "review" if issues else "ready"
    return DfdSemanticQuality(
        version=QUALITY_VERSION,
        status=status,
        metrics=metrics,
        counts=counts,
        primary_interaction_ids=primary_ids,
        primary_interactions_by_feature=primary_by_feature,
        deferred_interaction_ids=deferred_ids,
        alias_mappings=aliases,
        issues=issues,
    )


def evaluate_expected_dfd(model: DfdModel | dict, expected: dict) -> dict:
    """Compare a model with labelled corpus expectations using explicit counts."""
    if isinstance(model, DfdModel):
        payload = model.model_dump()
    else:
        payload = model if isinstance(model, dict) else {}
    nodes = [item for item in payload.get("nodes") or [] if isinstance(item, dict)]
    data_objects = [item for item in payload.get("data_objects") or [] if isinstance(item, dict)]
    flows = [item for item in payload.get("flows") or [] if isinstance(item, dict)]
    node_labels = {normalize_semantic_label(item.get("name")) for item in nodes}
    data_labels = {normalize_semantic_label(item.get("name")) for item in data_objects}
    aliases: dict[str, str] = {}
    for item in nodes:
        canonical = normalize_semantic_label(item.get("name"))
        for alias in [item.get("name"), *(item.get("identity_aliases") or [])]:
            aliases[normalize_semantic_label(alias)] = canonical

    def observe(values: list[str], available: set[str], allow_aliases: bool = True) -> dict:
        matched = 0
        for value in values:
            normalized = normalize_semantic_label(value)
            if normalized in available or (allow_aliases and normalized in aliases):
                matched += 1
        return {"numerator": matched, "denominator": len(values)}

    required = expected.get("required_entities") or []
    required_labels = [str(item.get("label") if isinstance(item, dict) else item) for item in required]
    required_data = [str(item.get("label") if isinstance(item, dict) else item) for item in (expected.get("required_data") or [])]
    allowed = {
        normalize_semantic_label(value)
        for value in [
            *(expected.get("optional_entities") or []),
            *(expected.get("inferred_allowed") or []),
        ]
    }
    expected_label_set = {
        normalize_semantic_label(value)
        for value in [*required_labels, *required_data]
    }
    unsupported = [
        item.get("id") for item in [*nodes, *data_objects]
        if normalize_semantic_label(item.get("name")) not in expected_label_set | allowed
    ]
    endpoint_valid = sum(
        bool(flow.get("source_id") and flow.get("target_id") and flow.get("source_id") != flow.get("target_id"))
        for flow in flows
    )
    return {
        "entity_recall": observe(required_labels, node_labels),
        "data_recall": observe(required_data, data_labels, allow_aliases=False),
        "precision": {
            "numerator": len(nodes) + len(data_objects) - len(unsupported),
            "denominator": len(nodes) + len(data_objects),
        },
        "unsupported_ids": unsupported,
        "valid_endpoint": {"numerator": endpoint_valid, "denominator": len(flows)},
        "duplicate_node": {
            "numerator": max(0, len(nodes) - len({_node_signature(item) for item in nodes})),
            "denominator": len(nodes),
        },
        "flow_count": len(flows),
    }
