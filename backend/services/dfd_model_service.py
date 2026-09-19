"""Build and validate the canonical DFD model from the grounded topology."""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict

from backend.models.dfd import (
    DfdAssertion,
    DfdBoundary,
    DfdDataObject,
    DfdEvidenceRef,
    DfdFlow,
    DfdModel,
    DfdNode,
    DfdProcessMetadata,
    DfdStoreMetadata,
    DfdQuestion,
    DfdView,
    DfdZone,
)
from backend.services.posture_service import build_project_evidence_catalog


DFD_SCHEMA_VERSION = "dfd-v1"
_VALID_INTERACTIONS = {"request", "response", "event", "read", "write", "replication", "unknown"}
_VALID_BOUNDARY_TYPES = {"network", "identity", "privilege", "tenant", "organization", "unknown"}


def _stable_id(prefix: str, *values: object) -> str:
    raw = "|".join(str(value or "").strip().casefold() for value in values)
    return f"{prefix}-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]}"


def _unique(values) -> list[str]:
    result = []
    seen = set()
    for value in values or []:
        text = str(value or "").strip()
        if text and text.casefold() not in seen:
            seen.add(text.casefold())
            result.append(text)
    return result


def _display_ids(items: list[dict], prefix: str) -> dict[str, str]:
    return {
        str(item["id"]): f"{prefix}{index}"
        for index, item in enumerate(sorted(items, key=lambda value: str(value.get("name") or "").casefold()), start=1)
    }


def _zone_label(zone_id: str) -> str:
    labels = {
        "external": "External",
        "external-privileged": "Privileged External",
        "external-dependency": "External Dependency",
        "application": "Application",
        "data": "Data Store",
    }
    return labels.get(zone_id, zone_id.replace("-", " ").title())


def _node_type(entity_type: str) -> str:
    if entity_type == "data_store":
        return "data_store"
    if entity_type in {"actor", "external_system"}:
        return "entity"
    return "process"


def _source_refs(project: dict) -> list[str]:
    refs = [f"artifact:{source.get('artifact_id')}" for source in project.get("artifact_sources", []) or [] if isinstance(source, dict) and source.get("artifact_id") and source.get("active", True)]
    if project.get("manual_context"):
        refs.append("manual:context")
    return _unique(refs)


def _model_evidence(project: dict, additional_refs: list[str] | None = None) -> list[DfdEvidenceRef]:
    sources = {
        str(source.get("filename") or source.get("artifact_type") or ""): source
        for source in project.get("artifact_sources", []) or []
        if isinstance(source, dict) and source.get("active", True)
    }
    result = []
    for source_ref in _source_refs(project):
        if source_ref.startswith("artifact:"):
            artifact_id = source_ref.split(":", 1)[1]
            source = next((item for item in project.get("artifact_sources", []) or []
                           if isinstance(item, dict) and str(item.get("artifact_id")) == artifact_id), {})
            result.append(DfdEvidenceRef(
                id=source_ref,
                document_id=artifact_id,
                document_revision=source.get("revision"),
                document_hash=source.get("content_hash"),
                locator="Artifact source identity",
            ))
        elif source_ref == "manual:context":
            result.append(DfdEvidenceRef(
                id=source_ref,
                document_id="manual-context",
                locator="Project context",
            ))
    for item in build_project_evidence_catalog(project)[:96]:
        source = sources.get(str(item.get("source") or ""))
        if any(existing.id == str(item.get("evidence_id")) for existing in result):
            continue
        result.append(DfdEvidenceRef(
            id=str(item.get("evidence_id")),
            document_id=str((source or {}).get("artifact_id") or "project-context"),
            document_revision=(source or {}).get("revision"),
            document_hash=(source or {}).get("content_hash"),
            locator=str(item.get("locator") or "Artifact content"),
            excerpt_redacted=str(item.get("snippet") or ""),
        ))
    for evidence_id in _unique(additional_refs or []):
        if any(existing.id == evidence_id for existing in result):
            continue
        prefix, _, locator = evidence_id.partition(":")
        result.append(DfdEvidenceRef(
            id=evidence_id,
            document_id=prefix or "grounded-model",
            locator=locator or "Grounded model reference",
        ))
    return result


def _unknown_assertions(
    nodes: list[DfdNode],
    data_objects: list[DfdDataObject],
    flows: list[DfdFlow],
    stores: dict[str, DfdStoreMetadata],
) -> list:
    assertions = []
    for node in nodes:
        for field in ("scope", "ownership", "exposure"):
            value = getattr(node, field)
            if value == "unknown":
                assertions.append(DfdAssertion(
                    object_id=node.id,
                    field_path=field,
                    value=None,
                    status="unknown",
                    evidence_refs=node.evidence_refs,
                    inference_reason="The current grounded topology does not establish this classification.",
                ))
    for flow in flows:
        if flow.interaction_kind == "unknown":
            assertions.append(DfdAssertion(
                object_id=flow.id,
                field_path="interaction_kind",
                value=None,
                status="unknown",
                evidence_refs=flow.evidence_refs,
                inference_reason="The source does not distinguish request, response, event, read, write, or replication.",
            ))
    for data_object in data_objects:
        for field in (
            "purpose", "recipients", "data_subjects", "identifiers", "sensitivity",
            "direct_identifiers", "indirect_identifiers", "linkability", "notice",
            "individual_control", "legal_basis",
        ):
            value = getattr(data_object, field)
            if value in (None, "", []):
                assertions.append(DfdAssertion(
                    object_id=data_object.id,
                    field_path=field,
                    value=None,
                    status="unknown",
                    evidence_refs=data_object.evidence_refs,
                    inference_reason="Privacy metadata is not documented for this data object.",
                ))
    for store_id, store in stores.items():
        for field in ("retention", "deletion", "backup"):
            if getattr(store, field) in (None, "unknown"):
                assertions.append(DfdAssertion(
                    object_id=store_id,
                    field_path=field,
                    value=None,
                    status="unknown",
                    inference_reason="Lifecycle metadata is not documented.",
                ))
    return assertions


def _conflict_assertions(project: dict) -> list[DfdAssertion]:
    assertions = []
    for conflict in project.get("artifact_conflicts", []) or []:
        if not isinstance(conflict, dict):
            continue
        operation_key = str(conflict.get("operation_key") or "unknown-operation")
        field = str(conflict.get("field") or "unknown-field")
        source_refs = [
            f"artifact:{item.get('artifact_id')}"
            for item in (conflict.get("values") or [])
            if isinstance(item, dict) and item.get("artifact_id")
        ]
        assertions.append(DfdAssertion(
            object_id=_stable_id("conflict", operation_key, field),
            field_path=f"operation[{operation_key}].{field}",
            value=conflict.get("values"),
            status="conflicting",
            evidence_refs=source_refs,
            inference_reason=str(conflict.get("message") or "Source documents disagree."),
        ))
    return assertions


def _semantic_hash(model: DfdModel) -> str:
    """Hash semantic state only; view positions and viewport are presentation."""
    payload = model.model_dump(exclude={
        "views", "semantic_hash", "revision", "layout_revision",
        "human_edit_revision", "source_semantic_hash",
    })
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def _zone_membership(node: DfdNode, zones_by_id: dict[str, DfdZone]) -> tuple[set[str], bool]:
    """Return a node's zone plus ancestors and whether membership is unresolved."""
    if not node.zone_ids:
        return set(), True
    members: set[str] = set()
    unresolved = False
    for zone_id in node.zone_ids:
        current = zone_id
        seen: set[str] = set()
        while current:
            if current in seen:
                unresolved = True
                break
            seen.add(current)
            zone = zones_by_id.get(current)
            if not zone:
                unresolved = True
                break
            members.add(current)
            current = zone.parent_zone_id
    return members, unresolved


def recalculate_boundary_crossings(model: DfdModel) -> DfdModel:
    """Derive zone crossings from semantic membership, preserving reviewer links.

    Visual line intersections are deliberately not consulted. A missing or
    invalid zone membership makes the flow unresolved rather than silently
    asserting that no boundary was crossed.
    """
    zones_by_id = {zone.id: zone for zone in model.zones}
    nodes_by_id = {node.id: node for node in model.nodes}
    boundary_by_id = {boundary.id: boundary for boundary in model.boundaries}
    memberships = {
        node_id: _zone_membership(node, zones_by_id)
        for node_id, node in nodes_by_id.items()
    }
    flow_matches: dict[str, set[str]] = defaultdict(set)

    for flow in model.flows:
        source_members, source_unresolved = memberships.get(flow.source_id, (set(), True))
        target_members, target_unresolved = memberships.get(flow.target_id, (set(), True))
        reviewer_crossings = {
            boundary_id for boundary_id in flow.boundary_crossings
            if boundary_id in boundary_by_id
            and flow.crossing_origins.get(boundary_id) == "reviewer"
        }
        # Models from before crossing_origins existed may still contain a
        # reviewer-authored non-derived boundary link. Preserve it when the
        # boundary is explicitly marked non-derived.
        reviewer_crossings.update(
            boundary_id for boundary_id in flow.boundary_crossings
            if boundary_id in boundary_by_id
            and not boundary_by_id[boundary_id].derived
            and boundary_id not in flow.crossing_origins
        )
        derived_crossings: set[str] = set()
        for boundary in model.boundaries:
            if boundary.status == "rejected":
                continue
            if boundary.transition_scope == "logical":
                continue
            if not boundary.source_zone_ids or not boundary.target_zone_ids:
                continue
            if source_unresolved or target_unresolved:
                continue
            source_boundary = set(boundary.source_zone_ids)
            target_boundary = set(boundary.target_zone_ids)
            # An ancestor is useful for matching a child node to a parent
            # boundary, but a shared ancestor must not turn an intra-zone flow
            # into a crossing. Require each endpoint to be outside the other
            # side of the transition.
            forward = bool(
                source_members & source_boundary
                and target_members & target_boundary
                and not source_members & target_boundary
                and not target_members & source_boundary
            )
            reverse = bool(
                source_members & target_boundary
                and target_members & source_boundary
                and not source_members & source_boundary
                and not target_members & target_boundary
            )
            if forward or reverse:
                derived_crossings.add(boundary.id)
                direction = "source-to-target" if forward else "target-to-source"
                flow.crossing_rationales[boundary.id] = (
                    f"Derived from zone membership ({direction}); "
                    f"{flow.source_id} → {flow.target_id} crosses {boundary.name}."
                )
                flow.crossing_origins[boundary.id] = "derived"

        crossing_ids = sorted(reviewer_crossings | derived_crossings)
        flow.boundary_crossings = crossing_ids
        flow.crossing_status = "unresolved" if source_unresolved or target_unresolved else "resolved"
        for boundary_id in crossing_ids:
            flow_matches.setdefault(boundary_id, set()).add(flow.id)

    for boundary in model.boundaries:
        preserved = {
            flow.id for flow in model.flows
            if boundary.id in flow.boundary_crossings
            and (flow.crossing_origins.get(boundary.id) == "reviewer" or not boundary.derived)
        }
        boundary.crossing_flow_ids = sorted(preserved | flow_matches.get(boundary.id, set()))

    model.semantic_hash = _semantic_hash(model)
    return model


def refresh_attribute_assertions(model: DfdModel) -> DfdModel:
    """Synchronize per-attribute knowledge assertions after a human edit.

    A value entered without evidence is ``inferred`` rather than ``documented``;
    clearing a value restores an explicit ``unknown`` assertion. Existing
    ``conflicting`` assertions are retained until a reviewer resolves them.
    """
    def is_missing(value: object) -> bool:
        return value is None or value == "" or value == [] or value == "unknown"

    value_by_object: dict[str, object] = {
        **{item.id: item for item in [*model.nodes, *model.data_objects]},
        **{store_id: store for store_id, store in model.stores.items()},
    }

    def update_assertions(
        object_id: str,
        current: list[DfdAssertion],
        fields: tuple[str, ...],
        evidence_refs: list[str],
    ) -> list[DfdAssertion]:
        existing = {assertion.field_path: assertion for assertion in current}
        owner = value_by_object[object_id]
        updated: list[DfdAssertion] = []
        for field in fields:
            value = getattr(owner, field, None)
            prior = existing.get(field)
            if prior and prior.status == "conflicting":
                updated.append(prior)
                continue
            if is_missing(value):
                updated.append(DfdAssertion(
                    object_id=object_id,
                    field_path=field,
                    value=None,
                    status="unknown",
                    evidence_refs=list(evidence_refs),
                    inference_reason="The value is not established by the current model or evidence.",
                    review_status=prior.review_status if prior else "open",
                ))
            else:
                status = "documented" if evidence_refs else "inferred"
                updated.append(DfdAssertion(
                    object_id=object_id,
                    field_path=field,
                    value=value,
                    status=status,
                    evidence_refs=list(evidence_refs),
                    inference_reason=None if status == "documented" else "Value entered or normalized without direct source evidence.",
                    review_status=prior.review_status if prior else "reviewed",
                ))
        return updated

    node_fields = ("scope", "ownership", "exposure")
    for node in model.nodes:
        node.assertions = update_assertions(node.id, node.assertions, node_fields, node.evidence_refs)
    data_fields = (
        "purpose", "recipients", "data_subjects", "identifiers", "sensitivity",
        "direct_identifiers", "indirect_identifiers", "linkability", "notice",
        "individual_control", "legal_basis",
    )
    for item in model.data_objects:
        item.assertions = update_assertions(item.id, item.assertions, data_fields, item.evidence_refs)
    for store_id, store in model.stores.items():
        store.assertions = update_assertions(store_id, store.assertions, ("retention", "deletion", "backup"), store.evidence_refs)

    managed_ids = {node.id for node in model.nodes} | {item.id for item in model.data_objects} | set(model.stores)
    preserved = [assertion for assertion in model.assertions if assertion.object_id not in managed_ids]
    model.assertions = [
        *preserved,
        *(assertion for node in model.nodes for assertion in node.assertions),
        *(assertion for item in model.data_objects for assertion in item.assertions),
        *(assertion for store in model.stores.values() for assertion in store.assertions),
    ]
    return model


def diff_dfd_models(previous: DfdModel, candidate: DfdModel) -> dict:
    """Return a reviewable semantic proposal without mutating the saved model."""
    def index(items):
        return {item.id: item.model_dump() for item in items}

    sections = {}
    for name in ("nodes", "data_objects", "flows", "stores", "zones", "boundaries", "questions"):
        old = {key: value.model_dump() for key, value in previous.stores.items()} if name == "stores" else index(getattr(previous, name))
        new = {key: value.model_dump() for key, value in candidate.stores.items()} if name == "stores" else index(getattr(candidate, name))
        sections[name] = {
            "added": sorted(set(new) - set(old)),
            "removed": sorted(set(old) - set(new)),
            "changed": sorted(key for key in set(old) & set(new) if old[key] != new[key]),
        }
    return {
        "base_revision": previous.revision,
        "candidate_revision": candidate.revision,
        "base_semantic_hash": previous.semantic_hash,
        "candidate_semantic_hash": candidate.semantic_hash,
        "sections": sections,
    }


def reconcile_generated_dfd(generated: DfdModel, previous: dict | None) -> tuple[DfdModel, dict | None, bool]:
    """Keep human edits authoritative and expose source changes as a proposal."""
    if not isinstance(previous, dict) or int(previous.get("human_edit_revision", 0) or 0) <= 0:
        return generated, None, False
    try:
        prior = DfdModel.model_validate(previous)
    except Exception:
        return generated, None, False
    source_baseline = prior.source_semantic_hash or prior.semantic_hash
    if generated.semantic_hash == source_baseline:
        return prior, None, False
    return prior, diff_dfd_models(prior, generated), True


PROPOSAL_SECTIONS = ("nodes", "data_objects", "flows", "stores", "zones", "boundaries", "questions")


def preview_dfd_delete_impact(
    model: DfdModel,
    element_type: str,
    element_id: str,
    threats: list[dict] | None = None,
) -> dict:
    """Describe semantic dependencies before a caller attempts deletion."""
    collections = {
        "node": model.nodes,
        "data_object": model.data_objects,
        "flow": model.flows,
        "zone": model.zones,
        "boundary": model.boundaries,
        "question": model.questions,
    }
    items = collections.get(element_type)
    if items is None:
        raise ValueError(f"Unsupported DFD element type: {element_type}")
    element = next((item for item in items if item.id == element_id), None)
    if element is None:
        raise KeyError(element_id)

    dependent_flows = []
    dependent_nodes = []
    dependent_views = []
    dependent_boundaries = []
    dependent_zones = []
    dependent_questions = []
    dependent_threats = []
    for flow in model.flows:
        if element_type == "node" and (flow.source_id == element_id or flow.target_id == element_id):
            dependent_flows.append(flow.id)
        elif element_type == "data_object" and element_id in flow.data_object_ids:
            dependent_flows.append(flow.id)
        elif element_type == "boundary" and element_id in flow.boundary_crossings:
            dependent_flows.append(flow.id)
    if element_type == "zone":
        parent_by_zone = {zone.id: zone.parent_zone_id for zone in model.zones}

        def node_in_zone(node: DfdNode) -> bool:
            for zone_id in node.zone_ids:
                current = zone_id
                visited = set()
                while current and current not in visited:
                    if current == element_id:
                        return True
                    visited.add(current)
                    current = parent_by_zone.get(current)
            return False

        dependent_nodes = [node.id for node in model.nodes if node_in_zone(node)]
        descendants = []
        pending = [element_id]
        while pending:
            parent_id = pending.pop()
            children = [zone.id for zone in model.zones if zone.parent_zone_id == parent_id]
            descendants.extend(child for child in children if child not in descendants)
            pending.extend(child for child in children if child not in pending)
        dependent_zones = descendants
        dependent_flows = [
            flow.id for flow in model.flows
            if any(node_in_zone(node) for node in model.nodes if node.id in {flow.source_id, flow.target_id})
        ]
        dependent_boundaries = [
            boundary.id for boundary in model.boundaries
            if any(zone_id in {element_id, *dependent_zones} for zone_id in [*boundary.source_zone_ids, *boundary.target_zone_ids])
        ]
    if element_type == "boundary":
        dependent_boundaries = [element_id]
    if element_type in {"node", "data_object", "flow", "boundary", "zone"}:
        dependent_views = [
            view.id for view in model.views
            if element_id in view.element_refs
            or element_id in view.projection_mappings
            or any(element_id in mapped for mapped in view.projection_mappings.values())
        ]
        dependent_questions = [
            question.id for question in model.questions if element_id in question.affected_refs
        ]
        dependent_threats = [
            str(threat.get("threat_id")) for threat in (threats or [])
            if isinstance(threat, dict)
            and any(str(ref.get("id")) == element_id for ref in (threat.get("target_refs") or []) if isinstance(ref, dict))
        ]

    dependencies = (
        dependent_nodes
        + dependent_flows
        + dependent_views
        + dependent_boundaries
        + dependent_zones
        + dependent_questions
        + dependent_threats
    )
    return {
        "element_type": element_type,
        "element_id": element_id,
        "label": getattr(element, "name", getattr(element, "question", element_id)),
        "safe_to_delete": not dependencies,
        "dependent_nodes": sorted(set(dependent_nodes)),
        "dependent_flows": sorted(set(dependent_flows)),
        "dependent_views": sorted(set(dependent_views)),
        "dependent_boundaries": sorted(set(dependent_boundaries)),
        "dependent_zones": sorted(set(dependent_zones)),
        "dependent_questions": sorted(set(dependent_questions)),
        "dependent_threats": sorted(set(dependent_threats)),
        "requires_review": bool(dependent_questions or dependent_threats),
    }


def apply_dfd_proposal(current: DfdModel, candidate: DfdModel, sections: list[str] | None = None) -> DfdModel:
    """Apply an explicitly reviewed regeneration proposal.

    Candidate generation never mutates the saved model. This helper is only
    called by the review endpoint after the caller has explicitly selected all
    or a subset of semantic sections. Presentation state is always retained
    from the current model so accepting source changes cannot reset a user's
    layout or collapsed groups.
    """
    selected = set(sections or PROPOSAL_SECTIONS)
    invalid = selected - set(PROPOSAL_SECTIONS)
    if invalid:
        raise ValueError(f"Unsupported proposal sections: {', '.join(sorted(invalid))}")

    updated = current.model_copy(deep=True)
    candidate_copy = candidate.model_copy(deep=True)
    for section in selected:
        setattr(updated, section, getattr(candidate_copy, section))

    candidate_views = {view.id: view for view in candidate.views}
    current_views = {view.id: view for view in current.views}
    merged_views = []
    for view_id, generated_view in candidate_views.items():
        saved_view = current_views.get(view_id)
        if saved_view:
            merged_views.append(generated_view.model_copy(update={
                "positions": saved_view.positions,
                "collapsed_groups": saved_view.collapsed_groups,
                "viewport": saved_view.viewport,
            }))
        else:
            merged_views.append(generated_view)
    updated.views = merged_views
    recalculate_boundary_crossings(updated)
    return updated


def build_dfd_model(project: dict, trust_model: dict, previous: dict | None = None) -> DfdModel:
    """Project grounded topology into the canonical semantic contract.

    This adapter deliberately preserves unknown classification values. It does
    not promote the current heuristic trust labels into ownership or exposure
    facts.
    """
    entities = [item for item in trust_model.get("entities", []) if isinstance(item, dict) and item.get("entity_id") and item.get("name")]
    flows = [item for item in trust_model.get("data_flows", []) if isinstance(item, dict) and item.get("flow_id")]
    boundaries = [item for item in trust_model.get("boundaries", []) if isinstance(item, dict) and item.get("boundary_id")]
    entity_by_name = {str(item.get("name")).casefold(): item for item in entities}

    raw_nodes = [{
        "id": item["entity_id"],
        "name": item["name"],
        "type": _node_type(item.get("entity_type", "component")),
    } for item in entities]
    display_by_node = {}
    for node_type, prefix in (("entity", "E"), ("process", "P"), ("data_store", "D")):
        display_by_node.update(_display_ids([item for item in raw_nodes if item["type"] == node_type], prefix))

    zone_ids = sorted({str(item.get("zone_id")) for item in entities if item.get("zone_id")})
    zone_display = {zone_id: f"Z{index}" for index, zone_id in enumerate(zone_ids, start=1)}
    zones = [DfdZone(
        id=f"zone-{zone_id}",
        display_id=zone_display[zone_id],
        name=_zone_label(zone_id),
        description="Derived from grounded topology; ownership and exposure require review.",
        trust_assumptions=[],
        knowledge_status="inferred",
    ) for zone_id in zone_ids]
    zone_ref = {zone_id: f"zone-{zone_id}" for zone_id in zone_ids}

    nodes = []
    for item in entities:
        node_id = item["entity_id"]
        raw_type = _node_type(item.get("entity_type", "component"))
        nodes.append(DfdNode(
            id=node_id,
            display_id=display_by_node[node_id],
            type=raw_type,
            name=item["name"],
            scope="unknown",
            ownership="unknown",
            exposure="unknown",
            zone_ids=[zone_ref[item["zone_id"]]] if item.get("zone_id") in zone_ref else [],
            knowledge_status="inferred" if item.get("confidence") != "High" else "documented",
            evidence_refs=_unique(item.get("evidence_refs", [])),
        ))

    canonical_operations = [item for item in (project.get("canonical_operations") or []) if isinstance(item, dict)]
    operation_request_fields = _unique(
        field for operation in canonical_operations for field in (operation.get("request_fields") or [])
    )
    operation_response_fields = _unique(
        field for operation in canonical_operations for field in (operation.get("response_fields") or [])
    )
    all_flow_data = [
        *(field for flow in flows for field in (flow.get("data") or [])),
        *operation_request_fields,
        *operation_response_fields,
    ]
    data_objects = []
    data_object_by_name = {}
    for value in _unique(all_flow_data):
        object_id = _stable_id("data-object", value)
        data_object_by_name[value.casefold()] = object_id
        data_objects.append(DfdDataObject(
            id=object_id,
            display_id=f"DO{len(data_objects) + 1}",
            name=value,
            knowledge_status="inferred",
        ))

    dfd_flows = []
    flow_variants = []
    for flow in flows:
        flow_variants.append((flow, "request", flow.get("data") or operation_request_fields, False))
        if canonical_operations and operation_response_fields:
            flow_variants.append((flow, "response", operation_response_fields, True))
    for index, (flow, interaction_kind, variant_data, reverse_direction) in enumerate(flow_variants, start=1):
        source = entity_by_name.get(str(flow.get("source") or "").casefold())
        target = entity_by_name.get(str(flow.get("destination") or "").casefold())
        if not source or not target:
            continue
        raw_interaction = str(flow.get("interaction_kind") or interaction_kind)
        if raw_interaction not in _VALID_INTERACTIONS or raw_interaction == "unknown":
            raw_interaction = interaction_kind
        data_ids = [data_object_by_name[str(value).casefold()] for value in variant_data if str(value).casefold() in data_object_by_name]
        flow_id = flow["flow_id"] if not reverse_direction else _stable_id("flow-response", flow["flow_id"])
        dfd_flows.append(DfdFlow(
            id=flow_id,
            display_id=f"F{index}",
            source_id=target["entity_id"] if reverse_direction else source["entity_id"],
            target_id=source["entity_id"] if reverse_direction else target["entity_id"],
            name=(variant_data or ["Unknown data flow"])[0],
            data_object_ids=data_ids,
            protocol=flow.get("protocol"),
            interaction_kind=raw_interaction,
            authn=project.get("auth_method") or None,
            authz=("documented" if any(operation.get("security_status") == "secured" for operation in canonical_operations) else None),
            boundary_crossings=[],
            crossing_status="resolved",
            evidence_refs=_unique(flow.get("evidence_refs", [])),
            knowledge_status="documented" if flow.get("evidence_type") == "direct" else "inferred",
        ))

    dfd_flow_by_id = {item.id: item for item in dfd_flows}
    dfd_boundaries = []
    boundary_display = {}
    for index, boundary in enumerate(boundaries, start=1):
        boundary_id = boundary["boundary_id"]
        boundary_display[boundary_id] = f"TB{index}"
        source_entity = entity_by_name.get(str(boundary.get("source") or "").casefold())
        target_entity = entity_by_name.get(str(boundary.get("destination") or "").casefold())
        source_zone = source_entity.get("zone_id") if source_entity else None
        target_zone = target_entity.get("zone_id") if target_entity else None
        crossing_flow_ids = [flow_id for flow_id in boundary.get("crossing_flow_ids", []) if flow_id in dfd_flow_by_id]
        for flow_id in crossing_flow_ids:
            dfd_flow_by_id[flow_id].boundary_crossings.append(boundary_id)
        boundary_types = [value for value in (boundary.get("boundary_types") or []) if value in _VALID_BOUNDARY_TYPES]
        dfd_boundaries.append(DfdBoundary(
            id=boundary_id,
            display_id=boundary_display[boundary_id],
            name=boundary.get("boundary_label") or f"{boundary.get('source')} → {boundary.get('destination')}",
            types=boundary_types or ["unknown"],
            rationale=boundary.get("basis"),
            source_zone_ids=[zone_ref[source_zone]] if source_zone in zone_ref else [],
            target_zone_ids=[zone_ref[target_zone]] if target_zone in zone_ref else [],
            crossing_flow_ids=crossing_flow_ids,
            transition_scope="zone" if source_zone in zone_ref and target_zone in zone_ref else "unknown",
            status={"Candidate": "candidate", "Confirmed": "confirmed", "Rejected": "rejected"}.get(boundary.get("status"), "unresolved"),
            derived=True,
            evidence_refs=_unique(boundary.get("evidence_refs", [])),
        ))

    for flow in dfd_flows:
        flow.boundary_crossings = _unique(flow.boundary_crossings)

    flow_inputs: dict[str, list[str]] = defaultdict(list)
    flow_outputs: dict[str, list[str]] = defaultdict(list)
    store_data: dict[str, set[str]] = defaultdict(set)
    store_readers: dict[str, set[str]] = defaultdict(set)
    store_writers: dict[str, set[str]] = defaultdict(set)
    for flow in dfd_flows:
        flow_outputs[flow.source_id].append(flow.id)
        flow_inputs[flow.target_id].append(flow.id)
        if node_by_id := next((node for node in nodes if node.id == flow.target_id), None):
            if node_by_id.type == "data_store":
                store_data[node_by_id.id].update(flow.data_object_ids)
                store_writers[node_by_id.id].add(flow.source_id)
        if node_by_id := next((node for node in nodes if node.id == flow.source_id), None):
            if node_by_id.type == "data_store":
                store_data[node_by_id.id].update(flow.data_object_ids)
                store_readers[node_by_id.id].add(flow.target_id)
    nodes = [
        node.model_copy(update={
            "process_metadata": DfdProcessMetadata(
                input_flow_ids=sorted(flow_inputs.get(node.id, [])),
                output_flow_ids=sorted(flow_outputs.get(node.id, [])),
            ) if node.type == "process" else None,
        })
        for node in nodes
    ]

    all_element_ids = [item.id for item in nodes] + [item.id for item in dfd_flows] + [item.id for item in dfd_boundaries] + [item.id for item in data_objects]
    identity_projection = {element_id: [element_id] for element_id in all_element_ids}
    views = [
        DfdView(
            id="view-context",
            kind="context",
            element_refs=all_element_ids,
            projection_mappings=identity_projection,
        ),
        DfdView(
            id="view-system",
            kind="system",
            element_refs=all_element_ids,
            projection_mappings=identity_projection,
        ),
    ]
    for process in [node for node in nodes if node.type == "process"]:
        related_flows = [
            flow for flow in dfd_flows
            if flow.source_id == process.id or flow.target_id == process.id
        ]
        related_nodes = {
            node_id for flow in related_flows for node_id in (flow.source_id, flow.target_id)
        }
        feature_refs = sorted({
            process.id,
            *related_nodes,
            *(flow.id for flow in related_flows),
            *(data_id for flow in related_flows for data_id in flow.data_object_ids),
        })
        views.append(DfdView(
            id=f"view-feature-{process.id}",
            kind="feature",
            parent_process_id=process.id,
            element_refs=feature_refs,
            projection_mappings={element_id: [element_id] for element_id in feature_refs},
            input_flow_ids=sorted(flow.id for flow in related_flows if flow.target_id == process.id),
            output_flow_ids=sorted(flow.id for flow in related_flows if flow.source_id == process.id),
            port_mappings={
                "input": sorted(flow.id for flow in related_flows if flow.target_id == process.id),
                "output": sorted(flow.id for flow in related_flows if flow.source_id == process.id),
            },
        ))

    questions = []
    unknown_nodes = [item.id for item in nodes if item.scope == "unknown" or item.ownership == "unknown" or item.exposure == "unknown"]
    if unknown_nodes:
        questions.append(DfdQuestion(
            id="question-classification",
            affected_refs=unknown_nodes,
            question="Which scope, ownership, and exposure apply to each DFD element?",
            reason="These dimensions are required to calculate trust boundaries without treating internal as trusted.",
            source_refs=_source_refs(project),
        ))
    if any(flow.interaction_kind == "unknown" for flow in dfd_flows):
        questions.append(DfdQuestion(
            id="question-interaction-kind",
            affected_refs=[flow.id for flow in dfd_flows if flow.interaction_kind == "unknown"],
            question="Are these flows requests, responses, events, reads, writes, or replication?",
            reason="The current artifact model does not reliably distinguish interaction direction/semantics.",
            source_refs=_source_refs(project),
        ))
    if canonical_operations and not operation_response_fields:
        questions.append(DfdQuestion(
            id="question-response-semantics",
            affected_refs=[flow.id for flow in dfd_flows if flow.interaction_kind == "request"],
            question="What response payloads and direction should be modeled for these API operations?",
            reason="The available API collection describes requests but does not document response data.",
            source_refs=_source_refs(project),
        ))

    stores = {
        store_id: DfdStoreMetadata(
            data_object_ids=sorted(data_ids),
            readers=sorted(store_readers.get(store_id, set())),
            writers=sorted(store_writers.get(store_id, set())),
        )
        for store_id, data_ids in store_data.items()
    }
    if any(value in (None, "unknown") for store in stores.values() for value in (store.retention, store.deletion, store.backup)):
        lifecycle_refs = sorted({
            *stores.keys(),
            *(data_id for store in stores.values() for data_id in store.data_object_ids),
        })
        questions.append(DfdQuestion(
            id="question-data-lifecycle",
            affected_refs=lifecycle_refs,
            question="What are the retention, deletion, backup, and vendor lifecycle rules for stored data?",
            reason="Data-store lifecycle metadata is unknown and must not be treated as safe or compliant.",
            source_refs=_source_refs(project),
        ))
    privacy_metadata_unknown = any(
        getattr(data_object, field) in (None, "", [])
        for data_object in data_objects
        for field in (
            "purpose", "recipients", "data_subjects", "identifiers", "sensitivity",
            "direct_identifiers", "indirect_identifiers", "linkability", "notice",
            "individual_control", "legal_basis",
        )
    )
    if data_objects and privacy_metadata_unknown:
        questions.append(DfdQuestion(
            id="question-data-privacy-context",
            affected_refs=[data_object.id for data_object in data_objects],
            question="What are the purpose, data subjects, direct/indirect identifiers, recipients, sensitivity, linkability, notice, individual-control expectations, and documented legal basis for these data objects?",
            reason="LINDDUN analysis needs documented privacy context and must not treat missing metadata as safe or compliant.",
            source_refs=_source_refs(project),
        ))
    model_assertions = [
        *_unknown_assertions(nodes, data_objects, dfd_flows, stores),
        *_conflict_assertions(project),
    ]
    assertions_by_object: dict[str, list[DfdAssertion]] = defaultdict(list)
    for assertion in model_assertions:
        assertions_by_object[assertion.object_id].append(assertion)
    nodes = [node.model_copy(update={"assertions": assertions_by_object.get(node.id, [])}) for node in nodes]
    data_objects = [item.model_copy(update={"assertions": assertions_by_object.get(item.id, [])}) for item in data_objects]
    stores = {
        store_id: store.model_copy(update={"assertions": assertions_by_object.get(store_id, [])})
        for store_id, store in stores.items()
    }
    model_evidence = _model_evidence(project, [
        *(ref for node in nodes for ref in node.evidence_refs),
        *(ref for data_object in data_objects for ref in data_object.evidence_refs),
        *(ref for flow in dfd_flows for ref in flow.evidence_refs),
        *(ref for boundary in dfd_boundaries for ref in boundary.evidence_refs),
        *(ref for store in stores.values() for ref in store.evidence_refs),
    ])
    if any(assertion.status == "conflicting" for assertion in model_assertions):
        questions.append(DfdQuestion(
            id="question-conflicting-sources",
            affected_refs=[],
            question="Which source or runtime observation resolves the conflicting artifact assertions?",
            reason="Conflicting source claims must remain visible and cannot be silently resolved by recency.",
            source_refs=_source_refs(project),
        ))
    initial_revision = max(int(previous.get("revision", 0)), 1) if isinstance(previous, dict) else 1
    model = DfdModel(
        id=(previous or {}).get("id") or _stable_id("dfd-model", project.get("project_id"), project.get("name")),
        project_id=str(project.get("project_id") or ""),
        schema_version=DFD_SCHEMA_VERSION,
        revision=initial_revision,
        layout_revision=int((previous or {}).get("layout_revision", 1)) if isinstance(previous, dict) else 1,
        human_edit_revision=int((previous or {}).get("human_edit_revision", 0)) if isinstance(previous, dict) else 0,
        source_semantic_hash=None,
        title=str(project.get("name") or "Threat Model"),
        scope_description=project.get("description"),
        source_refs=_source_refs(project),
        evidence=model_evidence,
        assertions=model_assertions,
        nodes=nodes,
        data_objects=data_objects,
        flows=dfd_flows,
        stores=stores,
        zones=zones,
        boundaries=dfd_boundaries,
        views=views,
        questions=questions,
    )
    recalculate_boundary_crossings(model)
    semantic_hash = model.semantic_hash
    model.source_semantic_hash = semantic_hash
    previous_hash = previous.get("semantic_hash") if isinstance(previous, dict) else None
    previous_revision = int(previous.get("revision", 0)) if isinstance(previous, dict) else 0
    revision = previous_revision + 1 if previous_hash and previous_hash != semantic_hash else max(previous_revision, 1)
    model.revision = revision
    return model


def validate_dfd_model(model: DfdModel) -> dict:
    """Return blocking graph errors separately from reviewable warnings."""
    errors: list[str] = []
    warnings: list[str] = []
    node_ids = [item.id for item in model.nodes]
    data_ids = [item.id for item in model.data_objects]
    zone_ids = [item.id for item in model.zones]
    boundary_ids = [item.id for item in model.boundaries]
    flow_ids = [item.id for item in model.flows]
    all_ids = node_ids + data_ids + zone_ids + boundary_ids + flow_ids

    def duplicates(values: list[str], label: str):
        seen = set()
        for value in values:
            if value in seen:
                errors.append(f"Duplicate {label} ID: {value}")
            seen.add(value)

    duplicates(node_ids, "node")
    duplicates(data_ids, "data object")
    duplicates(zone_ids, "zone")
    duplicates(boundary_ids, "boundary")
    duplicates(flow_ids, "flow")
    duplicates(all_ids, "model element")
    duplicates([item.id for item in model.views], "view")
    duplicates([item.id for item in model.questions], "question")
    for items, label in (
        (model.nodes, "node display"),
        (model.data_objects, "data object display"),
        (model.flows, "flow display"),
        (model.zones, "zone display"),
        (model.boundaries, "boundary display"),
    ):
        duplicates([item.display_id for item in items], label)

    node_by_id = {item.id: item for item in model.nodes}
    data_set = set(data_ids)
    zone_set = set(zone_ids)
    boundary_set = set(boundary_ids)
    flow_set = set(flow_ids)
    evidence_set = {item.id for item in model.evidence}

    def validate_evidence_refs(owner: str, refs: list[str]):
        for evidence_id in refs:
            if evidence_id not in evidence_set:
                errors.append(f"{owner} references missing evidence {evidence_id}")

    for node in model.nodes:
        validate_evidence_refs(f"Node {node.id}", node.evidence_refs)
        for assertion in node.assertions:
            validate_evidence_refs(f"Assertion {assertion.object_id}.{assertion.field_path}", assertion.evidence_refs)
    for data_object in model.data_objects:
        validate_evidence_refs(f"Data object {data_object.id}", data_object.evidence_refs)
        for assertion in data_object.assertions:
            validate_evidence_refs(f"Assertion {assertion.object_id}.{assertion.field_path}", assertion.evidence_refs)
    for flow in model.flows:
        validate_evidence_refs(f"Flow {flow.id}", flow.evidence_refs)
    for boundary in model.boundaries:
        validate_evidence_refs(f"Boundary {boundary.id}", boundary.evidence_refs)
        for assertion in boundary.assertions:
            validate_evidence_refs(f"Assertion {assertion.object_id}.{assertion.field_path}", assertion.evidence_refs)
    for store_id, store in model.stores.items():
        validate_evidence_refs(f"Store {store_id}", store.evidence_refs)
        for assertion in store.assertions:
            validate_evidence_refs(f"Assertion {assertion.object_id}.{assertion.field_path}", assertion.evidence_refs)
    for assertion in model.assertions:
        validate_evidence_refs(f"Assertion {assertion.object_id}.{assertion.field_path}", assertion.evidence_refs)

    for zone in model.zones:
        if zone.parent_zone_id and zone.parent_zone_id not in zone_set:
            errors.append(f"Zone {zone.id} references missing parent zone {zone.parent_zone_id}")
    for zone in model.zones:
        seen = set()
        current = zone
        while current.parent_zone_id:
            if current.id in seen:
                errors.append(f"Zone cycle detected at {current.id}")
                break
            seen.add(current.id)
            parent = next((item for item in model.zones if item.id == current.parent_zone_id), None)
            if not parent:
                break
            current = parent

    for node in model.nodes:
        for zone_id in node.zone_ids:
            if zone_id not in zone_set:
                errors.append(f"Node {node.id} references missing zone {zone_id}")
        if node.parent_process_id and node.parent_process_id not in node_by_id:
            errors.append(f"Node {node.id} references missing parent process {node.parent_process_id}")
        elif node.parent_process_id and node_by_id[node.parent_process_id].type != "process":
            errors.append(f"Node {node.id} parent {node.parent_process_id} is not a process")

    for flow in model.flows:
        if flow.source_id not in node_by_id or flow.target_id not in node_by_id:
            errors.append(f"Flow {flow.id} has a dangling source/target reference")
        for data_id in flow.data_object_ids:
            if data_id not in data_set:
                errors.append(f"Flow {flow.id} references missing data object {data_id}")
        for boundary_id in flow.boundary_crossings:
            if boundary_id not in boundary_set:
                errors.append(f"Flow {flow.id} references missing boundary {boundary_id}")
        if flow.source_id in node_by_id and flow.target_id in node_by_id:
            source_type = node_by_id[flow.source_id].type
            target_type = node_by_id[flow.target_id].type
            if source_type != "process" and target_type != "process":
                warnings.append(f"Flow {flow.id} does not touch a process and requires review")
            if not flow.data_object_ids:
                warnings.append(f"Flow {flow.id} has no data object label and requires review")
            if flow.name.casefold() in {str(flow.protocol or "").casefold(), "https", "http", "post", "get", "unknown data flow"}:
                warnings.append(f"Flow {flow.id} name is not a data label and requires review")
            if flow.crossing_status == "resolved" and (
                not node_by_id[flow.source_id].zone_ids or not node_by_id[flow.target_id].zone_ids
            ):
                errors.append(f"Flow {flow.id} is marked resolved but has incomplete zone membership")
        if flow.crossing_status == "unresolved":
            warnings.append(f"Flow {flow.id} has unresolved zone membership or boundary crossing")

    for boundary in model.boundaries:
        for zone_id in [*boundary.source_zone_ids, *boundary.target_zone_ids]:
            if zone_id not in zone_set:
                errors.append(f"Boundary {boundary.id} references missing zone {zone_id}")
        for flow_id in boundary.crossing_flow_ids:
            if flow_id not in flow_set:
                errors.append(f"Boundary {boundary.id} references missing flow {flow_id}")
            elif boundary.id not in next(flow for flow in model.flows if flow.id == flow_id).boundary_crossings:
                errors.append(f"Boundary {boundary.id} and flow {flow_id} have inconsistent crossing references")

    for store_id, store in model.stores.items():
        if store_id not in node_by_id or node_by_id[store_id].type != "data_store":
            errors.append(f"Store metadata {store_id} does not reference a data_store node")
        for data_id in store.data_object_ids:
            if data_id not in data_set:
                errors.append(f"Store {store_id} references missing data object {data_id}")
        for actor_id in [*store.readers, *store.writers]:
            if actor_id not in node_by_id:
                errors.append(f"Store {store_id} references missing reader/writer node {actor_id}")

    for view in model.views:
        for element_id in view.element_refs:
            if element_id not in set(all_ids):
                errors.append(f"View {view.id} references missing element {element_id}")
        if view.parent_process_id and view.parent_process_id not in node_by_id:
            errors.append(f"View {view.id} references missing parent process {view.parent_process_id}")
        elif view.parent_process_id and node_by_id[view.parent_process_id].type != "process":
            errors.append(f"View {view.id} parent {view.parent_process_id} is not a process")
        for projection_id, mapped_ids in view.projection_mappings.items():
            if projection_id not in set(all_ids):
                errors.append(f"View {view.id} projection references missing element {projection_id}")
            for mapped_id in mapped_ids:
                if mapped_id not in set(all_ids):
                    errors.append(f"View {view.id} projection maps to missing element {mapped_id}")
        if view.kind == "feature":
            if not view.parent_process_id or view.parent_process_id not in node_by_id:
                errors.append(f"Feature view {view.id} requires a valid parent process")
            elif node_by_id[view.parent_process_id].type != "process":
                errors.append(f"Feature view {view.id} parent {view.parent_process_id} is not a process")
            if view.parent_process_id and view.parent_process_id not in view.element_refs:
                errors.append(f"Feature view {view.id} must include its parent process in element_refs")
            for port_name, flow_ids in {
                "input": view.input_flow_ids,
                "output": view.output_flow_ids,
            }.items():
                for flow_id in flow_ids:
                    flow = next((item for item in model.flows if item.id == flow_id), None)
                    if not flow:
                        errors.append(f"Feature view {view.id} {port_name} port references missing flow {flow_id}")
                    elif (
                        (port_name == "input" and flow.target_id != view.parent_process_id)
                        or (port_name == "output" and flow.source_id != view.parent_process_id)
                    ):
                        errors.append(f"Feature view {view.id} {port_name} port flow {flow_id} does not connect to its parent")
                    elif flow_id not in view.element_refs:
                        errors.append(f"Feature view {view.id} port flow {flow_id} is missing from element_refs")
            if view.port_mappings.get("input", []) != view.input_flow_ids:
                errors.append(f"Feature view {view.id} input port mapping is inconsistent")
            if view.port_mappings.get("output", []) != view.output_flow_ids:
                errors.append(f"Feature view {view.id} output port mapping is inconsistent")

    for question in model.questions:
        for affected_id in question.affected_refs:
            if affected_id not in set(all_ids):
                errors.append(f"Question {question.id} references missing element {affected_id}")

    for flow in model.flows:
        for crossing_id in [*flow.crossing_origins.keys(), *flow.crossing_rationales.keys()]:
            if crossing_id not in boundary_set:
                errors.append(f"Flow {flow.id} crossing metadata references missing boundary {crossing_id}")
        for boundary_id in flow.boundary_crossings:
            boundary = next((item for item in model.boundaries if item.id == boundary_id), None)
            if boundary and boundary.transition_scope in {"logical", "mixed"}:
                if flow.crossing_origins.get(boundary_id) != "reviewer":
                    warnings.append(f"Flow {flow.id} logical boundary {boundary_id} requires reviewer confirmation")
                if not str(flow.crossing_rationales.get(boundary_id) or "").strip():
                    warnings.append(f"Flow {flow.id} logical boundary {boundary_id} has no reviewer rationale")

    for flow in model.flows:
        if len(flow.boundary_crossings) != len(set(flow.boundary_crossings)):
            errors.append(f"Flow {flow.id} contains duplicate boundary crossings")

    # Structural validity permits a partial draft. Report disconnected trust
    # zones separately so a green schema check cannot imply a usable topology.
    zone_members = {zone.id: set() for zone in model.zones}
    for node in model.nodes:
        for zone_id in node.zone_ids:
            if zone_id in zone_members:
                zone_members[zone_id].add(node.id)
    connected_zones: set[str] = set()
    connected_nodes: set[str] = set()
    semantic_issues: list[str] = []
    for flow in model.flows:
        if flow.source_id not in node_by_id or flow.target_id not in node_by_id:
            continue
        connected_nodes.update((flow.source_id, flow.target_id))
        source_zones = set(node_by_id[flow.source_id].zone_ids)
        target_zones = set(node_by_id[flow.target_id].zone_ids)
        if source_zones and target_zones and source_zones != target_zones:
            connected_zones.update(source_zones | target_zones)
            if not flow.boundary_crossings:
                semantic_issues.append(f"Flow {flow.display_id} crosses zones without a trust boundary")
    if len(zone_members) > 1:
        for zone in model.zones:
            if zone.id not in connected_zones:
                reason = "has no nodes" if not zone_members[zone.id] else "has no evidenced cross-zone flow"
                semantic_issues.append(f"Zone {zone.display_id} ({zone.name}) {reason}")
    isolated_nodes = [node.display_id for node in model.nodes if node.id not in connected_nodes]
    if isolated_nodes:
        semantic_issues.append(f"Nodes without evidenced flows: {', '.join(isolated_nodes)}")
    warnings.extend(semantic_issues)

    return {
        "valid": not errors,
        "semantic_ready": not errors and not semantic_issues,
        "semantic_issues": _unique(semantic_issues),
        "errors": _unique(errors),
        "warnings": _unique(warnings),
        "counts": {
            "nodes": len(model.nodes),
            "data_objects": len(model.data_objects),
            "flows": len(model.flows),
            "zones": len(model.zones),
            "boundaries": len(model.boundaries),
            "questions": len(model.questions),
        },
    }


def format_dfd_analysis_context(dfd_model: dict | None) -> str:
    """Format stable DFD IDs for analysis adapters without exposing raw artifacts."""
    if not isinstance(dfd_model, dict):
        return "No canonical DFD model is available. Keep affected references empty and explain the information gap."

    lines = [
        f"DFD model id: {dfd_model.get('id', 'unknown')}",
        f"DFD schema: {dfd_model.get('schema_version', 'unknown')} · revision: {dfd_model.get('revision', 'unknown')} · layout_revision: {dfd_model.get('layout_revision', 'unknown')}",
        "NODES:",
    ]
    for node in dfd_model.get("nodes", []) or []:
        lines.append(
            f"- {node.get('id')} ({node.get('display_id')}) · {node.get('type')} · {node.get('name')} · "
            f"scope={node.get('scope')} ownership={node.get('ownership')} exposure={node.get('exposure')}"
        )
    lines.append("DATA OBJECTS:")
    for item in dfd_model.get("data_objects", []) or []:
        lines.append(
            f"- {item.get('id')} ({item.get('display_id')}) · {item.get('name')} · "
            f"classification={item.get('classification') or 'unknown'} · sensitivity={item.get('sensitivity') or 'unknown'} · "
            f"purpose={item.get('purpose') or 'unknown'} · subjects={item.get('data_subjects') or 'unknown'} · "
            f"identifiers={item.get('identifiers') or 'unknown'} · direct_identifiers={item.get('direct_identifiers') or 'unknown'} · "
            f"indirect_identifiers={item.get('indirect_identifiers') or 'unknown'} · recipients={item.get('recipients') or 'unknown'} · "
            f"linkability={item.get('linkability') or 'unknown'} · notice={item.get('notice') or 'unknown'} · "
            f"individual_control={item.get('individual_control') or 'unknown'} · legal_basis={item.get('legal_basis') or 'unknown'} · "
            f"status={item.get('knowledge_status')} · evidence={item.get('evidence_refs') or []}"
        )
    lines.append("STORES AND DATA LIFECYCLE:")
    node_names = {
        str(node.get("id")): node.get("name")
        for node in dfd_model.get("nodes", []) or []
        if isinstance(node, dict) and node.get("id")
    }
    for store_id, store in (dfd_model.get("stores") or {}).items():
        if not isinstance(store, dict):
            continue
        lines.append(
            f"- {store_id} ({node_names.get(str(store_id), 'data store')}) · data={store.get('data_object_ids') or []} · "
            f"readers={store.get('readers') or []} · writers={store.get('writers') or []} · "
            f"retention={store.get('retention') or 'unknown'} · deletion={store.get('deletion') or 'unknown'} · "
            f"backup={store.get('backup') or 'unknown'} · controls={store.get('protection_controls') or []}"
        )
    lines.append("FLOWS:")
    for flow in dfd_model.get("flows", []) or []:
        lines.append(
            f"- {flow.get('id')} ({flow.get('display_id')}) · {flow.get('source_id')} → {flow.get('target_id')} · "
            f"data={flow.get('name')} · interaction={flow.get('interaction_kind')} · boundaries={flow.get('boundary_crossings') or []} · crossing={flow.get('crossing_status')}"
        )
    lines.append("BOUNDARIES:")
    for boundary in dfd_model.get("boundaries", []) or []:
        lines.append(
            f"- {boundary.get('id')} ({boundary.get('display_id')}) · {boundary.get('name')} · "
            f"types={boundary.get('types') or []} · flows={boundary.get('crossing_flow_ids') or []} · status={boundary.get('status')}"
        )
    if dfd_model.get("questions"):
        lines.append("OPEN QUESTIONS:")
        for question in dfd_model.get("questions", []) or []:
            lines.append(
                f"- {question.get('id')} · status={question.get('status')} · {question.get('question')} · "
                f"affected={question.get('affected_refs') or []} · source_refs={question.get('source_refs') or []} · "
                f"resolution={question.get('resolution') or 'unresolved'}"
            )
    return "\n".join(lines)
