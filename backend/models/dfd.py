"""Canonical semantic DFD contract.

The report and canvas are projections of this model.  The contract intentionally
keeps unknown values explicit so extraction can produce a reviewable partial
model without turning missing information into facts.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, ConfigDict


KnowledgeStatus = Literal["documented", "inferred", "unknown", "conflicting"]
ImplementationStatus = Literal["planned", "implemented", "unknown"]
ScopeValue = Literal["in_scope", "external_dependency", "unknown"]
OwnershipValue = Literal["organization", "customer", "vendor", "shared", "unknown"]
ExposureValue = Literal["internet_facing", "private", "local", "unknown"]
NodeType = Literal["entity", "process", "data_store"]
BoundaryType = Literal["network", "identity", "privilege", "tenant", "organization", "unknown"]
InteractionKind = Literal["request", "response", "event", "read", "write", "replication", "unknown"]
ViewKind = Literal["context", "system", "feature"]
QuestionStatus = Literal["open", "answered", "deferred"]
BoundaryStatus = Literal["candidate", "confirmed", "rejected", "unresolved"]
CrossingOrigin = Literal["derived", "reviewer"]
TransitionScope = Literal["zone", "logical", "mixed", "unknown"]


class DfdBase(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DfdEvidenceRef(DfdBase):
    id: str
    document_id: str | None = None
    document_revision: int | None = None
    document_hash: str | None = None
    locator: str | None = None
    excerpt_redacted: str | None = None


class DfdAssertion(DfdBase):
    object_id: str
    field_path: str
    value: object | None = None
    status: KnowledgeStatus = "unknown"
    evidence_refs: list[str] = Field(default_factory=list)
    inference_reason: str | None = None
    review_status: str = "open"


class DfdDataObject(DfdBase):
    id: str
    display_id: str
    name: str = Field(min_length=1, max_length=240)
    fields: list[str] = Field(default_factory=list)
    classification: str | None = None
    data_subjects: list[str] = Field(default_factory=list)
    identifiers: list[str] = Field(default_factory=list)
    sensitivity: str | None = None
    purpose: str | None = None
    recipients: list[str] = Field(default_factory=list)
    transformation_refs: list[str] = Field(default_factory=list)
    lineage_refs: list[str] = Field(default_factory=list)
    knowledge_status: KnowledgeStatus = "unknown"
    evidence_refs: list[str] = Field(default_factory=list)


class DfdNode(DfdBase):
    id: str
    display_id: str
    type: NodeType
    name: str = Field(min_length=1, max_length=240)
    description: str | None = None
    scope: ScopeValue = "unknown"
    ownership: OwnershipValue = "unknown"
    operator_control_party: str | None = None
    exposure: ExposureValue = "unknown"
    zone_ids: list[str] = Field(default_factory=list)
    parent_process_id: str | None = None
    knowledge_status: KnowledgeStatus = "unknown"
    implementation_status: ImplementationStatus = "unknown"
    evidence_refs: list[str] = Field(default_factory=list)
    assertions: list[DfdAssertion] = Field(default_factory=list)
    process_metadata: "DfdProcessMetadata | None" = None


class DfdProcessMetadata(DfdBase):
    purpose: str | None = None
    execution_identity: str | None = None
    privileges: list[str] = Field(default_factory=list)
    input_flow_ids: list[str] = Field(default_factory=list)
    output_flow_ids: list[str] = Field(default_factory=list)
    transformations: list[str] = Field(default_factory=list)
    control_refs: list[str] = Field(default_factory=list)


class DfdFlow(DfdBase):
    id: str
    display_id: str
    source_id: str
    target_id: str
    name: str = Field(min_length=1, max_length=240)
    data_object_ids: list[str] = Field(default_factory=list)
    protocol: str | None = None
    interaction_kind: InteractionKind = "unknown"
    authn: str | None = None
    authz: str | None = None
    boundary_crossings: list[str] = Field(default_factory=list)
    crossing_rationales: dict[str, str] = Field(default_factory=dict)
    crossing_origins: dict[str, CrossingOrigin] = Field(default_factory=dict)
    crossing_status: Literal["resolved", "unresolved"] = "resolved"
    evidence_refs: list[str] = Field(default_factory=list)
    knowledge_status: KnowledgeStatus = "unknown"
    implementation_status: ImplementationStatus = "unknown"


class DfdStoreMetadata(DfdBase):
    data_object_ids: list[str] = Field(default_factory=list)
    readers: list[str] = Field(default_factory=list)
    writers: list[str] = Field(default_factory=list)
    retention: str | None = None
    deletion: str | None = None
    backup: str | None = None
    protection_controls: list[str] = Field(default_factory=list)


class DfdZone(DfdBase):
    id: str
    display_id: str
    name: str = Field(min_length=1, max_length=180)
    description: str | None = None
    parent_zone_id: str | None = None
    ownership_group_id: str | None = None
    trust_assumptions: list[str] = Field(default_factory=list)
    knowledge_status: KnowledgeStatus = "unknown"
    evidence_refs: list[str] = Field(default_factory=list)


class DfdBoundary(DfdBase):
    id: str
    display_id: str
    name: str = Field(min_length=1, max_length=180)
    types: list[BoundaryType] = Field(default_factory=list)
    rationale: str | None = None
    source_zone_ids: list[str] = Field(default_factory=list)
    target_zone_ids: list[str] = Field(default_factory=list)
    crossing_flow_ids: list[str] = Field(default_factory=list)
    transition_scope: TransitionScope = "unknown"
    controls: list[str] = Field(default_factory=list)
    assertions: list[DfdAssertion] = Field(default_factory=list)
    status: BoundaryStatus = "unresolved"
    derived: bool = True
    evidence_refs: list[str] = Field(default_factory=list)


class DfdView(DfdBase):
    id: str
    kind: ViewKind
    parent_process_id: str | None = None
    element_refs: list[str] = Field(default_factory=list)
    projection_mappings: dict[str, list[str]] = Field(default_factory=dict)
    input_flow_ids: list[str] = Field(default_factory=list)
    output_flow_ids: list[str] = Field(default_factory=list)
    port_mappings: dict[str, list[str]] = Field(default_factory=dict)
    positions: dict[str, dict[str, float]] = Field(default_factory=dict)
    collapsed_groups: list[str] = Field(default_factory=list)
    viewport: dict[str, float] = Field(default_factory=dict)


class DfdQuestion(DfdBase):
    id: str
    affected_refs: list[str] = Field(default_factory=list)
    question: str = Field(min_length=1, max_length=1000)
    reason: str = Field(min_length=1, max_length=1000)
    source_refs: list[str] = Field(default_factory=list)
    status: QuestionStatus = "open"
    resolution: str | None = None


class DfdModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    project_id: str
    schema_version: str = "dfd-v1"
    revision: int = Field(default=1, ge=1)
    layout_revision: int = Field(default=1, ge=1)
    human_edit_revision: int = Field(default=0, ge=0)
    source_semantic_hash: str | None = None
    semantic_hash: str | None = None
    title: str
    scope_description: str | None = None
    source_refs: list[str] = Field(default_factory=list)
    evidence: list[DfdEvidenceRef] = Field(default_factory=list)
    assertions: list[DfdAssertion] = Field(default_factory=list)
    nodes: list[DfdNode] = Field(default_factory=list)
    data_objects: list[DfdDataObject] = Field(default_factory=list)
    flows: list[DfdFlow] = Field(default_factory=list)
    stores: dict[str, DfdStoreMetadata] = Field(default_factory=dict)
    zones: list[DfdZone] = Field(default_factory=list)
    boundaries: list[DfdBoundary] = Field(default_factory=list)
    views: list[DfdView] = Field(default_factory=list)
    questions: list[DfdQuestion] = Field(default_factory=list)


# DfdNode intentionally keeps the process metadata optional because entity and
# data-store nodes do not need it. Resolve the forward reference once all
# domain classes are available.
DfdNode.model_rebuild()
