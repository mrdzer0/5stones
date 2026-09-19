from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional, List, Literal
from datetime import datetime
import uuid


# ── Enums & literals ────────────────────────────────────────────────────────

ConfidenceLevel = Literal["High", "Medium", "Low"]
RiskLevel = Literal["Critical", "High", "Medium", "Low"]
ThreatStatus = Literal["Open", "Needs Info", "Reviewed", "Accepted", "Mitigation Planned", "Mitigated", "Verified"]
DataClassification = Literal["Public", "Internal", "PII", "Financial", "Secret"]
Framework = Literal["STRIDE", "LINDDUN"]
StrideCategory = Literal["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"]
# Canonical labels follow the feature specification. Legacy labels remain
# accepted for loading older reports and are normalized for new AI output.
LinddunCategory = Literal[
    "Linking", "Identifying", "Non-repudiation", "Detecting", "Data Disclosure",
    "Unawareness & Unintervenability", "Non-compliance",
    "Linkability", "Identifiability", "Detectability", "Disclosure of Information", "Unawareness",
]
DataPolicy = Literal["local_only", "byok_allowed", "cloud_allowed"]
ControlStatus = Literal["Implemented", "Partial", "Missing", "Unknown"]
TestPriority = Literal["Critical", "High", "Medium", "Low"]
ExportFormat = Literal["markdown", "csv", "json"]


# ── Project ─────────────────────────────────────────────────────────────────

class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=200)
    description: Optional[str] = None
    environment: Optional[str] = None
    data_policy: DataPolicy = "byok_allowed"
    actors: List[str] = Field(default_factory=list)
    entry_points: List[str] = Field(default_factory=list)
    data_involved: List[str] = Field(default_factory=list)
    auth_method: Optional[str] = None
    external_systems: List[str] = Field(default_factory=list)
    critical_actions: List[str] = Field(default_factory=list)
    existing_controls: List[str] = Field(default_factory=list)
    # Optional evidence-backed architecture classifications. Unknown values
    # remain explicit in the canonical DFD until a reviewer supplies them.
    entity_metadata: dict = Field(default_factory=dict)
    zone_metadata: List[dict] = Field(default_factory=list)
    boundary_metadata: List[dict] = Field(default_factory=list)


class Project(ProjectCreate):
    project_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    artifacts: List[str] = Field(default_factory=list)
    analysis_status: str = "pending"
    risk_summary: dict = Field(default_factory=dict)


# ── Artifact ─────────────────────────────────────────────────────────────────

class ArtifactUpload(BaseModel):
    artifact_type: Literal["prd", "openapi", "postman", "markdown", "database_schema", "csv", "text", "har"]
    content: str
    filename: Optional[str] = None


class ParsedArtifact(BaseModel):
    artifact_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    artifact_type: str
    filename: Optional[str] = None
    extracted_actors: List[str] = Field(default_factory=list)
    extracted_components: List[str] = Field(default_factory=list)
    extracted_data_flows: List[dict] = Field(default_factory=list)
    extracted_endpoints: List[str] = Field(default_factory=list)
    extracted_data_fields: List[str] = Field(default_factory=list)
    raw_content: str = ""
    parsed_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


# ── Data Flow ────────────────────────────────────────────────────────────────

class DataFlow(BaseModel):
    flow_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str
    destination: str
    protocol: Optional[str] = "HTTPS"
    data: List[str] = Field(default_factory=list)
    trust_boundary: Optional[str] = None
    evidence: List[str] = Field(default_factory=list)
    evidence_refs: List[str] = Field(default_factory=list)
    evidence_type: Optional[Literal["direct", "derived", "inference"]] = None
    basis: Optional[str] = None
    confidence: ConfidenceLevel = "Low"
    status: Literal["Confirmed", "Candidate"] = "Candidate"


# ── Trust Boundary ────────────────────────────────────────────────────────────

class TrustBoundary(BaseModel):
    boundary_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str
    destination: str
    source_trust_level: str
    destination_trust_level: str
    boundary_label: str
    data_flows: List[str] = Field(default_factory=list)
    source_zone_id: Optional[str] = None
    destination_zone_id: Optional[str] = None
    risk_note: Optional[str] = None
    basis: Optional[str] = None
    confidence: ConfidenceLevel = "Low"
    status: Literal["Confirmed", "Candidate", "Rejected"] = "Candidate"
    evidence_refs: List[str] = Field(default_factory=list)
    crossing_flow_ids: List[str] = Field(default_factory=list)
    generation_method: Literal["deterministic", "manual"] = "deterministic"
    model_fingerprint: Optional[str] = None
    review_note: Optional[str] = None
    reviewed_at: Optional[str] = None
    review_stale: bool = False


# ── Threat ───────────────────────────────────────────────────────────────────

class Threat(BaseModel):
    threat_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    feature: Optional[str] = None
    component: Optional[str] = None
    source: Optional[str] = None
    destination: Optional[str] = None
    trust_boundary: Optional[str] = None
    trust_boundary_ids: List[str] = Field(default_factory=list)
    target_refs: List[dict] = Field(default_factory=list)
    mapping_status: Literal["mapped", "unmapped"] = "unmapped"
    asset: Optional[str] = None
    data_classification: Optional[DataClassification] = None
    framework: Framework
    threat_category: str
    threat_description: str
    abuse_case: Optional[str] = None
    recommended_control: Optional[str] = None
    test_scenario: Optional[str] = None
    expected_result: Optional[str] = None
    evidence: List[str] = Field(default_factory=list)
    evidence_refs: List[str] = Field(default_factory=list)
    evidence_type: Optional[Literal["direct", "context", "inference"]] = None
    evidence_source: Optional[str] = None
    evidence_locator: Optional[str] = None
    evidence_snippet: Optional[str] = None
    assumption: Optional[str] = None
    missing_info: Optional[str] = None
    confidence_reason: Optional[str] = None
    needs_human_review: bool = True
    review_notes: Optional[str] = None
    reviewed_at: Optional[str] = None
    fingerprint: Optional[str] = None
    confidence: ConfidenceLevel = "Medium"
    risk_level: RiskLevel = "Medium"
    owner: Optional[str] = None
    status: ThreatStatus = "Open"
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


# ── Control ───────────────────────────────────────────────────────────────────

class Control(BaseModel):
    control_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    implementation_guidance: Optional[str] = None
    status: ControlStatus = "Unknown"
    implementation_status: ControlStatus = "Unknown"
    evidence: Optional[str] = None
    verification_evidence_refs: List[str] = Field(default_factory=list)
    checklist_items: List[str] = Field(default_factory=list)
    affected_components: List[str] = Field(default_factory=list)
    verification_method: Optional[str] = None
    priority: TestPriority = "Medium"
    review_status: Literal["Open", "In Progress", "Implemented", "Verified", "Accepted Risk"] = "Open"
    owner: Optional[str] = None
    threat_ids: List[str] = Field(default_factory=list)
    target_refs: List[dict] = Field(default_factory=list)
    location_ref: Optional[dict] = None


# ── Test Scenario ─────────────────────────────────────────────────────────────

class TestScenario(BaseModel):
    test_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scenario_name: str
    preconditions: str
    steps: List[str] = Field(default_factory=list)
    expected_result: str
    evidence_needed: List[str] = Field(default_factory=list)
    related_control: Optional[str] = None
    priority: TestPriority = "Medium"
    owner: Optional[str] = None
    threat_id: Optional[str] = None
    target_refs: List[dict] = Field(default_factory=list)


# ── Assumption ────────────────────────────────────────────────────────────────

class Assumption(BaseModel):
    assumption_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    area: str
    assumption: str
    confidence: ConfidenceLevel = "Medium"
    target_refs: List[dict] = Field(default_factory=list)


# ── Missing Info ──────────────────────────────────────────────────────────────

class MissingInfo(BaseModel):
    missing_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    area: str
    question: str
    why_it_matters: str
    priority: TestPriority = "Medium"
    target_team: Optional[str] = None
    status: Literal["Open", "Answered", "Deferred"] = "Open"
    question_to_ask: Optional[str] = None


# ── Full Report ───────────────────────────────────────────────────────────────

class ThreatModelReport(BaseModel):
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    project_id: str
    project_name: str
    generated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    data_flows: List[DataFlow] = Field(default_factory=list)
    trust_boundaries: List[TrustBoundary] = Field(default_factory=list)
    threats: List[Threat] = Field(default_factory=list)
    controls: List[Control] = Field(default_factory=list)
    test_scenarios: List[TestScenario] = Field(default_factory=list)
    assumptions: List[Assumption] = Field(default_factory=list)
    missing_info: List[MissingInfo] = Field(default_factory=list)
    completeness: dict = Field(default_factory=dict)
    risk_summary: dict = Field(default_factory=dict)


# ── Settings ──────────────────────────────────────────────────────────────────

class LLMProviderConfig(BaseModel):
    provider_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    provider_type: Literal["openai", "azure", "openrouter", "local", "custom"]
    base_url: str
    model: str
    api_key_masked: Optional[str] = None
    max_tokens: int = 4096
    is_active: bool = False
    is_local: bool = False


class AppSettings(BaseModel):
    active_provider_id: Optional[str] = None
    providers: List[dict] = Field(default_factory=list)
    local_llm_endpoint: Optional[str] = None
    local_llm_model: Optional[str] = None
    default_data_policy: DataPolicy = "byok_allowed"
    mcp_servers: List[dict] = Field(default_factory=list)


# ── API Response ──────────────────────────────────────────────────────────────

class APIResponse(BaseModel):
    success: bool
    message: str
    data: Optional[dict] = None


class AnalysisRequest(BaseModel):
    project_id: str
    analysis_types: List[Literal["trust_boundary", "stride", "linddun", "controls", "tests", "missing_info", "assumptions"]] = [
        "trust_boundary", "stride", "linddun", "controls", "tests", "missing_info", "assumptions"
    ]
    additional_context: Optional[str] = None
