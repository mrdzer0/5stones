"""Strict contracts shared by AI-generated controls and test scenarios."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


CONTROL_STATUSES = ("Implemented", "Partial", "Missing", "Unknown")
PRIORITIES = ("Critical", "High", "Medium", "Low")
OWNERS = (
    "Backend", "DevOps", "QA", "Security", "Product", "Product/Legal",
    "QA/Security", "Engineering", "Operations",
)
REF_TYPES = {
    "data_flow", "process", "data_store", "entity", "boundary", "data_object",
}
REF_TYPE_ALIASES = {
    "flow": "data_flow",
    "external_entity": "entity",
    "external_system": "entity",
    "trust_boundary": "boundary",
}


class GenerationContractError(ValueError):
    """Raised when a stage envelope cannot be safely consumed."""

    def __init__(self, message: str, *, code: str = "contract_invalid", metadata: dict | None = None):
        super().__init__(message)
        self.code = code
        self.response_metadata = dict(metadata or {})


class CanonicalRef(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: str
    id: str = Field(min_length=1)

    @field_validator("type", mode="before")
    @classmethod
    def normalize_type(cls, value):
        normalized = str(value or "").strip().casefold().replace("-", "_")
        normalized = REF_TYPE_ALIASES.get(normalized, normalized)
        if normalized not in REF_TYPES:
            raise ValueError(f"unsupported canonical reference type: {value}")
        return normalized


class ControlGenerationItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str = Field(min_length=1)
    description: str = ""
    implementation_guidance: str = ""
    status: Literal["Implemented", "Partial", "Missing", "Unknown"] = "Unknown"
    implementation_status: Literal["Implemented", "Partial", "Missing", "Unknown"] = "Unknown"
    implementation_state: Literal["unknown", "planned", "documented", "runtime_verified"] = "unknown"
    implementation_plan: str = ""
    evidence: str = ""
    implementation_evidence_requested: list[str] = Field(default_factory=list)
    verification_evidence_refs: list[str] = Field(default_factory=list)
    implementation_evidence_refs: list[str] = Field(default_factory=list)
    runtime_verification_refs: list[str] = Field(default_factory=list)
    priority: Literal["Critical", "High", "Medium", "Low"] = "Medium"
    owner: Literal[
        "Backend", "DevOps", "QA", "Security", "Product", "Product/Legal",
        "QA/Security", "Engineering", "Operations",
    ] | None = None
    threat_ids: list[str] = Field(default_factory=list)
    target_refs: list[CanonicalRef] = Field(default_factory=list)
    location_ref: CanonicalRef | None = None


class ControlGenerationEnvelope(BaseModel):
    model_config = ConfigDict(extra="allow")

    controls: list[ControlGenerationItem]


class TestScenarioGenerationItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    scenario_name: str = Field(min_length=1)
    preconditions: str = Field(min_length=1)
    steps: list[str] = Field(min_length=1)
    expected_result: str = Field(min_length=1)
    evidence_needed: list[str] = Field(default_factory=list)
    related_control: str | None = None
    related_control_id: str | None = None
    priority: Literal["Critical", "High", "Medium", "Low"] = "Medium"
    owner: Literal[
        "Backend", "DevOps", "QA", "Security", "Product", "Product/Legal",
        "QA/Security", "Engineering", "Operations",
    ] | None = None
    threat_id: str = Field(min_length=1)
    target_refs: list[CanonicalRef] = Field(default_factory=list)
    analysis_revision: int | None = None
    dfd_revision: int | None = None
    dfd_semantic_hash: str | None = None
    execution_status: Literal["Not Run", "Passed", "Failed", "Blocked"] = "Not Run"
    actual_result: str = ""
    execution_evidence_refs: list[str] = Field(default_factory=list)
    applicability_status: Literal["applicable", "not_applicable", "blocked"] = "applicable"
    applicability_reason: str = ""

    @field_validator("steps", mode="after")
    @classmethod
    def require_nonempty_steps(cls, value):
        cleaned = [str(step).strip() for step in value if str(step).strip()]
        if not cleaned:
            raise ValueError("steps must contain at least one non-empty step")
        return cleaned


class TestScenarioGenerationEnvelope(BaseModel):
    model_config = ConfigDict(extra="allow")

    scenarios: list[TestScenarioGenerationItem]


def model_ids(dfd_model: dict | None) -> set[str]:
    if not isinstance(dfd_model, dict):
        return set()
    return {
        str(item.get("id"))
        for collection in ("nodes", "data_objects", "flows", "boundaries")
        for item in (dfd_model.get(collection) or [])
        if isinstance(item, dict) and item.get("id")
    }
