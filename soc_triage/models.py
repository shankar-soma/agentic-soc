"""Typed data contracts shared by every agent and the graph state."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Action(str, Enum):
    AUTO_REMEDIATE = "auto_remediate"
    ESCALATE_TO_ANALYST = "escalate_to_analyst"
    SUPPRESS_AS_FALSE_POSITIVE = "suppress_as_false_positive"


class RawAlert(BaseModel):
    model_config = {"extra": "allow"}

    event_id: str
    timestamp: datetime | None = None
    event_type: str | None = None
    source: str | None = None
    severity: str | None = None
    description: str = ""
    raw_log: str | None = None
    action: str | None = None
    alert_type: str | None = None
    category: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    flow_duration_us: int | None = None
    fwd_packets: int | None = None
    bwd_packets: int | None = None
    fwd_bytes: int | None = None
    bwd_bytes: int | None = None
    process_id: int | None = None
    parent_process: str | None = None
    cloud_service: str | None = None
    asset_criticality: str | None = None


class ClassifiedAlert(BaseModel):
    alert: RawAlert
    severity: Severity
    rationale: str
    confidence: float = Field(ge=0.0, le=1.0)
    backend: str = "unknown"


class RetrievedIncident(BaseModel):
    incident_id: str
    summary: str
    score: float = Field(description="Cosine similarity, higher is more similar")
    event_type: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Enrichment(BaseModel):
    incidents: list[RetrievedIncident]
    max_score: float
    weak_retrieval: bool


class Decision(BaseModel):
    action: Action
    reasoning: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    cited_incident_ids: list[str] = Field(default_factory=list)


class GuardrailResult(BaseModel):
    final_action: Action
    overridden: bool = False
    reasons: list[str] = Field(default_factory=list)
    requires_human_approval: bool = False


class TriageResult(BaseModel):
    alert_id: str
    classification: ClassifiedAlert
    enrichment: Enrichment
    proposed: Decision
    guardrail: GuardrailResult
    status: str = Field(description="simulated_remediation | pending_approval | suppressed | escalated")
