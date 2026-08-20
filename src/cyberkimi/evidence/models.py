from __future__ import annotations

from typing import Any

from pydantic import Field

from cyberkimi.core import DataClassification, StrictModel, new_id


class ArtifactRecord(StrictModel):
    artifact_id: str = Field(default_factory=lambda: new_id("ARTIFACT"))
    sha256: str
    media_type: str
    byte_count: int = Field(ge=0)
    relative_path: str
    source_run_id: str | None = None


class EvidenceRecord(StrictModel):
    evidence_id: str = Field(default_factory=lambda: new_id("EVIDENCE"))
    task_id: str
    asset_versioned_id: str
    evidence_type: str
    evidence_class: str
    summary: str
    payload: dict[str, Any] = Field(default_factory=dict)
    artifact_id: str | None = None
    provenance: dict[str, Any] = Field(default_factory=dict)


class HandlerOutput(StrictModel):
    media_type: str = "application/json"
    raw: bytes
    normalized: dict[str, Any]
    evidence_type: str
    evidence_class: str
    summary: str


class ModelEvidence(StrictModel):
    classification: DataClassification
    content: dict[str, Any]
    redactions: int = Field(ge=0)
    restricted_summary: bool = False
