from __future__ import annotations

from typing import Any

from pydantic import Field, model_validator

from cyberkimi.core import RiskTier, StrictModel, TaskMode, new_id


class BudgetCost(StrictModel):
    model_turns: int = Field(default=0, ge=0)
    tool_calls: int = Field(default=1, ge=0)
    runtime_seconds: int = Field(default=0, ge=0)
    artifact_bytes: int = Field(default=0, ge=0)
    retries: int = Field(default=0, ge=0)


class TaskSpec(StrictModel):
    task_id: str = Field(default_factory=lambda: new_id("TASK"))
    engagement_id: str
    mode: TaskMode
    objective: str = Field(min_length=1, max_length=4000)
    assets: tuple[str, ...]
    risk_tier: RiskTier = RiskTier.R1_READ_ONLY
    allowed_effects: frozenset[str]
    prohibited_effects: frozenset[str] = frozenset()
    success_criteria: tuple[str, ...] = ()
    required_evidence: tuple[str, ...] = ()
    parent_task_id: str | None = None
    root_task_id: str | None = None

    @model_validator(mode="after")
    def validate_effects(self) -> "TaskSpec":
        overlap = self.allowed_effects & self.prohibited_effects
        if overlap:
            raise ValueError(f"effects cannot be both allowed and prohibited: {sorted(overlap)}")
        if not self.assets:
            raise ValueError("task must reference at least one asset")
        return self


class ProposedAction(StrictModel):
    action_id: str = Field(default_factory=lambda: new_id("ACTION"))
    task_id: str
    action_template: str
    target_asset_id: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    purpose: str = Field(min_length=1, max_length=2000)
    requested_profile: str | None = None
    estimated_cost: BudgetCost = BudgetCost()
