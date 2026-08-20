from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from cyberkimi.core import DecisionKind, RiskTier, StrictModel, TrustProfile
from cyberkimi.tasking.models import ProposedAction, TaskSpec
from cyberkimi.tools.models import CapabilityProfile


class AuthorizationRequest(StrictModel):
    scope_token: str
    task: TaskSpec
    action: ProposedAction
    actor: str
    kill_switch_armed: bool = False


class PolicyDecision(StrictModel):
    decision_id: str
    pass_number: int = Field(ge=1)
    decision: DecisionKind
    reason_code: str
    message: str
    configuration_before: dict[str, Any] = Field(default_factory=dict)
    configuration_after: dict[str, Any] = Field(default_factory=dict)


class ExecutionGrantClaims(StrictModel):
    grant_id: str
    action_id: str
    engagement_id: str
    task_id: str
    asset_versioned_id: str
    tool_id: str
    tool_version: str
    profile_name: str
    risk_tier: RiskTier
    trust_profile: TrustProfile
    effects: frozenset[str]
    arguments_hash: str
    nonce: str
    issued_at: datetime
    expires_at: datetime


class AuthorizationOutcome(StrictModel):
    decision: PolicyDecision
    grant_token: str | None = Field(default=None, repr=False)
    grant: ExecutionGrantClaims | None = None
    profile: CapabilityProfile | None = None
    approval_id: str | None = None
