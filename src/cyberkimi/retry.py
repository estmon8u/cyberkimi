from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .domain import TaskState
from .store import canonical_json


class NonResponseCategory(StrEnum):
    HTTP_ERROR = "HTTP_ERROR"
    RATE_LIMIT = "RATE_LIMIT"
    TOOL_SCHEMA_ERROR = "TOOL_SCHEMA_ERROR"
    TOOL_CALL_ID_ERROR = "TOOL_CALL_ID_ERROR"
    CONTEXT_FORMAT_ERROR = "CONTEXT_FORMAT_ERROR"
    TIMEOUT = "TIMEOUT"
    MISSING_AUTH_CONTEXT = "MISSING_AUTH_CONTEXT"
    AMBIGUOUS_TARGET = "AMBIGUOUS_TARGET"
    ACTIVE_ACTION_REQUIRES_ENV = "ACTIVE_ACTION_REQUIRES_ENV"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    CONTEXT_TOO_BROAD = "CONTEXT_TOO_BROAD"
    MODEL_REFUSAL = "MODEL_REFUSAL"
    PROVIDER_POLICY = "PROVIDER_POLICY"
    UNKNOWN = "UNKNOWN"


class RetryStrategy(StrEnum):
    TECHNICAL_RETRY = "technical_retry"
    AUTHORIZATION_CLARIFICATION = "authorization_clarification"
    ASSET_CANONICALIZATION = "asset_canonicalization"
    ENVIRONMENT_CONFIGURATION = "environment_configuration"
    APPROVAL_RESOLUTION = "approval_resolution"
    CONTEXT_NARROWING = "context_narrowing"
    TERMINAL_QUESTION = "terminal_question"
    SESSION_DECOMPOSITION = "session_decomposition"
    DETERMINISTIC_INVESTIGATION = "deterministic_investigation"
    EXHAUSTED = "exhausted"


@dataclass(frozen=True)
class RetryOutcome:
    retry: bool
    strategy: RetryStrategy
    task_state: TaskState
    fresh_session: bool
    include_original_triggering_context: bool
    reason: str


@dataclass(frozen=True)
class NonResponseEvent:
    category: NonResponseCategory
    subtype: str
    status_code: int | None = None
    provider_code: str | None = None
    body: str = ""


class RetryManager:
    """Bounded recovery without unbounded or disguise-based rephrasing.

    Provider-boundary passes progressively ask narrower, independently valid
    questions or fall back to deterministic evidence collection. The manager
    never changes scope, target authorization, effects, or execution policy.
    """

    PROVIDER_ESCALATION: tuple[RetryStrategy, ...] = (
        RetryStrategy.TECHNICAL_RETRY,
        RetryStrategy.CONTEXT_NARROWING,
        RetryStrategy.TERMINAL_QUESTION,
        RetryStrategy.SESSION_DECOMPOSITION,
        RetryStrategy.DETERMINISTIC_INVESTIGATION,
    )

    def __init__(self, maximum_attempts: int) -> None:
        if maximum_attempts < 0:
            raise ValueError("maximum_attempts cannot be negative")
        self.maximum_attempts = maximum_attempts

    @staticmethod
    def classify(
        *,
        status_code: int | None,
        provider_code: str | None,
        body: str,
    ) -> NonResponseEvent:
        lowered = body.lower()
        if status_code == 429:
            category = NonResponseCategory.RATE_LIMIT
        elif status_code is not None and status_code >= 500:
            category = NonResponseCategory.HTTP_ERROR
        elif "tool_call_id" in lowered:
            category = NonResponseCategory.TOOL_CALL_ID_ERROR
        elif "json schema" in lowered or "schema" in lowered and "invalid" in lowered:
            category = NonResponseCategory.TOOL_SCHEMA_ERROR
        elif "context length" in lowered or "too many tokens" in lowered:
            category = NonResponseCategory.CONTEXT_TOO_BROAD
        elif "timeout" in lowered:
            category = NonResponseCategory.TIMEOUT
        elif provider_code and provider_code.upper() in {"CONTENT_POLICY", "SAFETY", "POLICY"}:
            category = NonResponseCategory.PROVIDER_POLICY
        elif re.search(r"\b(cannot|can't|unable to) (help|assist|comply)\b", lowered):
            category = NonResponseCategory.MODEL_REFUSAL
        elif "authorization" in lowered and "missing" in lowered:
            category = NonResponseCategory.MISSING_AUTH_CONTEXT
        elif "target" in lowered and ("ambiguous" in lowered or "unknown" in lowered):
            category = NonResponseCategory.AMBIGUOUS_TARGET
        else:
            category = NonResponseCategory.UNKNOWN
        return NonResponseEvent(
            category=category,
            subtype=provider_code or "UNSPECIFIED",
            status_code=status_code,
            provider_code=provider_code,
            body=body,
        )

    def next_outcome(self, event: NonResponseEvent, *, attempt: int) -> RetryOutcome:
        if attempt >= self.maximum_attempts:
            return RetryOutcome(
                retry=False,
                strategy=RetryStrategy.EXHAUSTED,
                task_state=TaskState.PROVIDER_BOUNDARY_EXHAUSTED
                if event.category == NonResponseCategory.PROVIDER_POLICY
                else TaskState.FAILED,
                fresh_session=False,
                include_original_triggering_context=False,
                reason="configured retry budget exhausted",
            )
        if event.category in {
            NonResponseCategory.HTTP_ERROR,
            NonResponseCategory.RATE_LIMIT,
            NonResponseCategory.TOOL_SCHEMA_ERROR,
            NonResponseCategory.TOOL_CALL_ID_ERROR,
            NonResponseCategory.CONTEXT_FORMAT_ERROR,
            NonResponseCategory.TIMEOUT,
        }:
            return RetryOutcome(
                retry=True,
                strategy=RetryStrategy.TECHNICAL_RETRY,
                task_state=TaskState.READY,
                fresh_session=False,
                include_original_triggering_context=True,
                reason="retry exact semantic request after repairing technical failure",
            )
        if event.category == NonResponseCategory.MISSING_AUTH_CONTEXT:
            return RetryOutcome(
                retry=True,
                strategy=RetryStrategy.AUTHORIZATION_CLARIFICATION,
                task_state=TaskState.NEEDS_AUTHORIZATION,
                fresh_session=True,
                include_original_triggering_context=True,
                reason="attach signed engagement summary without changing requested scope",
            )
        if event.category == NonResponseCategory.AMBIGUOUS_TARGET:
            return RetryOutcome(
                retry=True,
                strategy=RetryStrategy.ASSET_CANONICALIZATION,
                task_state=TaskState.NEEDS_SCOPE,
                fresh_session=True,
                include_original_triggering_context=True,
                reason="replace ambiguous target text with registered asset identifiers",
            )
        if event.category == NonResponseCategory.APPROVAL_REQUIRED:
            return RetryOutcome(
                retry=True,
                strategy=RetryStrategy.APPROVAL_RESOLUTION,
                task_state=TaskState.HUMAN_APPROVAL_REQUIRED,
                fresh_session=False,
                include_original_triggering_context=True,
                reason="resolve approval through policy engine",
            )
        if event.category == NonResponseCategory.PROVIDER_POLICY:
            index = min(attempt, len(self.PROVIDER_ESCALATION) - 1)
            strategy = self.PROVIDER_ESCALATION[index]
            return RetryOutcome(
                retry=True,
                strategy=strategy,
                task_state=TaskState.PROVIDER_BOUNDARY,
                fresh_session=index >= 1,
                include_original_triggering_context=index < 2,
                reason=(
                    "bounded provider-boundary recovery; later passes receive only a newly "
                    "compiled, independently valid sub-question and normalized evidence"
                ),
            )
        return RetryOutcome(
            retry=True,
            strategy=RetryStrategy.CONTEXT_NARROWING,
            task_state=TaskState.READY,
            fresh_session=True,
            include_original_triggering_context=True,
            reason="narrow task to its minimum evidence question",
        )

    @staticmethod
    def fingerprint(payload: dict[str, Any]) -> str:
        return hashlib.sha256(canonical_json(payload).encode()).hexdigest()
