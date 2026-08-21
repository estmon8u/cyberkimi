"""Bounded retry classification and provider-boundary handling."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import TypeVar

import httpx
from pydantic import Field

from cyberkimi.models import StrictModel

T = TypeVar("T")


class NonResponseCategory(StrEnum):
    HTTP_TRANSIENT = "HTTP_TRANSIENT"
    RATE_LIMIT = "RATE_LIMIT"
    TIMEOUT = "TIMEOUT"
    CONNECTION_RESET = "CONNECTION_RESET"
    TOOL_CALL_ID_MISMATCH = "TOOL_CALL_ID_MISMATCH"
    MESSAGE_HISTORY_ERROR = "MESSAGE_HISTORY_ERROR"
    TOOL_SCHEMA_ERROR = "TOOL_SCHEMA_ERROR"
    STRUCTURED_OUTPUT_INVALID = "STRUCTURED_OUTPUT_INVALID"
    CONTEXT_LIMIT = "CONTEXT_LIMIT"
    CONTEXT_TOO_BROAD = "CONTEXT_TOO_BROAD"
    MISSING_SCOPE = "MISSING_SCOPE"
    MISSING_APPROVAL = "MISSING_APPROVAL"
    DATA_POLICY_BLOCK = "DATA_POLICY_BLOCK"
    MODEL_REFUSAL = "MODEL_REFUSAL"
    PROVIDER_POLICY = "PROVIDER_POLICY"
    NO_PROGRESS = "NO_PROGRESS"
    PERMANENT = "PERMANENT"


class NonResponseEvent(StrictModel):
    event_id: str
    task_id: str
    subtask_id: str | None = None
    stage: str
    category: NonResponseCategory
    retryable: bool
    retry_count: int = Field(ge=0)
    prompt_fingerprint: str
    response_fingerprint: str
    model: str
    provider: str
    resulting_state: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ProviderBoundaryError(RuntimeError):
    """A semantic or provider-policy boundary that must not be reframed or retried."""

    def __init__(self, message: str, category: NonResponseCategory):
        super().__init__(message)
        self.category = category


class StructuredOutputError(RuntimeError):
    """The provider returned data that does not satisfy the requested schema."""


@dataclass(frozen=True)
class RetryLimits:
    transport_retries: int = 3
    schema_retries: int = 1
    history_retries: int = 1
    context_recompositions: int = 1
    provider_policy_retries: int = 0
    repeated_action_signature: int = 2
    no_progress_rounds: int = 2


@dataclass
class RetryState:
    transport: int = 0
    schema: int = 0
    history: int = 0
    context: int = 0


def keyed_fingerprint(key: bytes, value: str) -> str:
    digest = hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def classify_exception(exc: BaseException) -> NonResponseCategory:
    if isinstance(exc, ProviderBoundaryError):
        return exc.category
    if isinstance(exc, StructuredOutputError):
        return NonResponseCategory.STRUCTURED_OUTPUT_INVALID
    if isinstance(exc, (httpx.TimeoutException, asyncio.TimeoutError, TimeoutError)):
        return NonResponseCategory.TIMEOUT
    if isinstance(exc, (httpx.ConnectError, httpx.ReadError, ConnectionResetError)):
        return NonResponseCategory.CONNECTION_RESET
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status == 429:
            return NonResponseCategory.RATE_LIMIT
        if status in {408, 425, 500, 502, 503, 504}:
            return NonResponseCategory.HTTP_TRANSIENT
        return NonResponseCategory.PERMANENT
    return NonResponseCategory.PERMANENT


def provider_error_category(status_code: int, error: object) -> NonResponseCategory:
    """Classify one provider error without attempting semantic workarounds."""

    text = str(error).lower()
    if status_code == 429:
        return NonResponseCategory.RATE_LIMIT
    if status_code in {408, 425, 500, 502, 503, 504}:
        return NonResponseCategory.HTTP_TRANSIENT
    if "context" in text and any(token in text for token in ("length", "limit", "window")):
        return NonResponseCategory.CONTEXT_LIMIT
    if any(token in text for token in ("policy", "safety", "not allowed", "prohibited")):
        return NonResponseCategory.PROVIDER_POLICY
    if any(token in text for token in ("refus", "cannot assist", "can't assist")):
        return NonResponseCategory.MODEL_REFUSAL
    return NonResponseCategory.PERMANENT


class RetryController:
    """Retry only transport-equivalent work and one strict schema repair."""

    def __init__(self, limits: RetryLimits = RetryLimits(), *, base_delay: float = 0.25):
        self.limits = limits
        self.base_delay = base_delay

    async def run(
        self,
        operation: Callable[[], Awaitable[T]],
        *,
        idempotent: bool = True,
        on_retry: Callable[[NonResponseCategory, int], Awaitable[None] | None] | None = None,
    ) -> T:
        state = RetryState()
        while True:
            try:
                return await operation()
            except BaseException as exc:
                category = classify_exception(exc)
                retry_number: int | None = None
                if category in {
                    NonResponseCategory.HTTP_TRANSIENT,
                    NonResponseCategory.RATE_LIMIT,
                    NonResponseCategory.CONNECTION_RESET,
                }:
                    if state.transport < self.limits.transport_retries:
                        state.transport += 1
                        retry_number = state.transport
                elif category is NonResponseCategory.TIMEOUT and idempotent:
                    if state.transport < self.limits.transport_retries:
                        state.transport += 1
                        retry_number = state.transport
                elif category is NonResponseCategory.STRUCTURED_OUTPUT_INVALID:
                    if state.schema < self.limits.schema_retries:
                        state.schema += 1
                        retry_number = state.schema
                if retry_number is None:
                    raise
                if on_retry is not None:
                    maybe_awaitable = on_retry(category, retry_number)
                    if maybe_awaitable is not None:
                        await maybe_awaitable
                delay = self.base_delay * (2 ** (retry_number - 1))
                delay += random.uniform(0, max(delay * 0.25, 0.001))
                await asyncio.sleep(delay)
