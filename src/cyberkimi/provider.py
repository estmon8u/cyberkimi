"""Kimi K3 structured-output and bounded tool-loop provider adapter."""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Protocol, TypeVar

import httpx
from pydantic import BaseModel, ValidationError
from sqlalchemy import insert

from cyberkimi.audit import AuditStore
from cyberkimi.canonical import canonical_text, sha256_digest
from cyberkimi.errors import DataPolicyError
from cyberkimi.ids import new_id
from cyberkimi.models import (
    Engagement,
    ModelCallRecord,
    ProviderOutcome,
    StrictModel,
    TaskSpec,
    ToolManifest,
)
from cyberkimi.persistence import Database, model_calls
from cyberkimi.retry import (
    NonResponseCategory,
    ProviderBoundaryError,
    RetryController,
    StructuredOutputError,
    keyed_fingerprint,
    provider_error_category,
)

OutputT = TypeVar("OutputT", bound=BaseModel)
ToolExecutor = Callable[[str, dict[str, Any], str], Awaitable[Mapping[str, Any]]]


class ProviderUsage(StrictModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cached_tokens: int = 0


class AssistantMessage(StrictModel):
    role: Literal["assistant"] = "assistant"
    content: str | None = None
    reasoning_content: str | None = None
    tool_calls: tuple[dict[str, Any], ...] = ()

    def to_api(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"role": "assistant", "content": self.content or ""}
        if self.reasoning_content is not None:
            payload["reasoning_content"] = self.reasoning_content
        if self.tool_calls:
            payload["tool_calls"] = list(self.tool_calls)
        return payload


class StructuredResult(StrictModel):
    output: dict[str, Any]
    assistant_message: AssistantMessage
    usage: ProviderUsage
    response_id: str
    model: str
    finish_reason: str
    history: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class StructuredCall:
    engagement: Engagement
    task: TaskSpec
    role: Literal["director", "worker", "verifier", "reporter"]
    output_model: type[OutputT]
    messages: Sequence[Mapping[str, Any]]
    reasoning_effort: Literal["low", "high", "max"] = "high"
    prompt_version: str = "cyberkimi-k3/v1"
    schema_version: str = "v1"
    tools: Sequence[ToolManifest] = ()
    tool_choice: Literal["auto", "none", "required"] = "none"
    max_completion_tokens: int = 8192
    session_id: str = field(default_factory=lambda: new_id("SESSION"))


@dataclass(frozen=True)
class ToolLoopRequest:
    call: StructuredCall
    execute_tool: ToolExecutor
    max_turns: int = 12


class ReasoningProvider(Protocol):
    async def structured_call(self, request: StructuredCall) -> StructuredResult: ...

    async def tool_loop(self, request: ToolLoopRequest) -> StructuredResult: ...


def _strict_schema(model_type: type[BaseModel]) -> dict[str, Any]:
    schema = model_type.model_json_schema()
    return {
        "type": "json_schema",
        "json_schema": {
            "name": model_type.__name__,
            "strict": True,
            "schema": schema,
        },
    }


def _tool_definition(manifest: ToolManifest) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": manifest.api_name,
            "description": manifest.description,
            "parameters": manifest.arguments_schema,
            "strict": True,
        },
    }


def _complete_message(raw: Mapping[str, Any]) -> AssistantMessage:
    calls_raw = raw.get("tool_calls") or []
    calls: list[dict[str, Any]] = []
    if isinstance(calls_raw, list):
        for call in calls_raw:
            if isinstance(call, dict):
                calls.append(dict(call))
    return AssistantMessage(
        content=raw.get("content") if isinstance(raw.get("content"), str) else None,
        reasoning_content=(
            raw.get("reasoning_content")
            if isinstance(raw.get("reasoning_content"), str)
            else None
        ),
        tool_calls=tuple(calls),
    )


class MoonshotProvider:
    """Direct Moonshot chat-completions adapter with no semantic refusal retries."""

    provider_name = "moonshot"

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model: str,
        database: Database,
        audit: AuditStore,
        fingerprint_key_path: Path,
        timeout_seconds: float = 120.0,
        client: httpx.AsyncClient | None = None,
    ):
        if not api_key:
            raise ValueError("Moonshot API key is required")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.database = database
        self.audit = audit
        self.fingerprint_key_path = fingerprint_key_path
        self.timeout_seconds = timeout_seconds
        self._client = client
        self.retry = RetryController()

    def _fingerprint_key(self) -> bytes:
        self.fingerprint_key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self.fingerprint_key_path.exists():
            import os

            temporary = self.fingerprint_key_path.with_suffix(".tmp")
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(descriptor, os.urandom(32))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, self.fingerprint_key_path)
            os.chmod(self.fingerprint_key_path, 0o600)
        return self.fingerprint_key_path.read_bytes()

    def _validate_data_policy(self, engagement: Engagement) -> None:
        if not engagement.data_policy.permits_provider(self.provider_name):
            raise DataPolicyError("engagement data policy does not permit Moonshot model exposure")

    async def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        owned = self._client is None
        client = self._client or httpx.AsyncClient(timeout=self.timeout_seconds)
        try:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            if response.status_code >= 400:
                try:
                    error_payload: object = response.json()
                except ValueError:
                    error_payload = response.text
                category = provider_error_category(response.status_code, error_payload)
                if category in {
                    NonResponseCategory.PROVIDER_POLICY,
                    NonResponseCategory.MODEL_REFUSAL,
                }:
                    raise ProviderBoundaryError(str(error_payload), category)
                response.raise_for_status()
            parsed = response.json()
            if not isinstance(parsed, dict):
                raise StructuredOutputError("provider response is not a JSON object")
            return parsed
        finally:
            if owned:
                await client.aclose()

    def _record_call(
        self,
        request: StructuredCall,
        *,
        payload: dict[str, Any],
        response: dict[str, Any] | None,
        started: float,
        outcome: ProviderOutcome,
        tool_count: int,
    ) -> None:
        usage = response.get("usage", {}) if response else {}
        if not isinstance(usage, dict):
            usage = {}
        key = self._fingerprint_key()
        record = ModelCallRecord(
            provider=self.provider_name,
            model=self.model,
            role=request.role,
            reasoning_effort=request.reasoning_effort,
            task_id=request.task.task_id,
            subtask_id=None,
            prompt_version=request.prompt_version,
            schema_version=request.schema_version,
            prompt_fingerprint=keyed_fingerprint(key, canonical_text(payload)),
            response_fingerprint=keyed_fingerprint(key, canonical_text(response or {})),
            input_tokens=int(usage.get("prompt_tokens", 0) or 0),
            output_tokens=int(usage.get("completion_tokens", 0) or 0),
            tool_count_exposed=tool_count,
            latency_ms=max(0, int((time.monotonic() - started) * 1000)),
            result=outcome,
            session_id=request.session_id,
        )
        call_id = new_id("MCALL")
        with self.database.transaction() as connection:
            connection.execute(
                insert(model_calls).values(
                    model_call_id=call_id,
                    task_id=request.task.task_id,
                    result=outcome.value,
                    record_json=record.model_dump_json(),
                    created_at=datetime.now(timezone.utc),
                )
            )
            self.audit.append(
                request.engagement.engagement_id,
                "model.call",
                {
                    "model_call_id": call_id,
                    "task_id": request.task.task_id,
                    "provider": self.provider_name,
                    "model": self.model,
                    "role": request.role,
                    "result": outcome.value,
                    "prompt_fingerprint": record.prompt_fingerprint,
                    "response_fingerprint": record.response_fingerprint,
                    "tool_count_exposed": tool_count,
                },
                connection=connection,
            )

    def _payload(self, request: StructuredCall, messages: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        tools = [_tool_definition(item) for item in request.tools]
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [dict(item) for item in messages],
            "reasoning_effort": request.reasoning_effort,
            "response_format": _strict_schema(request.output_model),
            "max_completion_tokens": request.max_completion_tokens,
            "prompt_cache_key": request.session_id,
            "safety_identifier": sha256_digest(request.engagement.owner_id),
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = request.tool_choice
        return payload

    async def _one_call(
        self, request: StructuredCall, messages: Sequence[Mapping[str, Any]]
    ) -> tuple[dict[str, Any], AssistantMessage, str]:
        payload = self._payload(request, messages)
        raw = await self._post(payload)
        choices = raw.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise StructuredOutputError("provider response has no completion choice")
        choice = choices[0]
        message_raw = choice.get("message")
        if not isinstance(message_raw, dict):
            raise StructuredOutputError("provider response has no assistant message")
        return raw, _complete_message(message_raw), str(choice.get("finish_reason", ""))

    async def structured_call(self, request: StructuredCall) -> StructuredResult:
        self._validate_data_policy(request.engagement)
        messages = tuple(dict(item) for item in request.messages)
        payload = self._payload(request, messages)
        started = time.monotonic()
        raw: dict[str, Any] | None = None
        try:
            async def operation() -> tuple[dict[str, Any], AssistantMessage, str]:
                response, assistant, finish = await self._one_call(request, messages)
                if finish == "tool_calls":
                    raise StructuredOutputError("structured_call received an unresolved tool call")
                content = assistant.content or ""
                try:
                    parsed = json.loads(content)
                    request.output_model.model_validate(parsed)
                except (json.JSONDecodeError, ValidationError) as exc:
                    raise StructuredOutputError(str(exc)) from exc
                return response, assistant, finish

            raw, assistant, finish_reason = await self.retry.run(operation)
            parsed_output = json.loads(assistant.content or "{}")
            validated = request.output_model.model_validate(parsed_output)
            usage = ProviderUsage.model_validate(raw.get("usage", {}))
            history = (*messages, assistant.to_api())
            self._record_call(
                request,
                payload=payload,
                response=raw,
                started=started,
                outcome=ProviderOutcome.STRUCTURED_SUCCESS,
                tool_count=len(request.tools),
            )
            return StructuredResult(
                output=validated.model_dump(mode="json"),
                assistant_message=assistant,
                usage=usage,
                response_id=str(raw.get("id", "")),
                model=str(raw.get("model", self.model)),
                finish_reason=finish_reason,
                history=tuple(history),
            )
        except ProviderBoundaryError:
            self._record_call(
                request,
                payload=payload,
                response=raw,
                started=started,
                outcome=ProviderOutcome.PROVIDER_BOUNDARY,
                tool_count=len(request.tools),
            )
            raise
        except StructuredOutputError:
            self._record_call(
                request,
                payload=payload,
                response=raw,
                started=started,
                outcome=ProviderOutcome.SCHEMA_ERROR,
                tool_count=len(request.tools),
            )
            raise
        except Exception:
            self._record_call(
                request,
                payload=payload,
                response=raw,
                started=started,
                outcome=ProviderOutcome.TRANSPORT_ERROR,
                tool_count=len(request.tools),
            )
            raise

    async def tool_loop(self, request: ToolLoopRequest) -> StructuredResult:
        call = request.call
        self._validate_data_policy(call.engagement)
        if not 1 <= request.max_turns <= call.engagement.budgets.max_model_turns_per_subtask:
            raise ValueError("tool-loop turn budget is invalid")
        history: list[dict[str, Any]] = [dict(item) for item in call.messages]
        seen_signatures: dict[str, int] = {}
        for _turn in range(request.max_turns):
            raw, assistant, finish_reason = await self._one_call(call, history)
            history.append(assistant.to_api())
            if finish_reason != "tool_calls":
                content = assistant.content or ""
                try:
                    parsed = json.loads(content)
                    validated = call.output_model.model_validate(parsed)
                except (json.JSONDecodeError, ValidationError) as exc:
                    raise StructuredOutputError(str(exc)) from exc
                return StructuredResult(
                    output=validated.model_dump(mode="json"),
                    assistant_message=assistant,
                    usage=ProviderUsage.model_validate(raw.get("usage", {})),
                    response_id=str(raw.get("id", "")),
                    model=str(raw.get("model", self.model)),
                    finish_reason=finish_reason,
                    history=tuple(history),
                )
            if not assistant.tool_calls:
                raise StructuredOutputError("finish_reason=tool_calls without tool_calls")
            for tool_call in assistant.tool_calls:
                call_id = tool_call.get("id")
                function = tool_call.get("function")
                if not isinstance(call_id, str) or not isinstance(function, dict):
                    raise StructuredOutputError("malformed tool call")
                name = function.get("name")
                arguments_text = function.get("arguments")
                if not isinstance(name, str) or not isinstance(arguments_text, str):
                    raise StructuredOutputError("malformed tool-call function")
                try:
                    arguments = json.loads(arguments_text)
                except json.JSONDecodeError as exc:
                    result: Mapping[str, Any] = {
                        "error": "TOOL_SCHEMA_ERROR",
                        "detail": str(exc),
                    }
                else:
                    if not isinstance(arguments, dict):
                        result = {"error": "TOOL_SCHEMA_ERROR", "detail": "arguments must be object"}
                    else:
                        signature = sha256_digest({"name": name, "arguments": arguments})
                        count = seen_signatures.get(signature, 0) + 1
                        seen_signatures[signature] = count
                        if count > 2:
                            result = {
                                "error": "NO_PROGRESS",
                                "detail": "repeated action signature budget exceeded",
                            }
                        else:
                            result = await request.execute_tool(name, arguments, call_id)
                history.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": canonical_text(result),
                    }
                )
        raise ProviderBoundaryError(
            "model turn budget exhausted without a terminal structured result",
            NonResponseCategory.NO_PROGRESS,
        )
