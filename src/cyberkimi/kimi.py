from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Literal, TypeVar

from openai import AsyncOpenAI
from pydantic import BaseModel, ConfigDict, Field

from .store import canonical_json


ReasoningEffort = Literal["low", "high", "max"]
RoleName = Literal["director", "worker", "verifier", "reporter"]
T = TypeVar("T", bound=BaseModel)


class KimiError(RuntimeError):
    pass


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hypothesis_id: str
    claim: str
    confidence: float = Field(ge=0.0, le=1.0)
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class ProposedActionOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_template: str
    target_asset_id: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    purpose: str
    requested_effects: list[str] = Field(default_factory=list)
    requested_timeout_seconds: int = Field(ge=1, le=7200)


class DirectorOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task_status: Literal[
        "continue",
        "needs_scope",
        "needs_authorization",
        "needs_evidence",
        "human_approval_required",
        "provider_refusal",
        "completed",
    ]
    summary: str
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    proposed_actions: list[ProposedActionOutput] = Field(default_factory=list)


@dataclass(frozen=True)
class ModelCallRecord:
    role: RoleName
    model: str
    reasoning_effort: ReasoningEffort
    prompt_hash: str
    response_hash: str
    input_tokens: int | None
    output_tokens: int | None
    latency_ms: int
    result: str
    session_id: str
    tool_count_exposed: int


DIRECTOR_SYSTEM = """You are the Security Director for a declared, authorized defensive engagement.
The engagement manifest and asset registry are authoritative. Do not infer authorization for
assets or effects not explicitly listed. Generate precise, falsifiable security hypotheses and
request only registered typed action templates. Search for counterevidence before recommending
confirmation. You do not execute tools, generate arbitrary shell commands, alter scope, or approve
actions. Return only the supplied strict JSON schema.
"""

VERIFIER_SYSTEM = """You are an independent security finding verifier. You receive a claim,
evidence for and against it, source excerpts, deterministic oracle results, and scope. You do not
receive the planner's confidence or conclusion. Determine whether the claim and stated impact are
supported. Return only the supplied strict JSON schema.
"""

REPORTER_SYSTEM = """You are a defensive security reporter. Convert only verified evidence and
explicit unresolved items into a clear report. Never elevate an unverified signal into a finding.
Return only the supplied strict JSON schema.
"""


class KimiClient:
    def __init__(
        self,
        *,
        api_key: str,
        model: str = "kimi-k3",
        base_url: str = "https://api.moonshot.ai/v1",
        timeout_seconds: float = 120.0,
    ) -> None:
        if not api_key:
            raise ValueError("a control-plane Moonshot API key is required")
        self.model = model
        self._client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout_seconds,
        )

    async def structured_call(
        self,
        *,
        role: RoleName,
        system: str,
        messages: list[dict[str, Any]],
        output_model: type[T],
        reasoning_effort: ReasoningEffort,
        session_id: str,
        tools: list[dict[str, Any]] | None = None,
    ) -> tuple[T, dict[str, Any], ModelCallRecord]:
        complete_messages = [{"role": "system", "content": system}, *messages]
        prompt_hash = hashlib.sha256(canonical_json(complete_messages).encode()).hexdigest()
        schema = output_model.model_json_schema()
        start = time.monotonic()
        response = await self._client.chat.completions.create(
            model=self.model,
            messages=complete_messages,
            tools=tools or None,
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": output_model.__name__,
                    "strict": True,
                    "schema": schema,
                },
            },
            extra_body={"reasoning_effort": reasoning_effort},
        )
        latency_ms = round((time.monotonic() - start) * 1000)
        if not response.choices:
            raise KimiError("provider returned no choices")
        assistant_message = response.choices[0].message.model_dump(exclude_none=True)
        content = assistant_message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise KimiError("provider returned no final structured content")
        try:
            parsed = output_model.model_validate_json(content)
        except (ValueError, json.JSONDecodeError) as exc:
            raise KimiError("strict structured response failed local validation") from exc
        response_hash = hashlib.sha256(content.encode()).hexdigest()
        usage = response.usage
        record = ModelCallRecord(
            role=role,
            model=self.model,
            reasoning_effort=reasoning_effort,
            prompt_hash=prompt_hash,
            response_hash=response_hash,
            input_tokens=getattr(usage, "prompt_tokens", None),
            output_tokens=getattr(usage, "completion_tokens", None),
            latency_ms=latency_ms,
            result="structured_success",
            session_id=session_id,
            tool_count_exposed=len(tools or ()),
        )
        # Return the complete assistant message so reasoning/tool-call metadata can be
        # preserved losslessly in a subsequent application-controlled tool loop. The
        # reasoning field must not be promoted to business evidence.
        return parsed, assistant_message, record

    async def director(
        self,
        *,
        messages: list[dict[str, Any]],
        session_id: str,
        tools: list[dict[str, Any]],
    ) -> tuple[DirectorOutput, dict[str, Any], ModelCallRecord]:
        return await self.structured_call(
            role="director",
            system=DIRECTOR_SYSTEM,
            messages=messages,
            output_model=DirectorOutput,
            reasoning_effort="high",
            session_id=session_id,
            tools=tools,
        )


def append_assistant_and_tool_result(
    messages: list[dict[str, Any]],
    assistant_message: dict[str, Any],
    *,
    tool_call_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    """Preserve the exact assistant message before appending an application tool result."""
    return [
        *messages,
        assistant_message,
        {
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": canonical_json(result),
        },
    ]
