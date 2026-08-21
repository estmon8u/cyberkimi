from __future__ import annotations

import httpx
import pytest
from pydantic import Field

from cyberkimi.models import StrictModel
from cyberkimi.provider import MoonshotProvider, StructuredCall
from cyberkimi.retry import ProviderBoundaryError
from tests.conftest import make_task


class Answer(StrictModel):
    status: str
    count: int = Field(ge=0)


@pytest.mark.asyncio
async def test_structured_call_preserves_complete_assistant_message(runtime) -> None:
    task, _token, _digest = make_task(runtime, task_id="TASK-PROVIDER")
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        body = request.read().decode()
        assert '"type":"json_schema"' in body or '"type": "json_schema"' in body
        return httpx.Response(
            200,
            json={
                "id": "cmpl-test",
                "model": "kimi-k3",
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": '{"status":"ok","count":1}',
                            "reasoning_content": "preserved session state",
                        },
                    }
                ],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 5,
                    "total_tokens": 15,
                    "cached_tokens": 0,
                },
            },
        )

    engagement = runtime["engagement"].model_copy(
        update={
            "data_policy": runtime["engagement"].data_policy.model_copy(
                update={
                    "external_model_allowed": True,
                    "allowed_model_providers": ("moonshot",),
                }
            )
        }
    )
    provider = MoonshotProvider(
        api_key="test",
        base_url="https://api.moonshot.ai/v1",
        model="kimi-k3",
        database=runtime["database"],
        audit=runtime["audit"],
        fingerprint_key_path=runtime["settings"].fingerprint_key_path,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    result = await provider.structured_call(
        StructuredCall(
            engagement=engagement,
            task=task,
            role="worker",
            output_model=Answer,
            messages=({"role": "user", "content": "Return the result"},),
            reasoning_effort="low",
        )
    )
    assert result.output == {"status": "ok", "count": 1}
    assert result.assistant_message.reasoning_content == "preserved session state"
    assert calls == 1
    await provider._client.aclose()  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_provider_policy_is_terminal_and_not_rephrased(runtime) -> None:
    task, _token, _digest = make_task(runtime, task_id="TASK-BOUNDARY")
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            400,
            json={"error": {"type": "policy_error", "message": "blocked by provider policy"}},
        )

    engagement = runtime["engagement"].model_copy(
        update={
            "data_policy": runtime["engagement"].data_policy.model_copy(
                update={
                    "external_model_allowed": True,
                    "allowed_model_providers": ("moonshot",),
                }
            )
        }
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = MoonshotProvider(
        api_key="test",
        base_url="https://api.moonshot.ai/v1",
        model="kimi-k3",
        database=runtime["database"],
        audit=runtime["audit"],
        fingerprint_key_path=runtime["settings"].fingerprint_key_path,
        client=client,
    )
    with pytest.raises(ProviderBoundaryError):
        await provider.structured_call(
            StructuredCall(
                engagement=engagement,
                task=task,
                role="director",
                output_model=Answer,
                messages=({"role": "user", "content": "Analyze evidence"},),
            )
        )
    assert calls == 1
    await client.aclose()
