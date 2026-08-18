from __future__ import annotations

import json

import httpx
import pytest
from link2vault_providers.contracts import CleanRequest, TranscriptSegment
from link2vault_providers.deepseek_cleaner import DeepSeekCleaner


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_deepseek_cleaner_validates_structured_result_and_uncertainty() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        content = json.dumps(
            {
                "summary": "讨论了交付日期",
                "decisions": [],
                "action_items": ["负责人待确认"],
                "open_questions": ["日期[听不清]"],
                "cleaned_transcript": "说话人1：日期是[听不清]。",
            },
            ensure_ascii=False,
        )
        return httpx.Response(
            200,
            json={
                "id": "synthetic-request",
                "choices": [{"message": {"content": content}}],
            },
        )

    cleaner = DeepSeekCleaner(
        api_key="DUMMY_" + "deepseek-key",
        model="deepseek-chat",
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            base_url="https://example.com",
        ),
    )

    result = await cleaner.clean(
        CleanRequest(
            raw_transcript="说话人1：日期是八号或九号。",
            segments=(TranscriptSegment(0, 2, "日期是八号或九号", "说话人1"),),
        )
    )

    assert result.open_questions == ("日期[听不清]",)
    assert "[听不清]" in result.cleaned_transcript
    system_prompt = captured["body"]["messages"][0]["content"]
    assert "不得猜测" in system_prompt
    assert "[听不清]" in system_prompt
