from __future__ import annotations

import httpx
import pytest
from link2vault_providers.contracts import MediaInput
from link2vault_providers.openai_asr import OpenAICompatibleAsrProvider


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_openai_compatible_asr_posts_multipart_and_maps_segments(tmp_path) -> None:
    media = tmp_path / "synthetic.wav"
    media.write_bytes(b"synthetic-audio")
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            headers={"x-request-id": "synthetic-request"},
            json={
                "text": "hello",
                "duration": 2.0,
                "language": "en",
                "segments": [
                    {"start": 0.0, "end": 2.0, "text": "hello", "speaker": "A"}
                ],
            },
        )

    provider = OpenAICompatibleAsrProvider(
        api_key="DUMMY_" + "asr-key",
        model="synthetic-asr",
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            base_url="https://example.com",
        ),
    )

    result = await provider.transcribe(MediaInput(media, 2.0))

    assert requests[0].headers["content-type"].startswith("multipart/form-data")
    assert b"synthetic-asr" in requests[0].content
    assert result.provider_job_id == "synthetic-request"
    assert result.segments[0].speaker == "A"
