from __future__ import annotations

import pytest
from link2vault_providers.contracts import MediaInput, ProviderError
from link2vault_providers.tencent_asr import (
    TencentAsrProvider,
    TencentQuotaSnapshot,
    select_tencent_asr_engine,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def test_routes_to_free_engine_when_free_quota_covers_duration_and_margin() -> None:
    assert (
        select_tencent_asr_engine(
            duration_seconds=60,
            free_remaining_seconds=360,
            paid_2_remaining_seconds=1_000,
            safety_seconds=300,
        )
        == "16k_zh"
    )


def test_routes_to_purchased_2_engine_after_free_quota() -> None:
    assert (
        select_tencent_asr_engine(
            duration_seconds=60,
            free_remaining_seconds=100,
            paid_2_remaining_seconds=360,
            safety_seconds=300,
        )
        == "16k_zh_en_2.0"
    )


def test_fails_closed_instead_of_falling_back_to_postpaid() -> None:
    with pytest.raises(ProviderError) as captured:
        select_tencent_asr_engine(
            duration_seconds=60,
            free_remaining_seconds=100,
            paid_2_remaining_seconds=359,
            safety_seconds=300,
        )

    assert captured.value.code == "TENCENT_ASR_QUOTA_EXHAUSTED"
    assert captured.value.retryable is False
    assert "359" not in str(captured.value)


@pytest.mark.anyio
async def test_tencent_maps_speakers_and_cleans_temporary_object(tmp_path) -> None:
    cleaned: list[str] = []

    class Backend:
        async def transcribe(self, _media, engine: str):
            assert engine == "16k_zh_en_2.0"
            return {
                "request_id": "synthetic-request",
                "text": "你好",
                "language": "zh",
                "segments": [
                    {"start": 0, "end": 1, "text": "你好", "speaker_id": 2}
                ],
            }

        async def cleanup(self, _media) -> None:
            cleaned.append("done")

    provider = TencentAsrProvider(
        backend=Backend(),
        quota_loader=lambda: TencentQuotaSnapshot(0, 1_000),
        safety_seconds=300,
    )

    result = await provider.transcribe(MediaInput(tmp_path / "safe.wav", 10))

    assert result.segments[0].speaker == "Speaker 2"
    assert result.provider_job_id == "synthetic-request"
    assert cleaned == ["done"]
