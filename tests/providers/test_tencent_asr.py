from __future__ import annotations

import threading

import pytest
from link2vault_providers.contracts import MediaInput, ProviderError
from link2vault_providers.tencent_asr import (
    TencentAsrProvider,
    TencentQuotaSnapshot,
    TencentSdkBackend,
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


@pytest.mark.anyio
async def test_sdk_backend_uploads_polls_maps_segments_and_deletes_object(tmp_path) -> None:
    media_path = tmp_path / "meeting.wav"
    media_path.write_bytes(b"synthetic audio")
    calls: list[tuple[str, object]] = []

    class CosClient:
        def upload_file(self, **kwargs):
            calls.append(("upload", kwargs))

        def get_presigned_url(self, **kwargs):
            calls.append(("sign", kwargs))
            return "https://media.example.invalid/object"

        def delete_object(self, **kwargs):
            calls.append(("delete", kwargs))

    class AsrClient:
        def CreateRecTask(self, request):
            calls.append(("create", request))
            return {"Data": {"TaskId": 42}}

        def DescribeTaskStatus(self, request):
            calls.append(("poll", request))
            return {
                "Data": {
                    "Status": 2,
                    "RequestId": "synthetic-request",
                    "Result": "你好",
                    "ResultDetail": [
                        {
                            "StartMs": 0,
                            "EndMs": 1200,
                            "FinalSentence": "你好",
                            "SpeakerId": 1,
                        }
                    ],
                }
            }

    backend = TencentSdkBackend(
        secret_id="synthetic-id",
        secret_key="synthetic-key",
        region="synthetic-region",
        bucket="synthetic-bucket",
        cos_client=CosClient(),
        asr_client=AsrClient(),
        request_builder=lambda _kind, payload: payload,
        poll_interval_seconds=0,
    )
    media = MediaInput(media_path, 1.2)

    payload = await backend.transcribe(media, "16k_zh")
    await backend.cleanup(media)

    assert payload["text"] == "你好"
    assert payload["segments"] == [
        {"start": 0.0, "end": 1.2, "text": "你好", "speaker_id": 1}
    ]
    upload = next(value for name, value in calls if name == "upload")
    assert upload["LocalFilePath"] == str(media_path)
    assert upload["Key"].startswith("temporary/")
    assert upload["Key"].endswith(".wav")
    assert calls[-1][0] == "delete"
    assert calls[-1][1]["Key"] == upload["Key"]


def test_sdk_backend_quota_loader_accepts_only_matching_prepaid_packages() -> None:
    class AsrClient:
        def call(self, action, payload):
            assert action == "DescribePidOrders"
            assert payload == {"AvailableType": 1}
            return {
                "Response": {
                    "PidOrders": [
                        {
                            "SubProductCode": "sp_asr_file_prepay",
                            "Name": "录音文件识别免费包",
                            "FeeMode": True,
                            "RestNumFloat": 600,
                        },
                        {
                            "SubProductCode": "sp_asr_file_prepay",
                            "Name": "录音文件识别大模型2.0资源包",
                            "FeeMode": False,
                            "RestNum": 3600,
                        },
                        {
                            "SubProductCode": "unrelated",
                            "Name": "录音文件识别免费包",
                            "FeeMode": True,
                            "RestNum": 999999,
                        },
                    ]
                }
            }

    backend = TencentSdkBackend(
        secret_id="synthetic-id",
        secret_key="synthetic-key",
        region="synthetic-region",
        bucket="synthetic-bucket",
        cos_client=object(),
        asr_client=AsrClient(),
        request_builder=lambda _kind, payload: payload,
    )

    assert backend.load_quota() == TencentQuotaSnapshot(
        free_remaining_seconds=600,
        paid_2_remaining_seconds=3600,
    )


@pytest.mark.anyio
async def test_quota_lookup_is_offloaded_and_cleanup_failure_does_not_recharge(
    tmp_path,
) -> None:
    event_loop_thread = threading.get_ident()
    quota_threads: list[int] = []

    class Backend:
        async def transcribe(self, _media, _engine):
            return {
                "request_id": "synthetic-request",
                "text": "完成",
                "language": "zh",
                "segments": [],
            }

        async def cleanup(self, _media) -> None:
            raise RuntimeError("synthetic cleanup failure")

    def load_quota() -> TencentQuotaSnapshot:
        quota_threads.append(threading.get_ident())
        return TencentQuotaSnapshot(1_000, 0)

    provider = TencentAsrProvider(
        backend=Backend(),
        quota_loader=load_quota,
        safety_seconds=0,
    )

    result = await provider.transcribe(MediaInput(tmp_path / "safe.wav", 10))

    assert result.text == "完成"
    assert quota_threads and quota_threads[0] != event_loop_thread
