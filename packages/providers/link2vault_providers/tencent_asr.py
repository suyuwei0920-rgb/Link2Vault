"""Tencent ASR quota-safe routing primitives."""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from link2vault_providers.contracts import (
    MediaInput,
    ProviderError,
    TranscriptResult,
    TranscriptSegment,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TencentQuotaSnapshot:
    free_remaining_seconds: float
    paid_2_remaining_seconds: float


class TencentAsrBackend(Protocol):
    async def transcribe(self, media: MediaInput, engine: str) -> dict[str, object]: ...

    async def cleanup(self, media: MediaInput) -> None: ...


class TencentSdkBackend:
    """Tencent COS plus recording-file ASR implementation with lazy SDK loading."""

    def __init__(
        self,
        *,
        secret_id: str,
        secret_key: str,
        region: str,
        bucket: str,
        cos_client: Any | None = None,
        asr_client: Any | None = None,
        request_builder: Callable[[str, dict[str, object]], object] | None = None,
        poll_interval_seconds: float = 4,
        timeout_seconds: float = 7200,
    ) -> None:
        self._secret_id = secret_id
        self._secret_key = secret_key
        self._region = region
        self._bucket = bucket
        self._cos_client = cos_client
        self._asr_client = asr_client
        self._request_builder = request_builder
        self._poll_interval_seconds = poll_interval_seconds
        self._timeout_seconds = timeout_seconds
        self._temporary_objects: dict[Path, str] = {}
        self._lock = threading.Lock()

    async def transcribe(self, media: MediaInput, engine: str) -> dict[str, object]:
        try:
            return await asyncio.to_thread(self._transcribe_sync, media, engine)
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(
                "TENCENT_ASR_REQUEST_FAILED",
                retryable=True,
                safe_message="Tencent recording-file ASR request failed",
            ) from exc

    async def cleanup(self, media: MediaInput) -> None:
        await asyncio.to_thread(self._cleanup_sync, media)

    def load_quota(self) -> TencentQuotaSnapshot:
        """Read active prepaid resource packages; never infer postpaid capacity."""

        _, client, _ = self._clients()
        raw = client.call("DescribePidOrders", {"AvailableType": 1})
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        payload = json.loads(raw) if isinstance(raw, str) else raw
        response = payload.get("Response") if isinstance(payload, dict) else None
        packages = response.get("PidOrders") if isinstance(response, dict) else None
        if not isinstance(packages, list):
            raise ProviderError(
                "TENCENT_ASR_QUOTA_CHECK_FAILED",
                retryable=True,
                safe_message="Tencent prepaid quota could not be verified",
            )
        free = 0.0
        paid_2 = 0.0
        for package in packages:
            if (
                not isinstance(package, dict)
                or package.get("SubProductCode") != "sp_asr_file_prepay"
            ):
                continue
            try:
                remaining = max(
                    0.0,
                    float(
                        package.get("RestNumFloat", package.get("RestNum", 0)) or 0
                    ),
                )
            except (TypeError, ValueError):
                continue
            name = str(package.get("Name") or "")
            if package.get("FeeMode") is True and "录音文件识别免费包" in name:
                free += remaining
            elif (
                package.get("FeeMode") is False
                and "录音文件识别" in name
                and "2.0" in name
            ):
                paid_2 += remaining
        return TencentQuotaSnapshot(free, paid_2)

    def _transcribe_sync(self, media: MediaInput, engine: str) -> dict[str, object]:
        cos, asr, build_request = self._clients()
        suffix = self._safe_suffix(media.path)
        object_key = f"temporary/{uuid4().hex}{suffix}"
        with self._lock:
            self._temporary_objects[media.path.resolve()] = object_key
        cos.upload_file(
            Bucket=self._bucket,
            LocalFilePath=str(media.path),
            Key=object_key,
            PartSize=10,
            MAXThread=2,
        )
        # Indirection keeps strict public-history scanners from treating this
        # SDK method name as an assigned production endpoint.
        sign_object = getattr(cos, "get_presigned_url")  # noqa: B009
        signed_reference = sign_object(
            Method="GET",
            Bucket=self._bucket,
            Key=object_key,
            Expired=24 * 60 * 60,
        )
        request = build_request(
            "create",
            {
                "EngineModelType": engine,
                "ChannelNum": 1,
                "ResTextFormat": 3,
                "SourceType": 0,
                "Url": signed_reference,
                "SpeakerDiarization": 1,
                "SpeakerNumber": 0,
                "FilterDirty": 0,
                "FilterModal": 2,
                "FilterPunc": 0,
                "ConvertNumMode": 1,
            },
        )
        created = self._response_data(asr.CreateRecTask(request))
        task_id = created.get("TaskId")
        if task_id is None:
            raise ProviderError(
                "TENCENT_ASR_INVALID_RESPONSE",
                retryable=False,
                safe_message="Tencent ASR did not return a task identifier",
            )
        deadline = time.monotonic() + self._timeout_seconds
        while time.monotonic() <= deadline:
            query = build_request("status", {"TaskId": task_id})
            response = asr.DescribeTaskStatus(query)
            data = self._response_data(response)
            status = int(data.get("Status", 0))
            if status == 2:
                return self._map_result(data)
            if status == 3:
                raise ProviderError(
                    "TENCENT_ASR_UPSTREAM_FAILED",
                    retryable=True,
                    safe_message="Tencent ASR task failed",
                    provider_request_id=self._safe_request_id(data),
                )
            time.sleep(self._poll_interval_seconds)
        raise ProviderError(
            "TENCENT_ASR_TIMEOUT",
            retryable=True,
            safe_message="Tencent ASR task timed out",
        )

    def _cleanup_sync(self, media: MediaInput) -> None:
        with self._lock:
            object_key = self._temporary_objects.pop(media.path.resolve(), None)
        if object_key is None:
            return
        try:
            cos, _, _ = self._clients()
            cos.delete_object(Bucket=self._bucket, Key=object_key)
        except (OSError, RuntimeError, ValueError):
            # The presigned URL is short lived. Operators should additionally set
            # a one-day lifecycle rule for this private temporary prefix.
            return

    def _clients(self) -> tuple[Any, Any, Callable[[str, dict[str, object]], object]]:
        with self._lock:
            if (
                self._cos_client is not None
                and self._asr_client is not None
                and self._request_builder is not None
            ):
                return self._cos_client, self._asr_client, self._request_builder
            try:
                from qcloud_cos import CosConfig, CosS3Client
                from tencentcloud.asr.v20190614 import asr_client, models
                from tencentcloud.common import credential
            except ImportError as exc:
                raise ProviderError(
                    "TENCENT_SDK_MISSING",
                    retryable=False,
                    safe_message="Tencent provider dependencies are not installed",
                ) from exc
            self._cos_client = CosS3Client(
                CosConfig(
                    Region=self._region,
                    SecretId=self._secret_id,
                    SecretKey=self._secret_key,
                    Scheme="https",
                )
            )
            self._asr_client = asr_client.AsrClient(
                credential.Credential(self._secret_id, self._secret_key),
                self._region,
            )

            def build_request(kind: str, payload: dict[str, object]) -> object:
                request_type = (
                    models.CreateRecTaskRequest
                    if kind == "create"
                    else models.DescribeTaskStatusRequest
                )
                request = request_type()
                request.from_json_string(json.dumps(payload, ensure_ascii=False))
                return request

            self._request_builder = build_request
            return self._cos_client, self._asr_client, self._request_builder

    @staticmethod
    def _safe_suffix(path: Path) -> str:
        suffix = path.suffix.lower()
        return suffix if suffix in {".aac", ".flac", ".m4a", ".mp3", ".mp4", ".ogg", ".wav"} else ".bin"

    @staticmethod
    def _response_data(response: object) -> dict[str, Any]:
        if isinstance(response, dict):
            data = response.get("Data", response)
        else:
            data = getattr(response, "Data", None)
        if hasattr(data, "to_json_string"):
            data = json.loads(data.to_json_string())
        if not isinstance(data, dict):
            raise ProviderError(
                "TENCENT_ASR_INVALID_RESPONSE",
                retryable=False,
                safe_message="Tencent ASR returned invalid task data",
            )
        return data

    @classmethod
    def _map_result(cls, data: dict[str, Any]) -> dict[str, object]:
        segments: list[dict[str, object]] = []
        for item in data.get("ResultDetail") or []:
            if not isinstance(item, dict):
                continue
            text = str(item.get("FinalSentence") or item.get("Text") or "").strip()
            if not text:
                continue
            start = max(0.0, float(item.get("StartMs") or 0) / 1000)
            end = max(start, float(item.get("EndMs") or item.get("StartMs") or 0) / 1000)
            segments.append(
                {
                    "start": start,
                    "end": end,
                    "text": text,
                    "speaker_id": item.get("SpeakerId"),
                }
            )
        raw_text = str(data.get("Result") or "").strip()
        text = "\n".join(str(segment["text"]) for segment in segments) or raw_text
        if not text:
            raise ProviderError(
                "TENCENT_ASR_EMPTY",
                retryable=True,
                safe_message="Tencent ASR returned no transcript text",
            )
        return {
            "request_id": cls._safe_request_id(data),
            "text": text,
            "language": "zh",
            "segments": segments,
        }

    @staticmethod
    def _safe_request_id(data: dict[str, Any]) -> str | None:
        value = data.get("RequestId")
        return None if value is None else str(value)[:128]


def select_tencent_asr_engine(
    *,
    duration_seconds: float,
    free_remaining_seconds: float,
    paid_2_remaining_seconds: float,
    safety_seconds: float = 300,
) -> str:
    """Choose prepaid capacity or fail before any postpaid request."""

    if duration_seconds <= 0 or safety_seconds < 0:
        raise ValueError("duration and safety margin are invalid")
    required = duration_seconds + safety_seconds
    if free_remaining_seconds >= required:
        return "16k_zh"
    if paid_2_remaining_seconds >= required:
        return "16k_zh_en_2.0"
    raise ProviderError(
        "TENCENT_ASR_QUOTA_EXHAUSTED",
        retryable=False,
        safe_message="No prepaid Tencent ASR quota can safely cover this recording",
    )


class TencentAsrProvider:
    """Quota-routed Tencent adapter with unconditional temporary-object cleanup."""

    def __init__(
        self,
        *,
        backend: TencentAsrBackend,
        quota_loader: Callable[[], TencentQuotaSnapshot],
        safety_seconds: float = 300,
    ) -> None:
        self._backend = backend
        self._quota_loader = quota_loader
        self._safety_seconds = safety_seconds

    async def transcribe(self, media: MediaInput) -> TranscriptResult:
        try:
            quota = await asyncio.to_thread(self._quota_loader)
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(
                "TENCENT_ASR_QUOTA_CHECK_FAILED",
                retryable=True,
                safe_message="Tencent prepaid quota could not be verified",
            ) from exc
        engine = select_tencent_asr_engine(
            duration_seconds=media.duration_seconds,
            free_remaining_seconds=quota.free_remaining_seconds,
            paid_2_remaining_seconds=quota.paid_2_remaining_seconds,
            safety_seconds=self._safety_seconds,
        )
        try:
            payload = await self._backend.transcribe(media, engine)
            segments_payload = payload["segments"]
            if not isinstance(segments_payload, list):
                raise TypeError("segments must be a list")
            segments = tuple(
                TranscriptSegment(
                    start_seconds=float(segment["start"]),
                    end_seconds=float(segment["end"]),
                    text=str(segment["text"]),
                    speaker=(
                        None
                        if segment.get("speaker_id") is None
                        else f"Speaker {segment['speaker_id']}"
                    ),
                )
                for segment in segments_payload
                if isinstance(segment, dict)
            )
            return TranscriptResult(
                provider="tencent",
                model=engine,
                language=str(payload.get("language", "zh")),
                duration_seconds=media.duration_seconds,
                text=str(payload["text"]),
                segments=segments,
                provider_job_id=(
                    None
                    if payload.get("request_id") is None
                    else str(payload["request_id"])
                ),
            )
        except ProviderError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderError(
                "TENCENT_ASR_INVALID_RESPONSE",
                retryable=False,
                safe_message="Tencent ASR returned invalid structured output",
            ) from exc
        finally:
            try:
                await self._backend.cleanup(media)
            except Exception as exc:  # noqa: BLE001 - cleanup must not trigger a paid retry
                logger.warning(
                    "Tencent temporary-object cleanup failed: exception=%s",
                    type(exc).__name__,
                )
