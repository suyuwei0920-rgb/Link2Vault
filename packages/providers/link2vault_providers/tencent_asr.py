"""Tencent ASR quota-safe routing primitives."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from link2vault_providers.contracts import (
    MediaInput,
    ProviderError,
    TranscriptResult,
    TranscriptSegment,
)


@dataclass(frozen=True)
class TencentQuotaSnapshot:
    free_remaining_seconds: float
    paid_2_remaining_seconds: float


class TencentAsrBackend(Protocol):
    async def transcribe(self, media: MediaInput, engine: str) -> dict[str, object]: ...

    async def cleanup(self, media: MediaInput) -> None: ...


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
        quota = self._quota_loader()
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
            await self._backend.cleanup(media)
