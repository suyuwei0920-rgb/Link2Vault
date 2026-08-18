"""Stable value types and async provider protocols."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class ProviderError(RuntimeError):
    """Content-free provider failure safe for persistence and logs."""

    def __init__(
        self,
        code: str,
        *,
        retryable: bool,
        safe_message: str,
        provider_request_id: str | None = None,
    ) -> None:
        super().__init__(safe_message)
        self.code = code
        self.retryable = retryable
        self.provider_request_id = provider_request_id


@dataclass(frozen=True)
class MediaInput:
    path: Path
    duration_seconds: float


@dataclass(frozen=True)
class TranscriptSegment:
    start_seconds: float
    end_seconds: float
    text: str
    speaker: str | None = None


@dataclass(frozen=True)
class TranscriptResult:
    provider: str
    model: str
    language: str
    duration_seconds: float
    text: str
    segments: tuple[TranscriptSegment, ...]
    provider_job_id: str | None = None


@dataclass(frozen=True)
class CleanRequest:
    raw_transcript: str
    segments: tuple[TranscriptSegment, ...]


@dataclass(frozen=True)
class CleanResult:
    provider: str
    model: str
    summary: str
    decisions: tuple[str, ...]
    action_items: tuple[str, ...]
    open_questions: tuple[str, ...]
    cleaned_transcript: str


@dataclass(frozen=True)
class Notification:
    task_id: str
    status: str
    title: str
    preview: str | None = None


@dataclass(frozen=True)
class NotificationReceipt:
    provider: str
    accepted: bool
    provider_message_id: str | None = None


class AsrProvider(Protocol):
    async def transcribe(self, media: MediaInput) -> TranscriptResult: ...


class CleanerProvider(Protocol):
    async def clean(self, request: CleanRequest) -> CleanResult: ...


class NotifierProvider(Protocol):
    async def send(self, notification: Notification) -> NotificationReceipt: ...
