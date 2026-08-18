"""Deterministic offline providers for tests and clean-room demonstrations."""

from __future__ import annotations

from link2vault_providers.contracts import (
    CleanRequest,
    CleanResult,
    MediaInput,
    Notification,
    NotificationReceipt,
    TranscriptResult,
    TranscriptSegment,
)


class FakeAsrProvider:
    async def transcribe(self, media: MediaInput) -> TranscriptResult:
        text = "Speaker 1: synthetic transcript."
        return TranscriptResult(
            provider="fake",
            model="offline-v1",
            language="en",
            duration_seconds=media.duration_seconds,
            text=text,
            segments=(
                TranscriptSegment(
                    start_seconds=0.0,
                    end_seconds=media.duration_seconds,
                    text="synthetic transcript.",
                    speaker="Speaker 1",
                ),
            ),
        )


class FakeCleanerProvider:
    async def clean(self, request: CleanRequest) -> CleanResult:
        cleaned = request.raw_transcript.strip()
        return CleanResult(
            provider="fake",
            model="offline-v1",
            summary="Synthetic capture processed.",
            decisions=(),
            action_items=(),
            open_questions=(),
            cleaned_transcript=cleaned,
        )


class FakeNotifier:
    def __init__(self) -> None:
        self._sent: list[Notification] = []

    @property
    def sent(self) -> tuple[Notification, ...]:
        return tuple(self._sent)

    async def send(self, notification: Notification) -> NotificationReceipt:
        self._sent.append(notification)
        return NotificationReceipt(provider="fake", accepted=True)
