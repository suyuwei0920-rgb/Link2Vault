from __future__ import annotations

from pathlib import Path

import pytest
from link2vault_providers.contracts import CleanRequest, MediaInput, Notification
from link2vault_providers.fakes import (
    FakeAsrProvider,
    FakeCleanerProvider,
    FakeNotifier,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_fake_asr_returns_immutable_speaker_segments() -> None:
    provider = FakeAsrProvider()

    result = await provider.transcribe(MediaInput(Path("synthetic.wav"), 3.0))

    assert result.text == "Speaker 1: synthetic transcript."
    assert result.segments[0].speaker == "Speaker 1"
    with pytest.raises(AttributeError):
        result.segments[0].text = "changed"  # type: ignore[misc]


@pytest.mark.anyio
async def test_fake_cleaner_returns_structure_without_mutating_raw_transcript() -> None:
    provider = FakeCleanerProvider()
    request = CleanRequest(raw_transcript="  Original statement.  ", segments=())

    result = await provider.clean(request)

    assert request.raw_transcript == "  Original statement.  "
    assert result.cleaned_transcript == "Original statement."
    assert result.summary
    assert result.decisions == ()
    assert result.action_items == ()
    assert result.open_questions == ()


@pytest.mark.anyio
async def test_fake_notifier_captures_metadata_without_content_preview() -> None:
    provider = FakeNotifier()
    notification = Notification(
        task_id="synthetic-task",
        status="completed",
        title="Capture completed",
        preview=None,
    )

    receipt = await provider.send(notification)

    assert receipt.accepted is True
    assert provider.sent == (notification,)
    assert provider.sent[0].preview is None
