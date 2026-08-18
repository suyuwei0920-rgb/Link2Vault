from __future__ import annotations

import pytest
from link2vault.domain.tasks import CaptureSource, CaptureTask, TaskStage, TaskStatus
from link2vault.output.markdown import write_task_artifacts
from link2vault.storage.task_repository import TaskRepository
from link2vault.worker.pipeline import Pipeline, StageHandlers
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
async def test_recording_runs_offline_through_raw_and_cleaned_markdown(
    tmp_path,
    anyio_backend,
) -> None:
    repository = TaskRepository(tmp_path / "state")
    created = repository.create_capture(
        source=CaptureSource.RECORDING,
        fingerprint="fake-e2e-recording",
        media_seconds=3.0,
    )
    repository.claim_next("worker-a")
    asr = FakeAsrProvider()
    cleaner = FakeCleanerProvider()
    notifier = FakeNotifier()
    state: dict[str, object] = {}

    async def handler(task: CaptureTask) -> str:
        if task.stage is TaskStage.ASR:
            result = await asr.transcribe(MediaInput(tmp_path / "synthetic.wav", 3.0))
            state["transcript"] = result
            return "fake-request-id"
        if task.stage is TaskStage.CLEANING:
            transcript = state["transcript"]
            result = await cleaner.clean(
                CleanRequest(
                    raw_transcript=transcript.text,
                    segments=transcript.segments,
                )
            )
            state["cleaned"] = result
            return "fake-clean-result"
        if task.stage is TaskStage.WRITING:
            manifest = write_task_artifacts(
                task,
                state["transcript"],
                state["cleaned"],
                tmp_path / "vault-root",
                title="Synthetic meeting",
            )
            return str(manifest.task_dir)
        if task.stage is TaskStage.NOTIFYING:
            receipt = await notifier.send(
                Notification(
                    task_id=task.id,
                    status="completed",
                    title="Capture completed",
                )
            )
            return receipt.provider
        return f"offline/{task.stage.value}"

    completed = await Pipeline(
        repository,
        StageHandlers({stage: handler for stage in TaskStage}),
    ).run(created.id)

    task_dir = next((tmp_path / "vault-root").glob("2026/*/*"))
    assert completed.status is TaskStatus.COMPLETED
    assert "synthetic transcript" in (task_dir / "transcript.raw.md").read_text()
    assert "## 摘要" in (task_dir / "note.md").read_text()
    assert len(notifier.sent) == 1
