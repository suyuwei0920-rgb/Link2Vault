from __future__ import annotations

from collections.abc import Awaitable, Callable

import pytest
from link2vault.domain.tasks import CaptureSource, CaptureTask, TaskStage, TaskStatus
from link2vault.storage.task_repository import TaskRepository
from link2vault.worker.pipeline import Pipeline, StageHandlers


class StageFailure(RuntimeError):
    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__("safe stage failure")
        self.code = code
        self.retryable = retryable


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def successful_handlers(
    overrides: dict[TaskStage, Callable[[CaptureTask], Awaitable[str]]] | None = None,
) -> StageHandlers:
    async def complete(task: CaptureTask) -> str:
        return f"artifact/{task.stage.value}"

    handlers = {stage: complete for stage in TaskStage}
    handlers.update(overrides or {})
    return StageHandlers(handlers)


@pytest.mark.anyio
@pytest.mark.parametrize("source", list(CaptureSource))
async def test_complete_link_and_recording_flows_checkpoint_every_stage(
    tmp_path,
    source: CaptureSource,
) -> None:
    repository = TaskRepository(tmp_path)
    created = repository.create_capture(source=source, fingerprint=f"fp-{source.value}")
    repository.claim_next("worker-a")

    completed = await Pipeline(repository, successful_handlers()).run(created.id)

    assert completed.status is TaskStatus.COMPLETED
    assert completed.artifacts == {
        stage.value: f"artifact/{stage.value}" for stage in TaskStage
    }


@pytest.mark.anyio
async def test_asr_checkpoint_is_reused_after_cleaner_failure(tmp_path) -> None:
    repository = TaskRepository(tmp_path)
    created = repository.create_capture(
        source=CaptureSource.RECORDING,
        fingerprint="recording-checkpoint",
    )
    repository.claim_next("worker-a")
    asr_calls = 0

    async def asr(task: CaptureTask) -> str:
        nonlocal asr_calls
        asr_calls += 1
        return f"artifact/{task.stage.value}"

    async def fail_cleaning(_task: CaptureTask) -> str:
        raise StageFailure("CLEANING_FAILED")

    failed = await Pipeline(
        repository,
        successful_handlers(
            {TaskStage.ASR: asr, TaskStage.CLEANING: fail_cleaning}
        ),
    ).run(created.id)

    assert failed.status is TaskStatus.FAILED
    assert failed.error_code == "CLEANING_FAILED"
    assert asr_calls == 1

    repository.reset_from_stage(created.id, TaskStage.CLEANING)
    repository.claim_next("worker-b")
    completed = await Pipeline(
        repository,
        successful_handlers({TaskStage.ASR: asr}),
    ).run(created.id)

    assert completed.status is TaskStatus.COMPLETED
    assert asr_calls == 1
    assert completed.artifacts["asr"] == "artifact/asr"


@pytest.mark.anyio
async def test_notification_failure_completes_task_with_warning(tmp_path) -> None:
    repository = TaskRepository(tmp_path)
    created = repository.create_capture(
        source=CaptureSource.DOUYIN,
        fingerprint="notification-warning",
    )
    repository.claim_next("worker-a")

    async def fail_notification(_task: CaptureTask) -> str:
        raise StageFailure("NOTIFICATION_FAILED")

    completed = await Pipeline(
        repository,
        successful_handlers({TaskStage.NOTIFYING: fail_notification}),
    ).run(created.id)

    assert completed.status is TaskStatus.COMPLETED
    assert completed.error_code is None
    assert completed.artifacts["notifying"] == "warning:NOTIFICATION_FAILED"
