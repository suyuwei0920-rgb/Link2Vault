"""Checkpointed, resumable capture pipeline."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from functools import partial

from link2vault.domain.tasks import CaptureTask, TaskStage, TaskStatus
from link2vault.storage.task_repository import TaskRepository
from link2vault.worker.retry import RetryPolicy, run_with_retry

StageHandler = Callable[[CaptureTask], Awaitable[str]]


class StageHandlers:
    """Exact handler registry for every persisted task stage."""

    def __init__(self, handlers: Mapping[TaskStage, StageHandler]) -> None:
        missing = set(TaskStage).difference(handlers)
        if missing:
            names = ", ".join(sorted(stage.value for stage in missing))
            raise ValueError(f"missing stage handlers: {names}")
        self._handlers = dict(handlers)

    def for_stage(self, stage: TaskStage) -> StageHandler:
        return self._handlers[stage]


class Pipeline:
    """Advance one claimed task one durable checkpoint at a time."""

    def __init__(
        self,
        repository: TaskRepository,
        handlers: StageHandlers,
        *,
        retry_policy: RetryPolicy | None = None,
        sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._repository = repository
        self._handlers = handlers
        self._retry_policy = retry_policy or RetryPolicy()
        self._sleeper = sleeper

    async def run(self, task_id: str) -> CaptureTask:
        """Run until completed or a safe terminal failure is checkpointed."""

        while True:
            task = self._repository.get(task_id)
            if task.status in {TaskStatus.COMPLETED, TaskStatus.FAILED}:
                return task
            if task.status is not TaskStatus.RUNNING:
                raise ValueError("task must be claimed before pipeline execution")
            handler = self._handlers.for_stage(task.stage)

            try:
                artifact = await run_with_retry(
                    partial(_execute_stage, handler, task),
                    self._retry_policy,
                    sleeper=self._sleeper,
                )
            except Exception as exc:  # noqa: BLE001 - provider boundary is normalized
                code = str(getattr(exc, "code", "STAGE_FAILED"))
                if task.stage is TaskStage.NOTIFYING:
                    return self._repository.complete_stage(
                        task.id,
                        task.stage,
                        f"warning:{code}",
                    )
                return self._repository.fail_stage(task.id, task.stage, code)
            self._repository.complete_stage(task.id, task.stage, artifact)


async def _execute_stage(handler: StageHandler, task: CaptureTask) -> str:
    return await handler(task)
