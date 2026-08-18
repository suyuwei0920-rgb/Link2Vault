"""Single-concurrency worker runtime primitives."""

from __future__ import annotations

import argparse
import asyncio
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from link2vault.config import Settings
from link2vault.domain.tasks import CaptureTask
from link2vault.providers.runtime import build_runtime_pipeline
from link2vault.storage.task_repository import TaskRepository
from link2vault.worker.pipeline import Pipeline


async def worker_once(
    repository: TaskRepository,
    pipeline: Pipeline,
    *,
    worker_id: str,
    heartbeat_interval: float = 30.0,
) -> CaptureTask | None:
    """Claim and run one task while refreshing its persistent heartbeat."""

    if heartbeat_interval <= 0:
        raise ValueError("heartbeat_interval must be positive")
    claimed = repository.claim_next(worker_id)
    if claimed is None:
        return None
    stop = asyncio.Event()

    async def heartbeat_loop() -> None:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=heartbeat_interval)
            except TimeoutError:
                repository.heartbeat(claimed.id, worker_id)

    heartbeat_task = asyncio.create_task(heartbeat_loop())
    try:
        return await pipeline.run(claimed.id)
    finally:
        stop.set()
        heartbeat_task.cancel()
        with suppress(asyncio.CancelledError):
            await heartbeat_task


async def _run(settings: Settings, *, once: bool) -> None:
    if settings.app_env == "production" and (
        settings.asr_provider == "fake" or settings.cleaner_provider == "fake"
    ):
        raise RuntimeError("fake providers are forbidden in production")
    repository = TaskRepository(settings.data_dir)
    pipeline = build_runtime_pipeline(settings, repository)
    worker_id = f"worker-{uuid4()}"
    while True:
        repository.release_stale_claims(
            datetime.now(UTC) - timedelta(minutes=5)
        )
        result = await worker_once(repository, pipeline, worker_id=worker_id)
        if once:
            return
        if result is None:
            await asyncio.sleep(1.0)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Link2Vault worker")
    parser.add_argument("--once", action="store_true", help="process at most one task")
    arguments = parser.parse_args()
    try:
        asyncio.run(_run(Settings(), once=arguments.once))
    except RuntimeError as exc:
        parser.exit(2, f"worker configuration error: {exc}\n")


if __name__ == "__main__":
    main()
