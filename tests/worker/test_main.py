from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta

import pytest
from link2vault.domain.tasks import CaptureSource, CaptureTask, TaskStage, TaskStatus
from link2vault.storage.task_repository import TaskRepository
from link2vault.worker.main import worker_once
from link2vault.worker.pipeline import Pipeline, StageHandlers


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_worker_heartbeats_while_a_stage_is_running(tmp_path) -> None:
    repository = TaskRepository(tmp_path)
    created = repository.create_capture(
        source=CaptureSource.RECORDING,
        fingerprint="heartbeat-task",
    )
    started = asyncio.Event()
    release = asyncio.Event()

    async def handler(task: CaptureTask) -> str:
        if task.stage is TaskStage.VALIDATING:
            started.set()
            await release.wait()
        return f"artifact/{task.stage.value}"

    pipeline = Pipeline(repository, StageHandlers({stage: handler for stage in TaskStage}))
    running = asyncio.create_task(
        worker_once(
            repository,
            pipeline,
            worker_id="worker-a",
            heartbeat_interval=0.01,
        )
    )
    await started.wait()
    claimed_at = repository.get(created.id).updated_at
    await asyncio.sleep(0.03)
    heartbeat_at = repository.get(created.id).updated_at
    release.set()

    completed = await running

    assert heartbeat_at > claimed_at
    assert completed is not None
    assert completed.status is TaskStatus.COMPLETED


def test_stale_running_claim_can_be_requeued(tmp_path) -> None:
    repository = TaskRepository(tmp_path)
    created = repository.create_capture(
        source=CaptureSource.DOUYIN,
        fingerprint="stale-task",
    )
    repository.claim_next("worker-a")

    released = repository.release_stale_claims(
        datetime.now(UTC) + timedelta(seconds=1)
    )

    assert released == 1
    assert repository.get(created.id).status is TaskStatus.QUEUED


@pytest.mark.anyio
async def test_worker_returns_none_when_queue_is_empty(tmp_path) -> None:
    repository = TaskRepository(tmp_path)

    result = await worker_once(
        repository,
        Pipeline(
            repository,
            StageHandlers(
                {
                    stage: _unused_handler
                    for stage in TaskStage
                }
            ),
        ),
        worker_id="worker-a",
    )

    assert result is None


def test_module_once_processes_one_task_with_offline_development_handlers(
    tmp_path,
) -> None:
    repository = TaskRepository(tmp_path)
    media = tmp_path / "synthetic.wav"
    media.write_bytes(b"synthetic")
    created = repository.create_capture(
        source=CaptureSource.RECORDING,
        fingerprint="module-once",
        input_ref=str(media),
    )
    repository.close()
    environment = os.environ.copy()
    environment.update(
        {
            "LINK2VAULT_APP_ENV": "development",
            "LINK2VAULT_DATA_DIR": str(tmp_path),
            "LINK2VAULT_VAULT_ROOT": str(tmp_path / "vault-root"),
            "LINK2VAULT_MEDIA_TMP_DIR": str(tmp_path),
        }
    )

    completed = subprocess.run(
        [sys.executable, "-m", "link2vault.worker.main", "--once"],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )

    reopened = TaskRepository(tmp_path)
    assert completed.returncode == 0, completed.stderr
    assert reopened.get(created.id).status is TaskStatus.COMPLETED
    assert len(list((tmp_path / "vault-root").rglob("transcript.raw.md"))) == 1
    assert len(list((tmp_path / "vault-root").rglob("note.md"))) == 1


def test_offline_worker_fails_closed_in_production(tmp_path) -> None:
    environment = os.environ.copy()
    environment.update(
        {
            "LINK2VAULT_APP_ENV": "production",
            "LINK2VAULT_DATA_DIR": str(tmp_path),
        }
    )

    completed = subprocess.run(
        [sys.executable, "-m", "link2vault.worker.main", "--once"],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )

    assert completed.returncode != 0


def test_module_once_processes_synthetic_link_with_development_fakes(tmp_path) -> None:
    repository = TaskRepository(tmp_path)
    created = repository.create_capture(
        source=CaptureSource.DOUYIN,
        fingerprint="module-link-once",
        input_ref="https://" + "v." + "douyin.com/synthetic/",
    )
    repository.close()
    environment = os.environ.copy()
    environment.update(
        {
            "LINK2VAULT_APP_ENV": "development",
            "LINK2VAULT_DATA_DIR": str(tmp_path),
            "LINK2VAULT_VAULT_ROOT": str(tmp_path / "vault-root"),
            "LINK2VAULT_MEDIA_TMP_DIR": str(tmp_path),
        }
    )

    completed = subprocess.run(
        [sys.executable, "-m", "link2vault.worker.main", "--once"],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )

    reopened = TaskRepository(tmp_path)
    assert completed.returncode == 0, completed.stderr
    assert reopened.get(created.id).status is TaskStatus.COMPLETED
    assert len(list((tmp_path / "vault-root").rglob("note.md"))) == 1


async def _unused_handler(_task: CaptureTask) -> str:
    raise AssertionError("empty queues must not run a handler")
