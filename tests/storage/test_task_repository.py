from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import pytest
from link2vault.domain.tasks import CaptureSource, TaskStage, TaskStatus
from link2vault.storage.task_repository import TaskRepository


def test_created_task_survives_repository_restart(tmp_path) -> None:
    first = TaskRepository(tmp_path)
    created = first.create_capture(
        source=CaptureSource.RECORDING,
        fingerprint="sha256:recording-a",
        media_seconds=61.5,
    )
    first.close()

    reopened = TaskRepository(tmp_path)
    loaded = reopened.get(created.id)

    assert loaded == created
    assert loaded.status is TaskStatus.QUEUED
    assert loaded.stage is TaskStage.VALIDATING


def test_input_reference_survives_repository_restart(tmp_path) -> None:
    first = TaskRepository(tmp_path)
    created = first.create_capture(
        source=CaptureSource.DOUYIN,
        fingerprint="sha256:input-reference",
        input_ref="synthetic-reference",
    )
    first.close()

    reopened = TaskRepository(tmp_path)

    assert reopened.get(created.id).input_ref == "synthetic-reference"


def test_queued_input_reference_can_be_bound_once(tmp_path) -> None:
    repository = TaskRepository(tmp_path)
    created = repository.create_capture(
        source=CaptureSource.RECORDING,
        fingerprint="sha256:recording-input",
    )

    updated = repository.set_input_ref(created.id, "media/task/source.wav")

    assert updated.input_ref == "media/task/source.wav"
    with pytest.raises(ValueError, match="already bound"):
        repository.set_input_ref(created.id, "media/other/source.wav")


def test_two_repository_instances_cannot_claim_the_same_task(tmp_path) -> None:
    first = TaskRepository(tmp_path)
    second = TaskRepository(tmp_path)
    created = first.create_capture(
        source=CaptureSource.DOUYIN,
        fingerprint="sha256:douyin-a",
    )

    claimed = first.claim_next("worker-a")
    duplicate = second.claim_next("worker-b")

    assert claimed is not None
    assert claimed.id == created.id
    assert claimed.status is TaskStatus.RUNNING
    assert duplicate is None


def test_completing_stages_preserves_earlier_artifacts(tmp_path) -> None:
    repository = TaskRepository(tmp_path)
    created = repository.create_capture(
        source=CaptureSource.RECORDING,
        fingerprint="sha256:recording-b",
    )
    repository.claim_next("worker-a")

    repository.complete_stage(created.id, TaskStage.VALIDATING, "media/input.m4a")
    updated = repository.complete_stage(
        created.id,
        TaskStage.FETCHING,
        "media/normalized.flac",
    )

    assert updated.artifacts == {
        "validating": "media/input.m4a",
        "fetching": "media/normalized.flac",
    }
    assert updated.stage is TaskStage.ASR


def test_terminal_task_requires_explicit_reset_before_mutation(tmp_path) -> None:
    repository = TaskRepository(tmp_path)
    created = repository.create_capture(
        source=CaptureSource.DOUYIN,
        fingerprint="sha256:douyin-b",
    )
    repository.claim_next("worker-a")
    failed = repository.fail_stage(created.id, TaskStage.FETCHING, "UPSTREAM_BLOCKED")

    assert failed.status is TaskStatus.FAILED
    with pytest.raises(ValueError, match="terminal"):
        repository.complete_stage(created.id, TaskStage.FETCHING, "media/video.mp4")

    reset = repository.reset_from_stage(created.id, TaskStage.FETCHING)

    assert reset.status is TaskStatus.QUEUED
    assert reset.stage is TaskStage.FETCHING
    assert reset.error_code is None


def test_completed_fingerprint_and_monthly_audio_are_queryable(tmp_path) -> None:
    repository = TaskRepository(tmp_path)
    created = repository.create_capture(
        source=CaptureSource.RECORDING,
        fingerprint="sha256:recording-c",
        media_seconds=120.25,
    )
    repository.claim_next("worker-a")
    for stage in TaskStage:
        repository.complete_stage(created.id, stage, f"artifact/{stage.value}")

    completed = repository.find_completed_by_fingerprint("sha256:recording-c")

    assert completed is not None
    assert completed.status is TaskStatus.COMPLETED
    assert repository.sum_audio_seconds(datetime.now(UTC).strftime("%Y-%m")) == 120.25


def test_database_uses_wal_and_required_connection_pragmas(tmp_path) -> None:
    repository = TaskRepository(tmp_path)
    repository.create_capture(
        source=CaptureSource.DOUYIN,
        fingerprint="sha256:douyin-c",
    )
    repository.close()

    connection = sqlite3.connect(tmp_path / "link2vault.sqlite3")
    journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
    connection.close()

    assert journal_mode.lower() == "wal"
