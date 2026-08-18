from __future__ import annotations

from datetime import timedelta

from link2vault.domain.tasks import CaptureSource, TaskStage
from link2vault.maintenance.retention import RetentionService
from link2vault.storage.task_repository import TaskRepository


def completed_task(repository: TaskRepository):
    created = repository.create_capture(
        source=CaptureSource.RECORDING,
        fingerprint="completed-media",
    )
    repository.claim_next("worker-a")
    for stage in TaskStage:
        repository.complete_stage(created.id, stage, f"artifact/{stage.value}")
    return repository.get(created.id)


def failed_task(repository: TaskRepository):
    created = repository.create_capture(
        source=CaptureSource.RECORDING,
        fingerprint="failed-media",
    )
    repository.claim_next("worker-a")
    return repository.fail_stage(created.id, TaskStage.ASR, "ASR_FAILED")


def test_completed_media_is_deleted_after_24_hours(tmp_path) -> None:
    repository = TaskRepository(tmp_path / "state")
    task = completed_task(repository)
    media_root = tmp_path / "media-root"
    media_dir = media_root / task.id
    media_dir.mkdir(parents=True)
    (media_dir / "source.wav").write_bytes(b"synthetic")

    report = RetentionService(repository, media_root).run(
        task.updated_at + timedelta(hours=25)
    )

    assert report.deleted_task_ids == (task.id,)
    assert not media_dir.exists()


def test_failed_media_is_kept_for_seven_days_then_deleted(tmp_path) -> None:
    repository = TaskRepository(tmp_path / "state")
    task = failed_task(repository)
    media_root = tmp_path / "media-root"
    media_dir = media_root / task.id
    media_dir.mkdir(parents=True)
    (media_dir / "source.wav").write_bytes(b"synthetic")
    service = RetentionService(repository, media_root)

    first = service.run(task.updated_at + timedelta(days=6))
    second = service.run(task.updated_at + timedelta(days=8))

    assert first.deleted_task_ids == ()
    assert second.deleted_task_ids == (task.id,)


def test_retention_never_follows_symlinks_outside_media_root(tmp_path) -> None:
    repository = TaskRepository(tmp_path / "state")
    task = completed_task(repository)
    media_root = tmp_path / "media-root"
    media_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    protected = outside / "keep.txt"
    protected.write_text("keep", encoding="utf-8")
    (media_root / task.id).symlink_to(outside, target_is_directory=True)

    report = RetentionService(repository, media_root).run(
        task.updated_at + timedelta(days=2)
    )

    assert report.deleted_task_ids == ()
    assert report.skipped_task_ids == (task.id,)
    assert protected.read_text(encoding="utf-8") == "keep"
