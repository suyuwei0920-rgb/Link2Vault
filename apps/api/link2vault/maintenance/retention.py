"""Bounded media retention without symlink traversal."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from link2vault.domain.tasks import TaskStatus
from link2vault.storage.task_repository import TaskRepository


@dataclass(frozen=True)
class RetentionReport:
    deleted_task_ids: tuple[str, ...]
    skipped_task_ids: tuple[str, ...]


class RetentionService:
    """Delete successful media after 24h and failed media after seven days."""

    def __init__(self, repository: TaskRepository, media_root: Path) -> None:
        self._repository = repository
        self._media_root = media_root

    def run(self, now: datetime) -> RetentionReport:
        if now.tzinfo is None:
            raise ValueError("retention time must be timezone-aware")
        if not self._media_root.exists():
            return RetentionReport((), ())
        root = self._media_root.resolve(strict=True)
        deleted: list[str] = []
        skipped: list[str] = []
        for candidate in sorted(self._media_root.iterdir(), key=lambda path: path.name):
            task_id = candidate.name
            try:
                task = self._repository.get(task_id)
            except KeyError:
                continue
            threshold = {
                TaskStatus.COMPLETED: timedelta(hours=24),
                TaskStatus.FAILED: timedelta(days=7),
            }.get(task.status)
            if threshold is None or now - task.updated_at < threshold:
                continue
            if candidate.is_symlink() or not candidate.is_dir():
                skipped.append(task_id)
                continue
            resolved = candidate.resolve(strict=True)
            if not resolved.is_relative_to(root) or any(
                child.is_symlink() for child in candidate.rglob("*")
            ):
                skipped.append(task_id)
                continue
            shutil.rmtree(resolved)
            deleted.append(task_id)
        return RetentionReport(tuple(deleted), tuple(skipped))
