"""Persistent capture task repository."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from link2vault.domain.tasks import CaptureSource, CaptureTask, TaskStage, TaskStatus
from link2vault.storage.database import Database

_SCHEMA_VERSION = 1
_STAGES = tuple(TaskStage)
_TERMINAL = frozenset({TaskStatus.COMPLETED, TaskStatus.FAILED})


def _now() -> datetime:
    return datetime.now(UTC)


def _encode_items(items: dict[str, str]) -> str:
    return json.dumps(
        {"schema_version": _SCHEMA_VERSION, "items": items},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _encode_error(code: str | None) -> str:
    return json.dumps(
        {"schema_version": _SCHEMA_VERSION, "code": code},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


class TaskRepository:
    """Store and atomically claim resumable capture tasks."""

    def __init__(self, data_dir: Path) -> None:
        self._database = Database(data_dir)
        self._connection = self._database.connection

    def close(self) -> None:
        """Release the repository connection."""

        self._database.close()

    def create_capture(
        self,
        *,
        source: CaptureSource,
        fingerprint: str,
        media_seconds: float | None = None,
        input_ref: str | None = None,
    ) -> CaptureTask:
        """Create a queued capture at the validation stage."""

        if not fingerprint:
            raise ValueError("fingerprint must not be empty")
        if media_seconds is not None and media_seconds < 0:
            raise ValueError("media_seconds must be non-negative")
        task_id = str(uuid4())
        timestamp = _now().isoformat()
        self._connection.execute(
            """
            INSERT INTO capture_tasks (
                id, source, status, stage, fingerprint, created_at, updated_at,
                media_seconds, artifacts_json, error_json, worker_id, input_ref
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
            """,
            (
                task_id,
                source.value,
                TaskStatus.QUEUED.value,
                TaskStage.VALIDATING.value,
                fingerprint,
                timestamp,
                timestamp,
                media_seconds,
                _encode_items({}),
                _encode_error(None),
                input_ref,
            ),
        )
        return self.get(task_id)

    def get(self, task_id: str) -> CaptureTask:
        """Load one task or raise ``KeyError``."""

        row = self._connection.execute(
            "SELECT * FROM capture_tasks WHERE id = ?",
            (task_id,),
        ).fetchone()
        if row is None:
            raise KeyError(task_id)
        return self._to_task(row)

    def claim_next(self, worker_id: str) -> CaptureTask | None:
        """Atomically claim the oldest queued task."""

        if not worker_id:
            raise ValueError("worker_id must not be empty")
        with self._database.lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    """
                    SELECT id FROM capture_tasks
                    WHERE status = ?
                    ORDER BY created_at, id
                    LIMIT 1
                    """,
                    (TaskStatus.QUEUED.value,),
                ).fetchone()
                if row is None:
                    self._connection.execute("COMMIT")
                    return None
                timestamp = _now().isoformat()
                self._connection.execute(
                    """
                    UPDATE capture_tasks
                    SET status = ?, worker_id = ?, updated_at = ?
                    WHERE id = ? AND status = ?
                    """,
                    (
                        TaskStatus.RUNNING.value,
                        worker_id,
                        timestamp,
                        row["id"],
                        TaskStatus.QUEUED.value,
                    ),
                )
                self._connection.execute("COMMIT")
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise
        return self.get(row["id"])

    def complete_stage(
        self,
        task_id: str,
        stage: TaskStage,
        artifact: str,
    ) -> CaptureTask:
        """Checkpoint one stage without replacing earlier artifacts."""

        current = self.get(task_id)
        self._require_mutable(current)
        if current.status is not TaskStatus.RUNNING:
            raise ValueError("task must be claimed before completing a stage")
        if stage is not current.stage:
            raise ValueError("stage does not match current task stage")
        artifacts = dict(current.artifacts)
        artifacts[stage.value] = artifact
        index = _STAGES.index(stage)
        is_last = index == len(_STAGES) - 1
        next_stage = stage if is_last else _STAGES[index + 1]
        next_status = TaskStatus.COMPLETED if is_last else TaskStatus.RUNNING
        self._connection.execute(
            """
            UPDATE capture_tasks
            SET status = ?, stage = ?, updated_at = ?, artifacts_json = ?,
                error_json = ?, worker_id = ?
            WHERE id = ?
            """,
            (
                next_status.value,
                next_stage.value,
                _now().isoformat(),
                _encode_items(artifacts),
                _encode_error(None),
                None if is_last else self._worker_id(task_id),
                task_id,
            ),
        )
        return self.get(task_id)

    def fail_stage(self, task_id: str, stage: TaskStage, error: str) -> CaptureTask:
        """Record a typed terminal error without storing provider detail."""

        current = self.get(task_id)
        self._require_mutable(current)
        if current.status is not TaskStatus.RUNNING:
            raise ValueError("task must be claimed before failing a stage")
        if not error:
            raise ValueError("error code must not be empty")
        self._connection.execute(
            """
            UPDATE capture_tasks
            SET status = ?, stage = ?, updated_at = ?, error_json = ?, worker_id = NULL
            WHERE id = ?
            """,
            (
                TaskStatus.FAILED.value,
                stage.value,
                _now().isoformat(),
                _encode_error(error),
                task_id,
            ),
        )
        return self.get(task_id)

    def reset_from_stage(self, task_id: str, stage: TaskStage) -> CaptureTask:
        """Explicitly requeue a terminal task from one stage."""

        current = self.get(task_id)
        if current.status not in _TERMINAL:
            raise ValueError("only terminal tasks can be reset")
        start = _STAGES.index(stage)
        artifacts = {
            key: value
            for key, value in current.artifacts.items()
            if _STAGES.index(TaskStage(key)) < start
        }
        self._connection.execute(
            """
            UPDATE capture_tasks
            SET status = ?, stage = ?, updated_at = ?, artifacts_json = ?,
                error_json = ?, worker_id = NULL
            WHERE id = ?
            """,
            (
                TaskStatus.QUEUED.value,
                stage.value,
                _now().isoformat(),
                _encode_items(artifacts),
                _encode_error(None),
                task_id,
            ),
        )
        return self.get(task_id)

    def find_completed_by_fingerprint(self, fingerprint: str) -> CaptureTask | None:
        """Return the newest completed task for a content fingerprint."""

        row = self._connection.execute(
            """
            SELECT * FROM capture_tasks
            WHERE fingerprint = ? AND status = ?
            ORDER BY updated_at DESC
            LIMIT 1
            """,
            (fingerprint, TaskStatus.COMPLETED.value),
        ).fetchone()
        return None if row is None else self._to_task(row)

    def delete_if_queued(self, task_id: str) -> bool:
        """Remove only a task that has not been claimed or charged."""

        cursor = self._connection.execute(
            "DELETE FROM capture_tasks WHERE id = ? AND status = ?",
            (task_id, TaskStatus.QUEUED.value),
        )
        return cursor.rowcount == 1

    def set_input_ref(self, task_id: str, input_ref: str) -> CaptureTask:
        """Bind a server-controlled input reference exactly once while queued."""

        if not input_ref:
            raise ValueError("input reference must not be empty")
        current = self.get(task_id)
        if current.status is not TaskStatus.QUEUED:
            raise ValueError("input reference can only be bound while queued")
        if current.input_ref is not None:
            raise ValueError("input reference is already bound")
        self._connection.execute(
            "UPDATE capture_tasks SET input_ref = ?, updated_at = ? WHERE id = ?",
            (input_ref, _now().isoformat(), task_id),
        )
        return self.get(task_id)

    def heartbeat(self, task_id: str, worker_id: str) -> bool:
        """Refresh one running claim only for its owning worker."""

        cursor = self._connection.execute(
            """
            UPDATE capture_tasks SET updated_at = ?
            WHERE id = ? AND status = ? AND worker_id = ?
            """,
            (
                _now().isoformat(),
                task_id,
                TaskStatus.RUNNING.value,
                worker_id,
            ),
        )
        return cursor.rowcount == 1

    def release_stale_claims(self, stale_before: datetime) -> int:
        """Requeue running tasks whose heartbeat predates an aware UTC cutoff."""

        if stale_before.tzinfo is None:
            raise ValueError("stale_before must be timezone-aware")
        cursor = self._connection.execute(
            """
            UPDATE capture_tasks
            SET status = ?, worker_id = NULL, updated_at = ?
            WHERE status = ? AND updated_at < ?
            """,
            (
                TaskStatus.QUEUED.value,
                _now().isoformat(),
                TaskStatus.RUNNING.value,
                stale_before.isoformat(),
            ),
        )
        return cursor.rowcount

    def list_tasks(self) -> tuple[CaptureTask, ...]:
        """List tasks newest first without exposing stored content."""

        rows = self._connection.execute(
            "SELECT * FROM capture_tasks ORDER BY created_at DESC, id DESC"
        ).fetchall()
        return tuple(self._to_task(row) for row in rows)

    def delete_terminal(self, task_id: str) -> bool:
        """Delete only a completed or failed task record."""

        cursor = self._connection.execute(
            """
            DELETE FROM capture_tasks
            WHERE id = ? AND status IN (?, ?)
            """,
            (task_id, TaskStatus.COMPLETED.value, TaskStatus.FAILED.value),
        )
        return cursor.rowcount == 1

    def sum_audio_seconds(self, month: str) -> float:
        """Sum completed audio seconds for a UTC ``YYYY-MM`` month."""

        if re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", month) is None:
            raise ValueError("month must use YYYY-MM")
        row = self._connection.execute(
            """
            SELECT COALESCE(SUM(media_seconds), 0.0) AS total
            FROM capture_tasks
            WHERE status = ? AND substr(created_at, 1, 7) = ?
            """,
            (TaskStatus.COMPLETED.value, month),
        ).fetchone()
        return float(row["total"])

    def _worker_id(self, task_id: str) -> str | None:
        row = self._connection.execute(
            "SELECT worker_id FROM capture_tasks WHERE id = ?",
            (task_id,),
        ).fetchone()
        return None if row is None else row["worker_id"]

    @staticmethod
    def _require_mutable(task: CaptureTask) -> None:
        if task.status in _TERMINAL:
            raise ValueError("terminal task requires an explicit reset")

    @staticmethod
    def _to_task(row: object) -> CaptureTask:
        artifacts_payload = json.loads(row["artifacts_json"])
        error_payload = json.loads(row["error_json"])
        if artifacts_payload.get("schema_version") != _SCHEMA_VERSION:
            raise ValueError("unsupported artifact schema")
        if error_payload.get("schema_version") != _SCHEMA_VERSION:
            raise ValueError("unsupported error schema")
        return CaptureTask(
            id=row["id"],
            source=CaptureSource(row["source"]),
            status=TaskStatus(row["status"]),
            stage=TaskStage(row["stage"]),
            fingerprint=row["fingerprint"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            media_seconds=row["media_seconds"],
            artifacts=dict(artifacts_payload["items"]),
            error_code=error_payload["code"],
            input_ref=row["input_ref"],
        )
