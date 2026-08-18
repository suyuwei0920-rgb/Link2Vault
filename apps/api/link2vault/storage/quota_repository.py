"""Atomic monthly audio quota reservations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from link2vault.storage.database import Database


class QuotaExceeded(ValueError):
    """Raised before paid work when the configured month cap is exceeded."""


@dataclass(frozen=True)
class QuotaReservation:
    """One persistent audio allocation."""

    task_id: str
    month: str
    seconds: float


class QuotaRepository:
    """Reserve audio seconds using an immediate SQLite transaction."""

    def __init__(self, data_dir: Path) -> None:
        self._database = Database(data_dir)
        self._connection = self._database.connection

    def close(self) -> None:
        self._database.close()

    def reserve_audio_seconds(
        self,
        task_id: str,
        seconds: float,
        monthly_limit: float,
        *,
        now: datetime | None = None,
    ) -> QuotaReservation:
        """Atomically reject any reservation that would cross the month cap."""

        if not task_id:
            raise ValueError("task_id must not be empty")
        if not 0 < seconds <= 240 * 60:
            raise ValueError("audio duration must be between zero and 240 minutes")
        if monthly_limit <= 0:
            raise ValueError("monthly limit must be positive")
        timestamp = now or datetime.now(UTC)
        month = timestamp.strftime("%Y-%m")
        with self._database.lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    """
                    SELECT COALESCE(SUM(seconds), 0.0) AS total
                    FROM quota_reservations
                    WHERE month = ? AND status = 'reserved'
                    """,
                    (month,),
                ).fetchone()
                if float(row["total"]) + seconds > monthly_limit:
                    self._connection.execute("ROLLBACK")
                    raise QuotaExceeded("monthly audio quota exceeded")
                self._connection.execute(
                    """
                    INSERT INTO quota_reservations (
                        task_id, month, seconds, status, created_at, updated_at
                    ) VALUES (?, ?, ?, 'reserved', ?, ?)
                    """,
                    (
                        task_id,
                        month,
                        seconds,
                        timestamp.isoformat(),
                        timestamp.isoformat(),
                    ),
                )
                self._connection.execute("COMMIT")
            except QuotaExceeded:
                raise
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise
        return QuotaReservation(task_id=task_id, month=month, seconds=seconds)

    def release(self, task_id: str, *, now: datetime | None = None) -> None:
        """Release a reservation when task creation or validation fails."""

        timestamp = now or datetime.now(UTC)
        self._connection.execute(
            """
            UPDATE quota_reservations
            SET status = 'released', updated_at = ?
            WHERE task_id = ? AND status = 'reserved'
            """,
            (timestamp.isoformat(), task_id),
        )

    def sum_reserved_seconds(self, month: str) -> float:
        """Return active reserved seconds for a UTC month."""

        row = self._connection.execute(
            """
            SELECT COALESCE(SUM(seconds), 0.0) AS total
            FROM quota_reservations
            WHERE month = ? AND status = 'reserved'
            """,
            (month,),
        ).fetchone()
        return float(row["total"])
