from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier

import pytest
from link2vault.storage.quota_repository import QuotaExceeded, QuotaRepository

NOW = datetime(2026, 8, 18, 10, 0, tzinfo=UTC)


def test_reservation_is_persistent_and_can_be_released(tmp_path) -> None:
    repository = QuotaRepository(tmp_path)
    reservation = repository.reserve_audio_seconds(
        "task-a",
        90.5,
        monthly_limit=600,
        now=NOW,
    )

    assert reservation.month == "2026-08"
    assert repository.sum_reserved_seconds("2026-08") == 90.5

    repository.release("task-a", now=NOW)

    assert repository.sum_reserved_seconds("2026-08") == 0.0


def test_concurrent_reservations_cannot_exceed_monthly_limit(tmp_path) -> None:
    first = QuotaRepository(tmp_path)
    second = QuotaRepository(tmp_path)
    barrier = Barrier(2)

    def reserve(repository: QuotaRepository, task_id: str) -> str:
        barrier.wait()
        try:
            repository.reserve_audio_seconds(
                task_id,
                60,
                monthly_limit=100,
                now=NOW,
            )
        except QuotaExceeded:
            return "rejected"
        return "reserved"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda args: reserve(*args),
                [(first, "task-a"), (second, "task-b")],
            )
        )

    assert sorted(results) == ["rejected", "reserved"]
    assert first.sum_reserved_seconds("2026-08") == 60.0


@pytest.mark.parametrize("seconds", [0, -1, 14_400.01])
def test_rejects_zero_negative_or_more_than_four_hours(
    tmp_path,
    seconds: float,
) -> None:
    repository = QuotaRepository(tmp_path)

    with pytest.raises(ValueError, match="duration"):
        repository.reserve_audio_seconds(
            "task-a",
            seconds,
            monthly_limit=36_000,
            now=NOW,
        )
