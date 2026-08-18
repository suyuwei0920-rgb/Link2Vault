from __future__ import annotations

import pytest
from link2vault.worker.retry import RetryPolicy, run_with_retry


class SyntheticFailure(RuntimeError):
    def __init__(self, *, retryable: bool) -> None:
        super().__init__("safe failure")
        self.retryable = retryable


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_transient_failure_uses_one_two_four_second_delays() -> None:
    attempts = 0
    delays: list[float] = []

    async def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 4:
            raise SyntheticFailure(retryable=True)
        return "ok"

    async def sleeper(delay: float) -> None:
        delays.append(delay)

    result = await run_with_retry(operation, RetryPolicy(), sleeper=sleeper)

    assert result == "ok"
    assert attempts == 4
    assert delays == [1.0, 2.0, 4.0]


@pytest.mark.anyio
async def test_stops_after_maximum_three_retries() -> None:
    attempts = 0

    async def operation() -> None:
        nonlocal attempts
        attempts += 1
        raise SyntheticFailure(retryable=True)

    with pytest.raises(SyntheticFailure):
        await run_with_retry(operation, RetryPolicy(), sleeper=lambda _delay: _noop())

    assert attempts == 4


@pytest.mark.anyio
@pytest.mark.parametrize("code", ["AUTH", "QUOTA", "INVALID_INPUT"])
async def test_non_retryable_categories_run_once(code: str) -> None:
    attempts = 0

    async def operation() -> None:
        nonlocal attempts
        attempts += 1
        error = SyntheticFailure(retryable=False)
        error.code = code
        raise error

    with pytest.raises(SyntheticFailure):
        await run_with_retry(operation, RetryPolicy(), sleeper=lambda _delay: _noop())

    assert attempts == 1


async def _noop() -> None:
    return None
