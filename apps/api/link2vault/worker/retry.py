"""Bounded retry policy for explicitly transient provider failures."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class RetryPolicy:
    """Exponential 1/2/4 second delays with at most three retries."""

    max_retries: int = 3
    base_delay_seconds: float = 1.0

    def delay(self, attempt: int) -> float:
        if not 1 <= attempt <= self.max_retries:
            raise ValueError("retry attempt is outside the policy")
        return self.base_delay_seconds * (2 ** (attempt - 1))


async def run_with_retry[T](
    operation: Callable[[], Awaitable[T]],
    policy: RetryPolicy,
    *,
    sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> T:
    """Retry only exceptions that explicitly declare ``retryable=True``."""

    retries = 0
    while True:
        try:
            return await operation()
        except Exception as exc:
            if not getattr(exc, "retryable", False) or retries >= policy.max_retries:
                raise
            retries += 1
            await sleeper(policy.delay(retries))
