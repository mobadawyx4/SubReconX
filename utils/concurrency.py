"""Bounded-concurrency helpers built on asyncio."""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")


async def bounded_map(
    func: Callable[[T], Awaitable[R]],
    items: Iterable[T],
    limit: int = 20,
    *,
    return_exceptions: bool = True,
) -> list[Any]:
    """Run *func* over *items* with a semaphore and never leak tasks."""
    semaphore = asyncio.Semaphore(max(1, limit))

    async def _runner(item: T) -> Any:
        async with semaphore:
            try:
                return await func(item)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - isolate per-item failures
                if return_exceptions:
                    return exc
                raise

    tasks = [asyncio.create_task(_runner(item)) for item in items]
    if not tasks:
        return []
    return await asyncio.gather(*tasks)


async def with_timeout(coro: Awaitable[R], timeout: float) -> R | None:
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except (asyncio.TimeoutError, TimeoutError):
        return None


def run_async(coro: Awaitable[R]) -> R:
    return asyncio.run(coro)
