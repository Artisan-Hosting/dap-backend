"""Helpers for bounded parallel execution inside plugins."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")


def parallel_map(items: Iterable[T], func: Callable[[T], R], max_workers: int = 8) -> list[R]:
    values = list(items)
    if not values:
        return []
    if len(values) == 1:
        return [func(values[0])]

    worker_count = max(1, min(max_workers, len(values)))
    results: list[R | None] = [None] * len(values)
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        future_map = {pool.submit(func, value): index for index, value in enumerate(values)}
        for future in as_completed(future_map):
            index = future_map[future]
            results[index] = future.result()

    return [result for result in results if result is not None]
