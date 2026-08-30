from __future__ import annotations

import json
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Iterable

import pytest


pytestmark = [pytest.mark.resilience, pytest.mark.stress, pytest.mark.slow]

DEFAULT_TIMEOUT_SECONDS = 20.0


def fail_closed_evidence(*, reason: str, pressure_model: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema": "usbay.governance_resilience_evidence.v1",
        "decision": "FAIL_CLOSED",
        "reason": reason,
        "pressure_model": pressure_model,
        "details": details or {},
        "silent_pass": False,
    }


def assert_elapsed_within(start: float, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS) -> None:
    elapsed = time.perf_counter() - start
    assert elapsed <= timeout_seconds, fail_closed_evidence(
        reason="RESILIENCE_TEST_TIMEOUT",
        pressure_model="bounded_execution",
        details={"elapsed_seconds": round(elapsed, 3), "timeout_seconds": timeout_seconds},
    )


def run_parallel(
    worker: Callable[[int], Any],
    *,
    count: int,
    max_workers: int,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> list[Any]:
    started = time.perf_counter()
    results: list[Any] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures: list[Future[Any]] = [pool.submit(worker, index) for index in range(count)]
        for future in as_completed(futures, timeout=timeout_seconds):
            results.append(future.result(timeout=timeout_seconds))
    assert len(results) == count, fail_closed_evidence(
        reason="RESILIENCE_PARALLEL_EXECUTION_INCOMPLETE",
        pressure_model="parallel_executor",
        details={"expected": count, "actual": len(results), "max_workers": max_workers},
    )
    assert_elapsed_within(started, timeout_seconds)
    return results


class SaturationGate:
    def __init__(self, *, capacity: int, pressure_model: str):
        self._semaphore = threading.BoundedSemaphore(capacity)
        self._pressure_model = pressure_model

    def run(self, work: Callable[[], Any]) -> dict[str, Any]:
        if not self._semaphore.acquire(blocking=False):
            return fail_closed_evidence(reason="QUEUE_OVERLOADED", pressure_model=self._pressure_model)
        try:
            return {"decision": "PASS", "result": work(), "silent_pass": False}
        finally:
            self._semaphore.release()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def decisions(results: Iterable[dict[str, Any]]) -> list[str]:
    return [str(item.get("decision")) for item in results]
