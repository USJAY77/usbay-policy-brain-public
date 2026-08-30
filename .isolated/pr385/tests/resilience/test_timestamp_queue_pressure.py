from __future__ import annotations

import time

import pytest

from tests.helpers.rfc3161_timestamp_policy import timestamp_queue_overload_evidence
from tests.resilience.conftest import SaturationGate, decisions, run_parallel


pytestmark = [pytest.mark.resilience, pytest.mark.stress, pytest.mark.slow]


def test_rfc3161_timestamp_queue_pressure_fails_closed_when_saturated() -> None:
    gate = SaturationGate(capacity=3, pressure_model="rfc3161_timestamp_queue")

    def worker(index: int) -> dict:
        if index >= 3:
            return timestamp_queue_overload_evidence(queue_depth=index + 1, queue_capacity=3)
        return gate.run(lambda: (time.sleep(0.01), {"hash_only": True, "timestamp_request": index})[1])

    results = run_parallel(worker, count=24, max_workers=12, timeout_seconds=10)
    rejected = [item for item in results if item["decision"] == "FAIL_CLOSED"]

    assert "PASS" in decisions(results)
    assert rejected
    assert all(item["reason"] == "RFC3161_TIMESTAMP_QUEUE_OVERLOADED" for item in rejected)
    assert all(item["silent_pass"] is False for item in rejected)
