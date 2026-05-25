from __future__ import annotations

import time

import pytest

from tests.resilience.conftest import assert_elapsed_within, fail_closed_evidence


pytestmark = [pytest.mark.resilience, pytest.mark.stress, pytest.mark.slow]


class ReplayStormGate:
    def __init__(self, *, max_unique_nonces: int):
        self.max_unique_nonces = max_unique_nonces
        self.used_nonces: set[str] = set()

    def accept(self, nonce: str) -> dict:
        if not nonce:
            return fail_closed_evidence(reason="NONCE_MISSING", pressure_model="replay_storm")
        if nonce in self.used_nonces:
            return fail_closed_evidence(reason="REPLAY_DETECTED", pressure_model="replay_storm")
        if len(self.used_nonces) >= self.max_unique_nonces:
            return fail_closed_evidence(reason="REPLAY_QUEUE_OVERLOADED", pressure_model="replay_storm")
        self.used_nonces.add(nonce)
        return {"decision": "PASS", "nonce_hash_only": True, "silent_pass": False}


def test_10k_replay_request_simulation_rejects_duplicate_nonce() -> None:
    started = time.perf_counter()
    gate = ReplayStormGate(max_unique_nonces=32)

    results = [gate.accept("same-replay-nonce") for _ in range(10_000)]

    assert results[0]["decision"] == "PASS"
    assert all(item["decision"] == "FAIL_CLOSED" for item in results[1:])
    assert {item["reason"] for item in results[1:]} == {"REPLAY_DETECTED"}
    assert all(item.get("silent_pass") is False for item in results)
    assert_elapsed_within(started)


def test_nonce_pressure_over_capacity_fails_closed() -> None:
    gate = ReplayStormGate(max_unique_nonces=128)

    results = [gate.accept(f"nonce-{index}") for index in range(256)]

    assert sum(1 for item in results if item["decision"] == "PASS") == 128
    overloaded = [item for item in results if item["decision"] == "FAIL_CLOSED"]
    assert len(overloaded) == 128
    assert {item["reason"] for item in overloaded} == {"REPLAY_QUEUE_OVERLOADED"}
    assert all(item["pressure_model"] == "replay_storm" for item in overloaded)
