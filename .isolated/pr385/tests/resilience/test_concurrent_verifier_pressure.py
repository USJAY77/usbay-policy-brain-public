from __future__ import annotations

from pathlib import Path

import pytest

from scripts.verify_governance_evidence_pack import verify_pack
from tests.resilience.conftest import fail_closed_evidence, run_parallel


pytestmark = [pytest.mark.resilience, pytest.mark.stress, pytest.mark.slow]

PACK_DIR = Path("artifacts/governance-demo-evidence-pack")


def _verify_once(_: int) -> dict:
    try:
        report = verify_pack(PACK_DIR)
    except Exception as exc:  # pragma: no cover - assertion reports exact fail-closed evidence
        return fail_closed_evidence(
            reason="OFFLINE_VERIFIER_UNAVAILABLE",
            pressure_model="concurrent_verifier",
            details={"error_type": type(exc).__name__},
        )
    return {
        "decision": "PASS",
        "verify_pass": report["result"] == "PASS",
        "timestamp_verify_pass": report["timestamp_result"] == "PASS",
        "latest_event_hash": report["latest_event_hash"],
        "timestamp_hash": report["timestamp_hash"],
        "silent_pass": False,
    }


def test_parallel_verify_pass_and_timestamp_verify_pass_are_stable() -> None:
    results = run_parallel(_verify_once, count=32, max_workers=8, timeout_seconds=20)

    assert all(item["decision"] == "PASS" for item in results)
    assert all(item["verify_pass"] is True for item in results)
    assert all(item["timestamp_verify_pass"] is True for item in results)
    assert len({item["latest_event_hash"] for item in results}) == 1
    assert len({item["timestamp_hash"] for item in results}) == 1


def test_verifier_pressure_missing_pack_fails_closed(tmp_path: Path) -> None:
    missing_pack = tmp_path / "missing-pack"

    def worker(_: int) -> dict:
        try:
            verify_pack(missing_pack)
        except Exception as exc:
            return fail_closed_evidence(
                reason="OFFLINE_VERIFIER_UNAVAILABLE",
                pressure_model="concurrent_verifier",
                details={"error_type": type(exc).__name__},
            )
        return {"decision": "PASS", "silent_pass": True}

    results = run_parallel(worker, count=8, max_workers=4, timeout_seconds=10)

    assert all(item["decision"] == "FAIL_CLOSED" for item in results)
    assert all(item["silent_pass"] is False for item in results)
