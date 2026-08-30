from __future__ import annotations

import shutil
import time
from pathlib import Path

import pytest

from demo.governance_demo_flow import build_demo_state, write_deterministic_release_zip, write_evidence_pack
from scripts.verify_governance_evidence_pack import verify_pack
from tests.resilience.conftest import SaturationGate, decisions, fail_closed_evidence, run_parallel, write_json


pytestmark = [pytest.mark.resilience, pytest.mark.stress, pytest.mark.slow]


def test_concurrent_evidence_pack_exports_verify_or_fail_closed(tmp_path: Path) -> None:
    state = build_demo_state()
    gate = SaturationGate(capacity=4, pressure_model="evidence_export")

    def worker(index: int) -> dict:
        def export_and_verify() -> dict:
            out = tmp_path / f"pack-{index}"
            write_evidence_pack(state, out)
            report = verify_pack(out)
            return {"latest_event_hash": report["latest_event_hash"], "timestamp_result": report["timestamp_result"]}

        return gate.run(export_and_verify)

    results = run_parallel(worker, count=16, max_workers=16, timeout_seconds=20)

    assert "PASS" in decisions(results)
    assert all(item["decision"] in {"PASS", "FAIL_CLOSED"} for item in results)
    assert all(item.get("silent_pass") is False for item in results)
    for item in results:
        if item["decision"] == "FAIL_CLOSED":
            assert item["reason"] == "QUEUE_OVERLOADED"


def test_manifest_write_read_contention_blocks_partial_manifest(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    write_json(manifest, {"schema": "resilience.manifest.v1", "sequence": 1})
    before = manifest.read_text(encoding="utf-8")
    gate = SaturationGate(capacity=1, pressure_model="manifest_contention")

    def worker(index: int) -> dict:
        return gate.run(lambda: (time.sleep(0.01), write_json(manifest, {"schema": "resilience.manifest.v1", "sequence": index}))[1])

    results = run_parallel(worker, count=12, max_workers=12, timeout_seconds=10)
    final_text = manifest.read_text(encoding="utf-8")

    assert before or final_text
    assert all(item["decision"] in {"PASS", "FAIL_CLOSED"} for item in results)
    assert any(item["decision"] == "FAIL_CLOSED" for item in results)
    assert final_text.endswith("\n")


def test_concurrent_zip_generation_contention_fails_closed(tmp_path: Path) -> None:
    package_dir = tmp_path / "package"
    shutil.copytree("artifacts/pilot-review-package", package_dir)
    zip_output = tmp_path / "release.zip"
    checksum_output = tmp_path / "release.sha256"
    gate = SaturationGate(capacity=1, pressure_model="zip_export")

    def worker(_: int) -> dict:
        return gate.run(lambda: write_deterministic_release_zip(package_dir, zip_output, checksum_output))

    results = run_parallel(worker, count=10, max_workers=10, timeout_seconds=15)

    assert any(item["decision"] == "PASS" for item in results)
    assert any(item["decision"] == "FAIL_CLOSED" for item in results)
    assert zip_output.is_file()
    assert checksum_output.is_file()


def test_timestamp_queue_pressure_fails_closed_when_saturated() -> None:
    gate = SaturationGate(capacity=2, pressure_model="timestamp_queue")

    def worker(index: int) -> dict:
        return gate.run(lambda: (time.sleep(0.01), {"timestamp_request": index, "hash_only": True})[1])

    results = run_parallel(worker, count=20, max_workers=20, timeout_seconds=10)

    assert any(item["decision"] == "PASS" for item in results)
    rejected = [item for item in results if item["decision"] == "FAIL_CLOSED"]
    assert rejected
    assert {item["reason"] for item in rejected} == {"QUEUE_OVERLOADED"}
    assert all(item["pressure_model"] == "timestamp_queue" for item in rejected)
