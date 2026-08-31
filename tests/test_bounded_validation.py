from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from scripts.run_bounded_validation import OBSERVABILITY_ENV_ALLOWLIST, _hash_file, _timeout_for_lane, main


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.critical
@pytest.mark.governance
def test_bounded_validation_pass_writes_hash_only_evidence(tmp_path: Path) -> None:
    evidence = tmp_path / "validation.json"

    result = main(
        [
            "--lane",
            "fast_pr",
            "--timeout-seconds",
            "10",
            "--evidence-output",
            str(evidence),
            "--",
            sys.executable,
            "-c",
            "print('ok')",
        ]
    )

    record = _read(evidence)
    assert result == 0
    assert record["status"] == "PASS"
    assert record["reason_code"] == "VALIDATION_PASSED"
    assert record["fail_closed"] is False
    assert "command_sha256" in record
    assert "print('ok')" not in json.dumps(record)


@pytest.mark.critical
@pytest.mark.governance
def test_bounded_validation_timeout_fails_closed_with_reason_code(tmp_path: Path) -> None:
    evidence = tmp_path / "timeout.json"

    result = main(
        [
            "--lane",
            "fast_pr",
            "--timeout-seconds",
            "1",
            "--evidence-output",
            str(evidence),
            "--",
            sys.executable,
            "-c",
            "import time; time.sleep(5)",
        ]
    )

    record = _read(evidence)
    assert result == 124
    assert record["status"] == "TIMEOUT"
    assert record["reason_code"] == "VALIDATION_TIMEOUT_FAST_PR"
    assert record["fail_closed"] is True
    assert record["partial_audit_preserved"] is True


@pytest.mark.critical
@pytest.mark.governance
def test_bounded_validation_failed_command_fails_closed(tmp_path: Path) -> None:
    evidence = tmp_path / "failed.json"

    result = main(
        [
            "--lane",
            "dependency",
            "--timeout-seconds",
            "10",
            "--evidence-output",
            str(evidence),
            "--",
            sys.executable,
            "-c",
            "raise SystemExit(7)",
        ]
    )

    record = _read(evidence)
    assert result == 7
    assert record["status"] == "FAIL"
    assert record["reason_code"] == "VALIDATION_COMMAND_FAILED"
    assert record["fail_closed"] is True


def test_bounded_validation_rejects_timeout_above_lane_max() -> None:
    with pytest.raises(SystemExit, match="VALIDATION_TIMEOUT_EXCEEDS_LANE_MAX"):
        _timeout_for_lane("fast_pr", 601)


def test_bounded_validation_rejects_unsafe_command(tmp_path: Path) -> None:
    evidence = tmp_path / "unsafe.json"

    with pytest.raises(SystemExit, match="VALIDATION_COMMAND_UNSAFE"):
        main(
            [
                "--lane",
                "fast_pr",
                "--timeout-seconds",
                "10",
                "--evidence-output",
                str(evidence),
                "--",
                sys.executable,
                "-c",
                "print('PRIVATE KEY')",
            ]
        )


@pytest.mark.critical
@pytest.mark.governance
def test_bounded_validation_writes_privacy_preserving_observability(tmp_path: Path, monkeypatch) -> None:
    evidence = tmp_path / "validation.json"
    observability = tmp_path / "observability.json"
    collection = tmp_path / "collection.txt"
    collection.write_text(
        "tests/test_gateway_app.py::test_device_trust_requires_verifier_continuity_quorum\n",
        encoding="utf-8",
    )
    for name in OBSERVABILITY_ENV_ALLOWLIST:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_WORKFLOW", "codex-autofix-ci")
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token-must-not-appear")
    monkeypatch.setenv("USBAY_SECRET", "fake-secret-must-not-appear")

    result = main(
        [
            "--lane",
            "fast_pr",
            "--timeout-seconds",
            "10",
            "--evidence-output",
            str(evidence),
            "--observability-output",
            str(observability),
            "--collection-file",
            str(collection),
            "--",
            sys.executable,
            "-c",
            "print('ok')",
        ]
    )

    record = _read(observability)
    encoded = json.dumps(record, sort_keys=True)
    assert result == 0
    assert record["schema"] == "usbay.ci_nondeterminism_observability.v1"
    assert record["status"] == "PASS"
    assert record["tested_sha"]
    assert record["workflow_context"]["raw_values_persisted"] is False
    assert record["workflow_context"]["present"] == ["GITHUB_SHA", "GITHUB_WORKFLOW"]
    assert "a" * 40 not in encoded
    assert "codex-autofix-ci" not in encoded
    assert "fake-token-must-not-appear" not in encoded
    assert "fake-secret-must-not-appear" not in encoded
    assert "GITHUB_TOKEN" not in encoded
    assert "USBAY_SECRET" not in encoded
    assert record["dependency_fingerprint"]["freeze_sha256"]
    assert record["collection_fingerprint"]["test_node_count"] == 1
    assert record["collection_fingerprint"]["test_order_sha256"]
    assert record["privacy_boundary"]["environment_presence_only"] is True
    assert record["privacy_boundary"]["raw_environment_values_allowlisted"] is False
    assert record["privacy_boundary"]["raw_command_persisted"] is False


def test_collection_fingerprint_is_deterministic_for_identical_collection(tmp_path: Path) -> None:
    collection = tmp_path / "collection.txt"
    collection.write_text(
        "\n".join(
            [
                "tests/test_gateway_app.py::test_device_trust_requires_verifier_continuity_quorum",
                "tests/test_gateway_app.py::test_frontend_query_cannot_override_device_identity_lifecycle",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    first = _hash_file(collection)
    second = _hash_file(collection)

    assert first == second
    assert first["present"] is True
    assert first["test_node_count"] == 2


def test_observability_write_failure_fails_closed_after_command(tmp_path: Path) -> None:
    evidence = tmp_path / "validation.json"

    with pytest.raises(OSError):
        main(
            [
                "--lane",
                "fast_pr",
                "--timeout-seconds",
                "10",
                "--evidence-output",
                str(evidence),
                "--observability-output",
                "/dev/null/observability.json",
                "--",
                sys.executable,
                "-c",
                "print('ok')",
            ]
        )
