from __future__ import annotations

import hashlib
import json
from pathlib import Path

from governance.dependency_artifact_provenance import ELIGIBLE, PROVEN, EligibilityDecision
from scripts.verify_platform_dependency_lock import (
    parse_hash_locked_requirements,
    validate_lock_parity,
    validate_platform_lock,
)


ROOT = Path(__file__).resolve().parents[1]


def _lock(package: str, version: str, digest: str) -> str:
    return f"{package}=={version} --hash=sha256:{digest}\n"


def _parity_policy(*, exceptions=None) -> dict:
    return {
        "parity": {
            "shared_versions_must_match": True,
            "platform_exceptions": exceptions or [],
        }
    }


def test_matching_versions_are_parallel_but_hash_authorization_is_platform_specific():
    linux = parse_hash_locked_requirements(_lock("synthetic-package", "1.0.0", "1" * 64))
    macos = parse_hash_locked_requirements(_lock("synthetic-package", "1.0.0", "2" * 64))
    assert linux["synthetic-package"].version == macos["synthetic-package"].version
    assert linux["synthetic-package"].hashes != macos["synthetic-package"].hashes
    assert validate_lock_parity(linux, macos, _parity_policy()).valid is True


def test_shared_dependency_version_mismatch_denies():
    linux = parse_hash_locked_requirements(_lock("synthetic-package", "1.0.0", "1" * 64))
    macos = parse_hash_locked_requirements(_lock("synthetic-package", "2.0.0", "2" * 64))
    result = validate_lock_parity(linux, macos, _parity_policy())
    assert result.decision == "DENY"
    assert result.reason_codes == ("DEPENDENCY_ARTIFACT_UNAUTHORIZED_PLATFORM_EXCEPTION",)


def test_missing_platform_dependency_denies_without_explicit_exception():
    linux = parse_hash_locked_requirements(
        _lock("synthetic-package", "1.0.0", "1" * 64)
        + _lock("linux-only-package", "3.0.0", "3" * 64)
    )
    macos = parse_hash_locked_requirements(_lock("synthetic-package", "1.0.0", "2" * 64))
    assert validate_lock_parity(linux, macos, _parity_policy()).decision == "DENY"


def test_exact_human_approved_platform_exception_is_bounded():
    linux = parse_hash_locked_requirements(
        _lock("synthetic-package", "1.0.0", "1" * 64)
        + _lock("linux-only-package", "3.0.0", "3" * 64)
    )
    macos = parse_hash_locked_requirements(_lock("synthetic-package", "1.0.0", "2" * 64))
    exception = {
        "package": "linux-only-package",
        "side": "linux-only",
        "version": "3.0.0",
        "approval_id": "synthetic-human-approval",
    }
    assert validate_lock_parity(linux, macos, _parity_policy(exceptions=[exception])).valid is True
    exception["version"] = "2.9.0"
    assert validate_lock_parity(linux, macos, _parity_policy(exceptions=[exception])).decision == "DENY"


def test_linux_hash_cannot_substitute_for_macos_artifact_authorization():
    linux_text = _lock("synthetic-package", "1.0.0", "1" * 64)
    macos_text = _lock("synthetic-package", "1.0.0", "1" * 64)
    target = {
        "os": "macos",
        "architecture": "arm64",
        "python_implementation": "cpython",
        "python_version": "3.11",
        "python_tag": "cp311",
    }
    policy = {
        "policy_version": "synthetic-policy-v1",
        "target_lock_id": "macos-arm64-cpython311",
        "target": target,
        "parity": {
            "linux_lock_sha256": hashlib.sha256(linux_text.encode()).hexdigest(),
            "shared_versions_must_match": True,
            "platform_exceptions": [],
        },
    }
    record_hash = "sha256:" + ("4" * 64)
    manifest = {
        "schema": "usbay.platform_dependency_lock.v1",
        "lock_id": policy["target_lock_id"],
        "platform": target,
        "logical_dependency_graph_sha256": "sha256:" + ("5" * 64),
        "linux_reference_lock_sha256": hashlib.sha256(linux_text.encode()).hexdigest(),
        "generated_requirements_sha256": hashlib.sha256(macos_text.encode()).hexdigest(),
        "artifact_records": [{"package": "synthetic-package", "version": "1.0.0", "sha256": "1" * 64, "record_id": "mac-record"}],
        "platform_exception_ids": [],
        "approval_event_ids": ["synthetic-human-approval"],
        "external_checkpoint_references": ["sha256:" + ("6" * 64)],
        "created_at": "2026-09-04T12:00:00Z",
        "policy_version": policy["policy_version"],
        "previous_manifest_hash": "sha256:" + ("0" * 64),
        "manifest_hash": "sha256:" + ("7" * 64),
    }
    records = {
        "mac-record": {
            "record_id": "mac-record",
            "record_hash": record_hash,
            "package": {"normalized_project_name": "synthetic-package", "version": "1.0.0"},
            "artifact": {"sha256": "2" * 64},
        }
    }
    decisions = {"mac-record": EligibilityDecision(ELIGIBLE, PROVEN, (), "mac-record", record_hash)}
    result = validate_platform_lock(
        linux_text=linux_text,
        macos_text=macos_text,
        manifest=manifest,
        records=records,
        decisions=decisions,
        policy=policy,
    )
    assert result.decision == "DENY"
    assert "DEPENDENCY_ARTIFACT_BINDING_MISMATCH" in result.reason_codes


def test_repository_linux_lock_hash_is_unchanged_and_policy_bound():
    linux_bytes = (ROOT / "requirements-ci.txt").read_bytes()
    policy = json.loads((ROOT / "governance/dependency_artifact_policy.json").read_text())
    assert hashlib.sha256(linux_bytes).hexdigest() == policy["parity"]["linux_lock_sha256"]
    assert policy["target"]["os"] == "macos"
    assert policy["target"]["architecture"] == "arm64"
    assert policy["default_decision"] == "DENY"
