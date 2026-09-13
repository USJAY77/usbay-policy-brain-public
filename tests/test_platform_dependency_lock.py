from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from governance.dependency_artifact_provenance import (
    DENY,
    ELIGIBLE,
    FAILED,
    PARTIAL,
    PROVEN,
    UNKNOWN,
    EligibilityDecision,
    evaluate_artifact_evidence,
)
from scripts.verify_platform_dependency_lock import (
    parse_hash_locked_requirements,
    validate_platform_lock,
)


ROOT = Path(__file__).resolve().parents[1]
LINUX_HASH = "1" * 64
MACOS_HASH = "2" * 64
RECORD_HASH = "sha256:" + ("3" * 64)


def _lock(digest: str, *, version: str = "1.0.0") -> str:
    return f"synthetic-package=={version} --hash=sha256:{digest}\n"


def _policy(linux_text: str) -> dict:
    return {
        "policy_version": "synthetic-policy-v1",
        "target_lock_id": "macos-arm64-cpython311",
        "target": {
            "os": "macos",
            "architecture": "arm64",
            "python_implementation": "cpython",
            "python_version": "3.11",
            "python_tag": "cp311",
        },
        "parity": {
            "linux_lock_sha256": hashlib.sha256(linux_text.encode()).hexdigest(),
            "shared_versions_must_match": True,
            "platform_exceptions": [],
        },
    }


def _record(*, digest: str = MACOS_HASH) -> dict:
    return {
        "record_id": "synthetic-record-1",
        "record_hash": RECORD_HASH,
        "package": {"normalized_project_name": "synthetic-package", "version": "1.0.0"},
        "artifact": {"sha256": digest},
    }


def _decision(*, state: str = PROVEN, reason: str = "") -> EligibilityDecision:
    if state == PROVEN:
        return EligibilityDecision(ELIGIBLE, PROVEN, (), "synthetic-record-1", RECORD_HASH)
    return EligibilityDecision(DENY, state, (reason or "DEPENDENCY_ARTIFACT_PROVENANCE_NOT_PROVEN",), "synthetic-record-1", RECORD_HASH)


def _manifest(linux_text: str, macos_text: str, policy: dict, *, digest: str = MACOS_HASH) -> dict:
    return {
        "schema": "usbay.platform_dependency_lock.v1",
        "lock_id": policy["target_lock_id"],
        "platform": dict(policy["target"]),
        "logical_dependency_graph_sha256": "sha256:" + ("4" * 64),
        "linux_reference_lock_sha256": hashlib.sha256(linux_text.encode()).hexdigest(),
        "generated_requirements_sha256": hashlib.sha256(macos_text.encode()).hexdigest(),
        "artifact_records": [
            {
                "package": "synthetic-package",
                "version": "1.0.0",
                "sha256": digest,
                "record_id": "synthetic-record-1",
            }
        ],
        "platform_exception_ids": [],
        "approval_event_ids": ["synthetic-human-approval-event"],
        "external_checkpoint_references": ["sha256:" + ("5" * 64)],
        "created_at": "2026-09-04T12:00:00Z",
        "policy_version": policy["policy_version"],
        "previous_manifest_hash": "sha256:" + ("0" * 64),
        "manifest_hash": "sha256:" + ("6" * 64),
    }


def _validate(*, decision: EligibilityDecision | None = None):
    linux_text = _lock(LINUX_HASH)
    macos_text = _lock(MACOS_HASH)
    policy = _policy(linux_text)
    return validate_platform_lock(
        linux_text=linux_text,
        macos_text=macos_text,
        manifest=_manifest(linux_text, macos_text, policy),
        records={"synthetic-record-1": _record()},
        decisions={"synthetic-record-1": decision or _decision()},
        policy=policy,
    )


def test_complete_synthetic_platform_lock_is_deterministically_valid():
    first = _validate()
    second = _validate()
    assert first == second
    assert first.valid is True
    assert first.decision == "ALLOW"


def test_repository_policy_is_fail_closed_and_authorizes_no_artifact():
    policy = json.loads((ROOT / "governance/dependency_artifact_policy.json").read_text())
    decision = evaluate_artifact_evidence({}, policy, evaluated_at="2026-09-04T12:00:00Z")
    assert policy["status"] == "draft"
    assert policy["default_decision"] == DENY
    assert policy["accepted_signer_identities"] == []
    assert policy["allowed_human_actors"] == []
    assert decision.decision == DENY


@pytest.mark.parametrize(
    ("state", "reason"),
    [
        (UNKNOWN, "DEPENDENCY_ARTIFACT_PROVENANCE_NOT_PROVEN"),
        (PARTIAL, "DEPENDENCY_ARTIFACT_PROVENANCE_NOT_PROVEN"),
        (FAILED, "DEPENDENCY_ARTIFACT_PROVENANCE_NOT_PROVEN"),
        (FAILED, "DEPENDENCY_ARTIFACT_APPROVAL_MISSING"),
        (FAILED, "DEPENDENCY_ARTIFACT_REPLAY"),
        (FAILED, "DEPENDENCY_ARTIFACT_EVIDENCE_STALE"),
        (FAILED, "DEPENDENCY_ARTIFACT_REVOKED"),
        (FAILED, "DEPENDENCY_ARTIFACT_CONFLICT"),
    ],
)
def test_noneligible_evidence_never_enters_platform_lock(state: str, reason: str):
    result = _validate(decision=_decision(state=state, reason=reason))
    assert result.decision == DENY
    assert "DEPENDENCY_ARTIFACT_PROVENANCE_NOT_PROVEN" in result.reason_codes


@pytest.mark.parametrize(
    ("field", "value"),
    [("os", "linux"), ("architecture", "x86_64"), ("python_tag", "cp312")],
)
def test_platform_architecture_and_python_tag_mismatch_deny(field: str, value: str):
    linux_text = _lock(LINUX_HASH)
    macos_text = _lock(MACOS_HASH)
    policy = _policy(linux_text)
    manifest = _manifest(linux_text, macos_text, policy)
    manifest["platform"][field] = value
    result = validate_platform_lock(
        linux_text=linux_text,
        macos_text=macos_text,
        manifest=manifest,
        records={"synthetic-record-1": _record()},
        decisions={"synthetic-record-1": _decision()},
        policy=policy,
    )
    assert result.decision == DENY
    assert "DEPENDENCY_ARTIFACT_PLATFORM_MISMATCH" in result.reason_codes


def test_unauthorized_artifact_hash_substitution_denies():
    linux_text = _lock(LINUX_HASH)
    macos_text = _lock("7" * 64)
    policy = _policy(linux_text)
    manifest = _manifest(linux_text, macos_text, policy, digest="7" * 64)
    result = validate_platform_lock(
        linux_text=linux_text,
        macos_text=macos_text,
        manifest=manifest,
        records={"synthetic-record-1": _record(digest=MACOS_HASH)},
        decisions={"synthetic-record-1": _decision()},
        policy=policy,
    )
    assert result.decision == DENY
    assert "DEPENDENCY_ARTIFACT_BINDING_MISMATCH" in result.reason_codes


def test_missing_record_has_no_fallback_to_linux_or_source_artifact():
    linux_text = _lock(LINUX_HASH)
    macos_text = _lock(MACOS_HASH)
    policy = _policy(linux_text)
    result = validate_platform_lock(
        linux_text=linux_text,
        macos_text=macos_text,
        manifest=_manifest(linux_text, macos_text, policy),
        records={},
        decisions={},
        policy=policy,
    )
    assert result.decision == DENY
    assert "DEPENDENCY_ARTIFACT_PROVENANCE_NOT_PROVEN" in result.reason_codes


@pytest.mark.parametrize(
    "text",
    [
        "synthetic-package==1.0.0\n",
        "synthetic-package>=1.0.0 --hash=sha256:" + ("8" * 64) + "\n",
        "synthetic-package==1.0.0; sys_platform == 'darwin' --hash=sha256:" + ("8" * 64) + "\n",
        "synthetic-package @ https://index.example.test/file.whl\n",
    ],
)
def test_unpinned_unhashed_or_alternate_source_lock_is_rejected(text: str):
    with pytest.raises(ValueError, match="DEPENDENCY_ARTIFACT_LOCK_MALFORMED"):
        parse_hash_locked_requirements(text)


def test_require_hashes_input_is_parsed_without_mutation():
    text = (
        "Synthetic_Package==1.0.0 \\\n"
        "  --hash=sha256:" + ("9" * 64) + " \\\n"
        "  --hash=sha256:" + ("8" * 64) + "\n"
    )
    before = text
    first = parse_hash_locked_requirements(text)
    second = parse_hash_locked_requirements(text)
    assert text == before
    assert first == second
    assert first["synthetic-package"].hashes == ("8" * 64, "9" * 64)


def test_manifest_requires_human_approval_and_external_checkpoint_references():
    linux_text = _lock(LINUX_HASH)
    macos_text = _lock(MACOS_HASH)
    policy = _policy(linux_text)
    manifest = _manifest(linux_text, macos_text, policy)
    manifest["approval_event_ids"] = []
    manifest["external_checkpoint_references"] = []
    result = validate_platform_lock(
        linux_text=linux_text,
        macos_text=macos_text,
        manifest=manifest,
        records={"synthetic-record-1": _record()},
        decisions={"synthetic-record-1": _decision()},
        policy=policy,
    )
    assert result.decision == DENY
    assert "DEPENDENCY_ARTIFACT_EXTERNAL_CHECKPOINT_MISSING" in result.reason_codes
