from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from governance.policy_pack import redacted_policy_payload

RUNTIME_PARITY_SCHEMA = "usbay.governance_runtime_parity.v1"
RUNTIME_PARITY_ERROR_REGISTRY_PATH = Path("governance/runtime_parity_errors.json")
RUNTIME_PARITY_ERROR_SCHEMA = "usbay.governance_runtime_parity_error_registry.v1"
RUNTIME_PARITY_ERROR_CODES = (
    "RUNTIME_PARITY_RUNTIME_HASH_MISSING",
    "RUNTIME_PARITY_POLICY_HASH_MISMATCH",
    "RUNTIME_PARITY_EVIDENCE_MANIFEST_MISSING",
    "RUNTIME_PARITY_UNKNOWN_SOURCE",
    "RUNTIME_PARITY_STALE_COMMIT",
    "RUNTIME_PARITY_ARTIFACT_SIGNATURE_MISMATCH",
    "RUNTIME_PARITY_VERIFIER_FAILURE",
    "RUNTIME_PARITY_DIAGNOSTICS_UNSAFE",
)
PARITY_MATCH = "MATCH"
PARITY_DEGRADED = "DEGRADED"
PARITY_DENY = "DENY"
PARITY_FAIL_CLOSED = "FAIL_CLOSED"
PARITY_HUMAN_REVIEW = "HUMAN_REVIEW"
MODULE_VERSIONS = {"runtime_parity": RUNTIME_PARITY_SCHEMA}
HASH_KEYS = ("commit_hash", "policy_hash", "manifest_hash", "evidence_hash")
FORBIDDEN_MARKERS = (
    "PRIVATE KEY",
    "BEGIN RSA",
    "BEGIN OPENSSH",
    "raw_secret",
    "approval_contents",
    "private_key",
    "token",
    "secret",
)


class RuntimeParityError(RuntimeError):
    pass


@dataclass(frozen=True)
class RuntimeParityResult:
    valid: bool
    parity_status: str
    reason_code: str
    commit_hash: str
    policy_hash: str
    manifest_hash: str
    evidence_hash: str
    build_timestamp: str
    runtime_environment: str
    deployment_source: str
    canonical_reference: str
    canonical_commit_hash: str
    build_artifact_signature_hash: str
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "parity_status": self.parity_status,
            "reason_code": self.reason_code,
            "commit_hash": self.commit_hash,
            "policy_hash": self.policy_hash,
            "manifest_hash": self.manifest_hash,
            "evidence_hash": self.evidence_hash,
            "build_timestamp": self.build_timestamp,
            "runtime_environment": self.runtime_environment,
            "deployment_source": self.deployment_source,
            "canonical_reference": self.canonical_reference,
            "canonical_commit_hash": self.canonical_commit_hash,
            "build_artifact_signature_hash": self.build_artifact_signature_hash,
            "errors": list(self.errors),
        }


def verify_runtime_parity(runtime_state: dict[str, Any], canonical_state: dict[str, Any]) -> RuntimeParityResult:
    try:
        assert_runtime_parity_safe(runtime_state)
        assert_runtime_parity_safe(canonical_state)
    except RuntimeParityError:
        return _result(runtime_state, canonical_state, PARITY_FAIL_CLOSED, "RUNTIME_PARITY_DIAGNOSTICS_UNSAFE", ["RUNTIME_PARITY_DIAGNOSTICS_UNSAFE"])

    errors: list[str] = []
    for key in HASH_KEYS:
        if not _is_sha256_hex(str(runtime_state.get(key, ""))):
            if key == "evidence_hash":
                errors.append("RUNTIME_PARITY_EVIDENCE_MANIFEST_MISSING")
            else:
                errors.append("RUNTIME_PARITY_RUNTIME_HASH_MISSING")
    source = str(runtime_state.get("deployment_source", ""))
    allowed_sources = set(_list(canonical_state.get("approved_deployment_sources")))
    if source not in allowed_sources:
        errors.append("RUNTIME_PARITY_UNKNOWN_SOURCE")

    canonical_commit = _canonical_commit_for_source(source, canonical_state)
    stale_allowed = set(_list(canonical_state.get("allowed_stale_commits")))
    if canonical_commit and runtime_state.get("commit_hash") != canonical_commit:
        if runtime_state.get("commit_hash") in stale_allowed:
            errors.append("RUNTIME_PARITY_STALE_COMMIT")
        else:
            errors.append("RUNTIME_PARITY_UNKNOWN_SOURCE")
    if not canonical_commit:
        errors.append("RUNTIME_PARITY_UNKNOWN_SOURCE")

    for runtime_key, canonical_key, code in (
        ("policy_hash", "expected_policy_hash", "RUNTIME_PARITY_POLICY_HASH_MISMATCH"),
        ("manifest_hash", "expected_manifest_hash", "RUNTIME_PARITY_RUNTIME_HASH_MISSING"),
        ("evidence_hash", "expected_evidence_hash", "RUNTIME_PARITY_EVIDENCE_MANIFEST_MISSING"),
    ):
        expected = str(canonical_state.get(canonical_key, ""))
        if not _is_sha256_hex(expected) or runtime_state.get(runtime_key) != expected:
            errors.append(code)
    expected_signature = str(canonical_state.get("expected_build_artifact_signature_hash", ""))
    runtime_signature = str(runtime_state.get("build_artifact_signature_hash", ""))
    if expected_signature:
        if not _is_sha256_hex(runtime_signature) or runtime_signature != expected_signature:
            errors.append("RUNTIME_PARITY_ARTIFACT_SIGNATURE_MISMATCH")

    status, reason = _decision_from_errors(errors)
    return _result(runtime_state, canonical_state, status, reason, errors)


def verify_runtime_parity_file(runtime_state_path: Path, canonical_state_path: Path) -> RuntimeParityResult:
    return verify_runtime_parity(
        _load_json_object(runtime_state_path, "RUNTIME_PARITY_VERIFIER_FAILURE"),
        _load_json_object(canonical_state_path, "RUNTIME_PARITY_VERIFIER_FAILURE"),
    )


def append_runtime_parity_evidence_file(
    result: RuntimeParityResult,
    output_path: Path,
    *,
    timestamp_utc: str | None = None,
) -> dict[str, Any]:
    record = runtime_parity_evidence_record(result, timestamp_utc=timestamp_utc)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("a", encoding="utf-8") as handle:
        handle.write(_canonical_json(record) + "\n")
    return record


def runtime_parity_evidence_record(result: RuntimeParityResult, *, timestamp_utc: str | None = None) -> dict[str, Any]:
    timestamp = timestamp_utc or _utc_now()
    record = {
        "schema": "usbay.governance_runtime_parity_evidence.v1",
        "timestamp": timestamp,
        "parity_status": result.parity_status,
        "reason_code": result.reason_code,
        "canonical_reference": result.canonical_reference,
        "canonical_commit_hash": result.canonical_commit_hash,
        "commit_hash": result.commit_hash,
        "policy_hash": result.policy_hash,
        "manifest_hash": result.manifest_hash,
        "evidence_hash": result.evidence_hash,
        "fail_closed_decision": result.parity_status in {PARITY_DENY, PARITY_FAIL_CLOSED, PARITY_HUMAN_REVIEW},
        "governance_module_versions": dict(MODULE_VERSIONS),
    }
    record["record_hash"] = _sha256_hex(_canonical_json(record).encode("utf-8"))
    assert_runtime_parity_safe(record)
    return record


def runtime_attestation_metadata(result: RuntimeParityResult) -> dict[str, Any]:
    payload = {
        "commit_hash": result.commit_hash,
        "policy_hash": result.policy_hash,
        "manifest_hash": result.manifest_hash,
        "evidence_hash": result.evidence_hash,
        "build_timestamp": result.build_timestamp,
        "runtime_environment": result.runtime_environment,
        "parity_status": result.parity_status,
        "reason_code": result.reason_code,
    }
    assert_runtime_parity_safe(payload)
    return payload


def load_runtime_parity_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / RUNTIME_PARITY_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeParityError("runtime_parity_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != RUNTIME_PARITY_ERROR_SCHEMA:
        raise RuntimeParityError("runtime_parity_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise RuntimeParityError("runtime_parity_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise RuntimeParityError("runtime_parity_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(RUNTIME_PARITY_ERROR_CODES) - set(registry))
    if missing:
        raise RuntimeParityError("runtime_parity_error_registry_incomplete:" + ",".join(missing))
    return registry


def explain_runtime_parity_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_runtime_parity_error_registry(root)
    if code not in registry:
        raise RuntimeParityError("runtime_parity_error_unknown:" + code)
    return {"code": code, **registry[code]}


def runtime_parity_summary(result: RuntimeParityResult) -> dict[str, Any]:
    return runtime_attestation_metadata(result) | {
        "valid": result.valid,
        "canonical_reference": result.canonical_reference,
        "canonical_commit_hash": result.canonical_commit_hash,
        "errors": list(result.errors),
    }


def redacted_runtime_parity_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_runtime_parity_safe(payload: Any) -> None:
    redacted = redacted_policy_payload(payload)
    if redacted != payload:
        raise RuntimeParityError("RUNTIME_PARITY_DIAGNOSTICS_UNSAFE")
    text = _canonical_json(redacted)
    lowered = text.lower()
    for marker in FORBIDDEN_MARKERS:
        marker_lower = marker.lower()
        if marker_lower in lowered and marker_lower not in {"runtime_parity"}:
            raise RuntimeParityError("RUNTIME_PARITY_DIAGNOSTICS_UNSAFE")


def _result(
    runtime_state: dict[str, Any],
    canonical_state: dict[str, Any],
    status: str,
    reason: str,
    errors: list[str],
) -> RuntimeParityResult:
    source = str(runtime_state.get("deployment_source", ""))
    canonical_commit = _canonical_commit_for_source(source, canonical_state)
    reference = _canonical_reference_for_source(source, canonical_state)
    return RuntimeParityResult(
        valid=status == PARITY_MATCH,
        parity_status=status,
        reason_code=reason,
        commit_hash=str(runtime_state.get("commit_hash", "")),
        policy_hash=str(runtime_state.get("policy_hash", "")),
        manifest_hash=str(runtime_state.get("manifest_hash", "")),
        evidence_hash=str(runtime_state.get("evidence_hash", "")),
        build_timestamp=str(runtime_state.get("build_timestamp", "")),
        runtime_environment=str(runtime_state.get("runtime_environment", "")),
        deployment_source=source,
        canonical_reference=reference,
        canonical_commit_hash=canonical_commit,
        build_artifact_signature_hash=str(runtime_state.get("build_artifact_signature_hash", "")),
        errors=tuple(dict.fromkeys(errors)),
    )


def _decision_from_errors(errors: list[str]) -> tuple[str, str]:
    if not errors:
        return PARITY_MATCH, "RUNTIME_PARITY_MATCH"
    if "RUNTIME_PARITY_DIAGNOSTICS_UNSAFE" in errors or "RUNTIME_PARITY_VERIFIER_FAILURE" in errors:
        return PARITY_FAIL_CLOSED, "RUNTIME_PARITY_VERIFIER_FAILURE"
    if "RUNTIME_PARITY_RUNTIME_HASH_MISSING" in errors or "RUNTIME_PARITY_EVIDENCE_MANIFEST_MISSING" in errors:
        return PARITY_FAIL_CLOSED, errors[0]
    if "RUNTIME_PARITY_POLICY_HASH_MISMATCH" in errors:
        return PARITY_DENY, "RUNTIME_PARITY_POLICY_HASH_MISMATCH"
    if "RUNTIME_PARITY_ARTIFACT_SIGNATURE_MISMATCH" in errors:
        return PARITY_DENY, "RUNTIME_PARITY_ARTIFACT_SIGNATURE_MISMATCH"
    if errors == ["RUNTIME_PARITY_STALE_COMMIT"]:
        return PARITY_DEGRADED, "RUNTIME_PARITY_STALE_COMMIT"
    if "RUNTIME_PARITY_UNKNOWN_SOURCE" in errors:
        return PARITY_HUMAN_REVIEW, "RUNTIME_PARITY_UNKNOWN_SOURCE"
    return PARITY_FAIL_CLOSED, errors[0]


def _canonical_commit_for_source(source: str, canonical_state: dict[str, Any]) -> str:
    if source == "github_main":
        return str(canonical_state.get("github_main_head", ""))
    branches = canonical_state.get("approved_governance_branch_heads", {})
    if isinstance(branches, dict) and source in branches:
        return str(branches[source])
    return ""


def _canonical_reference_for_source(source: str, canonical_state: dict[str, Any]) -> str:
    if source == "github_main":
        return "github_main"
    branches = canonical_state.get("approved_governance_branch_heads", {})
    if isinstance(branches, dict) and source in branches:
        return source
    return "unknown"


def _list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, tuple):
        return [str(item) for item in value]
    return []


def _load_json_object(path: Path, failure_code: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeParityError(failure_code) from exc
    if not isinstance(payload, dict):
        raise RuntimeParityError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise RuntimeParityError("RUNTIME_PARITY_VERIFIER_FAILURE") from exc


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
