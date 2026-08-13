#!/usr/bin/env python3
"""
USBAY execution attestation helpers.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from audit import ledger, sealing
import runtime.security_guard as security_guard


OUTCOME_SCHEMA_VERSION = "usbay.execution_outcome_evidence.v1"
OUTCOME_COMPLETED = "COMPLETED"
OUTCOME_FAILED = "FAILED"
OUTCOME_PARTIAL_UNKNOWN = "PARTIAL_UNKNOWN"
REQUIRED_BINDING_FIELDS = (
    "execution_authorization_hash",
    "authorization_id",
    "consumed_decision_evidence_hash",
    "decision_evidence_hash",
    "decision_consumption_evidence_hash",
    "decision_replay_evidence_hash",
    "policy_id",
    "policy_version",
    "policy_hash",
    "request_hash",
    "command_hash",
    "execution_contract_hash",
)
ALLOWED_ATTESTATION_FIELDS = frozenset(
    {
        "schema_version",
        "command_id",
        "execution_hash",
        "stdout_hash",
        "stderr_hash",
        "exit_code",
        "outcome_state",
        "execution_authorization_hash",
        "authorization_id",
        "consumed_decision_evidence_hash",
        "decision_evidence_hash",
        "decision_consumption_evidence_hash",
        "decision_replay_evidence_hash",
        "policy_id",
        "policy_version",
        "policy_hash",
        "request_hash",
        "command_hash",
        "execution_contract_hash",
        "previous_evidence_hash",
        "timestamp",
        "key_id",
        "signer_type",
        "signature_status",
        "outcome_hash",
        "current_evidence_hash",
    }
)
SENSITIVE_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "body",
        "content",
        "credential",
        "credentials",
        "customer_data",
        "password",
        "payload",
        "personal_data",
        "private_key",
        "prompt",
        "raw",
        "raw_payload",
        "secret",
        "sensitive_data",
        "token",
    }
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest().lower()


def _sha256_payload(payload: dict[str, Any]) -> str:
    return hashlib.sha256(ledger.canonical_json_bytes(payload)).hexdigest().lower()


def _sha256_reference(payload: dict[str, Any]) -> str:
    return "sha256:" + _sha256_payload(payload)


def _is_sha256_reference(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(character in "0123456789abcdef" for character in digest.lower())


def _execution_hash(*, command: dict, stdout: str, stderr: str, exit_code: int) -> str:
    payload = {
        "command": command,
        "stdout_hash": _sha256_text(stdout),
        "stderr_hash": _sha256_text(stderr),
        "exit_code": exit_code,
    }
    return hashlib.sha256(ledger.canonical_json_bytes(payload)).hexdigest().lower()


def _contains_sensitive_data(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in SENSITIVE_KEYS:
                return True
            if _contains_sensitive_data(child):
                return True
        return False
    if isinstance(value, (list, tuple)):
        return any(_contains_sensitive_data(child) for child in value)
    return False


def execution_contract_hash(contract: dict[str, Any] | None) -> str:
    if not isinstance(contract, dict) or _contains_sensitive_data(contract):
        return ""
    redacted = {key: value for key, value in contract.items() if key != "authorization_nonce"}
    if isinstance(contract.get("authorization_nonce"), str) and contract["authorization_nonce"]:
        redacted["authorization_nonce_hash"] = _sha256_reference({"authorization_nonce": contract["authorization_nonce"]})
    return _sha256_reference(redacted)


def command_hash(command: dict[str, Any]) -> str:
    if not isinstance(command, dict) or _contains_sensitive_data(command):
        return ""
    return _sha256_reference(command)


def outcome_state(exit_code: int | None, *, side_effect_completed: bool, evidence_binding_valid: bool) -> str:
    if not side_effect_completed or not evidence_binding_valid or exit_code is None:
        return OUTCOME_PARTIAL_UNKNOWN
    return OUTCOME_COMPLETED if int(exit_code) == 0 else OUTCOME_FAILED


def _binding_from_context(
    *,
    command: dict[str, Any],
    governed_execution_authorization: dict[str, Any] | None,
    governed_execution_contract: dict[str, Any] | None,
    consumed_decision_evidence_hash: str | None,
) -> dict[str, Any]:
    if not isinstance(governed_execution_authorization, dict):
        return {}
    contract_hash = execution_contract_hash(governed_execution_contract)
    resolved_command_hash = command_hash(command)
    binding = {
        "execution_authorization_hash": governed_execution_authorization.get("execution_authorization_hash"),
        "authorization_id": governed_execution_authorization.get("authorization_id"),
        "consumed_decision_evidence_hash": consumed_decision_evidence_hash,
        "decision_evidence_hash": governed_execution_authorization.get("decision_evidence_hash"),
        "decision_consumption_evidence_hash": governed_execution_authorization.get("decision_consumption_evidence_hash"),
        "decision_replay_evidence_hash": governed_execution_authorization.get("decision_replay_evidence_hash"),
        "policy_id": governed_execution_authorization.get("policy_id"),
        "policy_version": governed_execution_authorization.get("policy_version"),
        "policy_hash": governed_execution_authorization.get("policy_hash"),
        "request_hash": governed_execution_authorization.get("request_hash"),
        "command_hash": resolved_command_hash,
        "execution_contract_hash": contract_hash,
    }
    return binding


def _binding_valid(binding: dict[str, Any]) -> bool:
    if any(field not in binding for field in REQUIRED_BINDING_FIELDS):
        return False
    if not all(isinstance(binding[field], str) and binding[field] for field in REQUIRED_BINDING_FIELDS):
        return False
    for field in (
        "execution_authorization_hash",
        "consumed_decision_evidence_hash",
        "decision_evidence_hash",
        "decision_consumption_evidence_hash",
        "decision_replay_evidence_hash",
        "policy_hash",
        "request_hash",
        "command_hash",
        "execution_contract_hash",
    ):
        if not _is_sha256_reference(binding[field]):
            return False
    return True


def _outcome_hash_payload(attestation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": attestation.get("schema_version"),
        "command_id": attestation.get("command_id"),
        "execution_hash": attestation.get("execution_hash"),
        "exit_code": attestation.get("exit_code"),
        "outcome_state": attestation.get("outcome_state"),
        "execution_authorization_hash": attestation.get("execution_authorization_hash"),
        "authorization_id": attestation.get("authorization_id"),
        "consumed_decision_evidence_hash": attestation.get("consumed_decision_evidence_hash"),
        "decision_evidence_hash": attestation.get("decision_evidence_hash"),
        "decision_consumption_evidence_hash": attestation.get("decision_consumption_evidence_hash"),
        "decision_replay_evidence_hash": attestation.get("decision_replay_evidence_hash"),
        "policy_id": attestation.get("policy_id"),
        "policy_version": attestation.get("policy_version"),
        "policy_hash": attestation.get("policy_hash"),
        "request_hash": attestation.get("request_hash"),
        "command_hash": attestation.get("command_hash"),
        "execution_contract_hash": attestation.get("execution_contract_hash"),
        "previous_evidence_hash": attestation.get("previous_evidence_hash"),
    }


def _attestation_hash_payload(attestation: dict[str, Any]) -> dict[str, Any]:
    payload = dict(attestation)
    payload.pop("current_evidence_hash", None)
    return payload


def _sha256_file_reference(path: Path) -> str:
    return "sha256:" + ledger.sha256_file(path)


def validate_execution_outcome_attestation(
    attestation: dict[str, Any] | None,
    *,
    command: dict[str, Any],
    governed_execution_authorization: dict[str, Any],
    governed_execution_contract: dict[str, Any],
    consumed_decision_evidence_hash: str,
) -> str | None:
    if not isinstance(attestation, dict):
        return "OUTCOME_EVIDENCE_MISSING"
    if any(field not in ALLOWED_ATTESTATION_FIELDS for field in attestation):
        return "OUTCOME_EVIDENCE_MALFORMED"
    if any(field in attestation for field in SENSITIVE_KEYS):
        return "OUTCOME_EVIDENCE_MALFORMED"
    expected_binding = _binding_from_context(
        command=command,
        governed_execution_authorization=governed_execution_authorization,
        governed_execution_contract=governed_execution_contract,
        consumed_decision_evidence_hash=consumed_decision_evidence_hash,
    )
    if not _binding_valid(expected_binding):
        return "OUTCOME_BINDING_INVALID"
    for field in REQUIRED_BINDING_FIELDS:
        if attestation.get(field) != expected_binding[field]:
            return "OUTCOME_BINDING_MISMATCH"
    expected_state = outcome_state(
        attestation.get("exit_code"),
        side_effect_completed=True,
        evidence_binding_valid=True,
    )
    if attestation.get("outcome_state") != expected_state:
        return "OUTCOME_STATE_INVALID"
    if attestation.get("outcome_hash") != _sha256_reference(_outcome_hash_payload(attestation)):
        return "OUTCOME_HASH_INVALID"
    if attestation.get("current_evidence_hash") != _sha256_reference(_attestation_hash_payload(attestation)):
        return "OUTCOME_EVIDENCE_HASH_INVALID"
    return None


def execution_attestation_signature_evidence(
    *,
    attestation: dict[str, Any] | None,
    attestation_path: Path,
    signature_path: Path,
    public_key: Path,
    cwd: Path,
) -> tuple[str | None, dict[str, Any]]:
    evidence = {
        "attestation_payload_hash": "sha256:" + ("0" * 64),
        "attestation_signature_hash": "sha256:" + ("0" * 64),
        "signature_verification_result": "FAILED",
        "key_id": attestation.get("key_id") if isinstance(attestation, dict) else "",
        "signer_type": attestation.get("signer_type") if isinstance(attestation, dict) else "",
    }
    if not isinstance(attestation, dict):
        return "OUTCOME_EVIDENCE_MISSING", evidence
    if not attestation_path.exists():
        return "OUTCOME_EVIDENCE_UNWRITTEN", evidence
    if not signature_path.exists():
        return "OUTCOME_SIGNATURE_MISSING", evidence
    try:
        payload_hash = _sha256_file_reference(attestation_path)
        signature_hash = _sha256_file_reference(signature_path)
    except Exception:
        return "OUTCOME_SIGNATURE_UNREADABLE", evidence
    evidence["attestation_payload_hash"] = payload_hash
    evidence["attestation_signature_hash"] = signature_hash
    try:
        sealing.verify_path(
            public_key=public_key,
            payload_path=attestation_path,
            signature_path=signature_path,
            cwd=cwd,
        )
    except Exception:
        return "OUTCOME_SIGNATURE_UNVERIFIABLE", evidence
    evidence["signature_verification_result"] = "VERIFIED"
    return None, evidence


def generate_execution_attestation(
    *,
    command_id: str,
    command: dict,
    stdout: str,
    stderr: str,
    exit_code: int,
    signer_adapter: Any,
    key_id: str,
    cwd: Path,
    attestation_path: Path,
    signature_path: Path,
    governed_execution_authorization: dict | None = None,
    governed_execution_contract: dict | None = None,
    consumed_decision_evidence_hash: str | None = None,
    previous_evidence_hash: str = "sha256:" + ("0" * 64),
) -> dict:
    binding = _binding_from_context(
        command=command,
        governed_execution_authorization=governed_execution_authorization,
        governed_execution_contract=governed_execution_contract,
        consumed_decision_evidence_hash=consumed_decision_evidence_hash,
    )
    binding_valid = _binding_valid(binding)
    attestation = {
        "schema_version": OUTCOME_SCHEMA_VERSION,
        "command_id": command_id,
        "execution_hash": _execution_hash(
            command=command,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
        ),
        "stdout_hash": _sha256_text(stdout),
        "stderr_hash": _sha256_text(stderr),
        "exit_code": int(exit_code),
        "outcome_state": outcome_state(int(exit_code), side_effect_completed=True, evidence_binding_valid=binding_valid),
        **binding,
        "previous_evidence_hash": previous_evidence_hash if _is_sha256_reference(previous_evidence_hash) else "sha256:" + ("0" * 64),
        "timestamp": _utc_now(),
        "key_id": key_id,
        "signer_type": signer_adapter.signer_type,
        "signature_status": "signed",
    }
    attestation["outcome_hash"] = _sha256_reference(_outcome_hash_payload(attestation))
    attestation["current_evidence_hash"] = _sha256_reference(_attestation_hash_payload(attestation))
    if not binding_valid:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: OUTCOME_BINDING_INVALID")
    security_guard.write_guarded_bytes(attestation_path, ledger.canonical_json_bytes(attestation))
    security_guard.guard_runtime_write_path(signature_path)
    signer_adapter.sign_file(payload_path=attestation_path, signature_path=signature_path, cwd=cwd)
    if not signature_path.exists():
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: OUTCOME_SIGNATURE_MISSING")
    return attestation
