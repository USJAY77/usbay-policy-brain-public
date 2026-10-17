from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.hashing import is_sha256_reference, sha256_reference
from runtime import policy_validator
from security.policy_authority_replay_registry import (
    ADOPTED,
    ALREADY_ADOPTED,
    PolicyAuthorityAdoptionResult,
    SQLitePolicyAuthorityReplayRegistry,
)


SCHEMA_VERSION = "usbay.policy_authority_adoption.v1"
STATE_SCHEMA_VERSION = "usbay.policy_authority_state.v1"


class PolicyAuthorityAdoptionError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class AdoptedPolicyAuthority:
    schema_version: str
    adoption_id: str
    scope_key: str
    policy_id: str
    policy_hash: str
    policy_version: str
    tenant_reference: str
    environment_reference: str
    environment: str
    approval_bundle_hashes: tuple[str, str]
    approval_nonce_hashes: tuple[str, str]
    approver_ids: tuple[str, str]
    approver_identity_references: tuple[str, str]
    approver_key_fingerprints: tuple[str, str]
    approver_registry_hash: str
    approver_registry_version: str
    registry_evidence_hash: str
    revocation_state_reference: str
    valid_from: str
    valid_until: str
    status: str
    authority_state_reference: str
    record_hash: str
    execution_authorized: bool = False
    provider_authorized: bool = False
    deployment_authorized: bool = False
    activation_authorized: bool = False
    policy_authoring_authorized: bool = False


def adopt_current_scoped_policy_authority(
    *,
    policy_id: str,
    policy_hash: str,
    policy_version: str,
    tenant_reference: str,
    environment_reference: str,
    environment: str,
    store: SQLitePolicyAuthorityReplayRegistry,
    adopted_at: str | None = None,
) -> AdoptedPolicyAuthority:
    """Validate signed scope and atomically adopt using the legacy nonce store."""
    _validate_current_policy(policy_id, policy_hash, policy_version)
    bundle = policy_validator.inspect_scoped_policy_approval_artifacts(
        policy_id=policy_id,
        policy_hash=policy_hash.removeprefix("sha256:"),
        policy_version=policy_version,
        tenant_reference=tenant_reference,
        environment_reference=environment_reference,
        environment=environment,
    )
    timestamp = adopted_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    scope_key = sha256_reference(
        {
            "schema_version": SCHEMA_VERSION,
            "policy_id": policy_id,
            "tenant_reference": tenant_reference,
            "environment_reference": environment_reference,
        }
    )
    adoption_id = sha256_reference(
        {
            "schema_version": SCHEMA_VERSION,
            "scope_key": scope_key,
            "policy_hash": policy_hash,
            "policy_version": policy_version,
            "approval_bundle_hashes": bundle.approval_bundle_hashes,
        }
    )
    valid_until = min(
        _coerce_time(bundle.registry_valid_until),
        _coerce_time(bundle.revocation_fresh_until),
    ).isoformat().replace("+00:00", "Z")
    core: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "adoption_id": adoption_id,
        "scope_key": scope_key,
        "policy_id": policy_id,
        "policy_hash": _policy_hash_reference(policy_hash),
        "policy_version": policy_version,
        "tenant_reference": tenant_reference,
        "environment_reference": environment_reference,
        "environment": environment,
        "approval_bundle_hashes": list(bundle.approval_bundle_hashes),
        "approval_nonce_hashes": list(bundle.approval_nonce_hashes),
        "approver_ids": list(bundle.approver_ids),
        "approver_identity_references": list(bundle.approver_identity_references),
        "approver_key_fingerprints": list(bundle.approver_key_fingerprints),
        "approver_registry_hash": bundle.approver_registry_hash,
        "approver_registry_version": bundle.approver_registry_version,
        "registry_evidence_hash": bundle.registry_evidence_hash,
        "revocation_state_reference": bundle.revocation_state_reference,
        "valid_from": timestamp,
        "valid_until": valid_until,
        "status": "ADOPTED",
        "execution_authorized": False,
        "provider_authorized": False,
        "deployment_authorized": False,
        "activation_authorized": False,
        "policy_authoring_authorized": False,
    }
    state_reference = sha256_reference({"schema_version": STATE_SCHEMA_VERSION, **core})
    core["authority_state_reference"] = state_reference
    record_hash = sha256_reference(core)
    core["record_hash"] = record_hash
    record_json = json.dumps(core, sort_keys=True, separators=(",", ":"))
    result = store.adopt_if_unused(
        bundle.approval_nonce_hashes,
        registry_evidence_hash=bundle.registry_evidence_hash,
        consumed_at=timestamp,
        adoption_id=adoption_id,
        scope_key=scope_key,
        record_hash=record_hash,
        record_json=record_json,
    )
    return _result_record(result)


def load_adopted_policy_authority(
    *,
    adoption_id: str,
    policy_id: str,
    policy_hash: str,
    policy_version: str,
    tenant_reference: str,
    environment_reference: str,
    environment: str,
    store: SQLitePolicyAuthorityReplayRegistry,
    now: datetime | str | None = None,
) -> AdoptedPolicyAuthority:
    """Read and revalidate an adoption without consuming or writing state."""
    _validate_current_policy(policy_id, policy_hash, policy_version)
    try:
        raw = store.load_adoption(adoption_id)
    except Exception as exc:
        raise PolicyAuthorityAdoptionError("POLICY_ADOPTION_STORE_UNAVAILABLE") from exc
    if raw is None:
        raise PolicyAuthorityAdoptionError("POLICY_ADOPTION_MISSING")
    record = _decode_record(raw)
    expected = {
        "adoption_id": adoption_id,
        "policy_id": policy_id,
        "policy_hash": _policy_hash_reference(policy_hash),
        "policy_version": policy_version,
        "tenant_reference": tenant_reference,
        "environment_reference": environment_reference,
        "environment": environment,
        "status": "ADOPTED",
    }
    if any(record.get(key) != value for key, value in expected.items()):
        raise PolicyAuthorityAdoptionError("POLICY_ADOPTION_BINDING_MISMATCH")
    comparison_time = _coerce_time(now)
    if comparison_time < _coerce_time(record["valid_from"]) or comparison_time >= _coerce_time(record["valid_until"]):
        raise PolicyAuthorityAdoptionError("POLICY_ADOPTION_EXPIRED")

    bundle = policy_validator.inspect_scoped_policy_approval_artifacts(
        policy_id=policy_id,
        policy_hash=policy_hash.removeprefix("sha256:"),
        policy_version=policy_version,
        tenant_reference=tenant_reference,
        environment_reference=environment_reference,
        environment=environment,
    )
    comparisons = {
        "approval_bundle_hashes": list(bundle.approval_bundle_hashes),
        "approval_nonce_hashes": list(bundle.approval_nonce_hashes),
        "approver_ids": list(bundle.approver_ids),
        "approver_identity_references": list(bundle.approver_identity_references),
        "approver_key_fingerprints": list(bundle.approver_key_fingerprints),
        "approver_registry_hash": bundle.approver_registry_hash,
        "approver_registry_version": bundle.approver_registry_version,
        "registry_evidence_hash": bundle.registry_evidence_hash,
        "revocation_state_reference": bundle.revocation_state_reference,
    }
    if any(record.get(key) != value for key, value in comparisons.items()):
        raise PolicyAuthorityAdoptionError("POLICY_ADOPTION_AUTHORITY_STATE_CHANGED")
    return _coerce_record(record)


def revalidate_adopted_policy_authority(
    authority: AdoptedPolicyAuthority,
    *,
    store: SQLitePolicyAuthorityReplayRegistry,
    now: datetime | str | None = None,
) -> AdoptedPolicyAuthority:
    current = load_adopted_policy_authority(
        adoption_id=authority.adoption_id,
        policy_id=authority.policy_id,
        policy_hash=authority.policy_hash,
        policy_version=authority.policy_version,
        tenant_reference=authority.tenant_reference,
        environment_reference=authority.environment_reference,
        environment=authority.environment,
        store=store,
        now=now,
    )
    if current != authority:
        raise PolicyAuthorityAdoptionError("POLICY_ADOPTION_AUTHORITY_STATE_CHANGED")
    return current


def _result_record(result: PolicyAuthorityAdoptionResult) -> AdoptedPolicyAuthority:
    if result.state not in {ADOPTED, ALREADY_ADOPTED} or not result.record_json:
        raise PolicyAuthorityAdoptionError(f"POLICY_ADOPTION_{result.state}")
    return _coerce_record(_decode_record(result.record_json))


def _decode_record(raw: str) -> dict[str, Any]:
    try:
        record = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise PolicyAuthorityAdoptionError("POLICY_ADOPTION_RECORD_CORRUPT") from exc
    if not isinstance(record, dict) or record.get("schema_version") != SCHEMA_VERSION:
        raise PolicyAuthorityAdoptionError("POLICY_ADOPTION_RECORD_CORRUPT")
    stored_hash = record.get("record_hash")
    if stored_hash != sha256_reference({key: value for key, value in record.items() if key != "record_hash"}):
        raise PolicyAuthorityAdoptionError("POLICY_ADOPTION_RECORD_CORRUPT")
    return record


def _coerce_record(record: dict[str, Any]) -> AdoptedPolicyAuthority:
    payload = dict(record)
    for field in (
        "approval_bundle_hashes",
        "approval_nonce_hashes",
        "approver_ids",
        "approver_identity_references",
        "approver_key_fingerprints",
    ):
        values = payload.get(field)
        if not isinstance(values, list) or len(values) != 2:
            raise PolicyAuthorityAdoptionError("POLICY_ADOPTION_RECORD_CORRUPT")
        payload[field] = tuple(str(value) for value in values)
    try:
        result = AdoptedPolicyAuthority(**payload)
    except (TypeError, ValueError) as exc:
        raise PolicyAuthorityAdoptionError("POLICY_ADOPTION_RECORD_CORRUPT") from exc
    if not all(
        is_sha256_reference(value)
        for value in (
            result.adoption_id,
            result.scope_key,
            result.policy_hash,
            result.tenant_reference,
            result.environment_reference,
            result.approver_registry_hash,
            result.registry_evidence_hash,
            result.revocation_state_reference,
            result.authority_state_reference,
            result.record_hash,
        )
    ) or any(
        (
            result.execution_authorized,
            result.provider_authorized,
            result.deployment_authorized,
            result.activation_authorized,
            result.policy_authoring_authorized,
        )
    ):
        raise PolicyAuthorityAdoptionError("POLICY_ADOPTION_RECORD_CORRUPT")
    return result


def _policy_hash_reference(value: str) -> str:
    candidate = str(value).lower()
    if is_sha256_reference(candidate):
        return candidate
    reference = "sha256:" + candidate
    if not is_sha256_reference(reference):
        raise PolicyAuthorityAdoptionError("POLICY_ADOPTION_POLICY_HASH_INVALID")
    return reference


def _validate_current_policy(policy_id: str, policy_hash: str, policy_version: str) -> None:
    policy_validator.validate_required_files()
    policy_validator.validate_policy_json()
    policy_validator.validate_sha256()
    policy_validator.validate_signature()
    metadata = policy_validator.load_policy_metadata()
    policy = metadata["policy"]
    current_id = next(
        (str(policy[field]) for field in ("policy_id", "scope", "id") if isinstance(policy.get(field), str) and policy[field]),
        "policy/policy.json",
    )
    if (
        current_id != policy_id
        or metadata["policy_version"] != policy_version
        or metadata["policy_hash"] != policy_hash.removeprefix("sha256:")
    ):
        raise PolicyAuthorityAdoptionError("POLICY_ADOPTION_POLICY_BINDING_MISMATCH")


def _coerce_time(value: datetime | str | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise PolicyAuthorityAdoptionError("POLICY_ADOPTION_TIMESTAMP_INVALID") from exc
    if parsed.tzinfo is None:
        raise PolicyAuthorityAdoptionError("POLICY_ADOPTION_TIMESTAMP_INVALID")
    return parsed.astimezone(timezone.utc)


__all__ = [
    "AdoptedPolicyAuthority",
    "PolicyAuthorityAdoptionError",
    "adopt_current_scoped_policy_authority",
    "load_adopted_policy_authority",
    "revalidate_adopted_policy_authority",
]
