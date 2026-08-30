from __future__ import annotations

import copy
from functools import cache
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from governance.auditor_verification_bundle import create_auditor_verification_bundle
from governance.evidence_chain import append_evidence_chain
from governance.evidence_merkle_checkpoint import create_merkle_checkpoint
from governance.evidence_merkle_consistency import create_merkle_consistency_proof
from governance.evidence_merkle_inclusion import create_merkle_inclusion_proof
from governance.evidence_record_chain import create_evidence_record
from governance.evidence_renewal_runtime import prepare_evidence_renewal_runtime_record
from governance.policy_pack import POLICY_PACK_SCHEMA
from governance.policy_parity import build_runtime_decision_record
from governance.policy_proof_bundle import build_policy_proof_bundle
from governance.policy_simulation import DECISION_ALLOW
from governance.proof_timestamp_anchor import anchor_proof_bundle
from governance.regulator_export_profile import prepare_regulator_export_profile
from governance.rfc3161_timestamp import DEFAULT_POLICY_OID_PLACEHOLDER, prepare_rfc3161_request_material
from governance.sealed_audit_archive import create_sealed_audit_archive
from governance.signed_auditor_bundle import create_signed_auditor_bundle, signer_key_fingerprint
from governance.signed_bundle_ltv import create_signed_bundle_ltv_evidence
from governance.signed_bundle_revocation_preflight import create_revocation_preflight
from governance.signed_bundle_revocation_response import create_revocation_response
from governance.signed_bundle_timestamp import attach_signed_bundle_timestamp
from governance.tsa_live_verification import prepare_tsa_live_verification_plan
from governance.worm_evidence_manifest import prepare_worm_manifest
from governance.worm_immutable_storage import prepare_worm_immutable_storage_plan


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
TENANT_ID = "tenant-governance-test"
POLICY_VERSION = "policy.v1"
SCHEMA_VERSION = "usbay.governance.test.v1"
TSA_CERTIFICATE_HASH = SHA_A
TRUST_ANCHOR_HASH = SHA_B
REVOCATION_EVIDENCE_HASH = SHA_C
REVOCATION_SOURCE_HASH = "d" * 64
RESPONDER_KEY_HASH = "f" * 64


def _with_overrides(base: dict[str, Any], overrides: dict[str, Any], allowed: set[str]) -> dict[str, Any]:
    unknown = tuple(sorted(set(overrides) - allowed))
    if unknown:
        raise ValueError("unsupported governance test override:" + ",".join(unknown))
    merged = copy.deepcopy(base)
    for key, value in overrides.items():
        merged[key] = value
    return merged


class PolicyBuilder:
    """Deterministic policy fixtures for governance tests."""

    def __init__(self, *, tenant_id: str = TENANT_ID, policy_version: str = POLICY_VERSION) -> None:
        self.tenant_id = tenant_id
        self.policy_version = policy_version

    def policy_metadata(self, **overrides: str) -> dict[str, str]:
        base = {
            "actor_hash": SHA_A,
            "decision_timestamp_utc": "2026-05-12T00:13:00Z",
            "policy_decision": "ALLOW",
            "policy_decision_id": SHA_B,
            "policy_hash": SHA_C,
            "policy_version_hash": SHA_D,
        }
        return _with_overrides(base, overrides, set(base))

    def policy_pack(self, **overrides: Any) -> dict[str, Any]:
        base = {
            "schema": SCHEMA_VERSION,
            "tenant_id": self.tenant_id,
            "policy_version": self.policy_version,
            "policy_hash": SHA_C,
            "policy_version_hash": SHA_D,
        }
        return _with_overrides(base, overrides, set(base))


class ApprovalBuilder:
    """Hash-only approval fixtures with no raw approval contents."""

    def __init__(self, *, tenant_id: str = TENANT_ID) -> None:
        self.tenant_id = tenant_id

    def approval_reference(self, *, state: str = "APPROVED", **overrides: str) -> dict[str, str]:
        base = {
            "approval_state": state,
            "approval_hash": SHA_A,
            "approval_reference": f"approval://local-only/sha256/{SHA_A}",
            "tenant_id": self.tenant_id,
        }
        return _with_overrides(base, overrides, set(base))


class ManifestBuilder:
    """Immutable manifest fixtures for tests that need canonical metadata."""

    def __init__(self, *, tenant_id: str = TENANT_ID) -> None:
        self.tenant_id = tenant_id

    def manifest(self, *, namespace: str = "governance-test", **overrides: str) -> dict[str, str]:
        base = {
            "schema": SCHEMA_VERSION,
            "namespace": namespace,
            "manifest_hash": SHA_B,
            "tenant_id": self.tenant_id,
            "policy_hash": SHA_C,
        }
        return _with_overrides(base, overrides, set(base))


class SignedBundleBuilder:
    """Hash-only signed bundle fixtures; signatures are references, not secrets."""

    def __init__(self, *, tenant_id: str = TENANT_ID) -> None:
        self.tenant_id = tenant_id

    def signed_bundle(self, *, bundle_hash: str = SHA_D, **overrides: str) -> dict[str, str]:
        base = {
            "bundle_hash": bundle_hash,
            "signature_hash": SHA_A,
            "signature_reference": f"signature://local-only/sha256/{SHA_A}",
            "tenant_id": self.tenant_id,
            "policy_hash": SHA_C,
        }
        return _with_overrides(base, overrides, set(base))


class EvidenceBuilder:
    """Shared immutable governance evidence builders.

    Cached source fixtures are deep-copied at the boundary so callers can mutate
    test data independently without leaking state into later tests.
    """

    def __init__(self, *, tenant_id: str = TENANT_ID, policy_version: str = POLICY_VERSION) -> None:
        self.tenant_id = tenant_id
        self.policy_version = policy_version

    def evidence_bundle(self, **overrides: str) -> dict[str, str]:
        base = {
            "schema": SCHEMA_VERSION,
            "tenant_id": self.tenant_id,
            "evidence_hash": SHA_A,
            "policy_hash": SHA_C,
            "policy_version": self.policy_version,
            "evidence_reference": f"evidence://local-only/sha256/{SHA_A}",
        }
        return _with_overrides(base, overrides, set(base))

    def worm_archive(self, **overrides: str) -> dict[str, str]:
        base = {
            "schema": SCHEMA_VERSION,
            "tenant_id": self.tenant_id,
            "worm_archive_hash": SHA_B,
            "archive_reference": f"worm://local-only/sha256/{SHA_B}",
        }
        return _with_overrides(base, overrides, set(base))

    def worm_immutable_storage_plan(self) -> tuple[dict, dict, dict]:
        return copy.deepcopy(_worm_immutable_storage_plan_source())

    def regulator_export_profile(
        self,
        profile_type: str = "EU_AI_ACT_AUDIT",
    ) -> tuple[dict, dict, dict, dict, dict, dict]:
        return copy.deepcopy(_regulator_export_profile_source(profile_type))

    def evidence_renewal_runtime_record(self) -> tuple[dict, dict, dict, dict, dict, dict, dict]:
        return copy.deepcopy(_evidence_renewal_runtime_record_source())

    def signed_bundle_ltv_evidence(self) -> tuple[dict, dict]:
        return copy.deepcopy(_signed_bundle_ltv_source())

    def signed_bundle_timestamp_attachment(self) -> tuple[dict, dict, dict]:
        return copy.deepcopy(_signed_bundle_timestamp_attachment_source())

    def signed_auditor_envelope(self) -> tuple[dict, dict, dict]:
        return copy.deepcopy(_signed_auditor_envelope_source())


@cache
def _worm_immutable_storage_plan_source() -> tuple[dict, dict, dict]:
    evidence_record, archive = _evidence_record_source()
    plan = prepare_worm_immutable_storage_plan(
        sealed_archive=archive,
        evidence_record_chain=evidence_record,
        created_at_utc="2026-05-12T00:12:00Z",
    )
    return plan, archive, evidence_record


@cache
def _signed_bundle_ltv_source() -> tuple[dict, dict]:
    attachment, _envelope, _policy = _signed_bundle_timestamp_attachment_source()
    ltv = create_signed_bundle_ltv_evidence(
        attachment,
        tsa_certificate_fingerprint=TSA_CERTIFICATE_HASH,
        tsa_certificate_chain_fingerprints=[TSA_CERTIFICATE_HASH, TRUST_ANCHOR_HASH],
        trust_anchor_fingerprint=TRUST_ANCHOR_HASH,
        revocation_evidence_type="offline_mock",
        revocation_evidence_hash=REVOCATION_EVIDENCE_HASH,
        revocation_checked_at_utc="2026-05-12T00:07:00Z",
        validation_policy_id="usb.ltv.v1",
    )
    return ltv, attachment


@cache
def _keypair_source() -> tuple[str, str]:
    key = Ed25519PrivateKey.generate()
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_key, public_key


def _trust_policy(public_key: str, *, signer_id: str = "signed-auditor-test-signer") -> dict[str, Any]:
    return {
        "policy_version": "signed-auditor-test-v1",
        "allowed_signers": [
            {
                "signer_id": signer_id,
                "public_key_fingerprint": signer_key_fingerprint(public_key),
                "public_key_pem": public_key,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
            }
        ],
        "revoked_fingerprints": [],
    }


def _worm_manifest(policy_id: str = "policy.allow.read") -> dict[str, Any]:
    policy_pack = {
        "schema": POLICY_PACK_SCHEMA,
        "fail_closed": True,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
        "policies": [
            {
                "policy_id": policy_id,
                "risk_level": "low",
                "requires_human_approval": False,
                "fail_closed": True,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
                "allow_rules": [{"action": "read", "resource": "ledger"}],
                "deny_rules": [],
            }
        ],
    }
    request = {"action": "read", "resource": "ledger"}
    runtime_record = build_runtime_decision_record(
        decision=DECISION_ALLOW,
        policy_pack=policy_pack,
        request_context=request,
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )
    bundle = build_policy_proof_bundle(
        policy_pack,
        request,
        runtime_record,
        tenant_id="t1",
        environment="test",
        risk_level="low",
        validation_timestamp="2026-05-12T00:00:00Z",
    )
    anchor = anchor_proof_bundle(bundle, timestamp="2026-05-12T00:00:00Z")
    rfc3161_request = prepare_rfc3161_request_material(bundle, anchor)
    return prepare_worm_manifest(
        bundle,
        anchor,
        rfc3161_request,
        retention_policy_label="governance-retain-7y",
        created_at="2026-05-12T00:00:00Z",
    )


@cache
def _auditor_bundle_source() -> dict[str, Any]:
    chain = append_evidence_chain(None, _worm_manifest("policy.allow.read"), timestamp="2026-05-12T00:00:00Z")
    previous = create_merkle_checkpoint(
        chain,
        chain_start_position=0,
        chain_end_position=0,
        timestamp="2026-05-12T00:01:00Z",
    )
    chain = append_evidence_chain(chain, _worm_manifest("policy.allow.other"), timestamp="2026-05-12T00:02:00Z")
    current = create_merkle_checkpoint(
        chain,
        chain_start_position=0,
        chain_end_position=1,
        timestamp="2026-05-12T00:03:00Z",
    )
    return create_auditor_verification_bundle(
        current,
        create_merkle_inclusion_proof(current, leaf_index=1),
        create_merkle_consistency_proof(previous, current),
        verification_scope={"tenant_id": "t1", "environment": "test", "purpose": "offline-audit"},
        timestamp="2026-05-12T00:04:00Z",
    )


@cache
def _signed_auditor_envelope_source() -> tuple[dict, dict, dict]:
    private_key, public_key = _keypair_source()
    policy = _trust_policy(public_key)
    auditor_bundle = _auditor_bundle_source()
    envelope = create_signed_auditor_bundle(
        auditor_bundle,
        private_key_pem=private_key,
        public_key_pem=public_key,
        signer_id="signed-auditor-test-signer",
        trust_policy=policy,
        signed_at_utc="2026-05-12T00:05:00Z",
    )
    return envelope, auditor_bundle, policy


@cache
def _signed_bundle_timestamp_attachment_source() -> tuple[dict, dict, dict]:
    envelope, _auditor_bundle, policy = _signed_auditor_envelope_source()
    attachment = attach_signed_bundle_timestamp(
        envelope,
        trust_policy=policy,
        tsa_policy_id=DEFAULT_POLICY_OID_PLACEHOLDER,
        tsa_gen_time_utc="2026-05-12T00:06:00Z",
    )
    return attachment, envelope, policy


@cache
def _sealed_audit_archive_source() -> tuple[dict, dict[str, dict]]:
    timestamp_attachment, signed_bundle, _policy = _signed_bundle_timestamp_attachment_source()
    ltv_evidence, _attachment = _signed_bundle_ltv_source()
    revocation_preflight = create_revocation_preflight(
        ltv_evidence,
        revocation_source_type="OCSP",
        revocation_source_uri_hash=REVOCATION_SOURCE_HASH,
        expected_freshness_window_seconds=86400,
        checked_at_utc="2026-05-12T00:08:00Z",
        validation_policy_id="usb.ltv.v1",
    )
    revocation_response = create_revocation_response(
        revocation_preflight,
        response_status="GOOD",
        response_this_update_utc="2026-05-12T00:07:30Z",
        response_next_update_utc="2026-05-13T00:07:30Z",
        responder_key_fingerprint=RESPONDER_KEY_HASH,
        checked_at_utc="2026-05-12T00:08:30Z",
        validation_policy_id="usb.ltv.v1",
    )
    artifacts = {
        "evidence_chain": _evidence_chain_source(),
        "signed_bundle": signed_bundle,
        "timestamp_attachment": timestamp_attachment,
        "ltv_evidence": ltv_evidence,
        "revocation_preflight": revocation_preflight,
        "revocation_response": revocation_response,
    }
    archive = create_sealed_audit_archive(
        **artifacts,
        archive_created_at_utc="2026-05-12T00:09:00Z",
        archive_scope="external-audit",
    )
    return archive, artifacts


@cache
def _evidence_chain_source() -> dict[str, Any]:
    chain = append_evidence_chain(None, _worm_manifest("policy.allow.read"), timestamp="2026-05-12T00:00:00Z")
    return append_evidence_chain(chain, _worm_manifest("policy.allow.other"), timestamp="2026-05-12T00:02:00Z")


@cache
def _evidence_record_source() -> tuple[dict, dict]:
    archive, _artifacts = _sealed_audit_archive_source()
    record = create_evidence_record(
        archive,
        renewal_timestamp_utc="2026-05-12T00:10:00Z",
        renewal_reason="initial_archive_timestamp",
    )
    return record, archive


@cache
def _regulator_export_profile_source(
    profile_type: str = "EU_AI_ACT_AUDIT",
) -> tuple[dict, dict, dict, dict, dict, dict]:
    evidence_record, archive = _evidence_record_source()
    worm = prepare_worm_immutable_storage_plan(
        sealed_archive=archive,
        evidence_record_chain=evidence_record,
        created_at_utc="2026-05-12T00:12:00Z",
    )
    attachment, _envelope, _policy = _signed_bundle_timestamp_attachment_source()
    tsa = prepare_tsa_live_verification_plan(
        attachment,
        verification_checked_at_utc="2026-05-12T00:07:00Z",
    )
    policy_metadata = PolicyBuilder().policy_metadata()
    profile = prepare_regulator_export_profile(
        sealed_archive=archive,
        evidence_record_chain=evidence_record,
        worm_immutable_storage=worm,
        tsa_live_verification=tsa,
        policy_decision_metadata=policy_metadata,
        export_profile_type=profile_type,
        created_at_utc="2026-05-12T00:14:00Z",
    )
    return profile, archive, evidence_record, worm, tsa, policy_metadata


@cache
def _evidence_renewal_runtime_record_source() -> tuple[dict, dict, dict, dict, dict, dict, dict]:
    profile, archive, evidence_record, worm, tsa, policy_metadata = _regulator_export_profile_source()
    record = prepare_evidence_renewal_runtime_record(
        evidence_record_chain=evidence_record,
        sealed_archive=archive,
        worm_immutable_storage=worm,
        tsa_live_verification=tsa,
        regulator_export_profile=profile,
        policy_decision_metadata=policy_metadata,
        created_at_utc="2026-05-12T00:15:00Z",
    )
    return record, profile, archive, evidence_record, worm, tsa, policy_metadata


def _result_errors(result: Any) -> tuple[str, ...]:
    if hasattr(result, "errors"):
        return tuple(result.errors)
    if isinstance(result, dict):
        values = result.get("errors") or result.get("denial_reasons") or result.get("gaps") or ()
        return tuple(values)
    return ()


def assert_fail_closed(result: Any, error_code: str | None = None) -> None:
    if hasattr(result, "valid"):
        assert result.valid is False
    elif isinstance(result, dict):
        assert result.get("decision") == "FAIL_CLOSED" or result.get("status") == "FAIL_CLOSED"
    if error_code is not None:
        assert error_code in _result_errors(result)


def assert_approval_required(result: Any) -> None:
    assert "APPROVAL_REQUIRED" in _result_errors(result) or getattr(result, "approval_required", False) is True


def assert_approval_expired(result: Any) -> None:
    assert "APPROVAL_EXPIRED" in _result_errors(result)


def assert_approval_blocked(result: Any) -> None:
    assert "APPROVAL_BLOCKED" in _result_errors(result)


def assert_invalid_signature(result: Any) -> None:
    assert "INVALID_SIGNATURE" in _result_errors(result)


def assert_invalid_manifest(result: Any) -> None:
    assert "INVALID_MANIFEST" in _result_errors(result)


def assert_invalid_worm(result: Any) -> None:
    assert "INVALID_WORM" in _result_errors(result)


def assert_invalid_regulator_export(result: Any, error_code: str) -> None:
    assert_fail_closed(result, error_code)
