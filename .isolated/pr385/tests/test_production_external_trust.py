from __future__ import annotations

import copy
import json
from pathlib import Path

from governance.hashing import sha256_reference
from governance.production_external_trust import (
    BLOCKED,
    CONFIGURED,
    CONNECTIVITY_VERIFIED,
    EVIDENCE_VERIFIED,
    FALSE_FLAGS,
    UnavailableExternalCapabilityAdapter,
    aggregate_external_trust,
    evaluate_external_capability,
    export_external_capability_evidence,
    external_trust_contract,
)
from governance.production_readiness_phase4 import (
    EXTERNAL_TRUST_EVIDENCE_VERIFIED,
    deterministic_phase4_signature_reference,
    evaluate_phase4_external_trust_gate,
    load_phase4_manifest,
)


NOW = "2026-07-25T12:00:00Z"
FUTURE = "2026-07-26T12:00:00Z"
COMMIT = "a" * 40
H1 = "sha256:" + ("1" * 64)
H2 = "sha256:" + ("2" * 64)
H3 = "sha256:" + ("3" * 64)
H4 = "sha256:" + ("4" * 64)
H5 = "sha256:" + ("5" * 64)
H6 = "sha256:" + ("6" * 64)
H7 = "sha256:" + ("7" * 64)


def _common(capability_type: str, provider_type: str) -> dict:
    return {
        "capability_id": f"capability:{capability_type}",
        "capability_type": capability_type,
        "provider_id": f"provider:{capability_type}",
        "provider_type": provider_type,
        "environment": "limited_pilot",
        "configuration_state": CONFIGURED,
        "verification_state": EVIDENCE_VERIFIED,
        "verified_at": NOW,
        "expires_at": FUTURE,
        "evidence_reference": H1,
        "evidence_hash": H2,
        "policy_version": "policy:v1",
        "source_commit_sha": COMMIT,
        "request_id": H3,
        "correlation_id": H4,
        "failure_code": "",
        "failure_reason": "",
        "contains_sensitive_data": False,
        "production_eligible": True,
        **FALSE_FLAGS,
    }


def _rfc3161() -> dict:
    payload = _common("rfc3161", "tsa")
    payload.update(
        {
            "tsa_endpoint_id": "tsa:primary",
            "trust_anchor_reference": H5,
            "timeout_ms": 1000,
            "allowed_digest_algorithms": ["sha256"],
            "request_digest": H1,
            "response_digest": H2,
            "nonce_reference": H3,
            "response_nonce_reference": H3,
            "certificate_chain_hash": H4,
            "timestamp_signature_hash": H5,
            "message_imprint_hash": H6,
            "expected_message_imprint_hash": H6,
            "policy_oid": "1.2.3.4",
            "expected_policy_oid": "1.2.3.4",
            "replay_reference": H7,
            "used_replay_references": [],
            "certificate_fingerprint": H5,
        }
    )
    return payload


def _worm() -> dict:
    payload = _common("worm_object_lock", "s3_object_lock")
    payload.update(
        {
            "bucket_reference": "bucket:prod-evidence",
            "object_reference": "object:evidence/1",
            "object_lock_enabled": True,
            "retention_mode": "COMPLIANCE",
            "retention_until": "2027-07-25T12:00:00Z",
            "minimum_retention_until": FUTURE,
            "legal_hold_enabled": True,
            "version_id": "version:1",
            "immutable_object_checksum": H5,
            "readback_checksum": H5,
            "overwrite_attempt_blocked": True,
            "delete_attempt_blocked": True,
            "retention_downgrade_blocked": True,
            "provider_response_hash": H6,
        }
    )
    return payload


def _signing() -> dict:
    payload = _common("external_signing", "external_signing_service")
    payload.update(
        {
            "signer_identity": "signer:external",
            "key_identifier": "key:phase4",
            "key_version": "1",
            "algorithm": "ED25519",
            "allowed_algorithms": ["ED25519"],
            "trust_root_reference": "trust-root:external",
            "payload_hash": H5,
            "signed_payload_hash": H5,
            "environment_binding": "limited_pilot",
            "request_nonce": "nonce:1",
            "signature_hash": H6,
            "signature_verified": True,
            "key_revoked": False,
            "key_expired": False,
            "signer_authorized": True,
            "verification_evidence_hash": H7,
        }
    )
    return payload


def _regulator() -> dict:
    payload = _common("regulator_transport", "governed_outbox")
    payload.update(
        {
            "submission_state": "ACKNOWLEDGED",
            "regulator_jurisdiction": "EU",
            "regulator_endpoint_id": "regulator:eu",
            "approved_regulator_destinations": ["regulator:eu"],
            "submission_type": "audit_export",
            "schema_version": "schema:v1",
            "source_evidence_references": [H1],
            "evidence_hashes": [H2],
            "human_approver_identity": "identity:approver",
            "requester_identity": "identity:requester",
            "approval_timestamp": NOW,
            "approval_expires_at": FUTURE,
            "payload_minimized": True,
            "sensitive_field_classification": "redacted",
            "encryption_required": True,
            "signing_required": True,
            "external_signature_reference": H5,
            "rfc3161_reference": H6,
            "worm_reference": H7,
            "idempotency_key": H1,
            "anti_replay_nonce": H2,
            "used_anti_replay_nonces": [],
            "submission_receipt_hash": H3,
            "acknowledgement_receipt_hash": H4,
            "retry_policy_reference": "retry:bounded",
            "permanent_failure": False,
            "policy_not_applicable_proof": "",
        }
    )
    return payload


def _deployment() -> dict:
    payload = _common("deployment_evidence", "deployment_evidence_provider")
    payload.update(
        {
            "deployment_id": "deployment:1",
            "repository": "USJAY77/usbay-policy-brain-public",
            "artifact_digest": H5,
            "build_provenance_reference": "provenance:1",
            "sbom_reference": "sbom:1",
            "workflow_identity": "workflow:production-readiness",
            "authorized_workflow_identities": ["workflow:production-readiness"],
            "runner_identity": "runner:github-hosted",
            "deployment_target": "target:metadata-only",
            "deployment_start": NOW,
            "deployment_end": FUTURE,
            "deployment_result": "SUCCEEDED",
            "rollback_reference": "rollback:1",
            "human_authorization_reference": H6,
            "external_signature_reference": H5,
            "rfc3161_reference": H6,
            "worm_reference": H7,
            "commit_exists": True,
            "artifact_matches_provenance": True,
            "environment_approved": True,
            "human_authorization_current": True,
            "signature_evidence_valid": True,
            "timestamp_evidence_valid": True,
            "worm_evidence_valid": True,
            "rollback_reference_exists": True,
            "evidence_fresh": True,
            "replay_reference": H1,
            "used_replay_references": [],
            "target_binding": COMMIT,
        }
    )
    return payload


def _verified_results() -> list[dict]:
    return [
        evaluate_external_capability(builder(), timestamp=NOW).to_dict()
        for builder in (_rfc3161, _worm, _signing, _deployment)
    ]


def test_contract_schema_lists_only_governed_states_and_false_flags() -> None:
    contract = external_trust_contract()

    assert "READY" not in contract["capability_states"]
    assert "OPERATIONAL" not in contract["capability_states"]
    assert contract["capability_states"] == [
        "BLOCKED",
        "CONFIGURED",
        "CONNECTIVITY_VERIFIED",
        "EVIDENCE_VERIFIED",
        "INVALID",
        "NOT_CONFIGURED",
        "UNAVAILABLE",
    ]
    for flag in FALSE_FLAGS:
        assert contract[flag] is False


def test_schema_and_manifest_are_parseable_and_truthful() -> None:
    schema = json.loads(Path("governance/evidence/production_external_trust_schema.json").read_text(encoding="utf-8"))
    manifest = json.loads(Path("governance/evidence/production_external_trust_manifest.json").read_text(encoding="utf-8"))

    assert schema["properties"]["execution_allowed"]["const"] is False
    assert manifest["configuration_is_verification"] is False
    assert manifest["connectivity_is_evidence"] is False
    assert manifest["external_evidence_authorizes_execution"] is False


def test_rfc3161_valid_fixture_is_deterministic_but_not_live_production() -> None:
    first = evaluate_external_capability(_rfc3161(), timestamp=NOW)
    second = evaluate_external_capability(_rfc3161(), timestamp=NOW)

    assert first.verification_state == EVIDENCE_VERIFIED
    assert first.capability_hash == second.capability_hash
    assert first.execution_allowed is False
    assert first.provider_execution is False
    assert first.production_activation is False


def test_rfc3161_missing_configuration_blocks() -> None:
    payload = _rfc3161()
    payload["configuration_state"] = "NOT_CONFIGURED"

    result = evaluate_external_capability(payload, timestamp=NOW)

    assert result.verification_state == BLOCKED
    assert "RFC3161_NOT_CONFIGURED" in result.failure_codes


def test_rfc3161_rejects_nonce_replay_imprint_policy_and_timeout_failures() -> None:
    payload = _rfc3161()
    payload["response_nonce_reference"] = H4
    payload["message_imprint_hash"] = H1
    payload["policy_oid"] = "9.9.9"
    payload["used_replay_references"] = [H7]
    payload["timeout_ms"] = 0

    result = evaluate_external_capability(payload, timestamp=NOW)

    assert "RFC3161_NONCE_MISMATCH" in result.failure_codes
    assert "RFC3161_MESSAGE_IMPRINT_MISMATCH" in result.failure_codes
    assert "RFC3161_POLICY_MISMATCH" in result.failure_codes
    assert "RFC3161_REPLAY_DETECTED" in result.failure_codes
    assert "RFC3161_TIMEOUT" in result.failure_codes


def test_worm_valid_fixture_requires_compliance_controls() -> None:
    result = evaluate_external_capability(_worm(), timestamp=NOW)

    assert result.verification_state == EVIDENCE_VERIFIED
    assert result.production_eligible is True
    assert result.deployment_authorized is False


def test_worm_rejects_non_compliance_for_enterprise_production() -> None:
    payload = _worm()
    payload["environment"] = "enterprise_production"
    payload["retention_mode"] = "GOVERNANCE"

    result = evaluate_external_capability(payload, timestamp=NOW)

    assert result.verification_state == BLOCKED
    assert "WORM_RETENTION_MODE_INVALID" in result.failure_codes


def test_worm_rejects_overwrite_delete_checksum_and_version_gaps() -> None:
    payload = _worm()
    payload["overwrite_attempt_blocked"] = False
    payload["delete_attempt_blocked"] = False
    payload["readback_checksum"] = H1
    payload["version_id"] = ""

    result = evaluate_external_capability(payload, timestamp=NOW)

    assert "WORM_OVERWRITE_POSSIBLE" in result.failure_codes
    assert "WORM_DELETE_POSSIBLE" in result.failure_codes
    assert "WORM_CHECKSUM_MISMATCH" in result.failure_codes
    assert "WORM_VERSION_MISSING" in result.failure_codes


def test_external_signing_valid_fixture_has_no_secret_material() -> None:
    result = evaluate_external_capability(_signing(), timestamp=NOW)
    exported = export_external_capability_evidence(result)

    assert result.verification_state == EVIDENCE_VERIFIED
    assert exported["capability_hash"].startswith("sha256:")
    assert "private_key" not in str(exported)
    assert exported["release_authorized"] is False


def test_external_signing_rejects_bad_algorithm_context_and_revoked_key() -> None:
    payload = _signing()
    payload["algorithm"] = "MD5"
    payload["environment_binding"] = "enterprise_production"
    payload["key_revoked"] = True

    result = evaluate_external_capability(payload, timestamp=NOW)

    assert "SIGNATURE_ALGORITHM_UNSUPPORTED" in result.failure_codes
    assert "SIGNATURE_CONTEXT_MISMATCH" in result.failure_codes
    assert "SIGNING_KEY_REVOKED" in result.failure_codes


def test_regulator_transport_valid_fixture_is_evidence_only() -> None:
    result = evaluate_external_capability(_regulator(), timestamp=NOW)

    assert result.verification_state == EVIDENCE_VERIFIED
    assert result.provider_execution is False
    assert result.release_authorized is False


def test_regulator_transport_requires_approval_signature_timestamp_and_worm() -> None:
    payload = _regulator()
    payload["human_approver_identity"] = "identity:requester"
    payload["external_signature_reference"] = ""
    payload["rfc3161_reference"] = ""
    payload["worm_reference"] = ""

    result = evaluate_external_capability(payload, timestamp=NOW)

    assert "REGULATOR_SELF_APPROVAL_BLOCKED" in result.failure_codes
    assert "REGULATOR_SIGNATURE_MISSING" in result.failure_codes
    assert "REGULATOR_TIMESTAMP_MISSING" in result.failure_codes
    assert "REGULATOR_WORM_EVIDENCE_MISSING" in result.failure_codes


def test_deployment_evidence_verifies_evidence_without_authorizing_deploy() -> None:
    result = evaluate_external_capability(_deployment(), timestamp=NOW)

    assert result.verification_state == EVIDENCE_VERIFIED
    assert result.deployment_authorized is False
    assert result.release_authorized is False


def test_deployment_evidence_rejects_mismatched_commit_and_missing_rollback() -> None:
    payload = _deployment()
    payload["target_binding"] = "b" * 40
    payload["rollback_reference_exists"] = False
    payload["replay_reference"] = H1
    payload["used_replay_references"] = [H1]

    result = evaluate_external_capability(payload, timestamp=NOW)

    assert "DEPLOYMENT_COMMIT_MISMATCH" in result.failure_codes
    assert "DEPLOYMENT_ROLLBACK_REFERENCE_MISSING" in result.failure_codes
    assert "DEPLOYMENT_REPLAY_DETECTED" in result.failure_codes


def test_unknown_fields_and_sensitive_data_fail_closed() -> None:
    payload = _rfc3161()
    payload["raw_provider_response"] = "forbidden"

    result = evaluate_external_capability(payload, timestamp=NOW)

    assert result.verification_state == BLOCKED
    assert "EXTERNAL_TRUST_UNKNOWN_FIELD" in result.failure_codes
    assert "EXTERNAL_TRUST_SENSITIVE_DATA_PRESENT" in result.failure_codes


def test_unavailable_adapter_never_simulates_success() -> None:
    result = UnavailableExternalCapabilityAdapter("rfc3161").evaluate(None, timestamp=NOW)

    assert result.verification_state == BLOCKED
    assert "EXTERNAL_TRUST_PROVIDER_ID_MISSING" in result.failure_codes
    assert result.production_eligible is False


def test_enterprise_production_fixture_provider_cannot_satisfy_live_evidence() -> None:
    payload = _rfc3161()
    payload["environment"] = "enterprise_production"
    payload["provider_id"] = "fixture:tsa"

    result = evaluate_external_capability(payload, timestamp=NOW)

    assert result.verification_state == BLOCKED
    assert "EXTERNAL_TRUST_PRODUCTION_ELIGIBLE_WITHOUT_EVIDENCE" in result.failure_codes


def test_interfaces_only_do_not_satisfy_external_trust_aggregate() -> None:
    payload = _rfc3161()
    payload["verification_state"] = CONNECTIVITY_VERIFIED
    results = [evaluate_external_capability(payload, timestamp=NOW).to_dict()]

    aggregate = aggregate_external_trust(results, regulator_required=False)

    assert aggregate.decision == BLOCKED
    assert "EXTERNAL_TRUST_REQUIRED_CAPABILITY_MISSING:rfc3161" in aggregate.failure_codes


def test_all_required_verified_evidence_returns_external_trust_verified() -> None:
    aggregate = aggregate_external_trust(_verified_results(), regulator_required=False)

    assert aggregate.decision == "EXTERNAL_TRUST_EVIDENCE_VERIFIED"
    assert aggregate.production_boundary_ready is False
    for flag in FALSE_FLAGS:
        assert getattr(aggregate, flag) is False


def test_one_missing_capability_blocks_aggregate() -> None:
    aggregate = aggregate_external_trust(_verified_results()[:-1], regulator_required=False)

    assert aggregate.decision == BLOCKED
    assert "EXTERNAL_TRUST_REQUIRED_CAPABILITY_MISSING:deployment_evidence" in aggregate.failure_codes


def test_regulator_required_blocks_without_regulator_evidence() -> None:
    aggregate = aggregate_external_trust(_verified_results(), regulator_required=True)

    assert aggregate.decision == BLOCKED
    assert "EXTERNAL_TRUST_REQUIRED_CAPABILITY_MISSING:regulator_transport" in aggregate.failure_codes


def test_regulator_evidence_satisfies_aggregate_when_policy_requires_it() -> None:
    results = _verified_results() + [evaluate_external_capability(_regulator(), timestamp=NOW).to_dict()]

    aggregate = aggregate_external_trust(results, regulator_required=True)

    assert aggregate.decision == "EXTERNAL_TRUST_EVIDENCE_VERIFIED"


def test_phase4_external_trust_gate_keeps_authorization_flags_false() -> None:
    manifest = copy.deepcopy(load_phase4_manifest())
    manifest["signature_reference"] = deterministic_phase4_signature_reference(manifest)

    result = evaluate_phase4_external_trust_gate(
        manifest,
        timestamp=NOW,
        external_trust_results=_verified_results(),
        regulator_required=False,
    )

    assert result.decision == EXTERNAL_TRUST_EVIDENCE_VERIFIED
    assert result.production_boundary_ready is False
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False
    assert result.release_authorized is False


def test_deterministic_hashing_for_provider_evidence() -> None:
    first = evaluate_external_capability(_deployment(), timestamp=NOW)
    second = evaluate_external_capability(_deployment(), timestamp=NOW)

    assert first.capability_hash == second.capability_hash
    assert first.capability_hash == sha256_reference(
        {
            "schema": "usbay.production_readiness.external_trust.v1",
            "capability_id": "capability:deployment_evidence",
            "capability_type": "deployment_evidence",
            "provider_id": "provider:deployment_evidence",
            "provider_type": "deployment_evidence_provider",
            "environment": "limited_pilot",
            "configuration_state": "CONFIGURED",
            "verification_state": "EVIDENCE_VERIFIED",
            "failure_codes": [],
            "evidence_reference": H1,
            "evidence_hash": H2,
            "policy_version": "policy:v1",
            "source_commit_sha": COMMIT,
            "request_id": H3,
            "correlation_id": H4,
            "production_eligible": True,
            "timestamp": NOW,
            **FALSE_FLAGS,
        }
    )
