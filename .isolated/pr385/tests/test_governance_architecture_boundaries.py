from __future__ import annotations

from pathlib import Path

from governance.chronology import validate_chronology_consensus_interface
from governance.evidence import validate_evidence_manifest_interface
from governance.timestamping import validate_timestamp_verification_interface
from governance.trust_policy import validate_trust_policy_interface
from scripts import generate_ci_evidence_manifest as evidence


def _keypair() -> tuple[str, str]:
    return evidence.generate_ed25519_keypair()


def _trust_policy(public_key: str, signer_id: str = evidence.DEFAULT_SIGNER_ID) -> dict:
    return {
        "policy_version": "ci-evidence-trust-v1",
        "allowed_signers": [
            {
                "signer_id": signer_id,
                "public_key_fingerprint": evidence.signer_key_id(public_key),
                "public_key_pem": evidence.normalize_public_key_pem(public_key),
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
            }
        ],
        "revoked_fingerprints": [],
    }


def test_evidence_manifest_interface_accepts_canonical_manifest(tmp_path: Path) -> None:
    target = tmp_path / "guard-output.txt"
    target.write_text("PRODUCTION_READINESS=true\n", encoding="utf-8")
    manifest = evidence.build_manifest(tmp_path, ["guard-output.txt"], generated_at="2026-05-12T00:00:00Z")

    result = validate_evidence_manifest_interface(manifest)

    assert result.valid is True
    assert result.failures == ()


def test_malformed_chronology_records_fail_closed() -> None:
    result = validate_chronology_consensus_interface(
        {
            "schema": "usbay.governance_chronology_consensus.v1",
            "authority_ids": ["tsa-a", "tsa-b"],
            "quorum_required": 2,
            "max_authority_skew_seconds": 300,
            "chain_head": "hash",
            "targets": [
                {
                    "target": "not-a-dict",
                    "consensus_result": "MAYBE",
                    "consensus_hash": "",
                    "authority_results": "not-a-list",
                }
            ],
        }
    )

    assert result.valid is False
    assert "GOVERNANCE_CHRONOLOGY_CONSENSUS_TARGET_INVALID:0" in result.failures
    assert "GOVERNANCE_CHRONOLOGY_CONSENSUS_RESULT_INVALID:0" in result.failures
    assert "GOVERNANCE_CHRONOLOGY_CONSENSUS_HASH_MISSING:0" in result.failures
    assert "GOVERNANCE_CHRONOLOGY_AUTHORITY_RESULTS_MISSING:0" in result.failures


def test_trust_policy_drift_fails_boundary_validation() -> None:
    _private, public_key = _keypair()
    policy = _trust_policy(public_key)
    del policy["allowed_signers"][0]["public_key_pem"]

    result = validate_trust_policy_interface(policy)

    assert result.valid is False
    assert "EVIDENCE_TRUST_POLICY_SIGNER_FIELD_MISSING:0:public_key_pem" in result.failures


def test_invalid_timestamp_evidence_fails_boundary_validation() -> None:
    result = validate_timestamp_verification_interface(
        {
            "valid": True,
            "timestamp_hash": "",
            "failures": "not-a-list",
        }
    )

    assert result.valid is False
    assert "GOVERNANCE_TIMESTAMP_MESSAGE_IMPRINT_MISSING" in result.failures
    assert "GOVERNANCE_TIMESTAMP_HASH_MISSING" in result.failures
    assert "GOVERNANCE_TIMESTAMP_FAILURES_INVALID" in result.failures


def test_signer_mismatch_continuity_fails_closed() -> None:
    _trusted_private, trusted_public = _keypair()
    _runtime_private, runtime_public = _keypair()
    policy = _trust_policy(trusted_public)

    failures = evidence.validate_signing_key_trusted(runtime_public, evidence.DEFAULT_SIGNER_ID, policy)

    assert "EVIDENCE_SIGNER_NOT_TRUSTED" in failures
    assert "EVIDENCE_PUBLIC_KEY_FINGERPRINT_MISMATCH" in failures

