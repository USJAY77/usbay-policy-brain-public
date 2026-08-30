from __future__ import annotations

import json

from runtime.computer_use.production_readiness_evidence_export import (
    BLOCKED,
    READY,
    READY_WITH_RESTRICTIONS,
    generate_production_readiness_export,
    verify_production_readiness_export,
)


HASH = "sha256:" + ("a" * 64)
HASH_B = "sha256:" + ("b" * 64)
REVISION = "5283c1ef11ed4ead87a95025502901e488f97045"


def _manifest(**overrides):
    manifest = {
        "schema": "usbay.production_readiness.evidence_export.v1",
        "manifest_id": "pb-1e",
        "generated_at": "2026-07-27T12:00:00Z",
        "repository_revision": REVISION,
        "source_branch": "usbay/p1-e-production-readiness-evidence-export",
        "policy_version": "policy-v1",
        "policy_hash": HASH,
        "execution_contract_version": "pb-1b",
        "execution_contract_hash": HASH,
        "approval_contract_version": "pb-1b",
        "approval_reference": HASH,
        "runtime_gate_version": "pb-1b",
        "runtime_readiness_reference": HASH,
        "dependency_readiness_version": "pb-1c-reference",
        "dependency_readiness_reference": HASH,
        "adapter_contract_version": "pb-1d-reference",
        "adapter_readiness_reference": HASH,
        "evidence_chain_reference": HASH,
        "evidence_chain_integrity": "VERIFIED",
        "timestamp_reference": HASH,
        "timestamp_verification": "VALID_FRESH",
        "test_summary": {"passed": 1, "failed": 0},
        "required_test_results": [{"id": "pb-1e-focused", "required": True, "status": "PASS"}],
        "ci_check_summary": {"passed": 1, "failed": 0},
        "required_ci_results": [{"id": "governance-check", "required": True, "status": "PASS"}],
        "rollback_reference": HASH,
        "rollback_verified": True,
        "known_gaps": [],
        "critical_gap_count": 0,
        "restrictions": [],
        "evidence_hash": HASH,
        "package_hash": "",
        "final_readiness_decision": READY,
        "blocked_reasons": [],
    }
    manifest.update(overrides)
    return manifest


def _restriction(**overrides):
    restriction = {
        "restriction_id": "non-critical-gap",
        "reason": "pilot only",
        "owner": "human-governance-review",
        "approval_reference": HASH,
        "expires_at": "2026-08-27T12:00:00Z",
        "evidence_hash": HASH,
        "policy_authorized": True,
    }
    restriction.update(overrides)
    return restriction


def _assert_blocked(result, reason: str):
    assert result.final_readiness_decision == BLOCKED
    assert reason in result.blocked_reasons
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False


def test_complete_ready_package() -> None:
    result = generate_production_readiness_export(_manifest())

    assert result.final_readiness_decision == READY
    assert result.blocked_reasons == ()


def test_ready_with_valid_reviewed_restriction() -> None:
    result = generate_production_readiness_export(
        _manifest(final_readiness_decision=READY_WITH_RESTRICTIONS, restrictions=[_restriction()])
    )

    assert result.final_readiness_decision == READY_WITH_RESTRICTIONS


def test_missing_policy_version_blocks() -> None:
    manifest = _manifest()
    manifest["policy_version"] = ""
    _assert_blocked(generate_production_readiness_export(manifest), "MISSING_POLICY_VERSION")


def test_missing_execution_contract_reference_blocks() -> None:
    _assert_blocked(generate_production_readiness_export(_manifest(execution_contract_hash="")), "INVALID_EXECUTION_CONTRACT_HASH")


def test_missing_approval_reference_blocks() -> None:
    _assert_blocked(generate_production_readiness_export(_manifest(approval_reference="")), "INVALID_APPROVAL_REFERENCE")


def test_missing_runtime_readiness_blocks() -> None:
    _assert_blocked(generate_production_readiness_export(_manifest(runtime_readiness_reference="")), "INVALID_RUNTIME_READINESS_REFERENCE")


def test_missing_dependency_readiness_blocks() -> None:
    _assert_blocked(generate_production_readiness_export(_manifest(dependency_readiness_reference="")), "INVALID_DEPENDENCY_READINESS_REFERENCE")


def test_missing_adapter_readiness_blocks() -> None:
    _assert_blocked(generate_production_readiness_export(_manifest(adapter_readiness_reference="")), "INVALID_ADAPTER_READINESS_REFERENCE")


def test_missing_evidence_chain_reference_blocks() -> None:
    _assert_blocked(generate_production_readiness_export(_manifest(evidence_chain_reference="")), "INVALID_EVIDENCE_CHAIN_REFERENCE")


def test_invalid_evidence_hash_blocks() -> None:
    _assert_blocked(generate_production_readiness_export(_manifest(evidence_hash="not-a-hash")), "INVALID_EVIDENCE_HASH")


def test_broken_evidence_chain_blocks() -> None:
    _assert_blocked(generate_production_readiness_export(_manifest(evidence_chain_integrity="BROKEN")), "EVIDENCE_CHAIN_BROKEN")


def test_stale_timestamp_blocks() -> None:
    _assert_blocked(generate_production_readiness_export(_manifest(timestamp_verification="STALE")), "TIMESTAMP_STALE_OR_INVALID")


def test_failed_required_test_blocks() -> None:
    _assert_blocked(
        generate_production_readiness_export(_manifest(required_test_results=[{"id": "focused", "required": True, "status": "FAIL"}])),
        "FAILED_REQUIRED_TEST",
    )


def test_missing_required_test_blocks() -> None:
    _assert_blocked(generate_production_readiness_export(_manifest(required_test_results=[])), "MISSING_REQUIRED_TEST")


def test_failed_required_ci_check_blocks() -> None:
    _assert_blocked(
        generate_production_readiness_export(_manifest(required_ci_results=[{"id": "governance", "required": True, "status": "FAIL"}])),
        "FAILED_REQUIRED_CI",
    )


def test_missing_required_ci_check_blocks() -> None:
    _assert_blocked(generate_production_readiness_export(_manifest(required_ci_results=[])), "MISSING_REQUIRED_CI")


def test_missing_rollback_record_blocks() -> None:
    _assert_blocked(generate_production_readiness_export(_manifest(rollback_reference="")), "INVALID_ROLLBACK_REFERENCE")


def test_unverified_rollback_record_blocks() -> None:
    _assert_blocked(generate_production_readiness_export(_manifest(rollback_verified=False)), "ROLLBACK_NOT_VERIFIED")


def test_unresolved_critical_gap_blocks() -> None:
    gap = {"gap_id": "gap-critical", "severity": "CRITICAL"}
    _assert_blocked(generate_production_readiness_export(_manifest(known_gaps=[gap], critical_gap_count=1)), "CRITICAL_GAP_UNRESOLVED")


def test_non_critical_gap_with_valid_restriction() -> None:
    result = generate_production_readiness_export(
        _manifest(
            final_readiness_decision=READY_WITH_RESTRICTIONS,
            known_gaps=[{"gap_id": "gap-low", "severity": "LOW"}],
            restrictions=[_restriction()],
        )
    )

    assert result.final_readiness_decision == READY_WITH_RESTRICTIONS


def test_unauthorized_restriction_blocks() -> None:
    _assert_blocked(
        generate_production_readiness_export(
            _manifest(final_readiness_decision=READY_WITH_RESTRICTIONS, restrictions=[_restriction(policy_authorized=False)])
        ),
        "RESTRICTION_UNAUTHORIZED",
    )


def test_expired_restriction_blocks() -> None:
    _assert_blocked(
        generate_production_readiness_export(
            _manifest(final_readiness_decision=READY_WITH_RESTRICTIONS, restrictions=[_restriction(expires_at="2026-07-27T11:00:00Z")])
        ),
        "RESTRICTION_EXPIRED",
    )


def test_malformed_restriction_blocks() -> None:
    restriction = _restriction()
    restriction.pop("owner")
    _assert_blocked(
        generate_production_readiness_export(_manifest(final_readiness_decision=READY_WITH_RESTRICTIONS, restrictions=[restriction])),
        "MALFORMED_RESTRICTION",
    )


def test_malformed_manifest_blocks() -> None:
    _assert_blocked(generate_production_readiness_export(None), "MALFORMED_MANIFEST")


def test_unsupported_decision_blocks() -> None:
    _assert_blocked(generate_production_readiness_export(_manifest(final_readiness_decision="CERTIFIED")), "UNSUPPORTED_DECISION")


def test_exporter_exception_blocks() -> None:
    class ExplodingManifest(dict):
        def __contains__(self, _key):
            raise RuntimeError("synthetic failure")

    _assert_blocked(generate_production_readiness_export(ExplodingManifest()), "INTERNAL_ERROR")


def test_sensitive_prompt_rejection() -> None:
    _assert_blocked(generate_production_readiness_export(_manifest(prompt="synthetic")), "SENSITIVE_DATA_REJECTED")


def test_credential_rejection() -> None:
    _assert_blocked(generate_production_readiness_export(_manifest(credential="synthetic")), "SENSITIVE_DATA_REJECTED")


def test_personal_data_rejection() -> None:
    _assert_blocked(generate_production_readiness_export(_manifest(personal_data="synthetic")), "SENSITIVE_DATA_REJECTED")


def test_raw_payload_rejection() -> None:
    _assert_blocked(generate_production_readiness_export(_manifest(raw_payload="synthetic")), "SENSITIVE_DATA_REJECTED")


def test_deterministic_json_generation() -> None:
    assert generate_production_readiness_export(_manifest()).canonical_json == generate_production_readiness_export(_manifest()).canonical_json


def test_deterministic_markdown_generation() -> None:
    assert generate_production_readiness_export(_manifest()).markdown_summary == generate_production_readiness_export(_manifest()).markdown_summary


def test_deterministic_package_hash() -> None:
    assert generate_production_readiness_export(_manifest()).package_hash == generate_production_readiness_export(_manifest()).package_hash


def test_tampered_manifest_detection() -> None:
    result = generate_production_readiness_export(_manifest())
    tampered = json.loads(result.canonical_json)
    tampered["policy_hash"] = HASH_B

    verification = verify_production_readiness_export(json.dumps(tampered, sort_keys=True, separators=(",", ":")), result.package_hash)

    _assert_blocked(verification, "PACKAGE_HASH_MISMATCH")


def test_no_deployment_or_execution_side_effect() -> None:
    result = generate_production_readiness_export(_manifest())

    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False


def test_unknown_state_fails_closed() -> None:
    _assert_blocked(generate_production_readiness_export(_manifest(timestamp_verification="UNKNOWN")), "TIMESTAMP_STALE_OR_INVALID")
