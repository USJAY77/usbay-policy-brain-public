from __future__ import annotations

import json

import pytest

from governance.evidence_renewal_runtime import verify_evidence_renewal_runtime_record
from governance.regulator_export_profile import verify_regulator_export_profile
from governance.signed_auditor_bundle import verify_signed_auditor_bundle
from governance.signed_bundle_ltv import verify_signed_bundle_ltv_evidence
from governance.signed_bundle_timestamp import verify_signed_bundle_timestamp
from governance.worm_immutable_storage import verify_worm_immutable_storage_plan
from tests.governance_test_builders import (
    ApprovalBuilder,
    EvidenceBuilder,
    ManifestBuilder,
    PolicyBuilder,
    SignedBundleBuilder,
    assert_approval_blocked,
    assert_approval_expired,
    assert_approval_required,
    assert_fail_closed,
    assert_invalid_manifest,
    assert_invalid_regulator_export,
    assert_invalid_signature,
    assert_invalid_worm,
)


def test_policy_builder_returns_deterministic_hash_only_metadata() -> None:
    builder = PolicyBuilder()

    first = builder.policy_metadata()
    second = builder.policy_metadata()

    assert first == second
    assert len(first["actor_hash"]) == 64
    assert len(first["policy_hash"]) == 64
    assert "PRIVATE KEY" not in repr(first)
    assert "approval_contents" not in repr(first)


def test_builders_preserve_canonical_serialization() -> None:
    policy = PolicyBuilder().policy_pack()
    evidence = EvidenceBuilder().evidence_bundle()

    first = json.dumps({"evidence": evidence, "policy": policy}, sort_keys=True, separators=(",", ":"))
    second = json.dumps({"evidence": dict(reversed(evidence.items())), "policy": dict(reversed(policy.items()))}, sort_keys=True, separators=(",", ":"))

    assert first == second


def test_fixture_builders_return_hash_only_references() -> None:
    approval = ApprovalBuilder().approval_reference()
    manifest = ManifestBuilder().manifest()
    signed_bundle = SignedBundleBuilder().signed_bundle()
    evidence = EvidenceBuilder().evidence_bundle()
    worm = EvidenceBuilder().worm_archive()

    rendered = repr((approval, manifest, signed_bundle, evidence, worm))

    assert "approval://local-only/sha256/" in approval["approval_reference"]
    assert "signature://local-only/sha256/" in signed_bundle["signature_reference"]
    assert "evidence://local-only/sha256/" in evidence["evidence_reference"]
    assert "worm://local-only/sha256/" in worm["archive_reference"]
    assert "PRIVATE KEY" not in rendered
    assert "approval_contents" not in rendered


def test_simple_builders_return_fresh_copies() -> None:
    approval_builder = ApprovalBuilder()
    manifest_builder = ManifestBuilder()
    signed_bundle_builder = SignedBundleBuilder()
    evidence_builder = EvidenceBuilder()

    approval = approval_builder.approval_reference()
    manifest = manifest_builder.manifest()
    signed_bundle = signed_bundle_builder.signed_bundle()
    evidence = evidence_builder.evidence_bundle()

    approval["approval_hash"] = "mutated"
    manifest["manifest_hash"] = "mutated"
    signed_bundle["signature_hash"] = "mutated"
    evidence["evidence_hash"] = "mutated"

    assert approval_builder.approval_reference()["approval_hash"] != "mutated"
    assert manifest_builder.manifest()["manifest_hash"] != "mutated"
    assert signed_bundle_builder.signed_bundle()["signature_hash"] != "mutated"
    assert evidence_builder.evidence_bundle()["evidence_hash"] != "mutated"


def test_explicit_overrides_do_not_cross_tenant_or_policy_boundaries() -> None:
    tenant_a_policy = PolicyBuilder(tenant_id="tenant-a", policy_version="policy.a").policy_pack()
    tenant_b_policy = PolicyBuilder(tenant_id="tenant-b", policy_version="policy.b").policy_pack()
    tenant_a_evidence = EvidenceBuilder(tenant_id="tenant-a", policy_version="policy.a").evidence_bundle()

    assert tenant_a_policy["tenant_id"] == "tenant-a"
    assert tenant_a_policy["policy_version"] == "policy.a"
    assert tenant_b_policy["tenant_id"] == "tenant-b"
    assert tenant_b_policy["policy_version"] == "policy.b"
    assert tenant_a_evidence["tenant_id"] == tenant_a_policy["tenant_id"]
    assert tenant_a_evidence["policy_version"] == tenant_a_policy["policy_version"]
    assert tenant_a_policy["tenant_id"] != tenant_b_policy["tenant_id"]
    assert tenant_a_policy["policy_version"] != tenant_b_policy["policy_version"]


def test_builders_reject_unsupported_override_fields() -> None:
    with pytest.raises(ValueError, match="unsupported governance test override:raw_payload"):
        PolicyBuilder().policy_pack(raw_payload="do-not-default")

    with pytest.raises(ValueError, match="unsupported governance test override:approval_contents"):
        ApprovalBuilder().approval_reference(approval_contents="do-not-default")


def test_evidence_builder_returns_isolated_regulator_export_copies() -> None:
    builder = EvidenceBuilder()
    first_profile, *_first_rest = builder.regulator_export_profile()
    first_profile["export_profile_hash"] = "mutated"

    second_profile, *_second_rest = builder.regulator_export_profile()

    assert second_profile["export_profile_hash"] != "mutated"


def test_evidence_builder_returns_isolated_renewal_runtime_copies() -> None:
    builder = EvidenceBuilder()
    first_record, *_first_rest = builder.evidence_renewal_runtime_record()
    first_record["latest_renewal_runtime_hash"] = "mutated"

    second_record, *_second_rest = builder.evidence_renewal_runtime_record()

    assert second_record["latest_renewal_runtime_hash"] != "mutated"


def test_evidence_builder_returns_isolated_worm_and_ltv_copies() -> None:
    builder = EvidenceBuilder()
    first_worm, _first_archive, _first_record = builder.worm_immutable_storage_plan()
    first_attachment, _first_envelope, _first_policy = builder.signed_bundle_timestamp_attachment()
    first_ltv, _first_attachment = builder.signed_bundle_ltv_evidence()
    first_worm["immutable_storage_manifest_hash"] = "mutated"
    first_attachment["timestamp_token_hash"] = "mutated"
    first_ltv["ltv_evidence_id"] = "mutated"

    second_worm, _second_archive, _second_record = builder.worm_immutable_storage_plan()
    second_attachment, _second_envelope, _second_policy = builder.signed_bundle_timestamp_attachment()
    second_ltv, _second_attachment = builder.signed_bundle_ltv_evidence()

    assert second_worm["immutable_storage_manifest_hash"] != "mutated"
    assert second_attachment["timestamp_token_hash"] != "mutated"
    assert second_ltv["ltv_evidence_id"] != "mutated"


def test_regulator_export_builder_matches_verifier_contract() -> None:
    profile, archive, evidence_record, worm, tsa, policy_metadata = EvidenceBuilder().regulator_export_profile()

    result = verify_regulator_export_profile(
        profile,
        sealed_archive=archive,
        evidence_record_chain=evidence_record,
        worm_immutable_storage=worm,
        tsa_live_verification=tsa,
        policy_decision_metadata=policy_metadata,
    )

    assert result.valid is True
    assert result.errors == ()


def test_worm_builder_matches_verifier_contract() -> None:
    plan, archive, evidence_record = EvidenceBuilder().worm_immutable_storage_plan()

    result = verify_worm_immutable_storage_plan(
        plan,
        sealed_archive=archive,
        evidence_record_chain=evidence_record,
    )

    assert result.valid is True
    assert result.errors == ()


def test_signed_bundle_ltv_builder_matches_verifier_contract() -> None:
    ltv, attachment = EvidenceBuilder().signed_bundle_ltv_evidence()

    result = verify_signed_bundle_ltv_evidence(ltv, timestamp_attachment=attachment)

    assert result.valid is True
    assert result.errors == ()


def test_signed_auditor_builder_matches_verifier_contract() -> None:
    envelope, auditor_bundle, policy = EvidenceBuilder().signed_auditor_envelope()

    result = verify_signed_auditor_bundle(
        envelope,
        auditor_bundle=auditor_bundle,
        trust_policy=policy,
    )

    assert result.valid is True
    assert result.errors == ()


def test_signed_bundle_timestamp_builder_matches_verifier_contract() -> None:
    attachment, envelope, _policy = EvidenceBuilder().signed_bundle_timestamp_attachment()

    result = verify_signed_bundle_timestamp(attachment, signed_bundle=envelope)

    assert result.valid is True
    assert result.errors == ()


def test_renewal_runtime_builder_matches_verifier_contract() -> None:
    record, profile, archive, evidence_record, worm, tsa, policy_metadata = EvidenceBuilder().evidence_renewal_runtime_record()

    result = verify_evidence_renewal_runtime_record(
        record,
        evidence_record_chain=evidence_record,
        sealed_archive=archive,
        worm_immutable_storage=worm,
        tsa_live_verification=tsa,
        regulator_export_profile=profile,
        policy_decision_metadata=policy_metadata,
    )

    assert result.valid is True
    assert result.errors == ()


def test_negative_mutations_remain_explicit_and_fail_closed() -> None:
    profile, archive, _evidence_record, worm, tsa, policy_metadata = EvidenceBuilder().regulator_export_profile()
    profile["evidence_record_id"] = ""

    result = verify_regulator_export_profile(
        profile,
        sealed_archive=archive,
        worm_immutable_storage=worm,
        tsa_live_verification=tsa,
        policy_decision_metadata=policy_metadata,
    )

    assert_invalid_regulator_export(result, "REGULATOR_EXPORT_EVIDENCE_CHAIN_MISSING")


def test_governance_assertion_helpers_preserve_fail_closed_checks() -> None:
    class Result:
        valid = False
        errors = (
            "APPROVAL_REQUIRED",
            "APPROVAL_EXPIRED",
            "APPROVAL_BLOCKED",
            "INVALID_SIGNATURE",
            "INVALID_MANIFEST",
            "INVALID_WORM",
            "REGULATOR_EXPORT_EVIDENCE_CHAIN_MISSING",
        )

    result = Result()

    assert_fail_closed(result, "INVALID_MANIFEST")
    assert_approval_required(result)
    assert_approval_expired(result)
    assert_approval_blocked(result)
    assert_invalid_signature(result)
    assert_invalid_manifest(result)
    assert_invalid_worm(result)
    assert_invalid_regulator_export(result, "REGULATOR_EXPORT_EVIDENCE_CHAIN_MISSING")


def test_governance_assertion_helpers_fail_on_missing_error() -> None:
    class Result:
        valid = False
        errors = ("OTHER_ERROR",)

    with pytest.raises(AssertionError):
        assert_invalid_manifest(Result())
