from __future__ import annotations

import json

import pytest

from governance.audit_evidence import (
    AUDIT_EVIDENCE_FIELDS,
    AUDIT_EVIDENCE_SCHEMA,
    AUDIT_PIPELINE_STAGE_SEQUENCE,
    ZERO_AUDIT_CHAIN_HASH,
    AuditEvidenceContext,
    AuditEvidenceError,
    attach_audit_evidence,
    audit_evidence_schema,
    build_audit_chain_record,
    build_audit_evidence,
    build_audit_pipeline_summary,
    canonical_audit_json,
    serialize_audit_evidence,
    serialize_audit_pipeline_summary,
    sha256_audit_hash,
    validate_audit_evidence,
    verify_audit_chain_records,
)
from governance.policy_pack import validate_policy_pack
from governance.regulator_export_profile import verify_regulator_export_profile
from governance.repo_production_readiness import RepoReadinessResult
from governance.signed_bundle_ltv import verify_signed_bundle_ltv_evidence
from governance.worm_immutable_storage import verify_worm_immutable_storage_plan
from tests.governance_test_builders import (
    ApprovalBuilder,
    EvidenceBuilder,
    ManifestBuilder,
    PolicyBuilder,
    SignedBundleBuilder,
)


TIMESTAMP = "2026-05-12T00:20:00Z"


def _audit_kwargs(validator: str, output: object, payload: object) -> dict:
    return {
        "validator": validator,
        "validation_output": output,
        "canonical_payload": payload,
        "timestamp": TIMESTAMP,
        "policy_version": "policy.v1",
        "tenant": "tenant-governance-test",
        "evidence_id": "evidence://local-only/sha256/" + ("e" * 64),
    }


def _context(validator: str, *, tenant: str = "tenant-governance-test", policy_version: str = "policy.v1") -> AuditEvidenceContext:
    return AuditEvidenceContext(
        validator=validator,
        timestamp=TIMESTAMP,
        policy_version=policy_version,
        tenant=tenant,
        evidence_id="evidence://local-only/sha256/" + ("e" * 64),
    )


def _pipeline_evidences(*, tenant: str = "tenant-governance-test", policy_version: str = "policy.v1") -> tuple:
    evidences = []
    for index, validator in enumerate(AUDIT_PIPELINE_STAGE_SEQUENCE):
        attached = attach_audit_evidence(
            {"valid": True, "errors": []},
            canonical_payload={"stage": validator, "position": index},
            context=AuditEvidenceContext(
                validator=validator,
                timestamp=TIMESTAMP,
                policy_version=policy_version,
                tenant=tenant,
                evidence_id=f"evidence://local-only/sha256/{index:064x}",
            ),
        )
        assert attached.audit_evidence is not None
        evidences.append(attached.audit_evidence)
    return tuple(evidences)


def _blocked_output(reason: str) -> dict:
    return {
        "valid": False,
        "errors": [reason],
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
        "runtime_execution": False,
        "deployment_execution": False,
        "policy_mutation": False,
        "network_access": False,
    }


def test_audit_schema_is_machine_readable_and_ordered() -> None:
    schema = audit_evidence_schema()

    assert schema["schema"] == AUDIT_EVIDENCE_SCHEMA
    assert tuple(schema["fields"]) == AUDIT_EVIDENCE_FIELDS
    assert schema["payload_policy"] == "hash-only"
    assert tuple(schema["pipeline_stage_sequence"]) == AUDIT_PIPELINE_STAGE_SEQUENCE
    assert json.loads(canonical_audit_json(schema)) == schema


def test_audit_serialization_is_deterministic_for_identical_validation() -> None:
    plan, archive, evidence_record = EvidenceBuilder().worm_immutable_storage_plan()
    result = verify_worm_immutable_storage_plan(plan, sealed_archive=archive, evidence_record_chain=evidence_record)

    first = build_audit_evidence(**_audit_kwargs("worm", result, plan))
    second = build_audit_evidence(**_audit_kwargs("worm", result, dict(reversed(plan.items()))))

    assert first == second
    assert serialize_audit_evidence(first) == serialize_audit_evidence(second)
    assert first.audit_hash == second.audit_hash
    assert first.canonical_payload_hash == second.canonical_payload_hash


def test_serialized_audit_output_has_stable_key_order() -> None:
    result = {"valid": True, "errors": []}
    audit = build_audit_evidence(**_audit_kwargs("approvals", result, ApprovalBuilder().approval_reference()))
    serialized = serialize_audit_evidence(audit)

    assert tuple(json.loads(serialized)) == tuple(sorted(AUDIT_EVIDENCE_FIELDS))
    assert serialized == canonical_audit_json(audit.to_dict())


@pytest.mark.parametrize(
    ("validator", "validation_output", "payload"),
    (
        ("approvals", {"valid": True, "errors": []}, ApprovalBuilder().approval_reference()),
        ("evidence", {"valid": True, "errors": []}, EvidenceBuilder().evidence_bundle()),
        ("signatures", {"valid": True, "errors": []}, SignedBundleBuilder().signed_bundle()),
        ("manifests", {"valid": True, "errors": []}, ManifestBuilder().manifest()),
        (
            "production_readiness",
            RepoReadinessResult(valid=True, verdict="READY", reason_codes=(), audit={"summary": "hash-only"}),
            {"readiness": "metadata-only"},
        ),
    ),
)
def test_audit_evidence_wraps_governance_validation_domains(validator: str, validation_output: object, payload: object) -> None:
    audit = build_audit_evidence(**_audit_kwargs(validator, validation_output, payload))

    validate_audit_evidence(audit.to_dict())
    assert audit.result == "PASS"
    assert audit.failure_code == ""
    assert audit.audit_hash.startswith("sha256:")
    assert audit.canonical_payload_hash.startswith("sha256:")


def test_audit_evidence_wraps_regulator_exports_signed_bundles_and_worm() -> None:
    profile, archive, evidence_record, worm, tsa, policy_metadata = EvidenceBuilder().regulator_export_profile()
    regulator_result = verify_regulator_export_profile(
        profile,
        sealed_archive=archive,
        evidence_record_chain=evidence_record,
        worm_immutable_storage=worm,
        tsa_live_verification=tsa,
        policy_decision_metadata=policy_metadata,
    )
    ltv, attachment = EvidenceBuilder().signed_bundle_ltv_evidence()
    ltv_result = verify_signed_bundle_ltv_evidence(ltv, timestamp_attachment=attachment)
    worm_result = verify_worm_immutable_storage_plan(worm, sealed_archive=archive, evidence_record_chain=evidence_record)

    regulator_audit = build_audit_evidence(**_audit_kwargs("regulator_exports", regulator_result, profile))
    ltv_audit = build_audit_evidence(**_audit_kwargs("signed_bundles", ltv_result, ltv))
    worm_audit = build_audit_evidence(**_audit_kwargs("worm", worm_result, worm))

    assert regulator_audit.result == "PASS"
    assert ltv_audit.result == "PASS"
    assert worm_audit.result == "PASS"
    assert len({regulator_audit.audit_hash, ltv_audit.audit_hash, worm_audit.audit_hash}) == 3


def test_policy_validation_audit_preserves_fail_closed_output() -> None:
    policy_pack = PolicyBuilder().policy_pack()
    policy_pack.pop("schema")

    result = validate_policy_pack(policy_pack)
    error_order = tuple(error.code for error in result.errors)
    audit = build_audit_evidence(**_audit_kwargs("policy_validation", result, policy_pack))

    assert result.valid is False
    assert tuple(error.code for error in result.errors) == error_order
    assert audit.result == "FAIL_CLOSED"
    assert audit.failure_code == error_order[0]
    validate_audit_evidence(audit.to_dict())


def test_regulator_export_fail_closed_output_is_unchanged() -> None:
    profile, archive, _evidence_record, worm, tsa, policy_metadata = EvidenceBuilder().regulator_export_profile()
    profile["evidence_record_id"] = ""

    result = verify_regulator_export_profile(
        profile,
        sealed_archive=archive,
        worm_immutable_storage=worm,
        tsa_live_verification=tsa,
        policy_decision_metadata=policy_metadata,
    )
    audit = build_audit_evidence(**_audit_kwargs("regulator_exports", result, profile))

    assert result.valid is False
    assert result.errors == ("REGULATOR_EXPORT_EVIDENCE_CHAIN_MISSING",)
    assert audit.result == "FAIL_CLOSED"
    assert audit.failure_code == "REGULATOR_EXPORT_EVIDENCE_CHAIN_MISSING"


def test_audit_evidence_contains_no_raw_payload() -> None:
    payload = {"raw_payload": "customer-secret", "evidence_hash": "e" * 64}
    audit = build_audit_evidence(**_audit_kwargs("evidence", {"valid": True}, payload))
    serialized = serialize_audit_evidence(audit)

    assert "customer-secret" not in serialized
    assert "raw_payload" not in serialized
    assert sha256_audit_hash(payload) == audit.canonical_payload_hash


def test_opt_in_attachment_preserves_original_validation_output() -> None:
    result = _blocked_output("APPROVAL_EXPIRED")

    attached = attach_audit_evidence(
        result,
        canonical_payload=ApprovalBuilder().approval_reference(state="EXPIRED"),
        context=_context("approvals"),
    )

    assert attached.validation_output is result
    assert attached.audit_generation_error == ""
    assert attached.audit_evidence is not None
    assert attached.audit_evidence.result == "FAIL_CLOSED"
    assert attached.audit_evidence.failure_code == "APPROVAL_EXPIRED"
    assert attached.validation_output["execution_allowed"] is False
    assert attached.validation_output["provider_execution"] is False
    assert attached.validation_output["production_activation"] is False
    assert attached.validation_output["runtime_execution"] is False
    assert attached.validation_output["deployment_execution"] is False
    assert attached.validation_output["policy_mutation"] is False
    assert attached.validation_output["network_access"] is False


def test_attachment_reports_incomplete_context_without_changing_decision() -> None:
    result = _blocked_output("APPROVAL_REQUIRED")

    attached = attach_audit_evidence(
        result,
        canonical_payload=ApprovalBuilder().approval_reference(state="REVIEW_REQUIRED"),
        context=AuditEvidenceContext(
            validator="approvals",
            timestamp=TIMESTAMP,
            policy_version="",
            tenant="tenant-governance-test",
            evidence_id="evidence://local-only/sha256/" + ("e" * 64),
        ),
    )

    assert attached.validation_output is result
    assert attached.audit_evidence is None
    assert attached.audit_generation_error == "AUDIT_EVIDENCE_CONTEXT_POLICY_VERSION_MISSING"
    assert attached.validation_output["errors"] == ["APPROVAL_REQUIRED"]


@pytest.mark.parametrize(
    ("validator", "reason", "payload"),
    (
        ("evidence", "EVIDENCE_MISSING", {}),
        ("evidence", "EVIDENCE_MALFORMED", {"schema": None}),
        ("signatures", "INVALID_SIGNATURE", {"signature_hash": ""}),
        ("manifests", "INVALID_MANIFEST", {"manifest_hash": "mismatch"}),
        ("approvals", "APPROVAL_EXPIRED", ApprovalBuilder().approval_reference(state="EXPIRED")),
        ("approvals", "APPROVAL_REQUIRED", ApprovalBuilder().approval_reference(state="REVIEW_REQUIRED")),
        ("worm", "INVALID_WORM", {"worm_archive_hash": ""}),
        ("regulator_exports", "REGULATOR_EXPORT_EVIDENCE_CHAIN_MISSING", {"evidence_record_id": ""}),
        ("signed_bundles", "SIGNED_BUNDLE_SIGNATURE_INVALID", {"signature": "invalid"}),
        ("production_readiness", "PRODUCTION_READINESS_FAILURE", {"ready": False}),
    ),
)
def test_negative_audit_adoption_preserves_fail_closed_flags(validator: str, reason: str, payload: dict) -> None:
    result = _blocked_output(reason)

    attached = attach_audit_evidence(
        result,
        canonical_payload=payload,
        context=_context(validator),
    )

    assert attached.audit_evidence is not None
    assert attached.audit_evidence.result == "FAIL_CLOSED"
    assert attached.audit_evidence.failure_code == reason
    assert attached.validation_output["errors"] == [reason]
    assert attached.validation_output["execution_allowed"] is False
    assert attached.validation_output["provider_execution"] is False
    assert attached.validation_output["production_activation"] is False
    assert attached.validation_output["runtime_execution"] is False
    assert attached.validation_output["deployment_execution"] is False
    assert attached.validation_output["policy_mutation"] is False
    assert attached.validation_output["network_access"] is False


def test_tenant_policy_content_and_failure_changes_modify_audit_hash() -> None:
    result = _blocked_output("TENANT_MISMATCH")
    base_payload = {"tenant_hash": "tenant-a", "policy_version": "policy.v1", "evidence": "a"}
    base = attach_audit_evidence(result, canonical_payload=base_payload, context=_context("evidence")).audit_evidence
    tenant_changed = attach_audit_evidence(
        result,
        canonical_payload=base_payload,
        context=_context("evidence", tenant="tenant-b"),
    ).audit_evidence
    policy_changed = attach_audit_evidence(
        result,
        canonical_payload=base_payload,
        context=_context("evidence", policy_version="policy.v2"),
    ).audit_evidence
    content_changed = attach_audit_evidence(
        result,
        canonical_payload={**base_payload, "evidence": "b"},
        context=_context("evidence"),
    ).audit_evidence
    failure_changed = attach_audit_evidence(
        _blocked_output("POLICY_VERSION_MISMATCH"),
        canonical_payload=base_payload,
        context=_context("evidence"),
    ).audit_evidence

    assert base is not None
    assert tenant_changed is not None
    assert policy_changed is not None
    assert content_changed is not None
    assert failure_changed is not None
    assert len(
        {
            base.audit_hash,
            tenant_changed.audit_hash,
            policy_changed.audit_hash,
            content_changed.audit_hash,
            failure_changed.audit_hash,
        }
    ) == 5


def test_reordered_payloads_preserve_canonical_payload_hash() -> None:
    result = {"valid": True, "errors": []}
    first = attach_audit_evidence(
        result,
        canonical_payload={"b": {"d": 2, "c": 1}, "a": [3, 2, 1]},
        context=_context("evidence"),
    ).audit_evidence
    second = attach_audit_evidence(
        result,
        canonical_payload={"a": [3, 2, 1], "b": {"c": 1, "d": 2}},
        context=_context("evidence"),
    ).audit_evidence

    assert first is not None
    assert second is not None
    assert first.canonical_payload_hash == second.canonical_payload_hash
    assert first.audit_hash == second.audit_hash


def test_audit_records_are_chain_compatible_and_tamper_evident() -> None:
    first = attach_audit_evidence(
        {"valid": True, "errors": []},
        canonical_payload=EvidenceBuilder().evidence_bundle(),
        context=_context("evidence"),
    ).audit_evidence
    second = attach_audit_evidence(
        _blocked_output("INVALID_WORM"),
        canonical_payload=EvidenceBuilder().worm_archive(),
        context=_context("worm"),
    ).audit_evidence
    assert first is not None
    assert second is not None
    first_record = build_audit_chain_record(first, previous_hash=ZERO_AUDIT_CHAIN_HASH, position=0)
    second_record = build_audit_chain_record(second, previous_hash=first_record["record_hash"], position=1)

    assert verify_audit_chain_records((first_record, second_record)) == ()

    tampered = dict(second_record)
    tampered["audit_hash"] = first_record["audit_hash"]
    assert "AUDIT_CHAIN_DUPLICATE_RECORD" in verify_audit_chain_records((first_record, tampered))
    assert "AUDIT_CHAIN_RECORD_HASH_MISMATCH" in verify_audit_chain_records((first_record, tampered))
    assert "AUDIT_CHAIN_POSITION_INVALID" in verify_audit_chain_records((second_record, first_record))
    assert "AUDIT_CHAIN_PREVIOUS_HASH_MISMATCH" in verify_audit_chain_records((second_record, first_record))


def test_pipeline_summary_proves_end_to_end_audit_continuity() -> None:
    evidences = _pipeline_evidences()

    summary = build_audit_pipeline_summary(evidences)
    repeated = build_audit_pipeline_summary(tuple(evidence.to_dict() for evidence in evidences))

    assert summary.valid is True
    assert summary.errors == ()
    assert summary.stage_count == len(AUDIT_PIPELINE_STAGE_SEQUENCE)
    assert summary.stage_hashes == tuple(evidence.audit_hash for evidence in evidences)
    assert summary.canonical_payload_hashes == tuple(evidence.canonical_payload_hash for evidence in evidences)
    assert summary.correlation_id == repeated.correlation_id
    assert serialize_audit_pipeline_summary(summary) == serialize_audit_pipeline_summary(repeated)
    assert '"position"' not in serialize_audit_pipeline_summary(summary)
    assert "policy_validation" not in serialize_audit_pipeline_summary(summary)


def test_pipeline_summary_detects_missing_duplicate_and_reordered_stages() -> None:
    evidences = _pipeline_evidences()

    missing = build_audit_pipeline_summary(evidences[:-1])
    duplicate = build_audit_pipeline_summary((*evidences, evidences[-1]))
    reordered = build_audit_pipeline_summary((evidences[1], evidences[0], *evidences[2:]))

    assert missing.valid is False
    assert missing.errors == ("AUDIT_PIPELINE_STAGE_MISSING",)
    assert duplicate.valid is False
    assert duplicate.errors == ("AUDIT_PIPELINE_STAGE_DUPLICATE",)
    assert reordered.valid is False
    assert reordered.errors == ("AUDIT_PIPELINE_STAGE_ORDER_INVALID",)


def test_pipeline_summary_detects_tenant_and_policy_isolation() -> None:
    evidences = list(_pipeline_evidences())
    tenant_changed = attach_audit_evidence(
        {"valid": True, "errors": []},
        canonical_payload={"stage": "worm"},
        context=AuditEvidenceContext(
            validator="worm",
            timestamp=TIMESTAMP,
            policy_version="policy.v1",
            tenant="tenant-b",
            evidence_id=evidences[6].evidence_id,
        ),
    ).audit_evidence
    policy_changed = attach_audit_evidence(
        {"valid": True, "errors": []},
        canonical_payload={"stage": "regulator_exports"},
        context=AuditEvidenceContext(
            validator="regulator_exports",
            timestamp=TIMESTAMP,
            policy_version="policy.v2",
            tenant="tenant-governance-test",
            evidence_id=evidences[7].evidence_id,
        ),
    ).audit_evidence
    assert tenant_changed is not None
    assert policy_changed is not None

    tenant_evidences = tuple(evidences[:6] + [tenant_changed] + evidences[7:])
    policy_evidences = tuple(evidences[:7] + [policy_changed] + evidences[8:])

    tenant_summary = build_audit_pipeline_summary(tenant_evidences)
    policy_summary = build_audit_pipeline_summary(policy_evidences)

    assert tenant_summary.valid is False
    assert tenant_summary.errors == ("AUDIT_PIPELINE_TENANT_MISMATCH",)
    assert policy_summary.valid is False
    assert policy_summary.errors == ("AUDIT_PIPELINE_POLICY_VERSION_MISMATCH",)
    assert tenant_summary.correlation_id != build_audit_pipeline_summary(evidences).correlation_id
    assert policy_summary.correlation_id != build_audit_pipeline_summary(evidences).correlation_id


def test_pipeline_summary_detects_invalid_stage_evidence() -> None:
    evidences = [evidence.to_dict() for evidence in _pipeline_evidences()]
    evidences[4]["audit_hash"] = "sha256:" + ("0" * 64)

    summary = build_audit_pipeline_summary(evidences)

    assert summary.valid is False
    assert summary.errors == ("AUDIT_PIPELINE_EVIDENCE_INVALID",)


def test_audit_evidence_rejects_unknown_validator_and_hash_drift() -> None:
    with pytest.raises(AuditEvidenceError, match="AUDIT_EVIDENCE_VALIDATOR_UNSUPPORTED"):
        build_audit_evidence(**_audit_kwargs("unknown", {"valid": True}, {}))

    audit = build_audit_evidence(**_audit_kwargs("evidence", {"valid": True}, {})).to_dict()
    audit["audit_hash"] = "sha256:" + ("0" * 64)

    with pytest.raises(AuditEvidenceError, match="AUDIT_EVIDENCE_HASH_MISMATCH"):
        validate_audit_evidence(audit)
