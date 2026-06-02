from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AWS_PROFILE = ROOT / "governance" / "worm" / "aws_object_lock_evidence_profile.yaml"
AWS_DOC = ROOT / "docs" / "governance" / "WORM_AWS_OBJECT_LOCK_EVIDENCE_PILOT.md"
REGISTRY = ROOT / "governance" / "worm" / "provider_registry.yaml"


REQUIRED_AWS_FIELDS = {
    "aws_account_boundary",
    "aws_region",
    "s3_bucket_identifier",
    "s3_object_key",
    "s3_object_version_id",
    "object_lock_mode",
    "retain_until_timestamp",
    "legal_hold_status",
    "immutable_write_receipt",
    "provider_audit_event_reference",
    "export_verification_record",
    "sha256_evidence_hash",
    "usbay_sealed_archive_id",
    "usbay_archive_root_hash",
    "usbay_worm_storage_plan_id",
}


FORBIDDEN_EVIDENCE_FIELDS = {
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_session_token",
    "private_key",
    "raw_payload",
    "approval_contents",
    "raw_regulator_export",
}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _missing_required_aws_evidence(record: dict[str, str]) -> set[str]:
    return {field for field in REQUIRED_AWS_FIELDS if not record.get(field)}


def test_aws_object_lock_profile_is_pilot_only_and_fail_closed() -> None:
    text = _text(AWS_PROFILE)

    assert "status: PILOT_PREPARATION_ONLY" in text
    assert "provider_id: aws_s3_object_lock" in text
    assert "production_enabled: false" in text
    assert "certification_claim: false" in text
    assert "regulator_grade_assertion: false" in text
    assert "provider_credentials_allowed: false" in text
    assert "runtime_enforcement_modified: false" in text
    assert "default_decision: BLOCKED" in text


def test_aws_object_lock_profile_lists_required_evidence_and_forbidden_fields() -> None:
    text = _text(AWS_PROFILE)

    for field in REQUIRED_AWS_FIELDS:
        assert f"  - {field}" in text
        assert f"  {field}: Information not provided." in text

    for field in FORBIDDEN_EVIDENCE_FIELDS:
        assert f"  - {field}" in text


def test_aws_object_lock_missing_evidence_blocks_pilot_verification() -> None:
    candidate = {
        "aws_account_boundary": "aws-account-boundary-ref",
        "aws_region": "region-ref",
        "s3_bucket_identifier": "bucket-ref",
        "s3_object_key": "object-key-ref",
        "sha256_evidence_hash": "a" * 64,
    }

    missing = _missing_required_aws_evidence(candidate)

    assert "s3_object_version_id" in missing
    assert "object_lock_mode" in missing
    assert "retain_until_timestamp" in missing
    assert "legal_hold_status" in missing
    assert "immutable_write_receipt" in missing
    assert "provider_audit_event_reference" in missing
    assert "export_verification_record" in missing
    assert "Decision: BLOCKED" in _text(AWS_DOC)


def test_registry_links_aws_object_lock_profile_without_activation() -> None:
    text = _text(REGISTRY)

    assert "provider_id: aws_s3_object_lock" in text
    assert "pilot_status: PILOT_PREPARATION_ONLY" in text
    assert "pilot_profile: governance/worm/aws_object_lock_evidence_profile.yaml" in text
    assert "evidence_checklist: docs/governance/WORM_AWS_OBJECT_LOCK_EVIDENCE_PILOT.md" in text
    assert "production_activation: PROHIBITED" in text
    assert "certification_status: BLOCKED" in text
