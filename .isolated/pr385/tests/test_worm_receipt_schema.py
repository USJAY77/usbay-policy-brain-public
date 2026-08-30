from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "docs" / "governance" / "AWS_OBJECT_LOCK_EVIDENCE_PLAN.md"
EXAMPLES = ROOT / "docs" / "governance" / "AWS_OBJECT_LOCK_RECEIPT_EXAMPLES.md"
PROFILE = ROOT / "governance" / "worm" / "aws_object_lock_evidence_profile.yaml"


REQUIRED_CLOSURE_EVIDENCE = {
    "Object Lock write receipt",
    "Retention configuration evidence",
    "Legal hold evidence",
    "Export verification evidence",
    "Provider audit reference",
}


REQUIRED_RECEIPT_FIELDS = {
    "provider_id",
    "aws_account_boundary",
    "aws_region",
    "s3_bucket_identifier",
    "s3_object_key",
    "s3_object_version_id",
    "object_lock_write_receipt",
    "object_lock_mode",
    "retention_configuration_evidence",
    "retain_until_timestamp",
    "legal_hold_evidence",
    "legal_hold_status",
    "export_verification_evidence",
    "provider_audit_reference",
    "sha256_evidence_hash",
    "usbay_sealed_archive_id",
    "usbay_archive_root_hash",
    "usbay_worm_storage_plan_id",
}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _missing_required_receipt_fields(receipt: dict[str, str]) -> set[str]:
    return {field for field in REQUIRED_RECEIPT_FIELDS if not receipt.get(field)}


def test_aws_receipt_plan_documents_blocker_003_closure_evidence() -> None:
    text = _text(PLAN)

    assert "BLOCKER-003 status: OPEN." in text
    assert "Certification claim: prohibited." in text
    assert "Provider credentials in repository: prohibited." in text
    for evidence in REQUIRED_CLOSURE_EVIDENCE:
        assert evidence in text
    assert "Decision: BLOCKED." in text


def test_aws_receipt_examples_document_required_schema_fields() -> None:
    text = _text(EXAMPLES)

    for field in REQUIRED_RECEIPT_FIELDS:
        assert field in text
    assert "This is a redacted structure only. It is not provider evidence." in text
    assert "BLOCKER-003 remains OPEN" in text


def test_missing_object_lock_receipt_fails_closed() -> None:
    receipt = {field: "value" for field in REQUIRED_RECEIPT_FIELDS}
    receipt["object_lock_write_receipt"] = ""

    missing = _missing_required_receipt_fields(receipt)

    assert missing == {"object_lock_write_receipt"}
    assert "Decision: BLOCKED." in _text(EXAMPLES)


def test_aws_profile_does_not_allow_credentials_or_certification_claims() -> None:
    text = _text(PROFILE)

    assert "provider_credentials_allowed: false" in text
    assert "certification_claim: false" in text
    assert "production_enabled: false" in text
    assert "aws_secret_access_key" in text
    assert "credential_or_secret_detected" in text
