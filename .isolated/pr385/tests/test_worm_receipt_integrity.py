from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT_REQUIREMENTS = ROOT / "docs" / "governance" / "WORM_RECEIPT_REQUIREMENTS.md"
SCHEMA = ROOT / "governance" / "worm" / "evidence_manifest_schema.yaml"


REQUIRED_RECEIPT_FIELDS = {
    "provider_receipt_id",
    "provider_id",
    "object_id",
    "storage_location_id",
    "receipt_timestamp",
    "sha256_evidence_hash",
    "retention_class",
    "retention_until",
    "legal_hold_state",
    "immutable_write_proof",
    "provider_audit_reference",
    "usbay_sealed_archive_id",
    "usbay_archive_root_hash",
    "usbay_worm_storage_plan_id",
    "export_verification_record_id",
}


def _canonical_hash(payload: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _receipt_valid(receipt: dict[str, str]) -> bool:
    if any(not receipt.get(field) for field in REQUIRED_RECEIPT_FIELDS):
        return False
    return receipt["sha256_evidence_hash"] == receipt["usbay_archive_root_hash"]


def test_receipt_requirements_document_all_integrity_fields() -> None:
    text = RECEIPT_REQUIREMENTS.read_text(encoding="utf-8")

    for field_label in (
        "Provider receipt ID",
        "Provider object ID",
        "Provider storage location identifier",
        "SHA256 evidence hash",
        "Retention class",
        "Legal hold state",
        "Immutable write proof",
        "Provider audit reference",
        "USBAY archive root hash",
        "USBAY WORM storage plan ID",
        "Export verification record ID",
    ):
        assert field_label in text


def test_receipt_with_missing_provider_audit_reference_is_blocked() -> None:
    receipt = {field: "value" for field in REQUIRED_RECEIPT_FIELDS}
    receipt["sha256_evidence_hash"] = "b" * 64
    receipt["usbay_archive_root_hash"] = "b" * 64
    receipt["provider_audit_reference"] = ""

    assert _receipt_valid(receipt) is False
    assert "Decision: BLOCKED" in RECEIPT_REQUIREMENTS.read_text(encoding="utf-8")


def test_receipt_hash_mismatch_is_blocked() -> None:
    receipt = {field: "value" for field in REQUIRED_RECEIPT_FIELDS}
    receipt["sha256_evidence_hash"] = _canonical_hash({"evidence": "local"})
    receipt["usbay_archive_root_hash"] = _canonical_hash({"evidence": "provider"})

    assert _receipt_valid(receipt) is False
    assert "sha256_hash_mismatch" in SCHEMA.read_text(encoding="utf-8")
