from __future__ import annotations

import json
from pathlib import Path

from publication.decision_engine import evaluate_publication_decision
from publication.models import (
    ApprovalState,
    BlockReason,
    PublicationDecision,
    RegistryRecord,
    SensitiveDataCategory,
)
from publication.sensitive_data_scanner import scan_publication_content


ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = ROOT / "policy" / "publication" / "publication_registry_record.example.json"


def example_record(**overrides: object) -> RegistryRecord:
    data = json.loads(RECORD_PATH.read_text(encoding="utf-8"))
    data.update(overrides)
    return RegistryRecord.from_dict(data)


def test_clean_artifact_passes_scan() -> None:
    result = scan_publication_content(
        artifact_id="PUB-SAFE-001",
        content="USBAY explains governance controls with approved public wording.",
    )

    assert result.passed is True
    assert result.block_reason == BlockReason.NONE
    assert result.detected_categories == ()
    assert result.evidence["raw_values_stored"] is False


def test_sensitive_artifact_blocks_publication() -> None:
    result = scan_publication_content(
        artifact_id="PUB-SENSITIVE-001",
        content="Contact operator@example.com before publication.",
    )

    assert result.passed is False
    assert result.decision == PublicationDecision.SENSITIVE_DATA_BLOCKED
    assert result.block_reason == BlockReason.SENSITIVE_DATA_PRESENT
    assert SensitiveDataCategory.EMAIL in result.detected_categories


def test_detects_required_sensitive_categories() -> None:
    private_key_marker = "-----BEGIN " + "PRIVATE" + " KEY-----"
    content = """
    phone +31 20 123 4567
    api_key = ABCDEFGHIJKL123456
    token: abcdefghijklmnop123456
    {private_key_marker}
    password = never-store-this
    NL91ABNA0417164300
    4111 1111 1111 1111
    customer confidential
    """.format(private_key_marker=private_key_marker)

    result = scan_publication_content(artifact_id="PUB-MULTI-001", content=content)

    assert result.passed is False
    assert SensitiveDataCategory.PHONE in result.detected_categories
    assert SensitiveDataCategory.API_KEY in result.detected_categories
    assert SensitiveDataCategory.TOKEN in result.detected_categories
    assert SensitiveDataCategory.PRIVATE_KEY in result.detected_categories
    assert SensitiveDataCategory.PASSWORD_OR_SECRET in result.detected_categories
    assert SensitiveDataCategory.IBAN in result.detected_categories
    assert SensitiveDataCategory.CREDIT_CARD in result.detected_categories
    assert SensitiveDataCategory.CUSTOMER_CONFIDENTIAL in result.detected_categories


def test_audit_output_is_redacted_and_hash_only() -> None:
    secret = "password = top-secret-value"
    result = scan_publication_content(artifact_id="PUB-SECRET-001", content=secret)

    evidence_text = json.dumps(result.evidence, sort_keys=True)
    audit_text = json.dumps(result.audit.to_dict(), sort_keys=True)

    assert "top-secret-value" not in evidence_text
    assert "top-secret-value" not in audit_text
    assert result.evidence["content_hash"].startswith("sha256:")
    assert result.audit.audit_hash.startswith("sha256:")
    assert result.evidence["detected_categories"] == ("PASSWORD_OR_SECRET",)


def test_invalid_scan_input_fails_closed() -> None:
    result = scan_publication_content(artifact_id="", content=None)  # type: ignore[arg-type]

    assert result.passed is False
    assert result.block_reason == BlockReason.INVALID_SCAN_INPUT
    assert result.decision == PublicationDecision.SENSITIVE_DATA_BLOCKED


def test_decision_engine_blocks_when_scan_is_missing() -> None:
    record = example_record()

    result = evaluate_publication_decision(record, approval_state=ApprovalState.APPROVED)

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.SENSITIVE_DATA_BLOCKED
    assert result.block_reason == BlockReason.SENSITIVE_SCAN_MISSING


def test_decision_engine_blocks_when_scan_fails() -> None:
    record = example_record()
    scan = scan_publication_content(
        artifact_id=record.artifact_id,
        content="customer confidential material must not publish",
    )

    result = evaluate_publication_decision(
        record,
        approval_state=ApprovalState.APPROVED,
        sensitive_scan_result=scan,
    )

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.SENSITIVE_DATA_BLOCKED
    assert result.block_reason == BlockReason.SENSITIVE_DATA_PRESENT
    assert "CUSTOMER_CONFIDENTIAL" in result.details
