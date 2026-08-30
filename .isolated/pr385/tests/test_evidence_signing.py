from __future__ import annotations

import pytest

from governance.evidence_signing import build_evidence_signature, validate_evidence_signature


pytestmark = pytest.mark.governance


def test_valid_local_signature_placeholder_verifies():
    signature = build_evidence_signature(
        manifest_hash="m" * 64,
        signer_id="operator-1",
        signer_role="USBAY_AUDITOR",
        created_at="2026-06-17T05:10:00Z",
    )

    valid, reasons = validate_evidence_signature(signature, manifest_hash="m" * 64)

    assert valid is True
    assert reasons == ()


def test_missing_signature_blocks():
    valid, reasons = validate_evidence_signature(None, manifest_hash="m" * 64)

    assert valid is False
    assert "EVIDENCE_SIGNATURE_MISSING" in reasons


def test_invalid_signature_blocks():
    signature = build_evidence_signature(
        manifest_hash="m" * 64,
        signer_id="operator-1",
        signer_role="USBAY_AUDITOR",
        created_at="2026-06-17T05:10:00Z",
    )
    signature["signature_hash"] = "0" * 64

    valid, reasons = validate_evidence_signature(signature, manifest_hash="m" * 64)

    assert valid is False
    assert "EVIDENCE_SIGNATURE_INVALID" in reasons


@pytest.mark.parametrize("role", ["AI_AGENT", "CODEX", "AUTOMATION", "SYSTEM"])
def test_rejected_signer_roles_block(role):
    signature = build_evidence_signature(
        manifest_hash="m" * 64,
        signer_id="operator-1",
        signer_role=role,
        created_at="2026-06-17T05:10:00Z",
    )

    valid, reasons = validate_evidence_signature(signature, manifest_hash="m" * 64)

    assert valid is False
    assert f"EVIDENCE_SIGNATURE_SIGNER_ROLE_REJECTED:{role}" in reasons
