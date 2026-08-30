from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "governance" / "worm" / "provider_registry.yaml"
SCHEMA = ROOT / "governance" / "worm" / "evidence_manifest_schema.yaml"
CRITERIA = ROOT / "governance" / "worm" / "pilot_acceptance_criteria.md"


REQUIRED_EVIDENCE = {
    "provider_receipt",
    "object_id",
    "retention_class",
    "legal_hold_state",
    "immutable_write_proof",
    "audit_receipt",
    "export_verification_record",
    "sha256_evidence_hash",
}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _missing_required_evidence(record: dict[str, str]) -> set[str]:
    return {field for field in REQUIRED_EVIDENCE if not record.get(field)}


def test_worm_pilot_registry_is_pilot_only_and_fail_closed() -> None:
    text = _text(REGISTRY)

    assert "status: PILOT_ONLY" in text
    assert "production_enabled: false" in text
    assert "certification_claim: false" in text
    assert "regulator_grade_assertion: false" in text
    assert "fail_closed_default: true" in text
    assert "provider_credentials_allowed: false" in text
    assert "certification_status: BLOCKED" in text
    assert "Information not provided." in text


def test_worm_evidence_schema_requires_all_blocking_evidence() -> None:
    text = _text(SCHEMA)

    for field in REQUIRED_EVIDENCE:
        assert f"  - {field}" in text
    assert "default_decision: BLOCKED" in text
    assert "provider_outage" in text
    assert "provider_capability_unverified" in text


def test_missing_evidence_fails_closed() -> None:
    candidate = {
        "provider_receipt": "receipt-1",
        "object_id": "object-1",
        "retention_class": "governance_evidence_worm",
        "legal_hold_state": "enabled",
        "sha256_evidence_hash": "a" * 64,
    }

    missing = _missing_required_evidence(candidate)

    assert missing == {"audit_receipt", "export_verification_record", "immutable_write_proof"}
    assert "Decision: BLOCKED" in _text(CRITERIA)
