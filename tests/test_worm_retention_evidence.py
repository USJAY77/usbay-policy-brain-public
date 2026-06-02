from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "docs" / "governance" / "AWS_OBJECT_LOCK_EVIDENCE_PLAN.md"
STEPS = ROOT / "docs" / "governance" / "AWS_OBJECT_LOCK_VALIDATION_STEPS.md"
EXAMPLES = ROOT / "docs" / "governance" / "AWS_OBJECT_LOCK_RECEIPT_EXAMPLES.md"


REQUIRED_RETENTION_EVIDENCE = {
    "retention_configuration_evidence",
    "retain_until_timestamp",
    "legal_hold_evidence",
    "legal_hold_status",
    "export_verification_evidence",
    "provider_audit_reference",
}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _retention_evidence_valid(evidence: dict[str, str]) -> bool:
    return all(evidence.get(field) for field in REQUIRED_RETENTION_EVIDENCE)


def test_validation_steps_require_retention_legal_hold_export_and_audit_reference() -> None:
    text = _text(STEPS)

    assert "Verify retention configuration evidence exists." in text
    assert "Verify retain-until timestamp exists." in text
    assert "Verify legal hold evidence exists." in text
    assert "Verify legal hold status exists." in text
    assert "Verify export verification evidence exists." in text
    assert "Verify provider audit reference exists." in text
    assert "Verify delete attempt is denied during retention." in text
    assert "Verify overwrite attempt is denied during retention." in text
    assert "Decision: BLOCKED." in text


def test_missing_retention_evidence_fails_closed() -> None:
    evidence = {field: "value" for field in REQUIRED_RETENTION_EVIDENCE}
    evidence["retention_configuration_evidence"] = ""

    assert _retention_evidence_valid(evidence) is False
    assert "Retention configuration evidence is missing." in _text(EXAMPLES)


def test_missing_legal_hold_evidence_fails_closed() -> None:
    evidence = {field: "value" for field in REQUIRED_RETENTION_EVIDENCE}
    evidence["legal_hold_evidence"] = ""

    assert _retention_evidence_valid(evidence) is False
    assert "Legal hold evidence is missing." in _text(EXAMPLES)


def test_missing_export_or_provider_audit_evidence_fails_closed() -> None:
    missing_export = {field: "value" for field in REQUIRED_RETENTION_EVIDENCE}
    missing_export["export_verification_evidence"] = ""
    missing_audit = {field: "value" for field in REQUIRED_RETENTION_EVIDENCE}
    missing_audit["provider_audit_reference"] = ""

    assert _retention_evidence_valid(missing_export) is False
    assert _retention_evidence_valid(missing_audit) is False
    assert "Export verification evidence is missing." in _text(EXAMPLES)
    assert "Provider audit reference is missing." in _text(EXAMPLES)


def test_plan_preserves_open_blocker_and_no_runtime_activation() -> None:
    text = _text(PLAN)

    assert "BLOCKER-003 remains OPEN." in text
    assert "No runtime changes." not in text
    assert "Runtime impact: none." in text
    assert "Production activation: prohibited." in text
    assert "The pilot does not configure AWS infrastructure." in text
