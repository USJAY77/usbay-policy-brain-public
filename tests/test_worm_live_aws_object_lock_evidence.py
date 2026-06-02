from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LIVE_PACKAGE = ROOT / "docs" / "governance" / "AWS_OBJECT_LOCK_LIVE_EVIDENCE_PACKAGE.md"
AWS_PROFILE = ROOT / "governance" / "worm" / "aws_object_lock_evidence_profile.yaml"


REQUIRED_LIVE_EVIDENCE = {
    "Object Lock write receipt",
    "Retention configuration evidence",
    "Legal hold evidence",
    "Export verification evidence",
    "Provider audit reference",
}


FORBIDDEN_REPOSITORY_CONTENT = {
    "AWS access key ID",
    "AWS secret access key",
    "AWS session token",
    "Provider credentials",
    "Private keys",
    "Raw governance payloads",
    "Approval contents",
    "Raw regulator exports",
}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _missing_live_evidence(evidence: dict[str, str]) -> set[str]:
    return {field for field in REQUIRED_LIVE_EVIDENCE if not evidence.get(field)}


def test_live_aws_object_lock_package_records_blocked_capture_state() -> None:
    text = _text(LIVE_PACKAGE)

    assert "Decision: BLOCKED." in text
    assert "BLOCKER-003 status: OPEN." in text
    assert "Certification claim: prohibited." in text
    assert "Provider credentials stored in repository: prohibited." in text
    assert "Live provider evidence status: Information not provided." in text


def test_live_aws_object_lock_package_requires_all_closure_evidence() -> None:
    text = _text(LIVE_PACKAGE)

    for evidence in REQUIRED_LIVE_EVIDENCE:
        assert evidence in text
    assert "If any required live evidence element is missing:" in text
    assert "Missing evidence keeps BLOCKER-003 OPEN." in text


def test_missing_live_aws_evidence_fails_closed() -> None:
    candidate = {
        "Object Lock write receipt": "receipt-ref",
        "Retention configuration evidence": "",
        "Legal hold evidence": "legal-hold-ref",
        "Export verification evidence": "",
        "Provider audit reference": "audit-ref",
    }

    missing = _missing_live_evidence(candidate)

    assert missing == {"Retention configuration evidence", "Export verification evidence"}
    assert "Decision: BLOCKED." in _text(LIVE_PACKAGE)


def test_live_aws_object_lock_package_forbids_credentials_and_raw_evidence() -> None:
    text = _text(LIVE_PACKAGE)

    for forbidden in FORBIDDEN_REPOSITORY_CONTENT:
        assert forbidden in text
    assert "If forbidden repository content is detected:" in text
    assert "Decision: BLOCKED." in text


def test_aws_profile_links_live_evidence_package_without_activation() -> None:
    text = _text(AWS_PROFILE)

    assert "live_evidence_package: docs/governance/AWS_OBJECT_LOCK_LIVE_EVIDENCE_PACKAGE.md" in text
    assert "production_enabled: false" in text
    assert "provider_credentials_allowed: false" in text
    assert "certification_claim: false" in text
    assert "regulator_grade_assertion: false" in text
