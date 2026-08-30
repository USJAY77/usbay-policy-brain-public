from pathlib import Path

from scripts.validate_governance_templates import (
    render_pb_title,
    render_pr_body,
    validate_pr_body,
    validate_template_inventory,
    validate_title,
)


def test_commit_title_validation_accepts_single_pb() -> None:
    result = validate_title("PB-172 VERIFIED: Governance Template Enforcement")

    assert result.valid is True


def test_commit_title_validation_accepts_batch_pb() -> None:
    result = validate_title("PB-167-171 VERIFIED: Governed computer-use runtime vNext")

    assert result.valid is True


def test_commit_title_validation_rejects_missing_pb_number() -> None:
    result = validate_title("VERIFIED: Governance Template Enforcement")

    assert result.valid is False
    assert "TITLE_FORMAT_INVALID" in result.errors


def test_pr_title_validation_rejects_lowercase_decision() -> None:
    result = validate_title("PB-172 verified: Governance Template Enforcement")

    assert result.valid is False


def test_pr_body_validation_requires_sections() -> None:
    body = render_pr_body(
        purpose="Create canonical governance templates.",
        risk="Audit drift.",
        policy_link="USBAY Governance Principles.",
        governance_checks="JSON validation.",
        audit="Template validation report.",
        impact="Deterministic future PB artifacts.",
        decision="VERIFIED",
        status="READY_FOR_REVIEW",
    )

    result = validate_pr_body(body)

    assert result.valid is True


def test_pr_body_validation_rejects_missing_impact() -> None:
    body = "PURPOSE\nx\n\nRISK\nx\n\nPOLICY LINK\nx\n\nGOVERNANCE CHECKS\nx\n\nAUDIT\nx\n"

    result = validate_pr_body(body)

    assert result.valid is False
    assert "SECTION_MISSING:IMPACT" in result.errors


def test_template_inventory_validates_required_templates() -> None:
    results = validate_template_inventory(Path("templates"))

    assert all(item["valid"] for item in results.values())


def test_render_pb_title_uses_canonical_format() -> None:
    assert render_pb_title("172", "Governance Template Enforcement") == (
        "PB-172 VERIFIED: Governance Template Enforcement"
    )
