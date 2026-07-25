from __future__ import annotations

from pathlib import Path

import pytest

from scripts.governance_pr_body_integration import PRBodyIntegrationBlocked, validate_generated_pr_evidence
from scripts.precommit_governance_checks import check_secrets


SOURCE_REF = "commit:a" + ("a" * 39)


def _generated_body() -> str:
    return """## RISK
Readiness metadata could be mistaken for authorization.

## MECHANISM
Deterministic validation blocks missing or malformed evidence.

## GAP
No production provider is activated.

## AUDIT
Hash-only evidence is attached.

## IMPACT
Reviewers can verify the control boundary.

## DECISION
READY_FOR_REVIEW

## STATUS
GENERATED

## CHANGED FILES
- governance/example.py

## VALIDATION RESULTS
- pytest: PASS

## ROLLBACK PLAN
Revert the commit.

## COMMIT OR SOURCE REFERENCE
commit:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"""


def test_generated_evidence_with_required_sections_passes() -> None:
    result = validate_generated_pr_evidence(_generated_body(), source_reference=SOURCE_REF)

    assert result["evidence_mode"] == "GENERATED_GOVERNANCE_EVIDENCE"
    assert result["fallback_template"] == "ABSENT"
    assert result["unresolved_placeholders"] == "ABSENT"


def test_fallback_template_text_is_not_valid_evidence() -> None:
    body = _generated_body() + "\nFallback template use is not sufficient audit evidence.\n"

    with pytest.raises(PRBodyIntegrationBlocked, match="FALLBACK_TEMPLATE_NOT_AUDIT_EVIDENCE"):
        validate_generated_pr_evidence(body, source_reference=SOURCE_REF)


def test_unresolved_placeholder_fails_closed() -> None:
    body = _generated_body().replace("Deterministic validation blocks missing or malformed evidence.", "Describe what is changing and why.")

    with pytest.raises(PRBodyIntegrationBlocked, match="UNRESOLVED_TEMPLATE_PLACEHOLDER"):
        validate_generated_pr_evidence(body, source_reference=SOURCE_REF)


def test_missing_evidence_fails_closed() -> None:
    with pytest.raises(PRBodyIntegrationBlocked, match="PR_EVIDENCE_MISSING"):
        validate_generated_pr_evidence("", source_reference=SOURCE_REF)


def test_malformed_evidence_missing_required_section_fails_closed() -> None:
    body = _generated_body().replace("## GAP\nNo production provider is activated.\n\n", "")

    with pytest.raises(PRBodyIntegrationBlocked, match="PR_EVIDENCE_SECTION_MISSING:GAP"):
        validate_generated_pr_evidence(body, source_reference=SOURCE_REF)


def _token(prefix: str) -> str:
    if prefix == "AK" + "IA":
        return prefix + ("A" * 16)
    return prefix + ("A" * 32)


def test_secret_guard_does_not_flag_its_own_source() -> None:
    source = Path("scripts/precommit_governance_checks.py")

    assert check_secrets([source]) == []


@pytest.mark.parametrize(
    ("prefix", "label"),
    (
        ("gh" + "p_", "GITHUB_CLASSIC_TOKEN"),
        ("github" + "_pat_", "GITHUB_FINE_GRAINED_TOKEN"),
        ("xox" + "b-", "SLACK_BOT_TOKEN"),
        ("AK" + "IA", "AWS_ACCESS_KEY_ID"),
    ),
)
def test_secret_guard_blocks_synthetic_markers_with_masked_reporting(tmp_path: Path, prefix: str, label: str) -> None:
    path = tmp_path / "sample.txt"
    path.write_text("token=" + _token(prefix) + "\n", encoding="utf-8")

    failures = check_secrets([path])

    assert len(failures) == 1
    assert f"{path}:1:SECRET_MARKER_DETECTED:{label}" == failures[0]
    assert _token(prefix) not in failures[0]


def test_secret_guard_allows_benign_text(tmp_path: Path) -> None:
    path = tmp_path / "sample.txt"
    path.write_text("ordinary governed audit text\n", encoding="utf-8")

    assert check_secrets([path]) == []
