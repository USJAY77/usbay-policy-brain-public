from __future__ import annotations

from pathlib import Path


WORKFLOW = Path(".github/workflows/policy-verification.yml")
GOVERNANCE_WORKFLOW = Path(".github/workflows/usbay-policy-validation.yml")


CORE_REQUIRED_SECRETS = {
    "USBAY_POLICY_PUBLIC_KEY_PEM",
    "USBAY_POLICY_APPROVAL_1_JSON",
    "USBAY_POLICY_APPROVAL_1_SIG",
}


OPTIONAL_PRODUCTION_SECRETS = {
    "USBAY_APPROVER1_PUBLIC_KEY_PEM",
    "USBAY_POLICY_APPROVAL_2_JSON",
    "USBAY_POLICY_APPROVAL_2_SIG",
    "USBAY_APPROVER2_PUBLIC_KEY_PEM",
    "USBAY_EVIDENCE_RULESETS_JSON",
    "USBAY_EVIDENCE_RULESETS_SHA256",
    "USBAY_EVIDENCE_RULESETS_META_JSON",
    "USBAY_RUNTIME_ATTESTATION_JSON",
    "USBAY_RUNTIME_ATTESTATION_SIG",
    "USBAY_RUNTIME_ATTESTATION_PUBLIC_KEY_PEM",
    "USBAY_AUDIT_LOG_JSONL",
    "USBAY_AUDIT_LEDGER_HEAD_JSON",
    "USBAY_AUDIT_LEDGER_HEAD_SIG",
    "USBAY_AUDIT_SEAL_PUBLIC_KEY_PEM",
}


OPTIONAL_PILOT_SECRETS = {
    "USBAY_APPROVER1_PUBLIC_KEY_PEM",
    "USBAY_POLICY_APPROVAL_2_JSON",
    "USBAY_POLICY_APPROVAL_2_SIG",
    "USBAY_APPROVER2_PUBLIC_KEY_PEM",
    "USBAY_DEVICE_REGISTRY_JSON",
}


def test_policy_verification_keeps_core_secrets_fail_closed() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "CORE_REQUIRED_SECRETS=(" in text
    assert "missing_core=0" in text
    assert "exit 1" in text
    for secret_name in CORE_REQUIRED_SECRETS:
        assert secret_name in text


def test_policy_verification_warns_for_optional_production_attestation() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "OPTIONAL_PRODUCTION_SECRETS=(" in text
    assert "::warning title=Optional production attestation missing::${secret_name}" in text
    assert "full production attestation validation skipped" in text
    for secret_name in OPTIONAL_PRODUCTION_SECRETS:
        assert secret_name in text
        assert f': "${{{secret_name}:?missing}}"' not in text


def test_policy_verification_runs_core_or_full_validator_without_printing_values() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "python3 runtime/policy_validator.py | tee validator_output.txt" in text
    assert "POLICY_CORE_VALIDATION_OK" in text
    assert 'printf "%s" "$USBAY_POLICY_PUBLIC_KEY_PEM"' in text
    assert 'echo "$USBAY_POLICY_PUBLIC_KEY_PEM"' not in text
    assert 'cat policy/public_key.pem' not in text


def test_governance_check_keeps_core_secrets_fail_closed() -> None:
    text = GOVERNANCE_WORKFLOW.read_text(encoding="utf-8")

    assert "CORE_REQUIRED_SECRETS=(" in text
    assert "missing_core=0" in text
    assert "::error title=Missing required governance secret::${secret_name}" in text
    assert "exit 1" in text
    for secret_name in CORE_REQUIRED_SECRETS:
        assert secret_name in text


def test_governance_check_warns_for_optional_pilot_secrets() -> None:
    text = GOVERNANCE_WORKFLOW.read_text(encoding="utf-8")

    assert "OPTIONAL_PILOT_SECRETS=(" in text
    assert "::warning title=Optional pilot governance secret missing::${secret_name}" in text
    assert "pilot-maturity governance-check will continue" in text
    for secret_name in OPTIONAL_PILOT_SECRETS:
        assert secret_name in text
        assert f': "${{{secret_name}:?missing}}"' not in text


def test_governance_check_runs_core_or_full_path_without_printing_values() -> None:
    text = GOVERNANCE_WORKFLOW.read_text(encoding="utf-8")

    assert "USBAY_GOVERNANCE_OPTIONAL_COMPLETE=true" in text
    assert "bash governance_check.sh" in text
    assert "GOVERNANCE_CORE_VALIDATION_OK" in text
    assert 'printf "%s" "$USBAY_POLICY_PUBLIC_KEY_PEM"' in text
    assert 'printf "%s" "${{ secrets.' not in text
    assert 'echo "$USBAY_POLICY_PUBLIC_KEY_PEM"' not in text
    assert 'cat policy/public_key.pem' not in text
    assert "pull_request_target" not in text
