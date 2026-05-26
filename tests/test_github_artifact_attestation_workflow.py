from __future__ import annotations

from pathlib import Path

from tests.helpers.github_actions_policy import (
    approved_action_ref,
    evaluate_action_ref,
    load_github_actions_policy,
)


WORKFLOW = Path(".github/workflows/governance-export-attestation.yml")
DOC = Path("docs/github-artifact-attestation.md")


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_governance_export_attestation_workflow_declares_minimal_permissions() -> None:
    text = _workflow_text()

    assert "permissions:" in text
    assert "contents: read" in text
    assert "id-token: write" in text
    assert "attestations: write" in text
    assert "actions: read" in text
    assert "contents: write" not in text
    assert "packages: write" not in text


def test_governance_export_package_build_and_verify_are_required_before_attestation() -> None:
    text = _workflow_text()

    build_index = text.index("Build tenant audit package")
    verify_index = text.index("Verify tenant audit package")
    prepare_index = text.index("Prepare non-secret attestation subjects")
    attest_index = text.index("Attest governance export package provenance")

    assert build_index < verify_index < prepare_index < attest_index
    assert "python3 -m audit.exporter build-tenant-package" in text
    assert "python3 -m audit.exporter verify-tenant-package /tmp/usbay_tenant_audit_package" in text
    assert 'report.get("result") != "PASS"' in text
    assert 'echo "package_verified=true" >> "$GITHUB_OUTPUT"' in text


def test_attestation_runs_only_after_verification_pass() -> None:
    text = _workflow_text()

    gated_steps = (
        "Prepare non-secret attestation subjects",
        "Upload governance export attestation subjects",
        "Attest governance export package provenance",
    )
    for step_name in gated_steps:
        step_index = text.index(step_name)
        condition_index = text.index("if: steps.verify_package.outputs.package_verified == 'true'", step_index)
        assert condition_index > step_index


def test_official_github_artifact_actions_are_used() -> None:
    text = _workflow_text()
    policy = load_github_actions_policy()

    upload_action = approved_action_ref("actions/upload-artifact", policy)
    attest_action = approved_action_ref("actions/attest-build-provenance", policy)
    assert f"uses: {upload_action}" in text
    assert f"uses: {attest_action}" in text
    assert evaluate_action_ref(upload_action, context="manual_resilience", policy=policy)["decision"] == "PASS"
    assert evaluate_action_ref(attest_action, context="manual_resilience", policy=policy)["decision"] == "PASS"
    assert evaluate_action_ref(attest_action, context="fast_pr", policy=policy)["decision"] == "FAIL_CLOSED"
    assert "subject-path:" in text


def test_attestation_subjects_are_limited_to_non_secret_outputs() -> None:
    text = _workflow_text()
    subject_section = text.split("subject-path:", 1)[1]

    assert "tenant_audit_package_attestation.tar.gz" in subject_section
    assert "evidence_index.json" in subject_section
    assert "verification_report.md" in subject_section
    assert "verification_manifest.json" in subject_section
    assert "runtime_authority_identity.json" in subject_section
    assert "tsa_certificate_chain.pem" not in subject_section
    assert "rfc3161_timestamp.tsr" not in subject_section
    assert "audit.jsonl" not in subject_section
    assert "signatures.json" not in subject_section
    assert "raw_nonce" not in subject_section
    assert "BEGIN " + "PRIVATE KEY" not in subject_section


def test_forbidden_marker_scan_is_fail_closed() -> None:
    text = _workflow_text()

    assert "FAIL-CLOSED: forbidden package marker detected" in text
    assert '"BEGIN " + "PRIVATE KEY"' in text
    assert "raw_nonce" in text
    assert "raw_payload" in text
    assert "approval_contents" in text
    assert "approval_material" in text
    assert '"private" + "_" + "key"' in text


def test_documentation_explains_external_and_internal_provenance() -> None:
    text = DOC.read_text(encoding="utf-8")

    assert "GitHub attestation proves" in text
    assert "USBAY internal verification proves" in text
    assert "does not attest or upload private keys" in text
    assert "raw nonces" in text
    assert "PEM certificate material" in text
    assert "verify-tenant-package" in text
