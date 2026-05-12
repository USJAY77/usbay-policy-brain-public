from __future__ import annotations

import json
import os
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path

from scripts import generate_ci_evidence_manifest as evidence
from scripts import generate_ci_dependency_sbom as sbom
from scripts import verify_production_readiness as readiness


def _write_required_docs(root: Path) -> None:
    docs = root / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    for doc in readiness.REQUIRED_DOCS:
        path = root / doc
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("ok\n", encoding="utf-8")


def _write_helper(root: Path, size: int = 128) -> None:
    helper = root / "tests" / "provenance_helpers.py"
    helper.parent.mkdir(parents=True, exist_ok=True)
    helper.write_text("x" * size, encoding="utf-8")


def _write_ci_lock(root: Path, text: str | None = None) -> None:
    lock = root / "requirements-ci.txt"
    lock.write_text(
        text
        or (
            "cffi==2.0.0 \\\n"
            "    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
            "cryptography==46.0.5 \\\n"
            "    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
            "pycparser==3.0 \\\n"
            "    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
            "pytest==9.0.3 \\\n"
            "    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        ),
        encoding="utf-8",
    )


def _write_production_readiness_workflow(root: Path, text: str | None = None) -> None:
    workflow = root / ".github" / "workflows" / "production-readiness.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(
        text
        or (
            "name: production-readiness\n"
            "jobs:\n"
            "  production-readiness:\n"
            "    steps:\n"
            "      - uses: actions/setup-python@v5\n"
            "      - run: python -m pip install --require-hashes -r requirements-ci.txt\n"
            "      - run: python -c \"import importlib.metadata; print(importlib.metadata.version('cryptography'))\"\n"
            "      - run: python -c \"import audit.anchor, audit.rfc3161_anchor, audit.worm_archive, scripts.generate_ci_evidence_manifest; print('GOVERNANCE_CRYPTO_IMPORTS_VALID=true')\"\n"
            "      - run: python scripts/generate_ci_dependency_sbom.py --output sbom/production-readiness-ci-sbom.json\n"
            "      - run: test -s sbom/production-readiness-ci-sbom.json\n"
            "      - uses: actions/upload-artifact@v4\n"
            "        with:\n"
            "          name: production-readiness-ci-sbom\n"
            "      - run: python scripts/generate_ci_evidence_manifest.py --output evidence/governance-evidence-manifest.json --trust-policy governance/ci_evidence_trust_policy.json\n"
            "        env:\n"
            "          USBAY_CI_EVIDENCE_SIGNER_ID: github-actions-production-readiness\n"
            "          USBAY_CI_EVIDENCE_PRIVATE_KEY_PEM: ${{ secrets.USBAY_CI_EVIDENCE_PRIVATE_KEY_PEM }}\n"
            "      - run: test -s evidence/governance-evidence-manifest.json\n"
            "      - run: python scripts/generate_ci_evidence_manifest.py --verify evidence/governance-evidence-manifest.json --trust-policy governance/ci_evidence_trust_policy.json\n"
            "        env:\n"
            "          USBAY_CI_EVIDENCE_SIGNER_ID: github-actions-production-readiness\n"
            "      - run: python scripts/generate_ci_evidence_manifest.py --timestamp-output evidence/governance-timestamps --trust-policy governance/ci_evidence_trust_policy.json\n"
            "      - run: test -s evidence/governance-timestamps/chronology_consensus.json\n"
            "      - run: test -s evidence/governance-timestamps/chronology_consensus_audit.jsonl\n"
            "      - run: test -s evidence/governance-timestamps/transparency_anchor.json\n"
            "      - run: test -s evidence/governance-timestamps/witness_proofs.json\n"
            "      - run: test -s evidence/governance-timestamps/witness_verification.json\n"
            "      - run: test -s evidence/governance-timestamps/witness_audit.jsonl\n"
            "      - run: test -s evidence/governance-timestamps/witness_trust_audit.jsonl\n"
            "      - run: test -s evidence/governance-timestamps/witness_reputation_history.jsonl\n"
            "      - run: python scripts/generate_ci_evidence_manifest.py --verify-timestamps evidence/governance-timestamps --trust-policy governance/ci_evidence_trust_policy.json\n"
            "      - uses: actions/upload-artifact@v4\n"
            "        with:\n"
            "          name: production-readiness-governance-evidence\n"
            "      - uses: actions/upload-artifact@v4\n"
            "        with:\n"
            "          name: production-readiness-governance-timestamps\n"
        ),
        encoding="utf-8",
    )


def _write_ci_trust_policy_governance_files(root: Path) -> None:
    governance = root / "governance"
    governance.mkdir(parents=True, exist_ok=True)
    for rel in (
        readiness.CI_EVIDENCE_TRUST_POLICY,
        readiness.CI_EVIDENCE_TRUST_POLICY_SIGNATURE,
        readiness.CI_EVIDENCE_TRUST_POLICY_AUTHORITY,
        readiness.CI_EVIDENCE_TRUST_POLICY_AUDIT,
    ):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n" if path.suffix == ".json" or path.name.endswith(".sig") else "{}\n", encoding="utf-8")


def _write_clean_readiness_tree(root: Path) -> None:
    _write_helper(root)
    _write_required_docs(root)
    _write_ci_lock(root)
    _write_production_readiness_workflow(root)
    _write_ci_trust_policy_governance_files(root)


def _test_keypair() -> tuple[str, str]:
    return evidence.generate_ed25519_keypair()


def _trust_policy(
    *,
    signer_id: str,
    public_key: str,
    valid_from: str = "2026-01-01T00:00:00Z",
    valid_until: str = "2027-01-01T00:00:00Z",
    revoked: list[str] | None = None,
    extra_signers: list[dict] | None = None,
) -> dict:
    entry = {
        "signer_id": signer_id,
        "public_key_fingerprint": evidence.signer_key_id(public_key),
        "public_key_pem": public_key,
        "valid_from": valid_from,
        "valid_until": valid_until,
    }
    return {
        "policy_version": "ci-evidence-trust-v1",
        "allowed_signers": [entry, *(extra_signers or [])],
        "revoked_fingerprints": revoked or [],
    }


def _write_trust_policy_governance(
    root: Path,
    policy: dict,
    *,
    signer_id: str = "policy-authority",
    revoked_policy_signers: list[str] | None = None,
    authorize_signer: bool = True,
) -> tuple[Path, str]:
    private_key, public_key = _test_keypair()
    fingerprint = evidence.signer_key_id(public_key)
    policy_path = root / "trust_policy.json"
    signature_path = root / "trust_policy.json.sig"
    authority_path = root / "trust_policy.json.authority.json"
    audit_path = root / "trust_policy.json.audit.jsonl"
    policy_path.write_text(evidence._canonical_json(policy), encoding="utf-8")
    signature_payload = {
        "algorithm": evidence.TRUST_POLICY_SIGNATURE_ALGORITHM,
        "policy_hash": evidence._trust_policy_hash(policy),
        "policy_version": policy["policy_version"],
        "signature": evidence.SIGNATURE_PREFIX + evidence._ed25519_sign(evidence._canonical_json(policy), private_key),
        "signed_at": "2026-05-12T00:00:00Z",
        "signer_id": signer_id,
        "signer_key_id": fingerprint,
    }
    authority = {
        "authority_version": "ci-evidence-trust-policy-authority-v1",
        "allowed_policy_signers": [
            {
                "signer_id": signer_id,
                "public_key_fingerprint": fingerprint,
                "public_key_pem": public_key,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
            }
        ]
        if authorize_signer
        else [],
        "revoked_policy_signer_fingerprints": revoked_policy_signers or [],
    }
    audit = {
        "record_id": "ci-evidence-trust-policy-0001",
        "timestamp": "2026-05-12T00:00:00Z",
        "policy_version": policy["policy_version"],
        "policy_hash": evidence._trust_policy_hash(policy),
        "previous_policy_version": evidence.GENESIS_HASH,
        "previous_policy_hash": evidence.GENESIS_HASH,
        "signature_hash": evidence._trust_policy_hash(signature_payload),
        "policy_signer_id": signer_id,
        "policy_signer_fingerprint": fingerprint,
        "previous_record_hash": evidence.GENESIS_HASH,
    }
    audit["current_record_hash"] = evidence._trust_policy_audit_hash(audit)
    signature_path.write_text(evidence._canonical_json(signature_payload), encoding="utf-8")
    authority_path.write_text(evidence._canonical_json(authority), encoding="utf-8")
    audit_path.write_text(evidence._canonical_json(audit) + "\n", encoding="utf-8")
    return policy_path, fingerprint


def _timestamp_fixture(root: Path) -> tuple[Path, Path, Path]:
    evidence_file = root / "guard-output.txt"
    evidence_file.write_text("PRODUCTION_READINESS=true\n", encoding="utf-8")
    private_key, public_key = _test_keypair()
    policy = _trust_policy(signer_id="test-signer", public_key=public_key)
    policy_path, _fingerprint = _write_trust_policy_governance(root, policy)
    manifest_path = root / "evidence_manifest.json"
    old_env = {
        evidence.PRIVATE_KEY_ENV: os.environ.get(evidence.PRIVATE_KEY_ENV),
        evidence.PUBLIC_KEY_ENV: os.environ.get(evidence.PUBLIC_KEY_ENV),
        evidence.SIGNER_ID_ENV: os.environ.get(evidence.SIGNER_ID_ENV),
    }
    try:
        os.environ[evidence.PRIVATE_KEY_ENV] = private_key
        os.environ[evidence.PUBLIC_KEY_ENV] = public_key
        os.environ[evidence.SIGNER_ID_ENV] = "test-signer"
        evidence.write_manifest(root, manifest_path, ["guard-output.txt"], trust_policy_path=policy_path)
    finally:
        for key, value in old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    timestamp_dir = root / "timestamps"
    evidence.generate_governance_timestamps(root, timestamp_dir, manifest_path, trust_policy_path=policy_path)
    return manifest_path, policy_path, timestamp_dir


def test_guard_accepts_clean_minimal_tree(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)

    assert readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"]) == []


def test_guard_detects_oversized_helper_file(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    _write_helper(tmp_path, readiness.MAX_HELPER_BYTES)

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert any(failure.startswith("PROVENANCE_HELPER_OVERSIZED") for failure in failures)


def test_guard_detects_tracked_generated_manifest_artifacts(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    manifest = tmp_path / ("governance_" + "release.json")
    manifest.write_text("{}", encoding="utf-8")
    generated = tmp_path / "generated_manifest_path.json"
    generated.write_text("{}", encoding="utf-8")

    failures = readiness.collect_failures(
        tmp_path,
        tracked_files=[
            "tests/provenance_helpers.py",
            "governance_release.json",
            "generated_manifest_path.json",
        ],
    )

    assert "TRACKED_ROOT_GOVERNANCE_RELEASE:governance_release.json" in failures
    assert "TRACKED_GENERATED_MANIFEST_ARTIFACT:generated_manifest_path.json" in failures


def test_guard_detects_missing_readiness_docs(tmp_path: Path) -> None:
    _write_helper(tmp_path)
    _write_ci_lock(tmp_path)
    _write_production_readiness_workflow(tmp_path)

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert any(failure.startswith("READINESS_DOC_MISSING:") for failure in failures)


def test_guard_detects_production_manifest_bypass_attempt(monkeypatch) -> None:
    monkeypatch.setattr(readiness, "check_production_manifest_required", lambda: ["PRODUCTION_MANIFEST_BYPASS_ALLOWED"])

    assert "PRODUCTION_MANIFEST_BYPASS_ALLOWED" in readiness.check_production_manifest_required()


def test_guard_rejects_secret_like_markers_in_generated_artifacts(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    generated = tmp_path / "generated_manifest_path.json"
    marker = "BEGIN " + "PRIVATE KEY"
    generated.write_text(marker, encoding="utf-8")

    failures = readiness.collect_failures(
        tmp_path,
        tracked_files=["tests/provenance_helpers.py", "generated_manifest_path.json"],
    )

    assert f"SECRET_MARKER_IN_GENERATED_ARTIFACT:generated_manifest_path.json:{marker}" in failures


def test_guard_detects_tracked_file_over_50mb(monkeypatch, tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    huge = tmp_path / "huge.bin"
    huge.write_text("x", encoding="utf-8")
    monkeypatch.setattr(readiness, "tracked_file_size", lambda root, tracked: readiness.MAX_TRACKED_BYTES + 1 if tracked == "huge.bin" else 1)

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py", "huge.bin"])

    assert any(failure.startswith("TRACKED_FILE_OVERSIZED:huge.bin:") for failure in failures)


def test_guard_detects_missing_ci_dependency_lock(tmp_path: Path) -> None:
    _write_helper(tmp_path)
    _write_required_docs(tmp_path)
    _write_production_readiness_workflow(tmp_path)

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert "CI_REQUIREMENTS_LOCK_MISSING:requirements-ci.txt" in failures


def test_guard_detects_unpinned_ci_dependency(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    _write_ci_lock(
        tmp_path,
        "pytest>=9.0.3 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    )

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert any(failure.startswith("CI_REQUIREMENT_UNPINNED:pytest>=9.0.3") for failure in failures)


def test_guard_detects_missing_ci_dependency_hash(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    _write_ci_lock(tmp_path, "pytest==9.0.3\n")

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert "CI_REQUIREMENT_HASH_MISSING:pytest==9.0.3" in failures


def test_guard_detects_empty_ci_dependency_lock(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    _write_ci_lock(tmp_path, "# comments only\n")

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert "CI_REQUIREMENTS_LOCK_EMPTY:requirements-ci.txt" in failures


def test_guard_detects_incomplete_ci_dependency_lock_without_pytest(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    _write_ci_lock(
        tmp_path,
        "packaging==25.0 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    )

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert "CI_REQUIREMENT_REQUIRED_PACKAGE_MISSING:pytest" in failures


def test_guard_detects_missing_governance_crypto_dependency(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    _write_ci_lock(
        tmp_path,
        "cffi==2.0.0 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "pycparser==3.0 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "pytest==9.0.3 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    )

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert "CI_REQUIREMENT_REQUIRED_PACKAGE_MISSING:cryptography" in failures
    assert "CI_REQUIREMENT_GOVERNANCE_CRYPTO_MISSING:cryptography" in failures


def test_guard_detects_workflow_without_hash_verified_install(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    _write_production_readiness_workflow(
        tmp_path,
        "name: production-readiness\n"
        "jobs:\n"
        "  production-readiness:\n"
        "    steps:\n"
        "      - uses: actions/setup-python@v5\n"
        "      - run: python -m pip install pytest\n",
    )

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert "WORKFLOW_REQUIRE_HASHES_MISSING" in failures
    assert any(failure.startswith("WORKFLOW_UNHASHED_INSTALL:") for failure in failures)
    assert "WORKFLOW_CRYPTOGRAPHY_VERSION_AUDIT_MISSING" in failures
    assert "WORKFLOW_GOVERNANCE_CRYPTO_IMPORT_CHECK_MISSING" in failures


def test_guard_detects_workflow_without_ci_sbom_generation(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    _write_production_readiness_workflow(
        tmp_path,
        "name: production-readiness\n"
        "jobs:\n"
        "  production-readiness:\n"
        "    steps:\n"
        "      - uses: actions/setup-python@v5\n"
        "      - run: python -m pip install --require-hashes -r requirements-ci.txt\n",
    )

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert "WORKFLOW_CI_SBOM_GENERATION_MISSING" in failures
    assert "WORKFLOW_CI_SBOM_UPLOAD_MISSING" in failures
    assert "WORKFLOW_CI_SBOM_EXISTENCE_CHECK_MISSING" in failures


def test_guard_detects_workflow_without_ci_evidence_chain(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    _write_production_readiness_workflow(
        tmp_path,
        "name: production-readiness\n"
        "jobs:\n"
        "  production-readiness:\n"
        "    steps:\n"
        "      - uses: actions/setup-python@v5\n"
        "      - run: python -m pip install --require-hashes -r requirements-ci.txt\n"
        "      - run: python scripts/generate_ci_dependency_sbom.py --output sbom/production-readiness-ci-sbom.json\n"
        "      - run: test -s sbom/production-readiness-ci-sbom.json\n"
        "      - uses: actions/upload-artifact@v4\n",
    )

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert "WORKFLOW_CI_EVIDENCE_CHAIN_MISSING" in failures
    assert "WORKFLOW_CI_EVIDENCE_MANIFEST_PATH_MISSING" in failures
    assert "WORKFLOW_CI_EVIDENCE_EXISTENCE_CHECK_MISSING" in failures
    assert "WORKFLOW_CI_EVIDENCE_VERIFY_MISSING" in failures


def test_guard_detects_workflow_without_ci_evidence_trust_policy(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    _write_production_readiness_workflow(
        tmp_path,
        "name: production-readiness\n"
        "jobs:\n"
        "  production-readiness:\n"
        "    steps:\n"
        "      - uses: actions/setup-python@v5\n"
        "      - run: python -m pip install --require-hashes -r requirements-ci.txt\n"
        "      - run: python scripts/generate_ci_dependency_sbom.py --output sbom/production-readiness-ci-sbom.json\n"
        "      - run: test -s sbom/production-readiness-ci-sbom.json\n"
        "      - uses: actions/upload-artifact@v4\n"
        "      - run: python scripts/generate_ci_evidence_manifest.py --output evidence/governance-evidence-manifest.json\n"
        "        env:\n"
        "          USBAY_CI_EVIDENCE_SIGNER_ID: github-actions-production-readiness\n"
        "          USBAY_CI_EVIDENCE_PRIVATE_KEY_PEM: ${{ secrets.USBAY_CI_EVIDENCE_PRIVATE_KEY_PEM }}\n"
        "      - run: test -s evidence/governance-evidence-manifest.json\n"
        "      - run: python scripts/generate_ci_evidence_manifest.py --verify evidence/governance-evidence-manifest.json\n"
        "      - uses: actions/upload-artifact@v4\n"
        "        with:\n"
        "          name: production-readiness-governance-evidence\n",
    )

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert "WORKFLOW_CI_EVIDENCE_TRUST_POLICY_MISSING" in failures


def test_guard_detects_workflow_without_governance_timestamping(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    _write_production_readiness_workflow(
        tmp_path,
        "name: production-readiness\n"
        "jobs:\n"
        "  production-readiness:\n"
        "    steps:\n"
        "      - uses: actions/setup-python@v5\n"
        "      - run: python -m pip install --require-hashes -r requirements-ci.txt\n"
        "      - run: python scripts/generate_ci_dependency_sbom.py --output sbom/production-readiness-ci-sbom.json\n"
        "      - run: test -s sbom/production-readiness-ci-sbom.json\n"
        "      - uses: actions/upload-artifact@v4\n"
        "      - run: python scripts/generate_ci_evidence_manifest.py --output evidence/governance-evidence-manifest.json --trust-policy governance/ci_evidence_trust_policy.json\n"
        "        env:\n"
        "          USBAY_CI_EVIDENCE_SIGNER_ID: github-actions-production-readiness\n"
        "          USBAY_CI_EVIDENCE_PRIVATE_KEY_PEM: ${{ secrets.USBAY_CI_EVIDENCE_PRIVATE_KEY_PEM }}\n"
        "      - run: test -s evidence/governance-evidence-manifest.json\n"
        "      - run: python scripts/generate_ci_evidence_manifest.py --verify evidence/governance-evidence-manifest.json --trust-policy governance/ci_evidence_trust_policy.json\n"
        "      - uses: actions/upload-artifact@v4\n"
        "        with:\n"
        "          name: production-readiness-governance-evidence\n",
    )

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert "WORKFLOW_CI_GOVERNANCE_TIMESTAMP_MISSING" in failures
    assert "WORKFLOW_CI_GOVERNANCE_TIMESTAMP_VERIFY_MISSING" in failures
    assert "WORKFLOW_CI_GOVERNANCE_TIMESTAMP_ARTIFACT_MISSING" in failures
    assert "WORKFLOW_CI_CHRONOLOGY_CONSENSUS_CHECK_MISSING" in failures
    assert "WORKFLOW_CI_CHRONOLOGY_CONSENSUS_AUDIT_CHECK_MISSING" in failures
    assert "WORKFLOW_CI_TRANSPARENCY_ANCHOR_CHECK_MISSING" in failures
    assert "WORKFLOW_CI_WITNESS_PROOFS_CHECK_MISSING" in failures
    assert "WORKFLOW_CI_WITNESS_VERIFICATION_CHECK_MISSING" in failures
    assert "WORKFLOW_CI_WITNESS_AUDIT_CHECK_MISSING" in failures
    assert "WORKFLOW_CI_WITNESS_TRUST_AUDIT_CHECK_MISSING" in failures
    assert "WORKFLOW_CI_WITNESS_REPUTATION_HISTORY_CHECK_MISSING" in failures


def test_ci_dependency_sbom_contains_auditable_inventory(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)

    document = sbom.build_sbom(tmp_path, generated_at="2026-05-12T00:00:00Z")
    failures = sbom.validate_sbom(document)

    assert failures == []
    assert document["audit_metadata"]["python_version"]
    assert document["audit_metadata"]["workflow_version"] == sbom.WORKFLOW_VERSION
    assert document["audit_metadata"]["generated_at"] == "2026-05-12T00:00:00Z"
    dependencies = {str(dependency["name"]).lower(): dependency for dependency in document["dependencies"]}
    assert set(readiness.REQUIRED_CI_PACKAGES).issubset(dependencies)
    assert dependencies["cryptography"]["version"] == "46.0.5"
    assert dependencies["cryptography"]["sha256_hashes"] == ["a" * 64]
    assert all(dependency["source_registry"] == "https://pypi.org/simple" for dependency in dependencies.values())


def test_ci_dependency_sbom_fails_closed_on_incomplete_inventory(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    _write_ci_lock(tmp_path, "pytest==9.0.3\n")

    try:
        sbom.build_sbom(tmp_path, generated_at="2026-05-12T00:00:00Z")
    except SystemExit as exc:
        assert str(exc).startswith("SBOM_DEPENDENCY_LOCK_INVALID:")
    else:
        raise AssertionError("SBOM generation allowed an unhashed dependency")


def test_ci_dependency_sbom_fails_closed_without_governance_crypto(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    _write_ci_lock(
        tmp_path,
        "cffi==2.0.0 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "pycparser==3.0 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "pytest==9.0.3 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    )

    document = sbom.build_sbom(tmp_path, generated_at="2026-05-12T00:00:00Z")
    failures = sbom.validate_sbom(document)

    assert "SBOM_DEPENDENCY_REQUIRED_PACKAGE_MISSING:cryptography" in failures
    assert "SBOM_DEPENDENCY_GOVERNANCE_CRYPTO_MISSING:cryptography" in failures


def test_ci_evidence_manifest_chains_hashes(tmp_path: Path) -> None:
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("alpha\n", encoding="utf-8")
    second.write_text("beta\n", encoding="utf-8")
    private_key, public_key = _test_keypair()

    manifest = evidence.build_manifest(tmp_path, ["first.txt", "second.txt"], generated_at="2026-05-12T00:00:00Z")
    manifest = evidence.sign_manifest(manifest, private_key, public_key, signer_id="test-signer", signed_at="2026-05-12T00:00:00Z")
    failures = evidence.validate_manifest(tmp_path, manifest, public_key_pem=public_key, expected_signer_id="test-signer")

    assert failures == []
    assert manifest["records"][0]["previous_record_hash"] == evidence.GENESIS_HASH
    assert manifest["records"][1]["previous_record_hash"] == manifest["records"][0]["current_record_hash"]
    assert manifest["chain_head"] == manifest["records"][1]["current_record_hash"]


def test_ci_evidence_manifest_detects_file_tampering(tmp_path: Path) -> None:
    target = tmp_path / "sbom.json"
    target.write_text('{"ok": true}\n', encoding="utf-8")
    private_key, public_key = _test_keypair()
    manifest = evidence.build_manifest(tmp_path, ["sbom.json"], generated_at="2026-05-12T00:00:00Z")
    manifest = evidence.sign_manifest(manifest, private_key, public_key, signer_id="test-signer", signed_at="2026-05-12T00:00:00Z")
    target.write_text('{"ok": false}\n', encoding="utf-8")

    failures = evidence.validate_manifest(tmp_path, manifest, public_key_pem=public_key, expected_signer_id="test-signer")

    assert "EVIDENCE_HASH_MISMATCH:sbom.json" in failures


def test_ci_evidence_manifest_detects_broken_chain_link(tmp_path: Path) -> None:
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("alpha\n", encoding="utf-8")
    second.write_text("beta\n", encoding="utf-8")
    private_key, public_key = _test_keypair()
    manifest = evidence.build_manifest(tmp_path, ["first.txt", "second.txt"], generated_at="2026-05-12T00:00:00Z")
    manifest = evidence.sign_manifest(manifest, private_key, public_key, signer_id="test-signer", signed_at="2026-05-12T00:00:00Z")
    manifest["records"][1]["previous_record_hash"] = "0" * 64

    failures = evidence.validate_manifest(tmp_path, manifest, public_key_pem=public_key, expected_signer_id="test-signer")

    assert "EVIDENCE_CHAIN_PREVIOUS_HASH_MISMATCH:second.txt" in failures
    assert "EVIDENCE_RECORD_HASH_MISMATCH:second.txt" in failures


def test_ci_evidence_manifest_detects_missing_evidence_file(tmp_path: Path) -> None:
    target = tmp_path / "guard-output.txt"
    target.write_text("PRODUCTION_READINESS=true\n", encoding="utf-8")
    private_key, public_key = _test_keypair()
    manifest = evidence.build_manifest(tmp_path, ["guard-output.txt"], generated_at="2026-05-12T00:00:00Z")
    manifest = evidence.sign_manifest(manifest, private_key, public_key, signer_id="test-signer", signed_at="2026-05-12T00:00:00Z")
    target.unlink()

    failures = evidence.validate_manifest(tmp_path, manifest, public_key_pem=public_key, expected_signer_id="test-signer")

    assert "EVIDENCE_FILE_MISSING:guard-output.txt" in failures


def test_ci_evidence_manifest_rejects_missing_signature(tmp_path: Path) -> None:
    target = tmp_path / "guard-output.txt"
    target.write_text("PRODUCTION_READINESS=true\n", encoding="utf-8")
    _private_key, public_key = _test_keypair()
    manifest = evidence.build_manifest(tmp_path, ["guard-output.txt"], generated_at="2026-05-12T00:00:00Z")

    failures = evidence.validate_manifest(tmp_path, manifest, public_key_pem=public_key, expected_signer_id="test-signer")

    assert "EVIDENCE_SIGNATURE_MISSING" in failures


def test_ci_evidence_manifest_rejects_invalid_signature(tmp_path: Path) -> None:
    target = tmp_path / "guard-output.txt"
    target.write_text("PRODUCTION_READINESS=true\n", encoding="utf-8")
    private_key, public_key = _test_keypair()
    manifest = evidence.build_manifest(tmp_path, ["guard-output.txt"], generated_at="2026-05-12T00:00:00Z")
    manifest = evidence.sign_manifest(manifest, private_key, public_key, signer_id="test-signer", signed_at="2026-05-12T00:00:00Z")
    manifest["signature"]["signature"] = "ed25519:" + ("A" * 88)

    failures = evidence.validate_manifest(tmp_path, manifest, public_key_pem=public_key, expected_signer_id="test-signer")

    assert "EVIDENCE_SIGNATURE_INVALID" in failures


def test_ci_evidence_manifest_rejects_wrong_public_key(tmp_path: Path) -> None:
    target = tmp_path / "guard-output.txt"
    target.write_text("PRODUCTION_READINESS=true\n", encoding="utf-8")
    private_key, public_key = _test_keypair()
    _wrong_private_key, wrong_public_key = _test_keypair()
    manifest = evidence.build_manifest(tmp_path, ["guard-output.txt"], generated_at="2026-05-12T00:00:00Z")
    manifest = evidence.sign_manifest(manifest, private_key, public_key, signer_id="test-signer", signed_at="2026-05-12T00:00:00Z")

    failures = evidence.validate_manifest(tmp_path, manifest, public_key_pem=wrong_public_key, expected_signer_id="test-signer")

    assert "EVIDENCE_PUBLIC_KEY_MISMATCH" in failures
    assert "EVIDENCE_SIGNER_IDENTITY_MISMATCH" in failures


def test_ci_evidence_manifest_rejects_replayed_signature_on_new_manifest(tmp_path: Path) -> None:
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("alpha\n", encoding="utf-8")
    second.write_text("beta\n", encoding="utf-8")
    private_key, public_key = _test_keypair()
    original = evidence.build_manifest(tmp_path, ["first.txt"], generated_at="2026-05-12T00:00:00Z")
    original = evidence.sign_manifest(original, private_key, public_key, signer_id="test-signer", signed_at="2026-05-12T00:00:00Z")
    replayed = evidence.build_manifest(tmp_path, ["second.txt"], generated_at="2026-05-12T00:00:01Z")
    replayed["signature"] = original["signature"]

    failures = evidence.validate_manifest(tmp_path, replayed, public_key_pem=public_key, expected_signer_id="test-signer")

    assert "EVIDENCE_SIGNATURE_INVALID" in failures


def test_ci_evidence_manifest_rejects_altered_signer_metadata(tmp_path: Path) -> None:
    target = tmp_path / "guard-output.txt"
    target.write_text("PRODUCTION_READINESS=true\n", encoding="utf-8")
    private_key, public_key = _test_keypair()
    manifest = evidence.build_manifest(tmp_path, ["guard-output.txt"], generated_at="2026-05-12T00:00:00Z")
    manifest = evidence.sign_manifest(manifest, private_key, public_key, signer_id="test-signer", signed_at="2026-05-12T00:00:00Z")
    manifest["signature"]["signer_id"] = "altered-signer"

    failures = evidence.validate_manifest(tmp_path, manifest, public_key_pem=public_key, expected_signer_id="test-signer")

    assert "EVIDENCE_SIGNER_ID_MISMATCH" in failures


def test_ci_evidence_manifest_rejects_signer_identity_mismatch(tmp_path: Path) -> None:
    target = tmp_path / "guard-output.txt"
    target.write_text("PRODUCTION_READINESS=true\n", encoding="utf-8")
    private_key, public_key = _test_keypair()
    manifest = evidence.build_manifest(tmp_path, ["guard-output.txt"], generated_at="2026-05-12T00:00:00Z")
    manifest = evidence.sign_manifest(manifest, private_key, public_key, signer_id="wrong-signer", signed_at="2026-05-12T00:00:00Z")

    failures = evidence.validate_manifest(tmp_path, manifest, public_key_pem=public_key, expected_signer_id="test-signer")

    assert "EVIDENCE_SIGNER_ID_MISMATCH" in failures


def test_ci_evidence_manifest_rejects_missing_trust_policy(tmp_path: Path) -> None:
    target = tmp_path / "guard-output.txt"
    output = tmp_path / "manifest.json"
    target.write_text("PRODUCTION_READINESS=true\n", encoding="utf-8")
    private_key, public_key = _test_keypair()
    policy_path = tmp_path / "missing-policy.json"

    try:
        with_private = {evidence.PRIVATE_KEY_ENV: private_key, evidence.PUBLIC_KEY_ENV: public_key}
        original_env = {key: os.environ.get(key) for key in with_private}
        os.environ.update(with_private)
        evidence.write_manifest(tmp_path, output, ["guard-output.txt"], trust_policy_path=policy_path)
    except SystemExit as exc:
        assert str(exc).startswith("EVIDENCE_TRUST_POLICY_GOVERNANCE_INVALID:")
        assert "EVIDENCE_TRUST_POLICY_MISSING" in str(exc)
    else:
        raise AssertionError("manifest signing allowed a missing trust policy")
    finally:
        for key, value in original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_ci_evidence_manifest_accepts_matching_ci_private_secret(monkeypatch, capsys, tmp_path: Path) -> None:
    target = tmp_path / "guard-output.txt"
    output = tmp_path / "manifest.json"
    target.write_text("PRODUCTION_READINESS=true\n", encoding="utf-8")
    private_key, public_key = _test_keypair()
    policy = _trust_policy(signer_id=evidence.DEFAULT_SIGNER_ID, public_key=public_key)
    policy_path, _fingerprint = _write_trust_policy_governance(tmp_path, policy)
    monkeypatch.setenv(evidence.PRIVATE_KEY_ENV, private_key)
    monkeypatch.delenv(evidence.PUBLIC_KEY_ENV, raising=False)
    monkeypatch.setenv(evidence.SIGNER_ID_ENV, evidence.DEFAULT_SIGNER_ID)

    evidence.write_manifest(tmp_path, output, ["guard-output.txt"], trust_policy_path=policy_path)
    generation_output = capsys.readouterr().out
    manifest = json.loads(output.read_text(encoding="utf-8"))
    failures = evidence.validate_manifest(
        tmp_path,
        manifest,
        expected_signer_id=evidence.DEFAULT_SIGNER_ID,
        trust_policy=policy,
    )

    assert failures == []
    assert manifest["signature"]["public_key_pem"] == public_key
    assert manifest["signature"]["signer_key_id"] == evidence.signer_key_id(public_key)
    assert manifest["signature"]["public_key_fingerprint"] == evidence.signer_key_id(public_key)
    assert manifest["signature"]["signer_id"] == evidence.DEFAULT_SIGNER_ID
    assert f"CI_EVIDENCE_SIGNER_ID={evidence.DEFAULT_SIGNER_ID}" in generation_output
    assert f"CI_EVIDENCE_NORMALIZED_PUBLIC_KEY_SHA256_FINGERPRINT={evidence.signer_key_id(public_key)}" in generation_output
    assert f"CI_EVIDENCE_TRUST_POLICY_FINGERPRINT={policy['allowed_signers'][0]['public_key_fingerprint']}" in generation_output
    assert "CI_EVIDENCE_CANONICAL_DER_NORMALIZATION_VALID=true" in generation_output
    assert "CI_EVIDENCE_FINGERPRINT_MATCH=true" in generation_output

    evidence.verify_manifest(tmp_path, output, trust_policy_path=policy_path)
    verification_output = capsys.readouterr().out
    assert f"CI_EVIDENCE_NORMALIZED_PUBLIC_KEY_SHA256_FINGERPRINT={manifest['signature']['public_key_fingerprint']}" in verification_output
    assert f"CI_EVIDENCE_TRUST_POLICY_FINGERPRINT={policy['allowed_signers'][0]['public_key_fingerprint']}" in verification_output
    assert "CI_EVIDENCE_CANONICAL_DER_NORMALIZATION_VALID=true" in verification_output
    assert "CI_EVIDENCE_FINGERPRINT_MATCH=true" in verification_output


def test_ci_evidence_manifest_rejects_untrusted_ci_private_secret(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "guard-output.txt"
    output = tmp_path / "manifest.json"
    target.write_text("PRODUCTION_READINESS=true\n", encoding="utf-8")
    private_key, _public_key = _test_keypair()
    _trusted_private, trusted_public = _test_keypair()
    policy = _trust_policy(signer_id=evidence.DEFAULT_SIGNER_ID, public_key=trusted_public)
    policy_path, _fingerprint = _write_trust_policy_governance(tmp_path, policy)
    monkeypatch.setenv(evidence.PRIVATE_KEY_ENV, private_key)
    monkeypatch.delenv(evidence.PUBLIC_KEY_ENV, raising=False)
    monkeypatch.setenv(evidence.SIGNER_ID_ENV, evidence.DEFAULT_SIGNER_ID)

    try:
        evidence.write_manifest(tmp_path, output, ["guard-output.txt"], trust_policy_path=policy_path)
    except SystemExit as exc:
        assert str(exc).startswith("EVIDENCE_MANIFEST_INVALID:")
        assert "EVIDENCE_SIGNER_NOT_TRUSTED" in str(exc)
        assert "EVIDENCE_PUBLIC_KEY_FINGERPRINT_MISMATCH" in str(exc)
    else:
        raise AssertionError("manifest signing allowed a private key outside the trust policy")
    assert not output.exists()


def test_ci_evidence_public_key_fingerprint_normalizes_escaped_newlines() -> None:
    _private_key, public_key = _test_keypair()
    escaped = public_key.replace("\n", "\\n")

    assert evidence.signer_key_id(escaped) == evidence.signer_key_id(public_key)
    assert evidence.normalize_public_key_pem(escaped) == evidence.normalize_public_key_pem(public_key)


def test_ci_evidence_public_key_fingerprint_ignores_trailing_whitespace() -> None:
    _private_key, public_key = _test_keypair()
    padded = " \n" + public_key.replace("\n", "  \n") + " \n\t"

    assert evidence.signer_key_id(padded) == evidence.signer_key_id(public_key)
    assert evidence.normalize_public_key_pem(padded) == evidence.normalize_public_key_pem(public_key)


def test_ci_evidence_public_key_fingerprint_uses_canonical_der() -> None:
    _private_key, public_key = _test_keypair()
    der_hash = hashlib.sha256(evidence.public_key_der(public_key)).hexdigest()
    escaped = public_key.replace("\n", "\\n")

    assert evidence.signer_key_id(public_key) == der_hash
    assert evidence.signer_key_id(escaped) == der_hash
    assert hashlib.sha256(public_key.encode("utf-8")).hexdigest() != der_hash


def test_ci_evidence_private_key_derived_public_fingerprint_matches_runtime_public() -> None:
    private_key, public_key = _test_keypair()
    runtime_public_key = evidence.public_key_from_private_key(private_key)

    assert evidence.signer_key_id(runtime_public_key) == evidence.signer_key_id(public_key)
    assert evidence.normalize_public_key_pem(runtime_public_key) == evidence.normalize_public_key_pem(public_key)


def test_ci_evidence_trust_policy_fingerprint_matches_manifest_fingerprint(tmp_path: Path) -> None:
    target = tmp_path / "guard-output.txt"
    target.write_text("PRODUCTION_READINESS=true\n", encoding="utf-8")
    private_key, public_key = _test_keypair()
    policy = _trust_policy(signer_id=evidence.DEFAULT_SIGNER_ID, public_key=public_key)
    manifest = evidence.build_manifest(tmp_path, ["guard-output.txt"], generated_at="2026-05-12T00:00:00Z")
    manifest = evidence.sign_manifest(manifest, private_key, public_key, signer_id=evidence.DEFAULT_SIGNER_ID, signed_at="2026-05-12T00:00:00Z")

    assert policy["allowed_signers"][0]["public_key_fingerprint"] == manifest["signature"]["public_key_fingerprint"]
    assert policy["allowed_signers"][0]["public_key_fingerprint"] == evidence.signer_key_id(manifest["signature"]["public_key_pem"])


def test_ci_evidence_public_key_normalization_rejects_duplicate_pem_headers() -> None:
    _private_key, public_key = _test_keypair()
    duplicated = public_key.replace("-----BEGIN PUBLIC KEY-----", "-----BEGIN PUBLIC KEY-----\n-----BEGIN PUBLIC KEY-----", 1)

    try:
        evidence.signer_key_id(duplicated)
    except SystemExit as exc:
        assert str(exc) == "EVIDENCE_PUBLIC_KEY_INVALID"
    else:
        raise AssertionError("duplicate PEM headers must fail closed")


def test_ci_evidence_manifest_rejects_signer_public_key_mismatch(tmp_path: Path) -> None:
    target = tmp_path / "guard-output.txt"
    target.write_text("PRODUCTION_READINESS=true\n", encoding="utf-8")
    private_key, public_key = _test_keypair()
    _wrong_private_key, wrong_public_key = _test_keypair()
    manifest = evidence.build_manifest(tmp_path, ["guard-output.txt"], generated_at="2026-05-12T00:00:00Z")
    manifest = evidence.sign_manifest(manifest, private_key, public_key, signer_id=evidence.DEFAULT_SIGNER_ID, signed_at="2026-05-12T00:00:00Z")
    manifest["signature"]["public_key_pem"] = evidence.normalize_public_key_pem(wrong_public_key)

    failures = evidence.validate_manifest(tmp_path, manifest, public_key_pem=public_key, expected_signer_id=evidence.DEFAULT_SIGNER_ID)

    assert "EVIDENCE_PUBLIC_KEY_MISMATCH" in failures
    assert "EVIDENCE_SIGNATURE_INVALID" not in failures


def test_ci_evidence_trust_policy_governance_accepts_valid_anchor(tmp_path: Path) -> None:
    _private_key, public_key = _test_keypair()
    policy = _trust_policy(signer_id="test-signer", public_key=public_key)
    policy_path, _fingerprint = _write_trust_policy_governance(tmp_path, policy)

    state = evidence.verify_trust_policy_governance(tmp_path, policy_path)

    assert state["valid"] is True
    assert state["policy_hash"] == evidence._trust_policy_hash(policy)
    assert state["policy_version"] == "ci-evidence-trust-v1"


def test_ci_evidence_trust_policy_governance_rejects_tampering(tmp_path: Path) -> None:
    _private_key, public_key = _test_keypair()
    policy = _trust_policy(signer_id="test-signer", public_key=public_key)
    policy_path, _fingerprint = _write_trust_policy_governance(tmp_path, policy)
    tampered = dict(policy)
    tampered["revoked_fingerprints"] = [evidence.signer_key_id(public_key)]
    policy_path.write_text(evidence._canonical_json(tampered), encoding="utf-8")

    state = evidence.verify_trust_policy_governance(tmp_path, policy_path)

    assert state["valid"] is False
    assert "EVIDENCE_TRUST_POLICY_HASH_MISMATCH" in state["failures"]
    assert "EVIDENCE_TRUST_POLICY_SIGNATURE_INVALID" in state["failures"]


def test_ci_evidence_trust_policy_governance_rejects_unauthorized_change(tmp_path: Path) -> None:
    _private_key, public_key = _test_keypair()
    policy = _trust_policy(signer_id="test-signer", public_key=public_key)
    policy_path, _fingerprint = _write_trust_policy_governance(tmp_path, policy, authorize_signer=False)

    state = evidence.verify_trust_policy_governance(tmp_path, policy_path)

    assert state["valid"] is False
    assert "EVIDENCE_TRUST_POLICY_SIGNER_UNAUTHORIZED" in state["failures"]


def test_ci_evidence_trust_policy_governance_rejects_revoked_policy_signer(tmp_path: Path) -> None:
    _private_key, public_key = _test_keypair()
    policy = _trust_policy(signer_id="test-signer", public_key=public_key)
    policy_path, fingerprint = _write_trust_policy_governance(tmp_path, policy)
    authority_path = policy_path.with_suffix(policy_path.suffix + ".authority.json")
    authority = evidence._load_json_file(authority_path, "authority")
    authority["revoked_policy_signer_fingerprints"] = [fingerprint]
    authority_path.write_text(evidence._canonical_json(authority), encoding="utf-8")

    state = evidence.verify_trust_policy_governance(tmp_path, policy_path)

    assert state["valid"] is False
    assert "EVIDENCE_TRUST_POLICY_SIGNER_REVOKED" in state["failures"]


def test_ci_evidence_trust_policy_governance_rejects_version_continuity_break(tmp_path: Path) -> None:
    _private_key, public_key = _test_keypair()
    policy = _trust_policy(signer_id="test-signer", public_key=public_key)
    policy_path, _fingerprint = _write_trust_policy_governance(tmp_path, policy)
    audit_path = policy_path.with_suffix(policy_path.suffix + ".audit.jsonl")
    audit = evidence._load_json_file(audit_path, "audit")
    audit["previous_policy_version"] = "unexpected-version"
    audit["current_record_hash"] = evidence._trust_policy_audit_hash(audit)
    audit_path.write_text(evidence._canonical_json(audit) + "\n", encoding="utf-8")

    state = evidence.verify_trust_policy_governance(tmp_path, policy_path)

    assert state["valid"] is False
    assert "EVIDENCE_TRUST_POLICY_VERSION_CONTINUITY_BREAK:1" in state["failures"]


def test_ci_evidence_manifest_rejects_revoked_key(tmp_path: Path) -> None:
    target = tmp_path / "guard-output.txt"
    target.write_text("PRODUCTION_READINESS=true\n", encoding="utf-8")
    private_key, public_key = _test_keypair()
    manifest = evidence.build_manifest(tmp_path, ["guard-output.txt"], generated_at="2026-05-12T00:00:00Z")
    manifest = evidence.sign_manifest(manifest, private_key, public_key, signer_id="test-signer", signed_at="2026-05-12T00:00:00Z")
    policy = _trust_policy(signer_id="test-signer", public_key=public_key, revoked=[evidence.signer_key_id(public_key)])

    failures = evidence.validate_manifest(tmp_path, manifest, expected_signer_id="test-signer", trust_policy=policy)

    assert "EVIDENCE_SIGNER_FINGERPRINT_REVOKED" in failures


def test_ci_evidence_manifest_rejects_expired_key(tmp_path: Path) -> None:
    target = tmp_path / "guard-output.txt"
    target.write_text("PRODUCTION_READINESS=true\n", encoding="utf-8")
    private_key, public_key = _test_keypair()
    manifest = evidence.build_manifest(tmp_path, ["guard-output.txt"], generated_at="2026-05-12T00:00:00Z")
    manifest = evidence.sign_manifest(manifest, private_key, public_key, signer_id="test-signer", signed_at="2026-05-12T00:00:00Z")
    policy = _trust_policy(
        signer_id="test-signer",
        public_key=public_key,
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2026-05-11T23:59:59Z",
    )

    failures = evidence.validate_manifest(tmp_path, manifest, expected_signer_id="test-signer", trust_policy=policy)

    assert "EVIDENCE_SIGNER_KEY_EXPIRED" in failures


def test_ci_evidence_manifest_rejects_unauthorized_signer(tmp_path: Path) -> None:
    target = tmp_path / "guard-output.txt"
    target.write_text("PRODUCTION_READINESS=true\n", encoding="utf-8")
    private_key, public_key = _test_keypair()
    manifest = evidence.build_manifest(tmp_path, ["guard-output.txt"], generated_at="2026-05-12T00:00:00Z")
    manifest = evidence.sign_manifest(manifest, private_key, public_key, signer_id="untrusted-signer", signed_at="2026-05-12T00:00:00Z")
    policy = _trust_policy(signer_id="trusted-signer", public_key=public_key)

    failures = evidence.validate_manifest(tmp_path, manifest, trust_policy=policy)

    assert "EVIDENCE_SIGNER_NOT_TRUSTED" in failures


def test_ci_evidence_manifest_allows_rotated_key_continuity(tmp_path: Path) -> None:
    target = tmp_path / "guard-output.txt"
    target.write_text("PRODUCTION_READINESS=true\n", encoding="utf-8")
    old_private, old_public = _test_keypair()
    new_private, new_public = _test_keypair()
    new_entry = {
        "signer_id": "test-signer",
        "public_key_fingerprint": evidence.signer_key_id(new_public),
        "public_key_pem": new_public,
        "valid_from": "2026-06-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
    }
    policy = _trust_policy(
        signer_id="test-signer",
        public_key=old_public,
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2026-05-31T23:59:59Z",
        extra_signers=[new_entry],
    )
    old_manifest = evidence.build_manifest(tmp_path, ["guard-output.txt"], generated_at="2026-05-12T00:00:00Z")
    old_manifest = evidence.sign_manifest(old_manifest, old_private, old_public, signer_id="test-signer", signed_at="2026-05-12T00:00:00Z")
    new_manifest = evidence.build_manifest(tmp_path, ["guard-output.txt"], generated_at="2026-06-15T00:00:00Z")
    new_manifest = evidence.sign_manifest(new_manifest, new_private, new_public, signer_id="test-signer", signed_at="2026-06-15T00:00:00Z")

    old_failures = evidence.validate_manifest(tmp_path, old_manifest, expected_signer_id="test-signer", trust_policy=policy)
    new_failures = evidence.validate_manifest(tmp_path, new_manifest, expected_signer_id="test-signer", trust_policy=policy)

    assert old_failures == []
    assert new_failures == []


def test_governance_timestamping_covers_policy_manifest_and_audit(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is True
    assert {target["target_name"] for target in summary["timestamp_targets"]} == {
        "trust_policy",
        "trust_policy_signature",
        "trust_policy_authority",
        "trust_policy_audit_chain",
        "evidence_manifest",
    }
    assert summary["transparency_records"] == 5
    assert summary["chronology_consensus"]["valid"] is True
    assert summary["chronology_consensus"]["quorum_required"] == evidence.DEFAULT_CHRONOLOGY_QUORUM
    assert len(summary["chronology_consensus"]["authority_ids"]) == 3
    assert (timestamp_dir / evidence.TIMESTAMP_VERIFICATION_FILE).is_file()
    assert (timestamp_dir / evidence.TRANSPARENCY_LOG_FILE).is_file()
    assert (timestamp_dir / evidence.CHRONOLOGY_CONSENSUS_FILE).is_file()
    assert (timestamp_dir / evidence.CHRONOLOGY_CONSENSUS_AUDIT_FILE).is_file()
    assert (timestamp_dir / evidence.TRANSPARENCY_ANCHOR_FILE).is_file()
    assert (timestamp_dir / evidence.WITNESS_PROOFS_FILE).is_file()
    assert (timestamp_dir / evidence.WITNESS_VERIFICATION_FILE).is_file()
    assert (timestamp_dir / evidence.WITNESS_AUDIT_FILE).is_file()
    assert (timestamp_dir / evidence.WITNESS_TRUST_AUDIT_FILE).is_file()
    assert (timestamp_dir / evidence.WITNESS_REPUTATION_HISTORY_FILE).is_file()
    assert summary["transparency_anchor"]["valid"] is True
    assert summary["witness_verification"]["valid"] is True
    assert summary["witness_verification"]["quorum_required"] == evidence.DEFAULT_WITNESS_QUORUM
    assert summary["witness_verification"]["weighted_trust"] >= evidence.DEFAULT_WITNESS_TRUST_THRESHOLD


def test_governance_timestamping_rejects_missing_transparency_log(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    (timestamp_dir / evidence.TRANSPARENCY_LOG_FILE).unlink()

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("GOVERNANCE_TRANSPARENCY_LOG_MISSING" in failure for failure in summary["failures"])


def test_governance_timestamping_rejects_replayed_timestamps(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    proofs_path = timestamp_dir / evidence.TIMESTAMP_PROOFS_FILE
    proofs = json.loads(proofs_path.read_text(encoding="utf-8"))
    proofs[1] = proofs[0]
    proofs_path.write_text(json.dumps(proofs, sort_keys=True), encoding="utf-8")

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("timestamp_replay_detected" in failure or "message_imprint_mismatch" in failure for failure in summary["failures"])


def test_governance_timestamping_rejects_stale_timestamps(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)

    summary = evidence.verify_governance_timestamps(
        tmp_path,
        timestamp_dir,
        manifest_path,
        trust_policy_path=policy_path,
        now=datetime.now(timezone.utc) + timedelta(days=1),
    )

    assert summary["valid"] is False
    assert any("timestamp_freshness_invalid" in failure for failure in summary["failures"])


def test_governance_timestamping_rejects_forged_timestamp_response(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    proofs_path = timestamp_dir / evidence.TIMESTAMP_PROOFS_FILE
    proofs = json.loads(proofs_path.read_text(encoding="utf-8"))
    token_payload = json.loads(__import__("base64").b64decode(proofs[0]["token"]).decode("utf-8"))
    token_payload["signature"] = "forged"
    proofs[0]["token"] = __import__("base64").b64encode(json.dumps(token_payload, sort_keys=True).encode("utf-8")).decode("ascii")
    proofs_path.write_text(json.dumps(proofs, sort_keys=True), encoding="utf-8")

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("tsa_signature_invalid" in failure for failure in summary["failures"])


def test_chronology_consensus_rejects_conflicting_timestamp_authorities(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    consensus_path = timestamp_dir / evidence.CHRONOLOGY_CONSENSUS_FILE
    consensus = json.loads(consensus_path.read_text(encoding="utf-8"))
    consensus["targets"][0]["authority_results"][0]["proof"]["message_imprint"] = "0" * 64
    consensus_path.write_text(json.dumps(consensus, sort_keys=True), encoding="utf-8")

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("message_imprint_mismatch" in failure for failure in summary["failures"])


def test_chronology_consensus_rejects_replayed_consensus_proofs(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    consensus_path = timestamp_dir / evidence.CHRONOLOGY_CONSENSUS_FILE
    consensus = json.loads(consensus_path.read_text(encoding="utf-8"))
    consensus["targets"][1]["authority_results"][0]["proof"] = consensus["targets"][0]["authority_results"][0]["proof"]
    consensus["targets"][1]["authority_results"][0]["timestamp_hash"] = consensus["targets"][0]["authority_results"][0]["timestamp_hash"]
    consensus_path.write_text(json.dumps(consensus, sort_keys=True), encoding="utf-8")

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any(
        "timestamp_replay_detected" in failure
        or "message_imprint_mismatch" in failure
        or "timestamp_continuity_invalid" in failure
        for failure in summary["failures"]
    )


def test_chronology_consensus_rejects_stale_authority_responses(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)

    summary = evidence.verify_governance_timestamps(
        tmp_path,
        timestamp_dir,
        manifest_path,
        trust_policy_path=policy_path,
        now=datetime.now(timezone.utc) + timedelta(days=1),
    )

    assert summary["valid"] is False
    assert any("timestamp_freshness_invalid" in failure for failure in summary["failures"])


def test_chronology_consensus_rejects_missing_quorum_members(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    consensus_path = timestamp_dir / evidence.CHRONOLOGY_CONSENSUS_FILE
    consensus = json.loads(consensus_path.read_text(encoding="utf-8"))
    consensus["targets"][0]["authority_results"] = consensus["targets"][0]["authority_results"][:1]
    consensus["targets"][0]["valid_authority_count"] = 1
    consensus_path.write_text(json.dumps(consensus, sort_keys=True), encoding="utf-8")

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("GOVERNANCE_CHRONOLOGY_QUORUM_NOT_REACHED" in failure for failure in summary["failures"])
    assert any("GOVERNANCE_CHRONOLOGY_AUTHORITY_MEMBER_MISSING" in failure for failure in summary["failures"])


def test_witness_verification_rejects_forged_witness_signatures(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    proofs_path = timestamp_dir / evidence.WITNESS_PROOFS_FILE
    witness_payload = json.loads(proofs_path.read_text(encoding="utf-8"))
    witness_payload["proofs"][0]["signature"] = "ed25519:" + ("A" * 88)
    proofs_path.write_text(json.dumps(witness_payload, sort_keys=True), encoding="utf-8")

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("GOVERNANCE_WITNESS_SIGNATURE_INVALID" in failure for failure in summary["failures"])


def test_witness_verification_rejects_stale_witness_proofs(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)

    summary = evidence.verify_governance_timestamps(
        tmp_path,
        timestamp_dir,
        manifest_path,
        trust_policy_path=policy_path,
        now=datetime.now(timezone.utc) + timedelta(days=1),
    )

    assert summary["valid"] is False
    assert any("GOVERNANCE_WITNESS_STALE" in failure for failure in summary["failures"])


def test_witness_verification_rejects_conflicting_witness_attestations(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    proofs_path = timestamp_dir / evidence.WITNESS_PROOFS_FILE
    witness_payload = json.loads(proofs_path.read_text(encoding="utf-8"))
    witness_payload["proofs"][0]["attestation_result"] = "DENY"
    proofs_path.write_text(json.dumps(witness_payload, sort_keys=True), encoding="utf-8")

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("GOVERNANCE_WITNESS_CONFLICT" in failure for failure in summary["failures"])


def test_witness_verification_rejects_missing_witness_quorum(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    proofs_path = timestamp_dir / evidence.WITNESS_PROOFS_FILE
    witness_payload = json.loads(proofs_path.read_text(encoding="utf-8"))
    witness_payload["proofs"] = witness_payload["proofs"][:1]
    proofs_path.write_text(json.dumps(witness_payload, sort_keys=True), encoding="utf-8")

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("GOVERNANCE_WITNESS_QUORUM_NOT_REACHED" in failure for failure in summary["failures"])
    assert any("GOVERNANCE_WITNESS_MEMBER_MISSING" in failure for failure in summary["failures"])


def test_transparency_anchor_unavailable_fails_closed(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    (timestamp_dir / evidence.TRANSPARENCY_ANCHOR_FILE).unlink()

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("GOVERNANCE_TRANSPARENCY_ANCHOR_MISSING" in failure for failure in summary["failures"])


def test_adversarial_witness_reputation_below_minimum_fails_closed(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    proofs_path = timestamp_dir / evidence.WITNESS_PROOFS_FILE
    witness_payload = json.loads(proofs_path.read_text(encoding="utf-8"))
    witness_payload["trust_policy"]["trust_threshold"] = 2.5
    witness_payload["trust_policy"]["witnesses"][0]["reputation_score"] = 0.1
    proofs_path.write_text(json.dumps(witness_payload, sort_keys=True), encoding="utf-8")

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("GOVERNANCE_WITNESS_REPUTATION_BELOW_MINIMUM" in failure for failure in summary["failures"])
    assert any("GOVERNANCE_WITNESS_TRUST_THRESHOLD_NOT_MET" in failure for failure in summary["failures"])


def test_adversarial_witness_quarantine_after_repeated_invalid_attestations(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    proofs_path = timestamp_dir / evidence.WITNESS_PROOFS_FILE
    witness_payload = json.loads(proofs_path.read_text(encoding="utf-8"))
    witness_payload["trust_policy"]["witnesses"][0]["invalid_attestation_count"] = 2
    proofs_path.write_text(json.dumps(witness_payload, sort_keys=True), encoding="utf-8")

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("GOVERNANCE_WITNESS_QUARANTINED" in failure for failure in summary["failures"])
    assert any("GOVERNANCE_WITNESS_QUARANTINE_ACTIVE" in failure for failure in summary["failures"])


def test_adversarial_witness_collusion_below_weighted_threshold_fails_closed(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    proofs_path = timestamp_dir / evidence.WITNESS_PROOFS_FILE
    witness_payload = json.loads(proofs_path.read_text(encoding="utf-8"))
    witness_payload["trust_policy"]["trust_threshold"] = 2.5
    witness_payload["trust_policy"]["witnesses"][0]["trust_weight"] = 0.25
    witness_payload["trust_policy"]["witnesses"][1]["trust_weight"] = 0.25
    witness_payload["trust_policy"]["witnesses"][2]["trust_weight"] = 0.25
    proofs_path.write_text(json.dumps(witness_payload, sort_keys=True), encoding="utf-8")

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("GOVERNANCE_WITNESS_TRUST_THRESHOLD_NOT_MET" in failure for failure in summary["failures"])


def test_adversarial_witness_conflicting_quorum_partitions_fail_closed(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    proofs_path = timestamp_dir / evidence.WITNESS_PROOFS_FILE
    witness_payload = json.loads(proofs_path.read_text(encoding="utf-8"))
    witness_payload["trust_policy"]["conflict_tolerance"] = 1
    witness_payload["proofs"][0]["attestation_result"] = "DENY"
    witness_payload["proofs"][1]["attestation_result"] = "DENY"
    proofs_path.write_text(json.dumps(witness_payload, sort_keys=True), encoding="utf-8")

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("GOVERNANCE_WITNESS_CONFLICT_TOLERANCE_EXCEEDED" in failure for failure in summary["failures"])
    assert any("GOVERNANCE_WITNESS_QUORUM_NOT_REACHED" in failure for failure in summary["failures"])


def test_adversarial_witness_replayed_attestation_fails_closed(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    proofs_path = timestamp_dir / evidence.WITNESS_PROOFS_FILE
    witness_payload = json.loads(proofs_path.read_text(encoding="utf-8"))
    witness_payload["proofs"][1] = dict(witness_payload["proofs"][0])
    witness_payload["proofs"][1]["witness_id"] = witness_payload["witness_ids"][1]
    proofs_path.write_text(json.dumps(witness_payload, sort_keys=True), encoding="utf-8")

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("GOVERNANCE_WITNESS_REPLAY_DETECTED" in failure for failure in summary["failures"])
    assert any("GOVERNANCE_WITNESS_SIGNATURE_INVALID" in failure for failure in summary["failures"])


def test_witness_reputation_reset_attack_fails_closed(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    history_path = timestamp_dir / evidence.WITNESS_REPUTATION_HISTORY_FILE
    history_path.unlink()

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("GOVERNANCE_WITNESS_REPUTATION_HISTORY_MISSING" in failure for failure in summary["failures"])


def test_witness_quarantine_evasion_fails_closed(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    proofs_path = timestamp_dir / evidence.WITNESS_PROOFS_FILE
    history_path = timestamp_dir / evidence.WITNESS_REPUTATION_HISTORY_FILE
    witness_payload = json.loads(proofs_path.read_text(encoding="utf-8"))
    witness_payload["trust_policy"]["witnesses"][0]["quarantined"] = False
    proofs_path.write_text(json.dumps(witness_payload, sort_keys=True), encoding="utf-8")
    history_records = [json.loads(line) for line in history_path.read_text(encoding="utf-8").splitlines()]
    history_records[0]["quarantined"] = True
    history_records[0]["current_record_hash"] = evidence._witness_reputation_history_hash(history_records[0])
    history_path.write_text("\n".join(json.dumps(record, sort_keys=True) for record in history_records) + "\n", encoding="utf-8")

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("GOVERNANCE_WITNESS_REPUTATION_CONTINUITY_MISMATCH" in failure for failure in summary["failures"])


def test_witness_collusion_recovery_abuse_fails_closed(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    proofs_path = timestamp_dir / evidence.WITNESS_PROOFS_FILE
    witness_payload = json.loads(proofs_path.read_text(encoding="utf-8"))
    for entry in witness_payload["trust_policy"]["witnesses"][:2]:
        entry["quarantined"] = True
        entry["recovery_requested"] = True
        entry["probation_until"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    proofs_path.write_text(json.dumps(witness_payload, sort_keys=True), encoding="utf-8")

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("GOVERNANCE_WITNESS_PROBATION_EXPIRED" in failure for failure in summary["failures"])
    assert any("GOVERNANCE_WITNESS_TRUST_THRESHOLD_NOT_MET" in failure for failure in summary["failures"])


def test_witness_stale_reputation_records_decay_below_minimum(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    proofs_path = timestamp_dir / evidence.WITNESS_PROOFS_FILE
    witness_payload = json.loads(proofs_path.read_text(encoding="utf-8"))
    stale_time = (datetime.now(timezone.utc) - timedelta(days=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    witness_payload["trust_policy"]["witnesses"][0]["last_seen_at"] = stale_time
    proofs_path.write_text(json.dumps(witness_payload, sort_keys=True), encoding="utf-8")

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("GOVERNANCE_WITNESS_REPUTATION_BELOW_MINIMUM" in failure for failure in summary["failures"])


def test_witness_reputation_tampering_fails_closed(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    history_path = timestamp_dir / evidence.WITNESS_REPUTATION_HISTORY_FILE
    history_records = [json.loads(line) for line in history_path.read_text(encoding="utf-8").splitlines()]
    history_records[0]["reputation_score"] = 0.2
    history_path.write_text("\n".join(json.dumps(record, sort_keys=True) for record in history_records) + "\n", encoding="utf-8")

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("GOVERNANCE_WITNESS_REPUTATION_TAMPERING_DETECTED" in failure for failure in summary["failures"])


def test_witness_oscillating_malicious_behavior_fails_closed(tmp_path: Path) -> None:
    manifest_path, policy_path, timestamp_dir = _timestamp_fixture(tmp_path)
    history_path = timestamp_dir / evidence.WITNESS_REPUTATION_HISTORY_FILE
    history_records = [json.loads(line) for line in history_path.read_text(encoding="utf-8").splitlines()]
    base = dict(history_records[0])
    extra_records = []
    previous_hash = history_records[-1]["current_record_hash"]
    for offset, event_type in enumerate(("malicious_detected", "recovered", "malicious_detected"), start=1):
        record = dict(base)
        record["record_id"] = f"governance-witness-reputation-extra-{offset:04d}"
        record["event_type"] = event_type
        record["previous_record_hash"] = previous_hash
        record["current_record_hash"] = evidence._witness_reputation_history_hash(record)
        previous_hash = record["current_record_hash"]
        extra_records.append(record)
    history_records.extend(extra_records)
    history_path.write_text("\n".join(json.dumps(record, sort_keys=True) for record in history_records) + "\n", encoding="utf-8")

    summary = evidence.verify_governance_timestamps(tmp_path, timestamp_dir, manifest_path, trust_policy_path=policy_path)

    assert summary["valid"] is False
    assert any("GOVERNANCE_WITNESS_OSCILLATION_DETECTED" in failure for failure in summary["failures"])
