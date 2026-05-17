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
            "    timeout-minutes: 30\n"
            "    steps:\n"
            "      - uses: actions/setup-python@v5\n"
            "      - run: python -m pip install --require-hashes -r requirements-ci.txt\n"
            "      - run: python -c \"import importlib.metadata; print(importlib.metadata.version('cryptography'))\"\n"
            "      - run: python -c \"import audit.anchor, audit.rfc3161_anchor, audit.worm_archive, scripts.generate_ci_evidence_manifest; print('GOVERNANCE_CRYPTO_IMPORTS_VALID=true')\"\n"
            "      - run: python scripts/run_bounded_validation.py --lane production_readiness --timeout-seconds 1200 --evidence-output evidence/production-readiness-tests-validation.json -- python -m pytest -q -m \"critical or dependency\" tests/test_ci_tiered_validation.py tests/test_production_readiness.py\n"
            "      - run: python scripts/generate_ci_dependency_sbom.py --output sbom/production-readiness-ci-sbom.json\n"
            "      - run: test -s sbom/production-readiness-ci-sbom.json\n"
            "      - uses: actions/upload-artifact@v4\n"
            "        with:\n"
            "          name: production-readiness-ci-sbom\n"
            "      - run: rm -rf evidence/governance-evidence-manifest.json evidence/governance-timestamps\n"
            "      - run: python scripts/generate_ci_evidence_manifest.py --output evidence/governance-evidence-manifest.json --trust-policy governance/ci_evidence_trust_policy.json\n"
            "        env:\n"
            "          USBAY_CI_EVIDENCE_SIGNER_ID: github-actions-production-readiness\n"
            "          USBAY_CI_EVIDENCE_PRIVATE_KEY_PEM: ${{ secrets.USBAY_CI_EVIDENCE_PRIVATE_KEY_PEM }}\n"
            "      - run: test -s evidence/stale-lineage-invalidation.json\n"
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


def _write_audit_artifact_guard(root: Path) -> None:
    workflow = root / ".github" / "workflows" / "audit-artifact-guard.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(
        "name: audit-artifact-guard\n"
        "jobs:\n"
        "  audit-artifact-guard:\n"
        "    steps:\n"
        "      - run: python3 scripts/resolve_ci_changed_files.py --output changed_files.txt --audit-output lineage-reconciliation.json\n",
        encoding="utf-8",
    )
    resolver = root / readiness.CI_CHANGED_FILES_RESOLVER
    resolver.parent.mkdir(parents=True, exist_ok=True)
    resolver.write_text("# stale lineage resolver\n", encoding="utf-8")


def _write_bounded_validation_tooling(root: Path) -> None:
    script = root / readiness.BOUNDED_VALIDATION_SCRIPT
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(
        "VALIDATION_TIMEOUT_FAST_PR\n"
        "VALIDATION_TIMEOUT_DEPENDENCY\n"
        "VALIDATION_TIMEOUT_PRODUCTION_READINESS\n"
        "VALIDATION_TIMEOUT_FULL_REGRESSION\n"
        "partial_audit_preserved\n",
        encoding="utf-8",
    )
    codex = root / ".github" / "workflows" / "codex-autofix-ci.yml"
    codex.parent.mkdir(parents=True, exist_ok=True)
    codex.write_text(
        "name: codex-autofix-ci\n"
        "jobs:\n"
        "  auto-fix:\n"
        "    timeout-minutes: 15\n"
        "    steps:\n"
        "      - run: python3 scripts/run_bounded_validation.py --lane fast_pr --evidence-output evidence/pr-critical-validation.json -- python3 -m pytest -q -m \"critical or governance or dependency\"\n",
        encoding="utf-8",
    )
    full = root / ".github" / "workflows" / "full-regression.yml"
    full.write_text(
        "name: full-regression\n"
        "on:\n"
        "  schedule:\n"
        "  workflow_dispatch:\n"
        "jobs:\n"
        "  full-regression:\n"
        "    timeout-minutes: 130\n"
        "    steps:\n"
        "      - run: python scripts/run_bounded_validation.py --lane full_regression --evidence-output evidence/full-regression-validation.json -- python -m pytest -q\n",
        encoding="utf-8",
    )


def _write_dependabot_governed_automation(root: Path) -> None:
    workflow = root / readiness.DEPENDABOT_GOVERNED_AUTOMERGE_WORKFLOW
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(
        "name: dependabot-governed-automerge\n"
        "on: workflow_dispatch\n"
        "jobs:\n"
        "  governed-dependabot-automerge:\n"
        "    timeout-minutes: 10\n"
        "    steps:\n"
        "      - run: echo audit-artifact-guard production-readiness governance-check policy-verification codeql-quality\n"
        "      - run: python3 scripts/resolve_ci_changed_files.py --output /tmp/dependabot-changed-files.txt --audit-output /tmp/dependabot-lineage-reconciliation.json\n"
        "      - run: python3 scripts/governed_dependabot_pr_automation.py --pr 1 --lineage-diagnostics /tmp/dependabot-lineage-reconciliation.json --merge\n",
        encoding="utf-8",
    )
    script = root / readiness.DEPENDABOT_GOVERNED_AUTOMERGE_SCRIPT
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(
        "dependabot[bot]\n"
        "head_branch_not_dependabot\n"
        "required_check_not_success\n"
        "governance-review-required\n"
        "Governed auto-merge approved.\n"
        '"pr", "merge"\n'
        "--squash --delete-branch\n",
        encoding="utf-8",
    )


def _write_governance_boundary_modules(root: Path) -> None:
    governance = root / "governance"
    governance.mkdir(parents=True, exist_ok=True)
    (governance / "__init__.py").write_text("", encoding="utf-8")
    (governance / "interfaces.py").write_text(
        "from dataclasses import dataclass\n\n"
        "@dataclass(frozen=True)\n"
        "class GovernanceValidationResult:\n"
        "    valid: bool\n"
        "    failures: tuple[str, ...] = ()\n",
        encoding="utf-8",
    )
    for module_name in ("evidence", "chronology", "timestamping", "trust_policy"):
        (governance / f"{module_name}.py").write_text(
            "from governance.interfaces import GovernanceValidationResult\n",
            encoding="utf-8",
        )
    (governance / "release_integrity.py").write_text("# release integrity tooling\n", encoding="utf-8")
    (governance / "operations_observability.py").write_text("# operations observability tooling\n", encoding="utf-8")
    (governance / "policy_pack.py").write_text("# policy pack validator\n", encoding="utf-8")
    (governance / "policy_simulation.py").write_text("# policy simulation\n", encoding="utf-8")
    (governance / "policy_parity.py").write_text("# policy parity\n", encoding="utf-8")
    (governance / "policy_proof_bundle.py").write_text("# policy proof bundle\n", encoding="utf-8")
    (governance / "proof_timestamp_anchor.py").write_text("# proof timestamp anchor\n", encoding="utf-8")
    (governance / "rfc3161_timestamp.py").write_text("# rfc3161 timestamp preflight\n", encoding="utf-8")
    (governance / "worm_evidence_manifest.py").write_text("# worm evidence manifest\n", encoding="utf-8")
    (governance / "evidence_chain.py").write_text("# evidence chain\n", encoding="utf-8")
    (governance / "evidence_merkle_checkpoint.py").write_text("# evidence merkle checkpoint\n", encoding="utf-8")
    (governance / "evidence_merkle_inclusion.py").write_text("# evidence merkle inclusion\n", encoding="utf-8")
    (governance / "evidence_merkle_consistency.py").write_text("# evidence merkle consistency\n", encoding="utf-8")
    (governance / "auditor_verification_bundle.py").write_text("# auditor verification bundle\n", encoding="utf-8")
    (governance / "signed_auditor_bundle.py").write_text("# signed auditor bundle\n", encoding="utf-8")
    (governance / "signed_bundle_timestamp.py").write_text("# signed bundle timestamp\n", encoding="utf-8")
    (governance / "tsa_live_verification.py").write_text("# tsa live verification\n", encoding="utf-8")
    (governance / "signed_bundle_ltv.py").write_text("# signed bundle ltv\n", encoding="utf-8")
    (governance / "signed_bundle_revocation_preflight.py").write_text("# signed bundle revocation preflight\n", encoding="utf-8")
    (governance / "signed_bundle_revocation_response.py").write_text("# signed bundle revocation response\n", encoding="utf-8")
    (governance / "revocation_live_fetch.py").write_text("# revocation live fetch\n", encoding="utf-8")
    (governance / "sealed_audit_archive.py").write_text("# sealed audit archive\n", encoding="utf-8")
    (governance / "evidence_record_chain.py").write_text("# evidence record chain\n", encoding="utf-8")
    (governance / "worm_immutable_storage.py").write_text("# worm immutable storage\n", encoding="utf-8")
    (governance / "regulator_export_profile.py").write_text("# regulator export profile\n", encoding="utf-8")
    (governance / "evidence_renewal_runtime.py").write_text("# evidence renewal runtime\n", encoding="utf-8")
    (governance / "evidence_pq_renewal_plan.py").write_text("# evidence pq renewal plan\n", encoding="utf-8")
    (governance / "pq_runtime_verification.py").write_text("# pq runtime verification\n", encoding="utf-8")
    (governance / "hidden_trust_assumption_scanner.py").write_text("# hidden trust assumption scanner\n", encoding="utf-8")
    (governance / "runtime_parity.py").write_text("# runtime parity\n", encoding="utf-8")
    policy_error_codes = [
        "POLICY_SCHEMA_INVALID",
        "POLICY_DUPLICATE_ID",
        "POLICY_CONFLICTING_RULES",
        "POLICY_MISSING_HUMAN_APPROVAL",
        "POLICY_FAIL_CLOSED_MISSING",
        "POLICY_EXPIRED",
        "POLICY_SCOPE_INVALID",
    ]
    (governance / "policy_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_policy_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny execution until policy pack is valid",
                    }
                    for code in policy_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    simulation_error_codes = [
        "SIM_POLICY_PACK_INVALID",
        "SIM_SCOPE_MISMATCH",
        "SIM_CONFLICTING_DECISION",
        "SIM_HUMAN_APPROVAL_REQUIRED",
        "SIM_FAIL_CLOSED_DEFAULT",
    ]
    (governance / "policy_simulation_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_policy_simulation_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny simulation preview until inputs are valid",
                    }
                    for code in simulation_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    parity_error_codes = [
        "PARITY_DECISION_MISMATCH",
        "PARITY_SCOPE_MISMATCH",
        "PARITY_POLICY_HASH_MISMATCH",
        "PARITY_CONTEXT_DRIFT",
        "PARITY_FAIL_CLOSED_REQUIRED",
    ]
    (governance / "policy_parity_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_policy_parity_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny rollout until policy simulation and runtime parity is verified",
                    }
                    for code in parity_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    proof_bundle_error_codes = [
        "PROOF_POLICY_HASH_MISSING",
        "PROOF_CONTEXT_HASH_MISSING",
        "PROOF_PARITY_UNVERIFIED",
        "PROOF_DIAGNOSTICS_UNSAFE",
        "PROOF_BUNDLE_INVALID",
    ]
    (governance / "policy_proof_bundle_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_policy_proof_bundle_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny proof bundle verification until policy evidence is complete and safe",
                    }
                    for code in proof_bundle_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    timestamp_anchor_error_codes = [
        "TIMESTAMP_BUNDLE_HASH_MISSING",
        "TIMESTAMP_PAYLOAD_INVALID",
        "TIMESTAMP_CLOCK_INVALID",
        "TIMESTAMP_ANCHOR_UNVERIFIED",
        "TIMESTAMP_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "proof_timestamp_anchor_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_proof_timestamp_anchor_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny timestamp verification until anchor evidence is canonical and safe",
                    }
                    for code in timestamp_anchor_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    rfc3161_error_codes = [
        "RFC3161_BUNDLE_HASH_MISSING",
        "RFC3161_ANCHOR_HASH_MISSING",
        "RFC3161_REQUEST_INVALID",
        "RFC3161_NONCE_INVALID",
        "RFC3161_DIAGNOSTICS_UNSAFE",
        "RFC3161_TSA_RESPONSE_UNVERIFIED",
    ]
    (governance / "rfc3161_timestamp_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_rfc3161_timestamp_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny RFC3161 preflight until request material is canonical and safe",
                    }
                    for code in rfc3161_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    worm_error_codes = [
        "WORM_PROOF_BUNDLE_HASH_MISSING",
        "WORM_TIMESTAMP_ANCHOR_MISSING",
        "WORM_RFC3161_DIGEST_MISSING",
        "WORM_MANIFEST_INVALID",
        "WORM_RETENTION_POLICY_MISSING",
        "WORM_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "worm_evidence_manifest_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_worm_evidence_manifest_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny WORM manifest verification until evidence metadata is canonical and safe",
                    }
                    for code in worm_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    evidence_chain_error_codes = [
        "EVIDENCE_CHAIN_PREVIOUS_HASH_MISSING",
        "EVIDENCE_CHAIN_MANIFEST_HASH_MISSING",
        "EVIDENCE_CHAIN_POSITION_INVALID",
        "EVIDENCE_CHAIN_REPLAY_DETECTED",
        "EVIDENCE_CHAIN_CONTINUITY_BROKEN",
        "EVIDENCE_CHAIN_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "evidence_chain_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_evidence_chain_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny evidence chain verification until chronology continuity is canonical and safe",
                    }
                    for code in evidence_chain_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    merkle_error_codes = [
        "MERKLE_LEAVES_MISSING",
        "MERKLE_CHAIN_RANGE_INVALID",
        "MERKLE_ROOT_MISMATCH",
        "MERKLE_CHECKPOINT_REPLAY_DETECTED",
        "MERKLE_CHAIN_HEAD_MISMATCH",
        "MERKLE_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "evidence_merkle_checkpoint_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_evidence_merkle_checkpoint_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny Merkle checkpoint verification until batched evidence is canonical and safe",
                    }
                    for code in merkle_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    merkle_inclusion_error_codes = [
        "MERKLE_INCLUSION_LEAF_MISSING",
        "MERKLE_INCLUSION_INDEX_INVALID",
        "MERKLE_INCLUSION_PATH_INVALID",
        "MERKLE_INCLUSION_ROOT_MISMATCH",
        "MERKLE_INCLUSION_CHECKPOINT_MISMATCH",
        "MERKLE_INCLUSION_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "evidence_merkle_inclusion_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_evidence_merkle_inclusion_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny Merkle inclusion verification until proof evidence is canonical and safe",
                    }
                    for code in merkle_inclusion_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    merkle_consistency_error_codes = [
        "MERKLE_CONSISTENCY_PREVIOUS_MISSING",
        "MERKLE_CONSISTENCY_CURRENT_MISSING",
        "MERKLE_CONSISTENCY_RANGE_INVALID",
        "MERKLE_CONSISTENCY_ROOT_MISMATCH",
        "MERKLE_CONSISTENCY_PATH_INVALID",
        "MERKLE_CONSISTENCY_REPLAY_DETECTED",
        "MERKLE_CONSISTENCY_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "evidence_merkle_consistency_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_evidence_merkle_consistency_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny Merkle consistency verification until checkpoint continuity is canonical and safe",
                    }
                    for code in merkle_consistency_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    auditor_bundle_error_codes = [
        "AUDITOR_BUNDLE_CHECKPOINT_MISSING",
        "AUDITOR_BUNDLE_INCLUSION_MISSING",
        "AUDITOR_BUNDLE_CONSISTENCY_MISSING",
        "AUDITOR_BUNDLE_SCOPE_INVALID",
        "AUDITOR_BUNDLE_HASH_MISMATCH",
        "AUDITOR_BUNDLE_REPLAY_DETECTED",
        "AUDITOR_BUNDLE_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "auditor_verification_bundle_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_auditor_verification_bundle_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny auditor verification until portable proof bundle evidence is canonical and safe",
                    }
                    for code in auditor_bundle_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    signed_auditor_bundle_error_codes = [
        "SIGNED_BUNDLE_MISSING",
        "SIGNED_BUNDLE_HASH_MISMATCH",
        "SIGNED_BUNDLE_SIGNATURE_INVALID",
        "SIGNED_BUNDLE_SIGNER_UNTRUSTED",
        "SIGNED_BUNDLE_REPLAY_DETECTED",
        "SIGNED_BUNDLE_SCOPE_INVALID",
        "SIGNED_BUNDLE_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "signed_auditor_bundle_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_signed_auditor_bundle_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny signed auditor bundle verification until signature and signer trust are canonical and safe",
                    }
                    for code in signed_auditor_bundle_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    signed_bundle_timestamp_error_codes = [
        "SIGNED_BUNDLE_TIMESTAMP_MISSING",
        "SIGNED_BUNDLE_TIMESTAMP_HASH_MISMATCH",
        "SIGNED_BUNDLE_TIMESTAMP_TOKEN_INVALID",
        "SIGNED_BUNDLE_TIMESTAMP_POLICY_INVALID",
        "SIGNED_BUNDLE_TIMESTAMP_REPLAY_DETECTED",
        "SIGNED_BUNDLE_TIMESTAMP_SCOPE_INVALID",
        "SIGNED_BUNDLE_TIMESTAMP_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "signed_bundle_timestamp_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_signed_bundle_timestamp_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny signed bundle timestamp verification until timestamp evidence is canonical and safe",
                    }
                    for code in signed_bundle_timestamp_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    tsa_live_error_codes = [
        "TSA_LIVE_TIMESTAMP_ATTACHMENT_MISSING",
        "TSA_LIVE_IMPRINT_MALFORMED",
        "TSA_LIVE_POLICY_UNEXPECTED",
        "TSA_LIVE_TIMESTAMP_METADATA_STALE",
        "TSA_LIVE_SIGNATURE_HASH_MISMATCH",
        "TSA_LIVE_OUTPUT_PATH_MUTABLE",
        "TSA_LIVE_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "tsa_live_verification_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_tsa_live_verification_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny TSA live verification readiness until local-only timestamp metadata verification passes",
                    }
                    for code in tsa_live_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    signed_bundle_ltv_error_codes = [
        "SIGNED_BUNDLE_LTV_TIMESTAMP_MISSING",
        "SIGNED_BUNDLE_LTV_CERT_CHAIN_MISSING",
        "SIGNED_BUNDLE_LTV_TRUST_ANCHOR_MISSING",
        "SIGNED_BUNDLE_LTV_REVOCATION_MISSING",
        "SIGNED_BUNDLE_LTV_HASH_MISMATCH",
        "SIGNED_BUNDLE_LTV_POLICY_INVALID",
        "SIGNED_BUNDLE_LTV_REPLAY_DETECTED",
        "SIGNED_BUNDLE_LTV_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "signed_bundle_ltv_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_signed_bundle_ltv_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny signed bundle LTV verification until certificate and revocation metadata are canonical and safe",
                    }
                    for code in signed_bundle_ltv_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    revocation_preflight_error_codes = [
        "REVOCATION_PREFLIGHT_LTV_MISSING",
        "REVOCATION_PREFLIGHT_CERT_MISSING",
        "REVOCATION_PREFLIGHT_SOURCE_MISSING",
        "REVOCATION_PREFLIGHT_SOURCE_INVALID",
        "REVOCATION_PREFLIGHT_FRESHNESS_INVALID",
        "REVOCATION_PREFLIGHT_HASH_MISMATCH",
        "REVOCATION_PREFLIGHT_REPLAY_DETECTED",
        "REVOCATION_PREFLIGHT_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "signed_bundle_revocation_preflight_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_signed_bundle_revocation_preflight_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny revocation preflight until hash-only OCSP or CRL planning evidence is canonical and safe",
                    }
                    for code in revocation_preflight_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    revocation_response_error_codes = [
        "REVOCATION_RESPONSE_PREFLIGHT_MISSING",
        "REVOCATION_RESPONSE_LTV_MISSING",
        "REVOCATION_RESPONSE_SOURCE_MISMATCH",
        "REVOCATION_RESPONSE_STATUS_UNKNOWN",
        "REVOCATION_RESPONSE_STATUS_REVOKED",
        "REVOCATION_RESPONSE_STALE",
        "REVOCATION_RESPONSE_TIME_INVALID",
        "REVOCATION_RESPONSE_SIGNATURE_INVALID",
        "REVOCATION_RESPONSE_NONCE_MISMATCH",
        "REVOCATION_RESPONSE_HASH_MISMATCH",
        "REVOCATION_RESPONSE_REPLAY_DETECTED",
        "REVOCATION_RESPONSE_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "signed_bundle_revocation_response_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_signed_bundle_revocation_response_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny revocation response verification until supplied OCSP or CRL metadata is GOOD, fresh, bound, and safe",
                    }
                    for code in revocation_response_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    revocation_live_fetch_error_codes = [
        "REVOCATION_LIVE_FETCH_SOURCE_MISSING",
        "REVOCATION_LIVE_FETCH_SOURCE_MALFORMED",
        "REVOCATION_LIVE_FETCH_SOURCE_STALE",
        "REVOCATION_LIVE_FETCH_RESPONSE_MISSING",
        "REVOCATION_LIVE_FETCH_RESPONSE_UNSIGNED",
        "REVOCATION_LIVE_FETCH_RESPONSE_MISMATCH",
        "REVOCATION_LIVE_FETCH_PATH_MUTABLE",
        "REVOCATION_LIVE_FETCH_RAW_PAYLOAD_LEAKAGE",
        "REVOCATION_LIVE_FETCH_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "revocation_live_fetch_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_revocation_live_fetch_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny revocation live-fetch readiness until hash-only metadata verification passes",
                    }
                    for code in revocation_live_fetch_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    sealed_archive_error_codes = [
        "SEALED_ARCHIVE_MANIFEST_MISSING",
        "SEALED_ARCHIVE_ROOT_HASH_MISMATCH",
        "SEALED_ARCHIVE_SCOPE_INVALID",
        "SEALED_ARCHIVE_CHAIN_MISMATCH",
        "SEALED_ARCHIVE_REPLAY_DETECTED",
        "SEALED_ARCHIVE_POSITION_INVALID",
        "SEALED_ARCHIVE_ARTIFACT_MISSING",
        "SEALED_ARCHIVE_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "sealed_audit_archive_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_sealed_audit_archive_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny sealed audit archive verification until ordered hash-bound evidence is complete and safe",
                    }
                    for code in sealed_archive_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    evidence_record_error_codes = [
        "EVIDENCE_RECORD_ARCHIVE_MISSING",
        "EVIDENCE_RECORD_CHAIN_MISMATCH",
        "EVIDENCE_RECORD_TIMESTAMP_MISSING",
        "EVIDENCE_RECORD_HASH_ALGORITHM_INVALID",
        "EVIDENCE_RECORD_RENEWAL_INVALID",
        "EVIDENCE_RECORD_APPEND_ONLY_VIOLATION",
        "EVIDENCE_RECORD_REPLAY_DETECTED",
        "EVIDENCE_RECORD_POSITION_INVALID",
        "EVIDENCE_RECORD_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "evidence_record_chain_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_evidence_record_chain_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny evidence record verification until archive renewal chronology is append-only and safe",
                    }
                    for code in evidence_record_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    pq_renewal_error_codes = [
        "PQ_RENEWAL_EVIDENCE_RECORD_MISSING",
        "PQ_RENEWAL_TARGET_ALGORITHM_INVALID",
        "PQ_RENEWAL_SIGNATURE_FAMILY_INVALID",
        "PQ_RENEWAL_DOWNGRADE_DETECTED",
        "PQ_RENEWAL_APPEND_ONLY_VIOLATION",
        "PQ_RENEWAL_REPLAY_DETECTED",
        "PQ_RENEWAL_POLICY_INVALID",
        "PQ_RENEWAL_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "evidence_pq_renewal_plan_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_evidence_pq_renewal_plan_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny PQ renewal planning until transition metadata is governed, append-only, and safe",
                    }
                    for code in pq_renewal_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    pq_runtime_error_codes = [
        "PQ_RUNTIME_PLAN_MISSING",
        "PQ_RUNTIME_POLICY_MISSING",
        "PQ_RUNTIME_POLICY_DENIED",
        "PQ_RUNTIME_VERIFIER_MODE_INVALID",
        "PQ_RUNTIME_SIGNATURE_FAMILY_INVALID",
        "PQ_RUNTIME_HASH_ALGORITHM_INVALID",
        "PQ_RUNTIME_REPLAY_DETECTED",
        "PQ_RUNTIME_APPEND_ONLY_VIOLATION",
        "PQ_RUNTIME_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "pq_runtime_verification_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_pq_runtime_verification_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny PQ runtime verification until explicit governed STUB_ONLY approval is present",
                    }
                    for code in pq_runtime_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    hidden_trust_error_codes = [
        "HIDDEN_TRUST_INPUT_MISSING",
        "HIDDEN_TRUST_INPUT_MALFORMED",
        "HIDDEN_TRUST_INPUT_STALE",
        "HIDDEN_TRUST_INPUT_UNSIGNED",
        "HIDDEN_TRUST_INPUT_AMBIGUOUS",
        "HIDDEN_TRUST_IMPLICIT_ASSUMPTION",
        "HIDDEN_TRUST_STALE_AUTHORITY_REUSE",
        "HIDDEN_TRUST_CACHED_APPROVAL_WITHOUT_FRESHNESS",
        "HIDDEN_TRUST_FALLBACK_ALLOW",
        "HIDDEN_TRUST_REPLAYABLE_STATE",
        "HIDDEN_TRUST_MUTABLE_TRACKED_REGISTRY",
        "HIDDEN_TRUST_SUBPROCESS_LEAKAGE",
        "HIDDEN_TRUST_RUNTIME_POLICY_BYPASS",
        "HIDDEN_TRUST_UNSIGNED_METADATA",
        "HIDDEN_TRUST_MISSING_HUMAN_APPROVAL",
        "HIDDEN_TRUST_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "hidden_trust_assumption_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_hidden_trust_assumption_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny merge readiness until hidden trust assumptions are reviewed",
                    }
                    for code in hidden_trust_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    runtime_parity_error_codes = [
        "RUNTIME_PARITY_RUNTIME_HASH_MISSING",
        "RUNTIME_PARITY_POLICY_HASH_MISMATCH",
        "RUNTIME_PARITY_EVIDENCE_MANIFEST_MISSING",
        "RUNTIME_PARITY_UNKNOWN_SOURCE",
        "RUNTIME_PARITY_STALE_COMMIT",
        "RUNTIME_PARITY_ARTIFACT_SIGNATURE_MISMATCH",
        "RUNTIME_PARITY_VERIFIER_FAILURE",
        "RUNTIME_PARITY_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "runtime_parity_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_runtime_parity_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny runtime parity acceptance until deployed state matches audited lineage",
                    }
                    for code in runtime_parity_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    worm_immutable_error_codes = [
        "WORM_IMMUTABLE_ARCHIVE_ROOT_HASH_MISSING",
        "WORM_IMMUTABLE_EVIDENCE_RECORD_CHAIN_MISSING",
        "WORM_IMMUTABLE_ENTRY_ORDER_INVALID",
        "WORM_IMMUTABLE_DUPLICATE_ARCHIVE_ID",
        "WORM_IMMUTABLE_OUTPUT_PATH_MUTABLE",
        "WORM_IMMUTABLE_MANIFEST_INVALID",
        "WORM_IMMUTABLE_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "worm_immutable_storage_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_worm_immutable_storage_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny WORM immutable storage readiness until hash-only manifest verification passes",
                    }
                    for code in worm_immutable_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    regulator_export_error_codes = [
        "REGULATOR_EXPORT_EVIDENCE_CHAIN_MISSING",
        "REGULATOR_EXPORT_SEALED_ARCHIVE_MISSING",
        "REGULATOR_EXPORT_WORM_MANIFEST_MISSING",
        "REGULATOR_EXPORT_TSA_METADATA_MISSING",
        "REGULATOR_EXPORT_POLICY_DECISION_MISSING",
        "REGULATOR_EXPORT_OUTPUT_PATH_MUTABLE",
        "REGULATOR_EXPORT_DUPLICATE_EVIDENCE_REFERENCE",
        "REGULATOR_EXPORT_ENTRY_ORDER_INVALID",
        "REGULATOR_EXPORT_RAW_PAYLOAD_LEAKAGE",
        "REGULATOR_EXPORT_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "regulator_export_profile_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_regulator_export_profile_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny regulator export planning until all hash-only evidence bindings verify",
                    }
                    for code in regulator_export_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    evidence_renewal_runtime_error_codes = [
        "EVIDENCE_RENEWAL_RUNTIME_EVIDENCE_CHAIN_MISSING",
        "EVIDENCE_RENEWAL_RUNTIME_SEALED_ARCHIVE_MISSING",
        "EVIDENCE_RENEWAL_RUNTIME_WORM_MANIFEST_MISSING",
        "EVIDENCE_RENEWAL_RUNTIME_TSA_METADATA_MISSING",
        "EVIDENCE_RENEWAL_RUNTIME_REGULATOR_PROFILE_MISSING",
        "EVIDENCE_RENEWAL_RUNTIME_ENTRY_ORDER_INVALID",
        "EVIDENCE_RENEWAL_RUNTIME_DUPLICATE_RENEWAL_ID",
        "EVIDENCE_RENEWAL_RUNTIME_POLICY_DECISION_STALE",
        "EVIDENCE_RENEWAL_RUNTIME_PATH_MUTABLE",
        "EVIDENCE_RENEWAL_RUNTIME_RAW_PAYLOAD_LEAKAGE",
        "EVIDENCE_RENEWAL_RUNTIME_DIAGNOSTICS_UNSAFE",
    ]
    (governance / "evidence_renewal_runtime_errors.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_evidence_renewal_runtime_error_registry.v1",
                "errors": [
                    {
                        "code": code,
                        "description": code,
                        "fail_closed_reason": "deny evidence renewal runtime planning until all hash-only evidence bindings verify",
                    }
                    for code in evidence_renewal_runtime_error_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    incident_codes = [
        ("GOV_SIGNER_DRIFT", ["trust_policy_fingerprint_mismatch"]),
        ("GOV_DEPENDENCY_DRIFT", ["GOVERNANCE_DEPENDENCY_GRAPH_DRIFT"]),
        ("GOV_RELEASE_MISMATCH", ["release_integrity_signature_invalid"]),
        ("GOV_ROLLBACK_INVALID", ["release_integrity_rollback_target_invalid"]),
        ("GOV_TRUST_POLICY_MISMATCH", ["release_integrity_trust_policy_mismatch"]),
        ("GOV_TELEMETRY_UNSAFE", ["GOVERNANCE_TELEMETRY_UNSAFE"]),
    ]
    (governance / "incident_runbooks.json").write_text(
        json.dumps(
            {
                "schema": "usbay.governance_incident_runbooks.v1",
                "incident_codes": [
                    {
                        "code": code,
                        "title": code,
                        "mapped_failures": mapped,
                        "fail_closed_reason": "deny execution until governance is verified",
                        "recommended_operator_action": "escalate to governance owner",
                        "recovery_checklist": ["verify control", "obtain human approval"],
                        "human_approval_required": True,
                    }
                    for code, mapped in incident_codes
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    scripts = root / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "verify_governance_release_integrity.py").write_text("# release integrity verifier\n", encoding="utf-8")
    (scripts / "governance_diagnostics.py").write_text("# governance diagnostics\n", encoding="utf-8")


def _write_clean_readiness_tree(root: Path) -> None:
    _write_helper(root)
    _write_required_docs(root)
    _write_ci_lock(root)
    _write_production_readiness_workflow(root)
    _write_audit_artifact_guard(root)
    _write_bounded_validation_tooling(root)
    _write_dependabot_governed_automation(root)
    _write_ci_trust_policy_governance_files(root)
    _write_governance_boundary_modules(root)


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
    assert "WORKFLOW_CI_STALE_EVIDENCE_EXPIRATION_MISSING" in failures
    assert "WORKFLOW_CI_EVIDENCE_MANIFEST_PATH_MISSING" in failures
    assert "WORKFLOW_CI_EVIDENCE_EXISTENCE_CHECK_MISSING" in failures
    assert "WORKFLOW_CI_STALE_LINEAGE_INVALIDATION_MISSING" in failures
    assert "WORKFLOW_CI_STALE_LINEAGE_INVALIDATION_CHECK_MISSING" in failures
    assert "WORKFLOW_CI_EVIDENCE_VERIFY_MISSING" in failures


def test_guard_accepts_canonical_python_evidence_manifest_verification(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert "WORKFLOW_CI_EVIDENCE_CHAIN_MISSING" not in failures
    assert "WORKFLOW_CI_EVIDENCE_MANIFEST_PATH_MISSING" not in failures
    assert "WORKFLOW_CI_EVIDENCE_EXISTENCE_CHECK_MISSING" not in failures
    assert "WORKFLOW_CI_EVIDENCE_VERIFY_MISSING" not in failures
    assert "WORKFLOW_CI_EVIDENCE_TRUST_POLICY_MISSING" not in failures
    assert "WORKFLOW_CI_STALE_EVIDENCE_EXPIRATION_MISSING" not in failures
    assert "WORKFLOW_CI_STALE_LINEAGE_INVALIDATION_MISSING" not in failures
    assert "WORKFLOW_CI_STALE_LINEAGE_INVALIDATION_CHECK_MISSING" not in failures


def test_guard_rejects_raw_audit_artifact_diff_without_lineage_resolver(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    workflow = tmp_path / ".github" / "workflows" / "audit-artifact-guard.yml"
    workflow.write_text(
        "name: audit-artifact-guard\n"
        "jobs:\n"
        "  audit-artifact-guard:\n"
        "    steps:\n"
        "      - run: git diff --name-only --diff-filter=ACMR \"$base\" \"$head\" > changed_files.txt\n",
        encoding="utf-8",
    )

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert "AUDIT_ARTIFACT_LINEAGE_RESOLVER_NOT_USED" in failures
    assert "AUDIT_ARTIFACT_RAW_EVENT_DIFF_STALE_LINEAGE_RISK" in failures


def test_guard_detects_missing_dependabot_governed_automation(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    (tmp_path / readiness.DEPENDABOT_GOVERNED_AUTOMERGE_WORKFLOW).unlink()

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert "DEPENDABOT_GOVERNED_AUTOMERGE_WORKFLOW_MISSING" in failures


def test_guard_rejects_dependabot_automation_with_continue_on_error(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    workflow = tmp_path / readiness.DEPENDABOT_GOVERNED_AUTOMERGE_WORKFLOW
    workflow.write_text(workflow.read_text(encoding="utf-8") + "continue-on-error: true\n", encoding="utf-8")

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert "DEPENDABOT_GOVERNED_AUTOMERGE_CONTINUE_ON_ERROR_FORBIDDEN" in failures


def test_guard_rejects_temporary_openssl_evidence_diagnostic(tmp_path: Path) -> None:
    _write_clean_readiness_tree(tmp_path)
    workflow = tmp_path / readiness.PRODUCTION_READINESS_WORKFLOW
    text = workflow.read_text(encoding="utf-8")
    workflow.write_text(
        text
        + (
            "      - name: TEMPORARY DIAGNOSTIC - derive CI evidence public key fingerprint\n"
            "        run: |\n"
            "          openssl pkey -in \"${private_key_path}\" -pubout -out \"${public_key_path}\"\n"
            "          openssl pkey -pubin -in \"${public_key_path}\" -outform DER -out \"${der_path}\"\n"
            "          echo \"TEMPORARY_DIAGNOSTIC_CI_EVIDENCE_PUBLIC_KEY_PEM_BEGIN\"\n"
            "          cat \"${public_key_path}\"\n"
            "          echo \"TEMPORARY_DIAGNOSTIC_CI_EVIDENCE_PUBLIC_KEY_PEM_END\"\n"
        ),
        encoding="utf-8",
    )

    failures = readiness.collect_failures(tmp_path, tracked_files=["tests/provenance_helpers.py"])

    assert "WORKFLOW_CI_EVIDENCE_UNSAFE_DIAGNOSTIC:TEMPORARY DIAGNOSTIC" in failures
    assert "WORKFLOW_CI_EVIDENCE_UNSAFE_DIAGNOSTIC:openssl pkey -in" in failures
    assert "WORKFLOW_CI_EVIDENCE_UNSAFE_DIAGNOSTIC:openssl pkey -pubin" in failures
    assert "WORKFLOW_CI_EVIDENCE_UNSAFE_DIAGNOSTIC:TEMPORARY_DIAGNOSTIC_CI_EVIDENCE_PUBLIC_KEY_PEM_BEGIN" in failures
    assert "WORKFLOW_CI_EVIDENCE_UNSAFE_DIAGNOSTIC:cat \"${public_key_path}\"" in failures


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


def test_ci_evidence_manifest_rejects_untrusted_ci_private_secret(monkeypatch, capsys, tmp_path: Path) -> None:
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
        captured = capsys.readouterr()
        telemetry = captured.out + captured.err
        assert str(exc).startswith("EVIDENCE_MANIFEST_INVALID:")
        assert "EVIDENCE_SIGNER_NOT_TRUSTED" in str(exc)
        assert "EVIDENCE_PUBLIC_KEY_FINGERPRINT_MISMATCH" in str(exc)
    else:
        raise AssertionError("manifest signing allowed a private key outside the trust policy")
    assert not output.exists()
    runtime_public_key = evidence.public_key_from_private_key(private_key)
    assert f"CI_EVIDENCE_SIGNER_ID={evidence.DEFAULT_SIGNER_ID}" in telemetry
    assert f"CI_EVIDENCE_NORMALIZED_PUBLIC_KEY_SHA256={evidence.signer_key_id(runtime_public_key)}" in telemetry
    assert f"CI_EVIDENCE_TRUST_POLICY_FINGERPRINT={policy['allowed_signers'][0]['public_key_fingerprint']}" in telemetry
    assert "CI_EVIDENCE_CANONICAL_DER_NORMALIZATION_VALID=true" in telemetry
    assert "CI_EVIDENCE_FINGERPRINT_MATCH=false" in telemetry
    assert "CI_EVIDENCE_FINGERPRINT_MATCH=false" in captured.out
    assert "CI_EVIDENCE_FINGERPRINT_MATCH=false" in captured.err


def test_ci_evidence_telemetry_emits_on_public_key_normalization_failure(capsys) -> None:
    _private_key, trusted_public = _test_keypair()
    policy = _trust_policy(signer_id=evidence.DEFAULT_SIGNER_ID, public_key=trusted_public)

    failures = evidence.validate_signing_key_trusted(
        "not-a-public-key",
        evidence.DEFAULT_SIGNER_ID,
        policy,
        emit_telemetry=True,
    )
    captured = capsys.readouterr()
    telemetry = captured.out + captured.err

    assert failures == ["EVIDENCE_PUBLIC_KEY_INVALID"]
    assert f"CI_EVIDENCE_SIGNER_ID={evidence.DEFAULT_SIGNER_ID}" in telemetry
    assert "CI_EVIDENCE_NORMALIZED_PUBLIC_KEY_SHA256=" in telemetry
    assert f"CI_EVIDENCE_TRUST_POLICY_FINGERPRINT={policy['allowed_signers'][0]['public_key_fingerprint']}" in telemetry
    assert "CI_EVIDENCE_CANONICAL_DER_NORMALIZATION_VALID=false" in telemetry
    assert "CI_EVIDENCE_FINGERPRINT_MATCH=false" in telemetry
    assert "CI_EVIDENCE_CANONICAL_DER_NORMALIZATION_VALID=false" in captured.out
    assert "CI_EVIDENCE_CANONICAL_DER_NORMALIZATION_VALID=false" in captured.err


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
