# GitHub Artifact Attestation for Governance Exports

USBAY tenant audit packages have two provenance layers:

1. USBAY internal cryptographic evidence
2. GitHub Actions artifact attestation

The GitHub attestation proves that the published governance export subjects were produced by the configured GitHub Actions workflow for this repository, at a specific workflow run and commit context. It does not replace USBAY evidence validation.

USBAY internal verification proves tenant binding, release signature validity, immutable ledger continuity, WORM manifest integrity, RFC3161 timestamp integrity, package signature validity, and no-secret-leakage checks.

The attested subject set is intentionally limited to non-secret auditor-facing artifacts:

- `tenant_audit_package_attestation.tar.gz`
- `evidence_index.json`
- `verification_report.md`
- `verification_manifest.json`

The workflow does not attest or upload private keys, approval contents, raw nonces, PEM certificate material, raw audit secrets, or sensitive runtime evidence. The attestation subject archive is built from selected package files only after `python3 -m audit.exporter verify-tenant-package` returns `PASS`.

If package verification fails, the attestation step is skipped by workflow condition and no GitHub build provenance attestation is emitted for that failed package. This preserves fail-closed governance behavior: external build provenance exists only for packages that already passed USBAY internal verification.

Auditors should verify both layers:

- Use GitHub artifact attestation to confirm where and how the export artifacts were built.
- Use `python3 -m audit.exporter verify-tenant-package <package_path>` to verify USBAY tenant evidence, signatures, hashes, RFC3161 timestamp evidence, WORM integrity, and the human-readable report.

GitHub attestation answers “which trusted workflow produced this artifact?” USBAY verification answers “is the governance evidence internally valid, tenant-scoped, signed, timestamped, and fail-closed?”
