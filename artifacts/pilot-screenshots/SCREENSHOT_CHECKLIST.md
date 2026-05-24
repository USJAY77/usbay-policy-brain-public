# USBAY Pilot Screenshot Checklist

Use this checklist before sharing screenshots with enterprise reviewers.

## Filename Convention

Use numbered PNG filenames:

- `01_runtime_dashboard_healthy_state.png`
- `02_blocked_decision_badge.png`
- `03_review_required_broken_chain_warning.png`
- `04_evidence_pack_folder_contents.png`
- `05_offline_verifier_verify_pass.png`
- `06_zip_release_and_sha256_files.png`
- `07_architecture_mermaid_render_preview.png`

## Checklist Items

- [ ] Runtime dashboard healthy state captured.
- [ ] BLOCKED decision badge captured.
- [ ] REVIEW_REQUIRED or broken-chain warning captured.
- [ ] Evidence pack folder contents captured.
- [ ] Offline verifier VERIFY_PASS terminal output captured.
- [ ] ZIP release and SHA256 files captured.
- [ ] Architecture Mermaid render preview captured.
- [ ] Screenshot proves the stated governance/audit point.
- [ ] No secrets or tokens visible.
- [ ] No private keys visible.
- [ ] No personal data visible.
- [ ] No raw payload leakage visible.
- [ ] No production certification claim visible.
- [ ] Dark mode preferred where available.
- [ ] Enterprise-review purpose only.

## What Each Screenshot Proves

- Runtime dashboard healthy state: the UI renders and backend health is reachable.
- BLOCKED decision badge: fail-closed governance state is visible.
- REVIEW_REQUIRED or broken-chain warning: uncertain or unsafe evidence is not treated as approved.
- Evidence pack folder contents: portable review artifacts are present.
- Offline verifier VERIFY_PASS: the exported evidence pack validates offline.
- ZIP release and SHA256 files: the review package is checksum-bound.
- Architecture Mermaid render preview: reviewers can understand runtime, evidence, verifier, and fail-closed boundaries visually.
