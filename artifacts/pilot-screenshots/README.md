# USBAY Pilot Screenshot Pack

This folder defines the enterprise screenshot set for USBAY pilot review. It is an audit/demo packaging aid only and does not make production certification claims.

## Required Screenshots

Capture the following screenshots for an enterprise review bundle:

1. `01_runtime_dashboard_healthy_state.png`
   - Shows the runtime dashboard loaded and backend health visible.
   - Proves the pilot UI is not blank and the dashboard is reachable.

2. `02_blocked_decision_badge.png`
   - Shows the BLOCKED decision badge.
   - Proves fail-closed governance state is visible to reviewers.

3. `03_review_required_broken_chain_warning.png`
   - Shows REVIEW_REQUIRED or broken-chain warning state.
   - Proves unsafe or incomplete evidence is not displayed as approved.

4. `04_evidence_pack_folder_contents.png`
   - Shows `gate_history.json` and `chain_summary.json` inside the evidence pack.
   - Proves the portable evidence artifacts are present.

5. `05_offline_verifier_verify_pass.png`
   - Shows terminal output from the offline verifier.
   - Expected visible result: `VERIFY_PASS`.

6. `06_zip_release_and_sha256_files.png`
   - Shows the ZIP release and `.sha256` checksum file.
   - Proves the pilot package is checksummed for review.

7. `07_architecture_mermaid_render_preview.png`
   - Shows the rendered Mermaid architecture diagram.
   - Proves the enterprise architecture flow is available for non-code review.

## Required Verification Command

The terminal screenshot should show:

```bash
python3 scripts/verify_governance_evidence_pack.py artifacts/governance-demo-evidence-pack
```

Expected output includes:

```text
VERIFY_PASS
```

## Scope

Screenshots are for enterprise-review demonstration only. They must not show or imply production certification, production approval, or governance bypass.
