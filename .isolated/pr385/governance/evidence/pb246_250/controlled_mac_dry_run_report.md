# PB-250 Controlled Mac Dry-Run Report

Decision: VERIFIED
Status: READY_FOR_REVIEW

## Simulated Loop

The dry-run loop simulates:

1. screenshot metadata
2. screen classification
3. risk score
4. proposed action
5. approval required
6. audit evidence

## Evidence

- Screenshot evidence is metadata-only.
- Raw screenshot storage is disabled.
- Proposed desktop action includes policy decision and audit hash.
- Human approval request is created before any possible execution path.

## Prohibitions

- Must not click, type, scroll, or open apps.
- No pyautogui.
- No browser calls.
- No external API calls.
- No raw screenshots stored.
- No desktop control.

## Remaining Pilot Gaps

- Separate explicit human approval is required before controlled Mac execution.
- Screenshot capture must be bound to audited hash-only storage.
- Native Mac control and pyautogui must remain disabled until approval.
- Model provider calls require separate network governance.
