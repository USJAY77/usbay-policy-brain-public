# USBAY Governance Demo Flow

The governance demo flow renders an enterprise-readable evidence package from
checked-in governance evidence. It does not fabricate approval, provenance, or
validation state. If required evidence is missing or uncertain, the demo remains
`BLOCKED` or `REVIEW_REQUIRED`.

## Generated Outputs

- `artifacts/governance-demo-audit.json`
- `artifacts/governance-demo.html`
- `artifacts/governance-demo-screenshot.svg`

The demo uses `artifacts/governance-dashboard-audit.json` as the source of
truth. The source dashboard audit is hash-referenced in the demo audit so the
rendered package is replay-traceable without exposing raw unsafe payloads.

## Demonstration Sequence

The sequence shows:

- signed commit lineage
- reviewer approval flow
- governance validation state
- anomaly detection
- fail-closed blocked-state handling
- governance dashboard rendering
- audit export generation
- provenance visualization

The current generated demo is intentionally `BLOCKED` because the source
dashboard audit contains real governance gaps:

- `BRANCH_HYGIENE_EVIDENCE_MISSING`
- `pr42_reviews.json:DUAL_REVIEWER_AUTHORIZATION_MISSING`

This is expected behavior. The demo visually proves that USBAY does not convert
incomplete governance evidence into a false pass.

## Safety Properties

- Deterministic JSON and HTML rendering.
- Sanitized outputs only.
- Hash-only evidence source summaries.
- No raw signatures, unsafe payloads, credential material, or approval contents.
- Unsigned governance commits block rendering.
- Provenance chain-break anomalies block rendering.
- Missing reviewer approvals keep the demo in `BLOCKED`.

## Rebuild

```bash
PYTHONPATH=$(pwd)/python:$(pwd) python3 demo/governance_demo_flow.py --root . --timestamp 2026-05-22T00:00:00Z
```

Expected marker:

```text
GOVERNANCE_DEMO_DECISION=BLOCKED
```
