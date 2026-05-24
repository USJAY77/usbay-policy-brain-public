# USBAY Pilot Demo Walkthrough

This walkthrough is for enterprise review of the USBAY governance runtime demo. It is demo evidence only. It does not weaken production enforcement, bypass reviewer governance, or convert REVIEW_REQUIRED/BLOCKED states into approval.

## Pilot Flow

1. Open the governance runtime dashboard.
2. Confirm the dashboard renders the runtime decision summary.
3. Review the ALLOWED path.
4. Review the BLOCKED path.
5. Review the REVIEW_REQUIRED path.
6. Review the tamper-evident gate history.
7. Export or inspect the evidence pack.
8. Run offline verification.

## Decision States

### ALLOWED

The ALLOWED demo path shows that required evidence can support a permitted governance decision. It is evidence-backed by the demo state and is not a production execution approval.

### BLOCKED

The BLOCKED demo path shows fail-closed behavior when required governance evidence is incomplete. The dashboard should keep the blocked state visible and include the reason labels, including EVIDENCE_MISSING or DUAL_REVIEW_MISSING when applicable.

### REVIEW_REQUIRED

The REVIEW_REQUIRED path shows untrusted or unsigned validation paths. This state requires human review and does not claim trusted signed evidence.

## Broken-Chain Warning

The tamper-evident gate history includes chain continuity fields:

- `previous_event_hash`
- `current_event_hash`
- `chain_position`
- `chain_integrity_status`
- `broken_chain_warning`
- `latest_event_hash`

If a prior event changes or a chain link is missing, offline verification must fail with VERIFY_FAIL.

## Evidence Pack Export

The demo evidence pack contains:

- `gate_history.json`
- `chain_summary.json`

These files are hash-only, signer-continuity aware, and audit-safe. They must not contain private keys, tokens, or raw sensitive runtime data.

## Offline Verification

Run:

```bash
python3 scripts/verify_governance_evidence_pack.py artifacts/governance-demo-evidence-pack
```

Expected passing output includes:

```text
VERIFY_PASS
```

A tampered or incomplete pack must return a non-zero exit code and print:

```text
VERIFY_FAIL
```

## Validation Command

Run:

```bash
python3 -m pytest -q tests/test_governance_demo_flow.py tests/test_offline_evidence_verifier.py
```

Expected result: all tests pass.
