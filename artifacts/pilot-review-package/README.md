# USBAY Pilot Review Package

This package contains audit-safe pilot demo materials for enterprise review. It proves that the USBAY demo can show governance decision states, signer continuity, tamper-evident gate history, portable evidence-pack export, and offline verification without requiring the live runtime.

## Contents

- `docs/pilot/USBAY_PILOT_DEMO_WALKTHROUGH.md`
- `docs/pilot/USBAY_EVIDENCE_PACK_VERIFICATION.md`
- `docs/pilot/USBAY_ENTERPRISE_AUDIT_OVERVIEW.md`
- `scripts/verify_governance_evidence_pack.py`
- `artifacts/governance-demo-evidence-pack/gate_history.json`
- `artifacts/governance-demo-evidence-pack/chain_summary.json`
- `MANIFEST.json`

## Offline Verification

From this package root, run:

```bash
python3 scripts/verify_governance_evidence_pack.py artifacts/governance-demo-evidence-pack
```

Expected passing output includes:

```text
VERIFY_PASS
```

## Fail-Closed Behavior

Missing files, malformed JSON, broken `previous_event_hash` continuity, tampered historical events, mismatched `latest_event_hash`, or forbidden secret markers must produce VERIFY_FAIL and a non-zero exit code.

## Secret Hygiene

This package is intended to include no private keys, tokens, secrets, raw sensitive runtime payloads, or production signing material. It contains hash-only demo evidence and offline verification tooling.

## Scope

This is a pilot/demo review package only. It does not assert production approval, bypass governance, or change USBAY enforcement semantics.
