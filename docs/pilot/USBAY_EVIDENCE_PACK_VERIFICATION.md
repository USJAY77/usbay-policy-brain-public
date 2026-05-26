# USBAY Evidence Pack Verification

USBAY evidence packs are designed for offline auditor verification. The verifier does not require network access, private keys, or the live USBAY runtime.

## Required Files

The evidence pack directory must contain:

- `gate_history.json`
- `chain_summary.json`

Missing files are treated as verification failure.

## Verification Command

Run:

```bash
python3 scripts/verify_governance_evidence_pack.py artifacts/governance-demo-evidence-pack
```

## VERIFY_PASS

The verifier prints VERIFY_PASS and exits 0 only when:

- `gate_history.json` exists
- `chain_summary.json` exists
- signer identity exists
- signer fingerprint exists
- `latest_event_hash` matches the summary
- `previous_event_hash` continuity is valid
- all event hashes match canonical recomputation
- no forbidden secret markers are present

## VERIFY_FAIL

The verifier prints VERIFY_FAIL and exits non-zero when:

- required files are missing
- JSON is malformed
- signer identity is missing
- signer fingerprint is invalid
- an older event was modified
- `previous_event_hash` continuity is broken
- `latest_event_hash` does not match
- the pack is marked broken
- private key, token, or secret markers are present

Example:

```text
VERIFY_FAIL EVENT_HASH_MISMATCH:0
```

## What Is Verified

The offline verifier reconstructs each gate-history event hash from:

- the canonicalized previous event
- the current event payload
- signer continuity metadata

This makes historical event tampering visible without requiring blockchain dependencies or online services.

## Test Command

Run:

```bash
python3 -m pytest -q tests/test_governance_demo_flow.py tests/test_offline_evidence_verifier.py
```

The verifier must remain deterministic, audit-safe, and fail-closed.
