# USBAY Enterprise Audit Overview

This overview summarizes the pilot governance evidence architecture for enterprise reviewers.

## Architecture Summary

### Enforcement Gateway

The Enforcement Gateway is the backend runtime surface for governance decisions and health checks. The pilot dashboard is a visualization layer and does not change enforcement semantics.

### Signer Continuity

Signer continuity metadata gives auditors a stable identity to compare across evidence generations:

- `signer_id`
- `signer_fingerprint`
- `signer_created_at`
- `signer_algorithm`
- `trust_anchor`
- `continuity_status`

No private signing material is exported.

### Tamper-Evident Hash Chain

Governance gate history is represented as an ordered hash chain. Each event includes:

- `previous_event_hash`
- `current_event_hash`
- `chain_position`
- `chain_integrity_status`
- `generated_at`
- `event_type`

Changing an older event breaks canonical recomputation and must produce VERIFY_FAIL.

### Evidence Pack

The downloadable evidence pack contains:

- `gate_history.json`
- `chain_summary.json`

The pack is designed for portable review and excludes private keys, tokens, secrets, and raw sensitive runtime data.

### Offline Verifier

Auditors can verify a pack without the live runtime:

```bash
python3 scripts/verify_governance_evidence_pack.py artifacts/governance-demo-evidence-pack
```

Success returns:

```text
VERIFY_PASS
```

Failure returns:

```text
VERIFY_FAIL
```

### Fail-Closed Behavior

USBAY treats missing, malformed, unsigned, untrusted, or broken evidence as unsafe. The pilot demo must show BLOCKED or REVIEW_REQUIRED when evidence is incomplete.

## Demo States

- ALLOWED: required evidence supports the demo allow path.
- BLOCKED: required governance evidence is missing or incomplete.
- REVIEW_REQUIRED: untrusted or unsigned validation path requires human review.

## Validation

Run:

```bash
python3 -m pytest -q tests/test_governance_demo_flow.py tests/test_offline_evidence_verifier.py
```

Passing tests indicate the demo evidence flow, evidence pack export, and offline verifier remain deterministic and audit-safe.
