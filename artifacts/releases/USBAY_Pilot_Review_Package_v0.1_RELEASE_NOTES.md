# USBAY Pilot Review Package v0.1 Release Notes

## Package Purpose

This ZIP packages the USBAY pilot governance evidence review materials for enterprise reviewers. It is intended to demonstrate demo-scope governance visibility, signer continuity, tamper-evident gate history, evidence-pack portability, and offline verification.

## Verifier Command

Run from the extracted package root:

```bash
python3 scripts/verify_governance_evidence_pack.py artifacts/governance-demo-evidence-pack
```

## Expected Result

The expected successful verifier output includes:

```text
VERIFY_PASS
```

## SHA256 Checksum

```text
944f222f6b2e832c3262010944cd2d6cd99c06227c527e52f7e3d7ca84893831  USBAY_Pilot_Review_Package_v0.1.zip
```

## No-Secrets Statement

This ZIP is intended to include no private keys, tokens, secrets, raw sensitive runtime payloads, or production signing material. It contains hash-only pilot/demo evidence and offline verification tooling.

## Scope

This release is pilot/demo-only. It does not make production certification claims, bypass governance, or alter USBAY governance enforcement semantics.

## Governance Semantics

Governance semantics changed: no.

## Evidence Pack Contents

The packaged evidence pack contains:

- `artifacts/governance-demo-evidence-pack/gate_history.json`
- `artifacts/governance-demo-evidence-pack/chain_summary.json`

## Offline Verification Instructions

1. Unzip `USBAY_Pilot_Review_Package_v0.1.zip`.
2. Change into the extracted `pilot-review-package/` directory.
3. Run:

```bash
python3 scripts/verify_governance_evidence_pack.py artifacts/governance-demo-evidence-pack
```

A missing file, broken chain, tampered historical event, mismatched latest event hash, or forbidden secret marker must return VERIFY_FAIL with a non-zero exit code.
