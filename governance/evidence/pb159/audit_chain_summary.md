# PB-159 Tamper-Evident Decision Audit Chain

## Purpose

PB-159 adds a cryptographically chained audit trail for USBAY computer-use decisions. Each decision record links to the previous decision record, and any historical modification invalidates verification.

## Chain Rule

`current_hash = SHA256(previous_hash + decision_id + timestamp + decision + risk_level + policy_version)`

## Genesis Rule

The first decision record uses `previous_hash = GENESIS`.

## Verification

`verify_chain(records)` returns:

- `VALID`
- `CHAIN_BROKEN`

When verification fails, provenance returns a fail-closed decision with reason `AUDIT_CHAIN_BROKEN`.

## Audit Output

The audit chain output includes:

- `audit_chain_id`
- `chain_length`
- `genesis_hash`
- `latest_hash`
- `verification_status`

## Decision

VERIFIED

## Status

READY_FOR_REVIEW
