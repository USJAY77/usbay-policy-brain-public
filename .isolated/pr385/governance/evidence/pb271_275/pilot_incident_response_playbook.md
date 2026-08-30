# PB-274 Pilot Incident Response Playbook

## Default State

BLOCKED. This playbook is local-only and does not activate production, connectors, browser automation, desktop automation, terminal write execution, or external API calls.

## Kill Switch Activation Flow

1. Classify the failure as approval_failure, nonce_failure, replay_failure, audit_failure, or device_failure.
2. Block pilot operations immediately.
3. Record hash-only incident evidence.
4. Notify the human operator for review.
5. Preserve append-only evidence for later audit reconstruction.

## Recovery Flow

1. Require human review.
2. Verify the policy hash.
3. Verify the operator registry entry.
4. Verify the device registry entry.
5. Verify nonce freshness and replay protection.
6. Append recovery evidence.
7. Remain blocked until a new explicit approval exists.

## Evidence Requirements

- incident_id
- failure_type
- policy_hash
- operator_id
- device_id
- audit_hash
- kill_switch_state
- timestamp

## Fail-Closed Rule

Missing, malformed, unknown, or non-blocking incident state remains BLOCKED.
