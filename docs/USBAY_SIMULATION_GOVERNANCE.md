# USBAY Simulation Governance

## Problem

AI systems are moving from answering questions into running simulations, experiments, and optimization loops. A simulation can influence real-world systems when its output controls execution, infrastructure, policy, finance, health, or operational decisions.

## Governance Principle

USBAY treats simulated experiments as governed actions. A simulation must be classified, attributed to an actor, reviewed when risk is high, and denied when its real-world impact is unknown.

## Mandatory Controls

- Default decision is `DENY`.
- Every simulated experiment requires `actor_id`.
- Every simulation must declare `simulation_id`, `purpose`, `affected_system`, `risk_level`, and `real_world_impact`.
- Unknown `real_world_impact` is blocked.
- Critical infrastructure simulations require `human_review=true`.
- Simulation logs must not contain raw sensitive data.

## Audit Evidence

USBAY audit records may include only redacted metadata:

- `simulation_id`
- `actor_hash`
- `policy_version`
- `decision_id`
- `audit_hash`
- `risk_level`
- `reason_code`

Raw actor identifiers, prompts, payloads, secrets, tokens, device fingerprints, full IP addresses, payment identifiers, and precise location data are forbidden in simulation logs and audit exports.
