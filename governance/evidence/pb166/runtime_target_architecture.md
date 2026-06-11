# PB-166 Target Runtime Hardening Architecture

Decision: VERIFIED
Status: READY_FOR_REVIEW

## Control Principle
USBAY runtime hardening must be rebuilt from current main. The stale `runtime/governance-runtime-hardening` source branch is evidence input only, not implementation source.

## Target Layers
1. Runtime Controller: coordinates action intake, state checks, and fail-closed runtime outcomes.
2. Policy Enforcement: validates policy version, policy signature, and allowed scope before any decision.
3. Decision Engine: produces `ALLOW`, `BLOCK`, `HUMAN_REVIEW`, or `FAIL_CLOSED` only from validated inputs.
4. Risk Classifier: assigns deterministic risk level and privileged-target flags.
5. Approval Workflow: requires explicit human approval for high-risk actions and blocks replay/expiry.
6. Audit Chain: records tamper-evident decision lineage and evidence hashes.
7. Execution Contract: binds policy, decision, approval, audit, and rollback references before execution.
8. Vision Provider Layer: mock/dry-run-first provider boundary; no live external calls or raw screenshot persistence.
9. Runtime Safety Layer: unsafe target detection, secret hygiene, uncertainty stop conditions, and rate/replay controls.
10. Rollback Layer: deterministic rollback plans and evidence-preserving recovery for every runtime change.

## Architecture Rule
No layer may bypass policy enforcement, approval workflow, or audit chain. Missing evidence, missing policy, missing approval, unsupported target, unavailable registry, or invalid hash must fail closed.
