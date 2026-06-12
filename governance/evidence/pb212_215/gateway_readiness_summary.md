# PB-212 Live Governance Gateway Readiness

Decision: VERIFIED
Status: READY_FOR_REVIEW

## Scope

PB-212 adds `gateway/governance_gateway.py` as a readiness-only FastAPI gateway with `POST /evaluate`.

## Governance Controls

- Input fields: `diff`, `pr_number`, `policy_hash`, `actor`, `source`.
- Backend source of truth: `evaluators/policy_evaluator.py`.
- Audit evidence: `audit/audit_writer.py`.
- Fail-closed cases: malformed request, missing policy, unknown policy hash, audit write failure, evaluator timeout, evaluator exception.
- Live external calls: disabled.
- Production automation activation: disabled.
- Raw diff persistence: blocked; audit stores changed file count and hashes only.

## Remaining Production Gap

Production activation remains blocked until policy registry signature renewal, human approval integration, deployment attestation, connector credentials governance, and enterprise load validation are completed and reviewed.
