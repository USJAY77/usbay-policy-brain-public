# PB-206 Gateway Implementation Plan

Decision: FAIL_CLOSED
Status: REVIEW_REQUIRED
Generated: 2026-06-11T20:11:54.360299Z

## Exact Implementation Plan

1. Establish canonical evaluator contract.
   - Add or locate `evaluators/policy_evaluator.py`.
   - Required input: redacted PR payload, policy registry reference, actor/repository metadata hashes, changed-file summary, requested action.
   - Required output: decision, reason_code, policy_version, policy_hash, audit_required, human_review_required, evidence_hash.
   - Fail closed on missing policy registry, malformed payload, unknown action, unsupported repository, or evaluator exception.

2. Establish canonical audit writer contract.
   - Add or locate `audit/audit_writer.py`.
   - Use existing `audit.hash_chain` / `audit.exporter` primitives through a narrow facade.
   - Store redacted metadata and hashes only.
   - Fail closed on audit write, hash-chain, signature, or export failure.

3. Add gateway integration endpoint or adapter.
   - Prefer an internal adapter that composes evaluator + audit writer before any external workflow calls it.
   - Reuse existing gateway fail-closed patterns from `gateway/app.py`.
   - Never allow audit failure to return a successful PR governance decision.

4. Add GitHub Action only after contracts exist.
   - Trigger on pull_request.
   - Build redacted PR payload.
   - Call gateway with explicit timeout.
   - Treat network failure, non-2xx, malformed JSON, DENY, BLOCK, or FAIL_CLOSED as blocked.
   - Upload redacted evidence artifact.

5. Review and validation gates.
   - Unit tests for evaluator and audit writer.
   - Gateway contract tests with mocked request/response only.
   - Workflow syntax validation.
   - No secrets in logs.
   - Human approval from USBAY-AUDIT and USBAY-GLOBAL23 before any merge-affecting rollout.

## TAAK Safety

[
  {
    "task": "TAAK 1 - Contract extraction and schema definition",
    "can_proceed_safely": false,
    "reason": "Evaluator and audit writer contracts are missing; human approval required before creating canonical facades.",
    "implementation_plan": [
      "Create evaluators/policy_evaluator.py with a single deterministic evaluate_pr(payload) contract.",
      "Return only ALLOW, DENY, HUMAN_REVIEW, or FAIL_CLOSED with reason_code, policy_version, policy_hash, audit_required=true.",
      "Add focused tests for malformed payload, missing policy registry, invalid signature, and denied PR state."
    ]
  },
  {
    "task": "TAAK 2 - Audit writer facade",
    "can_proceed_safely": false,
    "reason": "Existing audit modules exist but no requested audit/audit_writer.py facade or PR audit contract exists.",
    "implementation_plan": [
      "Create audit/audit_writer.py as a small wrapper over audit.hash_chain and/or audit.exporter.",
      "Write only redacted PR decision fields, hashes, policy metadata, actor hash, and timestamps.",
      "Raise a typed error on write failure; gateway and GitHub Action must convert that to FAIL_CLOSED."
    ]
  },
  {
    "task": "TAAK 3 - GitHub Action to gateway integration",
    "can_proceed_safely": false,
    "reason": "No detected workflow currently calls Replit/FastAPI gateway; endpoint auth, timeout, payload schema, and fail-closed handling require review.",
    "implementation_plan": [
      "Add a new workflow or guarded job after contracts exist; do not modify branch protection.",
      "Build payload from PR metadata using hashes/redaction, not raw secrets or full diff payloads.",
      "Call gateway endpoint with explicit timeout and treat non-2xx, network failure, malformed JSON, or DENY/FAIL_CLOSED as blocked.",
      "Upload redacted evidence artifact and leave merge blocked for REVIEW_REQUIRED where human approval is needed."
    ]
  }
]

## No-Action Confirmation

No implementation, commit, push, deploy, external API call, secret modification, or production activation was performed by PB-206.
