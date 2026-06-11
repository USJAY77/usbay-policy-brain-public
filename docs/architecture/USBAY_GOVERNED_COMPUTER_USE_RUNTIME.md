# USBAY Governed Computer-Use Runtime

## Purpose

USBAY computer use is a governed runtime, not an uncontrolled desktop agent. It proposes structured actions, evaluates them through policy and approval gates, and records audit evidence before any execution path can proceed.

## Risk Model

Uncontrolled screen-reading and clicking agents can follow prompt-injected UI text, mutate GitHub or browser state, leak sensitive screen data, and perform high-risk actions without accountable approval. USBAY treats every computer-use action as untrusted until policy, evidence, and approval state are verified.

## Control Flow

1. Capture screen metadata without storing raw screenshots by default.
2. Convert observations into a structured action proposal.
3. Validate the action schema.
4. Evaluate safety guardrails.
5. Evaluate the USBAY computer-use policy.
6. Require human approval for high-risk targets such as merge, approve, delete, and deploy.
7. Execute only when the decision is `ALLOW`.
8. Record tamper-evident audit metadata for every decision.

## Approval Boundary

High-risk actions enter an approval queue. Approval records bind to the exact action ID and action hash. A reviewer must provide an approval reason before a short-lived approval token is issued. The runtime consumes approval tokens once. Replayed or expired tokens block execution. Missing, unknown, or action-mismatched tokens fail closed because the approval evidence cannot be trusted.

Denials are also recorded. A denied action is blocked and remains auditable through its approval audit hash. Approval evidence export redacts raw approval tokens and exports only token hashes, action hashes, decisions, reasons, timestamps, and evidence hashes.

## Fail-Closed Behavior

The runtime blocks when policy is missing, action type is unknown, policy signature evidence is missing, approval is missing, evidence is invalid, or secret-like text is detected. Unknown state is unsafe state.

## Human Approval Boundary

High-risk actions require explicit human approval. This includes GitHub merge, approval, deletion, deployment, and other sensitive mutating targets. The runtime does not auto-approve reviews and does not bypass branch protection or governance checks.

## Audit Evidence

Audit events include action ID, action type, target summary, risk level, capability, human approval state, policy decision, policy reason, previous hash, and audit hash. Raw screenshots and raw typed text are not stored by default.

## Provider Boundary

`vision_adapter.py` and `runtime/computer_use/providers/` define a provider-agnostic screen understanding boundary. PB-156 implements a deterministic mock provider only. The provider contract uses one normalized response schema and fails closed on provider errors, timeouts, malformed responses, unknown providers, missing providers, invalid observations, and high-risk responses without approval markers. Provider calls are audited with metadata hashes. Raw screenshots are not persisted by default.

Live Gemini, OpenAI, Claude, or other model API calls are intentionally out of scope and require a separate reviewed PR. Current provider behavior is local-only and mock-only.

## Why This Is Not An Uncontrolled Agent

The runtime is dry-run by default, policy-gated, approval-gated, audit-producing, and fail-closed. It cannot directly mutate desktop, browser, GitHub, Notion, or external state unless an explicit future implementation adds live drivers under separate governance review.
