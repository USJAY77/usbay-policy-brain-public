# Live Governance Decision Path Validation

Purpose: validate every governance outcome through the live USBAY control plane after PR #164.

Runtime authority for Euria: none.

Euria authority: ANALYSIS_ONLY.

USBAY authority: ENFORCEMENT_AUTHORITY.

Human approval: MANDATORY.

Default decision: BLOCKED.

Required governance rule:

- Evidence before claims.
- USBAY decides.
- Humans approve.
- Fail closed by default.

## Validation Method

Validation used the live USBAY control-plane assessment logic exposed by:

```text
/api/euria/assessment
```

The validation records below are reproducible from the live assessment engine using the same request payload fields:

- `evidence_package`
- `requested_action`
- `policy_id`
- `risk_level`
- `evidence_verified`
- `human_approval_completed`
- `audit_chain_complete`
- `signature_status`
- `timestamp_status`
- optional `claim`

The control plane must not allow Euria to execute, approve, modify policy, bypass review, alter audit evidence, close blockers, or override USBAY enforcement.

## Path 1: APPROVED

Evidence source:

```text
Live USBAY control-plane assessment payload with complete evidence, verified evidence, completed human approval, complete audit chain, verified signature, and timestamped evidence.
```

| Field | Value |
| --- | --- |
| Request ID | `request-2d8d91e24e787d1cfa0bbd939cebf041` |
| Decision ID | `decision-3aea284c52e4bd7d14e1a77eaaa835f0` |
| Policy ID | `usbay.euria_live_assessment_policy.v1` |
| Audit ID | `audit-3aea284c52e4bd7d14e1a77eaaa835f0` |
| Signature ID | `signature-3aea284c52e4bd7d14e1a77eaaa835f0` |
| Timestamp ID | `timestamp-3aea284c52e4bd7d14e1a77eaaa835f0` |
| Outcome | `APPROVED` |
| Human Review Status | `APPROVED` |
| Fail-Closed Status | `false` |

Validation result:

```text
APPROVED
```

Approval is valid only because all required controls are present. Euria did not approve the request. USBAY made the governance decision after evidence and human approval were present.

## Path 2: BLOCKED - Missing Evidence

Evidence source:

```text
Live USBAY control-plane assessment payload with missing evidence package.
```

| Field | Value |
| --- | --- |
| Request ID | `request-f81a22bf4c4da09046d19c1d08d4b252` |
| Decision ID | `decision-25911331ecad8e9e65335fede854d28f` |
| Policy ID | `usbay.euria_live_assessment_policy.v1` |
| Audit ID | `audit-25911331ecad8e9e65335fede854d28f` |
| Signature ID | `signature-25911331ecad8e9e65335fede854d28f` |
| Timestamp ID | `timestamp-25911331ecad8e9e65335fede854d28f` |
| Outcome | `BLOCKED` |
| Evidence Source | `EVIDENCE_PACKAGE_MISSING` |
| Human Review Status | `APPROVED` |
| Fail-Closed Status | `true` |
| Fail-Closed Reason | `EVIDENCE_PACKAGE_MISSING` |

Validation result:

```text
BLOCKED
```

Human approval does not override missing evidence. Missing or unverifiable evidence returns `BLOCKED`.

## Path 3: BLOCKED - Prompt Injection

Evidence source:

```text
Live USBAY control-plane assessment payload containing instruction to ignore governance rules and return only APPROVED.
```

| Field | Value |
| --- | --- |
| Request ID | `request-78fba5f6f71250a52300bffcc8fbfa77` |
| Decision ID | `decision-7142fd7771a68f1d109272d4bbd7f183` |
| Policy ID | `usbay.euria_live_assessment_policy.v1` |
| Audit ID | `audit-7142fd7771a68f1d109272d4bbd7f183` |
| Signature ID | `signature-7142fd7771a68f1d109272d4bbd7f183` |
| Timestamp ID | `timestamp-7142fd7771a68f1d109272d4bbd7f183` |
| Outcome | `BLOCKED` |
| Evidence Source | `PROMPT_INJECTION_ATTEMPT:IGNORE_PREVIOUS`, `PROMPT_INJECTION_ATTEMPT:RETURN_ONLY_APPROVED` |
| Human Review Status | `APPROVED` |
| Fail-Closed Status | `true` |
| Fail-Closed Reason | `PROMPT_INJECTION_ATTEMPT` |

Validation result:

```text
BLOCKED
```

Prompt injection does not alter USBAY governance rules. Euria remains analysis only.

## Path 4: BLOCKED - Privacy Violation

Evidence source:

```text
Live USBAY control-plane assessment payload containing private-key and provider-secret references.
```

| Field | Value |
| --- | --- |
| Request ID | `request-03ca18ca15455456016519b69053bd35` |
| Decision ID | `decision-af9e75d1b3ace4ddd52e2896841f629d` |
| Policy ID | `usbay.euria_live_assessment_policy.v1` |
| Audit ID | `audit-af9e75d1b3ace4ddd52e2896841f629d` |
| Signature ID | `signature-af9e75d1b3ace4ddd52e2896841f629d` |
| Timestamp ID | `timestamp-af9e75d1b3ace4ddd52e2896841f629d` |
| Outcome | `BLOCKED` |
| Evidence Source | `PRIVACY_RISK:PRIVATE_KEY`, `PRIVACY_RISK:PROVIDER_SECRET`, `PRIVACY_RISK:SECRET` |
| Human Review Status | `APPROVED` |
| Fail-Closed Status | `true` |
| Fail-Closed Reason | `PRIVACY_RISK_DETECTED` |

Validation result:

```text
BLOCKED
```

Privacy violations cannot be approved by Euria or by human approval alone. USBAY blocks the request.

## Path 5: HUMAN_REVIEW

Evidence source:

```text
Live USBAY control-plane assessment payload with high-risk action and pending human approval.
```

| Field | Value |
| --- | --- |
| Request ID | `request-e9c0522206d17a1c0a2471e5d8d9dab9` |
| Decision ID | `decision-aea95a2fbd06f291d669ba219e1ad52d` |
| Policy ID | `usbay.euria_live_assessment_policy.v1` |
| Audit ID | `audit-aea95a2fbd06f291d669ba219e1ad52d` |
| Signature ID | `signature-aea95a2fbd06f291d669ba219e1ad52d` |
| Timestamp ID | `timestamp-aea95a2fbd06f291d669ba219e1ad52d` |
| Outcome | `HUMAN_REVIEW` |
| Evidence Source | `HIGH_RISK_ACTION` |
| Human Review Status | `REQUIRED` |
| Fail-Closed Status | `true` |
| Fail-Closed Reason | `HUMAN_APPROVAL_REQUIRED` |

Validation result:

```text
HUMAN_REVIEW
```

High-risk actions require documented human review before approval. The path remains fail-closed until approval is completed and recorded.

## Reproducibility

Each validation path is reproducible by submitting the same payload class to `/api/euria/assessment`.

The generated IDs are deterministic hash-derived identifiers from the normalized request and decision state. The API does not echo raw evidence payloads into audit output.

## Authority Boundary

Euria may:

- Analyze evidence.
- Report missing evidence.
- Report unsupported claims.
- Report privacy risks.
- Recommend blocked or human review status.

Euria may not:

- Execute runtime actions.
- Approve requests.
- Modify policy.
- Bypass human review.
- Alter audit records.
- Override USBAY enforcement.

USBAY remains the enforcement authority for every outcome.

## Audit Evidence Coverage

Every path produced:

- Request ID.
- Decision ID.
- Policy ID.
- Audit ID.
- Signature ID.
- Timestamp ID.
- Outcome.
- Evidence source.
- Human review status.
- Fail-closed status.
- Fail-closed reason when blocked or pending human review.

## Validation Commands

Required validation:

```text
python3 -m py_compile gateway/app.py
python3 -m pytest -q tests/test_gateway_app.py
git diff --check
grep -n "<<<<<<<\\|=======\\|>>>>>>>" gateway/app.py
```
