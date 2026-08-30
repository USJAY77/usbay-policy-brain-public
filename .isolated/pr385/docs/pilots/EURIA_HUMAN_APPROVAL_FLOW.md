# Euria Human Approval Flow

Purpose: define the human approval checkpoint for the governed Euria evidence workflow pilot.

Runtime impact: none.

Default decision: BLOCKED.

## Approval Principle

Human approval is required for governed approval outcomes.

Human approval does not replace evidence.

Human approval does not override policy validation.

Human approval does not authorize Euria to execute, modify policy, alter audit records, bypass review, or override USBAY enforcement.

## Required Review Inputs

Before an `APPROVED` outcome may be recorded, the human reviewer must receive:

- Euria evidence analysis.
- USBAY policy validation result.
- Required evidence references.
- Missing evidence result.
- Prompt injection finding.
- Privacy boundary finding.
- Unsupported claim finding.
- Draft audit evidence record.
- Final decision options.

If any required review input is missing:

```text
BLOCKED
```

## Reviewer Responsibilities

Reviewer must confirm:

- Evidence comes from approved USBAY sources.
- Euria did not invent facts.
- Euria did not accept unsupported claims.
- USBAY policy validation passed.
- Audit evidence record can be generated.
- Privacy rules were followed.
- Prompt injection was rejected.
- Requested action is within approved scope.

Reviewer must reject requests that depend on undocumented evidence.

## Approval Path

The approval path is:

1. Euria performs evidence analysis.
2. USBAY policy validation passes.
3. Euria prepares reviewer packet.
4. Human reviewer confirms evidence and scope.
5. Human reviewer records explicit approval.
6. USBAY audit evidence record is generated.
7. Outcome is recorded as `APPROVED`.

Required outcome:

```text
APPROVED
```

Only when every step is complete and documented.

## Blocked Path

The blocked path is:

1. Euria identifies missing evidence, unsupported claim, prompt injection, privacy violation, or out-of-scope request.
2. USBAY policy validation fails or cannot run.
3. Human review is missing or rejects the request.
4. Audit evidence cannot be generated.
5. Outcome is recorded as `BLOCKED`.

Required outcome:

```text
BLOCKED
```

## Audit Evidence Record

The final decision must be recorded with:

- Actor.
- Device or system identity.
- Decision.
- Timestamp.
- Policy version.
- Evidence references.
- Reviewer reference.
- Validation result reference.

If any audit evidence field is missing:

```text
BLOCKED
```

## Human Override Boundary

Human approval may approve only within documented USBAY policy.

Human approval must not:

- Override missing evidence.
- Override failed policy validation.
- Override prompt injection findings.
- Override privacy violations.
- Override audit evidence requirements.
- Override USBAY enforcement.

If a reviewer attempts to approve without required evidence:

```text
BLOCKED
```

## Final Decision Rules

| Condition | Outcome |
| --- | --- |
| Evidence complete, policy validation passed, human review approved, audit record generated | APPROVED |
| Evidence missing | BLOCKED |
| Policy validation failed or unavailable | BLOCKED |
| Human review missing | BLOCKED |
| Audit evidence incomplete | BLOCKED |
| Prompt injection detected | BLOCKED |
| Privacy violation detected | BLOCKED |
| Unsupported claim required for approval | BLOCKED |
