# Audit Evidence Adoption

## Integrated Validators

The audit-evidence adapter is opt-in and currently integrated through explicit wrapper calls for high-value validation domains:

- approvals
- evidence
- signatures
- manifests
- policy validation
- production readiness
- regulator exports
- signed bundles
- WORM

Existing validators keep their return types and decisions. The adapter must be called after the original validation result is known.

## Deferred Validators

Repository-wide direct validator mutation is deferred. Runtime, connector, model, customer, and media governance validators should adopt this contract in separate focused batches only when they can provide explicit tenant, policy version, evidence ID, validator name, and timestamp context without guessing.

## Required Audit Context

Each audit record requires:

- validator
- timestamp
- policy version
- tenant
- evidence ID
- validator version

Missing context produces an explicit audit-generation error. It must not change the original validation result, authorization decision, or fail-closed state.

## Deterministic Hashing

Canonical payload hashes and audit hashes use deterministic JSON serialization with sorted keys and compact separators. Tests use fixed timestamps to prove repeated runs, reordered input dictionaries, tenant changes, policy-version changes, evidence-content changes, and failure-code changes are reflected deterministically.

## Raw-Data Prohibition

Audit records serialize only hashes and metadata. Raw governance payloads, secrets, credentials, signatures, certificates, tokens, approval contents, provider data, and customer data must not enter the serialized audit record.

## Failure Behavior

Audit generation failure is reported as `audit_generation_error` beside the unchanged validation output. It must never convert a blocked decision into an allowed decision and must never fabricate audit evidence.

## Backward Compatibility

The adapter is additive. Existing callers continue to use validator return values without requesting audit evidence. No production path may depend on audit serialization for authorization.

## Chain Compatibility

Audit records can be wrapped in deterministic chain records with previous-hash binding. The current adapter verifies canonical serialization, record hashing, duplicate audit hashes, reordered records, and tampering. It does not redesign the existing audit chain.

## Pipeline Flow

The governed audit pipeline uses a fixed validator sequence:

1. policy validation
2. approval validation
3. signature validation
4. manifest validation
5. evidence validation
6. evidence-chain validation
7. WORM validation
8. regulator export validation
9. signed-bundle validation
10. production-readiness validation

Each stage keeps its original validator output. Audit evidence is generated only after the stage result is known and is additive to the original decision.

## Correlation IDs

Pipeline correlation is deterministic and hash-only. The correlation input includes each stage's validator name, evidence ID, audit hash, and canonical payload hash, plus the tenant and policy version. Raw payloads are not serialized into pipeline summaries.

## Deterministic Ordering

Pipeline summaries validate the fixed stage order and fail closed for missing stages, duplicate stages, reordered stages, tenant mismatches, policy-version mismatches, and invalid stage evidence. These checks are compatibility checks for audit continuity; they do not authorize runtime execution.

## Audit Generation Rules

Audit evidence generation must remain opt-in and additive. If audit generation fails, the original validation result remains unchanged and the failure is reported through `audit_generation_error`. No validator may treat audit serialization as authorization to allow execution.
