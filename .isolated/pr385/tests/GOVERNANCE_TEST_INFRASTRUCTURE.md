# Governance Test Infrastructure

This test-only infrastructure is approved for reducing duplicated governance setup while preserving exact verifier behavior.

## Approved Builders

- `ApprovalBuilder`: hash-only approval references. It must not provide approval contents.
- `EvidenceBuilder`: immutable evidence chains, WORM plans, regulator export profiles, renewal runtime records, and signed-bundle LTV evidence.
- `PolicyBuilder`: deterministic policy metadata and policy-pack references.
- `ManifestBuilder`: canonical manifest metadata for test setup only.
- `SignedBundleBuilder`: hash-only signed bundle references. It must not provide private keys or raw signatures.

## Required Explicit Fields

Tests must still set or mutate the exact field that proves the behavior under test. Missing approval, expired approval, malformed manifest, invalid WORM evidence, invalid signature, missing timestamp, invalid timestamp token, malformed certificate chain, tenant mismatch, policy-version mismatch, replay metadata, and incomplete regulator export cases must remain explicit in the test body.

## Safe Defaults

Builder defaults may be used only for valid baseline setup. Defaults are deterministic, local-only, hash-only, and redacted. They are not approval to weaken assertions or to infer production readiness.

## Forbidden Implicit Defaults

Builders must not silently add raw payloads, approval contents, credentials, private keys, provider data, production activation flags, runtime execution flags, or customer data. Unknown override keys are rejected so malformed negative-test payloads cannot be accidentally normalized into valid fixtures.

## Negative-Test Usage

Negative tests should construct a valid baseline and then explicitly mutate the precise invalid field. Do not hide the mutation inside a broad builder override when the exact field is the assertion subject.

## Isolation Guarantees

Builder outputs are deep-copied at the boundary. Tests may mutate returned fixtures without leaking state into later tests. Tenant and policy-version variants must be constructed explicitly and must not reuse another tenant or policy context by implication.

## Signed-Bundle Builder Usage

Use `EvidenceBuilder.signed_auditor_envelope()`, `EvidenceBuilder.signed_bundle_timestamp_attachment()`, and `EvidenceBuilder.signed_bundle_ltv_evidence()` for valid signed-bundle baselines. These builders include explicit certificate-chain, timestamp, auditor, and LTV metadata. They do not authorize cryptographic behavior; tests must still call the production verifiers and assert exact failure codes.

Negative signed-bundle tests must mutate the precise invalid field in the test body, such as `signature`, `signed_bundle_hash`, `timestamp_token_hash`, `tsa_certificate_chain_fingerprints`, `trust_anchor_fingerprint`, `revocation_evidence_hash`, `validation_policy_id`, or replay lists. Do not add builder defaults that turn missing, malformed, or mismatched signed-bundle evidence back into valid evidence.

## Collection-Time Import Rules

Shared builders must not import test modules. Test modules should avoid importing helper functions from other test modules when a dependency-neutral builder can provide the same valid baseline. This prevents collection-order coupling and circular imports across signed-bundle, sealed-archive, evidence-record, WORM, regulator-export, and renewal-runtime tests.
