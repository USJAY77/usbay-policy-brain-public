# Production Readiness Phase 4 Authorization Boundary

Phase 4 verifies production-authorization prerequisites as deterministic metadata. It does not authorize execution, deployment, release, provider execution, or production activation.

USBAY remains an execution control layer. The Enforcement Gateway remains the only runtime authority for current, context-bound execution decisions.

## Boundary

Phase 4 checks:

- policy binding
- source commit binding
- action-contract binding
- approval quorum
- signer identity reference
- trusted root reference
- deterministic signature reference
- timestamp evidence reference
- freshness window
- replay reference
- rollback reference
- external capability states

All evidence is hash-only or reference-only. Raw credentials, tokens, private keys, signature material, prompts, payloads, personal data, and production secrets are forbidden.

## Decisions

- `READY_METADATA_ONLY`: all metadata prerequisites are satisfied; this is not execution authorization.
- `BLOCKED`: known metadata is present but at least one governed prerequisite fails.
- `INVALID`: schema, required field, unknown field, or sensitive-field rules fail.

No Phase 4 decision grants execution authority.

## Mandatory False Flags

Every evaluation and exported evidence keeps:

- `execution_allowed=false`
- `provider_execution=false`
- `production_activation=false`
- `deployment_authorized=false`
- `release_authorized=false`

`production_boundary_ready=true` is metadata only and cannot override Policy Brain, the Enforcement Gateway, branch protection, human review, or runtime authorization.

## External Capability States

Phase 4 represents deferred integrations honestly. These states describe metadata or interface readiness only unless a future governed provider adapter supplies concrete operational evidence:

- `CONFIGURED`
- `VERIFIED_METADATA`
- `VERIFIED_INTERFACE`
- `MISSING`
- `INVALID`
- `UNAVAILABLE`
- `NOT_APPLICABLE`

Production-boundary readiness requires policy-mandatory capabilities to be `VERIFIED_METADATA` or `VERIFIED_INTERFACE` according to the Phase 4 evaluator. `CONFIGURED` is not verified. Metadata validation is not operational deployment. Metadata validation is not live signing. Metadata validation is not live RFC3161. Metadata validation is not WORM evidence. Metadata validation is not runtime authorization. Local timestamps are not RFC3161 evidence. Mutable files are not WORM evidence. Hashes alone are not signatures. Documentation statements are not operational evidence.

Phase 4 does not claim live provider availability, operational RFC3161 timestamping, operational WORM storage, operational external signing, or operational deployment evidence.

## Human Approval

Humans define approval policy. Phase 4 requires a quorum of unique, authorized, active approver identity references. The requester cannot self-approve when policy prohibits it. Stale, revoked, duplicate, missing, or context-mismatched approvals block readiness. Comments, labels, PR text, or bot statements alone do not count as approvals.

## Reuse Prevention

Phase 4 evidence binds to action type, target, environment, policy version, parameters digest, evidence digest, requester, approver set, and source commit. Evidence cannot be reused across another action, target, parameter set, environment, provider, tenant, or device.

## Operator Verification

Run:

```bash
python3 -m py_compile governance/production_readiness_phase4.py
python3 -m json.tool governance/evidence/production_readiness_phase4_schema.json
python3 -m json.tool governance/evidence/production_readiness_phase4_manifest.json
pytest -q tests/test_production_readiness_phase4.py
pytest -q tests/test_production_readiness_post_merge.py tests/test_governance_pr_evidence_validation.py
pre-commit run --all-files
git diff --check
git diff --cached --check
```

Any failure blocks review.

## Rollback

Rollback removes the Phase 4 evaluator, schema, manifest, tests, documentation, post-merge health extension, PR evidence section extension, and CI validation step. Existing Phase 1, Phase 2, Phase 3, runtime, policy, and gateway controls remain unchanged.
