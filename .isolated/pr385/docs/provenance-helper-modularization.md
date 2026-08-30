# Provenance Helper Modularization

## Purpose

The governance provenance test helpers are split into small modules under `tests/helpers/` so audit reviewers can trace release manifest generation, immutable authority installation, CI lineage snapshots, and diagnostics without reading one mixed-responsibility helper file.

The legacy `tests/provenance_helpers.py` module remains as a compatibility shim. It re-exports the canonical helper entry points and contains no governance logic.

## Module Responsibilities

`tests/helpers/provenance_manifest.py`

- Builds canonical temporary governance release manifests.
- Calls runtime manifest generation and signing logic.
- Sets `USBAY_GOVERNANCE_RELEASE_PATH` for tests so repo-root `governance_release.json` is never required.

`tests/helpers/provenance_authority.py`

- Installs immutable `RuntimeProvenanceAuthority` into gateway, immutable ledger, and audit export test paths.
- Keeps validator monkeypatches delegated to canonical `validate_release_manifest()`.

`tests/helpers/provenance_bootstrap.py`

- Writes deterministic authority bootstrap diagnostics.
- Captures authority identity, accepted lineage, expected/current commit, and release continuity.

`tests/helpers/provenance_ci.py`

- Exposes authority-derived lineage snapshots.
- Does not fabricate commit hashes or reconstruct CI state.

`tests/helpers/provenance_generation.py`

- Owns generated-manifest diagnostic file creation.
- Writes `generated_manifest_path.json` and `manifest_generation_audit.json`.

`tests/helpers/provenance_tenant.py`

- Holds tenant defaults used by provenance helper generation.
- Tenant validation remains in runtime policy code.

`tests/helpers/provenance_assertions.py`

- Isolates shared governance assertions for authority lineage.

`tests/helpers/provenance_runtime.py`

- Provides a runtime-facing import boundary for authority installation.

`tests/helpers/provenance_attestation.py`

- Reserved boundary for attestation freshness and node identity helper expansion.

`tests/helpers/provenance_worm.py`

- Reserved boundary for WORM retention and archive helper expansion.

`tests/helpers/__init__.py`

- Lightweight index module exposing stable helper entry points.

## Runtime Authority Flow

Tests call `install_runtime_authority()`.

The helper:

1. Generates a temporary signed governance release manifest through canonical runtime generation.
2. Resolves immutable `RuntimeProvenanceAuthority` from that manifest.
3. Installs the authority into runtime validation paths.
4. Writes authority diagnostics derived from the authority object.

No helper fabricates loose provenance dictionaries or bypasses release validation.

## Manifest Generation Flow

`ensure_test_release_manifest()` creates a temporary manifest under pytest temp storage. It uses runtime manifest generation, not a checked-in `governance_release.json` fixture.

Generated diagnostics are:

- `generated_manifest_path.json`
- `manifest_generation_audit.json`

These are test artifacts only and must not be tracked.

## CI Validation Flow

CI lineage assertions are authority-derived:

- expected commit
- current commit
- accepted commit set
- ancestor continuity
- release lineage

The helper modules do not set fake `GITHUB_SHA`, `GITHUB_HEAD_SHA`, or `GITHUB_BASE_SHA` values.

## Governance Boundaries

- Manifest generation is isolated from authority installation.
- Authority installation is isolated from diagnostics.
- CI lineage snapshots are read-only and authority-derived.
- Tenant defaults are isolated from manifest validation.
- Assertions are isolated from setup helpers.

This avoids circular helper dependencies and makes fail-closed behavior easier to review.

## Sensitive Data Handling

The helper modules never log:

- raw secrets
- private keys
- raw nonces
- approval contents
- raw device identifiers

Diagnostics contain only paths, tenant IDs, public hashes, release IDs, and lineage booleans.

## Audit Traceability Improvements

The modular layout makes it clear which helper is responsible for each governance concern. Reviewers can inspect manifest generation, authority bootstrap, CI lineage, and diagnostics independently, while existing tests continue importing from `tests.provenance_helpers`.
