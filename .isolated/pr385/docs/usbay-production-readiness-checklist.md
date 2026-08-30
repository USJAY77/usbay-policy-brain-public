# USBAY Production Readiness Checklist

This checklist is the production hardening gate for USBAY governance runtime releases after PR #24.

## Required Gates

- [ ] Fail-closed runtime enforcement is active and tested.
- [ ] Production runtime requires an explicit signed governance release manifest path.
- [ ] `RuntimeProvenanceAuthority` continuity is enforced for runtime, export, and verification paths.
- [ ] No generated governance artifacts are tracked in Git.
- [ ] No `governance_release*.json` repo-root blobs are tracked in Git.
- [ ] No tracked file exceeds GitHub's 50 MB warning threshold.
- [ ] `tests/provenance_helpers.py` remains a small compatibility shim below 1 MB.
- [ ] No raw secrets, private keys, raw nonces, approval contents, or device identifiers appear in generated artifacts.
- [ ] Tenant isolation tests pass and cross-tenant evidence reuse fails closed.
- [ ] Runtime drift detection reports healthy continuity.
- [ ] Attestation freshness enforcement is active.
- [ ] Startup integrity validation passes.
- [ ] Tenant audit package build and offline verification pass.
- [ ] GitHub workflow YAML parses.

## Validation Commands

```bash
python3 scripts/verify_production_readiness.py
pytest -q tests/test_production_readiness.py
pytest -q
python3 -c "import gateway.app as app; app.validate_policy_registry_startup(); print('STARTUP_INTEGRITY_VALID=true')"
python3 scripts/verify_live_pilot_v1.py
```

Tenant audit package validation should write outside the repository, for example:

```bash
rm -rf /private/tmp/usbay_prod_ready_package /private/tmp/usbay_prod_ready_source
python3 -m audit.exporter build-tenant-package --tenant-id t1 --evidence-bundle-dir /private/tmp/usbay_prod_ready_source --package-path /private/tmp/usbay_prod_ready_package
python3 -m audit.exporter verify-tenant-package /private/tmp/usbay_prod_ready_package
```

Workflow YAML parse:

```bash
ruby -e 'require "yaml"; Dir[".github/workflows/*.{yml,yaml}"].sort.each { |f| YAML.load_file(f) }; puts "WORKFLOW_YAML_PARSE=true"'
```

## Production Fail-Closed Rule

Production mode must not auto-generate or infer release provenance. If `USBAY_ENV=production` and no explicit `USBAY_GOVERNANCE_RELEASE_PATH` is configured, release manifest resolution must fail closed.

## Artifact Rule

Generated files such as `governance_release*.json`, `generated_manifest_path.json`, and `manifest_generation_audit.json` are runtime/test artifacts only. They must not be committed.
