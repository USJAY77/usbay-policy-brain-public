# USBAY-SURICATA-020 Isolated Commit Scope Plan

## Status

PASS. The SURICATA-001 through SURICATA-019 scope can be isolated safely.

No staging, commit, push, branch creation, network call, publication action, or live connector enablement was performed.

## Validation Output

```text
python3.11 -m py_compile publication/*.py tests/test_suricata*.py
PASS

pytest -q tests/test_suricata*.py
184 passed in 1.02s

pytest -q tests/test_publication_*.py tests/test_suricata*.py
383 passed in 2.11s

pytest -q tests/resilience/test_human_review_floods.py tests/test_edgeguard_demo.py
18 passed in 3.41s

git diff --check
PASS
```

## Safe Stage Command

Stage only these files:

```bash
git add -- \
  publication/__init__.py \
  publication/final_report.py \
  publication/models.py \
  publication/runtime_aggregator.py \
  publication/suricata_evidence_adapter.py \
  publication/suricata_external_signing_authority.py \
  publication/suricata_fetch_receipt.py \
  publication/suricata_fetch_receipt_finalizer.py \
  publication/suricata_live_fetcher_gate.py \
  publication/suricata_live_network_fetcher.py \
  publication/suricata_policy_gate.py \
  publication/suricata_policy_manifest.py \
  publication/suricata_policy_registry.py \
  publication/suricata_publication_connector.py \
  publication/suricata_rule_signature.py \
  publication/suricata_rule_source_fetcher.py \
  publication/suricata_rule_source_registry.py \
  publication/suricata_source_replacement_flow.py \
  publication/suricata_trust_anchor_store.py \
  tests/test_suricata_evidence_adapter.py \
  tests/test_suricata_external_signing_authority.py \
  tests/test_suricata_fetch_receipt.py \
  tests/test_suricata_fetch_receipt_finalizer.py \
  tests/test_suricata_live_fetcher_gate.py \
  tests/test_suricata_live_network_fetcher.py \
  tests/test_suricata_policy_gate.py \
  tests/test_suricata_policy_registry.py \
  tests/test_suricata_publication_connector.py \
  tests/test_suricata_rule_source_fetcher.py \
  tests/test_suricata_rule_source_registry.py \
  tests/test_suricata_source_replacement_flow.py \
  tests/test_suricata_trust_anchor_store.py \
  docs/publication/USBAY_SURICATA_001_NETWORK_IDS_EVIDENCE_ADAPTER.md \
  docs/publication/USBAY_SURICATA_002_POLICY_THRESHOLD_GATE.md \
  docs/publication/USBAY_SURICATA_003_POLICY_REGISTRY.md \
  docs/publication/USBAY_SURICATA_004_LIVE_RULE_SOURCE_GAP_REPORT.md \
  docs/publication/USBAY_SURICATA_005_RULE_SOURCE_REGISTRY_SIGNATURE.md \
  docs/publication/USBAY_SURICATA_006_RULE_SOURCE_FETCHER_GAP_REPORT.md \
  docs/publication/USBAY_SURICATA_007_GOVERNED_LOCAL_RULE_SOURCE_FETCHER.md \
  docs/publication/USBAY_SURICATA_008_PRODUCTION_TRUST_ANCHOR_STORE.md \
  docs/publication/USBAY_SURICATA_009_TRUST_ANCHOR_FINALIZER.md \
  docs/publication/USBAY_SURICATA_010_LIVE_FETCHER_GOVERNANCE_PLAN.md \
  docs/publication/USBAY_SURICATA_011_FETCH_RECEIPT_MODEL.md \
  docs/publication/USBAY_SURICATA_012_FETCH_RECEIPT_FINALIZER.md \
  docs/publication/USBAY_SURICATA_013_SOURCE_REPLACEMENT_FLOW.md \
  docs/publication/USBAY_SURICATA_014_EXTERNAL_SIGNING_AUTHORITY.md \
  docs/publication/USBAY_SURICATA_014_LIVE_NETWORK_FETCHER_GATE.md \
  docs/publication/USBAY_SURICATA_015_LIVE_NETWORK_FETCHER.md \
  docs/publication/USBAY_SURICATA_016_PUBLICATION_CONNECTOR.md \
  docs/publication/USBAY_SURICATA_017_PRODUCTION_CONNECTOR_FINALIZER.md \
  docs/publication/USBAY_SURICATA_019_FINAL_COMMIT_READINESS_REPORT.md \
  docs/publication/USBAY_SURICATA_020_ISOLATED_COMMIT_SCOPE_PLAN.md
```

## Explicit Exclusions

Do not stage:

- `.github/workflows/full-regression.yml`
- `docs/audits/`
- `docs/game/`
- `docs/governance/PB015_GOVERNANCE_MATURITY_ASSESSMENT.md`
- `governance/`
- `policy/publication/`
- `pricing_poster/`
- `scripts/`
- `tests/resilience/test_human_review_floods.py`
- `tests/test_ci_tiered_validation.py`
- `tests/test_commit_scope_validator.py`
- `tests/test_decide_first.py`
- `tests/test_edgeguard_demo.py`
- `tests/test_full_regression_phases.py`
- `tests/test_governed_dependabot_pr_automation.py`
- `tests/test_ownership_migration.py`
- `tests/test_pb015_governance_maturity_assessment.py`
- `tests/test_pbsec_security_gates.py`
- `tests/test_policy_bundle_readiness.py`
- `tests/test_policy_bundle_validator.py`
- `tests/test_production_readiness.py`
- `tests/test_publication_*.py`
- `tests/test_runtime_governance_state.py`
- `tests/test_simulation_governance.py`
- Any `GAME_*`, PB015, PBSEC, pricing poster, ownership migration, workflow/full-regression, gateway, Replit, simulator, or unrelated publication-runtime files.

## Commit Title

USBAY-SURICATA-001-020 Governed Suricata Evidence Chain

## Commit Body

```text
actor: codex
action: add governed local Suricata evidence chain, policy gating, policy registry, rule source governance, trust anchor validation, fetch receipt proofing, source replacement controls, live-fetch gating, production connector controls, and isolated commit readiness evidence
reason: provide fail-closed, hash-only network IDS evidence governance before Suricata evidence can participate in publication or runtime readiness decisions
risk: incorrect validation could block valid Suricata evidence or allow incomplete network IDS evidence to influence readiness decisions
policy_ref: USBAY-SURICATA-001 through USBAY-SURICATA-020
signed: false
```

## Rollback Command

After commit:

```bash
git revert <commit_sha>
```

Before commit, if the safe-stage command was run accidentally:

```bash
git restore --staged -- publication/__init__.py publication/final_report.py publication/models.py publication/runtime_aggregator.py publication/suricata_*.py tests/test_suricata*.py docs/publication/USBAY_SURICATA_*.md
```

## Remaining Gaps

- No real production endpoint is configured.
- No live connector is enabled by default.
- No real network calls are used in tests.
- CA/KMS/HSM provider evidence is locally modeled unless explicitly configured.
- Full repo suite was not rerun end-to-end in this batch.
- The surrounding worktree remains dirty with unrelated files; only the safe-stage command above should be used.

## Confirmation

No stage, commit, push, branch creation, network call, publication action, or live connector enablement was performed.
