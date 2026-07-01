# USBAY-SURICATA-004 Live Rule Source Gap Report

## Current State

USBAY currently has three local-only Suricata governance controls:

- `USBAY-SURICATA-001`: parses caller-provided Suricata EVE JSON, redacts sensitive alert fields, and emits hash-only evidence.
- `USBAY-SURICATA-002`: applies a human-defined severity threshold gate to redacted Suricata evidence.
- `USBAY-SURICATA-003`: validates a local Suricata policy registry record before Suricata evidence may participate in runtime decisions.

The current implementation does not ingest live Suricata rule sources. Rule-set records are caller-provided local data, and the registry validates hashes, signatures, approval metadata, active/revoked state, duplicate versions, and staleness.

## Control Gap

The remaining governance gap is live rule source ingestion. USBAY cannot yet prove that a Suricata rule set came from an approved source before it entered the local registry. The system can validate a local registry record, but it does not yet govern:

- where rule sets may originate
- how downloaded or imported rule bundles are authenticated
- how source identity is pinned
- how rule source freshness is verified
- how source compromise or revocation is reflected before evidence is consumed
- how rollback to a prior approved rule version is performed

Fail-closed implication: until this gap is closed, live rule ingestion must remain disabled and Suricata rule-set records must be treated as manually supplied governance artifacts.

## Risks

- Unapproved rule source could inject noisy, weak, or malicious rules.
- Source identity spoofing could create false evidence confidence.
- Rule-set downgrade could re-enable known-bad network behavior.
- Rule-set drift could break reproducibility between alert evidence and policy registry evidence.
- Missing revocation path could keep compromised rules active.
- Missing rollback isolation could mix evidence from old and new rule versions.
- Raw rule-source transport logs could leak URLs, credentials, internal hostnames, or operational metadata.

## Required Controls

### Rule Source Allowlist

Implementation must define an explicit local allowlist for rule sources. Each source record should include:

- `source_id`
- `source_name`
- `source_type`
- `source_reference_hash`
- `allowed_rule_families`
- `required_signature_type`
- `owner`
- `approved_by`
- `approval_timestamp`
- `active`
- `revoked`

Unknown sources must fail closed.

### Signature Verification

Every imported rule bundle must be verified before registry insertion:

- signature hash present
- signature format supported
- signer identity bound to allowlist source
- bundle hash matches signed payload
- verification evidence hash produced

Unsigned or unverifiable bundles must fail closed.

### Policy Approval

Human governance approval remains mandatory before a rule source or imported rule set becomes eligible:

- source approval
- rule-set approval
- policy threshold approval
- registry activation approval

Owner self-approval should be blocked.

### Registry Binding

Live ingestion must bind imported rule evidence to `SuricataPolicyRegistry`:

- imported bundle hash
- source validation hash
- signature verification hash
- rule count
- policy version
- registry evidence hash

RuntimeAggregator should continue to require approved registry evidence before Suricata evidence participates in decisions.

### Rollback And Revocation

Implementation must define:

- revocation reason codes
- revoked source handling
- revoked rule-set handling
- rollback target version
- rollback owner
- rollback audit hash
- deterministic evidence continuity from old version to replacement version

Revoked or rollback-incomplete source data must fail closed.

### Sensitive Data Handling

Live source ingestion must not store raw sensitive data:

- no raw URLs with credentials
- no raw API keys or tokens
- no raw internal hostnames
- no raw transport headers
- no raw payloads
- no private rule-source comments containing customer data

Evidence must remain hash-only and redacted.

## Files That Would Be Modified In Implementation Batch

Expected new files:

- `publication/suricata_rule_source_registry.py`
- `publication/suricata_rule_source_manifest.py`
- `publication/suricata_rule_source_verifier.py`
- `tests/test_suricata_rule_source_registry.py`
- `tests/test_suricata_rule_source_verifier.py`
- `docs/publication/USBAY_SURICATA_005_RULE_SOURCE_REGISTRY.md`

Expected updates:

- `publication/suricata_policy_registry.py`
- `publication/runtime_aggregator.py`
- `publication/__init__.py`
- `tests/test_suricata_policy_registry.py`
- `tests/test_suricata_policy_gate.py`

No Gateway, Replit, Simulator, Game, connector, endpoint, or network code should be modified.

## Validation Plan

Focused validation should include:

- allowed source passes
- unknown source fails closed
- revoked source fails closed
- unsigned rule bundle fails closed
- signature mismatch fails closed
- stale source approval fails closed
- duplicate source version fails closed
- rollback target missing fails closed
- registry binding mismatch fails closed
- RuntimeAggregator blocks when source verification is missing
- RuntimeAggregator allows only with source verification, policy registry approval, threshold gate approval, and accepted evidence
- raw source URL, credentials, headers, and payloads absent from audit output

Required commands:

```bash
python3.11 -m py_compile publication/*.py tests/test_suricata*.py
pytest -q tests/test_suricata*.py
git diff --check
```

## Rollback Plan

Implementation rollback must remove only SURICATA live-source files and restore Suricata runtime integration to the last approved local-only chain:

```bash
rm -f publication/suricata_rule_source_registry.py publication/suricata_rule_source_manifest.py publication/suricata_rule_source_verifier.py
rm -f tests/test_suricata_rule_source_registry.py tests/test_suricata_rule_source_verifier.py
rm -f docs/publication/USBAY_SURICATA_005_RULE_SOURCE_REGISTRY.md
```

Any edits to shared untracked publication files must be reviewed before rollback to avoid removing SURICATA-001 through SURICATA-003 controls.

## Remaining Gaps

- No live rule source allowlist exists.
- No source signature verification exists.
- No source-to-registry binding exists.
- No source revocation model exists.
- No source rollback model exists.
- No automated source freshness evidence exists.
- No source-sensitive-data redaction model exists.

## Next Recommended Batch

`USBAY-SURICATA-005 — Rule Source Registry And Signature Verification`

Recommended scope:

- local-only source allowlist
- deterministic source manifest
- signature verification contract
- source-to-policy-registry binding
- revoked source fail-closed tests
- no network calls or live Suricata dependency
