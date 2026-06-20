# INVENTORY_CONSISTENCY_AUDIT — Inventory vs. Repository Reality

PB-INVENTORY-002 — close the inventory inconsistency around the runtime policy
validator reference and prove the audit inventory matches repository reality with zero
orphan references.

- actor: replit-agent
- action: remediate stale inventory reference; prove inventory == repository
- scope: docs/audits/ only (documentation and test inventory); no runtime, gateway, or
  enforcement code changed
- method: existence check + repo-wide reference search + git-history check, then correct
  the invalid references and re-validate

## 1. The inconsistency

The PB-INVENTORY-001 task spec listed `tests/test_runtime_policy_validator_extraction.py`
in its validation command set. The audit docs faithfully recorded that the file produced
a "file or directory not found" error, but left it framed as a *missing-but-expected*
inventory artifact — an orphan reference.

## 2. Audit evidence (collected before remediation)

| Check | Command | Result |
|-------|---------|--------|
| File exists on disk? | `ls tests/test_runtime_policy_validator_extraction.py` | NO — "No such file or directory" |
| Any analog file? | `ls tests/ \| rg -i 'policy_validator\|extraction'` | NO analog |
| Ever existed in git? | `git log --oneline --all -- tests/test_runtime_policy_validator_extraction.py` | EMPTY — never tracked in any branch |
| References to the name (excluding the task-spec input) | `rg -n 'test_runtime_policy_validator_extraction' --glob '!attached_assets/**'` | Only `docs/audits/CANONICAL_GATE_AUDIT.md` and `docs/audits/BYPASS_MATRIX_V2.md` (the audit's own docs) |
| Does the subject module exist? | `ls runtime/policy_validator.py` | YES — `runtime/policy_validator.py` (27,511 bytes) |
| Real coverage of that module? | `rg -ln 'policy_validator' tests/` | `tests/test_governance_validation.py`, `tests/test_policy_verification_workflow.py`, `tests/conftest.py` |

## 3. Classification

**STALE / NON-CANONICAL (spec-originated).** The filename was introduced solely by the
PB-INVENTORY-001 task spec's validation list. It:

- never existed on disk,
- never existed in git history (no branch, no past commit),
- has no analog file,
- is **not** required to cover `runtime/policy_validator.py`, which is already exercised
  by `tests/test_governance_validation.py` (16 tests) and
  `tests/test_policy_verification_workflow.py` (6 tests).

It is therefore not historical (it was never real) and not canonical (no such artifact
should exist). The correct inventory entry for runtime-policy-validator coverage points
to the two existing suites above.

## 4. Remediation applied (documentation only)

- `docs/audits/CANONICAL_GATE_AUDIT.md` §4: removed the non-existent file from the
  validation evidence block and replaced it with the actual runtime-policy-validator
  coverage suites; updated the total from 65 to 87 passing tests.
- `docs/audits/CANONICAL_GATE_AUDIT.md` §6: replaced the "Known gap" entry with a
  resolved consistency note pointing here.
- `docs/audits/BYPASS_MATRIX_V2.md`: corrected the closing validation paragraph to cite
  the real coverage suites and the 87-test total.
- `docs/audits/EXECUTION_SURFACE_MAP.md` and `docs/audits/EXECUTION_CALL_GRAPH.md`: no
  change required — neither referenced the orphan file.

The orphan filename now appears in the audit set **only** inside this document, where it
is the explicitly-named subject of remediation (not an inventory pointer to a missing
artifact). No code, no tests, and no enforcement logic were modified.

## 5. Validation evidence (after remediation)

```
$ python3.11 -m py_compile gateway/*.py runtime/*.py security/*.py governance/*.py
py_compile OK   (no runtime files changed; compile remains clean)

$ pytest -q tests/test_gateway_app.py                 → 37 passed
$ pytest -q tests/test_execution_guard.py             → 16 passed
$ pytest -q tests/test_compute_governance.py          → 12 passed
$ pytest -q tests/test_governance_validation.py       → 16 passed
$ pytest -q tests/test_policy_verification_workflow.py →  6 passed
Total: 87 passed, 0 failed

# Orphan-reference proof: outside this file and the task-spec input under
# attached_assets/, no audit doc references the non-existent file.
$ rg -n 'test_runtime_policy_validator_extraction' docs/audits \
    --glob '!docs/audits/INVENTORY_CONSISTENCY_AUDIT.md'
(no matches)

# Every test artifact referenced by the audit docs exists on disk:
$ for f in test_gateway_app test_execution_guard test_compute_governance \
           test_governance_validation test_policy_verification_workflow; do
    test -f tests/$f.py && echo "OK tests/$f.py"; done
OK tests/test_gateway_app.py
OK tests/test_execution_guard.py
OK tests/test_compute_governance.py
OK tests/test_governance_validation.py
OK tests/test_policy_verification_workflow.py

$ git diff --check          → clean
$ git diff --cached --check → clean
```

## 6. Conclusion

Repository inventory equals repository reality. Every test artifact named in the audit
docs exists on disk; the single orphan reference has been reclassified and corrected.
**Zero orphan references remain** in the canonical inventory documents. Fail-closed
behavior is unchanged (no runtime/gateway/enforcement code was touched).
