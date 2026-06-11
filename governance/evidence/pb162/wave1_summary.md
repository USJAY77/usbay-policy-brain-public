# PB-162 Runtime Hardening Wave 1 Extraction

Decision: VERIFIED
Status: READY_FOR_REVIEW

## Scope
PB-162 extracts only the PB-161 Wave 1 approved Edgeguard runtime self-repair assets from `runtime/governance-runtime-hardening` into `governance/extract-runtime-hardening-wave1`.

Extracted files:
- `demos/edgeguard/reset_demo.sh`
- `tests/test_edgeguard_demo.py`

Excluded files:
- `local-freeze.txt` because it is already in main
- `pyproject.toml` because it is already in main
- `pytest.ini` because it is already in main

## Validation
Focused test command:

```bash
.venv/bin/python -m pytest -q tests/test_edgeguard_demo.py
```

Result: PASS, 14 passed in 1.42s.

## Governance Controls
- No deploy performed.
- No merge performed.
- No delete performed.
- No branch cleanup performed.
- No production activation performed.
- No credentials created.
- No external API calls performed.
- USBAY-AUDIT and USBAY-GLOBAL23 review remain required.

## Remaining Scope Note
The local worktree contains unrelated prior PB files and a `.gitignore` modification. These are excluded from PB-162 and must not be staged into the Wave 1 extraction package.

## Final Validation Results
- JSON validation: PASS
- Metadata validation: PASS
- Placeholder scan: PASS
- Conflict marker scan: PASS
- `git diff --check`: PASS
- Source branch file comparison: PASS
- Focused Edgeguard tests: PASS, 14 passed in 1.42s

## Scope Exclusion
`.gitignore`, PB-161 evidence, and prior computer-use architecture documents are present in the local worktree but are not part of PB-162 and must not be staged into the extraction package.
