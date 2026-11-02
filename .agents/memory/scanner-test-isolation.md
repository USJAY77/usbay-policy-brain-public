---
name: Scanner test isolation
description: Separate the isolated application source from hostile pytest fixtures during startup regressions.
---

Place pytest basetemp and general temporary fixtures outside the application
source root being scanned, even when the entire validation already runs in a
disposable source copy.

**Why:** Runtime startup scans treat test-created private-key fixtures and pytest
symlinks inside that source root as real deployment findings. An isolated copy
alone does not prevent this self-contamination. Do not suppress the findings or
weaken production rules to make that test arrangement pass.

**How to apply:** Use sibling temporary directories within the same bounded
validation area, retain the original failure evidence, and distinguish restricted
subprocess tests and repository-wide export scans from runtime scanner regressions.
