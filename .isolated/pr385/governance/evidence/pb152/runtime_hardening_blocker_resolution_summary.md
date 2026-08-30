# PB-152 Governance Runtime Hardening Blocker Resolution

## Decision
VERIFIED

## Status
READY_FOR_REVIEW

## Failure Cause
The Edgeguard reset script used hardcoded `python3`, allowing subprocess dependency context to diverge from the active pytest or virtualenv interpreter. That explains a `cryptography` import failure inside the reset subprocess even when the active validation environment had the dependency installed.

## Resolution
`demos/edgeguard/reset_demo.sh` now selects the interpreter in this order:

1. `USBAY_PYTHON`
2. `$VIRTUAL_ENV/bin/python`
3. `command -v python3`

The script fails closed if the selected interpreter is unavailable. Reset audit entries now include `python_executable` so the runtime context is replay-traceable.

## Validation
Focused Edgeguard validation passed:

```text
.venv/bin/python -m pytest -q tests/test_edgeguard_demo.py
14 passed in 1.14s
```

## Remaining Gaps
Full repository pytest was not run in this PB-152 step. Merge readiness still requires full-suite validation and human review by USBAY-AUDIT and USBAY-GLOBAL23.

## No Production Activation
No external API calls, credentials, deployment, merge, branch deletion, or production runtime activation were performed.
