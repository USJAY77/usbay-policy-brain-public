# USBAY Policy Brain

Policy-as-code repository responsible for:

- Policy definitions
- Rule evaluation logic
- Approval workflow state
- Audit decision logging

This repository represents the USBAY governance decision layer.
Execution enforcement occurs in the enforcement gateway.

## Live Runtime Proof

Run the live FastAPI governance proof from the repository root:

```bash
bash scripts/live_runtime_proof.sh
```

The proof starts Redis when needed, clears port `8001`, starts the FastAPI
gateway at `http://127.0.0.1:8001`, then uses the live endpoints `/decide` and
`/execute`. It writes redacted evidence to `AUDIT_PROOF.txt` with timestamps,
tested endpoint, exact outcomes, and a pass/fail summary. The proof never prints
or stores raw secrets.
governance test line
## Enforcement test 2
Non-functional change to validate branch protection...
# codex test
# codex test
trigger codex final
trigger codex new run
force new run v3
run after xname removal
