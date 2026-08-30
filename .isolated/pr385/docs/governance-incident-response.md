# USBAY Governance Incident Response

USBAY governance failures are operational incidents. Diagnostics are read-only,
audit-safe, and fail closed. Operators must never override governance controls
from the runtime layer.

## Operator Escalation Flow

1. Run `python3 scripts/governance_diagnostics.py incident-summary`.
2. Identify the machine-readable incident code.
3. Run `recommended-action`, `explain-fail-closed`, and `recovery-checklist`
   for the incident code.
4. Preserve diagnostic output as audit evidence.
5. Obtain explicit human approval before any recovery action.

## Incident Codes

- `GOV_SIGNER_DRIFT`: signer continuity or public key validation failed.
- `GOV_DEPENDENCY_DRIFT`: governance dependency graph changed or became
  ambiguous.
- `GOV_RELEASE_MISMATCH`: signed release integrity metadata no longer matches
  runtime governance state.
- `GOV_ROLLBACK_INVALID`: rollback lineage or target authorization failed.
- `GOV_TRUST_POLICY_MISMATCH`: trust-policy fingerprint does not match active
  signer or release metadata.
- `GOV_TELEMETRY_UNSAFE`: diagnostics or generated artifacts may expose
  sensitive material.

## Rollback Decision Flow

Rollback is denied unless the exact previous release hash is explicitly
approved. Operators must verify previous release metadata, audit lineage, and
human approval before retrying release integrity validation with an allowed
rollback target.

## Human Approval Requirements

Every incident code in `governance/incident_runbooks.json` requires human
approval before recovery. Approval must identify the incident code, failed
control, evidence reviewed, and recovery action.

## Telemetry Hygiene

Diagnostics must never include private keys, raw secrets, approval contents,
raw evidence payloads, or raw nonces. Unsafe telemetry is itself a fail-closed
incident under `GOV_TELEMETRY_UNSAFE`.

