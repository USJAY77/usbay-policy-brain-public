# WORM Evidence Requirements

Purpose: define evidence required before USBAY can treat external immutable storage as regulator-grade WORM evidence preservation.

Runtime impact: none.

Certification impact: none. Requirements do not close BLOCKER-003.

Evidence rule: evidence before claims. Human approval is not evidence.

## Required Evidence Artifacts

| Evidence artifact | Required fields | Fail-closed condition |
|---|---|---|
| Provider receipt | provider name, provider receipt ID, receipt timestamp, storage location identifier | Missing receipt blocks certification. |
| Object ID | provider object ID, object version or generation identifier when available | Missing object ID blocks certification. |
| Retention class | provider retention class, USBAY retention class, retention policy hash | Missing or mismatched retention class blocks certification. |
| Legal hold state | legal hold enabled or disabled state, legal hold timestamp, legal hold authority record if changed | Missing or mismatched legal hold state blocks certification. |
| Immutable write proof | object lock or immutability proof, write-once status, overwrite denial result | Missing immutable write proof blocks certification. |
| Audit receipt | provider audit event reference, write actor identity, timestamp, object ID, action result | Missing audit receipt blocks certification. |
| Export verification record | regulator export profile ID, USBAY sealed archive ID, USBAY WORM storage plan ID, provider receipt hash, verification result | Missing export verification blocks certification. |
| SHA256 evidence hash | local SHA256 evidence hash, provider-reported or independently read-back SHA256 hash, comparison result | Missing or mismatched hash blocks certification. |

## Evidence Binding Requirements

Every provider evidence record must bind to:

- USBAY sealed archive ID.
- USBAY archive root hash.
- USBAY evidence record ID.
- USBAY WORM storage plan ID.
- Provider receipt ID.
- Provider object ID.
- SHA256 evidence hash.
- Retention class.
- Legal hold state.
- Provider audit reference.

## Redaction Requirements

Evidence and diagnostics must not include:

- Raw governance payloads.
- Raw approval contents.
- Private keys.
- Secrets.
- Raw nonces.
- Raw regulator exports.
- Provider credentials.

If unsafe material is present:

Decision: BLOCKED.

## Verification Requirements

Verification must fail closed when:

- Provider receipt is absent.
- Provider object ID is absent.
- Provider retention evidence is absent.
- Provider legal hold evidence is absent.
- Provider audit reference is absent.
- Provider evidence hash mismatches USBAY evidence hash.
- Provider outage prevents verification.
- Provider evidence cannot be bound to USBAY evidence identifiers.
- Export verification cannot prove provider evidence continuity.

## Certification Boundary

External WORM evidence can support certification only after the required evidence artifacts are present, verified, versioned, and mapped to BLOCKER-003 closure requirements.

Until then:

Decision: BLOCKED.
