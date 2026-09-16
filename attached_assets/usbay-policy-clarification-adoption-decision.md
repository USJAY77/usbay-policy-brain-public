# USBAY policy clarification adoption decision

## Decision provenance

- Decision date: `2026-09-16`
- Exact decision time: UNKNOWN
- Decision source: owner instruction
- Reviewed proposal: `attached_assets/usbay-preservation-policy-clarification-proposal.md`
- Reviewed proposal SHA-256: `41a2354506c61a5595420175b04839802d0ad5aaa8afdfb3be100ae6afcf8295`
- Validated script: `attached_assets/usbay-age-preservation.zsh`
- Validated script SHA-256: `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07`

The reviewed proposal hash was verified before this decision record was created.

## Owner decision

The owner adopts the exact Gate A, Gate B, Gate C, and cross-gate amendment contained in the reviewed proposal identified above.

The adopted amendment establishes:

- Gate A before durable private-key creation;
- Gate B after separately authorized creation and before recovery setup may be declared validated;
- Gate C before any source removal;
- the cross-gate rule that no gate proves or authorizes a later gate and UNKNOWN remains UNKNOWN.

## Exact authorization boundary

This decision adopts the policy clarification only.

It does not:

- approve intended custody;
- approve the local primary-identity or evidence paths;
- approve the USB or paper-passphrase custody arrangement;
- authorize installation;
- authorize key or recipient creation;
- authorize USB writes;
- authorize settings changes;
- authorize archive operations;
- authorize source removal;
- authorize application restart;
- authorize any production action.

Approval of this adoption record, the proposal’s environment-variable gate, or any prior preparation is not operational execution authorization.

## Preservation of reviewed artifacts

The reviewed proposal remains unchanged at SHA-256 `41a2354506c61a5595420175b04839802d0ad5aaa8afdfb3be100ae6afcf8295`. Its internal `PROPOSED, NOT ADOPTED` language records its pre-decision state; this separate decision record is the authority for subsequent adoption status.

The validated script remains unchanged at SHA-256 `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07`.

## Governance disposition

- Policy clarification: ADOPTED by explicit owner decision.
- Custody approval: NOT GRANTED.
- Gate A evidence state: PARTIAL; custody review and separate operational authorization remain outstanding.
- Gate B: NOT_APPLICABLE before separately authorized creation.
- Gate C: NOT_APPLICABLE before Gate B and a separately authorized archive workflow.
- Operational authorization: NOT GRANTED.
- Production authorization: NOT GRANTED.