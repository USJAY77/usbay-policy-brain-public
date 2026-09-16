# USBAY custody owner response

## Decision provenance

- Decision date: `2026-09-16`
- Exact decision time: UNKNOWN
- Decision source: direct owner response
- Consolidated custody decision: `attached_assets/usbay-consolidated-custody-decision.md`
- Consolidated custody decision SHA-256: `25161dad4390843110744a6611ed412598952ae60b1eca74067d573f34b2deff`
- Reviewed custody document: `attached_assets/usbay-consolidated-custody-review.md`
- Reviewed custody document SHA-256: `3222ba2ecee07056b068c969973808cbc3dd5a20b827576a1c94c96d3ca3cbf2`
- Validated script: `attached_assets/usbay-age-preservation.zsh`
- Validated script SHA-256: `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07`

The referenced documents matched these hashes before this response record was created.

## Owner answers

### Separate locked paper-storage arrangement

Answer: **YES**

Owner statement:

> I confirm that locked, owner-controlled paper storage physically separate from the selected SanDisk USB is available.
>
> This confirms the storage arrangement only.
> It does not authorize key creation, installation, USB writes, archive operations, source removal, or restart.

Bounded conclusion: availability of a locked, owner-controlled paper-storage arrangement physically separate from the selected SanDisk USB is PROVEN by direct owner confirmation.

This does not establish that a passphrase has been created or stored. No passphrase or precise storage location was requested or recorded.

### Approval of all custody conditions

Answer: **NO**

No additional owner comment was provided.

Bounded conclusion: custody approval is NOT GRANTED.

## Effect on Gate A

- Policy clarification: ADOPTED.
- Active FileVault status at `2026-09-16T04:49:34Z`: PROVEN from retained owner-supplied native Mac evidence.
- Separate locked paper-storage arrangement availability: PROVEN by direct owner confirmation.
- Custody approval: NOT GRANTED.
- Gate A evidence state: PARTIAL.
- Operational authorization: NOT GRANTED.
- Gate B: NOT_APPLICABLE before separately authorized creation.
- Gate C: NOT_APPLICABLE before Gate B and separately authorized archive and Linux restoration work.
- Production authorization: NOT GRANTED.

The paper-storage confirmation closes only the availability question. It does not approve the complete custody conditions and does not authorize any operation.

## Governance verdict

Custody approval remains NOT GRANTED. Gate A remains PARTIAL. No installation, key creation, USB write, settings change, archive operation, source removal, restart, or production action is authorized.