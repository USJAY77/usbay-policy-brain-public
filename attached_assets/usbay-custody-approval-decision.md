# USBAY custody approval decision

## Decision provenance

- Decision date: `2026-09-16`
- Exact decision time: UNKNOWN
- Decision source: direct owner instruction
- Reviewed custody document: `attached_assets/usbay-consolidated-custody-review.md`
- Reviewed custody document SHA-256: `3222ba2ecee07056b068c969973808cbc3dd5a20b827576a1c94c96d3ca3cbf2`
- Consolidated custody decision: `attached_assets/usbay-consolidated-custody-decision.md`
- Consolidated custody decision SHA-256: `25161dad4390843110744a6611ed412598952ae60b1eca74067d573f34b2deff`
- Earlier owner response: `attached_assets/usbay-custody-owner-response.md`
- Earlier owner response SHA-256: `4b833e745f075e622957aaeb13ba9b8ee0069e0647dced7a0f5fbfebf5a5c496`
- Validated script: `attached_assets/usbay-age-preservation.zsh`
- Validated script SHA-256: `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07`

The referenced files matched these hashes before this decision record was created.

## Owner decision

The owner approves the complete custody arrangement in the reviewed custody document identified by SHA-256 `3222ba2ecee07056b068c969973808cbc3dd5a20b827576a1c94c96d3ca3cbf2`, with:

- the subsequently supplied FileVault evidence;
- the corrected screen-locking wording below;
- the corrected directory-permission wording below.

This approval includes:

- the exact local paths;
- the selected SanDisk USB;
- separate locked paper storage physically separate from the USB;
- the recorded copying configuration;
- the interval before validated USB recovery;
- all retained partial-state consequences.

## FileVault evidence and bounded conclusion

Owner-supplied native Mac evidence:

- timestamp: `2026-09-16T04:49:34Z`;
- command: `/usr/bin/fdesetup status`;
- output: `FileVault is On.`;
- exit status: `0`.

Active FileVault status is PROVEN only at that timestamp. This does not prove backup coverage, backup completion, retention, recovery, protection from processes running under the logged-in account, or continued FileVault state after the timestamp.

## Corrected screen-locking wording

FileVault protects the Mac’s data at rest when the Mac is powered off. Screen locking is different: while the Mac remains running and the encrypted volume remains mounted, locking the screen does not make the identity inaccessible to processes already running under the logged-in owner account.

## Corrected directory-permission wording

If `~/.config` is absent, the reviewed script creates it as mode `0700` only after confirmation. An existing `~/.config` is not automatically changed to mode `0700`. The script creates `~/.config/age` as mode `0700` if absent; if it already exists with another mode, the script stops rather than changing it. The primary identity is published as mode `0600`. It is therefore incorrect to claim that all parent directories are guaranteed to be mode `0700`.

These wording corrections clarify the approved custody conditions. They do not change the reviewed design or validated script.

## Supersession boundary

This decision supersedes only the earlier **NO** answer to approval of all custody conditions in `attached_assets/usbay-custody-owner-response.md`.

It does not supersede or alter:

- the earlier confirmation that locked, owner-controlled paper storage physically separate from the selected SanDisk USB is available;
- any retained evidence;
- the adopted gate ordering;
- the operational authorization boundary;
- Gate B or Gate C requirements;
- the reviewed custody document;
- the validated script.

No passphrase or precise paper-storage location is recorded.

## Authorization boundary

This custody approval does not authorize:

- installation;
- key or recipient creation;
- USB writes;
- settings changes;
- archive operations;
- source removal;
- application restart;
- deployment or production action.

Operational authorization remains separate and is NOT GRANTED.

## Governance disposition

- Policy clarification: ADOPTED.
- Active FileVault status at `2026-09-16T04:49:34Z`: PROVEN.
- Separate locked paper-storage availability: PROVEN.
- Complete custody arrangement: APPROVED by explicit owner decision, subject to the FileVault limitation and corrected wording recorded above.
- Custody approval: GRANTED for the exact reviewed arrangement and qualifications identified in this record.
- Gate A evidence state: PARTIAL because separate operational authorization remains NOT GRANTED.
- Operational authorization: NOT GRANTED.
- Gate B: NOT_APPLICABLE before separately authorized creation.
- Gate C: NOT_APPLICABLE before Gate B and separately authorized archive and Linux restoration work.
- Production authorization: NOT GRANTED.

## Governance verdict

The custody condition of Gate A is satisfied by explicit owner approval for the exact reviewed arrangement and qualifications recorded here. Gate A as a whole remains PARTIAL because operational execution has not been authorized. No operational action is authorized by this custody decision.