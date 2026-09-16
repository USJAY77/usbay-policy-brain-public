# USBAY consolidated custody decision

## Status and authority

This record presents the custody conditions for owner decision under adopted Gate A. Custody approval has not yet been granted.

This record does not authorize installation, key creation, USB writes, settings changes, archive operations, source removal, application restart, or production action.

## Authoritative references

- Reviewed custody document: `attached_assets/usbay-consolidated-custody-review.md`
- Reviewed custody document SHA-256: `3222ba2ecee07056b068c969973808cbc3dd5a20b827576a1c94c96d3ca3cbf2`
- Adopted policy proposal: `attached_assets/usbay-preservation-policy-clarification-proposal.md`
- Adopted policy proposal SHA-256: `41a2354506c61a5595420175b04839802d0ad5aaa8afdfb3be100ae6afcf8295`
- Validated script: `attached_assets/usbay-age-preservation.zsh`
- Validated script SHA-256: `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07`

The reviewed custody document and validated script remain unchanged.

## Owner-supplied FileVault evidence

- Timestamp: `2026-09-16T04:49:34Z`
- Command: `/usr/bin/fdesetup status`
- Output: `FileVault is On.`
- Exit status: `0`

Bounded conclusion: active FileVault status is PROVEN from owner-supplied native Mac evidence at the recorded timestamp.

This closes only the active-FileVault-status evidence gap at that timestamp. It does not prove:

- backup coverage;
- backup completion;
- retention;
- encryption of any backup destination;
- recovery;
- protection from a process running under the logged-in account;
- continued FileVault state after the recorded timestamp.

The completed FileVault inspection must not be repeated under this review.

## Custody conditions presented for owner decision

### 1. Exact local paths

The owner is asked to approve custody using exactly:

- primary identity: `/Users/jayceeiambella/.config/age/usbay-preservation-identity.txt`;
- public recipient: `/Users/jayceeiambella/.config/age/usbay-preservation-recipient.txt`;
- local evidence: `/Users/jayceeiambella/USBAY-Preservation-Evidence/<unique-run-directory>/`.

Retained inspection reported the effective paths unchanged, no symlink redirection, and the `age` directory, primary identity, and evidence directory absent at inspection time.

The intended script behavior is owner-only directories, exclusive publication of the primary identity at mode 0600, no replacement of existing paths, and refusal rather than permission repair when an existing `~/.config/age` mode is unacceptable.

### 2. Selected SanDisk USB

The selected owner-controlled SanDisk ExFAT USB is intended to hold:

- `usbay-preservation-identity.txt.age`;
- the public recipient;
- recovery instructions;
- the SHA-256 manifest.

It is not intended to hold the unencrypted primary identity or the paper passphrase.

A separately authorized run would repeatedly reidentify the USB, write only inside a new unique recovery directory, synchronize and eject the whole device, require reconnection, verify device identity and exact contents, verify recipient equality and hashes, and perform the bounded one-explicit-identity recovery challenge.

No encrypted identity has been written, reconnect integrity has not been established, and recovery-key usability has not been validated. Those are Gate B matters after separately authorized creation.

### 3. Separate locked paper passphrase

The paper arrangement requires:

- a fresh passphrase of at least seven independently selected Diceware words;
- locked, owner-controlled physical storage;
- physical separation from the SanDisk USB;
- no entry into chat, command arguments, digital files, logs, or evidence records.

This decision asks only whether that separate locked arrangement is available and whether the owner approves it. The passphrase and precise storage location must not be supplied.

### 4. Recorded copying configuration

Retained evidence establishes:

- documented iCloud Desktop & Documents does not apply to either proposed path;
- this does not generalize to every iCloud or copying mechanism;
- Time Machine returned `IsExcluded=0` for both paths and all inspected ancestors at `2026-09-16T04:34:38Z`;
- Time Machine reported `No destinations configured.` at `2026-09-16T04:38:14Z`;
- the supplied Time Machine screenshot showed **Add Backup Disk…** with no destination displayed.

Bounded conclusion: the paths were not excluded, but no Time Machine destination was configured at the recorded time.

This does not prove or disprove historical backups, local snapshots, other copying mechanisms, future changes, backup completion, retention, backup encryption, or recoverability.

### 5. Interval before USB recovery validation

If a future separately authorized run publishes the local identity, there is an interval before Gate B completes in which:

- the unencrypted primary identity exists at the local Mac path;
- the encrypted USB copy may not yet exist or may not yet be verified;
- no Time Machine destination was configured in the retained evidence;
- a failure may leave the primary identity without a validated USB recovery copy.

The owner must approve this interval as part of custody. Approval would not authorize execution.

### 6. Retained partial-state consequences

The owner is asked to approve all of these consequences:

- Homebrew age may remain installed after a later failure; no automatic rollback is claimed.
- The local primary identity and public recipient may remain after a later USB or recovery-test failure.
- The local evidence directory and captured Homebrew output may remain.
- A new USB recovery directory or partial USB files may remain but are not valid recovery coverage.
- Private staging cleanup is attempted, but success must be established from evidence.
- Status 124 is accepted only when timeout cleanup is proven.
- Status 125 blocks continuation and can mean either cleanup remained unproven or descendants were detected and successfully cleaned; recorded evidence must distinguish the case.
- Direct-child termination or reaping alone does not prove descendant cleanup.
- Operational calls do not guarantee a `SYNTHETIC_DIAGNOSTIC` record.
- A failed or interrupted run must not be automatically retried, deleted, overwritten, renamed, or repaired without evidence review and separate authorization.
- A failure after primary publication but before successful Gate B can leave durable local private-key material without validated USB recovery.
- UNKNOWN cleanup or status meaning blocks further lifecycle action.

## Exact custody questions

The owner is asked only:

1. Is a locked, owner-controlled paper-storage arrangement physically separate from the selected SanDisk USB available?
2. Do you approve all custody conditions in this record, including the exact local paths, FileVault evidence and limitation, selected USB arrangement, separate paper storage, recorded copying configuration, pre-Gate-B interval, and retained partial-state consequences?

Do not provide the passphrase or precise paper-storage location.

## Decision consequences

- If the separate paper arrangement is unavailable, custody approval fails closed and Gate A remains PARTIAL.
- If the owner does not approve every custody condition, custody approval remains NOT GRANTED and Gate A remains PARTIAL.
- If both answers are yes, custody approval may be recorded separately as granted for these exact conditions.
- Even if custody is approved, operational execution remains unauthorized until a later, separate explicit instruction authorizes the bounded operational effects.

## Current governance disposition

- Policy clarification: ADOPTED.
- Active FileVault status at `2026-09-16T04:49:34Z`: PROVEN.
- Custody approval: NOT GRANTED.
- Gate A evidence state: PARTIAL pending the two owner answers.
- Operational authorization: NOT GRANTED.
- Gate B: NOT_APPLICABLE before separately authorized creation.
- Gate C: NOT_APPLICABLE before Gate B and separately authorized archive and Linux restoration work.
- Production authorization: NOT GRANTED.