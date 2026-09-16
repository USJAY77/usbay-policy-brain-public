# USBAY consolidated custody review

## Status and scope

This document presents retained custody evidence and unresolved owner decisions under adopted Gate A. It does not approve custody and does not authorize execution.

The governing policy clarification was adopted separately by owner decision with reference to:

- proposal: `attached_assets/usbay-preservation-policy-clarification-proposal.md`;
- proposal SHA-256: `41a2354506c61a5595420175b04839802d0ad5aaa8afdfb3be100ae6afcf8295`.

Policy adoption is separate from this custody review and from any later operational authorization.

## 1. Exact local paths

### Intended paths

- Primary identity: `/Users/jayceeiambella/.config/age/usbay-preservation-identity.txt`
- Public recipient: `/Users/jayceeiambella/.config/age/usbay-preservation-recipient.txt`
- Local run evidence: `/Users/jayceeiambella/USBAY-Preservation-Evidence/<unique-run-directory>/`

### Retained evidence

Owner-supplied read-only path inspection reported:

- `/Users/jayceeiambella`: directory; resolved unchanged;
- `/Users/jayceeiambella/.config`: directory; resolved unchanged;
- `/Users/jayceeiambella/.config/age`: absent; resolved unchanged;
- the primary-identity path: absent; resolved unchanged;
- `/Users/jayceeiambella/USBAY-Preservation-Evidence`: absent; resolved unchanged;
- no symlink redirection for the inspected paths.

The operational proposal states that the script would:

- create `~/.config` as mode 0700 only if absent and confirmed;
- create `~/.config/age` as mode 0700 only if absent;
- refuse an existing `~/.config/age` with another mode rather than change it;
- publish the primary identity exclusively at mode 0600 without replacing an existing path;
- create the public recipient exclusively;
- create a unique owner-only run-evidence directory.

### Custody assessment

- Effective path identity: PROVEN from owner-supplied inspection at its recorded state.
- Current private identity at the path: NOT_APPLICABLE; the identity does not exist.
- Current evidence directory: NOT_APPLICABLE; it does not exist.
- Owner control of the Mac: owner-supplied statement says the owner manages the Mac.
- Active FileVault protection: UNKNOWN from the retained evidence available to this review.
- Owner approval of these paths and local custody: NOT GRANTED.

## 2. USB encrypted recovery copy

### Intended arrangement

The intended recovery medium is the owner-selected SanDisk ExFAT USB. A separately authorized run would:

- repeatedly identify and reidentify the same external physical USB;
- create one unique `USBAY-Recovery-<random>` directory;
- write `usbay-preservation-identity.txt.age`;
- write only the public recipient, recovery instructions, and SHA-256 manifest alongside it;
- record hashes locally;
- synchronize and eject the whole selected device;
- require reconnection and reidentification;
- verify exact directory contents, recipient equality, and hashes;
- run a bounded recovery challenge using exactly one explicit USB identity without referencing the Mac primary identity.

### Custody assessment

- Intended USB format and role: retained design identifies an ExFAT SanDisk USB for the encrypted recovery copy.
- Current encrypted identity on USB: NOT_APPLICABLE; no key creation or USB write has occurred.
- Current reconnect integrity: NOT_APPLICABLE; Gate B has not occurred.
- Current recovery-key usability: NOT_APPLICABLE; Gate B has not occurred.
- Physical ownership, current custody, acceptable existing contents, media health, and permission to create the unique directory: require explicit owner approval immediately before any separately authorized run.
- USB custody approval: NOT GRANTED.

The USB is intended to hold encrypted private recovery material, not the unencrypted primary identity or the paper passphrase.

## 3. Separate paper passphrase

### Intended arrangement

The retained design requires:

- a fresh passphrase of at least seven independently selected Diceware words;
- creation by the owner during the authorized interactive run;
- locked, owner-controlled storage;
- physical separation from the USB;
- no entry into chat, command arguments, files, logs, or digital evidence.

### Custody assessment

- Paper passphrase created: NOT_APPLICABLE; no authorized run has occurred.
- Locked storage location: UNKNOWN.
- Physical separation arrangement: intended but not yet confirmed.
- Owner readiness and approval of the paper custody arrangement: NOT GRANTED.

The passphrase must not be recorded in this review or any digital evidence.

## 4. Recorded copying and backup configuration

### iCloud

Retained owner-supplied settings report:

- iCloud Drive **Sync this Mac**: ON;
- **Desktop & Documents Folders**: OFF;
- **Optimize Mac Storage**: ON;
- all 13 listed application-sync switches: ON.

Using Apple’s documented Desktop & Documents scope and the unchanged effective paths, the documented iCloud Desktop & Documents mechanism does not apply to either proposed path.

This bounded conclusion does not generalize to every iCloud feature or copying mechanism. The application list and Optimize Mac Storage setting establish no inclusion or exclusion for the proposed paths.

### Time Machine

Owner-supplied native Mac evidence reports:

- `2026-09-16T04:34:38Z`: `tmutil isexcluded -X` exited 0 and returned `IsExcluded=0` for both proposed paths and all inspected ancestors, including the absent targets;
- `2026-09-16T04:38:14Z`: `tmutil destinationinfo` exited 0 and printed `tmutil: No destinations configured.`;
- the supplied screenshot showed **Add Backup Disk…** with no destination displayed.

Bounded conclusion: the proposed paths were not excluded, but no Time Machine backup destination was configured at the recorded time.

This does not establish or disprove:

- historical backups;
- local snapshots;
- other copying mechanisms;
- future configuration changes;
- backup completion;
- retention;
- backup encryption;
- recoverability.

### Gate A configuration assessment

For the concrete standard mechanisms identified by retained evidence:

- documented iCloud Desktop & Documents: NOT_APPLICABLE to either path;
- Time Machine path exclusion: PROVEN not excluded at the recorded timestamp;
- Time Machine configured destination: PROVEN absent at the recorded timestamp.

No additional concrete copying mechanism is established by retained evidence. Universal absence of copying is not claimed or required.

Owner approval of the reported configuration and its consequences: NOT GRANTED.

Practical consequence: absent another approved backup arrangement, an authorized creation would initially place the unencrypted primary identity only at the local Mac path until Gate B verifies the separately encrypted USB recovery copy. The recorded no-destination Time Machine state provides no Time Machine backup coverage for that interval.

## 5. Retained partial-state behavior

The retained operational proposal states:

- Homebrew age may remain installed after a later failure; the script does not roll it back.
- A published primary identity and public recipient may remain after a later USB or recovery-test failure; the script does not delete them.
- A new USB recovery directory or partial files may remain after failure; they are not valid recovery coverage.
- The local evidence directory and captured Homebrew output remain for review.
- Private staging cleanup is attempted, but success must be established from evidence.
- Status 124 is accepted only when timeout cleanup is proven.
- Status 125 blocks continuation and may mean either unproven cleanup or detected descendants that were successfully cleaned; recorded evidence must distinguish the case.
- Direct-child termination or reaping alone never proves descendant cleanup.
- Operational calls do not guarantee a `SYNTHETIC_DIAGNOSTIC` record.
- Failed or interrupted operation must not be automatically retried or repaired without evidence review and separate authorization.

### Custody consequence

The owner must decide whether it is acceptable that:

- software may remain installed;
- the local unencrypted primary identity may remain after a later failure;
- local evidence may remain;
- partial USB outputs may remain but provide no recovery coverage;
- a failure after primary publication but before successful Gate B can leave durable key material without a validated USB recovery copy;
- cleanup or status meaning may remain UNKNOWN and block further lifecycle action.

Owner approval of retained partial-state behavior: NOT GRANTED.

## 6. Consolidated Gate A custody disposition

### Established

- The adopted gate ordering does not require recovery of a nonexistent identity before creation.
- Effective local paths were reported unchanged with no symlink redirection.
- The documented iCloud Desktop & Documents mechanism does not apply to either path.
- Time Machine reported the paths not excluded and reported no configured destination at the recorded timestamps.
- Intended local, USB, and paper custody arrangements are documented.
- Retained partial-state behavior is documented.

### Still requiring explicit owner approval

The owner must specifically approve:

1. the exact local primary-identity, recipient, and evidence paths;
2. the owner-controlled Mac and active FileVault custody condition;
3. use of the selected owner-controlled SanDisk ExFAT USB for the encrypted recovery copy;
4. creation and locked, owner-controlled, physically separate storage of the paper passphrase;
5. the recorded iCloud and Time Machine configuration, including no configured Time Machine destination;
6. the interval in which a published local identity may exist before Gate B validates the USB recovery copy;
7. every retained partial-state consequence listed above.

### Current decision state

- Policy clarification: ADOPTED.
- Custody approval: NOT GRANTED.
- Gate A evidence: PARTIAL pending owner confirmation of active FileVault and explicit custody approval.
- Gate A operational authorization: NOT GRANTED.
- Gate B: NOT_APPLICABLE before authorized creation.
- Gate C: NOT_APPLICABLE before Gate B and separately authorized archive and Linux restoration work.

Approval of this review would still not authorize operational execution unless the owner issues a separate instruction that explicitly authorizes the bounded operational effects.

## Governance verdict

Custody review evidence state is PARTIAL and the review is presented for owner consideration. Gate A remains unsatisfied. No installation, key creation, USB write, settings change, archive operation, source removal, restart, or production action is authorized.