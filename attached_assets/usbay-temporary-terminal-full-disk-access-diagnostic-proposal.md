# USBAY temporary Terminal Full Disk Access diagnostic proposal

## Status and authority

- Status: PROPOSED
- Full Disk Access change: NOT AUTHORIZED by this proposal
- Terminal quit/reopen: NOT AUTHORIZED by this proposal
- Diagnostic execution: NOT AUTHORIZED by this proposal
- USB file access or write: NOT AUTHORIZED
- Privacy reset: NOT AUTHORIZED
- Preservation-script execution: NOT AUTHORIZED
- Installation, key creation, cleanup, deletion, and operational retry: NOT AUTHORIZED

This proposal defines one possible bounded diagnostic sequence. It does not perform or authorize the sequence.

## Reused evidence

- macOS: owner-reported Tahoe 26.6.2; exact build UNKNOWN.
- Terminal: owner-reported Version 2.15 (470.2).
- Mac: owner reports personally managed; this does not prove management profiles are absent.
- Terminal Full Disk Access: displayed OFF in retained screenshot evidence.
- Terminal Removable Volumes control: absent from the retained Files & Folders screenshot.
- Terminal external/removable-storage control: absent from the retained General → Storage screenshot.
- Consumed-run prompt choice: owner selected **Don’t Allow**.
- Consumed-run supported failure phase: `PARTIAL` inference of initial USB discovery.
- Consumed-run internal `/usr/sbin/diskutil` status: `124`.
- Consumed-run overall script exit: `1`.
- Permission denial as exact failure cause: UNKNOWN.
- Cleanup success: UNKNOWN.

Completed screenshots, inspections, script tests, custody review, FileVault check, copying-configuration review, and post-failure metadata inspection are reused and must not be repeated absent contradictory evidence.

## Necessity assessment

### Full Disk Access is not established as necessary

Apple documents:

- **Files and folders**, including removable volumes, as one privacy category;
- **Full Disk Access** as a broader category allowing an app to access all files on the computer, including other apps’ data, Time Machine backup data, and certain administrative settings.

The reviewed preservation operation requires access to identify and later use one selected removable USB. No evidence establishes a requirement to access all internal files, other apps’ protected data, Time Machine backups, or administrative settings.

Therefore:

- necessity of Full Disk Access: NOT PROVEN;
- least-privilege fit: FAILED because the permission is materially broader than the identified removable-volume requirement;
- Full Disk Access must not be described as the required permission.

### Full Disk Access as a possible diagnostic workaround

Temporary Full Disk Access may be conditionally justified only as a last-resort diagnostic workaround because:

1. the owner denied the removable-storage prompt;
2. the narrower Files & Folders control was not displayed;
3. Apple’s Tahoe General → Storage route did not display the expected app control;
4. the prior failure occurred during a `/usr/sbin/diskutil` phase;
5. one read-only `diskutil list` operation can test whether the failure remains when Terminal has broader storage authority.

This diagnostic cannot prove that Full Disk Access is necessary. A success would show only that the tested command succeeded while the broader permission was active. It would not isolate which part of that permission changed the result or prove that the earlier denial caused the failure.

## Apple evidence

Apple describes Full Disk Access as allowing apps to access all files on the computer, including:

- data from other apps such as Mail, Messages, Safari, and Home;
- Time Machine backup data;
- certain administrative settings for all users on the Mac.

Apple separately identifies Files & Folders as including removable volumes.

Sources:

- Apple Mac User Guide, **Change Privacy & Security settings on Mac**: <https://support.apple.com/guide/mac-help/change-privacy-security-settings-on-mac-mchl211c911f/mac>
- Apple Platform Security, **Controlling app access to files in macOS**: <https://support.apple.com/guide/security/controlling-app-access-to-files-secddd1d86a6/web>
- Apple Mac User Guide for Tahoe 26, **Allow use of external and removable storage**: <https://support.apple.com/en-ca/guide/mac-help/mchl6f613f75/mac>

The reviewed Apple pages do not state that Full Disk Access is required for `diskutil list` or removable-volume access.

## One concrete bounded proposal

The following sequence may occur only if the owner later adopts it with explicit authority for every listed step.

### 1. Preconditions

Before enabling Full Disk Access:

- no preservation script or child process is running;
- no Terminal command is running;
- all required retained evidence is already saved;
- the selected SanDisk USB is connected in its existing state;
- the owner records the UTC start time;
- the owner understands that Terminal receives broad access during the exposure window.

If any precondition is UNKNOWN, stop.

### 2. Exact temporary permission change

Open:

`Apple menu → System Settings → Privacy & Security → Full Disk Access`

Confirm the existing **Terminal** entry is the expected Apple Terminal application, then turn only Terminal Full Disk Access from OFF to ON.

Do not:

- add another terminal application;
- enable Full Disk Access for any other app;
- change Files & Folders;
- change General → Storage;
- reset privacy controls;
- change USB, Finder, disk, or filesystem permissions.

Record the UTC enable time and displayed Terminal state.

### 3. Terminal restart decision

Apple’s reviewed pages do not establish a universal quit/reopen requirement after changing Full Disk Access. Therefore an operating-system requirement is UNKNOWN.

For this diagnostic design, one normal Terminal quit and reopen is methodologically required so the tested Terminal process starts after the permission change. Without that process boundary, a failure could be attributed to stale permission state and the diagnostic would be inconclusive.

This means adoption of this proposal must explicitly authorize:

- one normal quit of Terminal after Full Disk Access is enabled;
- one reopen of Apple Terminal;
- no Mac restart;
- no repeated Terminal restarts.

If macOS presents a specific **Quit & Reopen** action while changing Full Disk Access, that displayed requirement must be recorded. If Terminal cannot quit normally, stop; do not force quit and do not run the diagnostic.

### 4. One bounded read-only diagnostic

Run exactly one operation:

`/usr/sbin/diskutil list -plist external physical`

Requirements:

- use the reopened Apple Terminal;
- enforce a 15-second command deadline;
- capture stdout, stderr, and the exact command exit status;
- record whether any permission prompt appears;
- do not run `diskutil info`;
- do not list mounted directories;
- do not open or read USB files;
- do not write to the USB;
- do not run the preservation script.

The deadline wrapper must:

- terminate and wait for the direct `diskutil` process if 15 seconds expires;
- report diagnostic status `124` for the diagnostic deadline;
- make no claim about descendant cleanup unless separately evidenced.

No second attempt is permitted.

### 5. Maximum Full Disk Access exposure window

Terminal Full Disk Access may remain ON for no longer than five minutes measured from the recorded enable time.

The diagnostic must not start unless there is enough time to:

- perform the single 15-second attempt;
- record the result;
- return to System Settings;
- turn Terminal Full Disk Access OFF before the five-minute deadline.

If any delay threatens the deadline, skip or stop the diagnostic and revoke Full Disk Access.

### 6. Success criteria

Diagnostic result is `SUPPORTED_SUCCESS` only if all are evidenced:

- Full Disk Access was enabled only for Terminal;
- the diagnostic ran from the one reopened Apple Terminal;
- exactly one `diskutil list -plist external physical` operation was attempted;
- completion occurred within 15 seconds;
- command exit status was `0`;
- stdout was a syntactically valid property list;
- the property list contained the expected `AllDisksAndPartitions` key;
- the selected external physical USB appeared without ambiguity;
- no removable-volume permission prompt appeared;
- no USB file or mounted-directory access occurred;
- Full Disk Access was revoked within five minutes.

Even `SUPPORTED_SUCCESS` would establish only:

> The bounded read-only `diskutil list` command succeeded while Terminal Full Disk Access was active.

It would not establish necessity, causation, `diskutil info` access, mounted-volume access, USB writability, script readiness, cleanup, or Gate B.

### 7. Failure and inconclusive criteria

Result is `FAILED` or `INCONCLUSIVE` if any occurs:

- Full Disk Access cannot be enabled exactly as proposed;
- Terminal cannot quit normally or reopen once;
- macOS requires an unapproved additional action;
- the command exceeds 15 seconds;
- exit status is nonzero;
- stdout is missing or is not a valid property list;
- the required property-list key is absent;
- the selected USB is absent or ambiguous;
- a permission prompt appears;
- stderr or system UI indicates denial, interruption, or another error;
- an unauthorized command or access occurs;
- Full Disk Access revocation is not evidenced before the five-minute deadline.

No failure or inconclusive result authorizes repetition, broader access, another diagnostic, cleanup, or operational execution.

Interpretation:

- success is consistent with Full Disk Access working as a workaround but does not prove it was necessary;
- failure shows Full Disk Access was not sufficient for this diagnostic under the observed conditions but does not identify the cause;
- a changed result relative to the consumed run suggests a privacy-control relationship but does not prove causation because the executions differ in time and process state.

## Revocation

Immediately after the single diagnostic—or before it if the five-minute deadline is at risk—return to:

`Apple menu → System Settings → Privacy & Security → Full Disk Access`

Turn only Terminal Full Disk Access from ON to OFF and record:

- UTC revocation time;
- displayed Terminal state OFF;
- any macOS message or error.

After revocation:

- normally quit Terminal once;
- do not reopen Terminal under this proposal.

The post-revocation quit is included to end the diagnostic Terminal process that held the broader permission. It does not prove that all descendants terminated.

### Revocation limitations

Turning Full Disk Access OFF:

- does not undo any access that occurred while it was ON;
- does not erase information already read;
- does not delete files created elsewhere;
- does not terminate already running processes by itself;
- does not prove descendant cleanup;
- does not prove the privacy database is free of stale state;
- does not prove removable-volume permission state;
- does not restore or change USB contents;
- does not validate Gate B.

If OFF state or Terminal termination is not evidenced, revocation status remains UNKNOWN and human review is required. No cleanup action is implied.

## Evidence to retain

Retain only:

- UTC enable and revoke times;
- before/after screenshots showing Terminal Full Disk Access OFF → ON → OFF;
- whether macOS required Quit & Reopen;
- Terminal version `2.15 (470.2)`;
- macOS version `Tahoe 26.6.2`;
- exact diagnostic command;
- diagnostic start and end times;
- exit status;
- stdout property-list evidence;
- stderr;
- whether a permission prompt appeared;
- normal Terminal quit/reopen outcomes.

Do not retain or inspect private USB file contents. No passphrase is involved.

## Separation from operational authority

Adoption of this diagnostic proposal would authorize only:

- one temporary Terminal Full Disk Access ON transition;
- one normal Terminal quit and reopen before the diagnostic;
- one bounded read-only `diskutil list` attempt;
- Terminal Full Disk Access OFF within five minutes;
- one normal Terminal quit after revocation.

It would not authorize:

- `diskutil info`;
- mounted-volume listing;
- USB file access or writes;
- installation;
- key creation;
- preservation-script execution;
- cleanup or deletion;
- a repeat diagnostic;
- a new operational run.

The consumed one-run authorization remains consumed.

## Current evidence disposition

- Full Disk Access necessity: NOT PROVEN.
- Least-privilege fit: FAILED.
- Temporary diagnostic-workaround rationale: PARTIAL and conditional.
- Full Disk Access setting change: NOT AUTHORIZED.
- Diagnostic: NOT AUTHORIZED.
- Terminal restart: NOT AUTHORIZED.
- Permission denial as prior failure cause: UNKNOWN.
- Cleanup success: UNKNOWN.
- Gate B: UNKNOWN.
- New operational authorization: NOT GRANTED.

## Governance verdict

Temporary Terminal Full Disk Access is not established as necessary and is broader than the identified need. It is defensible only as a separately authorized, last-resort diagnostic workaround with one 15-second read-only `diskutil list` attempt, a five-minute maximum exposure window, one controlled Terminal quit/reopen before testing, immediate revocation, and no operational execution. Success would not prove necessity or authorize another run.