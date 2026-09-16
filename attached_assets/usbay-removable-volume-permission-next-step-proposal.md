# USBAY removable-volume permission next-step proposal

## Status and authority

- Status: PROPOSED
- Settings or permission change: NOT AUTHORIZED
- Read-only permission check: NOT AUTHORIZED
- New one-run authorization: NOT GRANTED
- Execution performed by this proposal: NONE

This is the single bounded next-step proposal following the consumed failed run. It does not itself authorize any step.

## Evidence basis

- Owner-reported macOS choice: **Don’t Allow** on the Terminal removable-volume access prompt.
- Consumed run: overall script exit `1`.
- Internal `/usr/sbin/diskutil` status: `124`.
- Supported failure phase: `PARTIAL` inference of initial USB discovery.
- Post-failure local state: `.config/age`, identity, recipient, and evidence root reported absent at inspection time.
- Permission denial as exact failure cause: UNKNOWN.
- Cleanup success: UNKNOWN.
- Existing one-run authorization: CONSUMED.
- Retry: NOT AUTHORIZED.

Completed script self-tests, custody review, FileVault check, path inspection, iCloud applicability review, Time Machine inspection, and post-failure metadata inspection remain retained and must not be repeated absent new contradictory evidence.

## Required macOS permission

Apple documents **removable volumes** as part of macOS **Files & Folders** privacy controls. Apple’s user guide says the owner can control access per listed app at:

> Apple menu → System Settings → Privacy & Security → Files & Folders

For this design, the relevant requesting app is **Terminal**, because the reviewed script is launched from Terminal and the macOS prompt identified Terminal.

The minimum proposed permission is:

- Terminal → Files & Folders → Removable Volumes: ON.

This proposal does not request or justify **Full Disk Access**. Full Disk Access would be broader than the identified removable-volume requirement.

### Scope

The macOS control is app-level and location-category-level. It is not evidenced as being limited to:

- this script;
- one command;
- one launch;
- one SanDisk device;
- one recovery directory;
- read-only access;
- only `diskutil`.

Enabling Terminal’s removable-volume access may permit Terminal and processes macOS attributes to Terminal to access files on removable volumes, subject to ordinary filesystem permissions and other macOS controls.

This privacy permission does not itself:

- select or validate the SanDisk USB;
- prove USB identity, health, filesystem, mount, writability, size, or free space;
- authorize USB writes;
- authorize the preservation script;
- authorize installation or key creation;
- bypass any script check or owner checkpoint.

## Persistence and limitations

Apple exposes the permission as an on/off control under Files & Folders, which establishes that it is a stored privacy preference rather than a one-command authorization.

Apple’s cited pages do not specify a guaranteed duration or every condition that can reset, remove, migrate, or alter the permission. Therefore:

- persistence across logout, reboot, macOS update, Terminal update or replacement, privacy-database reset, device management, or other system changes is UNKNOWN unless separately evidenced;
- enabling the control once does not prove it remains enabled at a later run;
- the permission does not prove that a particular child process will succeed;
- the permission does not prove that the prior denial caused the observed failure;
- the permission does not prove cleanup from the consumed run.

## Revocation

Apple documents revocation through:

> Apple menu → System Settings → Privacy & Security → Files & Folders → Terminal → turn off access for Removable Volumes

Turning the control off is a settings change. Any future permission grant and any later revocation require their own explicit owner authority.

Revocation limitations:

- turning the control off does not delete files already created;
- it does not undo prior reads or writes;
- it does not uninstall software;
- it does not remove identities, evidence, or USB files;
- it does not prove termination of already running processes;
- it does not prove that every process attributed differently by macOS loses access;
- it does not establish cleanup of the consumed run.

No command-line privacy reset is proposed. A broad privacy reset or Full Disk Access change is outside this proposal.

## Minimum evidence required before another run may be considered

Another run remains blocked unless all of the following are separately authorized and retained:

### 1. Explicit permission-change decision

The owner must explicitly authorize the single bounded settings change:

- enable only Terminal’s **Files & Folders → Removable Volumes** control.

That authorization must not be interpreted as authorization to run the preservation script.

### 2. Permission-state evidence

After an authorized change, retain:

- UTC timestamp;
- macOS version;
- requesting application identity shown as Terminal;
- System Settings location;
- the exact **Removable Volumes** control shown ON;
- evidence that Full Disk Access was not enabled as part of this change.

A screenshot or exact owner transcription may establish the displayed state. It proves only the displayed configuration at that timestamp.

### 3. Separately authorized bounded read-only permission check

Before considering another operational run, perform one separately authorized read-only check limited to:

- the same owner-controlled Mac;
- the selected SanDisk USB;
- the read-only `diskutil list -plist external physical` operation;
- only the `diskutil info -plist` records needed for the selected external device and its volume;
- listing only top-level USB names and path types, without opening file contents.

Retain the exact commands, timestamp, exit statuses, stdout, stderr, and whether another permission prompt appeared.

The check must not:

- write to the USB;
- open or print any USB file content;
- inspect unrelated volumes;
- install software;
- create an identity;
- change settings;
- run the preservation script;
- repeat the completed self-test;
- clean up or delete anything.

Denied access, another prompt, timeout, ambiguity, changed USB identity, or incomplete evidence leaves permission readiness UNKNOWN and blocks another run.

### 4. Unchanged reviewed artifacts and decisions

Before a new authorization decision, retain evidence that:

- the script still hashes to `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07`;
- the approved custody arrangement remains in effect;
- no new contradictory path, FileVault, copying-configuration, USB-custody, or partial-state evidence exists.

Completed checks are reused; they are not repeated without contradiction.

### 5. New explicit one-run authorization

Only after the permission change and bounded read-only check are separately authorized, performed, and reviewed may the owner consider a new one-run authorization.

The new authorization must:

- identify the exact script hash;
- authorize exactly one new owner-executed interactive Mac run;
- incorporate the existing prerequisites, checkpoints, stop conditions, retained partial-state behavior, and exclusions;
- acknowledge that the prior authorization was consumed and does not authorize a retry;
- remain separate from the permission decision.

## Permission approval is not run authorization

The decisions are separate:

1. **Permission-change approval** authorizes only changing Terminal’s Removable Volumes control.
2. **Read-only-check approval** authorizes only the bounded permission evidence check.
3. **New one-run authorization** authorizes one later operational script launch.

Approval or completion of one does not imply another. The environment variable `USBAY_RECOVERY_SETUP_AUTHORIZED=YES` is not sufficient human authorization.

Calling a future launch a “retry” does not inherit authority from the consumed run. It requires a new explicit one-run authorization after the new evidence is reviewed.

## Apple sources

- Apple Platform Security, **Controlling app access to files in macOS**: <https://support.apple.com/guide/security/controlling-app-access-to-files-secddd1d86a6/web>
- Apple Mac User Guide, **Control access to files and folders on Mac**: <https://support.apple.com/en-md/guide/mac-help/mchld5a35146/mac>

Apple states that Files & Folders includes removable volumes and that per-app access can be turned on or off under Privacy & Security → Files & Folders.

## Current governance disposition

- Owner-reported permission denial: PROVEN as a direct owner statement.
- Denial as exact failure cause: UNKNOWN.
- Cleanup success: UNKNOWN.
- Permission change: NOT AUTHORIZED.
- Permission readiness: UNKNOWN.
- Read-only permission check: NOT AUTHORIZED.
- Prior one-run authorization: CONSUMED.
- New one-run authorization: NOT GRANTED.
- Installation, key creation, USB writes, cleanup, deletion, and restart: NOT AUTHORIZED.
- Gate B: UNKNOWN and not validated.

## Governance verdict

The minimum next path is a separately authorized Terminal removable-volume permission change, followed by a separately authorized bounded read-only permission check and evidence review. Neither step authorizes a new run. A new one-run authorization may be considered only afterward and must be explicit.