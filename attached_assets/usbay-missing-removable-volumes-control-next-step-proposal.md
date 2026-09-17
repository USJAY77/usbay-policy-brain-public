# USBAY missing Removable Volumes control next-step proposal

## Status and authority

- Status: PROPOSED
- Permission change: NOT AUTHORIZED
- Full Disk Access: OFF and NOT AUTHORIZED
- Broad privacy reset: NOT AUTHORIZED
- USB access or check: NOT AUTHORIZED
- Terminal restart: NOT AUTHORIZED
- Preservation-script run: NOT AUTHORIZED
- Installation, key creation, USB writes, cleanup, and deletion: NOT AUTHORIZED

This proposal does not authorize or perform any action. It defines one bounded next step for human review after the expected Removable Volumes control was not present.

## Owner-supplied evidence

The owner reports that:

1. A screenshot shows:

   `Privacy & Security → Full Disk Access → Terminal: OFF`

2. An earlier Files & Folders screenshot showed no Removable Volumes control.

3. The reason for the missing control is UNKNOWN.

## Bounded findings

### Established

- Terminal does not have Full Disk Access enabled in the supplied screenshot.
- The expected Removable Volumes control was not visible in the supplied Files & Folders screenshot.
- The previously authorized settings change could not be evidenced as completed through that expected control.
- No broader permission was authorized.

### Not established

The evidence does not establish:

- why the Removable Volumes control was missing;
- whether the control is absent because of the macOS version, current privacy-state presentation, application attribution, device management, UI state, or another cause;
- the current underlying privacy-database state;
- whether reopening an application or changing another setting would make the control appear;
- whether Terminal can currently access removable volumes;
- whether permission denial conclusively caused the prior `diskutil` failure;
- whether cleanup from the consumed run succeeded.

No one of these explanations may be selected without additional evidence.

## Supported Apple baseline

Apple documents removable volumes as part of the Files & Folders privacy category and documents per-app controls at:

`Apple menu → System Settings → Privacy & Security → Files & Folders`

Apple also documents that access can be turned on or off for the locations shown for each listed app.

Sources:

- Apple Platform Security, **Controlling app access to files in macOS**: <https://support.apple.com/guide/security/controlling-app-access-to-files-secddd1d86a6/web>
- Apple Mac User Guide, **Control access to files and folders on Mac**: <https://support.apple.com/en-md/guide/mac-help/mchld5a35146/mac>

Those sources support the expected category and settings location. They do not explain the specific missing control shown in the owner’s environment.

## Single bounded next step

### Purpose

Collect only the minimum non-mutating platform and screenshot context needed to determine whether Apple documents a version-specific supported path. Do not attempt to make the control appear.

### Proposed evidence collection

Subject to a separate explicit owner authorization, collect:

1. **macOS version and build**
   - Use Apple menu → About This Mac.
   - Record the displayed macOS name, version, and build if shown.
   - Do not run a Terminal command.

2. **Terminal application identity**
   - If Terminal is already open, use Terminal → About Terminal.
   - Record the displayed application name and version.
   - Do not quit, restart, update, replace, or relaunch Terminal.
   - If Terminal is not already open, leave this item UNKNOWN rather than launching it under this proposal.

3. **Existing screenshot evidence**
   - Supply the existing uncropped or minimally cropped Files & Folders screenshot showing the Terminal entry and the absence of Removable Volumes.
   - Supply the existing Full Disk Access screenshot showing Terminal OFF.
   - Unrelated application names may be redacted.
   - Do not reopen settings merely to repeat the completed inspection.

4. **Management-status statement**
   - State only whether the owner knows the Mac to be personally managed or organization/device managed.
   - Do not inspect profiles, run commands, remove management, or change policy under this proposal.
   - If unknown, record UNKNOWN.

### Explicit exclusions

This proposed evidence collection must not:

- enable Full Disk Access;
- enable any other Files & Folders category;
- use `tccutil` or reset privacy controls;
- edit the macOS privacy database;
- restart or relaunch Terminal;
- reconnect, enumerate, mount, open, read, or write the USB;
- recreate the permission prompt;
- run `diskutil`;
- run the preservation script;
- repeat completed script tests or path inspections;
- install software;
- create a key or identity;
- clean up or delete anything.

## Review rule after collection

After the proposed evidence is supplied:

1. identify the exact macOS version and Terminal identity;
2. consult Apple documentation applicable to that version;
3. determine whether Apple documents a narrow Files & Folders path for the missing Removable Volumes control;
4. if no supported narrow path is established, remain BLOCKED and request human review or Apple support guidance;
5. do not substitute Full Disk Access, a privacy reset, another terminal application, or an operational retry.

No settings action may follow automatically from the review. Any newly identified permission action would require a separate explicit owner authorization.

## Separation from later lifecycle authority

Even if a supported Removable Volumes control is later identified and separately enabled:

- that permission change would not authorize USB inspection;
- it would not authorize a read-only permission check;
- it would not authorize installation, key creation, or USB writes;
- it would not authorize another preservation-script run;
- the previous one-run authorization remains consumed;
- any later run would require a new explicit one-run authorization after all prerequisite evidence is reviewed.

## Current evidence disposition

- Owner-reported permission denial: PROVEN as an owner statement.
- Full Disk Access shown OFF: PROVEN from owner-supplied screenshot report.
- Removable Volumes control absent from earlier Files & Folders screenshot: PROVEN from owner-supplied screenshot report.
- Reason for missing control: UNKNOWN.
- Current removable-volume permission state: UNKNOWN.
- Permission readiness: UNKNOWN.
- Exact cause of prior `diskutil` failure: UNKNOWN.
- Cleanup success: UNKNOWN.
- Gate B: UNKNOWN and not validated.
- Settings change completion: NOT PROVEN.
- USB check: NOT AUTHORIZED.
- New one-run authorization: NOT GRANTED.

## Governance verdict

The expected narrow control was not shown, so permission readiness remains BLOCKED. The only proposed next step is collection of existing screenshot evidence plus non-mutating macOS and Terminal version context, subject to separate owner authorization. Full Disk Access, privacy reset, USB access, Terminal restart, and operational retry remain excluded.