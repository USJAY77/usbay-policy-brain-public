# USBAY macOS Tahoe Storage-settings permission proposal

## Status and authority

- Status: PROPOSED
- Settings inspection under this proposal: NOT AUTHORIZED
- Settings change under this proposal: NOT AUTHORIZED
- Full Disk Access: OFF and NOT AUTHORIZED
- Privacy reset: NOT AUTHORIZED
- USB access or check: NOT AUTHORIZED
- Terminal restart or relaunch: NOT AUTHORIZED
- `diskutil` execution: NOT AUTHORIZED
- Preservation-script run: NOT AUTHORIZED
- Installation, key creation, USB writes, cleanup, and deletion: NOT AUTHORIZED

This proposal identifies a supported Apple-documented next step. It does not itself authorize that step.

## Reused owner-supplied evidence

- Mac management: owner reports that the Mac is personally managed.
  - This is owner testimony.
  - It does not prove that management profiles are absent.
- macOS: Tahoe 26.6.2.
- Exact macOS build: UNKNOWN.
- Terminal: Version 2.15 (470.2).
- Terminal Full Disk Access: displayed OFF in the existing screenshot.
- Terminal Removable Volumes control: not displayed in the existing Files & Folders screenshot.
- Consumed-run prompt choice: owner selected **Don’t Allow**.
- Permission denial as the exact cause of the prior `diskutil` failure: UNKNOWN.
- Cleanup success: UNKNOWN.

The existing screenshots are reused. This proposal does not request them again.

## Apple-documented Tahoe route

Apple’s macOS Tahoe 26 guide, **Allow use of external and removable storage**, states:

- authorization can be granted by selecting **Allow** in the access dialog;
- denial can be selected with **Don’t Allow**;
- apps and websites allowed to use external and removable storage can be reviewed and changed in **Storage settings**;
- Storage settings are opened through:

  `Apple menu → System Settings → General → Storage`

Source:

- Apple Mac User Guide for macOS Tahoe 26, **Allow use of external and removable storage**: <https://support.apple.com/en-ca/guide/mac-help/mchl6f613f75/mac>

Related Apple sources:

- **Change Storage settings on Mac**: <https://support.apple.com/guide/mac-help/change-storage-settings-mchl3d437fbc/mac>
- **Control access to files and folders on Mac**: <https://support.apple.com/en-ca/guide/mac-help/mchld5a35146/mac>
- Apple Platform Security, **Controlling app access to files in macOS**: <https://support.apple.com/guide/security/controlling-app-access-to-files-secddd1d86a6/web>

The Tahoe-specific Storage-settings route is supported by Apple documentation. The missing Files & Folders control therefore does not by itself establish that no supported settings route exists.

## One bounded next-step proposal

Subject to a new explicit owner authorization, the owner may:

1. Open:

   `Apple menu → System Settings → General → Storage`

2. Locate only the Apple-described control for apps or websites using external and removable storage.

3. Confirm that the entry is specifically **Terminal**.

4. If and only if an explicit Terminal external/removable-storage control is displayed, change only that Terminal control from denied or off to allowed or on.

5. Leave Full Disk Access and every unrelated permission or Storage setting unchanged.

6. Record:
   - UTC timestamp;
   - macOS version `26.6.2`;
   - Terminal version `2.15 (470.2)`;
   - the exact displayed setting path and label;
   - the before and after state of the Terminal external/removable-storage control;
   - whether local authentication was requested;
   - whether the setting was accepted without an error.

7. Stop immediately after the setting is saved. Do not access the USB, run a permission check, restart Terminal, execute `diskutil`, or launch the preservation script.

### Stop condition

If General → Storage does not display an explicit Terminal control for external or removable storage:

- stop without changing anything;
- do not infer that another Storage switch is equivalent;
- do not use Full Disk Access;
- do not reset privacy controls;
- do not add or replace Terminal;
- do not recreate the USB prompt;
- do not restart Terminal;
- do not access the USB.

At that point, no further supported local route is established by the reviewed Apple documentation. The bounded next step would be human review or Apple Support guidance using the retained screenshots and version information, not permission broadening.

## Exact effects

### Opening General → Storage

Expected effect:

- displays Storage settings.

It does not itself authorize Terminal or access the USB.

### Enabling the explicit Terminal external/removable-storage control

Expected intended effect, based on Apple’s Tahoe guide:

- changes macOS’s stored decision for Terminal’s use of external and removable storage from denied or off to allowed or on.

Scope:

- app-level: Terminal;
- category-level: external and removable storage.

It is not evidenced as limited to:

- the preservation script;
- one USB;
- one volume;
- one directory;
- one command;
- one run;
- read-only operations.

### Effects not established

Changing the setting would not itself:

- access, enumerate, mount, read, or write the SanDisk USB;
- prove that `diskutil list` or `diskutil info` will succeed;
- prove that the previous denial caused the consumed-run failure;
- prove successful process cleanup;
- install `age`;
- create an identity or recipient;
- write recovery files;
- validate Gate B;
- authorize a read-only USB check;
- authorize another operational run.

Apple’s reviewed pages do not establish whether Terminal must be restarted or relaunched before the changed decision takes effect. Terminal restart or relaunch therefore remains excluded and no immediate effectiveness claim may be made.

## Persistence, revocation, and limitations

The setting is presented by Apple as a stored app access decision that can be reviewed and changed in Storage settings.

Exact persistence across logout, reboot, macOS update, Terminal update, privacy-database reset, or device-management changes is not specified by the reviewed Apple pages and remains UNKNOWN.

If the explicit Terminal control is later enabled, the supported revocation route is to return to:

`Apple menu → System Settings → General → Storage`

and turn off or deny only that same explicit Terminal external/removable-storage control.

Revocation would be a separate settings change requiring explicit owner authorization. Revocation would not:

- undo earlier access;
- delete files;
- uninstall software;
- prove termination of running processes;
- establish cleanup.

No Full Disk Access change, `tccutil` reset, privacy-database edit, or broader reset is proposed.

## Exact-build decision

The exact macOS build is not essential to the current decision because:

- the owner supplied the product version `macOS Tahoe 26.6.2`;
- Apple’s Tahoe 26 guide documents the Storage-settings route at the product-version level;
- no build-specific operation is proposed.

The exact build would become relevant if:

- the explicit control is also missing from General → Storage;
- the displayed behavior conflicts with Apple’s Tahoe guide;
- a build-specific defect, security update, or enterprise-management interaction must be investigated;
- Apple Support requests the build for diagnosis.

If the control is missing from General → Storage, the result remains BLOCKED even without the build. The build would support later diagnosis, not authorize a substitute permission.

## Separation of decisions

The following remain separate:

1. authorization to inspect General → Storage;
2. authorization to change the explicit Terminal external/removable-storage control;
3. authorization to perform a bounded read-only USB permission check;
4. authorization for one new operational run.

Approval of one does not imply another.

The previous authorization covered a specifically described Files & Folders toggle. Because that expected control was missing and the current message authorizes no settings change, this Tahoe Storage-settings route requires a new explicit owner decision before use.

The previous operational authorization remains consumed. Permission approval is not a new one-run authorization.

## Current evidence disposition

- Personally managed Mac: owner testimony; not proof that management profiles are absent.
- macOS product version: owner-reported `Tahoe 26.6.2`.
- Exact macOS build: UNKNOWN and not essential to the current route decision.
- Terminal version: owner-reported `2.15 (470.2)`.
- Full Disk Access displayed OFF: owner-supplied screenshot evidence.
- Removable Volumes absent in Files & Folders: owner-supplied screenshot evidence.
- Tahoe Storage-settings route: SUPPORTED by current Apple documentation.
- Terminal control actually present in General → Storage: UNKNOWN.
- Current Terminal external/removable-storage permission state: UNKNOWN.
- Settings change: NOT AUTHORIZED.
- USB check: NOT AUTHORIZED.
- Terminal restart: NOT AUTHORIZED.
- New one-run authorization: NOT GRANTED.
- Gate B: UNKNOWN and not validated.

## Governance verdict

A supported narrow route was found in Apple’s macOS Tahoe 26 documentation: review and change external/removable-storage app decisions in General → Storage. Use of that route is only PROPOSED and requires a new explicit owner authorization. If no explicit Terminal control appears there, stop; do not substitute Full Disk Access, a privacy reset, USB access, Terminal restart, or an operational retry.