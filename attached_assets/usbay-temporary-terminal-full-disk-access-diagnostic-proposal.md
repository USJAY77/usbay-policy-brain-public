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

### Full Disk Access necessity remains UNKNOWN

Apple documents:

- **Files and folders**, including removable volumes, as one privacy category;
- **Full Disk Access** as a broader category allowing an app to access all files on the computer, including other apps’ data, Time Machine backup data, and certain administrative settings.

The reviewed preservation operation requires access to identify and later use one selected removable USB. No evidence establishes a requirement to access all internal files, other apps’ protected data, Time Machine backups, or administrative settings.

Therefore:

- **Full Disk Access necessity remains UNKNOWN; it is not established as necessary by the available evidence.**
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

### 4. Exact reviewable launcher

The reviewable launcher is:

- File: `attached_assets/usbay-fda-readonly-diskutil-diagnostic.zsh`
- SHA-256: `b19bd48a797b3f5659c6fb850d4baff1792c6c73153bfec13b4eb6f5976f320b`
- Size: 17,394 bytes
- Lines: 515

The launcher contains one fixed child command:

`/usr/sbin/diskutil list -plist external physical`

It accepts no arguments. It also requires the technical runtime gate:

`USBAY_FDA_DIAGNOSTIC_AUTHORIZED=YES`

That environment value does not constitute human authority and does not enforce one-run replay protection.

The owner-review launch block is:

```zsh
diagnostic_path="$HOME/usbay-fda-readonly-diskutil-diagnostic.zsh"
expected_diagnostic_sha256="b19bd48a797b3f5659c6fb850d4baff1792c6c73153bfec13b4eb6f5976f320b"
/usr/bin/python3 - "$diagnostic_path" "$expected_diagnostic_sha256" <<'PY'
import hashlib
import os
import stat
import sys
import tempfile

path,expected=sys.argv[1:]
flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)
try:
    source_fd=os.open(path,flags)
except OSError as error:
    print('DIAGNOSTIC_BLOCKED=source-open-failed',flush=True)
    print('DIAGNOSTIC_SOURCE_ERROR_TYPE='+type(error).__name__,flush=True)
    raise SystemExit(66)
try:
    source_stat=os.fstat(source_fd)
    if not stat.S_ISREG(source_stat.st_mode):
        print('DIAGNOSTIC_BLOCKED=source-not-regular',flush=True)
        raise SystemExit(66)
    if source_stat.st_uid!=os.getuid():
        print('DIAGNOSTIC_BLOCKED=source-not-owner-controlled',flush=True)
        raise SystemExit(66)
    if stat.S_IMODE(source_stat.st_mode)&0o022:
        print('DIAGNOSTIC_BLOCKED=source-group-or-other-writable',flush=True)
        raise SystemExit(66)
    chunks=[]
    digest=hashlib.sha256()
    while True:
        chunk=os.read(source_fd,1<<20)
        if not chunk:
            break
        chunks.append(chunk)
        digest.update(chunk)
finally:
    os.close(source_fd)

actual=digest.hexdigest()
print('diagnostic_expected_sha256='+expected,flush=True)
print('diagnostic_actual_sha256='+actual,flush=True)
if actual!=expected:
    print('DIAGNOSTIC_BLOCKED=hash-mismatch',flush=True)
    raise SystemExit(65)

verified_bytes=b''.join(chunks)
stage=tempfile.TemporaryFile()
written=stage.write(verified_bytes)
stage.flush()
if written!=len(verified_bytes):
    print('DIAGNOSTIC_BLOCKED=verified-byte-stage-short-write',flush=True)
    raise SystemExit(74)
stage.seek(0)
stage_fd=stage.fileno()
os.set_inheritable(stage_fd,True)
environment=os.environ.copy()
environment['USBAY_FDA_DIAGNOSTIC_AUTHORIZED']='YES'
print('DIAGNOSTIC_VERIFIED_BYTES_EXECUTION=anonymous-file-descriptor',flush=True)
try:
    os.execve(
        '/bin/zsh',
        ['/bin/zsh','-f',f'/dev/fd/{stage_fd}'],
        environment,
    )
except OSError as error:
    print('DIAGNOSTIC_BLOCKED=verified-launch-failed',flush=True)
    print('DIAGNOSTIC_LAUNCH_ERROR_TYPE='+type(error).__name__,flush=True)
    raise SystemExit(69)
PY
diagnostic_launcher_exit_status=$?
/usr/bin/printf 'diagnostic_launcher_exit_status=%s\n' "$diagnostic_launcher_exit_status"
```

The verifier opens the source without following a final symlink, requires an owner-controlled regular file that is not group- or other-writable, hashes the bytes read, copies only those exact verified bytes into an anonymous temporary file, and executes zsh through the already-open anonymous file descriptor. It does not hash one pathname and later reopen that pathname for execution.

This block and launcher are review material only. Saving the launcher on the Mac, enabling Full Disk Access, quitting or reopening Terminal, and executing this block all require later explicit authority.

### 5. Enforced deadline, termination, and reaping

The launcher enforces the deadline programmatically. It does not rely on a manual timer.

It:

1. starts the fixed `diskutil` command with `subprocess.Popen(..., start_new_session=True)`;
2. waits with `child.wait(timeout=15)`;
3. on deadline expiry, sends `SIGTERM` to the child process group;
4. waits up to two seconds for the group to disappear and the direct child to be reaped;
5. if needed, sends `SIGKILL` to the process group;
6. waits up to another two seconds;
7. separately attempts direct-child termination and reaping if group cleanup does not complete;
8. emits a structured `SUPERVISOR_DIAGNOSTIC` record describing group probes, signal outcomes, child status, and cleanup result.

After the child exits, times out, or is interrupted, the one-shot launcher:

- blocks `SIGINT`, `SIGTERM`, and `SIGHUP`;
- installs non-raising latch handlers;
- drains pending watched signals into the structured record before final status classification;
- keeps those watched signals blocked through evidence emission;
- exits without restoring the old handlers or prior signal mask.

This deliberate one-shot behavior avoids delivering a queued cleanup-time signal to an old or default handler before evidence is emitted. It changes signal handling only inside the diagnostic launcher process, which exits after printing the result.

Catchable probe and drain exceptions remain on the normal evidence path:

- a fallback child-status probe failure while cleanup is already being established makes cleanup unproven and returns `125`;
- a post-wait group or child-status probe exception returns `70` if subsequent bounded cleanup is reported clean, otherwise `125`;
- a pending-signal drain exception makes cleanup/finalization unproven and returns `125`.

Each case records the exception in the trace and continues through normal timing, stream, bounded-reason, and supervisor evidence emission.

Status meanings:

- `0`: the child exited `0`, stdout parsed as a property list, and `AllDisksAndPartitions` was a list;
- `2`: `diskutil` exited `0`, but stdout failed property-list validation;
- `64`, `69`, or `77`: launcher precondition or technical-gate block;
- `65`, `66`, or `74`: verified-launch block due to hash, source-integrity, or staging failure;
- `70`: launcher exception where cleanup was reported clean or no child was spawned;
- `124` with `DIAGNOSTIC_BOUNDED_REASON=timeout-clean`: the 15-second deadline expired and the supervisor reported clean termination and reaping;
- `124` with `DIAGNOSTIC_BOUNDED_REASON=child-exit`: `diskutil` itself exited `124`; this is not an enforced-timeout result;
- `125` with a reason containing `cleanup-unproven`: cleanup is UNKNOWN;
- `125` with `DIAGNOSTIC_BOUNDED_REASON=descendant-cleaned`: descendants were detected after direct-child exit and cleanup was reported clean, but continuation remains blocked;
- `125` with `DIAGNOSTIC_BOUNDED_REASON=child-exit`: `diskutil` itself exited `125`; cleanup was not required merely because of that child status, but the diagnostic failed and continuation remains blocked;
- any other `125`: unclassified and blocked;
- `128+signal`: launcher interruption where process-group cleanup was reported clean;
- any other nonzero child status: propagated child failure.

For any status `125`:

- interpret `DIAGNOSTIC_BOUNDED_REASON` and `SUPERVISOR_DIAGNOSTIC` together;
- do not label child exit `125` as cleanup unproven;
- do not claim cleanup success unless the structured record specifically reports outcome `clean`;
- if the reason contains `cleanup-unproven`, cleanup remains UNKNOWN;
- revoke Full Disk Access immediately;
- retain the output;
- do not retry, probe processes, clean up, or continue.

On all outcomes, including launcher exception, timeout, interruption, invalid output, or status `125`, the manual Full Disk Access revocation instructions below remain controlling and available.

### 6. One bounded read-only diagnostic

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

The launcher captures:

- exact UTC start and end times;
- elapsed milliseconds;
- internal status;
- bounded-result reason;
- stdout and stderr lengths;
- stdout and stderr SHA-256 hashes;
- base64-encoded stdout and stderr;
- property-list validation;
- discovered external physical disk identifiers;
- structured supervisor and cleanup evidence.

It uses anonymous temporary files for command stdout and stderr. It does not create a retained evidence file, invoke `diskutil info`, list mounted directories, or open USB file contents.

If child spawn, signal handling, group probing, or cleanup raises internally, the launcher blocks signals during exception cleanup, records the exception type, attempts bounded cleanup when a child exists, and returns:

- `128+signal` if an observed launcher signal is paired with cleanup reported clean;
- `125` if exception-path cleanup is unproven;
- `70` if a non-signal launcher exception occurs and cleanup is reported clean or no child was spawned.

These paths still emit command timing, stream hashes and base64, bounded reason, and the structured supervisor record before the launcher exits.

No second attempt is permitted.

### 7. Maximum Full Disk Access exposure window

Terminal Full Disk Access may remain ON for no longer than five minutes measured from the recorded enable time.

The diagnostic must not start unless there is enough time to:

- perform the single 15-second attempt;
- record the result;
- return to System Settings;
- turn Terminal Full Disk Access OFF before the five-minute deadline.

If any delay threatens the deadline, skip or stop the diagnostic and revoke Full Disk Access.

### 8. Success criteria

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

### 9. Failure and inconclusive criteria

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

## Revocation remains required after every outcome

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

- Full Disk Access necessity: UNKNOWN; it is not established as necessary by the available evidence.
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

Full Disk Access necessity remains UNKNOWN; it is not established as necessary by the available evidence. It is broader than the identified need and defensible only as a separately authorized, last-resort diagnostic workaround with the exact reviewed launcher, one programmatically enforced 15-second read-only `diskutil list` attempt, a five-minute maximum exposure window, one controlled Terminal quit/reopen before testing, immediate revocation after every outcome, and no operational execution. Success would not prove necessity or authorize another run.