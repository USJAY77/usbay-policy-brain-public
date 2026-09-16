# USBAY consumed-run post-failure review

## Status and scope

This record combines:

- owner-supplied pre-run and terminal evidence from the consumed one-run authorization;
- owner-supplied post-failure path metadata;
- the completed read-only call-order analysis of the unchanged reviewed script.

It does not authorize or perform a retry, USB access, permission change, installation, key creation, cleanup, deletion, directory-permission change, application restart, deployment, or production action.

## Authoritative references

- Authorized script: `attached_assets/usbay-age-preservation.zsh`
- Authorized script SHA-256: `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07`
- Reviewed operational decision: `attached_assets/usbay-final-operational-decision-for-owner-review.md`
- Reviewed operational decision SHA-256: `1ead9704a12213b74e070b04d5b9d0e097c95d171fb9cbe3c39e854696aef8a3`
- One-run authorization decision: `attached_assets/usbay-one-run-operational-authorization-decision.md`
- One-run authorization decision SHA-256: `a44a8ff497ef39b3e6a2c6a245ab5fb9aead043ca695e0b09ecfc3a182767098`

The one-run authorization was consumed when the script launched. No retry is authorized.

## Owner-supplied pre-run and terminal evidence

- Timestamp: `2026-09-16T16:56:33Z`
- Pre-run record: `/Users/jayceeiambella/usbay-preservation-pre-run-hash-2026-09-16T165633Z.txt`
- Script path: `/Users/jayceeiambella/usbay-age-preservation.zsh`
- Expected script SHA-256: `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07`
- Actual script SHA-256: `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07`
- Hash result: `HASH_MATCH=YES`

Observed operational output:

```text
Starting the single authorized interactive run.
BLOCKED: command failed or timed out (124): /usr/sbin/diskutil:
diskutil: interrupted
operational_exit_status=1
```

Later shell output:

```text
Saving session...shell_session_save:9:
shell_session_save_user_state_functions: parameter not set
```

An immediate additional exit-status check returned `1`.

Bounded conclusion:

- internal `/usr/sbin/diskutil` command status: `124`;
- overall script exit status: `1`;
- run result: FAILED;
- Gate B result: UNKNOWN;
- no successful recovery result is evidenced.

Internal status `124` must not be conflated with overall script exit `1`. The script’s bounded-command wrapper reports the internal nonzero status, raises a blocking exception, and the outer operational exception handler exits `1`.

The evidence does not establish whether internal status `124` was produced by the supervisor timeout path or was an exit code returned by `diskutil`.

## Owner-supplied post-failure metadata

Inspection-time results:

| Path | Reported result | Mode | UID | GID | `stat` exit |
|---|---|---:|---:|---:|---:|
| `/Users/jayceeiambella` | directory | `0750` | `501` | `20` | `0` |
| `/Users/jayceeiambella/.config` | directory | `0751` | `501` | `20` | `0` |
| `/Users/jayceeiambella/.config/age` | `No such file or directory` | NOT_APPLICABLE | NOT_APPLICABLE | NOT_APPLICABLE | `1` |
| `/Users/jayceeiambella/.config/age/usbay-preservation-identity.txt` | `No such file or directory` | NOT_APPLICABLE | NOT_APPLICABLE | NOT_APPLICABLE | `1` |
| `/Users/jayceeiambella/.config/age/usbay-preservation-recipient.txt` | `No such file or directory` | NOT_APPLICABLE | NOT_APPLICABLE | NOT_APPLICABLE | `1` |
| `/Users/jayceeiambella/USBAY-Preservation-Evidence` | `No such file or directory` | NOT_APPLICABLE | NOT_APPLICABLE | NOT_APPLICABLE | `1` |

No symlink-stop message occurred.

These results establish the reported path state at inspection time only. They do not prove that no earlier mutation occurred.

The existing `.config` mode `0751` does not itself contradict the reviewed script. The script requires an existing `.config` to be a non-symlink directory but does not automatically change its mode or require mode `0700`. The mode-`0700` requirement applies to `.config/age` if that directory exists.

## Completed script call-order analysis

The reviewed script performs the following operational `diskutil` phases:

1. initial USB discovery and information collection at script line 650;
2. USB reidentification before creating the USB recovery directory at line 706;
3. USB reidentification before encrypting to the USB at line 711;
4. whole-device eject at line 717;
5. post-reconnect USB discovery and information collection at line 719.

The collection helper invokes:

- `diskutil list -plist external physical` at lines 361–363;
- one or more `diskutil info -plist /dev/<identifier>` calls at lines 363–368.

The blocking error formatter records the executable path, `/usr/sbin/diskutil`, but not the complete argument vector. Therefore the exact `diskutil` subcommand is not established.

### Mutations required before later phases

Before the line-706 reidentification, the script must already have created:

- `~/USBAY-Preservation-Evidence`;
- a unique evidence run directory;
- `results.txt`.

It could also already have:

- installed Homebrew `age`;
- retained installation stdout, stderr, and receipt;
- completed the harmless tooling round trip;
- created `.config/age`;
- published the primary identity;
- created the public recipient.

Those operations occur at script lines 665–705.

Before the line-711 reidentification, the line-706 prerequisites above must already have occurred, and the script must also have created the unique USB recovery directory at line 707.

Before the line-717 eject, the script must also have attempted or completed USB encryption and written the public recipient, recovery instructions, manifest, and recorded hashes at lines 712–716.

Before the line-719 post-reconnect discovery, all preceding local and USB effects could already exist, and the USB eject and owner reconnect checkpoint would have occurred.

## Failure-phase assessment

### Supported inference

**Initial USB discovery at script line 650 is the supported failure-phase inference.**

Reasons:

1. The reported blocking command was `/usr/sbin/diskutil`.
2. The initial USB discovery at line 650 occurs before creation of `~/USBAY-Preservation-Evidence` at lines 665–668.
3. Every later operational `diskutil` phase requires that evidence root and unique evidence directory to have been created first.
4. Post-failure metadata reported `~/USBAY-Preservation-Evidence` absent.
5. Post-failure metadata also reported `.config/age`, the primary identity, and the recipient absent.
6. The existing `.config` path was a directory, and no symlink-stop message occurred, which is consistent with the script reaching the initial USB-discovery phase after its local path checks.

The evidence therefore supports failure during the initial line-650 `collect_usb()` phase, before script-created evidence, installation, key creation, or USB writes.

### Assumptions required for that inference

This is an inference, not direct proof. It depends on all of the following:

- the post-failure `stat` commands examined the same owner home directory used by the authorized script;
- the reported path results are complete and accurate;
- no process or person created and then removed the evidence root, `.config/age`, identity, or recipient between the failure and metadata inspection;
- no external cleanup, rollback, filesystem restoration, or path substitution occurred;
- the unchanged reviewed script followed the analyzed control flow;
- the terminal transcription contains the relevant blocking output;
- the absence of a symlink-stop message reflects the observed run output but does not independently prove every earlier check passed.

Because the owner explicitly states that reported absence at inspection time does not prove no earlier mutation, earlier mutation and later removal remain logically possible but are not evidenced.

### Unsupported conclusions

The available evidence does not establish:

- whether the failing initial call was `diskutil list` or a particular `diskutil info`;
- whether the macOS permission prompt was allowed, denied, dismissed, or remained pending until interruption;
- whether permission handling caused the command result;
- whether internal status `124` represents a supervisor timeout or a `diskutil` exit code;
- the exact timeout or interruption cause;
- process-group or descendant cleanup success;
- universal absence of any transient or externally removed partial change;
- USB contents or USB filesystem state;
- successful Gate B validation.

## Current evidence disposition

- Pre-run script hash match: PROVEN from owner-supplied record.
- Authorized script launch: PROVEN from owner-supplied terminal evidence.
- One-run authorization consumption: PROVEN.
- Internal `diskutil` status: PROVEN as `124`.
- Overall script exit: PROVEN as `1`.
- Post-failure home-directory metadata: PROVEN as owner-supplied evidence at inspection time.
- Post-failure `.config` metadata: PROVEN as owner-supplied evidence at inspection time.
- Post-failure absence of `.config/age`, identity, recipient, and evidence root: PROVEN only at inspection time.
- Initial USB-discovery failure phase: PARTIAL; supported inference subject to the stated assumptions.
- Exact `diskutil` subcommand: UNKNOWN.
- Permission outcome: UNKNOWN.
- Exact timeout or interruption cause: UNKNOWN.
- Cleanup success: UNKNOWN.
- Earlier transient mutation followed by removal: UNKNOWN.
- Gate B: UNKNOWN and not validated.
- Retry: NOT AUTHORIZED.

## Governance verdict

The strongest supported explanation is that the consumed run failed during initial USB discovery at script line 650, before the reviewed script’s first durable mutation. This remains a PARTIAL inference rather than PROVEN phase identification because the post-failure absence evidence is time-bounded and cannot exclude earlier mutation followed by unobserved removal. No retry or further operational action is authorized.