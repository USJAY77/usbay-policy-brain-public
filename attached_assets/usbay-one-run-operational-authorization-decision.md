# USBAY one-run operational authorization decision

## Decision provenance

- Decision date: `2026-09-16`
- Exact decision time: UNKNOWN
- Decision source: direct owner instruction
- Reviewed operational decision: `attached_assets/usbay-final-operational-decision-for-owner-review.md`
- Reviewed operational decision SHA-256: `1ead9704a12213b74e070b04d5b9d0e097c95d171fb9cbe3c39e854696aef8a3`
- Authorized script SHA-256: `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07`
- Custody-approval decision: `attached_assets/usbay-custody-approval-decision.md`
- Custody-approval decision SHA-256: `0ec2cf05f537d94abffdeb7b0d133a0f1c9b188c8cfdc7cf27855deac6fc2d69`

The reviewed decision, authorized script, and custody-approval decision matched these hashes before this authorization record was created.

## Owner authorization

The owner explicitly adopts the complete **Exact proposed authorization wording** section of the reviewed operational decision identified by SHA-256 `1ead9704a12213b74e070b04d5b9d0e097c95d171fb9cbe3c39e854696aef8a3`.

This authorizes exactly one owner-executed interactive Mac run of the unchanged reviewed script with SHA-256 `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07`.

All prerequisites, human checkpoints, stop conditions, retained partial-state consequences, evidence requirements, and exclusions in the reviewed operational decision apply unchanged. The approved custody arrangement remains in effect.

## Exact adopted authorization wording

> I authorize exactly one interactive operational run on my owner-controlled Mac of `usbay-age-preservation.zsh` with SHA-256 `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07`, using my selected SanDisk ExFAT USB, solely to establish and validate the described age recovery-identity arrangement.
>
> I authorize the bounded effects stated in `attached_assets/usbay-final-operational-decision-for-owner-review.md`: the script’s current-state preflight checks; one Homebrew forced-bottle installation of official `homebrew/core` age 1.3.2; the harmless tooling round trip; creation of the exact local primary identity and public recipient; creation and use of one unique USB recovery directory; interactive passphrase-protected encryption of the identity to that directory; writing the stated public files and manifest; USB synchronization, eject, reconnect, reidentification, exact-content and hash verification; and the bounded synthetic recovery challenge using exactly one explicit USB identity.
>
> I confirm that the custody approval recorded in `attached_assets/usbay-custody-approval-decision.md` with SHA-256 `0ec2cf05f537d94abffdeb7b0d133a0f1c9b188c8cfdc7cf27855deac6fc2d69` remains in effect. I understand that the local identity is unencrypted, screen locking does not make it inaccessible to processes already running under my logged-in account, no Time Machine destination was configured in the retained evidence, and there is an interval before USB recovery validation during which the local identity may exist without a validated USB recovery copy.
>
> I accept all stated stop conditions and retained partial-state consequences. A failed, interrupted, status-125, ambiguous, or owner-declined run stops without automatic retry. I understand that Homebrew age, the local identity and recipient, local evidence, or partial USB files may remain after failure, and that partial USB files do not constitute recovery coverage.
>
> This authorization is for exactly one run. It does not authorize a retry, settings changes, archive creation or other archive work, Linux restoration, source removal, permission broadening, sudo, app or workflow restart, commit, push, PR, merge, publication, deployment, production action, or any operation outside the stated recovery-identity run.

## Authorization boundary

This authorization:

- is limited to one owner-executed interactive Mac run;
- is unconsumed until the authorized script is actually launched;
- is consumed when that one operational launch occurs, regardless of success, failure, interruption, or owner-declined checkpoint;
- does not authorize Replit to execute the procedure;
- does not authorize a second launch or retry;
- does not authorize any action excluded by the adopted wording or reviewed operational decision.

No passphrase or precise paper-storage location may be entered into chat or retained in digital evidence.

## Immediate pre-run requirement

The authorized launch remains blocked until the owner performs the immediately pre-run hash verification on the Mac and it reports the exact authorized hash.

The hash record must retain:

- UTC timestamp;
- exact script path;
- hash command;
- expected SHA-256;
- actual SHA-256;
- match result.

A mismatch, missing file, symlink, hash-command failure, evidence-record creation failure, or any other error blocks launch and does not authorize a retry or alternative script.

## Exact Mac hash-verification and launch instructions

Prerequisites before entering the commands:

- the unchanged reviewed script is present at `$HOME/usbay-age-preservation.zsh`;
- the selected SanDisk ExFAT USB is connected;
- the approved locked paper-storage arrangement is available and physically separate from the USB;
- the owner is present for every interactive checkpoint;
- no passphrase is placed in these commands, chat, a file, or a command argument.

In a new Terminal window on the owner-controlled Mac, paste the following block exactly:

```zsh
(
  set -eu
  setopt NO_CLOBBER
  umask 077

  SCRIPT="$HOME/usbay-age-preservation.zsh"
  EXPECTED_SHA256="d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07"

  if [[ ! -f "$SCRIPT" || -L "$SCRIPT" ]]; then
    /usr/bin/printf 'BLOCKED: reviewed script is missing, not a regular file, or is a symlink: %s\n' "$SCRIPT" >&2
    exit 125
  fi

  TIMESTAMP_UTC=$(/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')
  RECORD_TIMESTAMP=${TIMESTAMP_UTC//:/}
  HASH_RECORD="$HOME/usbay-preservation-pre-run-hash-${RECORD_TIMESTAMP}.txt"
  HASH_COMMAND="/usr/bin/shasum -a 256 -- $SCRIPT"
  ACTUAL_SHA256=$(/usr/bin/shasum -a 256 -- "$SCRIPT" | /usr/bin/awk '{print $1}')

  {
    /usr/bin/printf 'TIMESTAMP_UTC=%s\n' "$TIMESTAMP_UTC"
    /usr/bin/printf 'SCRIPT_PATH=%s\n' "$SCRIPT"
    /usr/bin/printf 'HASH_COMMAND=%s\n' "$HASH_COMMAND"
    /usr/bin/printf 'EXPECTED_SHA256=%s\n' "$EXPECTED_SHA256"
    /usr/bin/printf 'ACTUAL_SHA256=%s\n' "$ACTUAL_SHA256"
    if [[ "$ACTUAL_SHA256" == "$EXPECTED_SHA256" ]]; then
      /usr/bin/printf 'HASH_MATCH=YES\n'
    else
      /usr/bin/printf 'HASH_MATCH=NO\n'
    fi
  } > "$HASH_RECORD"

  /bin/chmod 600 "$HASH_RECORD"
  /usr/bin/printf 'Pre-run hash evidence: %s\n' "$HASH_RECORD"
  /bin/cat "$HASH_RECORD"

  if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
    /usr/bin/printf 'BLOCKED: script SHA-256 mismatch; operational launch not started.\n' >&2
    exit 125
  fi

  /usr/bin/printf 'Hash verified. Starting the single authorized interactive run.\n'
  USBAY_RECOVERY_SETUP_AUTHORIZED=YES /bin/zsh -f "$SCRIPT"
)
```

The block:

1. runs in a subshell so a blocked preflight does not close the Terminal window;
2. refuses a missing, non-regular, or symlink script path;
3. calculates SHA-256 with macOS `/usr/bin/shasum`;
4. creates one mode-0600 pre-run hash record in the owner’s home directory without overwriting an existing file;
5. displays the retained record;
6. exits with status 125 before launch on any hash mismatch;
7. sets `USBAY_RECOVERY_SETUP_AUTHORIZED=YES` only for the one script process;
8. invokes the reviewed script through its reviewed interpreter command, `/bin/zsh -f`;
9. does not run `--self-test`;
10. does not authorize or perform a retry.

The pre-run hash record may remain after failure and must be retained with the operational evidence. Its creation is part of satisfying the authorized pre-run evidence prerequisite; it does not broaden the authorized operational scope.

## Human authority during the run

Authorization does not require the owner to approve any interactive checkpoint. The owner may decline any prompt. A decline stops the run and consumes the one-run authorization.

The owner must:

- review the displayed USB identity, top-level names and types, evidence location, age version, bottle tag, and bottle hash before the first confirmation;
- review the installation result and harmless tooling round trip before authorizing real identity creation at the second confirmation;
- create and store the paper passphrase only at the script’s checkpoint;
- enter the passphrase only through the interactive prompt;
- reconnect the same USB when instructed.

No failed technical check can be overridden by owner confirmation.

## Post-launch decision boundary

Once the script is launched:

- the one-run authorization is consumed;
- success does not authorize archive work, source removal, settings changes, restart, deployment, production action, or another run;
- failure, interruption, status 125, ambiguity, or a declined checkpoint does not authorize retry;
- retained evidence must be reviewed before any new lifecycle decision;
- partial outputs must not be treated as complete recovery coverage.

## Current governance disposition

- Policy clarification: ADOPTED.
- Custody approval: GRANTED for the exact recorded arrangement and qualifications.
- One-run operational authorization: GRANTED by explicit owner decision.
- Authorized executor and environment: owner on the owner-controlled Mac only.
- Authorization consumption: UNCONSUMED; no operational launch is evidenced.
- Immediate pre-run Mac hash verification: REQUIRED and NOT YET EVIDENCED.
- Operational run: NOT EXECUTED by Replit.
- Retry: NOT AUTHORIZED.
- Gate B result: NOT_APPLICABLE before the authorized run.
- Archive work: NOT AUTHORIZED.
- Source removal: BLOCKED and NOT AUTHORIZED.
- Settings changes: NOT AUTHORIZED.
- Application restart: NOT AUTHORIZED.
- Deployment and production action: NOT AUTHORIZED.

## Governance verdict

Exactly one owner-executed interactive Mac run is authorized, subject to the unchanged prerequisites and fail-closed immediate hash verification. No evidence currently establishes that the authorization has been consumed or that any operational effect has occurred. Replit must not execute the procedure.