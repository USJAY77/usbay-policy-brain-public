# USBAY final operational decision for owner review

## Status and authority

- Status: PROPOSED FOR OWNER REVIEW
- Operational authorization: NOT GRANTED
- Execution performed by this document: NONE
- Number of proposed runs: exactly one interactive Mac run
- Reviewed script: `attached_assets/usbay-age-preservation.zsh`
- Reviewed script SHA-256: `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07`

This document does not authorize or execute the proposed run. Only a later explicit owner instruction containing or unambiguously adopting the exact proposed authorization wording below can grant the bounded operational authorization.

## Authoritative retained records

- Existing operational proposal: `attached_assets/usbay-native-validation-and-operational-authorization-proposal.md`
- Existing operational proposal SHA-256: `9bba6f1e9d2f3b439b854709a60c8d599c8df444ea5a8637177cacf14a459fd1`
- Adopted policy proposal: `attached_assets/usbay-preservation-policy-clarification-proposal.md`
- Adopted policy proposal SHA-256: `41a2354506c61a5595420175b04839802d0ad5aaa8afdfb3be100ae6afcf8295`
- Policy-adoption decision: `attached_assets/usbay-policy-clarification-adoption-decision.md`
- Approved custody review: `attached_assets/usbay-consolidated-custody-review.md`
- Approved custody review SHA-256: `3222ba2ecee07056b068c969973808cbc3dd5a20b827576a1c94c96d3ca3cbf2`
- Custody-approval decision: `attached_assets/usbay-custody-approval-decision.md`
- Custody-approval decision SHA-256: `0ec2cf05f537d94abffdeb7b0d133a0f1c9b188c8cfdc7cf27855deac6fc2d69`
- Reviewed script SHA-256: `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07`

The reviewed script and approved custody review matched their recorded hashes while this decision was prepared.

The adopted Gate A/B/C clarification controls the current gate ordering. The older operational proposal’s pre-creation requirement for completed backup or recovery of a nonexistent identity is superseded by that adopted policy clarification. The bounded effects, runtime checks, failure handling, evidence requirements, and exclusions of the operational proposal remain the basis of this decision.

## Checks and decisions already completed

These matters are retained and must not be repeated absent new contradictory evidence:

1. **Native script self-test:** owner-supplied native evidence reported 41 PASS with exit status 0 for the exact reviewed script hash.
2. **Supervisor regressions:** the retained self-test evidence validated normal completion, timeout cleanup, orphan handling, ordinary and setup interruption, transient Darwin denial followed by authoritative absence, persistent-denial fail-closed behavior, direct-child liveness and reaping, and parent signal restoration.
3. **Effective local paths:** owner-supplied inspection reported the exact proposed paths and ancestors unchanged with no symlink redirection; the proposed `age` directory, primary identity, and evidence directory were absent.
4. **Documented iCloud Desktop & Documents applicability:** NOT_APPLICABLE to the proposed identity and evidence paths.
5. **Time Machine configuration:** both proposed paths and inspected ancestors returned `IsExcluded=0` at `2026-09-16T04:34:38Z`; no Time Machine destination was configured at `2026-09-16T04:38:14Z`.
6. **FileVault status:** `/usr/bin/fdesetup status` returned `FileVault is On.` with exit status 0 at `2026-09-16T04:49:34Z`.
7. **Separate paper storage:** the owner confirmed that locked, owner-controlled paper storage physically separate from the selected SanDisk USB is available.
8. **Custody:** the owner approved the complete custody arrangement in review SHA-256 `3222ba2ecee07056b068c969973808cbc3dd5a20b827576a1c94c96d3ca3cbf2`, with the retained FileVault evidence and corrected screen-locking and directory-permission wording.
9. **Policy ordering:** the owner adopted the exact Gate A, Gate B, Gate C, and cross-gate amendment.

These completed matters do not prove an operational result. They do not prove installation, identity creation, USB integrity, Gate B recovery validation, archive preservation, Linux restoration, source-removal safety, deployment, or production readiness.

The FileVault evidence proves only the recorded status at its timestamp. Screen locking does not make the mounted identity inaccessible to processes already running under the logged-in owner account.

The directory guarantee is bounded: if `~/.config` is absent, the script creates it as mode 0700 only after confirmation; an existing `~/.config` is not automatically changed to mode 0700. The script creates `~/.config/age` as mode 0700 if absent and refuses an existing directory with another mode. The primary identity is published as mode 0600.

## Prerequisites for the one proposed run

Every prerequisite below must hold. Missing, changed, stale, conflicting, ambiguous, unsupported, or failed prerequisites block the run.

1. The owner must issue a new explicit operational authorization for exactly one interactive run. This document and the environment-variable gate are not authorization.
2. Immediately before execution on the Mac, a read-only hash command must establish that the executable script file hashes exactly to `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07`. The command, path, hash, and timestamp must be retained.
3. The exact approved custody arrangement and adopted policy ordering must remain in effect without new contradictory evidence.
4. The run must occur on the owner-controlled Mac using the owner-selected SanDisk ExFAT USB.
5. The owner must be present for all interactive checkpoints, USB reconnection, passphrase entry, and decisions.
6. The locked paper-storage arrangement must remain available and physically separate from the USB.
7. The passphrase must not be entered into chat, command arguments, files, logs, or digital evidence.
8. The runtime environment gate must be exactly `USBAY_RECOVERY_SETUP_AUTHORIZED=YES`.
9. The script’s preflight must pass every current-state technical check listed below.
10. No unrelated operation may be combined with this one run.

The retained custody approval accepts the recorded no-Time-Machine-destination configuration and the interval before Gate B. It does not claim backup completion, retention, backup encryption, or recoverability.

## Complete bounded effects of one authorized run

If, and only if, the owner separately authorizes the run and every gate passes, the unchanged reviewed script would:

1. Require macOS and the exact environment authorization gate `USBAY_RECOVERY_SETUP_AUTHORIZED=YES`.
2. Refuse existing primary or recipient destination paths, symlinks, unsafe directories, unsupported architecture or macOS combinations, missing Homebrew, an existing Homebrew `age`, changed formula metadata, or an unrecognized USB identity.
3. Identify the selected external physical USB and record its identifiers, mount, media identity, size, free space, and top-level entries.
4. Create a unique owner-only evidence directory under `~/USBAY-Preservation-Evidence/`.
5. Display the evidence location, USB identity, visible top-level USB contents, reviewed age version, bottle tag, and reviewed bottle SHA-256.
6. Pause for interactive owner confirmation before installation or key creation.
7. Run one Homebrew forced-bottle installation of official `homebrew/core` age 1.3.2 with auto-update, cleanup, and upgrade suppression passed to the child process.
8. Retain Homebrew installation stdout, stderr, result status, and installed receipt; validate age 1.3.2 and `poured_from_bottle=true`.
9. Run a harmless temporary age encryption and decryption round trip before creating the real identity.
10. Pause for a second interactive owner confirmation before real key creation.
11. Create `~/.config` as mode 0700 only if it is absent and the owner confirms creation; do not automatically change an existing `~/.config`.
12. Create `~/.config/age` as mode 0700 only if absent; refuse an existing directory with any other mode rather than changing it.
13. Generate the primary identity in a unique owner-only staging directory on the destination filesystem.
14. Publish the primary identity exclusively to `~/.config/age/usbay-preservation-identity.txt` as mode 0600 without replacing an existing path.
15. Derive and exclusively create `~/.config/age/usbay-preservation-recipient.txt`.
16. Reidentify the same USB before creating a unique `USBAY-Recovery-<random>` directory.
17. Instruct the owner to create a fresh paper passphrase of at least seven independently selected Diceware words and keep it locked, owner-controlled, and physically separate from the USB.
18. Pause for explicit owner confirmation that the paper passphrase has been created and stored.
19. Reidentify the same USB again and require the new recovery directory to remain empty before encryption.
20. Interactively encrypt the primary identity to `usbay-preservation-identity.txt.age` on the USB.
21. Write only the public recipient, recovery instructions, and SHA-256 manifest alongside the encrypted identity on the USB.
22. Record USB file hashes in the local evidence record.
23. Synchronize and eject the selected whole USB device.
24. Pause for the owner to reconnect the same USB.
25. Reidentify the USB, verify exact recovery-directory contents, compare the public recipient, and verify all recorded hashes.
26. Run a bounded synthetic recovery challenge using exactly one explicit USB identity and without referencing the Mac primary identity.
27. Record the recovery result and synthetic challenge hashes, then remove only the temporary synthetic challenge files.

## Checks performed during the authorized run

The following are current-state technical checks performed by the unchanged script during the run. They are not replacements for the completed self-test, custody, policy, path, copying-configuration, or FileVault evidence above.

The script checks:

- the authorization environment gate is exactly `USBAY_RECOVERY_SETUP_AUTHORIZED=YES`;
- the platform is macOS;
- the primary identity and recipient destinations do not already exist and are not symlinks;
- `~/.config` and `~/.config/age` have acceptable path types and symlink status;
- any existing `~/.config/age` directory is mode 0700;
- Homebrew exists at a supported executable path;
- Homebrew reports that `age` is not already installed;
- the machine architecture and macOS major version map to a reviewed bottle tag;
- downloaded Homebrew formula metadata matches the locked formula name, tap, age version, dependency expectation, bottle tag, and bottle SHA-256;
- exactly one qualifying external physical USB is identified;
- required USB identifiers, parent relationship, filesystem, mount, writability, media identity, size, and free-space conditions match the script’s constraints;
- USB identity and physical characteristics remain consistent at every reidentification point;
- the newly created USB recovery directory is empty before encrypted-identity writing;
- post-install receipt data identifies age 1.3.2 and reports `poured_from_bottle=true`;
- the harmless tooling round trip succeeds before real identity creation;
- reconnect identity, exact recovery-directory contents, recipient equality, recorded hashes, and the bounded synthetic recovery challenge succeed.

A human confirmation cannot override a failed script check.

## Human checkpoints during the run

The owner retains authority at every checkpoint:

1. **Before installation or key creation:** review the displayed evidence location, USB identity, visible top-level USB contents, age version, bottle tag, and bottle SHA-256; decline if any item is unrecognized or unacceptable.
2. **Before real key creation:** explicitly confirm or decline after the Homebrew installation result and harmless tooling round trip are available.
3. **Paper passphrase checkpoint:** create a fresh passphrase of at least seven independently selected Diceware words, store it in the approved locked paper arrangement physically separate from the USB, and confirm only that creation and storage are complete.
4. **Interactive encryption:** enter the passphrase only through the script’s interactive prompt; never disclose it in chat, command arguments, files, logs, or evidence.
5. **USB reconnect checkpoint:** physically reconnect the selected USB after the script synchronizes and ejects it so the script can reidentify and validate it.

The owner may decline any prompt. A declined prompt stops the run and does not authorize a retry.

## Stop conditions

The run stops on any:

- command failure;
- timeout;
- denied or unproven process-group cleanup;
- status 125;
- USB identity or physical-characteristic change;
- missing or ambiguous qualifying USB;
- hash mismatch;
- Homebrew receipt or formula-metadata mismatch;
- unsafe, redirected, unexpected, or existing destination path;
- unsupported platform, architecture, or macOS combination;
- unacceptable existing directory mode;
- nonempty new USB recovery directory before encryption;
- reconnect, exact-content, recipient-equality, file-hash, or recovery-challenge failure;
- owner-declined checkpoint;
- missing, changed, ambiguous, or contradictory prerequisite.

Status 124 is accepted only when timeout cleanup is proven.

Status 125 always blocks continuation. Evidence must distinguish whether cleanup remained unproven or descendants were detected after the direct child exited and were successfully cleaned. The latter is still an abnormal outcome and still blocks continuation. If the evidence cannot distinguish the case, its meaning remains UNKNOWN.

Direct-child termination or reaping does not prove descendant cleanup. Interruption status such as 143 is returned only when cleanup is proven.

There is no automatic retry. Any later retry requires review of retained evidence and a new explicit authorization.

## Retained partial-state behavior

The owner has approved these custody consequences, but they remain operational risks:

- Homebrew age may remain installed after a later failure; the script does not roll it back.
- A published unencrypted primary identity may remain at `~/.config/age/usbay-preservation-identity.txt`.
- The public recipient may remain.
- The local evidence directory, `results.txt`, and captured Homebrew output may remain.
- A newly created USB recovery directory or partial USB files may remain.
- Partial USB outputs are not valid recovery coverage.
- A failure after local identity publication but before Gate B succeeds may leave durable local private-key material without a validated USB recovery copy.
- Private staging cleanup is attempted, but successful cleanup must be established from evidence.
- Cleanup or status meaning may remain UNKNOWN and block further lifecycle action.
- Operational runs do not guarantee a `SYNTHETIC_DIAGNOSTIC` record; those structured records come from self-test fixtures.

After failure or interruption, do not automatically delete, overwrite, rename, repair, or retry. Preserve the evidence and obtain separate human authorization before any further lifecycle action.

## Evidence retained from the run

Retain without alteration:

- this decision, the existing operational proposal, custody approval, adopted policy records, and exact script;
- the immediately pre-run Mac command, path, timestamp, and SHA-256 for the executable script;
- the existing owner-supplied 41-PASS native self-test record without repeating it;
- the complete operational terminal transcript, excluding the secret passphrase;
- the unique local evidence directory and `results.txt`;
- `brew-install.stdout` and `brew-install.stderr`;
- `homebrew-installed-receipt.json` and its SHA-256;
- formula version, bottle tag, and reviewed bottle SHA-256;
- initial and repeated USB identity and reidentification records;
- USB recovery-file hashes and `manifest.txt`;
- USB reconnect identity, exact-content, recipient, and hash results;
- synthetic recovery result, explicit one-identity claim, and synthetic challenge hashes;
- every available command status, stdout, stderr, evidence-log entry, and failure record;
- any `SYNTHETIC_DIAGNOSTIC` record from separately completed self-test fixtures, without assuming one will appear operationally;
- the owner’s written operational authorization, denial, or superseding decision.

Do not retain the paper passphrase in digital evidence.

## Explicit exclusions

The proposed one-run authorization does not include:

- creating an archive of `.isolated/pr385` or any other source;
- modifying, moving, deleting, or removing `.isolated/pr385`;
- restoring stale `.git/worktrees/pr385` metadata;
- source-archive creation, upload, transfer, verification, or restoration;
- Linux archive restoration;
- source removal;
- writing any backup payload other than the named recovery-identity files inside the unique USB recovery directory;
- changing USB partitioning, formatting, or filesystem structure outside that unique directory;
- changing iCloud, Time Machine, FileVault, backup, sync, security, or other settings;
- sudo or broader permissions;
- permission broadening or automatic repair of existing directory permissions;
- changing policy, authorization, signing, replay protection, evidence requirements, security boundaries, or runtime governance;
- committing, pushing, creating a PR, merging, publishing, deploying, or taking production action;
- application or workflow restart;
- a second run or automatic retry.

Recovery-identity setup is not preservation of `.isolated/pr385`. Even a successful Gate B result would not create a source archive, prove Linux restoration, authorize source removal, or establish production readiness.

## Exact proposed authorization wording

The following wording is proposed for owner review only. It is not active unless the owner later issues it or unambiguously adopts it as a new explicit authorization:

> I authorize exactly one interactive operational run on my owner-controlled Mac of `usbay-age-preservation.zsh` with SHA-256 `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07`, using my selected SanDisk ExFAT USB, solely to establish and validate the described age recovery-identity arrangement.
>
> I authorize the bounded effects stated in `attached_assets/usbay-final-operational-decision-for-owner-review.md`: the script’s current-state preflight checks; one Homebrew forced-bottle installation of official `homebrew/core` age 1.3.2; the harmless tooling round trip; creation of the exact local primary identity and public recipient; creation and use of one unique USB recovery directory; interactive passphrase-protected encryption of the identity to that directory; writing the stated public files and manifest; USB synchronization, eject, reconnect, reidentification, exact-content and hash verification; and the bounded synthetic recovery challenge using exactly one explicit USB identity.
>
> I confirm that the custody approval recorded in `attached_assets/usbay-custody-approval-decision.md` with SHA-256 `0ec2cf05f537d94abffdeb7b0d133a0f1c9b188c8cfdc7cf27855deac6fc2d69` remains in effect. I understand that the local identity is unencrypted, screen locking does not make it inaccessible to processes already running under my logged-in account, no Time Machine destination was configured in the retained evidence, and there is an interval before USB recovery validation during which the local identity may exist without a validated USB recovery copy.
>
> I accept all stated stop conditions and retained partial-state consequences. A failed, interrupted, status-125, ambiguous, or owner-declined run stops without automatic retry. I understand that Homebrew age, the local identity and recipient, local evidence, or partial USB files may remain after failure, and that partial USB files do not constitute recovery coverage.
>
> This authorization is for exactly one run. It does not authorize a retry, settings changes, archive creation or other archive work, Linux restoration, source removal, permission broadening, sudo, app or workflow restart, commit, push, PR, merge, publication, deployment, production action, or any operation outside the stated recovery-identity run.

The owner must not include the paper passphrase or precise storage location in an authorization response.

## Current governance disposition

- Adopted policy ordering: PROVEN.
- Custody approval: PROVEN for the exact approved arrangement and qualifications.
- Existing native self-test evidence: VALIDATED for the exact reviewed script revision; not repeated.
- Proposed operational authorization: NOT GRANTED.
- Proposed operational run: NOT EXECUTED.
- Immediate pre-run hash evidence on the Mac: NOT YET RECORDED; required only after authorization and immediately before execution.
- Homebrew installation result: NOT_APPLICABLE before an authorized run.
- Primary and recovery identity creation: NOT_APPLICABLE before an authorized run.
- Gate B USB integrity and recovery usability: NOT_APPLICABLE before authorized creation.
- Archive work and Linux restoration: OUTSIDE SCOPE and NOT AUTHORIZED.
- Source removal: BLOCKED and NOT AUTHORIZED.
- Application restart, deployment, and production action: NOT AUTHORIZED.

## Governance verdict

This final operational decision is ready for owner review as a proposal only. It does not grant authority. No action may occur unless the owner later provides the exact or unambiguously equivalent bounded authorization and the immediately pre-run script hash and every runtime check pass.