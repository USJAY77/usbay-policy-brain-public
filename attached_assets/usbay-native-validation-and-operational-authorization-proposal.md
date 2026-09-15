# USBAY Native Validation Record and Operational Authorization Proposal

## Document status

- Status: PROPOSED
- Operational authorization: NOT GRANTED
- Execution performed by this document: NONE
- Script covered: `usbay-age-preservation.zsh`
- Script SHA-256: `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07`
- Native evidence provenance: owner-supplied
- Native evidence scope: one macOS `--self-test` run of the exact script hash above

This document records bounded test evidence and proposes one possible operational authorization. It does not itself authorize or execute any action.

## Owner-supplied native Mac validation

The owner reported:

- Native self-test result: 41 PASS
- Native self-test exit status: 0
- Timeout supervisor: group probe transitioned `denied` to `absent`; child reaped; actual status 124
- Setup-interruption supervisor: group probe transitioned `denied` to `absent`; child reaped; `direct_child_alive=false`; actual status 143
- Signal masks restored
- Signal handlers restored
- Persistent-denial synthetic regression passed

### Regression disposition for this revision and run

The following regressions are VALIDATED by owner-supplied native evidence for the exact script hash and run recorded above:

- supervisor normal completion: expected 0
- supervisor timeout cleanup: expected 124 only after cleanup became proven
- supervisor orphan handling: included in the reported 41 PASS self-test
- supervisor ordinary interruption: included in the reported 41 PASS self-test
- supervisor setup interruption: expected 143 only after cleanup became proven
- transient Darwin denial followed by authoritative group absence
- persistent group denial remains fail-closed
- direct-child liveness/reaping checks
- parent signal-mask restoration
- parent signal-handler restoration

Evidence limitation: this validation applies only to these synthetic supervisor regressions, this script revision, and this owner-reported run. It does not prove operational installation, key custody, USB integrity, archive preservation, Linux restoration, source-removal safety, or production readiness.

## Consolidated operational authorization proposal

### Proposed bounded authorization

Authorize exactly one interactive operational run of the exact script hash above, on the owner-controlled FileVault-protected Mac, against the owner-selected SanDisk ExFAT USB, solely to establish the age recovery identity arrangement described below.

This proposal remains inactive until the owner gives a new, explicit authorization after reviewing the prerequisites, effects, failure handling, exclusions, and evidence requirements in this document.

### Exact proposed effects

If separately authorized and all gates pass, one operational run would:

1. Require macOS and the exact environment authorization gate `USBAY_RECOVERY_SETUP_AUTHORIZED=YES`.
2. Refuse existing primary or recipient destination paths, symlinks, unsafe directories, unsupported architecture/macOS combinations, missing Homebrew, existing Homebrew `age`, changed formula metadata, or unrecognized USB identity.
3. Identify the selected external physical USB and record its identifiers, mount, media identity, size, free space, and top-level entries.
4. Create a unique owner-only evidence directory under `~/USBAY-Preservation-Evidence/`.
5. Display the evidence location, USB identity, visible top-level USB contents, reviewed age version, bottle tag, and reviewed bottle SHA-256.
6. Pause for an interactive owner confirmation before installation or key creation.
7. Run one Homebrew forced-bottle installation of official `homebrew/core` age 1.3.2 with auto-update, cleanup, and upgrade suppression passed to the actual child process.
8. Retain Homebrew installation stdout, stderr, result status, and installed receipt; validate age 1.3.2 and `poured_from_bottle=true`.
9. Run a harmless temporary age encrypt/decrypt round trip before creating the real identity.
10. Pause for a second interactive owner confirmation before real key creation.
11. Create `~/.config` mode 0700 only if absent and confirmed.
12. Create `~/.config/age` mode 0700 only if absent; refuse an existing directory with any other mode rather than changing it.
13. Generate the primary identity in a unique owner-only staging directory on the destination filesystem.
14. Publish the primary identity exclusively to `~/.config/age/usbay-preservation-identity.txt` mode 0600 without replacing an existing path.
15. Derive and exclusively create `~/.config/age/usbay-preservation-recipient.txt`.
16. Reidentify the same USB before creating a unique `USBAY-Recovery-<random>` directory.
17. Instruct the owner to create a fresh paper passphrase of at least seven independently selected Diceware words and keep it locked, owner-controlled, and physically separate from the USB.
18. Pause for explicit owner confirmation that the paper passphrase has been created and stored.
19. Reidentify the same USB again and require the new recovery directory to remain empty before encryption.
20. Interactively encrypt the primary identity to `usbay-preservation-identity.txt.age` on the USB.
21. Write only the public recipient, recovery instructions, and SHA-256 manifest alongside the encrypted identity on the USB.
22. Record USB file hashes in the local evidence record.
23. Sync and eject the selected whole USB device.
24. Pause for the owner to reconnect the same USB.
25. Reidentify the USB, verify exact recovery-directory contents, compare the public recipient, and verify all recorded hashes.
26. Run a bounded synthetic recovery challenge using exactly one explicit USB identity and without referencing the primary identity.
27. Record the recovery result and synthetic challenge hashes, then remove only the temporary synthetic challenge files.

### Remaining prerequisites before authorization

The owner must confirm all of the following immediately before any operational run:

- The executable file being run hashes exactly to `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07`.
- The Mac is owner-controlled and FileVault protection is active.
- The intended SanDisk ExFAT USB is connected directly, is owner-controlled, and may receive a new uniquely named recovery directory.
- The owner has reviewed and accepts every currently visible top-level USB entry displayed by preflight.
- The USB contains sufficient free space and no unresolved filesystem or hardware warning.
- Homebrew is already present and functioning.
- Homebrew `age` is not already installed; an existing installation blocks this script.
- Network access to the official Homebrew formula metadata and bottle is available.
- The Mac architecture and macOS major version map to one of the reviewed bottle tags embedded in the script.
- `~/.config`, `~/.config/age`, and both destination files satisfy the script's absence, type, symlink, ownership-context, and mode expectations.
- The owner is ready to create and physically secure the paper passphrase without entering it into chat, command arguments, files, logs, or this evidence document.
- The owner understands that the script installs software and creates durable key material before USB verification completes.
- The owner accepts the failure-state retention rules below.

Any missing, stale, conflicting, or unverified prerequisite blocks authorization.

### Failure and interruption handling

- Any command failure, timeout, denied process-group cleanup, USB identity change, hash mismatch, receipt mismatch, unsafe path, unexpected existing destination, or declined prompt stops the run.
- Status 124 is accepted only when timeout cleanup is proven.
- Status 125 means cleanup remains unproven and requires immediate human review; it is never converted to success based only on direct-child termination.
- Interruption status such as 143 is returned only when cleanup is proven.
- Do not automatically retry an operational failure.
- Do not delete, overwrite, rename, or repair outputs after failure without inspecting the retained evidence and obtaining separate authorization.
- Homebrew age may remain installed after a later failure; the script does not roll it back.
- A published primary identity and public recipient may remain after a later USB or recovery-test failure; the script does not delete them.
- A newly created USB recovery directory or partial files may remain after failure; the script does not claim them valid and they must not be treated as recovery coverage.
- The local evidence directory and captured Homebrew output remain for review.
- Private staging cleanup is attempted, but successful cleanup must be established from evidence rather than assumed.
- If process-group cleanup is unproven, stop other lifecycle action and retain the complete synthetic diagnostic record.

### Evidence to retain

Retain without alteration:

- This proposal and the exact script file.
- SHA-256 of the reviewed script before execution.
- The owner-supplied native 41-PASS self-test record for this revision.
- The full operational terminal transcript, excluding the secret passphrase.
- The unique local evidence directory and its `results.txt`.
- `brew-install.stdout` and `brew-install.stderr`.
- `homebrew-installed-receipt.json` and its recorded SHA-256.
- Recorded formula version, bottle tag, and reviewed bottle SHA-256.
- Initial and repeated USB identity/reidentification records.
- USB recovery-file SHA-256 values and the USB `manifest.txt`.
- USB reconnect identity, exact-content, recipient, and hash checks.
- Synthetic recovery result, explicit one-identity claim, and synthetic challenge hashes.
- Any `SYNTHETIC_DIAGNOSTIC` record associated with failure or interruption.
- A written owner decision stating whether the proposed one-run authorization was granted, declined, or superseded.

Do not retain the paper passphrase in digital evidence.

## Explicit exclusions

This proposal does not authorize:

- creating an archive of `.isolated/pr385` or any other source;
- modifying, deleting, moving, or removing `.isolated/pr385`;
- restoring stale `.git/worktrees/pr385` metadata;
- writing any backup payload other than the recovery identity files named above;
- sudo or broader permissions;
- changing USB partitioning, formatting, or filesystem structure outside the unique recovery directory;
- changing production, policy, authorization, signing, replay protection, or runtime governance;
- committing, pushing, opening a PR, merging, publishing, deploying, or restarting the app.

## Unresolved backup coverage

Recovery-identity setup is not preservation of `.isolated/pr385`.

Even after a successful authorized run:

- no source archive has been created;
- no archive manifest has been produced;
- no independent backup destination has been proven to contain the source;
- no end-to-end archive decryption, extraction, or content comparison has occurred;
- Replit App Storage and Cloudflare R2 remain unproven as independent preservation destinations;
- source removal remains unauthorized and blocked.

Backup coverage remains OPEN until a separately authorized archive workflow creates a lossless source archive, writes it to an approved independent destination, verifies hashes and contents, and completes the required restore validation.

## Unresolved Linux restore requirements

The Mac synthetic recovery challenge validates only recovery-identity use on the Mac. It does not validate restoration of the future source archive on Linux.

Before any source-removal proposal, a separately authorized Linux restore validation must establish:

- a trusted, reviewable Linux age installation and its provenance;
- access to the encrypted recovery identity from the USB;
- access to the separately held paper passphrase;
- use of exactly one explicit recovery identity rather than ambient identities;
- successful decryption of the actual preservation archive;
- verification of the archive ciphertext and plaintext hashes against retained manifests;
- lossless extraction on Linux to a separate destination;
- comparison sufficient to prove required tracked, untracked, hidden, metadata, and repository content was preserved;
- explicit treatment of platform-specific metadata or filesystem semantics that cannot be reproduced on Linux;
- retained commands, tool versions, hashes, outputs, and failure evidence.

Until that validation is complete, Linux restore capability and source-removal safety remain UNKNOWN.

## Proposed owner authorization text

If, and only if, the owner accepts every prerequisite and effect above, the owner may issue a new instruction equivalent to:

> I authorize exactly one interactive operational run of `usbay-age-preservation.zsh` with SHA-256 `d1a499e562f58aadea6cee96713b7ddbb55016e9147c7f8afbf178bd496e1c07` on my owner-controlled FileVault-protected Mac and selected SanDisk ExFAT USB. I authorize the stated Homebrew age 1.3.2 forced-bottle installation, primary identity and recipient creation, unique USB recovery-directory writes, USB eject/reconnect verification, and bounded synthetic recovery test. I accept the stated retained partial-output behavior on failure. I do not authorize archive creation, source removal, permission broadening, sudo, app restart, commit, push, merge, deployment, or production action.

The environment variable gate alone is not sufficient human authorization. The current instruction does not grant this proposed authorization.

## Governance disposition

- Supervisor regression validation: VALIDATED for the owner-supplied native run and exact script revision.
- Operational recovery setup: PROPOSED, NOT AUTHORIZED, NOT EXECUTED.
- Actual USB integrity: UNKNOWN.
- Homebrew installation result: NOT EXECUTED.
- Primary/recovery identity creation: NOT EXECUTED.
- Backup coverage: OPEN.
- Linux archive restore: OPEN.
- Source removal: BLOCKED and NOT AUTHORIZED.
- Production readiness: NOT_APPLICABLE.