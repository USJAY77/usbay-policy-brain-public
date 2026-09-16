# USBAY preservation policy clarification proposal

## Status and authority

This is a proposed policy clarification for owner review. It is not adopted and does not modify the current policy unless the owner explicitly adopts the exact amendment below.

It does not authorize installation, key creation, USB writes, settings changes, archive operations, source removal, application restart, or any repeated inspection or self-test.

The validated script remains unchanged and outside this proposal’s modification scope.

## Retained evidence applied

The proposal relies only on the retained evidence:

- the documented iCloud Desktop & Documents mechanism does not apply to either proposed effective path;
- that bounded iCloud conclusion does not generalize to every iCloud feature or copying mechanism;
- the proposed paths resolve unchanged and no symlink redirection was reported;
- the primary identity, its `~/.config/age` parent, and the local evidence directory were reported absent;
- the substantive retained Time Machine evidence is unavailable in the current artifact set;
- no universal absence of copying is claimed or required.

Unknown copying coverage is not resolved by this ordering clarification.

## Exact missing Time Machine record or result

The exact missing evidence is the substantive retained Time Machine inspection record that identifies:

1. the original read-only command or supported macOS interface used;
2. its timestamp and Mac context;
3. its unaltered result for each effective proposed path—or, because the proposed leaves are absent, the nearest existing ancestor whose Time Machine configuration governs a future child:
   - `/Users/jayceeiambella/.config/age/usbay-preservation-identity.txt`;
   - `/Users/jayceeiambella/USBAY-Preservation-Evidence`;
4. whether each path is configured as included, excluded, or unresolved;
5. any limitation showing that the result establishes configuration only and not a completed, retained, or recoverable backup.

The current artifacts contain only references to retained Time Machine evidence, not these substantive results. Its contents must not be invented, described as applied, or replaced by a repeated inspection without separate authorization.

Until this exact retained record or its authenticated path-specific result is supplied, Time Machine applicability at Gate A remains UNKNOWN and blocks key creation.

### Preservation-record search result

A bounded search of the existing preservation attachments and their repository history found only references to retained Time Machine evidence. It did not find an artifact containing the original Time Machine command/interface, timestamp/context, path-specific configuration result, completed-backup result, or restore result.

Therefore:

- exact source artifact: UNKNOWN; no substantive artifact was found in the searched preservation records and attachments;
- original command or interface: UNKNOWN;
- recorded timestamp/context: UNKNOWN;
- primary-identity path applicability: UNKNOWN;
- local-evidence path applicability: UNKNOWN;
- actual backup evidence: UNKNOWN; no substantive result was found;
- actual recovery evidence: UNKNOWN; no substantive result was found.

The absence of this artifact does not prove that Time Machine excludes either path or that no backup exists.

### Minimal proposed read-only Time Machine configuration check

For owner review only, the exact proposed Mac Terminal command is:

```zsh
{ /bin/date -u '+TIMESTAMP_UTC=%Y-%m-%dT%H:%M:%SZ'; /usr/bin/tmutil isexcluded -X "$HOME" "$HOME/.config" "$HOME/.config/age" "$HOME/.config/age/usbay-preservation-identity.txt" "$HOME/USBAY-Preservation-Evidence"; }
```

This command is not executed or authorized by this proposal. It uses the documented read-only `tmutil isexcluded` interface and requests property-list output with `-X`. It makes no settings change, creates no path, reads no private file content, and uses no `sudo`.

The command asks Time Machine for exclusion configuration on:

- the existing home directory;
- the existing `.config` ancestor;
- the currently absent `age` directory;
- the currently absent primary-identity path;
- the currently absent local-evidence directory.

Interpretation must remain fail-closed:

- an explicit result for each exact path can establish the reported Time Machine inclusion/exclusion configuration at the command timestamp;
- an error, omitted path, unsupported response, or ambiguous inheritance leaves that absent path’s applicability UNKNOWN;
- the `tmutil` documentation describes `isexcluded` for a file, directory, or volume but does not promise that every currently absent item will receive a conclusive result;
- an `Included` result is configuration evidence only; it does not prove that a backup has completed, contains the future identity, is retained, or can be restored;
- an `Excluded` result does not establish the absence of other copying mechanisms.

If the command cannot classify either absent exact path, no broader scan or inference is authorized. Gate A remains blocked pending a concrete supported way to establish the missing configuration fact or a further owner policy decision.

## Exact proposed policy amendment

If adopted, replace the current pre-creation requirement and its ordering implication with the following text exactly:

> ### Gate A — before durable private-key creation
>
> Durable private-key creation is blocked unless retained evidence establishes all of the following:
>
> 1. **Intended custody:** the owner-controlled FileVault-protected Mac, owner-controlled USB, physically separate paper passphrase, intended local identity path, intended local evidence path, and retained-partial-state behavior are identified and specifically accepted by the owner.
> 2. **Effective paths:** the proposed identity and evidence paths and their existing ancestors have been checked for type and redirection, and their effective paths are established.
> 3. **Applicable copying and backup configuration:** for each concrete copying or backup mechanism identified by retained evidence, configuration applicability to both effective paths is established as included, excluded, or UNKNOWN. Missing, stale, conflicting, incomplete, or unverified applicability remains UNKNOWN and blocks Gate A. This requirement does not demand proof that every possible copying mechanism is absent.
> 4. **Owner authorization:** after reviewing the verified custody and configuration evidence, the owner explicitly authorizes the bounded installation and durable private-key creation effects. An environment variable, generic acceptance of unknown exposure, or approval of this policy clarification is not execution authorization.
>
> Gate A requires verified intended custody and applicable configuration. It does not require a completed backup or recovery of an identity that does not yet exist.
>
> ### Gate B — after authorized creation, before recovery setup may be declared validated
>
> After separately authorized creation, recovery setup remains unvalidated unless retained evidence establishes all of the following:
>
> 1. the encrypted identity was written only to the authorized USB recovery directory with the authorized public files and manifest;
> 2. the USB was synchronized, ejected, reconnected, and reidentified as the same approved device;
> 3. exact recovery-directory contents, recipient equality, and recorded hashes passed;
> 4. the bounded recovery challenge succeeded using exactly one explicit USB identity without referencing the Mac primary identity;
> 5. any failure, interruption, status 125, or retained partial state was handled under the existing fail-closed evidence rules.
>
> Gate B verifies the encrypted USB recovery copy and recovery-key usability. It does not create or validate a source archive and does not authorize source removal.
>
> ### Gate C — before any source removal
>
> Source removal remains blocked unless a separately authorized archive workflow:
>
> 1. creates a lossless archive of the authorized source;
> 2. writes it to an owner-approved independent destination;
> 3. retains and verifies ciphertext, plaintext, manifest, and content evidence;
> 4. completes a separately authorized Linux restoration to a separate destination;
> 5. verifies the restored tracked, untracked, hidden, metadata, and repository content to the required preservation standard;
> 6. receives separate explicit owner authorization for source removal after all prior evidence is reviewed.
>
> Gate C cannot be inferred from Gate A or Gate B. Archive creation, Linux restoration, and source removal remain separately authorized lifecycle actions.
>
> ### Cross-gate rule
>
> Passing, implementing, or authorizing one gate does not prove or authorize a later gate. UNKNOWN remains UNKNOWN. No gate may be bypassed through generic acceptance, optimistic interpretation, or evidence from a different gate.

## Effect of adoption

Adoption would correct only the ordering error that required recovery of a nonexistent identity at Gate A.

Adoption would not:

- establish the missing Time Machine result;
- resolve any other UNKNOWN copying configuration;
- authorize installation or key creation;
- validate the encrypted USB recovery copy;
- create or validate a source archive;
- authorize source removal or application restart;
- modify the validated script.

Because the substantive Time Machine result is unavailable, Gate A remains BLOCKED even if this clarification is adopted.

## One owner decision

The owner must decide:

> Adopt the exact Gate A, Gate B, Gate C, and cross-gate amendment above as the governing policy clarification, without granting execution authorization?

Practical consequences:

- **Adopt:** the impossible pre-creation recovery requirement is removed, but Gate A remains blocked until the missing Time Machine applicability result and any other concrete applicable configuration evidence are verified and specifically approved. No operation is authorized.
- **Do not adopt:** the current policy remains unchanged, including its pre-creation independent-recovery requirement, and durable private-key creation remains blocked.

## Governance disposition

- Policy clarification: PROPOSED, NOT ADOPTED.
- Time Machine applicability: UNKNOWN because the substantive retained result is unavailable.
- Other copying coverage: not generalized; UNKNOWN where not specifically evidenced.
- Validated script: unchanged.
- Gate A: BLOCKED.
- Gate B evidence state: UNKNOWN; Gate A has not passed and no authorized creation has occurred.
- Gate C evidence state: UNKNOWN; neither prior gates nor the separately authorized archive and Linux restoration requirements have been satisfied.
- Operational authorization: NOT GRANTED.