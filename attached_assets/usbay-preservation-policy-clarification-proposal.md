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
- at `2026-09-16T04:34:38Z`, owner-supplied native Mac evidence reports that `tmutil isexcluded -X` exited `0` and returned `IsExcluded=0` for both proposed paths and all inspected ancestors;
- at `2026-09-16T04:38:14Z`, owner-supplied native Mac evidence reports that `tmutil destinationinfo` exited `0` and printed `tmutil: No destinations configured.`;
- the owner-supplied Time Machine screenshot shows **Add Backup Disk…** with no destination displayed;
- no universal absence of copying is claimed or required.

Unknown copying coverage is not resolved by this ordering clarification.

## Time Machine configuration evidence

The owner-supplied native Mac evidence establishes:

- both proposed paths and all inspected ancestors returned `IsExcluded=0` at `2026-09-16T04:34:38Z`, including the currently absent targets;
- `tmutil destinationinfo` reported `tmutil: No destinations configured.` and exited `0` at `2026-09-16T04:38:14Z`;
- the supplied Time Machine screenshot showed **Add Backup Disk…** with no destination displayed.

The bounded conclusion is that the proposed paths were not excluded, but no Time Machine backup destination was configured at the recorded time.

This closes only the path-specific exclusion and configured-destination uncertainties. It does not establish or disprove historical backups, local snapshots, other copying mechanisms, future configuration changes, backup completion, retention, encryption, or recoverability. These completed inspections must not be repeated.

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

- extend the recorded Time Machine configuration evidence into proof of backup completion, retention, encryption, or recoverability;
- resolve any other UNKNOWN copying configuration;
- authorize installation or key creation;
- validate the encrypted USB recovery copy;
- create or validate a source archive;
- authorize source removal or application restart;
- modify the validated script.

If this clarification is adopted, Gate A would no longer require recovery of a nonexistent identity. The retained evidence would establish the identified standard configuration facts: the documented iCloud Desktop & Documents mechanism does not apply to either proposed path, and Time Machine reported the paths not excluded while no destination was configured at the recorded time.

Adoption would still not authorize execution. Before any operational run, the owner would have to specifically approve the intended custody, effective paths, reported configuration, and retained-partial-state behavior, then issue a separate explicit operational authorization.

## One owner decision

The owner must decide:

> Adopt the exact Gate A, Gate B, Gate C, and cross-gate amendment above as the governing policy clarification, without granting execution authorization?

Practical consequences:

- **Adopt:** the impossible pre-creation recovery requirement is removed. The existing Gate A evidence and no-destination configuration still require specific owner review, and execution still requires a separate explicit operational authorization. No operation is authorized by adoption.
- **Do not adopt:** the current policy remains unchanged, including its pre-creation independent-recovery requirement, and durable private-key creation remains blocked.

## Governance disposition

- Policy clarification: PROPOSED, NOT ADOPTED.
- Time Machine path-specific exclusion result: PROVEN; both proposed paths returned `IsExcluded=0` at `2026-09-16T04:34:38Z`.
- Time Machine configured destination: PROVEN absent at `2026-09-16T04:38:14Z`.
- Time Machine backup completion, retention, encryption, and recoverability: UNKNOWN.
- Other copying coverage: not generalized; UNKNOWN where not specifically evidenced.
- Validated script: unchanged.
- Gate A: BLOCKED while the clarification remains unadopted and pending specific owner review and separate operational authorization.
- Gate B evidence state: UNKNOWN; Gate A has not passed and no authorized creation has occurred.
- Gate C evidence state: UNKNOWN; neither prior gates nor the separately authorized archive and Linux restoration requirements have been satisfied.
- Operational authorization: NOT GRANTED.