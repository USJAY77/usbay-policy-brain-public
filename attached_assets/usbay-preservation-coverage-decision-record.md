# USBAY preservation coverage decision record

## Scope and authority

This record consolidates retained evidence only. It does not authorize or perform installation, key generation, USB writes, settings changes, archive operations, source removal, application restart, or any repeated inspection or self-test.

## Proposed paths

- Primary identity: `/Users/jayceeiambella/.config/age/usbay-preservation-identity.txt`
- Local evidence: `/Users/jayceeiambella/USBAY-Preservation-Evidence`

## Retained path evidence

Owner-supplied read-only inspection reported:

- `/Users/jayceeiambella`: directory; resolved unchanged;
- `/Users/jayceeiambella/.config`: directory; resolved unchanged;
- `/Users/jayceeiambella/.config/age`: absent; resolved unchanged;
- primary-identity path: absent; resolved unchanged;
- local-evidence path: absent; resolved unchanged;
- no symlink redirection reported for the inspected paths.

These results do not prove backup exclusion or the absence of configured copying.

## 1. Bounded iCloud conclusion

Retained settings report:

- iCloud Drive **Sync this Mac**: ON;
- **Desktop & Documents Folders**: OFF;
- **Optimize Mac Storage**: ON;
- all 13 listed app-sync switches: ON.

Apple documents Desktop & Documents Folders as the mechanism that stores those two folders in iCloud Drive: <https://support.apple.com/en-us/109344>.

Neither proposed effective path is under Desktop or Documents, and no redirection into those folders was reported. Therefore, the documented iCloud **Desktop & Documents** mechanism does not cover either proposed path.

This is a bounded inference from Apple’s documented mechanism, retained settings, and retained path resolution. It is not a conclusion about every iCloud feature or every copying mechanism. The application-switch list and Optimize Mac Storage setting establish no coverage or exclusion for either proposed path.

## 2. Time Machine evidence applied to both paths

The owner supplied the following native Mac evidence:

- at `2026-09-16T04:34:38Z`, `tmutil isexcluded -X` exited `0`, and each exact queried path returned `IsExcluded=0`:
  - `/Users/jayceeiambella`;
  - `/Users/jayceeiambella/.config`;
  - `/Users/jayceeiambella/.config/age`;
  - `/Users/jayceeiambella/.config/age/usbay-preservation-identity.txt`;
  - `/Users/jayceeiambella/USBAY-Preservation-Evidence`;
- at `2026-09-16T04:38:14Z`, `tmutil destinationinfo` printed `tmutil: No destinations configured.` and exited `0`;
- the supplied native Time Machine screenshot showed **Add Backup Disk…** with no destination displayed.

Time Machine therefore reported both proposed paths and their queried ancestors as **not excluded** at the first timestamp, including the currently absent targets, while reporting no configured backup destination at the second timestamp. This closes the previously missing path-specific exclusion-result gap and the configured-destination uncertainty only.

For both proposed paths:

| Question | Result |
|---|---|
| What did the path-specific exclusion query report? | `IsExcluded=0` / not excluded at `2026-09-16T04:34:38Z` |
| Was a Time Machine backup destination configured? | No destination configured at `2026-09-16T04:38:14Z` |
| Was Time Machine operating against a configured destination? | NOT_APPLICABLE at that timestamp because no destination was configured |
| Is there a completed backup containing material from the path? | UNKNOWN |
| What retention and backup encryption apply? | UNKNOWN |
| Has material from the path been successfully restored and verified? | UNKNOWN |

The successful exclusion query and destination query are configuration evidence only. Together they establish that the paths were not excluded but no Time Machine destination was configured at the recorded times. They do not prove or disprove historical backups or local snapshots, do not establish future configuration, and do not prove that a backup ran, contains either path, has any retention or encryption property, or can be restored.

These completed inspections must not be repeated.

## 3. Exact current policy requirement

The current proposal states:

> Before the owner may authorize durable private-key creation:
>
> - the services and mechanisms that may synchronize, back up, snapshot, migrate, monitor, collect, retain, or restore the Mac primary-identity path must be identified from retained evidence;
> - the resulting confidentiality, retention, deletion, and independent-recovery coverage must be verified;
> - the owner must specifically approve that verified coverage.
>
> Generic acceptance of unknown exposure does not satisfy these requirements. If coverage remains missing, stale, conflicting, incomplete, or unverified, durable private-key creation remains blocked.

This requirement remains binding and blocks durable private-key creation.

## 4. Specific missing fact

The missing path-specific Time Machine exclusion result and configured-destination uncertainty are no longer gaps.

Under the current, unamended policy, the actionable missing fact remains whether an identified, owner-approved backup mechanism has successfully backed up and restored the actual durable primary identity from its effective path, with retained evidence sufficient to verify independent recovery.

Under the separately proposed Gate A clarification, the retained evidence establishes the current applicable configuration for the two concrete standard mechanisms identified:

- documented iCloud Desktop & Documents: not applicable to either proposed path;
- Time Machine: paths not excluded, but no backup destination configured at the recorded time.

No additional concrete copying mechanism is established by the retained evidence. This does not prove that every other copying mechanism is absent and does not require universal-absence proof.

If the clarification is adopted, the remaining concrete pre-creation requirements are owner decisions rather than another recovery test:

1. specifically approve the intended custody, the effective paths, the reported iCloud applicability, the Time Machine not-excluded/no-destination configuration, and the retained-partial-state behavior;
2. provide a separate explicit operational authorization for the bounded installation and key-creation effects.

Policy adoption alone cannot satisfy item 2 and cannot authorize execution.

## 5. Satisfiability decision

A supported read-only configuration check can establish prospective Time Machine inclusion or exclusion for an effective path. It cannot prove a recoverable backup of an actual primary identity that does not yet exist.

The proposed primary identity, its parent `~/.config/age`, and the local evidence directory are currently absent. Therefore, before durable private-key creation:

- no backup can contain the actual primary identity;
- no restore can recover and verify that actual primary identity;
- a read-only configuration check cannot create the missing recoverability evidence.

Under the current policy and ordering, the independent-recovery requirement cannot be satisfied by a concrete pre-creation read-only check. Durable private-key creation remains BLOCKED.

The Gate A, Gate B, Gate C, and cross-gate clarification remains PROPOSED and NOT ADOPTED. If the owner separately adopts it, the ordering correction would remove recovery of the nonexistent identity from Gate A. The retained Time Machine evidence now establishes that no destination was configured at the recorded time; adoption would not convert that fact into backup coverage or execution authorization.

Policy adoption and execution authorization are distinct:

- adopting the clarification would change the governing gate order only;
- it would not authorize installation, key creation, or any other operation;
- a later execution authorization could be considered only after Gate A evidence is complete and specifically reviewed by the owner.

This record does not weaken the requirement, substitute generic acceptance for verification, or authorize staged creation.

## 6. Next owner decision

The precise next question is:

> Adopt the separately proposed Gate A, Gate B, Gate C, and cross-gate clarification as the governing policy ordering, without authorizing execution?

Practical consequences:

- **Adopt:** recovery of the nonexistent identity is removed from Gate A. The reported no-destination configuration and other Gate A evidence would still require specific owner review, and a separate operational authorization would still be required. No installation or key creation is authorized by adoption.
- **Do not adopt:** the current unamended policy remains binding, including its pre-creation independent-recovery requirement, and durable private-key creation remains blocked.

## Governance disposition

- Documented iCloud Desktop & Documents applicability: NOT_APPLICABLE to both proposed paths.
- Other iCloud or copying mechanisms: not generalized; UNKNOWN unless separately evidenced.
- Time Machine path-specific exclusion result: PROVEN from owner-supplied evidence; both proposed paths returned `IsExcluded=0` at `2026-09-16T04:34:38Z`.
- Time Machine configured destination: PROVEN absent at `2026-09-16T04:38:14Z`.
- Time Machine completed backup, retention, encryption, and recoverability: UNKNOWN.
- Policy clarification: PROPOSED, NOT ADOPTED.
- Current policy requirement: binding.
- Durable private-key creation: BLOCKED.
- Operational authorization: NOT GRANTED.