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

The current retained artifact set states that completed Time Machine evidence exists and must not be reinspected, but it does not contain that evidence’s substantive path-specific results.

For both proposed paths:

| Question | Result |
|---|---|
| Is Time Machine configured to cover the effective path? | UNKNOWN from the available retained artifact |
| Is there a completed backup containing material from the path? | UNKNOWN from the available retained artifact |
| Has material from the path been successfully restored and verified? | UNKNOWN from the available retained artifact |

Configured coverage and proven recoverability are not equivalent. A configuration result showing that a path is not excluded would establish only configured coverage. It would not prove that a backup completed, retained the material, or could restore it.

The Time Machine inspection must not be repeated. The existing retained Time Machine record itself must be supplied or referenced with its exact path-specific conclusions if those conclusions are to be applied.

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

The actionable missing fact is whether an identified, owner-approved backup mechanism has successfully backed up and restored the actual durable primary identity from its effective path, with retained evidence sufficient to verify independent recovery.

That fact is different from proving universal absence of all other copying. Universal absence is not claimed and is not required.

The documented iCloud Desktop & Documents mechanism is not applicable to either path. The available retained artifact does not expose a substantive Time Machine result. No additional separate copying mechanism is established by the retained evidence.

## 5. Satisfiability decision

A supported read-only configuration check can establish prospective Time Machine inclusion or exclusion for an effective path. It cannot prove a recoverable backup of an actual primary identity that does not yet exist.

The proposed primary identity, its parent `~/.config/age`, and the local evidence directory are currently absent. Therefore, before durable private-key creation:

- no backup can contain the actual primary identity;
- no restore can recover and verify that actual primary identity;
- a read-only configuration check cannot create the missing recoverability evidence.

Under the current policy and ordering, the independent-recovery requirement cannot be satisfied by a concrete pre-creation read-only check. Durable private-key creation remains BLOCKED.

This record does not weaken the requirement, substitute generic acceptance for verification, or authorize staged creation. Any policy change or reordered staged workflow would require a separate explicit owner decision and authorization.

## 6. Next owner decision

The precise next question is:

> Do you confirm that the current policy remains unchanged, accepting that durable private-key creation stays blocked because recovery of the actual not-yet-created identity cannot be verified before creation?

Practical consequences:

- **Yes:** the recovery-identity setup remains blocked; no installation or key creation may proceed.
- **No:** this does not authorize execution. It means a separate, explicit policy-review proposal would be required before considering a bounded staged workflow that creates material and then verifies backup and restoration.

## Governance disposition

- Documented iCloud Desktop & Documents applicability: NOT_APPLICABLE to both proposed paths.
- Other iCloud or copying mechanisms: not generalized; UNKNOWN unless separately evidenced.
- Time Machine configured coverage: UNKNOWN from the available retained artifact.
- Time Machine proven recoverability: UNKNOWN and not currently provable for the absent identity.
- Current policy requirement: binding.
- Durable private-key creation: BLOCKED.
- Operational authorization: NOT GRANTED.