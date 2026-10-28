# PB-364: Python setup and explicit Ubuntu CI runners

Decision: REVIEW_REQUIRED
Status: AWAITING_APPROVAL

This candidate changes thirteen setup-python references from v5 to v7 and
nineteen Linux job labels in eighteen workflows from ubuntu-latest to
ubuntu-24.04. Python 3.11, commands, triggers, permissions, secrets and Mac
runner labels remain unchanged. An OS-major label does not freeze every image
package. The v7 action uses Node 24; the documented minimum runner version is
2.327.1. The inspected hosted runner was 2.338.0.

The existing update PR #270 fails with UNAPPROVED_GITHUB_ACTION_VERSION because
the registry permits setup-python v5 only. This candidate therefore also
proposes v7 in the actions policy and recalculates its manifest. It is a PB
policy proposal, not eligible for the non-PB CI-maintenance body route.

## Approval boundary

The existing approvals file is deliberately unchanged. Its placeholder
signature records are non-production scaffolding and bind the previous
manifest. They do not approve this new manifest. No reviewer identity,
approval time, signature or approval record is fabricated or rebound.

Consequently, verification of root policy approval evidence must continue
to fail closed until genuine new human adoption evidence is recorded through
the appropriate review process. Source-review requests, passing version
compatibility checks and an assigned PB number are not that adoption evidence.
Existing approval-gate tests are retained, including their expectation that
the repository's adopted policy has a valid approval chain. Failures caused by
the pending manifest adoption must be reported, not skipped or weakened.
The approval test module is marked governance so the normal PR CI tier must
execute these gates; green bootstrap/version tests alone cannot unlock merge.

## Validation and integration

Validate exact workflow edits, policy-manifest integrity, version allow/deny
behavior and unknown-action rejection. Record approval-chain failures
separately from action/runtime compatibility. GitHub CI must be read against
the exact candidate SHA. Both USBAY-AUDIT and USBAY-GLOBAL23 reviews are required;
do not merge or adopt the policy while approval evidence is missing.

Keep PR #270 as the existing historical update request; link it from this
governed candidate rather than silently claiming it was validated or merged.
Any future integration must use the generated PB-364 commit title and preserve
the reviewed file boundary. No deployment, activation, permission changes,
automatic merge or production-readiness assertion is part of this batch.
