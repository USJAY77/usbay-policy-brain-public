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

## Prepared reviews and automatic evidence collection

`python scripts/pb364_review_evidence.py prepare` reads the current PR head,
policy and manifest through public GitHub GET endpoints. It checks the policy
digest and prints one complete scoped review draft for both nominated accounts.
Each reviewer must inspect the candidate and choose their own GitHub decision.
Logging in alone is not a decision. The draft is prepared by one agent and is
not two independent reviews or a grant of either governance role.

`python scripts/pb364_review_evidence.py collect` reads all review pages and
prints JSON evidence to stdout. It copies GitHub account, submitted timestamp,
review ID and URL only from submitted reviews. It requires both nominated User
accounts, APPROVED state, exact current commit and the complete binding marker.
Stale, dismissed, broader, malformed or absent decisions remain pending. A later
submitted objection takes precedence. A head change during reading fails closed.
Pending collection exits 2; read/validation failures exit 1. Neither command
submits reviews, writes repository files, mutates approvals or uses secrets.

The result is a point-in-time API observation, not a signed attestation or an
atomic GitHub snapshot. Reviews may subsequently be dismissed or changed; read
them again immediately before any separately authorized integration. Two account
records do not prove two independent humans. Account-role authority must still be
established from a separate authorized mandate; it is never inferred from login,
write access or the review request.

This is an evidence collection path, not a replacement for the existing policy
adoption verifier. It explicitly reports authority NOT_VERIFIED, policy_adopted
false, production_signatures false and merge_authorized false even when both
reviews are recorded. The placeholder-based approval gate remains unchanged and
still blocks adoption. A trusted authority-validation/adoption design remains
separate work; a collected review must not be relabeled as that missing check.
