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

Historical v1 placeholder records remain preserved in Git history. The current
v2 approvals file is a verification specification, not a list of granted
approvals. It binds the proposed policy and manifest and requires live GitHub
owner/reviewer verification. It contains no invented identity, decision, time,
role grant or signature. It cannot return PASS without those live decisions.

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

`python -m scripts.pb364_review_evidence prepare` reads the current PR head,
policy and manifest through public GitHub GET endpoints. It checks the policy
digest and prints one complete scoped review draft for both nominated accounts.
Each reviewer must inspect the candidate and choose their own GitHub decision.
Logging in alone is not a decision. The draft is prepared by one agent and is
not two independent reviews or a grant of either governance role.

`python -m scripts.pb364_review_evidence collect` reads all review pages and
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

Collection alone reports authority NOT_VERIFIED and grants no adoption. The
following v2 route is separate from that observation and from historical v1
placeholder scaffolding.

## Explicit mandate and live CI-policy adoption verification

`python -m scripts.pb364_review_evidence mandate` prints a PROPOSED owner-mandate
draft. The proposed mapping is USBAY-AUDIT as security_reviewer and USBAY-GLOBAL23
as governance_owner, only for this exact CI-policy candidate. These roles have
NOT been granted by generating or publishing an AI draft. The repository owner
must inspect the scope and roles, confirm them by changing PROPOSED to ACTIVE,
and submit only the declaration line in a separate PR comment. A quoted or
multiline AI draft cannot satisfy this requirement. No mandate is created by
login, write access, reviewer nomination, a review request or this document.

The reviewers each inspect and submit the prepared exact-head decision. The
marker explicitly states CI_POLICY_ADOPTION, the exact manifest/policy hashes,
scope and exclusions. It does not authorize merging or production operation.

The v2 verification specification is committed before human decisions. This
avoids a self-referential commit hash and avoids dismissing reviews with a later
registration commit. The current exact candidate is resolved from PR #410, not
from an editable approver assertion in the specification.

`python -m scripts.pb364_review_evidence register` outputs a full verification
receipt only after live owner/review verification succeeds. It automatically
records the observed mandate URL, assigned roles, reviewer accounts, timestamps,
review IDs, URLs and exact binding. It never writes a file or submits a decision.
Keep the receipt as external evidence; do not replace the approvals specification
with it or commit it to the reviewed PR. Any code commit would require fresh
decisions for the new head. Failure output is a diagnostic, not an approval.

The root verifier dispatches v2 records to
`governance/github_policy_review_adoption.py`. It does not trust local record
claims: public GitHub GET responses must confirm the current repository owner,
the latest explicit owner mandate, its scoped role mapping, and both current
submitted decisions. An owner revocation, dismissal, source change, wrong hash,
wrong role, partial pagination or unavailable API fails closed. Decisions and PR
head are re-read to detect concurrent changes. This is still a point-in-time
GitHub observation, not a signed or atomic attestation.

Reviews and mandate bind the complete, final PR candidate. Any change to that
candidate, including the approvals specification itself, requires fresh reviews
and a new scoped mandate. API verification can then be rerun on the same commit
without invalidating reviews or manufacturing another registration commit.

After a separately authorized merge, the verifier additionally requires the
merged tree to equal that reviewed PR tree and the merged verification
specification to match. Later checkouts must descend from that merge and retain
the same manifest, policy bytes and verification specification. This preserves a
completed adoption without turning an unrelated branch or an unreviewed squash
tree into authority. It does not itself perform or authorize a merge.

Legacy placeholders cannot grant adoption. Their explicit test-only verifier
option remains for isolated historical fixtures. The former placeholder test
now exercises such a temporary fixture; a new root assertion requires real v2
CI-policy adoption and rejects placeholder status. The real root PASS gate is
retained. Missing current decisions continue to block the PR.

A successful v2 check authorizes only the declared CI-policy adoption. It reports
production_signatures false, merge_authorized false, deployment_authorized false
and activation_authorized false. No production signing keys are introduced. Main
and runtime behavior remain unchanged; any merge still requires separate owner
authorization and all ordinary PR gates.

The live checks use public GitHub GET endpoints without credentials. API outages,
rate limits or deleted evidence block validation; there is no offline PASS or
fallback to placeholders. This is a CI-specific GitHub evidence adapter, not a
provider-independent production signing system.
