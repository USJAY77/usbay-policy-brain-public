# PB-365 Shared Offline Product Dry-Run Foundation

## PURPOSE
PB-365 prepares the shared offline foundation for USBAY Trade and Governed Mail. A normalized request binds actor, agent, tenant, capability, policy, target and payload; no external action is implemented.

## RISK
This is an offline prototype. Operator-controlled issuer enrollment, local database integrity/access control and tenant membership are trust inputs. A signed fixture proves key control, not a specific human identity. The in-memory fallback is for unit fixtures only. SQLite replay is a local adapter, not provisioned production infrastructure. Preparation-time approval lookup is not atomic with future execution or external revocation.

## MECHANISM
Reuse AgentRegistry, the existing human-approval gate, authenticated Ed25519 issuance verifier, SQLite replay registry and signed audit writer. Read approval/issuer metadata in a read-only SQLite transaction on each lookup. Reject missing/revoked/expired/wrong-scope evidence, changed request binding, live requests and replay. Restrict audit payloads to declared hashes and fixed codes. Both new test modules are governance-marked for required PR CI.

## GAP
No real human approval intake, production IdP, issuer onboarding, live connector, product capability or execution authority is introduced. Trade product scope and Mail provider/recipient controls remain separate work. No production-readiness or live Replit-source binding claim. Exact-head native CI and two real code reviews are still required.

## AUDIT
Baseline 205250807544f5353e19272b84bd101f2dcebf9d. Task #411 registers PB-365. Only two new source modules, two new test modules, one design document and one generated metadata record are proposed. Tests use synthetic keys/reviewers, tenant t1 and isolated temporary audit stores. Existing runtime, policies, workflows, secrets handling and tracked audit evidence are unchanged.

## IMPACT
Adds an unconnected offline preparation API and local adapters. PREPARED_DRY_RUN always has execution_authorized=false and external_mutation_performed=false. No mailbox, trade account or provider is contacted.

## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL

## VALIDATION
Local CPython 3.12.14: 94 tests +34 subtests passed, covering the new boundary/adapters and affected agent, approval, issuance and replay components. Fresh-process replay denial and real audit tamper detection are included. Full repository suite not run. Native exact-head CI pending; local proof is not relabeled as native success.

## REQUIRED APPROVALS
USBAY-AUDIT and USBAY-GLOBAL23 must submit their own code-review decisions. No role mandate or reviewer decision is inferred from PB-364. Do not merge this Draft or activate any external capability.

## ROLLBACK
Remove these additive modules/docs/tests; no existing production path is connected to them. No data migration, provider configuration or policy widening.

Task: #411
