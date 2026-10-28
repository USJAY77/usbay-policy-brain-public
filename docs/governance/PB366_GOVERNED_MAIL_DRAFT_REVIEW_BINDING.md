# PB-366 Offline Governed Mail Draft Review Binding

## PURPOSE
PB-366 adds offline exact-action binding for Governed Mail draft review, on the merged PB-365 foundation. It creates only a governance_review DryRunRequest; no mail action is executed.

## RISK
Content hashes are not authorization or anonymization. Mailbox and source-version fields are caller-provided binding inputs, not authenticated provider observations. The deliberately narrow ASCII envelope syntax rejects display names, quoted local parts and EAI/IDN addresses. Address lowercase/strip/sort follows the supplied advisory v1 contract; this is not a universal mailbox identity equivalence or provider-alias implementation. No provider behavior or complete mail contract compliance is claimed.

## MECHANISM
Versioned canonical target/content hashes bind mailbox, source ID/version, sender, distinct To/CC/BCC lists, exact subject, exact body-byte digest and ordered attachment-byte digests plus filenames. Recipient-role changes, body bytes, attachment rename/reorder/change and policy/context changes invalidate B1 binding. Immutable inputs, narrow validation and header-injection rejection operate before preparation. The new tests are governance-marked for required PR CI. No existing runtime, policy, workflow, secret handling or approval rule is modified.

## GAP
No actual draft generation, semantic evidence validation, inbox reading, persistence, recipient ownership proof, sender authentication, delegation, production identity, provider acceptance, delivery, reconciliation or sending. Approval expiry and consumption remain separate B1 evidence checks; no approval is issued here. Default approval duration, address storage, audit retention and provider access remain open decisions. Full synthetic-pilot T1-T14 and live mail integration are not claimed complete.

## AUDIT
Baseline a993b0aa41b6d742b30cc910d3c639439ec470b2. Task #413. Proposed files: one source module, one test module, this document and generated metadata. Raw mail data is transient caller memory; no raw addresses, BCC, body, subject or filenames appear in the returned B1 request. Hash references are pseudonymous, not anonymous. There is no production privacy/retention decision in this patch.

## IMPACT
Adds an unconnected offline draft-review primitive. Action type is review_draft only. send, move, delete, flag and composite actions are rejected. A prepared result still grants no execution authority; no synthetic outcome is labeled sent or delivered.

## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL

## VALIDATION
Local CPython 3.12.14: 24 tests +68 subtests passed across the new module and existing B1 boundary tests. Includes exact recipient-role/content/attachment binding, malformed/header-injected input rejection and an end-to-end B1 review-fixture mutation denial. Full suite not run. Native exact-head CI pending; previous PB-365 results are not substituted.

## REQUIRED APPROVALS
USBAY-AUDIT and USBAY-GLOBAL23 must submit their own exact-head code-review decisions. Prior task approvals or role mandates are not inherited. No merge, deployment or activation requested in this Draft.

## ROLLBACK
Remove the additive files. No provider, schema migration, live capability or existing runtime route is connected.

Task: #413

## Advisory Source Snapshot
Supplied file: USBAY-Governed-Mail-EURIA-Contract.txt, dated 2026-10-26; SHA-256 67bc803039a468a6eeacdc1adfe4cb46dee11a33294a730a37e1dd45fb98da39. The source describes a larger advisory design and explicitly grants no implementation or execution authority. Current user roadmap instructions authorize only this offline code proposal; no provider facts/prices are adopted.

Selected rules: distinct recipient-role normalization; versioned content binding; exact subject/body bytes; attachment bytes plus filename/order binding; a hash is not authorization; no mailbox/credentials/delivery in the synthetic boundary. Other source requirements remain open and are listed above.
