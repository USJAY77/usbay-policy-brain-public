# Dormant producer-trust candidate — review data only

NOT ADOPTED — NO PRODUCTION AUTHORITY — DRAFT ENGINEERING REVIEW.

## Source and publication boundary

The candidate provenance is original HEAD
3fdd34305311f2e4a97d34544c95d87e0dbf781c / tree
ae0f1774ed72add2da4a62d4f6203dca4cfc39d0, not this publication branch.
Its original manifest is 064c5a91a88c06af3208aea574a561522d4f5a1ea74eed502576761583d458f3.
The locally checked handoff archive is
23540896ca0a28b702550d90bd5d0d963039bce8544b316220ec525127cccbbf;
that archive is NOT included in this publication.

The publication parent is GitHub main dc549b2167dc6bdbe8e5b1c988bb27e9176e388e,
used only as a packaging tree. The original local baseline was not resolvable
through the GitHub compare API; the local source history is shallow. No claim
about missing remote ancestry is manufactured. A direct original-tree/main
comparison spans 161 unrelated paths, so none of those integration changes are
published here. No candidate was semantically rebased onto main's runtime.
Historical tests do not validate this packaging parent or its runtime contracts.

## Inert, byte-preserving export

Only this review directory is added. Every original candidate file is copied
byte-for-byte; all Python sources, including runners and executed snapshots, use
the additional `.txt` suffix and non-executable Git mode 100644. They cannot be
ordinary Python imports or pytest-discovered Python files in this publication.
There are no active loader/startup imports, workflow edits, dependency changes,
application source changes, production keys, or operational records.

EXPORT_MANIFEST.json maps every original candidate path to its exported path and
hash. All 53 original manifest-listed contents plus the original manifest are
present. The original manifest is retained unmodified as provenance; running a
path-based verifier on the renamed tree without the mapping is NOT a valid
original-manifest check. Verify the export inventory and resolve original paths
through its mapping. No altered-file or new-baseline execution identity is claimed.
Historical documents describe storage and task state when originally written;
they are not statements that this later public review export remains local-only.

## Preserved evidence, not new execution

The original failing reproduction (4 cases, exit 1), intermediate run (84 cases,
163 subtests, exit 0), and final source-bound run (85 cases, 163 subtests,
exit 0) remain separate. Their source snapshots, runner metadata, inventories,
results, stdout and stderr are preserved, including failure bytes.
Final pre/post inventory:
c19987564ab4f1b154a759b447a086eb6732c15e8356e2fe684d8ec02780517b.
This publication runs integrity/syntax checks only, not tests or application code.
Automatic existing repository checks, if triggered, are separate new CI evidence.

candidate/REVIEW.md is implementation self-review. The retained separate static
review reported READY_FOR_SCOPED_REVIEW within the synthetic boundary; its
conclusions are summarized in handoff/REVIEWER_BRIEF.md, not a signed human review.
Neither statement is an independent human approval or full security audit.

## Decisions and open gates

USBAY-AUDIT and USBAY-GLOBAL23 are intended reviewer labels only. Both records
remain UNFILLED and all decisions UNRESOLVED; authority and distinct-human identity
are UNKNOWN. No reviewer messages or approval requests are sent by this task.
A positive engineering review grants no trust adoption, root/key/policy choice,
loader integration, production storage, provisioning, configuration, merge,
signing, publication, deployment or activation authority. See PRODUCTION_GATES.md.
The candidate only supports explicitly scoped synthetic, synchronous,
process-local CPython behavior. Persistence/crash/distributed/hostile-process
guarantees, real time/revocation services, image/dependency integrity, build-to-
serving binding, and production readiness remain unproved.
