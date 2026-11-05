# Governed Mail synthetic isolation preflight proposal

Status: PREPARED_NOT_PUBLISHED_NOT_RUN_IN_CI.

This candidate tests an ephemeral Ubuntu runner with synthetic canaries only.
It does not upload the unpublished Replit mail implementation or original mail
fixtures, invoke mail tests, start the app, connect a provider or issue authority.
Application execution and production readiness stay false in every report.

The proposed CI job checks out the exact PR head without persisted credentials,
uses read-only repository permissions, runs the result-contract unit tests, then
attempts a user/network/mount/PID namespace and a minimal chroot. The historical
kernel-restriction function is reused with its AST unchanged. The child loses
capabilities, receives a sanitized environment and inherits Landlock/seccomp.
A fresh interpreter must pass the exact ten-control set. Missing kernel support,
failed setup, timeout, incomplete controls or artifact upload failure fails CI.
There is no sudo, dependency installation, privileged fallback or automatic retry.

The synthetic probes cover source read/write, runtime write, an outside canary,
host process metadata, socket creation, a non-allowlisted shell executable,
chroot/namespace calls and writable scratch. They are bounded observations, not
an exhaustive sandbox assessment. In particular, the historical syscall filter
and process-command policy need independent review before application validation.
The original Python audit command grammar is not installed by this capability
probe. No probe result automatically authorizes the 475-case suite.

The separate suite_pass helper rejects incomplete or overlapping inventories,
missing terminal reports, test/group/controller failures and failed/skipped
subtests. Its unit tests pass locally. It is a proposed future harness integration
contract; the old Replit controller has not been modified or validated by this
proposal. Transitive dependency equivalence remains unproven.

Historical source intake was byte-verified against controller SHA256
16890c0ad83f6d124e6a9d63f7350aa7d615f1bfa2d4bfc0965508725bf0746c.
The original 475-node inventory remains bound to SHA256
b14fa64f2d7a1e037cadde87b46e968440e18e9822ec52255dbb906725476d02.
The original source-manifest SHA256 is
04ec8e9a35b2620e114624b9362b048723984e64a1325aaf195e2e8d19b759e0.
Those historical references are not new test outcomes or authority.

Review base: GitHub main 53e4c0efea5d5f67c91f70ba6b2b488b067d1530,
tree 33666efe14a83dfa867499c888bbafc1d0ac7250. No active app, main branch,
dependency policy, release issuer, trust anchor or operational grant is changed.

Before publication, complete canonical PB routing. Independent static review is
required before merge. Explicit publication and one CI-cycle authorization are required. The workflow
will also run the repository's existing PR checks. No merge is authorized.

Acceptance for this preparation is exact source intake, reproducible candidate
hashes, valid Python, passing result-contract unit tests and no remote writes.
Acceptance for a future CI preflight is a successful exact control set plus a
downloadable report/checksum artifact. Retention is thirty days, not permanent
archival or proof against an administrator modifying external evidence.

Even after preflight acceptance, mail validation requires a separately reviewed
source/dependency snapshot, exact inventory/exit integration and an applicable
authorized execution scope. Provider, release/issuer and production gates remain.
