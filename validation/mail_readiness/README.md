# Explicit ephemeral CI namespace bootstrap proposal

Status: PREPARED_NOT_PUBLISHED_NOT_EXECUTED.
Parent: 4ce82a3406a6d56f3844b5ad79b7e4621bc45dd2.

The observed launcher exited1 with allowlisted categories Operation not permitted
and write failed. No child controls ran. The exact denied operation remains
UNKNOWN. This proposal tests whether an explicit privileged namespace bootstrap
can establish the existing synthetic boundary on a disposable Ubuntu runner.
It is an engineering hypothesis, not a proven fix or a new operational grant.

GitHub documents passwordless sudo on hosted Linux virtual machines:
https://docs.github.com/en/actions/reference/runners/github-hosted-runners
That platform facility is not owner authorization and does not guarantee that
the proposed isolation setup will succeed.

Only the explicitly selected launcher receives the fixed prefix
/usr/bin/sudo --non-interactive -- /usr/bin/unshare. The parent controller,
source identity check, report creation and artifact upload stay unprivileged.
The child then uses the existing namespace/chroot/read-only-mount preparation,
drops capabilities and installs the unchanged Landlock/seccomp function before
the fresh-child synthetic controls. The report records the selected mode.

No arbitrary sudo command is accepted. The default mode is unchanged; there is
no automatic privilege fallback or retry. No sysctl, AppArmor, secret handling,
workflow token permission, product policy or host-wide security configuration
is modified. No mail/application test, provider or live runtime is executed.

The additional OS privilege use is confined to an ephemeral GitHub-hosted CI
runner. It requires explicit owner authorization for publication and one new
CI cycle. Merge, deployment, activation and production/provider/release authority
remain outside scope. Human authorization permits only this test; positive
machine-verifiable controls remain necessary before any success claim.

Local validation: 24 pure standard-library tests pass, including four fixed
launcher-argument tests. The historical kernel function AST is unchanged.
No sudo or privileged namespace operation was executed locally.

Acceptance is an exact-head native report proving the complete synthetic control
set and a verified report/checksum artifact, or a preserved failure with no
automatic retries. Even successful controls would not certify a general sandbox
or authorize the 475-case mail suite. Independent review remains required before
integration/merge and before application validation.
