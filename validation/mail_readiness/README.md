# Bounded runner-owner mapping proposal

Status: PREPARED_NOT_PUBLISHED_NOT_PRIVILEGED_EXECUTED.
Parent: e66b5f10bd026b5d4b0f1f1212982472d6fbd70c.

Observed native result: child_exit2, Permission denied, no controls. Exact denied
operation remains UNKNOWN. A static review identifies a mapping mismatch risk:
sudo changes the current effective host user before --map-root-user selects it.
That does not prove it was the sole cause of the observed failure.

Primary reference for map-root-user, explicit one-ID mapping and setuid/setgid:
https://man7.org/linux/man-pages/man1/unshare.1.html

The proposed launcher preserves sudo/unshare, user/network/mount/PID namespaces,
capability dropping, chroot, read-only mounts and the unchanged kernel function.
It replaces the privileged mode's implicit host-root mapping with exactly the
original unprivileged controller's numeric UID and GID mapped to inner0, count1.
Host-root IDs, booleans, strings, wildcard or arbitrary ranges are rejected.
After mapping, the child explicitly selects inner UID/GID0; no supplementary
groups are granted. A source-owner check precedes mounts. The report records
the exact numeric mapping and source-bound mode, not an operational identity.

Colon mapping syntax requires a recognized util-linux2.x version >=2.39; old,
malformed and unknown-major versions stop before privileged launch. There is no
fallback. OS permissions and the ten positive/negative controls still determine
the actual outcome. The default unprivileged mode is unchanged.

The workflow bytes and sudo prefix remain identical to the already authorized
explicit-bootstrap proposal. No AppArmor/sysctl/seccomp relaxation, extra sudo
command, wildcard identity mapping, product authority or application test is
introduced. No root or namespace operation was executed locally for this proposal.

Local validation:34 pure tests pass, including ten new owner-mapping and version
contract tests. Kernel-function AST and workflow bytes are unchanged. Those
tests prove data/argv behavior only, not live namespace behavior.

Proposed next authorization is one bounded owner-mapping repair batch, with at
most three new-head CI cycles after evidence-backed corrections within the same
fixed sudo/unshare and synthetic-only boundary. No unchanged-run retries, kernel
policy relaxation, new privilege scope or application/mail tests. Stop on success,
the cycle limit, missing authority or a newly required permission. Preserve every
failure and verified artifact. Merge, deployment and activation remain excluded.


## Bounded repair cycle2

Cycle1 failed before controls with child_exit1 and no prior allowlisted launcher
category. util-linux2.39.3 source inspection shows range mapping invokes the
external newuidmap/newgidmap helpers even on this privileged launch path. This
source observation does not establish the native failure cause. Cycle2 only
adds fixed helper/range/set-ID categories, supported version and helper presence
to diagnostics. No mapping, workflow, kernel, sudo or permission change.
Primary source: https://github.com/util-linux/util-linux/blob/v2.39.3/sys-utils/unshare.c
