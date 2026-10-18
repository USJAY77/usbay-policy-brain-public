# USBAY local staging and authority-storage fixes

Status: PARTIAL overall; selected local validation PASSED. Not a production release.

## Baseline and scope

Repository: USJAY77/usbay-policy-brain-public.
Baseline commit: 3b68ba1e369151bb8ec8e863b1ffab9c3b79b3c3.
Baseline tree: 94e8bcc0608267c46fb03927d4b8839d6c139f41.
The patch consolidates the earlier eight-file staging overlay and this isolated local fix.
The original checkout, earlier candidate and recovery material are preserved.
No active Replit configuration, credentials, approval policy, deployment or external repository was changed.

## Implemented behavior

staging/launch.py requires explicit production security mode, separate staging runtime scope,
one worker, lifespan on and a valid port. Conflicting overrides and reload are rejected.
The proposed TOML invokes this guard; actual .replit is unchanged. Omitting a deployment
stanza does not disable baseline Autoscale settings or authorize platform activation.

The current signed approval contract only supports production authority. This batch does
not broaden that contract. The staging launcher rejects enabled Live-Policy evaluation;
it supports guarded startup/health validation only. A separate reviewed authority-model
change is needed before staging policy evaluation can be enabled.

DurableAuthorityRegistry now serializes cooperating POSIX processes using flock, verifies
registry/evidence pairs, flushes and fsyncs files and directories, and persists an uncertainty
marker before paired append. Readers reject uncertainty, corrupt or mismatched evidence.
A failed or interrupted write requires reviewed reconciliation; no auto-truncate or recovery
silently restores old authority. Revocation rejects stale writers. Evidence path aliases to
the registry or protocol files are rejected. Existing event formats are retained.

## Actual validation

Final selection: 520 passed, 0 failed in 27.00 seconds across 16 modules.
Exact command, collected nodeids and complete output are retained outside the source tree.
Tests cover seven fsync failure points, fresh-process reopen after uncertainty, abrupt
writer termination, process serialization, concurrent first creation, side-effect-free
missing lookup, evidence corruption and path conflicts. Existing stores that lack the
cooperating lock protocol fail closed; synthetic compatibility fixtures now copy the lock
state explicitly instead of silently bypassing that boundary.
Real lifespan runs exercise valid, missing, tampered and stale synthetic release inputs.
The stale test uses the actual configured age limit; the current policy permits a very
long release age. Passing this boundary test does not endorse that production policy.
Existing actual signed production-adoption expiry cases remain unchanged and pass.
Other endpoint cases use fixture loaders and/or omit lifespan; they are not startup proof.

Earlier unsuccessful runs are preserved: a stale-test age assumption was corrected;
a harness subprocess denial was reproduced on the unchanged candidate and resolved by
allowing only the reviewed, guarded local Hydra worker; exploratory staging-adoption
positive cases demonstrated the unsupported approval scope and were replaced with an
explicit rejection regression. No product consensus or approval checks were weakened.

CPython 3.11.17 uses a separate hash-enforced wheel-only target with 40 exact locked
distributions. Every downloaded wheel matched its requirement hash and CPython 3.11/Linux
x86-64 tags; dependency consistency and exact installed versions passed. No active
site-packages were reused. No synthetic private key or runtime
registry/database is included in this review package.

## Isolation and remaining risks

Kernel seccomp denies IPv4/IPv6 socket creation and bind/listen. Python audit guards
restrict filesystem/process access and wrap reviewed multiprocessing/Hydra children.
This is not an OS filesystem sandbox; arbitrary native filesystem access is not contained
by Python audit hooks. Tests used temporary synthetic state and fresh synthetic keys.
No standalone service, real enrollment, policy activation or external app connection ran.

File pairing is a fail-closed protocol, not a rollback-atomic or distributed transaction.
flock and fsync evidence applies only to cooperating processes sharing the same tested
local filesystem. No Autoscale, independent-instance, volume, backup/restore, hardware
power-loss or production durability guarantee is established. Complete rollback to an
older internally consistent pair needs an external freshness anchor to detect.
If storage cannot persist any uncertainty marker, a process-local poison cannot guarantee
blocking after a later restart; platform recovery needs independent operational controls.
The gateway revalidation-to-final-evidence race identified in the earlier design remains
outside this fix. Secret handling and production trust material were not changed.

## Review and activation

Apply only to the exact baseline after reviewing the patch and evidence. Old registries
with missing evidence will now fail closed and require explicit reconciliation. POSIX
locking is required; unsupported platforms have no unsafe fallback. Review the storage
behavior and authority-scope limitation before any PR or activation. Publication does not
authorize merge, deployment or production use.
