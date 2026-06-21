---
name: Runtime Health Authority enforcement constraint
description: Why the governance runtime health gate cannot be enforced inline at /execute without breaking existing deny-path tests.
---

# Runtime Health Authority (governance gateway)

A fail-closed runtime health authority lives in `gateway/app.py` near the
`/health` route: a canonical snapshot over 5 read-only subsystem probes (policy
engine, audit, runtime storage, approval, revocation) that aggregates to
HEALTHY / DEGRADED / FAILED and exposes `GET /runtime/health` (HTML panel +
audit table, or JSON; 200/503) and `GET /runtime/health/selftest`.

## Enforcement placement (RESOLVED — gate is now live)

`runtime_execution_gate()` IS now wired into `POST /execute` (fail-closed). The
single safe placement is **after `validate_execution_decision()` + `verify`, and
immediately before `route_execution()`** (the only execution sink).

**Why this exact spot:** the specific deny reasons are emitted *inside*
`validate_execution_decision` — `missing_decision_id` (early) and `replay_detected`
(`record.get("used") is True`) — which runs BEFORE the gate, so those deny tests
(`test_replay_fails`, `test_missing_decision_id_precedes_provenance`, which install a
bad runtime authority) still get their specific `403`. Do NOT wire the gate at the
TOP of `/execute`: that returns a generic `503 runtime_health_blocked` first and
breaks deny-path ordering (that earlier attempt was reverted). Placing it after
validate/verify keeps deny precedence AND guarantees nothing executes while health
is FAILED/unavailable/indeterminate.

**Block response:** `runtime_health_block_response()` → `503`,
`error="runtime_health_blocked"`, `reason_code=RHC_RUNTIME_HEALTH_EXECUTION_BLOCKED`,
decision_id when known, reason_codes, + audit event `execution_blocked_runtime_health`;
never echoes raw payload/signature. A gate/probe exception synthesizes a FAILED
snapshot and blocks (fail-closed).

**DEGRADED is intentionally warning-only (allowed) — now the formalized canonical
policy (PB-RUNTIME-004, Option B).** Origin: PB-RUNTIME-001 design
(`_runtime_health_decision` → `EXECUTION_ALLOWED_WITH_WARNING`), pinned by
`test_runtime_health_degraded_warns_but_allows` + `test_degraded_runtime_health_still_allows_execute`
— these two tests ARE the product contract that forbids flipping DEGRADED to
fail-closed. Only FAILED (and authority/probe/gate exceptions) block. PB-RUNTIME-004
kept warning-only but made it non-silent: `/execute` now emits an explicit, fail-safe
(never-blocks, audit-failure swallowed) audit event `execution_allowed_runtime_health_degraded`
carrying `RHC_RUNTIME_HEALTH_DEGRADED_WARNING` (via `runtime_health_degraded_warning_event`,
fired after gate-allow, before route_execution, guarded on state==DEGRADED).
**Why warning-only, not block:** DEGRADED = subsystem still serving but with a
non-fatal signal; blocking on it turns a soft warning into a hard outage and pushes
operators to silence probes. Promoting DEGRADED to a block is a deliberate product
contract change (flip decision + add `*_DEGRADED_BLOCKED` code + update the two
contract tests), not a bug.

**PB-RUNTIME-006 (profile persistence):** HEALTHY `/execute` previously emitted NO
runtime-health audit event, so the governing profile could change silently between
healthy runs. Fix: a dedicated always-on event `runtime_health_profile_decision`
(reason_code `RHC_RUNTIME_HEALTH_PROFILE_DECISION`) fired via
`runtime_health_profile_audit_event(snapshot,*,decision_id,action)` at the `/execute`
call site AFTER the gate decides and BEFORE the block-return, so it records on EVERY
decision (allow AND block, incl. HEALTHY). It is fail-safe (swallows audit errors,
never touches `gate_allowed`). The allowlist was extended with `execution_allowed` +
`runtime_health_state` so all four required fields (those two + `runtime_health_profile`
+ `profile_reason_code`) PERSIST into the hash chain. Persistence is verifiable in
tests via `gateway_app.audit_chain.load()` → entries `{action, decision:<safe_event>}`.
**Lesson:** "emit on every decision" must be wired at the call site straddling the
allow/block branch, not inside the warning/block helpers (those fire on only one path).

**audit_governance_event allowlist:** persists only vetted fields — for the health
events that means `reason_code`, `decision_id`, `timestamp`, plus the non-sensitive
`runtime_health_profile` + `profile_reason_code` (PB-RUNTIME-005) and
`execution_allowed` + `runtime_health_state` (PB-RUNTIME-006). Extra keys like
`runtime_health_reason_codes`/`runtime_health_audit_trail` are PASSED but DROPPED at
persistence (deliberate data-minimisation; also the mechanism that blocks raw
payload/signature leakage). Tests assert on monkeypatched call args, not the stored
chain entry. **Lesson:** to make a new decision input persist (not just appear in
test-captured call args), you MUST add its key to this allowlist — otherwise it is
silently dropped from the stored chain.

## Runtime Health Policy Profiles (PB-RUNTIME-005)

DEGRADED handling is now policy-driven via named profiles, not hardcoded:
STRICT (DEGRADED→block), BALANCED (default, DEGRADED→warning-only), CONTINUITY
(DEGRADED→warning-only). FAILED + authority/probe/gate exceptions + unknown state
block in EVERY profile (fail-closed invariant — profiles only govern the DEGRADED
branch, can tighten it, can never loosen FAILED).

- Selector `runtime_health_profile()` reads env `USBAY_RUNTIME_HEALTH_PROFILE`:
  unset/empty→BALANCED (preserves the PB-RUNTIME-004 contract + its two pinned
  tests), valid (case-insensitive)→that, **invalid→STRICT (fail-closed)** so a
  typo can never loosen enforcement.
- `apply_runtime_health_profile(profile, snap)→(allowed, profile_reason_code)` is
  the pure decision table. `runtime_execution_gate(profile=None)` resolves the
  active profile (explicit arg if in RUNTIME_HEALTH_PROFILES else selector) and
  returns a **decorated COPY** of the snapshot (adds `profile`,
  `execution_allowed`, and on the profile-driven DEGRADED branch
  `profile_reason_code`, appended to `reason_codes`). `runtime_health_snapshot()`
  MUST stay pure — tests assert `reason_codes==[]` when healthy; never decorate it
  in place.
- **Why default=BALANCED:** any other default would flip
  `test_degraded_runtime_health_still_allows_execute` (DEGRADED `/execute`→200) —
  that test is the PB-RUNTIME-004 contract.
- **Decision-consistency trap (architect-caught):** when a profile blocks (STRICT
  on DEGRADED) you MUST also normalize the decorated `decision` to
  `RUNTIME_EXEC_BLOCKED`; otherwise the block response/audit reports the stale base
  `EXECUTION_ALLOWED_WITH_WARNING` and a blocked execution is mis-recorded as
  allowed-with-warning. Guarded by `test_execute_strict_profile_blocks_degraded`.
- Profile reason codes: `RHC_PROFILE_STRICT_DEGRADED_BLOCK`,
  `RHC_PROFILE_BALANCED_DEGRADED_WARNING`, `RHC_PROFILE_CONTINUITY_DEGRADED_WARNING`.
  The warning event keeps its event-level `reason_code=RHC_RUNTIME_HEALTH_DEGRADED_WARNING`
  (preserves a PB-RUNTIME-004 test) and carries the profile code separately as
  `profile_reason_code`. Evidence: `evidence/audit/RUNTIME_HEALTH_POLICY_PROFILE_AUDIT.md`.
- BALANCED and CONTINUITY are behaviorally identical today (both warning-only) by
  spec; CONTINUITY is a distinct named/auditable posture reserved for future
  divergence — do not collapse them.

**Natural test-env health = HEALTHY** (all 5 probes green under `configure_gateway`),
so allow-path `/execute` tests pass through the gate unchanged.

## Execution-path coverage (audit conclusion — now closed by PB-RUNTIME-003)

A prior execution-path coverage audit found `runtime_execution_gate()` had ZERO
production callers — observability-only, 0% coverage (GAP-1). PB-RUNTIME-003 CLOSED
this: the gate now has exactly one production caller in `/execute`, giving 100%
coverage of the single live governed execution path. Evidence:
`evidence/audit/RUNTIME_HEALTH_ENFORCEMENT_AUDIT.md`. (Historical 0%-coverage note
below kept for context.) There is exactly one governed compute path
(`POST /execute` -> `route_execution` in `security/compute_router.py` -> single
`executor.execute` sink); no alternate executor caller exists. This is a *coverage
gap*, not a classic bypass (no alternate route around an enforced gate, because the
gate is enforced nowhere). `runtime/enforcement_gateway.py` is execution-capable but
non-live (no Python importers; CLI-only via `governance_check.sh`). Evidence lives in
`evidence/audit/EXECUTION_PATH_{COVERAGE_AUDIT,GRAPH}.md` + `RUNTIME_BYPASS_MATRIX.md`.

## PB-RUNTIME-007: evidence integrity (hash chaining IS supported)

Tamper-evidence is SUPPORTED, not a gap. Audit records are persisted inside a
SHA-256 hash-chained entry *envelope* (`audit/hash_chain.py`): each entry is
`{timestamp, action, decision, hash_prev, hash_current}` where
`hash_current = compute_hash({timestamp,action,decision,hash_prev}, hash_prev)`.
The task's `previous_audit_hash`/`audit_hash` map to envelope `hash_prev`/
`hash_current` — hashes live on the ENVELOPE, never inlined into the `decision`
record (inlining a record's own hash is circular). Document this as supported.
**Why:** future "add audit_hash to the record" requests are wrong — recompute via
the envelope instead.

Evidence validators (`validate_runtime_health_evidence_record/_entry`,
`audit_runtime_health_evidence`, `_runtime_health_entry_hash_valid`) are
EVIDENCE-ONLY and deliberately NOT wired into `/execute` — wiring them in would add
a new runtime failure mode and risk the fail-closed decision path. Keep integrity
auditing offline/CI-only.

`audit_event_type` is a record field (= `runtime_health_profile_decision`) added to
the profile-event payload AND the allowlist; the envelope `action` carries the same
value. `profile_reason_code` must be PRESENT but may be None (legitimate for
HEALTHY) — required-but-nullable, distinct from the non-null required fields.

## PB-RUNTIME-008: cross-layer evidence linkage

Runtime-health records carry deterministic, non-sensitive context tokens linking
them to the wider governance chain: governance_context_id (REQUIRED, = namespaced
SHA-256 of decision_id), policy_context_id (best-effort, from signed policy
registry version), gateway_context_id (best-effort, from runtime provenance
current_commit). All opaque SHA-256(namespace|source)[:32] tokens — joinable by
recompute, leak nothing. **Why:** decision_id/version/commit are already
non-sensitive; hashing is defence-in-depth + uniform ids.

Context-id derivers MUST never raise (return None on failure) — they run before
audit_governance_event in the always-on profile-decision hook, so a raising
deriver would suppress the mandatory PB-RUNTIME-006 record. policy/gateway ids are
"if available": null + documented GAP when the layer is down, NEVER faked.

The audit hash binds decision_id<->audit_hash because decision_id sits INSIDE the
hashed decision record; mutating it breaks the envelope hash recompute (detected by
audit_runtime_health_cross_layer_linkage). governance_context_id derived from
decision_id gives a second, independent tamper signal (CONTEXT_MISMATCH).

Do NOT add governance_context_id to the 007 RUNTIME_HEALTH_EVIDENCE_REQUIRED_FIELDS
— that would break 007's _valid_evidence_record tests. 008 uses a SEPARATE
RUNTIME_HEALTH_CROSS_LAYER_REQUIRED_FIELDS layer and separate validators that wrap
the 007 ones.

**Architect false-positive (recurring):** the attached_assets/Pasted-PB-RUNTIME-0NN
task-spec file is the user's untracked attachment, NOT an agent change; architect
flags it as "out-of-scope file" every time. It is never in the commit — ignore.
