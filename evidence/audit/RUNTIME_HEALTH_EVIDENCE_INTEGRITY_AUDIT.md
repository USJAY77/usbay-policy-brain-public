# Runtime Health Evidence Integrity Audit (PB-RUNTIME-007)

**Scope:** `gateway/app.py`, `tests/test_gateway_app.py`, this document.
**Objective:** Prove that the Runtime Health audit evidence produced on every
governed `/execute` decision is **complete**, **tamper-evident**, and
**internally consistent** across runtime state, policy profile, profile reason
code, execution outcome, and the persisted record.

This work is **additive and evidence-only**. It introduces validation/audit
functions and tests; it does **not** change the `/execute` decision path, the
fail-closed behaviour, or any runtime-gateway enforcement. No simulator, travel,
voucher, tenant, RFC3161, or Codex surfaces were touched.

---

## 1. What evidence exists per decision

PB-RUNTIME-006 made the gateway emit a `runtime_health_profile_decision` audit
event on **every** governed `/execute` decision (allow and block, including
`HEALTHY`). PB-RUNTIME-007 makes that record self-describing and integrity-checkable.

Each persisted runtime-health decision record now carries:

| Field | Meaning |
|---|---|
| `decision_id` | Correlates the record to the execution decision. |
| `runtime_health_state` | `HEALTHY` / `DEGRADED` / `FAILED`. |
| `runtime_health_profile` | Active policy profile: `STRICT` / `BALANCED` / `CONTINUITY`. |
| `profile_reason_code` | Why the profile decided as it did (None for `HEALTHY`). |
| `execution_allowed` | Boolean execution outcome. |
| `audit_event_type` | Explicit event-type tag (`runtime_health_profile_decision`). |

`audit_event_type` is **new in PB-RUNTIME-007** — it is added to the event payload
and to the persisted-record allowlist so the record is self-identifying without
relying on the envelope `action` alone.

### Required-field constant

`RUNTIME_HEALTH_EVIDENCE_REQUIRED_FIELDS` enumerates the six fields above. A record
missing any of them, or whose non-null fields are null, is flagged
`RUNTIME_HEALTH_EVIDENCE_INCOMPLETE`. `profile_reason_code` must be *present* but is
allowed to be `None` (its legitimate value for a `HEALTHY` decision).

---

## 2. Tamper-evidence — hash chaining IS supported

**Status: SUPPORTED (not a gap).**

The workspace persists every audit event inside a SHA-256 hash-chained entry
*envelope* (`audit/hash_chain.py`). Each entry has the shape:

```
{ "timestamp", "action", "decision", "hash_prev", "hash_current" }
```

where `hash_current = SHA-256(hash_prev + canonical_json({timestamp, action, decision, hash_prev}))`
(`compute_hash`), and `verify_chain` re-derives every link from `GENESIS_HASH`.

**Mapping to the task's `previous_audit_hash` / `audit_hash`:** these correspond to
the envelope's `hash_prev` / `hash_current`. The hashes deliberately live on the
**envelope**, not inlined inside the `decision` record, because inlining a record's
own hash into the record it hashes would be circular. The honest framing: the
decision record is the hashed payload; the chain entry that wraps it provides
`previous_audit_hash` (`hash_prev`) and `audit_hash` (`hash_current`). This is
tamper-evident and deterministically verifiable — **no gap, no faking required.**

`_runtime_health_entry_hash_valid()` performs the deterministic recompute for a
single entry and optionally checks linkage to the previous entry's hash. Any
mutation of a persisted record without recomputing its hash is detected.

---

## 3. Internal consistency

`_runtime_health_evidence_consistent()` enforces the canonical state/profile/reason/
outcome matrix (fail-closed — unknown combinations are inconsistent):

| State | Profile | `execution_allowed` | `profile_reason_code` |
|---|---|---|---|
| `HEALTHY` | any | `True` | `None` |
| `FAILED` | any | `False` | (blocks in every profile) |
| `DEGRADED` | `STRICT` | `False` | `PROFILE_STRICT_DEGRADED_BLOCK` |
| `DEGRADED` | `BALANCED` | `True` | `PROFILE_BALANCED_DEGRADED_WARNING` |
| `DEGRADED` | `CONTINUITY` | `True` | `PROFILE_CONTINUITY_DEGRADED_WARNING` |

A profile value outside `RUNTIME_HEALTH_PROFILES`, a non-boolean
`execution_allowed`, a `HEALTHY` record carrying a reason code, or a
profile/state/reason mismatch all yield `RUNTIME_HEALTH_EVIDENCE_INCONSISTENT`.

This complements the existing selector invariant: an unrecognised
`RUNTIME_HEALTH_PROFILE` env value resolves to `STRICT` (fail-closed), re-asserted
by `test_invalid_profile_resolves_to_strict_fail_closed`.

---

## 4. No sensitive data

`runtime_health_evidence_contains_sensitive_data()` is fail-closed: a record is
rejected (`RUNTIME_HEALTH_EVIDENCE_SENSITIVE_DATA`) if it contains any forbidden
**key** (`decision_signature*`, `signature`, `payload`, `raw_payload`,
`private_key`, `secret`, `password`, `actor_id`, `user_id`, `client_id`, `device`,
`nonce`) or any forbidden **value marker** (`-----begin`, `private_key`,
`decision_signature`). Hashed counterparts (e.g. `actor_hash`, `nonce_hash`) are
explicitly permitted — only the raw forms are forbidden. A record that cannot be
serialised is treated as sensitive (cannot be proven clean).

---

## 5. Validation surface (functions added)

All functions are **pure / fail-closed and never raise**:

- `validate_runtime_health_evidence_record(record) -> (bool, [codes])` —
  completeness + event-type + no-sensitive-data + consistency.
- `validate_runtime_health_evidence_entry(entry, *, prev_hash=None) -> (bool, [codes])` —
  record validation + envelope action check + deterministic hash integrity.
- `audit_runtime_health_evidence(chain=None) -> report` — walks the full persisted
  chain (default `audit_chain.load()`), verifies tamper-evident linkage across
  every entry, and validates every runtime-health record. Returns:
  `{ hash_chain_supported: True, checked, valid, hash_chain_valid, failures[] }`.

These are **not wired into `/execute`** — they are offline/CI integrity auditors.
This deliberately preserves the existing decision path and fail-closed behaviour
(no new runtime failure mode is introduced into request handling).

### Reason codes

`RUNTIME_HEALTH_EVIDENCE_VALID`, `_INCOMPLETE`, `_INCONSISTENT`, `_SENSITIVE_DATA`,
`_WRONG_EVENT_TYPE`, `_HASH_CHAIN_BROKEN`.

---

## 6. Test coverage (`tests/test_gateway_app.py`)

Pure-record validation:
- valid `HEALTHY/BALANCED` record passes; valid `DEGRADED/STRICT` block passes.
- **missing each required field** fails (`runtime_health_state`,
  `runtime_health_profile`, `profile_reason_code`, `execution_allowed`,
  `audit_event_type`) → `INCOMPLETE`.
- null required field → `INCOMPLETE`.
- **mismatched** profile/state/reason → `INCONSISTENT`; `HEALTHY` with a reason
  code → `INCONSISTENT`; invalid profile value → `INCONSISTENT`.
- wrong `audit_event_type` → `WRONG_EVENT_TYPE`.
- sensitive data (raw signature, raw `actor_id`) → `SENSITIVE_DATA`; hashed
  counterparts are not flagged.
- invalid `RUNTIME_HEALTH_PROFILE` env → selector resolves to `STRICT`.

Hash-chain / persisted-evidence integration (real `/execute` via test client):
- persisted runtime-health entry passes entry validation; full-chain audit reports
  `hash_chain_supported=True`, `hash_chain_valid=True`, `valid=True`.
- **tampering** a persisted record without recomputing its hash → audit reports
  `hash_chain_valid=False`, `valid=False`.
- an incomplete persisted record (hash intact) → `valid=False` with the failing
  `decision_id` and reason codes surfaced; empty chain is vacuously valid.

**Result:** `114 passed` (`tests/test_gateway_app.py`). Regression:
`tests/test_voucher_authority.py` + `tests/test_governance_actions_policy_approvals.py`
→ `74 passed`.

---

## 7. Conclusion

Runtime Health audit evidence is **complete** (six required fields, enforced),
**tamper-evident** (SHA-256 hash-chained envelopes, deterministically
re-verifiable — supported, not faked), **internally consistent** (canonical
state/profile/reason/outcome matrix, fail-closed), and **free of raw sensitive
data**. The added surface is additive, evidence-only, and preserves the existing
fail-closed `/execute` decision path.
