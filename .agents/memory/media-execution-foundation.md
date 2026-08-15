---
name: Governed media execution foundation
description: Higgsfield/media provider governance foundation in workspace — fail-closed by design, blocked pieces, evidence conventions
---

# Governed media execution foundation (workspace, not pb-main)

- `governance/media_execution.py` + `governance/media_provider_adapter.py` + `tests/test_media_execution_governance.py` implement the bounded MediaExecutionContract, fail-closed gate, single-use SQLite consumption store, hash-chained evidence, and human publication gate.
- **Rule:** HiggsfieldAdapter must stay fail-closed (`HIGGSFIELD_INTERFACE_NOT_PROVEN` / `PROVIDER_NOT_CONFIGURED`) — no official Higgsfield API/CLI/MCP interface has ever been proven from this environment. Never fabricate provider HTTP calls.
- **Why:** governance batches explicitly forbid invented endpoints; discovery (Aug 2026) confirmed zero Higgsfield presence and no MCP libs installed.
- Evidence reuses `audit/ledger.py` chain format (extra fields allowed; required fields populated with semantic hashes) so `verify_chain` works on `audit/media_execution_evidence.jsonl`.
- Known accepted limitation: MediaAuthorization/PublicationAuthorization are caller-constructed — unverifiable until the durable authority registries exist (same blocker as PR #318 live wiring). Adapter substitution and evidence field leakage ARE enforced (closed adapter class registry, metadata allowlist, result-to-contract binding).
- Pre-existing failures: 5 tests in `tests/test_gateway_app.py` (GAME-017R) fail on the workspace branch independent of any media work.

## Governance hardening batch (Aug 2026)
- `governance/authority_registry.py` (MediaAuthorityRegistry) is now MANDATORY in `execute_media_contract` (`authority_registry=` kwarg; None => BLOCK AUTHORITY_REGISTRY_MISSING). Order: adapter check -> validate+reserve -> registry verify (consumes approval) -> adapter.
- **Why:** caller-constructed MediaAuthorization was unverifiable; registry binds actor+approval terms via binding hash, single-use, expiry, optional execution_id pinning.
- Residual (architect-confirmed): register_actor/register_approval are unauthenticated mutators — anyone with DB access can mint approvals. Real fix needs signed issuer/identity infra. Never claim GAP-1 PROVEN until then.
- Subprocess layer (`security/execution_guard.py _run_command`): allowlisted env only (secret-like approved_env names refused), timeout + process-group SIGKILL (start_new_session), 64KB output cap post-hoc (memory exhaustion during communicate() still possible — residual), evidence needs tenant_id or immutable_ledger raises tenant_context_missing.
- /game #usbgre panel is server-rendered snapshot (@@TOKEN@@ replacement), zero client fetches; diagnostic values labeled "(SELF-REPORTED)". Tests assert fetch count == 0 on /game.
