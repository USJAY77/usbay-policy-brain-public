# Test Execution Lanes

USBAY validation remains fail-closed: passing a narrow lane is never proof of
release readiness. The lanes below reduce repeated local validation during
implementation while preserving full-suite validation before commit/PR/merge
readiness.

## Current Runtime Profile

Baseline profile command:

```bash
pytest -q --durations=50 --durations-min=0.25
```

Clean `origin/main` profile on this audit collected 4178 tests and completed in
5682.83 seconds. The top slow group was repeated production-readiness heavy-scan
coverage in `tests/test_production_readiness.py`, where each negative case
re-runs the full heavy scan over a synthetic repository. Secondary slow groups
were regulator export profile and evidence renewal runtime tests, which perform
repeated file serialization, cryptographic verification, and CLI-style evidence
checks.

## Lane Rules

### Fast Lane

Use during iterative implementation for a narrowly scoped module change.

Required checks:

```bash
python3 -m py_compile <changed-python-files>
python3 -m json.tool <changed-json-evidence-files>
pytest -q <changed-test-files> <direct-upstream-tests> <direct-downstream-tests>
git diff --check
git diff --cached --check
```

The fast lane must include the changed test file, directly changed runtime
module tests, direct upstream/downstream contract tests, governance evidence
validation, compile validation, JSON validation, and diff checks. It must not
skip a known failing test.

### Phase B/PB-C Regression Lane

Use after a Phase B runtime or PB-C module reaches focused green.

Current executable PB-C lane in this worktree:

```bash
pytest -q \
  tests/test_runtime_release_gate_adapter.py \
  tests/test_runtime_simulator.py \
  tests/test_human_approval_gateway.py
```

When present in the worktree, include the full Phase B runtime chain:

```bash
pytest -q \
  tests/test_agent_runtime.py \
  tests/test_execution_scheduler.py \
  tests/test_event_bus.py \
  tests/test_runtime_health.py \
  tests/test_runtime_coordinator.py \
  tests/test_runtime_evidence_aggregator.py \
  tests/test_runtime_policy_binding.py \
  tests/test_runtime_approval_gate.py \
  tests/test_runtime_replay_verifier.py \
  tests/test_runtime_release_gate_adapter.py \
  tests/test_runtime_simulator.py \
  tests/test_human_approval_gateway.py \
  tests/test_edgeguard_demo.py \
  tests/test_decide_first.py
```

This lane verifies metadata-only runtime contracts, evidence-chain continuity,
approval flow, replay/release flow, EdgeGuard tenant-authority regression, and
all execution flags remaining false.

### Full-Suite Release Lane

Use exactly when release evidence is required:

```bash
pytest -q
```

The full suite remains mandatory:

- once after implementation is complete;
- once before `READY_FOR_HUMAN_TERMINAL_COMMIT`;
- after any shared fixture, runtime, security, or governance enforcement change;
- after merge on `main`.

Do not repeatedly run the complete suite during intermediate local edits unless
a shared critical component changed.

### Slow Profiling Lane

Use to refresh evidence when test runtime changes materially:

```bash
pytest -q --durations=50 --durations-min=0.25
pytest --collect-only -q
```

Slow tests must be classified before optimization as sleep, polling, timeout,
subprocess, cryptography, repeated fixture setup, filesystem, Git operations,
large parameterization, service initialization, serialization, or unknown.

## Performance Fix Policy

Allowed fixes:

- reuse immutable parsed fixtures;
- reuse deterministic hash fixtures;
- replace real sleeps with injected clocks;
- replace polling waits with deterministic state transitions;
- avoid repeatedly creating identical temporary repositories;
- cache immutable schema loading inside tests;
- narrow expensive setup to tests that actually need it;
- remove duplicate validation invocations.

Prohibited fixes:

- weakening assertions;
- marking failures `xfail`;
- deleting governance, security, fail-closed, tenant, evidence, or crypto tests;
- changing production decisions for speed;
- bypassing cryptographic verification;
- sharing mutable state across tests;
- hiding flakes with retries;
- enabling parallel execution before isolation is proven.

## Parallelization Assessment

Current verdict: `PARALLEL_UNSAFE_SHARED_GOVERNANCE_STATE`.

The suite contains tests that use fixed Git worktrees, process-wide environment
variables, local trust registries, signing key stores, subprocess-based
verifiers, and filesystem evidence paths. Pytest-xdist must stay disabled until
those resources are partitioned by worker and trust-state isolation is proven.
