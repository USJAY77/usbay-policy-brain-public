# GAME Demo Prototype Stability Gate (USBAY-GAME-010R)

_Last run: 2026-06-24 17:46:39Z_  ·  **Overall result: PASS**

**Scope:** STABILITY / TESTING ONLY, additive, read-only. This gate never
modifies or exercises `/execute`, governance enforcement, the simulator,
booking, or payment, and makes no external network calls. `gateway/app.py` and
the `/game` prototype are not modified.

## Stability command
```bash
python3.11 scripts/game_stability_gate.py
```

## Boot check
- GET /game -> 200 (76984 bytes)

## DOM test result
- Suites: `tests/test_game_interactive_dom.py`, `tests/test_game_ux_hardening_dom.py`, `tests/test_game_stability_gate_dom.py` (one shared jsdom render)
- Summary: `23 passed in 3.95s`
- passed=23 failed=0 skipped=0 errors=0
- Result: **PASS** (a skip is treated as a failure - no silent skips)

## Runtime benchmark
- Total gate runtime: **6.5 s**
- DOM-suite phase: 4.7 s
- Warm run (this run, from harness `__timing`): import=2213 ms · construct=417 ms · execution=489 ms · total=3126 ms
- Cold run (009A staged baseline, cited): import=74934 ms · construct=3547 ms · total=78662 ms

## Timeout guardrails
- Expected warm runtime: ~60 s
- Expected cold runtime: ~120 s
- Acceptable timeout threshold (hard fail above this): 300 s
- This run: 6.5 s -> within expected window (<= 300s)

## Safety regression result
| Property | Result | Detail |
| --- | --- | --- |
| demo banner remains visible | PASS | present at load + after route/cs/a11y |
| no booking/payment UI | PASS | buttonsBad=[] inputs=[] |
| no external network calls | PASS | net=[] |
| no personal data persisted | PASS | persist=[] cookie='' |
| VIP discount remains demo-only | PASS | fixed 20% cut, no real-money language |
| route selection deterministic | PASS | fixed winners + 15 trips |
| child-safe active after interactions | PASS | child-safe + banner persist after route |
| accessibility active after interactions | PASS | a11y + banner persist after route |

## Forbidden-file check
- 1 files changed in working tree
- Forbidden surfaces: `gateway/app.py`, prefixes `runtime/`
- Violations: NONE -> **PASS**

## Remaining limitations / gaps
- jsdom module import dominates wall-clock (cold ~75 s / warm ~32 s); it is
  irreducible here - jsdom 29 cannot be bundled into one file (it reads its own
  data assets from disk at runtime).
- Cold cache cannot be force-reproduced (no privilege to drop the OS page cache),
  so cold timing is cited from the 009A staged probe, not measured live.
- Boot is verified in-process via `TestClient` (the same path the DOM tests use),
  not against the long-running workflow server.

## Rollback
```bash
git checkout HEAD -- tests/conftest.py
rm -f tests/test_game_stability_gate_dom.py scripts/game_stability_gate.py \
      evidence/audit/GAME_DEMO_STABILITY_GATE_010R.md
```
