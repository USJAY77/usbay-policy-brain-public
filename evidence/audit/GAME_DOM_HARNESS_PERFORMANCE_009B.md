# GAME DOM Test Harness — Performance Hardening (USBAY-GAME-009B)

**Scope:** TEST INFRASTRUCTURE ONLY. Additive. No change to gameplay, governance,
the simulator, `/execute`, booking/payment, or any production/UI code. The
demo-only `/game` prototype (`gateway/app.py::usbay_game_html`) is **untouched**.

This report records the before/after benchmark for the jsdom-backed browser-level
test harness that executes the real client-side JavaScript of the `/game`
prototype inside jsdom and asserts on the resulting DOM.

---

## 1. Files changed

| File | Status | Change |
| --- | --- | --- |
| `tests/conftest.py` | modified | Subprocess timeout for the shared session render raised `180 → 300` s so a worst-case **cold** first render cannot spuriously fail. The session-scoped `dom_result` fixture itself pre-existed (GAME-008). |
| `tests/game_dom_harness.mjs` | modified | Phase **timing instrumentation** added: `nodeStartupMs`, `importMs`, `constructMs`, `executionMs`, `teardownMs`, `totalMs`, emitted as `R.__timing`. The `jsdom` import was converted from a static top-level import to a timed `await import("jsdom")` purely to measure it. No behavioral change to what is asserted. |
| `tests/test_game_ux_hardening_dom.py` | **new** | 7 GAME-009R UX/behavior tests that **reuse the single session render** via the shared `dom_result` fixture, so they add **zero** additional jsdom imports. |
| `tsconfig.json` | **new** | Reduces TypeScript/LSP contention: `typeAcquisition.enable = false`, `types: []`, and excludes `node_modules` plus `tests/**/*.mjs` / `tests/**/*.cjs` from indexing. |

---

## 2. Root cause (from 009A) — confirmed

The cost is dominated by the **jsdom module import** (hundreds of small file reads
on a slow, I/O-bound filesystem), not by memory, CPU, or selector work:

- 009A staged cold probe: `importMs = 74934`, `constructMs = 3547`,
  `selectorMs = 13`, `total = 78662`.
- Environment was I/O-bound, not saturated: memory ~1.4 GB / 16 GB, load ~4 / 8,
  `node` no-op cold startup ≈ 4.27 s real with buff/cache only ~469 MB.
- 7+ TypeScript LSP processes were observed contending for I/O during runs.

009B's instrumentation independently re-confirms this: import is **~91 %** of a
warm run's wall-clock.

---

## 3. Timing — before vs after

### Per single full-harness run (instrumented)

| Phase | BEFORE (009A staged probe, **cold**) | AFTER (009B, **warm**) |
| --- | --- | --- |
| node startup | ~4,270 ms (noop) | 1,522 ms |
| **jsdom import** | **74,934 ms** | **32,021 ms** |
| JSDOM construct | 3,547 ms | 1,613 ms |
| execution (full interaction walk) | (selector probe 13 ms) | 1,232 ms |
| teardown | — | 2 ms |
| **total** | **78,662 ms** | **35,012 ms** |

> Cold cannot be re-measured exactly in 009B: dropping the OS page cache requires
> root, which is unavailable here. Cold figures are cited from the 009A staged
> probe; warm figures are measured in 009B.

### Whole DOM suite via pytest (shared session render, hot cache)

```
tests/test_game_interactive_dom.py  (8 GAME-008 tests)
tests/test_game_ux_hardening_dom.py (7 GAME-009R tests)
=> 15 passed in 9.99s
```

---

## 4. Improvements delivered

- **jsdom import improvement:** import remains the single dominant phase (~91 % of
  a warm run). The structural win is **import count**, not per-import time: the
  session-scoped fixture renders **exactly once per test session** regardless of
  how many DOM test files exist. Adding the 7 GAME-009R tests therefore costs
  **0 extra jsdom imports** — without session reuse it would have added one more
  import (≈ +32 s warm / ≈ +75 s cold). Per-run import time itself can only be
  reduced by bundling, which is not feasible for jsdom 29 (see §5).
- **Warm-cache improvement:** the full 15-test DOM suite runs in **~10 s** hot in
  a single shared render; a single full instrumented run is **~35 s** warm vs the
  **~79 s** cold 009A baseline.
- **Cold-run robustness:** subprocess timeout raised `180 → 300` s so a cold first
  render (~79 s plus headroom) cannot cause a false failure.
- **LSP/TS contention reduced:** `tsconfig.json` disables automatic type
  acquisition and removes the harness `.mjs`/`.cjs` and `node_modules` from TS
  indexing, cutting `typingsInstaller`/LSP I/O that competed with the harness.

---

## 5. Remaining bottlenecks

- **jsdom module import (cold ~75 s / warm ~32 s) is irreducible without
  bundling**, and bundling is **DEFERRED — not cleanly possible for jsdom 29**:
  - An esbuild **ESM** bundle (required because the harness uses top-level
    `await`) first failed with `Dynamic require of "path" is not supported`. That
    was fixed with a `createRequire(import.meta.url)` banner.
  - The rebuilt bundle then failed with **`__dirname is not defined in ES module
    scope`**: jsdom reads its own data assets — e.g.
    `browser/default-stylesheet.css`, and the XHR sync worker — from its package
    directory via `__dirname`-relative `fs.readFileSync` **at runtime**. A single
    12 MB bundle would still require those on-disk assets, which defeats the
    purpose of bundling.
  - Conclusion: jsdom 29 is effectively unbundleable into one self-contained
    file. `esbuild` was removed and `package.json` restored to its original
    dependency set (`prettier`, `typescript`, `jsdom`).
- **Cold-cache cannot be force-reproduced** in this environment (no privilege to
  drop the page cache); cold numbers are cited from the 009A staged probe.

---

## 6. Rollback

```bash
git checkout HEAD -- tests/conftest.py tests/game_dom_harness.mjs
rm -f tests/test_game_ux_hardening_dom.py tsconfig.json
```

This fully reverts 009B: it restores the original subprocess timeout and the
static jsdom import / un-instrumented harness, and removes the new GAME-009R test
file and the TypeScript config. `gateway/app.py` is untouched by 009B, so nothing
in the application or its `/game` prototype changes on rollback.
