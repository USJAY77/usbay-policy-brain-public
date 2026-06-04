---
name: USBAY governance dashboard conventions
description: Naming reality, preview-section pattern, and test-runner quirks for the single-file FastAPI gateway
---

# USBAY governance dashboard

## "Euria" branding does not exist — product is USBAY
Users repeatedly ask to verify/render "Euria" fields (e.g. `authority_euria`, "Euria Analysis ID"). The codebase has zero "Euria" references; everything is USBAY-namespaced. When a request names "Euria", confirm whether they want a net-new feature vs. the wrong project — do NOT assume an "API mapping bug."
**Why:** Avoids building on a false premise. A user did confirm they wanted "Euria" built as a brand-new preview-only UI layer on top of USBAY.

## Preview-only demo sections: two homes, two %-rules
Two distinct injection sites for preview-only UI. Both are client-side only (no fetch/backend), self-contained (scoped CSS prefix + IIFE), and must NOT touch governance logic.
1. **`_simulator_block_html()`** (grep that def) — injected at top of `<main>` on BOTH `/` and `/playground`. It returns a PLAIN triple-quoted string with NO Python `%`-formatting → use SINGLE `%` in CSS (do NOT write `%%`). The intake modal ("Start Governance Assessment" → "Generate preview" submit id=`usbsim-intake-submit`, handler `generatePreview()`) lives here.
2. **`playground_html()`** page builder — runs through Python `%`-formatting → escape every literal `%` as `%%`. Playground-only sections (e.g. demo-readiness) go here, before the runtime-telemetry `strip`.
Always `esc()`/`garEsc()` all dynamic JS values regardless of site.

## Governance Assessment Result is wired to "Generate preview", not a standalone button
The Governance Assessment Result panel (id=`usbsim-gar`) is rendered by `generatePreview()` inside the intake preview output (`#usbsim-intake-out`, itself inside the intake modal). Because it lives in `_simulator_block_html()`, it shows on both `/` and `/playground`. A prior standalone `#usbsim-assess` section (playground-only, own "Start Governance Assessment" run button) was removed to avoid a duplicate panel.
**Why:** user reported the panel "did not render" because they were on `/` where only the simulator block exists; the standalone panel was playground-only. Consolidating into the Generate-preview flow fixes both pages with one source of truth.
**How to apply:** outcome model lives in `GAR_DATA` (ALLOW/BLOCKED/HUMAN_REVIEW/FAIL_CLOSED → rec/sig/ts/euria/usbay/human); toggle chips re-render; IDs are random hex (`garHex`), illustrative only.

## Test runner quirk
Repo has ~150 test files; whole-repo `pytest` exits `-1` with no output in the sandbox — run per-file/per-target. Gateway-relevant suites: `tests/test_gateway_app.py`, `tests/test_governance_dashboard.py`. `./signed_test.py` is a live-network test that fails on SSL verification offline — pre-existing, unrelated.

## Dev-preview 502 — root cause + fix
Bare dev domain returned 502 while `:5000` was 200, because `.replit` `[[ports]]` pins externalPort 80 -> localPort 8765 (stale; nothing listens there) while the app runs on 5000. `.replit` cannot be edited directly (platform-protected) and `configureWorkflow` only sets the workflow's own `waitForPort` (5000) — it does NOT reassign the stale externalPort, and a hard restart does not reconcile a pinned `[[ports]]` entry.
**Fix:** added `scripts/preview_port_forward.py` (stdlib asyncio TCP relay 0.0.0.0:8765 -> 127.0.0.1:5000) and run it backgrounded in the workflow command before uvicorn. This makes externalPort 80 reach the app, so bare `/` and `/playground` return 200. Production unaffected (uses `$PORT`).
**Why a relay, not a .replit edit:** direct `.replit` edits are blocked and no exposed tool rewrites externalPort; the relay is the minimal, reversible, governance-logic-free way to satisfy the existing 80->8765 mapping. The workspace preview pane / screenshot tooling also expect the app on port 80, so this fixes those too.
