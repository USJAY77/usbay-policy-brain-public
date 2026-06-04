---
name: USBAY governance dashboard conventions
description: Naming reality, preview-section pattern, and test-runner quirks for the single-file FastAPI gateway
---

# USBAY governance dashboard

## "Euria" branding does not exist — product is USBAY
Users repeatedly ask to verify/render "Euria" fields (e.g. `authority_euria`, "Euria Analysis ID"). The codebase has zero "Euria" references; everything is USBAY-namespaced. When a request names "Euria", confirm whether they want a net-new feature vs. the wrong project — do NOT assume an "API mapping bug."
**Why:** Avoids building on a false premise. A user did confirm they wanted "Euria" built as a brand-new preview-only UI layer on top of USBAY.

## Preview-only demo sections are playground-scoped and must stay additive
Demo/preview sections (scenario launcher, demo-readiness, governance-assessment-result) render only on `/playground` (nav label "Governance Control Plane"; `/` is "Policy Enforcement Gateway"). They must NOT leak to `/` or `/dashboard`. Keep each fully self-contained: scoped CSS prefix + IIFE, client-side only, no fetch/backend, no governance-logic changes.
**How to apply:** Add them in the playground page builder (grep `def playground_html`), before the runtime-telemetry `strip`. The page HTML goes through Python `%`-formatting, so escape every literal `%` as `%%`, and `esc()` all dynamic JS values.

## Test runner quirk
Repo has ~150 test files; whole-repo `pytest` exits `-1` with no output in the sandbox — run per-file/per-target. Gateway-relevant suites: `tests/test_gateway_app.py`, `tests/test_governance_dashboard.py`. `./signed_test.py` is a live-network test that fails on SSL verification offline — pre-existing, unrelated.

## Dev-preview 502 — root cause + fix
Bare dev domain returned 502 while `:5000` was 200, because `.replit` `[[ports]]` pins externalPort 80 -> localPort 8765 (stale; nothing listens there) while the app runs on 5000. `.replit` cannot be edited directly (platform-protected) and `configureWorkflow` only sets the workflow's own `waitForPort` (5000) — it does NOT reassign the stale externalPort, and a hard restart does not reconcile a pinned `[[ports]]` entry.
**Fix:** added `scripts/preview_port_forward.py` (stdlib asyncio TCP relay 0.0.0.0:8765 -> 127.0.0.1:5000) and run it backgrounded in the workflow command before uvicorn. This makes externalPort 80 reach the app, so bare `/` and `/playground` return 200. Production unaffected (uses `$PORT`).
**Why a relay, not a .replit edit:** direct `.replit` edits are blocked and no exposed tool rewrites externalPort; the relay is the minimal, reversible, governance-logic-free way to satisfy the existing 80->8765 mapping. The workspace preview pane / screenshot tooling also expect the app on port 80, so this fixes those too.
