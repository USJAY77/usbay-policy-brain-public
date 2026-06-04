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

## Dev-preview 502 (not yet fixed)
Public dev domain returns 502 while `localhost:5000` is 200, because `.replit` `[[ports]]` maps externalPort 80 to a localPort nothing listens on; app runs on 5000. Production unaffected (uses `$PORT`). This blocks live browser screenshots of dev-only changes.
