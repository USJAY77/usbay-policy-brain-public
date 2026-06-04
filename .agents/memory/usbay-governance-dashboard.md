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
Repo has ~150 test files (~1641 collected tests); whole-repo `pytest` exits `-1`/hangs in the sandbox — run per-file/per-target or per-marker (`-m critical`, `-m governance`). No `pytest-xdist` (`-n` unsupported). Some files hang on missing services (`test_redis_store`, `test_hydra_consensus`) — run lighter files individually with `timeout`. Gateway-relevant suites: `tests/test_gateway_app.py` (37 tests, all pass), `tests/test_governance_dashboard.py`. `./signed_test.py` is a live-network test that fails on SSL verification offline — pre-existing, unrelated.

## Pre-existing openssl Ed25519 test failures (sandbox env, NOT your change)
In the sandbox, the `critical` + `governance` lanes have ~5 pre-existing failures rooted in openssl Ed25519 signing/verification: `pkeyutl: Option unknown option -rawin` and `SystemExit: EVIDENCE_ED25519_SIGN_FAILED`. Affected: `tests/test_governance_validation.py` (committed-policy signature verify / fail-closed-on-changed-policy), `tests/test_production_readiness.py` (CI evidence manifest signature tests). Source: `runtime/policy_validator.py:~222`, `scripts/generate_ci_evidence_manifest.py:~824`.
**Why:** the sandbox openssl build lacks `-rawin` (raw Ed25519). These are environment-blocked, unrelated to any UI/simulator change — do NOT try to "fix" them when verifying a frontend task.

## Dev-preview 502 — root cause + fix
Bare dev domain returned 502 while `:5000` was 200, because `.replit` `[[ports]]` pins externalPort 80 -> localPort 8765 (stale; nothing listens there) while the app runs on 5000. `.replit` cannot be edited directly (platform-protected) and `configureWorkflow` only sets the workflow's own `waitForPort` (5000) — it does NOT reassign the stale externalPort, and a hard restart does not reconcile a pinned `[[ports]]` entry.
**Fix:** added `scripts/preview_port_forward.py` (stdlib asyncio TCP relay 0.0.0.0:8765 -> 127.0.0.1:5000) and run it backgrounded in the workflow command before uvicorn. This makes externalPort 80 reach the app, so bare `/` and `/playground` return 200. Production unaffected (uses `$PORT`).
**Why a relay, not a .replit edit:** direct `.replit` edits are blocked and no exposed tool rewrites externalPort; the relay is the minimal, reversible, governance-logic-free way to satisfy the existing 80->8765 mapping. The workspace preview pane / screenshot tooling also expect the app on port 80, so this fixes those too.

## Wizard checklist "bags" must be cleared in place, never reassigned
The Governance Pilot Wizard stores per-item toggle state in shared objects (`wizChecks.milestones/evidence/approvals/criteria`). `wizBindChecks()` adds ONE delegated `change` listener per container that closes over the bag object reference. Render/read (`wizRenderChecks`, `wizSelected`) read from `wizChecks.<bag>`.
**Why:** Reassigning a bag (`wizChecks.evidence = {}`) on restart / intake-handoff orphans the listener — it keeps writing to the old object while renders read the new one, so toggles silently stop persisting. Fix is `wizResetChecks()` → `wizClearBag()` which `delete`s keys in place, preserving object identity.
**How to apply:** any new wizard checklist must (1) bind once via `wizBindChecks`, (2) reset only by clearing in place. Adding a new bag means adding it to `wizResetChecks()` AND to the `wizBindChecks` calls at init.

## Governance Pilot Wizard is 9 steps and bridges from the assessment
Flow: assessment modal ("Generate preview") shows recommended license → "Continue to Governance Pilot" button (`#usbwiz-from-intake`) copies assessment form fields into `#usbwiz-form`, closes intake, and `openWiz(3)` jumps to Scope. Wizard steps: 1 Assessment, 2 License, 3 Scope, 4 Objectives, 5 Evidence, 6 Approvals, 7 Criteria, 8 Timeline, 9 Summary. CTA label is gated on `WIZ_MAX-1`/`WIZ_MAX`, not hardcoded step numbers.
**Why:** user wants the license recommendation kept as the bridge between assessment and pilot (no payment/booking framing). Assessment and wizard share identical form field `name`s, so prefill is a plain value/checkbox copy.

## Recommended Pilot Engagement section (assessment result) — capture + summary
A second capture+generate block lives after the Recommended License card (`#usbsim-pileng`, form `#usbeng-form`: company/industry/country/challenge/aisystems/regulatory; button `#usbeng-generate`; output `#usbeng-summary`). It follows the GAR pattern of a self-contained inline `<style>` with scoped `usbeng-*` classes. `prefillEngagement(industry, usage, opts)` is called in `generatePreview` right after `applyLicensingFromAssessment` and overwrites the 3 derived fields (industry/aisystems/regulatory via INDUSTRY_LABELS/USAGE_LABELS/REG_LABELS) + hides the stale summary; company/country/challenge are never auto-filled. `generateIntakeSummary()` builds the summary via innerHTML but escapes every dynamic value with a local `esc()` helper, and reads the recommended license + posture from existing `#intake-lic-*`/`#intake-dim-*` textContent (illustrative, like buildDemoSummary).
**Why:** UI-only demo — no payment, no account, no governance-logic change; summary is a client-side illustrative artifact.
**How to apply:** any new field added to the summary HTML MUST go through `esc()`. USAGE_LABELS/REG_LABELS were added near the intake license vars (no equivalent existed before).
