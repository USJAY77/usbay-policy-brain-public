# USBAY-GAME-032R — Pilot Intake Demo Gate Lock

**Scope:** UI / tests / evidence only. No backend governance changes, no
`/execute` changes, no payment/booking/contact form/API/real intake submission.
DEMO ONLY banner and fail-closed behavior preserved.

## Route correction (drift note)

The task brief said "Verify **/game** shows" the Pilot Intake section. In the
current codebase that demo section does **not** live on `/game` — it renders on the
root governance demo page (`/`) as `<section id="usbsim-pilot-rec">`. This task
locks the section **where it actually exists (`/`)**. No new section was created on
`/game` (that would be a feature add, which is out of scope for a lock task).

## Verification (live `/`)

| Item | Result |
|------|--------|
| Recommended Pilot (scope) | PASS |
| Estimated Duration: 6–8 weeks | PASS |
| Expected Outcome checklist | PASS |
| Governance Value text | PASS |
| Pilot Intake section (`#usbsim-pilot-rec`) | PASS |
| "Start Governance Pilot Wizard" button | PASS |
| "Request paid governance intake" button | PASS |
| DEMO ONLY banner | PASS |

## Intake buttons are inert / demo-only

| Button | id | Behavior |
|--------|----|----------|
| Start Governance Pilot Wizard | `usbwiz-open` (+ `usbwiz-open-cta`) | `type="button"`; opens a **client-side** wizard modal (`openWiz(1)`). No form submit, no external link, no payment route, no network call. |
| Request paid governance intake | `usbsim-pilot-paid` | `type="button"`; opens a **client-side** intake modal (`openIntake`). No form submit, no external link, no payment route, no network call. |

The section carries a permanent disclaimer:
> "Preview only — no booking, payment, or contact data is submitted from this demo.
> Assessment preview runs locally; no submitted company information is stored."

The pilot section contains no `action=`, `href=`, `window.open`, `stripe`,
`/checkout`, `/pay`, or `mailto:` — i.e. no real action, link, or data capture.

## Regression tests (drift guard)

Appended `test_game032r_*` to `tests/test_gateway_app.py` (6 tests). These fail if:

- `test_game032r_pilot_intake_section_present` — the section or any of its required
  markers (Recommended Pilot, Estimated Duration / 6–8 weeks, Expected Outcome,
  Governance Value, both intake button labels) disappears.
- `test_game032r_intake_buttons_inert_demo_only` — either intake button stops being
  `type="button"`, gains an `href`/`formaction` (becomes a real action), or the
  preview-only disclaimer disappears.
- `test_game032r_pilot_section_no_real_action` — a form action, external link,
  payment route, `window.open`, `stripe`, or `mailto:` appears inside the section.
- `test_game032r_demo_only_banner_present` — the DEMO ONLY banner disappears.
- `test_game032r_no_commerce_or_booking_wording` — commerce/booking/contact CTA
  wording (book now, pay now, checkout, add to cart, buy now, proceed to payment,
  schedule a call, contact sales) appears on `/`, `/game`, or `/simulator`.
- `test_game032r_failclosed_preserved` — `/execute` stops being fail-closed
  (GET 404; valid-signed = EXECUTED; missing-nonce = 403).

**Run:** `pytest -k "game032r"` → **6 passed**.

## Screenshot

- `screenshots/game_032_pilot_intake_demo_gate_lock.png` — the locked Pilot Intake
  section with both inert intake buttons and the preview-only disclaimer.

## Result

**PASS.** Pilot Intake section verified, both intake buttons confirmed inert and
demo-only, no payment/booking/contact/real-submission wiring, DEMO ONLY banner and
fail-closed `/execute` preserved, all behavior now regression-locked.

## Remaining gaps

- The section lives on `/`, not `/game` (see route-correction note). Locked where it
  exists; no feature was added to `/game`.
- The wizard/intake modals collect inputs **locally** for the demo preview only;
  nothing is submitted or stored server-side, consistent with the disclaimer.

## Rollback command

This task added only tests + evidence + a screenshot (no `gateway/app.py`
application code). To roll back:

```
git revert --no-edit <GAME-032R checkpoint commit>
```

Or roll back manually:

```
git checkout -- tests/test_gateway_app.py   # drops the test_game032r_* block
rm evidence/audit/USBAY_GAME_PILOT_INTAKE_DEMO_GATE_LOCK.md
rm screenshots/game_032_pilot_intake_demo_gate_lock.png
```

Simplest path: Replit's checkpoint rollback to the checkpoint immediately before
GAME-032R.
