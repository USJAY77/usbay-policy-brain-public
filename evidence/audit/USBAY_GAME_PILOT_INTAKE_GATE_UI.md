# USBAY-GAME-034R — Pilot Intake Gate (UI only) on `/game`

**Scope:** UI + tests + evidence only. No backend governance changes, no
`/execute` changes, no real intake / payment / contact / booking / external API.

## What changed
Builds on the `/game` Pilot Intake gate added in 033R (`#gamePilotGate`). 034R
makes the gate explicit and self-documenting:

- The gate is now clearly labelled **"Pilot Intake Gate"** (section eyebrow).
- Added a **Gate Guarantees** checklist inside the gate with the required
  assurances:
  - Preview only
  - No booking
  - No payment
  - No contact data submitted
  - No company data stored
  - Human review required before any pilot
  - Fail-closed if governance evidence is missing

The standing preview-only disclaimer from 033R remains:
*"Preview only — no booking, payment, or contact data is submitted from this demo.
Assessment preview runs locally; no submitted company information is stored."*

### Files
- `gateway/app.py` — two edits inside the existing `#gamePilotGate` section:
  (1) eyebrow text → "Pilot Intake Gate"; (2) new "Gate Guarantees" list cell.
  No other application code touched; no `/execute` / governance changes.
- `tests/test_gateway_app.py` — added `test_game034r_*` (6 regression tests).
- `screenshots/game_034_pilot_intake_gate_full.png`,
  `screenshots/game_034_pilot_intake_gate_panel.png`.

## Inert / demo-only guarantees
- CTAs `Start Governance Pilot Wizard` (`#gamewiz-open`) and
  `Request Paid Governance Intake` (`#game-pilot-paid`) remain
  `<button type="button">` with no `href`, `formaction`, inline `onclick`,
  `mailto:`, external URL, form submit, `fetch`, or payment route. Their only
  effect is revealing a local hidden in-page note (`#gamePilotNote`).

## Verification
- `python -m py_compile gateway/app.py` → OK.
- `pytest -k game034r` → 6 passed.
- `pytest -q tests/test_gateway_app.py -k "game or intake or execute or demo"`
  → 146 passed, **1 pre-existing unrelated failure**
  (`test_game017r_premium_hero_landing`, see Remaining gaps).
- Live (after restart): `/` 200, `/game` 200, `/simulator` 200,
  `GET /execute` → 404. `/game` contains: "Pilot Intake Gate", all 7 guarantee
  lines, both CTAs, "USBAY Game", "Governance evidence generated", "DEMO ONLY".
  No commerce CTA wording on any of the three routes.

## Remaining gaps
- `test_game017r_premium_hero_landing` fails on `/game`, but this is
  **pre-existing and unrelated** to 034R: it expects a `<span>`-separated hero
  subtitle while the committed code (HEAD) uses a bullet-separated subtitle
  (`Travel • Earn • Govern • Play`). 034R did not touch the hero. Left as-is to
  respect scope; flag for a separate hero-subtitle test/code reconciliation.

## Rollback
Revert this change set (`gateway/app.py`, `tests/test_gateway_app.py`, the two
034 screenshots, this doc), or use Replit checkpoint rollback to the checkpoint
immediately before USBAY-GAME-034R. No runtime/governance/`/execute` code was
modified — rollback is purely additive removal.

## Result
**PASS** — `/game` now shows a clearly labelled Pilot Intake Gate with explicit
preview-only / human-review / fail-closed guarantees, inert CTAs, preserved
routes, DEMO ONLY banner, and no commercial wording; locked by 6 regression
tests.
