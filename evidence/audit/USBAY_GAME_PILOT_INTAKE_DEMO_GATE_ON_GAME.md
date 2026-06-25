# USBAY-GAME-033R — Pilot Intake Demo Gate ported to `/game`

**Scope:** UI + tests + evidence only. No backend governance changes, no `/execute`
changes, no payment / booking / contact / mailto / external link / form submit, no
real intake submission.

## What changed
The Pilot Intake Demo Gate previously existed only on the root governance demo page
`/` (section `id="usbsim-pilot-rec"`, locked under 032R). 033R adds the same locked,
preview-only gate to the `/game` route as a self-contained section
(`id="gamePilotGate"`), rendered directly below the game hero / Demo Publish
Readiness proof panel (`#pubGate`).

Root `/` keeps its own gate; `/game` is no longer missing it.

### Files
- `gateway/app.py`
  - New CSS block (`.gpgate*`) next to the existing `.pubgate-*` styles.
  - New section markup (`#gamePilotGate`) inserted after `#pubGate`, before the
    travel nav, inside the `/game` hero/map screen.
  - One added branch in the existing `/game` delegated click handler for
    `[data-pgate]` that reveals a local, hidden, in-page note (`#gamePilotNote`).
    No network, no navigation, no storage.
- `tests/test_gateway_app.py` — added `test_game033r_*` (8 regression tests).
- `screenshots/game_033_pilot_intake_gate_full.png` — full `/game` page with gate.
- `screenshots/game_033_pilot_intake_gate_panel.png` — focused gate panel.

## Gate content (rendered on `/game`)
- Eyebrow: **Recommended Pilot Scope**
- Title: *A governance pilot tailored to your sector.*
- Industry: Financial Services · Current governance maturity: Medium
- Top governance gaps (3 items)
- **Recommended Pilot:** Governed AI for credit triage under USBAY runtime control.
- **Estimated Duration: 6–8 weeks**
- **Expected Outcome** (5-item checklist)
- **Governance Value** (regulator-ready summary)
- Pilot Intake CTAs (both inert / local-only)

## Demo-only / fail-closed guarantees
- Both CTAs are `<button type="button">`:
  - `Start Governance Pilot Wizard` (`id="gamewiz-open"`, `data-pgate="wizard"`)
  - `Request Paid Governance Intake` (`id="game-pilot-paid"`, `data-pgate="paid"`)
- Neither button has `href`, `formaction`, inline `onclick`, `mailto:`, external
  URL, or form submission. The only effect is revealing a local in-page note.
- Permanent visible disclaimer:
  *"Preview only — no booking, payment, or contact data is submitted from this demo.
  Assessment preview runs locally; no submitted company information is stored."*
- Sticky **DEMO ONLY** banner is preserved on every `/game` screen.
- No commerce / booking / contact CTA wording ("book now", "pay now", "checkout",
  "add to cart", "buy now", "proceed to payment", "schedule a call", "contact
  sales") appears on `/`, `/game`, or `/simulator`.
- `/execute` remains fail-closed: `GET /execute` → 404; valid signed payload →
  EXECUTED (200); payload with a missing nonce → 403. No `/execute` code touched.

## Verification
- `python3 -m py_compile gateway/app.py` → OK.
- `pytest -k game033r` → 8 passed.
- `pytest -k "game030r or game031r or game032r or game033r"` → 24 passed.
- Live `/game` (after workflow restart, HTML cached at import):
  - `GET /game` → 200, contains `#gamePilotGate`, `Recommended Pilot`, `6–8 weeks`,
    `Expected Outcome`, `Governance Value`, both buttons, the `Preview only`
    disclaimer, and `DEMO ONLY`.
  - `GET /execute` → 404.

## Rollback
Revert this change set (`gateway/app.py`, `tests/test_gateway_app.py`, the two
screenshots, and this evidence doc), or use Replit's checkpoint rollback to the
checkpoint immediately before USBAY-GAME-033R. No application/runtime governance
code or `/execute` path was modified, so rollback is purely additive removal.

## Result
**PASS** — the Pilot Intake Demo Gate now renders on `/game` directly below the
governance proof area, fully inert / preview-only, with DEMO ONLY and fail-closed
behavior preserved, locked by 8 regression tests.
