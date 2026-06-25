# USBAY-GAME-030R — Publish Gate UI Evidence Panel

**Scope:** UI only. No backend governance changes, no `/execute` changes, no
booking/payment/API, no automatic publication. DEMO ONLY banner and fail-closed
behavior preserved.

## What was added

A visible, read-only **"Demo Publish Readiness"** evidence panel (`#pubGate`) on
the `/game` page, rendered directly beneath the gameplay loop. The panel surfaces
the GAME-029R publish gate as auditor-readable, locked evidence — it makes no live
calls and changes no runtime behavior.

### Locked checks (9, all PASS)

| # | Check | State |
|---|-------|-------|
| 1 | Root `/` returns 200 | 🔒 PASS |
| 2 | `/game` returns 200 | 🔒 PASS |
| 3 | `/simulator` returns 200 | 🔒 PASS |
| 4 | `/execute` fail-closed | 🔒 PASS |
| 5 | Root USBAY Game card links to `/game` | 🔒 PASS |
| 6 | Top-nav USBAY Game links to `/game` | 🔒 PASS |
| 7 | Client Demo Ready seal visible | 🔒 PASS |
| 8 | DEMO ONLY banner visible | 🔒 PASS |
| 9 | No commerce/payment CTA | 🔒 PASS |

### Final badge

> **READY FOR DEMO — NOT READY FOR AUTOMATED PUBLICATION**

The badge intentionally reaffirms that this is demo-readiness only; it does not
authorize or trigger any automated publication path.

## Files changed

- `gateway/app.py`
  - CSS for `.pubgate`, `.pubgate-head`, `.pubgate-grid`, `.pg-check`,
    `.pg-lock`, `.pg-label`, `.pg-pass`, `.pubgate-badge` (added near the
    `.client-seal` rules).
  - `#pubGate` panel markup injected into the scMap hero after the `#gameLoop`
    grid (additive JS-string HTML).
- `tests/test_gateway_app.py` — appended `test_game030r_*` (4 tests).
- `evidence/audit/USBAY_GAME_PUBLISH_GATE_UI_EVIDENCE_PANEL.md` — this document.

## Tests run

`pytest -k "game030r"` → **4 passed**.

- `test_game030r_publish_readiness_panel_present` — `#pubGate` exists, all 9 check
  labels present, exactly 9 `PASS` pills.
- `test_game030r_final_badge_present` — final badge text present.
- `test_game030r_panel_introduces_no_commerce_language` — no commerce/payment CTA
  (`book now`, `pay now`, `checkout`, `add to cart`, `buy now`,
  `proceed to payment`) on `/`, `/game`, `/simulator`.
- `test_game030r_demo_only_and_failclosed_preserved` — DEMO ONLY banner + Client
  Demo Ready seal still present; `/execute` still fail-closed (GET 404, valid
  signed = EXECUTED, missing-nonce = 403).

## Screenshots

- `screenshots/pack_publish_readiness_panel.png` — focused capture of the panel.
- `screenshots/pack_publish_readiness_full.png` — full `/game` page in context.

## Result

**PASS.** Panel is visible and read-only, all 9 checks show locked PASS, final
badge present, no commerce/payment language introduced, DEMO ONLY banner and
fail-closed `/execute` preserved.

## Remaining gaps

None functional. The panel is static evidence reflecting the GAME-029R gate; it is
not a live monitor. Per task rules it intentionally does **not** wire to any
automated publication path.
