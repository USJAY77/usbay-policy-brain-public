# USBAY-GAME-013R — Visual Content & World Map Implementation Report

**Scope:** demo-only, additive VISUAL content for the existing `/game` route.
No real booking, no real payment, no external APIs, no sensitive data storage.
No governance / `/execute` / simulator logic was touched. The persistent
**DEMO ONLY — NO REAL BOOKING / NO REAL PAYMENT** banner is preserved on every
screen.

## Files changed

| File | Change |
| --- | --- |
| `gateway/app.py` | Inside `usbay_game_html()` only: enriched world-map `NODES`; new `ROUTES`, `MISSIONS_TRAVEL`, `PASSES`, `TOKENS` demo data; rewrote `scMap()` (SVG route lines, status tags, mode/status legend); added a Travel-missions panel to `scHub()`; built out `scMarketplace()` with transport-pass + reward-token concept cards; added a "Simulated · non-redeemable" marker to the VIP card in `scRewards()`; added CSS for `.routes`, `.map-legend`, `.statustag`. |
| `tests/game_visual_content_harness.mjs` | New jsdom harness (network/persistence spied) asserting the new visual content. |
| `tests/test_game_visual_content_dom.py` | New pytest wrapper (7 tests) over the harness. |
| `evidence/audit/USBAY_GAME_013R_VISUAL_CONTENT_REPORT.md` | This report. |

## Screens visually improved

- **World Map** — distinct map panel with SVG multi-modal route lines behind
  city pins, per-hub status tags, and a Modes + Status legend.
- **Travel Hub** — new "Travel missions" card grid above the route finder.
- **Marketplace** — upgraded from a bare placeholder to a visual shell with
  transport-pass and reward-token concept cards (still NOT IMPLEMENTED).
- **Rewards** — VIP Discount Pass now explicitly marked simulated /
  non-redeemable.

## Transport modes (visible)

Flights (air), Trains (rail), Buses (bus), Cruise ships (cruise), Ferries
(ferry), Metro — plus Airport Hub, Rail Hub, Bus Terminal, Cruise Port, Ferry
Port, Hotel Network and Logistics screens (all pre-existing, retained). Map
route lines cover the five required modes: air, rail, bus, cruise, ferry.

## World map content added

- **City hubs (12):** New York, London, Berlin, Nairobi, Dubai, Mumbai, Tokyo,
  Singapore, Sydney, Mexico City, Rio, Cape Town — including all seven required
  cities (New York, London, Dubai, Tokyo, Cape Town, Rio, Sydney).
- **Route lines (13):** illustrative SVG lines colored per transport mode (air,
  rail, bus, cruise, ferry).
- **Status tags:** HOT, LOW COST, GOVERNED, DEMO — shown in the map legend and
  pinned to individual hubs.

## Crew / character content

Existing diverse 14-member roster retained (globally varied regions, pronoun
sets, heritages and roles incl. pilot, cruise captain, ferry master, metro/rail
operators, bus fleet manager, governance officer, audit lead, accessibility
advocate, sustainability officer, human review officer). No stereotypes, no
sensitive identity claims. Verified ≥6 cards with roles render.

## Marketplace shell status

**Coming Soon / NOT IMPLEMENTED.** Adds 4 transport-pass concept cards and 3
reward-token concept cards, all display-only. **No buy button, no sell button,
no payment language, no inputs, no real redemption claim** — each card is marked
"Concept only - not for sale" / "Non-redeemable concept". Harness confirms
`mainButtons == 0` and `mainInputs == 0`.

## Game economy display

Demo-only Travel Credits, Governance Credits, Experience (XP) and Audit Tokens
shown on Home and Rewards. VIP Discount Pass clearly marked **Simulated ·
non-redeemable**. Rewards screen reiterates that points are virtual demo points
with no monetary value.

## Test results

- `tests/test_game_visual_content_dom.py` — **7 passed** (new).
- `tests/test_game_screen_visibility_dom.py` (GAME-012R) — passed.
- `tests/test_game_interactive_dom.py` (GAME-008/009) — passed.
- `tests/test_game_ux_hardening_dom.py` (GAME-009/011) — passed.
- `tests/test_game_stability_gate_dom.py` (GAME-010R/011) — passed.
- Combined run: **35 passed**.
- `python3.11 -m py_compile gateway/app.py` — OK.
- `GET /game` → 200, `GET /simulator` → 200 (unaffected).
- `git diff --check` — clean.

Validated by the harness: all 16 screens render with a heading and the DEMO
banner; all transport modes visible; marketplace shell visible; no
booking/payment controls; no form inputs; no network calls; no storage writes;
no cookies; no forbidden phrases across the screen corpus.

## Remaining gaps

- World map is a stylized illustrative panel (percentage-positioned nodes + SVG
  lines), not a geographic projection — intentional for a demo.
- Mission cards are descriptive concept cards; the interactive comparison lives
  in the existing route finder (cheapest/fastest/XP/governance).
- Marketplace is intentionally non-functional (shell only).

## Rollback command

```
git checkout HEAD -- gateway/app.py
rm -f tests/game_visual_content_harness.mjs tests/test_game_visual_content_dom.py \
      evidence/audit/USBAY_GAME_013R_VISUAL_CONTENT_REPORT.md
```
