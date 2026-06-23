# USBAY-GAME-014 — Travel World Landing Experience Report

**Scope:** demo-only, UI-only changes to the existing `/game` route. The landing
experience is now travel-first (World Map by default) while all governance
controls remain available behind a dedicated navigation group. No real booking,
no real payment, no external APIs, no governance enforcement changes, no
simulator changes. The persistent **DEMO ONLY** banner is preserved on every
screen.

## Files changed

| File | Change |
| --- | --- |
| `gateway/app.py` | Inside `usbay_game_html()` only: added `TRAVELNAV` (7 modes) and `DEST` (7 destination cities) demo data; rewrote `scMap()` into the travel-first landing (travel-nav strip, route-visualization map, transport selection panel, world destination cards); added `.travelnav`/`.tnav`/`.tk`/`.dest-card` CSS; switched the default landing screen from `home` to `map` (`var active` initial value and the boot `show(... || "map")`). |
| `tests/game_travel_world_harness.mjs` | New jsdom harness (network/persistence spied) asserting the travel-first landing. |
| `tests/test_game_travel_world_dom.py` | New pytest wrapper (8 tests). |
| `evidence/audit/USBAY_GAME_014_TRAVEL_WORLD_LANDING_REPORT.md` | This report. |
| `screenshots/game_014_travel_world_landing.png` | Landing screenshot. |

## World map changes

- **Default landing.** `/game` with no hash now boots directly onto the **World
  Map** (previously the governance-inclusive Home Dashboard). Home Dashboard
  remains reachable from the nav.
- **Route visualization retained/enhanced.** SVG multi-modal route lines (air,
  rail, bus, cruise, ferry) behind city pins, per-hub status tags
  (HOT / LOW COST / GOVERNED / DEMO) and a Modes + Status legend.
- **Travel-first copy.** The map header now reads "World Map / Travel World"
  with a welcome that points governance users to the Governance Center.

## Travel navigation changes

- **Visible travel navigation strip** on the landing with all seven required
  entries: **Flights, Trains, Buses, Cruises, Ferries, Hotels, Logistics** —
  each a pill that deep-links to its dedicated mode screen.
- **Transport selection panel** ("Choose your transport") — one card per mode
  showing the demo route count, each linking to the mode screen.
- **World destination cards** ("Featured destinations") for **New York, London,
  Dubai, Tokyo, Cape Town, Rio, Sydney**, each with a transport tag, status tag
  and a short demo blurb.
- **Governance moved behind separate navigation.** The Governance Center is no
  longer part of the landing; it lives in its own "Governance" nav group and is
  still fully reachable (`/game#governance`).
- **Academy, Rewards, Crew (Character / Crew) and Profile** all remain in the
  navigation and render.

## Screenshots generated

- `screenshots/game_014_travel_world_landing.png` — `/game` booting on the
  travel-first World Map (travel nav, route map with status tags, transport
  selection panel, featured destinations, DEMO banner, full nav incl.
  Governance Center).

## Test results

- `tests/test_game_travel_world_dom.py` — **8 passed** (new).
- `tests/test_game_visual_content_dom.py` (GAME-013R) — passed.
- `tests/test_game_screen_visibility_dom.py` (GAME-012R) — passed.
- `tests/test_game_interactive_dom.py` (GAME-008/009) — passed.
- `tests/test_game_ux_hardening_dom.py` (GAME-009/011) — passed.
- `tests/test_game_stability_gate_dom.py` (GAME-010R/011) — passed.
- Combined run: **43 passed**.
- `python3.11 -m py_compile gateway/app.py` — OK.
- `GET /game` → 200, `GET /simulator` → 200 (unaffected).
- `git diff --check` — clean.

Validated by the harness: World Map is the default landing (active nav = `map`);
the seven travel-nav entries are present; the transport selection panel and the
seven destination cards render; route visualization (SVG lines + legend) is
present; the Governance Center is reachable behind its own nav; Academy /
Rewards / Crew / Profile remain accessible; the DEMO banner shows on every
screen; and walking every screen produces no booking/payment phrases, no form
inputs, no network calls and no persistence.

## Validation summary

| Check | Result |
| --- | --- |
| `GET /game` | 200 |
| All routes render | yes (every nav screen renders a heading) |
| Travel World loads by default | yes (active nav = `map`) |
| No payment controls | yes (0 inputs, no payment phrases) |
| No booking controls | yes |
| `git diff --check` | PASS |

## Remaining gaps

- World map remains a stylized illustrative panel (percentage-positioned nodes +
  SVG lines), not a geographic projection — intentional for a demo.
- Hotels / Logistics show "-" in the transport selection panel because the demo
  route dataset (`TRIPS`) covers air/rail/bus/cruise/ferry/metro; the Hotels and
  Logistics cards still link to their dedicated screens.
- Destination cards link to the Travel Hub (no per-city deep screen) by design.

## Rollback command

```
git checkout HEAD -- gateway/app.py
rm -f tests/game_travel_world_harness.mjs tests/test_game_travel_world_dom.py \
      evidence/audit/USBAY_GAME_014_TRAVEL_WORLD_LANDING_REPORT.md \
      screenshots/game_014_travel_world_landing.png
```
