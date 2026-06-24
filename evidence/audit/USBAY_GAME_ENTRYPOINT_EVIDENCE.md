# USBAY Game Entrypoint Evidence (GAME-025R)

**Scope:** Replit only. Tests + screenshots + report only; no payment/booking/
external-API changes; no `/execute` changes; no governance-enforcement changes.
DEMO ONLY banner and fail-closed behavior preserved.

**Result summary**
- PLAY GAME (root card CTA) works: **YES** — click navigates to `/game` and the
  World Map gameplay landing renders.
- Top-nav USBAY Game works: **YES** — click navigates to `/game` with active nav
  state (`nav.gamenav a.gnav-active aria-current="page"`).
- `/game` first screen exact label seen: **"World Map"** (hero subtitle
  "Travel • Earn • Govern • Play"); default screen is `active="map"`.

## Tested URLs

| URL | Method | Expected | Status |
|-----|--------|----------|--------|
| `/` | GET | 200, USBAY Game card visible, CTA + top-nav → `/game` | PASS (200) |
| `/game` | GET | 200, World Map gameplay landing + required markers | PASS (200) |
| `/simulator` | GET | 200 (unchanged) | PASS (200) |
| `/execute` | GET | 404 (POST-only, fail-closed unchanged) | PASS (404) |

## Entry-point navigation (real browser click-through — Playwright)

Both entry points are native HTML anchors (no JS handler), so navigation is real:
- Root card: `<a class="ps-card ps-card-game" href="/game">` wrapping the visible
  `Play Game →` CTA span (`.ps-cta.ps-cta-play`).
- Top nav: `<a href="/game" class="nav-game">USBAY Game</a>`.

| Check | Status |
|-------|--------|
| Root USBAY Game card visible | PASS |
| Root CTA target = `/game` | PASS |
| Top-nav target = `/game` | PASS |
| Click PLAY GAME → loads `/game` | PASS |
| `/game` gameplay rendered (World Map + Start Demo Trip) | PASS |
| Click top-nav USBAY Game → loads `/game` | PASS |
| Active nav state on `/game` | PASS |
| No commerce CTA on `/game` | PASS |

## Required visible markers on `/game` landing

| Marker | Status |
|--------|--------|
| World Map | PASS |
| Travel • Earn • Govern • Play | PASS |
| Start Demo Trip | PASS |
| Rewards | PASS |
| Governance Center | PASS |
| DEMO ONLY | PASS |
| no real booking | PASS |
| no real payment | PASS |

All 16 live Playwright checks passed (ALL_PASS: True).

## Screenshots (in `screenshots/`)

| File | Shows |
|------|-------|
| `root_usbay_game_card.png` | Root page with visible USBAY Game card + PLAY GAME CTA |
| `root_play_game_click_loaded_game.png` | `/game` loaded after clicking PLAY GAME |
| `topnav_usbay_game_loaded_game.png` | `/game` loaded after clicking top-nav USBAY Game (active state) |
| `game_world_map_landing.png` | `/game` World Map gameplay-first landing |

## Automated tests (`tests/test_gateway_app.py`)

| Test | Verifies | Status |
|------|----------|--------|
| `test_game025r_root_entry_contract` | Root card + CTA span inside `/game` anchor; top-nav → `/game` | PASS |
| `test_game025r_game_landing_markers` | All required `/game` markers + World Map default | PASS |
| `test_game025r_topnav_active_on_game` | Active nav state on `/game` | PASS |
| `test_game025r_no_commerce_cta` | No commerce CTAs on `/` and `/game` | PASS |
| `test_game025r_routes_and_failclosed_unchanged` | Routes serve; `/execute` GET 404; valid decide→execute EXECUTED; missing-nonce 403 | PASS |

Run: `pytest tests/test_gateway_app.py -k "game025r"` → 5 passed.
