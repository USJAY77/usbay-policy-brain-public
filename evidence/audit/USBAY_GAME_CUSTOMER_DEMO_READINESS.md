# USBAY Game — Customer Demo Readiness (GAME-026R)

**Scope:** Replit only. UI / test / evidence only. No booking, no payment, no
external APIs, no `/execute` changes, no governance-enforcement changes. DEMO ONLY
banner and fail-closed behavior preserved.

## Result summary
- PLAY GAME (root card) → `/game`: **YES** (click-through proven).
- Top-nav USBAY Game → `/game`: **YES** (click-through proven).
- `/game` first screen: **World Map** (sidebar "World Map" active; default
  `active="map"`).
- Customer-demo proof panel rendered on the `/game` landing: **YES**.

## 1. Visible clarity polish (`/game` landing)
| Item | Status |
|------|--------|
| "Start Demo Trip" is the primary action (gradient button + PRIMARY badge, only primary) | PASS |
| "World Map" is the default active screen (sidebar active + `active="map"`) | PASS |
| "Travel • Earn • Govern • Play" visible above the gameplay panel (hero subtitle) | PASS |
| "No real booking / no real payment" remains visible (top ribbon + hero copy + proof panel) | PASS |

## 2. Customer-demo proof panel (`#demoProof`, in the hero, above gameplay)
| Guarantee shown | Status |
|-----------------|--------|
| Demo Only | PASS |
| No real booking | PASS |
| No real payment | PASS |
| Local simulation | PASS |
| Governance evidence generated | PASS |

## 3. Navigation
| Path / action | Expected | Status |
|---------------|----------|--------|
| root PLAY GAME CTA | navigates to `/game` | PASS |
| top-nav USBAY Game | navigates to `/game` | PASS |
| `/game` default screen | World Map | PASS |
| sidebar "World Map" | active | PASS |

## Tested URLs
| URL | Method | Expected | Status |
|-----|--------|----------|--------|
| `/` | GET | 200 | PASS |
| `/game` | GET | 200 | PASS |
| `/execute` | GET | 404 (POST-only, fail-closed unchanged) | PASS |

## Screenshots (in `screenshots/`)
| File | Shows |
|------|-------|
| `game_customer_demo_landing.png` | `/game` landing: primary CTA + subtitle + proof panel + World Map active |
| `game_demo_proof_panel.png` | Focused customer-demo proof panel (5 guarantees) |
| `game_world_map_default.png` | `/game` default World Map screen |

## Automated tests (`tests/test_gateway_app.py`)
| Test | Verifies | Status |
|------|----------|--------|
| `test_game026r_demo_proof_panel` | Proof panel with all 5 customer guarantees | PASS |
| `test_game026r_primary_cta_and_clarity` | Primary Start Demo Trip; World Map default; subtitle; no real booking/payment visible | PASS |
| `test_game026r_routes_ok` | `/` and `/game` = 200 | PASS |
| `test_game026r_no_commerce_cta` | No commerce CTAs on `/` and `/game` | PASS |
| `test_game026r_failclosed_unchanged` | `/execute` GET 404; valid decide→execute EXECUTED; missing-nonce 403 | PASS |

Run: `pytest tests/test_gateway_app.py -k "game026r"` → 5 passed.
Live Playwright proof (`/tmp/shot_026.py`, not committed): 13/13 checks PASS.
