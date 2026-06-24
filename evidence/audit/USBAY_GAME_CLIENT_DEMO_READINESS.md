# USBAY Game — Client Demo Readiness Seal (GAME-027R)

**Scope:** Replit only. UI / test / evidence only. No backend governance changes,
no `/execute` changes, no booking, no payment, no external APIs. DEMO ONLY banner
and fail-closed behavior preserved.

## Result summary
- `/game` renders a visible **"Client Demo Ready"** seal strip in the hero,
  above the gameplay loop: **YES**.
- "Start Demo Trip" is the strongest CTA (gradient primary button + PRIMARY
  badge; only primary action): **YES**.
- World Map is the default active screen: **YES** (`active="map"`, sidebar
  "World Map" active).
- "Travel • Earn • Govern • Play" visible above the gameplay panel: **YES**.

## 1. Client Demo Ready seal strip (`#clientDemoReady`, hero, above gameplay loop)
| Item shown | Status |
|------------|--------|
| Client Demo Ready (seal badge) | PASS |
| Demo-only simulation | PASS |
| No real booking | PASS |
| No real payment | PASS |
| Governance evidence generated | PASS |
| Local training mode | PASS |

## 2. Visual hierarchy
| Item | Status |
|------|--------|
| Start Demo Trip is the strongest CTA (gradient + PRIMARY badge) | PASS |
| World Map is the default active screen | PASS |
| "Travel • Earn • Govern • Play" visible above gameplay panel | PASS |
| Seal strip visible above the gameplay loop (`#clientDemoReady` before `#gameLoop`) | PASS |

## Tested URLs
| URL | Method | Expected | Status |
|-----|--------|----------|--------|
| `/` | GET | 200 | PASS |
| `/game` | GET | 200 | PASS |
| `/execute` | GET | 404 (POST-only, fail-closed unchanged) | PASS |

## Screenshots (in `screenshots/`)
| File | Shows |
|------|-------|
| `game_client_demo_ready.png` | `/game` landing with Client Demo Ready seal + proof panel |
| `game_client_seal_strip.png` | Focused Client Demo Ready seal strip (badge + 5 items) |
| `game_client_demo_landing.png` | `/game` default World Map landing |

## Automated tests (`tests/test_gateway_app.py`)
| Test | Verifies | Status |
|------|----------|--------|
| `test_game027r_client_seal_strip` | Seal strip with badge + all 5 client guarantees | PASS |
| `test_game027r_visual_hierarchy` | Strongest CTA; World Map default; subtitle; seal above gameplay loop | PASS |
| `test_game027r_route_ok` | `/game` = 200 | PASS |
| `test_game027r_no_commerce_cta` | No commerce CTAs on `/` and `/game` | PASS |
| `test_game027r_execute_failclosed_unchanged` | `/execute` GET 404; valid decide→execute EXECUTED; missing-nonce 403 | PASS |

Run: `pytest tests/test_gateway_app.py -k "game027r"` → 5 passed.
Live Playwright proof (`/tmp/shot_027.py`, not committed): all checks PASS.
