# USBAY Game — Demo Publish Readiness Gate (GAME-029R)

**Scope:** Replit only. Report / evidence / test only. No UI changes, no backend
governance changes, no `/execute` changes, no booking, no payment, no external
APIs. DEMO ONLY banner and fail-closed behavior preserved.

## Client-demo readiness verdict
**PASS — READY to publish the demo.** Every gate check below passes: all three
public routes serve 200, both entrypoints route to `/game`, the Client Demo
Ready seal and DEMO ONLY banner are visible, no commerce/payment CTA appears, and
`/execute` remains fail-closed.

## Exact URLs tested
| URL | Method | Expected |
|-----|--------|----------|
| `/` | GET | 200 |
| `/game` | GET | 200 |
| `/simulator` | GET | 200 |
| `/execute` | GET | 404 (POST-only) |
| `/execute` | POST (valid signed decide→execute) | 200 EXECUTED |
| `/execute` | POST (missing nonce) | 403 |

## PASS/FAIL table
| # | Gate check | Result |
|---|------------|--------|
| 1 | `/` returns 200 | PASS |
| 2 | `/game` returns 200 | PASS |
| 3 | `/simulator` returns 200 | PASS |
| 4 | `/execute` remains fail-closed (GET 404; valid signed = EXECUTED; missing-nonce = 403) | PASS |
| 5 | Root "USBAY Game" card links to `/game` | PASS |
| 6 | Top-nav "USBAY Game" links to `/game` | PASS |
| 7 | `/game` shows Client Demo Ready seal (badge + 5 guarantees) | PASS |
| 8 | `/game` shows DEMO ONLY banner | PASS |
| 9 | `/game` (and `/`, `/simulator`) show no Book Now / Pay Now / checkout / commerce CTA | PASS |

## Visible client proof guarantees (on `/game`)
Client Demo Ready (seal badge), Demo-only simulation, No real booking, No real
payment, Governance evidence generated, Local training mode, plus the green
demo-proof panel (Demo Only / Local simulation) and the DEMO ONLY ribbon.

## Visible screenshots list (reused from GAME-028R pack, `screenshots/`)
| File | State |
|------|-------|
| `pack_root_product_cards.png` | Root product cards incl. USBAY Game card → `/game` |
| `pack_game_landing_seal.png` | `/game` landing with Client Demo Ready seal |
| `pack_world_map_default.png` | World Map default active screen |
| `pack_start_demo_trip.png` | Start Demo Trip state |
| `pack_governance_center.png` | Governance Center proof state |

## Automated gate tests (`tests/test_gateway_app.py`)
| Test | Verifies | Result |
|------|----------|--------|
| `test_game029r_routes_gate` | `/`, `/game`, `/simulator` = 200 | PASS |
| `test_game029r_execute_failclosed` | `/execute` GET 404; valid decide→execute EXECUTED; missing-nonce 403 | PASS |
| `test_game029r_entrypoints_link_to_game` | Root card + top-nav "USBAY Game" link to `/game` | PASS |
| `test_game029r_client_seal_and_demo_banner` | Client Demo Ready seal (5 guarantees) + DEMO ONLY banner | PASS |
| `test_game029r_no_commerce_cta_gate` | No commerce CTA on `/`, `/game`, `/simulator` | PASS |

Run: `pytest tests/test_gateway_app.py -k "game029r"` → 5 passed.

## Remaining gaps
None functional. This is a report-only gate; no UI/governance/`/execute` change
was required (no broken client-demo claim was found).

## Rollback command
Revert the two added files (test block + this evidence doc) via your version
control to the prior checkpoint; no application code was modified by GAME-029R.
