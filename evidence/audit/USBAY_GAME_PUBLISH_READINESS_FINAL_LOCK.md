# USBAY-GAME-031R — Demo Publish Readiness Final Lock

**Scope:** UI / tests / evidence only. No backend governance changes, no
`/execute` changes, no booking/payment/API, no automatic publication. DEMO ONLY
banner and fail-closed behavior preserved.

## Purpose

Lock the GAME-030R **Demo Publish Readiness** UI panel (`#pubGate` on `/game`) as
final evidence and guard it against future UI drift with dedicated regression
tests. No new UI was added in this task — the panel from GAME-030R is verified and
fenced.

## Verification (live `/game`)

| Item | Result |
|------|--------|
| Demo Publish Readiness panel (`#pubGate`) present | PASS |
| 9 locked PASS checks present | PASS (9 `pg-pass` pills) |
| Final badge "READY FOR DEMO — NOT READY FOR AUTOMATED PUBLICATION" | PASS |
| DEMO ONLY banner present | PASS |

### Locked checks

1. Root `/` returns 200
2. `/game` returns 200
3. `/simulator` returns 200
4. `/execute` fail-closed
5. Root USBAY Game card links to `/game`
6. Top-nav USBAY Game links to `/game`
7. Client Demo Ready seal visible
8. DEMO ONLY banner visible
9. No commerce/payment CTA

## Regression tests (drift guard)

Appended `test_game031r_*` to `tests/test_gateway_app.py` (6 tests). These fail if:

- `test_game031r_panel_locked_present` — the panel disappears.
- `test_game031r_all_nine_pass_checks_locked` — any PASS check label disappears, or
  the count of PASS pills changes from 9.
- `test_game031r_final_badge_locked` — the final readiness badge disappears.
- `test_game031r_demo_only_banner_locked` — the DEMO ONLY banner / Client Demo Ready
  seal disappears.
- `test_game031r_no_commerce_cta_locked` — a commerce/payment CTA appears on `/`,
  `/game`, or `/simulator`.
- `test_game031r_failclosed_preserved` — `/execute` stops being fail-closed
  (GET 404; valid-signed = EXECUTED; missing-nonce = 403).

**Run:** `pytest -k "game031r"` → **6 passed**.

## Screenshot

- `screenshots/game_031_publish_readiness_final_lock.png` — final locked panel
  showing all 9 PASS checks and the readiness badge.

## Result

**PASS.** Panel, 9 PASS checks, and final badge are present and now regression-
locked; DEMO ONLY banner and fail-closed `/execute` preserved; no commerce/payment
language present.

## Remaining gaps

None functional. The panel remains static evidence (no live monitor) and is
intentionally not wired to any automated publication path.

## Rollback command

This task added only tests + evidence + a screenshot (no `gateway/app.py`
application code). To roll back:

```
git revert --no-edit <GAME-031R checkpoint commit>
```

Or roll back manually (remove the GAME-031R artifacts):

```
git checkout -- tests/test_gateway_app.py   # drops the test_game031r_* block
rm evidence/audit/USBAY_GAME_PUBLISH_READINESS_FINAL_LOCK.md
rm screenshots/game_031_publish_readiness_final_lock.png
```

The simplest path is Replit's checkpoint rollback to the checkpoint immediately
before GAME-031R.
