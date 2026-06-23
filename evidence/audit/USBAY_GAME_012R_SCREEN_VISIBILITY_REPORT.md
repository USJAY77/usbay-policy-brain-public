# USBAY-GAME-012R — Screen Visibility & Screenshot/Export Readiness Report

**Scope:** Additive, demo-only UI visibility/navigation for the `/game` prototype.
No booking, no payment, no external APIs, no sensitive storage. No changes to
governance enforcement, `/execute`, the simulator, or PB-RUNTIME-013..017. The
`DEMO ONLY — NO REAL BOOKING / NO REAL PAYMENT` banner is preserved on every
screen.

---

## 1. Files changed

| File | Change |
| --- | --- |
| `gateway/app.py` (`usbay_game()` HTML/JS) | Added `scMarketplace()` coming-soon placeholder; registered `marketplace` as a 16th entry in `SCREENS` (group "Stay & Trade"); added `type="button"` + `aria-current="page"` to selector buttons; `show()` now syncs `aria-current` and `window.location.hash`; added arrow-key keyboard navigation on the selector; added `screenFromHash()`, a `hashchange` listener, and hash-aware init (`show(screenFromHash() \|\| "home")`). |
| `tests/game_screen_visibility_harness.mjs` (new) | jsdom harness that drives every screen via `location.hash`, with network/storage spies, and emits a JSON report. |
| `tests/test_game_screen_visibility_dom.py` (new) | 5 pytest cases asserting selector, deep-links, initial-hash boot, marketplace placeholder, and no booking/payment/network/persistence. |
| `evidence/audit/USBAY_GAME_012R_SCREEN_VISIBILITY_REPORT.md` (new) | This report. |

> The stability gate also regenerated `evidence/audit/GAME_DEMO_STABILITY_GATE_010R.md` as a side effect of being run for reporting.

---

## 2. All screen URLs (deep-link capture targets)

Base: `https://76bb5c69-eeb6-4278-9927-109581d606aa-00-1fyogkgg2jqy9.worf.replit.dev`
(in deployment, the same paths apply under the published domain).

### Implemented (15 originally-shipped screens)

| # | Screen | Deep-link |
| --- | --- | --- |
| 1 | Home Dashboard | `/game#home` |
| 2 | World Map | `/game#map` |
| 3 | Multi-Modal Travel Hub | `/game#hub` |
| 4 | Rail Hub | `/game#rail` |
| 5 | Bus Terminal | `/game#bus` |
| 6 | Cruise Port | `/game#cruise` |
| 7 | Ferry Port | `/game#ferry` |
| 8 | Airport Hub | `/game#airport` |
| 9 | Hotel Network | `/game#hotel` |
| 10 | Business District | `/game#business` |
| 11 | Governance Center | `/game#governance` |
| 12 | Academy | `/game#academy` |
| 13 | Character / Crew | `/game#crew` |
| 14 | Rewards | `/game#rewards` |
| 15 | Profile | `/game#profile` |

### Placeholder (NOT IMPLEMENTED)

| # | Screen | Deep-link |
| --- | --- | --- |
| 16 | Marketplace — Coming Soon | `/game#marketplace` |

---

## 3. Selector behavior

- The persistent left-hand `#nav` lists **all 16 screens** grouped by section
  (Overview / Travel / Stay & Trade / Governance / Academy / Roster / Player).
- Each entry is a native `<button type="button">` and is keyboard-focusable.
- The active screen is highlighted (`.active` class) **and** marked
  `aria-current="page"`; both update on every navigation.
- **One click** changes the visible screen (existing global click handler routes
  `[data-nav]` → `show()`).
- **Keyboard navigation:** buttons are natively activated with Enter/Space, and
  `ArrowDown` / `ArrowUp` move focus through the selector (roving) — verified by
  the harness (`keyboardMovesFocus = true`).
- Navigating updates `window.location.hash`, so the address bar always reflects
  the current screen and is directly shareable.

---

## 4. Marketplace placeholder status

- Visible in the selector as **"Marketplace — Coming Soon"** (group "Stay & Trade").
- Screen renders a **`NOT IMPLEMENTED`** badge, a "Marketplace — Coming Soon"
  heading, and explicit copy: *no buying, no selling, no payment, no currency,
  no real economy; nothing on this screen is functional.*
- Contains **0 inputs** and **0 buttons** — review-only, no actionable controls.
- Verified by `test_marketplace_is_coming_soon_placeholder`.

---

## 5. Screenshot / export readiness

**Automated PNG-per-screen export: NOT AVAILABLE in this environment.**

Reason: the only screenshot capability available to the agent is a single
JPEG **app-preview** capture. It (a) outputs JPEG, not the requested PNG, and
(b) cannot reliably batch-capture client-rendered `#hash` routes (the router
runs in-browser after load), so it cannot deterministically produce one image
per screen. No headless-browser/Playwright export pipeline is wired into this
repo for `/game`.

**What IS provided instead (deterministic + manual path):**

1. **Deterministic capture-target list** — the 16 deep-links in §2 are stable,
   bookmarkable, and render the correct screen on direct load (initial-hash boot
   is verified by `test_initial_hash_boots_to_requested_screen`).
2. **Exact manual capture path** (one image per screen):
   - Open `https://<dev-or-published-domain>/game#<id>` for each `<id>` in §2.
   - Wait for the screen to render (instant; no network), then capture with the
     browser's built-in screenshot (DevTools → *Capture full size screenshot*),
     or any OS screenshot tool. Save as `game_<id>.png`.
   - Suggested output directory: `evidence/screenshots/game/`.
3. The deep-links make this fully repeatable and scriptable later (e.g. a future
   Playwright job iterating the §2 list) without further UI changes.

---

## 6. Test results

| Suite | Result |
| --- | --- |
| `tests/test_game_screen_visibility_dom.py` (new, GAME-012R) | **5 passed** |
| `tests/test_game_interactive_dom.py` (GAME-008) | passed (part of 23) |
| `tests/test_game_ux_hardening_dom.py` (GAME-009R) | passed (part of 23) |
| `tests/test_game_stability_gate_dom.py` (GAME-011) | passed (part of 23) |
| Combined existing GAME-008/009/011 DOM suites | **23 passed** |
| `python3.11 -m py_compile gateway/app.py` | OK |
| `GET /game` | 200 |
| `git diff --check` | clean (no whitespace/conflict markers) |

New-test coverage: selector lists every screen; every `/game#<id>` deep-link
renders the correct screen with active selector + `aria-current`; initial-hash
boot lands on the requested screen; banner present on every screen; **0** form
inputs and **0** booking/payment buttons on any screen; **0** network calls,
**0** storage writes, empty cookie, **0** JS errors across a full screen walk.

---

## 7. Forbidden-file check result

`scripts/game_stability_gate.py` (the GAME-010R gate) reports:

- `[boot] OK — GET /game → 200`
- `[dom] OK — 23 passed`
- All `[safety]` checks **PASS** (banner visible, no booking/payment UI, no
  external network, no personal data persisted, VIP demo-only, deterministic
  routes, child-safe + accessibility persist).
- `[forbidden] FAIL — gateway/app.py changed` → **expected and by design.** The
  010R gate flags *any* edit to `gateway/app.py`; GAME-012R explicitly authorizes
  UI-visibility edits to `usbay_game()`. This is reported for transparency and is
  **not** a 012R blocker. No out-of-scope files were touched (governance,
  `/execute`, simulator, PB-RUNTIME-013..017 all untouched).

---

## 8. Remaining gaps

- **Automated image export** is not wired up (see §5) — manual/scriptable path
  provided. Adding a Playwright capture job over the §2 list is a clean future
  follow-up if PNG artifacts must be committed.
- **Marketplace** is intentionally a non-functional placeholder (no economy by
  design).
- Deep-links use URL **hash** fragments (client-side routing); there are no
  server-rendered per-screen routes (out of scope and unnecessary for review).
- Screen headings differ slightly from registry labels (e.g. registry "Travel
  Hub" renders as "Multi-Modal Travel Hub") — cosmetic, expected.

---

## 9. Rollback command

Revert all GAME-012R changes (UI edit + new test files + this report):

```bash
git checkout -- gateway/app.py
rm -f tests/game_screen_visibility_harness.mjs \
      tests/test_game_screen_visibility_dom.py \
      evidence/audit/USBAY_GAME_012R_SCREEN_VISIBILITY_REPORT.md
```

Then restart the workflow: **USBAY Gateway**.
