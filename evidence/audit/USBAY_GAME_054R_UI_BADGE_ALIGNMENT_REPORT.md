# GAME-054R — UI Badge String Alignment Report

**Result: PASS**

Date: 2026-06-27
Workspace: Replit Agent only
Branch: `governance/media-production-gap-scaffolding`
HEAD: `73f23c5` (unchanged — no commit/stage/push performed)
Scope: UI label/badge text only. No route, runtime, policy, simulator, or gateway-logic changes.

---

## 1. Objective

Resolve the reported mismatch between underlying governance concepts and the exact
visible UI strings. GAME-053R confirmed the *concepts* are present but the exact
strings **"Replay Active"** and **"Audit Verified"** were not rendered verbatim
anywhere in the UI. GAME-054R authorizes adding label/badge text only where the
exact strings are missing and it is safe to do so.

---

## 2. Inspection findings (gateway/app.py + served UI)

### Route → handler map (relevant)
- `/` → `root_gateway()` → `_render_governance_html_safe()` → `governance_gateway_html()` (line 7651). Template via `string.Template.substitute()` (`$`-sigil).
- `/playground` → `playground()` → `_render_playground_html_safe()` → `playground_html()` (line 8795). Template via `%`-formatting.
- `/simulator` → `governance_simulator()` → `governance_simulator_html()` (line 11839). `usbsim-` prefixed markup.

### Exact equivalent labels found BEFORE this change (where the concepts appear)
| Concept | Exact current label | Location |
|---|---|---|
| Replay (live telemetry) | `Replay ACTIVE` / `Replay INACTIVE` (split by `<b>` tags: `Replay <b>ACTIVE</b>`) | `/` runtime-strip chip (app.py ~8448), driven by `replay_word`/`public_replay_protection_active` |
| Replay (simulator capability) | `Replay protection` → `Active — duplicate or stale requests are blocked…` | `/simulator` (app.py ~2070) |
| Replay (risk/value/reg copy) | "Replay protection coverage", "Replay attacks mitigated", "Nonce & replay proof" | `/simulator` |
| Audit (evidence) | `Evidence verification` → "Every decision is sealed in a signed, append-only audit chain." | `/simulator` (app.py ~2071) |
| Audit (capability) | "Append-only audit trail", "Audit readiness", "Audit Readiness High" | `/simulator` |
| Policy signature | `Policy Signature Valid` is **not** a verbatim source string; rendered as `Policy signature` row + `VERIFIED`/`DEGRADED` pill, and pipeline node `policy.signature` | `/` |

**Conclusion:** the exact contiguous strings "Replay Active" and "Audit Verified" were
**absent** from all served routes (confirmed `grep -c` = 0 before change). They are
therefore missing and safe to add as capability/badge text.

---

## 3. Change made (UI label/badge text ONLY)

Two governance-capability badges added to the two human-facing executive surfaces,
framed as capability labels (neutral styling) so they do **not** override or
contradict the live LIVE/DEGRADED telemetry already present in the `/` runtime-strip.

**`/` — Governance Control Plane (`governance_gateway_html`, page-head):**
```html
<div class="gov-cap-badges" aria-label="Governance capability badges" style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;">
  <span class="pill pill-info" style="text-transform:none;">Replay Active</span>
  <span class="pill pill-info" style="text-transform:none;">Audit Verified</span>
</div>
```

**`/playground` — Executive Surface (`playground_html`, exec-hero-row):**
```html
<span class="exec-hero-tag" style="text-transform:none;">Replay Active</span>
<span class="exec-hero-tag" style="text-transform:none;">Audit Verified</span>
```

Design notes:
- `text-transform:none` inline override preserves the **exact casing** "Replay Active" /
  "Audit Verified" (both reused classes otherwise force uppercase).
- Added text contains no `$` (safe for `/`'s `string.Template.substitute`) and no `%`/`{}`
  (safe for `/playground`'s `%`-formatting). No new template variables were introduced,
  so no `.substitute(...)` / format-arg changes were required.
- The live `/` runtime-strip telemetry chip `Replay <b>ACTIVE</b>` (state-driven) is
  **untouched**, so the real LIVE/DEGRADED distinction remains authoritative.

**Files changed:** `gateway/app.py` (+6 lines, 1 file). No other files modified.

---

## 4. Exact visible UI strings AFTER change

Confirmed present (contiguous) via `curl … | grep -c`:
- `/`          → `Replay Active` = 1, `Audit Verified` = 1
- `/playground`→ `Replay Active` = 1, `Audit Verified` = 1

Required confirmation set on `/`:
- `LIVE` present (9 occurrences)
- posture pill renders (`pill pill-degraded` observed — DEGRADED token renderable; distinction preserved)
- live replay telemetry chip `Replay <b>ACTIVE</b>` present (state-driven, unchanged)
- `Policy Enforcement Gateway Active` present
- DEMO banner present (see §5)

---

## 5. Validation output

```
python3.11 -m py_compile gateway/app.py        → py_compile OK
git --no-optional-locks diff --check           → diff --check clean
pytest -k "game034r or game033r or demo_banner or failclosed"
                                               → 24 passed, 396 deselected

Route status codes:
  /                          -> 200
  /game                      -> 200
  /simulator                 -> 200
  /health                    -> 200
  /api/status                -> 200
  /playground                -> 200
  /api/governance/evidence   -> 200
  GET  /execute              -> 404   (fail-closed preserved)
  POST /execute              -> 422   (rejected, fail-closed preserved)

DEMO banner phrases (case-insensitive count):
  /          DEMO ONLY:1  NO REAL BOOKING:2  NO REAL PAYMENT:2
  /game      DEMO ONLY:9  NO REAL BOOKING:6  NO REAL PAYMENT:3
  /simulator DEMO ONLY:0  NO REAL BOOKING:1  NO REAL PAYMENT:0

Commerce CTA scan (/ and /playground): 0 matches
  (book now / pay now / checkout / add to cart / buy now / proceed to payment /
   schedule a call / contact sales)
```

---

## 6. Remaining gaps

- `/simulator` still expresses the concepts with its own established phrasing
  ("Replay protection / Active", "Evidence verification") rather than the exact
  "Replay Active" / "Audit Verified" badges. Left unchanged intentionally: the
  simulator is a standalone SOC/training console with its own `usbsim-` design
  language, and adding the badges there was not required by the validation set
  (which targets `/`). No mismatch remains on the validated surfaces.
- `Policy Signature Valid` remains a concept (row label `Policy signature` + pill),
  not a verbatim contiguous string. Out of scope for GAME-054R (only "Replay Active"
  and "Audit Verified" were specified).
- The added badges are static capability labels (consistent with the existing
  simulator/playground static capability framing). Authoritative live state continues
  to be carried by the `/` runtime-strip telemetry chips and posture pill.

---

## 7. Git lineage status (unchanged — report-only on git)

No git write operations were performed (no stage / commit / push / branch).
Branch lineage blocker is unchanged from prior reports:
- Active branch: `governance/media-production-gap-scaffolding`
- Local `main`: ABSENT; `pre-sync-master-backup`: ABSENT; `origin/main`: `097248b`
- `.git` is not writable from the Replit Agent sandbox (destructive git operations blocked).

External commands (to be run outside the sandbox) to reconcile lineage remain:
```
git branch pre-sync-master-backup
git checkout -B main --track origin/main
git status --short
git log --oneline -5
```
Stop rule: if `checkout` fails due to local changes, stop and report `git status`;
do not stash/reset/clean/force.

---

## 8. Rollback command

Revert the two UI badge additions (only `gateway/app.py` lines were touched):
```
git checkout -- gateway/app.py
```
(Or manually remove the `gov-cap-badges` div in `governance_gateway_html` and the two
`exec-hero-tag` "Replay Active"/"Audit Verified" spans in `playground_html`.)

Then restart the **USBAY Gateway** workflow.

---

## 9. Constraints honored

- UI label/badge text only — no route/runtime/policy/simulator/gateway-logic changes.
- `/execute` fail-closed preserved (GET 404, POST 422).
- DEMO ONLY / NO REAL BOOKING / NO REAL PAYMENT banners preserved.
- LIVE / DEGRADED distinction preserved (live telemetry untouched).
- No commerce CTA introduced.
- No git stage / commit / push / branch.
- `mark_task_complete` not invoked.
