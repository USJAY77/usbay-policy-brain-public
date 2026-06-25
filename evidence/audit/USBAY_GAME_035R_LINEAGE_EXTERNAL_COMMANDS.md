# USBAY-GAME-035R — Lineage Block Resolution: External Commands

**Date:** 2026-06-25
**Workspace:** Replit Agent only
**Repository:** usbay-demo / Agent Governance Gateway
**Type:** Report-only. No runtime logic changed. No app code, `/execute`,
backend governance, booking, payment, contact, API, or connector behavior
touched. No commit / push / stage / reset / stash / clean performed. DEMO ONLY /
NO REAL BOOKING / NO PAYMENT and fail-closed behavior preserved.

## Result: PASS (runtime + demo readiness). Remaining GAP is Git-lineage only.

> No runtime crash found; no application code change required.

---

## 1. Runtime health (verified live, this run)

| Route | Expected | Actual |
|-------|----------|--------|
| `/` | 200 | **200** |
| `/game` | 200 | **200** |
| `/simulator` | 200 | **200** |
| `/execute` (GET) | 404 fail-closed | **404** |

`python -m py_compile gateway/app.py` → **OK**.

## 2. Demo readiness (on `/game`)

| Marker | Expected | Actual |
|--------|----------|--------|
| PASS pills | 9 | **9** |
| Pilot Intake Gate present | yes | **yes** |
| "READY FOR DEMO — NOT READY FOR AUTOMATED PUBLICATION" | yes | **yes** |
| DEMO ONLY banner present | yes | **yes (3)** |
| Booking / payment / contact CTA phrases | 0 | **0 of 8** |

No-commerce CTA scan (book now / pay now / checkout / add to cart / buy now /
proceed to payment / schedule a call / contact sales) returned **0** matches.

## 3. No runtime crash

- USBAY Gateway workflow startup completes; app serves all routes.
- No traceback / exception / fatal / crash entries in the workflow logs.
- No application code change required.

## 4. The only remaining blocker: Git branch-lineage / sandbox permission

The agent sandbox rejects **every** `.git/` write (branch create, checkout/
switch, ref update) with "Destructive git operations are not allowed". This
guard applies to both the main agent and background task agents, so the lineage
steps cannot be performed from inside this environment — they require a shell
with `.git` write permission (the Replit Git pane in the UI, or an SSH shell on
the VM).

Current git state (read-only, verified this run):

| Fact | Value |
|------|-------|
| current branch | `governance/media-production-gap-scaffolding` |
| local HEAD | `180d073` |
| local `main` branch | **not present** |
| `pre-sync-master-backup` branch | **not present** |
| `origin/main` | `097248b` |
| `origin` URL | `https://github.com/USJAY77/usbay-policy-brain-public.git` |

### Exact external commands (run in a Git-write-capable shell)

```bash
git branch pre-sync-master-backup
git checkout -B main --track origin/main
git status --short
git log --oneline -5
```

### Safety instruction

If `git checkout -B main --track origin/main` fails because local changes
exist, **stop and report `git status`**. Do **not** stash, reset, clean, or
force without explicit approval.

---

## Summary

- **PASS/FAIL:** PASS for runtime + demo readiness.
- **Files changed:** `evidence/audit/USBAY_GAME_035R_LINEAGE_EXTERNAL_COMMANDS.md`
  (this report only). No code changes.
- **Routes checked:** `/` 200, `/game` 200, `/simulator` 200, `GET /execute` 404.
- **Tests executed:** `py_compile gateway/app.py` (OK);
  `pytest -k "game034r or game033r or demo_banner or failclosed"`
  (24 passed, 396 deselected).
- **Remaining blocker:** Git branch-lineage requires a shell with `.git` write
  permission; it cannot be done from the agent sandbox.
- **Rollback command:**
  `git checkout -- evidence/audit/USBAY_GAME_035R_LINEAGE_EXTERNAL_COMMANDS.md`
  (or restore the prior checkpoint via the Replit UI). No runtime rollback needed
  — no application code was modified.
- **Statement:** No runtime crash found; no application code change required.
