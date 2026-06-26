# USBAY-GAME-038R — Git Lineage External Handoff (Command Pack)

**Date:** 2026-06-25
**Workspace:** Replit Agent only
**Repository:** USBAY Gateway
**Type:** Report-only. No gateway / Game / Simulator / governance change. No
booking / payment / contact CTA. No git branch / checkout / stash / reset /
clean / force / commit / push performed. Fails closed: `.git` write remains
blocked in the agent sandbox, so the lineage action is handed off externally.

## Result: PASS. Runtime healthy and demo-ready; lineage step handed off to Terminal / Git pane.

> No runtime crash exists. No application code change is required. Remaining
> blocker is Git write permission only.

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
| DEMO ONLY banner present | yes | **yes (3)** |
| Booking / payment / contact CTA phrases | 0 | **0 of 8** |
| Runtime crash | none | **none** |

## 3. Exact blocker

The agent sandbox rejects **all** `.git/` writes with:

> `Destructive git operations are not allowed in the main agent.`

(GAME-036R confirmed this via a direct `.git` write test.) The guard applies to
both the main agent and background task agents, so branch-create, fetch, and
checkout cannot run in-environment. The lineage action must be executed in a
**Git-write-capable shell** — the **Replit Terminal / Git pane**, or a **VM /
SSH shell**.

Current git state (read-only):

| Fact | Value |
|------|-------|
| current branch | `governance/media-production-gap-scaffolding` |
| current commit SHA | `5732dc5` |
| `git status --short` | **(empty — working tree clean)** |
| local `main` branch | **not present** |
| `pre-sync-master-backup` branch | **not present** |
| `origin/main` (last known) | `097248b` |
| `origin` URL | `https://github.com/USJAY77/usbay-policy-brain-public.git` |

## 4. External command pack (run in Terminal / Git pane, in order)

```bash
git branch pre-sync-master-backup
git checkout -B main --track origin/main
git status --short
git log --oneline -5
```

## 5. Stop rule

If `git checkout -B main --track origin/main` fails because local changes exist,
**stop and report**:

```bash
git status
```

Do **not** stash, reset, clean, or force without explicit approval.

---

## Summary

- **PASS/FAIL:** PASS.
- **Files changed:** `evidence/audit/USBAY_GAME_038R_GIT_LINEAGE_EXTERNAL_HANDOFF.md`
  (this report only). No code, UI, gateway, or simulator change.
- **Routes checked:** `/` 200, `/game` 200, `/simulator` 200, `GET /execute` 404.
- **Demo readiness result:** 9 PASS pills, Pilot Intake Gate present, DEMO ONLY
  banner (×3), 0 of 8 commerce CTA phrases, no runtime crash. Validation:
  `pytest -k "game034r or game033r or demo_banner or failclosed"` →
  **24 passed, 396 deselected**.
- **Exact blocker:** Git write permission only — `.git` writes are blocked in the
  agent sandbox; lineage must run in Terminal / Git pane / VM shell.
- **External command pack:** see §4. Stop rule: see §5.
- **Rollback command:**
  `git checkout -- evidence/audit/USBAY_GAME_038R_GIT_LINEAGE_EXTERNAL_HANDOFF.md`
  (or restore the prior checkpoint via the Replit UI). No runtime rollback needed
  — no application code was modified.
- **Statement:** No runtime crash exists; no application code change is required.
