# USBAY Governance Dashboard

## Project Overview

USBAY is a governance-enforcement platform. This workspace hosts:

- **USBAY Gateway** — FastAPI application (`gateway/app.py`) serving the governance dashboard, simulator, pilot readiness center, and API surfaces, routed by hostname via `routing/host_router.py`.
- **Governance enforcement** — policy validation, runtime health authority, audit ledger, WORM archive, and signed deployment attestation.
- **Pilot Readiness Center** (`/pilot-readiness`) — fpdf2-generated PDF/JSON deliverables and a pilot intake wizard.
- **Simulator** (`/simulator`) — standalone SOC console.
- **Game** (`/game`) — USBAY-GAME-004 playable travel prototype.
- **Demo repo mirror** — `USBAY-GLOBAL/usbay-demo-governance-app` on GitHub, kept in sync via GitHub Git Data API delta pushes.

## Running the App

The **USBAY Gateway** workflow starts the server. Restart it after code changes:

```
# workflow name: USBAY Gateway
```

## User Preferences

- Always use authentic data; never mock or placeholder data in production paths.
- Surface explicit errors; no silent fallbacks.
- Keep full-page routes (`/simulator`, `/game`) before the catch-all in the router.

---

## governance_release.json — Large File Warning & Regeneration

### What happened

`governance_release.json` was committed to git history across 23 commits (earliest: `8bab7e3`).
The file's `release_history` array accumulates an entry on every call to
`write_release_manifest(preserve_existing_lineage=True)`. By commit `64ae81c` the array
had grown to ~33 MB, making the file 54.81 MB and triggering GitHub's GH001 warning
on every push that transferred those objects for the first time.

Commit `a106af2` removed the file from HEAD and added `.gitignore` exclusions.

**The large blobs remain in git history** (history was not rewritten per policy).
They will not appear in future commits; new pushes to remotes that already received
those commits will not re-warn.

### Current protection

| Layer | Detail |
|-------|--------|
| `.gitignore` | `governance_release*.json` — prevents staging |
| `pre-commit` hook | Blocks the file even if staged with `git add --force` |
| `verify_production_readiness.py` | `TRACKED_ROOT_GOVERNANCE_RELEASE` check fails CI if file is tracked |

### Regeneration

`governance_release.json` is a **runtime-generated artifact**. It is written to
`/tmp/usbay-governance-release/governance_release.json` by default when the gateway
starts (`ensure_runtime_release_manifest`). The repo-root copy is only needed for
the `write-release` CLI command, and must never be committed.

To regenerate a fresh manifest at repo root (for inspection only — do not `git add`):

```bash
python3 -m security.deployment_attestation write-release
```

To control where the runtime writes it, set:

```bash
export USBAY_GOVERNANCE_RELEASE_PATH=/tmp/usbay-governance-release/governance_release.json
```

### Why it grew so large

`write_release_manifest(preserve_existing_lineage=True)` reads the existing file and
appends the previous manifest to `release_history`. Each call therefore grew the file
by the full previous size. The fix is to never commit the file — the runtime version
in `/tmp` is ephemeral and resets on restart, keeping history at O(1).

### Other large artifacts checked

`git cat-file --batch-all-objects` shows four blobs over 10 MB in the object store,
all belonging to historical versions of `governance_release.json`. No other tracked
files exceed 10 MB.
