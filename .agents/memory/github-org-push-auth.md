---
name: GitHub org push auth
description: How pushes to the USBAY-GLOBAL org repo authenticate durably across workspace restarts
---
Pushes to USBAY-GLOBAL/usbay-demo-governance-app need a classic PAT (repo+workflow scopes); Replit's default git OAuth can read but not write that org.

Durable setup (no /tmp scripts): checked-in `scripts/git_askpass.sh` answers Username→`x-access-token`, Password→`$GITHUB_TOKEN` (read at runtime, never on disk), wired via repo-local `core.askPass = /home/runner/workspace/scripts/git_askpass.sh` in `.git/config`.

**Why:** /tmp is wiped on restart; the old temp askpass approach broke backups after every restart.

**How to apply:** git push/pull just work in any fresh shell as long as the GITHUB_TOKEN secret exists. If the repo moves off `/home/runner/workspace`, update the absolute `core.askPass` path.
