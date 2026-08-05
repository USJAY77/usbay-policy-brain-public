---
name: GitHub org push auth
description: How to push to USBAY-GLOBAL org repos from this workspace
---
- App code lives in `USBAY-GLOBAL/usbay-demo-governance-app` (origin); `USJAY77/usbay-policy-brain-public` is only the docs repo.
- Replit's GitHub OAuth token (`replit-git-askpass`) authenticates but is NOT honored for writes to the USBAY-GLOBAL org (git push "Invalid username or token"; API writes masked as 404). Reads work.
- Working push path: classic PAT in `GITHUB_TOKEN` secret with **repo + workflow** scopes, via a temp `GIT_ASKPASS` script (Username→`x-access-token`, Password→`$GITHUB_TOKEN`). `workflow` scope is mandatory — the history ships 17 files under `.github/workflows/`.
- **Why:** repeated failures came from tokens missing `workflow` scope or bad pastes; verify with `X-OAuth-Scopes` header on `GET /user` before pushing.
- **How to apply:** recreate `/tmp/gh_askpass.sh` each session (tmp is wiped); never print the token; mask URLs in output.
