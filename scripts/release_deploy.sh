#!/usr/bin/env bash
# USBAY release deploy — the ONLY sanctioned path for production deploys.
#
# Lifecycle it enforces (fail-closed at every step):
#   1. Working tree must be committed (release = a commit, not a dirty tree).
#   2. governance/runtime_commit.txt is regenerated to HEAD (deployment-time
#      stamp; wrangler container builds ship the working-dir file).
#   3. GitHub main is pushed to HEAD so repository == workspace.
#   4. wrangler deploy injects EXPECTED_GIT_COMMIT=<HEAD> so the container's
#      startup check rejects any stale/mismatching runtime commit.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -n "$(git status --porcelain --untracked-files=no -- . ':!governance/runtime_commit.txt')" ]; then
  echo "FAIL: uncommitted changes present; commit before releasing." >&2
  git status --porcelain --untracked-files=no >&2
  exit 1
fi

HEAD_SHA="$(git rev-parse HEAD)"
python3 scripts/stamp_runtime_commit.py
STAMP="$(cat governance/runtime_commit.txt)"
if [ "$STAMP" != "$HEAD_SHA" ]; then
  echo "FAIL: runtime commit stamp ($STAMP) != HEAD ($HEAD_SHA)" >&2
  exit 1
fi

echo "[release] pushing $HEAD_SHA to GitHub main"
GIT_ASKPASS="$(pwd)/scripts/git_askpass.sh" git push --force-with-lease \
  https://github.com/USBAY-GLOBAL/usbay-demo-governance-app.git HEAD:main

echo "[release] deploying with EXPECTED_GIT_COMMIT=$HEAD_SHA"
npx wrangler deploy --var "EXPECTED_GIT_COMMIT:$HEAD_SHA"

echo "[release] done: $HEAD_SHA"
