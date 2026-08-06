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

# The Docker build context ships these paths verbatim (see Dockerfile COPY
# list). Any modified OR untracked file here would enter the image without
# being part of HEAD, silently breaking the deployed-commit guarantee — so
# reject both. governance/runtime_commit.txt is the one sanctioned generated
# deploy artifact (restamped below).
SHIPPED_PATHS=(audit executors gateway governance policy routing runtime \
  scripts surfaces security utils simulator governance_runtime_monitor.py \
  requirements.txt Dockerfile wrangler.toml cloudflare)
DIRTY="$(git status --porcelain --untracked-files=all -- "${SHIPPED_PATHS[@]}" \
  ':!governance/runtime_commit.txt')"
if [ -n "$DIRTY" ]; then
  echo "FAIL: uncommitted or untracked files in shipped paths; commit or remove before releasing:" >&2
  echo "$DIRTY" >&2
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
# --force-with-lease needs an up-to-date remote-tracking ref when pushing by
# URL, so fetch the current remote tip first and lease against it.
REPO_URL="https://github.com/USBAY-GLOBAL/usbay-demo-governance-app.git"
export GIT_ASKPASS="$(pwd)/scripts/git_askpass.sh"
REMOTE_TIP="$(git ls-remote "$REPO_URL" refs/heads/main | cut -f1)"
git push --force-with-lease="refs/heads/main:${REMOTE_TIP}" "$REPO_URL" HEAD:main

echo "[release] deploying with EXPECTED_GIT_COMMIT=$HEAD_SHA"
npx wrangler deploy --var "EXPECTED_GIT_COMMIT:$HEAD_SHA"

echo "[release] done: $HEAD_SHA"
