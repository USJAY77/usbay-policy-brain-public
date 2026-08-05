#!/bin/bash
# Post-merge setup for the USBAY gateway workspace.
# Runs automatically after a task merge. Idempotent, non-interactive, fast.
set -e

cd "$(dirname "$0")/.."

# Repair Python dependencies only if the gateway fails to import.
if ! python3 -c "import gateway.app" >/dev/null 2>&1; then
  if [ -f requirements.txt ]; then
    python3 -m pip install -q -r requirements.txt
  fi
  python3 -c "import gateway.app" >/dev/null
fi

# Refresh the runtime commit stamp so the dashboard shows the merged commit.
if [ -f scripts/stamp_runtime_commit.py ]; then
  python3 scripts/stamp_runtime_commit.py || true
fi

echo "post-merge setup OK"
