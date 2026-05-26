"""Stamp the current git commit SHA to governance/runtime_commit.txt.

Run at build/Promote time so the deployed snapshot can resolve its commit
when .git is not shipped (autoscale). The runtime falls back to this file
only when `git rev-parse HEAD` fails; if neither source is available the
attestation fails closed.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
STAMP_PATH = REPO_ROOT / "governance" / "runtime_commit.txt"


def main() -> int:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
    except Exception as exc:
        print(f"ERROR: git rev-parse HEAD failed: {exc}", file=sys.stderr)
        return 2
    sha = completed.stdout.strip().lower()
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
        print(f"ERROR: invalid git sha: {sha!r}", file=sys.stderr)
        return 3
    STAMP_PATH.parent.mkdir(parents=True, exist_ok=True)
    STAMP_PATH.write_text(sha + "\n", encoding="utf-8")
    print(f"stamped {STAMP_PATH.relative_to(REPO_ROOT)} = {sha}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
