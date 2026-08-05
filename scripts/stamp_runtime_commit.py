"""Stamp the current git commit SHA to governance/runtime_commit.txt.

Run at build/Promote time so the deployed snapshot can resolve its commit
when .git is not shipped (autoscale). The runtime falls back to this file
only when `git rev-parse HEAD` fails; if neither source is available the
attestation fails closed.

Usage:
    python3 scripts/stamp_runtime_commit.py               # read from git
    python3 scripts/stamp_runtime_commit.py --commit SHA  # use provided SHA (Docker build-arg)
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
STAMP_PATH = REPO_ROOT / "governance" / "runtime_commit.txt"

_HEX_CHARS = frozenset("0123456789abcdef")


def _validate_sha(sha: str) -> str | None:
    """Return lowercased sha if valid 40-char hex, else None."""
    sha = sha.strip().lower()
    if len(sha) == 40 and all(c in _HEX_CHARS for c in sha):
        return sha
    return None


def _sha_from_git() -> str | None:
    """Run git rev-parse HEAD; return sha string or None on failure."""
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        return _validate_sha(completed.stdout)
    except Exception:
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stamp runtime commit SHA")
    parser.add_argument(
        "--commit",
        metavar="SHA",
        default=None,
        help="40-char hex SHA to stamp; if omitted, resolved from git",
    )
    args = parser.parse_args(argv)

    if args.commit is not None:
        sha = _validate_sha(args.commit)
        if sha is None:
            print(f"ERROR: invalid sha provided via --commit: {args.commit!r}", file=sys.stderr)
            return 3
    else:
        sha = _sha_from_git()
        if sha is None:
            print("ERROR: git rev-parse HEAD failed and no --commit provided", file=sys.stderr)
            return 2

    STAMP_PATH.parent.mkdir(parents=True, exist_ok=True)
    STAMP_PATH.write_text(sha + "\n", encoding="utf-8")
    try:
        display_path = STAMP_PATH.relative_to(REPO_ROOT)
    except ValueError:
        display_path = STAMP_PATH
    print(f"stamped {display_path} = {sha}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
