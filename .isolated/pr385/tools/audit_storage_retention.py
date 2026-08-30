#!/usr/bin/env python3
"""Apply USBAY audit storage retention policy v1."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from python.audit import storage_policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply USBAY audit storage retention policy v1")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--environment", choices=["test", "production"], default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    result = storage_policy.enforce_retention(
        root=args.root,
        environment=args.environment,
        dry_run=args.dry_run,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
