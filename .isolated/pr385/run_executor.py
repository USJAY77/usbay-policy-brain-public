#!/usr/bin/env python3
"""
Minimal Replit run entrypoint for the USBAY executor.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def main() -> int:
    result = subprocess.run(
        [sys.executable, str(ROOT / "runtime" / "replit_executor.py")],
        cwd=str(ROOT),
        check=False,
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
