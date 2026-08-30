from __future__ import annotations

import sys

from audit.exporter import verify_audit_chain_export


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python tools/verify_audit_chain.py <export_file>", file=sys.stderr)
        return 2
    return 0 if verify_audit_chain_export(argv[1]) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
