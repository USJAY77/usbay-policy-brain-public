#!/usr/bin/env python3
"""Validate architecture claim-level traceability matrix completeness."""

from __future__ import annotations

import re
import sys
from pathlib import Path


MATRIX_PATH = Path(__file__).with_name("CLAIM_LEVEL_TRACEABILITY_MATRIX.md")
REQUIRED_COLUMNS = [
    "claim_id",
    "authoritative GitHub source path",
    "exact source claim text",
    "implementation evidence",
    "test evidence",
    "audit evidence",
    "status",
    "missing evidence",
]
ALLOWED_STATUSES = {"VERIFIED", "PARTIAL", "BLOCKED"}


def _table_rows(text: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|") or not stripped.endswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if cells and all(re.fullmatch(r"-+", cell) for cell in cells):
            continue
        rows.append(cells)
    return rows


def main() -> int:
    if not MATRIX_PATH.exists():
        print(f"TRACEABILITY_MATRIX_MISSING:{MATRIX_PATH}")
        return 1
    rows = _table_rows(MATRIX_PATH.read_text(encoding="utf-8"))
    if len(rows) < 2:
        print("TRACEABILITY_MATRIX_TABLE_MISSING")
        return 1
    header = rows[0]
    if header != REQUIRED_COLUMNS:
        print("TRACEABILITY_MATRIX_COLUMNS_INVALID")
        print("expected=" + ",".join(REQUIRED_COLUMNS))
        print("actual=" + ",".join(header))
        return 1
    failures = []
    for index, row in enumerate(rows[1:], start=1):
        if len(row) != len(REQUIRED_COLUMNS):
            failures.append(f"row_{index}:COLUMN_COUNT_INVALID")
            continue
        record = dict(zip(REQUIRED_COLUMNS, row))
        for column in REQUIRED_COLUMNS:
            if not record[column]:
                failures.append(f"{record.get('claim_id', f'row_{index}')}:{column}:EMPTY")
        if record.get("status") not in ALLOWED_STATUSES:
            failures.append(f"{record.get('claim_id', f'row_{index}')}:STATUS_INVALID")
        if record.get("status") in {"PARTIAL", "BLOCKED"} and record.get("missing evidence") in {"", "None", "N/A"}:
            failures.append(f"{record.get('claim_id', f'row_{index}')}:MISSING_EVIDENCE_REQUIRED")
    if failures:
        for failure in failures:
            print(failure)
        return 1
    print("TRACEABILITY_MATRIX_VALID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
