#!/usr/bin/env python3
"""Portable local governance checks for pre-commit.

The checks are intentionally dependency-free so the repository can validate
basic hygiene without network access or local machine-specific hook state.
"""

from __future__ import annotations

import argparse
import json
import py_compile
import re
import sys
from pathlib import Path


SECRET_PATTERNS = (
    ("PRIVATE_KEY_BLOCK", re.compile("BEGIN " + "PRIVATE KEY")),
    ("RSA_PRIVATE_KEY_BLOCK", re.compile("BEGIN RSA " + "PRIVATE KEY")),
    ("EC_PRIVATE_KEY_BLOCK", re.compile("BEGIN EC " + "PRIVATE KEY")),
    ("GITHUB_CLASSIC_TOKEN", re.compile(r"\b" + "gh" + "p_" + r"[A-Za-z0-9_]{20,}\b")),
    ("GITHUB_FINE_GRAINED_TOKEN", re.compile(r"\b" + "github" + "_pat_" + r"[A-Za-z0-9_]{20,}\b")),
    ("SLACK_BOT_TOKEN", re.compile(r"\b" + "xox" + "b-" + r"[A-Za-z0-9-]{12,}\b")),
    ("AWS_ACCESS_KEY_ID", re.compile(r"\b" + "AK" + "IA" + r"[A-Z0-9]{16}\b")),
)


def _failures_for_text(path: Path, text: str) -> list[str]:
    failures: list[str] = []
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines, start=1):
        stripped_newline = line[:-1] if line.endswith("\n") else line
        if stripped_newline.endswith((" ", "\t")):
            failures.append(f"{path}:{index}:TRAILING_WHITESPACE")
    if text and not text.endswith("\n"):
        failures.append(f"{path}:EOF_NEWLINE_MISSING")
    return failures


def check_whitespace(paths: list[Path]) -> list[str]:
    failures: list[str] = []
    for path in paths:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        failures.extend(_failures_for_text(path, text))
    return failures


def check_json(paths: list[Path]) -> list[str]:
    failures: list[str] = []
    for path in paths:
        if not path.is_file() or path.suffix != ".json":
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            failures.append(f"{path}:JSON_INVALID:{exc.msg}")
    return failures


def check_python(paths: list[Path]) -> list[str]:
    failures: list[str] = []
    for path in paths:
        if not path.is_file() or path.suffix != ".py":
            continue
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as exc:
            failures.append(f"{path}:PY_COMPILE_INVALID:{exc.msg}")
    return failures


def check_secrets(paths: list[Path]) -> list[str]:
    failures: list[str] = []
    for path in paths:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            for label, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    failures.append(f"{path}:{line_number}:SECRET_MARKER_DETECTED:{label}")
    return failures


CHECKS = {
    "whitespace": check_whitespace,
    "json": check_json,
    "python": check_python,
    "secrets": check_secrets,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run dependency-free USBAY pre-commit governance checks")
    parser.add_argument("check", choices=sorted(CHECKS))
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args(argv)
    failures = CHECKS[args.check]([Path(path) for path in args.paths])
    if failures:
        print("\n".join(sorted(set(failures))))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
