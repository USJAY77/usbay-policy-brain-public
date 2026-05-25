#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


NULL_SHA = "0" * 40


def _run_git(root: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        capture_output=True,
        check=False,
    )


def _git_stdout(root: Path, args: list[str], failure_code: str) -> str:
    completed = _run_git(root, args)
    if completed.returncode != 0:
        stderr = completed.stderr.strip().replace("\n", " ")
        raise SystemExit(f"{failure_code}:{stderr}")
    return completed.stdout


def _object_exists(root: Path, ref: str) -> bool:
    if not ref or ref == NULL_SHA:
        return False
    return _run_git(root, ["cat-file", "-e", f"{ref}^{{commit}}"]).returncode == 0


def _current_head(root: Path) -> str:
    return _git_stdout(root, ["rev-parse", "HEAD"], "CI_LINEAGE_HEAD_UNAVAILABLE").strip()


def _changed_by_diff(root: Path, base: str, head: str) -> list[str]:
    output = _git_stdout(
        root,
        ["diff", "--name-only", "--diff-filter=ACMR", base, head],
        "CI_LINEAGE_DIFF_UNAVAILABLE",
    )
    return [line.strip() for line in output.splitlines() if line.strip()]


def _changed_by_tree(root: Path, head: str) -> list[str]:
    output = _git_stdout(root, ["ls-tree", "-r", "--name-only", head], "CI_LINEAGE_TREE_UNAVAILABLE")
    return [line.strip() for line in output.splitlines() if line.strip()]


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _diagnostic_hash(payload: dict[str, object]) -> str:
    return hashlib.sha256(_canonical_json(dict(payload)).encode("utf-8")).hexdigest()


def resolve_changed_files(root: Path, env: dict[str, str]) -> tuple[list[str], dict[str, object]]:
    root = root.resolve()
    event_name = env.get("EVENT_NAME", "")
    current_sha = env.get("CURRENT_SHA", "") or _current_head(root)
    stale_refs: list[str] = []
    recovery_mode = "diff"

    if event_name == "pull_request":
        base = env.get("PR_BASE_SHA", "")
        head = env.get("PR_HEAD_SHA", "") or current_sha
        if not _object_exists(root, head):
            stale_refs.append(f"pr_head:{head}")
            head = current_sha
        if _object_exists(root, base) and _object_exists(root, head):
            changed = _changed_by_diff(root, base, head)
        elif _object_exists(root, head):
            if base:
                stale_refs.append(f"pr_base:{base}")
            recovery_mode = "canonical_current_tree"
            changed = _changed_by_tree(root, head)
        else:
            raise SystemExit("CI_LINEAGE_UNRESOLVABLE")
        resolved_base = base if _object_exists(root, base) else ""
        resolved_head = head
    else:
        head = current_sha
        before = env.get("PUSH_BEFORE_SHA", "")
        if not _object_exists(root, head):
            raise SystemExit(f"CI_LINEAGE_HEAD_STALE:{head}")
        if before and before != NULL_SHA and _object_exists(root, before):
            changed = _changed_by_diff(root, before, head)
            resolved_base = before
        else:
            if before and before != NULL_SHA:
                stale_refs.append(f"push_before:{before}")
            recovery_mode = "canonical_current_tree"
            changed = _changed_by_tree(root, head)
            resolved_base = ""
        resolved_head = head

    diagnostics: dict[str, object] = {
        "lineage_schema": "usbay.ci_lineage_reconciliation.v1",
        "event_name": event_name or "unknown",
        "recovery_mode": recovery_mode,
        "lineage_status": "REWRITTEN_OR_ORPHANED" if stale_refs else "CURRENT",
        "invalidation_status": "EXPIRED_INVALID" if stale_refs else "NOT_REQUIRED",
        "invalidation_reason": "stale_or_orphaned_git_reference" if stale_refs else "canonical_refs_reachable",
        "tampering_assessment": "transient_branch_rewrite" if stale_refs else "none",
        "stale_refs_expired": stale_refs,
        "resolved_base": resolved_base,
        "resolved_head": resolved_head,
        "changed_file_count": len(set(changed)),
    }
    diagnostics["diagnostic_hash"] = _diagnostic_hash(diagnostics)
    return sorted(set(changed)), diagnostics


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Resolve CI changed files with stale lineage recovery")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--audit-output", type=Path)
    args = parser.parse_args(argv)

    changed, diagnostics = resolve_changed_files(args.root, dict(os.environ))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(changed) + ("\n" if changed else ""), encoding="utf-8")
    if args.audit_output:
        args.audit_output.parent.mkdir(parents=True, exist_ok=True)
        args.audit_output.write_text(json.dumps(diagnostics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"CI_LINEAGE_RECOVERY_MODE={diagnostics['recovery_mode']}")
    print(f"CI_LINEAGE_STALE_REFS_EXPIRED={len(diagnostics['stale_refs_expired'])}")
    print(f"CI_LINEAGE_INVALIDATION_STATUS={diagnostics['invalidation_status']}")
    print(f"CI_LINEAGE_RECONCILIATION_HASH={diagnostics['diagnostic_hash']}")
    print(f"CI_LINEAGE_CHANGED_FILES={diagnostics['changed_file_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
