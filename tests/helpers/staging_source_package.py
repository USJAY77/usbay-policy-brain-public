"""Test-only snapshot preparation; never an operational source issuer."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess


def snapshot_staging_source(root: Path, destination: Path) -> dict:
    root = root.resolve(strict=True)
    destination = destination.absolute()
    if destination.exists() or destination.is_relative_to(root):
        raise RuntimeError("synthetic_source_destination_invalid")
    # Only public Git identity/source data is read; no inherited Git overrides.
    environment = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": os.devnull, "GIT_NO_REPLACE_OBJECTS": "1",
                   "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0",
                   "GIT_OPTIONAL_LOCKS": "0"}

    def git(*arguments):
        return subprocess.run(["git", "-C", str(root), *arguments], env=environment,
                              check=True, capture_output=True, timeout=30).stdout

    def identity():
        if git("status", "--porcelain=v1", "--untracked-files=no"):
            raise RuntimeError("synthetic_source_requires_clean_candidate")
        return git("rev-parse", "HEAD", "HEAD^{tree}").decode("ascii").splitlines()

    before = identity()
    entries = []
    destination.mkdir(mode=0o700)
    for raw in git("ls-tree", "-r", "-z", "HEAD").split(b"\0"):
        if not raw:
            continue
        metadata, name = raw.split(b"\t", 1)
        mode, kind, blob_id = metadata.decode("ascii").split()
        path = Path(name.decode("utf-8", "strict"))
        if (kind != "blob" or mode not in {"100644", "100755"}
                or path.is_absolute() or any(part in {".", "..", ".git"} for part in path.parts)):
            raise RuntimeError("synthetic_source_entry_invalid")
        source = root / path
        info = source.lstat()
        if not stat.S_ISREG(info.st_mode) or source.resolve(strict=True) != source:
            raise RuntimeError("synthetic_source_entry_invalid")
        content = source.read_bytes()
        blob = b"blob " + str(len(content)).encode("ascii") + b"\0" + content
        if hashlib.sha1(blob).hexdigest() != blob_id:
            raise RuntimeError("synthetic_source_changed")
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(0o755 if mode == "100755" else 0o644)
        entries.append({"path": path.as_posix(), "mode": mode, "size": len(content),
                        "sha256": hashlib.sha256(content).hexdigest()})
    if before != identity():
        raise RuntimeError("synthetic_source_changed")
    return {"source_commit": before[0], "source_tree_reference": before[1],
            "managed_files": sorted(entries, key=lambda item: item["path"])}


def run_staging_case(package: Path, metadata: dict, state: Path, mutation: str) -> dict:
    import sys

    if mutation not in {"valid", "missing", "tampered", "stale"}:
        raise RuntimeError("synthetic_staging_case_invalid")
    state.mkdir(mode=0o700)
    inputs = state / "public-source-inputs.json"
    inputs.write_text(json.dumps(metadata), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(package / "tests/helpers/staging_artifact_child.py"),
         str(inputs), str(state), mutation], cwd=package,
        env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
        check=False, capture_output=True, timeout=60,
    )
    # Never reflect arbitrary child stdout, exception text or environment values.
    if result.returncode != 0 or result.stderr or len(result.stdout) > 4096:
        raise AssertionError("synthetic_staging_child_failed")
    try:
        payload = json.loads(result.stdout)
    except (UnicodeError, ValueError):
        raise AssertionError("synthetic_staging_result_invalid") from None
    if not isinstance(payload, dict) or payload.get("case") != mutation:
        raise AssertionError("synthetic_staging_result_invalid")
    return payload
