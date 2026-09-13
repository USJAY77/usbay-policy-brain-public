#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import marshal
import os
import re
import stat
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
APPROVED_PUBLIC_PEM_PATHS = {
    "approvals/approver1_public_key.pem",
    "approvals/approver2_public_key.pem",
    "approvals/dev-ci/approver1_public_key.pem",
    "approvals/dev-ci/approver2_public_key.pem",
    "audit/public_key.pem",
    "keys_runtime/audit_ed25519.pub.pem",
    "keys_runtime/release_ed25519.pub.pem",
    "keys_runtime/root_authority_ed25519.pub.pem",
    "policy/public_key.pem",
    "python/audit/audit_seal_public_key.pem",
    "python/audit/keys/anchor_ed25519_public_key.pem",
    "python/audit/keys/audit_ed25519_public_key.pem",
    "python/audit/.embedded_trust/embedded_root_authority_public_key_0183f70ecb108985.pem",
}
APPROVED_PUBLIC_HISTORY_KEY_PATHS = APPROVED_PUBLIC_PEM_PATHS | {
    "governance/keys/actor_public.key",
    "governance/keys/request_public.key",
    "governance/policy_public.key",
    "governance/request_public.key",
}
EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "usbay_policy_brain.egg-info",
}
MANAGED_ARTIFACT_PREFIXES = (
    (".cache", "uv"),
    (".config", ".semgrep"),
    (".config", "replit", ".semgrep"),
    (".local", "share", "pnpm", "store"),
    (".local", "state", "replit"),
    (".pythonlibs",),
    ("node_modules", ".pnpm"),
)
PRIVATE_NAME_RE = re.compile(r"(private|secret|password).*(\.key|\.pem|\.env)$", re.IGNORECASE)
FORBIDDEN_DEMO_TERMS = {
    "raw_payload",
    "raw_prompt",
    "payment_id",
    "payment_identifier",
    "full_ip_address",
    "raw_ip",
    "precise_location",
    "raw_device_fingerprint",
}
TASK_MARKERS_RE = re.compile(r"(TODO|FIXME)", re.IGNORECASE)
UNSAFE_LANGUAGE_RE = re.compile(
    "(" + "by" + "pass" + r"|disable.*validation|allow.*without|skip.*signature)",
    re.IGNORECASE,
)
NON_EXECUTING_RM_RF_CONTEXT_RE = re.compile(
    r"(classify_command|build_payload|command=|requested_action|denied_payload|not in text)",
)
EXECUTING_RM_RF_CONTEXT_RE = re.compile(r"(subprocess\.|os\.system|Popen|run\(|call\()", re.IGNORECASE)
APPROVED_BOUNDED_RM_RF_TARGETS = {
    "evidence/governance-evidence-manifest.json",
    "evidence/governance-timestamps",
}


def iter_files(root: Path):
    for path in root.rglob("*"):
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path


def is_public_key_file(path: Path) -> bool:
    lowered = path.name.lower()
    if "public" in lowered or lowered.endswith(".pub.pem"):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="ignore")[:200]
    except Exception:
        return False
    return "PUBLIC KEY" in head and "PRIVATE KEY" not in head


class PublicReleaseScanError(RuntimeError):
    def __init__(self, rule: str, path: str = ".") -> None:
        super().__init__(rule)
        self.rule = rule
        self.path = path


def _decode_git_paths(raw_paths: bytes) -> set[str]:
    try:
        decoded_paths = raw_paths.decode("utf-8", errors="strict").split("\0")
    except UnicodeDecodeError as exc:
        raise PublicReleaseScanError("git_paths_invalid") from exc
    paths: set[str] = set()
    for raw_path in decoded_paths:
        if not raw_path:
            continue
        relative = Path(raw_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise PublicReleaseScanError("git_paths_invalid")
        normalized = relative.as_posix()
        if normalized in {"", "."}:
            raise PublicReleaseScanError("git_paths_invalid")
        paths.add(normalized)
    return paths


def _git_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }


def _run_git(
    root: Path,
    *arguments: str,
    allowed_returncodes: tuple[int, ...] = (0,),
) -> bytes:
    try:
        result = subprocess.run(
            ("git", "-C", str(root), *arguments),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=_git_environment(),
        )
    except OSError as exc:
        raise PublicReleaseScanError("git_authority_unavailable") from exc
    if result.returncode not in allowed_returncodes:
        raise PublicReleaseScanError("git_authority_unavailable")
    return result.stdout


def _validate_git_identity(root: Path) -> None:
    raw_identity = _run_git(
        root,
        "rev-parse",
        "--show-toplevel",
        "--absolute-git-dir",
    )
    try:
        identity_lines = raw_identity.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise PublicReleaseScanError("git_identity_invalid") from exc
    if len(identity_lines) != 2:
        raise PublicReleaseScanError("git_identity_invalid")
    try:
        worktree_root = Path(identity_lines[0]).resolve(strict=True)
        git_directory = Path(identity_lines[1]).resolve(strict=True)
    except OSError as exc:
        raise PublicReleaseScanError("git_identity_invalid") from exc
    git_marker = root / ".git"
    try:
        if git_marker.is_dir():
            expected_git_directory = git_marker.resolve(strict=True)
        elif git_marker.is_file():
            marker_lines = git_marker.read_text(encoding="utf-8", errors="strict").splitlines()
            if len(marker_lines) != 1 or not marker_lines[0].startswith("gitdir: "):
                raise PublicReleaseScanError("git_identity_invalid")
            marker_target = Path(marker_lines[0][len("gitdir: "):])
            if not marker_target.is_absolute():
                marker_target = git_marker.parent / marker_target
            expected_git_directory = marker_target.resolve(strict=True)
        else:
            raise PublicReleaseScanError("git_identity_invalid")
    except (OSError, UnicodeError) as exc:
        raise PublicReleaseScanError("git_identity_invalid") from exc
    if worktree_root != root or git_directory != expected_git_directory:
        raise PublicReleaseScanError("git_identity_invalid")
    if not git_directory.is_dir():
        raise PublicReleaseScanError("git_identity_invalid")


def _governed_paths(root: Path) -> set[str]:
    commands = (
        ("ls-files", "-z", "--cached", "--"),
        ("ls-tree", "-rz", "--name-only", "HEAD"),
    )
    governed: set[str] = set()
    for command in commands:
        governed.update(_decode_git_paths(_run_git(root, *command)))
    return governed


def _private_key_markers() -> tuple[str, ...]:
    return tuple(
        "".join(parts)
        for parts in (
            ("BEGIN ", "PRIVATE KEY"),
            ("BEGIN ", "RSA ", "PRIVATE KEY"),
            ("BEGIN ", "OPENSSH ", "PRIVATE KEY"),
            ("BEGIN ", "EC ", "PRIVATE KEY"),
            ("BEGIN ", "ENCRYPTED ", "PRIVATE KEY"),
        )
    )


def _git_private_marker_paths(root: Path) -> set[str]:
    marker_arguments = ["-z", "-l", "-F"]
    for marker in _private_key_markers():
        marker_arguments.extend(("-e", marker))
    indexed = _run_git(
        root,
        "grep",
        *marker_arguments,
        "--cached",
        "--",
        allowed_returncodes=(0, 1),
    )
    headed = _run_git(
        root,
        "grep",
        *marker_arguments,
        "HEAD",
        "--",
        allowed_returncodes=(0, 1),
    )
    indexed_paths = _decode_git_paths(indexed)
    try:
        headed_entries = headed.decode("utf-8", errors="strict").split("\0")
    except UnicodeDecodeError as exc:
        raise PublicReleaseScanError("git_paths_invalid") from exc
    headed_paths: set[str] = set()
    for entry in headed_entries:
        if not entry:
            continue
        if not entry.startswith("HEAD:"):
            raise PublicReleaseScanError("git_paths_invalid")
        headed_paths.update(_decode_git_paths((entry[len("HEAD:"):] + "\0").encode("utf-8")))
    return indexed_paths | headed_paths


def _is_managed_artifact_path(relative_path: Path) -> bool:
    parts = relative_path.parts
    return any(parts[: len(prefix)] == prefix for prefix in MANAGED_ARTIFACT_PREFIXES)


def _is_exact_governed_source_bytecode(
    canonical_root: Path,
    relative_path: Path,
    path: Path,
    governed_paths: set[str],
) -> bool:
    if relative_path.as_posix() in governed_paths:
        return False
    if path.parent.name != "__pycache__":
        return False
    cache_tag = sys.implementation.cache_tag
    if not cache_tag:
        return False
    match = re.fullmatch(
        rf"(?P<stem>.+)\.{re.escape(cache_tag)}"
        rf"(?:(?:\.opt-(?P<opt>[12]))|(?:-pytest-(?P<pytest_version>[0-9.]+)))?\.pyc",
        path.name,
    )
    if match is None:
        return False
    source = path.parent.parent / f"{match.group('stem')}.py"
    try:
        source_mode = source.lstat().st_mode
        resolved_source = source.resolve(strict=True)
        resolved_source.relative_to(canonical_root)
    except (OSError, ValueError):
        return False
    if not stat.S_ISREG(source_mode):
        return False
    source_relative = resolved_source.relative_to(canonical_root).as_posix()
    if source_relative not in governed_paths:
        return False
    try:
        bytecode = path.read_bytes()
        if len(bytecode) < 16 or bytecode[:4] != importlib.util.MAGIC_NUMBER:
            return False
        code = marshal.loads(bytecode[16:])
        source_bytes = source.read_bytes()
        pytest_version = match.group("pytest_version")
        if pytest_version is None:
            expected_code = compile(
                source_bytes,
                str(source),
                "exec",
                dont_inherit=True,
                optimize=int(match.group("opt") or 0),
            )
        else:
            import pytest
            from _pytest.assertion.rewrite import _rewrite_test
            from _pytest.config import Config

            if pytest_version != pytest.__version__:
                return False
            _, expected_code = _rewrite_test(source, Config.fromdictargs({}, []))
    except (EOFError, ImportError, OSError, SyntaxError, TypeError, ValueError):
        return False
    return code == expected_code


def _is_managed_artifact_symlink(
    canonical_root: Path,
    relative_path: Path,
    resolved: Path,
    governed_paths: set[str],
) -> bool:
    if relative_path.as_posix() in governed_paths:
        return False
    for prefix in MANAGED_ARTIFACT_PREFIXES:
        if relative_path.parts[: len(prefix)] != prefix:
            continue
        managed_root = canonical_root.joinpath(*prefix)
        return resolved.is_relative_to(managed_root)
    return False


def _private_scan_files(
    root: Path,
) -> tuple[list[Path], list[str], set[str], set[str]]:
    try:
        canonical_root = root.resolve(strict=True)
    except OSError as exc:
        raise PublicReleaseScanError("root_unavailable") from exc
    if not canonical_root.is_dir():
        raise PublicReleaseScanError("root_not_directory")

    _validate_git_identity(canonical_root)
    governed_paths = _governed_paths(canonical_root)
    governed_marker_paths = _git_private_marker_paths(canonical_root)
    files: list[Path] = []
    findings: list[str] = []
    traversal_failures: list[str] = []

    def record_traversal_failure(error: OSError) -> None:
        failed_path = getattr(error, "filename", None)
        try:
            relative = Path(failed_path).relative_to(canonical_root).as_posix()
        except (TypeError, ValueError):
            relative = "."
        traversal_failures.append(relative)

    for dir_path, dir_names, file_names in os.walk(
        canonical_root,
        topdown=True,
        onerror=record_traversal_failure,
        followlinks=False,
    ):
        if Path(dir_path) == canonical_root:
            dir_names[:] = [name for name in dir_names if name != ".git"]
        dir_names.sort()
        file_names.sort()
        blocked_directories: set[str] = set()
        for entry_name in [*dir_names, *file_names]:
            path = Path(dir_path) / entry_name
            try:
                relative = path.relative_to(canonical_root)
            except ValueError:
                findings.append(f"path_outside_root:{path}")
                blocked_directories.add(entry_name)
                continue
            rel = relative.as_posix()
            try:
                path_mode = path.lstat().st_mode
            except OSError:
                findings.append(f"path_inspection_failed:{rel}")
                blocked_directories.add(entry_name)
                continue
            if stat.S_ISLNK(path_mode):
                try:
                    resolved = path.resolve(strict=True)
                except OSError:
                    findings.append(f"unsafe_symlink:{rel}")
                    blocked_directories.add(entry_name)
                    continue
                if not _is_managed_artifact_symlink(
                    canonical_root,
                    relative,
                    resolved,
                    governed_paths,
                ):
                    findings.append(f"unsafe_symlink:{rel}")
                blocked_directories.add(entry_name)
                continue
            if stat.S_ISDIR(path_mode):
                continue
            if not stat.S_ISREG(path_mode):
                continue
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(canonical_root)
            except OSError:
                findings.append(f"path_inspection_failed:{rel}")
                continue
            except ValueError:
                findings.append(f"path_outside_root:{rel}")
                continue
            if _is_managed_artifact_path(relative) and rel not in governed_paths:
                continue
            files.append(path)
        dir_names[:] = [
            name
            for name in dir_names
            if name not in blocked_directories
        ]

    findings.extend(
        f"traversal_failed:{relative_path}"
        for relative_path in traversal_failures
    )
    _validate_git_identity(canonical_root)
    if (
        _governed_paths(canonical_root) != governed_paths
        or _git_private_marker_paths(canonical_root) != governed_marker_paths
    ):
        raise PublicReleaseScanError("git_authority_changed")
    return files, findings, governed_paths, governed_marker_paths


def _private_finding(
    relative_path: str,
    text: str | None,
    marker_present: bool,
) -> str | None:
    path = Path(relative_path)
    private_markers = _private_key_markers()
    marker_present = marker_present or (
        text is not None and any(marker in text for marker in private_markers)
    )
    if path.name == ".env" or path.suffix == ".env":
        return f"env_file:{relative_path}"
    if path.suffix.lower() == ".pem":
        if relative_path not in APPROVED_PUBLIC_PEM_PATHS:
            return f"unapproved_pem_file:{relative_path}"
        if marker_present:
            return f"private_key_material:{relative_path}"
        if text is not None and "PUBLIC KEY" not in text[:200]:
            return f"invalid_public_key_file:{relative_path}"
        return None
    if path.suffix.lower() == ".key" or PRIVATE_NAME_RE.search(path.name):
        if relative_path in APPROVED_PUBLIC_HISTORY_KEY_PATHS and not marker_present:
            return None
        return f"private_key_file:{relative_path}"
    if marker_present:
        return f"private_key_material:{relative_path}"
    return None


def scan_private_keys(root: Path) -> list[str]:
    try:
        files, boundary_findings, governed_paths, governed_marker_paths = _private_scan_files(root)
    except PublicReleaseScanError as exc:
        return [f"{exc.rule}:{exc.path}"]
    canonical_root = root.resolve(strict=True)
    findings = set(boundary_findings)
    for relative_path in governed_paths:
        finding = _private_finding(
            relative_path,
            text=None,
            marker_present=relative_path in governed_marker_paths,
        )
        if finding is not None:
            findings.add(finding)
    for path in files:
        rel = path.relative_to(canonical_root).as_posix()
        if _is_exact_governed_source_bytecode(
            canonical_root,
            Path(rel),
            path,
            governed_paths,
        ):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeError):
            findings.add(f"file_read_failed:{rel}")
            continue
        finding = _private_finding(
            rel,
            text=text,
            marker_present=rel in governed_marker_paths,
        )
        if finding is not None:
            findings.add(finding)
    return sorted(findings)


def _contains_private_key_marker(data: bytes) -> bool:
    private_markers = tuple(marker.encode("ascii") for marker in _private_key_markers())
    return any(marker in data for marker in private_markers)


def _history_object_bytes(root: Path, object_id: str) -> bytes | None:
    try:
        return _run_git(root, "cat-file", "-p", object_id)
    except PublicReleaseScanError:
        return None


def _approved_public_history_key(root: Path, object_id: str, path: str) -> bool:
    if path not in APPROVED_PUBLIC_HISTORY_KEY_PATHS:
        return False
    data = _history_object_bytes(root, object_id)
    if data is None:
        return False
    return not _contains_private_key_marker(data)


def _forbidden_history_path(root: Path, object_id: str, path: str) -> bool:
    name = Path(path).name.lower()
    lowered = path.lower()
    if name == ".env" or name.endswith(".env"):
        return True
    if lowered.startswith("secrets/") or "/secrets/" in lowered:
        return True
    if lowered.startswith("tmp/") or "/tmp/" in lowered:
        return True
    if name.endswith(".pem") or name.endswith(".key"):
        if _approved_public_history_key(root, object_id, path):
            return False
        return True
    return False


def scan_git_history(root: Path) -> list[str]:
    if not (root / ".git").exists():
        return ["git_history_scan_failed"]
    try:
        canonical_root = root.resolve(strict=True)
        _validate_git_identity(canonical_root)
        history_lines = _run_git(
            canonical_root,
            "rev-list",
            "--objects",
            "--all",
        ).decode("utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError, PublicReleaseScanError):
        return ["git_history_scan_failed"]
    findings: list[str] = []
    for line in history_lines:
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        object_id, path = parts
        if _forbidden_history_path(root, object_id, path):
            findings.append(f"git_history_secret_path:{path}")
    return sorted(set(findings))


def scan_demo_outputs(root: Path) -> list[str]:
    findings: list[str] = []
    out_dir = root / "demos" / "edgeguard" / "out"
    if not out_dir.exists():
        return findings
    for path in iter_files(out_dir):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        lowered = text.lower()
        for term in FORBIDDEN_DEMO_TERMS:
            if term in lowered:
                findings.append(f"demo_sensitive_term:{path.relative_to(root).as_posix()}:{term}")
    return findings


def _rm_rf_targets(line: str) -> list[str]:
    marker = "rm " + "-rf"
    if marker not in line:
        return []
    after = line.split(marker, 1)[1]
    targets: list[str] = []
    for raw in after.split():
        target = raw.strip().strip("\"'`,)")
        if not target or target.startswith("-"):
            continue
        if target in {"&&", "||", "|"}:
            break
        targets.append(target)
    return targets


def _bounded_rm_rf_target(target: str) -> bool:
    if target in APPROVED_BOUNDED_RM_RF_TARGETS:
        return True
    return target.startswith("/tmp/usbay_") or target.startswith("/private/tmp/usbay_")


def _safe_rm_rf_context(path: Path, line: str) -> bool:
    rel_parts = path.parts
    if NON_EXECUTING_RM_RF_CONTEXT_RE.search(line) and not EXECUTING_RM_RF_CONTEXT_RE.search(line):
        return True
    targets = _rm_rf_targets(line)
    if targets and all(_bounded_rm_rf_target(target) for target in targets):
        return True
    if rel_parts and rel_parts[0] == "tests" and not EXECUTING_RM_RF_CONTEXT_RE.search(line):
        return True
    return False


def scan_unsafe_shell(root: Path) -> list[str]:
    findings: list[str] = []
    for path in iter_files(root):
        if path.suffix not in {".sh", ".py", ".md"} and path.name not in {"Dockerfile"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        unsafe_delete = "rm " + "-rf"
        for line_no, line in enumerate(text.splitlines(), start=1):
            if unsafe_delete in line and not _safe_rm_rf_context(path.relative_to(root), line):
                findings.append(f"unsafe_rm_rf:{path.relative_to(root).as_posix()}:{line_no}")
            if TASK_MARKERS_RE.search(line) and UNSAFE_LANGUAGE_RE.search(line):
                findings.append(f"security_unsafe_todo:{path.relative_to(root).as_posix()}:{line_no}")
    return findings


def run_tests(root: Path) -> list[str]:
    if os.getenv("USBAY_PUBLIC_RELEASE_SKIP_TESTS") == "1":
        return []
    env = _git_environment()
    env["PYTHONPYCACHEPREFIX"] = "/tmp/usbay-pycache"
    env["PYTHONPATH"] = str(root)
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return [] if result.returncode == 0 else ["tests_failed"]


def run_checks(root: Path = REPO_ROOT, include_tests: bool = True) -> list[str]:
    findings: list[str] = []
    findings.extend(scan_private_keys(root))
    findings.extend(scan_git_history(root))
    findings.extend(scan_demo_outputs(root))
    findings.extend(scan_unsafe_shell(root))
    if include_tests:
        findings.extend(run_tests(root))
    return findings


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else REPO_ROOT
    findings = run_checks(root)
    if findings:
        print("PUBLIC_RELEASE_INVALID")
        for finding in findings:
            print(finding, file=sys.stderr)
        return 1
    print("PUBLIC_RELEASE_VALID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
