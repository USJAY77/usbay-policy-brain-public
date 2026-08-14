#!/usr/bin/env python3
from __future__ import annotations

import os
import re
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


def scan_private_keys(root: Path) -> list[str]:
    findings: list[str] = []
    for path in iter_files(root):
        rel = path.relative_to(root).as_posix()
        if path.name == ".env" or path.suffix == ".env":
            findings.append(f"env_file:{rel}")
            continue
        if path.suffix.lower() == ".pem" and rel not in APPROVED_PUBLIC_PEM_PATHS:
            findings.append(f"unapproved_pem_file:{rel}")
            continue
        if path.suffix.lower() in {".key", ".pem"} or PRIVATE_NAME_RE.search(path.name):
            if is_public_key_file(path):
                continue
            findings.append(f"private_key_file:{rel}")
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        private_markers = (
            "BEGIN " + "PRIVATE KEY",
            "BEGIN RSA " + "PRIVATE KEY",
            "BEGIN OPENSSH " + "PRIVATE KEY",
        )
        if any(marker in text for marker in private_markers):
            findings.append(f"private_key_material:{rel}")
    return findings


def _contains_private_key_marker(data: bytes) -> bool:
    private_markers = (
        b"BEGIN " + b"PRIVATE KEY",
        b"BEGIN RSA " + b"PRIVATE KEY",
        b"BEGIN OPENSSH " + b"PRIVATE KEY",
    )
    return any(marker in data for marker in private_markers)


def _history_object_bytes(root: Path, object_id: str) -> bytes | None:
    result = subprocess.run(
        ["git", "cat-file", "-p", object_id],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout


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
        return []
    try:
        result = subprocess.run(
            ["git", "rev-list", "--objects", "--all"],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
        )
    except Exception:
        return ["git_history_scan_failed"]
    if result.returncode != 0:
        return ["git_history_scan_failed"]
    findings: list[str] = []
    for line in result.stdout.splitlines():
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
    env = os.environ.copy()
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
