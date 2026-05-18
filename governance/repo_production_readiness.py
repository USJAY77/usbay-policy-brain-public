"""Local-only repository-to-production readiness scanner for USBAY governance.

This scanner inspects repository metadata only. It never clones external
repositories, executes repository code, emits raw payloads, or logs secrets.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_READINESS_SCHEMA = "usbay.governance_repo_production_readiness.v1"
REPO_READINESS_ERROR_REGISTRY_PATH = Path("governance/repo_production_readiness_errors.json")
REPO_READINESS_ERROR_SCHEMA = "usbay.governance_repo_production_readiness_error_registry.v1"
REPO_READINESS_POLICY_VERSION = "repo-production-readiness.v1"
REPO_READINESS_ERROR_CODES = (
    "UNTRUSTED_REPO_SOURCE",
    "MISSING_LICENSE",
    "COMMERCIAL_USE_UNCLEAR",
    "WORKFLOW_PERMISSION_WIDENING",
    "UNPINNED_ACTION_VERSION",
    "SECRET_PATTERN_DETECTED",
    "ENV_FILE_PRESENT_BLOCKED",
    "TEST_SIGNAL_MISSING",
    "PRODUCTION_READINESS_MISSING",
    "AUDIT_EVIDENCE_MISSING",
    "RUNTIME_PARITY_MISSING",
    "BRANCH_PROTECTION_UNKNOWN",
    "DEPENDENCY_LINEAGE_UNCLEAR",
    "HUMAN_REVIEW_REQUIRED",
    "REPO_READY_WITH_GOVERNANCE",
)
REPO_PRODUCTION_READY = "REPO_PRODUCTION_READY"
REPO_REVIEW_REQUIRED = "REPO_REVIEW_REQUIRED"
REPO_BLOCKED = "REPO_BLOCKED"
REPO_UNKNOWN = "REPO_UNKNOWN"
MODULE_VERSIONS = {"repo_production_readiness": REPO_READINESS_SCHEMA}

DEPENDENCY_MANIFESTS = {
    "requirements.txt",
    "requirements-ci.txt",
    "pyproject.toml",
    "poetry.lock",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
}
LOCK_OR_HASH_FILES = {
    "requirements-ci.txt",
    "poetry.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "go.sum",
    "Cargo.lock",
}
LICENSE_FILES = ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "NOTICE")
COMMERCIAL_LICENSE_MARKERS = ("MIT", "Apache License", "BSD", "ISC License", "MPL")
ENV_FILENAMES = {".env", ".env.local", ".env.production", ".envrc"}
SECRET_RE = re.compile(
    r"(?:api[_-]?key|secret|token|password|private[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{12,}",
    re.IGNORECASE,
)
ACTION_USES_RE = re.compile(r"uses:\s*([^@\s]+)@([^\s#]+)")
PINNED_ACTION_REF_RE = re.compile(r"^[0-9a-f]{40}$|^v?\d+(?:\.\d+){1,2}$", re.IGNORECASE)
SAFE_SCAN_SUFFIXES = {".py", ".json", ".yml", ".yaml", ".toml", ".txt", ".md", ".ini", ".cfg"}
EXCLUDED_DIRS = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules", ".venv"}
FORBIDDEN_OUTPUT_MARKERS = (
    "PRIVATE KEY",
    "BEGIN RSA",
    "BEGIN OPENSSH",
    "raw_payload",
    "approval_contents",
    "password",
    "secret=",
    "token=",
)


class RepoProductionReadinessError(RuntimeError):
    pass


@dataclass(frozen=True)
class RepoReadinessResult:
    valid: bool
    verdict: str
    reason_codes: tuple[str, ...]
    audit: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "verdict": self.verdict,
            "reason_codes": list(self.reason_codes),
            "audit": dict(self.audit),
        }


def scan_repo_production_readiness(root: Path, *, timestamp_utc: str | None = None) -> RepoReadinessResult:
    root = root.resolve()
    timestamp = timestamp_utc or _utc_now()
    reason_codes: list[str] = []

    files = tuple(_iter_repo_files(root))
    categories = _categorize_files(files)
    dependency_fingerprints = _fingerprints(root, [path for path in files if path.name in DEPENDENCY_MANIFESTS])
    workflow_files = tuple(path for path in files if len(path.parts) >= 3 and path.parts[0] == ".github" and path.parts[1] == "workflows")
    workflow_fingerprints = _fingerprints(root, workflow_files)

    if not (root / ".git").exists():
        reason_codes.append("UNTRUSTED_REPO_SOURCE")
    if not any((root / name).is_file() for name in LICENSE_FILES):
        reason_codes.append("MISSING_LICENSE")
    elif not _license_commercial_use_clear(root):
        reason_codes.append("COMMERCIAL_USE_UNCLEAR")
    if any(Path(*path.parts).name in ENV_FILENAMES for path in files):
        reason_codes.append("ENV_FILE_PRESENT_BLOCKED")
    if _secret_pattern_detected(root, files):
        reason_codes.append("SECRET_PATTERN_DETECTED")
    workflow_codes = _workflow_reason_codes(root, workflow_files)
    reason_codes.extend(workflow_codes)
    test_signal = _has_test_signal(files)
    production_readiness_signal = _has_production_readiness_signal(files)
    audit_evidence_signal = _has_audit_evidence_signal(files)
    runtime_parity_signal = _has_runtime_parity_signal(files)
    branch_protection_signal = _has_branch_protection_signal(files)
    dependency_lineage_signal = _has_dependency_lineage_signal(root, files)
    maintainer_trust_signal = _has_maintainer_trust_signal(files)
    if not test_signal:
        reason_codes.append("TEST_SIGNAL_MISSING")
    if not production_readiness_signal:
        reason_codes.append("PRODUCTION_READINESS_MISSING")
    if not audit_evidence_signal:
        reason_codes.append("AUDIT_EVIDENCE_MISSING")
    if not runtime_parity_signal:
        reason_codes.append("RUNTIME_PARITY_MISSING")
    if not branch_protection_signal:
        reason_codes.append("BRANCH_PROTECTION_UNKNOWN")
    if not dependency_lineage_signal:
        reason_codes.append("DEPENDENCY_LINEAGE_UNCLEAR")

    unique_codes = tuple(sorted(set(reason_codes)))
    verdict_codes = list(unique_codes)
    verdict = _verdict(unique_codes)
    if verdict == REPO_REVIEW_REQUIRED and "HUMAN_REVIEW_REQUIRED" not in verdict_codes:
        verdict_codes.append("HUMAN_REVIEW_REQUIRED")
    if verdict == REPO_PRODUCTION_READY:
        verdict_codes.append("REPO_READY_WITH_GOVERNANCE")
    reason_tuple = tuple(sorted(set(verdict_codes)))

    audit = {
        "schema": REPO_READINESS_SCHEMA,
        "repo_path_fingerprint": _sha256_hex(str(root).encode("utf-8")),
        "scanned_file_categories": categories,
        "dependency_manifest_fingerprints": dependency_fingerprints,
        "workflow_fingerprints": workflow_fingerprints,
        "classified_signals": {
            "dependency_risk": "PASS" if dependency_lineage_signal else "REVIEW",
            "github_actions_workflow_risk": "BLOCK" if workflow_codes else "PASS",
            "permission_widening_risk": "BLOCK" if "WORKFLOW_PERMISSION_WIDENING" in workflow_codes else "PASS",
            "secret_exposure_risk": "BLOCK" if any(code in reason_tuple for code in ("SECRET_PATTERN_DETECTED", "ENV_FILE_PRESENT_BLOCKED")) else "PASS",
            "test_coverage_signal": "PASS" if test_signal else "REVIEW",
            "production_readiness_signal": "PASS" if production_readiness_signal else "REVIEW",
            "audit_evidence_signal": "PASS" if audit_evidence_signal else "REVIEW",
            "runtime_parity_signal": "PASS" if runtime_parity_signal else "REVIEW",
            "branch_protection_signal": "PASS" if branch_protection_signal else "REVIEW",
            "maintainer_trust_signal": "PASS" if maintainer_trust_signal else "REVIEW",
            "license_commercial_use_signal": "PASS"
            if not any(code in reason_tuple for code in ("MISSING_LICENSE", "COMMERCIAL_USE_UNCLEAR"))
            else "REVIEW",
        },
        "reason_codes": reason_tuple,
        "final_verdict": verdict,
        "policy_version": REPO_READINESS_POLICY_VERSION,
        "policy_hash": _sha256_hex(REPO_READINESS_POLICY_VERSION.encode("utf-8")),
        "timestamp_utc": timestamp,
        "governance_module_versions": dict(MODULE_VERSIONS),
    }
    audit["audit_hash"] = _sha256_hex(_canonical_json(audit).encode("utf-8"))
    assert_repo_readiness_safe(audit)
    return RepoReadinessResult(verdict == REPO_PRODUCTION_READY, verdict, reason_tuple, audit)


def repo_readiness_summary(result: RepoReadinessResult) -> dict[str, Any]:
    payload = {
        "verdict": result.verdict,
        "valid": result.valid,
        "reason_codes": list(result.reason_codes),
        "audit_hash": result.audit["audit_hash"],
        "repo_path_fingerprint": result.audit["repo_path_fingerprint"],
    }
    assert_repo_readiness_safe(payload)
    return payload


def load_repo_readiness_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / REPO_READINESS_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RepoProductionReadinessError("repo_readiness_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != REPO_READINESS_ERROR_SCHEMA:
        raise RepoProductionReadinessError("repo_readiness_error_registry_invalid")
    entries = payload.get("errors")
    if not isinstance(entries, list):
        raise RepoProductionReadinessError("repo_readiness_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise RepoProductionReadinessError("repo_readiness_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(REPO_READINESS_ERROR_CODES) - set(registry))
    if missing:
        raise RepoProductionReadinessError("repo_readiness_error_registry_incomplete:" + ",".join(missing))
    return registry


def explain_repo_readiness(root: Path, code: str) -> dict[str, str]:
    registry = load_repo_readiness_error_registry(root)
    if code not in registry:
        raise RepoProductionReadinessError("repo_readiness_error_unknown:" + code)
    return {"code": code, **registry[code]}


def redacted_repo_readiness_payload(payload: Any) -> Any:
    if isinstance(payload, dict):
        return {str(key): redacted_repo_readiness_payload(value) for key, value in payload.items()}
    if isinstance(payload, list):
        return [redacted_repo_readiness_payload(item) for item in payload]
    if isinstance(payload, tuple):
        return [redacted_repo_readiness_payload(item) for item in payload]
    if isinstance(payload, str) and _contains_forbidden_marker(payload):
        return "[REDACTED]"
    return payload


def assert_repo_readiness_safe(payload: Any) -> None:
    encoded = _canonical_json(redacted_repo_readiness_payload(payload))
    if _contains_forbidden_marker(encoded):
        raise RepoProductionReadinessError("REPO_READINESS_DIAGNOSTICS_UNSAFE")


def _verdict(reason_codes: tuple[str, ...]) -> str:
    if "UNTRUSTED_REPO_SOURCE" in reason_codes:
        return REPO_UNKNOWN
    blocked = {
        "WORKFLOW_PERMISSION_WIDENING",
        "UNPINNED_ACTION_VERSION",
        "SECRET_PATTERN_DETECTED",
        "ENV_FILE_PRESENT_BLOCKED",
    }
    if blocked.intersection(reason_codes):
        return REPO_BLOCKED
    if reason_codes:
        return REPO_REVIEW_REQUIRED
    return REPO_PRODUCTION_READY


def _iter_repo_files(root: Path) -> Iterable[Path]:
    if not root.exists():
        return ()
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in EXCLUDED_DIRS for part in rel.parts):
            continue
        if path.is_file():
            yield rel


def _categorize_files(files: tuple[Path, ...]) -> dict[str, int]:
    categories = {
        "dependency_manifests": 0,
        "workflows": 0,
        "tests": 0,
        "docs": 0,
        "audit_or_evidence": 0,
        "runtime_parity": 0,
        "license": 0,
    }
    for path in files:
        if path.name in DEPENDENCY_MANIFESTS:
            categories["dependency_manifests"] += 1
        if len(path.parts) >= 3 and path.parts[0] == ".github" and path.parts[1] == "workflows":
            categories["workflows"] += 1
        if path.parts and path.parts[0] == "tests":
            categories["tests"] += 1
        if path.parts and path.parts[0] == "docs":
            categories["docs"] += 1
        if path.parts and path.parts[0] in {"audit", "evidence"}:
            categories["audit_or_evidence"] += 1
        if "runtime_parity" in path.name or "runtime-parity" in path.name:
            categories["runtime_parity"] += 1
        if path.name in LICENSE_FILES:
            categories["license"] += 1
    return categories


def _fingerprints(root: Path, paths: Iterable[Path]) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for rel in sorted(paths):
        full = root / rel
        try:
            data = full.read_bytes()
        except OSError:
            continue
        records.append(
            {
                "path_fingerprint": _sha256_hex(str(rel).encode("utf-8")),
                "file_hash": _sha256_hex(data),
                "category": _category_for_path(rel),
            }
        )
    return records


def _category_for_path(path: Path) -> str:
    if path.name in DEPENDENCY_MANIFESTS:
        return "dependency_manifest"
    if len(path.parts) >= 3 and path.parts[0] == ".github" and path.parts[1] == "workflows":
        return "workflow"
    return "metadata"


def _license_commercial_use_clear(root: Path) -> bool:
    for name in LICENSE_FILES:
        path = root / name
        if not path.is_file():
            continue
        text = _safe_read_text(path, max_bytes=16_384)
        if any(marker in text for marker in COMMERCIAL_LICENSE_MARKERS):
            return True
    return False


def _secret_pattern_detected(root: Path, files: tuple[Path, ...]) -> bool:
    for rel in files:
        if rel.name in ENV_FILENAMES or rel.suffix not in SAFE_SCAN_SUFFIXES:
            continue
        text = _safe_read_text(root / rel, max_bytes=128_000)
        if SECRET_RE.search(text):
            return True
    return False


def _workflow_reason_codes(root: Path, workflow_files: tuple[Path, ...]) -> list[str]:
    codes: list[str] = []
    for rel in workflow_files:
        text = _safe_read_text(root / rel, max_bytes=128_000)
        in_permissions_block = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped == "permissions:":
                in_permissions_block = True
                continue
            if in_permissions_block and stripped and not line.startswith((" ", "\t", "-")):
                in_permissions_block = False
            if in_permissions_block and re.search(r":\s*write\b|write-all", stripped):
                codes.append("WORKFLOW_PERMISSION_WIDENING")
            if stripped.startswith("permissions:") and any(term in stripped for term in ("write-all", "contents: write", "id-token: write")):
                codes.append("WORKFLOW_PERMISSION_WIDENING")
            match = ACTION_USES_RE.search(line)
            if match and not PINNED_ACTION_REF_RE.match(match.group(2)):
                codes.append("UNPINNED_ACTION_VERSION")
    return codes


def _has_test_signal(files: tuple[Path, ...]) -> bool:
    return any(path.parts and path.parts[0] == "tests" and path.name.startswith("test_") for path in files)


def _has_production_readiness_signal(files: tuple[Path, ...]) -> bool:
    return any(
        str(path) in {"scripts/verify_production_readiness.py", ".github/workflows/production-readiness.yml"}
        for path in files
    )


def _has_audit_evidence_signal(files: tuple[Path, ...]) -> bool:
    return any(path.parts and path.parts[0] in {"audit", "evidence"} for path in files)


def _has_runtime_parity_signal(files: tuple[Path, ...]) -> bool:
    return any("runtime_parity" in str(path) or "runtime-parity" in str(path) for path in files)


def _has_branch_protection_signal(files: tuple[Path, ...]) -> bool:
    return any("branch-protection" in path.name or str(path) == ".github/CODEOWNERS" for path in files)


def _has_maintainer_trust_signal(files: tuple[Path, ...]) -> bool:
    return any(str(path) in {".github/CODEOWNERS", "SECURITY.md", "MAINTAINERS.md"} for path in files)


def _has_dependency_lineage_signal(root: Path, files: tuple[Path, ...]) -> bool:
    if any(path.name in LOCK_OR_HASH_FILES for path in files):
        return True
    requirements_ci = root / "requirements-ci.txt"
    if requirements_ci.is_file() and "--hash=sha256:" in _safe_read_text(requirements_ci, max_bytes=256_000):
        return True
    return False


def _safe_read_text(path: Path, *, max_bytes: int) -> str:
    try:
        data = path.read_bytes()[:max_bytes]
    except OSError:
        return ""
    return data.decode("utf-8", errors="ignore")


def _contains_forbidden_marker(value: str) -> bool:
    lowered = value.lower()
    return any(marker.lower() in lowered for marker in FORBIDDEN_OUTPUT_MARKERS)


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
