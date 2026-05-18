"""Local-only repository-to-production readiness scanner for USBAY governance.

This scanner inspects repository metadata only. It never clones external
repositories, executes repository code, emits raw payloads, or logs secrets.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_READINESS_SCHEMA = "usbay.governance_repo_production_readiness.v1"
SEMANTIC_WORKFLOW_SCHEMA = "usbay.semantic_workflow.v1"
SEMANTIC_WORKFLOW_PARSER_VERSION = "semantic-workflow-parser.v1"
REPO_READINESS_ERROR_REGISTRY_PATH = Path("governance/repo_production_readiness_errors.json")
REPO_READINESS_ERROR_SCHEMA = "usbay.governance_repo_production_readiness_error_registry.v1"
REPO_READINESS_POLICY_VERSION = "repo-production-readiness.v1"
REPO_READINESS_ERROR_CODES = (
    "UNTRUSTED_REPO_SOURCE",
    "MISSING_LICENSE",
    "COMMERCIAL_USE_UNCLEAR",
    "WORKFLOW_PERMISSION_WIDENING",
    "WORKFLOW_PERMISSION_TOO_BROAD",
    "READ_ALL_PERMISSION_BLOCKED",
    "WRITE_ALL_PERMISSION_BLOCKED",
    "IMPLICIT_PERMISSION_WIDENING",
    "UNNECESSARY_WRITE_SCOPE",
    "LEAST_PRIVILEGE_ENFORCED",
    "WORKFLOW_PERMISSION_SCOPE_APPROVED",
    "WORKFLOW_STRUCTURE_UNKNOWN",
    "YAML_STRUCTURE_UNSAFE",
    "WORKFLOW_CAPABILITY_UNCLEAR",
    "SEMANTIC_WORKFLOW_ANALYSIS_UNAVAILABLE",
    "UNPINNED_ACTION_VERSION",
    "ACTION_NOT_SHA_PINNED",
    "SECRET_PATTERN_DETECTED",
    "SECRET_EXPOSURE_RISK",
    "ENV_FILE_PRESENT_BLOCKED",
    "NPM_LIFECYCLE_SCRIPT_BLOCKED",
    "PIP_HASH_LOCK_MISSING",
    "DEPENDENCY_INSTALL_UNTRUSTED",
    "CI_TOKEN_EXFILTRATION_RISK",
    "ARTIFACT_ATTESTATION_MISSING",
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
KNOWN_WORKFLOW_PERMISSION_SCOPES = {
    "actions",
    "attestations",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "id-token",
    "issues",
    "packages",
    "pages",
    "pull-requests",
    "repository-projects",
    "security-events",
    "statuses",
}


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


@dataclass(frozen=True)
class WorkflowAnalysis:
    reason_codes: tuple[str, ...]
    manifest: dict[str, Any]


@dataclass(frozen=True)
class SemanticWorkflow:
    rel: Path
    parser_version: str
    semantic_schema_version: str
    parser_mode: str
    workflow_fingerprint: str
    text_hash: str
    unsafe_yaml_reason: str | None
    workflow_permissions: Any
    job_blocks: dict[str, list[str]]
    job_permissions: dict[str, Any]
    actions: tuple[str, ...]
    run_commands: tuple[str, ...]
    trigger_names: tuple[str, ...]
    has_workflow_call: bool
    has_matrix: bool
    secret_exposure_candidates: tuple[str, ...]


def scan_repo_production_readiness(root: Path, *, timestamp_utc: str | None = None) -> RepoReadinessResult:
    root = root.resolve()
    timestamp = timestamp_utc or _utc_now()
    reason_codes: list[str] = []

    files = tuple(_iter_repo_files(root))
    categories = _categorize_files(files)
    dependency_fingerprints = _fingerprints(root, [path for path in files if path.name in DEPENDENCY_MANIFESTS])
    workflow_files = tuple(path for path in files if len(path.parts) >= 3 and path.parts[0] == ".github" and path.parts[1] == "workflows")
    workflow_fingerprints = _fingerprints(root, workflow_files)
    workflow_analyses = tuple(_analyze_workflow(root, path) for path in workflow_files)
    workflow_manifests = [analysis.manifest for analysis in workflow_analyses]
    permission_evidence = [
        {
            "workflow_fingerprint": manifest["workflow_fingerprint"],
            "permission_model_fingerprint": manifest["permission_graph"]["permission_model_fingerprint"],
            "detected_scopes": manifest["permission_graph"]["detected_scopes"],
            "blocked_scopes": manifest["permission_graph"]["blocked_scopes"],
            "final_governance_verdict": manifest["permission_graph"]["final_governance_verdict"],
        }
        for manifest in workflow_manifests
    ]

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
    workflow_codes = [code for analysis in workflow_analyses for code in analysis.reason_codes]
    reason_codes.extend(workflow_codes)
    dependency_install_signal = "DEPENDENCY_INSTALL_UNTRUSTED" not in workflow_codes
    artifact_attestation_signal = "ARTIFACT_ATTESTATION_MISSING" not in workflow_codes
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
        "workflow_manifests": workflow_manifests,
        "workflow_permission_evidence": permission_evidence,
        "classified_signals": {
            "dependency_risk": "PASS" if dependency_lineage_signal else "REVIEW",
            "github_actions_workflow_risk": "BLOCK" if workflow_codes else "PASS",
            "permission_widening_risk": "BLOCK" if "WORKFLOW_PERMISSION_WIDENING" in workflow_codes else "PASS",
            "secret_exposure_risk": "BLOCK"
            if any(code in reason_tuple for code in ("SECRET_PATTERN_DETECTED", "SECRET_EXPOSURE_RISK", "ENV_FILE_PRESENT_BLOCKED"))
            else "PASS",
            "dependency_install_signal": "PASS" if dependency_install_signal else "BLOCK",
            "artifact_attestation_signal": "PASS" if artifact_attestation_signal else "REVIEW",
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
    positive_codes = {"LEAST_PRIVILEGE_ENFORCED", "WORKFLOW_PERMISSION_SCOPE_APPROVED"}
    effective_reason_codes = tuple(code for code in reason_codes if code not in positive_codes)
    if "UNTRUSTED_REPO_SOURCE" in effective_reason_codes:
        return REPO_UNKNOWN
    blocked = {
        "WORKFLOW_PERMISSION_WIDENING",
        "WORKFLOW_PERMISSION_TOO_BROAD",
        "READ_ALL_PERMISSION_BLOCKED",
        "WRITE_ALL_PERMISSION_BLOCKED",
        "IMPLICIT_PERMISSION_WIDENING",
        "UNNECESSARY_WRITE_SCOPE",
        "WORKFLOW_STRUCTURE_UNKNOWN",
        "YAML_STRUCTURE_UNSAFE",
        "WORKFLOW_CAPABILITY_UNCLEAR",
        "SEMANTIC_WORKFLOW_ANALYSIS_UNAVAILABLE",
        "UNPINNED_ACTION_VERSION",
        "ACTION_NOT_SHA_PINNED",
        "SECRET_PATTERN_DETECTED",
        "SECRET_EXPOSURE_RISK",
        "ENV_FILE_PRESENT_BLOCKED",
        "NPM_LIFECYCLE_SCRIPT_BLOCKED",
        "DEPENDENCY_INSTALL_UNTRUSTED",
        "CI_TOKEN_EXFILTRATION_RISK",
    }
    if blocked.intersection(effective_reason_codes):
        return REPO_BLOCKED
    if effective_reason_codes:
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
        if _metadata_secret_candidate_detected(text):
            return True
    return False


def _metadata_secret_candidate_detected(text: str) -> bool:
    for line in text.splitlines():
        lowered = line.lower()
        if not any(marker in lowered for marker in ("api_key", "apikey", "secret", "token", "password", "private_key")):
            continue
        if "=" not in line and ":" not in line:
            continue
        value = line.split("=", 1)[-1].split(":", 1)[-1].strip().strip("'\"")
        if len(value) >= 12 and any(char.isalpha() for char in value) and any(char.isdigit() for char in value):
            return True
    return False


def _parse_semantic_workflow(root: Path, rel: Path) -> SemanticWorkflow:
    text = _safe_read_text(root / rel, max_bytes=128_000)
    unsafe_reason = _yaml_structure_unsafe(text)
    job_blocks = _job_blocks(text)
    job_permissions: dict[str, Any] = {}
    for job_id, block in job_blocks.items():
        permissions = _nested_permissions(block)
        if permissions is not None:
            job_permissions[job_id] = permissions
    actions = tuple(_workflow_actions(job_blocks))
    run_commands = tuple(_workflow_run_commands(job_blocks))
    return SemanticWorkflow(
        rel=rel,
        parser_version=SEMANTIC_WORKFLOW_PARSER_VERSION,
        semantic_schema_version=SEMANTIC_WORKFLOW_SCHEMA,
        parser_mode="SEMANTIC",
        workflow_fingerprint=_sha256_hex(str(rel).encode("utf-8")),
        text_hash=_sha256_hex(text.encode("utf-8")),
        unsafe_yaml_reason=unsafe_reason,
        workflow_permissions=_top_level_permissions(text),
        job_blocks=job_blocks,
        job_permissions=job_permissions,
        actions=actions,
        run_commands=run_commands,
        trigger_names=tuple(_workflow_triggers(text)),
        has_workflow_call=_has_workflow_call(text),
        has_matrix=_has_matrix(job_blocks),
        secret_exposure_candidates=tuple(_secret_exposure_candidates(text)),
    )


def _unavailable_workflow_manifest(rel: Path) -> dict[str, Any]:
    manifest = {
        "schema": "usbay.governance_workflow_manifest.v1",
        "parser_version": "UNAVAILABLE",
        "semantic_schema_version": SEMANTIC_WORKFLOW_SCHEMA,
        "parser_mode": "UNAVAILABLE",
        "workflow_fingerprint": _sha256_hex(str(rel).encode("utf-8")),
        "capability_graph": ["UNKNOWN"],
        "permission_graph": {
            "workflow_permissions": [],
            "job_permissions": {},
            "detected_scopes": [],
            "blocked_scopes": ["semantic_parser_unavailable"],
            "permission_model_fingerprint": _sha256_hex(b"semantic_parser_unavailable"),
            "final_governance_verdict": "BLOCK",
        },
        "mutation_intent": [],
        "sha_pinning_status": "BLOCK",
    }
    manifest["workflow_manifest_hash"] = _sha256_hex(_canonical_json(manifest).encode("utf-8"))
    manifest["capability_graph_hash"] = _sha256_hex(_canonical_json(manifest["capability_graph"]).encode("utf-8"))
    manifest["audit_hash"] = _sha256_hex(_canonical_json(manifest).encode("utf-8"))
    return manifest


def _analyze_workflow(root: Path, rel: Path) -> WorkflowAnalysis:
    codes: list[str] = []
    try:
        semantic = _parse_semantic_workflow(root, rel)
    except Exception:
        semantic = None
    if semantic is None:
        manifest = _unavailable_workflow_manifest(rel)
        return WorkflowAnalysis(("SEMANTIC_WORKFLOW_ANALYSIS_UNAVAILABLE", "WORKFLOW_CAPABILITY_UNCLEAR"), manifest)

    if semantic.unsafe_yaml_reason:
        codes.append(semantic.unsafe_yaml_reason)
    workflow_permissions, permission_codes = _permission_model_for_block(rel, semantic.workflow_permissions)
    codes.extend(permission_codes)
    job_permissions: dict[str, list[str]] = {}
    blocked_scopes = list(workflow_permissions["blocked_scopes"])
    detected_scopes = list(workflow_permissions["detected_scopes"])
    for job_id, nested_permissions in semantic.job_permissions.items():
        if nested_permissions is None:
            continue
        job_model, job_codes = _permission_model_for_block(rel, nested_permissions)
        codes.extend(job_codes)
        if job_model["detected_scopes"]:
            job_permissions[job_id] = job_model["detected_scopes"]
            detected_scopes.extend(job_model["detected_scopes"])
            blocked_scopes.extend(job_model["blocked_scopes"])

    for action in semantic.actions:
        if _is_reusable_workflow(action):
            codes.append("WORKFLOW_STRUCTURE_UNKNOWN")
        if "@" not in action:
            codes.extend(("UNPINNED_ACTION_VERSION", "ACTION_NOT_SHA_PINNED"))
            continue
        ref = action.rsplit("@", 1)[1]
        if not _is_full_commit_sha(ref):
            codes.extend(("UNPINNED_ACTION_VERSION", "ACTION_NOT_SHA_PINNED"))

    mutation_intent = _mutation_intent(semantic, detected_scopes)
    capability_graph = _capability_graph(semantic, detected_scopes, mutation_intent)
    if "UNKNOWN" in capability_graph:
        codes.append("WORKFLOW_CAPABILITY_UNCLEAR")
    workflow_has_dependency_install, dependency_codes = _dependency_install_codes(semantic)
    codes.extend(dependency_codes)
    if _risky_trigger(semantic) and any(scope.endswith(":write") for scope in detected_scopes) and workflow_has_dependency_install:
        codes.append("CI_TOKEN_EXFILTRATION_RISK")
    if _workflow_uploads_artifact(semantic) and not _workflow_attests_artifact(semantic) and not _workflow_has_hash_evidence(semantic):
        codes.append("ARTIFACT_ATTESTATION_MISSING")
    if semantic.secret_exposure_candidates:
        codes.append("SECRET_EXPOSURE_RISK")
    unique_codes = tuple(sorted(set(codes)))
    permission_graph = {
        "workflow_permissions": workflow_permissions["detected_scopes"],
        "job_permissions": job_permissions,
        "detected_scopes": sorted(set(detected_scopes)),
        "blocked_scopes": sorted(set(blocked_scopes)),
        "permission_model_fingerprint": _sha256_hex(
            _canonical_json({"detected_scopes": sorted(set(detected_scopes)), "blocked_scopes": sorted(set(blocked_scopes))}).encode("utf-8")
        ),
        "final_governance_verdict": "PASS" if not blocked_scopes and not any(code in unique_codes for code in ("IMPLICIT_PERMISSION_WIDENING", "READ_ALL_PERMISSION_BLOCKED", "WRITE_ALL_PERMISSION_BLOCKED")) else "BLOCK",
    }
    if permission_graph["final_governance_verdict"] == "PASS" and not any(code in unique_codes for code in ("YAML_STRUCTURE_UNSAFE", "WORKFLOW_STRUCTURE_UNKNOWN")):
        unique_codes = tuple(sorted(set(unique_codes + ("LEAST_PRIVILEGE_ENFORCED", "WORKFLOW_PERMISSION_SCOPE_APPROVED"))))
    manifest = {
        "schema": "usbay.governance_workflow_manifest.v1",
        "parser_version": semantic.parser_version,
        "semantic_schema_version": semantic.semantic_schema_version,
        "parser_mode": semantic.parser_mode,
        "workflow_fingerprint": semantic.workflow_fingerprint,
        "capability_graph": sorted(set(capability_graph)),
        "permission_graph": permission_graph,
        "mutation_intent": sorted(set(mutation_intent)),
        "sha_pinning_status": "PASS" if not any(code in unique_codes for code in ("ACTION_NOT_SHA_PINNED", "UNPINNED_ACTION_VERSION")) else "BLOCK",
    }
    manifest["workflow_manifest_hash"] = _sha256_hex(_canonical_json({key: value for key, value in manifest.items() if key != "workflow_manifest_hash"}).encode("utf-8"))
    manifest["capability_graph_hash"] = _sha256_hex(_canonical_json(manifest["capability_graph"]).encode("utf-8"))
    manifest["audit_hash"] = _sha256_hex(_canonical_json(manifest).encode("utf-8"))
    return WorkflowAnalysis(unique_codes, manifest)


def _permission_model_for_block(rel: Path, permissions: Any) -> tuple[dict[str, Any], list[str]]:
    detected_scopes: list[str] = []
    blocked_scopes: list[str] = []
    codes: list[str] = []
    if permissions is None:
        return {"detected_scopes": [], "blocked_scopes": ["implicit_default_permissions"]}, ["IMPLICIT_PERMISSION_WIDENING"]
    if isinstance(permissions, str):
        if permissions == "write-all":
            return {"detected_scopes": ["write-all"], "blocked_scopes": ["write-all"]}, [
                "WRITE_ALL_PERMISSION_BLOCKED",
                "WORKFLOW_PERMISSION_TOO_BROAD",
                "WORKFLOW_PERMISSION_WIDENING",
            ]
        if permissions == "read-all":
            return {"detected_scopes": ["read-all"], "blocked_scopes": ["read-all"]}, [
                "READ_ALL_PERMISSION_BLOCKED",
                "WORKFLOW_PERMISSION_TOO_BROAD",
            ]
        return {"detected_scopes": [permissions], "blocked_scopes": [permissions]}, ["WORKFLOW_STRUCTURE_UNKNOWN"]
    if not isinstance(permissions, dict):
        return {"detected_scopes": [], "blocked_scopes": ["unknown_permissions"]}, ["WORKFLOW_STRUCTURE_UNKNOWN"]
    if not permissions:
        return {"detected_scopes": [], "blocked_scopes": ["empty_permissions"]}, ["WORKFLOW_STRUCTURE_UNKNOWN"]
    for scope, access in permissions.items():
        scope_text = str(scope).strip()
        access_text = str(access).strip()
        detected_scopes.append(f"{scope_text}:{access_text}")
        if scope_text not in KNOWN_WORKFLOW_PERMISSION_SCOPES:
            blocked_scopes.append(f"{scope_text}:{access_text}")
            codes.append("WORKFLOW_STRUCTURE_UNKNOWN")
        if access_text == "write" and not _write_scope_allowed(rel, scope_text):
            blocked_scopes.append(f"{scope_text}:{access_text}")
            codes.extend(("UNNECESSARY_WRITE_SCOPE", "WORKFLOW_PERMISSION_WIDENING"))
        if access_text not in {"read", "write", "none"}:
            blocked_scopes.append(f"{scope_text}:{access_text}")
            codes.append("WORKFLOW_STRUCTURE_UNKNOWN")
    return {"detected_scopes": sorted(set(detected_scopes)), "blocked_scopes": sorted(set(blocked_scopes))}, sorted(set(codes))


def _yaml_structure_unsafe(text: str) -> str | None:
    for line in text.splitlines():
        stripped = _strip_comment(line).strip()
        if not stripped:
            continue
        if "\t" in line:
            return "YAML_STRUCTURE_UNSAFE"
        if stripped.startswith("<<:") or " &" in stripped or ": &" in stripped or stripped.startswith("*") or ": *" in stripped:
            return "YAML_STRUCTURE_UNSAFE"
        if stripped.startswith("permissions:") and stripped.split(":", 1)[1].strip() in {"|", ">"}:
            return "YAML_STRUCTURE_UNSAFE"
    if "jobs:" not in text:
        return "WORKFLOW_STRUCTURE_UNKNOWN"
    return None


def _top_level_permissions(text: str) -> Any:
    return _permissions_at_indent(text.splitlines(), 0)


def _nested_permissions(block: list[str]) -> Any:
    base_indent = min((_indent(line) for line in block if line.strip()), default=0)
    return _permissions_at_indent(block, base_indent + 2)


def _permissions_at_indent(lines: list[str], parent_indent: int) -> Any:
    for index, line in enumerate(lines):
        clean = _strip_comment(line)
        stripped = clean.strip()
        if not stripped:
            continue
        indent = _indent(line)
        if indent != parent_indent or not stripped.startswith("permissions:"):
            continue
        value = stripped.split(":", 1)[1].strip()
        if value:
            return _unquote(value)
        return _mapping_children(lines, index, indent)
    return None


def _mapping_children(lines: list[str], start_index: int, parent_indent: int) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for line in lines[start_index + 1 :]:
        clean = _strip_comment(line)
        stripped = clean.strip()
        if not stripped:
            continue
        indent = _indent(line)
        if indent <= parent_indent:
            break
        if ":" not in stripped or stripped.startswith("-"):
            continue
        key, value = stripped.split(":", 1)
        mapping[_unquote(key.strip())] = _unquote(value.strip())
    return mapping


def _job_blocks(text: str) -> dict[str, list[str]]:
    lines = text.splitlines()
    jobs_index = None
    jobs_indent = 0
    for index, line in enumerate(lines):
        stripped = _strip_comment(line).strip()
        if stripped == "jobs:":
            jobs_index = index
            jobs_indent = _indent(line)
            break
    if jobs_index is None:
        return {}
    blocks: dict[str, list[str]] = {}
    current_job: str | None = None
    current_lines: list[str] = []
    current_indent = 0
    for line in lines[jobs_index + 1 :]:
        stripped = _strip_comment(line).strip()
        if not stripped:
            if current_job is not None:
                current_lines.append(line)
            continue
        indent = _indent(line)
        if indent <= jobs_indent:
            break
        if indent == jobs_indent + 2 and stripped.endswith(":") and not stripped.startswith("-"):
            if current_job is not None:
                blocks[current_job] = current_lines
            current_job = stripped[:-1].strip()
            current_lines = [line]
            current_indent = indent
            continue
        if current_job is not None and indent > current_indent:
            current_lines.append(line)
    if current_job is not None:
        blocks[current_job] = current_lines
    return blocks


def _workflow_actions(job_blocks: dict[str, list[str]]) -> list[str]:
    actions: list[str] = []
    for block in job_blocks.values():
        for line in block:
            stripped = _strip_comment(line).strip()
            if stripped.startswith("- uses:"):
                actions.append(_unquote(stripped.split(":", 1)[1].strip()))
            elif stripped.startswith("uses:"):
                actions.append(_unquote(stripped.split(":", 1)[1].strip()))
    return actions


def _workflow_run_commands(job_blocks: dict[str, list[str]]) -> list[str]:
    commands: list[str] = []
    capturing_multiline = False
    multiline_indent = 0
    for block in job_blocks.values():
        for line in block:
            clean = _strip_comment(line)
            stripped = clean.strip()
            indent = _indent(line)
            if capturing_multiline and indent > multiline_indent:
                commands.append(stripped)
                continue
            capturing_multiline = False
            if stripped.startswith("- run:") or stripped.startswith("run:"):
                value = _unquote(stripped.split(":", 1)[1].strip())
                if value in {"|", ">"}:
                    capturing_multiline = True
                    multiline_indent = indent
                    continue
                commands.append(value)
    return commands


def _workflow_triggers(text: str) -> list[str]:
    triggers: list[str] = []
    in_on_block = False
    on_indent = 0
    for line in text.splitlines():
        stripped = _strip_comment(line).strip()
        if not stripped:
            continue
        indent = _indent(line)
        if stripped == "on:":
            in_on_block = True
            on_indent = indent
            continue
        if stripped.startswith("on:") and stripped != "on:":
            value = _unquote(stripped.split(":", 1)[1].strip())
            if value.startswith("[") and value.endswith("]"):
                triggers.extend(_unquote(item.strip()) for item in value[1:-1].split(",") if item.strip())
            elif value:
                triggers.append(value)
            continue
        if in_on_block:
            if indent <= on_indent:
                in_on_block = False
                continue
            if indent == on_indent + 2 and ":" in stripped:
                triggers.append(_unquote(stripped.split(":", 1)[0].strip()))
    return sorted(set(triggers))


def _has_workflow_call(text: str) -> bool:
    return "workflow_call" in _workflow_triggers(text)


def _has_matrix(job_blocks: dict[str, list[str]]) -> bool:
    for block in job_blocks.values():
        if any(_strip_comment(line).strip().startswith("matrix:") for line in block):
            return True
    return False


def _secret_exposure_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    for line in text.splitlines():
        lowered = _strip_comment(line).strip().lower()
        if not lowered:
            continue
        if any(marker in lowered for marker in ("github_token", "github.token", "secrets.", ".env")):
            candidates.append(_sha256_hex(lowered.encode("utf-8")))
        elif "bearer " in lowered:
            candidates.append(_sha256_hex(b"bearer-token-reference"))
    return sorted(set(candidates))


def _is_reusable_workflow(action: str) -> bool:
    return action.endswith(".yml") or action.endswith(".yaml") or "/.github/workflows/" in action


def _is_full_commit_sha(value: str) -> bool:
    return len(value) == 40 and all(char in "0123456789abcdefABCDEF" for char in value)


def _dependency_install_codes(semantic: SemanticWorkflow) -> tuple[bool, list[str]]:
    codes: list[str] = []
    has_dependency_install = False
    for command in semantic.run_commands:
        command_tokens = command.split()
        if _is_npm_install_command(command_tokens):
            has_dependency_install = True
            if "--ignore-scripts" not in command_tokens:
                codes.extend(("NPM_LIFECYCLE_SCRIPT_BLOCKED", "DEPENDENCY_INSTALL_UNTRUSTED"))
        if _is_pip_install_command(command_tokens):
            has_dependency_install = True
            if "--require-hashes" not in command_tokens:
                codes.extend(("PIP_HASH_LOCK_MISSING", "DEPENDENCY_INSTALL_UNTRUSTED"))
    return has_dependency_install, sorted(set(codes))


def _is_npm_install_command(tokens: list[str]) -> bool:
    return len(tokens) >= 2 and tokens[0] == "npm" and tokens[1] in {"install", "i", "ci"}


def _is_pip_install_command(tokens: list[str]) -> bool:
    if len(tokens) >= 2 and tokens[0] in {"pip", "pip3"} and tokens[1] == "install":
        return True
    return len(tokens) >= 5 and tokens[0] in {"python", "python3"} and tokens[1:4] == ["-m", "pip", "install"]


def _risky_trigger(semantic: SemanticWorkflow) -> bool:
    return any(trigger in {"pull_request", "workflow_run"} for trigger in semantic.trigger_names)


def _workflow_uploads_artifact(semantic: SemanticWorkflow) -> bool:
    return any(action.startswith("actions/upload-artifact@") for action in semantic.actions)


def _workflow_attests_artifact(semantic: SemanticWorkflow) -> bool:
    return any(action.startswith("actions/attest-build-provenance@") for action in semantic.actions) or "attestation" in semantic.rel.name


def _workflow_has_hash_evidence(semantic: SemanticWorkflow) -> bool:
    return any("sha256" in command.lower() or "hash" in command.lower() for command in semantic.run_commands)


def _mutation_intent(semantic: SemanticWorkflow, scopes: list[str]) -> list[str]:
    intents: list[str] = []
    if any(scope in scopes for scope in ("pull-requests:write",)):
        intents.append("modifies_prs")
    if any(scope in scopes for scope in ("issues:write",)):
        intents.append("writes_comments_or_issues")
    if any(scope in scopes for scope in ("contents:write",)):
        intents.extend(("pushes_commits", "mutates_branches_or_tags"))
    if any(scope in scopes for scope in ("attestations:write",)):
        intents.append("uploads_attestations")
    for command in semantic.run_commands:
        lowered = command.lower()
        if "gh pr" in lowered or "pr comment" in lowered:
            intents.append("modifies_prs")
        if "git push" in lowered:
            intents.extend(("pushes_commits", "mutates_branches_or_tags"))
        if "gh release" in lowered:
            intents.append("creates_releases")
    if "releases:write" in scopes:
        intents.append("creates_releases")
    if _workflow_uploads_artifact(semantic):
        intents.append("uploads_artifacts")
    if "branch" in semantic.rel.name and "contents:write" in scopes:
        intents.append("mutates_branches_or_tags")
    return sorted(set(intents))


def _capability_graph(semantic: SemanticWorkflow, scopes: list[str], mutation_intent: list[str]) -> list[str]:
    if semantic.unsafe_yaml_reason:
        return ["UNKNOWN"]
    lowered = str(semantic.rel).lower()
    command_text = "\n".join(semantic.run_commands).lower()
    capabilities = ["MUTATING" if mutation_intent or any(scope.endswith(":write") for scope in scopes) else "READ_ONLY"]
    if any(term in lowered or term in command_text for term in ("deploy", "deployment", "environment:", "release")):
        capabilities.append("DEPLOYMENT")
    if any(term in lowered for term in ("governance", "policy", "audit", "production-readiness")):
        capabilities.append("GOVERNANCE")
    if semantic.has_workflow_call or semantic.has_matrix:
        capabilities.append("GOVERNANCE")
    if any("attest" in action for action in semantic.actions) or "attestation" in lowered:
        capabilities.append("ATTESTATION")
    return sorted(set(capabilities))


def _strip_comment(line: str) -> str:
    in_single = False
    in_double = False
    for index, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            return line[:index]
    return line


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _write_scope_allowed(rel: Path, scope: str) -> bool:
    path = str(rel)
    allowed_by_workflow = {
        ".github/workflows/dependabot-governed-automerge.yml": {"contents", "issues", "pull-requests"},
        ".github/workflows/governed-branch-hygiene.yml": {"contents", "issues", "pull-requests"},
        ".github/workflows/governance-export-attestation.yml": {"id-token", "attestations"},
        ".github/workflows/codeql.yml": {"security-events"},
    }
    return scope in allowed_by_workflow.get(path, set())


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
