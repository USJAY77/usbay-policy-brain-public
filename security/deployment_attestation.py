from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security.node_identity import (
    DEFAULT_NODE_ATTESTATION_POLICY_PATH,
    load_node_attestation_policy,
)
from security.tenant_context import DEFAULT_TENANT_POLICY_PATH, validate_tenant_id


class DeploymentAttestationError(RuntimeError):
    pass


DEFAULT_GOVERNANCE_RELEASE_PATH = Path("governance_release.json")
DEFAULT_POLICY_REGISTRY_PATH = Path("governance/policy_registry.json")
DEFAULT_POLICY_SIGNATURE_PATH = Path("governance/policy_registry.sig")
DEFAULT_POLICY_RELEASE_MANIFEST_PATH = Path("governance/policy_release_manifest.json")
POLICY_BUNDLE_FILES = (
    DEFAULT_POLICY_REGISTRY_PATH,
    DEFAULT_POLICY_SIGNATURE_PATH,
    DEFAULT_POLICY_RELEASE_MANIFEST_PATH,
    DEFAULT_NODE_ATTESTATION_POLICY_PATH,
    DEFAULT_TENANT_POLICY_PATH,
)
SIGNATURE_PREFIX = "hmac-sha256:"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def file_sha256(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except Exception as exc:
        raise DeploymentAttestationError("policy_bundle_artifact_missing") from exc


def policy_bundle_hash(paths: tuple[Path, ...] = POLICY_BUNDLE_FILES) -> str:
    artifacts = {path.as_posix(): file_sha256(path) for path in paths}
    return sha256_text(canonical_json(artifacts))


def current_git_commit() -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parents[1],
            text=True,
            capture_output=True,
            check=True,
        )
    except Exception as exc:
        raise DeploymentAttestationError("git_commit_unavailable") from exc
    commit = completed.stdout.strip()
    if len(commit) != 40:
        raise DeploymentAttestationError("git_commit_unavailable")
    return commit


def environment_mode() -> str:
    raw = os.getenv("USBAY_ENV", os.getenv("USBAY_ENVIRONMENT", "test")).strip().lower()
    return "production" if raw in {"prod", "production"} else "test"


def github_actions_ci() -> bool:
    return (
        os.getenv("GITHUB_ACTIONS", "").lower() == "true"
        and bool(os.getenv("GITHUB_SHA", "").strip())
        and bool(os.getenv("GITHUB_REPOSITORY", "").strip())
    )


def _git_ancestor(candidate: str, descendant: str) -> bool:
    if candidate == descendant:
        return True
    try:
        completed = subprocess.run(
            ["git", "merge-base", "--is-ancestor", candidate, descendant],
            cwd=Path(__file__).resolve().parents[1],
            text=True,
            capture_output=True,
            check=False,
        )
    except Exception:
        return False
    return completed.returncode == 0


def _git_parents(commit: str) -> set[str]:
    try:
        completed = subprocess.run(
            ["git", "rev-list", "--parents", "-n", "1", commit],
            cwd=Path(__file__).resolve().parents[1],
            text=True,
            capture_output=True,
            check=True,
        )
    except Exception:
        return set()
    parts = completed.stdout.strip().split()
    return set(parts[1:])


def _ci_commit_candidates(expected_commit: str) -> set[str]:
    candidates = {expected_commit}
    for name in ("GITHUB_SHA", "GITHUB_HEAD_SHA", "GITHUB_BASE_SHA"):
        value = os.getenv(name, "").strip()
        if len(value) == 40:
            candidates.add(value)
    candidates.update(_git_parents(expected_commit))
    return candidates


def commit_continuity_valid(release_commit: str, expected_commit: str) -> bool:
    if release_commit == expected_commit:
        return True
    if environment_mode() == "production" or not github_actions_ci():
        return False
    if release_commit in _ci_commit_candidates(expected_commit):
        return True
    if _git_ancestor(release_commit, expected_commit):
        return True
    github_sha = os.getenv("GITHUB_SHA", "").strip()
    if len(github_sha) == 40 and _git_ancestor(release_commit, github_sha):
        return True
    return False


def _signing_material() -> str:
    return os.getenv("USBAY_DEPLOYMENT_SIGNING_MATERIAL", "usbay-local-deployment-signing-material-v1")


def signature_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    payload = dict(manifest)
    payload.pop("release_signature", None)
    return payload


def release_hash(manifest: dict[str, Any]) -> str:
    return sha256_text(canonical_json(signature_payload(manifest)))


def sign_release_manifest(manifest: dict[str, Any], signing_material: str | None = None) -> str:
    digest = hmac.new(
        (signing_material or _signing_material()).encode("utf-8"),
        canonical_json(signature_payload(manifest)).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{SIGNATURE_PREFIX}{digest}"


def verify_release_signature(manifest: dict[str, Any]) -> bool:
    signature = manifest.get("release_signature")
    if not isinstance(signature, str) or not signature.startswith(SIGNATURE_PREFIX):
        return False
    expected = sign_release_manifest(manifest)
    return hmac.compare_digest(signature, expected)


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception as exc:
        raise DeploymentAttestationError("deployment_timestamp_invalid") from exc
    if parsed.tzinfo is None:
        raise DeploymentAttestationError("deployment_timestamp_invalid")
    return parsed.astimezone(timezone.utc)


def _enrolled_node_ids(policy_path: Path | str = DEFAULT_NODE_ATTESTATION_POLICY_PATH) -> set[str]:
    policy = load_node_attestation_policy(policy_path)
    return {
        str(entry["node_id"])
        for entry in policy["enrolled_nodes"].values()
        if isinstance(entry, dict) and entry.get("node_id")
    }


def _load_manifest(path: Path | str) -> dict[str, Any]:
    try:
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise DeploymentAttestationError("release_manifest_missing") from exc
    if not isinstance(manifest, dict):
        raise DeploymentAttestationError("release_manifest_invalid")
    return manifest


def load_release_manifest(path: Path | str = DEFAULT_GOVERNANCE_RELEASE_PATH) -> dict[str, Any]:
    return _load_manifest(path)


def validate_release_manifest(
    path: Path | str = DEFAULT_GOVERNANCE_RELEASE_PATH,
    *,
    expected_git_commit: str | None = None,
    expected_policy_bundle_hash: str | None = None,
    expected_tenant_id: str | None = None,
    node_policy_path: Path | str = DEFAULT_NODE_ATTESTATION_POLICY_PATH,
    now: datetime | None = None,
) -> dict[str, Any]:
    manifest = _load_manifest(path)
    required = {
        "release_id",
        "git_commit",
        "policy_bundle_hash",
        "deployment_timestamp",
        "activating_node_id",
        "tenant_id",
        "release_signature",
        "previous_release_hash",
    }
    if any(manifest.get(field) in (None, "") for field in required):
        raise DeploymentAttestationError("release_manifest_invalid")
    if not verify_release_signature(manifest):
        raise DeploymentAttestationError("release_signature_invalid")
    expected_bundle = expected_policy_bundle_hash or policy_bundle_hash()
    if manifest.get("policy_bundle_hash") != expected_bundle:
        raise DeploymentAttestationError("policy_bundle_hash_mismatch")
    expected_commit = expected_git_commit or current_git_commit()
    if not commit_continuity_valid(str(manifest.get("git_commit", "")), expected_commit):
        raise DeploymentAttestationError("git_commit_mismatch")
    if manifest.get("activating_node_id") not in _enrolled_node_ids(node_policy_path):
        raise DeploymentAttestationError("activating_node_unknown")
    tenant_id = validate_tenant_id(manifest.get("tenant_id"))
    if expected_tenant_id is not None and tenant_id != expected_tenant_id:
        raise DeploymentAttestationError("tenant_deployment_provenance_mismatch")
    deployment_time = _parse_utc(str(manifest.get("deployment_timestamp", "")))
    current_time = now or datetime.now(timezone.utc)
    if deployment_time > current_time:
        raise DeploymentAttestationError("deployment_timestamp_invalid")
    previous_hash = str(manifest.get("previous_release_hash", ""))
    if previous_hash != "GENESIS":
        history = manifest.get("release_history")
        if not isinstance(history, list) or not history:
            raise DeploymentAttestationError("rollback_lineage_ambiguous")
        previous_manifest = history[-1]
        if not isinstance(previous_manifest, dict) or release_hash(previous_manifest) != previous_hash:
            raise DeploymentAttestationError("previous_release_hash_mismatch")
        previous_time = _parse_utc(str(previous_manifest.get("deployment_timestamp", "")))
        if previous_time > deployment_time:
            raise DeploymentAttestationError("deployment_timestamp_invalid")
    return {
        "release_id": str(manifest["release_id"]),
        "git_commit": str(manifest["git_commit"]),
        "policy_bundle_hash": str(manifest["policy_bundle_hash"]),
        "deployment_timestamp": str(manifest["deployment_timestamp"]),
        "activating_node_id": str(manifest["activating_node_id"]),
        "tenant_id": tenant_id,
        "previous_release_hash": previous_hash,
        "release_hash": release_hash(manifest),
        "release_signature_valid": True,
    }


def release_provenance_summary(path: Path | str = DEFAULT_GOVERNANCE_RELEASE_PATH) -> dict[str, Any]:
    return validate_release_manifest(path)


def assert_startup_release_integrity(path: Path | str = DEFAULT_GOVERNANCE_RELEASE_PATH) -> None:
    validate_release_manifest(path)
