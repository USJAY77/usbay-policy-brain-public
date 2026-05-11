from __future__ import annotations

from dataclasses import dataclass
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


@dataclass(frozen=True)
class ProvenanceContext:
    expected_commit: str
    current_commit: str
    ci_mode: bool
    accepted_commit_set: tuple[str, ...]
    ancestor_continuity: bool
    release_lineage: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "expected_commit": self.expected_commit,
            "current_commit": self.current_commit,
            "ci_mode": self.ci_mode,
            "accepted_commit_set": list(self.accepted_commit_set),
            "ancestor_continuity": self.ancestor_continuity,
            "release_lineage": self.release_lineage,
        }


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


def provenance_context(
    release_commit: str,
    *,
    expected_git_commit: str | None = None,
    release_lineage: bool = True,
) -> ProvenanceContext:
    current_commit = current_git_commit()
    expected_commit = expected_git_commit or current_commit
    ci_mode = environment_mode() != "production" and github_actions_ci()
    accepted = {expected_commit}
    ancestor_continuity = release_commit == expected_commit
    if ci_mode:
        accepted.update(_ci_commit_candidates(expected_commit))
        if release_commit in accepted:
            ancestor_continuity = True
        if _git_ancestor(release_commit, expected_commit):
            ancestor_continuity = True
            accepted.add(release_commit)
        github_sha = os.getenv("GITHUB_SHA", "").strip()
        if len(github_sha) == 40 and _git_ancestor(release_commit, github_sha):
            ancestor_continuity = True
            accepted.add(release_commit)
    return ProvenanceContext(
        expected_commit=expected_commit,
        current_commit=current_commit,
        ci_mode=ci_mode,
        accepted_commit_set=tuple(sorted(accepted)),
        ancestor_continuity=ancestor_continuity,
        release_lineage=release_lineage,
    )


def _context_from_mapping(context: dict[str, Any]) -> ProvenanceContext:
    try:
        accepted = context["accepted_commit_set"]
        if not isinstance(accepted, list):
            raise TypeError
        return ProvenanceContext(
            expected_commit=str(context["expected_commit"]),
            current_commit=str(context["current_commit"]),
            ci_mode=bool(context["ci_mode"]),
            accepted_commit_set=tuple(str(commit) for commit in accepted),
            ancestor_continuity=bool(context["ancestor_continuity"]),
            release_lineage=bool(context["release_lineage"]),
        )
    except Exception as exc:
        raise DeploymentAttestationError("provenance_context_invalid") from exc


def validate_normalized_provenance_context(context: dict[str, Any], release_commit: str | None = None) -> ProvenanceContext:
    normalized = _context_from_mapping(context)
    if not normalized.release_lineage:
        raise DeploymentAttestationError("rollback_lineage_ambiguous")
    if not normalized.ancestor_continuity and (
        release_commit is None or release_commit not in normalized.accepted_commit_set
    ):
        raise DeploymentAttestationError("git_commit_mismatch")
    return normalized


def normalized_provenance_context(path: Path | str = DEFAULT_GOVERNANCE_RELEASE_PATH) -> dict[str, Any]:
    return validate_release_manifest(path)["provenance_context"]


def commit_continuity_valid(release_commit: str, expected_commit: str) -> bool:
    context = provenance_context(release_commit, expected_git_commit=expected_commit)
    if not context.ci_mode:
        return release_commit == expected_commit
    return context.ancestor_continuity or release_commit in context.accepted_commit_set


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
    expected_provenance_context: dict[str, Any] | None = None,
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
    release_lineage_valid = True
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
    if expected_provenance_context is None:
        context = provenance_context(
            str(manifest.get("git_commit", "")),
            expected_git_commit=expected_git_commit,
            release_lineage=release_lineage_valid,
        )
    else:
        context = validate_normalized_provenance_context(
            expected_provenance_context,
            str(manifest.get("git_commit", "")),
        )
    if not context.release_lineage:
        raise DeploymentAttestationError("rollback_lineage_ambiguous")
    if not context.ancestor_continuity and str(manifest.get("git_commit", "")) not in context.accepted_commit_set:
        raise DeploymentAttestationError("git_commit_mismatch")
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
        "provenance_context": context.to_dict(),
    }


def release_provenance_summary(path: Path | str = DEFAULT_GOVERNANCE_RELEASE_PATH) -> dict[str, Any]:
    return validate_release_manifest(path)


def assert_startup_release_integrity(
    path: Path | str = DEFAULT_GOVERNANCE_RELEASE_PATH,
    *,
    expected_provenance_context: dict[str, Any] | None = None,
) -> None:
    validate_release_manifest(path, expected_provenance_context=expected_provenance_context)
