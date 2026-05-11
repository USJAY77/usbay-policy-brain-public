from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import subprocess
import sys
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


@dataclass(frozen=True)
class RuntimeProvenanceAuthority:
    release_path: str
    release_hash: str
    policy_bundle_hash: str
    tenant_id: str
    provenance_context: ProvenanceContext
    authority_id: str

    def context_dict(self) -> dict[str, Any]:
        return self.provenance_context.to_dict()

    def to_dict(self) -> dict[str, Any]:
        return {
            "authority_id": self.authority_id,
            "release_path": self.release_path,
            "release_hash": self.release_hash,
            "policy_bundle_hash": self.policy_bundle_hash,
            "tenant_id": self.tenant_id,
            "provenance_context": self.context_dict(),
        }


@dataclass(frozen=True)
class RuntimeProvenanceBootstrap:
    context: ProvenanceContext
    diagnostics: dict[str, Any]


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


def _valid_git_sha(value: str | None) -> str | None:
    candidate = (value or "").strip()
    if len(candidate) == 40 and all(char in "0123456789abcdefABCDEF" for char in candidate):
        return candidate.lower()
    return None


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


def _ci_event_commit_candidates() -> set[str]:
    event_path = os.getenv("GITHUB_EVENT_PATH", "").strip()
    if not event_path:
        return set()
    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except Exception:
        return set()
    candidates: set[str] = set()

    def add(value: Any) -> None:
        commit = _valid_git_sha(str(value) if value is not None else None)
        if commit:
            candidates.add(commit)

    if isinstance(event, dict):
        for key in ("after", "before", "merge_commit_sha"):
            add(event.get(key))
        pull_request = event.get("pull_request")
        if isinstance(pull_request, dict):
            add(pull_request.get("merge_commit_sha"))
            head = pull_request.get("head")
            base = pull_request.get("base")
            if isinstance(head, dict):
                add(head.get("sha"))
            if isinstance(base, dict):
                add(base.get("sha"))
        workflow_run = event.get("workflow_run")
        if isinstance(workflow_run, dict):
            add(workflow_run.get("head_sha"))
        check_suite = event.get("check_suite")
        if isinstance(check_suite, dict):
            add(check_suite.get("head_sha"))
        merge_group = event.get("merge_group")
        if isinstance(merge_group, dict):
            add(merge_group.get("head_sha"))
            add(merge_group.get("base_sha"))
    return candidates


def _ci_commit_candidates(expected_commit: str, current_commit: str) -> set[str]:
    candidates = {expected_commit}
    current = _valid_git_sha(current_commit)
    if current:
        candidates.add(current)
    for name in ("GITHUB_SHA", "GITHUB_HEAD_SHA", "GITHUB_BASE_SHA"):
        value = _valid_git_sha(os.getenv(name))
        if value:
            candidates.add(value)
    candidates.update(_ci_event_commit_candidates())
    candidates.update(_git_parents(expected_commit))
    return candidates


def _canonical_ci_expected_commit(current_commit: str) -> str:
    github_sha = _valid_git_sha(os.getenv("GITHUB_SHA"))
    return github_sha or current_commit


def _bootstrap_commit_candidates(current_commit: str, expected_commit: str) -> set[str]:
    candidates = {expected_commit, current_commit}
    for name in ("GITHUB_SHA", "GITHUB_HEAD_SHA", "GITHUB_BASE_SHA"):
        value = _valid_git_sha(os.getenv(name))
        if value:
            candidates.add(value)
    candidates.update(_ci_event_commit_candidates())
    for commit in tuple(candidates):
        candidates.update(_git_parents(commit))
    return {commit for commit in candidates if _valid_git_sha(commit)}


def bootstrap_runtime_provenance(
    release_commit: str,
    *,
    expected_git_commit: str | None = None,
    release_lineage: bool = True,
) -> RuntimeProvenanceBootstrap:
    normalized_release = _valid_git_sha(release_commit)
    if not normalized_release:
        raise DeploymentAttestationError("git_commit_mismatch")
    current_commit = current_git_commit()
    ci_mode = environment_mode() != "production" and github_actions_ci()
    expected_commit = expected_git_commit or (_canonical_ci_expected_commit(current_commit) if ci_mode else current_commit)
    accepted = {expected_commit}
    rejected_paths: list[dict[str, str]] = []
    continuity = normalized_release == expected_commit
    if ci_mode:
        candidates = _bootstrap_commit_candidates(current_commit, expected_commit)
        accepted.update(candidates)
        if normalized_release in candidates:
            continuity = True
        else:
            for candidate in sorted(candidates):
                if _git_ancestor(normalized_release, candidate):
                    continuity = True
                    accepted.add(normalized_release)
                    break
                rejected_paths.append({"release_commit": normalized_release, "candidate": candidate})
    context = ProvenanceContext(
        expected_commit=expected_commit,
        current_commit=current_commit,
        ci_mode=ci_mode,
        accepted_commit_set=tuple(sorted(accepted)),
        ancestor_continuity=continuity,
        release_lineage=release_lineage,
    )
    diagnostics = {
        "runtime_provenance_bootstrap": "v1",
        "release_commit": normalized_release,
        "expected_commit": expected_commit,
        "current_commit": current_commit,
        "ci_mode": ci_mode,
        "accepted_commit_candidates": list(context.accepted_commit_set),
        "ancestor_continuity": continuity,
        "release_lineage": release_lineage,
        "github_event_name": os.getenv("GITHUB_EVENT_NAME", ""),
        "rejected_lineage_paths": rejected_paths if not continuity else [],
    }
    return RuntimeProvenanceBootstrap(context=context, diagnostics=diagnostics)


def provenance_context(
    release_commit: str,
    *,
    expected_git_commit: str | None = None,
    release_lineage: bool = True,
) -> ProvenanceContext:
    return bootstrap_runtime_provenance(
        release_commit,
        expected_git_commit=expected_git_commit,
        release_lineage=release_lineage,
    ).context


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
    return resolve_runtime_provenance_authority(path).context_dict()


def _authority_id(path: Path | str, release_digest: str, context: dict[str, Any]) -> str:
    payload = {
        "context": context,
        "release_hash": release_digest,
    }
    return sha256_text(canonical_json(payload))


def resolve_runtime_provenance_authority(path: Path | str = DEFAULT_GOVERNANCE_RELEASE_PATH) -> RuntimeProvenanceAuthority:
    manifest = _load_manifest(path)
    bootstrap = bootstrap_runtime_provenance(str(manifest.get("git_commit", "")))
    context = bootstrap.context.to_dict()
    summary = validate_release_manifest(path, expected_provenance_context=context)
    if summary["provenance_context"] != context:
        raise DeploymentAttestationError("runtime_provenance_authority_mismatch")
    normalized = validate_normalized_provenance_context(context, str(manifest.get("git_commit", "")))
    release_digest = str(summary["release_hash"])
    return RuntimeProvenanceAuthority(
        release_path=str(Path(path)),
        release_hash=release_digest,
        policy_bundle_hash=str(summary["policy_bundle_hash"]),
        tenant_id=str(summary["tenant_id"]),
        provenance_context=normalized,
        authority_id=_authority_id(path, release_digest, context),
    )


def runtime_provenance_bootstrap_diagnostics(
    path: Path | str = DEFAULT_GOVERNANCE_RELEASE_PATH,
) -> dict[str, Any]:
    manifest = _load_manifest(path)
    return bootstrap_runtime_provenance(str(manifest.get("git_commit", ""))).diagnostics


def write_runtime_provenance_bootstrap_diagnostics(
    path: Path | str = DEFAULT_GOVERNANCE_RELEASE_PATH,
    output_path: Path | str = "runtime_provenance_bootstrap.json",
) -> dict[str, Any]:
    diagnostics = runtime_provenance_bootstrap_diagnostics(path)
    target = Path(output_path)
    target.write_text(canonical_json(diagnostics) + "\n", encoding="utf-8")
    return diagnostics


def assert_runtime_provenance_authority(
    authority: RuntimeProvenanceAuthority,
    path: Path | str | None = None,
) -> RuntimeProvenanceAuthority:
    if not isinstance(authority, RuntimeProvenanceAuthority):
        raise DeploymentAttestationError("runtime_provenance_authority_required")
    release_path = path or authority.release_path
    context = authority.context_dict()
    summary = validate_release_manifest(release_path, expected_provenance_context=context)
    if summary["release_hash"] != authority.release_hash:
        raise DeploymentAttestationError("runtime_provenance_authority_mismatch")
    if summary["policy_bundle_hash"] != authority.policy_bundle_hash:
        raise DeploymentAttestationError("runtime_provenance_authority_mismatch")
    if summary["tenant_id"] != authority.tenant_id:
        raise DeploymentAttestationError("runtime_provenance_authority_mismatch")
    if summary["provenance_context"] != context:
        raise DeploymentAttestationError("runtime_provenance_authority_mismatch")
    if _authority_id(release_path, authority.release_hash, context) != authority.authority_id:
        raise DeploymentAttestationError("runtime_provenance_authority_mismatch")
    return authority


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


def _canonical_activating_node_id(policy_path: Path | str = DEFAULT_NODE_ATTESTATION_POLICY_PATH) -> str:
    policy = load_node_attestation_policy(policy_path)
    enrolled = policy["enrolled_nodes"]
    gateway_nodes = sorted(
        str(entry["node_id"])
        for entry in enrolled.values()
        if isinstance(entry, dict) and entry.get("role") == "gateway" and entry.get("node_id")
    )
    if gateway_nodes:
        return gateway_nodes[0]
    node_ids = sorted(
        str(entry["node_id"])
        for entry in enrolled.values()
        if isinstance(entry, dict) and entry.get("node_id")
    )
    if not node_ids:
        raise DeploymentAttestationError("activating_node_unknown")
    return node_ids[0]


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


def _release_timestamp(value: datetime | str | None = None) -> str:
    if value is None:
        value = datetime.now(timezone.utc).replace(microsecond=0)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise DeploymentAttestationError("deployment_timestamp_invalid")
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    parsed = _parse_utc(str(value))
    return parsed.isoformat().replace("+00:00", "Z")


def _release_id(timestamp: str) -> str:
    compact = timestamp.replace("-", "").replace(":", "").replace("Z", "Z")
    return f"usbay-governance-release-{compact}"


def build_release_manifest(
    *,
    release_id: str | None = None,
    deployment_timestamp: datetime | str | None = None,
    activating_node_id: str | None = None,
    tenant_id: str = "t1",
    previous_manifest: dict[str, Any] | None = None,
    node_policy_path: Path | str = DEFAULT_NODE_ATTESTATION_POLICY_PATH,
    tenant_policy_path: Path | str = DEFAULT_TENANT_POLICY_PATH,
) -> dict[str, Any]:
    timestamp = _release_timestamp(deployment_timestamp)
    current_commit = current_git_commit()
    context = provenance_context(current_commit, expected_git_commit=current_commit)
    if not context.release_lineage or not context.ancestor_continuity:
        raise DeploymentAttestationError("git_commit_mismatch")
    validated_tenant = validate_tenant_id(tenant_id, tenant_policy_path)
    node_id = activating_node_id or _canonical_activating_node_id(node_policy_path)
    if node_id not in _enrolled_node_ids(node_policy_path):
        raise DeploymentAttestationError("activating_node_unknown")

    manifest = {
        "activating_node_id": node_id,
        "deployment_timestamp": timestamp,
        "git_commit": current_commit,
        "policy_bundle_hash": policy_bundle_hash(),
        "previous_release_hash": "GENESIS",
        "release_id": release_id or _release_id(timestamp),
        "tenant_id": validated_tenant,
    }

    if previous_manifest is not None:
        if not isinstance(previous_manifest, dict):
            raise DeploymentAttestationError("release_manifest_invalid")
        if not verify_release_signature(previous_manifest):
            raise DeploymentAttestationError("release_signature_invalid")
        previous_time = _parse_utc(str(previous_manifest.get("deployment_timestamp", "")))
        current_time = _parse_utc(timestamp)
        if previous_time > current_time:
            raise DeploymentAttestationError("deployment_timestamp_invalid")
        previous_hash = release_hash(previous_manifest)
        history = list(previous_manifest.get("release_history", []))
        history.append(previous_manifest)
        manifest["previous_release_hash"] = previous_hash
        manifest["release_history"] = history

    manifest["release_signature"] = sign_release_manifest(manifest)
    return manifest


def write_release_manifest(
    path: Path | str = DEFAULT_GOVERNANCE_RELEASE_PATH,
    *,
    release_id: str | None = None,
    deployment_timestamp: datetime | str | None = None,
    activating_node_id: str | None = None,
    tenant_id: str = "t1",
    preserve_existing_lineage: bool = True,
    node_policy_path: Path | str = DEFAULT_NODE_ATTESTATION_POLICY_PATH,
    tenant_policy_path: Path | str = DEFAULT_TENANT_POLICY_PATH,
) -> dict[str, Any]:
    target = Path(path)
    previous_manifest = None
    if preserve_existing_lineage and target.exists():
        previous_manifest = _load_manifest(target)
    manifest = build_release_manifest(
        release_id=release_id,
        deployment_timestamp=deployment_timestamp,
        activating_node_id=activating_node_id,
        tenant_id=tenant_id,
        previous_manifest=previous_manifest,
        node_policy_path=node_policy_path,
        tenant_policy_path=tenant_policy_path,
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = validate_release_manifest(
        target,
        expected_git_commit=manifest["git_commit"],
        expected_policy_bundle_hash=manifest["policy_bundle_hash"],
        expected_tenant_id=manifest["tenant_id"],
        node_policy_path=node_policy_path,
    )
    if summary.get("release_signature_valid") is not True:
        raise DeploymentAttestationError("release_signature_invalid")
    return manifest


def validate_release_manifest(
    path: Path | str = DEFAULT_GOVERNANCE_RELEASE_PATH,
    *,
    expected_git_commit: str | None = None,
    expected_policy_bundle_hash: str | None = None,
    expected_tenant_id: str | None = None,
    expected_provenance_context: dict[str, Any] | None = None,
    expected_provenance_authority: RuntimeProvenanceAuthority | None = None,
    node_policy_path: Path | str = DEFAULT_NODE_ATTESTATION_POLICY_PATH,
    now: datetime | None = None,
) -> dict[str, Any]:
    manifest = _load_manifest(path)
    if expected_provenance_authority is not None:
        expected_provenance_context = assert_runtime_provenance_authority(
            expected_provenance_authority,
            path,
        ).context_dict()
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


def _main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "write-release":
        manifest = write_release_manifest()
        print(canonical_json({
            "git_commit": manifest["git_commit"],
            "policy_bundle_hash": manifest["policy_bundle_hash"],
            "release_id": manifest["release_id"],
            "release_signature_valid": verify_release_signature(manifest),
            "wrote": str(DEFAULT_GOVERNANCE_RELEASE_PATH),
        }))
        return 0
    print("usage: python3 -m security.deployment_attestation write-release", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
