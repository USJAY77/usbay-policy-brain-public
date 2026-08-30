from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from governance.dependencies import GOVERNANCE_DOMAIN_MODULES, build_governance_dependency_map

RELEASE_INTEGRITY_SCHEMA = "usbay.governance_release_integrity.v1"
SIGNATURE_PREFIX = "hmac-sha256:"
DEFAULT_BASELINE_TAG = "governance-baseline-v1"
DEFAULT_TRUST_POLICY_PATH = Path("governance/ci_evidence_trust_policy.json")


class GovernanceReleaseIntegrityError(RuntimeError):
    pass


@dataclass(frozen=True)
class GovernanceReleaseIntegritySummary:
    valid: bool
    release_id: str
    release_hash: str
    dependency_graph_hash: str
    trust_policy_fingerprint: str
    governance_baseline_tag: str
    failures: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "release_id": self.release_id,
            "release_hash": self.release_hash,
            "dependency_graph_hash": self.dependency_graph_hash,
            "trust_policy_fingerprint": self.trust_policy_fingerprint,
            "governance_baseline_tag": self.governance_baseline_tag,
            "failures": list(self.failures),
        }


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _run_git(root: Path, args: list[str]) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise GovernanceReleaseIntegrityError("git_metadata_unavailable")
    return completed.stdout.strip()


def current_git_commit(root: Path) -> str:
    commit = _run_git(root, ["rev-parse", "HEAD"])
    if len(commit) != 40:
        raise GovernanceReleaseIntegrityError("git_metadata_unavailable")
    return commit


def git_parent_commits(root: Path, commit: str) -> tuple[str, ...]:
    output = _run_git(root, ["rev-list", "--parents", "-n", "1", commit])
    parts = output.split()
    return tuple(parts[1:])


def baseline_tag_commit(root: Path, baseline_tag: str) -> str:
    try:
        commit = _run_git(root, ["rev-parse", f"{baseline_tag}^{{commit}}"])
    except GovernanceReleaseIntegrityError:
        return "UNRESOLVED"
    return commit


def canonical_public_key_fingerprint(public_key_pem: str) -> str:
    try:
        normalized = public_key_pem.strip().replace("\\r\\n", "\n").replace("\\n", "\n").replace("\r\n", "\n").replace("\r", "\n")
        lines = [line.strip() for line in normalized.split("\n") if line.strip()]
        normalized = "\n".join(lines) + "\n"
        key = serialization.load_pem_public_key(normalized.encode("utf-8"))
    except Exception as exc:
        raise GovernanceReleaseIntegrityError("trust_policy_public_key_invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise GovernanceReleaseIntegrityError("trust_policy_public_key_invalid")
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def trust_policy_fingerprint(root: Path, trust_policy_path: Path = DEFAULT_TRUST_POLICY_PATH) -> str:
    path = trust_policy_path if trust_policy_path.is_absolute() else root / trust_policy_path
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise GovernanceReleaseIntegrityError("trust_policy_missing") from exc
    allowed = policy.get("allowed_signers")
    if not isinstance(allowed, list) or not allowed:
        raise GovernanceReleaseIntegrityError("trust_policy_empty")
    fingerprints: list[str] = []
    for index, entry in enumerate(allowed):
        if not isinstance(entry, dict):
            raise GovernanceReleaseIntegrityError("trust_policy_invalid")
        public_key_pem = str(entry.get("public_key_pem", ""))
        declared = str(entry.get("public_key_fingerprint", ""))
        derived = canonical_public_key_fingerprint(public_key_pem)
        if declared != derived:
            raise GovernanceReleaseIntegrityError(f"trust_policy_fingerprint_mismatch:{index}")
        fingerprints.append(derived)
    return sha256_text(canonical_json({"allowed_signer_fingerprints": sorted(fingerprints)}))


def governance_module_versions(root: Path) -> dict[str, str]:
    versions: dict[str, str] = {}
    for domain, module_name in sorted(GOVERNANCE_DOMAIN_MODULES.items()):
        path = root / Path(*module_name.split(".")).with_suffix(".py")
        if not path.is_file():
            raise GovernanceReleaseIntegrityError(f"governance_module_missing:{module_name}")
        versions[domain] = hashlib.sha256(path.read_bytes()).hexdigest()
    return versions


def _signing_material() -> str:
    return os.getenv("USBAY_GOVERNANCE_RELEASE_INTEGRITY_SIGNING_MATERIAL", "usbay-governance-release-integrity-v1")


def _signature_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    payload = dict(manifest)
    payload.pop("release_signature", None)
    return payload


def release_integrity_hash(manifest: dict[str, Any]) -> str:
    return sha256_text(canonical_json(_signature_payload(manifest)))


def sign_release_integrity_manifest(manifest: dict[str, Any], signing_material: str | None = None) -> str:
    digest = hmac.new(
        (signing_material or _signing_material()).encode("utf-8"),
        canonical_json(_signature_payload(manifest)).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return SIGNATURE_PREFIX + digest


def verify_release_integrity_signature(manifest: dict[str, Any]) -> bool:
    signature = manifest.get("release_signature")
    if not isinstance(signature, str) or not signature.startswith(SIGNATURE_PREFIX):
        return False
    return hmac.compare_digest(signature, sign_release_integrity_manifest(manifest))


def build_release_integrity_manifest(
    root: Path,
    *,
    release_id: str,
    governance_baseline_tag: str = DEFAULT_BASELINE_TAG,
    previous_manifest: dict[str, Any] | None = None,
    generated_at: datetime | str | None = None,
    trust_policy_path: Path = DEFAULT_TRUST_POLICY_PATH,
) -> dict[str, Any]:
    root = root.resolve()
    commit = current_git_commit(root)
    timestamp = _timestamp(generated_at)
    dependency_graph = build_governance_dependency_map(root).to_dict()
    manifest: dict[str, Any] = {
        "schema": RELEASE_INTEGRITY_SCHEMA,
        "release_id": release_id,
        "generated_at": timestamp,
        "commit_lineage": {
            "current_commit": commit,
            "parent_commits": list(git_parent_commits(root, commit)),
        },
        "governance_baseline": {
            "tag": governance_baseline_tag,
            "tag_commit": baseline_tag_commit(root, governance_baseline_tag),
        },
        "dependency_graph_hash": dependency_graph["graph_hash"],
        "dependency_graph": dependency_graph,
        "trust_policy_fingerprint": trust_policy_fingerprint(root, trust_policy_path),
        "governance_module_versions": governance_module_versions(root),
        "audit_metadata": {
            "previous_release_hash": "GENESIS",
            "previous_release_id": None,
        },
    }
    if previous_manifest is not None:
        previous_summary = validate_release_integrity_manifest(previous_manifest, root)
        manifest["audit_metadata"] = {
            "previous_release_hash": previous_summary.release_hash,
            "previous_release_id": previous_summary.release_id,
        }
    manifest["release_signature"] = sign_release_integrity_manifest(manifest)
    return manifest


def validate_release_integrity_manifest(
    manifest: dict[str, Any],
    root: Path,
    *,
    expected_baseline_tag: str | None = None,
    rollback_targets: tuple[str, ...] = (),
    trust_policy_path: Path = DEFAULT_TRUST_POLICY_PATH,
) -> GovernanceReleaseIntegritySummary:
    root = root.resolve()
    failures: list[str] = []
    if not isinstance(manifest, dict):
        raise GovernanceReleaseIntegrityError("release_integrity_manifest_invalid")
    if manifest.get("schema") != RELEASE_INTEGRITY_SCHEMA:
        failures.append("release_integrity_schema_invalid")
    required = {
        "release_id",
        "generated_at",
        "commit_lineage",
        "governance_baseline",
        "dependency_graph_hash",
        "dependency_graph",
        "trust_policy_fingerprint",
        "governance_module_versions",
        "audit_metadata",
        "release_signature",
    }
    for field in sorted(required):
        if manifest.get(field) in (None, ""):
            failures.append(f"release_integrity_field_missing:{field}")
    if not verify_release_integrity_signature(manifest):
        failures.append("release_integrity_signature_invalid")
    dependency_graph = build_governance_dependency_map(root).to_dict()
    if manifest.get("dependency_graph_hash") != dependency_graph["graph_hash"]:
        failures.append("release_integrity_dependency_drift")
    if manifest.get("dependency_graph") != dependency_graph:
        failures.append("release_integrity_dependency_graph_mismatch")
    try:
        current_trust_fingerprint = trust_policy_fingerprint(root, trust_policy_path)
    except GovernanceReleaseIntegrityError as exc:
        failures.append(str(exc))
        current_trust_fingerprint = ""
    if manifest.get("trust_policy_fingerprint") != current_trust_fingerprint:
        failures.append("release_integrity_trust_policy_mismatch")
    if manifest.get("governance_module_versions") != governance_module_versions(root):
        failures.append("release_integrity_module_version_mismatch")
    lineage = manifest.get("commit_lineage")
    if not isinstance(lineage, dict) or not lineage.get("current_commit"):
        failures.append("release_integrity_commit_lineage_missing")
    else:
        try:
            commit = str(lineage["current_commit"])
            if tuple(lineage.get("parent_commits", [])) != git_parent_commits(root, commit):
                failures.append("release_integrity_commit_lineage_mismatch")
        except Exception:
            failures.append("release_integrity_commit_lineage_mismatch")
    baseline = manifest.get("governance_baseline")
    if not isinstance(baseline, dict) or not baseline.get("tag") or not baseline.get("tag_commit"):
        failures.append("release_integrity_baseline_missing")
    else:
        if expected_baseline_tag is not None and baseline.get("tag") != expected_baseline_tag:
            failures.append("release_integrity_baseline_mismatch")
        if baseline.get("tag_commit") != baseline_tag_commit(root, str(baseline.get("tag"))):
            failures.append("release_integrity_tag_drift")
    audit = manifest.get("audit_metadata")
    if not isinstance(audit, dict) or not audit.get("previous_release_hash"):
        failures.append("release_integrity_audit_lineage_missing")
    elif audit.get("previous_release_hash") != "GENESIS" and audit.get("previous_release_hash") not in rollback_targets:
        failures.append("release_integrity_rollback_target_invalid")
    if failures:
        raise GovernanceReleaseIntegrityError(",".join(sorted(set(failures))))
    return GovernanceReleaseIntegritySummary(
        valid=True,
        release_id=str(manifest["release_id"]),
        release_hash=release_integrity_hash(manifest),
        dependency_graph_hash=str(manifest["dependency_graph_hash"]),
        trust_policy_fingerprint=str(manifest["trust_policy_fingerprint"]),
        governance_baseline_tag=str(manifest["governance_baseline"]["tag"]),
    )


def load_release_integrity_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise GovernanceReleaseIntegrityError("release_integrity_manifest_missing") from exc
    if not isinstance(payload, dict):
        raise GovernanceReleaseIntegrityError("release_integrity_manifest_invalid")
    return payload


def validate_release_integrity_file(
    path: Path,
    root: Path,
    *,
    expected_baseline_tag: str | None = None,
    rollback_targets: tuple[str, ...] = (),
    trust_policy_path: Path = DEFAULT_TRUST_POLICY_PATH,
) -> GovernanceReleaseIntegritySummary:
    return validate_release_integrity_manifest(
        load_release_integrity_manifest(path),
        root,
        expected_baseline_tag=expected_baseline_tag,
        rollback_targets=rollback_targets,
        trust_policy_path=trust_policy_path,
    )


def _timestamp(value: datetime | str | None) -> str:
    if value is None:
        value = datetime.now(timezone.utc).replace(microsecond=0)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise GovernanceReleaseIntegrityError("release_integrity_timestamp_invalid")
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception as exc:
        raise GovernanceReleaseIntegrityError("release_integrity_timestamp_invalid") from exc
    if parsed.tzinfo is None:
        raise GovernanceReleaseIntegrityError("release_integrity_timestamp_invalid")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
