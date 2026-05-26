from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "governance" / "approved_github_actions_policy.manifest.json"


REQUIRED_FIELDS = (
    "policy_file",
    "policy_sha256",
    "policy_version",
    "generated_at",
    "governance_owner",
    "fail_closed_on_manifest_mismatch",
)


def verify_policy_manifest(
    *,
    root: Path = ROOT,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    resolved_manifest = manifest_path or root / "governance" / "approved_github_actions_policy.manifest.json"
    if not resolved_manifest.exists():
        return _fail_closed("GITHUB_ACTIONS_POLICY_MANIFEST_MISSING")

    try:
        manifest = json.loads(resolved_manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _fail_closed("GITHUB_ACTIONS_POLICY_MANIFEST_MALFORMED")

    if not isinstance(manifest, dict):
        return _fail_closed("GITHUB_ACTIONS_POLICY_MANIFEST_MALFORMED")

    missing = [field for field in REQUIRED_FIELDS if field not in manifest]
    if missing:
        return _fail_closed("GITHUB_ACTIONS_POLICY_MANIFEST_MALFORMED", missing_fields=missing)

    if manifest.get("fail_closed_on_manifest_mismatch") is not True:
        return _fail_closed("GITHUB_ACTIONS_POLICY_MANIFEST_NOT_FAIL_CLOSED")

    policy_rel = manifest.get("policy_file")
    if not isinstance(policy_rel, str):
        return _fail_closed("GITHUB_ACTIONS_POLICY_MANIFEST_MALFORMED")

    policy_path = (root / policy_rel).resolve()
    root_path = root.resolve()
    if root_path not in policy_path.parents:
        return _fail_closed("GITHUB_ACTIONS_POLICY_FILE_OUTSIDE_REPOSITORY")

    if not policy_path.exists():
        return _fail_closed("GITHUB_ACTIONS_POLICY_FILE_UNKNOWN")

    expected_hash = manifest.get("policy_sha256")
    if not isinstance(expected_hash, str) or len(expected_hash) != 64:
        return _fail_closed("GITHUB_ACTIONS_POLICY_MANIFEST_MALFORMED")

    actual_hash = hashlib.sha256(policy_path.read_bytes()).hexdigest()
    if actual_hash != expected_hash:
        return _fail_closed(
            "GITHUB_ACTIONS_POLICY_MANIFEST_HASH_MISMATCH",
            actual_policy_sha256=actual_hash,
            expected_policy_sha256=expected_hash,
        )

    return {
        "decision": "PASS",
        "fail_closed": False,
        "policy_file": policy_rel,
        "policy_sha256": actual_hash,
        "policy_version": manifest["policy_version"],
        "reason": "GITHUB_ACTIONS_POLICY_MANIFEST_VALID",
    }


def _fail_closed(reason: str, **details: Any) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "decision": "FAIL_CLOSED",
        "fail_closed": True,
        "reason": reason,
        "silent_pass": False,
    }
    evidence.update(details)
    return evidence
