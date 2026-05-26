from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
APPROVALS_PATH = ROOT / "governance" / "approved_github_actions_policy.approvals.json"
MANIFEST_PATH = ROOT / "governance" / "approved_github_actions_policy.manifest.json"
PLACEHOLDER_SIGNATURE = "SIGNATURE_PLACEHOLDER_NON_PRODUCTION_DO_NOT_TRUST"
ALLOWED_ROLES = {"governance_owner", "security_reviewer"}


REQUIRED_APPROVAL_FIELDS = (
    "approver_id",
    "role",
    "approved_at",
    "approval_reason",
    "signature_placeholder",
)


def verify_policy_approvals(
    *,
    root: Path = ROOT,
    approvals_path: Path | None = None,
) -> dict[str, Any]:
    resolved_approvals = approvals_path or root / "governance" / "approved_github_actions_policy.approvals.json"
    resolved_manifest = root / "governance" / "approved_github_actions_policy.manifest.json"

    if not resolved_approvals.exists():
        return _fail_closed("GITHUB_ACTIONS_POLICY_APPROVALS_MISSING")
    if not resolved_manifest.exists():
        return _fail_closed("GITHUB_ACTIONS_POLICY_APPROVALS_MANIFEST_MISSING")

    try:
        approvals = json.loads(resolved_approvals.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _fail_closed("GITHUB_ACTIONS_POLICY_APPROVALS_MALFORMED")

    if not isinstance(approvals, dict):
        return _fail_closed("GITHUB_ACTIONS_POLICY_APPROVALS_MALFORMED")

    if approvals.get("fail_closed_on_missing_approval") is not True:
        return _fail_closed("GITHUB_ACTIONS_POLICY_APPROVALS_NOT_FAIL_CLOSED")

    required_approvers = approvals.get("required_approvers")
    approval_entries = approvals.get("approvals")
    if not isinstance(required_approvers, int) or required_approvers < 2:
        return _fail_closed("GITHUB_ACTIONS_POLICY_APPROVALS_MALFORMED")
    if not isinstance(approval_entries, list):
        return _fail_closed("GITHUB_ACTIONS_POLICY_APPROVALS_MALFORMED")

    manifest_hash = hashlib.sha256(resolved_manifest.read_bytes()).hexdigest()
    if approvals.get("manifest_sha256") != manifest_hash:
        return _fail_closed(
            "GITHUB_ACTIONS_POLICY_APPROVALS_MANIFEST_HASH_MISMATCH",
            actual_manifest_sha256=manifest_hash,
            expected_manifest_sha256=approvals.get("manifest_sha256"),
        )

    if len(approval_entries) < required_approvers:
        return _fail_closed("GITHUB_ACTIONS_POLICY_APPROVALS_INSUFFICIENT")

    seen_approvers: set[str] = set()
    placeholder_count = 0
    for entry in approval_entries:
        if not isinstance(entry, dict):
            return _fail_closed("GITHUB_ACTIONS_POLICY_APPROVALS_MALFORMED")
        missing = [field for field in REQUIRED_APPROVAL_FIELDS if field not in entry]
        if missing:
            return _fail_closed("GITHUB_ACTIONS_POLICY_APPROVALS_MALFORMED", missing_fields=missing)

        role = entry["role"]
        if role not in ALLOWED_ROLES:
            return _fail_closed("GITHUB_ACTIONS_POLICY_APPROVER_ROLE_UNKNOWN", role=role)

        approver_id = entry["approver_id"]
        if not isinstance(approver_id, str) or not approver_id:
            return _fail_closed("GITHUB_ACTIONS_POLICY_APPROVALS_MALFORMED")
        seen_approvers.add(approver_id)

        if entry["signature_placeholder"] == PLACEHOLDER_SIGNATURE:
            placeholder_count += 1
        else:
            return _fail_closed("GITHUB_ACTIONS_POLICY_APPROVAL_SIGNATURE_NOT_PLACEHOLDER")

    if len(seen_approvers) < required_approvers:
        return _fail_closed("GITHUB_ACTIONS_POLICY_APPROVALS_DUPLICATE_APPROVER")

    return {
        "decision": "PASS",
        "fail_closed": False,
        "manifest_sha256": manifest_hash,
        "placeholder_signatures": True,
        "production_signatures": False,
        "reason": "GITHUB_ACTIONS_POLICY_APPROVAL_CHAIN_VALID",
        "recognized_placeholder_signatures": placeholder_count,
        "required_approvers": required_approvers,
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
