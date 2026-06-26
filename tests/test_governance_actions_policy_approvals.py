from __future__ import annotations

import json
from pathlib import Path

from tests.helpers.governance_policy_approvals import APPROVALS_PATH, verify_policy_approvals
from tests.helpers.governance_policy_manifest import MANIFEST_PATH


ROOT = Path(__file__).resolve().parents[1]


def _write_approval_tree(tmp_path: Path, *, approvals: dict | None = None, manifest_text: str | None = None) -> Path:
    governance = tmp_path / "governance"
    governance.mkdir(parents=True)
    manifest = manifest_text if manifest_text is not None else MANIFEST_PATH.read_text(encoding="utf-8")
    governance.joinpath("approved_github_actions_policy.manifest.json").write_text(manifest, encoding="utf-8")
    if approvals is None:
        approvals = json.loads(APPROVALS_PATH.read_text(encoding="utf-8"))
    governance.joinpath("approved_github_actions_policy.approvals.json").write_text(
        json.dumps(approvals, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return tmp_path


def test_valid_two_approval_chain_passes() -> None:
    evidence = verify_policy_approvals()

    assert evidence["decision"] == "PASS"
    assert evidence["reason"] == "GITHUB_ACTIONS_POLICY_APPROVAL_CHAIN_VALID"
    assert evidence["required_approvers"] == 2


def test_missing_approval_file_fails_closed(tmp_path: Path) -> None:
    governance = tmp_path / "governance"
    governance.mkdir(parents=True)
    governance.joinpath("approved_github_actions_policy.manifest.json").write_text(
        MANIFEST_PATH.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    evidence = verify_policy_approvals(root=tmp_path)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "GITHUB_ACTIONS_POLICY_APPROVALS_MISSING"
    assert evidence["silent_pass"] is False


def test_one_approval_only_fails_closed(tmp_path: Path) -> None:
    approvals = json.loads(APPROVALS_PATH.read_text(encoding="utf-8"))
    approvals["approvals"] = approvals["approvals"][:1]
    root = _write_approval_tree(tmp_path, approvals=approvals)

    evidence = verify_policy_approvals(root=root)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "GITHUB_ACTIONS_POLICY_APPROVALS_INSUFFICIENT"
    assert evidence["silent_pass"] is False


def test_manifest_hash_mismatch_fails_closed(tmp_path: Path) -> None:
    root = _write_approval_tree(tmp_path, manifest_text='{"changed": true}\n')

    evidence = verify_policy_approvals(root=root)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "GITHUB_ACTIONS_POLICY_APPROVALS_MANIFEST_HASH_MISMATCH"
    assert evidence["silent_pass"] is False


def test_malformed_approval_file_fails_closed(tmp_path: Path) -> None:
    root = _write_approval_tree(tmp_path)
    root.joinpath("governance", "approved_github_actions_policy.approvals.json").write_text(
        "{not-json",
        encoding="utf-8",
    )

    evidence = verify_policy_approvals(root=root)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "GITHUB_ACTIONS_POLICY_APPROVALS_MALFORMED"
    assert evidence["silent_pass"] is False


def test_unknown_approver_role_fails_closed(tmp_path: Path) -> None:
    approvals = json.loads(APPROVALS_PATH.read_text(encoding="utf-8"))
    approvals["approvals"][0]["role"] = "untrusted_admin"
    root = _write_approval_tree(tmp_path, approvals=approvals)

    evidence = verify_policy_approvals(root=root)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "GITHUB_ACTIONS_POLICY_APPROVER_ROLE_UNKNOWN"
    assert evidence["silent_pass"] is False


def test_placeholder_signatures_are_non_production_scaffolding() -> None:
    evidence = verify_policy_approvals()
    approvals = json.loads(APPROVALS_PATH.read_text(encoding="utf-8"))

    assert evidence["decision"] == "PASS"
    assert evidence["placeholder_signatures"] is True
    assert evidence["production_signatures"] is False
    assert evidence["recognized_placeholder_signatures"] == len(approvals["approvals"])
