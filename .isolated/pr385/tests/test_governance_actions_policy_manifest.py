from __future__ import annotations

import json
from pathlib import Path

from tests.helpers.governance_policy_manifest import MANIFEST_PATH, verify_policy_manifest


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "governance" / "approved_github_actions_policy.json"


def _write_manifest_tree(tmp_path: Path, *, manifest: dict | None = None, policy_text: str | None = None) -> Path:
    governance = tmp_path / "governance"
    governance.mkdir(parents=True)
    policy = policy_text if policy_text is not None else POLICY_PATH.read_text(encoding="utf-8")
    (governance / "approved_github_actions_policy.json").write_text(policy, encoding="utf-8")
    if manifest is None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    (governance / "approved_github_actions_policy.manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return tmp_path


def test_valid_github_actions_policy_manifest_passes() -> None:
    evidence = verify_policy_manifest()

    assert evidence["decision"] == "PASS"
    assert evidence["policy_file"] == "governance/approved_github_actions_policy.json"
    assert evidence["reason"] == "GITHUB_ACTIONS_POLICY_MANIFEST_VALID"


def test_changed_policy_hash_fails_closed(tmp_path: Path) -> None:
    root = _write_manifest_tree(tmp_path, policy_text='{"actions":{}}\n')

    evidence = verify_policy_manifest(root=root)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "GITHUB_ACTIONS_POLICY_MANIFEST_HASH_MISMATCH"
    assert evidence["silent_pass"] is False


def test_missing_manifest_fails_closed(tmp_path: Path) -> None:
    governance = tmp_path / "governance"
    governance.mkdir(parents=True)
    (governance / "approved_github_actions_policy.json").write_text(
        POLICY_PATH.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    evidence = verify_policy_manifest(root=tmp_path)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "GITHUB_ACTIONS_POLICY_MANIFEST_MISSING"
    assert evidence["silent_pass"] is False


def test_malformed_manifest_fails_closed(tmp_path: Path) -> None:
    root = _write_manifest_tree(tmp_path)
    (root / "governance" / "approved_github_actions_policy.manifest.json").write_text(
        "{not-json",
        encoding="utf-8",
    )

    evidence = verify_policy_manifest(root=root)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "GITHUB_ACTIONS_POLICY_MANIFEST_MALFORMED"
    assert evidence["silent_pass"] is False


def test_unknown_policy_file_fails_closed(tmp_path: Path) -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    manifest["policy_file"] = "governance/missing-policy.json"
    root = _write_manifest_tree(tmp_path, manifest=manifest)

    evidence = verify_policy_manifest(root=root)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "GITHUB_ACTIONS_POLICY_FILE_UNKNOWN"
    assert evidence["silent_pass"] is False


def test_manifest_declares_fail_closed_mismatch_behavior() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    assert manifest["fail_closed_on_manifest_mismatch"] is True


def test_approved_github_actions_policy_has_no_wildcard_approvals() -> None:
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))

    assert "*" not in policy["actions"]
    for action_name, action_policy in policy["actions"].items():
        assert "*" not in action_name
        assert action_policy["allowed_version"] != "*"
