from __future__ import annotations

from pathlib import Path

import pytest

from governance.workstation_agent import (
    ALLOW,
    BLOCK,
    HUMAN_APPROVAL_REQUIRED,
    NOT_IMPLEMENTED,
    GovernedWorkstationAgent,
    WorkstationEvidenceRecorder,
    WorkstationLockStore,
    WorkstationPolicyDecision,
    WorkstationReplayStore,
    allow_policy_decision,
    build_task_contract,
    build_workspace_registration,
    sha256_reference,
)


pytestmark = pytest.mark.governance

NOW = "2026-08-16T12:00:00Z"


def _workspace(tmp_path: Path, **overrides):
    workspace_id = overrides.pop("workspace_id", "workspace-a")
    root = tmp_path / workspace_id
    root.mkdir(exist_ok=True)
    (root / "runtime").mkdir(exist_ok=True)
    (root / "tests").mkdir(exist_ok=True)
    (root / "governance").mkdir(exist_ok=True)
    overrides["workspace_id"] = workspace_id
    return build_workspace_registration(local_root=str(root), **overrides)


def _request(**overrides):
    payload = {
        "action": "git_status",
        "workspace_id": "workspace-a",
        "repository_id": "usbay-policy-brain-public",
        "remote_identity": "https://github.com/USJAY77/usbay-policy-brain-public.git",
        "branch": "main",
        "base_sha": "a" * 40,
        "paths": ["runtime/example.py"],
        "tool": "git",
        "arguments": {},
        "network_destinations": [],
        "expected_commits": 0,
        "policy_version_hash": build_task_contract()["policy_version_hash"],
    }
    payload.update(overrides)
    return payload


def _agent(tmp_path: Path, *, workspaces=None, policy=allow_policy_decision, adapters=None, replay_store=None, lock_store=None, recorder=None):
    return GovernedWorkstationAgent(
        workspaces=workspaces if workspaces is not None else [_workspace(tmp_path)],
        policy_evaluator=policy,
        evidence_recorder=recorder,
        replay_store=replay_store,
        lock_store=lock_store,
        adapters=adapters or {"git": lambda payload: {"status": "clean", "paths": payload["paths"]}},
        clock=lambda: NOW,
    )


def test_registered_workspace_observe_action_passes_with_hash_chained_evidence(tmp_path: Path) -> None:
    recorder = WorkstationEvidenceRecorder()
    agent = _agent(tmp_path, recorder=recorder)
    result = agent.execute(build_task_contract(), _request())
    second = agent.execute(build_task_contract(nonce="nonce-2"), _request(paths=["tests/example.py"]))

    assert result.decision == ALLOW
    assert result.reason == "ACTION_ALLOWED"
    assert result.evidence["event_id"].startswith("sha256:")
    assert result.evidence["contract_hash"] == build_task_contract()["request_hash"]
    assert result.evidence["previous_evidence_hash"] == "sha256:" + ("0" * 64)
    assert second.evidence["previous_evidence_hash"] == result.evidence["event_id"]
    assert recorder.records == [result.evidence, second.evidence]


def test_unknown_workspace_blocks_before_adapter(tmp_path: Path) -> None:
    called = {"value": False}
    agent = _agent(tmp_path, adapters={"git": lambda _payload: called.update(value=True)})

    result = agent.execute(build_task_contract(), _request(workspace_id="missing"))

    assert result.decision == BLOCK
    assert result.reason == "UNKNOWN_WORKSPACE"
    assert called["value"] is False


def test_repository_identity_mismatch_blocks(tmp_path: Path) -> None:
    result = _agent(tmp_path).execute(build_task_contract(), _request(repository_id="other-repo"))

    assert result.decision == BLOCK
    assert result.reason == "REPOSITORY_IDENTITY_MISMATCH"


def test_remote_identity_mismatch_blocks(tmp_path: Path) -> None:
    result = _agent(tmp_path).execute(build_task_contract(), _request(remote_identity="https://github.com/attacker/repo.git"))

    assert result.decision == BLOCK
    assert result.reason == "REMOTE_IDENTITY_MISMATCH"


def test_wrong_branch_and_stale_sha_block(tmp_path: Path) -> None:
    assert _agent(tmp_path).execute(build_task_contract(), _request(branch="feature")).reason == "BRANCH_MISMATCH"
    assert _agent(tmp_path).execute(build_task_contract(nonce="nonce-2"), _request(base_sha="b" * 40)).reason == "STALE_BASE_SHA"


def test_expired_task_and_replayed_nonce_block(tmp_path: Path) -> None:
    assert _agent(tmp_path).execute(build_task_contract(expires_at="2026-08-16T11:59:59Z"), _request()).reason == "CONTRACT_EXPIRED"

    replay_store = WorkstationReplayStore()
    agent = _agent(tmp_path, replay_store=replay_store)
    assert agent.execute(build_task_contract(nonce="same"), _request()).decision == ALLOW
    assert agent.execute(build_task_contract(nonce="same"), _request()).reason == "CONTRACT_REPLAYED"


def test_changed_request_hash_blocks(tmp_path: Path) -> None:
    contract = build_task_contract()
    contract["allowed_actions"] = ["git_status", "merge"]

    result = _agent(tmp_path).execute(contract, _request())

    assert result.decision == BLOCK
    assert result.reason == "CONTRACT_HASH_MISMATCH"


@pytest.mark.parametrize(
    ("paths", "reason"),
    [
        (["../outside.py"], "PATH_TRAVERSAL_REJECTED"),
        (["/tmp/outside.py"], "PATH_ABSOLUTE_REJECTED"),
        (["docs/outside.md"], "PATH_NOT_IN_WORKSPACE_SCOPE"),
    ],
)
def test_path_boundary_blocks_traversal_absolute_and_out_of_scope(tmp_path: Path, paths: list[str], reason: str) -> None:
    result = _agent(tmp_path).execute(build_task_contract(), _request(paths=paths))

    assert result.decision == BLOCK
    assert result.reason == reason


def test_symlink_escape_blocks(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    root = Path(workspace["local_root"])
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "runtime" / "escape.py").symlink_to(outside)

    result = _agent(tmp_path, workspaces=[workspace]).execute(build_task_contract(), _request(paths=["runtime/escape.py"]))

    assert result.decision == BLOCK
    assert result.reason == "PATH_SYMLINK_ESCAPE_REJECTED"


def test_unauthorized_command_tool_and_network_block_before_adapter(tmp_path: Path) -> None:
    agent = _agent(tmp_path)

    assert agent.execute(build_task_contract(), _request(action="write_file")).reason == "ACTION_NOT_AUTHORIZED"
    assert agent.execute(build_task_contract(nonce="tool"), _request(tool="cloud")).reason == "TOOL_NOT_AUTHORIZED"
    assert (
        agent.execute(build_task_contract(nonce="network"), _request(network_destinations=["https://example.com"])).reason
        == "NETWORK_DESTINATION_NOT_AUTHORIZED"
    )
    assert agent.execute(build_task_contract(nonce="shell", allowed_actions=["shell"]), _request(action="shell")).reason == "ACTION_FORBIDDEN"


def test_authorized_network_destination_and_bounded_write_review_gate(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, allowed_network_destinations=["https://api.github.com"])
    agent = _agent(tmp_path, workspaces=[workspace], adapters={"github": lambda _payload: {"ok": True}, "filesystem": lambda _payload: {"ok": True}})

    network_contract = build_task_contract(
        nonce="network-allow",
        allowed_actions=["inspect_pr"],
        allowed_tools=["github"],
        allowed_network_destinations=["https://api.github.com"],
    )
    network_result = agent.execute(
        network_contract,
        _request(action="inspect_pr", tool="github", network_destinations=["https://api.github.com"], paths=[]),
    )
    assert network_result.decision == ALLOW

    write_contract = build_task_contract(nonce="write", allowed_actions=["write_file"], allowed_tools=["filesystem"], requires_human_review=False)
    write_result = agent.execute(write_contract, _request(action="write_file", tool="filesystem", paths=["runtime/example.py"]))
    assert write_result.decision == BLOCK
    assert write_result.reason == "HUMAN_REVIEW_REQUIRED_FOR_WRITE"


@pytest.mark.parametrize("action", ["force_push", "merge", "deploy", "iam_change", "secret_change", "autonomous_policy_create", "autonomous_policy_mutate"])
def test_forbidden_and_human_gated_actions_never_auto_execute(tmp_path: Path, action: str) -> None:
    called = {"value": False}
    result = _agent(tmp_path, adapters={"git": lambda _payload: called.update(value=True)}).execute(
        build_task_contract(allowed_actions=[action], forbidden_actions=["force_push", "autonomous_policy_create", "autonomous_policy_mutate"]),
        _request(action=action),
    )

    if action in {"merge", "deploy", "iam_change", "secret_change"}:
        assert result.decision == HUMAN_APPROVAL_REQUIRED
        assert result.reason == "HUMAN_APPROVAL_REQUIRED"
    else:
        assert result.decision == BLOCK
        assert result.reason == "ACTION_FORBIDDEN"
    assert called["value"] is False


def test_unavailable_adapter_reports_not_implemented(tmp_path: Path) -> None:
    result = _agent(tmp_path, adapters={}).execute(build_task_contract(allowed_tools=["github"], allowed_actions=["inspect_pr"]), _request(action="inspect_pr", tool="github"))

    assert result.decision == BLOCK
    assert result.reason == "ADAPTER_NOT_IMPLEMENTED"


def test_policy_unavailable_denied_or_mismatched_blocks(tmp_path: Path) -> None:
    assert _agent(tmp_path, policy=lambda _c, _a: None).execute(build_task_contract(), _request()).reason == "POLICY_UNAVAILABLE"
    assert _agent(
        tmp_path,
        policy=lambda c, _a: WorkstationPolicyDecision(BLOCK, "DENY", c["policy_id"], c["policy_version_hash"], sha256_reference("policy")),
    ).execute(build_task_contract(), _request()).reason == "POLICY_DENIED"
    assert _agent(
        tmp_path,
        policy=lambda c, _a: WorkstationPolicyDecision(ALLOW, "ALLOW", c["policy_id"], sha256_reference("other"), sha256_reference("policy")),
    ).execute(build_task_contract(), _request()).reason == "POLICY_VERSION_MISMATCH"


def test_evidence_recorder_unavailable_fails_closed(tmp_path: Path) -> None:
    class FailingRecorder:
        def record(self, _payload):
            raise RuntimeError("recorder unavailable")

    result = _agent(tmp_path, recorder=FailingRecorder()).execute(build_task_contract(), _request())

    assert result.decision == BLOCK
    assert result.reason == "EVIDENCE_RECORDER_UNAVAILABLE"


def test_concurrent_conflicting_task_blocks_and_audits_lock(tmp_path: Path) -> None:
    lock_store = WorkstationLockStore()
    assert lock_store.acquire("workspace-a", "usbay-policy-brain-public", task_id="other", timestamp=NOW) is True

    result = _agent(tmp_path, lock_store=lock_store).execute(build_task_contract(), _request())

    assert result.decision == BLOCK
    assert result.reason == "CONCURRENT_TASK_CONFLICT"
    assert any(event["lock_result"] == "LOCK_CONFLICT" for event in lock_store.audit)


def test_multi_repository_task_isolation_and_explicit_dual_scope(tmp_path: Path) -> None:
    ws_a = _workspace(tmp_path, workspace_id="workspace-a", repository_name="repo-a", remote_identity="https://github.com/USJAY77/repo-a.git")
    ws_b = _workspace(tmp_path, workspace_id="workspace-b", repository_name="repo-b", remote_identity="https://github.com/USJAY77/repo-b.git")
    agent = _agent(tmp_path, workspaces=[ws_a, ws_b])

    contract_a = build_task_contract(workspace_ids=["workspace-a"], repository_ids=["repo-a"], nonce="a")
    req_b = _request(
        workspace_id="workspace-b",
        repository_id="repo-b",
        remote_identity="https://github.com/USJAY77/repo-b.git",
    )
    assert agent.execute(contract_a, req_b).reason == "WORKSPACE_NOT_AUTHORIZED"

    contract_ab = build_task_contract(workspace_ids=["workspace-a", "workspace-b"], repository_ids=["repo-a", "repo-b"], nonce="ab")
    assert agent.execute(contract_ab, req_b).decision == ALLOW


def test_workspace_policy_cannot_be_substituted(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    workspace["policy_binding"]["policy_version_hash"] = sha256_reference({"policy": "different"})
    result = _agent(tmp_path, workspaces=[workspace]).execute(build_task_contract(), _request())

    assert result.decision == BLOCK
    assert result.reason == "POLICY_VERSION_MISMATCH"
