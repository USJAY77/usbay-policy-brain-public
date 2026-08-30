from __future__ import annotations

from pathlib import Path

import pytest

from governance.workstation_agent import (
    ALLOW,
    BLOCK,
    FAILED,
    HUMAN_APPROVAL_REQUIRED,
    NOT_IMPLEMENTED,
    GovernedTaskDispatcher,
    GovernedWorkstationRouter,
    GovernedWorkstationAgent,
    WorkstationAdapterDescriptor,
    WorkstationAdapterRegistry,
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


def _router(*, workspaces, recorder=None, replay_store=None):
    return GovernedWorkstationRouter(
        workspaces=workspaces,
        evidence_recorder=recorder,
        replay_store=replay_store,
        clock=lambda: NOW,
    )


def _routing_request(workspace, **overrides):
    repository_id = workspace["repository_name"]
    payload = {
        "workspace_ids": [workspace["workspace_id"]],
        "repository_ids": [repository_id],
        "remote_identities": {repository_id: workspace["remote_identity"]},
        "local_roots": {repository_id: workspace["local_root"]},
        "branch": "main",
        "base_shas": {repository_id: "a" * 40},
        "paths_by_repository": {repository_id: ["runtime/example.py"]},
        "action_class": "OBSERVE",
        "policy_id": build_task_contract()["policy_id"],
        "policy_version_hash": build_task_contract()["policy_version_hash"],
        "requires_human_review": False,
    }
    payload.update(overrides)
    return payload


def _approval(contract, repositories, **overrides):
    payload = {
        "approved": True,
        "contract_hash": contract["request_hash"],
        "repository_ids": repositories,
        "policy_id": contract["policy_id"],
        "policy_version_hash": contract["policy_version_hash"],
        "expires_at": "2026-08-16T13:00:00Z",
        "nonce": "approval-1",
    }
    payload.update(overrides)
    return payload


def _dispatch_contract(**overrides):
    payload = {"action_class": "OBSERVE"}
    payload.update(overrides)
    return build_task_contract(**payload)


def _dispatch_request(workspace, **overrides):
    repository_id = workspace["repository_name"]
    payload = {
        "action": "git_status",
        "adapter": "git",
        "workspace_ids": [workspace["workspace_id"]],
        "repository_ids": [repository_id],
        "remote_identities": {repository_id: workspace["remote_identity"]},
        "local_roots": {repository_id: workspace["local_root"]},
        "branch": "main",
        "base_shas": {repository_id: "a" * 40},
        "paths_by_repository": {repository_id: ["runtime/example.py"]},
        "action_class": "OBSERVE",
        "policy_id": build_task_contract()["policy_id"],
        "policy_version_hash": build_task_contract()["policy_version_hash"],
        "requires_human_review": False,
        "arguments": {},
    }
    payload.update(overrides)
    return payload


def _adapter_descriptor(**overrides):
    payload = {
        "adapter_id": "git",
        "adapter_type": "git",
        "allowed_action_classes": ("OBSERVE",),
        "adapter_version": "test-git-adapter-v1",
        "invocation_schema": "usbay.workstation.adapter.invocation.v1",
    }
    payload.update(overrides)
    return WorkstationAdapterDescriptor(**payload)


def _dispatcher(*, workspaces, adapters=None, adapter_registry=None, recorder=None, replay_store=None, lock_store=None):
    return GovernedTaskDispatcher(
        workspaces=workspaces,
        adapters=adapters
        if adapters is not None
        else {"git": lambda payload: {"status": "OK", "metadata": {"repositories": len(payload["repositories"])}}},
        adapter_registry=adapter_registry,
        evidence_recorder=recorder,
        replay_store=replay_store,
        lock_store=lock_store,
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


def test_router_allows_only_registered_workspace_without_repository_mutation(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    before = sorted(path.relative_to(Path(workspace["local_root"])).as_posix() for path in Path(workspace["local_root"]).rglob("*"))

    result = _router(workspaces=[workspace]).route(build_task_contract(), _routing_request(workspace))
    after = sorted(path.relative_to(Path(workspace["local_root"])).as_posix() for path in Path(workspace["local_root"]).rglob("*"))

    assert result.decision == ALLOW
    assert result.reason == "ROUTE_ALLOWED"
    assert result.selected_repositories == ("usbay-policy-brain-public",)
    assert result.evidence["repository_mutation"] is False
    assert result.evidence["autonomous_repository_registration"] is False
    assert before == after


def test_router_rejects_unknown_disabled_or_ambiguous_repositories(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    disabled = _workspace(tmp_path, workspace_id="disabled", enabled=False)
    duplicate = dict(workspace)
    duplicate["local_root"] = str(tmp_path / "duplicate")
    Path(duplicate["local_root"]).mkdir()

    assert _router(workspaces=[]).route(build_task_contract(), _routing_request(workspace)).reason == "ROUTING_AMBIGUOUS_OR_UNKNOWN_REPOSITORY"
    assert _router(workspaces=[disabled]).route(
        build_task_contract(workspace_ids=["disabled"]),
        _routing_request(disabled),
    ).reason == "ROUTING_WORKSPACE_DISABLED"
    assert _router(workspaces=[workspace, duplicate]).route(build_task_contract(), _routing_request(workspace)).reason == "ROUTING_AMBIGUOUS_OR_UNKNOWN_REPOSITORY"


def test_router_requires_canonical_remote_and_policy_binding(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    wrong_policy = _workspace(tmp_path, workspace_id="wrong-policy")
    wrong_policy["policy_binding"]["policy_version_hash"] = sha256_reference({"policy": "other"})

    assert _router(workspaces=[workspace]).route(
        build_task_contract(),
        _routing_request(workspace, remote_identities={workspace["repository_name"]: "https://github.com/attacker/repo.git"}),
    ).reason == "ROUTING_REMOTE_IDENTITY_MISMATCH"
    assert _router(workspaces=[workspace]).route(
        build_task_contract(),
        _routing_request(workspace, local_roots={workspace["repository_name"]: str(tmp_path / "elsewhere")}),
    ).reason == "ROUTING_CANONICAL_ROOT_MISMATCH"
    assert _router(workspaces=[wrong_policy]).route(
        build_task_contract(workspace_ids=["wrong-policy"]),
        _routing_request(wrong_policy),
    ).reason == "ROUTING_POLICY_VERSION_MISMATCH"


@pytest.mark.parametrize(
    ("request_overrides", "reason"),
    [
        ({"action_class": "FORBIDDEN"}, "ROUTING_ACTION_CLASS_NOT_AUTHORIZED"),
        ({"branch": "feature"}, "ROUTING_BRANCH_MISMATCH"),
    ],
)
def test_router_blocks_unauthorized_action_class_and_branch(request_overrides, reason, tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)

    result = _router(workspaces=[workspace]).route(build_task_contract(), _routing_request(workspace, **request_overrides))

    assert result.decision == BLOCK
    assert result.reason == reason


@pytest.mark.parametrize(
    ("paths", "reason"),
    [
        (["../outside.py"], "ROUTING_PATH_TRAVERSAL_REJECTED"),
        (["/tmp/outside.py"], "ROUTING_PATH_ABSOLUTE_REJECTED"),
        (["docs/outside.md"], "ROUTING_PATH_NOT_IN_WORKSPACE_SCOPE"),
    ],
)
def test_router_blocks_path_escape_variants(paths, reason, tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    request = _routing_request(workspace, paths_by_repository={workspace["repository_name"]: paths})

    result = _router(workspaces=[workspace]).route(build_task_contract(), request)

    assert result.decision == BLOCK
    assert result.reason == reason


def test_router_blocks_symlink_escape(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (Path(workspace["local_root"]) / "runtime" / "escape.py").symlink_to(outside)

    result = _router(workspaces=[workspace]).route(
        build_task_contract(),
        _routing_request(workspace, paths_by_repository={workspace["repository_name"]: ["runtime/escape.py"]}),
    )

    assert result.decision == BLOCK
    assert result.reason == "ROUTING_PATH_SYMLINK_ESCAPE_REJECTED"


def test_router_requires_explicit_multi_repository_authorization(tmp_path: Path) -> None:
    ws_a = _workspace(tmp_path, workspace_id="workspace-a", repository_name="repo-a", remote_identity="https://github.com/USJAY77/repo-a.git")
    ws_b = _workspace(tmp_path, workspace_id="workspace-b", repository_name="repo-b", remote_identity="https://github.com/USJAY77/repo-b.git")
    contract = build_task_contract(workspace_ids=["workspace-a", "workspace-b"], repository_ids=["repo-a", "repo-b"])
    request = _routing_request(
        ws_a,
        workspace_ids=["workspace-a", "workspace-b"],
        repository_ids=["repo-a", "repo-b"],
        remote_identities={"repo-a": ws_a["remote_identity"], "repo-b": ws_b["remote_identity"]},
        local_roots={"repo-a": ws_a["local_root"], "repo-b": ws_b["local_root"]},
        base_shas={"repo-a": "a" * 40, "repo-b": "a" * 40},
        paths_by_repository={"repo-a": ["runtime/example.py"], "repo-b": ["tests/example.py"]},
    )

    assert _router(workspaces=[ws_a, ws_b]).route(contract, request).reason == "MULTI_REPOSITORY_AUTHORIZATION_MISSING"
    allowed = _router(workspaces=[ws_a, ws_b]).route(build_task_contract(workspace_ids=["workspace-a", "workspace-b"], repository_ids=["repo-a", "repo-b"], nonce="multi"), {**request, "multi_repository_authorized": True})
    assert allowed.decision == ALLOW
    assert allowed.selected_repositories == ("repo-a", "repo-b")


def test_router_blocks_stale_repository_state(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, current_sha="b" * 40)

    result = _router(workspaces=[workspace]).route(build_task_contract(), _routing_request(workspace))

    assert result.decision == BLOCK
    assert result.reason == "ROUTING_STALE_REPOSITORY_STATE"


def test_router_requires_bound_human_review_and_rejects_replay(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, requires_human_review=True)
    replay_store = WorkstationReplayStore()
    router = _router(workspaces=[workspace], replay_store=replay_store)
    contract = build_task_contract()
    request = _routing_request(workspace, requires_human_review=True)

    assert router.route(contract, request).reason == "ROUTING_HUMAN_REVIEW_REQUIRED"
    assert router.route(build_task_contract(nonce="review-1"), request, human_approval=_approval(contract, ["wrong"])).reason == "ROUTING_HUMAN_APPROVAL_BINDING_MISMATCH"

    contract_two = build_task_contract(nonce="review-2")
    approval = _approval(contract_two, ["usbay-policy-brain-public"], nonce="approval-replay")
    assert router.route(contract_two, request, human_approval=approval).decision == ALLOW
    contract_three = build_task_contract(nonce="review-3")
    replayed = _approval(contract_three, ["usbay-policy-brain-public"], nonce="approval-replay")
    assert router.route(contract_three, request, human_approval=replayed).reason == "ROUTING_HUMAN_APPROVAL_REPLAYED"


def test_router_records_hash_chained_decision_evidence(tmp_path: Path) -> None:
    recorder = WorkstationEvidenceRecorder()
    workspace = _workspace(tmp_path)
    router = _router(workspaces=[workspace], recorder=recorder)

    first = router.route(build_task_contract(nonce="route-1"), _routing_request(workspace))
    second = router.route(build_task_contract(nonce="route-2"), _routing_request(workspace))

    assert first.evidence["event_id"].startswith("sha256:")
    assert first.evidence["previous_evidence_hash"] == "sha256:" + ("0" * 64)
    assert second.evidence["previous_evidence_hash"] == first.evidence["event_id"]
    assert second.evidence["autonomous_policy_creation"] is False
    assert second.evidence["policy_mutation"] is False


def test_router_fails_closed_when_evidence_recorder_is_unavailable(tmp_path: Path) -> None:
    class FailingRecorder:
        def record(self, _payload):
            raise RuntimeError("recorder unavailable")

    workspace = _workspace(tmp_path)
    result = _router(workspaces=[workspace], recorder=FailingRecorder()).route(build_task_contract(), _routing_request(workspace))

    assert result.decision == BLOCK
    assert result.reason == "ROUTING_EVIDENCE_RECORDER_UNAVAILABLE"


def test_router_does_not_autonomously_register_discovered_repository(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    unregistered_root = tmp_path / "unregistered"
    unregistered_root.mkdir()
    request = _routing_request(
        workspace,
        workspace_ids=["unregistered"],
        repository_ids=["unregistered-repo"],
        remote_identities={"unregistered-repo": "https://github.com/USJAY77/unregistered.git"},
        local_roots={"unregistered-repo": str(unregistered_root)},
        base_shas={"unregistered-repo": "a" * 40},
        paths_by_repository={"unregistered-repo": ["runtime/example.py"]},
    )

    result = _router(workspaces=[workspace]).route(
        build_task_contract(workspace_ids=["workspace-a", "unregistered"], repository_ids=["usbay-policy-brain-public", "unregistered-repo"]),
        request,
    )

    assert result.decision == BLOCK
    assert result.reason == "ROUTING_AMBIGUOUS_OR_UNKNOWN_REPOSITORY"
    assert result.evidence["autonomous_repository_registration"] is False


def test_dispatcher_allows_valid_registered_workspace_task(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    result = _dispatcher(workspaces=[workspace]).dispatch(_dispatch_contract(), _dispatch_request(workspace))

    assert result.decision == ALLOW
    assert result.reason == "DISPATCH_INVOKED"
    assert result.adapter_result["status"] == "OK"
    assert result.evidence["schema"] == "usbay.governed_workstation_dispatch.evidence.v1"
    assert result.evidence["workspace_id"] == "workspace-a"
    assert result.evidence["repository_id"] == "usbay-policy-brain-public"
    assert result.evidence["adapter_selected"] == "git"
    assert result.evidence["invocation_status"] == "INVOKED"


def test_dispatcher_allows_explicit_multi_workspace_dispatch(tmp_path: Path) -> None:
    ws_a = _workspace(tmp_path, workspace_id="workspace-a", repository_name="repo-a", remote_identity="https://github.com/USJAY77/repo-a.git")
    ws_b = _workspace(tmp_path, workspace_id="workspace-b", repository_name="repo-b", remote_identity="https://github.com/USJAY77/repo-b.git")
    contract = _dispatch_contract(workspace_ids=["workspace-a", "workspace-b"], repository_ids=["repo-a", "repo-b"])
    request = _dispatch_request(
        ws_a,
        workspace_ids=["workspace-a", "workspace-b"],
        repository_ids=["repo-a", "repo-b"],
        remote_identities={"repo-a": ws_a["remote_identity"], "repo-b": ws_b["remote_identity"]},
        local_roots={"repo-a": ws_a["local_root"], "repo-b": ws_b["local_root"]},
        base_shas={"repo-a": "a" * 40, "repo-b": "a" * 40},
        paths_by_repository={"repo-a": ["runtime/example.py"], "repo-b": ["tests/example.py"]},
        multi_repository_authorized=True,
    )

    result = _dispatcher(workspaces=[ws_a, ws_b]).dispatch(contract, request)

    assert result.decision == ALLOW
    assert result.adapter_result["status"] == "OK"
    assert result.evidence["repository_ids"] == ["repo-a", "repo-b"]


@pytest.mark.parametrize(
    ("contract_overrides", "request_overrides", "workspace_overrides", "reason"),
    [
        ({}, {"workspace_ids": ["missing"]}, {}, "ROUTING_WORKSPACE_NOT_AUTHORIZED"),
        ({}, {"repository_ids": ["missing"]}, {}, "ROUTING_REPOSITORY_NOT_AUTHORIZED"),
        ({"workspace_ids": ["disabled"]}, {}, {"workspace_id": "disabled", "enabled": False}, "ROUTING_WORKSPACE_DISABLED"),
        ({}, {"remote_identities": {"usbay-policy-brain-public": "https://github.com/attacker/repo.git"}}, {}, "ROUTING_REMOTE_IDENTITY_MISMATCH"),
        ({}, {"local_roots": {"usbay-policy-brain-public": "/tmp/not-this-repo"}}, {}, "ROUTING_CANONICAL_ROOT_MISMATCH"),
        ({}, {}, {"current_sha": "b" * 40}, "ROUTING_STALE_REPOSITORY_STATE"),
        ({}, {"branch": "feature"}, {}, "ROUTING_BRANCH_MISMATCH"),
        ({}, {"policy_id": "other-policy"}, {}, "DISPATCH_POLICY_ID_MISMATCH"),
        ({}, {"policy_version_hash": sha256_reference({"policy": "other"})}, {}, "DISPATCH_POLICY_VERSION_MISMATCH"),
        ({"action_class": "OBSERVE"}, {"action_class": "FORBIDDEN"}, {}, "DISPATCH_ACTION_CLASS_MISMATCH"),
    ],
)
def test_dispatcher_blocks_identity_policy_and_authority_failures(
    contract_overrides,
    request_overrides,
    workspace_overrides,
    reason,
    tmp_path: Path,
) -> None:
    called = {"value": False}
    workspace = _workspace(tmp_path, **workspace_overrides)
    contract = _dispatch_contract(**contract_overrides)
    request = _dispatch_request(workspace, **request_overrides)

    result = _dispatcher(workspaces=[workspace], adapters={"git": lambda _payload: called.update(value=True)}).dispatch(contract, request)

    assert result.decision == BLOCK
    assert result.reason == reason
    assert called["value"] is False


def test_dispatcher_blocks_ambiguous_repository_before_adapter(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    duplicate = dict(workspace)
    duplicate["local_root"] = str(tmp_path / "duplicate")
    Path(duplicate["local_root"]).mkdir()
    called = {"value": False}

    result = _dispatcher(
        workspaces=[workspace, duplicate],
        adapters={"git": lambda _payload: called.update(value=True)},
    ).dispatch(_dispatch_contract(), _dispatch_request(workspace))

    assert result.decision == BLOCK
    assert result.reason == "ROUTING_AMBIGUOUS_OR_UNKNOWN_REPOSITORY"
    assert called["value"] is False


@pytest.mark.parametrize(
    ("paths", "reason"),
    [
        (["../outside.py"], "ROUTING_PATH_TRAVERSAL_REJECTED"),
        (["/tmp/outside.py"], "ROUTING_PATH_ABSOLUTE_REJECTED"),
        (["docs/outside.md"], "ROUTING_PATH_NOT_IN_WORKSPACE_SCOPE"),
    ],
)
def test_dispatcher_blocks_path_boundary_failures(paths, reason, tmp_path: Path) -> None:
    called = {"value": False}
    workspace = _workspace(tmp_path)
    request = _dispatch_request(workspace, paths_by_repository={workspace["repository_name"]: paths})

    result = _dispatcher(workspaces=[workspace], adapters={"git": lambda _payload: called.update(value=True)}).dispatch(_dispatch_contract(), request)

    assert result.decision == BLOCK
    assert result.reason == reason
    assert called["value"] is False


def test_dispatcher_blocks_symlink_escape(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (Path(workspace["local_root"]) / "runtime" / "escape.py").symlink_to(outside)

    result = _dispatcher(workspaces=[workspace]).dispatch(
        _dispatch_contract(),
        _dispatch_request(workspace, paths_by_repository={workspace["repository_name"]: ["runtime/escape.py"]}),
    )

    assert result.decision == BLOCK
    assert result.reason == "ROUTING_PATH_SYMLINK_ESCAPE_REJECTED"


def test_dispatcher_blocks_expired_malformed_and_replayed_contract(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    replay_store = WorkstationReplayStore()
    dispatcher = _dispatcher(workspaces=[workspace], replay_store=replay_store)
    malformed = _dispatch_contract()
    del malformed["action_class"]

    assert dispatcher.dispatch(_dispatch_contract(expires_at="2026-08-16T11:59:59Z"), _dispatch_request(workspace)).reason == "DISPATCH_CONTRACT_EXPIRED"
    assert dispatcher.dispatch(malformed, _dispatch_request(workspace)).reason == "DISPATCH_CONTRACT_MALFORMED"
    assert dispatcher.dispatch(_dispatch_contract(nonce="same"), _dispatch_request(workspace)).decision == ALLOW
    assert dispatcher.dispatch(_dispatch_contract(nonce="same"), _dispatch_request(workspace)).reason == "ROUTING_CONTRACT_REPLAYED"


def test_dispatcher_requires_valid_human_approval_and_rejects_replay(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, requires_human_review=True)
    replay_store = WorkstationReplayStore()
    dispatcher = _dispatcher(workspaces=[workspace], replay_store=replay_store)
    request = _dispatch_request(workspace, requires_human_review=True)

    assert dispatcher.dispatch(_dispatch_contract(nonce="review-0"), request).reason == "ROUTING_HUMAN_REVIEW_REQUIRED"
    contract_one = _dispatch_contract(nonce="review-1")
    assert dispatcher.dispatch(contract_one, request, human_approval=_approval(contract_one, ["wrong"])).reason == "ROUTING_HUMAN_APPROVAL_BINDING_MISMATCH"
    contract_two = _dispatch_contract(nonce="review-2")
    expired = _approval(contract_two, ["usbay-policy-brain-public"], expires_at="2026-08-16T11:59:59Z")
    assert dispatcher.dispatch(contract_two, request, human_approval=expired).reason == "ROUTING_HUMAN_APPROVAL_EXPIRED"
    contract_three = _dispatch_contract(nonce="review-3")
    approval = _approval(contract_three, ["usbay-policy-brain-public"], nonce="approval-same")
    assert dispatcher.dispatch(contract_three, request, human_approval=approval).decision == ALLOW
    contract_four = _dispatch_contract(nonce="review-4")
    replayed = _approval(contract_four, ["usbay-policy-brain-public"], nonce="approval-same")
    assert dispatcher.dispatch(contract_four, request, human_approval=replayed).reason == "ROUTING_HUMAN_APPROVAL_REPLAYED"


def test_dispatcher_blocks_evidence_recorder_failure_before_adapter(tmp_path: Path) -> None:
    class FailingRecorder:
        def record(self, _payload):
            raise RuntimeError("recorder unavailable")

    called = {"value": False}
    workspace = _workspace(tmp_path)
    result = _dispatcher(
        workspaces=[workspace],
        recorder=FailingRecorder(),
        adapters={"git": lambda _payload: called.update(value=True)},
    ).dispatch(_dispatch_contract(), _dispatch_request(workspace))

    assert result.decision == BLOCK
    assert result.reason == "DISPATCH_EVIDENCE_RECORDER_UNAVAILABLE"
    assert called["value"] is False


def test_dispatcher_blocks_concurrency_conflict_before_adapter(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    lock_store = WorkstationLockStore()
    assert lock_store.acquire("workspace-a", "usbay-policy-brain-public", task_id="other", timestamp=NOW) is True
    called = {"value": False}

    result = _dispatcher(
        workspaces=[workspace],
        lock_store=lock_store,
        adapters={"git": lambda _payload: called.update(value=True)},
    ).dispatch(_dispatch_contract(), _dispatch_request(workspace))

    assert result.decision == BLOCK
    assert result.reason == "DISPATCH_CONCURRENT_TASK_CONFLICT"
    assert called["value"] is False
    assert any(event["lock_result"] == "LOCK_CONFLICT" for event in lock_store.audit)


def test_dispatcher_records_hash_chained_decision_evidence(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    recorder = WorkstationEvidenceRecorder()
    dispatcher = _dispatcher(workspaces=[workspace], recorder=recorder)

    first = dispatcher.dispatch(_dispatch_contract(nonce="dispatch-1"), _dispatch_request(workspace))
    second = dispatcher.dispatch(_dispatch_contract(nonce="dispatch-2"), _dispatch_request(workspace))

    assert first.evidence["event_id"].startswith("sha256:")
    assert first.evidence["previous_evidence_hash"].startswith("sha256:")
    assert second.evidence["previous_evidence_hash"].startswith("sha256:")
    assert second.evidence["policy_mutation"] is False
    assert second.evidence["autonomous_repository_registration"] is False


def test_dispatcher_never_adds_autonomous_or_unrestricted_capabilities(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    result = _dispatcher(workspaces=[workspace]).dispatch(_dispatch_contract(), _dispatch_request(workspace))

    assert result.evidence["autonomous_policy_creation"] is False
    assert result.evidence["policy_mutation"] is False
    assert result.evidence["autonomous_repository_registration"] is False
    assert result.evidence["autonomous_authority_expansion"] is False
    assert result.evidence["autonomous_merge"] is False
    assert result.evidence["autonomous_deploy"] is False
    assert result.evidence["unrestricted_shell"] is False
    assert result.evidence["unrestricted_network"] is False
    assert result.evidence["unrestricted_filesystem"] is False


def test_adapter_registry_invokes_registered_adapter_once_and_records_post_evidence(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    recorder = WorkstationEvidenceRecorder()
    calls = {"count": 0}

    def adapter(payload):
        calls["count"] += 1
        return {"status": "OK", "metadata": {"adapter": payload["adapter"]}}

    result = _dispatcher(
        workspaces=[workspace],
        adapters={"git": adapter},
        adapter_registry=[_adapter_descriptor(allowed_workspace_ids=("workspace-a",), allowed_repository_ids=("usbay-policy-brain-public",))],
        recorder=recorder,
    ).dispatch(_dispatch_contract(), _dispatch_request(workspace))

    assert result.decision == ALLOW
    assert result.reason == "DISPATCH_INVOKED"
    assert calls["count"] == 1
    assert result.evidence["adapter_id"] == "git"
    assert result.evidence["adapter_version"] == "test-git-adapter-v1"
    assert result.evidence["invocation_status"] == "INVOKED"
    assert recorder.records[-1]["previous_evidence_hash"] == recorder.records[-2]["event_id"]


@pytest.mark.parametrize(
    ("registry", "adapter_name", "reason"),
    [
        ([], "git", "DISPATCH_ADAPTER_UNKNOWN"),
        ([_adapter_descriptor(enabled=False)], "git", "DISPATCH_ADAPTER_DISABLED"),
        ([_adapter_descriptor(), _adapter_descriptor(adapter_version="test-git-adapter-v2")], "git", "DISPATCH_ADAPTER_AMBIGUOUS"),
        ([_adapter_descriptor(allowed_action_classes=("BOUNDED_WRITE",))], "git", "DISPATCH_ADAPTER_ACTION_CLASS_MISMATCH"),
        ([_adapter_descriptor(allowed_workspace_ids=("workspace-b",))], "git", "DISPATCH_ADAPTER_WORKSPACE_MISMATCH"),
        ([_adapter_descriptor(allowed_repository_ids=("other-repo",))], "git", "DISPATCH_ADAPTER_REPOSITORY_MISMATCH"),
        ([_adapter_descriptor(adapter_id="filesystem", adapter_type="filesystem")], "unknown", "DISPATCH_ADAPTER_UNKNOWN"),
    ],
)
def test_adapter_registry_blocks_invalid_resolution_and_authority(registry, adapter_name, reason, tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    calls = {"count": 0}
    request = _dispatch_request(workspace, adapter=adapter_name)

    result = _dispatcher(
        workspaces=[workspace],
        adapters={"git": lambda _payload: calls.update(count=calls["count"] + 1)},
        adapter_registry=registry,
    ).dispatch(_dispatch_contract(), request)

    assert result.decision == BLOCK
    assert result.reason == reason
    assert calls["count"] == 0


def test_adapter_registry_blocks_callable_missing_before_invocation(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    result = _dispatcher(
        workspaces=[workspace],
        adapters={},
        adapter_registry=[_adapter_descriptor()],
    ).dispatch(_dispatch_contract(), _dispatch_request(workspace))

    assert result.decision == BLOCK
    assert result.reason == "DISPATCH_ADAPTER_CALLABLE_MISSING"


@pytest.mark.parametrize(
    ("contract_overrides", "request_overrides", "workspace_overrides", "reason"),
    [
        ({}, {"policy_id": "other-policy"}, {}, "DISPATCH_POLICY_ID_MISMATCH"),
        ({}, {"policy_version_hash": sha256_reference({"policy": "other"})}, {}, "DISPATCH_POLICY_VERSION_MISMATCH"),
        ({}, {"branch": "feature"}, {}, "ROUTING_BRANCH_MISMATCH"),
        ({}, {}, {"current_sha": "b" * 40}, "ROUTING_STALE_REPOSITORY_STATE"),
        ({}, {"paths_by_repository": {"usbay-policy-brain-public": ["../outside.py"]}}, {}, "ROUTING_PATH_TRAVERSAL_REJECTED"),
    ],
)
def test_adapter_invocation_blocks_upstream_dispatch_failures(contract_overrides, request_overrides, workspace_overrides, reason, tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, **workspace_overrides)
    calls = {"count": 0}

    result = _dispatcher(
        workspaces=[workspace],
        adapters={"git": lambda _payload: calls.update(count=calls["count"] + 1)},
        adapter_registry=[_adapter_descriptor()],
    ).dispatch(_dispatch_contract(**contract_overrides), _dispatch_request(workspace, **request_overrides))

    assert result.decision == BLOCK
    assert result.reason == reason
    assert calls["count"] == 0


def test_adapter_invocation_replay_blocks_second_execution(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    replay_store = WorkstationReplayStore()
    calls = {"count": 0}

    def adapter(_payload):
        calls["count"] += 1
        return {"status": "OK", "metadata": {}}

    dispatcher = _dispatcher(
        workspaces=[workspace],
        adapters={"git": adapter},
        adapter_registry=[_adapter_descriptor()],
        replay_store=replay_store,
    )

    assert dispatcher.dispatch(_dispatch_contract(nonce="same"), _dispatch_request(workspace)).decision == ALLOW
    assert dispatcher.dispatch(_dispatch_contract(nonce="same"), _dispatch_request(workspace)).decision == BLOCK
    assert calls["count"] == 1


def test_adapter_invocation_concurrency_conflict_blocks_before_side_effect(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    lock_store = WorkstationLockStore()
    assert lock_store.acquire("workspace-a", "usbay-policy-brain-public", task_id="other", timestamp=NOW) is True
    calls = {"count": 0}

    result = _dispatcher(
        workspaces=[workspace],
        adapters={"git": lambda _payload: calls.update(count=calls["count"] + 1)},
        adapter_registry=[_adapter_descriptor()],
        lock_store=lock_store,
    ).dispatch(_dispatch_contract(), _dispatch_request(workspace))

    assert result.decision == BLOCK
    assert result.reason == "DISPATCH_CONCURRENT_TASK_CONFLICT"
    assert calls["count"] == 0


def test_adapter_invocation_malformed_result_is_controlled_failure(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    calls = {"count": 0}

    def adapter(_payload):
        calls["count"] += 1
        return "raw-result"

    result = _dispatcher(
        workspaces=[workspace],
        adapters={"git": adapter},
        adapter_registry=[_adapter_descriptor()],
    ).dispatch(_dispatch_contract(), _dispatch_request(workspace))

    assert result.decision == FAILED
    assert result.reason == "DISPATCH_ADAPTER_RESULT_MALFORMED"
    assert result.adapter_result["status"] == "REJECTED"
    assert calls["count"] == 1


def test_adapter_invocation_exception_is_controlled_failure_without_secret_leak(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    calls = {"count": 0}

    def adapter(_payload):
        calls["count"] += 1
        raise RuntimeError("token=do-not-log")

    result = _dispatcher(
        workspaces=[workspace],
        adapters={"git": adapter},
        adapter_registry=[_adapter_descriptor()],
    ).dispatch(_dispatch_contract(), _dispatch_request(workspace))

    assert result.decision == FAILED
    assert result.reason == "DISPATCH_ADAPTER_FAILED"
    assert calls["count"] == 1
    assert "token" not in str(result.evidence)


def test_post_invocation_evidence_failure_does_not_report_success(tmp_path: Path) -> None:
    class FailsOnPostInvocation:
        def __init__(self):
            self.records = []
            self.previous_evidence_hash = "sha256:" + ("0" * 64)

        def record(self, payload):
            if len(self.records) >= 2:
                raise RuntimeError("post evidence unavailable")
            event = dict(payload)
            event["previous_evidence_hash"] = self.previous_evidence_hash
            event["event_id"] = sha256_reference(event)
            self.previous_evidence_hash = event["event_id"]
            self.records.append(event)
            return event

    workspace = _workspace(tmp_path)
    calls = {"count": 0}

    def adapter(_payload):
        calls["count"] += 1
        return {"status": "OK", "metadata": {}}

    result = _dispatcher(
        workspaces=[workspace],
        adapters={"git": adapter},
        adapter_registry=[_adapter_descriptor()],
        recorder=FailsOnPostInvocation(),
    ).dispatch(_dispatch_contract(), _dispatch_request(workspace))

    assert result.decision == BLOCK
    assert result.reason == "DISPATCH_POST_INVOCATION_EVIDENCE_UNAVAILABLE"
    assert calls["count"] == 1


def test_adapter_invocation_human_review_failure_keeps_count_zero(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, requires_human_review=True)
    calls = {"count": 0}
    request = _dispatch_request(workspace, requires_human_review=True)

    result = _dispatcher(
        workspaces=[workspace],
        adapters={"git": lambda _payload: calls.update(count=calls["count"] + 1)},
        adapter_registry=[_adapter_descriptor()],
    ).dispatch(_dispatch_contract(), request)

    assert result.reason == "ROUTING_HUMAN_REVIEW_REQUIRED"
    assert calls["count"] == 0


def test_no_autonomous_adapter_registration_occurs(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    result = _dispatcher(
        workspaces=[workspace],
        adapters={"git": lambda _payload: {"status": "OK", "metadata": {}}},
        adapter_registry=[],
    ).dispatch(_dispatch_contract(), _dispatch_request(workspace))

    assert result.decision == BLOCK
    assert result.reason == "DISPATCH_ADAPTER_UNKNOWN"
    assert result.evidence["autonomous_repository_registration"] is False
    assert result.evidence["autonomous_policy_creation"] is False
    assert result.evidence["policy_mutation"] is False
