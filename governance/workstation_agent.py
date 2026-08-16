from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Mapping


ALLOW = "ALLOW"
BLOCK = "BLOCK"
FAILED = "FAILED"
HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
NOT_IMPLEMENTED = "NOT_IMPLEMENTED"

OBSERVE = "OBSERVE"
BOUNDED_WRITE = "BOUNDED_WRITE"
HUMAN_GATED = "HUMAN_GATED"
FORBIDDEN = "FORBIDDEN"

FORBIDDEN_ACTIONS = {
    "autonomous_policy_create",
    "autonomous_policy_mutate",
    "delete_audit_evidence",
    "disable_enforcement",
    "force_push",
    "self_approval",
    "self_expand_workspace_authority",
    "shell",
}
HUMAN_GATED_ACTIONS = {
    "branch_protection_change",
    "deploy",
    "destructive_delete",
    "iam_change",
    "merge",
    "production_authorize",
    "production_release",
    "secret_change",
}
OBSERVE_ACTIONS = {
    "collect_evidence",
    "compare_shas",
    "git_status",
    "inspect_branch",
    "inspect_ci",
    "inspect_diff",
    "inspect_pr",
    "read_file",
    "run_tests",
}
BOUNDED_WRITE_ACTIONS = {
    "create_file",
    "create_pr",
    "git_commit",
    "git_push",
    "stage_files",
    "update_branch",
    "write_file",
}
IMPLEMENTED_TOOLS = {"filesystem", "git", "github", "test_runner"}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256_reference(value: Any) -> str:
    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _is_sha256_reference(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 71 and value.startswith("sha256:") and all(
        char in "0123456789abcdef" for char in value[7:]
    )


def _hash_if_missing(contract: Mapping[str, Any]) -> str:
    payload = {key: value for key, value in contract.items() if key != "request_hash"}
    return sha256_reference(payload)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class WorkstationPolicyDecision:
    decision: str
    reason: str
    policy_id: str
    policy_version_hash: str
    evidence_hash: str


@dataclass(frozen=True)
class WorkstationActionResult:
    decision: str
    reason: str
    evidence: dict[str, Any]
    adapter_result: Any = None


class WorkstationReplayStore:
    def __init__(self) -> None:
        self._nonces: set[str] = set()

    def consume(self, nonce: str) -> bool:
        if nonce in self._nonces:
            return False
        self._nonces.add(nonce)
        return True


class WorkstationLockStore:
    def __init__(self) -> None:
        self._locks: set[tuple[str, str]] = set()
        self.audit: list[dict[str, Any]] = []

    def acquire(self, workspace_id: str, repository_id: str, *, task_id: str, timestamp: str) -> bool:
        key = (workspace_id, repository_id)
        event = {
            "task_id": task_id,
            "workspace_id": workspace_id,
            "repository_id": repository_id,
            "timestamp": timestamp,
        }
        if key in self._locks:
            self.audit.append({**event, "lock_result": "LOCK_CONFLICT"})
            return False
        self._locks.add(key)
        self.audit.append({**event, "lock_result": "LOCK_ACQUIRED"})
        return True

    def release(self, workspace_id: str, repository_id: str, *, task_id: str, timestamp: str) -> None:
        self._locks.discard((workspace_id, repository_id))
        self.audit.append(
            {
                "task_id": task_id,
                "workspace_id": workspace_id,
                "repository_id": repository_id,
                "timestamp": timestamp,
                "lock_result": "LOCK_RELEASED",
            }
        )


class WorkstationEvidenceRecorder:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self.previous_evidence_hash = "sha256:" + ("0" * 64)

    def record(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        event = dict(payload)
        event["previous_evidence_hash"] = self.previous_evidence_hash
        event["event_id"] = sha256_reference(event)
        self.previous_evidence_hash = event["event_id"]
        self.records.append(event)
        return event


class GovernedWorkstationAgent:
    def __init__(
        self,
        *,
        workspaces: list[Mapping[str, Any]],
        policy_evaluator: Callable[[Mapping[str, Any], Mapping[str, Any]], WorkstationPolicyDecision],
        evidence_recorder: WorkstationEvidenceRecorder | None = None,
        replay_store: WorkstationReplayStore | None = None,
        lock_store: WorkstationLockStore | None = None,
        adapters: Mapping[str, Callable[[Mapping[str, Any]], Any]] | None = None,
        clock: Callable[[], str] = utc_now,
    ) -> None:
        self._workspaces = {str(workspace.get("workspace_id")): dict(workspace) for workspace in workspaces if isinstance(workspace, Mapping)}
        self._policy_evaluator = policy_evaluator
        self._evidence_recorder = evidence_recorder or WorkstationEvidenceRecorder()
        self._replay_store = replay_store or WorkstationReplayStore()
        self._lock_store = lock_store or WorkstationLockStore()
        self._adapters = dict(adapters or {})
        self._clock = clock

    def execute(self, contract: Mapping[str, Any] | None, action_request: Mapping[str, Any] | None) -> WorkstationActionResult:
        timestamp = self._clock()
        reason = self._validate_contract_shape(contract, action_request, timestamp)
        workspace = None
        action_class = "UNKNOWN"
        policy_decision = None
        if reason is None and isinstance(contract, Mapping) and isinstance(action_request, Mapping):
            workspace_id = str(action_request.get("workspace_id"))
            repository_id = str(action_request.get("repository_id"))
            workspace = self._workspaces.get(workspace_id)
            reason = self._validate_workspace(workspace, repository_id, action_request)
            if reason is None:
                reason = self._validate_contract_binding(contract, workspace, action_request, timestamp)
            if reason is None:
                action_class = classify_action(str(action_request.get("action")))
                reason = self._validate_action(contract, workspace, action_request, action_class)
            if reason is None:
                policy_decision = self._policy_evaluator(contract, action_request)
                reason = self._validate_policy_decision(policy_decision, contract)
            if reason is None:
                reason = self._last_pre_side_effect_validation(contract, workspace, action_request, action_class, timestamp)
        if reason is not None:
            decision = HUMAN_APPROVAL_REQUIRED if reason == "HUMAN_APPROVAL_REQUIRED" else BLOCK
            return self._finalize(
                decision,
                reason,
                contract,
                action_request,
                workspace,
                action_class,
                timestamp,
                policy_decision=policy_decision,
            )
        if not isinstance(action_request, Mapping) or not isinstance(workspace, Mapping):
            return self._finalize(BLOCK, "ACTION_REQUEST_MALFORMED", contract, action_request, workspace, action_class, timestamp)
        workspace_id = str(action_request["workspace_id"])
        repository_id = str(action_request["repository_id"])
        if not self._lock_store.acquire(workspace_id, repository_id, task_id=str(contract["task_id"]), timestamp=timestamp):
            return self._finalize(BLOCK, "CONCURRENT_TASK_CONFLICT", contract, action_request, workspace, action_class, timestamp, policy_decision=policy_decision)
        try:
            adapter_result = self._execute_adapter(action_request, workspace)
            if adapter_result == NOT_IMPLEMENTED:
                return self._finalize(BLOCK, "ADAPTER_NOT_IMPLEMENTED", contract, action_request, workspace, action_class, timestamp, policy_decision=policy_decision)
            return self._finalize(ALLOW, "ACTION_ALLOWED", contract, action_request, workspace, action_class, timestamp, policy_decision=policy_decision, adapter_result=adapter_result)
        except Exception:
            return self._finalize(FAILED, "ADAPTER_FAILED", contract, action_request, workspace, action_class, timestamp, policy_decision=policy_decision)
        finally:
            self._lock_store.release(workspace_id, repository_id, task_id=str(contract["task_id"]), timestamp=self._clock())

    def _validate_contract_shape(
        self,
        contract: Mapping[str, Any] | None,
        action_request: Mapping[str, Any] | None,
        timestamp: str,
    ) -> str | None:
        if not isinstance(contract, Mapping) or not isinstance(action_request, Mapping):
            return "CONTRACT_MISSING"
        required = {
            "task_id",
            "human_intent",
            "workspace_ids",
            "repository_ids",
            "base_sha",
            "allowed_branch",
            "allowed_paths",
            "allowed_actions",
            "allowed_tools",
            "allowed_network_destinations",
            "forbidden_actions",
            "max_runtime",
            "max_changed_files",
            "max_commits",
            "requires_human_review",
            "requires_human_merge",
            "requires_human_deploy",
            "policy_id",
            "policy_version_hash",
            "issued_at",
            "expires_at",
            "nonce",
            "request_hash",
        }
        if any(field not in contract for field in required):
            return "CONTRACT_MALFORMED"
        if contract.get("request_hash") != _hash_if_missing(contract):
            return "CONTRACT_HASH_MISMATCH"
        issued = _parse_utc(contract.get("issued_at"))
        expires = _parse_utc(contract.get("expires_at"))
        now = _parse_utc(timestamp)
        if issued is None or expires is None or now is None or now < issued or now >= expires:
            return "CONTRACT_EXPIRED"
        nonce = contract.get("nonce")
        if not isinstance(nonce, str) or not nonce or not self._replay_store.consume(nonce):
            return "CONTRACT_REPLAYED"
        return None

    def _validate_workspace(
        self,
        workspace: Mapping[str, Any] | None,
        repository_id: str,
        action_request: Mapping[str, Any],
    ) -> str | None:
        if not isinstance(workspace, Mapping) or not workspace.get("enabled"):
            return "UNKNOWN_WORKSPACE"
        if workspace.get("repository_name") != repository_id:
            return "REPOSITORY_IDENTITY_MISMATCH"
        if action_request.get("remote_identity") != workspace.get("remote_identity"):
            return "REMOTE_IDENTITY_MISMATCH"
        local_root = workspace.get("local_root")
        if not isinstance(local_root, str) or not Path(local_root).exists():
            return "WORKSPACE_ROOT_UNAVAILABLE"
        return None

    def _validate_contract_binding(
        self,
        contract: Mapping[str, Any],
        workspace: Mapping[str, Any] | None,
        action_request: Mapping[str, Any],
        timestamp: str,
    ) -> str | None:
        del timestamp
        if not isinstance(workspace, Mapping):
            return "UNKNOWN_WORKSPACE"
        workspace_id = str(action_request.get("workspace_id"))
        repository_id = str(action_request.get("repository_id"))
        if workspace_id not in set(contract.get("workspace_ids") or []):
            return "WORKSPACE_NOT_AUTHORIZED"
        if repository_id not in set(contract.get("repository_ids") or []):
            return "REPOSITORY_NOT_AUTHORIZED"
        if action_request.get("branch") != contract.get("allowed_branch"):
            return "BRANCH_MISMATCH"
        if action_request.get("base_sha") != contract.get("base_sha"):
            return "STALE_BASE_SHA"
        if action_request.get("policy_version_hash") != contract.get("policy_version_hash"):
            return "POLICY_VERSION_MISMATCH"
        policy_binding = workspace.get("policy_binding") if isinstance(workspace, Mapping) else None
        if not isinstance(policy_binding, Mapping):
            return "POLICY_BINDING_MISSING"
        if policy_binding.get("policy_id") != contract.get("policy_id"):
            return "POLICY_ID_MISMATCH"
        if policy_binding.get("policy_version_hash") != contract.get("policy_version_hash"):
            return "POLICY_VERSION_MISMATCH"
        if contract.get("max_commits", 0) < action_request.get("expected_commits", 0):
            return "COMMIT_LIMIT_EXCEEDED"
        if contract.get("max_changed_files", 0) < len(action_request.get("paths") or []):
            return "CHANGED_FILE_LIMIT_EXCEEDED"
        return None

    def _validate_action(
        self,
        contract: Mapping[str, Any],
        workspace: Mapping[str, Any] | None,
        action_request: Mapping[str, Any],
        action_class: str,
    ) -> str | None:
        action = str(action_request.get("action"))
        if action_class == FORBIDDEN or action in set(contract.get("forbidden_actions") or []):
            return "ACTION_FORBIDDEN"
        if action_class == HUMAN_GATED:
            return "HUMAN_APPROVAL_REQUIRED"
        if action not in set(contract.get("allowed_actions") or []):
            return "ACTION_NOT_AUTHORIZED"
        tool = action_request.get("tool")
        if tool not in set(contract.get("allowed_tools") or []):
            return "TOOL_NOT_AUTHORIZED"
        if tool not in IMPLEMENTED_TOOLS:
            return "ADAPTER_NOT_IMPLEMENTED"
        if not isinstance(workspace, Mapping) or tool not in set(workspace.get("allowed_tool_classes") or []):
            return "TOOL_NOT_AUTHORIZED"
        path_error = self._validate_paths(workspace, contract, action_request)
        if path_error:
            return path_error
        network_error = self._validate_network(workspace, contract, action_request)
        if network_error:
            return network_error
        return None

    def _validate_paths(
        self,
        workspace: Mapping[str, Any],
        contract: Mapping[str, Any],
        action_request: Mapping[str, Any],
    ) -> str | None:
        root = Path(str(workspace["local_root"])).resolve()
        workspace_patterns = tuple(str(pattern) for pattern in workspace.get("allowed_path_patterns") or [])
        contract_patterns = tuple(str(pattern) for pattern in contract.get("allowed_paths") or [])
        for raw_path in action_request.get("paths") or []:
            if not isinstance(raw_path, str) or not raw_path:
                return "PATH_MALFORMED"
            candidate = Path(raw_path)
            if candidate.is_absolute():
                return "PATH_ABSOLUTE_REJECTED"
            unresolved = root / candidate
            if any(part == ".." for part in candidate.parts):
                return "PATH_TRAVERSAL_REJECTED"
            if unresolved.exists() and unresolved.is_symlink():
                return "PATH_SYMLINK_ESCAPE_REJECTED"
            resolved = unresolved.resolve(strict=False)
            if not _inside(resolved, root):
                return "PATH_ESCAPE_REJECTED"
            relative = resolved.relative_to(root).as_posix()
            if not any(fnmatch.fnmatch(relative, pattern) for pattern in workspace_patterns):
                return "PATH_NOT_IN_WORKSPACE_SCOPE"
            if not any(fnmatch.fnmatch(relative, pattern) for pattern in contract_patterns):
                return "PATH_NOT_IN_CONTRACT_SCOPE"
        return None

    def _validate_network(
        self,
        workspace: Mapping[str, Any],
        contract: Mapping[str, Any],
        action_request: Mapping[str, Any],
    ) -> str | None:
        destinations = action_request.get("network_destinations") or []
        if not destinations:
            return None
        workspace_allowed = set(workspace.get("allowed_network_destinations") or [])
        contract_allowed = set(contract.get("allowed_network_destinations") or [])
        for destination in destinations:
            if destination not in workspace_allowed or destination not in contract_allowed:
                return "NETWORK_DESTINATION_NOT_AUTHORIZED"
        return None

    def _validate_policy_decision(
        self,
        policy_decision: WorkstationPolicyDecision | Any,
        contract: Mapping[str, Any],
    ) -> str | None:
        if not isinstance(policy_decision, WorkstationPolicyDecision):
            return "POLICY_UNAVAILABLE"
        if policy_decision.decision != ALLOW:
            return "POLICY_DENIED"
        if policy_decision.policy_id != contract.get("policy_id"):
            return "POLICY_ID_MISMATCH"
        if policy_decision.policy_version_hash != contract.get("policy_version_hash"):
            return "POLICY_VERSION_MISMATCH"
        if not _is_sha256_reference(policy_decision.evidence_hash):
            return "POLICY_EVIDENCE_MALFORMED"
        return None

    def _last_pre_side_effect_validation(
        self,
        contract: Mapping[str, Any],
        workspace: Mapping[str, Any] | None,
        action_request: Mapping[str, Any],
        action_class: str,
        timestamp: str,
    ) -> str | None:
        shape_error = self._validate_contract_binding(contract, workspace, action_request, timestamp)
        if shape_error:
            return shape_error
        if action_class != OBSERVE and contract.get("requires_human_review") is not True:
            return "HUMAN_REVIEW_REQUIRED_FOR_WRITE"
        return None

    def _execute_adapter(self, action_request: Mapping[str, Any], workspace: Mapping[str, Any]) -> Any:
        tool = str(action_request.get("tool"))
        adapter = self._adapters.get(tool)
        if adapter is None:
            return NOT_IMPLEMENTED
        payload = {
            "action": action_request.get("action"),
            "workspace_id": action_request.get("workspace_id"),
            "repository_id": action_request.get("repository_id"),
            "local_root": workspace.get("local_root"),
            "paths": list(action_request.get("paths") or []),
            "arguments": dict(action_request.get("arguments") or {}),
        }
        return adapter(payload)

    def _finalize(
        self,
        decision: str,
        reason: str,
        contract: Mapping[str, Any] | None,
        action_request: Mapping[str, Any] | None,
        workspace: Mapping[str, Any] | None,
        action_class: str,
        timestamp: str,
        *,
        policy_decision: WorkstationPolicyDecision | None = None,
        adapter_result: Any = None,
    ) -> WorkstationActionResult:
        evidence = {
            "schema": "usbay.governed_workstation_agent.evidence.v1",
            "task_id": _safe_get(contract, "task_id"),
            "human_intent_hash": sha256_reference(_safe_get(contract, "human_intent")),
            "workspace_id": _safe_get(action_request, "workspace_id"),
            "repository_id": _safe_get(action_request, "repository_id"),
            "policy_id": _safe_get(contract, "policy_id"),
            "policy_version_hash": _safe_get(contract, "policy_version_hash"),
            "contract_hash": _hash_if_missing(contract) if isinstance(contract, Mapping) else None,
            "request_hash": _safe_get(contract, "request_hash"),
            "action_class": action_class,
            "requested_action": _safe_get(action_request, "action"),
            "decision": decision,
            "decision_reason": reason,
            "pre_state_hash": sha256_reference(
                {
                    "workspace": workspace.get("workspace_id") if isinstance(workspace, Mapping) else None,
                    "base_sha": _safe_get(action_request, "base_sha"),
                    "branch": _safe_get(action_request, "branch"),
                }
            ),
            "post_state_hash": sha256_reference(adapter_result) if adapter_result is not None else None,
            "command_action_hash": sha256_reference(action_request or {}),
            "result_hash": sha256_reference({"decision": decision, "reason": reason, "adapter_result": adapter_result}),
            "actor": "codex",
            "timestamp": timestamp,
            "nonce": _safe_get(contract, "nonce"),
            "policy_decision_evidence_hash": policy_decision.evidence_hash if isinstance(policy_decision, WorkstationPolicyDecision) else None,
        }
        try:
            record = self._evidence_recorder.record(evidence)
        except Exception:
            fallback = {
                **evidence,
                "decision": BLOCK,
                "decision_reason": "EVIDENCE_RECORDER_UNAVAILABLE",
                "previous_evidence_hash": "sha256:" + ("0" * 64),
            }
            fallback["event_id"] = sha256_reference(fallback)
            return WorkstationActionResult(decision=BLOCK, reason="EVIDENCE_RECORDER_UNAVAILABLE", evidence=fallback)
        return WorkstationActionResult(decision=decision, reason=reason, evidence=record, adapter_result=adapter_result)


def _safe_get(value: Mapping[str, Any] | None, key: str) -> Any:
    return value.get(key) if isinstance(value, Mapping) else None


def classify_action(action: str) -> str:
    if action in FORBIDDEN_ACTIONS:
        return FORBIDDEN
    if action in HUMAN_GATED_ACTIONS:
        return HUMAN_GATED
    if action in OBSERVE_ACTIONS:
        return OBSERVE
    if action in BOUNDED_WRITE_ACTIONS:
        return BOUNDED_WRITE
    return FORBIDDEN


def build_task_contract(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "task_id": "task-1",
        "human_intent": "inspect governed workstation state",
        "workspace_ids": ["workspace-a"],
        "repository_ids": ["usbay-policy-brain-public"],
        "base_sha": "a" * 40,
        "allowed_branch": "main",
        "allowed_paths": ["runtime/**", "tests/**", "governance/**"],
        "allowed_actions": ["git_status", "read_file", "run_tests"],
        "allowed_tools": ["git", "filesystem", "test_runner"],
        "allowed_network_destinations": [],
        "forbidden_actions": sorted(FORBIDDEN_ACTIONS),
        "max_runtime": 300,
        "max_changed_files": 4,
        "max_commits": 1,
        "requires_human_review": True,
        "requires_human_merge": True,
        "requires_human_deploy": True,
        "policy_id": "usbay.governed_workstation_agent.v1",
        "policy_version_hash": sha256_reference({"policy": "workstation-agent-v1"}),
        "issued_at": "2026-08-16T00:00:00Z",
        "expires_at": "2026-08-17T00:00:00Z",
        "nonce": "nonce-1",
    }
    payload.update(overrides)
    payload["request_hash"] = _hash_if_missing(payload)
    return payload


def build_workspace_registration(**overrides: Any) -> dict[str, Any]:
    root = Path(str(overrides.pop("local_root", os.getcwd()))).resolve()
    payload: dict[str, Any] = {
        "workspace_id": "workspace-a",
        "workspace_type": "Policy Brain",
        "repository_name": "usbay-policy-brain-public",
        "local_root": str(root),
        "remote_identity": "https://github.com/USJAY77/usbay-policy-brain-public.git",
        "allowed_branches": ["main"],
        "allowed_path_patterns": ["runtime/**", "tests/**", "governance/**"],
        "allowed_tool_classes": ["filesystem", "git", "test_runner", "github"],
        "allowed_network_destinations": [],
        "risk_class": "governance-critical",
        "human_approval_requirements": {"merge": True, "deploy": True, "secret_change": True},
        "policy_binding": {
            "policy_id": "usbay.governed_workstation_agent.v1",
            "policy_version_hash": sha256_reference({"policy": "workstation-agent-v1"}),
        },
        "evidence_namespace": "usbay.workstation.policy_brain",
        "enabled": True,
    }
    payload.update(overrides)
    return payload


def allow_policy_decision(contract: Mapping[str, Any], _action_request: Mapping[str, Any]) -> WorkstationPolicyDecision:
    return WorkstationPolicyDecision(
        decision=ALLOW,
        reason="POLICY_ALLOWED",
        policy_id=str(contract.get("policy_id")),
        policy_version_hash=str(contract.get("policy_version_hash")),
        evidence_hash=sha256_reference({"policy_id": contract.get("policy_id"), "request_hash": contract.get("request_hash")}),
    )
