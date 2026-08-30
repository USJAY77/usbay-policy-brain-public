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


@dataclass(frozen=True)
class WorkstationRouteResult:
    decision: str
    reason: str
    evidence: dict[str, Any]
    selected_repositories: tuple[str, ...] = ()


@dataclass(frozen=True)
class WorkstationDispatchResult:
    decision: str
    reason: str
    evidence: dict[str, Any]
    adapter_result: Any = None


@dataclass(frozen=True)
class WorkstationAdapterDescriptor:
    adapter_id: str
    adapter_type: str
    allowed_action_classes: tuple[str, ...]
    adapter_version: str
    invocation_schema: str
    allowed_workspace_ids: tuple[str, ...] = ()
    allowed_repository_ids: tuple[str, ...] = ()
    enabled: bool = True


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


class WorkstationAdapterRegistry:
    def __init__(self, adapters: list[WorkstationAdapterDescriptor] | Mapping[str, WorkstationAdapterDescriptor] | None = None) -> None:
        if adapters is None:
            self._adapters: tuple[WorkstationAdapterDescriptor, ...] = ()
        elif isinstance(adapters, Mapping):
            self._adapters = tuple(adapters.values())
        else:
            self._adapters = tuple(adapters)

    def resolve(self, adapter_id: str) -> tuple[WorkstationAdapterDescriptor | None, str | None]:
        matches = [adapter for adapter in self._adapters if adapter.adapter_id == adapter_id]
        if not matches:
            return None, "DISPATCH_ADAPTER_UNKNOWN"
        if len(matches) > 1:
            return None, "DISPATCH_ADAPTER_AMBIGUOUS"
        descriptor = matches[0]
        if not descriptor.enabled:
            return None, "DISPATCH_ADAPTER_DISABLED"
        return descriptor, None


class GovernedWorkstationRouter:
    def __init__(
        self,
        *,
        workspaces: list[Mapping[str, Any]],
        evidence_recorder: WorkstationEvidenceRecorder | None = None,
        replay_store: WorkstationReplayStore | None = None,
        clock: Callable[[], str] = utc_now,
    ) -> None:
        self._workspaces = tuple(dict(workspace) for workspace in workspaces if isinstance(workspace, Mapping))
        self._evidence_recorder = evidence_recorder or WorkstationEvidenceRecorder()
        self._replay_store = replay_store or WorkstationReplayStore()
        self._clock = clock

    def route(
        self,
        contract: Mapping[str, Any] | None,
        routing_request: Mapping[str, Any] | None,
        *,
        human_approval: Mapping[str, Any] | None = None,
    ) -> WorkstationRouteResult:
        timestamp = self._clock()
        reason = self._validate_contract_shape(contract, routing_request, timestamp)
        selected: tuple[Mapping[str, Any], ...] = ()
        if reason is None and isinstance(contract, Mapping) and isinstance(routing_request, Mapping):
            selected, reason = self._select_repositories(contract, routing_request)
        if reason is None and isinstance(contract, Mapping) and isinstance(routing_request, Mapping):
            reason = self._validate_human_review(contract, routing_request, selected, human_approval, timestamp)
        decision = ALLOW if reason is None else BLOCK
        decision_reason = "ROUTE_ALLOWED" if reason is None else reason
        return self._finalize(decision, decision_reason, contract, routing_request, selected, timestamp)

    def _validate_contract_shape(
        self,
        contract: Mapping[str, Any] | None,
        routing_request: Mapping[str, Any] | None,
        timestamp: str,
    ) -> str | None:
        if not isinstance(contract, Mapping) or not isinstance(routing_request, Mapping):
            return "ROUTING_CONTRACT_MISSING"
        required = {
            "task_id",
            "human_intent",
            "workspace_ids",
            "repository_ids",
            "allowed_branch",
            "allowed_paths",
            "allowed_actions",
            "policy_id",
            "policy_version_hash",
            "issued_at",
            "expires_at",
            "nonce",
            "request_hash",
        }
        if any(field not in contract for field in required):
            return "ROUTING_CONTRACT_MALFORMED"
        if contract.get("request_hash") != _hash_if_missing(contract):
            return "ROUTING_CONTRACT_HASH_MISMATCH"
        issued = _parse_utc(contract.get("issued_at"))
        expires = _parse_utc(contract.get("expires_at"))
        now = _parse_utc(timestamp)
        if issued is None or expires is None or now is None or now < issued or now >= expires:
            return "ROUTING_CONTRACT_EXPIRED"
        nonce = contract.get("nonce")
        if not isinstance(nonce, str) or not nonce or not self._replay_store.consume(f"route-contract:{nonce}"):
            return "ROUTING_CONTRACT_REPLAYED"
        if set(routing_request.get("workspace_ids") or []) - set(contract.get("workspace_ids") or []):
            return "ROUTING_WORKSPACE_NOT_AUTHORIZED"
        if set(routing_request.get("repository_ids") or []) - set(contract.get("repository_ids") or []):
            return "ROUTING_REPOSITORY_NOT_AUTHORIZED"
        if routing_request.get("policy_id") != contract.get("policy_id"):
            return "ROUTING_POLICY_ID_MISMATCH"
        if routing_request.get("policy_version_hash") != contract.get("policy_version_hash"):
            return "ROUTING_POLICY_VERSION_MISMATCH"
        return None

    def _select_repositories(
        self,
        contract: Mapping[str, Any],
        routing_request: Mapping[str, Any],
    ) -> tuple[tuple[Mapping[str, Any], ...], str | None]:
        requested_workspace_ids = tuple(str(value) for value in routing_request.get("workspace_ids") or [])
        requested_repository_ids = tuple(str(value) for value in routing_request.get("repository_ids") or [])
        if not requested_workspace_ids or not requested_repository_ids:
            return (), "ROUTING_REQUEST_MALFORMED"
        if len(requested_repository_ids) > 1 and routing_request.get("multi_repository_authorized") is not True:
            return (), "MULTI_REPOSITORY_AUTHORIZATION_MISSING"
        if len(requested_workspace_ids) != len(requested_repository_ids):
            return (), "ROUTING_REQUEST_MALFORMED"

        remote_identities = routing_request.get("remote_identities")
        base_shas = routing_request.get("base_shas")
        local_roots = routing_request.get("local_roots") or {}
        if not isinstance(remote_identities, Mapping) or not isinstance(base_shas, Mapping) or not isinstance(local_roots, Mapping):
            return (), "ROUTING_REQUEST_MALFORMED"

        selected: list[Mapping[str, Any]] = []
        seen_roots: set[str] = set()
        for workspace_id, repository_id in zip(requested_workspace_ids, requested_repository_ids):
            matches = [
                workspace
                for workspace in self._workspaces
                if str(workspace.get("workspace_id")) == workspace_id
                and str(workspace.get("repository_name")) == repository_id
            ]
            if len(matches) != 1:
                return (), "ROUTING_AMBIGUOUS_OR_UNKNOWN_REPOSITORY"
            workspace = matches[0]
            reason = self._validate_workspace_route(contract, routing_request, workspace, repository_id, remote_identities, base_shas, local_roots)
            if reason is not None:
                return (), reason
            root = str(Path(str(workspace["local_root"])).resolve())
            if root in seen_roots:
                return (), "ROUTING_CANONICAL_ROOT_AMBIGUOUS"
            seen_roots.add(root)
            selected.append(workspace)
        return tuple(selected), None

    def _validate_workspace_route(
        self,
        contract: Mapping[str, Any],
        routing_request: Mapping[str, Any],
        workspace: Mapping[str, Any],
        repository_id: str,
        remote_identities: Mapping[str, Any],
        base_shas: Mapping[str, Any],
        local_roots: Mapping[str, Any],
    ) -> str | None:
        if not workspace.get("enabled"):
            return "ROUTING_WORKSPACE_DISABLED"
        local_root = workspace.get("local_root")
        if not isinstance(local_root, str) or not Path(local_root).exists():
            return "ROUTING_WORKSPACE_ROOT_UNAVAILABLE"
        canonical_root = str(Path(local_root).resolve())
        requested_root = local_roots.get(repository_id)
        if requested_root is not None and str(Path(str(requested_root)).resolve()) != canonical_root:
            return "ROUTING_CANONICAL_ROOT_MISMATCH"
        if remote_identities.get(repository_id) != workspace.get("remote_identity"):
            return "ROUTING_REMOTE_IDENTITY_MISMATCH"
        if routing_request.get("branch") != contract.get("allowed_branch"):
            return "ROUTING_BRANCH_MISMATCH"
        if routing_request.get("branch") not in set(workspace.get("allowed_branches") or []):
            return "ROUTING_BRANCH_NOT_REGISTERED"
        if base_shas.get(repository_id) != workspace.get("current_sha", contract.get("base_sha")):
            return "ROUTING_STALE_REPOSITORY_STATE"
        policy_binding = workspace.get("policy_binding")
        if not isinstance(policy_binding, Mapping):
            return "ROUTING_POLICY_BINDING_MISSING"
        if policy_binding.get("policy_id") != contract.get("policy_id"):
            return "ROUTING_POLICY_ID_MISMATCH"
        if policy_binding.get("policy_version_hash") != contract.get("policy_version_hash"):
            return "ROUTING_POLICY_VERSION_MISMATCH"
        action_class = routing_request.get("action_class")
        if action_class not in set(workspace.get("allowed_action_classes") or [OBSERVE, BOUNDED_WRITE]):
            return "ROUTING_ACTION_CLASS_NOT_AUTHORIZED"
        return self._validate_routing_paths(contract, routing_request, workspace, repository_id)

    def _validate_routing_paths(
        self,
        contract: Mapping[str, Any],
        routing_request: Mapping[str, Any],
        workspace: Mapping[str, Any],
        repository_id: str,
    ) -> str | None:
        root = Path(str(workspace["local_root"])).resolve()
        workspace_patterns = tuple(str(pattern) for pattern in workspace.get("allowed_path_patterns") or [])
        contract_patterns = tuple(str(pattern) for pattern in contract.get("allowed_paths") or [])
        paths_by_repository = routing_request.get("paths_by_repository")
        if not isinstance(paths_by_repository, Mapping):
            return "ROUTING_REQUEST_MALFORMED"
        for raw_path in paths_by_repository.get(repository_id) or []:
            if not isinstance(raw_path, str) or not raw_path:
                return "ROUTING_PATH_MALFORMED"
            candidate = Path(raw_path)
            if candidate.is_absolute():
                return "ROUTING_PATH_ABSOLUTE_REJECTED"
            if any(part == ".." for part in candidate.parts):
                return "ROUTING_PATH_TRAVERSAL_REJECTED"
            unresolved = root / candidate
            if unresolved.exists() and unresolved.is_symlink():
                return "ROUTING_PATH_SYMLINK_ESCAPE_REJECTED"
            resolved = unresolved.resolve(strict=False)
            if not _inside(resolved, root):
                return "ROUTING_PATH_ESCAPE_REJECTED"
            relative = resolved.relative_to(root).as_posix()
            if not any(fnmatch.fnmatch(relative, pattern) for pattern in workspace_patterns):
                return "ROUTING_PATH_NOT_IN_WORKSPACE_SCOPE"
            if not any(fnmatch.fnmatch(relative, pattern) for pattern in contract_patterns):
                return "ROUTING_PATH_NOT_IN_CONTRACT_SCOPE"
        return None

    def _validate_human_review(
        self,
        contract: Mapping[str, Any],
        routing_request: Mapping[str, Any],
        selected: tuple[Mapping[str, Any], ...],
        human_approval: Mapping[str, Any] | None,
        timestamp: str,
    ) -> str | None:
        if not routing_request.get("requires_human_review") and not any(workspace.get("requires_human_review") for workspace in selected):
            return None
        if not isinstance(human_approval, Mapping):
            return "ROUTING_HUMAN_REVIEW_REQUIRED"
        if human_approval.get("approved") is not True:
            return "ROUTING_HUMAN_REVIEW_REQUIRED"
        if human_approval.get("contract_hash") != contract.get("request_hash"):
            return "ROUTING_HUMAN_APPROVAL_BINDING_MISMATCH"
        if tuple(human_approval.get("repository_ids") or []) != tuple(routing_request.get("repository_ids") or []):
            return "ROUTING_HUMAN_APPROVAL_BINDING_MISMATCH"
        if human_approval.get("policy_id") != contract.get("policy_id"):
            return "ROUTING_HUMAN_APPROVAL_BINDING_MISMATCH"
        if human_approval.get("policy_version_hash") != contract.get("policy_version_hash"):
            return "ROUTING_HUMAN_APPROVAL_BINDING_MISMATCH"
        expires = _parse_utc(human_approval.get("expires_at"))
        now = _parse_utc(timestamp)
        if expires is None or now is None or now >= expires:
            return "ROUTING_HUMAN_APPROVAL_EXPIRED"
        nonce = human_approval.get("nonce")
        if not isinstance(nonce, str) or not nonce or not self._replay_store.consume(f"route-approval:{nonce}"):
            return "ROUTING_HUMAN_APPROVAL_REPLAYED"
        return None

    def _finalize(
        self,
        decision: str,
        reason: str,
        contract: Mapping[str, Any] | None,
        routing_request: Mapping[str, Any] | None,
        selected: tuple[Mapping[str, Any], ...],
        timestamp: str,
    ) -> WorkstationRouteResult:
        repository_ids = tuple(str(workspace.get("repository_name")) for workspace in selected)
        evidence = {
            "schema": "usbay.governed_workstation_router.evidence.v1",
            "task_id": _safe_get(contract, "task_id"),
            "human_intent_hash": sha256_reference(_safe_get(contract, "human_intent")),
            "contract_hash": _hash_if_missing(contract) if isinstance(contract, Mapping) else None,
            "request_hash": sha256_reference(routing_request or {}),
            "policy_id": _safe_get(contract, "policy_id"),
            "policy_version_hash": _safe_get(contract, "policy_version_hash"),
            "decision": decision,
            "decision_reason": reason,
            "selected_repository_ids": list(repository_ids),
            "selected_workspace_ids": [str(workspace.get("workspace_id")) for workspace in selected],
            "canonical_repository_identity_hash": sha256_reference(
                [
                    {
                        "workspace_id": workspace.get("workspace_id"),
                        "repository_id": workspace.get("repository_name"),
                        "remote_identity": workspace.get("remote_identity"),
                        "canonical_root": str(Path(str(workspace.get("local_root"))).resolve())
                        if isinstance(workspace.get("local_root"), str)
                        else None,
                    }
                    for workspace in selected
                ]
            ),
            "repository_mutation": False,
            "autonomous_repository_registration": False,
            "autonomous_policy_creation": False,
            "policy_mutation": False,
            "actor": "codex",
            "timestamp": timestamp,
        }
        try:
            record = self._evidence_recorder.record(evidence)
        except Exception:
            fallback = {
                **evidence,
                "decision": BLOCK,
                "decision_reason": "ROUTING_EVIDENCE_RECORDER_UNAVAILABLE",
                "previous_evidence_hash": "sha256:" + ("0" * 64),
            }
            fallback["event_id"] = sha256_reference(fallback)
            return WorkstationRouteResult(decision=BLOCK, reason="ROUTING_EVIDENCE_RECORDER_UNAVAILABLE", evidence=fallback)
        return WorkstationRouteResult(decision=decision, reason=reason, evidence=record, selected_repositories=repository_ids)


class GovernedTaskDispatcher:
    def __init__(
        self,
        *,
        workspaces: list[Mapping[str, Any]],
        adapters: Mapping[str, Callable[[Mapping[str, Any]], Any]] | None = None,
        adapter_registry: WorkstationAdapterRegistry | list[WorkstationAdapterDescriptor] | Mapping[str, WorkstationAdapterDescriptor] | None = None,
        evidence_recorder: WorkstationEvidenceRecorder | None = None,
        replay_store: WorkstationReplayStore | None = None,
        lock_store: WorkstationLockStore | None = None,
        clock: Callable[[], str] = utc_now,
    ) -> None:
        self._workspaces = tuple(dict(workspace) for workspace in workspaces if isinstance(workspace, Mapping))
        self._workspace_by_repo = {
            (str(workspace.get("workspace_id")), str(workspace.get("repository_name"))): dict(workspace)
            for workspace in self._workspaces
        }
        self._evidence_recorder = evidence_recorder or WorkstationEvidenceRecorder()
        self._replay_store = replay_store or WorkstationReplayStore()
        self._lock_store = lock_store or WorkstationLockStore()
        self._adapters = dict(adapters or {})
        self._adapter_registry = (
            adapter_registry
            if isinstance(adapter_registry, WorkstationAdapterRegistry)
            else WorkstationAdapterRegistry(
                self._default_adapter_descriptors(self._adapters) if adapter_registry is None else adapter_registry
            )
        )
        self._clock = clock

    def _default_adapter_descriptors(
        self,
        adapters: Mapping[str, Callable[[Mapping[str, Any]], Any]],
    ) -> list[WorkstationAdapterDescriptor]:
        return [
            WorkstationAdapterDescriptor(
                adapter_id=str(adapter_id),
                adapter_type=str(adapter_id),
                allowed_action_classes=(OBSERVE, BOUNDED_WRITE),
                adapter_version="legacy-callable-v1",
                invocation_schema="usbay.workstation.adapter.invocation.v1",
            )
            for adapter_id in adapters
        ]

    def dispatch(
        self,
        contract: Mapping[str, Any] | None,
        task_request: Mapping[str, Any] | None,
        *,
        human_approval: Mapping[str, Any] | None = None,
    ) -> WorkstationDispatchResult:
        timestamp = self._clock()
        reason = self._validate_dispatch_contract(contract, task_request, timestamp)
        route_result: WorkstationRouteResult | None = None
        selected: tuple[Mapping[str, Any], ...] = ()
        adapter_descriptor: WorkstationAdapterDescriptor | None = None
        if reason is None and isinstance(contract, Mapping) and isinstance(task_request, Mapping):
            router = GovernedWorkstationRouter(
                workspaces=list(self._workspaces),
                evidence_recorder=self._evidence_recorder,
                replay_store=self._replay_store,
                clock=self._clock,
            )
            route_result = router.route(contract, self._routing_request(task_request), human_approval=human_approval)
            if route_result.decision != ALLOW:
                reason = route_result.reason
            else:
                selected = self._selected_workspaces(task_request)
        if reason is None and isinstance(contract, Mapping) and isinstance(task_request, Mapping):
            adapter_descriptor, reason = self._validate_adapter_authority(contract, task_request, selected)
        if reason is not None:
            return self._record_dispatch(BLOCK, reason, contract, task_request, selected, timestamp, adapter_descriptor=adapter_descriptor)

        if not isinstance(contract, Mapping) or not isinstance(task_request, Mapping):
            return self._record_dispatch(BLOCK, "DISPATCH_REQUEST_MALFORMED", contract, task_request, selected, timestamp, adapter_descriptor=adapter_descriptor)
        acquired: list[tuple[str, str]] = []
        for workspace in selected:
            workspace_id = str(workspace.get("workspace_id"))
            repository_id = str(workspace.get("repository_name"))
            if not self._lock_store.acquire(workspace_id, repository_id, task_id=str(contract["task_id"]), timestamp=timestamp):
                for locked_workspace_id, locked_repository_id in reversed(acquired):
                    self._lock_store.release(locked_workspace_id, locked_repository_id, task_id=str(contract["task_id"]), timestamp=self._clock())
                return self._record_dispatch(
                    BLOCK,
                    "DISPATCH_CONCURRENT_TASK_CONFLICT",
                    contract,
                    task_request,
                    selected,
                    timestamp,
                    adapter_descriptor=adapter_descriptor,
                )
            acquired.append((workspace_id, repository_id))

        decision_record = self._record_dispatch(
            ALLOW,
            "DISPATCH_PRE_INVOCATION_ALLOWED",
            contract,
            task_request,
            selected,
            timestamp,
            adapter_descriptor=adapter_descriptor,
            invocation_status="NOT_INVOKED",
        )
        if decision_record.decision != ALLOW:
            for workspace_id, repository_id in reversed(acquired):
                self._lock_store.release(workspace_id, repository_id, task_id=str(contract["task_id"]), timestamp=self._clock())
            return decision_record
        try:
            adapter_result = self._invoke_adapter(contract, task_request, selected, adapter_descriptor)
            normalized_result, normalization_reason = self._normalize_adapter_result(adapter_result)
            if normalization_reason is not None:
                post_record = self._record_dispatch(
                    FAILED,
                    normalization_reason,
                    contract,
                    task_request,
                    selected,
                    self._clock(),
                    adapter_descriptor=adapter_descriptor,
                    invocation_status="RESULT_REJECTED",
                    adapter_result=normalized_result,
                )
                return WorkstationDispatchResult(
                    decision=post_record.decision,
                    reason=post_record.reason,
                    evidence=post_record.evidence,
                    adapter_result=normalized_result,
                )
        except Exception:
            post_record = self._record_dispatch(
                FAILED,
                "DISPATCH_ADAPTER_FAILED",
                contract,
                task_request,
                selected,
                self._clock(),
                adapter_descriptor=adapter_descriptor,
                invocation_status="ADAPTER_EXCEPTION",
                adapter_result={"status": FAILED},
            )
            return WorkstationDispatchResult(
                decision=post_record.decision,
                reason=post_record.reason,
                evidence=post_record.evidence,
                adapter_result={"status": FAILED},
            )
        finally:
            for workspace_id, repository_id in reversed(acquired):
                self._lock_store.release(workspace_id, repository_id, task_id=str(contract["task_id"]), timestamp=self._clock())
        post_record = self._record_dispatch(
            ALLOW,
            "DISPATCH_INVOKED",
            contract,
            task_request,
            selected,
            self._clock(),
            adapter_descriptor=adapter_descriptor,
            invocation_status="INVOKED",
            adapter_result=normalized_result,
            evidence_failure_reason="DISPATCH_POST_INVOCATION_EVIDENCE_UNAVAILABLE",
        )
        return WorkstationDispatchResult(decision=post_record.decision, reason=post_record.reason, evidence=post_record.evidence, adapter_result=normalized_result)

    def _validate_dispatch_contract(
        self,
        contract: Mapping[str, Any] | None,
        task_request: Mapping[str, Any] | None,
        timestamp: str,
    ) -> str | None:
        if not isinstance(contract, Mapping) or not isinstance(task_request, Mapping):
            return "DISPATCH_CONTRACT_MISSING"
        required = {
            "task_id",
            "human_intent",
            "workspace_ids",
            "repository_ids",
            "action_class",
            "allowed_actions",
            "allowed_paths",
            "allowed_branch",
            "policy_id",
            "policy_version_hash",
            "request_hash",
            "base_sha",
            "issued_at",
            "expires_at",
            "nonce",
            "requires_human_review",
        }
        if any(field not in contract for field in required):
            return "DISPATCH_CONTRACT_MALFORMED"
        if contract.get("request_hash") != _hash_if_missing(contract):
            return "DISPATCH_CONTRACT_HASH_MISMATCH"
        issued = _parse_utc(contract.get("issued_at"))
        expires = _parse_utc(contract.get("expires_at"))
        now = _parse_utc(timestamp)
        if issued is None or expires is None or now is None or now < issued or now >= expires:
            return "DISPATCH_CONTRACT_EXPIRED"
        action_class = task_request.get("action_class")
        if action_class != contract.get("action_class"):
            return "DISPATCH_ACTION_CLASS_MISMATCH"
        if action_class in {FORBIDDEN, HUMAN_GATED}:
            return "DISPATCH_ACTION_CLASS_NOT_AUTHORIZED"
        action = task_request.get("action")
        if action not in set(contract.get("allowed_actions") or []):
            return "DISPATCH_ACTION_NOT_AUTHORIZED"
        if action in FORBIDDEN_ACTIONS or action in HUMAN_GATED_ACTIONS:
            return "DISPATCH_ACTION_NOT_AUTHORIZED"
        if task_request.get("policy_id") != contract.get("policy_id"):
            return "DISPATCH_POLICY_ID_MISMATCH"
        if task_request.get("policy_version_hash") != contract.get("policy_version_hash"):
            return "DISPATCH_POLICY_VERSION_MISMATCH"
        return None

    def _routing_request(self, task_request: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "workspace_ids": list(task_request.get("workspace_ids") or []),
            "repository_ids": list(task_request.get("repository_ids") or []),
            "remote_identities": dict(task_request.get("remote_identities") or {}),
            "local_roots": dict(task_request.get("local_roots") or {}),
            "branch": task_request.get("branch"),
            "base_shas": dict(task_request.get("base_shas") or {}),
            "paths_by_repository": dict(task_request.get("paths_by_repository") or {}),
            "action_class": task_request.get("action_class"),
            "policy_id": task_request.get("policy_id"),
            "policy_version_hash": task_request.get("policy_version_hash"),
            "requires_human_review": task_request.get("requires_human_review"),
            "multi_repository_authorized": task_request.get("multi_repository_authorized"),
        }

    def _selected_workspaces(self, task_request: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
        selected: list[Mapping[str, Any]] = []
        for workspace_id, repository_id in zip(task_request.get("workspace_ids") or [], task_request.get("repository_ids") or []):
            workspace = self._workspace_by_repo.get((str(workspace_id), str(repository_id)))
            if isinstance(workspace, Mapping):
                selected.append(workspace)
        return tuple(selected)

    def _validate_adapter_authority(
        self,
        contract: Mapping[str, Any],
        task_request: Mapping[str, Any],
        selected: tuple[Mapping[str, Any], ...],
    ) -> tuple[WorkstationAdapterDescriptor | None, str | None]:
        adapter_name = task_request.get("adapter")
        if not isinstance(adapter_name, str) or not adapter_name:
            return None, "DISPATCH_ADAPTER_UNKNOWN"
        adapter_descriptor, adapter_error = self._adapter_registry.resolve(adapter_name)
        if adapter_error is not None:
            return None, adapter_error
        if adapter_name not in self._adapters:
            return adapter_descriptor, "DISPATCH_ADAPTER_CALLABLE_MISSING"
        if not selected:
            return adapter_descriptor, "DISPATCH_ROUTE_SELECTION_MISSING"
        if not isinstance(adapter_descriptor, WorkstationAdapterDescriptor):
            return None, "DISPATCH_ADAPTER_UNKNOWN"
        action_class = str(task_request.get("action_class"))
        if action_class not in set(adapter_descriptor.allowed_action_classes):
            return adapter_descriptor, "DISPATCH_ADAPTER_ACTION_CLASS_MISMATCH"
        allowed_workspaces = set(adapter_descriptor.allowed_workspace_ids)
        allowed_repositories = set(adapter_descriptor.allowed_repository_ids)
        for workspace in selected:
            workspace_id = str(workspace.get("workspace_id"))
            repository_id = str(workspace.get("repository_name"))
            if adapter_name not in set(workspace.get("allowed_tool_classes") or []):
                return adapter_descriptor, "DISPATCH_ADAPTER_WORKSPACE_MISMATCH"
            if allowed_workspaces and workspace_id not in allowed_workspaces:
                return adapter_descriptor, "DISPATCH_ADAPTER_WORKSPACE_MISMATCH"
            if allowed_repositories and repository_id not in allowed_repositories:
                return adapter_descriptor, "DISPATCH_ADAPTER_REPOSITORY_MISMATCH"
        if contract.get("policy_id") != task_request.get("policy_id"):
            return adapter_descriptor, "DISPATCH_POLICY_ID_MISMATCH"
        if contract.get("policy_version_hash") != task_request.get("policy_version_hash"):
            return adapter_descriptor, "DISPATCH_POLICY_VERSION_MISMATCH"
        return adapter_descriptor, None

    def _invoke_adapter(
        self,
        contract: Mapping[str, Any],
        task_request: Mapping[str, Any],
        selected: tuple[Mapping[str, Any], ...],
        adapter_descriptor: WorkstationAdapterDescriptor | None,
    ) -> Any:
        adapter_name = str(task_request.get("adapter"))
        adapter = self._adapters[adapter_name]
        paths_by_repository = task_request.get("paths_by_repository") or {}
        payload = {
            "task_id": contract.get("task_id"),
            "contract_hash": contract.get("request_hash"),
            "action": task_request.get("action"),
            "action_class": task_request.get("action_class"),
            "adapter": adapter_name,
            "adapter_version": adapter_descriptor.adapter_version if isinstance(adapter_descriptor, WorkstationAdapterDescriptor) else None,
            "invocation_schema": adapter_descriptor.invocation_schema if isinstance(adapter_descriptor, WorkstationAdapterDescriptor) else None,
            "repositories": [
                {
                    "workspace_id": workspace.get("workspace_id"),
                    "repository_id": workspace.get("repository_name"),
                    "local_root": workspace.get("local_root"),
                    "remote_identity": workspace.get("remote_identity"),
                    "branch": task_request.get("branch"),
                    "base_sha": (task_request.get("base_shas") or {}).get(workspace.get("repository_name")),
                    "paths": list(paths_by_repository.get(workspace.get("repository_name")) or []),
                }
                for workspace in selected
            ],
            "policy_id": contract.get("policy_id"),
            "policy_version_hash": contract.get("policy_version_hash"),
            "arguments": dict(task_request.get("arguments") or {}),
        }
        return adapter(payload)

    def _normalize_adapter_result(self, adapter_result: Any) -> tuple[dict[str, Any], str | None]:
        if not isinstance(adapter_result, Mapping):
            return {"status": "REJECTED", "result_hash": sha256_reference(adapter_result)}, "DISPATCH_ADAPTER_RESULT_MALFORMED"
        sensitive_keys = {"secret", "token", "credential", "password", "private_key", "raw_payload"}
        if any(str(key).lower() in sensitive_keys for key in adapter_result):
            return {"status": "REJECTED", "result_hash": sha256_reference("sensitive-result-rejected")}, "DISPATCH_ADAPTER_RESULT_MALFORMED"
        status = adapter_result.get("status", "OK")
        if not isinstance(status, str) or not status:
            return {"status": "REJECTED", "result_hash": sha256_reference(adapter_result)}, "DISPATCH_ADAPTER_RESULT_MALFORMED"
        metadata = adapter_result.get("metadata", {})
        if metadata is not None and not isinstance(metadata, Mapping):
            return {"status": "REJECTED", "result_hash": sha256_reference(adapter_result)}, "DISPATCH_ADAPTER_RESULT_MALFORMED"
        return {
            "status": status,
            "metadata_hash": sha256_reference(metadata or {}),
            "result_hash": sha256_reference(adapter_result),
        }, None

    def _record_dispatch(
        self,
        decision: str,
        reason: str,
        contract: Mapping[str, Any] | None,
        task_request: Mapping[str, Any] | None,
        selected: tuple[Mapping[str, Any], ...],
        timestamp: str,
        *,
        adapter_descriptor: WorkstationAdapterDescriptor | None = None,
        invocation_status: str = "NOT_REACHED",
        adapter_result: Mapping[str, Any] | None = None,
        evidence_failure_reason: str = "DISPATCH_EVIDENCE_RECORDER_UNAVAILABLE",
    ) -> WorkstationDispatchResult:
        repository_ids = [str(workspace.get("repository_name")) for workspace in selected]
        workspace_ids = [str(workspace.get("workspace_id")) for workspace in selected]
        evidence = {
            "schema": "usbay.governed_workstation_dispatch.evidence.v1",
            "task_id": _safe_get(contract, "task_id"),
            "human_intent_hash": sha256_reference(_safe_get(contract, "human_intent")),
            "contract_hash": _hash_if_missing(contract) if isinstance(contract, Mapping) else None,
            "request_hash": sha256_reference(task_request or {}),
            "workspace_id": workspace_ids[0] if len(workspace_ids) == 1 else None,
            "repository_id": repository_ids[0] if len(repository_ids) == 1 else None,
            "workspace_ids": workspace_ids,
            "repository_ids": repository_ids,
            "policy_id": _safe_get(contract, "policy_id"),
            "policy_version_hash": _safe_get(contract, "policy_version_hash"),
            "base_sha": _safe_get(contract, "base_sha"),
            "action_class": _safe_get(task_request, "action_class"),
            "decision": decision,
            "decision_reason": reason,
            "adapter_selected": _safe_get(task_request, "adapter"),
            "adapter_id": adapter_descriptor.adapter_id if isinstance(adapter_descriptor, WorkstationAdapterDescriptor) else _safe_get(task_request, "adapter"),
            "adapter_type": adapter_descriptor.adapter_type if isinstance(adapter_descriptor, WorkstationAdapterDescriptor) else None,
            "adapter_version": adapter_descriptor.adapter_version if isinstance(adapter_descriptor, WorkstationAdapterDescriptor) else None,
            "adapter_identity_hash": sha256_reference(adapter_descriptor) if isinstance(adapter_descriptor, WorkstationAdapterDescriptor) else None,
            "invocation_schema": adapter_descriptor.invocation_schema if isinstance(adapter_descriptor, WorkstationAdapterDescriptor) else None,
            "invocation_status": invocation_status,
            "adapter_result_hash": sha256_reference(adapter_result or {}),
            "human_review_state": "REQUIRED"
            if _safe_get(task_request, "requires_human_review") or _safe_get(contract, "requires_human_review")
            else "NOT_REQUIRED",
            "repository_mutation": False,
            "autonomous_repository_registration": False,
            "autonomous_policy_creation": False,
            "policy_mutation": False,
            "autonomous_authority_expansion": False,
            "autonomous_merge": False,
            "autonomous_deploy": False,
            "unrestricted_shell": False,
            "unrestricted_network": False,
            "unrestricted_filesystem": False,
            "actor": "codex",
            "timestamp": timestamp,
        }
        try:
            record = self._evidence_recorder.record(evidence)
        except Exception:
            fallback = {
                **evidence,
                "decision": BLOCK,
                "decision_reason": evidence_failure_reason,
                "previous_evidence_hash": "sha256:" + ("0" * 64),
            }
            fallback["event_id"] = sha256_reference(fallback)
            return WorkstationDispatchResult(decision=BLOCK, reason=evidence_failure_reason, evidence=fallback)
        return WorkstationDispatchResult(decision=decision, reason=reason, evidence=record)


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
