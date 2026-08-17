from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Callable, Mapping


ALLOW = "ALLOW"
BLOCK = "BLOCK"

READ_CAPABILITIES = frozenset(
    {
        "READ_METADATA",
        "READ_STATE",
        "READ_STATUS",
        "READ_EVIDENCE",
        "READ_REPOSITORY_STATE",
        "READ_PR_STATE",
        "READ_CHECK_STATE",
        "READ_REVIEW_STATE",
        "READ_RUNTIME_STATE",
        "READ_MESSAGE_STATE",
        "READ_PROCESS_STATE",
    }
)
WRITE_CAPABILITY_PREFIXES = ("WRITE_", "MERGE", "DEPLOY", "EXECUTE", "DELETE", "PUBLISH")
FORBIDDEN_CAPABILITIES = frozenset(
    {
        "CREATE",
        "UPDATE",
        "DELETE",
        "WRITE",
        "EXECUTE",
        "APPROVE",
        "MERGE",
        "DEPLOY",
        "PUBLISH",
        "CHANGE_POLICY",
        "REGISTER_NEW_AUTHORITY",
    }
)
GENESIS_EVIDENCE_HASH = "sha256:" + ("0" * 64)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256_reference(value: Any) -> str:
    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _is_sha256_reference(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 71 and value.startswith("sha256:") and all(
        char in "0123456789abcdef" for char in value[7:]
    )


def _contains_sensitive_marker(value: Any) -> bool:
    text = canonical_json(value).lower()
    return any(marker in text for marker in ("password", "secret", "token", "private_key", "authorization", "raw_payload"))


def _normal_tuple(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple, set, frozenset)):
        return ()
    return tuple(str(value) for value in values if isinstance(value, str) and value)


@dataclass(frozen=True)
class GovernedWorkspaceRecord:
    workspace_id: str
    workspace_type: str
    remote_identity: str
    policy_id: str
    policy_version_hash: str
    allowed_connector_ids: tuple[str, ...]
    capabilities: Mapping[str, tuple[str, ...]]
    enabled: bool
    registration_version: str
    created_at: str
    updated_at: str
    repository_id: str | None = None
    project_id: str | None = None
    local_identity: str | None = None
    connector_types: Mapping[str, str] = field(default_factory=dict)

    def to_record(self) -> dict[str, Any]:
        return {
            "workspace_id": self.workspace_id,
            "workspace_type": self.workspace_type,
            "repository_id": self.repository_id,
            "project_id": self.project_id,
            "remote_identity": self.remote_identity,
            "local_identity": self.local_identity,
            "policy_id": self.policy_id,
            "policy_version_hash": self.policy_version_hash,
            "allowed_connector_ids": list(self.allowed_connector_ids),
            "capabilities": {connector_id: list(caps) for connector_id, caps in sorted(self.capabilities.items())},
            "connector_types": dict(sorted(self.connector_types.items())),
            "enabled": self.enabled,
            "registration_version": self.registration_version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True)
class WorkspaceObservation:
    observation_id: str
    workspace_id: str
    connector_id: str
    connector_type: str
    capability: str
    observed_at: str
    source_state_reference: str
    source_revision: str
    payload_hash: str
    policy_id: str
    policy_version_hash: str
    freshness_deadline: str
    evidence_reference: str
    evidence_hash: str

    def to_record(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "workspace_id": self.workspace_id,
            "connector_id": self.connector_id,
            "connector_type": self.connector_type,
            "capability": self.capability,
            "observed_at": self.observed_at,
            "source_state_reference": self.source_state_reference,
            "source_revision": self.source_revision,
            "payload_hash": self.payload_hash,
            "policy_id": self.policy_id,
            "policy_version_hash": self.policy_version_hash,
            "freshness_deadline": self.freshness_deadline,
            "evidence_reference": self.evidence_reference,
            "evidence_hash": self.evidence_hash,
        }


@dataclass(frozen=True)
class GovernedReadOnlyConnectorDescriptor:
    connector_id: str
    connector_type: str
    connector_version: str
    capabilities: tuple[str, ...]
    credential_reference: str
    credential_scopes: tuple[str, ...]
    enabled: bool = True

    def to_record(self) -> dict[str, Any]:
        return {
            "connector_id": self.connector_id,
            "connector_type": self.connector_type,
            "connector_version": self.connector_version,
            "capabilities": list(self.capabilities),
            "credential_reference_hash": sha256_reference(self.credential_reference),
            "credential_scopes": list(self.credential_scopes),
            "enabled": self.enabled,
            "read_only": True,
            "write_authority": False,
            "execution_authority": False,
            "deployment_authority": False,
        }


@dataclass(frozen=True)
class WorkspaceConnectorReadRequest:
    request_id: str
    workspace_id: str
    connector_id: str
    capability: str
    resource_id: str
    policy_id: str
    policy_version_hash: str
    expected_source_identity: str
    expected_source_revision: str | None = None


@dataclass(frozen=True)
class GovernedExternalObservation:
    source_identity: str
    observed_at: str
    retrieved_at: str
    source_state_reference: str
    source_revision: str
    observed_state: Mapping[str, Any]
    freshness_deadline: str


@dataclass(frozen=True)
class WorkspaceObservationDecision:
    decision: str
    reason: str
    evidence: dict[str, Any]
    workspace_id: str | None = None
    connector_id: str | None = None


class WorkspaceControlPlaneEvidenceRecorder:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self.previous_evidence_hash = GENESIS_EVIDENCE_HASH

    def record(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        event = dict(payload)
        event["previous_evidence_hash"] = self.previous_evidence_hash
        event["event_hash"] = sha256_reference(event)
        self.previous_evidence_hash = event["event_hash"]
        self.records.append(event)
        return event


class GovernedWorkspaceControlPlane:
    def __init__(
        self,
        workspaces: list[GovernedWorkspaceRecord | Mapping[str, Any]],
        *,
        connectors: list[GovernedReadOnlyConnectorDescriptor | Mapping[str, Any]] | None = None,
        evidence_recorder: WorkspaceControlPlaneEvidenceRecorder | None = None,
        clock: Callable[[], str] = utc_now,
    ) -> None:
        self._workspaces = tuple(_coerce_workspace(record) for record in workspaces)
        self._connectors = tuple(_coerce_connector(record) for record in connectors or [])
        self._evidence_recorder = evidence_recorder or WorkspaceControlPlaneEvidenceRecorder()
        self._clock = clock

    def resolve_workspace(self, workspace_id: str, *, policy_id: str, policy_version_hash: str) -> WorkspaceObservationDecision:
        timestamp = self._clock()
        workspace, reason = self._resolve_workspace_identity(workspace_id, policy_id=policy_id, policy_version_hash=policy_version_hash)
        decision = ALLOW if reason is None else BLOCK
        return self._finalize(
            decision,
            "WORKSPACE_ACCEPTED" if reason is None else reason,
            workspace=workspace,
            observation=None,
            timestamp=timestamp,
        )

    def resolve_repository_identity(
        self,
        *,
        repository_id: str,
        remote_identity: str,
        local_identity: str | None,
        policy_id: str,
        policy_version_hash: str,
    ) -> WorkspaceObservationDecision:
        timestamp = self._clock()
        matches = [
            workspace
            for workspace in self._workspaces
            if workspace.repository_id == repository_id
            and workspace.remote_identity == remote_identity
            and (local_identity is None or workspace.local_identity == local_identity)
        ]
        if len(matches) != 1:
            return self._finalize(BLOCK, "WORKSPACE_IDENTITY_AMBIGUOUS", workspace=None, observation=None, timestamp=timestamp)
        workspace = matches[0]
        reason = self._validate_workspace_record(workspace, policy_id=policy_id, policy_version_hash=policy_version_hash)
        return self._finalize(
            ALLOW if reason is None else BLOCK,
            "WORKSPACE_ACCEPTED" if reason is None else reason,
            workspace=workspace if reason is None else None,
            observation=None,
            timestamp=timestamp,
        )

    def consume_observation(
        self,
        observation: WorkspaceObservation | Mapping[str, Any] | None,
        *,
        expected_workspace_id: str | None = None,
        expected_connector_id: str | None = None,
        expected_source_revision: str | None = None,
    ) -> WorkspaceObservationDecision:
        timestamp = self._clock()
        normalized_observation = _coerce_observation(observation)
        workspace: GovernedWorkspaceRecord | None = None
        reason = "OBSERVATION_MALFORMED" if normalized_observation is None else None
        if reason is None and normalized_observation is not None:
            if expected_workspace_id is not None and normalized_observation.workspace_id != expected_workspace_id:
                reason = "OBSERVATION_WORKSPACE_SUBSTITUTION"
            elif expected_connector_id is not None and normalized_observation.connector_id != expected_connector_id:
                reason = "OBSERVATION_CONNECTOR_SUBSTITUTION"
        if reason is None and normalized_observation is not None:
            workspace, reason = self._resolve_workspace_identity(
                normalized_observation.workspace_id,
                policy_id=normalized_observation.policy_id,
                policy_version_hash=normalized_observation.policy_version_hash,
            )
        if reason is None and normalized_observation is not None and workspace is not None:
            reason = self._validate_connector_capability(workspace, normalized_observation)
        if reason is None and normalized_observation is not None:
            reason = self._validate_observation_freshness(normalized_observation, timestamp, expected_source_revision)
        decision = ALLOW if reason is None else BLOCK
        return self._finalize(
            decision,
            "OBSERVATION_ACCEPTED" if reason is None else reason,
            workspace=workspace if reason is None else None,
            observation=normalized_observation,
            timestamp=timestamp,
        )

    def observe_with_connector(
        self,
        request: WorkspaceConnectorReadRequest | Mapping[str, Any] | None,
        external_reader: Callable[[dict[str, Any]], Mapping[str, Any]],
    ) -> WorkspaceObservationDecision:
        timestamp = self._clock()
        read_request = _coerce_read_request(request)
        workspace: GovernedWorkspaceRecord | None = None
        connector: GovernedReadOnlyConnectorDescriptor | None = None
        external_payload: GovernedExternalObservation | None = None
        observation: WorkspaceObservation | None = None
        reason = "CONNECTOR_REQUEST_MALFORMED" if read_request is None else None
        if reason is None and read_request is not None:
            workspace, reason = self._resolve_workspace_identity(
                read_request.workspace_id,
                policy_id=read_request.policy_id,
                policy_version_hash=read_request.policy_version_hash,
            )
        if reason is None and read_request is not None and workspace is not None:
            connector, reason = self._resolve_read_only_connector(workspace, read_request)
        if reason is None and read_request is not None and workspace is not None and connector is not None:
            invocation = self._build_read_invocation(workspace, connector, read_request)
            try:
                external_payload = _coerce_external_observation(external_reader(invocation))
            except TimeoutError:
                reason = "CONNECTOR_READ_TIMEOUT"
            except Exception:
                reason = "CONNECTOR_EXTERNAL_READ_FAILED"
        if reason is None and read_request is not None and workspace is not None and connector is not None:
            if external_payload is None:
                reason = "CONNECTOR_RESPONSE_MALFORMED"
            elif external_payload.source_identity != read_request.expected_source_identity:
                reason = "CONNECTOR_SOURCE_IDENTITY_MISMATCH"
        if reason is None and read_request is not None and workspace is not None and connector is not None and external_payload is not None:
            observation = WorkspaceObservation(
                observation_id=sha256_reference(
                    {
                        "request_id": read_request.request_id,
                        "workspace_id": read_request.workspace_id,
                        "connector_id": read_request.connector_id,
                        "resource_id": read_request.resource_id,
                        "source_revision": external_payload.source_revision,
                    }
                ),
                workspace_id=workspace.workspace_id,
                connector_id=connector.connector_id,
                connector_type=connector.connector_type,
                capability=read_request.capability,
                observed_at=external_payload.observed_at,
                source_state_reference=external_payload.source_state_reference,
                source_revision=external_payload.source_revision,
                payload_hash=sha256_reference(external_payload.observed_state),
                policy_id=workspace.policy_id,
                policy_version_hash=workspace.policy_version_hash,
                freshness_deadline=external_payload.freshness_deadline,
                evidence_reference=sha256_reference(
                    {
                        "request_id": read_request.request_id,
                        "connector_id": connector.connector_id,
                        "connector_version": connector.connector_version,
                        "retrieved_at": external_payload.retrieved_at,
                    }
                ),
                evidence_hash=sha256_reference(
                    {
                        "workspace_id": workspace.workspace_id,
                        "connector_id": connector.connector_id,
                        "connector_version": connector.connector_version,
                        "resource_id": read_request.resource_id,
                        "request_id": read_request.request_id,
                        "source_revision": external_payload.source_revision,
                        "payload_hash": sha256_reference(external_payload.observed_state),
                    }
                ),
            )
            consumed = self.consume_observation(
                observation,
                expected_workspace_id=read_request.workspace_id,
                expected_connector_id=read_request.connector_id,
                expected_source_revision=read_request.expected_source_revision,
            )
            if consumed.decision != ALLOW:
                return consumed
            return self._finalize(
                ALLOW,
                "CONNECTOR_OBSERVATION_ACCEPTED",
                workspace=workspace,
                observation=observation,
                timestamp=timestamp,
                connector=connector,
                read_request=read_request,
                external_invoked=True,
            )
        return self._finalize(
            BLOCK,
            reason or "CONNECTOR_OBSERVATION_BLOCKED",
            workspace=workspace,
            observation=observation,
            timestamp=timestamp,
            connector=connector,
            read_request=read_request,
            external_invoked=external_payload is not None,
        )

    def summary(self) -> dict[str, Any]:
        return {
            "workspace_count": len(self._workspaces),
            "connector_count": len(self._connectors),
            "read_only": True,
            "write_enabled": False,
            "write_authority": False,
            "execution_authority": False,
            "deployment_enabled": False,
            "production_authorized": False,
            "autonomous_workspace_registration": False,
            "autonomous_connector_registration": False,
            "autonomous_policy_creation": False,
            "policy_mutation": False,
        }

    def _resolve_workspace_identity(
        self,
        workspace_id: str,
        *,
        policy_id: str,
        policy_version_hash: str,
    ) -> tuple[GovernedWorkspaceRecord | None, str | None]:
        if not isinstance(workspace_id, str) or not workspace_id:
            return None, "WORKSPACE_ID_MISSING"
        matches = [workspace for workspace in self._workspaces if workspace.workspace_id == workspace_id]
        if not matches:
            return None, "WORKSPACE_UNKNOWN"
        if len(matches) > 1:
            return None, "WORKSPACE_IDENTITY_AMBIGUOUS"
        workspace = matches[0]
        reason = self._validate_workspace_record(workspace, policy_id=policy_id, policy_version_hash=policy_version_hash)
        return (workspace if reason is None else None), reason

    def _validate_workspace_record(
        self,
        workspace: GovernedWorkspaceRecord,
        *,
        policy_id: str,
        policy_version_hash: str,
    ) -> str | None:
        payload = workspace.to_record()
        if _contains_sensitive_marker(payload):
            return "WORKSPACE_REGISTRY_SENSITIVE_DATA"
        required = (
            workspace.workspace_id,
            workspace.workspace_type,
            workspace.remote_identity,
            workspace.policy_id,
            workspace.policy_version_hash,
            workspace.registration_version,
            workspace.created_at,
            workspace.updated_at,
        )
        if any(not isinstance(value, str) or not value for value in required):
            return "WORKSPACE_REGISTRY_MALFORMED"
        if workspace.repository_id and workspace.project_id:
            return "WORKSPACE_REPOSITORY_PROJECT_AMBIGUOUS"
        if workspace.enabled is not True:
            return "WORKSPACE_DISABLED"
        if not _is_sha256_reference(workspace.policy_version_hash):
            return "WORKSPACE_POLICY_BINDING_MALFORMED"
        if workspace.policy_id != policy_id:
            return "WORKSPACE_POLICY_ID_MISMATCH"
        if workspace.policy_version_hash != policy_version_hash:
            return "WORKSPACE_POLICY_VERSION_MISMATCH"
        if parse_utc(workspace.created_at) is None or parse_utc(workspace.updated_at) is None:
            return "WORKSPACE_REGISTRY_TIMESTAMP_MALFORMED"
        if len(set(workspace.allowed_connector_ids)) != len(workspace.allowed_connector_ids):
            return "WORKSPACE_CONNECTOR_ID_AMBIGUOUS"
        return None

    def _resolve_read_only_connector(
        self,
        workspace: GovernedWorkspaceRecord,
        read_request: WorkspaceConnectorReadRequest,
    ) -> tuple[GovernedReadOnlyConnectorDescriptor | None, str | None]:
        capability = read_request.capability
        if capability in FORBIDDEN_CAPABILITIES or any(capability.startswith(prefix) for prefix in WRITE_CAPABILITY_PREFIXES):
            return None, "CONNECTOR_WRITE_CAPABILITY_BLOCKED"
        matches = [connector for connector in self._connectors if connector.connector_id == read_request.connector_id]
        if not matches:
            return None, "CONNECTOR_UNKNOWN"
        if len(matches) > 1:
            return None, "CONNECTOR_AMBIGUOUS"
        connector = matches[0]
        if connector.enabled is not True:
            return connector, "CONNECTOR_DISABLED"
        if any(item in FORBIDDEN_CAPABILITIES or item.startswith(WRITE_CAPABILITY_PREFIXES) for item in connector.capabilities):
            return connector, "CONNECTOR_CAPABILITY_ESCALATION"
        if read_request.connector_id not in workspace.allowed_connector_ids:
            return connector, "CONNECTOR_NOT_AUTHORIZED_FOR_WORKSPACE"
        if connector.connector_type != workspace.connector_types.get(read_request.connector_id):
            return connector, "CONNECTOR_TYPE_MISMATCH"
        workspace_capabilities = workspace.capabilities.get(read_request.connector_id, ())
        if capability not in workspace_capabilities or capability not in connector.capabilities:
            return connector, "CONNECTOR_CAPABILITY_UNDECLARED"
        if capability not in READ_CAPABILITIES:
            return connector, "CONNECTOR_CAPABILITY_UNKNOWN"
        credential_reason = self._validate_credential_reference(connector, capability)
        if credential_reason is not None:
            return connector, credential_reason
        return connector, None

    def _validate_credential_reference(self, connector: GovernedReadOnlyConnectorDescriptor, capability: str) -> str | None:
        reference = connector.credential_reference
        if not isinstance(reference, str) or not reference:
            return "CONNECTOR_CREDENTIAL_REFERENCE_MISSING"
        if _contains_sensitive_marker(reference) or not reference.startswith(("credential://", "vault://", "keychain://")):
            return "CONNECTOR_CREDENTIAL_REFERENCE_MALFORMED"
        if capability not in connector.credential_scopes:
            return "CONNECTOR_CREDENTIAL_SCOPE_MISMATCH"
        if any(scope in FORBIDDEN_CAPABILITIES or scope.startswith(WRITE_CAPABILITY_PREFIXES) for scope in connector.credential_scopes):
            return "CONNECTOR_CREDENTIAL_SCOPE_MISMATCH"
        return None

    def _build_read_invocation(
        self,
        workspace: GovernedWorkspaceRecord,
        connector: GovernedReadOnlyConnectorDescriptor,
        read_request: WorkspaceConnectorReadRequest,
    ) -> dict[str, Any]:
        return {
            "request_id": read_request.request_id,
            "workspace_id": workspace.workspace_id,
            "workspace_identity_hash": sha256_reference(workspace.to_record()),
            "connector_id": connector.connector_id,
            "connector_type": connector.connector_type,
            "connector_version": connector.connector_version,
            "capability": read_request.capability,
            "resource_id": read_request.resource_id,
            "credential_reference_hash": sha256_reference(connector.credential_reference),
            "credential_material": None,
            "read_only": True,
            "write_enabled": False,
            "execution_enabled": False,
            "deployment_enabled": False,
        }

    def _validate_connector_capability(self, workspace: GovernedWorkspaceRecord, observation: WorkspaceObservation) -> str | None:
        capability = observation.capability
        if any(capability.startswith(prefix) for prefix in WRITE_CAPABILITY_PREFIXES):
            return "CONNECTOR_WRITE_CAPABILITY_BLOCKED"
        if capability not in READ_CAPABILITIES:
            return "CONNECTOR_CAPABILITY_UNKNOWN"
        connector_known = observation.connector_id in workspace.capabilities or observation.connector_id in workspace.connector_types
        if not connector_known:
            return "CONNECTOR_UNKNOWN"
        if observation.connector_id not in workspace.allowed_connector_ids:
            return "CONNECTOR_NOT_AUTHORIZED_FOR_WORKSPACE"
        declared = tuple(workspace.capabilities.get(observation.connector_id, ()))
        if capability not in declared:
            return "CONNECTOR_CAPABILITY_UNDECLARED"
        declared_type = workspace.connector_types.get(observation.connector_id)
        if declared_type is not None and declared_type != observation.connector_type:
            return "CONNECTOR_TYPE_MISMATCH"
        return None

    def _validate_observation_freshness(
        self,
        observation: WorkspaceObservation,
        timestamp: str,
        expected_source_revision: str | None,
    ) -> str | None:
        if any(not getattr(observation, field_name) for field_name in observation.__dataclass_fields__):
            return "OBSERVATION_MALFORMED"
        if not _is_sha256_reference(observation.payload_hash) or not _is_sha256_reference(observation.evidence_hash):
            return "OBSERVATION_MALFORMED"
        observed_at = parse_utc(observation.observed_at)
        deadline = parse_utc(observation.freshness_deadline)
        now = parse_utc(timestamp)
        if observed_at is None or deadline is None or now is None:
            return "OBSERVATION_FRESHNESS_UNKNOWN"
        if observed_at > now:
            return "OBSERVATION_MALFORMED"
        if now >= deadline:
            return "OBSERVATION_STALE"
        if expected_source_revision is not None and observation.source_revision != expected_source_revision:
            return "OBSERVATION_SOURCE_REVISION_MISMATCH"
        if _contains_sensitive_marker(observation.to_record()):
            return "OBSERVATION_SENSITIVE_DATA_BLOCKED"
        return None

    def _finalize(
        self,
        decision: str,
        reason: str,
        *,
        workspace: GovernedWorkspaceRecord | None,
        observation: WorkspaceObservation | None,
        timestamp: str,
        connector: GovernedReadOnlyConnectorDescriptor | None = None,
        read_request: WorkspaceConnectorReadRequest | None = None,
        external_invoked: bool = False,
    ) -> WorkspaceObservationDecision:
        payload = {
            "schema": "usbay.workspace_control_plane.observation_evidence.v1",
            "workspace_identity_hash": sha256_reference(workspace.to_record()) if workspace else None,
            "workspace_id": workspace.workspace_id if workspace else (observation.workspace_id if observation else None),
            "connector_id": observation.connector_id if observation else None,
            "connector_type": observation.connector_type if observation else None,
            "capability": observation.capability if observation else None,
            "policy_id": workspace.policy_id if workspace else (observation.policy_id if observation else None),
            "policy_version_hash": workspace.policy_version_hash if workspace else (observation.policy_version_hash if observation else None),
            "observation_hash": sha256_reference(observation.to_record()) if observation else None,
            "source_state_reference_hash": sha256_reference(observation.source_state_reference) if observation else None,
            "source_revision": observation.source_revision if observation else None,
            "connector_version": connector.connector_version if connector else None,
            "resource_id": read_request.resource_id if read_request else None,
            "request_id": read_request.request_id if read_request else None,
            "credential_reference_hash": sha256_reference(connector.credential_reference) if connector else None,
            "external_invoked": external_invoked,
            "freshness_result": "FRESH" if decision == ALLOW else "BLOCKED",
            "decision": decision,
            "reason": reason,
            "timestamp": timestamp,
            "read_only": True,
            "write_enabled": False,
            "execution_enabled": False,
            "deployment_authorized": False,
            "production_authorized": False,
            "autonomous_workspace_registration": False,
            "autonomous_connector_registration": False,
            "autonomous_policy_creation": False,
            "policy_mutation": False,
        }
        try:
            evidence = self._evidence_recorder.record(payload)
        except Exception:
            fallback = {
                **payload,
                "decision": BLOCK,
                "reason": "OBSERVATION_EVIDENCE_RECORDER_UNAVAILABLE",
                "previous_evidence_hash": GENESIS_EVIDENCE_HASH,
            }
            fallback["event_hash"] = sha256_reference(fallback)
            return WorkspaceObservationDecision(
                decision=BLOCK,
                reason="OBSERVATION_EVIDENCE_RECORDER_UNAVAILABLE",
                evidence=fallback,
                workspace_id=fallback.get("workspace_id"),
                connector_id=fallback.get("connector_id"),
            )
        return WorkspaceObservationDecision(
            decision=decision,
            reason=reason,
            evidence=evidence,
            workspace_id=evidence.get("workspace_id"),
            connector_id=evidence.get("connector_id"),
        )


def _coerce_workspace(record: GovernedWorkspaceRecord | Mapping[str, Any]) -> GovernedWorkspaceRecord:
    if isinstance(record, GovernedWorkspaceRecord):
        return record
    if not isinstance(record, Mapping):
        return GovernedWorkspaceRecord("", "", "", "", "", (), {}, False, "", "")
    capabilities = {
        str(connector_id): _normal_tuple(values)
        for connector_id, values in (record.get("capabilities") or {}).items()
        if isinstance(connector_id, str)
    }
    return GovernedWorkspaceRecord(
        workspace_id=str(record.get("workspace_id", "")),
        workspace_type=str(record.get("workspace_type", "")),
        repository_id=_optional_string(record.get("repository_id")),
        project_id=_optional_string(record.get("project_id")),
        remote_identity=str(record.get("remote_identity", "")),
        local_identity=_optional_string(record.get("local_identity")),
        policy_id=str(record.get("policy_id", "")),
        policy_version_hash=str(record.get("policy_version_hash", "")),
        allowed_connector_ids=_normal_tuple(record.get("allowed_connector_ids")),
        capabilities=capabilities,
        connector_types={str(key): str(value) for key, value in (record.get("connector_types") or {}).items() if isinstance(key, str)},
        enabled=record.get("enabled") is True,
        registration_version=str(record.get("registration_version", "")),
        created_at=str(record.get("created_at", "")),
        updated_at=str(record.get("updated_at", "")),
    )


def _coerce_connector(record: GovernedReadOnlyConnectorDescriptor | Mapping[str, Any]) -> GovernedReadOnlyConnectorDescriptor:
    if isinstance(record, GovernedReadOnlyConnectorDescriptor):
        return record
    if not isinstance(record, Mapping):
        return GovernedReadOnlyConnectorDescriptor("", "", "", (), "", (), False)
    return GovernedReadOnlyConnectorDescriptor(
        connector_id=str(record.get("connector_id", "")),
        connector_type=str(record.get("connector_type", "")),
        connector_version=str(record.get("connector_version", "")),
        capabilities=_normal_tuple(record.get("capabilities")),
        credential_reference=str(record.get("credential_reference", "")),
        credential_scopes=_normal_tuple(record.get("credential_scopes")),
        enabled=record.get("enabled") is True,
    )


def _coerce_read_request(request: WorkspaceConnectorReadRequest | Mapping[str, Any] | None) -> WorkspaceConnectorReadRequest | None:
    if isinstance(request, WorkspaceConnectorReadRequest):
        return request if _read_request_complete(request) else None
    if not isinstance(request, Mapping):
        return None
    candidate = WorkspaceConnectorReadRequest(
        request_id=str(request.get("request_id", "")),
        workspace_id=str(request.get("workspace_id", "")),
        connector_id=str(request.get("connector_id", "")),
        capability=str(request.get("capability", "")),
        resource_id=str(request.get("resource_id", "")),
        policy_id=str(request.get("policy_id", "")),
        policy_version_hash=str(request.get("policy_version_hash", "")),
        expected_source_identity=str(request.get("expected_source_identity", "")),
        expected_source_revision=_optional_string(request.get("expected_source_revision")),
    )
    return candidate if _read_request_complete(candidate) else None


def _read_request_complete(request: WorkspaceConnectorReadRequest) -> bool:
    return all(
        isinstance(value, str) and value
        for value in (
            request.request_id,
            request.workspace_id,
            request.connector_id,
            request.capability,
            request.resource_id,
            request.policy_id,
            request.policy_version_hash,
            request.expected_source_identity,
        )
    )


def _coerce_external_observation(payload: Mapping[str, Any] | GovernedExternalObservation | None) -> GovernedExternalObservation | None:
    if isinstance(payload, GovernedExternalObservation):
        return payload if _external_observation_complete(payload) else None
    if not isinstance(payload, Mapping):
        return None
    observed_state = payload.get("observed_state")
    if not isinstance(observed_state, Mapping):
        return None
    candidate = GovernedExternalObservation(
        source_identity=str(payload.get("source_identity", "")),
        observed_at=str(payload.get("observed_at", "")),
        retrieved_at=str(payload.get("retrieved_at", "")),
        source_state_reference=str(payload.get("source_state_reference", "")),
        source_revision=str(payload.get("source_revision", "")),
        observed_state=dict(observed_state),
        freshness_deadline=str(payload.get("freshness_deadline", "")),
    )
    return candidate if _external_observation_complete(candidate) else None


def _external_observation_complete(observation: GovernedExternalObservation) -> bool:
    return all(
        isinstance(value, str) and value
        for value in (
            observation.source_identity,
            observation.observed_at,
            observation.retrieved_at,
            observation.source_state_reference,
            observation.source_revision,
            observation.freshness_deadline,
        )
    ) and isinstance(observation.observed_state, Mapping)


def _coerce_observation(observation: WorkspaceObservation | Mapping[str, Any] | None) -> WorkspaceObservation | None:
    if isinstance(observation, WorkspaceObservation):
        return observation
    if not isinstance(observation, Mapping):
        return None
    try:
        return WorkspaceObservation(
            observation_id=str(observation.get("observation_id", "")),
            workspace_id=str(observation.get("workspace_id", "")),
            connector_id=str(observation.get("connector_id", "")),
            connector_type=str(observation.get("connector_type", "")),
            capability=str(observation.get("capability", "")),
            observed_at=str(observation.get("observed_at", "")),
            source_state_reference=str(observation.get("source_state_reference", "")),
            source_revision=str(observation.get("source_revision", "")),
            payload_hash=str(observation.get("payload_hash", "")),
            policy_id=str(observation.get("policy_id", "")),
            policy_version_hash=str(observation.get("policy_version_hash", "")),
            freshness_deadline=str(observation.get("freshness_deadline", "")),
            evidence_reference=str(observation.get("evidence_reference", "")),
            evidence_hash=str(observation.get("evidence_hash", "")),
        )
    except Exception:
        return None


def _optional_string(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)
