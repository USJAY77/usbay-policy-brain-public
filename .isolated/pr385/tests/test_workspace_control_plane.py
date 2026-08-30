from __future__ import annotations

import pytest

from governance.workspace_control_plane import (
    ALLOW,
    BLOCK,
    GovernedReadOnlyConnectorDescriptor,
    GovernedExternalObservation,
    GovernedWorkspaceControlPlane,
    GovernedWorkspaceRecord,
    WorkspaceControlPlaneEvidenceRecorder,
    WorkspaceConnectorReadRequest,
    WorkspaceObservation,
    sha256_reference,
)


pytestmark = pytest.mark.governance

POLICY_HASH = "sha256:" + ("a" * 64)
NOW = "2026-08-17T06:00:00Z"


def workspace(**overrides):
    payload = {
        "workspace_id": "workspace-1",
        "workspace_type": "GITHUB_REPOSITORY",
        "repository_id": "repo-1",
        "project_id": None,
        "remote_identity": "github:USJAY77/usbay-policy-brain-public",
        "local_identity": "/workspaces/usbay-policy-brain",
        "policy_id": "policy-workspace-v1",
        "policy_version_hash": POLICY_HASH,
        "allowed_connector_ids": ("github-read",),
        "capabilities": {"github-read": ("READ_REPOSITORY_STATE", "READ_PR_STATE", "READ_CHECK_STATE", "READ_REVIEW_STATE")},
        "connector_types": {"github-read": "GITHUB"},
        "enabled": True,
        "registration_version": "workspace-registry-v1",
        "created_at": "2026-08-17T05:00:00Z",
        "updated_at": "2026-08-17T05:30:00Z",
    }
    payload.update(overrides)
    return GovernedWorkspaceRecord(**payload)


def live_workspace(**overrides):
    payload = {"capabilities": {"github-read": ("READ_METADATA", "READ_STATE", "READ_STATUS", "READ_EVIDENCE")}}
    payload.update(overrides)
    return workspace(**payload)


def connector(**overrides):
    payload = {
        "connector_id": "github-read",
        "connector_type": "GITHUB",
        "connector_version": "readonly-github-v1",
        "capabilities": ("READ_METADATA", "READ_STATE", "READ_STATUS", "READ_EVIDENCE"),
        "credential_reference": "credential://github-readonly",
        "credential_scopes": ("READ_METADATA", "READ_STATE", "READ_STATUS", "READ_EVIDENCE"),
        "enabled": True,
    }
    payload.update(overrides)
    return GovernedReadOnlyConnectorDescriptor(**payload)


def read_request(**overrides):
    payload = {
        "request_id": "request-1",
        "workspace_id": "workspace-1",
        "connector_id": "github-read",
        "capability": "READ_STATE",
        "resource_id": "repo-1",
        "policy_id": "policy-workspace-v1",
        "policy_version_hash": POLICY_HASH,
        "expected_source_identity": "github:USJAY77/usbay-policy-brain-public",
        "expected_source_revision": "abc123",
    }
    payload.update(overrides)
    return WorkspaceConnectorReadRequest(**payload)


def external_observation(**overrides):
    payload = {
        "source_identity": "github:USJAY77/usbay-policy-brain-public",
        "observed_at": "2026-08-17T05:59:00Z",
        "retrieved_at": "2026-08-17T05:59:10Z",
        "source_state_reference": "github:USJAY77/usbay-policy-brain-public@main",
        "source_revision": "abc123",
        "observed_state": {"default_branch": "main", "head": "abc123"},
        "freshness_deadline": "2026-08-17T06:05:00Z",
    }
    payload.update(overrides)
    return GovernedExternalObservation(**payload)


class SpyReader:
    def __init__(self, payload=None, exc=None):
        self.payload = payload if payload is not None else external_observation()
        self.exc = exc
        self.calls = []

    def __call__(self, invocation):
        self.calls.append(dict(invocation))
        if self.exc:
            raise self.exc
        return self.payload


def observation(**overrides):
    payload = {
        "observation_id": "obs-1",
        "workspace_id": "workspace-1",
        "connector_id": "github-read",
        "connector_type": "GITHUB",
        "capability": "READ_REPOSITORY_STATE",
        "observed_at": "2026-08-17T05:59:00Z",
        "source_state_reference": "github:refs/heads/main",
        "source_revision": "abc123",
        "payload_hash": sha256_reference({"state": "main", "sha": "abc123"}),
        "policy_id": "policy-workspace-v1",
        "policy_version_hash": POLICY_HASH,
        "freshness_deadline": "2026-08-17T06:05:00Z",
        "evidence_reference": "evidence://obs-1",
        "evidence_hash": sha256_reference({"observation_id": "obs-1"}),
    }
    payload.update(overrides)
    return WorkspaceObservation(**payload)


def control_plane(records=None, *, recorder=None):
    return GovernedWorkspaceControlPlane(records or [workspace()], evidence_recorder=recorder, clock=lambda: NOW)


def live_control_plane(records=None, connectors=None, *, recorder=None):
    return GovernedWorkspaceControlPlane(
        records or [live_workspace()],
        connectors=connectors or [connector()],
        evidence_recorder=recorder,
        clock=lambda: NOW,
    )


def test_registered_workspace_accepted_and_evidence_hash_bound():
    result = control_plane().resolve_workspace("workspace-1", policy_id="policy-workspace-v1", policy_version_hash=POLICY_HASH)

    assert result.decision == ALLOW
    assert result.reason == "WORKSPACE_ACCEPTED"
    assert result.evidence["event_hash"].startswith("sha256:")
    assert result.evidence["autonomous_workspace_registration"] is False


@pytest.mark.parametrize(
    ("records", "workspace_id", "reason"),
    [
        ([workspace()], "missing", "WORKSPACE_UNKNOWN"),
        ([workspace(enabled=False)], "workspace-1", "WORKSPACE_DISABLED"),
        ([workspace(), workspace(remote_identity="github:other/repo")], "workspace-1", "WORKSPACE_IDENTITY_AMBIGUOUS"),
    ],
)
def test_workspace_identity_fail_closed(records, workspace_id, reason):
    result = control_plane(records).resolve_workspace(workspace_id, policy_id="policy-workspace-v1", policy_version_hash=POLICY_HASH)

    assert result.decision == BLOCK
    assert result.reason == reason
    assert result.evidence["decision"] == BLOCK


def test_ambiguous_repository_identity_blocked():
    result = control_plane(
        [
            workspace(workspace_id="workspace-1"),
            workspace(workspace_id="workspace-2", local_identity="/other"),
        ]
    ).resolve_repository_identity(
        repository_id="repo-1",
        remote_identity="github:USJAY77/usbay-policy-brain-public",
        local_identity=None,
        policy_id="policy-workspace-v1",
        policy_version_hash=POLICY_HASH,
    )

    assert result.decision == BLOCK
    assert result.reason == "WORKSPACE_IDENTITY_AMBIGUOUS"


def test_policy_version_mismatch_blocked():
    result = control_plane().resolve_workspace(
        "workspace-1",
        policy_id="policy-workspace-v1",
        policy_version_hash="sha256:" + ("b" * 64),
    )

    assert result.decision == BLOCK
    assert result.reason == "WORKSPACE_POLICY_VERSION_MISMATCH"


def test_missing_workspace_id_blocked():
    result = control_plane().resolve_workspace("", policy_id="policy-workspace-v1", policy_version_hash=POLICY_HASH)

    assert result.decision == BLOCK
    assert result.reason == "WORKSPACE_ID_MISSING"


def test_malformed_policy_binding_blocked():
    result = control_plane([workspace(policy_version_hash="not-a-sha256-reference")]).resolve_workspace(
        "workspace-1",
        policy_id="policy-workspace-v1",
        policy_version_hash="not-a-sha256-reference",
    )

    assert result.decision == BLOCK
    assert result.reason == "WORKSPACE_POLICY_BINDING_MALFORMED"


def test_registered_read_capability_observation_accepted():
    result = control_plane().consume_observation(observation(), expected_source_revision="abc123")

    assert result.decision == ALLOW
    assert result.reason == "OBSERVATION_ACCEPTED"
    assert result.evidence["freshness_result"] == "FRESH"
    assert result.evidence["write_enabled"] is False


@pytest.mark.parametrize(
    ("obs", "reason"),
    [
        (observation(connector_id="unknown"), "CONNECTOR_UNKNOWN"),
        (observation(connector_id="other"), "CONNECTOR_UNKNOWN"),
        (observation(capability="READ_RUNTIME_STATE"), "CONNECTOR_CAPABILITY_UNDECLARED"),
        (observation(capability="WRITE_REPOSITORY_STATE"), "CONNECTOR_WRITE_CAPABILITY_BLOCKED"),
        (observation(capability="READ_UNKNOWN_STATE"), "CONNECTOR_CAPABILITY_UNKNOWN"),
        (observation(freshness_deadline="2026-08-17T05:59:59Z"), "OBSERVATION_STALE"),
        (observation(observed_at=""), "OBSERVATION_MALFORMED"),
        (observation(payload_hash="not-a-hash"), "OBSERVATION_MALFORMED"),
    ],
)
def test_observation_fail_closed_negative_states(obs, reason):
    result = control_plane().consume_observation(obs)

    assert result.decision == BLOCK
    assert result.reason == reason


def test_unknown_connector_distinguished_when_not_registered_anywhere():
    result = control_plane([workspace(allowed_connector_ids=(), capabilities={}, connector_types={})]).consume_observation(observation())

    assert result.decision == BLOCK
    assert result.reason == "CONNECTOR_UNKNOWN"


def test_declared_connector_not_authorized_for_workspace_blocked():
    result = control_plane([workspace(allowed_connector_ids=(), capabilities={"github-read": ("READ_REPOSITORY_STATE",)})]).consume_observation(observation())

    assert result.decision == BLOCK
    assert result.reason == "CONNECTOR_NOT_AUTHORIZED_FOR_WORKSPACE"


def test_connector_type_mismatch_blocks_substitution():
    result = control_plane().consume_observation(observation(connector_type="SLACK"))

    assert result.decision == BLOCK
    assert result.reason == "CONNECTOR_TYPE_MISMATCH"


def test_missing_freshness_deadline_blocks_consumption():
    result = control_plane().consume_observation(observation(freshness_deadline=""))

    assert result.decision == BLOCK
    assert result.reason == "OBSERVATION_MALFORMED"


def test_observation_workspace_substitution_blocked():
    result = control_plane().consume_observation(observation(), expected_workspace_id="workspace-2")

    assert result.decision == BLOCK
    assert result.reason == "OBSERVATION_WORKSPACE_SUBSTITUTION"


def test_connector_substitution_blocked():
    result = control_plane().consume_observation(observation(), expected_connector_id="other-connector")

    assert result.decision == BLOCK
    assert result.reason == "OBSERVATION_CONNECTOR_SUBSTITUTION"


def test_source_revision_mismatch_blocks_consumption():
    result = control_plane().consume_observation(observation(), expected_source_revision="def456")

    assert result.decision == BLOCK
    assert result.reason == "OBSERVATION_SOURCE_REVISION_MISMATCH"


def test_evidence_produced_for_allow_and_block():
    recorder = WorkspaceControlPlaneEvidenceRecorder()
    plane = control_plane(recorder=recorder)

    allowed = plane.consume_observation(observation())
    blocked = plane.consume_observation(observation(freshness_deadline="2026-08-17T05:00:00Z"))

    assert allowed.evidence["event_hash"] == recorder.records[0]["event_hash"]
    assert blocked.evidence["event_hash"] == recorder.records[1]["event_hash"]
    assert recorder.records[1]["previous_evidence_hash"] == recorder.records[0]["event_hash"]


def test_evidence_recorder_failure_fails_closed():
    class BrokenRecorder:
        def record(self, payload):
            raise RuntimeError("disk unavailable")

    result = control_plane(recorder=BrokenRecorder()).consume_observation(observation())

    assert result.decision == BLOCK
    assert result.reason == "OBSERVATION_EVIDENCE_RECORDER_UNAVAILABLE"
    assert result.evidence["reason"] == "OBSERVATION_EVIDENCE_RECORDER_UNAVAILABLE"


def test_no_autonomous_workspace_or_connector_registration_and_no_policy_mutation():
    plane = control_plane()
    summary = plane.summary()

    assert not hasattr(plane, "register_workspace")
    assert not hasattr(plane, "register_connector")
    assert summary["autonomous_workspace_registration"] is False
    assert summary["autonomous_connector_registration"] is False
    assert summary["autonomous_policy_creation"] is False
    assert summary["policy_mutation"] is False
    assert summary["deployment_enabled"] is False
    assert summary["production_authorized"] is False


def test_sensitive_payload_markers_are_not_accepted_in_observation_evidence():
    result = control_plane().consume_observation(observation(source_state_reference="token=do-not-store"))

    assert result.decision == BLOCK
    assert result.reason == "OBSERVATION_SENSITIVE_DATA_BLOCKED"


def test_live_read_only_connector_returns_governed_observation_after_evidence():
    reader = SpyReader()

    result = live_control_plane().observe_with_connector(read_request(), reader)

    assert result.decision == ALLOW
    assert result.reason == "CONNECTOR_OBSERVATION_ACCEPTED"
    assert len(reader.calls) == 1
    assert reader.calls[0]["read_only"] is True
    assert reader.calls[0]["write_enabled"] is False
    assert reader.calls[0]["execution_enabled"] is False
    assert reader.calls[0]["credential_reference_hash"].startswith("sha256:")
    assert "credential://github-readonly" not in result.evidence.values()
    assert result.evidence["external_invoked"] is True
    assert result.evidence["request_id"] == "request-1"


@pytest.mark.parametrize(
    ("records", "connectors", "read_req", "reason"),
    [
        ([live_workspace()], [connector()], read_request(workspace_id="missing"), "WORKSPACE_UNKNOWN"),
        ([live_workspace(enabled=False)], [connector()], read_request(), "WORKSPACE_DISABLED"),
        ([live_workspace(), live_workspace(remote_identity="github:other/repo")], [connector()], read_request(), "WORKSPACE_IDENTITY_AMBIGUOUS"),
        ([live_workspace()], [connector()], read_request(policy_version_hash="sha256:" + ("b" * 64)), "WORKSPACE_POLICY_VERSION_MISMATCH"),
        ([live_workspace()], [], read_request(), "CONNECTOR_UNKNOWN"),
        ([live_workspace()], [connector(enabled=False)], read_request(), "CONNECTOR_DISABLED"),
        ([live_workspace()], [connector(), connector(connector_version="readonly-github-v2")], read_request(), "CONNECTOR_AMBIGUOUS"),
        ([live_workspace()], [connector()], read_request(connector_id="other"), "CONNECTOR_UNKNOWN"),
        ([live_workspace(allowed_connector_ids=())], [connector()], read_request(), "CONNECTOR_NOT_AUTHORIZED_FOR_WORKSPACE"),
        ([live_workspace(capabilities={"github-read": ("READ_METADATA",)})], [connector()], read_request(), "CONNECTOR_CAPABILITY_UNDECLARED"),
        ([live_workspace()], [connector()], read_request(capability="WRITE"), "CONNECTOR_WRITE_CAPABILITY_BLOCKED"),
        ([live_workspace()], [connector()], read_request(capability="EXECUTE"), "CONNECTOR_WRITE_CAPABILITY_BLOCKED"),
        ([live_workspace()], [connector(capabilities=("READ_METADATA", "READ_STATE", "WRITE"))], read_request(), "CONNECTOR_CAPABILITY_ESCALATION"),
        ([live_workspace()], [connector(credential_reference="")], read_request(), "CONNECTOR_CREDENTIAL_REFERENCE_MISSING"),
        ([live_workspace()], [connector(credential_reference="token=plaintext")], read_request(), "CONNECTOR_CREDENTIAL_REFERENCE_MALFORMED"),
        ([live_workspace()], [connector(credential_scopes=("READ_METADATA",))], read_request(), "CONNECTOR_CREDENTIAL_SCOPE_MISMATCH"),
    ],
)
def test_live_read_connector_blocks_before_external_invocation(records, connectors, read_req, reason):
    reader = SpyReader()

    result = GovernedWorkspaceControlPlane(records, connectors=connectors, clock=lambda: NOW).observe_with_connector(read_req, reader)

    assert result.decision == BLOCK
    assert result.reason == reason
    assert len(reader.calls) == 0
    assert result.evidence["external_invoked"] is False


@pytest.mark.parametrize(
    ("payload", "exc", "reason"),
    [
        ({"malformed": True}, None, "CONNECTOR_RESPONSE_MALFORMED"),
        (external_observation(source_identity="github:other/repo"), None, "CONNECTOR_SOURCE_IDENTITY_MISMATCH"),
        (external_observation(freshness_deadline="2026-08-17T05:00:00Z"), None, "OBSERVATION_STALE"),
        (external_observation(source_revision="stale"), None, "OBSERVATION_SOURCE_REVISION_MISMATCH"),
        (None, RuntimeError("network unavailable"), "CONNECTOR_EXTERNAL_READ_FAILED"),
        (None, TimeoutError("timeout"), "CONNECTOR_READ_TIMEOUT"),
    ],
)
def test_live_read_connector_blocks_after_failed_external_read(payload, exc, reason):
    reader = SpyReader(payload=payload, exc=exc)

    result = live_control_plane().observe_with_connector(read_request(), reader)

    assert result.decision == BLOCK
    assert result.reason == reason


def test_live_read_evidence_failure_does_not_return_trusted_observation():
    class BrokenRecorder:
        def record(self, payload):
            raise RuntimeError("evidence unavailable")

    reader = SpyReader()

    result = live_control_plane(recorder=BrokenRecorder()).observe_with_connector(read_request(), reader)

    assert len(reader.calls) == 1
    assert result.decision == BLOCK
    assert result.reason == "OBSERVATION_EVIDENCE_RECORDER_UNAVAILABLE"


def test_live_read_summary_has_no_authority_expansion():
    summary = live_control_plane().summary()

    assert summary["read_only"] is True
    assert summary["write_authority"] is False
    assert summary["execution_authority"] is False
    assert summary["deployment_enabled"] is False
    assert summary["production_authorized"] is False
    assert summary["autonomous_workspace_registration"] is False
    assert summary["autonomous_connector_registration"] is False
    assert summary["autonomous_policy_creation"] is False
    assert summary["policy_mutation"] is False
