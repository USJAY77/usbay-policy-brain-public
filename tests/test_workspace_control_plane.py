from __future__ import annotations

import pytest

from governance.workspace_control_plane import (
    ALLOW,
    BLOCK,
    GovernedWorkspaceControlPlane,
    GovernedWorkspaceRecord,
    WorkspaceControlPlaneEvidenceRecorder,
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
