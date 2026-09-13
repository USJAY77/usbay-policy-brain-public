from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor

from governance.dependency_artifact_provenance import ELIGIBLE, PROVEN, EligibilityDecision, artifact_record_hash
from security.dependency_artifact_evidence_store import (
    APPEND_ONLY_VIOLATION,
    CONFLICT,
    REPLAY,
    REVOKED,
    STORED,
    TIMEOUT,
    UNAVAILABLE,
    SQLiteDependencyArtifactEvidenceStore,
    UnavailableDependencyArtifactEvidenceStore,
)


def record(record_id="record-1", *, generation=1, supersedes=None):
    value = {
        "record_id": record_id,
        "package": {"normalized_project_name": "synthetic-package", "version": "1.0.0"},
        "platform": {"os": "macos", "architecture": "arm64", "python_tag": "cp311", "abi_tag": "cp311"},
        "lineage": {"generation": generation, "supersedes_record_id": supersedes},
        "artifact": {"sha256": "a" * 64},
        "record_hash": "sha256:" + "0" * 64,
    }
    value["record_hash"] = artifact_record_hash(value)
    return value


def decision(value):
    return EligibilityDecision(ELIGIBLE, PROVEN, (), value["record_id"], value["record_hash"])


def activate(store, value=None, replay_ids=None):
    value = value or record()
    return store.activate(
        record=value,
        decision=decision(value),
        replay_ids=replay_ids or ["evidence-1", "approval-1", "checkpoint-1"],
        actor_id="human-reviewer-1",
        device_id="device-1",
        timestamp="2026-09-04T12:00:00Z",
        policy_version="test-policy-v1",
    )


def aggregate_id():
    return "synthetic-package:macos:arm64:cp311:cp311"


def test_atomic_activation_is_restart_durable(tmp_path):
    path = tmp_path / "artifact-evidence.db"
    first = activate(SQLiteDependencyArtifactEvidenceStore(path))
    reopened = SQLiteDependencyArtifactEvidenceStore(path)
    assert first.state == STORED
    assert reopened.integrity_valid()
    assert reopened.current_record(aggregate_id())["record_id"] == "record-1"
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM consumed_artifact_evidence").fetchone()[0] == 3
        assert conn.execute("SELECT COUNT(*) FROM artifact_lifecycle_events").fetchone()[0] == 1


def test_replay_is_rejected_without_additional_events(tmp_path):
    path = tmp_path / "artifact-evidence.db"
    store = SQLiteDependencyArtifactEvidenceStore(path)
    assert activate(store).state == STORED
    assert activate(store).state == REPLAY
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM artifact_lifecycle_events").fetchone()[0] == 1


def test_concurrent_activation_has_exactly_one_winner(tmp_path):
    path = tmp_path / "artifact-evidence.db"

    def attempt(_):
        return activate(SQLiteDependencyArtifactEvidenceStore(path)).state

    with ThreadPoolExecutor(max_workers=12) as pool:
        states = list(pool.map(attempt, range(24)))
    assert states.count(STORED) == 1
    assert all(state in {STORED, REPLAY, CONFLICT, TIMEOUT} for state in states)
    assert SQLiteDependencyArtifactEvidenceStore(path).integrity_valid()


def test_rotation_requires_explicit_supersession_and_higher_generation(tmp_path):
    store = SQLiteDependencyArtifactEvidenceStore(tmp_path / "artifact-evidence.db")
    assert activate(store).state == STORED
    silent = record("record-2", generation=2)
    assert activate(store, silent, ["e2", "a2", "c2"]).reason_code == "DEPENDENCY_ARTIFACT_SUPERSESSION_REQUIRED"
    downgrade = record("record-2", generation=1, supersedes="record-1")
    assert activate(store, downgrade, ["e3", "a3", "c3"]).reason_code == "DEPENDENCY_ARTIFACT_DOWNGRADE"
    replacement = record("record-2", generation=2, supersedes="record-1")
    assert activate(store, replacement, ["e4", "a4", "c4"]).state == STORED
    assert store.current_record(aggregate_id())["record_id"] == "record-2"


def test_revocation_immediately_blocks_current_record_without_fallback(tmp_path):
    store = SQLiteDependencyArtifactEvidenceStore(tmp_path / "artifact-evidence.db")
    assert activate(store).state == STORED
    result = store.revoke(
        record_id="record-1", actor_id="human-reviewer-1", device_id="device-1",
        timestamp="2026-09-04T13:00:00Z", policy_version="test-policy-v1",
    )
    assert result.state == REVOKED
    assert store.current_record(aggregate_id()) is None
    repeated = store.revoke(
        record_id="record-1", actor_id="human-reviewer-1", device_id="device-1",
        timestamp="2026-09-04T14:00:00Z", policy_version="test-policy-v1",
    )
    assert repeated.state == CONFLICT


def test_record_and_event_tampering_fail_integrity_and_future_activation(tmp_path):
    path = tmp_path / "artifact-evidence.db"
    store = SQLiteDependencyArtifactEvidenceStore(path)
    assert activate(store).state == STORED
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE artifact_records SET payload_json='{}'")
    assert store.integrity_valid() is False
    replacement = record("record-2", generation=2, supersedes="record-1")
    assert activate(store, replacement, ["e2", "a2", "c2"]).state == APPEND_ONLY_VIOLATION


def test_event_deletion_detected_by_count_sentinel(tmp_path):
    path = tmp_path / "artifact-evidence.db"
    store = SQLiteDependencyArtifactEvidenceStore(path)
    assert activate(store).state == STORED
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM artifact_lifecycle_events")
    assert store.integrity_valid() is False


def test_partial_write_failure_rolls_back_record_replay_ids_and_events(tmp_path):
    class BrokenStore(SQLiteDependencyArtifactEvidenceStore):
        def _append_event(self, *args, **kwargs):
            raise OSError("simulated local reference-store failure")

    path = tmp_path / "artifact-evidence.db"
    assert activate(BrokenStore(path)).state == UNAVAILABLE
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM artifact_records").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM consumed_artifact_evidence").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM artifact_lifecycle_events").fetchone()[0] == 0


def test_database_lock_times_out_and_does_not_fallback(tmp_path):
    path = tmp_path / "artifact-evidence.db"
    store = SQLiteDependencyArtifactEvidenceStore(path, timeout_seconds=0.01)
    initializer = store._connect()
    initializer.close()
    locker = sqlite3.connect(path, isolation_level=None)
    try:
        locker.execute("BEGIN EXCLUSIVE")
        assert activate(store).state == TIMEOUT
    finally:
        locker.rollback()
        locker.close()


def test_non_eligible_decision_and_unavailable_store_deny(tmp_path):
    value = record()
    denied = EligibilityDecision("DENY", "FAILED", ("reason",), value["record_id"], value["record_hash"])
    result = SQLiteDependencyArtifactEvidenceStore(tmp_path / "db").activate(
        record=value, decision=denied, replay_ids=["one"], actor_id="human", device_id="device",
        timestamp="2026-09-04T12:00:00Z", policy_version="policy",
    )
    assert result.state != STORED
    assert UnavailableDependencyArtifactEvidenceStore().activate().state == UNAVAILABLE


def test_store_contains_no_raw_sensitive_material(tmp_path):
    path = tmp_path / "artifact-evidence.db"
    assert activate(SQLiteDependencyArtifactEvidenceStore(path)).state == STORED
    rendered = path.read_bytes().decode("latin1", errors="ignore").lower()
    for forbidden in ("private key", "password", "access_token", "bearer ", "raw wheel"):
        assert forbidden not in rendered
