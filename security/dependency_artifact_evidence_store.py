"""Append-only reference store for dependency-artifact authorization evidence.

SQLite is a bounded local reference/test adapter, not a production authority or
an external immutable/WORM anchor. Unknown or ambiguous storage outcomes deny.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from governance.dependency_artifact_provenance import EligibilityDecision, artifact_record_hash
from governance.hashing import canonical_json, sha256_reference


STORED = "STORED"
REPLAY = "REPLAY"
CONFLICT = "CONFLICT"
REVOKED = "REVOKED"
UNAVAILABLE = "UNAVAILABLE"
TIMEOUT = "TIMEOUT"
MALFORMED = "MALFORMED"
APPEND_ONLY_VIOLATION = "APPEND_ONLY_VIOLATION"
GENESIS_HASH = "sha256:" + ("0" * 64)


@dataclass(frozen=True)
class StoreResult:
    state: str
    reason_code: str
    event_hash: str = ""
    record_id: str = ""


class DependencyArtifactEvidenceStore(Protocol):
    def activate(
        self,
        *,
        record: Mapping[str, Any],
        decision: EligibilityDecision,
        replay_ids: Sequence[str],
        actor_id: str,
        device_id: str,
        timestamp: str,
        policy_version: str,
    ) -> StoreResult: ...

    def revoke(
        self,
        *,
        record_id: str,
        actor_id: str,
        device_id: str,
        timestamp: str,
        policy_version: str,
    ) -> StoreResult: ...


class SQLiteDependencyArtifactEvidenceStore:
    """Local reference adapter; it cannot satisfy external WORM requirements."""

    def __init__(self, path: str | Path, *, timeout_seconds: float = 1.0) -> None:
        self.path = Path(path)
        self.timeout_seconds = timeout_seconds

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=self.timeout_seconds, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS artifact_records (
              record_id TEXT PRIMARY KEY,
              aggregate_id TEXT NOT NULL,
              generation INTEGER NOT NULL,
              status TEXT NOT NULL,
              supersedes_record_id TEXT,
              record_hash TEXT NOT NULL UNIQUE,
              payload_json TEXT NOT NULL,
              UNIQUE(aggregate_id, generation)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_artifact_record
              ON artifact_records(aggregate_id) WHERE status = 'active';
            CREATE TABLE IF NOT EXISTS artifact_lifecycle_events (
              event_id TEXT PRIMARY KEY,
              aggregate_id TEXT NOT NULL,
              sequence INTEGER NOT NULL,
              event_type TEXT NOT NULL,
              previous_event_hash TEXT NOT NULL,
              payload_hash TEXT NOT NULL,
              actor_id TEXT NOT NULL,
              device_id TEXT NOT NULL,
              decision TEXT NOT NULL,
              timestamp TEXT NOT NULL,
              policy_version TEXT NOT NULL,
              event_hash TEXT NOT NULL UNIQUE,
              UNIQUE(aggregate_id, sequence)
            );
            CREATE TABLE IF NOT EXISTS consumed_artifact_evidence (
              replay_id TEXT PRIMARY KEY,
              record_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS artifact_store_metadata (
              metadata_key TEXT PRIMARY KEY,
              metadata_value TEXT NOT NULL
            );
            """
        )
        return conn

    def activate(
        self,
        *,
        record: Mapping[str, Any],
        decision: EligibilityDecision,
        replay_ids: Sequence[str],
        actor_id: str,
        device_id: str,
        timestamp: str,
        policy_version: str,
    ) -> StoreResult:
        if not decision.eligible or decision.record_hash != record.get("record_hash"):
            return StoreResult(MALFORMED, "DEPENDENCY_ARTIFACT_PROVENANCE_NOT_PROVEN")
        if artifact_record_hash(record) != record.get("record_hash"):
            return StoreResult(MALFORMED, "DEPENDENCY_ARTIFACT_INTEGRITY_FAILURE")
        if not replay_ids or len(set(replay_ids)) != len(replay_ids):
            return StoreResult(REPLAY, "DEPENDENCY_ARTIFACT_REPLAY")
        if not all((actor_id, device_id, timestamp, policy_version)):
            return StoreResult(MALFORMED, "DEPENDENCY_ARTIFACT_APPROVAL_MISSING")
        try:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                if not self._integrity_valid(conn):
                    conn.rollback()
                    return StoreResult(APPEND_ONLY_VIOLATION, "DEPENDENCY_ARTIFACT_INTEGRITY_FAILURE")
                for replay_id in replay_ids:
                    if conn.execute(
                        "SELECT 1 FROM consumed_artifact_evidence WHERE replay_id=?", (replay_id,)
                    ).fetchone():
                        conn.rollback()
                        return StoreResult(REPLAY, "DEPENDENCY_ARTIFACT_REPLAY")

                aggregate_id = _aggregate_id(record)
                current = conn.execute(
                    "SELECT * FROM artifact_records WHERE aggregate_id=? AND status='active'", (aggregate_id,)
                ).fetchone()
                supersedes = record["lineage"].get("supersedes_record_id")
                generation = int(record["lineage"]["generation"])
                if current is None and supersedes is not None:
                    conn.rollback()
                    return StoreResult(CONFLICT, "DEPENDENCY_ARTIFACT_SUPERSESSION_REQUIRED")
                if current is not None:
                    if supersedes != current["record_id"]:
                        conn.rollback()
                        return StoreResult(CONFLICT, "DEPENDENCY_ARTIFACT_SUPERSESSION_REQUIRED")
                    if generation <= int(current["generation"]):
                        conn.rollback()
                        return StoreResult(CONFLICT, "DEPENDENCY_ARTIFACT_DOWNGRADE")
                    self._append_event(
                        conn,
                        aggregate_id=aggregate_id,
                        event_type="SUPERSEDED",
                        payload_hash=str(current["record_hash"]),
                        actor_id=actor_id,
                        device_id=device_id,
                        decision="DENY_OLD",
                        timestamp=timestamp,
                        policy_version=policy_version,
                    )
                    conn.execute(
                        "UPDATE artifact_records SET status='superseded' WHERE record_id=? AND status='active'",
                        (current["record_id"],),
                    )

                payload_json = canonical_json(record)
                conn.execute(
                    "INSERT INTO artifact_records VALUES (?, ?, ?, 'active', ?, ?, ?)",
                    (
                        record["record_id"], aggregate_id, generation, supersedes,
                        record["record_hash"], payload_json,
                    ),
                )
                for replay_id in replay_ids:
                    conn.execute(
                        "INSERT INTO consumed_artifact_evidence VALUES (?, ?)",
                        (replay_id, record["record_id"]),
                    )
                event_hash = self._append_event(
                    conn,
                    aggregate_id=aggregate_id,
                    event_type="APPROVED",
                    payload_hash=str(record["record_hash"]),
                    actor_id=actor_id,
                    device_id=device_id,
                    decision="ALLOW_ELIGIBILITY",
                    timestamp=timestamp,
                    policy_version=policy_version,
                )
                conn.commit()
                return StoreResult(STORED, "DEPENDENCY_ARTIFACT_ELIGIBILITY_STORED", event_hash, str(record["record_id"]))
            except sqlite3.IntegrityError:
                conn.rollback()
                return StoreResult(REPLAY, "DEPENDENCY_ARTIFACT_REPLAY")
            except sqlite3.OperationalError as exc:
                conn.rollback()
                reason = str(exc).lower()
                if "locked" in reason or "timeout" in reason:
                    return StoreResult(TIMEOUT, "DEPENDENCY_ARTIFACT_STORE_TIMEOUT")
                return StoreResult(UNAVAILABLE, "DEPENDENCY_ARTIFACT_STORE_UNAVAILABLE")
            except Exception:
                conn.rollback()
                return StoreResult(UNAVAILABLE, "DEPENDENCY_ARTIFACT_STORE_UNAVAILABLE")
            finally:
                conn.close()
        except sqlite3.OperationalError as exc:
            reason = str(exc).lower()
            if "locked" in reason or "timeout" in reason:
                return StoreResult(TIMEOUT, "DEPENDENCY_ARTIFACT_STORE_TIMEOUT")
            return StoreResult(UNAVAILABLE, "DEPENDENCY_ARTIFACT_STORE_UNAVAILABLE")
        except Exception:
            return StoreResult(UNAVAILABLE, "DEPENDENCY_ARTIFACT_STORE_UNAVAILABLE")

    def revoke(
        self,
        *,
        record_id: str,
        actor_id: str,
        device_id: str,
        timestamp: str,
        policy_version: str,
    ) -> StoreResult:
        try:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                if not self._integrity_valid(conn):
                    conn.rollback()
                    return StoreResult(APPEND_ONLY_VIOLATION, "DEPENDENCY_ARTIFACT_INTEGRITY_FAILURE")
                row = conn.execute("SELECT * FROM artifact_records WHERE record_id=?", (record_id,)).fetchone()
                if row is None or row["status"] != "active":
                    conn.rollback()
                    return StoreResult(CONFLICT, "DEPENDENCY_ARTIFACT_REVOKED")
                conn.execute("UPDATE artifact_records SET status='revoked' WHERE record_id=?", (record_id,))
                event_hash = self._append_event(
                    conn,
                    aggregate_id=str(row["aggregate_id"]),
                    event_type="REVOKED",
                    payload_hash=str(row["record_hash"]),
                    actor_id=actor_id,
                    device_id=device_id,
                    decision="DENY",
                    timestamp=timestamp,
                    policy_version=policy_version,
                )
                conn.commit()
                return StoreResult(REVOKED, "DEPENDENCY_ARTIFACT_REVOKED", event_hash, record_id)
            except Exception:
                conn.rollback()
                return StoreResult(UNAVAILABLE, "DEPENDENCY_ARTIFACT_STORE_UNAVAILABLE")
            finally:
                conn.close()
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower() or "timeout" in str(exc).lower():
                return StoreResult(TIMEOUT, "DEPENDENCY_ARTIFACT_STORE_TIMEOUT")
            return StoreResult(UNAVAILABLE, "DEPENDENCY_ARTIFACT_STORE_UNAVAILABLE")
        except Exception:
            return StoreResult(UNAVAILABLE, "DEPENDENCY_ARTIFACT_STORE_UNAVAILABLE")

    def current_record(self, aggregate_id: str) -> Mapping[str, Any] | None:
        try:
            conn = self._connect()
            try:
                if not self._integrity_valid(conn):
                    return None
                row = conn.execute(
                    "SELECT payload_json FROM artifact_records WHERE aggregate_id=? AND status='active'",
                    (aggregate_id,),
                ).fetchone()
                return json.loads(row["payload_json"]) if row else None
            finally:
                conn.close()
        except Exception:
            return None

    def integrity_valid(self) -> bool:
        try:
            conn = self._connect()
            try:
                return self._integrity_valid(conn)
            finally:
                conn.close()
        except Exception:
            return False

    def _append_event(
        self,
        conn: sqlite3.Connection,
        *,
        aggregate_id: str,
        event_type: str,
        payload_hash: str,
        actor_id: str,
        device_id: str,
        decision: str,
        timestamp: str,
        policy_version: str,
    ) -> str:
        latest = conn.execute(
            "SELECT sequence, event_hash FROM artifact_lifecycle_events WHERE aggregate_id=? ORDER BY sequence DESC LIMIT 1",
            (aggregate_id,),
        ).fetchone()
        sequence = int(latest["sequence"]) + 1 if latest else 0
        previous = str(latest["event_hash"]) if latest else GENESIS_HASH
        body = {
            "aggregate_id": aggregate_id,
            "sequence": sequence,
            "event_type": event_type,
            "previous_event_hash": previous,
            "payload_hash": payload_hash,
            "actor_id": actor_id,
            "device_id": device_id,
            "decision": decision,
            "timestamp": timestamp,
            "policy_version": policy_version,
        }
        event_hash = sha256_reference(body)
        event_id = sha256_reference({"event_hash": event_hash, "aggregate_id": aggregate_id, "sequence": sequence})
        conn.execute(
            "INSERT INTO artifact_lifecycle_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event_id, aggregate_id, sequence, event_type, previous, payload_hash,
                actor_id, device_id, decision, timestamp, policy_version, event_hash,
            ),
        )
        event_count = int(conn.execute("SELECT COUNT(*) FROM artifact_lifecycle_events").fetchone()[0])
        conn.execute(
            "INSERT INTO artifact_store_metadata VALUES ('event_count', ?) "
            "ON CONFLICT(metadata_key) DO UPDATE SET metadata_value=excluded.metadata_value",
            (str(event_count),),
        )
        return event_hash

    def _integrity_valid(self, conn: sqlite3.Connection) -> bool:
        records = conn.execute("SELECT * FROM artifact_records ORDER BY record_id").fetchall()
        for row in records:
            try:
                payload = json.loads(row["payload_json"])
            except (TypeError, json.JSONDecodeError):
                return False
            if payload.get("record_id") != row["record_id"] or artifact_record_hash(payload) != row["record_hash"]:
                return False

        events = conn.execute("SELECT * FROM artifact_lifecycle_events ORDER BY aggregate_id, sequence").fetchall()
        metadata = conn.execute(
            "SELECT metadata_value FROM artifact_store_metadata WHERE metadata_key='event_count'"
        ).fetchone()
        if events and (metadata is None or int(metadata["metadata_value"]) != len(events)):
            return False
        if not events and metadata is not None and int(metadata["metadata_value"]) != 0:
            return False
        previous_by_aggregate: dict[str, str] = {}
        sequence_by_aggregate: dict[str, int] = {}
        for row in events:
            aggregate = str(row["aggregate_id"])
            expected_sequence = sequence_by_aggregate.get(aggregate, -1) + 1
            expected_previous = previous_by_aggregate.get(aggregate, GENESIS_HASH)
            body = {key: row[key] for key in (
                "aggregate_id", "sequence", "event_type", "previous_event_hash", "payload_hash",
                "actor_id", "device_id", "decision", "timestamp", "policy_version",
            )}
            if (
                int(row["sequence"]) != expected_sequence
                or row["previous_event_hash"] != expected_previous
                or row["event_hash"] != sha256_reference(body)
            ):
                return False
            expected_id = sha256_reference(
                {"event_hash": row["event_hash"], "aggregate_id": aggregate, "sequence": row["sequence"]}
            )
            if row["event_id"] != expected_id:
                return False
            sequence_by_aggregate[aggregate] = int(row["sequence"])
            previous_by_aggregate[aggregate] = str(row["event_hash"])
        return True


class UnavailableDependencyArtifactEvidenceStore:
    def activate(self, **_: Any) -> StoreResult:
        return StoreResult(UNAVAILABLE, "DEPENDENCY_ARTIFACT_STORE_UNAVAILABLE")

    def revoke(self, **_: Any) -> StoreResult:
        return StoreResult(UNAVAILABLE, "DEPENDENCY_ARTIFACT_STORE_UNAVAILABLE")


def _aggregate_id(record: Mapping[str, Any]) -> str:
    package = record["package"]
    platform = record["platform"]
    return ":".join(
        str(value)
        for value in (
            package["normalized_project_name"],
            platform["os"],
            platform["architecture"],
            platform["python_tag"],
            platform["abi_tag"],
        )
    )
