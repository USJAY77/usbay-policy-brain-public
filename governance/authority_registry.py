"""USBAY durable media authority registry (approvals + actor identities).

Closes the gap where MediaAuthorization objects were caller-constructed and
unverifiable: approvals and actor identities must now exist in a durable
(SQLite, WAL) registry created through an explicit registration step. At
execution time the registry verifies, fail-closed:

- actor identity exists and is not revoked;
- the approval (authorization_id) exists in the registry;
- the approval has not expired;
- the approval is bound to the presenting actor;
- the presented authorization + contract match the registered binding hash
  (field substitution => DENY);
- the approval has not already been consumed (replay => DENY); consumption
  is atomic and single-use.

Any unknown, missing, malformed, expired, substituted, or replayed state
DENIES. Any internal/registry error DENIES. The registry never creates
approvals autonomously — registration is an explicit, separate call that
represents the human/policy grant.

No secrets, raw prompts, or media bytes are stored — identifiers, hashes,
and timestamps only.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from audit.ledger import canonical_json_bytes, sha256_bytes

from governance.media_execution import (
    MediaAuthorization,
    MediaExecutionContract,
)

_ISO = "%Y-%m-%dT%H:%M:%SZ"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(_ISO)


def _deny(reason_code: str) -> dict:
    return {
        "decision": "BLOCK",
        "reason_code": reason_code,
        "timestamp": _iso(_utc_now()),
    }


def authorization_binding_hash(
    authorization: MediaAuthorization, actor_id: str
) -> str:
    """Canonical hash binding an approval to its exact granted terms."""
    payload = {
        "authorization_id": authorization.authorization_id,
        "actor_id": actor_id,
        "provider": authorization.provider,
        "action": authorization.action,
        "model_identifier": authorization.model_identifier or "UNSPECIFIED",
        "prompt_hash": authorization.prompt_hash,
        "max_outputs": authorization.max_outputs,
        "max_duration_seconds": authorization.max_duration_seconds,
        "budget_ceiling": (
            repr(authorization.budget_ceiling)
            if authorization.budget_ceiling is not None
            else "NONE"
        ),
        "policy_decision_id": authorization.policy_decision_id,
        "publication_authorized": bool(authorization.publication_authorized),
    }
    return sha256_bytes(canonical_json_bytes(payload))


class MediaAuthorityRegistry:
    """Durable actor-identity + approval registry (SQLite, WAL).

    verify_authority() is the ONLY trust decision surface; every failure
    mode returns an explicit BLOCK decision dict, never raises to callers.
    """

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS media_actor_identity ("
                "actor_id TEXT PRIMARY KEY,"
                "registered_at TEXT NOT NULL,"
                "revoked_at TEXT)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS media_approval ("
                "authorization_id TEXT PRIMARY KEY,"
                "actor_id TEXT NOT NULL,"
                "binding_hash TEXT NOT NULL,"
                "registered_at TEXT NOT NULL,"
                "expires_at TEXT NOT NULL,"
                "consumed_at TEXT,"
                "execution_id TEXT)"
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    # ---- explicit registration (the human/policy grant step) -------------

    def register_actor(self, actor_id: str) -> None:
        if not isinstance(actor_id, str) or not actor_id.strip():
            raise ValueError("AUTHORITY_REGISTRY:actor_id_REQUIRED")
        with self._conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO media_actor_identity (actor_id, registered_at)"
                " VALUES (?, ?)",
                (actor_id.strip(), _iso(_utc_now())),
            )

    def revoke_actor(self, actor_id: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE media_actor_identity SET revoked_at = ? WHERE actor_id = ?",
                (_iso(_utc_now()), actor_id),
            )

    def register_approval(
        self,
        *,
        authorization: MediaAuthorization,
        actor_id: str,
        valid_for_seconds: int = 3600,
        execution_id: Optional[str] = None,
    ) -> str:
        """Record a granted approval. Explicit call only — never automatic."""
        if not isinstance(authorization, MediaAuthorization):
            raise ValueError("AUTHORITY_REGISTRY:authorization_REQUIRED")
        if not isinstance(actor_id, str) or not actor_id.strip():
            raise ValueError("AUTHORITY_REGISTRY:actor_id_REQUIRED")
        if (
            isinstance(valid_for_seconds, bool)
            or not isinstance(valid_for_seconds, int)
            or valid_for_seconds <= 0
            or valid_for_seconds > 30 * 24 * 3600
        ):
            raise ValueError("AUTHORITY_REGISTRY:valid_for_seconds_OUT_OF_BOUNDS")
        if execution_id is not None and (
            not isinstance(execution_id, str) or not execution_id.strip()
        ):
            raise ValueError("AUTHORITY_REGISTRY:execution_id_INVALID")
        binding = authorization_binding_hash(authorization, actor_id.strip())
        now = _utc_now()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO media_approval "
                "(authorization_id, actor_id, binding_hash, registered_at,"
                " expires_at, execution_id)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    authorization.authorization_id,
                    actor_id.strip(),
                    binding,
                    _iso(now),
                    _iso(now + timedelta(seconds=valid_for_seconds)),
                    execution_id.strip() if execution_id is not None else None,
                ),
            )
        return binding

    # ---- fail-closed verification ----------------------------------------

    def verify_authority(
        self,
        contract: Optional[MediaExecutionContract],
        authorization: Optional[MediaAuthorization],
        *,
        consume: bool = True,
    ) -> dict:
        """Verify actor + approval against the durable registry. Fail-closed.

        When consume=True (default) a successful verification atomically
        consumes the approval: a second verification of the same approval
        DENIES with APPROVAL_REPLAYED.
        """
        try:
            if contract is None or not isinstance(contract, MediaExecutionContract):
                return _deny("CONTRACT_MISSING")
            if authorization is None or not isinstance(authorization, MediaAuthorization):
                return _deny("AUTHORIZATION_MISSING")
            with self._conn() as conn:
                actor_row = conn.execute(
                    "SELECT revoked_at FROM media_actor_identity WHERE actor_id = ?",
                    (contract.actor_id,),
                ).fetchone()
                if actor_row is None:
                    return _deny("ACTOR_UNKNOWN")
                if actor_row[0] is not None:
                    return _deny("ACTOR_REVOKED")
                approval_row = conn.execute(
                    "SELECT actor_id, binding_hash, expires_at, consumed_at,"
                    " execution_id"
                    " FROM media_approval WHERE authorization_id = ?",
                    (authorization.authorization_id,),
                ).fetchone()
                if approval_row is None:
                    return _deny("APPROVAL_UNKNOWN")
                (
                    approved_actor,
                    binding_hash,
                    expires_at,
                    consumed_at,
                    approved_execution_id,
                ) = approval_row
                if (
                    approved_execution_id is not None
                    and approved_execution_id != contract.execution_id
                ):
                    return _deny("APPROVAL_CONTRACT_MISMATCH")
                if approved_actor != contract.actor_id:
                    return _deny("APPROVAL_ACTOR_MISMATCH")
                try:
                    expiry = datetime.strptime(expires_at, _ISO).replace(
                        tzinfo=timezone.utc
                    )
                except Exception:
                    return _deny("APPROVAL_EXPIRY_MALFORMED")
                if _utc_now() >= expiry:
                    return _deny("APPROVAL_EXPIRED")
                presented = authorization_binding_hash(
                    authorization, contract.actor_id
                )
                if presented != binding_hash:
                    return _deny("APPROVAL_BINDING_MISMATCH")
                if consumed_at is not None:
                    return _deny("APPROVAL_REPLAYED")
                if consume:
                    cursor = conn.execute(
                        "UPDATE media_approval SET consumed_at = ?"
                        " WHERE authorization_id = ? AND consumed_at IS NULL",
                        (_iso(_utc_now()), authorization.authorization_id),
                    )
                    if cursor.rowcount != 1:
                        return _deny("APPROVAL_REPLAYED")
            return {
                "decision": "ALLOW_AUTHORITY",
                "authorization_id": authorization.authorization_id,
                "actor_id": contract.actor_id,
                "timestamp": _iso(_utc_now()),
            }
        except Exception:
            return _deny("AUTHORITY_REGISTRY_FAILURE")


def verify_media_authority(
    registry: Optional[Any],
    contract: Optional[MediaExecutionContract],
    authorization: Optional[MediaAuthorization],
    *,
    consume: bool = True,
) -> dict:
    """Registry-mandatory wrapper: missing/invalid registry DENIES."""
    try:
        if registry is None or not isinstance(registry, MediaAuthorityRegistry):
            return _deny("AUTHORITY_REGISTRY_MISSING")
        return registry.verify_authority(contract, authorization, consume=consume)
    except Exception:
        return _deny("AUTHORITY_REGISTRY_FAILURE")
