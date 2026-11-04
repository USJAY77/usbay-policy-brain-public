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

from governance.approval_issuance import (
    ApprovalIssuanceDenied,
    issuance_payload_hash,
    validate_issuance_freshness,
    validate_issuance_schema,
    verify_issuance_signature,
)
from governance.media_execution import (
    MediaAuthorization,
    MediaExecutionContract,
)

_ISO = "%Y-%m-%dT%H:%M:%SZ"


def _verify_blob_signature(public_key_pem: str, payload: dict, signature_hex: str) -> bool:
    """Ed25519 verification over a canonical-JSON payload (sponsorship)."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            return False
        key.verify(bytes.fromhex(signature_hex), canonical_json_bytes(payload))
        return True
    except Exception:
        return False


def sign_issuer_registration(private_key_pem: str, registration_payload: dict) -> str:
    """Sponsor-side helper: sign a canonical issuer-registration payload."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = serialization.load_pem_private_key(
        private_key_pem.encode("ascii"), password=None
    )
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("AUTHORITY_REGISTRY:sponsor_key_NOT_ED25519")
    return key.sign(canonical_json_bytes(registration_payload)).hex()


def build_issuer_registration_payload(
    *,
    issuer_id: str,
    public_key_pem: str,
    authorized_actors,
    authorized_providers,
    tenant_reference: Optional[str] = None,
) -> dict:
    return {
        "op": "register_issuer",
        "issuer_id": issuer_id.strip(),
        "public_key_pem": public_key_pem,
        "authorized_actors": sorted(authorized_actors),
        "authorized_providers": sorted(authorized_providers),
        "tenant_reference": tenant_reference,
    }


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
                "execution_id TEXT,"
                "tenant_reference TEXT,"
                "issuer_id TEXT)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS approval_issuer ("
                "issuer_id TEXT PRIMARY KEY,"
                "public_key_pem TEXT NOT NULL,"
                "authorized_actors TEXT NOT NULL,"  # canonical JSON list
                "authorized_providers TEXT NOT NULL,"  # canonical JSON list
                "tenant_reference TEXT,"
                "registered_at TEXT NOT NULL,"
                "revoked_at TEXT)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS issuance_nonce ("
                "nonce TEXT PRIMARY KEY,"
                "issuer_id TEXT NOT NULL,"
                "used_at TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS issuance_audit ("
                "seq INTEGER PRIMARY KEY AUTOINCREMENT,"
                "event TEXT NOT NULL,"
                "reason_code TEXT,"
                "issuer_id TEXT,"
                "actor_id TEXT,"
                "authorization_id TEXT,"
                "payload_hash TEXT,"
                "occurred_at TEXT NOT NULL,"
                "prev_hash TEXT NOT NULL,"
                "entry_hash TEXT NOT NULL)"
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

    def register_issuer(
        self,
        *,
        issuer_id: str,
        public_key_pem: str,
        authorized_actors: tuple[str, ...] | list[str],
        authorized_providers: tuple[str, ...] | list[str],
        tenant_reference: Optional[str] = None,
        sponsor_issuer_id: Optional[str] = None,
        sponsor_signature: Optional[str] = None,
    ) -> None:
        """Register an approval issuer's PUBLIC key + authorization scope.

        Trust model (labeled, no PKI claimed):
        - FIRST issuer: allowed only while the issuer table is EMPTY
          (trust-on-first-use bootstrap — an externally-governed human step).
        - Every subsequent issuer REQUIRES sponsorship: an existing,
          non-revoked issuer must sign the canonical registration payload.
          A caller with mere registry access can no longer add issuers once
          the registry is provisioned.
        The registry never generates or stores private keys.
        """
        if not isinstance(issuer_id, str) or not issuer_id.strip():
            raise ValueError("AUTHORITY_REGISTRY:issuer_id_REQUIRED")
        if not isinstance(public_key_pem, str) or "PUBLIC KEY" not in public_key_pem:
            raise ValueError("AUTHORITY_REGISTRY:public_key_pem_INVALID")
        if "PRIVATE" in public_key_pem:
            raise ValueError("AUTHORITY_REGISTRY:private_key_REJECTED")
        for group in (authorized_actors, authorized_providers):
            if not isinstance(group, (tuple, list)) or not group or not all(
                isinstance(item, str) and item.strip() for item in group
            ):
                raise ValueError("AUTHORITY_REGISTRY:issuer_scope_REQUIRED")
        registration_payload = {
            "op": "register_issuer",
            "issuer_id": issuer_id.strip(),
            "public_key_pem": public_key_pem,
            "authorized_actors": sorted(authorized_actors),
            "authorized_providers": sorted(authorized_providers),
            "tenant_reference": tenant_reference,
        }
        with self._conn() as conn:
            existing = conn.execute(
                "SELECT COUNT(*) FROM approval_issuer"
            ).fetchone()[0]
            if existing > 0:
                sponsor_row = (
                    conn.execute(
                        "SELECT public_key_pem, revoked_at FROM approval_issuer"
                        " WHERE issuer_id = ?",
                        (sponsor_issuer_id,),
                    ).fetchone()
                    if isinstance(sponsor_issuer_id, str)
                    else None
                )
                if sponsor_row is None or sponsor_row[1] is not None:
                    raise ValueError("AUTHORITY_REGISTRY:issuer_sponsor_REQUIRED")
                if not isinstance(sponsor_signature, str) or not _verify_blob_signature(
                    sponsor_row[0], registration_payload, sponsor_signature
                ):
                    raise ValueError(
                        "AUTHORITY_REGISTRY:issuer_sponsor_signature_INVALID"
                    )
            conn.execute(
                "INSERT INTO approval_issuer "
                "(issuer_id, public_key_pem, authorized_actors,"
                " authorized_providers, tenant_reference, registered_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    issuer_id.strip(),
                    public_key_pem,
                    canonical_json_bytes(sorted(authorized_actors)).decode("utf-8"),
                    canonical_json_bytes(sorted(authorized_providers)).decode("utf-8"),
                    tenant_reference,
                    _iso(_utc_now()),
                ),
            )

    def revoke_issuer(self, issuer_id: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE approval_issuer SET revoked_at = ? WHERE issuer_id = ?",
                (_iso(_utc_now()), issuer_id),
            )

    def _audit_issuance(
        self,
        conn: sqlite3.Connection,
        event: str,
        reason_code: Optional[str],
        issuer_id: Optional[str],
        actor_id: Optional[str],
        authorization_id: Optional[str],
        payload_hash: Optional[str],
    ) -> None:
        """Append a hash-chained issuance audit row (identifiers/hashes only)."""
        row = conn.execute(
            "SELECT seq, entry_hash FROM issuance_audit ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev_hash = row[1] if row else "GENESIS"
        seq = (row[0] + 1) if row else 1
        occurred_at = _iso(_utc_now())
        entry = {
            "seq": seq,
            "event": event,
            "reason_code": reason_code,
            "issuer_id": issuer_id,
            "actor_id": actor_id,
            "authorization_id": authorization_id,
            "payload_hash": payload_hash,
            "occurred_at": occurred_at,
            "prev_hash": prev_hash,
        }
        entry_hash = sha256_bytes(canonical_json_bytes(entry))
        conn.execute(
            "INSERT INTO issuance_audit (seq, event, reason_code, issuer_id,"
            " actor_id, authorization_id, payload_hash, occurred_at,"
            " prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                seq,
                event,
                reason_code,
                issuer_id,
                actor_id,
                authorization_id,
                payload_hash,
                occurred_at,
                prev_hash,
                entry_hash,
            ),
        )

    def issuance_events(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT seq, event, reason_code, issuer_id, actor_id,"
                " authorization_id, payload_hash, occurred_at, prev_hash,"
                " entry_hash FROM issuance_audit ORDER BY seq"
            ).fetchall()
        keys = (
            "seq",
            "event",
            "reason_code",
            "issuer_id",
            "actor_id",
            "authorization_id",
            "payload_hash",
            "occurred_at",
            "prev_hash",
            "entry_hash",
        )
        return [dict(zip(keys, row)) for row in rows]

    def verify_issuance_audit_chain(
        self, *, expected_head: Optional[dict] = None
    ) -> bool:
        """True only when the issuance audit hash chain is intact.

        Detects in-place edits and mid-chain deletion (seq continuity from 1).
        Tail truncation is only detectable against an externally anchored
        head — pass expected_head from issuance_audit_head() stored outside
        this database. Without an external anchor, tail truncation is a
        LABELED residual.
        """
        prev = "GENESIS"
        expected_seq = 1
        events = self.issuance_events()
        for event in events:
            if event["seq"] != expected_seq:
                return False
            entry = {key: event[key] for key in (
                "seq", "event", "reason_code", "issuer_id", "actor_id",
                "authorization_id", "payload_hash", "occurred_at",
            )}
            entry["prev_hash"] = event["prev_hash"]
            if event["prev_hash"] != prev:
                return False
            if sha256_bytes(canonical_json_bytes(entry)) != event["entry_hash"]:
                return False
            prev = event["entry_hash"]
            expected_seq += 1
        if expected_head is not None:
            if len(events) < expected_head.get("count", 0):
                return False
            if expected_head.get("count", 0) > 0:
                anchored = events[expected_head["count"] - 1]
                if anchored["entry_hash"] != expected_head.get("entry_hash"):
                    return False
        return True

    def issuance_audit_head(self) -> dict:
        """Exportable head (count + last entry hash) for EXTERNAL anchoring."""
        events = self.issuance_events()
        if not events:
            return {"count": 0, "entry_hash": "GENESIS"}
        return {"count": len(events), "entry_hash": events[-1]["entry_hash"]}

    def _deny_issuance(
        self,
        conn: sqlite3.Connection,
        reason_code: str,
        *,
        event: str = "APPROVAL_REJECTED",
        issuer_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        authorization_id: Optional[str] = None,
        payload_hash: Optional[str] = None,
    ) -> ApprovalIssuanceDenied:
        self._audit_issuance(
            conn, event, reason_code, issuer_id, actor_id,
            authorization_id, payload_hash,
        )
        conn.commit()
        return ApprovalIssuanceDenied(reason_code)

    def register_approval(
        self,
        *,
        authorization: MediaAuthorization,
        actor_id: str,
        issuance_payload: Optional[dict] = None,
        issuance_signature: Optional[str] = None,
        valid_for_seconds: int = 3600,
        execution_id: Optional[str] = None,
    ) -> str:
        """Record a granted approval — ONLY with an authenticated issuance.

        Fail-closed: the approval is inserted in the same transaction as the
        nonce consumption and audit row; any failed step leaves no usable
        approval behind. Raises ApprovalIssuanceDenied on every deny path.
        """
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
        actor = actor_id.strip()
        binding = authorization_binding_hash(authorization, actor)
        conn = self._conn()
        try:
            # 1. envelope schema
            schema_error = validate_issuance_schema(
                issuance_payload, issuance_signature
            )
            if schema_error is not None:
                raise self._deny_issuance(
                    conn, schema_error,
                    event="AUTHENTICATION_FAILED"
                    if schema_error == "AUTHENTICATION_FAILED"
                    else "PAYLOAD_BINDING_FAILED",
                    actor_id=actor,
                    authorization_id=authorization.authorization_id,
                )
            payload = dict(issuance_payload)
            payload_hash = issuance_payload_hash(payload)
            issuer_id = payload["issuer_id"]
            # 2. issuer known + not revoked
            issuer_row = conn.execute(
                "SELECT public_key_pem, authorized_actors, authorized_providers,"
                " tenant_reference, revoked_at FROM approval_issuer"
                " WHERE issuer_id = ?",
                (issuer_id,),
            ).fetchone()
            if issuer_row is None:
                raise self._deny_issuance(
                    conn, "ISSUER_UNKNOWN", event="ISSUER_UNKNOWN",
                    issuer_id=issuer_id, actor_id=actor,
                    authorization_id=authorization.authorization_id,
                    payload_hash=payload_hash,
                )
            (
                public_key_pem,
                authorized_actors_json,
                authorized_providers_json,
                issuer_tenant,
                issuer_revoked_at,
            ) = issuer_row
            if issuer_revoked_at is not None:
                raise self._deny_issuance(
                    conn, "ISSUER_REVOKED", event="APPROVAL_REVOKED",
                    issuer_id=issuer_id, actor_id=actor,
                    authorization_id=authorization.authorization_id,
                    payload_hash=payload_hash,
                )
            # 3. signature over the canonical payload (authenticity)
            if not verify_issuance_signature(
                public_key_pem, payload, issuance_signature
            ):
                raise self._deny_issuance(
                    conn, "AUTHENTICATION_FAILED", event="AUTHENTICATION_FAILED",
                    issuer_id=issuer_id, actor_id=actor,
                    authorization_id=authorization.authorization_id,
                    payload_hash=payload_hash,
                )
            # 4. payload must bind THIS approval exactly (substitution => DENY)
            if (
                payload["actor_id"] != actor
                or payload["authorization_id"] != authorization.authorization_id
                or payload["binding_hash"] != binding
                or payload.get("execution_id") != execution_id
            ):
                raise self._deny_issuance(
                    conn, "PAYLOAD_BINDING_FAILED", event="PAYLOAD_BINDING_FAILED",
                    issuer_id=issuer_id, actor_id=actor,
                    authorization_id=authorization.authorization_id,
                    payload_hash=payload_hash,
                )
            # 5. issuer authorization: scope must cover actor/provider/tenant
            import json as _json

            authorized_actors = set(_json.loads(authorized_actors_json))
            authorized_providers = set(_json.loads(authorized_providers_json))
            if (
                actor not in authorized_actors
                or authorization.provider not in authorized_providers
                or (
                    issuer_tenant is not None
                    and payload["tenant_reference"] != issuer_tenant
                )
            ):
                raise self._deny_issuance(
                    conn, "ISSUER_UNAUTHORIZED", event="ISSUER_UNAUTHORIZED",
                    issuer_id=issuer_id, actor_id=actor,
                    authorization_id=authorization.authorization_id,
                    payload_hash=payload_hash,
                )
            # 6. freshness / staleness / expiry of the issuance envelope
            freshness_error = validate_issuance_freshness(payload)
            if freshness_error is not None:
                raise self._deny_issuance(
                    conn, freshness_error,
                    event="APPROVAL_EXPIRED"
                    if freshness_error == "APPROVAL_EXPIRED"
                    else "APPROVAL_REJECTED",
                    issuer_id=issuer_id, actor_id=actor,
                    authorization_id=authorization.authorization_id,
                    payload_hash=payload_hash,
                )
            # 7. replay: nonce single-use, atomically with the approval insert
            now = _utc_now()
            try:
                conn.execute(
                    "INSERT INTO issuance_nonce (nonce, issuer_id, used_at)"
                    " VALUES (?, ?, ?)",
                    (payload["nonce"], issuer_id, _iso(now)),
                )
                conn.execute(
                    "INSERT INTO media_approval "
                    "(authorization_id, actor_id, binding_hash, registered_at,"
                    " expires_at, execution_id, tenant_reference, issuer_id)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        authorization.authorization_id,
                        actor,
                        binding,
                        _iso(now),
                        _iso(now + timedelta(seconds=valid_for_seconds)),
                        execution_id.strip() if execution_id is not None else None,
                        payload["tenant_reference"],
                        issuer_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                conn.rollback()
                if "issuance_nonce" in str(exc):
                    raise self._deny_issuance(
                        conn, "ISSUANCE_REPLAYED", event="APPROVAL_REPLAY_BLOCKED",
                        issuer_id=issuer_id, actor_id=actor,
                        authorization_id=authorization.authorization_id,
                        payload_hash=payload_hash,
                    )
                raise self._deny_issuance(
                    conn, "APPROVAL_DUPLICATE", event="APPROVAL_REJECTED",
                    issuer_id=issuer_id, actor_id=actor,
                    authorization_id=authorization.authorization_id,
                    payload_hash=payload_hash,
                )
            self._audit_issuance(
                conn, "APPROVAL_ISSUED", None, issuer_id, actor,
                authorization.authorization_id, payload_hash,
            )
            conn.commit()
            return binding
        finally:
            conn.close()

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
                    " execution_id, tenant_reference, issuer_id"
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
                    approved_tenant,
                    approving_issuer_id,
                ) = approval_row
                if (
                    approved_execution_id is not None
                    and approved_execution_id != contract.execution_id
                ):
                    return _deny("APPROVAL_CONTRACT_MISMATCH")
                # tenant binding: the signed issuance tenant must match the
                # executing contract's tenant (cross-tenant reuse => DENY)
                if (
                    approved_tenant is not None
                    and approved_tenant != contract.tenant_reference
                ):
                    return _deny("APPROVAL_TENANT_MISMATCH")
                # issuer revocation invalidates OUTSTANDING approvals too
                if approving_issuer_id is not None:
                    issuer_state = conn.execute(
                        "SELECT revoked_at FROM approval_issuer"
                        " WHERE issuer_id = ?",
                        (approving_issuer_id,),
                    ).fetchone()
                    if issuer_state is None or issuer_state[0] is not None:
                        return _deny("ISSUER_REVOKED")
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


class EnrollmentAuthorityView:
    """Open-only typed view of the SAME authority database, not a new registry.

    No provisioning, migration, issuer registration, first-head establishment or
    recovery API. The existing media constructor/semantics are unchanged. A live
    schema deployment and trust composition are explicitly outside this package.

    Local enrollment commits are facts, not admission/execute authority. Until a
    separately verified signed receipt exists, return DENY with the committed fact
    instead of inventing an ALLOW. No external transaction is claimed atomic.
    """
    def __init__(self, path: Path | str, trust=None, *, clock=None):
        from security.enrollment_policy_currentness import EnrollmentTrust
        from governance.tenant_enrollment_contracts import utc_now
        self.path = Path(path)
        self.trust = EnrollmentTrust() if trust is None else trust
        self.clock = utc_now if clock is None else clock

    def _connect_existing(self, *, read_only=False):
        from governance.tenant_enrollment_contracts import require
        require(self.path.is_file() and not self.path.is_symlink(), "ENROLLMENT_STORE_MISSING")
        conn = sqlite3.connect(self.path.resolve().as_uri() + ("?mode=ro" if read_only else "?mode=rw"), uri=True,
                               timeout=0, isolation_level=None)
        try:
            conn.execute("PRAGMA busy_timeout=0")
            conn.execute("PRAGMA synchronous=FULL")
            names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            require({"media_actor_identity", "approval_issuer", "enrollment_meta", "enrollment_events",
                     "enrollment_uses", "enrollment_tenants"} <= names, "ENROLLMENT_SCHEMA_MISSING")
            return conn
        except Exception:
            conn.close()
            raise

    @staticmethod
    def _snapshot(conn, *, require_finalized=True):
        from governance.tenant_enrollment_contracts import require, parse_json, digest
        rows = conn.execute("SELECT value FROM enrollment_meta WHERE name='state'").fetchall()
        require(len(rows) == 1, "STOPPED_UNVERIFIED_POLICY_HEAD")
        state = parse_json(rows[0][0])
        require(type(state) is dict and set(state) == {"schema", "head", "publication", "event_tip"}
                and state["schema"] == "usbay.enrollment.storage.v3"
                and state["publication"] in ("FINALIZED", "PENDING") and type(state["head"]) is dict
                and state["head"], "STOPPED_UNVERIFIED_POLICY_HEAD")
        previous = "sha256:" + "0" * 64
        expected_sequence = 1
        consumption = []
        tenants = {}
        terminal_revocations = {}
        terminal_grant_revocations = {}
        terminal_adoption_revocations = {}
        adoption_finalizations = {}
        for seq, encoded, event_hash in conn.execute("SELECT sequence,payload,event_hash FROM enrollment_events ORDER BY sequence"):
            event = parse_json(encoded)
            require(seq == expected_sequence and event["previous_event_hash"] == previous and event["sequence"] == seq
                    and event_hash == digest(event), "ENROLLMENT_HISTORY_INVALID")
            expected_sequence += 1
            consumption = event["consumption"]
            if event["kind"] == "REGISTERED_NON_EXECUTING":
                from governance.tenant_enrollment_contracts import TenantRegistrationRecord, scope
                record = TenantRegistrationRecord.from_payload(event["record"]).payload
                tenants[digest(list(scope(record)))] = record
            if event["kind"] == "POLICY_REVOCATION_TERMINAL_NON_PRODUCTION":
                key = (event["scope_hash"], event["object_id"])
                require(key not in terminal_revocations, "ENROLLMENT_HISTORY_INVALID")
                terminal_revocations[key] = (
                    event["object_version_hash"],
                    event["revocation_reference"],
                    event["revocation_hash"],
                    event["terminal_projection_hash"],
                    event["terminal_proof_hash"],
                    event["source_epoch"],
                    event["source_version"],
                    event["command_hash"],
                    event["transaction_id"],
                )
            if event["kind"] == "GRANT_REVOCATION_TERMINAL_NON_PRODUCTION":
                key = (event["scope_hash"], event["object_id"])
                require(key not in terminal_grant_revocations, "ENROLLMENT_HISTORY_INVALID")
                terminal_grant_revocations[key] = (
                    event["object_version_hash"],
                    event["target_grant_id"],
                    event["consumption_state"],
                    event["revocation_reference"],
                    event["revocation_hash"],
                    event["terminal_projection_hash"],
                    event["terminal_proof_hash"],
                    event["source_epoch"],
                    event["source_version"],
                    event["command_hash"],
                    event["transaction_id"],
                )
            if event["kind"] == "ADOPTION_REVOCATION_TERMINAL_NON_PRODUCTION":
                key = (event["scope_hash"], event["object_id"])
                require(key not in terminal_adoption_revocations, "ENROLLMENT_HISTORY_INVALID")
                terminal_adoption_revocations[key] = (
                    event["object_version_hash"],
                    event["adoption_id"],
                    event["policy_id"],
                    event["finalization_state"],
                    event["revocation_reference"],
                    event["revocation_hash"],
                    event["terminal_projection_hash"],
                    event["terminal_proof_hash"],
                    event["source_epoch"],
                    event["source_version"],
                    event["command_hash"],
                    event["transaction_id"],
                )
            if event["kind"] == "ADOPTION_FINALIZED_NON_PRODUCTION":
                key = (event["scope_hash"], event["adoption_id"])
                require(key not in adoption_finalizations, "ENROLLMENT_HISTORY_INVALID")
                adoption_finalizations[key] = (
                    event["adoption_version_hash"],
                    event["policy_id"],
                    event["policy_hash"],
                    event["previous_head"],
                    event["target_head"],
                    event["pending_event_hash"],
                    event["composition_hash"],
                    event["source_epoch"],
                    event["source_version"],
                    event["command_hash"],
                    event["transaction_id"],
                )
            previous = event_hash
        require(state["event_tip"] == previous, "ENROLLMENT_HISTORY_INVALID")
        require(consumption == [list(row) for row in conn.execute("SELECT kind,identity FROM enrollment_uses ORDER BY kind,identity")],
                "ENROLLMENT_HISTORY_INVALID")
        require(tenants == {key: parse_json(record) for key, record in conn.execute("SELECT scope,record FROM enrollment_tenants")},
                "ENROLLMENT_HISTORY_INVALID")
        table_names = {
            row[0] for row in
            conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if "policy_revocation_terminal" in table_names:
            materialized = {
                (row[0], row[1]): tuple(row[2:])
                for row in conn.execute(
                    "SELECT scope_hash,object_id,object_version_hash,"
                    "revocation_reference,revocation_hash,"
                    "terminal_projection_hash,terminal_proof_hash,"
                    "source_epoch,source_version,command_hash,transaction_id "
                    "FROM policy_revocation_terminal")
            }
            require(materialized == terminal_revocations,
                    "ENROLLMENT_HISTORY_INVALID")
        else:
            require(not terminal_revocations, "ENROLLMENT_HISTORY_INVALID")
        if "grant_revocation_terminal" in table_names:
            materialized_grants = {
                (row[0], row[1]): tuple(row[2:])
                for row in conn.execute(
                    "SELECT scope_hash,object_id,object_version_hash,"
                    "target_grant_id,consumption_state,"
                    "revocation_reference,revocation_hash,"
                    "terminal_projection_hash,terminal_proof_hash,"
                    "source_epoch,source_version,command_hash,transaction_id "
                    "FROM grant_revocation_terminal")
            }
            require(materialized_grants == terminal_grant_revocations,
                    "ENROLLMENT_HISTORY_INVALID")
        else:
            require(not terminal_grant_revocations,
                    "ENROLLMENT_HISTORY_INVALID")
        if "adoption_revocation_terminal" in table_names:
            materialized_adoptions = {
                (row[0], row[1]): tuple(row[2:])
                for row in conn.execute(
                    "SELECT scope_hash,object_id,object_version_hash,"
                    "adoption_id,policy_id,finalization_state,"
                    "revocation_reference,revocation_hash,"
                    "terminal_projection_hash,terminal_proof_hash,"
                    "source_epoch,source_version,command_hash,transaction_id "
                    "FROM adoption_revocation_terminal")
            }
            require(materialized_adoptions == terminal_adoption_revocations,
                    "ENROLLMENT_HISTORY_INVALID")
        else:
            require(not terminal_adoption_revocations,
                    "ENROLLMENT_HISTORY_INVALID")
        if "adoption_finalization" in table_names:
            materialized_finalizations = {
                (row[0], row[1]): tuple(row[2:])
                for row in conn.execute(
                    "SELECT scope_hash,adoption_id,adoption_version_hash,"
                    "policy_id,policy_hash,previous_head,target_head,"
                    "pending_event_hash,composition_hash,source_epoch,"
                    "source_version,command_hash,transaction_id "
                    "FROM adoption_finalization")
            }
            require(materialized_finalizations == adoption_finalizations,
                    "ENROLLMENT_HISTORY_INVALID")
            if adoption_finalizations:
                latest = list(adoption_finalizations.values())[-1]
                require(state["publication"] == "FINALIZED"
                        and state["head"]["head_hash"] == latest[4],
                        "ENROLLMENT_HISTORY_INVALID")
        else:
            require(not adoption_finalizations, "ENROLLMENT_HISTORY_INVALID")
        if require_finalized:
            require(state["publication"] == "FINALIZED", "STOPPED_UNVERIFIED_POLICY_HEAD")
        return state

    def history(self) -> dict:
        from governance.tenant_enrollment_contracts import decision, EnrollmentDenied, parse_json
        conn = None
        try:
            conn = self._connect_existing()
            conn.execute("BEGIN")
            self._snapshot(conn)
            rows = [parse_json(row[0]) for row in conn.execute("SELECT payload FROM enrollment_events ORDER BY sequence")]
            return decision("HISTORY_ONLY", events=rows)
        except Exception as error:
            return decision(str(error) if type(error) is EnrollmentDenied else "ENROLLMENT_STORE_UNAVAILABLE")
        finally:
            if conn is not None:
                conn.close()

    @staticmethod
    def _consume(conn, kind, payload):
        from governance.tenant_enrollment_contracts import digest
        # The grant ID, nonce AND replay identity remain consumed. Different
        # request IDs or rotated credentials cannot reopen any of these keys.
        issuer = payload["issuer_id"]
        for label in ("grant_id", "nonce", "replay_identity"):
            conn.execute("INSERT INTO enrollment_uses(kind,identity) VALUES(?,?)",
                         (kind + ":" + label, digest({"issuer": issuer, "value": payload[label]})))

    def _replay_evidence(self, inputs):
        """Read-only denial diagnostics, NEVER an admission precheck.

        Primary admission order remains unchanged. Validate stored history and
        signatures before attributing any consumed state. Corrupt/orphan history
        cannot manufacture a verified replay classification. No raw IDs/payloads
        or signatures are returned, and no reservation is released.
        """
        from governance.tenant_enrollment_contracts import PolicyAdoption, HeadAdvance, digest, require, scope
        from security.enrollment_policy_currentness import EnrollmentTrust
        conn = None
        try:
            require(type(self.trust) is EnrollmentTrust, "DIAGNOSTICS_UNAVAILABLE")
            conn = self._connect_existing(read_only=True)
            conn.execute("BEGIN")
            state = self._snapshot(conn, require_finalized=False)
            require(type(inputs) is dict and set(inputs) == {"policy", "adoption", "advance", "prior"}, "INPUTS_INVALID")
            now = self.clock()
            a = self.trust.verify(inputs["adoption"], PolicyAdoption, "adoption", now)
            b = self.trust.verify(inputs["advance"], HeadAdvance, "advance", now)
            require(scope(a) == scope(b) == scope(state["head"]), "DIAGNOSTIC_SCOPE_INVALID")
            from governance.tenant_enrollment_contracts import parse_json
            events = [parse_json(row[0]) for row in conn.execute("SELECT payload FROM enrollment_events ORDER BY sequence")]
            reasons = []
            for kind, payload, field, reason in (
                ("adoption", a, "adoption_core_hash", "ADOPTION_REPLAY"),
                ("advance", b, "head_advance_grant_hash", "HEAD_ADVANCE_REPLAY"),
            ):
                bound_event = any(event["kind"] == "ADOPTION_PENDING" and event.get(field) == digest(payload) for event in events)
                consumed = all(conn.execute("SELECT 1 FROM enrollment_uses WHERE kind=? AND identity=?",
                    (kind + ":" + label, digest({"issuer": payload["issuer_id"], "value": payload[label]}))).fetchone() is not None
                    for label in ("grant_id", "nonce", "replay_identity"))
                if bound_event and consumed:
                    reasons.append(reason)
            return {"internal_result": "REPLAY_DETECTED" if reasons else "NO_VERIFIED_REPLAY_EVIDENCE", "internal_reasons": reasons}
        except Exception:
            return {"internal_result": "REPLAY_DIAGNOSTICS_UNAVAILABLE", "internal_reasons": []}
        finally:
            if conn is not None:
                conn.close()

    @staticmethod
    def _append(conn, state, event):
        from governance.tenant_enrollment_contracts import canonical, digest
        sequence = conn.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM enrollment_events").fetchone()[0]
        event.update(sequence=sequence, previous_event_hash=state["event_tip"])
        event["consumption"] = [list(row) for row in conn.execute("SELECT kind,identity FROM enrollment_uses ORDER BY kind,identity")]
        event_hash = digest(event)
        conn.execute("INSERT INTO enrollment_events(sequence,payload,event_hash) VALUES(?,?,?)",
                     (sequence, canonical(event).decode(), event_hash))
        state["event_tip"] = event_hash
        conn.execute("UPDATE enrollment_meta SET value=? WHERE name='state'", (canonical(state).decode(),))
        return event_hash

    def mutation_attempt(self, *, currentness_fence=None):
        """Dormant infrastructure only; default source denies every commit.

        No policy/adoption/revocation writer or live source is installed here.
        """
        from governance.mutation_commit import MutationAttempt
        return MutationAttempt(self, currentness_fence)

    def enroll(self, inputs) -> dict:
        from governance.tenant_enrollment_contracts import (
            EnrollmentDenied, TenantRegistrationRecord, canonical, decision, digest, scope,
        )
        from governance.tenant_enrollment_verification import verify_enrollment
        conn = None
        commit_started = False
        try:
            conn = self._connect_existing()
            conn.execute("BEGIN IMMEDIATE")
            state = self._snapshot(conn)
            now = self.clock()
            verified = verify_enrollment(self.trust, inputs, expected=state["head"], now=now)
            g, request = verified["grant"], verified["request"]
            self._consume(conn, "enrollment", g)
            # Enforce authenticated request replay independently of grant replay.
            for name in ("nonce", "replay_identity", "request_id"):
                conn.execute("INSERT INTO enrollment_uses(kind,identity) VALUES(?,?)",
                             ("request:" + name, digest({"issuer": request["issuer_id"], "value": request[name]})))
            record = {k: g[k] for k in ("trust_domain", "policy_domain", "tenant_id", "environment", "purpose",
                "registry_instance_reference", "authority_flags", "delegation_allowed", "policy_id", "policy_version", "policy_hash",
                "issuer_id", "registrar_actor", "replay_identity", "currentness_reference", "revocation_reference", "enrollment_valid_until")}
            record.update(schema_version="usbay.enrollment.record.v3", record_id=digest({"grant": digest(g), "scope": list(scope(g))}),
                grant_hash=digest(g), request_digest=digest(request), nonce_reference=digest({"nonce": g["nonce"]}),
                previous_event_hash=state["event_tip"], evidence_fingerprint=digest(verified),
                created_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"), grant_valid_from=g["valid_from"], grant_expires_at=g["expires_at"],
                registration_status="REGISTERED_NON_EXECUTING", tenant_exists=True, allowed_actions=[])
            TenantRegistrationRecord.from_payload(record)
            # No update/reenroll path, including with a different grant.
            conn.execute("INSERT INTO enrollment_tenants(scope,record) VALUES(?,?)",
                         (digest(list(scope(g))), canonical(record).decode()))
            event_hash = self._append(conn, state, {"kind": "REGISTERED_NON_EXECUTING", "record": record})
            # A second full verification under the same write lock rejects time
            # expiry and any mutable caller input change before commit.
            verify_enrollment(self.trust, inputs, expected=state["head"], now=self.clock())
            commit_started = True
            conn.execute("COMMIT")
            return decision("SIGNED_RECEIPT_REQUIRED", registration_outcome="COMMITTED_NON_EXECUTING", event_hash=event_hash)
        except Exception as error:
            reason = str(error) if type(error) is EnrollmentDenied else "ENROLLMENT_STORE_UNAVAILABLE"
            return decision(reason, registration_outcome="UNKNOWN" if commit_started else "NOT_COMMITTED")
        finally:
            if conn is not None:
                conn.close()

    def propose_adoption(self, inputs) -> dict:
        from governance.tenant_enrollment_contracts import EnrollmentDenied, decision, digest
        from governance.tenant_enrollment_verification import verify_adoption
        conn = None
        commit_started = False
        try:
            conn = self._connect_existing()
            conn.execute("BEGIN IMMEDIATE")
            state = self._snapshot(conn)
            p, a, b = verify_adoption(self.trust, inputs, previous=state["head"], now=self.clock())
            self._consume(conn, "adoption", a)
            self._consume(conn, "advance", b)
            state["publication"] = "PENDING"
            event_hash = self._append(conn, state, {"kind": "ADOPTION_PENDING", "policy_hash": digest(p),
                "adoption_core_hash": digest(a), "head_advance_grant_hash": digest(b), "target_head": b["head_hash"]})
            verify_adoption(self.trust, inputs, previous=state["head"], now=self.clock())
            commit_started = True
            conn.execute("COMMIT")
            return decision("STOPPED_UNVERIFIED_POLICY_HEAD", publication="PENDING", event_hash=event_hash)
        except Exception as error:
            # Discard any uncommitted local rows before a separate read-only
            # snapshot classifies DURABLE consumption. Never label this failed
            # attempt's own rolled-back reservation as a prior replay.
            if conn is not None:
                conn.close()
                conn = None
            return decision(str(error) if type(error) is EnrollmentDenied else "ENROLLMENT_STORE_UNAVAILABLE",
                            adoption_outcome="UNKNOWN" if commit_started else "NOT_COMMITTED",
                            **self._replay_evidence(inputs))
        finally:
            if conn is not None:
                conn.close()
