"""Enforcement Gateway consumer/validator for the governed authorization request.

Consumes ``usbay.enforcement_gateway.authorization_request.v1`` produced by
Policy Brain (PR #316) and published as a canonical cross-repository contract
(PR #317).  The Gateway validates every request INDEPENDENTLY and is the ONLY
component that may produce the final runtime authorization decision.

Authority invariants (absolute):

* ``EURIA_EXECUTION_AUTHORITY = false``
* ``POLICY_BRAIN_EXECUTION_AUTHORITY = false``
* REQUEST_RECEIVED != EXECUTION_AUTHORIZED
* REQUEST_SCHEMA_VALID != EXECUTION_AUTHORIZED
* REQUEST_HASH_VALID != EXECUTION_AUTHORIZED

The consumer FAILS CLOSED: any uncertainty, malformed state, missing
dependency, validation error, replay uncertainty, storage failure, or
authority ambiguity produces an explicit ``BLOCK``.  ``ALLOW`` is produced
only after every mandatory control succeeds AND hash-correlated audit
evidence has been durably written.

Reservation semantics (intentional tradeoff): the replay reservation is
made BEFORE the TOCTOU recheck and audit write, so a request whose final
controls fail (or whose audit write fails) permanently burns its
nonce/request id.  A retry is REPLAY_DETECTED and blocked.  This is
deliberate fail-closed behavior: replay uncertainty must never be resolved
permissively, even at the cost of denying first use after a transient
failure.  The producer must issue a new governed request (new nonce and
request id) instead.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from audit.audit_writer import AuditWriteError, write_audit_record
from governance.euria_gateway_authorization_request import (
    CONTRACT_VERSION as PRODUCER_CONTRACT_VERSION,
    compute_gateway_authorization_request_hash,
    verify_gateway_authorization_request,
)
from governance.cross_repository_contracts import CrossRepositoryContractError
from governance.gateway_authorization_contract_publication import (
    resolve_canonical_contract,
)
from governance.hashing import sha256_reference
from security.tenant_context import validate_tenant_id

CONSUMER_VERSION = "usbay.enforcement_gateway.authorization_request_consumer.v1"

# Exact canonical pins (out-of-band, recorded at consumer build time from the
# post-merge PR #317 evidence).  Resolution through the cross-repository
# contract mechanism MUST reproduce these hashes or the consumer blocks.
CANONICAL_CONTRACT_ID = "usbay.enforcement_gateway.authorization_request.v1"
CANONICAL_CONTRACT_VERSION = "v1"
PINNED_CANONICAL_SCHEMA_HASH = (
    "sha256:6f34bd112586408216dde71f4799b56ce1f274a49ff5379f69db6915893694c8"
)
PINNED_PUBLICATION_HASH = (
    "sha256:e3bd95618925ad1039248479d7896025b7266faa9df06db3c568f090162eb0f2"
)

DECISION_ALLOW = "ALLOW"
DECISION_BLOCK = "BLOCK"

AUDIT_EVENT_TYPE = "GATEWAY_AUTHORIZATION_REQUEST_DECISION"

MAX_REQUEST_CANONICAL_BYTES = 65536

DEFAULT_REPLAY_DB_PATH = Path("tmp/usbay.db")
REPLAY_DB_ENV = "USBAY_GATEWAY_AUTHZ_REPLAY_DB"

# Authority invariants restated locally so this module is self-evidently
# incapable of granting upstream execution authority.
EURIA_EXECUTION_AUTHORITY = False
POLICY_BRAIN_EXECUTION_AUTHORITY = False

# Request binding fields that must be independently confirmed against an
# authoritative Gateway-side source.  A valid hash alone is NOT sufficient.
BINDING_FIELDS = (
    "tenant_reference",
    "environment_reference",
    "customer_onboarding_reference",
    "human_approval_reference",
    "policy_reference",
    "policy_hash",
    "pilot_reference",
    "activation_reference",
    "identity_reference",
    "identity_hash",
    "verifier_reference",
    "verifier_hash",
    "attestation_reference",
    "attestation_hash",
    "challenge_reference",
    "readiness_decision_hash",
    "activation_request_hash",
    "previous_evidence_hash",
    "current_evidence_hash",
    "evidence_chain_reference",
)

# Revocation flags the authority source must supply; each must be exactly False.
REVOCATION_FLAGS = (
    "approval_revoked",
    "pilot_revoked",
    "activation_revoked",
    "identity_revoked",
    "verifier_revoked",
    "attestation_revoked",
    "challenge_revoked",
)

# Freshness windows the authority source must supply; each must be a
# timezone-aware ISO-8601 timestamp strictly in the future at decision time.
FRESHNESS_FIELDS = (
    "approval_expires_at",
    "activation_expires_at",
    "attestation_expires_at",
    "challenge_expires_at",
)


class GatewayReplayStoreError(RuntimeError):
    """Replay store unavailable or returned an ambiguous result."""


class GatewayAuthorizationReplayStore:
    """Persistent, atomic first-use replay protection.

    Reuses the existing Gateway SQLite persistence convention
    (``security/store.py`` — WAL SQLite under ``tmp/``) with a dedicated
    table and a SINGLE transaction inserting both the nonce reference and
    the request id, so two concurrent requests sharing either identity
    cannot both reserve (PRIMARY KEY uniqueness is enforced by SQLite
    atomically).  Any storage error is raised — never treated as success.
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        resolved = db_path or os.environ.get(REPLAY_DB_ENV) or DEFAULT_REPLAY_DB_PATH
        self._db_path = Path(resolved)

    def _connect(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS gateway_authorization_replay (
                replay_key TEXT PRIMARY KEY,
                request_hash TEXT NOT NULL,
                reserved_at TEXT NOT NULL
            )
            """
        )
        return conn

    def reserve(self, nonce_reference: str, request_id: str, request_hash: str, reserved_at: str) -> bool:
        """Atomically reserve first use.  True = first valid use.

        False = duplicate nonce/request id (replay).  Raises
        :class:`GatewayReplayStoreError` on any storage failure.
        """
        if not nonce_reference or not request_id:
            raise GatewayReplayStoreError("REPLAY_IDENTITY_MISSING")
        try:
            conn = self._connect()
            try:
                with conn:
                    conn.execute(
                        "INSERT INTO gateway_authorization_replay (replay_key, request_hash, reserved_at) VALUES (?, ?, ?)",
                        (f"nonce:{nonce_reference}", request_hash, reserved_at),
                    )
                    conn.execute(
                        "INSERT INTO gateway_authorization_replay (replay_key, request_hash, reserved_at) VALUES (?, ?, ?)",
                        (f"request:{request_id}", request_hash, reserved_at),
                    )
                return True
            finally:
                conn.close()
        except sqlite3.IntegrityError:
            return False
        except GatewayReplayStoreError:
            raise
        except Exception as exc:  # noqa: BLE001 - fail closed on any store failure
            raise GatewayReplayStoreError("REPLAY_STORE_UNAVAILABLE") from exc


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    candidate = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _validate_structure(request: Any) -> list[str]:
    reasons: list[str] = []
    if not isinstance(request, Mapping):
        return ["REQUEST_NOT_A_MAPPING"]
    if any(not isinstance(key, str) for key in request.keys()):
        reasons.append("REQUEST_KEY_NOT_STRING")
        return reasons
    try:
        canonical = json.dumps(dict(request), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError):
        return ["REQUEST_NOT_CANONICALIZABLE"]
    if len(canonical.encode("utf-8")) > MAX_REQUEST_CANONICAL_BYTES:
        reasons.append("REQUEST_TOO_LARGE")
    return reasons


def _validate_contract_pins(root: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        contract = resolve_canonical_contract(
            CANONICAL_CONTRACT_ID,
            CANONICAL_CONTRACT_VERSION,
            root,
            expected_schema_hash=PINNED_CANONICAL_SCHEMA_HASH,
            expected_publication_hash=PINNED_PUBLICATION_HASH,
        )
    except CrossRepositoryContractError as exc:
        return None, [f"CONTRACT_{getattr(exc, 'code', 'RESOLUTION_FAILED')}"]
    except Exception:  # noqa: BLE001 - dependency failure fails closed
        return None, ["CONTRACT_RESOLUTION_FAILED"]
    if contract.get("canonical_schema_hash") != PINNED_CANONICAL_SCHEMA_HASH:
        return None, ["CONTRACT_SCHEMA_PIN_MISMATCH"]
    if contract.get("publication_hash") != PINNED_PUBLICATION_HASH:
        return None, ["CONTRACT_PUBLICATION_PIN_MISMATCH"]
    return contract, []


def _validate_request_contract_fields(request: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    if request.get("gateway_contract_version") != CANONICAL_CONTRACT_ID:
        reasons.append("CONTRACT_VERSION_UNSUPPORTED")
    if request.get("contract_version") != PRODUCER_CONTRACT_VERSION:
        reasons.append("PRODUCER_CONTRACT_VERSION_UNSUPPORTED")
    return reasons


def _validate_freshness(request: Mapping[str, Any], now: datetime) -> list[str]:
    reasons: list[str] = []
    issued = _parse_timestamp(request.get("issued_at"))
    expires = _parse_timestamp(request.get("expires_at"))
    if issued is None:
        reasons.append("ISSUED_AT_INVALID")
    if expires is None:
        reasons.append("EXPIRES_AT_INVALID")
    if issued is not None and expires is not None and expires <= issued:
        reasons.append("EXPIRES_BEFORE_ISSUED")
    if issued is not None and issued > now:
        reasons.append("ISSUED_AT_IN_FUTURE")
    if expires is not None and expires <= now:
        reasons.append("REQUEST_EXPIRED")
    return reasons


def _validate_authority_context(
    request: Mapping[str, Any], context: Any, now: datetime
) -> list[str]:
    reasons: list[str] = []
    if not isinstance(context, Mapping):
        return ["AUTHORITY_CONTEXT_MALFORMED"]
    if "tenant_id" not in context:
        reasons.append("TENANT_ID_UNAVAILABLE")
    else:
        try:
            validate_tenant_id(context["tenant_id"])
        except Exception:  # noqa: BLE001 - unauthorized/invalid tenant fails closed
            reasons.append("TENANT_ID_INVALID")
    for field in BINDING_FIELDS:
        if field not in context:
            reasons.append(f"BINDING_{field.upper()}_UNAVAILABLE")
        elif context[field] != request.get(field):
            reasons.append(f"BINDING_{field.upper()}_MISMATCH")
    for flag in REVOCATION_FLAGS:
        if flag not in context:
            reasons.append(f"REVOCATION_{flag.upper()}_UNAVAILABLE")
        elif context[flag] is not False:
            reasons.append(f"REVOCATION_{flag.upper()}")
    for field in FRESHNESS_FIELDS:
        window = _parse_timestamp(context.get(field))
        if window is None:
            reasons.append(f"FRESHNESS_{field.upper()}_UNAVAILABLE")
        elif window <= now:
            reasons.append(f"FRESHNESS_{field.upper()}_EXPIRED")
    return reasons


def _fetch_authority_context(authority_source: Any) -> tuple[Any, list[str]]:
    if not callable(authority_source):
        return None, ["AUTHORITY_SOURCE_UNAVAILABLE"]
    try:
        return authority_source(), []
    except Exception:  # noqa: BLE001 - dependency failure fails closed
        return None, ["AUTHORITY_SOURCE_UNAVAILABLE"]


def _decision_payload(
    request: Mapping[str, Any] | None,
    decision: str,
    reason_codes: list[str],
    now: datetime,
    tenant_id: str | None,
) -> dict[str, Any]:
    request = request if isinstance(request, Mapping) else {}
    payload = {
        # Governed ledger tenant identity: established from the authoritative
        # Gateway-side source and policy-validated.  When no tenant identity
        # could be established (early BLOCKs), evidence is recorded under the
        # default gateway tenant and explicitly marked unattributed.
        "tenant_id": tenant_id if tenant_id is not None else "t1",
        "tenant_attributed": tenant_id is not None,
        "consumer_version": CONSUMER_VERSION,
        "contract_id": CANONICAL_CONTRACT_ID,
        "contract_version": CANONICAL_CONTRACT_VERSION,
        "canonical_schema_hash": PINNED_CANONICAL_SCHEMA_HASH,
        "publication_hash": PINNED_PUBLICATION_HASH,
        "request_id": str(request.get("request_id", "")),
        "request_hash": str(request.get("request_hash", "")),
        "decision": decision,
        "reason_codes": sorted(set(reason_codes)),
        "policy_reference": str(request.get("policy_reference", "")),
        "policy_hash": str(request.get("policy_hash", "")),
        "tenant_reference": str(request.get("tenant_reference", "")),
        "environment_reference": str(request.get("environment_reference", "")),
        "human_approval_reference": str(request.get("human_approval_reference", "")),
        "activation_reference": str(request.get("activation_reference", "")),
        "identity_reference": str(request.get("identity_reference", "")),
        "verifier_reference": str(request.get("verifier_reference", "")),
        "previous_evidence_hash": str(request.get("previous_evidence_hash", "")),
        "evidence_chain_reference": str(request.get("evidence_chain_reference", "")),
        "timestamp": now.isoformat().replace("+00:00", "Z"),
        "euria_execution_authority": EURIA_EXECUTION_AUTHORITY,
        "policy_brain_execution_authority": POLICY_BRAIN_EXECUTION_AUTHORITY,
        "enforcement_gateway_final_authority": True,
    }
    payload["gateway_decision_hash"] = sha256_reference(payload)
    return payload


def _finalize(
    request: Mapping[str, Any] | None,
    decision: str,
    reason_codes: list[str],
    now: datetime,
    audit_path: str | Path | None,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """Write hash-correlated audit evidence and return the explicit decision.

    ALLOW is DOWNGRADED to BLOCK if mandatory audit evidence cannot be
    durably written.  No audit evidence = no ALLOW.
    """
    reasons = sorted(set(reason_codes))
    payload = _decision_payload(request, decision, reasons, now, tenant_id)
    audit_result: dict[str, Any] | None = None
    try:
        kwargs: dict[str, Any] = {}
        if audit_path is not None:
            kwargs["audit_path"] = audit_path
        audit_result = write_audit_record(AUDIT_EVENT_TYPE, payload, **kwargs)
    except AuditWriteError:
        decision = DECISION_BLOCK
        reasons = sorted(set(reasons + ["AUDIT_WRITE_FAILED"]))
        audit_result = None
    except Exception:  # noqa: BLE001 - unknown audit failure fails closed
        decision = DECISION_BLOCK
        reasons = sorted(set(reasons + ["AUDIT_WRITE_FAILED"]))
        audit_result = None
    result = {
        "decision": decision,
        "reason_codes": reasons,
        "consumer_version": CONSUMER_VERSION,
        "contract_id": CANONICAL_CONTRACT_ID,
        "contract_version": CANONICAL_CONTRACT_VERSION,
        "request_id": payload["request_id"],
        "request_hash": payload["request_hash"],
        "gateway_decision_hash": payload["gateway_decision_hash"],
        "execution_authorized": decision == DECISION_ALLOW,
        "euria_execution_authority": EURIA_EXECUTION_AUTHORITY,
        "policy_brain_execution_authority": POLICY_BRAIN_EXECUTION_AUTHORITY,
        "enforcement_gateway_final_authority": True,
        "audit": None,
    }
    if audit_result is not None:
        result["audit"] = {
            "event_type": AUDIT_EVENT_TYPE,
            "payload_hash": audit_result.get("payload_hash"),
            "audit_hash": audit_result.get("audit_hash"),
            "hash_prev": audit_result.get("hash_prev"),
            "timestamp": audit_result.get("timestamp"),
        }
    if result["decision"] != DECISION_ALLOW:
        result["decision"] = DECISION_BLOCK
        result["execution_authorized"] = False
    return result


def consume_gateway_authorization_request(
    request: Any,
    *,
    authority_source: Callable[[], Mapping[str, Any]],
    root: Path = Path("."),
    replay_store: GatewayAuthorizationReplayStore | None = None,
    audit_path: str | Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Independently validate a governed authorization request.

    Returns an explicit decision mapping whose ``decision`` is exactly
    ``ALLOW`` or ``BLOCK``.  Receiving/parsing a request has zero execution
    side effects; execution requires :func:`execute_with_gateway_authorization`.
    """
    try:
        decision_now = now or _utc_now()
        if now is not None and (not isinstance(now, datetime) or now.tzinfo is None):
            return _finalize(None, DECISION_BLOCK, ["DECISION_CLOCK_INVALID"], _utc_now(), audit_path)

        # Task 2 — size/structure (parse without executing).
        structure_reasons = _validate_structure(request)
        if structure_reasons:
            return _finalize(None, DECISION_BLOCK, structure_reasons, decision_now, audit_path)

        # Task 1 — canonical contract acquisition with exact out-of-band pins.
        _, contract_reasons = _validate_contract_pins(root)
        if contract_reasons:
            return _finalize(request, DECISION_BLOCK, contract_reasons, decision_now, audit_path)

        # Contract identifier/version carried by the request itself.
        reasons = _validate_request_contract_fields(request)

        # Task 3 — schema/authority/reference verification (producer rules)
        # plus INDEPENDENT request hash recomputation.  Never trust the
        # supplied request_hash.
        verification = verify_gateway_authorization_request(request)
        if not verification.get("valid", False):
            reasons.extend(str(code) for code in verification.get("reason_codes", []) or ["REQUEST_VERIFICATION_FAILED"])
        recomputed = compute_gateway_authorization_request_hash(dict(request))
        if recomputed != request.get("request_hash"):
            reasons.append("REQUEST_HASH_MISMATCH")

        # Task 5 — freshness/expiry.
        reasons.extend(_validate_freshness(request, decision_now))
        if reasons:
            return _finalize(request, DECISION_BLOCK, reasons, decision_now, audit_path)

        # Task 6 — independent authority binding.
        context, source_reasons = _fetch_authority_context(authority_source)
        if source_reasons:
            return _finalize(request, DECISION_BLOCK, source_reasons, decision_now, audit_path)
        binding_reasons = _validate_authority_context(request, context, decision_now)
        if binding_reasons:
            return _finalize(request, DECISION_BLOCK, binding_reasons, decision_now, audit_path)
        tenant_id = str(context["tenant_id"])

        # Task 4 — persistent, atomic replay protection.
        store = replay_store or GatewayAuthorizationReplayStore()
        try:
            first_use = store.reserve(
                str(request.get("nonce_reference", "")),
                str(request.get("request_id", "")),
                str(request.get("request_hash", "")),
                decision_now.isoformat().replace("+00:00", "Z"),
            )
        except GatewayReplayStoreError as exc:
            return _finalize(request, DECISION_BLOCK, [str(exc) or "REPLAY_STORE_UNAVAILABLE"], decision_now, audit_path, tenant_id)
        if first_use is not True:
            return _finalize(request, DECISION_BLOCK, ["REPLAY_DETECTED"], decision_now, audit_path, tenant_id)

        # Task 7 — TOCTOU revalidation immediately before authorization:
        # re-fetch mutable authority inputs and require an unchanged,
        # still-valid state.
        recheck_now = now or _utc_now()
        toctou_reasons: list[str] = []
        toctou_reasons.extend(_validate_freshness(request, recheck_now))
        context_2, source_reasons_2 = _fetch_authority_context(authority_source)
        if source_reasons_2:
            toctou_reasons.extend(source_reasons_2)
        else:
            toctou_reasons.extend(_validate_authority_context(request, context_2, recheck_now))
            if isinstance(context_2, Mapping):
                for field in ("tenant_id",) + BINDING_FIELDS + REVOCATION_FLAGS + FRESHNESS_FIELDS:
                    if context_2.get(field) != context.get(field):
                        toctou_reasons.append("TOCTOU_STATE_CHANGED")
                        break
        if toctou_reasons:
            return _finalize(request, DECISION_BLOCK, toctou_reasons, recheck_now, audit_path, tenant_id)

        # Tasks 8 + 10 — explicit decision with mandatory pre-execution
        # hash-correlated audit evidence (audit failure downgrades to BLOCK).
        return _finalize(request, DECISION_ALLOW, [], recheck_now, audit_path, tenant_id)
    except Exception:  # noqa: BLE001 - unknown state fails closed
        try:
            return _finalize(None, DECISION_BLOCK, ["GATEWAY_CONSUMER_ERROR"], _utc_now(), audit_path)
        except Exception:  # noqa: BLE001 - absolute last resort, still explicit BLOCK
            return {
                "decision": DECISION_BLOCK,
                "reason_codes": ["GATEWAY_CONSUMER_ERROR"],
                "consumer_version": CONSUMER_VERSION,
                "execution_authorized": False,
                "audit": None,
            }


def execute_with_gateway_authorization(
    request: Any,
    *,
    executor: Callable[[], Any],
    authority_source: Callable[[], Mapping[str, Any]],
    root: Path = Path("."),
    replay_store: GatewayAuthorizationReplayStore | None = None,
    audit_path: str | Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Execution boundary: the executor runs ONLY after explicit Gateway ALLOW
    with durable audit evidence.  Every other state blocks execution."""
    decision = consume_gateway_authorization_request(
        request,
        authority_source=authority_source,
        root=root,
        replay_store=replay_store,
        audit_path=audit_path,
        now=now,
    )
    if (
        decision.get("decision") == DECISION_ALLOW
        and decision.get("execution_authorized") is True
        and isinstance(decision.get("audit"), Mapping)
        and decision["audit"].get("audit_hash")
    ):
        return {"executed": True, "decision": decision, "result": executor()}
    return {"executed": False, "decision": decision, "result": None}
