"""USBAY Governance Simulator - signed voucher redemption authority.

Training-only. Fail-closed by design. This module demonstrates the *mechanism*
of a signed travel-voucher authority and partner-side verification. Nothing here
carries monetary value:

  * No payments, no booking APIs, no cash value, no crypto, no cashback.
  * Every verification failure fails closed (``valid`` is ``False``).

Security model (training):
  Vouchers are signed with HMAC-SHA256 over a fixed, ordered set of fields using
  a server-side secret. A partner verifies a voucher by recomputing the
  signature; any tampered field breaks the signature and the voucher is rejected
  (fail-closed). Signatures are compared in constant time.

  Revocation has two layers, both fail-closed:
    1. A signed ``revoked_at`` field set by the issuing authority at (or after)
       issuance, so the holder cannot forge or strip it.
    2. A central :class:`RevocationRegistry` (a revocation list / CRL) keyed by
       ``voucher_id``. A voucher can be revoked *after* issuance and the registry
       is consulted on every verification. If the registry cannot be read (or its
       data is tampered/corrupt) verification fails closed
       (``REVOCATION_REGISTRY_UNAVAILABLE``) rather than assuming the voucher is
       still valid.

  The registry stores only a non-reversible reference to the holder
  (``client_ref`` = a salted SHA-256 prefix), never the raw client id, so no
  sensitive identifier lands in the revocation record or audit trail.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from typing import Optional

__all__ = [
    "VoucherError",
    "SIGNED_FIELDS",
    "REQUIRED_FIELDS",
    "REVOCATION_REGISTRY_KEY",
    "voucher_secret",
    "make_voucher_id",
    "client_ref",
    "sign_payload",
    "issue_voucher",
    "voucher_status",
    "verify_voucher",
    "redemption_audit_trail",
    "RevocationRegistry",
]

# Fields covered by the signature. Order is fixed and part of the contract.
# ``revoked_at`` is signed so a revoked voucher cannot be downgraded by stripping
# the field.
SIGNED_FIELDS = (
    "voucher_id",
    "client_id",
    "partner_id",
    "issued_at",
    "expires_at",
    "revoked_at",
)

# Fields that must be present (non-empty) for a verification to even be attempted.
REQUIRED_FIELDS = ("voucher_id", "client_id", "partner_id", "issued_at", "expires_at")

# Training-only fallback secret. No real value is ever at stake; this only
# demonstrates the signing / verification mechanism. Overridable via env so a
# deployment can rotate it without a code change.
_DEFAULT_SECRET = "usbay-simulator-training-voucher-authority-v1"


class VoucherError(RuntimeError):
    """Base error for voucher authority operations."""


def voucher_secret() -> bytes:
    """Return the signing secret (server-side; env-overridable)."""
    return (os.getenv("USBAY_SIM_VOUCHER_SECRET") or _DEFAULT_SECRET).encode("utf-8")


def make_voucher_id(partner_id: str) -> str:
    """Build an opaque, non-monetary voucher id for a partner."""
    tag = "".join(ch for ch in str(partner_id).upper() if ch.isalnum())[:12] or "PARTNER"
    return "VCHR-" + tag + "-" + uuid.uuid4().hex[:8].upper()


# Salt for the holder reference hash. This is NOT a secret (the ref only needs to
# be non-reversible for casual inspection of the registry / audit trail); raw
# client ids must never be persisted in a revocation record or evidence row.
_CLIENT_REF_SALT = "usbay-sim-voucher-client-ref-v1"


def client_ref(client_id) -> str:
    """Return a stable, non-reversible reference for a client id (never the raw
    value). Used in revocation records and audit rows so no sensitive identifier
    is stored or logged."""
    if client_id in (None, ""):
        return "anon"
    digest = hashlib.sha256(
        (_CLIENT_REF_SALT + ":" + str(client_id)).encode("utf-8")
    ).hexdigest()
    return "cref_" + digest[:16]


def _norm(value) -> str:
    """Canonical string form of a signed field (None -> empty, still signed)."""
    if value is None:
        return ""
    return str(value)


def _canonical(payload: dict) -> str:
    return "\n".join("%s=%s" % (f, _norm(payload.get(f))) for f in SIGNED_FIELDS)


def sign_payload(payload: dict, secret: Optional[bytes] = None) -> str:
    """Return the hex HMAC-SHA256 signature over the signed fields of ``payload``."""
    key = secret or voucher_secret()
    msg = _canonical(payload).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def issue_voucher(
    voucher_id: str,
    client_id: str,
    partner_id: str,
    *,
    issued_at: Optional[int] = None,
    expires_at: Optional[int] = None,
    ttl_days: int = 30,
    revoked_at: Optional[int] = None,
    secret: Optional[bytes] = None,
) -> dict:
    """Issue a signed, non-monetary voucher (epoch-ms timestamps).

    The voucher is bound to ``client_id`` (ownership) and ``partner_id``. The
    returned object carries a ``voucher_signature`` plus explicit non-monetary
    contract markers.
    """
    now = int(time.time() * 1000)
    issued = int(issued_at) if issued_at is not None else now
    if expires_at is not None:
        expires = int(expires_at)
    else:
        expires = issued + int(ttl_days) * 86400000
    payload = {
        "voucher_id": str(voucher_id),
        "client_id": str(client_id),
        "partner_id": str(partner_id),
        "issued_at": issued,
        "expires_at": expires,
        "revoked_at": int(revoked_at) if revoked_at is not None else None,
    }
    payload["voucher_signature"] = sign_payload(payload, secret)
    # Non-monetary contract markers (mirror the client-side voucher object).
    payload["cash_value"] = "none"
    payload["transferable"] = False
    payload["funding"] = "partner_funded"
    return payload


def _is_revoked(payload: dict) -> bool:
    rv = payload.get("revoked_at")
    return rv not in (None, "", "0", 0)


def voucher_status(payload: dict, now_ms: int) -> str:
    """Expiration engine -> ``active`` | ``expired`` | ``revoked`` (fail-closed)."""
    if _is_revoked(payload):
        return "revoked"
    try:
        expires = int(payload.get("expires_at"))
    except (TypeError, ValueError):
        return "expired"  # unparseable / missing expiry -> fail closed
    if now_ms >= expires:
        return "expired"
    return "active"


def _audit_row(event, at, payload, status, reason_code, detail):
    """One audit/evidence row. Carries only a safe holder reference (never the
    raw client id) so no sensitive identifier is logged."""
    return {
        "event": event,
        "at": at,
        "voucher_id": payload.get("voucher_id"),
        "partner_id": payload.get("partner_id"),
        "client_ref": client_ref(payload.get("client_id")),
        "status": status,
        "reason_code": reason_code,
        "detail": detail,
    }


def redemption_audit_trail(
    payload: dict,
    status: str,
    now_ms: int,
    *,
    reason_code: Optional[str] = None,
    registry_record: Optional[dict] = None,
) -> list:
    """Build the redemption audit trail: issued / viewed / verified plus, by
    status, expired / revoked / revoke_failed. Read-only and illustrative; every
    row carries voucher_id, partner_id, a safe client_ref, status, reason_code,
    and a timestamp. No sensitive data is included."""
    trail = [
        _audit_row(
            "issued", payload.get("issued_at"), payload, status, reason_code,
            "Voucher issued by signing authority (no cash value)",
        ),
        _audit_row(
            "viewed", now_ms, payload, status, reason_code,
            "Voucher presented for partner verification",
        ),
        _audit_row(
            "verified", now_ms, payload, status, reason_code,
            "Signature verification outcome: " + str(status),
        ),
    ]
    if status == "expired":
        trail.append(_audit_row(
            "expired", payload.get("expires_at"), payload, status,
            reason_code or "VOUCHER_EXPIRED",
            "Validity window elapsed - fail-closed, not redeemable",
        ))
    if status == "revoked":
        if registry_record:
            at = registry_record.get("revoked_at")
            detail = (
                "Voucher revoked via revocation registry (reason: "
                + str(registry_record.get("reason") or "unspecified")
                + ") - fail-closed, confers nothing"
            )
        else:
            at = payload.get("revoked_at")
            detail = "Voucher revoked by authority - fail-closed, confers nothing"
        trail.append(_audit_row(
            "revoked", at, payload, status,
            reason_code or "VOUCHER_REVOKED", detail,
        ))
    if status == "unavailable":
        trail.append(_audit_row(
            "revoke_failed", now_ms, payload, status,
            reason_code or "REVOCATION_REGISTRY_UNAVAILABLE",
            "Revocation registry could not be consulted - fail-closed, voucher rejected",
        ))
    return trail


def verify_voucher(
    payload: dict,
    *,
    now_ms: Optional[int] = None,
    secret: Optional[bytes] = None,
    expected_client_id: Optional[str] = None,
    registry: "Optional[RevocationRegistry]" = None,
) -> dict:
    """Verify a signed voucher. Fail-closed: any problem yields ``valid=False``.

    Checks, in order: required fields + signature presence, signature integrity
    (constant-time), ownership binding, the central revocation registry (if one
    is supplied), then the expiration engine. If ``registry`` is supplied and
    cannot be consulted (unavailable / tampered data), verification fails closed
    with ``REVOCATION_REGISTRY_UNAVAILABLE``.

    Returns a dict with ``valid``, ``status`` (active/expired/revoked/invalid/
    unavailable), ``reasons``, the bound identifiers, and a redemption
    ``audit_trail``.
    """
    now = int(now_ms) if now_ms is not None else int(time.time() * 1000)
    result = {
        "valid": False,
        "status": "invalid",
        "reasons": [],
        "voucher_id": payload.get("voucher_id"),
        "client_id": payload.get("client_id"),
        "partner_id": payload.get("partner_id"),
        "checked_at": now,
    }

    # 1. Required signed fields + a signature must be present.
    missing = [f for f in REQUIRED_FIELDS if payload.get(f) in (None, "")]
    if missing:
        result["reasons"].append("MISSING_FIELD")
    if not payload.get("voucher_signature"):
        result["reasons"].append("MISSING_SIGNATURE")
    if result["reasons"]:
        result["audit_trail"] = redemption_audit_trail(
            payload, "invalid", now, reason_code=";".join(result["reasons"]))
        return result

    # 2. Signature must match (constant-time compare). Any tamper fails closed.
    expected_sig = sign_payload(payload, secret)
    if not hmac.compare_digest(str(payload.get("voucher_signature")), expected_sig):
        result["reasons"] = ["BAD_SIGNATURE"]
        result["audit_trail"] = redemption_audit_trail(
            payload, "invalid", now, reason_code="BAD_SIGNATURE")
        return result

    # 3. Ownership binding: the presented holder must match the bound client.
    if expected_client_id not in (None, "") and str(expected_client_id) != str(payload.get("client_id")):
        result["reasons"] = ["OWNERSHIP_MISMATCH"]
        result["audit_trail"] = redemption_audit_trail(
            payload, "invalid", now, reason_code="OWNERSHIP_MISMATCH")
        return result

    # 4. Central revocation registry (CRL). When supplied it is authoritative;
    # any failure to consult it (unavailable / corrupt / tampered) fails closed.
    registry_record = None
    if registry is not None:
        try:
            registry_record = registry.get_record(payload.get("voucher_id"))
        except Exception:
            result["status"] = "unavailable"
            result["reasons"] = ["REVOCATION_REGISTRY_UNAVAILABLE"]
            result["audit_trail"] = redemption_audit_trail(
                payload, "unavailable", now,
                reason_code="REVOCATION_REGISTRY_UNAVAILABLE")
            return result

    # 5. Expiration engine (active / expired / revoked). A registry revocation
    # is the strongest statement and overrides active/expired.
    status = voucher_status(payload, now)
    if registry_record is not None:
        status = "revoked"
    result["status"] = status
    if status == "revoked":
        reason_code = "VOUCHER_REVOKED"
        result["reasons"] = [reason_code]
    elif status == "expired":
        reason_code = "VOUCHER_EXPIRED"
        result["reasons"] = [reason_code]
    else:
        reason_code = "VOUCHER_ACTIVE"
        result["valid"] = True
        result["reasons"] = [reason_code]
    if registry_record is not None:
        result["revocation"] = {
            "reason": registry_record.get("reason"),
            "revoked_at": registry_record.get("revoked_at"),
            "source": registry_record.get("source"),
            "client_ref": registry_record.get("client_ref"),
        }
    result["audit_trail"] = redemption_audit_trail(
        payload, status, now, reason_code=reason_code,
        registry_record=registry_record)
    return result


# --------------------------------------------------------------------------- #
# Central voucher revocation registry (a revocation list / CRL)
# --------------------------------------------------------------------------- #
REVOCATION_REGISTRY_KEY = "voucher_revocations"


class RevocationRegistry:
    """Central, simulator-scoped voucher revocation list (CRL).

    Backed by a key/value ``StorageAdapter`` (see ``simulator.storage``). All
    revoked vouchers live under a single key as a JSON object keyed by
    ``voucher_id``. Fail-closed by design: any storage error, missing/corrupt
    payload, or tampered JSON raises so the caller rejects the voucher rather
    than assuming it is still valid. Only a non-reversible ``client_ref`` is
    stored — never the raw client id.
    """

    def __init__(self, storage, key: str = REVOCATION_REGISTRY_KEY):
        if storage is None:
            raise VoucherError("revocation registry requires a storage adapter")
        self._storage = storage
        self._key = key
        self._lock = threading.Lock()

    def _load(self) -> dict:
        raw = self._storage.get(self._key)  # may raise -> fail closed
        if not raw:
            return {}
        data = json.loads(raw)  # corrupt / tampered -> raises -> fail closed
        if not isinstance(data, dict):
            raise VoucherError("revocation registry payload is not an object")
        return data

    def get_record(self, voucher_id) -> Optional[dict]:
        """Return the revocation record for ``voucher_id`` or ``None`` if it is
        not revoked. Raises on any storage/parse failure OR on a malformed
        (non-object) record for a present key, so callers fail closed under
        tampered registry data rather than treating it as not-revoked."""
        if voucher_id in (None, ""):
            return None
        data = self._load()
        vid = str(voucher_id)
        if vid not in data:
            return None
        rec = data[vid]
        if not isinstance(rec, dict):
            raise VoucherError("revocation record is malformed")
        return rec

    def is_revoked(self, voucher_id) -> bool:
        return self.get_record(voucher_id) is not None

    def revoke(
        self,
        voucher_id,
        client_id,
        *,
        reason: Optional[str] = None,
        source: Optional[str] = None,
        now_ms: Optional[int] = None,
    ) -> dict:
        """Record a revocation. Idempotent: re-revoking returns the existing
        record with ``already=True``. Returns ``{"record": ..., "already": ...}``.
        Raises on storage failure (caller fails closed)."""
        if voucher_id in (None, ""):
            raise VoucherError("voucher_id is required to revoke")
        vid = str(voucher_id)
        now = int(now_ms) if now_ms is not None else int(time.time() * 1000)
        with self._lock:
            data = self._load()
            existing = data.get(vid)
            if isinstance(existing, dict):
                return {"record": existing, "already": True}
            record = {
                "voucher_id": vid,
                "client_ref": client_ref(client_id),
                "reason": str(reason or "unspecified")[:200],
                "revoked_at": now,
                "source": str(source or "simulator")[:80],
            }
            data[vid] = record
            self._storage.set(self._key, json.dumps(data))
            return {"record": record, "already": False}

    def list_records(self) -> list:
        """Return all revocation records (raises on failure -> fail closed)."""
        return list(self._load().values())
