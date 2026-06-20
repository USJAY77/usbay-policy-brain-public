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

  Revocation is represented as a signed ``revoked_at`` field set by the issuing
  authority, so the holder cannot forge or strip it. A real deployment would
  additionally back revocation with a server-side revocation list (CRL); that is
  out of scope for this training simulator.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
import uuid
from typing import Optional

__all__ = [
    "VoucherError",
    "SIGNED_FIELDS",
    "REQUIRED_FIELDS",
    "voucher_secret",
    "make_voucher_id",
    "sign_payload",
    "issue_voucher",
    "voucher_status",
    "verify_voucher",
    "redemption_audit_trail",
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


def redemption_audit_trail(payload: dict, status: str, now_ms: int) -> list:
    """Build the redemption audit trail: issued / viewed / verified [/ expired /
    revoked]. Read-only and illustrative."""
    vid = payload.get("voucher_id")
    pid = payload.get("partner_id")
    cid = payload.get("client_id")
    trail = [
        {
            "event": "issued",
            "at": payload.get("issued_at"),
            "voucher_id": vid,
            "client_id": cid,
            "partner_id": pid,
            "detail": "Voucher issued by signing authority (no cash value)",
        },
        {
            "event": "viewed",
            "at": now_ms,
            "voucher_id": vid,
            "detail": "Voucher presented for partner verification",
        },
        {
            "event": "verified",
            "at": now_ms,
            "voucher_id": vid,
            "detail": "Signature verification outcome: " + str(status),
        },
    ]
    if status == "expired":
        trail.append({
            "event": "expired",
            "at": payload.get("expires_at"),
            "voucher_id": vid,
            "detail": "Validity window elapsed - fail-closed, not redeemable",
        })
    if status == "revoked":
        trail.append({
            "event": "revoked",
            "at": payload.get("revoked_at"),
            "voucher_id": vid,
            "detail": "Voucher revoked by authority - fail-closed, confers nothing",
        })
    return trail


def verify_voucher(
    payload: dict,
    *,
    now_ms: Optional[int] = None,
    secret: Optional[bytes] = None,
    expected_client_id: Optional[str] = None,
) -> dict:
    """Verify a signed voucher. Fail-closed: any problem yields ``valid=False``.

    Returns a dict with ``valid``, ``status`` (active/expired/revoked/invalid),
    ``reasons``, the bound identifiers, and a redemption ``audit_trail``.
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
        result["audit_trail"] = redemption_audit_trail(payload, "invalid", now)
        return result

    # 2. Signature must match (constant-time compare). Any tamper fails closed.
    expected_sig = sign_payload(payload, secret)
    if not hmac.compare_digest(str(payload.get("voucher_signature")), expected_sig):
        result["reasons"] = ["BAD_SIGNATURE"]
        result["audit_trail"] = redemption_audit_trail(payload, "invalid", now)
        return result

    # 3. Ownership binding: the presented holder must match the bound client.
    if expected_client_id not in (None, "") and str(expected_client_id) != str(payload.get("client_id")):
        result["reasons"] = ["OWNERSHIP_MISMATCH"]
        result["audit_trail"] = redemption_audit_trail(payload, "invalid", now)
        return result

    # 4. Expiration engine (active / expired / revoked).
    status = voucher_status(payload, now)
    result["status"] = status
    if status == "revoked":
        result["reasons"] = ["VOUCHER_REVOKED"]
    elif status == "expired":
        result["reasons"] = ["VOUCHER_EXPIRED"]
    else:
        result["valid"] = True
        result["reasons"] = ["VOUCHER_ACTIVE"]
    result["audit_trail"] = redemption_audit_trail(payload, status, now)
    return result
