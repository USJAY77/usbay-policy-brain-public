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
    "redeem_preview",
    "REDEEM_PREVIEW_NOTE",
    "redemption_audit_trail",
    "RevocationRegistry",
    "APPROVAL_BIND_FIELDS",
    "APPROVAL_REASON_CODES",
    "approval_subject",
    "sign_approval",
    "make_approval_evidence",
    "verify_approval_evidence",
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


# --------------------------------------------------------------------------- #
# Governance approval-chain evidence (PB-TRAVEL-005)
# --------------------------------------------------------------------------- #
# An approval attestation records that a named governance approver authorized a
# voucher lifecycle event. It is *evidence only* and confers no monetary or
# reward value. The attestation binds the voucher subject (voucher_id, a
# non-reversible client_ref, partner_id, issued_at, expires_at, revoked_at) plus
# the approver, a simulated approval timestamp, and an approval expiry, then is
# signed with the server-side secret (HMAC-SHA256, domain-separated from the
# voucher signature). Verification fails closed on any missing, malformed,
# mismatched, expired, or bad-timestamp evidence.
APPROVAL_DOMAIN = "usbay-governance-approval-evidence-v1"
APPROVAL_BIND_FIELDS = (
    "voucher_id",
    "client_ref",
    "partner_id",
    "issued_at",
    "expires_at",
    "revoked_at",
)
DEFAULT_APPROVAL_TTL_MS = 30 * 86400000
_DEFAULT_APPROVER = "USBAY-GOVERNANCE"

# Fail-closed approval reason codes.
APPROVAL_MISSING = "APPROVAL_MISSING"
APPROVAL_INVALID = "APPROVAL_INVALID"
APPROVAL_SUBJECT_MISMATCH = "APPROVAL_SUBJECT_MISMATCH"
APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
TIMESTAMP_MISSING = "TIMESTAMP_MISSING"
TIMESTAMP_INVALID = "TIMESTAMP_INVALID"
APPROVAL_REASON_CODES = (
    APPROVAL_MISSING,
    APPROVAL_INVALID,
    APPROVAL_SUBJECT_MISMATCH,
    APPROVAL_EXPIRED,
    TIMESTAMP_MISSING,
    TIMESTAMP_INVALID,
)


def approval_subject(payload: dict) -> dict:
    """The fields an approval attestation binds. Uses a non-reversible
    ``client_ref`` only, never the raw client id."""
    return {
        "voucher_id": _norm(payload.get("voucher_id")),
        "client_ref": client_ref(payload.get("client_id")),
        "partner_id": _norm(payload.get("partner_id")),
        "issued_at": _norm(payload.get("issued_at")),
        "expires_at": _norm(payload.get("expires_at")),
        "revoked_at": _norm(payload.get("revoked_at")),
    }


def _approval_canonical(evidence: dict) -> str:
    subj = evidence.get("subject") or {}
    parts = [APPROVAL_DOMAIN]
    parts.extend("%s=%s" % (f, _norm(subj.get(f))) for f in APPROVAL_BIND_FIELDS)
    parts.append("approver=%s" % _norm(evidence.get("approver")))
    parts.append("approved_at=%s" % _norm(evidence.get("approved_at")))
    parts.append("approval_expires_at=%s" % _norm(evidence.get("approval_expires_at")))
    return "\n".join(parts)


def sign_approval(evidence: dict, secret: Optional[bytes] = None) -> str:
    """HMAC-SHA256 over the (domain-separated) approval attestation."""
    key = secret or voucher_secret()
    msg = _approval_canonical(evidence).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def make_approval_evidence(
    payload: dict,
    *,
    approver: str = _DEFAULT_APPROVER,
    approved_at: Optional[int] = None,
    approval_ttl_ms: int = DEFAULT_APPROVAL_TTL_MS,
    approval_expires_at: Optional[int] = None,
    secret: Optional[bytes] = None,
) -> dict:
    """Build a signed governance approval attestation for ``payload``. Evidence
    only -- it confers no monetary or reward value (mirrors the voucher's
    non-monetary contract markers)."""
    now = int(time.time() * 1000)
    approved = int(approved_at) if approved_at is not None else now
    if approval_expires_at is not None:
        expires = int(approval_expires_at)
    else:
        expires = approved + int(approval_ttl_ms)
    evidence = {
        "approver": str(approver),
        "approved_at": approved,
        "approval_expires_at": expires,
        "subject": approval_subject(payload),
        "evidence_kind": "governance_approval",
        "confers_value": "none",
    }
    evidence["approval_signature"] = sign_approval(evidence, secret)
    return evidence


def verify_approval_evidence(
    payload: dict,
    evidence: "Optional[dict]",
    *,
    now_ms: Optional[int] = None,
    secret: Optional[bytes] = None,
    bind_fields=APPROVAL_BIND_FIELDS,
) -> Optional[str]:
    """Validate a governance approval attestation against ``payload``.

    Returns ``None`` when the evidence is valid, otherwise a fail-closed reason
    code. Checks, in order: presence, the simulated approval timestamp,
    structural completeness, subject binding (only ``bind_fields`` are
    cross-checked so a partial caller -- e.g. the revoke endpoint, which only
    knows voucher_id + client_id -- can still validate the authentic, self-signed
    subject), signature integrity (constant-time), then the approval window.
    """
    now = int(now_ms) if now_ms is not None else int(time.time() * 1000)
    if not evidence or not isinstance(evidence, dict):
        return APPROVAL_MISSING
    # Simulated approval timestamp (the issuance / revocation evidence time).
    approved_raw = evidence.get("approved_at")
    if approved_raw in (None, ""):
        return TIMESTAMP_MISSING
    try:
        int(approved_raw)
    except (TypeError, ValueError):
        return TIMESTAMP_INVALID
    expires_raw = evidence.get("approval_expires_at")
    if expires_raw in (None, ""):
        return APPROVAL_INVALID
    try:
        approval_expires_at = int(expires_raw)
    except (TypeError, ValueError):
        return TIMESTAMP_INVALID
    # Structural completeness.
    subject = evidence.get("subject")
    if (
        not evidence.get("approver")
        or not evidence.get("approval_signature")
        or not isinstance(subject, dict)
    ):
        return APPROVAL_INVALID
    # Subject binding (only the requested fields are cross-checked).
    expected = approval_subject(payload)
    for f in bind_fields:
        if _norm(subject.get(f)) != _norm(expected.get(f)):
            return APPROVAL_SUBJECT_MISMATCH
    # Signature integrity (any tamper fails closed), constant-time compare.
    expected_sig = sign_approval(evidence, secret)
    if not hmac.compare_digest(str(evidence.get("approval_signature")), expected_sig):
        return APPROVAL_INVALID
    # Approval validity window.
    if now >= approval_expires_at:
        return APPROVAL_EXPIRED
    return None


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
    with_approval: bool = True,
    approver: str = _DEFAULT_APPROVER,
    approved_at: Optional[int] = None,
    approval_ttl_ms: int = DEFAULT_APPROVAL_TTL_MS,
    approval_expires_at: Optional[int] = None,
) -> dict:
    """Issue a signed, non-monetary voucher (epoch-ms timestamps).

    The voucher is bound to ``client_id`` (ownership) and ``partner_id``. The
    returned object carries a ``voucher_signature`` plus explicit non-monetary
    contract markers. Unless ``with_approval`` is ``False`` it also carries a
    governance ``approval_evidence`` attestation (evidence only, no value).
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
    if with_approval:
        # Governance approval-chain evidence (evidence only; confers no value).
        payload["approval_evidence"] = make_approval_evidence(
            payload,
            approver=approver,
            approved_at=approved_at if approved_at is not None else issued,
            approval_ttl_ms=approval_ttl_ms,
            approval_expires_at=approval_expires_at,
            secret=secret,
        )
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
    approval: Optional[dict] = None,
) -> list:
    """Build the redemption audit trail: issued / viewed / verified plus, by
    status, expired / revoked / revoke_failed, and (when approval is enforced) an
    approved / approval_failed governance row. Read-only and illustrative; every
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
    if approval is not None:
        if approval.get("ok"):
            trail.append(_audit_row(
                "approved", approval.get("at"), payload, status, "APPROVAL_OK",
                "Governance approval evidence verified (evidence only, no value)",
            ))
        else:
            trail.append(_audit_row(
                "approval_failed", now_ms, payload, "invalid",
                approval.get("reason"),
                "Governance approval evidence rejected - fail-closed, confers nothing",
            ))
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
    enforce_approval: bool = False,
    approval: Optional[dict] = None,
) -> dict:
    """Verify a signed voucher. Fail-closed: any problem yields ``valid=False``.

    Checks, in order: required fields + signature presence, signature integrity
    (constant-time), ownership binding, governance approval evidence (when
    ``enforce_approval`` is set), the central revocation registry (if one is
    supplied), then the expiration engine. If ``registry`` is supplied and
    cannot be consulted (unavailable / tampered data), verification fails closed
    with ``REVOCATION_REGISTRY_UNAVAILABLE``.

    When ``enforce_approval`` is set the voucher must carry a valid governance
    approval attestation -- supplied via ``approval`` or, when omitted, read from
    ``payload["approval_evidence"]``. Missing, malformed, mismatched, expired, or
    bad-timestamp evidence fails closed with the matching ``APPROVAL_*`` /
    ``TIMESTAMP_*`` reason code. Approval is left disabled by default so callers
    that only exercise the signing/revocation layers stay backward-compatible.

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

    # 3b. Governance approval evidence (approval chain). When enforced the
    # voucher must carry a valid, subject-bound, non-expired attestation or
    # verification fails closed with the matching reason code.
    approval_ctx = None
    if enforce_approval:
        evidence = approval if approval is not None else payload.get("approval_evidence")
        areason = verify_approval_evidence(payload, evidence, now_ms=now, secret=secret)
        if areason:
            result["status"] = "invalid"
            result["reasons"] = [areason]
            result["audit_trail"] = redemption_audit_trail(
                payload, "invalid", now, reason_code=areason,
                approval={"ok": False, "reason": areason})
            return result
        approval_ctx = {
            "ok": True,
            "approver": evidence.get("approver"),
            "at": evidence.get("approved_at"),
        }
        result["approval"] = {
            "status": "approved",
            "approver": evidence.get("approver"),
            "approved_at": evidence.get("approved_at"),
            "approval_expires_at": evidence.get("approval_expires_at"),
        }

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
        registry_record=registry_record, approval=approval_ctx)
    return result


# --------------------------------------------------------------------------- #
# PB-SIM-TRAVEL-006 -- preview-only, partner-side redemption (non-binding)
# --------------------------------------------------------------------------- #
REDEEM_PREVIEW_NOTE = (
    "Partner-side redemption preview only -- non-binding. Confers no money, "
    "creates no booking, no balance, and no redemption record; any real "
    "discount is partner-funded and validated outside USBAY."
)


def redeem_preview(
    payload: dict,
    *,
    action: str = "redeem",
    now_ms: Optional[int] = None,
    secret: Optional[bytes] = None,
    expected_client_id: Optional[str] = None,
    registry: "Optional[RevocationRegistry]" = None,
    enforce_approval: bool = True,
    approval: Optional[dict] = None,
) -> dict:
    """Preview-only, partner-side redemption check (PB-SIM-TRAVEL-006).

    Reuses :func:`verify_voucher` as the single source of truth: a voucher is
    only ever ``redeemable`` when verification fully succeeds. Every blocked
    state -- revoked, expired, wrong-owner, missing/invalid approval, tampered
    signature, missing fields, or an unavailable revocation registry -- can
    never become eligible here.

    This is strictly read-only: it NEVER records a redemption, moves value,
    creates a booking or a balance, or calls a partner API. It only reports
    whether a partner *could* honour the voucher. Only a non-reversible
    ``client_ref`` is returned; the raw client id is never echoed or logged.

    ``action`` selects the audit-event vocabulary: ``"preview"`` emits
    ``preview`` / ``preview_blocked`` rows, ``"redeem"`` (default) emits
    ``redeem_preview`` / ``redeem_blocked`` rows.

    Governance approval is enforced by default for the redemption surface, so a
    voucher with missing or invalid approval evidence can never be redeemable.
    """
    now = int(now_ms) if now_ms is not None else int(time.time() * 1000)
    act = "preview" if str(action) == "preview" else "redeem"
    verification = verify_voucher(
        payload,
        now_ms=now,
        secret=secret,
        expected_client_id=expected_client_id,
        registry=registry,
        enforce_approval=enforce_approval,
        approval=approval,
    )
    eligible = bool(verification.get("valid"))
    if act == "preview":
        event = "preview" if eligible else "preview_blocked"
        detail = (
            "Non-binding voucher preview -- eligible (preview only, confers nothing)"
            if eligible else
            "Non-binding voucher preview -- blocked, fail-closed, confers nothing"
        )
    else:
        event = "redeem_preview" if eligible else "redeem_blocked"
        detail = (
            "Partner-side redemption preview -- redeemable (preview only, confers nothing)"
            if eligible else
            "Partner-side redemption preview -- blocked, fail-closed, confers nothing"
        )
    reason_code = ";".join(verification.get("reasons") or []) or None
    trail = list(verification.get("audit_trail") or [])
    trail.append(_audit_row(
        event, now, payload, verification.get("status"), reason_code, detail))
    out = {
        "ok": True,
        "action": act,
        "preview_only": True,
        "partner_side": True,
        "redeemable": eligible,
        "valid": eligible,
        "redeem_state": "redeemable_preview" if eligible else "blocked",
        "status": verification.get("status"),
        "reasons": verification.get("reasons"),
        "voucher_id": payload.get("voucher_id"),
        "partner_id": payload.get("partner_id"),
        "client_ref": client_ref(payload.get("client_id")),
        "confers_value": "none",
        "note": REDEEM_PREVIEW_NOTE,
        "checked_at": now,
        "audit_trail": trail,
    }
    if verification.get("revocation"):
        out["revocation"] = verification["revocation"]
    if verification.get("approval"):
        out["approval"] = verification["approval"]
    return out


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
