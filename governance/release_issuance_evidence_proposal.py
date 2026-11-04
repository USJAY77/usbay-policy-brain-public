"""Unadopted, read-only evidence inspection; never release authorization.

Supplied public keys establish only cryptographic correspondence. They do not
establish governed issuer/reviewer identity, parent authority or currentness.
Even valid evidence returns DENY. No runtime consumer imports this prototype.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from governance.tenant_enrollment_contracts import (
    EnrollmentDenied, canonical, digest, instant, parse_json, require, utc_now,
)

SCHEMA = "usbay.release_issuance_evidence.proposal.v1"
CONTEXT = (
    "tenant_id", "actor_id", "purpose", "environment", "tool_id", "resource_id",
    "issuer_id", "source_commit", "source_tree", "policy_bundle_hash",
    "release_core_hash", "predecessor_hash", "parent_authority_hash",
    "issuer_grant_hash", "review_policy_hash", "currentness_reference", "nonce",
)
KEY_SCOPE = ("tenant_id", "purpose", "environment", "tool_id", "resource_id")
FIELDS = {*CONTEXT, "schema_version", "action", "resource_type", "issuer_key_id",
          "issued_at", "valid_from", "valid_until", "redelegation_allowed"}
REVIEWERS = frozenset({"USBAY-AUDIT", "USBAY-GLOBAL23"})
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class EvidenceKey:
    """Caller-supplied key binding, NOT a trusted authority artifact."""

    key_id: str
    subject_id: str
    role: str
    scope: tuple[str, ...]
    public_key: bytes
    valid_from: str
    valid_until: str


@dataclass(frozen=True)
class EvidenceInspection:
    reason: str
    signed_bindings_valid: bool = False
    evidence_reference: str | None = None
    outcome: str = field(default="DENY", init=False)
    issuance_authorized: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    deployment_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    human_identity_verified: bool = field(default=False, init=False)
    parent_currentness_verified: bool = field(default=False, init=False)
    replay_consumed: bool = field(default=False, init=False)


def _signature(value, payload, key):
    require(type(value) is str and bool(re.fullmatch(r"[0-9a-f]{128}", value)),
            "RELEASE_SIGNATURE_INVALID")
    try:
        Ed25519PublicKey.from_public_bytes(key.public_key).verify(
            bytes.fromhex(value), canonical(payload),
        )
    except Exception:
        raise EnrollmentDenied("RELEASE_SIGNATURE_INVALID") from None


def _key(keys, key_id, subject, role, payload, now):
    require(type(keys) is tuple and all(type(k) is EvidenceKey for k in keys),
            "RELEASE_KEY_BINDING_INVALID")
    require(len({k.key_id for k in keys}) == len(keys), "RELEASE_KEY_BINDING_INVALID")
    found = [k for k in keys if k.key_id == key_id]
    require(len(found) == 1, "RELEASE_KEY_BINDING_MISSING")
    key = found[0]
    require(key.subject_id == subject and key.role == role
            and type(key.scope) is tuple
            and key.scope == tuple(payload[n] for n in KEY_SCOPE)
            and type(key.public_key) is bytes and len(key.public_key) == 32,
            "RELEASE_KEY_BINDING_INVALID")
    require(instant(key.valid_from) <= instant(payload["valid_from"])
            and instant(payload["valid_until"]) <= instant(key.valid_until)
            and instant(key.valid_from) <= now < instant(key.valid_until),
            "RELEASE_KEY_INTERVAL_INVALID")
    return key


def inspect_release_issuance_evidence(raw, *, expected, keys=(), now=None,
                                    max_age_seconds=60):
    """Inspect bounded proposed evidence, without resolving/creating authority.

    expected and keys must be supplied separately from the untrusted evidence.
    This function has no I/O, registry, signing, replay-store or writer access.
    Its positive data result is deliberately still a DENY outcome.
    """
    try:
        require(type(raw) in (str, bytes), "RELEASE_EVIDENCE_INVALID")
        encoded = raw.encode("utf-8") if type(raw) is str else raw
        require(0 < len(encoded) <= 65536, "RELEASE_EVIDENCE_SIZE_INVALID")
        data = parse_json(encoded)
        canonical(data)
        require(type(data) is dict and set(data) == {"request", "reviews"},
                "RELEASE_EVIDENCE_INVALID")
        envelope = data["request"]
        require(type(envelope) is dict and set(envelope) == {"payload", "signature"},
                "RELEASE_EVIDENCE_INVALID")
        p = envelope["payload"]
        require(type(p) is dict and set(p) == FIELDS, "RELEASE_CONTRACT_INVALID")
        require(type(expected) is dict and set(expected) == set(CONTEXT),
                "RELEASE_EXPECTED_CONTEXT_INVALID")
        require(all(type(v) is str for v in expected.values()), "RELEASE_EXPECTED_CONTEXT_INVALID")
        require(p["schema_version"] == SCHEMA and p["action"] == "ISSUE_RELEASE_MANIFEST"
                and p["resource_type"] == "GOVERNANCE_RELEASE"
                and p["environment"] == "non-production"
                and p["purpose"] == "release_provenance"
                and p["redelegation_allowed"] is False, "RELEASE_SCOPE_INVALID")
        for name, value in p.items():
            if name == "redelegation_allowed":
                continue
            require(type(value) is str and 0 < len(value) <= 256
                    and not any(c in value for c in "*?[]")
                    and all(ord(c) >= 32 for c in value), "RELEASE_CONTRACT_INVALID")
        require(all(p[n] == expected[n] for n in CONTEXT), "RELEASE_BINDING_MISMATCH")
        for name in ("source_commit", "source_tree"):
            require(bool(re.fullmatch(r"[0-9a-f]{40}", p[name])), "RELEASE_CONTRACT_INVALID")
        for name in ("policy_bundle_hash", "release_core_hash", "predecessor_hash",
                     "parent_authority_hash", "issuer_grant_hash", "review_policy_hash",
                     "currentness_reference", "resource_id"):
            require(bool(HASH.fullmatch(p[name])), "RELEASE_CONTRACT_INVALID")
        require(p["resource_id"] == p["release_core_hash"] and bool(HEX64.fullmatch(p["nonce"])),
                "RELEASE_BINDING_MISMATCH")
        require(type(max_age_seconds) is int and max_age_seconds > 0,
                "RELEASE_TIME_INVALID")
        now = utc_now() if now is None else now
        require(type(now) is datetime and now.tzinfo is not None
                and now.utcoffset() is not None, "RELEASE_TIME_INVALID")
        start, end, issued = (instant(p[n]) for n in ("valid_from", "valid_until", "issued_at"))
        require(start <= issued <= now < end
                and 0 <= (now - issued).total_seconds() <= max_age_seconds,
                "RELEASE_TIME_INVALID")
        issuer = _key(keys, p["issuer_key_id"], p["issuer_id"], "release_issuer", p, now)
        _signature(envelope["signature"], p, issuer)
        reviews = data["reviews"]
        require(type(reviews) is list and len(reviews) == 2, "RELEASE_REVIEW_INVALID")
        seen, review_keys = set(), []
        for review in reviews:
            require(type(review) is dict
                    and set(review) == {"reviewer_id", "key_id", "decision", "request_hash", "signature"},
                    "RELEASE_REVIEW_INVALID")
            reviewer = review["reviewer_id"]
            require(type(reviewer) is str and reviewer in REVIEWERS and reviewer not in seen,
                    "RELEASE_REVIEW_INVALID")
            require(review["decision"] == "APPROVE"
                    and review["request_hash"] == digest(envelope), "RELEASE_REVIEW_INVALID")
            key = _key(keys, review["key_id"], reviewer, "review:" + reviewer, p, now)
            require(reviewer not in {p["issuer_id"], p["actor_id"]}, "RELEASE_REVIEW_INVALID")
            _signature(review["signature"], {n: v for n, v in review.items() if n != "signature"}, key)
            seen.add(reviewer)
            review_keys.append(key)
        participants = [issuer, *review_keys]
        require(len({k.key_id for k in participants}) == 3
                and len({k.public_key for k in participants}) == 3, "RELEASE_REVIEW_NOT_INDEPENDENT")
        return EvidenceInspection("LIVE_ISSUANCE_AUTHORITY_NOT_ESTABLISHED", True, digest(data))
    except EnrollmentDenied as error:
        return EvidenceInspection(str(error))
    except (ValueError, TypeError, UnicodeError, RecursionError, AttributeError, KeyError):
        return EvidenceInspection("RELEASE_EVIDENCE_INVALID")
