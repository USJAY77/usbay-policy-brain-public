"""Closed dormant enrollment contracts. No signer, provisioning or bootstrap API.

These schemas are a new wire contract, not an interpretation of legacy grants.
Hashes identify bytes; only the scoped verifier can establish their authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, ClassVar

TRUST_DOMAIN = "usbay.tenant_enrollment_non_production.policy_governance.v1"
SCHEMA_VERSION = 3
POLICY_DOMAIN = "tenant_enrollment_non_production"
PURPOSE = "USBAY_GOVERNED_MAIL_BOUNDED_PROVIDER_VERIFICATION"
ENROLL = "REGISTER_NON_PRODUCTION_TENANT"
ADOPT = "ADOPT_NON_PRODUCTION_TENANT_ENROLLMENT_POLICY"
ADVANCE = "ADVANCE_ENROLLMENT_POLICY_HEAD"
FLAGS = tuple(x + "_authorized" for x in (
    "execution", "mail_execution", "mailbox_access", "provider", "oauth",
    "credential_access", "policy_widening", "production", "deployment",
    "activation", "policy_authoring", "recovery", "remote_transport", "redelegation",
))
FORBIDDEN = ["SEND_EMAIL", "READ_EMAIL", "MAILBOX_ACCESS", "PROVIDER_AUTHENTICATION",
             "OAUTH", "CREDENTIAL_ACCESS", "PROVIDER_EXECUTION", "RECOVERY_EXECUTION",
             "POLICY_WIDENING", "PRODUCTION_TENANT_CREATION", "DEPLOYMENT", "ACTIVATION",
             "RE_DELEGATION", "REMOTE_TRANSPORT_AUTHORITY"]


class EnrollmentDenied(ValueError):
    """Bounded reason only: never include supplied payloads in errors."""


def require(condition: bool, reason: str = "ENROLLMENT_BINDING_INVALID") -> None:
    if not condition:
        raise EnrollmentDenied(reason)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def parse_json(raw: str | bytes) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(EnrollmentDenied("NONFINITE_JSON")))
    except (ValueError, TypeError, UnicodeError):
        raise EnrollmentDenied("INVALID_JSON") from None


def canonical(value: Any) -> bytes:
    def check(v):
        require(type(v) in (dict, list, str, int, bool, type(None)), "JSON_TYPE_INVALID")
        if type(v) is dict:
            require(all(type(k) is str for k in v), "JSON_KEY_INVALID")
            for item in v.values():
                check(item)
        elif type(v) is list:
            for item in v:
                check(item)
    check(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeError):
        raise EnrollmentDenied("INVALID_JSON") from None


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def instant(value: str) -> datetime:
    require(type(value) is str and bool(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z", value)), "TIME_INVALID")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise EnrollmentDenied("TIME_INVALID") from None


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def scope(value: dict) -> tuple:
    return tuple(value[k] for k in SCOPE_FIELDS)


SCOPE_FIELDS = ("trust_domain", "policy_domain", "tenant_id", "environment", "purpose", "registry_instance_reference")

# Derived solely from existing signed identity/scope fields. Version hashes,
# currentness/revocation snapshots, timestamps and runtime state are deliberately
# excluded. Same issuer rotating keys does not evade an object revocation.
OBJECT_ID_FIELDS = {
    "policy": ("policy_id", "allowed_action"),
    "grant": ("grant_id", "registrar_actor", "request_id", "action"),
    "adoption": ("grant_id", "adopter_actor", "policy_id", "action"),
    "advance": ("grant_id", "advance_actor", "policy_id", "action"),
}
REVOCATION_KINDS = {
    "POLICY_OBJECT_REVOCATION": "policy",
    "GRANT_OBJECT_REVOCATION": "grant",
    "ADOPTION_REVOCATION": "adoption",
    "HEAD_ADVANCE_OBJECT_REVOCATION": "advance",
    "KEY_REVOCATION": "key",
}


COMMON = {"schema_version", "trust_domain", "policy_domain", "tenant_id", "environment",
          "purpose", "registry_instance_reference", "authority_flags", "delegation_allowed"}
SIGNED = {"issuer_id", "issuer_key_id", "algorithm", "issued_at", "valid_from", "expires_at"}
POLICY = {"policy_id", "policy_version", "policy_hash"}
HEAD = {"head_hash", "sequence", "generation", "epoch", "lineage_hash"}
FIELDS = {
    "grant": SIGNED | POLICY | {"domain", "action", "grant_id", "registrar_actor", "request_id",
        "enrollment_valid_until", "currentness_reference", "revocation_reference", "nonce",
        "replay_identity", "max_registrations", "forbidden_capabilities"},
    "policy": SIGNED | {"policy_id", "policy_version", "allowed_action", "registrar_constraints",
        "parent_policy_reference", "lineage_hash", "revocation_reference", "currentness_reference",
        "adoption_authority_reference"},
    "adoption": SIGNED | POLICY | {"action", "grant_id", "adopter_actor", "nonce", "replay_identity",
        "previous_head_hash", "sequence", "generation", "epoch", "lineage_hash", "max_adoptions",
        "approval_references"},
    "advance": SIGNED | POLICY | HEAD | {"action", "grant_id", "advance_actor", "nonce", "replay_identity",
        "previous_head_hash", "adoption_core_hash", "max_advances"},
    "witness": SIGNED | POLICY | HEAD | {"role", "previous_head_hash", "adoption_core_hash",
        "adoption_record_hash", "head_advance_grant_hash", "challenge", "request_digest",
        "revocation_reference", "anchor_hash"},
    "revocation": SIGNED | {"revocation_reference", "revocations", "sequence", "generation", "epoch"},
    "request": SIGNED | POLICY | {"action", "actor", "request_id", "nonce", "replay_identity",
        "method", "path", "grant_hash", "correlation_id"},
    "record": POLICY | {"record_id", "grant_hash", "request_digest", "currentness_reference",
        "revocation_reference", "nonce_reference", "previous_event_hash", "evidence_fingerprint",
        "created_at", "grant_valid_from", "grant_expires_at", "enrollment_valid_until",
        "issuer_id", "registrar_actor", "replay_identity", "registration_status", "tenant_exists", "allowed_actions"},
}


@dataclass(frozen=True)
class Contract:
    """Immutable canonical payload. Construction validates shape, not authority."""
    encoded: bytes
    kind: ClassVar[str]

    @classmethod
    def from_payload(cls, value: dict) -> "Contract":
        require(type(value) is dict and set(value) == COMMON | FIELDS[cls.kind], "SCHEMA_INVALID")
        canonical(value)
        require(value["schema_version"] == "usbay.enrollment." + cls.kind + ".v3", "SCHEMA_VERSION_INVALID")
        require(value["trust_domain"] == TRUST_DOMAIN and value["policy_domain"] == POLICY_DOMAIN, "DOMAIN_INVALID")
        require(value["environment"] == "non-production" and value["purpose"] == PURPOSE, "SCOPE_INVALID")
        require(type(value["tenant_id"]) is str and bool(re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", value["tenant_id"])), "TENANT_INVALID")
        require(type(value["authority_flags"]) is dict and set(value["authority_flags"]) == set(FLAGS)
                and all(x is False for x in value["authority_flags"].values()), "AUTHORITY_WIDENING")
        require(value["delegation_allowed"] is False, "REDELEGATION_DENIED")
        special = {"authority_flags", "delegation_allowed", "max_registrations", "max_adoptions", "max_advances",
                   "sequence", "generation", "epoch", "forbidden_capabilities", "registrar_constraints",
                   "approval_references", "revocations", "tenant_exists", "allowed_actions"}
        for key, item in value.items():
            if key in special:
                continue
            require(type(item) is str and 0 < len(item) <= 256 and "*" not in item, "FIELD_INVALID")
            if key.endswith("_hash") or key.endswith("_reference") or key in ("grant_hash", "request_digest", "adoption_core_hash", "adoption_record_hash", "head_advance_grant_hash", "evidence_fingerprint", "nonce_reference"):
                require(bool(re.fullmatch(r"sha256:[0-9a-f]{64}", item)), "HASH_INVALID")
            if key in ("issued_at", "valid_from", "expires_at", "created_at", "grant_valid_from", "grant_expires_at", "enrollment_valid_until"):
                instant(item)
        for key in ("sequence", "generation", "epoch"):
            if key in value:
                require(type(value[key]) is int and value[key] >= 1, "CONTINUITY_INVALID")
        if cls.kind != "record":
            require(value["algorithm"] == "Ed25519", "ALGORITHM_INVALID")
            require(instant(value["issued_at"]) <= instant(value["expires_at"])
                    and instant(value["valid_from"]) < instant(value["expires_at"]), "TIME_INVALID")
        if "action" in value or "allowed_action" in value:
            expected = {"adoption": ADOPT, "advance": ADVANCE}.get(cls.kind, ENROLL)
            require(value.get("action", value.get("allowed_action")) == expected, "ACTION_INVALID")
        for key in ("max_registrations", "max_adoptions", "max_advances"):
            if key in value:
                require(type(value[key]) is int and value[key] == 1, "LIMIT_INVALID")
        for key in ("registrar_constraints", "approval_references"):
            if key in value:
                items = value[key]
                require(type(items) is list and all(type(x) is str and x and "*" not in x for x in items), "LIST_INVALID")
                require(len(items) == len(set(items)), "LIST_INVALID")
                require(bool(items), "LIST_INVALID")
        if cls.kind == "revocation":
            require(type(value["revocations"]) is list, "REVOCATION_SCHEMA_INVALID")
            seen = set()
            for entry in value["revocations"]:
                require(type(entry) is dict and set(entry) == {"kind", "target_id", "target_scope", "coverage", "effective_at"}, "REVOCATION_SCHEMA_INVALID")
                require(entry["kind"] in REVOCATION_KINDS, "REVOCATION_KIND_INVALID")
                require(type(entry["target_id"]) is str and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", entry["target_id"])), "REVOCATION_ID_INVALID")
                require(type(entry["target_scope"]) is dict and set(entry["target_scope"]) == set(SCOPE_FIELDS)
                        and entry["target_scope"] == {k: value[k] for k in SCOPE_FIELDS}, "REVOCATION_TARGET_SCOPE_INVALID")
                required_coverage = "EXACT_KEY_ID" if entry["kind"] == "KEY_REVOCATION" else "ALL_VERSIONS_OF_OBJECT"
                require(entry["coverage"] == required_coverage, "REVOCATION_COVERAGE_INVALID")
                instant(entry["effective_at"])
                identity = (entry["kind"], entry["target_id"])
                require(identity not in seen, "REVOCATION_DUPLICATE")
                seen.add(identity)
        if cls.kind == "grant":
            require(value["domain"] == "USBAY_TENANT_ENROLLMENT" and value["forbidden_capabilities"] == FORBIDDEN, "AUTHORITY_WIDENING")
            require(instant(value["valid_from"]) < instant(value["enrollment_valid_until"]) <= instant(value["expires_at"]), "TIME_INVALID")
        if cls.kind == "witness":
            require(value["role"] in ("H", "W"), "WITNESS_ROLE_INVALID")
        if cls.kind == "record":
            require(value["tenant_exists"] is True and value["allowed_actions"] == [] and value["registration_status"] == "REGISTERED_NON_EXECUTING", "RECORD_INVALID")
        return cls(canonical(value))

    @property
    def payload(self) -> dict:
        return parse_json(self.encoded)


class EnrollmentGrant(Contract):
    kind = "grant"


class EnrollmentPolicy(Contract):
    kind = "policy"


class PolicyAdoption(Contract):
    kind = "adoption"


class HeadAdvance(Contract):
    kind = "advance"


class CurrentHeadWitness(Contract):
    kind = "witness"


class RevocationRecord(Contract):
    kind = "revocation"


class EnrollmentRequest(Contract):
    kind = "request"


class TenantRegistrationRecord(Contract):
    kind = "record"


def object_id(model: type[Contract], payload: dict) -> str:
    """Non-authorizing semantic ID, rederived after signature verification.

    v2 objects are rejected, never silently migrated or reinterpreted as v3.
    Revocation coverage is explicitly ALL_VERSIONS_OF_OBJECT for this ID only;
    a different scope/semantic identity needs its own signed revocation entry.
    """
    require(model.kind in OBJECT_ID_FIELDS, "OBJECT_ID_NOT_SUPPORTED")
    validated = model.from_payload(payload).payload
    fields = ("schema_version", "issuer_id", *SCOPE_FIELDS, *OBJECT_ID_FIELDS[model.kind])
    return digest({"identity_contract": "usbay.enrollment.object_identity.v1", "object_type": model.kind,
                   "identity": {k: validated[k] for k in fields}})


def object_version_hash(model: type[Contract], payload: dict) -> str:
    """Exact complete protected bytes, still bound by the original signature."""
    return digest(model.from_payload(payload).payload)


def key_id(payload: dict) -> str:
    """Called with already verified payloads; no public key or trust is created."""
    return digest({"identity_contract": "usbay.enrollment.scoped_key_identity.v1",
                   "identity": {k: payload[k] for k in (*SCOPE_FIELDS, "issuer_id", "issuer_key_id")}})


def check_revocation(snapshot: dict, payload: dict, model: type[Contract], now: datetime) -> None:
    """Separate exact-key and explicitly scoped all-version object revocation.
    Snapshot authority/currentness is the caller verifier's independent gate.
    """
    RevocationRecord.from_payload(snapshot)
    require(scope(snapshot) == scope(payload), "REVOCATION_TARGET_SCOPE_INVALID")
    identity = object_id(model, payload) if model.kind in OBJECT_ID_FIELDS else None
    for entry in snapshot["revocations"]:
        if instant(entry["effective_at"]) > now:
            continue
        if entry["kind"] == "KEY_REVOCATION" and entry["target_id"] == key_id(payload):
            raise EnrollmentDenied("KEY_REVOKED")
        if REVOCATION_KINDS[entry["kind"]] == model.kind and entry["target_id"] == identity:
            raise EnrollmentDenied(entry["kind"])


def decision(reason: str, *, allowed: bool = False, **facts) -> dict:
    return dict(decision="ALLOW" if allowed else "DENY", reason=reason,
                authority_flags=dict.fromkeys(FLAGS, False), retry_allowed=False, **facts)
