"""Dormant, versioned release-chain inspection; no adoption, signer or writer.

ReleaseTrustContext is an independently provisioned composition input, never a
request field. Supplying keys proves correspondence only, not their provenance.
Even a completely matching chain returns DENY: a future protected writer must
authenticate current state again, fence CAS and durably consume the issuance.
This module reads no environment, files, registry or network, and changes none.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from security.runtime_artifact_provenance import canonical_bytes, public_key_id

DOMAIN = "USBAY_RELEASE_ISSUANCE_NONPRODUCTION_V1"
PROFILE = "usbay.release_review.owner_nonproduction.v1"
MAX_BYTES = 64 * 1024
SCOPE = frozenset({"tenant_id", "actor_id", "purpose", "environment", "target_id",
    "tool_id", "resource_type", "resource_id", "source_commit", "source_tree",
    "policy_bundle_hash", "release_core_hash", "predecessor_hash"})
COMMON = frozenset({"schema", "domain", "record_id", "issued_at", "valid_from", "valid_until"})
FIELDS = {
    "root": {"scope", "issuer_id", "issuer_key_id", "owner_id", "owner_key_id",
        "status_key_id", "review_profile", "review_threshold", "role_policy", "max_issuances",
        "redelegation_allowed"},
    "issuer": {"scope", "root_hash", "subject_id", "subject_key_id", "max_issuances",
        "redelegation_allowed"},
    "policy": {"root_hash", "owner_id", "owner_key_id", "profile", "threshold", "role_policy"},
    "request": {"scope", "root_hash", "issuer_grant_hash", "review_policy_hash",
        "issuer_id", "action", "nonce"},
    "review": {"request_hash", "review_policy_hash", "owner_id", "decision"},
    "status": {"root_hash", "issuer_grant_hash", "review_policy_hash", "request_hash",
        "review_hash", "challenge", "epoch", "sequence", "head_hash", "revocation_reference",
        "root_state", "issuer_state", "policy_state", "owner_state", "issuance_state"},
}


class ContractDenied(ValueError):
    """Only fixed reason codes leave this module."""


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise ContractDenied(code)


def _hash(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _is_hash(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _time(value: object) -> datetime:
    _need(type(value) is str and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value) is not None, "TIME_INVALID")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise ContractDenied("TIME_INVALID") from None


def _identifier(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}", value) is not None


def _scope(value: object) -> dict:
    _need(type(value) is dict and set(value) == SCOPE, "SCOPE_INVALID")
    _need(all(_identifier(value[k]) for k in SCOPE), "SCOPE_INVALID")
    _need(value["environment"] == "non-production", "ENVIRONMENT_DENIED")
    _need(value["purpose"] == "release_provenance"
          and value["resource_type"] == "GOVERNANCE_RELEASE", "PURPOSE_RESOURCE_DENIED")
    for k in ("source_commit", "source_tree"):
        _need(re.fullmatch(r"[0-9a-f]{40}", value[k]) is not None, "SOURCE_INVALID")
    for k in ("policy_bundle_hash", "release_core_hash", "predecessor_hash"):
        _need(_is_hash(value[k]), "RELEASE_BINDING_INVALID")
    return value


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _parse(raw: bytes) -> dict:
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "ENVELOPE_INVALID")
    def nonfinite(_):
        raise ContractDenied("NONFINITE_JSON")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                       parse_constant=nonfinite, parse_float=nonfinite)
    _need(type(value) is dict, "ENVELOPE_INVALID")
    return value


@dataclass(frozen=True)
class ReleaseIdentity:
    principal_id: str
    key_id: str
    public_key: bytes
    role: str
    tenant_id: str
    target_id: str
    valid_from: str
    valid_until: str
    provenance_reference: str


@dataclass(frozen=True)
class ReleaseTrustContext:
    """Trusted integration input. Never construct this from request JSON.

    Pins are necessary observations, not root adoption proof. A configured
    context cannot enable a writer; no registry/provider is installed here.
    """
    identities: tuple[ReleaseIdentity, ...]
    root_key_id: str
    root_hash: str
    issuer_grant_hash: str
    review_policy_hash: str
    tenant_id: str
    target_id: str
    status_hash: str
    challenge: str
    epoch: str
    sequence: int
    head_hash: str
    revocation_reference: str
    max_status_age_seconds: int


@dataclass(frozen=True)
class ReleaseContractInspection:
    decision: str = "DENY"
    reason: str = "RELEASE_AUTHORITY_UNAVAILABLE"
    bindings_valid: bool = False
    request_hash: str | None = None
    verification_valid_until: str | None = None
    issuance_authorized: bool = False
    consumption_confirmed: bool = False


def inspect_release_owner_contract(records: dict[str, bytes], *,
        trust: ReleaseTrustContext | None = None, now: datetime | None = None) -> ReleaseContractInspection:
    """Inspect a complete chain; return bounded evidence, never an ALLOW token.

    All record hashes bind the complete signed envelope. Root/policy/grant are
    independently pinned, avoiding circular root-to-policy hashes. The root
    commits review requirements; the pinned policy must match them exactly.
    """
    try:
        return _inspect(records, trust, now)
    except ContractDenied as error:
        return ReleaseContractInspection(reason=str(error))
    except Exception:
        return ReleaseContractInspection(reason="CONTRACT_INVALID")


def _inspect(records, trust, now):
    _need(type(trust) is ReleaseTrustContext, "RELEASE_AUTHORITY_UNAVAILABLE")
    _need(type(now) is datetime and now.tzinfo is timezone.utc, "CLOCK_INVALID")
    _need(type(records) is dict and set(records) == set(FIELDS), "CHAIN_INCOMPLETE")
    _need(type(trust.identities) is tuple and 4 <= len(trust.identities) <= 32, "TRUST_INVALID")
    _need(all(_is_hash(getattr(trust, k)) for k in ("root_hash", "issuer_grant_hash",
        "review_policy_hash", "status_hash", "head_hash", "revocation_reference")), "TRUST_INVALID")
    _need(_identifier(trust.tenant_id) and _identifier(trust.target_id)
        and _identifier(trust.challenge) and _identifier(trust.epoch), "TRUST_INVALID")
    _need(type(trust.sequence) is int and trust.sequence >= 0
        and type(trust.max_status_age_seconds) is int
        and 1 <= trust.max_status_age_seconds <= 60, "TRUST_INVALID")
    keys = {}
    for identity in trust.identities:
        _need(type(identity) is ReleaseIdentity and _identifier(identity.principal_id)
            and identity.role in {"root", "issuer", "owner", "status"}
            and identity.key_id == public_key_id(identity.public_key)
            and _is_hash(identity.provenance_reference), "IDENTITY_INVALID")
        _need(identity.key_id not in keys, "AMBIGUOUS_IDENTITY")
        _need(identity.tenant_id == trust.tenant_id and identity.target_id == trust.target_id,
              "IDENTITY_SCOPE_MISMATCH")
        _need(_time(identity.valid_from) <= now < _time(identity.valid_until), "IDENTITY_EXPIRED")
        keys[identity.key_id] = identity

    deadlines = []
    envelopes = {}

    def verify(kind, expected_key, role):
        env = _parse(records[kind])
        _need(set(env) == {"payload", "key_id", "signature"}, "ENVELOPE_INVALID")
        _need(env["key_id"] == expected_key and expected_key in keys, "SIGNER_INVALID")
        key = keys[expected_key]
        _need(key.role == role, "ROLE_MISMATCH")
        payload = env["payload"]
        _need(type(payload) is dict and set(payload) == COMMON | FIELDS[kind], "SCHEMA_INVALID")
        _need(payload["schema"] == "usbay.release_owner." + kind + ".v1"
              and payload["domain"] == DOMAIN, "DOMAIN_SCHEMA_MISMATCH")
        _need(_identifier(payload["record_id"]), "RECORD_ID_INVALID")
        start, issued, end = (_time(payload[k]) for k in ("valid_from", "issued_at", "valid_until"))
        _need(_time(key.valid_from) <= start <= issued <= now < end <= _time(key.valid_until),
              "RECORD_EXPIRED")
        encoded = env["signature"]
        _need(type(encoded) is str, "SIGNATURE_INVALID")
        signature = base64.b64decode(encoded, validate=True)
        _need(len(signature) == 64 and base64.b64encode(signature).decode("ascii") == encoded,
              "SIGNATURE_INVALID")
        try:
            Ed25519PublicKey.from_public_bytes(key.public_key).verify(signature, canonical_bytes(payload))
        except InvalidSignature:
            raise ContractDenied("SIGNATURE_INVALID") from None
        envelopes[kind] = env
        deadlines.append(end)
        return payload, key

    root, _ = verify("root", trust.root_key_id, "root")
    _need(_hash(envelopes["root"]) == trust.root_hash, "ROOT_PIN_MISMATCH")
    parent_scope = _scope(root["scope"])
    _need(parent_scope["tenant_id"] == trust.tenant_id
          and parent_scope["target_id"] == trust.target_id, "TENANT_TARGET_MISMATCH")
    _need(root["review_profile"] == PROFILE and type(root["review_threshold"]) is int
        and root["review_threshold"] == 1 and root["role_policy"] == "DISTINCT_ROLE_KEYS_V1",
        "ROOT_REVIEW_POLICY_DENIED")
    _need(type(root["max_issuances"]) is int and root["max_issuances"] == 1
        and root["redelegation_allowed"] is False, "ROOT_SCOPE_DENIED")
    role_keys = (trust.root_key_id, root["issuer_key_id"], root["owner_key_id"], root["status_key_id"])
    _need(all(type(k) is str and k in keys for k in role_keys)
          and len(set(role_keys)) == 4, "ROLE_KEY_SEPARATION_REQUIRED")
    _need(_identifier(root["issuer_id"]) and _identifier(root["owner_id"]), "IDENTITY_INVALID")

    issuer, _ = verify("issuer", trust.root_key_id, "root")
    policy, _ = verify("policy", trust.root_key_id, "root")
    _need(_hash(envelopes["issuer"]) == trust.issuer_grant_hash
          and _hash(envelopes["policy"]) == trust.review_policy_hash, "GRANT_POLICY_PIN_MISMATCH")
    _need(issuer["root_hash"] == policy["root_hash"] == trust.root_hash, "PARENT_BINDING_INVALID")
    _need(_scope(issuer["scope"]) == parent_scope, "CHILD_SCOPE_BROADENING")
    _need(issuer["subject_id"] == root["issuer_id"] == keys[root["issuer_key_id"]].principal_id
        and issuer["subject_key_id"] == root["issuer_key_id"], "ISSUER_BINDING_INVALID")
    _need(type(issuer["max_issuances"]) is int and issuer["max_issuances"] == 1
          and issuer["redelegation_allowed"] is False, "ISSUER_SCOPE_DENIED")
    _need(policy["profile"] == root["review_profile"] and type(policy["threshold"]) is int
        and policy["threshold"] == root["review_threshold"]
        and policy["role_policy"] == root["role_policy"], "REVIEW_POLICY_DOWNGRADE")
    _need(policy["owner_id"] == root["owner_id"] == keys[root["owner_key_id"]].principal_id
          and policy["owner_key_id"] == root["owner_key_id"], "OWNER_BINDING_INVALID")
    request, _ = verify("request", root["issuer_key_id"], "issuer")
    _need(_scope(request["scope"]) == issuer["scope"], "REQUEST_SCOPE_MISMATCH")
    _need(request["root_hash"] == trust.root_hash
        and request["issuer_grant_hash"] == trust.issuer_grant_hash
        and request["review_policy_hash"] == trust.review_policy_hash, "REQUEST_CHAIN_MISMATCH")
    _need(request["action"] == "ISSUE_RELEASE_MANIFEST" and request["issuer_id"] == issuer["subject_id"]
          and _identifier(request["nonce"]), "REQUEST_ACTION_INVALID")
    request_hash = _hash(envelopes["request"])
    review, _ = verify("review", root["owner_key_id"], "owner")
    _need(review["request_hash"] == request_hash
        and review["review_policy_hash"] == trust.review_policy_hash
        and review["owner_id"] == policy["owner_id"] and review["decision"] == "APPROVE",
        "OWNER_REVIEW_INVALID")
    status, _ = verify("status", root["status_key_id"], "status")
    _need(_hash(envelopes["status"]) == trust.status_hash, "STATUS_PIN_MISMATCH")
    expected = {"root_hash": trust.root_hash, "issuer_grant_hash": trust.issuer_grant_hash,
        "review_policy_hash": trust.review_policy_hash, "request_hash": request_hash,
        "review_hash": _hash(envelopes["review"]), "challenge": trust.challenge,
        "epoch": trust.epoch, "sequence": trust.sequence, "head_hash": trust.head_hash,
        "revocation_reference": trust.revocation_reference}
    _need(type(status["sequence"]) is int and all(status[k] == v for k, v in expected.items()),
          "CURRENTNESS_BINDING_INVALID")
    _need(0 <= (now - _time(status["issued_at"])).total_seconds() < trust.max_status_age_seconds,
          "STATUS_STALE")
    deadlines.append(_time(status["issued_at"]) + timedelta(seconds=trust.max_status_age_seconds))
    _need(all(status[k] == "ACTIVE" for k in ("root_state", "issuer_state", "policy_state", "owner_state")),
          "AUTHORITY_REVOKED")
    _need(status["issuance_state"] == "AVAILABLE", "ISSUANCE_REPLAY")
    # Every referenced authority edge carries a temporal constraint. The request
    # depends on both grant and policy; status attests the exact owner decision.
    for child, parent in ((issuer, root), (policy, root), (request, issuer),
                          (request, policy), (review, request), (status, review)):
        _need(_time(child["valid_from"]) >= _time(parent["valid_from"])
              and _time(child["issued_at"]) >= _time(parent["issued_at"])
              and _time(child["valid_until"]) <= _time(parent["valid_until"]), "VALIDITY_BROADENING")
    return ReleaseContractInspection(reason="RELEASE_WRITER_UNAVAILABLE", bindings_valid=True,
        request_hash=request_hash,
        verification_valid_until=min(deadlines).isoformat().replace("+00:00", "Z"))
