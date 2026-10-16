from __future__ import annotations

import hmac
import json
import math
import re
import secrets
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from governance.durable_authority_registries import (
    ACTIVE_STATUSES,
    IDENTITY,
    VALID,
    AuthorityRegistryError,
    DurableAuthorityRegistry,
)
from governance.hashing import is_sha256_reference, sha256_reference
from security.request_signing import (
    RequestSignatureError,
    VerifiedRequestKey,
    request_signature_message,
    verify_request_signature_identity,
)


CONTRACT_VERSION = "usbay.gateway.request_identity.v1"
CANONICALIZATION = "usbay.canonical_json.v1"
CALLER_IDENTITY_TYPE = "HTTP_REQUEST_CALLER"
MAX_CREDENTIAL_LIFETIME = timedelta(minutes=5)
MAX_CLOCK_SKEW = timedelta(seconds=30)
MAX_JSON_BYTES = 262_144
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 10_000
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
_CONTEXT_AUTHENTICATION_KEY = secrets.token_bytes(32)


class RequestIdentityError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class VerifiedRequestIdentity:
    contract_version: str
    identity_reference: str
    identity_record_hash: str
    identity_event_hash: str
    subject_reference: str
    issuer_id: str
    tenant_id: str
    actor_id: str
    tenant_reference: str
    environment_reference: str
    audience: str
    purpose: str
    environment: str
    caller_scope: str
    pubkey_id: str
    public_key_fingerprint: str
    key_config_fingerprint: str
    request_id: str
    correlation_id: str
    nonce_hash: str
    request_body_hash: str
    authenticated_request_digest: str
    valid_from: str
    valid_until: str
    _authentication_seal: str = field(repr=False, compare=False)
    execution_authorized: bool = False
    provider_authorized: bool = False
    deployment_authorized: bool = False
    activation_authorized: bool = False
    policy_authoring_authorized: bool = False

    def as_mapping(self) -> Mapping[str, Any]:
        return MappingProxyType(
            {
                item.name: getattr(self, item.name)
                for item in fields(self)
                if not item.name.startswith("_")
            }
        )


def parse_unique_json_object(raw: str | bytes | Mapping[str, Any], *, reason_code: str) -> dict[str, Any]:
    if isinstance(raw, Mapping):
        parsed = dict(raw)
        _validate_json_tree(parsed, reason_code=reason_code)
        try:
            encoded_size = len(
                json.dumps(parsed, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
            )
        except (TypeError, ValueError, RecursionError) as exc:
            raise RequestIdentityError(reason_code) from exc
        if encoded_size > MAX_JSON_BYTES:
            raise RequestIdentityError("REQUEST_IDENTITY_JSON_LIMIT_EXCEEDED")
        return parsed
    if not isinstance(raw, (str, bytes)):
        raise RequestIdentityError(reason_code)
    try:
        raw_size = len(raw.encode("utf-8")) if isinstance(raw, str) else len(raw)
    except UnicodeEncodeError as exc:
        raise RequestIdentityError(reason_code) from exc
    if raw_size > MAX_JSON_BYTES:
        raise RequestIdentityError("REQUEST_IDENTITY_JSON_LIMIT_EXCEEDED")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RequestIdentityError("REQUEST_IDENTITY_DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_constant=lambda _value: _raise_non_finite_json(),
        )
    except RequestIdentityError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RequestIdentityError(reason_code) from exc
    if not isinstance(parsed, dict):
        raise RequestIdentityError(reason_code)
    _validate_json_tree(parsed, reason_code=reason_code)
    return parsed


def authenticate_gateway_request(
    *,
    credential_json: str | bytes | Mapping[str, Any],
    request_body_json: str | bytes | Mapping[str, Any],
    method: str,
    path: str,
    expected_audience: str,
    expected_purpose: str,
    expected_environment: str,
    request_key_config_path: str | Path,
    authority_registry: DurableAuthorityRegistry,
    now: datetime | str | None = None,
) -> VerifiedRequestIdentity:
    """Authenticate one caller without reserving replay state or granting authority."""
    credential = parse_unique_json_object(credential_json, reason_code="REQUEST_IDENTITY_CREDENTIAL_MALFORMED")
    request_body = parse_unique_json_object(request_body_json, reason_code="REQUEST_IDENTITY_BODY_MALFORMED")
    comparison_time = _coerce_time(now)
    _validate_credential_shape(credential)
    _validate_request_binding(
        credential,
        request_body,
        method=method,
        path=path,
        audience=expected_audience,
        purpose=expected_purpose,
        environment=expected_environment,
        now=comparison_time,
    )
    verified_key = _verify_signature(credential, Path(request_key_config_path))
    record, resolution = _resolve_caller_record(authority_registry, credential, comparison_time)
    _validate_caller_record(record, credential, verified_key)
    _reject_ambiguous_mapping(authority_registry, record)
    _validate_client_identity_comparisons(request_body, str(record["tenant_id"]), str(record["actor_id"]))

    unsigned = request_signature_message(credential)
    authenticated_request_digest = sha256_reference(json.loads(unsigned))
    identity_values = {
        "contract_version": CONTRACT_VERSION,
        "identity_reference": str(credential["identity_reference"]),
        "identity_record_hash": str(resolution["record_hash"]),
        "identity_event_hash": str(resolution["event_hash"]),
        "subject_reference": str(credential["subject_reference"]),
        "issuer_id": str(credential["issuer_id"]),
        "tenant_id": str(record["tenant_id"]),
        "actor_id": str(record["actor_id"]),
        "tenant_reference": str(credential["tenant_reference"]),
        "environment_reference": str(credential["environment_reference"]),
        "audience": str(credential["audience"]),
        "purpose": str(credential["purpose"]),
        "environment": str(credential["environment"]),
        "caller_scope": sha256_reference(
            {
                "schema_version": "usbay.gateway.request_identity.caller_scope.v1",
                "issuer_id": record["issuer_id"],
                "subject_reference": record["subject_reference"],
            }
        ),
        "pubkey_id": verified_key.pubkey_id,
        "public_key_fingerprint": verified_key.public_key_fingerprint,
        "key_config_fingerprint": verified_key.key_config_fingerprint,
        "request_id": str(credential["request_id"]),
        "correlation_id": str(credential["correlation_id"]),
        "nonce_hash": sha256_reference({"nonce": credential["nonce"]}),
        "request_body_hash": str(credential["request_body_hash"]),
        "authenticated_request_digest": authenticated_request_digest,
        "valid_from": str(credential["valid_from"]),
        "valid_until": str(credential["valid_until"]),
        "execution_authorized": False,
        "provider_authorized": False,
        "deployment_authorized": False,
        "activation_authorized": False,
        "policy_authoring_authorized": False,
    }
    return _new_verified_request_identity(identity_values)


def revalidate_gateway_request_identity(
    context: VerifiedRequestIdentity,
    *,
    credential_json: str | bytes | Mapping[str, Any],
    request_body_json: str | bytes | Mapping[str, Any],
    method: str,
    path: str,
    request_key_config_path: str | Path,
    authority_registry: DurableAuthorityRegistry,
    now: datetime | str | None = None,
) -> VerifiedRequestIdentity:
    """Re-read key and identity authority state immediately before a later commit."""
    try:
        current = authenticate_gateway_request(
            credential_json=credential_json,
            request_body_json=request_body_json,
            method=method,
            path=path,
            expected_audience=context.audience,
            expected_purpose=context.purpose,
            expected_environment=context.environment,
            request_key_config_path=request_key_config_path,
            authority_registry=authority_registry,
            now=now,
        )
    except RequestIdentityError as exc:
        if exc.code in {
            "REQUEST_IDENTITY_KEY_UNAVAILABLE",
            "REQUEST_IDENTITY_ENROLLMENT_INVALID",
            "REQUEST_IDENTITY_ENROLLMENT_AMBIGUOUS",
            "REQUEST_IDENTITY_ENROLLMENT_BINDING_MISMATCH",
            "REQUEST_IDENTITY_REGISTRY_UNAVAILABLE",
        }:
            raise RequestIdentityError("REQUEST_IDENTITY_AUTHORITY_STATE_CHANGED") from exc
        raise
    if current != context:
        raise RequestIdentityError("REQUEST_IDENTITY_AUTHORITY_STATE_CHANGED")
    return current


def _validate_credential_shape(credential: Mapping[str, Any]) -> None:
    required = {
        "schema_version",
        "canonicalization",
        "identity_reference",
        "tenant_reference",
        "environment_reference",
        "subject_reference",
        "issuer_id",
        "audience",
        "purpose",
        "environment",
        "http_method",
        "request_path",
        "request_id",
        "correlation_id",
        "nonce",
        "valid_from",
        "valid_until",
        "request_body_hash",
        "signature_alg",
        "pubkey_id",
        "signature",
    }
    if set(credential) != required:
        raise RequestIdentityError("REQUEST_IDENTITY_CREDENTIAL_MALFORMED")
    if credential.get("schema_version") != CONTRACT_VERSION:
        raise RequestIdentityError("REQUEST_IDENTITY_SCHEMA_UNSUPPORTED")
    if credential.get("canonicalization") != CANONICALIZATION:
        raise RequestIdentityError("REQUEST_IDENTITY_CANONICALIZATION_UNSUPPORTED")
    for field in (
        "identity_reference",
        "tenant_reference",
        "environment_reference",
        "subject_reference",
        "request_body_hash",
    ):
        if not is_sha256_reference(credential.get(field)):
            raise RequestIdentityError("REQUEST_IDENTITY_CREDENTIAL_MALFORMED")
    for field in (
        "issuer_id",
        "audience",
        "purpose",
        "environment",
        "request_id",
        "correlation_id",
        "nonce",
        "pubkey_id",
    ):
        value = credential.get(field)
        if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
            raise RequestIdentityError("REQUEST_IDENTITY_CREDENTIAL_MALFORMED")
    if not isinstance(credential.get("signature"), str) or not credential["signature"]:
        raise RequestIdentityError("REQUEST_IDENTITY_CREDENTIAL_MALFORMED")


def _validate_request_binding(
    credential: Mapping[str, Any],
    request_body: Mapping[str, Any],
    *,
    method: str,
    path: str,
    audience: str,
    purpose: str,
    environment: str,
    now: datetime,
) -> None:
    if not isinstance(method, str) or credential.get("http_method") != method.upper():
        raise RequestIdentityError("REQUEST_IDENTITY_METHOD_MISMATCH")
    if not isinstance(path, str) or not path.startswith("/") or credential.get("request_path") != path:
        raise RequestIdentityError("REQUEST_IDENTITY_PATH_MISMATCH")
    for field, expected in (("audience", audience), ("purpose", purpose), ("environment", environment)):
        if not expected or credential.get(field) != expected:
            raise RequestIdentityError(f"REQUEST_IDENTITY_{field.upper()}_MISMATCH")
    if credential.get("request_body_hash") != sha256_reference(request_body):
        raise RequestIdentityError("REQUEST_IDENTITY_BODY_HASH_MISMATCH")
    valid_from = _parse_time(credential.get("valid_from"))
    valid_until = _parse_time(credential.get("valid_until"))
    if valid_from is None or valid_until is None or valid_until <= valid_from:
        raise RequestIdentityError("REQUEST_IDENTITY_VALIDITY_INVALID")
    if valid_until - valid_from > MAX_CREDENTIAL_LIFETIME:
        raise RequestIdentityError("REQUEST_IDENTITY_VALIDITY_TOO_LONG")
    if valid_from > now + MAX_CLOCK_SKEW:
        raise RequestIdentityError("REQUEST_IDENTITY_NOT_YET_VALID")
    if valid_until <= now:
        raise RequestIdentityError("REQUEST_IDENTITY_EXPIRED")


def _verify_signature(credential: dict[str, Any], config_path: Path) -> VerifiedRequestKey:
    try:
        return verify_request_signature_identity(credential, config_path)
    except RequestSignatureError as exc:
        code = (
            "REQUEST_IDENTITY_KEY_UNAVAILABLE"
            if str(exc)
            in {
                "unknown_pubkey_id",
                "request_key_config_invalid",
                "missing_request_signing_public_key",
                "request_public_key_invalid",
            }
            else "REQUEST_IDENTITY_SIGNATURE_INVALID"
        )
        raise RequestIdentityError(code) from exc


def _resolve_caller_record(
    registry: DurableAuthorityRegistry, credential: Mapping[str, Any], now: datetime
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        resolution = registry.resolve_identity(
            str(credential["identity_reference"]),
            tenant_reference=str(credential["tenant_reference"]),
            environment_reference=str(credential["environment_reference"]),
            subject_reference=str(credential["subject_reference"]),
            now=now,
        )
        records = registry.current_authority_records(IDENTITY)
    except (AuthorityRegistryError, OSError) as exc:
        raise RequestIdentityError("REQUEST_IDENTITY_REGISTRY_UNAVAILABLE") from exc
    if resolution.get("status") != VALID:
        raise RequestIdentityError("REQUEST_IDENTITY_ENROLLMENT_INVALID")
    matches = [record for record in records if record.get("authority_reference") == credential["identity_reference"]]
    if len(matches) != 1:
        raise RequestIdentityError("REQUEST_IDENTITY_ENROLLMENT_AMBIGUOUS")
    return matches[0], resolution


def _validate_caller_record(
    record: Mapping[str, Any], credential: Mapping[str, Any], verified_key: VerifiedRequestKey
) -> None:
    expected = {
        "identity_type": CALLER_IDENTITY_TYPE,
        "issuer_id": credential["issuer_id"],
        "subject_reference": credential["subject_reference"],
        "request_pubkey_id": verified_key.pubkey_id,
        "request_public_key_fingerprint": verified_key.public_key_fingerprint,
    }
    if any(record.get(field) != value for field, value in expected.items()):
        raise RequestIdentityError("REQUEST_IDENTITY_ENROLLMENT_BINDING_MISMATCH")
    for field in ("tenant_id", "actor_id"):
        if not isinstance(record.get(field), str) or not IDENTIFIER_RE.fullmatch(str(record[field])):
            raise RequestIdentityError("REQUEST_IDENTITY_ENROLLMENT_MALFORMED")
    for field, value in (
        ("audiences", credential["audience"]),
        ("purposes", credential["purpose"]),
        ("environments", credential["environment"]),
    ):
        allowed = record.get(field)
        if not isinstance(allowed, list) or not allowed or value not in allowed or not all(
            isinstance(item, str) and IDENTIFIER_RE.fullmatch(item) for item in allowed
        ):
            raise RequestIdentityError("REQUEST_IDENTITY_ENROLLMENT_BINDING_MISMATCH")


def _reject_ambiguous_mapping(registry: DurableAuthorityRegistry, selected: Mapping[str, Any]) -> None:
    try:
        records = registry.current_authority_records(IDENTITY)
    except (AuthorityRegistryError, OSError) as exc:
        raise RequestIdentityError("REQUEST_IDENTITY_REGISTRY_UNAVAILABLE") from exc
    active_matches = [
        record
        for record in records
        if str(record.get("current_status", "")).upper() in ACTIVE_STATUSES
        and record.get("revoked") is not True
        and record.get("identity_type") == CALLER_IDENTITY_TYPE
        and (
            (record.get("issuer_id"), record.get("subject_reference"))
            == (selected.get("issuer_id"), selected.get("subject_reference"))
            or record.get("request_pubkey_id") == selected.get("request_pubkey_id")
        )
    ]
    mappings = {
        (
            record.get("authority_reference"),
            record.get("tenant_id"),
            record.get("actor_id"),
        )
        for record in active_matches
    }
    if len(mappings) != 1:
        raise RequestIdentityError("REQUEST_IDENTITY_ENROLLMENT_AMBIGUOUS")


def _validate_client_identity_comparisons(body: Mapping[str, Any], tenant_id: str, actor_id: str) -> None:
    expected = {"tenant_id": tenant_id, "actor_id": actor_id}
    permitted_locations = {(), ("input_metadata",)}
    stack: list[tuple[Any, tuple[str, ...]]] = [(body, ())]
    while stack:
        value, location = stack.pop()
        if isinstance(value, Mapping):
            for key, item in value.items():
                if key in expected:
                    if location not in permitted_locations:
                        raise RequestIdentityError("REQUEST_IDENTITY_CLIENT_CLAIM_LOCATION_INVALID")
                    if item != expected[key]:
                        raise RequestIdentityError("REQUEST_IDENTITY_CLIENT_CLAIM_MISMATCH")
                stack.append((item, location + (str(key),)))
        elif isinstance(value, list):
            for item in value:
                stack.append((item, location + ("[]",)))

    metadata = body.get("input_metadata")
    if metadata is not None and not isinstance(metadata, Mapping):
        raise RequestIdentityError("REQUEST_IDENTITY_CLIENT_CLAIM_MALFORMED")


def is_authenticated_request_identity(value: object) -> bool:
    """Validate the module-private seal on a verifier-created identity context.

    Arbitrary code execution inside this Python process is outside this boundary.
    """
    if type(value) is not VerifiedRequestIdentity:
        return False
    context = value
    try:
        expected = _authentication_seal(_public_identity_values(context))
        return hmac.compare_digest(context._authentication_seal, expected)
    except (AttributeError, TypeError, ValueError):
        return False


def _new_verified_request_identity(values: Mapping[str, Any]) -> VerifiedRequestIdentity:
    public_values = dict(values)
    public_values["_authentication_seal"] = _authentication_seal(public_values)
    return VerifiedRequestIdentity(**public_values)


def _public_identity_values(context: VerifiedRequestIdentity) -> dict[str, Any]:
    return {
        item.name: getattr(context, item.name)
        for item in fields(context)
        if not item.name.startswith("_")
    }


def _authentication_seal(values: Mapping[str, Any]) -> str:
    payload = {
        item.name: values[item.name]
        for item in fields(VerifiedRequestIdentity)
        if not item.name.startswith("_")
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hmac.new(_CONTEXT_AUTHENTICATION_KEY, encoded, "sha256").hexdigest()


def _raise_non_finite_json() -> None:
    raise RequestIdentityError("REQUEST_IDENTITY_JSON_NON_FINITE")


def _validate_json_tree(value: Any, *, reason_code: str) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > MAX_JSON_DEPTH or nodes > MAX_JSON_NODES:
            raise RequestIdentityError("REQUEST_IDENTITY_JSON_LIMIT_EXCEEDED")
        if isinstance(item, float) and not math.isfinite(item):
            raise RequestIdentityError("REQUEST_IDENTITY_JSON_NON_FINITE")
        if item is None or isinstance(item, (str, bool, int, float)):
            continue
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise RequestIdentityError(reason_code)
                stack.append((child, depth + 1))
            continue
        if isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
            continue
        raise RequestIdentityError(reason_code)


def _coerce_time(value: datetime | str | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise RequestIdentityError("REQUEST_IDENTITY_TIME_INVALID")
        return value.astimezone(timezone.utc)
    parsed = _parse_time(value)
    if parsed is None:
        raise RequestIdentityError("REQUEST_IDENTITY_TIME_INVALID")
    return parsed


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or "T" not in value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


__all__ = [
    "CALLER_IDENTITY_TYPE",
    "CANONICALIZATION",
    "CONTRACT_VERSION",
    "RequestIdentityError",
    "VerifiedRequestIdentity",
    "authenticate_gateway_request",
    "is_authenticated_request_identity",
    "parse_unique_json_object",
    "revalidate_gateway_request_identity",
]
