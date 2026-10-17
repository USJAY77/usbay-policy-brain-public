from __future__ import annotations

import json
import multiprocessing
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway.request_identity import (
    CANONICALIZATION,
    CONTRACT_VERSION,
    RequestIdentityError,
    authenticate_gateway_request,
    parse_unique_json_object,
    revalidate_gateway_request_identity,
)
from gateway.request_identity_replay_store import (
    CONFLICT,
    REPLAY,
    RESERVED,
    RequestIdentityReplayStore,
    RequestIdentityReplayStoreError,
)
from governance.durable_authority_registries import IDENTITY, DurableAuthorityRegistry
from governance.hashing import sha256_reference
from security.request_signing import sign_request_payload


pytestmark = pytest.mark.governance

NOW = "2026-10-16T12:00:00Z"
ISSUED = "2026-10-16T11:55:00Z"
EXPIRES = "2026-10-16T13:00:00Z"
VALID_FROM = "2026-10-16T11:59:00Z"
VALID_UNTIL = "2026-10-16T12:04:00Z"
TENANT_REFERENCE = "sha256:" + "1" * 64
ENVIRONMENT_REFERENCE = "sha256:" + "2" * 64
SUBJECT_REFERENCE = "sha256:" + "3" * 64
IDENTITY_REFERENCE = "sha256:" + "4" * 64
PROVENANCE_REFERENCE = "sha256:" + "5" * 64
PUBKEY_ID = "synthetic_gateway_caller_key"
ISSUER_ID = "usbay.synthetic.test-issuer"
AUDIENCE = "usbay.gateway"
PURPOSE = "live_policy_evaluation"
ENVIRONMENT = "test"
METHOD = "POST"
PATH = "/api/governance/live-policy/evaluate"


def _setup(tmp_path: Path) -> dict:
    tmp_path.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    public_path = tmp_path / "synthetic_request_public.key"
    public_path.write_bytes(public_raw)
    config_path = tmp_path / "request_signing_keys.json"
    config_path.write_text(
        json.dumps(
            {
                "active_keys": [PUBKEY_ID],
                "revoked_keys": [],
                "key_map": {PUBKEY_ID: str(public_path)},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    fingerprint = "sha256:" + __import__("hashlib").sha256(public_raw).hexdigest()
    registry = DurableAuthorityRegistry(
        tmp_path / "caller-authority.jsonl",
        evidence_path=tmp_path / "caller-authority.evidence.jsonl",
    )
    record = {
        "authority_reference": IDENTITY_REFERENCE,
        "tenant_reference": TENANT_REFERENCE,
        "environment_reference": ENVIRONMENT_REFERENCE,
        "subject_reference": SUBJECT_REFERENCE,
        "issued_at": ISSUED,
        "effective_at": ISSUED,
        "expires_at": EXPIRES,
        "revoked": False,
        "current_status": "ENROLLED",
        "provenance_evidence_reference": PROVENANCE_REFERENCE,
        "identity_type": "HTTP_REQUEST_CALLER",
        "issuer_id": ISSUER_ID,
        "request_pubkey_id": PUBKEY_ID,
        "request_public_key_fingerprint": fingerprint,
        "tenant_id": "t1",
        "actor_id": "synthetic-reviewer",
        "audiences": [AUDIENCE],
        "purposes": [PURPOSE],
        "environments": [ENVIRONMENT],
    }
    event = registry.create_authority(IDENTITY, record, timestamp=ISSUED)
    body = {"input": {"operation": "read"}, "tenant_id": "t1", "actor_id": "synthetic-reviewer"}
    credential = {
        "schema_version": CONTRACT_VERSION,
        "canonicalization": CANONICALIZATION,
        "identity_reference": IDENTITY_REFERENCE,
        "tenant_reference": TENANT_REFERENCE,
        "environment_reference": ENVIRONMENT_REFERENCE,
        "subject_reference": SUBJECT_REFERENCE,
        "issuer_id": ISSUER_ID,
        "audience": AUDIENCE,
        "purpose": PURPOSE,
        "environment": ENVIRONMENT,
        "http_method": METHOD,
        "request_path": PATH,
        "request_id": "request-001",
        "correlation_id": "correlation-001",
        "nonce": "nonce-001",
        "valid_from": VALID_FROM,
        "valid_until": VALID_UNTIL,
        "request_body_hash": sha256_reference(body),
    }
    signed = sign_request_payload(credential, private_pem, PUBKEY_ID)
    return {
        "private_pem": private_pem,
        "config_path": config_path,
        "registry": registry,
        "record": record,
        "event": event,
        "body": body,
        "signed": signed,
    }


def _authenticate(material: dict, **overrides: object):
    parameters = {
        "credential_json": json.dumps(material["signed"]),
        "request_body_json": json.dumps(material["body"]),
        "method": METHOD,
        "path": PATH,
        "expected_audience": AUDIENCE,
        "expected_purpose": PURPOSE,
        "expected_environment": ENVIRONMENT,
        "request_key_config_path": material["config_path"],
        "authority_registry": material["registry"],
        "now": NOW,
    }
    parameters.update(overrides)
    return authenticate_gateway_request(**parameters)


def _resign(material: dict, **overrides: object) -> None:
    unsigned = {key: value for key, value in material["signed"].items() if key not in {"signature", "signature_alg", "pubkey_id"}}
    unsigned.update(overrides)
    material["signed"] = sign_request_payload(unsigned, material["private_pem"], PUBKEY_ID)


def test_authentication_returns_immutable_non_authorizing_context_and_writes_nothing(tmp_path: Path) -> None:
    material = _setup(tmp_path)
    tracked = [material["config_path"], material["registry"].registry_path, material["registry"].evidence_path]
    before = {path: path.read_bytes() for path in tracked}

    context = _authenticate(material)

    assert context.tenant_id == "t1"
    assert context.actor_id == "synthetic-reviewer"
    assert context.execution_authorized is False
    assert context.provider_authorized is False
    assert context.deployment_authorized is False
    assert context.activation_authorized is False
    assert context.policy_authoring_authorized is False
    with pytest.raises(TypeError):
        context.as_mapping()["actor_id"] = "attacker"
    assert {path: path.read_bytes() for path in tracked} == before


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    (
        ("issuer_id", "wrong-issuer", "REQUEST_IDENTITY_ENROLLMENT_BINDING_MISMATCH"),
        ("identity_reference", "sha256:" + "9" * 64, "REQUEST_IDENTITY_ENROLLMENT_INVALID"),
        ("subject_reference", "sha256:" + "8" * 64, "REQUEST_IDENTITY_ENROLLMENT_INVALID"),
        ("tenant_reference", "sha256:" + "7" * 64, "REQUEST_IDENTITY_ENROLLMENT_INVALID"),
        ("environment_reference", "sha256:" + "6" * 64, "REQUEST_IDENTITY_ENROLLMENT_INVALID"),
        ("audience", "other-audience", "REQUEST_IDENTITY_AUDIENCE_MISMATCH"),
        ("purpose", "other-purpose", "REQUEST_IDENTITY_PURPOSE_MISMATCH"),
        ("environment", "production", "REQUEST_IDENTITY_ENVIRONMENT_MISMATCH"),
    ),
)
def test_signed_binding_substitutions_fail_closed(tmp_path: Path, field: str, value: str, reason: str) -> None:
    material = _setup(tmp_path)
    _resign(material, **{field: value})
    with pytest.raises(RequestIdentityError, match=reason):
        _authenticate(material)


def test_method_path_and_complete_body_are_bound(tmp_path: Path) -> None:
    material = _setup(tmp_path)
    with pytest.raises(RequestIdentityError, match="METHOD_MISMATCH"):
        _authenticate(material, method="GET")
    with pytest.raises(RequestIdentityError, match="PATH_MISMATCH"):
        _authenticate(material, path="/other")
    changed_body = dict(material["body"], extra="changed")
    with pytest.raises(RequestIdentityError, match="BODY_HASH_MISMATCH"):
        _authenticate(material, request_body_json=json.dumps(changed_body))


def test_client_identity_is_comparison_only_and_substitution_fails(tmp_path: Path) -> None:
    material = _setup(tmp_path)
    material["body"]["actor_id"] = "attacker"
    _resign(material, request_body_hash=sha256_reference(material["body"]))
    with pytest.raises(RequestIdentityError, match="CLIENT_CLAIM_MISMATCH"):
        _authenticate(material)


def test_nested_identity_claims_fail_and_permitted_matching_claims_pass(tmp_path: Path) -> None:
    material = _setup(tmp_path)
    material["body"]["input_metadata"] = {"tenant_id": "t1", "actor_id": "synthetic-reviewer"}
    _resign(material, request_body_hash=sha256_reference(material["body"]))
    assert _authenticate(material).actor_id == "synthetic-reviewer"

    material["body"]["input"] = {"items": [{"actor_id": "synthetic-reviewer"}]}
    _resign(material, request_body_hash=sha256_reference(material["body"]))
    with pytest.raises(RequestIdentityError, match="CLIENT_CLAIM_LOCATION_INVALID"):
        _authenticate(material)

    material = _setup(tmp_path / "conflicting-metadata")
    material["body"]["input_metadata"] = {"tenant_id": "other"}
    _resign(material, request_body_hash=sha256_reference(material["body"]))
    with pytest.raises(RequestIdentityError, match="CLIENT_CLAIM_MISMATCH"):
        _authenticate(material)


def test_duplicate_json_keys_and_unknown_canonicalization_fail(tmp_path: Path) -> None:
    material = _setup(tmp_path)
    duplicate_body = '{"tenant_id":"t1","tenant_id":"attacker"}'
    with pytest.raises(RequestIdentityError, match="DUPLICATE_JSON_KEY"):
        _authenticate(material, request_body_json=duplicate_body)
    _resign(material, canonicalization="unsupported")
    with pytest.raises(RequestIdentityError, match="CANONICALIZATION_UNSUPPORTED"):
        _authenticate(material)


@pytest.mark.parametrize("non_finite", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_non_finite_json_fails_closed(tmp_path: Path, non_finite: str) -> None:
    material = _setup(tmp_path)
    with pytest.raises(RequestIdentityError, match="JSON_NON_FINITE"):
        _authenticate(material, request_body_json='{"number":' + non_finite + "}")
    malformed_credential = json.dumps(material["signed"]).replace('"nonce": "nonce-001"', '"nonce": NaN')
    with pytest.raises(RequestIdentityError, match="JSON_NON_FINITE"):
        _authenticate(material, credential_json=malformed_credential)
    with pytest.raises(RequestIdentityError, match="JSON_NON_FINITE"):
        parse_unique_json_object(
            {"number": float("inf")},
            reason_code="REQUEST_IDENTITY_BODY_MALFORMED",
        )


def test_excessive_json_nesting_fails_closed(tmp_path: Path) -> None:
    material = _setup(tmp_path)
    nested: dict = {"leaf": True}
    for _ in range(40):
        nested = {"next": nested}
    with pytest.raises(RequestIdentityError, match="JSON_LIMIT_EXCEEDED"):
        _authenticate(material, request_body_json=json.dumps(nested))


def test_signature_key_and_enrollment_are_all_required(tmp_path: Path) -> None:
    material = _setup(tmp_path)
    material["signed"]["signature"] = "not-a-signature"
    with pytest.raises(RequestIdentityError, match="SIGNATURE_INVALID"):
        _authenticate(material)

    material = _setup(tmp_path / "revoked-key")
    config = json.loads(material["config_path"].read_text(encoding="utf-8"))
    config["active_keys"] = []
    config["revoked_keys"] = [PUBKEY_ID]
    material["config_path"].write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(RequestIdentityError, match="KEY_UNAVAILABLE"):
        _authenticate(material)

    material = _setup(tmp_path / "missing-enrollment")
    empty_registry = DurableAuthorityRegistry(tmp_path / "empty.jsonl")
    with pytest.raises(RequestIdentityError, match="ENROLLMENT_INVALID"):
        _authenticate(material, authority_registry=empty_registry)


def test_expiry_revocation_and_authority_change_fail_freshness_revalidation(tmp_path: Path) -> None:
    material = _setup(tmp_path)
    context = _authenticate(material)
    with pytest.raises(RequestIdentityError, match="EXPIRED"):
        _authenticate(material, now=VALID_UNTIL)

    material["registry"].revoke_authority(
        IDENTITY,
        IDENTITY_REFERENCE,
        tenant_reference=TENANT_REFERENCE,
        environment_reference=ENVIRONMENT_REFERENCE,
        reason_code="TEST_REVOCATION",
        timestamp="2026-10-16T12:01:00Z",
    )
    with pytest.raises(RequestIdentityError, match="AUTHORITY_STATE_CHANGED"):
        revalidate_gateway_request_identity(
            context,
            credential_json=json.dumps(material["signed"]),
            request_body_json=json.dumps(material["body"]),
            method=METHOD,
            path=PATH,
            request_key_config_path=material["config_path"],
            authority_registry=material["registry"],
            now="2026-10-16T12:02:00Z",
        )


def test_key_revocation_is_detected_by_freshness_revalidation(tmp_path: Path) -> None:
    material = _setup(tmp_path)
    context = _authenticate(material)
    config = json.loads(material["config_path"].read_text(encoding="utf-8"))
    config["active_keys"] = []
    config["revoked_keys"] = [PUBKEY_ID]
    material["config_path"].write_text(json.dumps(config, sort_keys=True), encoding="utf-8")

    with pytest.raises(RequestIdentityError, match="AUTHORITY_STATE_CHANGED"):
        revalidate_gateway_request_identity(
            context,
            credential_json=json.dumps(material["signed"]),
            request_body_json=json.dumps(material["body"]),
            method=METHOD,
            path=PATH,
            request_key_config_path=material["config_path"],
            authority_registry=material["registry"],
            now=NOW,
        )


def test_ambiguous_subject_or_key_enrollment_fails(tmp_path: Path) -> None:
    material = _setup(tmp_path)
    duplicate = dict(material["record"])
    duplicate["authority_reference"] = "sha256:" + "a" * 64
    duplicate["tenant_id"] = "t2"
    duplicate["actor_id"] = "other-actor"
    material["registry"].create_authority(IDENTITY, duplicate, timestamp=ISSUED)
    with pytest.raises(RequestIdentityError, match="ENROLLMENT_AMBIGUOUS"):
        _authenticate(material)


def test_replay_store_reserves_nonce_and_request_id_independently_and_persists(tmp_path: Path) -> None:
    path = tmp_path / "replay.db"
    store = RequestIdentityReplayStore(path)
    material = _setup(tmp_path / "identity")
    initial = _authenticate(material)
    assert store.reserve(initial, reserved_at=NOW).status == RESERVED
    assert RequestIdentityReplayStore(path).reserve(initial, reserved_at=NOW).status == REPLAY

    _resign(material, request_id="request-002")
    changed_request_id = _authenticate(material)
    assert changed_request_id.caller_scope == initial.caller_scope
    assert changed_request_id.authenticated_request_digest != initial.authenticated_request_digest
    assert store.reserve(changed_request_id, reserved_at=NOW).status == CONFLICT

    second_path = tmp_path / "request-id-conflict.db"
    second_store = RequestIdentityReplayStore(second_path)
    assert second_store.reserve(initial, reserved_at=NOW).status == RESERVED
    _resign(material, request_id="request-001", nonce="nonce-002")
    changed_nonce = _authenticate(material)
    assert changed_nonce.authenticated_request_digest != initial.authenticated_request_digest
    assert second_store.reserve(changed_nonce, reserved_at=NOW).status == CONFLICT


def test_replay_store_rejects_forged_or_unverified_contexts(tmp_path: Path) -> None:
    material = _setup(tmp_path)
    context = _authenticate(material)
    store = RequestIdentityReplayStore(tmp_path / "replay.db")
    forged = replace(context, caller_scope="sha256:" + "f" * 64)
    with pytest.raises(RequestIdentityReplayStoreError, match="CONTEXT_UNVERIFIED"):
        store.reserve(forged, reserved_at=NOW)
    with pytest.raises(RequestIdentityReplayStoreError, match="CONTEXT_UNVERIFIED"):
        store.reserve(context.as_mapping(), reserved_at=NOW)
    with pytest.raises(RequestIdentityReplayStoreError, match="CONTEXT_UNVERIFIED"):
        store.reserve(object(), reserved_at=NOW)


def _authenticated_worker_context(
    credential_json: str,
    body_json: str,
    config_path: str,
    registry_path: str,
    evidence_path: str,
):
    return authenticate_gateway_request(
        credential_json=credential_json,
        request_body_json=body_json,
        method=METHOD,
        path=PATH,
        expected_audience=AUDIENCE,
        expected_purpose=PURPOSE,
        expected_environment=ENVIRONMENT,
        request_key_config_path=config_path,
        authority_registry=DurableAuthorityRegistry(registry_path, evidence_path=evidence_path),
        now=NOW,
    )


def _reserve_worker(path: str, auth_args: tuple[str, str, str, str, str], start, queue) -> None:
    start.wait()
    context = _authenticated_worker_context(*auth_args)
    result = RequestIdentityReplayStore(path, timeout_seconds=2.0).reserve(context, reserved_at=NOW)
    queue.put(result.status)


def test_replay_store_is_cross_process_safe(tmp_path: Path) -> None:
    material = _setup(tmp_path / "identity")
    auth_args = (
        json.dumps(material["signed"]),
        json.dumps(material["body"]),
        str(material["config_path"]),
        str(material["registry"].registry_path),
        str(material["registry"].evidence_path),
    )
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    queue = context.Queue()
    processes = [
        context.Process(target=_reserve_worker, args=(str(tmp_path / "parallel.db"), auth_args, start, queue))
        for _ in range(4)
    ]
    for process in processes:
        process.start()
    start.set()
    results = [queue.get(timeout=10) for _ in processes]
    for process in processes:
        process.join(timeout=10)
        assert process.exitcode == 0
    assert results.count(RESERVED) == 1
    assert results.count(REPLAY) == 3


def test_separate_process_observes_committed_reservation(tmp_path: Path) -> None:
    material = _setup(tmp_path / "identity")
    context = _authenticate(material)
    path = tmp_path / "restart.db"
    assert RequestIdentityReplayStore(path).reserve(context, reserved_at=NOW).status == RESERVED
    auth_args = (
        json.dumps(material["signed"]),
        json.dumps(material["body"]),
        str(material["config_path"]),
        str(material["registry"].registry_path),
        str(material["registry"].evidence_path),
    )
    process_context = multiprocessing.get_context("spawn")
    start = process_context.Event()
    queue = process_context.Queue()
    process = process_context.Process(target=_reserve_worker, args=(str(path), auth_args, start, queue))
    process.start()
    start.set()
    assert queue.get(timeout=10) == REPLAY
    process.join(timeout=10)
    assert process.exitcode == 0


class _FailAfterFirstInsertStore(RequestIdentityReplayStore):
    def _after_first_insert(self, _connection) -> None:
        raise sqlite3.OperationalError("synthetic interruption")


def test_failure_between_inserts_rolls_back_and_reopen_has_no_partial_reservation(tmp_path: Path) -> None:
    material = _setup(tmp_path / "identity")
    context = _authenticate(material)
    path = tmp_path / "rollback.db"
    with pytest.raises(RequestIdentityReplayStoreError, match="REPLAY_STORE_UNAVAILABLE"):
        _FailAfterFirstInsertStore(path).reserve(context, reserved_at=NOW)
    assert RequestIdentityReplayStore(path).reserve(context, reserved_at=NOW).status == RESERVED
    assert RequestIdentityReplayStore(path).reserve(context, reserved_at=NOW).status == REPLAY


def test_replay_store_corrupt_and_locked_storage_fail_closed(tmp_path: Path) -> None:
    material = _setup(tmp_path / "identity")
    context = _authenticate(material)
    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"not sqlite")
    with pytest.raises(RequestIdentityReplayStoreError, match="REPLAY_STORE_UNAVAILABLE"):
        RequestIdentityReplayStore(corrupt).reserve(context, reserved_at=NOW)

    locked = tmp_path / "locked.db"
    RequestIdentityReplayStore(locked).reserve(context, reserved_at=NOW)
    connection = sqlite3.connect(locked, isolation_level=None)
    connection.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(RequestIdentityReplayStoreError, match="REPLAY_STORE_UNAVAILABLE"):
            material2 = _setup(tmp_path / "locked-second")
            context2 = _authenticate(material2)
            RequestIdentityReplayStore(locked).reserve(context2, reserved_at=NOW)
    finally:
        connection.rollback()
        connection.close()


def test_errors_and_context_do_not_disclose_sensitive_inputs(tmp_path: Path) -> None:
    material = _setup(tmp_path)
    secret = "raw-sensitive-body-value"
    material["body"]["payload"] = secret
    _resign(material, request_body_hash=sha256_reference(material["body"]))
    context = _authenticate(material)
    assert secret not in repr(context)
    material["signed"]["signature"] = "raw-signature-secret"
    with pytest.raises(RequestIdentityError) as captured:
        _authenticate(material)
    assert secret not in str(captured.value)
    assert "raw-signature-secret" not in str(captured.value)
