from __future__ import annotations

import builtins
import json
import types

from fastapi.testclient import TestClient
from pyasn1.type import univ

import gateway.app as gateway_app
from audit.anchor import (
    DEFAULT_PRIVATE_KEY_PATH,
    DEFAULT_PUBLIC_KEY_PATH,
    LIVE_TSA_MESSAGE,
    LiveRFC3161Client,
    MockTSAClient,
    TimestampAuthorityClient,
    ensure_keypair,
    public_key_id,
    sign_event,
    timestamp_event,
    verify_event,
)
from audit.exporter import GENESIS_HASH, export_audit_event, verify_export_chain
from audit.hash_chain import AuditHashChain
from audit.keys import get_signing_key, resolve_public_key
from audit.verify import verify_audit_export, verify_export_file


def isolated_anchor_keys(tmp_path, monkeypatch):
    private_key_path = tmp_path / "audit_private_key.pem"
    public_key_path = tmp_path / "public_key.pem"
    monkeypatch.setattr("audit.keys.DEFAULT_REGISTRY_PATH", tmp_path / "key_registry.json")
    monkeypatch.setattr("audit.keys.DEFAULT_PRIVATE_KEY_PATH", private_key_path)
    monkeypatch.setattr("audit.keys.DEFAULT_PUBLIC_KEY_PATH", public_key_path)
    monkeypatch.setattr("audit.keys.DEFAULT_PRIVATE_KEY_DIR", tmp_path / "private_keys")
    monkeypatch.setattr("audit.keys.DEFAULT_PUBLIC_KEY_DIR", tmp_path / "public_keys")
    return private_key_path, public_key_path


def sample_event(**overrides):
    event = {
        "audit_id": "audit-1",
        "timestamp": "2026-04-27T00:00:00Z",
        "action": "execution_governance",
        "decision": {
            "command_hash": "abc123",
            "decision": "allow",
            "consensus": {
                "final_decision": "allow",
                "votes_allow": 2,
                "votes_deny": 1,
                "consensus_reached": True,
            },
        },
        "reason": "policy_allowed",
        "policy_version": "policy-v1",
        "signature_valid": True,
        "nonce_valid": True,
    }
    event.update(overrides)
    return event


def read_records(path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_records(path, records):
    path.write_text(
        "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n",
        encoding="utf-8",
    )


def test_export_file_created(tmp_path, monkeypatch) -> None:
    _, public_key_path = isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "audit_exports.jsonl"

    record = export_audit_event(sample_event(), str(path))

    assert path.exists()
    records = read_records(path)
    assert records == [record]
    assert record["audit_id"] == "audit-1"
    assert record["decision"] == "ALLOW"
    assert record["prev_hash"] == GENESIS_HASH
    assert "signature" in record
    assert record["public_key_id"] == public_key_id(public_key_path)
    assert record["key_version"] == "v1"
    assert record["timestamp_proof"]["type"] == "RFC3161"
    assert record["timestamp_proof"]["hash"] == record["event_hash"]
    assert record["timestamp_proof"]["mode"] == "mock"
    assert record["timestamp_proof"]["token"]
    assert "command" not in record
    assert record["command_hash"] == "abc123"


def test_hash_chain_valid(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "audit_exports.jsonl"
    export_audit_event(sample_event(audit_id="audit-1"), str(path))

    assert verify_export_chain(str(path))
    assert verify_export_file(str(path))
    assert verify_audit_export(str(path))["valid"] is True


def test_tampered_export_detectable(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "audit_exports.jsonl"
    export_audit_event(sample_event(audit_id="audit-1"), str(path))
    records = read_records(path)
    records[0]["decision"] = "DENY"
    write_records(path, records)

    assert not verify_export_chain(str(path))
    result = verify_audit_export(str(path))
    assert result["valid"] is False
    assert result["event_integrity"] is False


def test_multiple_events_chained_correctly(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "audit_exports.jsonl"
    first = export_audit_event(sample_event(audit_id="audit-1"), str(path))
    second = export_audit_event(sample_event(audit_id="audit-2"), str(path))

    assert second["prev_hash"] == first["event_hash"]
    assert verify_export_chain(str(path))
    assert verify_export_file(str(path))


def test_gateway_audit_export_route(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    chain = AuditHashChain(tmp_path / "audit_chain.json")
    event = chain.append_event(
        action="execution_governance",
        decision={
            "command_hash": "abc123",
            "decision": "allow",
            "consensus": {
                "votes_allow": 2,
                "votes_deny": 1,
                "consensus_reached": True,
            },
        },
    )
    monkeypatch.setattr(gateway_app, "audit_chain", chain)
    monkeypatch.setattr(gateway_app, "audit_export_file", tmp_path / "audit_exports.jsonl")
    client = TestClient(gateway_app.app)

    response = client.get(f"/audit/export/{event['hash_current']}")

    assert response.status_code == 200
    exported = response.json()
    assert exported["audit_id"] == event["hash_current"]
    assert exported["action"] == "execution_governance"
    assert exported["hydra"]["allow_votes"] == 2
    assert verify_export_chain(str(tmp_path / "audit_exports.jsonl"))
    assert verify_export_file(str(tmp_path / "audit_exports.jsonl"))


def test_signature_valid() -> None:
    private_key, public_key = ensure_keypair(DEFAULT_PRIVATE_KEY_PATH, DEFAULT_PUBLIC_KEY_PATH)
    event_hash = "abc123"
    signature = sign_event(event_hash, private_key)

    assert verify_event(event_hash, signature, public_key)


def test_signature_invalid_detected(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "audit_exports.jsonl"
    export_audit_event(sample_event(audit_id="audit-1"), str(path))
    records = read_records(path)
    records[0]["signature"] = "invalid"
    write_records(path, records)

    result = verify_audit_export(str(path))
    assert result["valid"] is False
    assert result["signature_valid"] is False


def test_timestamp_structure_invalid_detected(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "audit_exports.jsonl"
    export_audit_event(sample_event(audit_id="audit-1"), str(path))
    records = read_records(path)
    records[0]["timestamp_proof"]["hash"] = "wrong"
    write_records(path, records)

    result = verify_audit_export(str(path))
    assert result["valid"] is False
    assert result["timestamp_valid"] is False


def test_public_key_verification_works(tmp_path, monkeypatch) -> None:
    _, public_key_path = isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "audit_exports.jsonl"
    export_audit_event(sample_event(audit_id="audit-1"), str(path))

    assert verify_export_file(str(path), str(public_key_path))


def test_wrong_public_key_fails(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "audit_exports.jsonl"
    export_audit_event(sample_event(audit_id="audit-1"), str(path))
    _, wrong_public_key = ensure_keypair(
        tmp_path / "wrong_private_key.pem",
        tmp_path / "wrong_public_key.pem",
    )

    assert not verify_export_file(str(path), wrong_public_key)


def test_event_hash_modified_fails_verification(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "audit_exports.jsonl"
    export_audit_event(sample_event(audit_id="audit-1"), str(path))
    records = read_records(path)
    records[0]["event_hash"] = "0" * 64
    write_records(path, records)

    result = verify_audit_export(str(path))

    assert result["valid"] is False
    assert result["event_integrity"] is False
    assert result["signature_valid"] is False
    assert result["timestamp_valid"] is False


def test_public_key_id_mismatch_fails_verification(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "audit_exports.jsonl"
    export_audit_event(sample_event(audit_id="audit-1"), str(path))
    records = read_records(path)
    records[0]["public_key_id"] = "unknown-key"
    write_records(path, records)

    result = verify_audit_export(str(path))

    assert result["valid"] is False
    assert result["signature_valid"] is False


def test_prev_hash_chain_broken_fails_verification(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "audit_exports.jsonl"
    export_audit_event(sample_event(audit_id="audit-1"), str(path))
    export_audit_event(sample_event(audit_id="audit-2"), str(path))
    records = read_records(path)
    records[1]["prev_hash"] = "broken"
    write_records(path, records)

    result = verify_audit_export(str(path))

    assert result["valid"] is False
    assert result["hash_chain"] is False


def test_timestamp_proof_missing_fails_verification(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "audit_exports.jsonl"
    export_audit_event(sample_event(audit_id="audit-1"), str(path))
    records = read_records(path)
    records[0].pop("timestamp_proof")
    write_records(path, records)

    result = verify_audit_export(str(path))

    assert result["valid"] is False
    assert result["timestamp_valid"] is False


def test_timestamp_token_missing_fails_verification(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "audit_exports.jsonl"
    export_audit_event(sample_event(audit_id="audit-1"), str(path))
    records = read_records(path)
    records[0]["timestamp_proof"].pop("token")
    write_records(path, records)

    result = verify_audit_export(str(path))

    assert result["valid"] is False
    assert result["timestamp_valid"] is False


def test_timestamp_type_malformed_fails_verification(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "audit_exports.jsonl"
    export_audit_event(sample_event(audit_id="audit-1"), str(path))
    records = read_records(path)
    records[0]["timestamp_proof"]["type"] = "LOCAL"
    write_records(path, records)

    result = verify_audit_export(str(path))

    assert result["valid"] is False
    assert result["timestamp_valid"] is False


def test_mock_tsa_proof_passes_shape_check(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    proof = timestamp_event("abc123")

    assert proof["type"] == "RFC3161"
    assert proof["hash"] == "abc123"
    assert proof["mode"] == "mock"
    assert proof["token"]


def test_key_v1_event_verifies_with_key_v1(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "audit_exports.jsonl"

    record = export_audit_event(sample_event(audit_id="audit-1", key_version="v1"), str(path))

    assert record["key_version"] == "v1"
    assert resolve_public_key(record["public_key_id"])
    assert verify_audit_export(str(path))["valid"] is True


def test_key_v2_event_verifies_with_key_v2(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "audit_exports.jsonl"

    record = export_audit_event(sample_event(audit_id="audit-1", key_version="v2"), str(path))

    assert record["key_version"] == "v2"
    assert resolve_public_key(record["public_key_id"])
    assert verify_audit_export(str(path))["valid"] is True


def test_key_v1_event_fails_with_wrong_public_key_id(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "audit_exports.jsonl"
    export_audit_event(sample_event(audit_id="audit-1", key_version="v1"), str(path))
    wrong_key = get_signing_key("v2")
    records = read_records(path)
    records[0]["public_key_id"] = wrong_key["public_key_id"]
    records[0]["key_version"] = wrong_key["key_version"]
    write_records(path, records)

    result = verify_audit_export(str(path))

    assert result["valid"] is False
    assert result["signature_valid"] is False


def test_mixed_chain_with_v1_then_v2_verifies(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "audit_exports.jsonl"
    first = export_audit_event(sample_event(audit_id="audit-1", key_version="v1"), str(path))
    second = export_audit_event(sample_event(audit_id="audit-2", key_version="v2"), str(path))

    assert first["key_version"] == "v1"
    assert second["key_version"] == "v2"
    assert second["prev_hash"] == first["event_hash"]
    assert verify_audit_export(str(path))["valid"] is True


def test_verify_api_import() -> None:
    from audit.verify import verify_audit_export

    assert callable(verify_audit_export)


def test_mock_tsa_passes_in_local_test_mode(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "audit_exports.jsonl"
    export_audit_event(sample_event(audit_id="audit-1"), str(path))

    assert verify_audit_export(str(path))["valid"] is True


def test_live_tsa_failure_fails_closed(monkeypatch) -> None:
    event_hash = "ab" * 32

    try:
        LiveRFC3161Client("http://127.0.0.1:1/tsa").timestamp(event_hash)
    except RuntimeError as exc:
        assert str(exc).startswith(("tsa_dns_or_network_failed:", "tsa_request_failed:"))
    else:
        raise AssertionError("live TSA failure must fail closed")


def test_live_tsa_proof_passes(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)

    class GoodLiveTSA(TimestampAuthorityClient):
        def timestamp(self, event_hash: str) -> dict:
            return {
                "type": "RFC3161",
                "tsa": "https://tsa.example.test",
                "hash": event_hash,
                "created_at": "2026-04-27T00:00:00Z",
                "token": "bGl2ZS10b2tlbg==",
                "mode": "live",
            }

    monkeypatch.setattr("audit.exporter.timestamp_event", lambda event_hash: timestamp_event(event_hash, GoodLiveTSA()))
    path = tmp_path / "audit_exports.jsonl"
    export_audit_event(sample_event(audit_id="audit-1"), str(path))

    assert verify_audit_export(str(path))["valid"] is True


def test_missing_rfc3161ng_dependency_gives_clear_error(monkeypatch) -> None:
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "rfc3161ng":
            raise ImportError("missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    try:
        LiveRFC3161Client("https://tsa.example.test").timestamp("ab" * 32)
    except RuntimeError as exc:
        assert str(exc).startswith("missing_dependency:rfc3161ng:")
    else:
        raise AssertionError("missing rfc3161ng must fail closed")


def test_live_client_submits_hash_and_stores_base64_token(monkeypatch) -> None:
    event_hash = "ab" * 32
    captured = {}

    class FakeRemoteTimestamper:
        def __init__(self, url, hashname=None, timeout=None):
            captured["url"] = url
            captured["hashname"] = hashname
            captured["timeout"] = timeout

        def __call__(self, data=None):
            captured["data"] = data
            return univ.OctetString(b"rfc3161-token-bytes")

    fake_rfc3161ng = types.SimpleNamespace(RemoteTimestamper=FakeRemoteTimestamper)
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "rfc3161ng":
            return fake_rfc3161ng
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    proof = LiveRFC3161Client("https://tsa.example.test", timeout=2.5).timestamp(event_hash)

    assert captured["url"] == "https://tsa.example.test"
    assert captured["hashname"] == "sha256"
    assert captured["timeout"] == 2.5
    assert captured["data"] == LIVE_TSA_MESSAGE
    assert proof["mode"] == "live"
    assert proof["hash"] == "434e1e2044619250cc05fe4043d03fce988c974267d2d19d89e88d41a6a6e1df"
    assert proof["token"]


def test_live_client_base64_encodes_byte_response_directly(monkeypatch) -> None:
    class FakeRemoteTimestamper:
        def __init__(self, *args, **kwargs):
            pass

        def __call__(self, data=None):
            return b"raw-rfc3161-token"

    fake_rfc3161ng = types.SimpleNamespace(RemoteTimestamper=FakeRemoteTimestamper)
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "rfc3161ng":
            return fake_rfc3161ng
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    proof = LiveRFC3161Client("https://tsa.example.test").timestamp("ab" * 32)

    assert proof["token"] == "cmF3LXJmYzMxNjEtdG9rZW4="


def test_live_client_exception_fails_closed(monkeypatch) -> None:
    class FailingRemoteTimestamper:
        def __init__(self, *args, **kwargs):
            pass

        def __call__(self, data=None):
            raise RuntimeError("tsa down")

    fake_rfc3161ng = types.SimpleNamespace(RemoteTimestamper=FailingRemoteTimestamper)
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "rfc3161ng":
            return fake_rfc3161ng
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    try:
        LiveRFC3161Client("https://tsa.example.test").timestamp("ab" * 32)
    except RuntimeError as exc:
        assert str(exc).startswith("tsa_request_failed:RuntimeError:tsa down")
    else:
        raise AssertionError("TSA exception must fail closed")
