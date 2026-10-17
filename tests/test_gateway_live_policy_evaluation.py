from __future__ import annotations

import json
import hashlib
import multiprocessing
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import audit.keys as audit_keys
import audit.immutable_ledger as immutable_ledger
import gateway.live_policy_evaluation as live_gateway
from audit.immutable_ledger import append_evidence_event, verify_ledger
from gateway.app import app
from gateway.live_policy_evaluation import LivePolicyEvaluationDependencies
from gateway.request_identity_replay_store import RequestIdentityReplayStore
from governance.durable_authority_registries import IDENTITY
from governance.hashing import sha256_reference
from runtime.computer_use.ai_act_live_policy_engine import PolicyAuthority
import runtime.policy_validator as policy_validator
from security.policy_authority_adoption_store import adopt_current_scoped_policy_authority
from security.policy_authority_replay_registry import SQLitePolicyAuthorityReplayRegistry
from security.request_signing import sign_request_payload
from tests.test_gateway_request_identity import _setup
from tests.test_governance_validation import _write_policy_authority_fixture


pytestmark = pytest.mark.governance

def _audit_keys(monkeypatch, root: Path) -> None:
    values = {
        "DEFAULT_REGISTRY_PATH": root / "key_registry.json",
        "DEFAULT_PRIVATE_KEY_PATH": root / "private.pem",
        "DEFAULT_PUBLIC_KEY_PATH": root / "public.pem",
        "DEFAULT_PRIVATE_KEY_DIR": root / "private",
        "DEFAULT_PUBLIC_KEY_DIR": root / "public",
        "DEFAULT_REGISTRY_ROOT": root,
        "DEFAULT_PRIVATE_KEY_ROOT": root,
        "DEFAULT_PUBLIC_KEY_ROOT": root,
    }
    for name, value in values.items():
        monkeypatch.setattr(audit_keys, name, value)


def _policy(effect: str) -> dict:
    return {
        "policy_id": "synthetic-live-policy",
        "policy_version": "1.0",
        "fail_closed": True,
        "ai_act_live_policy_engine": {
            "enabled": True,
            "applicability": {
                "jurisdictions": ["EU"],
                "policy_scopes": ["ai_act_live_policy"],
                "use_case_classifications": ["bounded_ai_act"],
                "effective_from": "2026-01-01T00:00:00Z",
                "effective_until": "2027-01-01T00:00:00Z",
            },
            "obligations": [
                {
                    "obligation_id": "human-review",
                    "obligation_type": "human_review_required",
                    "required": True,
                    "evidence_required": True,
                    "freshness_seconds": 3600,
                },
                {
                    "obligation_id": "execution-contract",
                    "obligation_type": "execution_contract_required",
                    "required": True,
                    "evidence_required": True,
                },
            ],
            "rules": [{
                "rule_id": "synthetic-rule",
                "field": "risk_classification",
                "operator": "equals",
                "value": "LOW",
                "effect": effect,
            }],
        },
    }


def _request_body(effect: str, request_id: str) -> tuple[dict, PolicyAuthority]:
    policy = _policy(effect)
    policy_hash = sha256_reference(policy)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    body = {
        "adoption_id": sha256_reference({"adoption": effect}),
        "request_id": request_id,
        "correlation_id": "correlation-" + request_id,
        "tenant_id": "t1",
        "actor_id": "synthetic-reviewer",
        "environment": "test",
        "jurisdiction": "EU",
        "policy_scope": "ai_act_live_policy",
        "policy_id": policy["policy_id"],
        "policy_version": policy["policy_version"],
        "policy_hash": policy_hash,
        "input_metadata": {"risk_classification": "LOW", "system_type": "bounded_ai_act"},
    }
    context_hash = sha256_reference({
        "request_id": request_id,
        "tenant_id": "t1",
        "environment": "test",
        "actor_id": "synthetic-reviewer",
        "jurisdiction": "EU",
        "policy_scope": "ai_act_live_policy",
        "input_metadata_hash": sha256_reference(body["input_metadata"]),
    })
    body["obligation_satisfaction"] = [{
        "request_id": request_id,
        "policy_id": policy["policy_id"],
        "policy_version": policy["policy_version"],
        "policy_hash": policy_hash,
        "authority_state": "CURRENT",
        "execution_context_hash": context_hash,
        "state": "SATISFIED",
        "fulfilled_at": now,
        "obligation_id": "human-review",
        "obligation_type": "human_review_required",
        "evidence_hash": sha256_reference({"evidence": request_id}),
        "approved_by_human": True,
        "approver_type": "human",
    }, {
        "request_id": request_id,
        "policy_id": policy["policy_id"],
        "policy_version": policy["policy_version"],
        "policy_hash": policy_hash,
        "authority_state": "CURRENT",
        "execution_context_hash": context_hash,
        "state": "SATISFIED",
        "fulfilled_at": now,
        "obligation_id": "execution-contract",
        "obligation_type": "execution_contract_required",
        "evidence_hash": sha256_reference({"execution-contract": request_id}),
    }]
    authority = PolicyAuthority(
        policy_id=policy["policy_id"],
        policy_version=policy["policy_version"],
        policy_hash=policy_hash,
        approved=True,
        policy_document=policy,
        source="synthetic-adopted-authority",
        authority_state_reference=sha256_reference({"authority": effect}),
    )
    return body, authority


def _material(tmp_path: Path, body: dict) -> dict:
    material = _setup(tmp_path)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    record = dict(material["record"])
    record.update(
        issued_at=(now - timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
        effective_at=(now - timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
        expires_at=(now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        environments=[body["environment"]],
    )
    material["registry"].update_authority(IDENTITY, record, timestamp=now.isoformat().replace("+00:00", "Z"))
    credential = {key: value for key, value in material["signed"].items() if key not in {"signature", "signature_alg", "pubkey_id"}}
    credential.update(
        request_id=body["request_id"],
        correlation_id=body["correlation_id"],
        nonce="nonce-" + body["request_id"],
        valid_from=(now - timedelta(seconds=10)).isoformat().replace("+00:00", "Z"),
        valid_until=(now + timedelta(minutes=4)).isoformat().replace("+00:00", "Z"),
        request_body_hash=sha256_reference(body),
        environment=body["environment"],
    )
    material["body"] = body
    material["signed"] = sign_request_payload(credential, material["private_pem"], material["signed"]["pubkey_id"])
    return material


def _dependencies(tmp_path: Path, material: dict) -> LivePolicyEvaluationDependencies:
    return LivePolicyEvaluationDependencies(
        request_key_config_path=material["config_path"],
        authority_registry=material["registry"],
        request_replay_store=RequestIdentityReplayStore(tmp_path / "request-replay.db"),
        adoption_store=SQLitePolicyAuthorityReplayRegistry(tmp_path / "adoption.db"),
        evidence_root=tmp_path / "evidence",
        environment="test",
    )


def test_disabled_is_side_effect_free(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("USBAY_LIVE_POLICY_EVALUATION_ENABLED", raising=False)
    monkeypatch.setattr(live_gateway, "default_dependencies", lambda: (_ for _ in ()).throw(AssertionError("side effect")))
    response = TestClient(app).post(live_gateway.ENDPOINT_PATH, content=b"not-json")
    assert response.status_code == 503
    assert response.json()["reason_code"] == "LIVE_POLICY_EVALUATION_DISABLED"
    assert list(tmp_path.iterdir()) == []


def test_full_http_allow_review_block_and_replay(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("USBAY_LIVE_POLICY_EVALUATION_ENABLED", "true")
    _audit_keys(monkeypatch, tmp_path / "keys")
    client = TestClient(app)
    for effect, status in (("ALLOW", 200), ("REVIEW", 202), ("BLOCK", 403)):
        body, authority = _request_body(effect, "request-" + effect.lower())
        material = _material(tmp_path / effect.lower(), body)
        deps = _dependencies(tmp_path / effect.lower(), material)
        monkeypatch.setattr(live_gateway, "default_dependencies", lambda deps=deps: deps)
        monkeypatch.setattr(live_gateway, "load_adopted_human_policy_authority", lambda **_kwargs: authority)
        monkeypatch.setattr(live_gateway, "revalidate_adopted_human_policy_authority", lambda current, **_kwargs: current)
        headers = {"x-usbay-request-identity": json.dumps(material["signed"])}
        response = client.post(live_gateway.ENDPOINT_PATH, json=body, headers=headers)
        assert response.status_code == status, response.text
        payload = response.json()
        assert payload["decision"] == effect
        assert not any(payload[name] for name in (
            "execution_authorized", "provider_authorized", "deployment_authorized",
            "activation_authorized", "policy_authoring_authorized",
        ))
        ledger = deps.evidence_root / "tenant" / "t1" / "live-policy-evidence.jsonl"
        assert verify_ledger(ledger)
        evidence = ledger.read_text(encoding="utf-8")
        assert material["signed"]["signature"] not in evidence
        assert material["signed"]["nonce"] not in evidence
        replay = client.post(live_gateway.ENDPOINT_PATH, json=body, headers=headers)
        assert replay.status_code == 409


def test_http_allow_uses_actual_scoped_adoption_loader(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("USBAY_LIVE_POLICY_EVALUATION_ENABLED", "true")
    _audit_keys(monkeypatch, tmp_path / "keys")
    body, _unused = _request_body("ALLOW", "request-adopted")
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(_policy("ALLOW"), sort_keys=True), encoding="utf-8")
    private_key = Ed25519PrivateKey.generate()
    policy_signature = tmp_path / "policy.sig"
    policy_signature.write_bytes(private_key.sign(policy_path.read_bytes()))
    policy_public = tmp_path / "policy-public.pem"
    policy_public.write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    policy_sha = tmp_path / "policy.sha256"
    policy_sha.write_text(hashlib.sha256(policy_path.read_bytes()).hexdigest() + "\n", encoding="utf-8")
    monkeypatch.setattr(policy_validator, "POLICY_JSON", policy_path)
    monkeypatch.setattr(policy_validator, "POLICY_SHA256", policy_sha)
    monkeypatch.setattr(policy_validator, "POLICY_SIG", policy_signature)
    monkeypatch.setattr(policy_validator, "PUBLIC_KEY", policy_public)
    body["policy_hash"] = "sha256:" + policy_validator.compute_policy_hash()
    for satisfaction in body["obligation_satisfaction"]:
        satisfaction["policy_hash"] = body["policy_hash"]

    def scoped(approvals: list[dict]) -> None:
        for approval in approvals:
            approval.update(
                schema_version="usbay.policy_authority_approval.scoped.v1",
                policy_id="synthetic-live-policy",
                tenant_reference="sha256:" + "1" * 64,
                environment_reference="sha256:" + "2" * 64,
                environment="production",
            )

    def registry_scope(registry: dict, _approvals: list[dict]) -> None:
        return None

    (tmp_path / "authority").mkdir()
    authority_paths = _write_policy_authority_fixture(
        monkeypatch,
        tmp_path / "authority",
        approval_mutation=scoped,
        registry_mutation=registry_scope,
    )
    store = SQLitePolicyAuthorityReplayRegistry(authority_paths["replay_db"])
    adopted = adopt_current_scoped_policy_authority(
        policy_id="synthetic-live-policy",
        policy_hash=policy_validator.compute_policy_hash(),
        policy_version="1.0",
        tenant_reference="sha256:" + "1" * 64,
        environment_reference="sha256:" + "2" * 64,
        environment="production",
        store=store,
    )
    body["adoption_id"] = adopted.adoption_id
    body["environment"] = "production"
    production_context_hash = sha256_reference({
        "request_id": body["request_id"],
        "tenant_id": body["tenant_id"],
        "environment": body["environment"],
        "actor_id": body["actor_id"],
        "jurisdiction": body["jurisdiction"],
        "policy_scope": body["policy_scope"],
        "input_metadata_hash": sha256_reference(body["input_metadata"]),
    })
    for satisfaction in body["obligation_satisfaction"]:
        satisfaction["execution_context_hash"] = production_context_hash
    material = _material(tmp_path / "caller", body)
    deps = LivePolicyEvaluationDependencies(
        request_key_config_path=material["config_path"],
        authority_registry=material["registry"],
        request_replay_store=RequestIdentityReplayStore(tmp_path / "request-replay.db"),
        adoption_store=store,
        evidence_root=tmp_path / "evidence",
        environment="production",
    )
    monkeypatch.setattr(live_gateway, "default_dependencies", lambda: deps)
    response = TestClient(app).post(
        live_gateway.ENDPOINT_PATH,
        json=body,
        headers={"x-usbay-request-identity": json.dumps(material["signed"])},
    )
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "ALLOW"


def test_failure_after_replay_reservation_is_consumed(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("USBAY_LIVE_POLICY_EVALUATION_ENABLED", "true")
    body, authority = _request_body("ALLOW", "request-failure")
    material = _material(tmp_path, body)
    deps = _dependencies(tmp_path, material)
    monkeypatch.setattr(live_gateway, "default_dependencies", lambda: deps)
    monkeypatch.setattr(live_gateway, "load_adopted_human_policy_authority", lambda **_kwargs: authority)
    monkeypatch.setattr(live_gateway, "revalidate_adopted_human_policy_authority", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("revoked")))
    headers = {"x-usbay-request-identity": json.dumps(material["signed"])}
    client = TestClient(app)
    assert client.post(live_gateway.ENDPOINT_PATH, json=body, headers=headers).status_code == 503
    assert client.post(live_gateway.ENDPOINT_PATH, json=body, headers=headers).status_code == 409


def test_caller_revocation_before_commit_blocks_and_consumes_replay(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("USBAY_LIVE_POLICY_EVALUATION_ENABLED", "true")
    body, authority = _request_body("ALLOW", "request-revoked")
    material = _material(tmp_path, body)

    def revoke() -> None:
        material["registry"].revoke_authority(
            IDENTITY,
            material["record"]["authority_reference"],
            tenant_reference=material["record"]["tenant_reference"],
            environment_reference=material["record"]["environment_reference"],
            reason_code="SYNTHETIC_REVOCATION",
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )

    base = _dependencies(tmp_path, material)
    deps = LivePolicyEvaluationDependencies(**{**base.__dict__, "before_evidence_commit": revoke})
    monkeypatch.setattr(live_gateway, "default_dependencies", lambda: deps)
    monkeypatch.setattr(live_gateway, "load_adopted_human_policy_authority", lambda **_kwargs: authority)
    headers = {"x-usbay-request-identity": json.dumps(material["signed"])}
    client = TestClient(app)
    blocked = client.post(live_gateway.ENDPOINT_PATH, json=body, headers=headers)
    assert blocked.status_code == 401
    assert blocked.json()["reason_code"] == "REQUEST_IDENTITY_AUTHORITY_STATE_CHANGED"
    assert client.post(live_gateway.ENDPOINT_PATH, json=body, headers=headers).status_code in {401, 409}
    assert not (deps.evidence_root / "tenant" / "t1" / "live-policy-evidence.jsonl").exists()


def _append_child(path: str, index: int) -> None:
    append_evidence_event(
        path,
        action="concurrent",
        decision={"tenant_id": "t1", "decision": "BLOCK", "policy_hash": "p", "node_id": str(index)},
        timestamp=f"2026-10-16T18:00:{index:02d}Z",
    )


def test_ledger_cross_process_append_and_incomplete_tail_fail_closed(monkeypatch, tmp_path) -> None:
    _audit_keys(monkeypatch, tmp_path / "keys")
    path = tmp_path / "evidence.jsonl"
    context = multiprocessing.get_context("fork")
    processes = [context.Process(target=_append_child, args=(str(path), index)) for index in range(4)]
    for process in processes:
        process.start()
    for process in processes:
        process.join(10)
        assert process.exitcode == 0
    assert verify_ledger(path)
    assert len(path.read_text(encoding="utf-8").splitlines()) == 4
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"partial":')
    assert not verify_ledger(path)


def test_ledger_fsync_failure_is_reported_as_uncertain(monkeypatch, tmp_path) -> None:
    _audit_keys(monkeypatch, tmp_path / "keys")
    path = tmp_path / "evidence.jsonl"
    monkeypatch.setattr(immutable_ledger.os, "fsync", lambda _fd: (_ for _ in ()).throw(OSError("injected")))
    try:
        append_evidence_event(
            path,
            action="fsync-failure",
            decision={"tenant_id": "t1", "decision": "BLOCK", "policy_hash": "p", "node_id": "n"},
        )
    except immutable_ledger.LedgerIntegrityError as exc:
        assert str(exc) == "ledger_write_uncertain"
    else:
        raise AssertionError("fsync failure must not report success")
    assert path.with_suffix(path.suffix + ".uncertain").exists()
    assert not verify_ledger(path)
    monkeypatch.undo()
    try:
        append_evidence_event(
            path,
            action="retry-after-uncertain",
            decision={"tenant_id": "t1", "decision": "BLOCK", "policy_hash": "p", "node_id": "n"},
        )
    except immutable_ledger.LedgerIntegrityError as exc:
        assert str(exc) == "ledger_write_uncertain"
    else:
        raise AssertionError("uncertain ledger state must block later appends")
