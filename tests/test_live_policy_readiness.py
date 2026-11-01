"""Synthetic HTTP identity and evidence-boundary regressions; no execution."""
import concurrent.futures
import json
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

import audit.immutable_ledger as ledger
import gateway.live_policy_evaluation as live
from gateway.app import app
from gateway.request_identity_replay_store import RequestIdentityReplayStore
from tests.test_gateway_live_policy_evaluation import (
    _audit_keys, _dependencies, _material, _request_body,
)

pytestmark = [pytest.mark.governance, pytest.mark.regression]


def _caller(tmp_path, monkeypatch, suffix):
    monkeypatch.setenv("USBAY_LIVE_POLICY_EVALUATION_ENABLED", "true")
    _audit_keys(monkeypatch, tmp_path / "keys")
    body, authority = _request_body("ALLOW", "readiness-" + suffix)
    material = _material(tmp_path / "caller", body)
    deps = _dependencies(tmp_path / "caller", material)
    monkeypatch.setattr(live, "default_dependencies", lambda: deps)
    # Isolate the caller/ledger boundaries. Real scoped adoption is exercised by
    # test_http_allow_uses_actual_scoped_adoption_loader in the original module.
    monkeypatch.setattr(live, "load_adopted_human_policy_authority", lambda **kwargs: authority)
    monkeypatch.setattr(live, "revalidate_adopted_human_policy_authority", lambda current, **kwargs: current)
    return TestClient(app), body, material, deps


def _assert_no_grants(response):
    for name in ["execution_authorized", "provider_authorized", "deployment_authorized",
                 "activation_authorized", "policy_authoring_authorized"]:
        assert response.json()[name] is False


@pytest.mark.parametrize("other", ["identical", "conflicting"])
def test_duplicate_identity_headers_fail_closed(tmp_path, monkeypatch, other):
    client, body, material, deps = _caller(tmp_path, monkeypatch, "headers")
    credential = json.dumps(material["signed"])
    headers = [("x-usbay-request-identity", credential),
               ("X-USBAY-REQUEST-IDENTITY", credential if other == "identical" else "{}")]
    response = client.post(live.ENDPOINT_PATH, json=body, headers=headers)
    assert response.status_code == 401
    assert response.json()["reason_code"] == "REQUEST_IDENTITY_HEADER_AMBIGUOUS"
    _assert_no_grants(response)
    assert not deps.request_replay_store.path.exists()
    assert not deps.evidence_root.exists()
    # An ambiguous header never burns the otherwise-valid request.
    valid = client.post(live.ENDPOINT_PATH, json=body,
                        headers={"x-usbay-request-identity": credential})
    assert valid.status_code == 200
    _assert_no_grants(valid)


def test_foreign_tenant_ledger_is_not_extended(tmp_path, monkeypatch):
    client, body, material, deps = _caller(tmp_path, monkeypatch, "tenant")
    path = deps.evidence_root / "tenant/t1/live-policy-evidence.jsonl"
    ledger.append_evidence_event(path, action="synthetic-foreign-evidence", decision={
        "tenant_id": "t2", "node_id": "synthetic", "policy_hash": body["policy_hash"], "decision": "BLOCK"})
    before = {p.name: p.read_bytes() for p in path.parent.iterdir() if p.is_file()}
    response = client.post(live.ENDPOINT_PATH, json=body,
                           headers={"x-usbay-request-identity": json.dumps(material["signed"])})
    assert response.status_code == 503
    assert response.json()["reason_code"] == "LIVE_POLICY_EVIDENCE_COMMIT_FAILED"
    _assert_no_grants(response)
    assert {p.name: p.read_bytes() for p in path.parent.iterdir() if p.is_file()} == before
    assert client.post(live.ENDPOINT_PATH, json=body,
                       headers={"x-usbay-request-identity": json.dumps(material["signed"])}).status_code == 409


def test_empty_ledger_rejects_expected_tenant_substitution(tmp_path, monkeypatch):
    _audit_keys(monkeypatch, tmp_path / "keys")
    path = tmp_path / "new.jsonl"
    with pytest.raises(ledger.LedgerIntegrityError):
        ledger.append_evidence_event(path, action="synthetic", expected_tenant_id="t1",
                                     decision={"tenant_id": "t2", "node_id": "n", "policy_hash": "p"})
    assert not path.exists()
    assert not path.with_name(path.name + ".pair-transactions-v1.jsonl").exists()


def test_concurrent_tenants_cannot_share_expected_tenant_ledger(tmp_path, monkeypatch):
    _audit_keys(monkeypatch, tmp_path / "keys")
    path = tmp_path / "one.jsonl"
    def append(tenant):
        try:
            ledger.append_evidence_event(path, action="synthetic", expected_tenant_id=tenant,
                                         decision={"tenant_id": tenant, "node_id": "n", "policy_hash": "p"})
            return True
        except ledger.LedgerIntegrityError:
            return False
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(append, ["t1", "t2"]))
    assert results.count(True) == 1
    assert len(ledger.verified_ledger_records(path)) == 1


def test_uncertain_commit_stays_consumed_on_reopen(tmp_path, monkeypatch):
    client, body, material, deps = _caller(tmp_path, monkeypatch, "uncertain")
    path = deps.evidence_root / "tenant/t1/live-policy-evidence.jsonl"
    ledger.append_evidence_event(path, action="synthetic-seed", decision={
        "tenant_id": "t1", "node_id": "synthetic", "policy_hash": body["policy_hash"], "decision": "BLOCK"})
    original = path.read_bytes()
    with monkeypatch.context() as fault:
        fault.setattr(ledger.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("synthetic-fsync-failure")))
        response = client.post(live.ENDPOINT_PATH, json=body,
                               headers={"x-usbay-request-identity": json.dumps(material["signed"])})
    assert response.status_code == 503
    _assert_no_grants(response)
    journal = path.with_name(path.name + ".pair-transactions-v1.jsonl")
    pending = journal.read_bytes()
    assert json.loads(pending.splitlines()[-1])["kind"] == "INTENT"
    assert path.read_bytes() == original
    reopened = replace(deps, request_replay_store=RequestIdentityReplayStore(deps.request_replay_store.path))
    monkeypatch.setattr(live, "default_dependencies", lambda: reopened)
    retry = client.post(live.ENDPOINT_PATH, json=body,
                        headers={"x-usbay-request-identity": json.dumps(material["signed"])})
    assert retry.status_code == 409
    assert journal.read_bytes() == pending and path.read_bytes() == original
    assert not ledger.verify_ledger(path)


def test_concurrent_requests_have_one_evidence_winner(tmp_path, monkeypatch):
    client, body, material, deps = _caller(tmp_path, monkeypatch, "concurrent")
    headers = {"x-usbay-request-identity": json.dumps(material["signed"])}
    # Bounded waiting is test-local; all losers must still fail closed.
    deps = replace(deps, request_replay_store=RequestIdentityReplayStore(deps.request_replay_store.path, timeout_seconds=1))
    monkeypatch.setattr(live, "default_dependencies", lambda: deps)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(lambda _: client.post(live.ENDPOINT_PATH, json=body, headers=headers), range(8)))
    assert [r.status_code for r in responses].count(200) == 1
    assert all(r.status_code in {200, 409, 503} for r in responses)
    for response in responses:
        _assert_no_grants(response)
    records = ledger.verified_ledger_records(deps.evidence_root / "tenant/t1/live-policy-evidence.jsonl")
    assert len(records) == 1


@pytest.mark.parametrize("raw,reason", [
    (b'{"x":1,"x":2}', "REQUEST_IDENTITY_DUPLICATE_JSON_KEY"),
    (b'{"input_metadata":{"x":NaN}}', "REQUEST_IDENTITY_JSON_NON_FINITE"),
    (b'{"input_metadata":{"x":1e999}}', "REQUEST_IDENTITY_JSON_NON_FINITE"),
])
def test_strict_json_rejected_before_identity_or_replay(tmp_path, monkeypatch, raw, reason):
    client, body, material, deps = _caller(tmp_path, monkeypatch, "json")
    response = client.post(live.ENDPOINT_PATH, content=raw,
                           headers={"x-usbay-request-identity": json.dumps(material["signed"])})
    assert response.status_code == 401
    assert response.json()["reason_code"] == reason
    _assert_no_grants(response)
    assert not deps.request_replay_store.path.exists()
