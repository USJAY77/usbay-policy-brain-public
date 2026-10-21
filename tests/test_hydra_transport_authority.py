from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3

import pytest

from governance.durable_authority_registries import HUMAN_APPROVAL
from security.hydra_live_client import HydraLiveNodeClient, authorize_hydra_remote_transport
from security.hydra_transport_authority import transport_context, node_transport_context, NoTransportRedirect
from tests.helpers.hydra_transport import configure_transport_authority, NOW, POLICY_HASH
from tests.test_hydra_live_client import authorized_context

pytestmark = [pytest.mark.governance, pytest.mark.regression]


@pytest.fixture
def setup_grant(tmp_path, monkeypatch):
    signed, registry, record = configure_transport_authority(tmp_path, monkeypatch)
    monkeypatch.setattr("security.hydra_live_client.time.time", lambda: NOW)
    return signed(authorized_context()), registry, record


def authorize(context):
    return authorize_hydra_remote_transport(node_id="node1", url="https://hydra.example.test/vote",
                                           request_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", policy_version="policy-v1",
                                           context=context, now=NOW)


def test_signed_grant_consumed_once_across_reopen(setup_grant, tmp_path):
    context, _, _ = setup_grant
    assert authorize(context)["decision"] == "ALLOW"
    with pytest.raises(ValueError, match="authorization_replayed"):
        authorize(context)
    with sqlite3.connect(tmp_path / "replay.db") as conn:
        assert conn.execute("SELECT count(*) FROM hydra_transport_reservations").fetchone() == (1,)
        receipt = json.loads(conn.execute("SELECT receipt FROM hydra_transport_reservations").fetchone()[0])
        assert receipt["state"] == "START_RESERVED"
        assert receipt["policy_hash"] == POLICY_HASH
    raw = (tmp_path / "replay.db").read_bytes()
    assert b"PRIVATE KEY" not in raw and b"https://" not in raw


def test_parallel_grant_has_exactly_one_winner(setup_grant):
    context, _, _ = setup_grant
    def attempt(_):
        try:
            return authorize(context)["decision"]
        except ValueError as exc:
            return str(exc)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(16)))
    assert results.count("ALLOW") == 1
    assert results.count("hydra_remote_transport_authorization_replayed") == 15


@pytest.mark.parametrize("field,value", [
    ("tenant_reference", "sha256:" + "a" * 64),
    ("environment_reference", "sha256:" + "a" * 64),
    ("policy_hash", "sha256:" + "a" * 64),
    ("nonce", "changed"), ("authorization_id", "changed"),
    ("issuer_reference", "sha256:" + "a" * 64),
    ("signature", "00"), ("issued_at", float("nan")),
    ("expires_at", NOW - 1), ("node_id", "node2"),
    ("endpoint_url_hash", "changed"), ("request_hash", "changed"),
    ("policy_version", "changed"), ("decision", "DENY"),
])
def test_tampering_never_reaches_network(setup_grant, monkeypatch, field, value):
    context, _, _ = setup_grant
    context["hydra_remote_transport_authorization"][field] = value
    calls = []
    monkeypatch.setattr("security.hydra_live_client.open_hydra_transport", lambda *a, **k: calls.append(a))
    with pytest.raises(ValueError):
        HydraLiveNodeClient("node1", "https://hydra.example.test/vote").vote(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "policy-v1", context=context)
    assert calls == []


@pytest.mark.parametrize("variable", ["USBAY_GATEWAY_AUTHORITY_REGISTRY", "USBAY_HYDRA_ENVIRONMENT_REFERENCE", "USBAY_HYDRA_TRANSPORT_REPLAY_DB"])
def test_missing_configuration_blocks(setup_grant, monkeypatch, variable):
    context, _, _ = setup_grant
    monkeypatch.delenv(variable)
    with pytest.raises(ValueError):
        authorize(context)


def test_caller_flags_cannot_replace_signature(setup_grant):
    context, _, _ = setup_grant
    mandate = context["hydra_remote_transport_authorization"]
    mandate.pop("signature")
    mandate.update(evidence_verified=True, trust_material_available=True, replayed=False)
    with pytest.raises(ValueError, match="unsigned_or_malformed"):
        authorize(context)


def test_original_unsigned_context_cannot_reach_transport(monkeypatch):
    for name in ("USBAY_GATEWAY_AUTHORITY_REGISTRY", "USBAY_HYDRA_TRANSPORT_REPLAY_DB", "USBAY_HYDRA_ENVIRONMENT_REFERENCE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("security.hydra_live_client.time.time", lambda: NOW)
    calls = []
    monkeypatch.setattr("security.hydra_live_client.open_hydra_transport", lambda *a, **k: calls.append(a))
    client = HydraLiveNodeClient("node1", "https://hydra.example.test/vote")
    for _ in range(2):
        with pytest.raises(ValueError, match="unsigned_or_malformed"):
            client.vote("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "policy-v1", context=authorized_context())
    assert calls == []


def test_cross_tenant_context_blocks_signed_grant(setup_grant):
    context, _, _ = setup_grant
    context["tenant_id"] = "other-tenant"
    with pytest.raises(ValueError, match="tenant_mismatch"):
        authorize(context)


def test_revoked_issuer_blocks_existing_grant(setup_grant):
    context, registry, record = setup_grant
    registry.revoke_authority(HUMAN_APPROVAL, record["authority_reference"],
                              tenant_reference=record["tenant_reference"],
                              environment_reference=record["environment_reference"],
                              reason_code="human_revoked", timestamp="2023-11-14T22:13:25Z")
    with pytest.raises(ValueError, match="issuer_invalid"):
        authorize(context)


def test_wrong_role_cannot_issue_transport(setup_grant):
    context, registry, record = setup_grant
    record["issuer_role"] = "agent"
    registry.update_authority(HUMAN_APPROVAL, record)
    with pytest.raises(ValueError, match="issuer_scope_invalid"):
        authorize(context)


def test_network_failure_keeps_reservation(setup_grant, monkeypatch):
    context, _, _ = setup_grant
    calls = []
    def transport(*args, **kwargs):
        calls.append(args)
        raise TimeoutError("synthetic timeout")
    monkeypatch.setattr("security.hydra_live_client.open_hydra_transport", transport)
    client = HydraLiveNodeClient("node1", "https://hydra.example.test/vote")
    with pytest.raises(TimeoutError):
        client.vote("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "policy-v1", context=context)
    with pytest.raises(ValueError, match="authorization_replayed"):
        client.vote("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "policy-v1", context=context)
    assert len(calls) == 1


def test_detached_grant_selected_by_request_and_node(setup_grant, tmp_path, monkeypatch):
    context, _, _ = setup_grant
    path = tmp_path / "grants.json"
    path.write_text(json.dumps({"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {"node1": context["hydra_remote_transport_authorization"]}}))
    monkeypatch.setenv("USBAY_HYDRA_TRANSPORT_MANDATES_PATH", str(path))
    selected = node_transport_context(transport_context({"tenant_id": "test-tenant", "policy_hash": POLICY_HASH}, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "node1")
    assert authorize(selected)["decision"] == "ALLOW"
    absent = node_transport_context(transport_context({}, "other-request"), "node1")
    with pytest.raises(ValueError, match="authorization_missing"):
        authorize(absent)


def test_gateway_delivers_detached_grant_and_blocks_second_transport(setup_grant, tmp_path, monkeypatch):
    import gateway.app as gateway
    from security.hydra_node_service import build_vote_response
    context, _, _ = setup_grant
    path = tmp_path / "grants.json"
    path.write_text(json.dumps({"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {"node1": context["hydra_remote_transport_authorization"]}}))
    monkeypatch.setenv("USBAY_HYDRA_TRANSPORT_MANDATES_PATH", str(path))
    monkeypatch.setattr(gateway, "hydra_node_clients", [HydraLiveNodeClient("node1", "https://hydra.example.test/vote")])
    monkeypatch.setattr(gateway, "hydra_live_mode_enabled", lambda: True)
    calls = []
    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read(self):
            return json.dumps(build_vote_response(node_id="node1", decision="ALLOW", request_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", policy_version="policy-v1")).encode()
    def transport(req, **kwargs):
        calls.append(req)
        # Transport evidence is local and must not be forwarded to the node.
        assert "hydra_remote_transport_authorization" not in json.loads(req.data)["context"]
        return Response()
    monkeypatch.setattr("security.hydra_live_client.open_hydra_transport", transport)
    clean_context = {"tenant_id": "test-tenant", "policy_hash": POLICY_HASH.removeprefix("sha256:")}
    first = gateway.evaluate_hydra_request("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "policy-v1", context=clean_context)
    assert first.votes_allow == 1
    assert gateway.evaluate_hydra_request("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "policy-v1", context=clean_context).votes_allow == 0
    assert len(calls) == 1


def test_redirect_is_not_authorized_by_original_endpoint():
    with pytest.raises(ValueError, match="redirect_blocked"):
        NoTransportRedirect().redirect_request(None, None, 302, "Found", {}, "https://other.test/")


@pytest.mark.parametrize("failure", ["corrupt", "missing_parent", "directory"])
def test_storage_failure_blocks_before_transport(setup_grant, monkeypatch, tmp_path, failure):
    context, _, _ = setup_grant
    path = tmp_path / "invalid"
    if failure == "corrupt":
        path.write_bytes(b"not a database")
    elif failure == "directory":
        path.mkdir()
    else:
        path = path / "missing.db"
    monkeypatch.setenv("USBAY_HYDRA_TRANSPORT_REPLAY_DB", str(path))
    calls = []
    monkeypatch.setattr("security.hydra_live_client.open_hydra_transport", lambda *a, **k: calls.append(a))
    with pytest.raises(ValueError, match="trust_unavailable"):
        HydraLiveNodeClient("node1", "https://hydra.example.test/vote").vote("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "policy-v1", context=context)
    assert calls == []


def test_failed_commit_prevents_transport(setup_grant, monkeypatch):
    context, _, _ = setup_grant
    original_connect = sqlite3.connect
    class FailedCommit:
        def __init__(self, *args, **kwargs):
            self.conn = original_connect(*args, **kwargs)
        def execute(self, *args):
            return self.conn.execute(*args)
        def commit(self):
            raise sqlite3.OperationalError("synthetic failure")
        def close(self):
            self.conn.close()
    monkeypatch.setattr("security.hydra_transport_authority.sqlite3.connect", FailedCommit)
    calls = []
    monkeypatch.setattr("security.hydra_live_client.open_hydra_transport", lambda *a, **k: calls.append(a))
    with pytest.raises(ValueError, match="trust_unavailable"):
        HydraLiveNodeClient("node1", "https://hydra.example.test/vote").vote("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "policy-v1", context=context)
    assert calls == []


@pytest.mark.parametrize("field,value", [("allowed_node_ids", []), ("allowed_endpoint_hashes", []), ("ai_generated_only", True)])
def test_authoritative_scope_restrictions_win(setup_grant, field, value):
    context, registry, record = setup_grant
    record[field] = value
    registry.update_authority(HUMAN_APPROVAL, record)
    with pytest.raises(ValueError):
        authorize(context)


@pytest.mark.parametrize("field", ["allowed_node_ids", "allowed_endpoint_hashes"])
@pytest.mark.parametrize("container", ["string", "mapping"])
def test_malformed_scope_is_not_an_allowlist(setup_grant, field, container):
    context, registry, record = setup_grant
    value = record[field][0]
    record[field] = "prefix" + value + "suffix" if container == "string" else {value: True}
    registry.update_authority(HUMAN_APPROVAL, record)
    with pytest.raises(ValueError, match="issuer_scope_invalid"):
        authorize(context)


@pytest.mark.parametrize("expiry", ["mandate", "issuer", "commit"])
def test_expiry_during_storage_wait_blocks_network(setup_grant, monkeypatch, expiry):
    import time
    from datetime import datetime, timezone
    context, registry, record = setup_grant
    clock = [NOW]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    if expiry == "issuer":
        record["expires_at"] = datetime.fromtimestamp(NOW + 1, timezone.utc).isoformat()
        registry.update_authority(HUMAN_APPROVAL, record)
    original_connect = sqlite3.connect
    class DelayedStorage:
        def __init__(self, *args, **kwargs):
            self.conn = original_connect(*args, **kwargs)
        def execute(self, sql, *args):
            result = self.conn.execute(sql, *args)
            if sql == "BEGIN IMMEDIATE" and expiry != "commit":
                clock[0] += 51 if expiry == "mandate" else 2
            return result
        def commit(self):
            self.conn.commit()
            if expiry == "commit":
                clock[0] += 51
        def close(self):
            self.conn.close()
    monkeypatch.setattr("security.hydra_transport_authority.sqlite3.connect", DelayedStorage)
    calls = []
    monkeypatch.setattr("security.hydra_live_client.open_hydra_transport", lambda *a, **k: calls.append(a))
    with pytest.raises(ValueError):
        HydraLiveNodeClient("node1", "https://hydra.example.test/vote").vote(
            "a" * 64, "policy-v1", context=context)
    assert calls == []


def test_transport_preserves_configured_proxy(monkeypatch):
    from urllib import request
    from security.hydra_transport_authority import open_hydra_transport
    proxy = {"https": "http://synthetic-proxy.invalid:8080"}
    monkeypatch.setattr(request, "getproxies", lambda: proxy)
    def opened(opener, req, **kwargs):
        proxies = [handler.proxies for handler in opener.handlers if isinstance(handler, request.ProxyHandler)]
        assert proxies == [proxy]
        assert any(isinstance(handler, NoTransportRedirect) for handler in opener.handlers)
        return "mock-response"
    monkeypatch.setattr(request.OpenerDirector, "open", opened)
    assert open_hydra_transport(request.Request("https://hydra.example.test/vote"), timeout=1) == "mock-response"


def test_issuer_expiry_during_registry_read_blocks_transport(setup_grant, monkeypatch):
    import time
    from datetime import datetime, timezone
    from governance.durable_authority_registries import DurableAuthorityRegistry
    context, registry, record = setup_grant
    record["expires_at"] = datetime.fromtimestamp(NOW + 1, timezone.utc).isoformat()
    registry.update_authority(HUMAN_APPROVAL, record)
    clock = [NOW]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    original = DurableAuthorityRegistry._latest
    def delayed_read(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        clock[0] += 2
        return result
    monkeypatch.setattr(DurableAuthorityRegistry, "_latest", delayed_read)
    calls = []
    monkeypatch.setattr("security.hydra_live_client.open_hydra_transport", lambda *a, **k: calls.append(a))
    with pytest.raises(ValueError, match="issuer_invalid"):
        HydraLiveNodeClient("node1", "https://hydra.example.test/vote").vote(
            "a" * 64, "policy-v1", context=context)
    assert calls == []


@pytest.mark.parametrize("client_kind", ["live", "remote"])
def test_transport_uses_the_authorized_snapshot(tmp_path, monkeypatch, client_kind):
    from tests.helpers.hydra_transport import configure_transport_authority
    from security.hydra_node_service import build_vote_response
    from security.hydra_nodes import RemoteHydraNode
    from security import hydra_live_client, hydra_nodes
    sign, _, _ = configure_transport_authority(tmp_path, monkeypatch)
    node_id = "node1" if client_kind == "live" else "node-3"
    url = "https://hydra.example.test/" + ("vote" if client_kind == "live" else "evaluate")
    context = sign(authorized_context(node_id=node_id, url=url))
    context["metadata"] = {"value": "original"}
    module = hydra_live_client if client_kind == "live" else hydra_nodes
    client = HydraLiveNodeClient(node_id, url) if client_kind == "live" else RemoteHydraNode(url, node_id)
    real_authorize = module.authorize_hydra_remote_transport
    def authorize_then_mutate(**kwargs):
        result = real_authorize(**kwargs)
        client.url = "https://unapproved.example.test/"
        client.node_id = "other-node"
        kwargs["context"]["metadata"]["value"] = "mutated"
        return result
    monkeypatch.setattr(module, "authorize_hydra_remote_transport", authorize_then_mutate)
    response = build_vote_response(node_id=node_id, decision="ALLOW", request_hash="a" * 64, policy_version="policy-v1")
    if client_kind == "remote":
        response = dict(node_id=node_id, node_role="offline_backup", request_hash="a" * 64,
                        policy_version="policy-v1", decision="allow", reason="synthetic", timestamp=NOW)
    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read(self):
            return json.dumps(response).encode()
    def transport(req, **kwargs):
        assert req.full_url == url
        assert json.loads(req.data)["context"]["metadata"] == {"value": "original"}
        return Response()
    monkeypatch.setattr(module, "open_hydra_transport", transport)
    if client_kind == "live":
        assert client.vote("a" * 64, "policy-v1", context=context)["valid"] is True
    else:
        assert client.evaluate("a" * 64, "policy-v1", context=context).node_id == node_id


@pytest.mark.parametrize("scenario", ["valid", "swapped_node", "bad_request_signature", "wrong_tenant"])
def test_signed_gateway_request_with_independent_transport_quorum(tmp_path, monkeypatch, scenario):
    import time
    import gateway.app as gateway
    from security.hydra_node_service import build_vote_response
    from security.decision_store import verify_decision_signatures
    from tests.test_gateway_hydra import configure_gateway, build_payload, sign_payload
    from tests.test_hydra_live_client import remote_authorization

    # Reuse the established signed runtime/request/attestation fixtures. Keep
    # actual Gateway validation, remote clients, authority checks and consensus.
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="http-quorum-" + scenario)
    sign_payload(payload)
    request_hash = gateway.request_hash(gateway.request_signature_message(payload))
    policy = gateway.load_policy_registry(provenance_context=gateway.runtime_provenance_context())
    policy_ref = "sha256:" + policy["policy_hash"].removeprefix("sha256:")
    now = time.time()
    sign, _, _ = configure_transport_authority(
        tmp_path, monkeypatch, tenant="other-tenant" if scenario == "wrong_tenant" else "t1",
        policy_hash=policy_ref, now=now, node_ids=("node1", "node2", "node3"),
    )
    url = "https://hydra.example.test/vote"
    grants = {}
    for node in ("node1", "node2"):
        mandate = remote_authorization(node_id=node, url=url, request_hash=request_hash,
                                       policy_version=payload["policy_version"],
                                       issued_at=now - 1, expires_at=now + 60)
        mandate["authorization_id"] = "http-quorum-" + node
        grants[node] = sign({"hydra_remote_transport_authorization": mandate},
                            nonce="independent-transport-nonce-" + node)["hydra_remote_transport_authorization"]
    assert grants["node1"]["authorization_id"] != grants["node2"]["authorization_id"]
    assert grants["node1"]["nonce"] != grants["node2"]["nonce"]
    if scenario == "swapped_node":
        grants["node2"] = dict(grants["node1"])
    grant_file = tmp_path / "http-grants.json"
    grant_file.write_text(json.dumps({request_hash: grants}))
    monkeypatch.setenv("USBAY_HYDRA_TRANSPORT_MANDATES_PATH", str(grant_file))
    monkeypatch.setenv("USBAY_HYDRA_BACKEND", "services")
    monkeypatch.setattr(gateway, "hydra_node_clients",
                        [HydraLiveNodeClient(node, url) for node in ("node1", "node2", "node3")])
    calls = []
    class Response:
        def __init__(self, vote):
            self.vote = vote
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read(self):
            return json.dumps(self.vote).encode()
    def transport(req, **kwargs):
        index = len(calls)
        calls.append("unexpected")
        assert index < 2, "ungranted third transport"
        body = json.loads(req.data)
        assert body["request_hash"] == request_hash
        assert body["context"]["tenant_id"] == "t1"
        assert "hydra_remote_transport_authorization" not in body["context"]
        node = ("node1", "node2")[index]
        calls[index] = node
        return Response(build_vote_response(node_id=node, decision="ALLOW", request_hash=request_hash,
                                            policy_version=payload["policy_version"]))
    monkeypatch.setattr("security.hydra_live_client.open_hydra_transport", transport)
    if scenario == "bad_request_signature":
        payload["signature"] = "00"

    response = client.post("/decide", json=payload)
    assert response.status_code == (403 if scenario == "bad_request_signature" else 200), response.json()
    assert response.json()["decision"] == ("ALLOW" if scenario == "valid" else "DENY"), response.json()
    expected_calls = 2 if scenario == "valid" else 1 if scenario == "swapped_node" else 0
    assert len(calls) == expected_calls

    if scenario == "valid":
        record = gateway.decision_store.load_decision(response.json()["decision_id"])
        assert record["request_hash"] == request_hash
        assert record["tenant_id"] == "t1"
        assert verify_decision_signatures(record)
        events = [e for e in gateway.audit_chain.load() if e.get("action") == "consensus_allow"]
        assert events[-1]["decision"]["votes_allow"] == 2
        assert events[-1]["decision"]["consensus"] is True
        assert events[-1]["decision"]["tenant_id"] == "t1"
        assert events[-1]["decision"]["tenant_hash"] == gateway.tenant_execution_context("t1")["tenant_hash"]
        assert gateway.audit_chain.verify()
        with sqlite3.connect(tmp_path / "replay.db") as conn:
            receipts = [json.loads(row[0]) for row in conn.execute("SELECT receipt FROM hydra_transport_reservations")]
        assert {receipt["node_id"] for receipt in receipts} == {"node1", "node2"}
        assert {receipt["request_hash"] for receipt in receipts} == {request_hash}
        # HTTP request replay must fail before initiating another transport.
        replay = client.post("/decide", json=payload)
        assert replay.status_code == 403
        assert replay.json()["reason"] == "replay_detected"
        assert len(calls) == 2
        # Independently prove that transport grants cannot be re-used even if
        # an internal caller tries the consensus path again.
        repeated = gateway.evaluate_hydra_request(request_hash, payload["policy_version"],
                                                  context={"tenant_id": "t1", "policy_hash": policy["policy_hash"]})
        assert repeated.final_decision == "deny"
        assert len(calls) == 2
