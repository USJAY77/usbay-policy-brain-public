import time

import pytest
from fastapi.testclient import TestClient

from audit.hash_chain import AuditHashChain
from gateway import app as gateway_app
from security.decision_store import DecisionStoreTestDouble
from security.evidence_export_authorization import (
    EVIDENCE_EXPORT_AUDIENCE,
    EvidenceExportCredentialDenied,
    EvidenceExportIdentityAuthorityUnavailable,
)


ROUTES = (
    "/audit/export/{decision_id}",
    "/audit/bundle/{decision_id}",
    "/replay/export/{decision_id}",
)


def _record(decision_id: str, tenant_id: str) -> dict:
    return {
        "decision_id": decision_id,
        "tenant_id": tenant_id,
        "tenant_hash": f"hash-{tenant_id}",
        "decision": "allow",
        "request_hash": f"request-{decision_id}",
        "policy_version": "policy-v1",
        "policy_hash": "a" * 64,
        "policy_pubkey_id": "policy-key",
        "signature_valid": True,
        "decision_signature": "synthetic-signature",
        "expires_at_epoch": int(time.time()) + 600,
        "nonce_hash": f"nonce-{decision_id}",
        "gateway_id": "gateway-test",
        "previous_hash": "GENESIS",
        "audit_hash": f"audit-{decision_id}",
        "alg_version": "v1",
    }


def _principal(tenant_id="t1", **overrides):
    principal = {
        "subject_id": f"subject-{tenant_id}",
        "tenant_id": tenant_id,
        "audience": EVIDENCE_EXPORT_AUDIENCE,
        "scopes": ["evidence:read"],
        "expires_at_epoch": int(time.time()) + 600,
        "revoked": False,
        "rotation_state": "ROTATION_CURRENT",
        "credential_id": f"credential-{tenant_id}",
    }
    principal.update(overrides)
    return principal


@pytest.fixture
def export_context(tmp_path, monkeypatch):
    store = DecisionStoreTestDouble()
    audit = AuditHashChain(tmp_path / "export_access_audit.json")
    monkeypatch.setattr(gateway_app, "decision_store", store)
    monkeypatch.setattr(gateway_app, "audit_chain", audit)
    monkeypatch.setattr(gateway_app, "audit_export_file", tmp_path / "legacy_export.jsonl")
    client = TestClient(gateway_app.app, raise_server_exceptions=False)
    return client, store, audit


def _install_verifier(monkeypatch, principals):
    def verify(credential, *, required_audience, required_scope):
        assert required_audience == EVIDENCE_EXPORT_AUDIENCE
        assert required_scope == "evidence:read"
        result = principals.get(credential)
        if isinstance(result, Exception):
            raise result
        if result is None:
            raise EvidenceExportCredentialDenied("credential_denied")
        return result

    monkeypatch.setattr(gateway_app, "evidence_export_identity_verifier", verify)


def _get(client, route, decision_id, token=None, *, follow_redirects=True):
    headers = {"authorization": f"Bearer {token}"} if token is not None else {}
    return client.get(
        route.format(decision_id=decision_id),
        headers=headers,
        follow_redirects=follow_redirects,
    )


@pytest.mark.parametrize("route", ROUTES)
def test_missing_credential_denies_before_record_lookup(export_context, monkeypatch, route):
    client, store, audit = export_context
    store.records["decision-t1"] = _record("decision-t1", "t1")
    monkeypatch.setattr(
        store,
        "load_decision",
        lambda _decision_id: pytest.fail("protected record lookup occurred before authentication"),
    )

    response = _get(client, route, "decision-t1")

    assert response.status_code == 403
    assert response.json()["reason"] == "EVIDENCE_EXPORT_ACCESS_DENIED"
    assert response.json()["evidence_released"] is False
    denial = audit.load()[-1]["decision"]
    assert denial["identity_status"] == "UNAUTHENTICATED"
    assert "subject_id" not in denial


@pytest.mark.parametrize(
    ("token", "principal"),
    (
        ("forged", EvidenceExportCredentialDenied("credential_denied")),
        ("expired", _principal(expires_at_epoch=1)),
        ("revoked", _principal(revoked=True)),
        ("scope", _principal(scopes=["intake:read"])),
        ("audience", _principal(audience="other-service")),
        ("rotation", _principal(rotation_state="ROTATION_EXPIRED")),
    ),
)
def test_invalid_credential_claims_are_uniformly_denied(export_context, monkeypatch, token, principal):
    client, store, _ = export_context
    store.records["decision-t1"] = _record("decision-t1", "t1")
    _install_verifier(monkeypatch, {token: principal})

    responses = [_get(client, route, "decision-t1", token) for route in ROUTES]

    assert {(response.status_code, response.json()["reason"]) for response in responses} == {
        (403, "EVIDENCE_EXPORT_ACCESS_DENIED")
    }


def test_unavailable_identity_authority_fails_closed_without_lookup(export_context, monkeypatch):
    client, store, _ = export_context
    monkeypatch.setattr(
        gateway_app,
        "evidence_export_identity_verifier",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            EvidenceExportIdentityAuthorityUnavailable("identity_authority_unavailable")
        ),
    )
    monkeypatch.setattr(
        store,
        "load_decision",
        lambda _decision_id: pytest.fail("record lookup occurred while identity authority was unavailable"),
    )

    response = _get(client, ROUTES[0], "decision-t1", "opaque")

    assert response.status_code == 503
    assert response.json()["reason"] == "EVIDENCE_EXPORT_IDENTITY_AUTHORITY_UNAVAILABLE"


@pytest.mark.parametrize("route", ROUTES)
def test_unknown_and_wrong_tenant_ids_have_equivalent_external_denial(export_context, monkeypatch, route):
    client, store, audit = export_context
    store.records["decision-t2"] = _record("decision-t2", "t2")
    _install_verifier(monkeypatch, {"valid-t1": _principal("t1")})

    unknown = _get(client, route, "missing", "valid-t1")
    foreign = _get(client, route, "decision-t2", "valid-t1")

    assert unknown.status_code == foreign.status_code == 404
    assert unknown.json() == foreign.json()
    authenticated_denials = [
        event["decision"]
        for event in audit.load()
        if event["decision"].get("reason") == "EVIDENCE_EXPORT_NOT_AVAILABLE"
    ]
    assert len(authenticated_denials) == 2
    assert all(item["identity_status"] == "AUTHENTICATED" for item in authenticated_denials)
    assert all(item["tenant_id"] == "t1" for item in authenticated_denials)


@pytest.mark.parametrize("route", ROUTES)
def test_mixed_tenant_constituents_are_denied(export_context, monkeypatch, route):
    client, store, _ = export_context
    store.records["decision-t1"] = _record("decision-t1", "t1")
    store.records["decision-t2"] = _record("decision-t2", "t2")
    _install_verifier(monkeypatch, {"valid-t2": _principal("t2")})

    response = _get(client, route, "decision-t2", "valid-t2")

    assert response.status_code == 404
    assert response.json()["reason"] == "EVIDENCE_EXPORT_NOT_AVAILABLE"


@pytest.mark.parametrize("route", ROUTES)
def test_foreign_nested_consensus_constituent_is_denied(export_context, monkeypatch, route):
    client, store, _ = export_context
    record = _record("decision-t1", "t1")
    record["consensus_evidence_bundle"] = {
        "tenant_id": "t1",
        "nodes": [{"node_id": "foreign-node", "tenant_id": "t2"}],
        "attestation_evidence": [],
    }
    store.records["decision-t1"] = record
    _install_verifier(monkeypatch, {"valid-t1": _principal("t1")})

    response = _get(client, route, "decision-t1", "valid-t1")

    assert response.status_code == 404
    assert response.json()["reason"] == "EVIDENCE_EXPORT_NOT_AVAILABLE"


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize(
    "consensus_evidence",
    (
        {"tenant_id": "t1", "nodes": "not-a-list", "attestation_evidence": []},
        {"tenant_id": "t1", "nodes": ["not-a-record"], "attestation_evidence": []},
        {"tenant_id": "t1", "nodes": [], "attestation_evidence": "not-a-list"},
        {"tenant_id": "t1", "nodes": [], "attestation_evidence": ["not-a-record"]},
        {
            "tenant_id": "t1",
            "nodes": [],
            "attestation_evidence": [],
            "deployment_provenance": {"tenant_id": "t2"},
        },
        {
            "tenant_id": "t1",
            "nodes": [],
            "attestation_evidence": [],
            "deployment_provenance": {"runtime": {"tenant_id": "t2"}},
        },
        {
            "tenant_id": "t1",
            "nodes": [],
            "attestation_evidence": [],
            "deployment_provenance": "not-a-record",
        },
    ),
)
def test_malformed_or_foreign_nested_constituents_fail_closed(
    export_context,
    monkeypatch,
    route,
    consensus_evidence,
):
    client, store, _ = export_context
    record = _record("decision-t1", "t1")
    record["consensus_evidence_bundle"] = consensus_evidence
    store.records["decision-t1"] = record
    _install_verifier(monkeypatch, {"valid-t1": _principal("t1")})

    response = _get(client, route, "decision-t1", "valid-t1")

    assert response.status_code == 404
    assert response.json()["reason"] == "EVIDENCE_EXPORT_NOT_AVAILABLE"


@pytest.mark.parametrize("route", ROUTES)
def test_valid_tenant_bound_export_contains_only_permitted_tenant(
    export_context,
    monkeypatch,
    route,
):
    client, store, audit = export_context
    store.records["decision-t1"] = _record("decision-t1", "t1")
    _install_verifier(monkeypatch, {"valid-t1": _principal("t1")})

    response = _get(client, route, "decision-t1", "valid-t1")

    assert response.status_code == 200
    body = response.json()
    assert body["decision_id"] == "decision-t1"
    assert body["records"]
    assert {record["tenant_id"] for record in body["records"]} == {"t1"}
    success = audit.load()[-1]["decision"]
    assert success["outcome"] == "ALLOWED"
    assert success["tenant_id"] == "t1"


def test_replay_export_integrity_is_preserved(export_context, monkeypatch):
    client, store, _ = export_context
    store.records["decision-t1"] = _record("decision-t1", "t1")
    _install_verifier(monkeypatch, {"valid-t1": _principal("t1")})

    first = _get(client, ROUTES[2], "decision-t1", "valid-t1").json()
    second = _get(client, ROUTES[2], "decision-t1", "valid-t1").json()

    assert first["replay_hash"] == second["replay_hash"]
    assert first == second


@pytest.mark.parametrize("route", ROUTES)
def test_successful_export_fails_closed_when_access_audit_is_unavailable(
    export_context,
    monkeypatch,
    route,
):
    client, store, audit = export_context
    store.records["decision-t1"] = _record("decision-t1", "t1")
    _install_verifier(monkeypatch, {"valid-t1": _principal("t1")})
    monkeypatch.setattr(
        audit,
        "append_event",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("audit unavailable")),
    )

    response = _get(client, route, "decision-t1", "valid-t1")

    assert response.status_code == 503
    assert response.json()["reason"] == "EVIDENCE_EXPORT_AUDIT_UNAVAILABLE"
    assert response.json()["evidence_released"] is False


def test_denied_legacy_export_has_no_signing_timestamp_or_export_file_side_effect(
    export_context,
    monkeypatch,
    tmp_path,
):
    client, _, audit = export_context
    event = audit.append_event(
        "execution_governance",
        {"tenant_id": "t1", "decision": "allow"},
    )
    export_file = tmp_path / "legacy_export.jsonl"
    monkeypatch.setattr(gateway_app, "audit_export_file", export_file)
    monkeypatch.setattr(
        gateway_app,
        "export_audit_event",
        lambda *_args, **_kwargs: pytest.fail("legacy export signing/timestamping occurred after denial"),
    )

    response = _get(client, ROUTES[0], event["hash_current"])

    assert response.status_code == 403
    assert not export_file.exists()


@pytest.mark.parametrize("route", ROUTES)
def test_trailing_slash_reaches_same_authorization_boundary(export_context, route):
    client, _, _ = export_context

    denied = _get(
        client,
        route + "/",
        "decision-t1",
        follow_redirects=False,
    )

    assert denied.status_code == 403
    assert denied.json()["reason"] == "EVIDENCE_EXPORT_ACCESS_DENIED"


def test_openapi_declares_bearer_security_and_denial_contracts(export_context):
    client, _, _ = export_context

    spec = client.get("/openapi.json").json()

    assert spec["components"]["securitySchemes"]["EvidenceExportBearer"] == {
        "type": "http",
        "description": "Tenant-bound bearer credential with evidence:read scope.",
        "scheme": "bearer",
    }
    for route in ROUTES:
        canonical = route.format(decision_id="{decision_id}")
        if canonical.startswith("/audit/export/"):
            canonical = "/audit/export/{audit_id}"
        operation = spec["paths"][canonical]["get"]
        assert operation["security"] == [{"EvidenceExportBearer": []}]
        assert {"403", "404", "503"}.issubset(operation["responses"])
        assert canonical + "/" not in spec["paths"]