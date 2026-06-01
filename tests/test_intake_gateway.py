import json
import time

from fastapi.testclient import TestClient

import gateway.app as gateway_app
import intake.gateway as intake_gateway


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.expiry = {}

    def incr(self, key):
        self.values[key] = self.values.get(key, 0) + 1
        return self.values[key]

    def expire(self, key, seconds):
        self.expiry[key] = seconds
        return True

    def ttl(self, key):
        return self.expiry.get(key, 3600)

    def ping(self):
        return True


def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("USBAY_INTAKE_STORAGE_DIR", str(tmp_path / "intake-store"))
    admin_token = "test-admin-token"
    identity = {
        "identity_id": "test-admin",
        "token_sha256": intake_gateway.sha256_text(admin_token),
        "role": "intake_admin",
        "key_version": "test-v2",
        "status": "ACTIVE",
        "rotates_after_epoch": int(time.time()) + 86400,
    }
    monkeypatch.setenv("USBAY_INTAKE_ADMIN_IDENTITIES_JSON", json.dumps([identity]))
    monkeypatch.setenv("USBAY_INTAKE_EMAIL_TRANSPORT", "GOVERNED_OUTBOX")
    fake = FakeRedis()
    intake_gateway.set_redis_client_for_tests(fake)
    monkeypatch.setattr(intake_gateway, "_redis_client_override", fake)
    return TestClient(gateway_app.app, raise_server_exceptions=False)


def _valid_payload():
    return {
        "organization": "Example Enterprise",
        "contact_name": "Governance Owner",
        "contact_email": "governance.owner@example.com",
        "role": "AI Governance Lead",
        "governance_scope": "Assessment of AI-assisted workflow controls before enterprise deployment.",
        "regulated_industry": True,
        "high_risk_ai": True,
        "policy_validation_required": True,
        "human_oversight_required": True,
        "audit_evidence_required": True,
        "provenance_required": True,
        "fail_closed_required": True,
        "target_timeline": "30-60 days",
    }


def _jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_intake_static_page_is_governance_first_without_marketing_language(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    response = client.get("/intake")

    assert response.status_code == 200
    assert "Governance Assessment Request" in response.text
    assert "/intake/api" in response.text
    assert "AI magic" not in response.text
    assert "autonomous" not in response.text.lower()


def test_valid_intake_submission_stores_notification_and_redacted_audit(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    response = client.post("/intake/api", json=_valid_payload())

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "ACCEPTED_FOR_GOVERNANCE_REVIEW"
    assert body["risk_level"] == "HIGH"
    assert body["notification_recipients"] == ["governance@usbay.global", "pilot@usbay.global", "audit@usbay.global"]
    assert body["notification_status"] == "QUEUED_GOVERNED_OUTBOX"
    assert body["storage_backend"] == "SQLITE_DURABLE"
    assert body["audit_storage"] == "WORM_APPEND_ONLY_HASH_CHAIN"
    assert body["rate_limit_backend"] == "REDIS"

    store = tmp_path / "intake-store"
    admin = client.get("/intake/admin", headers={"x-usbay-admin-token": "test-admin-token"}).json()
    submissions = admin["submissions"]
    notifications = admin["notifications"]
    audit = admin["audit"]["events"]
    assert len(submissions) == 1
    assert len(notifications) == 3
    assert len(audit) == 2
    assert submissions[0]["submission"]["contact_email"] == "governance.owner@example.com"
    assert audit[0]["contact_email_hash"]
    assert "governance.owner@example.com" not in json.dumps(audit[0])
    assert audit[0]["actor"] == "public_intake_gateway"
    assert audit[0]["device"] == "usbay-intake-static-mvp"
    assert audit[0]["policy_version"] == "usbay.intake_gateway.phase1.v1"
    assert audit[1]["schema"] == "usbay.intake_admin_access_audit.worm.v1"
    assert audit[1]["admin_action"] == "/intake/admin"
    assert audit[1]["decision"] == "ADMIN_ACCESS_GRANTED"


def test_missing_required_intake_field_fails_closed_without_storage(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    payload = _valid_payload()
    payload.pop("contact_email")

    response = client.post("/intake/api", json=payload)

    assert response.status_code == 422
    assert response.json()["decision"] == "BLOCKED"
    assert response.json()["reason"] == "INTAKE_REQUIRED_FIELD_MISSING:contact_email"
    assert not (tmp_path / "intake-store" / "intake.db").exists()


def test_fail_closed_control_must_be_explicitly_required(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    payload = _valid_payload()
    payload["fail_closed_required"] = False

    response = client.post("/intake/api", json=payload)

    assert response.status_code == 422
    assert response.json()["decision"] == "BLOCKED"
    assert response.json()["reason"] == "INTAKE_FAIL_CLOSED_REQUIRED"
    assert not (tmp_path / "intake-store" / "audit.worm.jsonl").exists()


def test_intake_audit_export_verifies_hash_chain(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    first = _valid_payload()
    second = _valid_payload() | {
        "organization": "Second Enterprise",
        "contact_email": "risk.owner@example.com",
        "governance_scope": "Review of AI workflow policy validation, audit evidence, and provenance controls.",
    }

    assert client.post("/intake/api", json=first).status_code == 200
    assert client.post("/intake/api", json=second).status_code == 200
    response = client.get("/intake/audit", headers={"x-usbay-admin-token": "test-admin-token"})

    assert response.status_code == 200
    body = response.json()
    assert body["chain_valid"] is True
    assert body["event_count"] == 3
    assert body["events"][1]["previous_hash"] == body["events"][0]["audit_hash"]
    assert body["events"][2]["admin_action"] == "/intake/audit"
    assert body["storage_backend"] == "WORM_APPEND_ONLY_HASH_CHAIN"


def test_intake_audit_requires_admin_token(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    assert client.post("/intake/api", json=_valid_payload()).status_code == 200

    response = client.get("/intake/audit")

    assert response.status_code == 403
    assert response.json()["decision"] == "BLOCKED"
    assert response.json()["reason"] == "INTAKE_ADMIN_AUTH_REQUIRED"


def test_intake_admin_view_returns_records_with_retention_and_email_policy(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    assert client.post("/intake/api", json=_valid_payload()).status_code == 200

    response = client.get("/intake/admin", headers={"x-usbay-admin-token": "test-admin-token"})

    assert response.status_code == 200
    body = response.json()
    assert body["submission_count"] == 1
    assert body["storage_backend"] == "SQLITE_DURABLE"
    assert body["rate_limit_backend"] == "REDIS"
    assert body["audit_chain_valid"] is True
    assert body["retention_policy"]["retention_days"] == 365
    assert body["email_delivery_policy"]["recipients"] == ["governance@usbay.global", "pilot@usbay.global", "audit@usbay.global"]
    assert body["email_delivery_policy"]["transport_mode"] == "GOVERNED_OUTBOX"
    assert body["admin_identity_policy"]["key_rotation_required"] is True
    assert body["admin_identity_policy"]["identities"][0]["rotates_after_epoch"] > int(time.time())
    assert body["submissions"][0]["retention_until_epoch"] > body["submissions"][0]["created_at_epoch"]


def test_public_intake_rate_limit_blocks_excess_requests(tmp_path, monkeypatch):
    monkeypatch.setenv("USBAY_INTAKE_RATE_LIMIT_MAX_REQUESTS", "1")
    client = _client(tmp_path, monkeypatch)

    assert client.post("/intake/api", json=_valid_payload()).status_code == 200
    payload = _valid_payload()
    payload["contact_email"] = "second@example.com"

    response = client.post("/intake/api", json=payload)

    assert response.status_code == 422
    assert response.json()["decision"] == "BLOCKED"
    assert response.json()["reason"] == "INTAKE_RATE_LIMIT_EXCEEDED"


def test_ungoverned_email_transport_fails_closed(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    monkeypatch.setenv("USBAY_INTAKE_EMAIL_TRANSPORT", "SMTP")

    response = client.post("/intake/api", json=_valid_payload())

    assert response.status_code == 422
    assert response.json()["decision"] == "BLOCKED"
    assert response.json()["reason"] == "INTAKE_EMAIL_POLICY_UNGOVERNED_TRANSPORT"


def test_phase2_readiness_passes_for_controlled_review_with_governed_controls(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    response = client.get("/intake/readiness", headers={"x-usbay-admin-token": "test-admin-token"})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "READY_FOR_CONTROLLED_PHASE2_REVIEW"
    assert body["decision"] == "ALLOW_CONTROLLED_REVIEW"
    assert body["production_claim"] is False
    assert body["external_network_delivery_enabled"] is False
    assert body["failure_reasons"] == []
    assert {check["name"] for check in body["checks"]} == {
        "durable_datastore",
        "worm_audit_evidence",
        "distributed_rate_limit",
        "governed_email_delivery",
        "governed_admin_identity",
        "retention_policy",
    }


def test_phase2_readiness_fails_closed_without_admin_rotation_evidence(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    identity = {
        "identity_id": "test-admin",
        "token_sha256": intake_gateway.sha256_text("test-admin-token"),
        "role": "intake_admin",
        "key_version": "test-v2",
        "status": "ACTIVE",
    }
    monkeypatch.setenv("USBAY_INTAKE_ADMIN_IDENTITIES_JSON", json.dumps([identity]))

    response = client.get("/intake/readiness", headers={"x-usbay-admin-token": "test-admin-token"})

    assert response.status_code == 503
    assert response.json()["status"] == "BLOCKED"
    assert "INTAKE_ADMIN_KEY_ROTATION_EVIDENCE_REQUIRED" in response.json()["failure_reasons"]


def test_phase2_readiness_fails_closed_when_redis_unavailable(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    intake_gateway.set_redis_client_for_tests(None)
    monkeypatch.setattr(intake_gateway, "_redis_client_override", None)

    response = client.get("/intake/readiness", headers={"x-usbay-admin-token": "test-admin-token"})

    assert response.status_code == 503
    assert response.json()["status"] == "BLOCKED"
    assert "INTAKE_REDIS_RATE_LIMIT_UNAVAILABLE" in response.json()["failure_reasons"]


def test_phase2_readiness_fails_closed_on_worm_tamper(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    assert client.post("/intake/api", json=_valid_payload()).status_code == 200
    audit_path = tmp_path / "intake-store" / "audit.worm.jsonl"
    rows = _jsonl(audit_path)
    rows[0]["decision"] = "TAMPERED"
    audit_path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8")

    response = client.get("/intake/readiness", headers={"x-usbay-admin-token": "test-admin-token"})

    assert response.status_code == 503
    assert response.json()["decision"] == "BLOCKED"
    assert response.json()["reason"] == "INTAKE_WORM_AUDIT_CHAIN_INVALID"
