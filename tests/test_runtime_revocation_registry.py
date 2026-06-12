import json

import gateway.app as gateway_app


def _registry(**overrides):
    data = {
        "schema_version": "usbay.runtime_revocation_registry.v1",
        "registry_state": "ACTIVE",
        "revoked_runtime_ids": [],
        "revoked_device_ids": [],
        "revoked_attestation_ids": [],
        "revoked_operator_ids": [],
    }
    data.update(overrides)
    return data


def _write_registry(path, **overrides):
    path.write_text(json.dumps(_registry(**overrides), sort_keys=True), encoding="utf-8")
    return path


def _record():
    return {
        "decision_id": "decision-pb294",
        "nonce_hash": gateway_app.nonce_hash("nonce-pb294"),
        "request_hash": "r" * 64,
        "policy_hash": "p" * 64,
        "policy_version": "policy-v1",
    }


def _payload():
    return {
        "decision_id": "decision-pb294",
        "nonce": "nonce-pb294",
        "device": "device-pb294",
        "actor_id": "operator-pb294",
        "policy_version": "policy-v1",
    }


class AuditRecorder:
    def __init__(self):
        self.events = []

    def append(self, action, decision):
        self.events.append((action, decision))


def test_active_runtime_revocation_registry_returns_next_check_and_audits(tmp_path, monkeypatch):
    audit = AuditRecorder()
    monkeypatch.setattr(gateway_app, "audit_chain", audit)
    registry_path = _write_registry(tmp_path / "runtime_revocation_registry.json")

    result = gateway_app.validate_runtime_revocation_registry_for_runtime(
        _record(),
        payload=_payload(),
        runtime_attestation={"verification": {"attestation_hash": "attestation-pb294"}},
        registry_path=registry_path,
        timestamp="2026-06-12T00:00:00Z",
    )

    assert result["decision"] == gateway_app.RUNTIME_ENFORCEMENT_NEXT_CHECK
    assert result["execution_allowed"] is False
    assert audit.events[-1][0] == "runtime_revocation_decision"
    assert audit.events[-1][1]["reason_code"] == "ok"
    assert audit.events[-1][1]["audit_hash"]


def test_runtime_revocation_registry_blocks_revoked_runtime_device_attestation_and_operator(tmp_path, monkeypatch):
    audit = AuditRecorder()
    monkeypatch.setattr(gateway_app, "audit_chain", audit)
    cases = [
        ({"revoked_runtime_ids": ["gateway-1"]}, "runtime_id_revoked"),
        ({"revoked_device_ids": ["device-pb294"]}, "device_id_revoked"),
        ({"revoked_attestation_ids": ["attestation-pb294"]}, "attestation_id_revoked"),
        ({"revoked_operator_ids": ["operator-pb294"]}, "operator_id_revoked"),
    ]

    for index, (overrides, reason_code) in enumerate(cases):
        registry_path = _write_registry(tmp_path / f"runtime_revocation_registry_{index}.json", **overrides)
        result = gateway_app.validate_runtime_revocation_registry_for_runtime(
            _record(),
            payload=_payload(),
            runtime_attestation={"verification": {"attestation_hash": "attestation-pb294"}},
            registry_path=registry_path,
            timestamp="2026-06-12T00:00:00Z",
        )

        assert result["decision"] == gateway_app.RUNTIME_ENFORCEMENT_DENY
        assert result["execution_allowed"] is False
        assert result["reason_code"] == reason_code
        assert result["audit_evidence"]["reason_code"] == reason_code
        assert result["revocation_audit_evidence"]["reason_code"] == reason_code


def test_runtime_revocation_registry_unavailable_and_unknown_state_fail_closed(tmp_path, monkeypatch):
    audit = AuditRecorder()
    monkeypatch.setattr(gateway_app, "audit_chain", audit)
    unavailable = gateway_app.validate_runtime_revocation_registry_for_runtime(
        _record(),
        payload=_payload(),
        runtime_attestation={"verification": {"attestation_hash": "attestation-pb294"}},
        registry_path=tmp_path / "missing.json",
        timestamp="2026-06-12T00:00:00Z",
    )
    unknown_path = _write_registry(tmp_path / "unknown.json", registry_state="PAUSED")

    unknown = gateway_app.validate_runtime_revocation_registry_for_runtime(
        _record(),
        payload=_payload(),
        runtime_attestation={"verification": {"attestation_hash": "attestation-pb294"}},
        registry_path=unknown_path,
        timestamp="2026-06-12T00:00:00Z",
    )

    assert unavailable["decision"] == gateway_app.RUNTIME_ENFORCEMENT_DENY
    assert unavailable["reason_code"] == "runtime_revocation_registry_unavailable"
    assert unknown["decision"] == gateway_app.RUNTIME_ENFORCEMENT_DENY
    assert unknown["reason_code"] == "runtime_revocation_registry_unknown_state"
