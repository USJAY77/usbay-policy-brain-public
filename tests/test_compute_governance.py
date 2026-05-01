from __future__ import annotations

from tests.test_decide_first import approve, build_payload, configure_gateway


def _decide(tmp_path, monkeypatch, **overrides):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload.update(overrides)
    from tests.request_signing_helpers import sign_payload_ed25519

    return client, client.post("/decide", json=sign_payload_ed25519(payload))


def test_missing_compute_target_denied(tmp_path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload.pop("compute_target")
    from tests.request_signing_helpers import sign_payload_ed25519

    response = client.post("/decide", json=sign_payload_ed25519(payload))

    assert response.status_code == 403
    assert response.json()["reason"] == "compute_target_missing"


def test_tpu_without_human_review_denied(tmp_path, monkeypatch) -> None:
    _client, response = _decide(tmp_path, monkeypatch, compute_target="tpu", human_review=False)

    assert response.status_code == 403
    assert response.json()["reason"] == "human_review_required"


def test_sensitive_data_on_tpu_denied(tmp_path, monkeypatch) -> None:
    _client, response = _decide(
        tmp_path,
        monkeypatch,
        compute_target="tpu",
        human_review=True,
        data_sensitivity="high",
    )

    assert response.status_code == 403
    assert response.json()["reason"] == "sensitive_data_compute_denied"


def test_sensitive_data_on_cloud_denied(tmp_path, monkeypatch) -> None:
    _client, response = _decide(
        tmp_path,
        monkeypatch,
        compute_target="gpu",
        execution_location="cloud",
        human_review=True,
        data_sensitivity="high",
    )

    assert response.status_code == 403
    assert response.json()["reason"] == "compute_target_not_allowed"


def test_npu_local_sensitive_data_allowed(tmp_path, monkeypatch) -> None:
    _client, response = _decide(
        tmp_path,
        monkeypatch,
        compute_target="npu",
        data_sensitivity="high",
        compute_risk_level="low",
        execution_location="local",
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"


def test_unknown_compute_target_denied(tmp_path, monkeypatch) -> None:
    _client, response = _decide(tmp_path, monkeypatch, compute_target="quantum")

    assert response.status_code == 403
    assert response.json()["reason"] == "compute_target_not_allowed"


def test_npu_high_sensitivity_allowed_by_policy(tmp_path, monkeypatch) -> None:
    _client, response = _decide(
        tmp_path,
        monkeypatch,
        compute_target="npu",
        data_sensitivity="high",
        execution_location="local",
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"


def test_audit_export_contains_compute_evidence(tmp_path, monkeypatch) -> None:
    client, response = _decide(
        tmp_path,
        monkeypatch,
        compute_target="npu",
        data_sensitivity="high",
        compute_risk_level="medium",
        execution_location="local",
    )
    assert response.status_code == 200

    export = client.get(f"/audit/export/{response.json()['decision_id']}").json()
    record = export["decision_record"]

    assert record["compute_target"] == "npu"
    assert record["compute_policy_hash"]
    assert record["compute_risk_level"] == "medium"
    assert record["human_review"] is False
    assert record["data_sensitivity"] == "high"
    assert record["execution_location"] == "local"


def test_health_reports_compute_policy_state(tmp_path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["compute_policy_state"] == "valid"


def test_allowed_npu_request_routes_to_npu_executor(tmp_path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload.update(
        {
            "compute_target": "npu",
            "data_sensitivity": "high",
            "execution_location": "local",
            "compute_risk_level": "low",
        }
    )
    from tests.request_signing_helpers import sign_payload_ed25519

    approved = approve(client, sign_payload_ed25519(payload))
    response = client.post("/execute", json=approved)

    assert response.status_code == 200
    export = client.get(f"/audit/export/{approved['decision_id']}").json()
    record = export["decision_record"]
    assert record["compute_target"] == "npu"
    assert record["actual_execution_target"] == "npu"
    assert record["execution_verified"] is True


def test_denied_cloud_request_never_reaches_executor(tmp_path, monkeypatch) -> None:
    from executors import cpu_executor, npu_executor
    from tests.request_signing_helpers import sign_payload_ed25519

    def forbidden_executor(_payload):
        raise AssertionError("executor should not be reached for denied cloud request")

    monkeypatch.setattr(cpu_executor, "execute", forbidden_executor)
    monkeypatch.setattr(npu_executor, "execute", forbidden_executor)
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload.update(
        {
            "compute_target": "npu",
            "data_sensitivity": "high",
            "execution_location": "cloud",
        }
    )

    response = client.post("/decide", json=sign_payload_ed25519(payload))

    assert response.status_code == 403
    assert response.json()["reason"] == "compute_target_not_allowed"


def test_compute_target_execution_mismatch_fails_closed(tmp_path, monkeypatch) -> None:
    from executors import npu_executor
    from tests.request_signing_helpers import sign_payload_ed25519

    def mismatched_executor(_payload):
        return {
            "status": "EXECUTED",
            "actual_execution_target": "cpu",
            "execution_verified": True,
        }

    monkeypatch.setattr(npu_executor, "execute", mismatched_executor)
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload.update(
        {
            "compute_target": "npu",
            "data_sensitivity": "high",
            "execution_location": "local",
            "compute_risk_level": "low",
        }
    )
    approved = approve(client, sign_payload_ed25519(payload))

    response = client.post("/execute", json=approved)

    assert response.status_code == 403
    assert response.json() == {"error": "compute_execution_mismatch"}
