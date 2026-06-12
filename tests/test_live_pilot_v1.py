from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import gateway.app as gateway_app
from scripts.verify_live_pilot_v1 import (
    SECRET_SENTINELS,
    _configure_gateway,
    run_verification,
)
from governance.correction_proposals import detect_governance_issue, generate_correction_proposal
from governance.proposal_execution_adapter import ProposalExecutionAdapter
from governance.proposal_registry import ProposalRegistry, STATE_APPROVED, initialize_proposal_registry
from security.persistent_nonce_store import LocalPersistentNonceStore, initialize_persistent_nonce_store
from tests.request_signing_helpers import sign_payload_ed25519
from tests.test_decide_first import approve, build_payload, configure_gateway


def _contains_secret(value) -> bool:
    text = json.dumps(value, sort_keys=True, default=str)
    return any(secret in text for secret in SECRET_SENTINELS)


def _write_active_revocation_registry(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "usbay.runtime_revocation_registry.v1",
                "registry_state": "ACTIVE",
                "revoked_runtime_ids": [],
                "revoked_device_ids": [],
                "revoked_attestation_ids": [],
                "revoked_operator_ids": [],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _proposal_execution_eligibility(tmp_path: Path, approved_payload: dict) -> dict:
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    registry_path = tmp_path / "proposal_registry.json"
    nonce_store_path = tmp_path / "proposal_execution_nonce_store.json"
    revocation_path = tmp_path / "proposal_execution_revocation_registry.json"
    initialize_proposal_registry(registry_path)
    initialize_persistent_nonce_store(nonce_store_path)
    _write_active_revocation_registry(revocation_path)
    issue = detect_governance_issue(
        "CI_FAILURE",
        observed_failure="live pilot approved operator workflow requires PB-298 eligibility",
        source="test_live_pilot_v1",
    )
    proposal = generate_correction_proposal(issue, timestamp=timestamp)
    proposal_registry = ProposalRegistry(registry_path)
    proposal_registry.create(proposal, timestamp=timestamp)
    proposal_registry.transition(proposal["proposal_id"], lifecycle_state=STATE_APPROVED, timestamp=timestamp)
    adapter = ProposalExecutionAdapter(
        proposal_registry=proposal_registry,
        nonce_store=LocalPersistentNonceStore(
            nonce_store_path,
            now_fn=lambda: datetime.now(timezone.utc).timestamp(),
        ),
        revocation_registry_path=revocation_path,
        policy_loader=lambda: gateway_app.load_policy_registry(
            provenance_context=gateway_app.runtime_provenance_context()
        ),
    )
    return adapter.evaluate(
        {
            "proposal_id": proposal["proposal_id"],
            "proposal_hash": proposal["proposal_hash"],
            "approval_id": str(approved_payload["decision_id"]),
            "execution_id": str(approved_payload["decision_id"]),
            "actor": str(approved_payload.get("actor_id", "")),
            "runtime_id": "live-pilot-runtime",
            "device_id": str(approved_payload.get("device", "")),
            "attestation_id": "live-pilot-attestation",
            "operator_id": str(approved_payload.get("user_id", "")),
            "nonce": str(approved_payload.get("nonce", "")),
        },
        timestamp=timestamp,
    )


def test_live_pilot_v1_verification_markers_all_pass() -> None:
    markers = run_verification()

    assert markers == {
        "LIVE_PILOT_READY": True,
        "RUNTIME_STARTUP_VALID": True,
        "DASHBOARD_BOOT_VALID": True,
        "RECONNECT_CONTINUITY_VALID": True,
        "OPERATOR_WORKFLOW_VALID": True,
        "AUDIT_EXPORT_VALID": True,
        "REPLAY_EXPORT_VALID": True,
        "RUNTIME_DRIFT_DETECTOR_VALID": True,
        "ATTESTATION_FRESHNESS_VALID": True,
        "GOVERNANCE_CONTINUITY_VALID": True,
        "FAIL_CLOSED_RUNTIME_VALID": True,
        "NO_SECRET_LEAKAGE": True,
    }


def test_live_pilot_fixture_provides_signed_fresh_runtime_attestation(tmp_path, monkeypatch) -> None:
    _configure_gateway(tmp_path, monkeypatch)

    snapshot = gateway_app.signed_runtime_attestation_snapshot()
    result = gateway_app.validate_attestation_freshness_for_runtime(snapshot)

    assert snapshot["attestation_status"] == "SIGNED"
    assert snapshot["signature_valid"] is True
    assert result["decision"] == gateway_app.RUNTIME_ENFORCEMENT_NEXT_CHECK


def test_dashboard_boot_cannot_be_blank(tmp_path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)

    response = client.get("/dashboard")

    assert response.status_code == 200
    assert response.text.strip()
    assert "USBAY Live Pilot v1" in response.text
    assert "Runtime state:" in response.text


def test_runtime_starts_and_reports_backend_truth(tmp_path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)

    with client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["mode"] == "NORMAL"
    assert response.json()["policy_signature_valid"] is True
    assert response.json()["replay_protection_active"] is True


def test_vps_dockerfile_contains_runtime_dependencies() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    requirements = Path("requirements.txt").read_text(encoding="utf-8")
    dockerignore = Path(".dockerignore").read_text(encoding="utf-8")
    replit = Path(".replit").read_text(encoding="utf-8")
    replit_lines = replit.splitlines()
    run_lines = [line for line in replit_lines if line.strip().startswith("run = ")]
    deployment_run = json.loads(run_lines[0].split("run = ", 1)[1].strip())

    for package_dir in ("audit", "executors", "gateway", "governance", "policy", "runtime", "security", "utils"):
        assert f"COPY {package_dir} ./{package_dir}" in dockerfile
    assert 'CMD ["sh", "-c", ": \\"${PORT:?PORT is required for USBAY gateway deployment}\\" && exec python3 -m uvicorn gateway.app:app --host 0.0.0.0 --port \\"$PORT\\""]' in dockerfile
    assert run_lines == [run_lines[0]]
    assert "[deployment]" in replit
    assert 'deploymentTarget = "autoscale"' in replit
    assert deployment_run == [
        "sh",
        "-c",
        ': "${PORT:?PORT is required for USBAY gateway deployment}" && exec python3 -m uvicorn gateway.app:app --host 0.0.0.0 --port "$PORT"',
    ]
    assert "${PORT:-" not in dockerfile
    assert "${PORT:-" not in replit
    assert "EXPOSE 8000" not in dockerfile
    dockerignore_lines = {line.strip() for line in dockerignore.splitlines()}
    assert "runtime/" not in dockerignore_lines
    assert "runtime/*" not in dockerignore_lines
    assert "tmp/" in dockerignore
    assert "*.db" in dockerignore
    assert "usbay_audit.db" in dockerignore
    assert "fastapi" in requirements
    assert "uvicorn" in requirements
    assert "cryptography" in requirements


def test_websocket_reconnect_continuity(tmp_path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)

    with client.websocket_connect("/ws/status") as websocket:
        first = websocket.receive_json()
        websocket.send_text("ping")
        pong = websocket.receive_json()
    with client.websocket_connect("/ws/status") as websocket:
        reconnected = websocket.receive_json()

    assert first["type"] == "runtime_status"
    assert pong["type"] == "pong"
    assert reconnected["type"] == "runtime_status"
    assert first["snapshot"]["policy_signature_valid"] is True
    assert reconnected["snapshot"]["policy_signature_valid"] is True


def test_operator_approve_deny_and_unauthorized_blocked(tmp_path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    approved_payload = approve(client, build_payload())

    allowed = _proposal_execution_eligibility(tmp_path, approved_payload)
    denied = client.post("/decide", json=build_payload(command="rm -rf /"))
    unsigned = build_payload()
    unsigned["signature"] = "invalid"
    unsigned["nonce"] = "live-pilot-unauthorized"
    unauthorized = client.post("/execute", json=unsigned)

    assert allowed["decision"] == "EXECUTION_ELIGIBLE"
    assert allowed["execution_state"] == "EXECUTION_ELIGIBLE"
    assert denied.status_code == 200
    assert denied.json()["decision"] == "DENY"
    assert unauthorized.status_code == 403


def test_audit_export_readable_and_secret_free(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("USBAY_DECISION_SIGNING_KEY", SECRET_SENTINELS[0])
    client = configure_gateway(tmp_path, monkeypatch)
    approved_payload = approve(client, build_payload())

    response = client.get(f"/audit/export/{approved_payload['decision_id']}")
    body = response.json()

    assert response.status_code == 200
    assert body["type"] == "decision_audit_export"
    assert body["decision_id"] == approved_payload["decision_id"]
    assert body["records"]
    assert not _contains_secret(body)


def test_replay_export_reproducible_and_secret_free(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("USBAY_DECISION_SIGNING_KEY", SECRET_SENTINELS[0])
    client = configure_gateway(tmp_path, monkeypatch)
    approved_payload = approve(client, build_payload())

    first = client.get(f"/replay/export/{approved_payload['decision_id']}")
    second = client.get(f"/replay/export/{approved_payload['decision_id']}")
    body = first.json()

    assert first.status_code == 200
    assert second.status_code == 200
    assert body == second.json()
    assert body["type"] == "decision_replay_export"
    assert body["replay_hash"] == gateway_app.replay_export_for_decision(approved_payload["decision_id"])["replay_hash"]
    assert not _contains_secret(body)


def test_fail_closed_runtime_blocks_when_policy_hash_mismatches(tmp_path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    approved_payload = approve(client, build_payload())
    monkeypatch.setenv("USBAY_EXPECTED_POLICY_HASH", "0" * 64)

    response = client.post("/execute", json=approved_payload)

    assert response.status_code == 403
    assert response.json() == {"error": "degraded:policy_hash_mismatch"}


def test_audit_and_replay_exports_do_not_include_raw_payload_secrets(tmp_path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload["raw_secret"] = SECRET_SENTINELS[3]
    payload = sign_payload_ed25519(payload)

    decision = client.post("/decide", json=payload)
    audit = client.get(f"/audit/export/{decision.json()['decision_id']}")
    replay = client.get(f"/replay/export/{decision.json()['decision_id']}")

    assert decision.status_code == 200
    assert audit.status_code == 200
    assert replay.status_code == 200
    assert not _contains_secret(audit.json())
    assert not _contains_secret(replay.json())
