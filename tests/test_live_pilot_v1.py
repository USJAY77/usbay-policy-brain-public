from __future__ import annotations

import json
import os
import subprocess
import sys
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

import gateway.app as gateway_app
import scripts.verify_live_pilot_v1 as live_pilot_verifier
from scripts.verify_live_pilot_v1 import (
    SECRET_SENTINELS,
    _configure_gateway,
    run_verification,
)
from security.decision_store import DecisionStoreTestDouble, verify_decision_signatures
from tests.provenance_helpers import runtime_trust_state
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


def _synthetic_lifecycle_adapter(monkeypatch):
    from executors import cpu_executor

    calls = []

    def execute(_payload):
        calls.append("synthetic_cpu")
        return {"actual_execution_target": "cpu", "execution_verified": True}

    # Preserve route_execution, canonical gate, authority and lifecycle checks.
    monkeypatch.setattr(cpu_executor, "execute", execute)
    return calls


@pytest.mark.governance
def test_synthetic_lifecycle_completes_once_and_blocks_replay(tmp_path, monkeypatch):
    client = _configure_gateway(tmp_path, monkeypatch)
    calls = _synthetic_lifecycle_adapter(monkeypatch)
    payload = build_payload()
    payload["raw_secret"] = SECRET_SENTINELS[3]
    approved = live_pilot_verifier._approve_payload(client, sign_payload_ed25519(payload))

    executed = client.post("/execute", json=approved)
    replay = client.post("/execute", json=approved)

    assert executed.status_code == 200
    assert executed.json() == {"status": "EXECUTED"}
    assert replay.status_code == 403
    assert replay.json() == {"error": "replay_detected"}
    assert calls == ["synthetic_cpu"]
    db = tmp_path / "execution_lifecycle.db"
    # A new connection proves committed state, rather than an in-memory observation.
    with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True) as connection:
        rows = connection.execute("SELECT state, evidence_json FROM execution_lifecycle").fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "COMPLETED"
    assert not _contains_secret(rows[0][1])
    assert approved["nonce"] not in rows[0][1]
    assert not _contains_secret([executed.json(), replay.json()])


@pytest.mark.governance
def test_synthetic_lifecycle_deny_and_unauthorized_never_execute(tmp_path, monkeypatch):
    client = _configure_gateway(tmp_path, monkeypatch)
    calls = _synthetic_lifecycle_adapter(monkeypatch)
    denied = live_pilot_verifier._approve_payload(client, build_payload(command="rm -rf /"))
    signed_deny = gateway_app.decision_store.load_decision(denied["decision_id"])
    assert signed_deny["decision"] == "DENY"
    assert verify_decision_signatures(signed_deny)

    denial = client.post("/execute", json=denied)
    unauthorized = client.post("/execute", json=sign_payload_ed25519({
        **build_payload(), "raw_secret": SECRET_SENTINELS[3],
    }))

    assert denial.status_code == 403
    assert denial.json() == {"error": "policy_denied"}
    assert unauthorized.status_code == 403
    assert unauthorized.json() == {"error": "missing_decision_id"}
    assert calls == []
    assert not (tmp_path / "execution_lifecycle.db").exists()
    assert not (tmp_path / "gateway_authz_replay.db").exists()
    assert not _contains_secret([denial.json(), unauthorized.json()])


@pytest.mark.governance
@pytest.mark.parametrize("storage", ["missing_backend", "unsupported", "unavailable", "corrupt"])
def test_synthetic_lifecycle_storage_blocks_before_adapter(tmp_path, monkeypatch, storage):
    client = _configure_gateway(tmp_path, monkeypatch)
    calls = _synthetic_lifecycle_adapter(monkeypatch)
    if storage == "missing_backend":
        monkeypatch.delenv("USBAY_EXECUTION_LIFECYCLE_STORE")
    elif storage == "unsupported":
        monkeypatch.setenv("USBAY_EXECUTION_LIFECYCLE_STORE", "unsupported")
    else:
        path = tmp_path / "blocked-lifecycle"
        if storage == "unavailable":
            path.mkdir()
        else:
            path.write_bytes(b"synthetic-corrupt-sqlite")
        monkeypatch.setenv("USBAY_EXECUTION_LIFECYCLE_SQLITE_PATH", str(path))
    payload = build_payload()
    payload["raw_secret"] = SECRET_SENTINELS[3]
    approved = live_pilot_verifier._approve_payload(client, sign_payload_ed25519(payload))

    response = client.post("/execute", json=approved)

    assert response.status_code == 403
    assert response.json() == {"error": "execution_lifecycle_blocked"}
    assert calls == []
    assert not _contains_secret(response.json())
    assert not (tmp_path / "execution_lifecycle.db").exists()
    assert gateway_app.decision_store.load_decision(approved["decision_id"])["used"] is False


@pytest.mark.governance
def test_synthetic_lifecycle_fixture_restores_environment_and_authority(tmp_path, monkeypatch):
    import tests.test_decide_first as helpers

    names = ("USBAY_EXECUTION_LIFECYCLE_STORE", "USBAY_EXECUTION_LIFECYCLE_SQLITE_PATH")
    before = {name: os.environ.get(name) for name in names}
    registry, directory = helpers._GATEWAY_AUTHORITY_REGISTRY, helpers._GATEWAY_AUTHORITY_TMP_PATH
    with monkeypatch.context() as scoped:
        _configure_gateway(tmp_path, scoped)
        assert os.environ[names[0]] == "sqlite"
        assert Path(os.environ[names[1]]) == tmp_path / "execution_lifecycle.db"
        assert helpers._GATEWAY_AUTHORITY_TMP_PATH == tmp_path
    assert {name: os.environ.get(name) for name in names} == before
    assert helpers._GATEWAY_AUTHORITY_REGISTRY is registry
    assert helpers._GATEWAY_AUTHORITY_TMP_PATH is directory


def test_live_pilot_ready_fails_closed_on_degraded_runtime_governance(monkeypatch) -> None:
    def degraded_runtime_governance_health(**_kwargs):
        return {
            "health": {
                "status": "FAIL",
                "governance_continuity_score": 50,
                "failed_control_ids": ["runtime_lineage_divergence"],
            },
            "attestation_freshness": {
                "fresh": False,
                "stale_controls": ["release_manifest_freshness"],
            },
            "runtime_drift_report": {
                "drift_detected": True,
                "drift_reasons": ["runtime_lineage_divergence"],
            },
        }

    monkeypatch.setattr(
        live_pilot_verifier,
        "validate_runtime_governance_health",
        degraded_runtime_governance_health,
    )

    markers = run_verification()

    assert markers["LIVE_PILOT_READY"] is False
    assert markers["RUNTIME_DRIFT_DETECTOR_VALID"] is False
    assert markers["ATTESTATION_FRESHNESS_VALID"] is False
    assert markers["GOVERNANCE_CONTINUITY_VALID"] is False
    assert markers["FAIL_CLOSED_RUNTIME_VALID"] is True
    assert markers["NO_SECRET_LEAKAGE"] is True


def test_live_pilot_ready_fails_closed_when_audit_export_source_missing(monkeypatch) -> None:
    original_load_decision = DecisionStoreTestDouble.load_decision

    def audit_export_missing_after_execute(self, decision_id):
        record = original_load_decision(self, decision_id)
        if record and record.get("decision") == "ALLOW" and record.get("used") is True:
            return None
        return record

    monkeypatch.setattr(
        DecisionStoreTestDouble,
        "load_decision",
        audit_export_missing_after_execute,
    )

    markers = run_verification()

    assert markers["LIVE_PILOT_READY"] is False
    assert markers["AUDIT_EXPORT_VALID"] is False
    assert markers["REPLAY_EXPORT_VALID"] is False
    assert markers["FAIL_CLOSED_RUNTIME_VALID"] is True
    assert markers["NO_SECRET_LEAKAGE"] is True


def test_live_pilot_fixture_provides_signed_fresh_runtime_attestation(tmp_path, monkeypatch) -> None:
    _configure_gateway(tmp_path, monkeypatch)

    snapshot = gateway_app.signed_runtime_attestation_snapshot()
    result = gateway_app.validate_attestation_freshness_for_runtime(snapshot)

    assert snapshot["attestation_status"] == "SIGNED"
    assert snapshot["signature_valid"] is True
    assert result["decision"] == gateway_app.RUNTIME_ENFORCEMENT_NEXT_CHECK


def test_live_pilot_and_decide_first_fixtures_share_runtime_trust_state(
    tmp_path,
    monkeypatch,
) -> None:
    configure_gateway(tmp_path / "decide-first", monkeypatch)
    decide_first_state = runtime_trust_state(gateway_app.signed_runtime_attestation_snapshot())
    monkeypatch.undo()

    _configure_gateway(tmp_path / "live-pilot", monkeypatch)
    live_pilot_state = runtime_trust_state(gateway_app.signed_runtime_attestation_snapshot())

    assert live_pilot_state == decide_first_state == {
        "attestation_status": "SIGNED",
        "signature_valid": True,
    }


def test_live_pilot_script_preserves_tracked_audit_key_registry() -> None:
    registry_path = Path("audit/key_registry.json")
    before = registry_path.read_bytes()
    env = os.environ.copy()
    env.pop("PYTEST_CURRENT_TEST", None)

    try:
        result = subprocess.run(
            [sys.executable, "scripts/verify_live_pilot_v1.py"],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        after = registry_path.read_bytes()
    finally:
        registry_path.write_bytes(before)

    assert result.returncode == 0
    assert after == before


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
