#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import gateway.app as gateway_app
from audit.hash_chain import AuditHashChain
from security.decision_store import DecisionStoreTestDouble
from security.nonce_store import NonceStore
from security.persistent_nonce_store import initialize_persistent_nonce_store
from governance_runtime_monitor import validate_runtime_governance_health
from tests.request_signing_helpers import configure_request_signing, sign_payload_ed25519
from tests.provenance_helpers import (
    install_isolated_audit_key_registry,
    install_runtime_authority,
    install_signed_runtime_attestation_fixture,
)
from tests.test_decide_first import AllowClient, build_payload


MARKERS = {
    "LIVE_PILOT_READY": False,
    "RUNTIME_STARTUP_VALID": False,
    "DASHBOARD_BOOT_VALID": False,
    "RECONNECT_CONTINUITY_VALID": False,
    "OPERATOR_WORKFLOW_VALID": False,
    "AUDIT_EXPORT_VALID": False,
    "REPLAY_EXPORT_VALID": False,
    "RUNTIME_DRIFT_DETECTOR_VALID": False,
    "ATTESTATION_FRESHNESS_VALID": False,
    "GOVERNANCE_CONTINUITY_VALID": False,
    "FAIL_CLOSED_RUNTIME_VALID": False,
    "NO_SECRET_LEAKAGE": False,
}

SECRET_SENTINELS = (
    "live-pilot-test-decision-secret",
    "live-pilot-classic-secret",
    "live-pilot-pqc-secret",
    "raw-live-pilot-secret",
)


def _canonical(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _contains_secret(value: Any) -> bool:
    text = json.dumps(value, sort_keys=True, default=str)
    return any(secret in text for secret in SECRET_SENTINELS)


def _configure_gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    install_runtime_authority(monkeypatch, tmp_path)
    install_isolated_audit_key_registry(monkeypatch, tmp_path)
    monkeypatch.setattr(
        gateway_app,
        "runtime_governance_state_snapshot",
        lambda **_kwargs: {
            "schema_version": "usbay.runtime_governance_state.v1",
            "status": "READY",
            "reason": "PBSEC005_PRODUCTION_RELEASE_APPROVED",
            "promote_state": "PROMOTE_READY",
            "pb020_decision": "VERIFIED",
            "pb016_decision": "VERIFIED",
            "pb017_decision": "VERIFIED",
            "pb018_decision": "VERIFIED",
            "pb019_requirement": "NOT_APPLICABLE_NO_FAILURE_TO_EXPLAIN",
            "production_security_status": "APPROVED",
            "production_release_approved": True,
            "security_gate_chain": {"status": "APPROVED", "production_release_approved": True, "blockers": []},
            "evidence_hash": "a" * 64,
            "evidence_generated_at": "2026-05-20T00:00:00Z",
            "max_age_hours": 168.0,
            "fail_closed": False,
            "reason_codes": ["PB020_EVIDENCE_VERIFIED", "PBSEC005_PRODUCTION_RELEASE_APPROVED"],
        },
    )
    monkeypatch.setenv("USBAY_ALLOW_IN_MEMORY_DECISION_STORE", "true")
    monkeypatch.setenv("USBAY_DECISION_SIGNING_KEY", SECRET_SENTINELS[0])
    monkeypatch.setenv("USBAY_DECISION_CLASSIC_SIGNING_KEY", SECRET_SENTINELS[1])
    monkeypatch.setenv("USBAY_DECISION_PQC_SIGNING_KEY", SECRET_SENTINELS[2])
    monkeypatch.delenv("REQUIRE_REDIS", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("USBAY_EXPECTED_POLICY_HASH", raising=False)
    runtime_nonce_store_path = tmp_path / "runtime_nonce_store.json"
    initialize_persistent_nonce_store(runtime_nonce_store_path)
    monkeypatch.setenv("USBAY_RUNTIME_NONCE_STORE_PATH", str(runtime_nonce_store_path))
    runtime_revocation_registry_path = tmp_path / "runtime_revocation_registry.json"
    runtime_revocation_registry_path.write_text(
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
    monkeypatch.setenv("USBAY_RUNTIME_REVOCATION_REGISTRY_PATH", str(runtime_revocation_registry_path))
    configure_request_signing(tmp_path, monkeypatch, gateway_app)
    monkeypatch.setattr(gateway_app, "nonce_store", NonceStore(tmp_path / "used_nonces.json"))
    monkeypatch.setattr(gateway_app, "audit_chain", AuditHashChain(tmp_path / "audit_chain.json"))
    monkeypatch.setattr(gateway_app, "audit_export_file", tmp_path / "audit_exports.jsonl")
    install_signed_runtime_attestation_fixture(monkeypatch)
    monkeypatch.setattr(
        gateway_app,
        "hydra_node_clients",
        [AllowClient("node-1"), AllowClient("node-2"), AllowClient("node-3")],
    )
    store = DecisionStoreTestDouble()
    monkeypatch.setattr(gateway_app, "decision_store", store)
    return TestClient(gateway_app.app, raise_server_exceptions=False)


def _approve_payload(client: TestClient, payload: dict[str, Any]) -> dict[str, Any]:
    response = client.post("/decide", json=payload)
    if response.status_code != 200:
        raise RuntimeError(f"operator_approve_failed:{response.status_code}:{response.text}")
    body = response.json()
    approved = payload.copy()
    approved["decision_id"] = body["decision_id"]
    approved["decision_signature"] = body["decision_signature"]
    approved["decision_signature_classic"] = body["decision_signature_classic"]
    approved["decision_signature_pqc"] = body["decision_signature_pqc"]
    return approved


def _verify_replay_hash(replay: dict[str, Any]) -> bool:
    candidate = replay.copy()
    replay_hash = candidate.pop("replay_hash", None)
    return hashlib.sha256(_canonical(candidate).encode("utf-8")).hexdigest() == replay_hash


def run_verification() -> dict[str, bool]:
    for marker in MARKERS:
        MARKERS[marker] = False
    leaked_objects: list[Any] = []
    with tempfile.TemporaryDirectory(prefix="usbay-live-pilot-") as raw_tmp:
        tmp_path = Path(raw_tmp)
        monkeypatch = pytest.MonkeyPatch()
        try:
            client = _configure_gateway(tmp_path, monkeypatch)
            with client:
                health = client.get("/health")
                MARKERS["RUNTIME_STARTUP_VALID"] = (
                    health.status_code == 200
                    and health.json().get("mode") == "NORMAL"
                    and health.json().get("replay_protection_active") is True
                    and health.json().get("policy_signature_valid") is True
                )
                leaked_objects.append(health.json())

                dashboard = client.get("/dashboard")
                MARKERS["DASHBOARD_BOOT_VALID"] = (
                    dashboard.status_code == 200
                    and "USBAY Live Pilot v1" in dashboard.text
                    and "Runtime state:" in dashboard.text
                    and dashboard.text.strip() != ""
                )
                leaked_objects.append({"dashboard": dashboard.text})

                websocket_snapshots = []
                with client.websocket_connect("/ws/status") as ws:
                    websocket_snapshots.append(ws.receive_json())
                    ws.send_text("ping")
                    websocket_snapshots.append(ws.receive_json())
                with client.websocket_connect("/ws/status") as ws:
                    websocket_snapshots.append(ws.receive_json())
                MARKERS["RECONNECT_CONTINUITY_VALID"] = all(
                    item.get("type") in {"runtime_status", "pong"}
                    and item.get("snapshot", {}).get("policy_signature_valid") is True
                    for item in websocket_snapshots
                )
                leaked_objects.extend(websocket_snapshots)

                approved_payload = _approve_payload(client, build_payload())
                fail_closed_payload = _approve_payload(client, build_payload())
                execute = client.post("/execute", json=approved_payload)
                denied_payload = build_payload(command="rm -rf /")
                deny = client.post("/decide", json=denied_payload)
                unauthorized = client.post("/execute", json=sign_payload_ed25519({
                    **build_payload(),
                    "nonce": "unauthorized-live-pilot",
                    "signature": "invalid",
                    "raw_secret": SECRET_SENTINELS[3],
                }))
                MARKERS["OPERATOR_WORKFLOW_VALID"] = (
                    execute.status_code == 200
                    and execute.json().get("status") == "EXECUTED"
                    and deny.status_code == 200
                    and deny.json().get("decision") == "DENY"
                    and unauthorized.status_code == 403
                )
                leaked_objects.extend([execute.json(), deny.json(), unauthorized.json()])

                audit = client.get(f"/audit/export/{approved_payload['decision_id']}")
                MARKERS["AUDIT_EXPORT_VALID"] = (
                    audit.status_code == 200
                    and audit.json().get("type") == "decision_audit_export"
                    and audit.json().get("decision_id") == approved_payload["decision_id"]
                    and bool(audit.json().get("records"))
                    and bool(audit.json().get("audit_hash"))
                )
                leaked_objects.append(audit.json())

                replay_first = client.get(f"/replay/export/{approved_payload['decision_id']}")
                replay_second = client.get(f"/replay/export/{approved_payload['decision_id']}")
                MARKERS["REPLAY_EXPORT_VALID"] = (
                    replay_first.status_code == 200
                    and replay_second.status_code == 200
                    and replay_first.json() == replay_second.json()
                    and replay_first.json().get("type") == "decision_replay_export"
                    and _verify_replay_hash(replay_first.json())
                )
                leaked_objects.extend([replay_first.json(), replay_second.json()])

                runtime_authority = gateway_app.runtime_provenance_authority()
                runtime_health = validate_runtime_governance_health(
                    authority=runtime_authority,
                    release_path=runtime_authority.release_path,
                    output_dir=tmp_path / "runtime_governance_health",
                )
                health = runtime_health["health"]
                freshness = runtime_health["attestation_freshness"]
                drift = runtime_health["runtime_drift_report"]
                MARKERS["RUNTIME_DRIFT_DETECTOR_VALID"] = (
                    drift.get("drift_detected") is False
                    and health.get("status") == "PASS"
                    and (tmp_path / "runtime_governance_health" / "runtime_drift_report.json").is_file()
                )
                MARKERS["ATTESTATION_FRESHNESS_VALID"] = (
                    freshness.get("fresh") is True
                    and (tmp_path / "runtime_governance_health" / "attestation_freshness.json").is_file()
                )
                MARKERS["GOVERNANCE_CONTINUITY_VALID"] = (
                    health.get("governance_continuity_score") == 100
                    and (tmp_path / "runtime_governance_health" / "governance_runtime_health.json").is_file()
                )
                leaked_objects.extend([health, freshness, drift])

                monkeypatch.setenv("USBAY_EXPECTED_POLICY_HASH", "0" * 64)
                fail_closed = client.post("/execute", json=fail_closed_payload)
                fail_closed_reason = fail_closed.json().get("error")
                MARKERS["FAIL_CLOSED_RUNTIME_VALID"] = (
                    fail_closed.status_code == 403
                    and fail_closed_reason in {
                        "degraded:policy_hash_mismatch",
                        gateway_app.RUNTIME_DENY_ATTESTATION_UNVERIFIABLE,
                    }
                )
                leaked_objects.append(fail_closed.json())

                MARKERS["NO_SECRET_LEAKAGE"] = not _contains_secret(leaked_objects)
                MARKERS["LIVE_PILOT_READY"] = all(
                    value for key, value in MARKERS.items() if key != "LIVE_PILOT_READY"
                )
        finally:
            monkeypatch.undo()
    return MARKERS.copy()


def main() -> int:
    markers = run_verification()
    for key in MARKERS:
        print(f"{key}={str(markers[key]).lower()}")
    return 0 if markers["LIVE_PILOT_READY"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
