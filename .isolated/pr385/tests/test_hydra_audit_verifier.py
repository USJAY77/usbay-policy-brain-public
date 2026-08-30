from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import scripts.hydra_verify_audit as hydra_verify
from scripts.hydra_verify_audit import (
    AUDIT_DISPUTED,
    AUDIT_INVALID,
    AUDIT_VALID,
    audit_final_allows_execution,
    audit_final_requires_human_review,
    evaluate_hydra_audit_results,
    hydra_audit_evidence,
    load_policy_signature_mode,
    load_verifier_node_registry,
    sign_verifier_result,
    simulate_verifier_nodes,
)
from tests.test_decide_first import build_payload, configure_gateway


def _decision_export(tmp_path: Path, monkeypatch) -> dict:
    client = configure_gateway(tmp_path, monkeypatch)
    response = client.post("/decide", json=build_payload())
    assert response.status_code == 200
    export_response = client.get(f"/audit/export/{response.json()['decision_id']}")
    assert export_response.status_code == 200
    return export_response.json()


def _audit_hash(export: dict) -> str:
    return export["decision_record"]["audit_hash"]


def _sign_result(export: dict, node_id: str, result: str, audit_hash: str, **kwargs):
    record = export["decision_record"]
    return sign_verifier_result(
        node_id,
        result,
        audit_hash,
        policy_version=record["policy_version"],
        policy_hash=record["policy_hash"],
        **kwargs,
    )


def _write_registry(tmp_path: Path, monkeypatch, mutate):
    registry = json.loads(hydra_verify.VERIFIER_REGISTRY_PATH.read_text(encoding="utf-8"))
    mutate(registry)
    registry_path = tmp_path / "verifier_node_registry.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    monkeypatch.setattr(hydra_verify, "VERIFIER_REGISTRY_PATH", registry_path)
    return registry_path


def test_hydra_audit_three_valid_votes_returns_valid(tmp_path: Path, monkeypatch) -> None:
    export = _decision_export(tmp_path, monkeypatch)
    results = simulate_verifier_nodes(export)

    assert evaluate_hydra_audit_results(results) == AUDIT_VALID


def test_hydra_audit_two_valid_one_invalid_returns_valid(tmp_path: Path, monkeypatch) -> None:
    export = _decision_export(tmp_path, monkeypatch)
    audit_hash = _audit_hash(export)
    results = [
        _sign_result(export, "audit-verifier-1", AUDIT_VALID, audit_hash),
        _sign_result(export, "audit-verifier-2", AUDIT_VALID, audit_hash),
        _sign_result(export, "audit-verifier-3", AUDIT_INVALID, audit_hash),
    ]

    assert evaluate_hydra_audit_results(results) == AUDIT_VALID


def test_hydra_audit_one_valid_two_invalid_returns_invalid(tmp_path: Path, monkeypatch) -> None:
    export = _decision_export(tmp_path, monkeypatch)
    audit_hash = _audit_hash(export)
    results = [
        _sign_result(export, "audit-verifier-1", AUDIT_VALID, audit_hash),
        _sign_result(export, "audit-verifier-2", AUDIT_INVALID, audit_hash),
        _sign_result(export, "audit-verifier-3", AUDIT_INVALID, audit_hash),
    ]

    assert evaluate_hydra_audit_results(results) == AUDIT_INVALID


def test_hydra_audit_mixed_hashes_returns_disputed(tmp_path: Path, monkeypatch) -> None:
    export = _decision_export(tmp_path, monkeypatch)
    audit_hash = _audit_hash(export)
    different_hash = "f" * 64
    results = [
        _sign_result(export, "audit-verifier-1", AUDIT_VALID, audit_hash),
        _sign_result(export, "audit-verifier-2", AUDIT_VALID, audit_hash),
        _sign_result(export, "audit-verifier-3", AUDIT_VALID, different_hash),
    ]

    assert evaluate_hydra_audit_results(results) == AUDIT_DISPUTED


def test_hydra_audit_tampered_verifier_signature_returns_invalid(tmp_path: Path, monkeypatch) -> None:
    export = _decision_export(tmp_path, monkeypatch)
    results = [result.to_dict() for result in simulate_verifier_nodes(export)]
    results[1]["verifier_signature"] = "tampered"

    assert evaluate_hydra_audit_results(results) == AUDIT_INVALID


def test_hydra_audit_missing_verifier_node_returns_invalid(tmp_path: Path, monkeypatch) -> None:
    export = _decision_export(tmp_path, monkeypatch)
    results = simulate_verifier_nodes(export)[:2]

    assert evaluate_hydra_audit_results(results) == AUDIT_INVALID


def test_hydra_audit_cli_outputs_valid_for_valid_export(tmp_path: Path, monkeypatch) -> None:
    export = _decision_export(tmp_path, monkeypatch)
    export_file = tmp_path / "decision-export.json"
    export_file.write_text(json.dumps(export), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/hydra_verify_audit.py",
            str(export_file),
            "governance/policy_public.key",
        ],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == AUDIT_VALID


def test_hydra_audit_two_nodes_same_trust_domain_returns_invalid(tmp_path: Path, monkeypatch) -> None:
    _write_registry(
        tmp_path,
        monkeypatch,
        lambda registry: registry["nodes"][2].update({"trust_domain": registry["nodes"][1]["trust_domain"]}),
    )
    export = _decision_export(tmp_path, monkeypatch)
    audit_hash = _audit_hash(export)
    results = [
        _sign_result(export, "audit-verifier-1", AUDIT_VALID, audit_hash),
        _sign_result(export, "audit-verifier-2", AUDIT_VALID, audit_hash),
        _sign_result(export, "audit-verifier-3", AUDIT_VALID, audit_hash),
    ]

    assert evaluate_hydra_audit_results(results) == AUDIT_INVALID


def test_hydra_audit_unknown_verifier_node_returns_invalid(tmp_path: Path, monkeypatch) -> None:
    export = _decision_export(tmp_path, monkeypatch)
    results = [result.to_dict() for result in simulate_verifier_nodes(export)]
    results[0]["node_id"] = "unknown-verifier"

    assert evaluate_hydra_audit_results(results) == AUDIT_INVALID


def test_hydra_audit_revoked_verifier_key_returns_invalid(tmp_path: Path, monkeypatch) -> None:
    _write_registry(
        tmp_path,
        monkeypatch,
        lambda registry: registry["nodes"][1].update(
            {
                "status": "revoked",
                "revoked_at_epoch": 1800000000,
                "revocation_reason": "key_rotation",
            }
        ),
    )
    export = _decision_export(tmp_path, monkeypatch)
    results = simulate_verifier_nodes(export)

    assert evaluate_hydra_audit_results(results) == AUDIT_INVALID


def test_hydra_audit_signature_policy_mode_mismatch_returns_invalid(tmp_path: Path, monkeypatch) -> None:
    export = _decision_export(tmp_path, monkeypatch)
    audit_hash = _audit_hash(export)
    results = [
        _sign_result(export, "audit-verifier-1", AUDIT_VALID, audit_hash, signature_policy_mode="COMPAT"),
        _sign_result(export, "audit-verifier-2", AUDIT_VALID, audit_hash, signature_policy_mode="COMPAT"),
        _sign_result(export, "audit-verifier-3", AUDIT_VALID, audit_hash, signature_policy_mode="COMPAT"),
    ]

    assert evaluate_hydra_audit_results(results) == AUDIT_INVALID


def test_hydra_audit_disputed_blocks_execution_and_requires_human_review(tmp_path: Path, monkeypatch) -> None:
    export = _decision_export(tmp_path, monkeypatch)
    audit_hash = _audit_hash(export)
    results = [
        _sign_result(export, "audit-verifier-1", AUDIT_VALID, audit_hash),
        _sign_result(export, "audit-verifier-2", AUDIT_VALID, audit_hash),
        _sign_result(export, "audit-verifier-3", AUDIT_VALID, "e" * 64),
    ]

    audit_final = evaluate_hydra_audit_results(results)

    assert audit_final == AUDIT_DISPUTED
    assert audit_final_allows_execution(audit_final) is False
    assert audit_final_requires_human_review(audit_final) is True

    evidence = hydra_audit_evidence(
        export,
        verification_results=[AUDIT_VALID, AUDIT_VALID, AUDIT_VALID],
        audit_hashes=[audit_hash, audit_hash, "e" * 64],
    )
    assert evidence["audit_final"] == AUDIT_DISPUTED
    assert evidence["human_review_required"] is True
    assert evidence["execution_allowed"] is False


def test_hydra_audit_future_timestamp_beyond_skew_returns_invalid(tmp_path: Path, monkeypatch) -> None:
    export = _decision_export(tmp_path, monkeypatch)
    now_epoch = 1800000000
    audit_hash = _audit_hash(export)
    results = [
        _sign_result(export, "audit-verifier-1", AUDIT_VALID, audit_hash, verified_at_epoch=now_epoch),
        _sign_result(export, "audit-verifier-2", AUDIT_VALID, audit_hash, verified_at_epoch=now_epoch + 301),
        _sign_result(export, "audit-verifier-3", AUDIT_VALID, audit_hash, verified_at_epoch=now_epoch),
    ]

    assert evaluate_hydra_audit_results(results, now_epoch=now_epoch) == AUDIT_INVALID


def test_hydra_audit_expired_verifier_key_returns_invalid(tmp_path: Path, monkeypatch) -> None:
    _write_registry(
        tmp_path,
        monkeypatch,
        lambda registry: registry["nodes"][0].update({"valid_until_epoch": 100}),
    )
    export = _decision_export(tmp_path, monkeypatch)
    results = simulate_verifier_nodes(export)

    assert evaluate_hydra_audit_results(results) == AUDIT_INVALID


def test_hydra_audit_strict_remains_default() -> None:
    policy = json.loads(hydra_verify.POLICY_REGISTRY_PATH.read_text(encoding="utf-8"))
    assert "signature_policy_mode" not in policy
    assert load_policy_signature_mode() == "STRICT"


def test_hydra_audit_registry_contains_active_key_governance() -> None:
    registry = load_verifier_node_registry()
    for node in registry["nodes"]:
        assert node["status"] == "active"
        assert node["verifier_pubkey_id"]
        assert node["valid_from_epoch"] < node["valid_until_epoch"]
        assert node["trust_domain"]
