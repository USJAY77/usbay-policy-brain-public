from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

from scripts.hydra_verify_audit import AUDIT_DISPUTED, AUDIT_VALID, evaluate_hydra_audit_results, sign_verifier_result
from scripts.verify_reset_log import (
    GENESIS_HASH,
    expected_entry_hash,
    genesis_log_hash,
    load_actor_key_config,
    load_policy_anchor,
    sign_reset_entry,
)
from tests.request_signing_helpers import request_private_key_pem, request_public_key_pem, sign_payload_ed25519
from tests.test_decide_first import configure_gateway


REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = REPO_ROOT / "demos" / "edgeguard"


def _signed_demo_payload(name: str) -> dict:
    payload = json.loads((DEMO_DIR / name).read_text(encoding="utf-8"))
    payload["nonce"] = uuid.uuid4().hex
    payload["timestamp"] = int(time.time())
    return sign_payload_ed25519(payload)


def _verify(script_name: str, export_path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            f"scripts/{script_name}",
            str(export_path),
            "governance/policy_public.key",
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def _reset_env(tmp_path: Path) -> dict[str, str]:
    actor_public = tmp_path / "actor_public.key"
    actor_config = tmp_path / "actor_keys.json"
    actor_public.write_bytes(request_public_key_pem())
    actor_config.write_text(
        json.dumps(
            {
                "active_keys": ["actor_key_2026_01"],
                "revoked_keys": [],
                "key_map": {"actor_key_2026_01": actor_public.name},
                "validity": {"actor_key_2026_01": {"valid_from": 0, "valid_until": 1893456000}},
                "default_actor_pubkey_id": "actor_key_2026_01",
                "max_clock_skew_seconds": 60,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    env["USBAY_ACTOR_KEYS_PATH"] = str(actor_config)
    env["USBAY_ACTOR_SIGNING_KEY"] = request_private_key_pem().decode("utf-8")
    return env


def test_edgeguard_cloud_high_sensitivity_denied(tmp_path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)

    response = client.post("/decide", json=_signed_demo_payload("payload_cloud_denied.json"))

    assert response.status_code == 403
    assert response.json()["decision"] == "DENY"
    assert response.json()["reason"] == "compute_target_not_allowed"


def test_edgeguard_local_npu_high_sensitivity_allowed_and_verifiable(tmp_path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)

    response = client.post("/decide", json=_signed_demo_payload("payload_npu_allowed.json"))

    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"

    export = client.get(f"/audit/export/{response.json()['decision_id']}").json()
    record = export["decision_record"]
    assert record["compute_target"] == "npu"
    assert record["execution_location"] == "local"
    assert record["data_sensitivity"] == "high"
    assert record["compute_policy_hash"]
    assert record["policy_hash"]
    assert record["request_hash"]
    assert record["signature_valid"] is True

    export_path = tmp_path / "edgeguard-export.json"
    export_path.write_text(json.dumps(export, sort_keys=True), encoding="utf-8")

    decision_verify = _verify("verify_decision.py", export_path)
    hydra_verify = _verify("hydra_verify_audit.py", export_path)

    assert decision_verify.returncode == 0
    assert decision_verify.stdout.strip() == "VALID"
    assert hydra_verify.returncode == 0
    assert hydra_verify.stdout.strip() == "VALID"


def test_edgeguard_reset_refuses_wrong_path(tmp_path) -> None:
    result = subprocess.run(
        ["bash", "demos/edgeguard/reset_demo.sh"],
        cwd=REPO_ROOT,
        env={"EDGEGUARD_OUT_DIR": str(tmp_path)},
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "FAIL: wrong_path" in result.stderr


def test_edgeguard_reset_preserves_out_dir_and_writes_audit_log(tmp_path) -> None:
    out_dir = DEMO_DIR / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    audit_log = out_dir / "reset_audit.log"
    audit_log.unlink(missing_ok=True)
    generated_json = out_dir / "generated-test.json"
    generated_txt = out_dir / "generated-test.txt"
    generated_log = out_dir / "generated-test.log"
    for artifact in (generated_json, generated_txt, generated_log):
        artifact.write_text("generated\n", encoding="utf-8")

    result = subprocess.run(
        ["bash", "demos/edgeguard/reset_demo.sh"],
        cwd=REPO_ROOT,
        env=_reset_env(tmp_path),
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert out_dir.is_dir()
    assert not generated_json.exists()
    assert not generated_txt.exists()
    assert not generated_log.exists()
    assert audit_log.exists()
    audit_text = audit_log.read_text(encoding="utf-8")
    assert "generated-test.json" in audit_text
    entries = [json.loads(line) for line in audit_text.strip().splitlines()]
    entry = entries[0]
    assert entry["actor_id"] == "local_demo_operator"
    assert entry["actor_pubkey_id"] == "actor_key_2026_01"
    assert entry["actor_signature"]
    assert entry["file_list_deleted"]
    assert entry["previous_log_hash"] == "0" * 64
    assert entry["current_log_hash"]
    assert entry["genesis_log_hash"]
    assert entry["genesis_policy_signature"]
    assert entries[-1]["event_type"] == "reset_result"


def test_edgeguard_reset_log_tampering_is_invalid(tmp_path) -> None:
    env = _reset_env(tmp_path)
    out_dir = DEMO_DIR / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    audit_log = out_dir / "reset_audit.log"
    audit_log.unlink(missing_ok=True)
    (out_dir / "generated-tamper-test.json").write_text("generated\n", encoding="utf-8")

    first = subprocess.run(
        ["bash", "demos/edgeguard/reset_demo.sh"],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert first.returncode == 0

    original = audit_log.read_text(encoding="utf-8")
    tampered = original.replace("local_demo_operator", "tampered_actor", 1)
    audit_log.write_text(tampered, encoding="utf-8")

    try:
        verify = subprocess.run(
            ["bash", "demos/edgeguard/reset_demo.sh", "--verify-log"],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        rerun = subprocess.run(
            ["bash", "demos/edgeguard/reset_demo.sh"],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        audit_log.write_text(original, encoding="utf-8")

    assert verify.returncode != 0
    assert verify.stdout.strip() == "INVALID"
    assert rerun.returncode != 0
    assert "FAIL: reset_log_tampering_detected" in rerun.stderr


def test_edgeguard_reset_missing_signature_is_invalid(tmp_path) -> None:
    env = _reset_env(tmp_path)
    out_dir = DEMO_DIR / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    audit_log = out_dir / "reset_audit.log"
    audit_log.unlink(missing_ok=True)
    (out_dir / "generated-missing-signature-test.json").write_text("generated\n", encoding="utf-8")

    first = subprocess.run(
        ["bash", "demos/edgeguard/reset_demo.sh"],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert first.returncode == 0

    original = audit_log.read_text(encoding="utf-8")
    entry = json.loads(original.strip().splitlines()[-1])
    entry.pop("actor_signature")
    audit_log.write_text(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    try:
        verify = subprocess.run(
            ["bash", "demos/edgeguard/reset_demo.sh", "--verify-log"],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        audit_log.write_text(original, encoding="utf-8")

    assert verify.returncode != 0
    assert verify.stdout.strip() == "INVALID"


def test_edgeguard_reset_revoked_actor_key_is_invalid(tmp_path) -> None:
    env = _reset_env(tmp_path)
    actor_keys_path = Path(env["USBAY_ACTOR_KEYS_PATH"])
    original_actor_keys = actor_keys_path.read_text(encoding="utf-8")
    out_dir = DEMO_DIR / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    audit_log = out_dir / "reset_audit.log"
    audit_log.unlink(missing_ok=True)
    (out_dir / "generated-revoked-actor-test.json").write_text("generated\n", encoding="utf-8")

    first = subprocess.run(
        ["bash", "demos/edgeguard/reset_demo.sh"],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert first.returncode == 0

    actor_config = json.loads(original_actor_keys)
    actor_config["revoked_keys"] = ["actor_key_2026_01"]
    actor_keys_path.write_text(json.dumps(actor_config, sort_keys=True), encoding="utf-8")
    try:
        verify = subprocess.run(
            [sys.executable, "scripts/verify_reset_log.py", str(audit_log)],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        actor_keys_path.write_text(original_actor_keys, encoding="utf-8")

    assert verify.returncode != 0
    assert verify.stdout.strip() == "INVALID"


def test_edgeguard_reset_broken_chain_is_invalid(tmp_path) -> None:
    env = _reset_env(tmp_path)
    out_dir = DEMO_DIR / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    audit_log = out_dir / "reset_audit.log"
    audit_log.unlink(missing_ok=True)
    (out_dir / "generated-broken-chain-test.json").write_text("generated\n", encoding="utf-8")

    first = subprocess.run(
        ["bash", "demos/edgeguard/reset_demo.sh"],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert first.returncode == 0

    original = audit_log.read_text(encoding="utf-8")
    entries = [json.loads(line) for line in original.strip().splitlines()]
    entries[-1]["previous_log_hash"] = "f" * 64
    audit_log.write_text("\n".join(json.dumps(entry, sort_keys=True, separators=(",", ":")) for entry in entries) + "\n", encoding="utf-8")
    try:
        verify = subprocess.run(
            [sys.executable, "scripts/verify_reset_log.py", str(audit_log)],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        audit_log.write_text(original, encoding="utf-8")

    assert verify.returncode != 0
    assert verify.stdout.strip() == "INVALID"


def test_edgeguard_reset_fake_actor_is_invalid(tmp_path) -> None:
    env = _reset_env(tmp_path)
    out_dir = DEMO_DIR / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    audit_log = out_dir / "reset_audit.log"
    audit_log.unlink(missing_ok=True)
    (out_dir / "generated-fake-actor-test.json").write_text("generated\n", encoding="utf-8")

    first = subprocess.run(
        ["bash", "demos/edgeguard/reset_demo.sh"],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert first.returncode == 0

    original = audit_log.read_text(encoding="utf-8")
    entry = json.loads(original.strip().splitlines()[-1])
    entry["actor_pubkey_id"] = "unknown_actor_key"
    audit_log.write_text(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    try:
        verify = subprocess.run(
            ["bash", "demos/edgeguard/reset_demo.sh", "--verify-log"],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        audit_log.write_text(original, encoding="utf-8")

    assert verify.returncode != 0
    assert verify.stdout.strip() == "INVALID"


def test_edgeguard_reset_hydra_verification_validates_signed_log(tmp_path) -> None:
    env = _reset_env(tmp_path)
    out_dir = DEMO_DIR / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    audit_log = out_dir / "reset_audit.log"
    audit_log.unlink(missing_ok=True)
    (out_dir / "generated-hydra-reset-test.json").write_text("generated\n", encoding="utf-8")

    reset = subprocess.run(
        ["bash", "demos/edgeguard/reset_demo.sh"],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    hydra = subprocess.run(
        [sys.executable, "scripts/hydra_verify_audit.py", "--reset-log", str(audit_log)],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert reset.returncode == 0
    assert hydra.returncode == 0
    assert hydra.stdout.strip() == "VALID"


def test_edgeguard_reset_hydra_mixed_hashes_is_disputed() -> None:
    good_hash = "a" * 64
    bad_hash = "b" * 64
    results = [
        sign_verifier_result("audit-verifier-1", AUDIT_VALID, good_hash, policy_version="edgeguard-reset-audit-v1", policy_hash=good_hash),
        sign_verifier_result("audit-verifier-2", AUDIT_VALID, good_hash, policy_version="edgeguard-reset-audit-v1", policy_hash=good_hash),
        sign_verifier_result("audit-verifier-3", AUDIT_VALID, bad_hash, policy_version="edgeguard-reset-audit-v1", policy_hash=good_hash),
    ]

    assert evaluate_hydra_audit_results(results) == AUDIT_DISPUTED


def test_edgeguard_reset_rotation_preserves_anchor_and_verifies(tmp_path) -> None:
    env = _reset_env(tmp_path)
    retention_path = REPO_ROOT / "governance" / "log_retention.json"
    original_retention = retention_path.read_text(encoding="utf-8")
    out_dir = DEMO_DIR / "out"
    archive_dir = REPO_ROOT / "demos" / "edgeguard" / "archive"
    out_dir.mkdir(parents=True, exist_ok=True)
    audit_log = out_dir / "reset_audit.log"
    audit_log.unlink(missing_ok=True)
    (out_dir / "generated-rotation-test.json").write_text("generated\n", encoding="utf-8")

    first = subprocess.run(
        ["bash", "demos/edgeguard/reset_demo.sh"],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert first.returncode == 0

    retention = json.loads(original_retention)
    retention["max_log_size_mb"] = 0.000001
    retention_path.write_text(json.dumps(retention, sort_keys=True), encoding="utf-8")
    (out_dir / "generated-after-rotation-test.json").write_text("generated\n", encoding="utf-8")
    try:
        rotated = subprocess.run(
            ["bash", "demos/edgeguard/reset_demo.sh"],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        verify = subprocess.run(
            [sys.executable, "scripts/verify_reset_log.py", str(audit_log)],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        retention_path.write_text(original_retention, encoding="utf-8")

    assert rotated.returncode == 0
    assert verify.returncode == 0
    assert verify.stdout.strip() == "VALID"
    assert any(archive_dir.glob("reset_audit.*.archive.log"))


def test_edgeguard_reset_future_timestamp_exceeding_skew_is_invalid(tmp_path) -> None:
    env = _reset_env(tmp_path)
    out_dir = DEMO_DIR / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    audit_log = out_dir / "reset_audit.log"
    original = audit_log.read_text(encoding="utf-8") if audit_log.exists() else None
    _policy_hash, policy_signature = load_policy_anchor()
    actor_config = load_actor_key_config(Path(env["USBAY_ACTOR_KEYS_PATH"]))
    entry = {
        "timestamp": "2100-01-01T00:00:00Z",
        "event_type": "reset_intent",
        "actor_id": "local_demo_operator",
        "actor_pubkey_id": "actor_key_2026_01",
        "file_list_deleted": [],
        "previous_log_hash": GENESIS_HASH,
        "genesis_log_hash": genesis_log_hash(),
        "genesis_policy_signature": policy_signature,
    }
    original_actor_key_env = os.environ.get("USBAY_ACTOR_SIGNING_KEY")
    os.environ["USBAY_ACTOR_SIGNING_KEY"] = env["USBAY_ACTOR_SIGNING_KEY"]
    try:
        entry["actor_signature"] = sign_reset_entry(entry, actor_config)
    finally:
        if original_actor_key_env is None:
            os.environ.pop("USBAY_ACTOR_SIGNING_KEY", None)
        else:
            os.environ["USBAY_ACTOR_SIGNING_KEY"] = original_actor_key_env
    entry["current_log_hash"] = expected_entry_hash(GENESIS_HASH, entry)
    audit_log.write_text(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    try:
        verify = subprocess.run(
            [sys.executable, "scripts/verify_reset_log.py", str(audit_log)],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        if original is None:
            audit_log.unlink(missing_ok=True)
        else:
            audit_log.write_text(original, encoding="utf-8")

    assert verify.returncode != 0
    assert verify.stdout.strip() == "INVALID"
