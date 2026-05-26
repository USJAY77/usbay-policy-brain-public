from __future__ import annotations

import shutil
from pathlib import Path

from governance.deployment_runtime_health import (
    AUDIT_DB_IGNORED,
    DEPLOYMENT_RUNTIME_BLOCKED,
    DEPLOYMENT_RUNTIME_READY,
    STARTUP_FAILED,
    STARTUP_VERIFIED,
    deployment_runtime_health,
    validate_deployment_packaging,
)


ROOT = Path(__file__).resolve().parents[1]


def test_deployment_packaging_validates_startup_and_db_exclusion() -> None:
    evidence = validate_deployment_packaging(ROOT)

    assert evidence["status"] == "READY"
    assert STARTUP_VERIFIED in evidence["reason_codes"]
    assert AUDIT_DB_IGNORED in evidence["reason_codes"]
    assert DEPLOYMENT_RUNTIME_READY in evidence["reason_codes"]
    assert evidence["failures"] == []


def test_deployment_packaging_blocks_default_port_fallback(tmp_path: Path) -> None:
    for filename in ("Dockerfile", ".replit", ".dockerignore"):
        shutil.copy(ROOT / filename, tmp_path / filename)
    shutil.copytree(ROOT / "governance", tmp_path / "governance")
    (tmp_path / ".replit").write_text(
        "[deployment]\nrun = \"python3 -m uvicorn gateway.app:app --host 0.0.0.0 --port ${PORT:-8000}\"\n",
        encoding="utf-8",
    )
    policy_file = tmp_path / "governance" / "deployment_runtime_policy.json"
    policy = policy_file.read_text(encoding="utf-8")
    policy_file.write_text(policy.replace('"port_required": true,', '"default_port": "8000",'), encoding="utf-8")

    evidence = validate_deployment_packaging(tmp_path)

    assert evidence["status"] == "BLOCKED"
    assert "STARTUP_FAILED:default_port_fallback_configured" in evidence["failures"]
    assert "STARTUP_FAILED:default_port_policy_configured" in evidence["failures"]


def test_deployment_packaging_blocks_top_level_run_drift(tmp_path: Path) -> None:
    for filename in ("Dockerfile", ".replit", ".dockerignore"):
        shutil.copy(ROOT / filename, tmp_path / filename)
    shutil.copytree(ROOT / "governance", tmp_path / "governance")
    replit = (tmp_path / ".replit").read_text(encoding="utf-8")
    (tmp_path / ".replit").write_text('run = "python3 stale-start-dev.sh"\n' + replit, encoding="utf-8")

    evidence = validate_deployment_packaging(tmp_path)

    assert evidence["status"] == "BLOCKED"
    assert "STARTUP_FAILED:top_level_run_command_configured" in evidence["failures"]


def test_deployment_packaging_blocks_runtime_source_exclusion(tmp_path: Path) -> None:
    for filename in ("Dockerfile", ".replit", ".dockerignore"):
        shutil.copy(ROOT / filename, tmp_path / filename)
    shutil.copytree(ROOT / "governance", tmp_path / "governance")
    (tmp_path / ".dockerignore").write_text((tmp_path / ".dockerignore").read_text(encoding="utf-8") + "\nruntime/\n", encoding="utf-8")

    evidence = validate_deployment_packaging(tmp_path)

    assert evidence["status"] == "BLOCKED"
    assert STARTUP_FAILED in evidence["reason_codes"]
    assert DEPLOYMENT_RUNTIME_BLOCKED in evidence["reason_codes"]
    assert "STARTUP_FAILED:runtime_source_excluded" in evidence["failures"]


def test_deployment_packaging_blocks_missing_audit_db_ignore(tmp_path: Path) -> None:
    for filename in ("Dockerfile", ".replit", ".dockerignore"):
        shutil.copy(ROOT / filename, tmp_path / filename)
    shutil.copytree(ROOT / "governance", tmp_path / "governance")
    dockerignore = (tmp_path / ".dockerignore").read_text(encoding="utf-8")
    (tmp_path / ".dockerignore").write_text(dockerignore.replace("usbay_audit.db\n", ""), encoding="utf-8")

    evidence = validate_deployment_packaging(tmp_path)

    assert evidence["status"] == "BLOCKED"
    assert "STARTUP_FAILED:forbidden_artifact_not_ignored:usbay_audit.db" in evidence["failures"]


def test_runtime_health_blocks_when_backend_truth_is_not_ready() -> None:
    evidence = deployment_runtime_health(
        root=ROOT,
        runtime_snapshot={
            "status": "FAIL_CLOSED",
            "mode": "FAIL_CLOSED",
            "policy_signature_valid": False,
            "replay_protection_active": False,
            "runtime_parity": {"runtime_parity_status": "UNTRUSTED"},
        },
        audit_chain_entries=[],
    )

    assert evidence["status"] == "BLOCKED"
    assert STARTUP_FAILED in evidence["reason_codes"]
    assert DEPLOYMENT_RUNTIME_BLOCKED in evidence["reason_codes"]


def test_runtime_health_marks_fresh_audit_chain_without_reusing_local_db() -> None:
    evidence = deployment_runtime_health(
        root=ROOT,
        runtime_snapshot={
            "status": "OK",
            "mode": "NORMAL",
            "policy_signature_valid": True,
            "replay_protection_active": True,
            "runtime_parity": {"runtime_parity_status": "VERIFIED"},
        },
        audit_chain_entries=[],
    )

    assert evidence["status"] == "READY"
    assert evidence["port_binding"] == {
        "host": "0.0.0.0",
        "port_source": "PORT",
        "port_required": True,
    }
    assert evidence["audit_db_handling"]["status"] == "IGNORED"
    assert evidence["audit_db_handling"]["state"] == "FRESH_INITIALIZED"
    assert "usbay_audit.db" not in str(evidence)
