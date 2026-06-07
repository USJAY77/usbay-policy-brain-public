#!/usr/bin/env python3
"""PB-014 local governance recovery validation.

PB-014 validates that USBAY can restore its local certified governance
baseline after simulated artifact loss or corruption. Simulations run only in
an isolated recovery workspace and never modify source governance artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BACKUP_MANIFEST = "pb014_recovery_backup_manifest.json"
SIMULATION_REPORT = "pb014_recovery_simulation_report.json"
VERIFICATION_REPORT = "pb014_recovery_verification_report.json"
SCORECARD = "pb014_recovery_scorecard.json"
BACKUP_SCHEMA = "usbay.pb014.recovery_backup_manifest.v1"
SIMULATION_SCHEMA = "usbay.pb014.recovery_simulation_report.v1"
VERIFICATION_SCHEMA = "usbay.pb014.recovery_verification_report.v1"
SCORECARD_SCHEMA = "usbay.pb014.recovery_scorecard.v1"
BACKUP_KEY_ID = "USBAY-PB014-LOCAL-GOVERNANCE-RECOVERY-CONTROL"

PB012_FILES = [
    "governance/evidence/pb012_control_registry/governance_control_registry.json",
    "governance/evidence/pb012_control_registry/governance_control_manifest.json",
    "governance/evidence/pb012_control_registry/governance_self_attestation.json",
]
PB010_REFERENCE_FILES = [
    "governance/evidence/pb010_chain/pb010_chain_verification_report.json",
]
PB011_REFERENCE_FILES = [
    "governance/evidence/pb011_baseline/pb011_drift_report.json",
]
PB013_FILES = [
    "governance/evidence/pb013_monitor/pb013_governance_health_report.json",
    "governance/evidence/pb013_monitor/pb013_governance_risk_score.json",
    "governance/evidence/pb013_monitor/pb013_governance_monitor_report.json",
    "governance/evidence/pb013_monitor/pb013_governance_status_summary.json",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.name}:JSON_INVALID:{exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name}:JSON_OBJECT_REQUIRED")
    return payload


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def backup_signature(payload: dict[str, Any]) -> str:
    return sha256_bytes(
        canonical(
            {
                "backup_key_id": BACKUP_KEY_ID,
                "payload": payload,
            }
        ).encode("utf-8")
    )


def load_required_paths(project_root: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    registry_path = project_root / "governance/evidence/pb012_control_registry/governance_control_registry.json"
    if not registry_path.is_file():
        return [], ["PB014_RECOVERY_BASELINE_MISSING:governance_control_registry.json"]
    try:
        registry = load_json(registry_path)
    except Exception as exc:
        return [], [f"PB014_RECOVERY_BASELINE_INVALID:{exc}"]
    if registry.get("schema") != "usbay.pb012.governance_control_registry.v1":
        errors.append("PB014_REGISTRY_MISMATCH_AFTER_RECOVERY")
    controls = registry.get("controls")
    if not isinstance(controls, list):
        errors.append("PB014_RECOVERY_BASELINE_INVALID:controls")
        controls = []
    paths: list[str] = []
    for control in controls:
        definition_paths = control.get("definition_paths")
        if not isinstance(definition_paths, list):
            errors.append(f"PB014_RECOVERY_BASELINE_INVALID:{control.get('control_id')}:definition_paths")
            continue
        paths.extend(str(path) for path in definition_paths)
    paths.extend(PB012_FILES)
    paths.extend(PB010_REFERENCE_FILES)
    paths.extend(PB011_REFERENCE_FILES)
    paths.extend(PB013_FILES)
    return sorted(dict.fromkeys(paths)), errors


def copy_artifact(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def build_backup(project_root: Path, output_dir: Path) -> tuple[dict[str, Any], list[str]]:
    required_paths, errors = load_required_paths(project_root)
    artifact_hashes: dict[str, str] = {}
    backup_root = output_dir / "backup_artifacts"
    if backup_root.exists():
        shutil.rmtree(backup_root)
    backup_root.mkdir(parents=True, exist_ok=True)
    for relative_path in required_paths:
        source = project_root / relative_path
        if not source.is_file():
            errors.append(f"PB014_RECOVERY_BASELINE_MISSING:{relative_path}")
            continue
        artifact_hashes[relative_path] = sha256_file(source)
        copy_artifact(source, backup_root / relative_path)
    generated_at = utc_now()
    manifest = {
        "schema": BACKUP_SCHEMA,
        "generated_at": generated_at,
        "decision": "VERIFIED" if not errors else "BLOCKED",
        "fail_closed": bool(errors),
        "errors": errors,
        "backup_id": sha256_bytes(canonical(artifact_hashes).encode("utf-8")),
        "backup_root": backup_root.resolve().as_posix(),
        "artifact_hashes": artifact_hashes,
        "artifact_count": len(artifact_hashes),
        "aggregate_hash": sha256_bytes(canonical(artifact_hashes).encode("utf-8")),
        "registry_source": "governance/evidence/pb012_control_registry/governance_control_registry.json",
        "monitor_source": "governance/evidence/pb013_monitor",
        "local_governance_recovery_validation_only": True,
        "no_external_backup_certification_claim": True,
        "no_worm_certification_claim": True,
        "no_disaster_recovery_certification_claim": True,
        "no_production_readiness_claim": True,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "tsa_access_performed": False,
        "external_network_access_performed": False,
    }
    manifest["signature"] = {
        "algorithm": "SHA256_DETERMINISTIC_RECOVERY_BACKUP_SIGNATURE",
        "backup_key_id": BACKUP_KEY_ID,
        "signature_hash": backup_signature(manifest),
    }
    write_json(output_dir / BACKUP_MANIFEST, manifest)
    return manifest, errors


def verify_backup_manifest(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema") != BACKUP_SCHEMA:
        errors.append("PB014_RECOVERY_BACKUP_SCHEMA_INVALID")
    signature = manifest.get("signature")
    if not isinstance(signature, dict):
        errors.append("PB014_RECOVERY_BACKUP_SIGNATURE_MISSING")
    else:
        unsigned = dict(manifest)
        unsigned.pop("signature", None)
        if signature.get("backup_key_id") != BACKUP_KEY_ID:
            errors.append("PB014_RECOVERY_BACKUP_KEY_ID_MISMATCH")
        if signature.get("signature_hash") != backup_signature(unsigned):
            errors.append("PB014_RECOVERY_BACKUP_MANIFEST_MISMATCH")
    hashes = manifest.get("artifact_hashes")
    if not isinstance(hashes, dict) or not hashes:
        errors.append("PB014_RECOVERY_BASELINE_MISSING:artifact_hashes")
    elif manifest.get("aggregate_hash") != sha256_bytes(canonical(hashes).encode("utf-8")):
        errors.append("PB014_RECOVERY_BACKUP_MANIFEST_MISMATCH")
    backup_root = Path(str(manifest.get("backup_root", "")))
    if backup_root.is_dir() and isinstance(hashes, dict):
        actual_files = {
            path.relative_to(backup_root).as_posix()
            for path in backup_root.rglob("*")
            if path.is_file()
        }
        for relative_path in sorted(actual_files - set(hashes)):
            errors.append(f"PB014_UNSUPPORTED_RECOVERY_ARTIFACT:{relative_path}")
    return errors


def restore_artifact(backup_root: Path, workspace_root: Path, relative_path: str) -> None:
    source = backup_root / relative_path
    destination = workspace_root / relative_path
    if not source.is_file():
        raise FileNotFoundError(relative_path)
    copy_artifact(source, destination)


def simulate_and_restore(output_dir: Path, manifest: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    errors = verify_backup_manifest(manifest)
    artifact_hashes = manifest.get("artifact_hashes", {})
    if not isinstance(artifact_hashes, dict) or not artifact_hashes:
        report = {
            "schema": SIMULATION_SCHEMA,
            "generated_at": utc_now(),
            "decision": "BLOCKED",
            "fail_closed": True,
            "errors": errors,
            "missing_artifact_recovery_tested": False,
            "corrupted_artifact_recovery_tested": False,
        }
        write_json(output_dir / SIMULATION_REPORT, report)
        return report, errors
    backup_root = Path(str(manifest.get("backup_root", "")))
    workspace_root = output_dir / "recovery_workspace"
    if workspace_root.exists():
        shutil.rmtree(workspace_root)
    for relative_path in sorted(artifact_hashes):
        try:
            restore_artifact(backup_root, workspace_root, relative_path)
        except FileNotFoundError:
            errors.append(f"PB014_RECOVERY_BASELINE_MISSING:{relative_path}")

    paths = sorted(artifact_hashes)
    missing_target = paths[0]
    corrupt_target = paths[-1]
    missing_path = workspace_root / missing_target
    if missing_path.exists():
        missing_path.unlink()
    corrupted_path = workspace_root / corrupt_target
    corrupted_path.write_text("PB014_CORRUPTED_ARTIFACT\n", encoding="utf-8")

    try:
        restore_artifact(backup_root, workspace_root, missing_target)
        missing_recovered = sha256_file(workspace_root / missing_target) == artifact_hashes[missing_target]
    except FileNotFoundError:
        missing_recovered = False
        errors.append(f"PB014_REQUIRED_ARTIFACT_MISSING_AFTER_RECOVERY:{missing_target}")
    try:
        restore_artifact(backup_root, workspace_root, corrupt_target)
        corrupt_recovered = sha256_file(workspace_root / corrupt_target) == artifact_hashes[corrupt_target]
    except FileNotFoundError:
        corrupt_recovered = False
        errors.append(f"PB014_RESTORED_ARTIFACT_HASH_MISMATCH:{corrupt_target}")

    report = {
        "schema": SIMULATION_SCHEMA,
        "generated_at": utc_now(),
        "decision": "VERIFIED" if not errors and missing_recovered and corrupt_recovered else "BLOCKED",
        "fail_closed": bool(errors) or not missing_recovered or not corrupt_recovered,
        "errors": errors,
        "simulated_missing_artifact": missing_target,
        "simulated_corrupted_artifact": corrupt_target,
        "missing_artifact_recovery_tested": True,
        "corrupted_artifact_recovery_tested": True,
        "missing_artifact_recovered": missing_recovered,
        "corrupted_artifact_recovered": corrupt_recovered,
        "workspace_root": workspace_root.resolve().as_posix(),
    }
    write_json(output_dir / SIMULATION_REPORT, report)
    return report, errors


def verify_recovery(output_dir: Path, manifest: dict[str, Any], simulation_errors: list[str]) -> list[str]:
    errors = list(simulation_errors)
    artifact_hashes = manifest.get("artifact_hashes", {})
    workspace_root = output_dir / "recovery_workspace"
    if not isinstance(artifact_hashes, dict) or not artifact_hashes:
        errors.append("PB014_RECOVERY_BASELINE_MISSING:artifact_hashes")
        artifact_hashes = {}
    for relative_path, expected_hash in sorted(artifact_hashes.items()):
        path = workspace_root / relative_path
        if not path.is_file():
            errors.append(f"PB014_REQUIRED_ARTIFACT_MISSING_AFTER_RECOVERY:{relative_path}")
            continue
        if sha256_file(path) != expected_hash:
            errors.append(f"PB014_RESTORED_ARTIFACT_HASH_MISMATCH:{relative_path}")

    expected_files = set(artifact_hashes)
    actual_files = {
        path.relative_to(workspace_root).as_posix()
        for path in workspace_root.rglob("*")
        if path.is_file()
    } if workspace_root.is_dir() else set()
    for relative_path in sorted(actual_files - expected_files):
        errors.append(f"PB014_UNSUPPORTED_RECOVERY_ARTIFACT:{relative_path}")

    def check_report(relative_path: str, schema: str, error: str) -> dict[str, Any]:
        path = workspace_root / relative_path
        try:
            payload = load_json(path)
        except Exception as exc:
            errors.append(f"{error}:{exc}")
            return {}
        if payload.get("schema") != schema or payload.get("decision") != "VERIFIED" or payload.get("fail_closed") is not False:
            errors.append(error)
        return payload

    registry = check_report(
        "governance/evidence/pb012_control_registry/governance_self_attestation.json",
        "usbay.pb012.governance_self_attestation.v1",
        "PB014_REGISTRY_MISMATCH_AFTER_RECOVERY",
    )
    if registry.get("registry_hash_mismatch_detected") is True or registry.get("control_manifest_mismatch_detected") is True:
        errors.append("PB014_REGISTRY_MISMATCH_AFTER_RECOVERY")
    check_report(
        "governance/evidence/pb010_chain/pb010_chain_verification_report.json",
        "usbay.pb010.chain_verification_report.v1",
        "PB014_PB010_CERTIFICATION_MISMATCH_AFTER_RECOVERY",
    )
    check_report(
        "governance/evidence/pb011_baseline/pb011_drift_report.json",
        "usbay.pb011.drift_report.v1",
        "PB014_PB011_DRIFT_MISMATCH_AFTER_RECOVERY",
    )
    health_path = workspace_root / "governance/evidence/pb013_monitor/pb013_governance_health_report.json"
    try:
        health = load_json(health_path)
        if health.get("schema") != "usbay.pb013.governance_health_report.v1":
            errors.append("PB014_PB013_HEALTH_SCHEMA_INVALID_AFTER_RECOVERY")
        if int(health.get("health_score", -1)) < 100:
            errors.append("PB014_PB013_HEALTH_SCORE_BELOW_THRESHOLD")
    except Exception as exc:
        errors.append(f"PB014_PB013_HEALTH_SCORE_BELOW_THRESHOLD:{exc}")

    unique_errors = sorted(dict.fromkeys(errors))
    report = {
        "schema": VERIFICATION_SCHEMA,
        "generated_at": utc_now(),
        "decision": "VERIFIED" if not unique_errors else "BLOCKED",
        "fail_closed": bool(unique_errors),
        "errors": unique_errors,
        "verified_artifact_count": len(artifact_hashes) if not unique_errors else 0,
        "expected_artifact_count": len(artifact_hashes),
        "registry_verified_after_recovery": not any("REGISTRY_MISMATCH" in error for error in unique_errors),
        "pb010_verified_after_recovery": not any("PB010_CERTIFICATION_MISMATCH" in error for error in unique_errors),
        "pb011_verified_after_recovery": not any("PB011_DRIFT_MISMATCH" in error for error in unique_errors),
        "pb013_health_verified_after_recovery": not any("PB013_HEALTH" in error for error in unique_errors),
        "unsupported_recovery_artifact_detected": any("UNSUPPORTED_RECOVERY_ARTIFACT" in error for error in unique_errors),
        "local_governance_recovery_validation_only": True,
        "no_external_backup_certification_claim": True,
        "no_worm_certification_claim": True,
        "no_disaster_recovery_certification_claim": True,
        "no_production_readiness_claim": True,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "tsa_access_performed": False,
        "external_network_access_performed": False,
    }
    write_json(output_dir / VERIFICATION_REPORT, report)
    write_scorecard(output_dir, report)
    return unique_errors


def write_scorecard(output_dir: Path, verification_report: dict[str, Any]) -> None:
    errors = verification_report.get("errors", [])
    scorecard = {
        "schema": SCORECARD_SCHEMA,
        "generated_at": utc_now(),
        "decision": verification_report["decision"],
        "fail_closed": verification_report["fail_closed"],
        "score": 100 if not errors else 0,
        "max_score": 100,
        "missing_backup_detected": any("RECOVERY_BASELINE_MISSING" in error for error in errors),
        "hash_mismatch_detected": any("HASH_MISMATCH" in error for error in errors),
        "missing_after_recovery_detected": any("MISSING_AFTER_RECOVERY" in error for error in errors),
        "registry_mismatch_after_recovery": any("REGISTRY_MISMATCH" in error for error in errors),
        "pb010_mismatch_after_recovery": any("PB010_CERTIFICATION_MISMATCH" in error for error in errors),
        "pb011_mismatch_after_recovery": any("PB011_DRIFT_MISMATCH" in error for error in errors),
        "pb013_health_score_below_threshold": any("PB013_HEALTH_SCORE_BELOW_THRESHOLD" in error for error in errors),
        "unsupported_recovery_artifact_detected": any("UNSUPPORTED_RECOVERY_ARTIFACT" in error for error in errors),
        "local_governance_recovery_validation_only": True,
        "no_external_backup_certification_claim": True,
        "no_worm_certification_claim": True,
        "no_disaster_recovery_certification_claim": True,
        "no_production_readiness_claim": True,
    }
    write_json(output_dir / SCORECARD, scorecard)


def run(project_root: Path, output_dir: Path) -> list[str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest, backup_errors = build_backup(project_root, output_dir)
    _, simulation_errors = simulate_and_restore(output_dir, manifest)
    return verify_recovery(output_dir, manifest, backup_errors + simulation_errors)


def verify_existing(output_dir: Path) -> list[str]:
    manifest_path = output_dir / BACKUP_MANIFEST
    if not manifest_path.is_file():
        errors = ["PB014_RECOVERY_BASELINE_MISSING:pb014_recovery_backup_manifest.json"]
        report = {
            "schema": VERIFICATION_SCHEMA,
            "generated_at": utc_now(),
            "decision": "BLOCKED",
            "fail_closed": True,
            "errors": errors,
        }
        write_json(output_dir / VERIFICATION_REPORT, report)
        write_scorecard(output_dir, report)
        return errors
    manifest = load_json(manifest_path)
    _, simulation_errors = simulate_and_restore(output_dir, manifest)
    return verify_recovery(output_dir, manifest, simulation_errors)


def main() -> int:
    parser = argparse.ArgumentParser(description="PB-014 local governance recovery validation.")
    subparsers = parser.add_subparsers(dest="mode", required=True)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("project_root")
    run_parser.add_argument("output_dir")
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("output_dir")
    args = parser.parse_args()
    if args.mode == "run":
        errors = run(Path(args.project_root).resolve(), Path(args.output_dir).resolve())
    else:
        errors = verify_existing(Path(args.output_dir).resolve())
    if errors:
        print("Decision: BLOCKED")
        for error in errors:
            print(error)
        return 1
    print("Decision: VERIFIED")
    print("PB014_GOVERNANCE_RECOVERY_VALIDATED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
