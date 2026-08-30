#!/usr/bin/env python3
"""PB-012 local governance control registry.

PB-012 protects and verifies the governance controls themselves. It registers
PB-005 through PB-011, hashes their local definition artifacts, and fails
closed on missing controls, duplicate identifiers, count mismatch, registry
hash mismatch, manifest mismatch, or unauthorized control modification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REGISTRY_NAME = "governance_control_registry.json"
MANIFEST_NAME = "governance_control_manifest.json"
ATTESTATION_NAME = "governance_self_attestation.json"
REGISTRY_SCHEMA = "usbay.pb012.governance_control_registry.v1"
MANIFEST_SCHEMA = "usbay.pb012.governance_control_manifest.v1"
ATTESTATION_SCHEMA = "usbay.pb012.governance_self_attestation.v1"
REGISTRY_KEY_ID = "USBAY-PB012-LOCAL-GOVERNANCE-CONTROL-REGISTRY"

REGISTERED_CONTROLS: list[dict[str, Any]] = [
    {
        "control_id": "PB-005",
        "title": "Durable Evidence Backend Evidence",
        "version": "v1",
        "definition_paths": [
            "governance/evidence/pb005/pb005_endpoint_evidence.json",
            "governance/evidence/pb005/pb005_schema_evidence.json",
            "governance/evidence/pb005/pb005_write_receipt.json",
            "governance/evidence/pb005/pb005_read_receipt.json",
            "governance/evidence/pb005/pb005_persistence_evidence.json",
            "governance/evidence/pb005/pb005_evidence_manifest.json",
            "governance/evidence/pb005/pb005_final_execution_report.json",
        ],
    },
    {
        "control_id": "PB-006",
        "title": "Evidence Integrity Control",
        "version": "v1",
        "definition_paths": [
            "scripts/pb006_evidence_integrity.py",
            "tests/test_pb006_evidence_integrity.py",
            "docs/governance/PB006_EVIDENCE_INTEGRITY_CONTROL.md",
            "governance/evidence/pb005/pb006_signed_evidence_manifest.json",
            "governance/evidence/pb005/pb006_integrity_report.json",
        ],
    },
    {
        "control_id": "PB-007",
        "title": "Independent Evidence Verifier",
        "version": "v1",
        "definition_paths": [
            "scripts/pb007_independent_verifier.py",
            "tests/test_pb007_independent_verifier.py",
            "docs/governance/PB007_INDEPENDENT_VERIFIER.md",
            "governance/evidence/pb005/pb007_verification_report.json",
        ],
    },
    {
        "control_id": "PB-008",
        "title": "RFC3161 Timestamp Control",
        "version": "v1",
        "definition_paths": [
            "scripts/pb008_timestamp_verifier.py",
            "tests/test_pb008_timestamp_verifier.py",
            "docs/governance/PB008_RFC3161_TIMESTAMP_CONTROL.md",
            "governance/evidence/pb005/pb008_timestamp_receipt.json",
            "governance/evidence/pb005/pb008_non_repudiation_report.json",
        ],
    },
    {
        "control_id": "PB-009",
        "title": "Immutable Evidence Archive",
        "version": "v1",
        "definition_paths": [
            "scripts/pb009_immutable_archive.py",
            "tests/test_pb009_immutable_archive.py",
            "docs/governance/PB009_IMMUTABLE_EVIDENCE_ARCHIVE.md",
            "governance/evidence/pb009_archive/pb009_archive_manifest.json",
            "governance/evidence/pb009_archive/pb009_retention_report.json",
            "governance/evidence/pb009_archive/pb009_restore_verification_report.json",
            "governance/evidence/pb009_archive/pb009_archive_integrity_report.json",
        ],
    },
    {
        "control_id": "PB-010",
        "title": "Governance Chain Certification",
        "version": "v1",
        "definition_paths": [
            "scripts/pb010_governance_chain_certifier.py",
            "tests/test_pb010_governance_chain_certifier.py",
            "docs/governance/PB010_GOVERNANCE_CHAIN_CERTIFICATION.md",
            "governance/evidence/pb010_chain/pb010_chain_certificate.json",
            "governance/evidence/pb010_chain/pb010_chain_verification_report.json",
            "governance/evidence/pb010_chain/pb010_governance_scorecard.json",
        ],
    },
    {
        "control_id": "PB-011",
        "title": "Governance Baseline Drift Detection",
        "version": "v1",
        "definition_paths": [
            "scripts/pb011_baseline_drift_detector.py",
            "tests/test_pb011_baseline_drift_detector.py",
            "docs/governance/PB011_BASELINE_DRIFT_DETECTION.md",
            "governance/evidence/pb011_baseline/pb011_baseline_manifest.json",
            "governance/evidence/pb011_baseline/pb011_drift_report.json",
            "governance/evidence/pb011_baseline/pb011_drift_scorecard.json",
        ],
    },
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


def registry_signature(payload: dict[str, Any]) -> str:
    return sha256_bytes(
        canonical(
            {
                "registry_key_id": REGISTRY_KEY_ID,
                "payload": payload,
            }
        ).encode("utf-8")
    )


def normalized_controls(controls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "control_id": str(control["control_id"]),
            "title": str(control["title"]),
            "version": str(control["version"]),
            "definition_paths": sorted(str(path) for path in control["definition_paths"]),
        }
        for control in sorted(controls, key=lambda item: str(item["control_id"]))
    ]


def validate_control_definitions(project_root: Path, controls: list[dict[str, Any]]) -> tuple[list[str], dict[str, str]]:
    errors: list[str] = []
    artifact_hashes: dict[str, str] = {}
    control_ids = [str(control.get("control_id")) for control in controls]
    duplicates = sorted({control_id for control_id in control_ids if control_ids.count(control_id) > 1})
    for control_id in duplicates:
        errors.append(f"PB012_DUPLICATE_CONTROL_IDENTIFIER:{control_id}")

    expected_controls = {f"PB-{index:03d}" for index in range(5, 12)}
    actual_controls = set(control_ids)
    for control_id in sorted(expected_controls - actual_controls):
        errors.append(f"PB012_REGISTERED_CONTROL_MISSING:{control_id}")
    for control_id in sorted(actual_controls - expected_controls):
        errors.append(f"PB012_UNAUTHORIZED_CONTROL_REGISTERED:{control_id}")
    if len(control_ids) != len(expected_controls):
        errors.append("PB012_CONTROL_COUNT_MISMATCH")

    for control in normalized_controls(controls):
        control_id = control["control_id"]
        paths = control["definition_paths"]
        if not paths:
            errors.append(f"PB012_CONTROL_DEFINITION_EMPTY:{control_id}")
            continue
        for relative_path in paths:
            path = project_root / relative_path
            if not path.is_file():
                errors.append(f"PB012_REGISTERED_CONTROL_ARTIFACT_MISSING:{control_id}:{relative_path}")
                continue
            artifact_hashes[f"{control_id}:{relative_path}"] = sha256_file(path)
    return errors, artifact_hashes


def build_registry(project_root: Path, controls: list[dict[str, Any]]) -> dict[str, Any]:
    normalized = normalized_controls(controls)
    return {
        "schema": REGISTRY_SCHEMA,
        "generated_at": utc_now(),
        "control_count": len(normalized),
        "controls": normalized,
        "project_root": project_root.resolve().as_posix(),
        "local_governance_validation_only": True,
        "no_external_certification_claim": True,
        "no_regulatory_certification_claim": True,
        "no_production_readiness_claim": True,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "tsa_access_performed": False,
        "external_network_access_performed": False,
    }


def build_manifest(
    project_root: Path,
    controls: list[dict[str, Any]],
    registry: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    registry = registry or build_registry(project_root, controls)
    errors, artifact_hashes = validate_control_definitions(project_root, controls)
    registry_hash = sha256_bytes(canonical(registry).encode("utf-8"))
    aggregate_hash = sha256_bytes(canonical(artifact_hashes).encode("utf-8"))
    payload = {
        "schema": MANIFEST_SCHEMA,
        "generated_at": utc_now(),
        "decision": "VERIFIED" if not errors else "BLOCKED",
        "fail_closed": bool(errors),
        "errors": errors,
        "registry_hash": registry_hash,
        "control_definition_hashes": artifact_hashes,
        "control_definition_aggregate_hash": aggregate_hash,
        "registered_control_count": len(controls),
        "expected_control_count": 7,
        "registered_controls": [control["control_id"] for control in normalized_controls(controls)],
        "local_governance_validation_only": True,
        "no_external_certification_claim": True,
        "no_regulatory_certification_claim": True,
        "no_production_readiness_claim": True,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "tsa_access_performed": False,
        "external_network_access_performed": False,
    }
    payload["signature"] = {
        "algorithm": "SHA256_DETERMINISTIC_CONTROL_REGISTRY_SIGNATURE",
        "registry_key_id": REGISTRY_KEY_ID,
        "signature_hash": registry_signature(payload),
    }
    return payload, errors


def write_attestation(output_dir: Path, errors: list[str], registry: dict[str, Any], manifest: dict[str, Any]) -> None:
    attestation = {
        "schema": ATTESTATION_SCHEMA,
        "generated_at": utc_now(),
        "decision": "VERIFIED" if not errors else "BLOCKED",
        "fail_closed": bool(errors),
        "errors": errors,
        "registered_control_count": registry.get("control_count"),
        "expected_control_count": 7,
        "registry_hash": manifest.get("registry_hash"),
        "control_definition_aggregate_hash": manifest.get("control_definition_aggregate_hash"),
        "duplicate_control_detected": any("DUPLICATE_CONTROL_IDENTIFIER" in error for error in errors),
        "missing_control_detected": any("REGISTERED_CONTROL_MISSING" in error for error in errors),
        "control_count_mismatch_detected": any("CONTROL_COUNT_MISMATCH" in error for error in errors),
        "registry_hash_mismatch_detected": any("REGISTRY_HASH_MISMATCH" in error for error in errors),
        "control_manifest_mismatch_detected": any("CONTROL_MANIFEST_MISMATCH" in error for error in errors),
        "unauthorized_control_modification_detected": any(
            "CONTROL_DEFINITION_HASH_CHANGED" in error for error in errors
        ),
        "local_governance_validation_only": True,
        "no_external_certification_claim": True,
        "no_regulatory_certification_claim": True,
        "no_production_readiness_claim": True,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "tsa_access_performed": False,
        "external_network_access_performed": False,
    }
    write_json(output_dir / ATTESTATION_NAME, attestation)


def generate(project_root: Path, output_dir: Path, controls: list[dict[str, Any]] | None = None) -> list[str]:
    controls = controls or REGISTERED_CONTROLS
    registry = build_registry(project_root, controls)
    manifest, errors = build_manifest(project_root, controls, registry)
    write_json(output_dir / REGISTRY_NAME, registry)
    write_json(output_dir / MANIFEST_NAME, manifest)
    write_attestation(output_dir, errors, registry, manifest)
    return errors


def verify_manifest_signature(manifest: dict[str, Any]) -> list[str]:
    signature = manifest.get("signature")
    if not isinstance(signature, dict):
        return ["PB012_CONTROL_MANIFEST_SIGNATURE_MISSING"]
    unsigned = dict(manifest)
    unsigned.pop("signature", None)
    errors: list[str] = []
    if signature.get("registry_key_id") != REGISTRY_KEY_ID:
        errors.append("PB012_CONTROL_MANIFEST_KEY_ID_MISMATCH")
    if signature.get("signature_hash") != registry_signature(unsigned):
        errors.append("PB012_CONTROL_MANIFEST_MISMATCH")
    if signature.get("algorithm") != "SHA256_DETERMINISTIC_CONTROL_REGISTRY_SIGNATURE":
        errors.append("PB012_CONTROL_MANIFEST_SIGNATURE_ALGORITHM_INVALID")
    return errors


def verify(project_root: Path, output_dir: Path, controls: list[dict[str, Any]] | None = None) -> list[str]:
    controls = controls or REGISTERED_CONTROLS
    registry_path = output_dir / REGISTRY_NAME
    manifest_path = output_dir / MANIFEST_NAME
    errors: list[str] = []
    if not registry_path.is_file():
        errors.append("PB012_REGISTRY_MISSING")
        registry = build_registry(project_root, controls)
    else:
        try:
            registry = load_json(registry_path)
        except Exception as exc:
            registry = {}
            errors.append(f"PB012_REGISTRY_INVALID:{exc}")
    if not manifest_path.is_file():
        errors.append("PB012_CONTROL_MANIFEST_MISSING")
        manifest = {}
    else:
        try:
            manifest = load_json(manifest_path)
        except Exception as exc:
            manifest = {}
            errors.append(f"PB012_CONTROL_MANIFEST_INVALID:{exc}")

    expected_registry = build_registry(project_root, controls)
    expected_manifest, definition_errors = build_manifest(project_root, controls)
    errors.extend(definition_errors)

    if registry:
        if registry.get("schema") != REGISTRY_SCHEMA:
            errors.append("PB012_REGISTRY_SCHEMA_INVALID")
        if registry.get("control_count") != 7:
            errors.append("PB012_CONTROL_COUNT_MISMATCH")
        stored_controls = registry.get("controls")
        if stored_controls != expected_registry["controls"]:
            errors.append("PB012_REGISTRY_HASH_MISMATCH")
        stored_registry_hash = sha256_bytes(canonical(registry).encode("utf-8"))
    else:
        stored_registry_hash = ""

    if manifest:
        if manifest.get("schema") != MANIFEST_SCHEMA:
            errors.append("PB012_CONTROL_MANIFEST_SCHEMA_INVALID")
        errors.extend(verify_manifest_signature(manifest))
        if manifest.get("registry_hash") != stored_registry_hash:
            errors.append("PB012_REGISTRY_HASH_MISMATCH")
        if manifest.get("registered_control_count") != 7 or manifest.get("expected_control_count") != 7:
            errors.append("PB012_CONTROL_COUNT_MISMATCH")
        current_hashes = expected_manifest["control_definition_hashes"]
        stored_hashes = manifest.get("control_definition_hashes")
        if not isinstance(stored_hashes, dict):
            errors.append("PB012_CONTROL_MANIFEST_HASHES_MISSING")
            stored_hashes = {}
        for artifact, expected_hash in sorted(stored_hashes.items()):
            actual_hash = current_hashes.get(artifact)
            if actual_hash is None:
                errors.append(f"PB012_REGISTERED_CONTROL_ARTIFACT_MISSING:{artifact}")
            elif actual_hash != expected_hash:
                errors.append(f"PB012_CONTROL_DEFINITION_HASH_CHANGED:{artifact}")
        for artifact in sorted(set(current_hashes) - set(stored_hashes)):
            errors.append(f"PB012_CONTROL_MANIFEST_MISSING_HASH:{artifact}")
        if manifest.get("control_definition_aggregate_hash") != sha256_bytes(
            canonical(current_hashes).encode("utf-8")
        ):
            errors.append("PB012_CONTROL_MANIFEST_MISMATCH")

    unique_errors = sorted(dict.fromkeys(errors))
    effective_registry = registry if registry else expected_registry
    effective_manifest = manifest if manifest else expected_manifest
    write_attestation(output_dir, unique_errors, effective_registry, effective_manifest)
    return unique_errors


def main() -> int:
    parser = argparse.ArgumentParser(description="PB-012 local governance control registry.")
    subparsers = parser.add_subparsers(dest="mode", required=True)
    for mode in ("generate", "verify"):
        command = subparsers.add_parser(mode)
        command.add_argument("project_root")
        command.add_argument("output_dir")
    args = parser.parse_args()
    project_root = Path(args.project_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    errors = generate(project_root, output_dir) if args.mode == "generate" else verify(project_root, output_dir)
    if errors:
        print("Decision: BLOCKED")
        for error in errors:
            print(error)
        return 1
    print("Decision: VERIFIED")
    print("PB012_GOVERNANCE_CONTROL_REGISTRY_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
