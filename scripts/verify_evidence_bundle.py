#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from audit.anchor import verify_event
from audit.immutable_ledger import GENESIS_HASH, canonical_json, compute_event_hash, ledger_sha256
from audit.keys import resolve_public_key
from audit.rfc3161_anchor import component_hashes, message_imprint
from security.deployment_attestation import validate_release_manifest
from security.tenant_context import (
    TenantIsolationError,
    tenant_hash,
    validate_consensus_tenant,
    validate_records_single_tenant,
)


REQUIRED_FILES = (
    "audit.jsonl",
    "ledger.sha256",
    "signatures.json",
    "rfc3161_timestamp.tsr",
    "timestamp_verification.json",
    "tsa_certificate_chain.pem",
    "tsa_policy_oid.txt",
    "governance_release.json",
)
OPTIONAL_HASHED_FILES = ("consensus_evidence.json",)
FORBIDDEN_MARKERS = (
    "BEGIN " + "PRIVATE " + "KEY",
    "raw_nonce",
    "raw_payload",
    "approval_contents",
    "approval_material",
    "private" + "_" + "key",
    "secret",
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _json_loads(text: str, control_id: str, failures: list[str]) -> Any:
    try:
        return json.loads(text)
    except Exception:
        failures.append(control_id)
        return None


def _parse_audit_jsonl(text: str, failures: list[str]) -> list[dict[str, Any]]:
    records = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parsed = _json_loads(line, "AUDIT_JSONL_MALFORMED", failures)
        if not isinstance(parsed, dict):
            failures.append("AUDIT_RECORD_MALFORMED")
            continue
        records.append(parsed)
    if not records:
        failures.append("AUDIT_JSONL_EMPTY")
    return records


def _decode_token(token: str, failures: list[str]) -> dict[str, Any] | None:
    try:
        decoded = base64.b64decode(token.encode("ascii"), validate=True)
        parsed = json.loads(decoded.decode("utf-8"))
    except Exception:
        failures.append("RFC3161_TOKEN_MALFORMED")
        return None
    if not isinstance(parsed, dict):
        failures.append("RFC3161_TOKEN_MALFORMED")
        return None
    return parsed


def _parse_utc(value: str, failures: list[str], control_id: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timezone_required")
        return parsed.astimezone(timezone.utc)
    except Exception:
        failures.append(control_id)
        return None


def _check_no_secret_leakage(file_texts: dict[str, str], failures: list[str]) -> None:
    combined = "\n".join(file_texts.values()).lower()
    if any(marker.lower() in combined for marker in FORBIDDEN_MARKERS):
        failures.append("NO_SECRET_LEAKAGE")


def _verify_hash_chain(records: list[dict[str, Any]], failures: list[str]) -> None:
    previous_hash = GENESIS_HASH
    seen_event_ids: set[str] = set()
    for index, record in enumerate(records):
        required = {
            "event_id",
            "previous_event_hash",
            "current_event_hash",
            "timestamp",
            "node_id",
            "policy_hash",
            "consensus_result",
            "tenant_id",
            "tenant_hash",
        }
        if any(record.get(field) in (None, "") for field in required):
            failures.append(f"AUDIT_REQUIRED_FIELDS:{index}")
            continue
        if record["event_id"] in seen_event_ids:
            failures.append(f"AUDIT_EVENT_ID_DUPLICATE:{index}")
        seen_event_ids.add(str(record["event_id"]))
        if record.get("previous_event_hash") != previous_hash:
            failures.append(f"HASH_CHAIN_CONTINUITY:{index}")
        if compute_event_hash(record) != record.get("current_event_hash"):
            failures.append(f"AUDIT_EVENT_HASH:{index}")
        previous_hash = str(record.get("current_event_hash", ""))


def _verify_signatures(records: list[dict[str, Any]], signatures: dict[str, Any], failures: list[str]) -> None:
    for index, record in enumerate(records):
        event_id = str(record.get("event_id", ""))
        signature_record = signatures.get(event_id)
        if not isinstance(signature_record, dict):
            failures.append(f"SIGNATURE_MISSING:{index}")
            continue
        if signature_record.get("current_event_hash") != record.get("current_event_hash"):
            failures.append(f"SIGNATURE_HASH_MISMATCH:{index}")
        try:
            public_key = resolve_public_key(str(signature_record.get("public_key_id", "")))
            if not verify_event(
                str(record.get("current_event_hash", "")),
                str(signature_record.get("signature", "")),
                public_key,
            ):
                failures.append(f"SIGNATURE_INVALID:{index}")
        except Exception:
            failures.append(f"SIGNATURE_PUBLIC_KEY_UNRESOLVED:{index}")


def _verify_timestamp(
    *,
    token_text: str,
    verification: dict[str, Any],
    certificate_chain: str,
    policy_oid: str,
    expected_imprint: str,
    failures: list[str],
) -> dict[str, Any]:
    summary = {
        "message_imprint": verification.get("message_imprint"),
        "policy_oid": verification.get("policy_oid"),
        "valid": verification.get("valid") is True,
        "certificate_chain_present": bool(certificate_chain.strip()),
        "revocation_status": verification.get("revocation_status"),
        "errors": list(verification.get("errors", [])) if isinstance(verification.get("errors"), list) else [],
    }
    if verification.get("valid") is not True:
        failures.append("TIMESTAMP_METADATA_INVALID")
    token_payload = _decode_token(token_text.strip(), failures)
    if token_payload is None:
        return summary
    token_imprint = token_payload.get("message_imprint", token_payload.get("hash"))
    if token_imprint != expected_imprint or verification.get("message_imprint") != expected_imprint:
        failures.append("RFC3161_MESSAGE_IMPRINT")
    if verification.get("policy_oid") != policy_oid.strip():
        failures.append("TSA_POLICY_OID")
    if token_payload.get("policy") and token_payload.get("policy") != policy_oid.strip():
        failures.append("TSA_POLICY_OID")
    if not certificate_chain.strip():
        failures.append("TSA_CERTIFICATE_CHAIN")
    if verification.get("certificate_chain_valid") is not True:
        failures.append("TSA_CERTIFICATE_CHAIN_VALIDATION")
    if verification.get("revocation_status") in (None, ""):
        failures.append("TSA_REVOCATION_STATUS")
    if verification.get("revocation_valid") is not True:
        failures.append("TSA_REVOCATION_STATUS")
    now = datetime.now(timezone.utc)
    not_before = _parse_utc(str(verification.get("tsa_cert_not_before", "")), failures, "TSA_CERT_NOT_BEFORE")
    not_after = _parse_utc(str(verification.get("tsa_cert_not_after", "")), failures, "TSA_CERT_NOT_AFTER")
    if not_before and not_before > now:
        failures.append("TSA_CERT_NOT_YET_VALID")
    if not_after and not_after <= now:
        failures.append("TSA_CERT_EXPIRED")
    if verification.get("message_imprint_valid") is not True:
        failures.append("RFC3161_MESSAGE_IMPRINT")
    if verification.get("token_signature_valid") is not True:
        failures.append("RFC3161_TOKEN_SIGNATURE")
    return summary


def _verify_attestation_evidence(consensus_evidence: dict[str, Any], failures: list[str], tenant_id: str) -> dict[str, Any]:
    attestation_count = 0
    required = {
        "logical_node_id",
        "node_id",
        "node_role",
        "provider_mode",
        "hardware_backed",
        "attestation_hash",
        "attestation_timestamp",
        "tenant_id",
        "tenant_hash",
    }
    for event_id, evidence in consensus_evidence.items():
        if not isinstance(evidence, dict):
            failures.append(f"ATTESTATION_CONSENSUS_EVIDENCE_MALFORMED:{event_id}")
            continue
        attestations = evidence.get("attestation_evidence")
        if not isinstance(attestations, list) or not attestations:
            failures.append(f"ATTESTATION_EVIDENCE_MISSING:{event_id}")
            continue
        attestation_count += len(attestations)
        for index, attestation in enumerate(attestations):
            if not isinstance(attestation, dict):
                failures.append(f"ATTESTATION_EVIDENCE_MALFORMED:{event_id}:{index}")
                continue
            if any(attestation.get(field) in (None, "") for field in required):
                failures.append(f"ATTESTATION_EVIDENCE_INCOMPLETE:{event_id}:{index}")
            if attestation.get("tenant_id") != tenant_id or attestation.get("tenant_hash") != tenant_hash(tenant_id):
                failures.append(f"ATTESTATION_TENANT_MISMATCH:{event_id}:{index}")
            if str(attestation.get("provider_mode")) == "mock_local" and attestation.get("hardware_backed") is True:
                failures.append(f"ATTESTATION_HARDWARE_FLAG_INVALID:{event_id}:{index}")
            safe_projection = {
                key: attestation.get(key)
                for key in sorted(required)
            }
            lowered = json.dumps(safe_projection, sort_keys=True, separators=(",", ":")).lower()
            if "raw_device" in lowered or "device_serial" in lowered or ("private" + "_" + "key") in lowered:
                failures.append(f"ATTESTATION_SECRET_LEAKAGE:{event_id}:{index}")
    return {"attestation_count": attestation_count}


def _verify_deployment_provenance(bundle_dir: Path, failures: list[str], tenant_id: str) -> dict[str, Any]:
    try:
        provenance = validate_release_manifest(bundle_dir / "governance_release.json")
    except Exception as exc:
        failures.append(f"DEPLOYMENT_PROVENANCE:{exc}")
        return {}
    if provenance.get("tenant_id") != tenant_id:
        failures.append("TENANT_DEPLOYMENT_PROVENANCE_MISMATCH")
        return {}
    return {
        "release_id": provenance["release_id"],
        "release_hash": provenance["release_hash"],
        "policy_bundle_hash": provenance["policy_bundle_hash"],
        "activating_node_id": provenance["activating_node_id"],
    }


def verify_bundle(bundle_dir: Path) -> dict[str, Any]:
    failures: list[str] = []
    file_hashes: dict[str, str] = {}
    file_texts: dict[str, str] = {}
    for name in REQUIRED_FILES:
        path = bundle_dir / name
        if not path.exists() or not path.is_file():
            failures.append(f"REQUIRED_FILE_MISSING:{name}")
            continue
        data = path.read_bytes()
        file_hashes[name] = _sha256_bytes(data)
        try:
            file_texts[name] = data.decode("utf-8")
        except Exception:
            failures.append(f"FILE_NOT_UTF8:{name}")
            file_texts[name] = ""
    for name in OPTIONAL_HASHED_FILES:
        path = bundle_dir / name
        if path.exists() and path.is_file():
            data = path.read_bytes()
            file_hashes[name] = _sha256_bytes(data)
            try:
                file_texts[name] = data.decode("utf-8")
            except Exception:
                failures.append(f"FILE_NOT_UTF8:{name}")
                file_texts[name] = ""
    if failures:
        return _report(failures, file_hashes, {}, {})

    _check_no_secret_leakage(file_texts, failures)
    records = _parse_audit_jsonl(file_texts["audit.jsonl"], failures)
    signatures = _json_loads(file_texts["signatures.json"], "SIGNATURES_JSON_MALFORMED", failures)
    consensus_evidence = _json_loads(file_texts.get("consensus_evidence.json", "{}"), "CONSENSUS_EVIDENCE_JSON_MALFORMED", failures)
    timestamp_verification = _json_loads(file_texts["timestamp_verification.json"], "TIMESTAMP_VERIFICATION_JSON_MALFORMED", failures)
    if not isinstance(signatures, dict):
        failures.append("SIGNATURES_JSON_MALFORMED")
        signatures = {}
    if not isinstance(consensus_evidence, dict):
        failures.append("CONSENSUS_EVIDENCE_JSON_MALFORMED")
        consensus_evidence = {}
    if not isinstance(timestamp_verification, dict):
        failures.append("TIMESTAMP_VERIFICATION_JSON_MALFORMED")
        timestamp_verification = {}

    _verify_hash_chain(records, failures)
    try:
        tenant_id = validate_records_single_tenant(records)
    except TenantIsolationError as exc:
        failures.append(f"TENANT_ISOLATION:{exc}")
        tenant_id = ""
    if tenant_id:
        for event_id, evidence in consensus_evidence.items():
            if isinstance(evidence, dict):
                try:
                    validate_consensus_tenant(evidence, tenant_id)
                except TenantIsolationError as exc:
                    failures.append(f"TENANT_CONSENSUS_EVIDENCE:{event_id}:{exc}")
    expected_ledger_hash = ledger_sha256(records)
    if file_texts["ledger.sha256"].strip() != expected_ledger_hash:
        failures.append("LEDGER_SHA256")
    _verify_signatures(records, signatures, failures)
    attestation_summary = _verify_attestation_evidence(consensus_evidence, failures, tenant_id) if tenant_id else {"attestation_count": 0}
    deployment_summary = _verify_deployment_provenance(bundle_dir, failures, tenant_id) if tenant_id else {}
    deployment_provenance = _json_loads(
        file_texts["governance_release.json"],
        "DEPLOYMENT_PROVENANCE_JSON_MALFORMED",
        failures,
    )
    if not isinstance(deployment_provenance, dict):
        deployment_provenance = {}
    components = component_hashes(
        audit_jsonl=file_texts["audit.jsonl"],
        ledger_sha256=file_texts["ledger.sha256"].strip(),
        signatures=signatures,
        consensus_evidence=consensus_evidence,
        deployment_provenance=deployment_provenance,
    )
    expected_imprint = message_imprint(components)
    timestamp_summary = _verify_timestamp(
        token_text=file_texts["rfc3161_timestamp.tsr"],
        verification=timestamp_verification,
        certificate_chain=file_texts["tsa_certificate_chain.pem"],
        policy_oid=file_texts["tsa_policy_oid.txt"],
        expected_imprint=expected_imprint,
        failures=failures,
    )
    return _report(
        failures,
        file_hashes,
        timestamp_summary,
        {"event_count": len(records), **attestation_summary, "deployment_provenance": deployment_summary},
    )


def _report(
    failures: list[str],
    file_hashes: dict[str, str],
    timestamp_summary: dict[str, Any],
    evidence_summary: dict[str, Any],
) -> dict[str, Any]:
    unique_failures = sorted(set(failures))
    return {
        "result": "FAIL" if unique_failures else "PASS",
        "failed_control_ids": unique_failures,
        "evidence_file_hashes": dict(sorted(file_hashes.items())),
        "timestamp_verification_summary": timestamp_summary,
        "evidence_summary": evidence_summary,
    }


def write_reports(report: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "verification_result.json").write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    lines = [
        f"USBAY Evidence Verification: {report['result']}",
        "Failed controls:",
        *(f"- {control}" for control in report["failed_control_ids"]),
        "Evidence file hashes:",
        *(f"- {name}: {digest}" for name, digest in report["evidence_file_hashes"].items()),
        "Timestamp verification:",
        json.dumps(report["timestamp_verification_summary"], sort_keys=True, separators=(",", ":")),
    ]
    (output_dir / "human_readable_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify USBAY immutable evidence bundle offline")
    parser.add_argument("bundle_dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    report = verify_bundle(args.bundle_dir)
    write_reports(report, args.output_dir or args.bundle_dir)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
