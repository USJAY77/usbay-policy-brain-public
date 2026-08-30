#!/usr/bin/env python3
"""
USBAY audit storage policy v1.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from python.audit import audit_chain, compliance_report


POLICY_VERSION = "usbay.audit_storage.v1"
TEST_RETENTION_DAYS = 7
RUNTIME_ARTIFACT_DIRS = (
    Path("audit/logs"),
    Path("evidence"),
    Path("exports"),
    Path("python/audit/logs"),
    Path("python/evidence"),
    Path("python/exports"),
)
LEGACY_HASH_FIELDS = {"previous_hash", "record_hash", "environment"}


def environment_tag(value: str | None = None) -> str:
    raw = str(value or os.environ.get("USBAY_ENV", os.environ.get("USBAY_ENVIRONMENT", ""))).strip().lower()
    return "production" if raw in {"production", "prod"} else "test"


def verify_audit_log(log_path: Path, *, key_registry_path: Path | None = None) -> dict:
    try:
        latest_hash, entry_count, last_entry = audit_chain.verify_chain(
            log_path,
            key_registry_path=key_registry_path,
        )
    except Exception as exc:
        raise RuntimeError(f"FAIL_CLOSED:AUDIT_CHAIN_INVALID:{exc}") from exc
    return {
        "policy_version": POLICY_VERSION,
        "status": "verified",
        "latest_record_hash": latest_hash,
        "entry_count": entry_count,
        "last_audit_id": str(last_entry.get("audit_id", "")),
        "environment": str(last_entry.get("environment", "")),
    }


def _missing_legacy_hash_fields(record: dict) -> list[str]:
    return sorted(field for field in LEGACY_HASH_FIELDS if not str(record.get(field, "")).strip())


def _legacy_hex_fallback(record: dict) -> str:
    for field in ("signing_payload_hash", "entry_hash", "execution_hash", "policy_hash", "input_fingerprint"):
        value = str(record.get(field, "")).strip().lower()
        if len(value) == 64 and all(ch in "0123456789abcdef" for ch in value):
            return value
    return audit_chain.sha256_bytes(audit_chain.canonical_json_bytes(record))


def _enrich_legacy_record(record: dict, *, previous_hash: str, environment: str) -> tuple[dict, list[str]]:
    enriched = dict(record)
    added: list[str] = []

    if str(enriched.get("previous_hash", "")).strip() != previous_hash:
        enriched["previous_hash"] = previous_hash
        added.append("previous_hash")
    if not str(enriched.get("environment", "")).strip():
        enriched["environment"] = environment
        added.append("environment")

    # Legacy bootstrap records predate the v1 schema. These compatibility fields
    # are deterministic and avoid inventing operational facts.
    if not str(enriched.get("human_timestamp", "")).strip():
        enriched["human_timestamp"] = str(enriched.get("timestamp", ""))
        added.append("human_timestamp")
    if not str(enriched.get("signer_key_fingerprint", "")).strip():
        enriched["signer_key_fingerprint"] = _legacy_hex_fallback(enriched)
        added.append("signer_key_fingerprint")

    computed_hash = audit_chain.compute_hash(enriched, previous_hash)
    if str(enriched.get("entry_hash", "")).strip().lower() != computed_hash:
        enriched["entry_hash"] = computed_hash
        added.append("entry_hash")
    if str(enriched.get("record_hash", "")).strip().lower() != computed_hash:
        enriched["record_hash"] = computed_hash
        added.append("record_hash")

    audit_chain.validate_record(enriched, allow_unsigned=True)
    if str(enriched["previous_hash"]) != previous_hash:
        raise RuntimeError("LEGACY_AUDIT_MIGRATION_INVALID: previous_hash continuity failed")
    if str(enriched["entry_hash"]) != computed_hash or str(enriched["record_hash"]) != computed_hash:
        raise RuntimeError("LEGACY_AUDIT_MIGRATION_INVALID: record hash continuity failed")
    return enriched, sorted(set(added))


def migrate_legacy_audit_log(
    source_path: Path,
    output_path: Path,
    *,
    environment: str | None = None,
) -> dict:
    resolved_environment = environment_tag(environment)
    if not source_path.is_file():
        raise RuntimeError(f"FAIL_CLOSED:LEGACY_AUDIT_LOG_MISSING:{source_path}")

    lines = source_path.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise RuntimeError("FAIL_CLOSED:LEGACY_AUDIT_LOG_EMPTY")

    previous_hash = audit_chain.GENESIS_HASH
    migrated_records: list[dict] = []
    migrated_count = 0
    field_changes: dict[str, int] = {}

    for index, line in enumerate(lines, start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"FAIL_CLOSED:LEGACY_AUDIT_RECORD_INVALID_JSON:{index}:{exc}") from exc
        if not isinstance(record, dict):
            raise RuntimeError(f"FAIL_CLOSED:LEGACY_AUDIT_RECORD_INVALID:{index}: record must be a JSON object")

        missing_hash_fields = _missing_legacy_hash_fields(record)
        existing_previous = str(record.get("previous_hash", "")).strip()
        existing_entry_hash = str(record.get("entry_hash", "")).strip().lower()
        existing_record_hash = str(record.get("record_hash", "")).strip().lower()

        enriched, added = _enrich_legacy_record(
            record,
            previous_hash=previous_hash,
            environment=resolved_environment,
        )
        if missing_hash_fields or existing_previous != previous_hash or existing_entry_hash != enriched["entry_hash"] or existing_record_hash != enriched["record_hash"]:
            migrated_count += 1
        for field in added:
            field_changes[field] = field_changes.get(field, 0) + 1

        migrated_records.append(enriched)
        previous_hash = str(enriched["record_hash"])

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        "".join(
            json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
            for record in migrated_records
        ),
        encoding="utf-8",
    )

    validated_hash = audit_chain.GENESIS_HASH
    for index, record in enumerate(migrated_records, start=1):
        audit_chain.validate_record(record, index=index, allow_unsigned=True)
        if str(record["previous_hash"]) != validated_hash:
            raise RuntimeError(f"FAIL_CLOSED:LEGACY_AUDIT_MIGRATION_CHAIN_BREAK:{index}")
        expected_hash = audit_chain.compute_hash(record, validated_hash)
        if str(record["entry_hash"]) != expected_hash or str(record["record_hash"]) != expected_hash:
            raise RuntimeError(f"FAIL_CLOSED:LEGACY_AUDIT_MIGRATION_HASH_MISMATCH:{index}")
        validated_hash = expected_hash

    return {
        "policy_version": POLICY_VERSION,
        "status": "migrated",
        "source_path": str(source_path),
        "output_path": str(output_path),
        "environment": resolved_environment,
        "entry_count": len(migrated_records),
        "migrated_count": migrated_count,
        "latest_record_hash": previous_hash,
        "field_changes": field_changes,
    }


def verify_migrated_audit_log(log_path: Path) -> dict:
    if not log_path.is_file():
        raise RuntimeError(f"FAIL_CLOSED:MIGRATED_AUDIT_LOG_MISSING:{log_path}")

    lines = log_path.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise RuntimeError("FAIL_CLOSED:MIGRATED_AUDIT_LOG_EMPTY")

    previous_hash = audit_chain.GENESIS_HASH
    last_entry: dict | None = None
    for index, line in enumerate(lines, start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"FAIL_CLOSED:MIGRATED_AUDIT_RECORD_INVALID_JSON:{index}:{exc}") from exc
        if not isinstance(record, dict):
            raise RuntimeError(f"FAIL_CLOSED:MIGRATED_AUDIT_RECORD_INVALID:{index}: record must be a JSON object")
        audit_chain.validate_record(record, index=index, allow_unsigned=True)
        if str(record["previous_hash"]) != previous_hash:
            raise RuntimeError(f"FAIL_CLOSED:MIGRATED_AUDIT_PREVIOUS_HASH_MISMATCH:{index}")
        expected_hash = audit_chain.compute_hash(record, previous_hash)
        if str(record["entry_hash"]) != expected_hash:
            raise RuntimeError(f"FAIL_CLOSED:MIGRATED_AUDIT_ENTRY_HASH_MISMATCH:{index}")
        if str(record["record_hash"]) != expected_hash:
            raise RuntimeError(f"FAIL_CLOSED:MIGRATED_AUDIT_RECORD_HASH_MISMATCH:{index}")
        previous_hash = expected_hash
        last_entry = record

    if last_entry is None:
        raise RuntimeError("FAIL_CLOSED:MIGRATED_AUDIT_LOG_EMPTY")
    return {
        "policy_version": POLICY_VERSION,
        "status": "verified",
        "latest_record_hash": previous_hash,
        "entry_count": len(lines),
        "last_audit_id": str(last_entry.get("audit_id", "")),
        "environment": str(last_entry.get("environment", "")),
    }


def export_audit_record(*, audit_record: dict, output_dir: Path) -> dict:
    audit_chain.validate_record(audit_record)
    record_hash = str(audit_record["record_hash"])
    json_path = output_dir / f"audit_{record_hash}.json"
    pdf_path = output_dir / f"audit_{record_hash}.pdf"
    output_dir.mkdir(parents=True, exist_ok=True)
    export_payload = {
        "policy_version": POLICY_VERSION,
        "audit_record": audit_record,
        "record_hash": record_hash,
        "previous_hash": str(audit_record["previous_hash"]),
        "environment": str(audit_record["environment"]),
        "exported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    json_path.write_text(
        json.dumps(export_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    compliance_report.generate_pdf(
        {
            "actor_id": str(audit_record["actor_id"]),
            "device_id": str(audit_record["device_id"]),
            "tenant_id": str(audit_record["tenant_id"]),
            "policy_id": str(audit_record["policy_id"]),
            "policy_version": str(audit_record["policy_version"]),
            "policy_hash": str(audit_record["policy_hash"]),
            "execution_hash": str(audit_record["execution_hash"]),
            "decision": str(audit_record["decision"]),
            "fail_closed_reason": str(audit_record.get("fail_closed_reason", "")),
            "tsa_status": str(audit_record.get("tsa_status", audit_record.get("timestamp_status", "unverified"))),
            "chain_hash": record_hash,
        },
        pdf_path,
    )
    return {
        "policy_version": POLICY_VERSION,
        "json_path": str(json_path),
        "pdf_path": str(pdf_path),
        "record_hash": record_hash,
        "pdf_sha256": audit_chain.sha256_file(pdf_path),
    }


def enforce_retention(*, root: Path, environment: str | None = None, dry_run: bool = False) -> dict:
    resolved_environment = environment_tag(environment)
    if resolved_environment == "production":
        return {
            "policy_version": POLICY_VERSION,
            "environment": "production",
            "deleted": [],
            "blocked": True,
            "reason": "PRODUCTION_LOGS_NEVER_AUTO_DELETED",
        }
    cutoff = datetime.now(timezone.utc) - timedelta(days=TEST_RETENTION_DAYS)
    deleted: list[str] = []
    for relative_dir in RUNTIME_ARTIFACT_DIRS:
        artifact_dir = root / relative_dir
        if not artifact_dir.exists():
            continue
        for path in artifact_dir.rglob("*"):
            if not path.is_file():
                continue
            modified_at = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            if modified_at >= cutoff:
                continue
            deleted.append(str(path))
            if not dry_run:
                path.unlink()
    return {
        "policy_version": POLICY_VERSION,
        "environment": "test",
        "retention_days": TEST_RETENTION_DAYS,
        "deleted": deleted,
        "dry_run": dry_run,
        "blocked": False,
    }
