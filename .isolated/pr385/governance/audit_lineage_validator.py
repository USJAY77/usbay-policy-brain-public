from __future__ import annotations

from typing import Any

from governance.audit_registry_contracts import (
    AUDIT_LINEAGE_VALIDATION_SCHEMA,
    RECORD_TYPE_INDEX,
    REGISTRY_RECORD_TYPES,
    compute_record_hash,
    parse_timestamp,
    validate_registry_record,
)


def validate_audit_lineage(records: list[dict[str, Any]] | None) -> dict[str, Any]:
    if not isinstance(records, list):
        return {
            "schema": AUDIT_LINEAGE_VALIDATION_SCHEMA,
            "lineage_status": "BLOCKED",
            "tamper_status": "NOT_EVALUATED",
            "reason_codes": ["AUDIT_REGISTRY_RECORDS_MALFORMED"],
            "fail_closed": True,
        }
    by_id = {str(record.get("record_id", "")): record for record in records if isinstance(record, dict)}
    reasons: list[str] = []
    tamper_reasons: list[str] = []
    seen_types: set[str] = set()
    for record in records:
        validation = validate_registry_record(record)
        if validation.status == "TAMPER_DETECTED":
            tamper_reasons.extend(validation.reason_codes)
        elif not validation.valid:
            reasons.extend(validation.reason_codes)
        if not isinstance(record, dict):
            continue
        record_id = str(record.get("record_id", ""))
        record_type = str(record.get("record_type", ""))
        seen_types.add(record_type)
        parent_id = str(record.get("parent_id", ""))
        if record_type not in RECORD_TYPE_INDEX:
            continue
        if record_type == "Observation":
            if parent_id:
                reasons.append(f"AUDIT_LINEAGE_ROOT_PARENT_NOT_ALLOWED:{record_id}")
            continue
        parent = by_id.get(parent_id)
        if not isinstance(parent, dict):
            reasons.append(f"AUDIT_LINEAGE_PARENT_MISSING:{record_id}")
            continue
        expected_parent_type = REGISTRY_RECORD_TYPES[RECORD_TYPE_INDEX[record_type] - 1]
        if parent.get("record_type") != expected_parent_type:
            reasons.append(f"AUDIT_LINEAGE_PARENT_TYPE_INVALID:{record_id}")
        if not str(record.get("previous_hash", "")).strip():
            reasons.append(f"AUDIT_LINEAGE_PREVIOUS_HASH_MISSING:{record_id}")
        elif record.get("previous_hash") != parent.get("current_hash"):
            tamper_reasons.append(f"AUDIT_LINEAGE_PREVIOUS_HASH_MISMATCH:{record_id}")
        parent_time = parse_timestamp(parent.get("created_at"))
        record_time = parse_timestamp(record.get("created_at"))
        if parent_time is None or record_time is None:
            reasons.append(f"AUDIT_LINEAGE_TIMESTAMP_MISSING:{record_id}")
        elif record_time < parent_time:
            reasons.append(f"AUDIT_LINEAGE_TIMESTAMP_INVERSION:{record_id}")
        if record.get("current_hash") != compute_record_hash(record):
            tamper_reasons.append(f"AUDIT_REGISTRY_HASH_MISMATCH:{record_id}")
    missing_types = [record_type for record_type in REGISTRY_RECORD_TYPES if record_type not in seen_types]
    reasons.extend(f"AUDIT_LINEAGE_REQUIRED_TYPE_MISSING:{record_type}" for record_type in missing_types)
    tamper_status = "TAMPER_DETECTED" if tamper_reasons else "NO_TAMPER_DETECTED"
    lineage_status = "TAMPER_DETECTED" if tamper_reasons else ("BLOCKED" if reasons else "VERIFIED")
    return {
        "schema": AUDIT_LINEAGE_VALIDATION_SCHEMA,
        "lineage_status": lineage_status,
        "tamper_status": tamper_status,
        "reason_codes": sorted(set(reasons + tamper_reasons)),
        "fail_closed": lineage_status != "VERIFIED",
    }
