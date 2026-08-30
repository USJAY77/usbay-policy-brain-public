from __future__ import annotations

from typing import Any


def evaluate_artifact_scan_governance(
    record: dict[str, Any] | None,
    *,
    requesting_tenant_id: str = "",
    requesting_workspace_id: str = "",
) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.append("UNKNOWN_ARTIFACT")
    else:
        if record.get("artifact_scanned") is not True:
            reasons.append("ARTIFACT_NOT_SCANNED")
        if record.get("scan_record") is not True:
            reasons.append("MISSING_SCAN_RECORD")
        if requesting_tenant_id and str(record.get("tenant_id", "")) != str(requesting_tenant_id):
            reasons.append("CROSS_TENANT_ARTIFACT")
        if requesting_workspace_id and str(record.get("workspace_id", "")) != str(requesting_workspace_id):
            reasons.append("CROSS_TENANT_ARTIFACT")
    clean = sorted(set(reasons))
    return {
        "schema": "usbay.malware.artifact_scan.v1",
        "artifact_scan_status": "VALID" if not clean else "BLOCKED",
        "reason_codes": clean,
        "read_only": True,
        "file_modification_enabled": False,
        "file_deletion_enabled": False,
        "quarantine_enabled": False,
    }
