from __future__ import annotations

from typing import Any


def evaluate_consensus_lineage(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.append("MISSING_LINEAGE")
    else:
        if not str(record.get("lineage_hash", "")).strip():
            reasons.append("MISSING_LINEAGE")
        for node in record.get("nodes", []) if isinstance(record.get("nodes"), list) else []:
            if isinstance(node, dict) and not str(node.get("node_lineage", "")).strip():
                reasons.append("MISSING_LINEAGE")
        if record.get("consensus_bypass") is True:
            reasons.append("CONSENSUS_BYPASS_FORBIDDEN")
    clean_reasons = sorted(set(str(reason) for reason in reasons if reason))
    return {
        "schema": "usbay.hydra.lineage.v1",
        "consensus_lineage_status": "VALID" if not clean_reasons else "BLOCKED",
        "reason_codes": clean_reasons,
        "fail_closed": bool(clean_reasons),
        "read_only": True,
        "auto_remediation": False,
    }
