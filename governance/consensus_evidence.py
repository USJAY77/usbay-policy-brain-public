from __future__ import annotations

from typing import Any


def evaluate_consensus_evidence(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.append("MISSING_EVIDENCE")
    else:
        if not str(record.get("audit_hash", "")).strip():
            reasons.append("AUDIT_MISMATCH")
        if not str(record.get("evidence_hash", "")).strip():
            reasons.append("EVIDENCE_MISMATCH")
        if record.get("consensus_replay") is True:
            reasons.append("CONSENSUS_REPLAY_DETECTED")
        for node in record.get("nodes", []) if isinstance(record.get("nodes"), list) else []:
            if isinstance(node, dict) and str(node.get("evidence_hash", "")) != str(record.get("evidence_hash", "")):
                reasons.append("EVIDENCE_MISMATCH")
            if isinstance(node, dict) and str(node.get("audit_hash", "")) != str(record.get("audit_hash", "")):
                reasons.append("AUDIT_MISMATCH")
    clean_reasons = sorted(set(str(reason) for reason in reasons if reason))
    return {
        "schema": "usbay.hydra.evidence.v1",
        "consensus_evidence_status": "VALID" if not clean_reasons else "BLOCKED",
        "reason_codes": clean_reasons,
        "fail_closed": bool(clean_reasons),
        "read_only": True,
        "connector_write_enabled": False,
        "sensitive_data_logging": False,
    }
