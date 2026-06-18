from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from governance.hydra_consensus_contracts import parse_timestamp, validate_hydra_node


def evaluate_quorum(
    nodes: list[dict[str, Any]] | None,
    *,
    policy_version: str = "",
    timestamp: str = "",
    now: datetime | None = None,
    max_age_seconds: int = 3600,
) -> dict[str, Any]:
    reasons: list[str] = []
    valid_nodes: list[dict[str, Any]] = []
    if not isinstance(nodes, list):
        nodes = []
    for node in nodes:
        validation = validate_hydra_node(node)
        if validation.valid:
            valid_nodes.append(node)
        else:
            reasons.extend(validation.reason_codes)
    if len(valid_nodes) < 2:
        reasons.append("QUORUM_NOT_REACHED")
    versions = {str(node.get("policy_version", "")) for node in valid_nodes if node.get("policy_version")}
    if not policy_version or len(versions) != 1 or (versions and policy_version not in versions):
        reasons.append("POLICY_MISMATCH")
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    consensus_timestamp = parse_timestamp(timestamp)
    if consensus_timestamp is None or abs((effective_now - consensus_timestamp).total_seconds()) > max_age_seconds:
        reasons.append("STALE_TIMESTAMP")
    clean_reasons = sorted(set(str(reason) for reason in reasons if reason))
    return {
        "schema": "usbay.hydra.quorum.v1",
        "quorum_status": "QUORUM_READY" if not clean_reasons else "BLOCKED",
        "consensus_model": "2_OF_3_REQUIRED",
        "valid_node_count": len(valid_nodes),
        "required_node_count": 2,
        "reason_codes": clean_reasons,
        "fail_closed": bool(clean_reasons),
        "read_only": True,
        "quorum_override_enabled": False,
        "auto_approval": False,
    }
