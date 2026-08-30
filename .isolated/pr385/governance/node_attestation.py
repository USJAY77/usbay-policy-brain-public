from __future__ import annotations

from datetime import datetime
from typing import Any

from governance.hydra_consensus_contracts import validate_hydra_node


def evaluate_node_attestation(nodes: list[dict[str, Any]] | None, *, now: datetime | None = None) -> dict[str, Any]:
    reasons: list[str] = []
    valid_count = 0
    if not isinstance(nodes, list):
        nodes = []
    for node in nodes:
        validation = validate_hydra_node(node)
        if validation.valid:
            valid_count += 1
        else:
            reasons.extend(validation.reason_codes)
    if valid_count < 2:
        reasons.append("QUORUM_NOT_REACHED")
    clean_reasons = sorted(set(str(reason) for reason in reasons if reason))
    return {
        "schema": "usbay.hydra.node_attestation.v1",
        "node_attestation_status": "VALID" if not clean_reasons else "BLOCKED",
        "valid_node_count": valid_count,
        "reason_codes": clean_reasons,
        "fail_closed": bool(clean_reasons),
        "read_only": True,
        "node_control_enabled": False,
        "execution_enabled": False,
        "auto_approval": False,
        "auto_remediation": False,
    }
