from __future__ import annotations

from datetime import datetime
from typing import Any

from governance.consensus_evidence import evaluate_consensus_evidence
from governance.consensus_lineage import evaluate_consensus_lineage
from governance.hydra_consensus_contracts import validate_hydra_consensus_record
from governance.node_attestation import evaluate_node_attestation
from governance.quorum_validation import evaluate_quorum


def evaluate_hydra_consensus_governance(
    *,
    record: dict[str, Any] | None,
    now: datetime | None = None,
    max_age_seconds: int = 3600,
) -> dict[str, Any]:
    reasons: list[str] = []
    validation = validate_hydra_consensus_record(record)
    if not validation.valid:
        reasons.extend(validation.reason_codes)
    nodes = record.get("nodes", []) if isinstance(record, dict) else []
    policy_version = str(record.get("policy_version", "")) if isinstance(record, dict) else ""
    timestamp = str(record.get("timestamp", "")) if isinstance(record, dict) else ""
    quorum = evaluate_quorum(nodes, policy_version=policy_version, timestamp=timestamp, now=now, max_age_seconds=max_age_seconds)
    attestation = evaluate_node_attestation(nodes, now=now)
    evidence = evaluate_consensus_evidence(record)
    lineage = evaluate_consensus_lineage(record)
    for result in (quorum, attestation, evidence, lineage):
        reasons.extend(result.get("reason_codes", []))
    reason_codes = sorted(set(str(reason) for reason in reasons if reason))
    status = "CONSENSUS_REACHED" if not reason_codes and validation.status == "CONSENSUS_REACHED" else "BLOCKED"
    return {
        "schema": "usbay.hydra.consensus.governance.v1",
        "hydra_consensus_status": status,
        "quorum_status": quorum["quorum_status"],
        "node_attestation_status": attestation["node_attestation_status"],
        "consensus_evidence_status": evidence["consensus_evidence_status"],
        "consensus_lineage_status": lineage["consensus_lineage_status"],
        "hydra_reason_codes": reason_codes,
        "fail_closed": status == "BLOCKED",
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "shell_control_enabled": False,
        "connector_write_enabled": False,
        "node_control_enabled": False,
        "quorum_override_enabled": False,
        "auto_approval": False,
        "auto_remediation": False,
        "sensitive_data_logging": False,
    }


def empty_hydra_consensus_dashboard_state() -> dict[str, Any]:
    return {
        "hydra_consensus_status": "BLOCKED",
        "quorum_status": "BLOCKED",
        "node_attestation_status": "BLOCKED",
        "consensus_evidence_status": "BLOCKED",
        "consensus_lineage_status": "BLOCKED",
        "hydra_reason_codes": ["QUORUM_NOT_REACHED"],
        "fail_closed": True,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "shell_control_enabled": False,
        "connector_write_enabled": False,
        "node_control_enabled": False,
        "quorum_override_enabled": False,
        "auto_approval": False,
        "auto_remediation": False,
        "sensitive_data_logging": False,
    }
