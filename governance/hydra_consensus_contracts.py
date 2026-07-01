from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from typing import Any

from governance.execution_contracts import sha256_json


HYDRA_CONSENSUS_SCHEMA = "usbay.hydra.consensus.v1"
HYDRA_NODE_SCHEMA = "usbay.hydra.node.v1"
HYDRA_QUORUM_SCHEMA = "usbay.hydra.quorum.v1"
HYDRA_EVIDENCE_SCHEMA = "usbay.hydra.evidence.v1"
HYDRA_LINEAGE_SCHEMA = "usbay.hydra.lineage.v1"
HYDRA_POLICY_VERSION = "usbay.pb-hydra-consensus.governed-hydra-consensus.v1"

CONSENSUS_MODEL = "2_OF_3_REQUIRED"
SUPPORTED_NODES = frozenset({"PRIMARY_NODE", "SECONDARY_NODE", "OFFLINE_BACKUP_NODE"})
ALLOWED_CONSENSUS_STATES = frozenset({"PENDING", "REVIEW_REQUIRED", "QUORUM_READY", "CONSENSUS_REACHED", "BLOCKED"})
FAIL_CLOSED_REASON_CODES = frozenset(
    {
        "QUORUM_NOT_REACHED",
        "UNKNOWN_NODE",
        "UNTRUSTED_NODE",
        "MISSING_ATTESTATION",
        "MISSING_LINEAGE",
        "MISSING_EVIDENCE",
        "STALE_TIMESTAMP",
        "POLICY_MISMATCH",
        "AUDIT_MISMATCH",
        "EVIDENCE_MISMATCH",
        "CONSENSUS_REPLAY_DETECTED",
        "CONSENSUS_OVERRIDE_FORBIDDEN",
        "CONSENSUS_BYPASS_FORBIDDEN",
    }
)
REQUIRED_CONSENSUS_FIELDS = (
    "consensus_id",
    "consensus_model",
    "consensus_state",
    "nodes",
    "policy_version",
    "audit_hash",
    "evidence_hash",
    "lineage_hash",
    "timestamp",
    "reason_codes",
    "fail_closed",
)
REQUIRED_NODE_FIELDS = (
    "node_id",
    "node_identity",
    "node_attestation",
    "node_lineage",
    "policy_version",
    "audit_hash",
    "evidence_hash",
    "timestamp",
    "trusted",
)


@dataclass(frozen=True)
class HydraConsensusValidation:
    valid: bool
    status: str
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "status": self.status, "reason_codes": list(self.reason_codes)}


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def canonical_hydra_consensus_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "consensus_id": str(record.get("consensus_id", "")),
        "consensus_model": str(record.get("consensus_model", "")),
        "consensus_state": str(record.get("consensus_state", "")),
        "nodes": sorted(
            (canonical_hydra_node_payload(node) for node in record.get("nodes", []) if isinstance(node, dict)),
            key=lambda payload: json.dumps(payload, sort_keys=True, separators=(",", ":")),
        ),
        "policy_version": str(record.get("policy_version", "")),
        "audit_hash": str(record.get("audit_hash", "")),
        "evidence_hash": str(record.get("evidence_hash", "")),
        "lineage_hash": str(record.get("lineage_hash", "")),
        "timestamp": str(record.get("timestamp", "")),
        "reason_codes": sorted(str(code) for code in record.get("reason_codes", []) if code),
        "fail_closed": record.get("fail_closed") is True,
    }


def canonical_hydra_node_payload(node: dict[str, Any]) -> dict[str, Any]:
    return {
        "node_id": str(node.get("node_id", "")),
        "node_identity": str(node.get("node_identity", "")),
        "node_attestation": str(node.get("node_attestation", "")),
        "node_lineage": str(node.get("node_lineage", "")),
        "policy_version": str(node.get("policy_version", "")),
        "audit_hash": str(node.get("audit_hash", "")),
        "evidence_hash": str(node.get("evidence_hash", "")),
        "timestamp": str(node.get("timestamp", "")),
        "trusted": node.get("trusted") is True,
    }


def compute_hydra_consensus_hash(record: dict[str, Any]) -> str:
    return sha256_json(canonical_hydra_consensus_payload(record))


def validate_hydra_node(node: dict[str, Any] | None) -> HydraConsensusValidation:
    if not isinstance(node, dict):
        return HydraConsensusValidation(False, "BLOCKED", ("UNKNOWN_NODE",))
    reasons: list[str] = []
    if node.get("schema") != HYDRA_NODE_SCHEMA:
        reasons.append("UNKNOWN_NODE")
    for field in REQUIRED_NODE_FIELDS:
        if node.get(field) in ("", None):
            reasons.append(f"HYDRA_NODE_{field.upper()}_MISSING")
    if str(node.get("node_id", "")) not in SUPPORTED_NODES:
        reasons.append("UNKNOWN_NODE")
    if node.get("trusted") is not True:
        reasons.append("UNTRUSTED_NODE")
    if not str(node.get("node_identity", "")).strip():
        reasons.append("UNKNOWN_NODE")
    if not str(node.get("node_attestation", "")).strip():
        reasons.append("MISSING_ATTESTATION")
    if not str(node.get("node_lineage", "")).strip():
        reasons.append("MISSING_LINEAGE")
    if not str(node.get("evidence_hash", "")).strip():
        reasons.append("MISSING_EVIDENCE")
    if parse_timestamp(node.get("timestamp")) is None:
        reasons.append("STALE_TIMESTAMP")
    status = "BLOCKED" if reasons else "VALID"
    return HydraConsensusValidation(not reasons, status, tuple(sorted(set(reasons))))


def validate_hydra_consensus_record(record: dict[str, Any] | None) -> HydraConsensusValidation:
    if not isinstance(record, dict):
        return HydraConsensusValidation(False, "BLOCKED", ("QUORUM_NOT_REACHED",))
    reasons: list[str] = []
    if record.get("schema") != HYDRA_CONSENSUS_SCHEMA:
        reasons.append("CONSENSUS_BYPASS_FORBIDDEN")
    for field in REQUIRED_CONSENSUS_FIELDS:
        if record.get(field) in ("", None):
            reasons.append(f"HYDRA_CONSENSUS_{field.upper()}_MISSING")
    if record.get("consensus_model") != CONSENSUS_MODEL:
        reasons.append("CONSENSUS_BYPASS_FORBIDDEN")
    state = str(record.get("consensus_state", ""))
    if state not in ALLOWED_CONSENSUS_STATES:
        reasons.append(f"HYDRA_CONSENSUS_STATE_UNKNOWN:{state or 'MISSING'}")
    nodes = record.get("nodes", [])
    if not isinstance(nodes, list):
        reasons.append("QUORUM_NOT_REACHED")
        nodes = []
    for node in nodes:
        validation = validate_hydra_node(node)
        if not validation.valid:
            reasons.extend(validation.reason_codes)
    if len([node for node in nodes if validate_hydra_node(node).valid]) < 2:
        reasons.append("QUORUM_NOT_REACHED")
    if not str(record.get("policy_version", "")).strip():
        reasons.append("POLICY_MISMATCH")
    if not str(record.get("audit_hash", "")).strip():
        reasons.append("AUDIT_MISMATCH")
    if not str(record.get("evidence_hash", "")).strip():
        reasons.append("EVIDENCE_MISMATCH")
    if not str(record.get("lineage_hash", "")).strip():
        reasons.append("MISSING_LINEAGE")
    if parse_timestamp(record.get("timestamp")) is None:
        reasons.append("STALE_TIMESTAMP")
    if record.get("quorum_override") is True:
        reasons.append("CONSENSUS_OVERRIDE_FORBIDDEN")
    if record.get("consensus_bypass") is True:
        reasons.append("CONSENSUS_BYPASS_FORBIDDEN")
    if record.get("consensus_replay") is True:
        reasons.append("CONSENSUS_REPLAY_DETECTED")
    if record.get("consensus_hash") and record.get("consensus_hash") != compute_hydra_consensus_hash(record):
        return HydraConsensusValidation(False, "TAMPER_DETECTED", ("CONSENSUS_REPLAY_DETECTED",))
    status = "BLOCKED" if reasons else state
    return HydraConsensusValidation(not reasons and status in {"QUORUM_READY", "CONSENSUS_REACHED"}, status, tuple(sorted(set(reasons))))


def build_hydra_node(
    *,
    node_id: str,
    node_identity: str,
    node_attestation: str,
    node_lineage: str,
    policy_version: str,
    audit_hash: str,
    evidence_hash: str,
    timestamp: str,
    trusted: bool = True,
) -> dict[str, Any]:
    return {
        "schema": HYDRA_NODE_SCHEMA,
        "node_id": str(node_id),
        "node_identity": str(node_identity),
        "node_attestation": str(node_attestation),
        "node_lineage": str(node_lineage),
        "policy_version": str(policy_version),
        "audit_hash": str(audit_hash),
        "evidence_hash": str(evidence_hash),
        "timestamp": str(timestamp),
        "trusted": bool(trusted),
    }


def build_hydra_consensus_record(
    *,
    consensus_id: str,
    nodes: list[dict[str, Any]],
    policy_version: str,
    audit_hash: str,
    evidence_hash: str,
    lineage_hash: str,
    timestamp: str,
    consensus_state: str = "CONSENSUS_REACHED",
    reason_codes: list[str] | tuple[str, ...] = (),
    fail_closed: bool = False,
) -> dict[str, Any]:
    record = {
        "schema": HYDRA_CONSENSUS_SCHEMA,
        "consensus_id": str(consensus_id),
        "consensus_model": CONSENSUS_MODEL,
        "consensus_state": str(consensus_state),
        "nodes": [dict(node) for node in nodes],
        "policy_version": str(policy_version),
        "audit_hash": str(audit_hash),
        "evidence_hash": str(evidence_hash),
        "lineage_hash": str(lineage_hash),
        "timestamp": str(timestamp),
        "reason_codes": sorted(str(code) for code in reason_codes if code),
        "fail_closed": bool(fail_closed),
        "consensus_hash": "",
    }
    record["consensus_hash"] = compute_hydra_consensus_hash(record)
    return record
