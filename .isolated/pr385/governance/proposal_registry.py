from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from governance.correction_proposals import (
    APPROVAL_APPROVED,
    APPROVAL_REJECTED,
    EXECUTION_BLOCKED,
    EXECUTION_NOT_EXECUTED,
    REASON_APPROVAL_EXPIRED,
    REASON_UNKNOWN_STATE,
    _canonical,
    _is_expired,
    _sha256,
    proposal_hash,
)


SCHEMA_VERSION = "usbay.proposal_registry.v1"
GENESIS_HASH = "0" * 64
STATE_CREATED = "CREATED"
STATE_PENDING_APPROVAL = "PENDING_APPROVAL"
STATE_APPROVED = "APPROVED"
STATE_REJECTED = "REJECTED"
STATE_EXPIRED = "EXPIRED"
STATE_EXECUTED = "EXECUTED"
STATE_BLOCKED = "BLOCKED"
REASON_OK = "ok"
REASON_REGISTRY_UNAVAILABLE = "proposal_registry_unavailable"
REASON_REGISTRY_CORRUPTED = "proposal_registry_corrupted"
REASON_PROPOSAL_NOT_FOUND = "proposal_not_found"
REASON_PROPOSAL_EXPIRED = "proposal_expired"
REASON_EXECUTION_BLOCKED = "proposal_execution_blocked"

ALLOWED_STATES = {
    STATE_CREATED,
    STATE_PENDING_APPROVAL,
    STATE_APPROVED,
    STATE_REJECTED,
    STATE_EXPIRED,
    STATE_EXECUTED,
    STATE_BLOCKED,
}


class ProposalRegistryError(RuntimeError):
    pass


def empty_registry() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "proposals": {},
        "history": [],
    }


def initialize_proposal_registry(path: Path | str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(empty_registry(), sort_keys=True, separators=(",", ":")), encoding="utf-8")


def _event_hash(event: dict[str, Any]) -> str:
    payload = dict(event)
    payload.pop("event_hash", None)
    return _sha256(_canonical(payload))


def _record_audit_hash(record: dict[str, Any]) -> str:
    payload = dict(record)
    payload.pop("audit_hash", None)
    return _sha256(_canonical(payload))


def _proposal_payload_hash(proposal: dict[str, Any]) -> str:
    payload = {
        "proposal_id": str(proposal.get("proposal_id", "")),
        "proposal_hash": str(proposal.get("proposal_hash", "")),
        "issue_type": str(proposal.get("issue_type", "")),
        "risk_level": str(proposal.get("risk_level", "")),
        "proposed_action": str(proposal.get("proposed_action", "")),
        "source": str(proposal.get("source", "")),
        "observed_failure_hash": str(proposal.get("observed_failure_hash", "")),
    }
    return _sha256(_canonical(payload))


def _assert_safe_payload(value: Any) -> None:
    text = json.dumps(value, sort_keys=True, default=str).lower()
    forbidden = ("secret", "token", "password", "private key", "credential")
    if any(term in text for term in forbidden):
        raise ProposalRegistryError(REASON_REGISTRY_CORRUPTED)


def _normalize_record(proposal: dict[str, Any], *, lifecycle_state: str, created_at: str) -> dict[str, Any]:
    if proposal.get("proposal_hash") != proposal_hash(proposal):
        raise ProposalRegistryError(REASON_UNKNOWN_STATE)
    record = {
        "proposal_id": str(proposal.get("proposal_id", "")),
        "proposal_hash": str(proposal.get("proposal_hash", "")),
        "proposal_type": str(proposal.get("issue_type", "")),
        "risk_level": str(proposal.get("risk_level", "")),
        "proposal_payload_hash": _proposal_payload_hash(proposal),
        "approval_status": str(proposal.get("approval_status", "")),
        "execution_status": str(proposal.get("execution_status", EXECUTION_BLOCKED)),
        "lifecycle_state": lifecycle_state,
        "created_at": created_at,
        "expires_at": str(proposal.get("expires_at", "")),
    }
    record["audit_hash"] = _record_audit_hash(record)
    _assert_safe_payload(record)
    return record


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ProposalRegistryError(REASON_REGISTRY_UNAVAILABLE)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ProposalRegistryError(REASON_REGISTRY_CORRUPTED) from exc
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise ProposalRegistryError(REASON_REGISTRY_CORRUPTED)
    if not isinstance(data.get("proposals"), dict) or not isinstance(data.get("history"), list):
        raise ProposalRegistryError(REASON_REGISTRY_CORRUPTED)
    _verify_chain(data)
    return data


def _save(path: Path, data: dict[str, Any]) -> None:
    fd, raw_tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp_path = Path(raw_tmp)
    try:
        with open(fd, "w", encoding="utf-8", closefd=True) as handle:
            handle.write(json.dumps(data, sort_keys=True, separators=(",", ":")))
        tmp_path.replace(path)
    except Exception as exc:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise ProposalRegistryError(REASON_REGISTRY_UNAVAILABLE) from exc


def _verify_chain(data: dict[str, Any]) -> None:
    previous_hash = GENESIS_HASH
    proposal_states: dict[str, dict[str, Any]] = {}
    for event in data["history"]:
        if not isinstance(event, dict):
            raise ProposalRegistryError(REASON_REGISTRY_CORRUPTED)
        if event.get("previous_hash") != previous_hash:
            raise ProposalRegistryError(REASON_REGISTRY_CORRUPTED)
        if event.get("event_hash") != _event_hash(event):
            raise ProposalRegistryError(REASON_REGISTRY_CORRUPTED)
        state = str(event.get("lifecycle_state", ""))
        if state not in ALLOWED_STATES:
            raise ProposalRegistryError(REASON_UNKNOWN_STATE)
        previous_hash = str(event["event_hash"])
        proposal_states[str(event.get("proposal_id", ""))] = {
            "lifecycle_state": state,
            "audit_hash": str(event.get("record_audit_hash", "")),
        }
    for proposal_id, record in data["proposals"].items():
        if not isinstance(record, dict) or record.get("lifecycle_state") not in ALLOWED_STATES:
            raise ProposalRegistryError(REASON_UNKNOWN_STATE)
        if record.get("audit_hash") != _record_audit_hash(record):
            raise ProposalRegistryError(REASON_REGISTRY_CORRUPTED)
        latest = proposal_states.get(str(proposal_id))
        if latest and latest["lifecycle_state"] != record.get("lifecycle_state"):
            raise ProposalRegistryError(REASON_REGISTRY_CORRUPTED)


class ProposalRegistry:
    def __init__(self, path: Path | str):
        self.path = Path(path)

    def load(self) -> dict[str, Any]:
        return _load(self.path)

    def _append_event(self, data: dict[str, Any], record: dict[str, Any], *, transition: str, timestamp: str) -> None:
        previous_hash = data["history"][-1]["event_hash"] if data["history"] else GENESIS_HASH
        event = {
            "proposal_id": record["proposal_id"],
            "proposal_hash": record["proposal_hash"],
            "transition": transition,
            "lifecycle_state": record["lifecycle_state"],
            "record_audit_hash": record["audit_hash"],
            "timestamp": timestamp,
            "previous_hash": previous_hash,
        }
        event["event_hash"] = _event_hash(event)
        data["history"].append(event)

    def create(self, proposal: dict[str, Any], *, timestamp: str) -> dict[str, Any]:
        data = self.load()
        record = _normalize_record(proposal, lifecycle_state=STATE_CREATED, created_at=timestamp)
        if record["proposal_id"] in data["proposals"]:
            raise ProposalRegistryError(REASON_REGISTRY_CORRUPTED)
        data["proposals"][record["proposal_id"]] = record
        self._append_event(data, record, transition=STATE_CREATED, timestamp=timestamp)
        record["lifecycle_state"] = STATE_PENDING_APPROVAL
        record["audit_hash"] = _record_audit_hash(record)
        data["proposals"][record["proposal_id"]] = record
        self._append_event(data, record, transition=STATE_PENDING_APPROVAL, timestamp=timestamp)
        _verify_chain(data)
        _save(self.path, data)
        return record

    def transition(self, proposal_id: str, *, lifecycle_state: str, timestamp: str) -> dict[str, Any]:
        data = self.load()
        record = data["proposals"].get(str(proposal_id))
        if not isinstance(record, dict):
            raise ProposalRegistryError(REASON_PROPOSAL_NOT_FOUND)
        if lifecycle_state not in ALLOWED_STATES:
            raise ProposalRegistryError(REASON_UNKNOWN_STATE)
        if record.get("lifecycle_state") == STATE_EXPIRED and lifecycle_state == STATE_EXECUTED:
            raise ProposalRegistryError(REASON_PROPOSAL_EXPIRED)
        if lifecycle_state == STATE_EXECUTED and record.get("lifecycle_state") != STATE_APPROVED:
            raise ProposalRegistryError(REASON_EXECUTION_BLOCKED)
        updated = dict(record)
        updated["lifecycle_state"] = lifecycle_state
        if lifecycle_state == STATE_APPROVED:
            updated["approval_status"] = APPROVAL_APPROVED
            updated["execution_status"] = EXECUTION_NOT_EXECUTED
        elif lifecycle_state == STATE_REJECTED:
            updated["approval_status"] = APPROVAL_REJECTED
            updated["execution_status"] = EXECUTION_BLOCKED
        elif lifecycle_state == STATE_EXPIRED:
            updated["approval_status"] = "EXPIRED"
            updated["execution_status"] = EXECUTION_BLOCKED
        elif lifecycle_state in {STATE_BLOCKED, STATE_EXECUTED}:
            updated["execution_status"] = lifecycle_state
        updated["audit_hash"] = _record_audit_hash(updated)
        data["proposals"][proposal_id] = updated
        self._append_event(data, updated, transition=lifecycle_state, timestamp=timestamp)
        _verify_chain(data)
        _save(self.path, data)
        return updated

    def expire_if_needed(self, proposal_id: str, *, now: str) -> dict[str, Any]:
        data = self.load()
        record = data["proposals"].get(str(proposal_id))
        if not isinstance(record, dict):
            raise ProposalRegistryError(REASON_PROPOSAL_NOT_FOUND)
        if _is_expired(record, now=now):
            return self.transition(proposal_id, lifecycle_state=STATE_EXPIRED, timestamp=now)
        return record

    def assert_execution_allowed(self, proposal_id: str, *, now: str) -> dict[str, Any]:
        record = self.expire_if_needed(proposal_id, now=now)
        if record.get("lifecycle_state") == STATE_EXPIRED:
            raise ProposalRegistryError(REASON_PROPOSAL_EXPIRED)
        if record.get("lifecycle_state") != STATE_APPROVED:
            raise ProposalRegistryError(REASON_EXECUTION_BLOCKED)
        return record


def verify_proposal_registry(path: Path | str) -> bool:
    try:
        _load(Path(path))
        return True
    except ProposalRegistryError:
        return False
