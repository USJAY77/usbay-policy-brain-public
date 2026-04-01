from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


AUDIT_DIR = Path("audit")
AUDIT_LOG_PATH = AUDIT_DIR / "audit_log.jsonl"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _read_last_chain_hash(log_path: Path) -> str:
    if not log_path.exists():
        return "GENESIS"

    last_non_empty = ""
    with log_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                last_non_empty = stripped

    if not last_non_empty:
        return "GENESIS"

    try:
        record = json.loads(last_non_empty)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"FAIL_CLOSED:AUDIT_LOG_CORRUPTED:{exc}") from exc

    return str(record.get("chain_hash", "GENESIS"))


@dataclass(slots=True)
class AuditEvent:
    timestamp: str
    event_type: str
    actor: str
    decision: str
    policy_version: str
    execution_origin: str
    workspace: str
    input_fingerprint: str
    previous_chain_hash: str
    chain_hash: str


def build_audit_event(
    *,
    event_type: str,
    actor: str,
    decision: str,
    policy_version: str,
    execution_origin: str,
    workspace: str,
    input_fingerprint: str,
    previous_chain_hash: str,
) -> AuditEvent:
    payload_without_chain = {
        "timestamp": _utc_now_iso(),
        "event_type": event_type,
        "actor": actor,
        "decision": decision,
        "policy_version": policy_version,
        "execution_origin": execution_origin,
        "workspace": workspace,
        "input_fingerprint": input_fingerprint,
        "previous_chain_hash": previous_chain_hash,
    }

    chain_hash = _sha256_text(_canonical_json(payload_without_chain))

    return AuditEvent(
        **payload_without_chain,
        chain_hash=chain_hash,
    )


def write_audit_event(
    *,
    event_type: str,
    actor: str,
    decision: str,
    policy_version: str,
    execution_origin: str,
    workspace: str,
    input_payload: dict[str, Any],
    log_path: Path = AUDIT_LOG_PATH,
) -> AuditEvent:
    """
    Fail-closed audit writer.
    If logging fails, caller must treat execution as blocked.
    """
    try:
        AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        previous_chain_hash = _read_last_chain_hash(log_path)
        input_fingerprint = _sha256_text(_canonical_json(input_payload))

        event = build_audit_event(
            event_type=event_type,
            actor=actor,
            decision=decision,
            policy_version=policy_version,
            execution_origin=execution_origin,
            workspace=workspace,
            input_fingerprint=input_fingerprint,
            previous_chain_hash=previous_chain_hash,
        )

        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")

        return event

    except Exception as exc:
        raise RuntimeError(f"FAIL_CLOSED:AUDIT_WRITE_FAILED:{exc}") from exc
