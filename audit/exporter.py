from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

from audit.anchor import sign_event, timestamp_event
from audit.keys import DEFAULT_KEY_VERSION, get_signing_key


GENESIS_HASH = "GENESIS"
DEFAULT_EXPORT_FILE = Path("tmp/audit_exports.jsonl")
SAFE_AUDIT_FIELDS = (
    "event_type",
    "decision_id",
    "request_hash",
    "policy_version",
    "reason_code",
    "nonce_hash",
    "created_at",
    "expires_at",
    "used",
)


def _canonical_json(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _sha256_json(data: dict) -> str:
    return hashlib.sha256(_canonical_json(data).encode("utf-8")).hexdigest()


def _chain_hash(previous_hash: str, event: dict) -> str:
    return hashlib.sha256((previous_hash + _canonical_json(event)).encode("utf-8")).hexdigest()


def _safe_audit_event(event: dict, previous_hash: str) -> dict:
    decision = event.get("decision") if isinstance(event.get("decision"), dict) else {}
    source = {**event, **decision}
    safe = {field: source.get(field) for field in SAFE_AUDIT_FIELDS}
    safe["event_type"] = safe.get("event_type") or event.get("action", "")
    safe["previous_hash"] = previous_hash
    safe["current_hash"] = _chain_hash(previous_hash, safe)
    return safe


def _normalize_decision(value) -> str:
    if isinstance(value, dict):
        value = value.get("decision", value.get("final_decision", "DENY"))
    normalized = str(value or "DENY").upper()
    if normalized in {"ALLOW", "ALLOWED"}:
        return "ALLOW"
    return "DENY"


def _hydra_metadata(event: dict) -> dict:
    decision = event.get("decision")
    if isinstance(decision, dict):
        consensus = decision.get("consensus", {})
        consensus_value = decision.get("consensus_reached", "")
        if isinstance(consensus, dict):
            consensus_value = consensus.get("consensus_reached", consensus_value)
        elif consensus_value == "":
            consensus_value = consensus
        return {
            "consensus": str(consensus_value),
            "allow_votes": int(
                decision.get("votes_allow", decision.get("allow_votes", consensus.get("votes_allow", 0)))
                if isinstance(consensus, dict)
                else decision.get("votes_allow", decision.get("allow_votes", 0))
            ),
            "deny_votes": int(
                decision.get("votes_deny", decision.get("deny_votes", consensus.get("votes_deny", 0)))
                if isinstance(consensus, dict)
                else decision.get("votes_deny", decision.get("deny_votes", 0))
            ),
        }

    return {
        "consensus": str(event.get("consensus", "")),
        "allow_votes": int(event.get("allow_votes", 0)),
        "deny_votes": int(event.get("deny_votes", 0)),
    }


def _last_hash(filepath: Path) -> str:
    if not filepath.exists():
        return GENESIS_HASH

    last_hash = GENESIS_HASH
    for line in filepath.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        last_hash = str(record["event_hash"])
    return last_hash


def build_export_event(event: dict) -> dict:
    decision = event.get("decision")
    export = {
        "audit_id": str(event.get("audit_id", event.get("hash_current", ""))),
        "timestamp": str(event.get("timestamp", datetime.utcnow().isoformat() + "Z")),
        "action": str(event.get("action", "")),
        "decision": _normalize_decision(decision),
        "reason": str(event.get("reason", "")),
        "policy_version": str(event.get("policy_version", "")),
        "hydra": _hydra_metadata(event),
        "signature_valid": bool(event.get("signature_valid", True)),
        "nonce_valid": bool(event.get("nonce_valid", True)),
    }

    if isinstance(decision, dict) and decision.get("command_hash"):
        export["command_hash"] = str(decision["command_hash"])
    elif event.get("command_hash"):
        export["command_hash"] = str(event["command_hash"])

    return export


def export_audit_event(event: dict, filepath: str):
    export_path = Path(filepath)
    export_path.parent.mkdir(parents=True, exist_ok=True)

    export_event = build_export_event(event)
    prev_hash = _last_hash(export_path)
    event_hash = _sha256_json(export_event)
    signing_key = get_signing_key(str(event.get("key_version", DEFAULT_KEY_VERSION)))
    record = {
        **export_event,
        "event_hash": event_hash,
        "signature": sign_event(event_hash, signing_key["private_key"]),
        "public_key_id": signing_key["public_key_id"],
        "key_version": signing_key["key_version"],
        "timestamp_proof": timestamp_event(event_hash),
        "prev_hash": prev_hash,
    }

    with export_path.open("a", encoding="utf-8") as handle:
        handle.write(_canonical_json(record) + "\n")

    return record


def load_export_records(filepath: str) -> list[dict]:
    export_path = Path(filepath)
    if not export_path.exists():
        return []
    return [
        json.loads(line)
        for line in export_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def verify_export_chain(filepath: str) -> bool:
    prev_hash = GENESIS_HASH
    try:
        for record in load_export_records(filepath):
            if record.get("prev_hash") != prev_hash:
                return False
            event = dict(record)
            event_hash = event.pop("event_hash", None)
            event.pop("signature", None)
            event.pop("public_key_id", None)
            event.pop("key_version", None)
            event.pop("timestamp_proof", None)
            event.pop("prev_hash", None)
            if _sha256_json(event) != event_hash:
                return False
            prev_hash = str(event_hash)
    except Exception:
        return False

    return True


def export_audit_chain(events: list[dict], filepath: str) -> dict:
    previous_hash = GENESIS_HASH
    safe_events = []
    for event in events:
        safe = _safe_audit_event(event, previous_hash)
        previous_hash = safe["current_hash"]
        safe_events.append(safe)

    export = {
        "events": safe_events,
        "root_hash": previous_hash,
        "algorithm": "sha256(previous_hash + canonical_event_json)",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "event_count": len(safe_events),
    }
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_canonical_json(export), encoding="utf-8")
    return export


def verify_audit_chain_export(filepath: str) -> bool:
    try:
        export = json.loads(Path(filepath).read_text(encoding="utf-8"))
        events = export.get("events")
        if not isinstance(events, list):
            return False
        if export.get("event_count") != len(events):
            return False
        previous_hash = GENESIS_HASH
        for event in events:
            if event.get("previous_hash") != previous_hash:
                return False
            event_without_hash = dict(event)
            current_hash = event_without_hash.pop("current_hash", None)
            if _chain_hash(previous_hash, event_without_hash) != current_hash:
                return False
            previous_hash = str(current_hash)
        return export.get("root_hash") == previous_hash
    except Exception:
        return False
