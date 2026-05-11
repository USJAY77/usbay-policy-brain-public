from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from audit.anchor import sign_event, verify_event
from audit.keys import DEFAULT_KEY_VERSION, get_signing_key, resolve_public_key
from audit.rfc3161_anchor import (
    component_hashes,
    create_timestamp_proof,
    message_imprint,
    verify_timestamp_proof,
    write_timestamp_files,
)


GENESIS_HASH = "GENESIS"
FORBIDDEN_FIELD_NAMES = {
    "approval",
    "approval_contents",
    "approval_material",
    "private_key",
    "raw_nonce",
    "raw_payload",
    "secret",
    "token",
}


class LedgerIntegrityError(RuntimeError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _contains_forbidden(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            if normalized in FORBIDDEN_FIELD_NAMES:
                return True
            if _contains_forbidden(item):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden(item) for item in value)
    return False


def _safe_decision(decision: Any) -> dict[str, Any]:
    if isinstance(decision, dict):
        if _contains_forbidden(decision):
            raise LedgerIntegrityError("forbidden_evidence_field")
        return decision
    return {"decision": str(decision)}


def _consensus_result(decision: dict[str, Any]) -> str:
    value = (
        decision.get("consensus_result")
        or decision.get("final_decision")
        or decision.get("decision")
        or "DENY"
    )
    return str(value).upper()


def _policy_hash(decision: dict[str, Any]) -> str:
    return str(decision.get("policy_hash") or decision.get("policy_registry_hash") or "UNKNOWN_POLICY_HASH")


def _node_id(decision: dict[str, Any]) -> str:
    return str(decision.get("node_id") or decision.get("gateway_id") or "gateway-1")


def block_payload(block: dict[str, Any]) -> dict[str, Any]:
    payload = dict(block)
    payload.pop("current_event_hash", None)
    payload.pop("signature", None)
    payload.pop("public_key_id", None)
    payload.pop("key_version", None)
    return payload


def compute_event_hash(block: dict[str, Any]) -> str:
    return sha256_text(canonical_json(block_payload(block)))


def ledger_sha256(records: list[dict[str, Any]]) -> str:
    return sha256_text("\n".join(canonical_json(record) for record in records))


def ledger_path_for(chain_path: Path | str) -> Path:
    path = Path(chain_path)
    return path.with_suffix(path.suffix + ".ledger.jsonl")


def _read_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except Exception as exc:
            raise LedgerIntegrityError("ledger_corruption_detected") from exc
    return records


def _verify_record_signature(record: dict[str, Any]) -> bool:
    try:
        public_key = resolve_public_key(str(record.get("public_key_id", "")))
        return verify_event(
            str(record.get("current_event_hash", "")),
            str(record.get("signature", "")),
            public_key,
        )
    except Exception:
        return False


def verify_ledger(path: Path | str) -> bool:
    try:
        records = _read_records(Path(path))
        previous_hash = GENESIS_HASH
        seen_ids: set[str] = set()
        for record in records:
            required = {
                "event_id",
                "previous_event_hash",
                "current_event_hash",
                "timestamp",
                "node_id",
                "policy_hash",
                "consensus_result",
            }
            if any(record.get(field) in (None, "") for field in required):
                return False
            if record["event_id"] in seen_ids:
                return False
            seen_ids.add(str(record["event_id"]))
            if record.get("previous_event_hash") != previous_hash:
                return False
            if compute_event_hash(record) != record.get("current_event_hash"):
                return False
            if not _verify_record_signature(record):
                return False
            previous_hash = str(record["current_event_hash"])
    except Exception:
        return False
    return True


def assert_ledger_valid(path: Path | str) -> None:
    if not verify_ledger(path):
        raise LedgerIntegrityError("ledger_integrity_invalid")


def append_evidence_event(
    path: Path | str,
    *,
    action: str,
    decision: Any,
    timestamp: str | None = None,
    key_version: str = DEFAULT_KEY_VERSION,
) -> dict[str, Any]:
    ledger_path = Path(path)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    if ledger_path.exists() and not verify_ledger(ledger_path):
        raise LedgerIntegrityError("ledger_integrity_invalid")
    records = _read_records(ledger_path)
    previous_hash = records[-1]["current_event_hash"] if records else GENESIS_HASH
    safe_decision = _safe_decision(decision)
    created_at = timestamp or datetime.utcnow().isoformat() + "Z"
    event_id = sha256_text(canonical_json({
        "action": action,
        "decision": safe_decision,
        "previous_event_hash": previous_hash,
        "timestamp": created_at,
    }))
    block = {
        "event_id": event_id,
        "previous_event_hash": previous_hash,
        "timestamp": created_at,
        "node_id": _node_id(safe_decision),
        "policy_hash": _policy_hash(safe_decision),
        "consensus_result": _consensus_result(safe_decision),
        "action": str(action),
        "decision": safe_decision,
    }
    block["current_event_hash"] = compute_event_hash(block)
    signing_key = get_signing_key(key_version)
    block["signature"] = sign_event(block["current_event_hash"], signing_key["private_key"])
    block["public_key_id"] = signing_key["public_key_id"]
    block["key_version"] = signing_key["key_version"]
    with ledger_path.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json(block) + "\n")
    return block


def export_evidence_bundle(path: Path | str, export_dir: Path | str) -> dict[str, Any]:
    ledger_path = Path(path)
    if not verify_ledger(ledger_path):
        raise LedgerIntegrityError("ledger_integrity_invalid")
    records = _read_records(ledger_path)
    out_dir = Path(export_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    audit_jsonl = "\n".join(canonical_json(record) for record in records)
    if audit_jsonl:
        audit_jsonl += "\n"
    signatures = {
        record["event_id"]: {
            "current_event_hash": record["current_event_hash"],
            "signature": record["signature"],
            "public_key_id": record["public_key_id"],
            "key_version": record["key_version"],
        }
        for record in records
    }
    consensus_evidence = {
        record["event_id"]: record["decision"].get("consensus_evidence_bundle")
        for record in records
        if isinstance(record.get("decision"), dict) and record["decision"].get("consensus_evidence_bundle")
    }
    ledger_hash = ledger_sha256(records)
    components = component_hashes(
        audit_jsonl=audit_jsonl,
        ledger_sha256=ledger_hash,
        signatures=signatures,
        consensus_evidence=consensus_evidence,
    )
    imprint = message_imprint(components)
    proof = create_timestamp_proof(imprint)
    verification = verify_timestamp_proof(proof, imprint)
    if not verification.get("valid"):
        raise LedgerIntegrityError("timestamp_verification_failed")
    (out_dir / "audit.jsonl").write_text(audit_jsonl, encoding="utf-8")
    (out_dir / "ledger.sha256").write_text(ledger_hash + "\n", encoding="utf-8")
    (out_dir / "signatures.json").write_text(canonical_json(signatures), encoding="utf-8")
    (out_dir / "consensus_evidence.json").write_text(canonical_json(consensus_evidence), encoding="utf-8")
    write_timestamp_files(out_dir, proof, verification)
    return {
        "audit.jsonl": audit_jsonl,
        "ledger.sha256": ledger_hash,
        "signatures.json": signatures,
        "consensus_evidence.json": consensus_evidence,
        "rfc3161_timestamp.tsr": proof["token"],
        "timestamp_verification.json": verification,
        "tsa_certificate_chain.pem": proof.get("tsa_certificate_chain_pem", ""),
        "tsa_policy_oid.txt": str(proof.get("policy_oid", "")),
    }
