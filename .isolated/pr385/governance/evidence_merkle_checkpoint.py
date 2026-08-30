from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from governance.evidence_chain import (
    MODULE_VERSIONS as EVIDENCE_CHAIN_MODULE_VERSIONS,
    assert_evidence_chain_safe,
    verify_evidence_chain,
)
from governance.policy_pack import assert_policy_diagnostics_safe, redacted_policy_payload
from governance.policy_parity import assert_parity_diagnostics_safe
from governance.policy_proof_bundle import assert_proof_bundle_safe
from governance.policy_simulation import assert_simulation_diagnostics_safe
from governance.proof_timestamp_anchor import assert_timestamp_anchor_safe
from governance.rfc3161_timestamp import assert_rfc3161_safe
from governance.worm_evidence_manifest import assert_worm_safe

MERKLE_CHECKPOINT_SCHEMA = "usbay.governance_evidence_merkle_checkpoint.v1"
MERKLE_ERROR_REGISTRY_PATH = Path("governance/evidence_merkle_checkpoint_errors.json")
MERKLE_ERROR_SCHEMA = "usbay.governance_evidence_merkle_checkpoint_error_registry.v1"
MERKLE_ERROR_CODES = (
    "MERKLE_LEAVES_MISSING",
    "MERKLE_CHAIN_RANGE_INVALID",
    "MERKLE_ROOT_MISMATCH",
    "MERKLE_CHECKPOINT_REPLAY_DETECTED",
    "MERKLE_CHAIN_HEAD_MISMATCH",
    "MERKLE_DIAGNOSTICS_UNSAFE",
)
MODULE_VERSIONS = {
    **EVIDENCE_CHAIN_MODULE_VERSIONS,
    "evidence_merkle_checkpoint": MERKLE_CHECKPOINT_SCHEMA,
}


class EvidenceMerkleCheckpointError(RuntimeError):
    pass


@dataclass(frozen=True)
class MerkleCheckpointVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    checkpoint_id: str
    chain_start_position: int
    chain_end_position: int
    merkle_root: str
    evidence_chain_head_hash: str
    retention_policy_label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "checkpoint_id": self.checkpoint_id,
            "chain_start_position": self.chain_start_position,
            "chain_end_position": self.chain_end_position,
            "merkle_root": self.merkle_root,
            "evidence_chain_head_hash": self.evidence_chain_head_hash,
            "retention_policy_label": self.retention_policy_label,
        }


def load_merkle_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / MERKLE_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EvidenceMerkleCheckpointError("merkle_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != MERKLE_ERROR_SCHEMA:
        raise EvidenceMerkleCheckpointError("merkle_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise EvidenceMerkleCheckpointError("merkle_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise EvidenceMerkleCheckpointError("merkle_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(MERKLE_ERROR_CODES) - set(registry))
    if missing:
        raise EvidenceMerkleCheckpointError("merkle_error_registry_incomplete:" + ",".join(missing))
    return registry


def create_merkle_checkpoint(
    evidence_chain: dict[str, Any],
    *,
    chain_start_position: int,
    chain_end_position: int,
    timestamp: str | None = None,
) -> dict[str, Any]:
    chain_verification = verify_evidence_chain(evidence_chain)
    if not chain_verification.valid:
        raise EvidenceMerkleCheckpointError("MERKLE_CHAIN_HEAD_MISMATCH")
    entries = evidence_chain.get("entries", []) if isinstance(evidence_chain, dict) else []
    if not _range_valid(chain_start_position, chain_end_position, len(entries)):
        raise EvidenceMerkleCheckpointError("MERKLE_CHAIN_RANGE_INVALID")
    selected_entries = entries[chain_start_position : chain_end_position + 1]
    leaf_hashes = [str(entry.get("current_manifest_hash", "")) for entry in selected_entries]
    if not leaf_hashes or any(not _is_sha256_hex(leaf) for leaf in leaf_hashes):
        raise EvidenceMerkleCheckpointError("MERKLE_LEAVES_MISSING")
    if len(set(leaf_hashes)) != len(leaf_hashes):
        raise EvidenceMerkleCheckpointError("MERKLE_CHECKPOINT_REPLAY_DETECTED")
    timestamp_value = timestamp or _utc_now()
    if not _timestamp_is_valid(timestamp_value):
        raise EvidenceMerkleCheckpointError("MERKLE_CHAIN_RANGE_INVALID")
    retention_labels = {str(entry.get("retention_policy_label", "")) for entry in selected_entries}
    if len(retention_labels) != 1 or "" in retention_labels:
        raise EvidenceMerkleCheckpointError("MERKLE_CHAIN_RANGE_INVALID")
    root = merkle_root(leaf_hashes)
    payload = {
        "chain_end_position": chain_end_position,
        "chain_start_position": chain_start_position,
        "evidence_chain_head_hash": chain_verification.latest_chain_hash,
        "leaf_hashes": leaf_hashes,
        "merkle_root": root,
        "retention_policy_label": next(iter(retention_labels)),
        "utc_timestamp": timestamp_value,
    }
    checkpoint = {
        "schema": MERKLE_CHECKPOINT_SCHEMA,
        "checkpoint_id": _sha256_hex(_canonical_json(payload).encode("utf-8")),
        **payload,
        "governance_module_versions": dict(MODULE_VERSIONS),
    }
    _assert_merkle_safe(checkpoint)
    return checkpoint


def create_merkle_checkpoint_file(
    evidence_chain_path: Path,
    output_path: Path,
    *,
    chain_start_position: int,
    chain_end_position: int,
    timestamp: str | None = None,
) -> dict[str, Any]:
    checkpoint = create_merkle_checkpoint(
        _load_json_object(evidence_chain_path, "merkle_evidence_chain_invalid"),
        chain_start_position=chain_start_position,
        chain_end_position=chain_end_position,
        timestamp=timestamp,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(checkpoint) + "\n", encoding="utf-8")
    return checkpoint


def verify_merkle_checkpoint(
    checkpoint: dict[str, Any],
    *,
    evidence_chain: dict[str, Any] | None = None,
    existing_checkpoints: list[dict[str, Any]] | None = None,
) -> MerkleCheckpointVerificationResult:
    errors: list[str] = []
    if not isinstance(checkpoint, dict) or checkpoint.get("schema") != MERKLE_CHECKPOINT_SCHEMA:
        errors.append("MERKLE_ROOT_MISMATCH")
    checkpoint_id = str(checkpoint.get("checkpoint_id", "")) if isinstance(checkpoint, dict) else ""
    start = checkpoint.get("chain_start_position") if isinstance(checkpoint, dict) else None
    end = checkpoint.get("chain_end_position") if isinstance(checkpoint, dict) else None
    leaves = checkpoint.get("leaf_hashes") if isinstance(checkpoint, dict) else None
    root = str(checkpoint.get("merkle_root", "")) if isinstance(checkpoint, dict) else ""
    chain_head = str(checkpoint.get("evidence_chain_head_hash", "")) if isinstance(checkpoint, dict) else ""
    retention_policy_label = str(checkpoint.get("retention_policy_label", "")) if isinstance(checkpoint, dict) else ""
    if not isinstance(leaves, list) or not leaves or any(not isinstance(leaf, str) or not _is_sha256_hex(leaf) for leaf in leaves):
        errors.append("MERKLE_LEAVES_MISSING")
        leaves = []
    if not isinstance(start, int) or not isinstance(end, int) or start < 0 or end < start or len(leaves) != end - start + 1:
        errors.append("MERKLE_CHAIN_RANGE_INVALID")
    if len(set(leaves)) != len(leaves):
        errors.append("MERKLE_CHECKPOINT_REPLAY_DETECTED")
    expected_root = merkle_root(leaves) if leaves else ""
    if not _is_sha256_hex(root) or root != expected_root:
        errors.append("MERKLE_ROOT_MISMATCH")
    payload = {
        "chain_end_position": end,
        "chain_start_position": start,
        "evidence_chain_head_hash": chain_head,
        "leaf_hashes": leaves,
        "merkle_root": root,
        "retention_policy_label": retention_policy_label,
        "utc_timestamp": checkpoint.get("utc_timestamp", "") if isinstance(checkpoint, dict) else "",
    }
    if not _is_sha256_hex(checkpoint_id) or checkpoint_id != _sha256_hex(_canonical_json(payload).encode("utf-8")):
        errors.append("MERKLE_ROOT_MISMATCH")
    if not _is_sha256_hex(chain_head):
        errors.append("MERKLE_CHAIN_HEAD_MISMATCH")
    if not retention_policy_label or not _timestamp_is_valid(str(payload["utc_timestamp"])):
        errors.append("MERKLE_CHAIN_RANGE_INVALID")
    if evidence_chain is not None:
        chain_verification = verify_evidence_chain(evidence_chain)
        entries = evidence_chain.get("entries", []) if isinstance(evidence_chain, dict) else []
        if not chain_verification.valid or chain_verification.latest_chain_hash != chain_head:
            errors.append("MERKLE_CHAIN_HEAD_MISMATCH")
        elif not _range_valid(int(start), int(end), len(entries)):
            errors.append("MERKLE_CHAIN_RANGE_INVALID")
        else:
            expected_leaves = [str(entry.get("current_manifest_hash", "")) for entry in entries[int(start) : int(end) + 1]]
            if leaves != expected_leaves:
                errors.append("MERKLE_CHAIN_HEAD_MISMATCH")
    for existing in existing_checkpoints or []:
        if isinstance(existing, dict) and existing.get("checkpoint_id") == checkpoint_id:
            errors.append("MERKLE_CHECKPOINT_REPLAY_DETECTED")
    try:
        _assert_merkle_safe(checkpoint)
    except EvidenceMerkleCheckpointError:
        errors.append("MERKLE_DIAGNOSTICS_UNSAFE")
    return MerkleCheckpointVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        checkpoint_id=checkpoint_id,
        chain_start_position=int(start) if isinstance(start, int) else -1,
        chain_end_position=int(end) if isinstance(end, int) else -1,
        merkle_root=root,
        evidence_chain_head_hash=chain_head,
        retention_policy_label=retention_policy_label,
    )


def verify_merkle_checkpoint_file(
    checkpoint_path: Path,
    *,
    evidence_chain_path: Path | None = None,
) -> MerkleCheckpointVerificationResult:
    evidence_chain = _load_json_object(evidence_chain_path, "merkle_evidence_chain_invalid") if evidence_chain_path else None
    return verify_merkle_checkpoint(
        _load_json_object(checkpoint_path, "merkle_checkpoint_invalid"),
        evidence_chain=evidence_chain,
    )


def explain_merkle_checkpoint(root: Path, code: str) -> dict[str, str]:
    registry = load_merkle_error_registry(root)
    if code not in registry:
        raise EvidenceMerkleCheckpointError("merkle_error_unknown:" + code)
    return {"code": code, **registry[code]}


def merkle_checkpoint_summary(checkpoint: dict[str, Any]) -> dict[str, Any]:
    verification = verify_merkle_checkpoint(checkpoint)
    return {
        "valid": verification.valid,
        "error_codes": list(verification.errors),
        "checkpoint_id": verification.checkpoint_id,
        "chain_start_position": verification.chain_start_position,
        "chain_end_position": verification.chain_end_position,
        "merkle_root": verification.merkle_root,
        "evidence_chain_head_hash": verification.evidence_chain_head_hash,
        "retention_policy_label": verification.retention_policy_label,
    }


def merkle_root(leaf_hashes: list[str]) -> str:
    if not leaf_hashes:
        raise EvidenceMerkleCheckpointError("MERKLE_LEAVES_MISSING")
    level = list(leaf_hashes)
    while len(level) > 1:
        next_level: list[str] = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            next_level.append(_sha256_hex((left + right).encode("utf-8")))
        level = next_level
    return level[0]


def redacted_merkle_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_merkle_safe(payload: Any) -> None:
    _assert_merkle_safe(payload)


def _assert_merkle_safe(payload: Any) -> None:
    try:
        redacted = redacted_policy_payload(payload)
        assert_policy_diagnostics_safe(redacted)
        assert_simulation_diagnostics_safe(redacted)
        assert_parity_diagnostics_safe(redacted)
        assert_proof_bundle_safe(redacted)
        assert_timestamp_anchor_safe(redacted)
        assert_rfc3161_safe(redacted)
        assert_worm_safe(redacted)
        assert_evidence_chain_safe(redacted)
        if redacted != payload:
            raise EvidenceMerkleCheckpointError("MERKLE_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, EvidenceMerkleCheckpointError):
            raise
        raise EvidenceMerkleCheckpointError("MERKLE_DIAGNOSTICS_UNSAFE") from exc


def _range_valid(start: int, end: int, chain_length: int) -> bool:
    return isinstance(start, int) and isinstance(end, int) and 0 <= start <= end < chain_length


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise EvidenceMerkleCheckpointError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EvidenceMerkleCheckpointError(failure_code) from exc
    if not isinstance(payload, dict):
        raise EvidenceMerkleCheckpointError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise EvidenceMerkleCheckpointError("MERKLE_ROOT_MISMATCH") from exc


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _timestamp_is_valid(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return value.endswith("Z") and parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
