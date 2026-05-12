from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from governance.evidence_chain import assert_evidence_chain_safe
from governance.evidence_merkle_checkpoint import (
    MODULE_VERSIONS as CHECKPOINT_MODULE_VERSIONS,
    assert_merkle_safe,
    merkle_root,
    verify_merkle_checkpoint,
)
from governance.evidence_merkle_inclusion import assert_inclusion_safe
from governance.policy_pack import assert_policy_diagnostics_safe, redacted_policy_payload
from governance.policy_parity import assert_parity_diagnostics_safe
from governance.policy_proof_bundle import assert_proof_bundle_safe
from governance.policy_simulation import assert_simulation_diagnostics_safe
from governance.proof_timestamp_anchor import assert_timestamp_anchor_safe
from governance.rfc3161_timestamp import assert_rfc3161_safe
from governance.worm_evidence_manifest import assert_worm_safe

MERKLE_CONSISTENCY_SCHEMA = "usbay.governance_evidence_merkle_consistency.v1"
MERKLE_CONSISTENCY_ERROR_REGISTRY_PATH = Path("governance/evidence_merkle_consistency_errors.json")
MERKLE_CONSISTENCY_ERROR_SCHEMA = "usbay.governance_evidence_merkle_consistency_error_registry.v1"
MERKLE_CONSISTENCY_ERROR_CODES = (
    "MERKLE_CONSISTENCY_PREVIOUS_MISSING",
    "MERKLE_CONSISTENCY_CURRENT_MISSING",
    "MERKLE_CONSISTENCY_RANGE_INVALID",
    "MERKLE_CONSISTENCY_ROOT_MISMATCH",
    "MERKLE_CONSISTENCY_PATH_INVALID",
    "MERKLE_CONSISTENCY_REPLAY_DETECTED",
    "MERKLE_CONSISTENCY_DIAGNOSTICS_UNSAFE",
)
MODULE_VERSIONS = {
    **CHECKPOINT_MODULE_VERSIONS,
    "evidence_merkle_consistency": MERKLE_CONSISTENCY_SCHEMA,
}


class EvidenceMerkleConsistencyError(RuntimeError):
    pass


@dataclass(frozen=True)
class MerkleConsistencyVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    previous_checkpoint_id: str
    current_checkpoint_id: str
    previous_merkle_root: str
    current_merkle_root: str
    previous_chain_end_position: int
    current_chain_end_position: int
    evidence_chain_head_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "previous_checkpoint_id": self.previous_checkpoint_id,
            "current_checkpoint_id": self.current_checkpoint_id,
            "previous_merkle_root": self.previous_merkle_root,
            "current_merkle_root": self.current_merkle_root,
            "previous_chain_end_position": self.previous_chain_end_position,
            "current_chain_end_position": self.current_chain_end_position,
            "evidence_chain_head_hash": self.evidence_chain_head_hash,
        }


def load_merkle_consistency_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / MERKLE_CONSISTENCY_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EvidenceMerkleConsistencyError("merkle_consistency_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != MERKLE_CONSISTENCY_ERROR_SCHEMA:
        raise EvidenceMerkleConsistencyError("merkle_consistency_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise EvidenceMerkleConsistencyError("merkle_consistency_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise EvidenceMerkleConsistencyError("merkle_consistency_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(MERKLE_CONSISTENCY_ERROR_CODES) - set(registry))
    if missing:
        raise EvidenceMerkleConsistencyError("merkle_consistency_error_registry_incomplete:" + ",".join(missing))
    return registry


def create_merkle_consistency_proof(previous_checkpoint: dict[str, Any], current_checkpoint: dict[str, Any]) -> dict[str, Any]:
    previous = verify_merkle_checkpoint(previous_checkpoint)
    current = verify_merkle_checkpoint(current_checkpoint)
    if not previous.valid:
        raise EvidenceMerkleConsistencyError("MERKLE_CONSISTENCY_PREVIOUS_MISSING")
    if not current.valid:
        raise EvidenceMerkleConsistencyError("MERKLE_CONSISTENCY_CURRENT_MISSING")
    previous_leaves = previous_checkpoint.get("leaf_hashes", []) if isinstance(previous_checkpoint, dict) else []
    current_leaves = current_checkpoint.get("leaf_hashes", []) if isinstance(current_checkpoint, dict) else []
    if not _range_consistent(previous, current, previous_leaves, current_leaves):
        raise EvidenceMerkleConsistencyError("MERKLE_CONSISTENCY_RANGE_INVALID")
    if list(current_leaves[: len(previous_leaves)]) != list(previous_leaves):
        raise EvidenceMerkleConsistencyError("MERKLE_CONSISTENCY_PATH_INVALID")
    if previous.checkpoint_id == current.checkpoint_id or previous.merkle_root == current.merkle_root:
        raise EvidenceMerkleConsistencyError("MERKLE_CONSISTENCY_REPLAY_DETECTED")
    proof = {
        "schema": MERKLE_CONSISTENCY_SCHEMA,
        "previous_checkpoint_id": previous.checkpoint_id,
        "current_checkpoint_id": current.checkpoint_id,
        "previous_merkle_root": previous.merkle_root,
        "current_merkle_root": current.merkle_root,
        "previous_chain_end_position": previous.chain_end_position,
        "current_chain_end_position": current.chain_end_position,
        "consistency_path": {
            "previous_leaf_hashes": [str(leaf) for leaf in previous_leaves],
            "appended_leaf_hashes": [str(leaf) for leaf in current_leaves[len(previous_leaves) :]],
        },
        "evidence_chain_head_hash": current.evidence_chain_head_hash,
        "governance_module_versions": dict(MODULE_VERSIONS),
    }
    _assert_consistency_safe(proof)
    return proof


def create_merkle_consistency_proof_file(
    previous_checkpoint_path: Path,
    current_checkpoint_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    proof = create_merkle_consistency_proof(
        _load_json_object(previous_checkpoint_path, "MERKLE_CONSISTENCY_PREVIOUS_MISSING"),
        _load_json_object(current_checkpoint_path, "MERKLE_CONSISTENCY_CURRENT_MISSING"),
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(proof) + "\n", encoding="utf-8")
    return proof


def verify_merkle_consistency_proof(
    proof: dict[str, Any],
    *,
    previous_checkpoint: dict[str, Any] | None = None,
    current_checkpoint: dict[str, Any] | None = None,
    existing_proofs: list[dict[str, Any]] | None = None,
) -> MerkleConsistencyVerificationResult:
    errors: list[str] = []
    if not isinstance(proof, dict) or proof.get("schema") != MERKLE_CONSISTENCY_SCHEMA:
        errors.append("MERKLE_CONSISTENCY_PATH_INVALID")
    previous_checkpoint_id = str(proof.get("previous_checkpoint_id", "")) if isinstance(proof, dict) else ""
    current_checkpoint_id = str(proof.get("current_checkpoint_id", "")) if isinstance(proof, dict) else ""
    previous_root = str(proof.get("previous_merkle_root", "")) if isinstance(proof, dict) else ""
    current_root = str(proof.get("current_merkle_root", "")) if isinstance(proof, dict) else ""
    previous_end = proof.get("previous_chain_end_position") if isinstance(proof, dict) else None
    current_end = proof.get("current_chain_end_position") if isinstance(proof, dict) else None
    consistency_path = proof.get("consistency_path") if isinstance(proof, dict) else None
    chain_head = str(proof.get("evidence_chain_head_hash", "")) if isinstance(proof, dict) else ""
    previous_leaves, appended_leaves = _extract_consistency_path(consistency_path)
    if not _is_sha256_hex(previous_checkpoint_id):
        errors.append("MERKLE_CONSISTENCY_PREVIOUS_MISSING")
    if not _is_sha256_hex(current_checkpoint_id):
        errors.append("MERKLE_CONSISTENCY_CURRENT_MISSING")
    if not _range_values_valid(previous_end, current_end, previous_leaves, appended_leaves):
        errors.append("MERKLE_CONSISTENCY_RANGE_INVALID")
    if previous_checkpoint_id == current_checkpoint_id or previous_root == current_root or not appended_leaves:
        errors.append("MERKLE_CONSISTENCY_REPLAY_DETECTED")
    if not _path_valid(previous_leaves, appended_leaves):
        errors.append("MERKLE_CONSISTENCY_PATH_INVALID")
    else:
        expected_previous_root = merkle_root(previous_leaves)
        expected_current_root = merkle_root(previous_leaves + appended_leaves)
        if previous_root != expected_previous_root or current_root != expected_current_root:
            errors.append("MERKLE_CONSISTENCY_ROOT_MISMATCH")
    if not _is_sha256_hex(chain_head):
        errors.append("MERKLE_CONSISTENCY_CURRENT_MISSING")
    if previous_checkpoint is not None:
        previous_verification = verify_merkle_checkpoint(previous_checkpoint)
        previous_checkpoint_leaves = previous_checkpoint.get("leaf_hashes", []) if isinstance(previous_checkpoint, dict) else []
        if (
            not previous_verification.valid
            or previous_verification.checkpoint_id != previous_checkpoint_id
            or previous_verification.merkle_root != previous_root
            or previous_verification.chain_end_position != previous_end
            or list(previous_checkpoint_leaves) != previous_leaves
        ):
            errors.append("MERKLE_CONSISTENCY_PREVIOUS_MISSING")
    if current_checkpoint is not None:
        current_verification = verify_merkle_checkpoint(current_checkpoint)
        current_checkpoint_leaves = current_checkpoint.get("leaf_hashes", []) if isinstance(current_checkpoint, dict) else []
        if (
            not current_verification.valid
            or current_verification.checkpoint_id != current_checkpoint_id
            or current_verification.merkle_root != current_root
            or current_verification.chain_end_position != current_end
            or current_verification.evidence_chain_head_hash != chain_head
            or list(current_checkpoint_leaves) != previous_leaves + appended_leaves
        ):
            errors.append("MERKLE_CONSISTENCY_CURRENT_MISSING")
    for existing in existing_proofs or []:
        if (
            isinstance(existing, dict)
            and existing.get("previous_checkpoint_id") == previous_checkpoint_id
            and existing.get("current_checkpoint_id") == current_checkpoint_id
        ):
            errors.append("MERKLE_CONSISTENCY_REPLAY_DETECTED")
    try:
        _assert_consistency_safe(proof)
    except EvidenceMerkleConsistencyError:
        errors.append("MERKLE_CONSISTENCY_DIAGNOSTICS_UNSAFE")
    return MerkleConsistencyVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        previous_checkpoint_id=previous_checkpoint_id,
        current_checkpoint_id=current_checkpoint_id,
        previous_merkle_root=previous_root,
        current_merkle_root=current_root,
        previous_chain_end_position=int(previous_end) if isinstance(previous_end, int) else -1,
        current_chain_end_position=int(current_end) if isinstance(current_end, int) else -1,
        evidence_chain_head_hash=chain_head,
    )


def verify_merkle_consistency_proof_file(
    proof_path: Path,
    *,
    previous_checkpoint_path: Path | None = None,
    current_checkpoint_path: Path | None = None,
) -> MerkleConsistencyVerificationResult:
    previous_checkpoint = _load_json_object(previous_checkpoint_path, "MERKLE_CONSISTENCY_PREVIOUS_MISSING") if previous_checkpoint_path else None
    current_checkpoint = _load_json_object(current_checkpoint_path, "MERKLE_CONSISTENCY_CURRENT_MISSING") if current_checkpoint_path else None
    return verify_merkle_consistency_proof(
        _load_json_object(proof_path, "merkle_consistency_proof_invalid"),
        previous_checkpoint=previous_checkpoint,
        current_checkpoint=current_checkpoint,
    )


def explain_merkle_consistency_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_merkle_consistency_error_registry(root)
    if code not in registry:
        raise EvidenceMerkleConsistencyError("merkle_consistency_error_unknown:" + code)
    return {"code": code, **registry[code]}


def merkle_consistency_summary(proof: dict[str, Any]) -> dict[str, Any]:
    verification = verify_merkle_consistency_proof(proof)
    return {
        "valid": verification.valid,
        "error_codes": list(verification.errors),
        "previous_checkpoint_id": verification.previous_checkpoint_id,
        "current_checkpoint_id": verification.current_checkpoint_id,
        "previous_merkle_root": verification.previous_merkle_root,
        "current_merkle_root": verification.current_merkle_root,
        "previous_chain_end_position": verification.previous_chain_end_position,
        "current_chain_end_position": verification.current_chain_end_position,
        "evidence_chain_head_hash": verification.evidence_chain_head_hash,
    }


def redacted_consistency_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_consistency_safe(payload: Any) -> None:
    _assert_consistency_safe(payload)


def _extract_consistency_path(path: Any) -> tuple[list[str], list[str]]:
    if not isinstance(path, dict):
        return [], []
    previous_leaves = path.get("previous_leaf_hashes")
    appended_leaves = path.get("appended_leaf_hashes")
    if not isinstance(previous_leaves, list) or not isinstance(appended_leaves, list):
        return [], []
    return [str(leaf) for leaf in previous_leaves], [str(leaf) for leaf in appended_leaves]


def _range_consistent(previous: Any, current: Any, previous_leaves: Any, current_leaves: Any) -> bool:
    return (
        isinstance(previous_leaves, list)
        and isinstance(current_leaves, list)
        and previous.chain_start_position == current.chain_start_position == 0
        and previous.chain_end_position >= 0
        and current.chain_end_position > previous.chain_end_position
        and len(previous_leaves) == previous.chain_end_position + 1
        and len(current_leaves) == current.chain_end_position + 1
        and len(current_leaves) > len(previous_leaves)
    )


def _range_values_valid(previous_end: Any, current_end: Any, previous_leaves: list[str], appended_leaves: list[str]) -> bool:
    return (
        isinstance(previous_end, int)
        and isinstance(current_end, int)
        and previous_end >= 0
        and current_end > previous_end
        and len(previous_leaves) == previous_end + 1
        and len(previous_leaves) + len(appended_leaves) == current_end + 1
    )


def _path_valid(previous_leaves: list[str], appended_leaves: list[str]) -> bool:
    all_leaves = previous_leaves + appended_leaves
    return bool(previous_leaves) and bool(appended_leaves) and all(_is_sha256_hex(leaf) for leaf in all_leaves) and len(set(all_leaves)) == len(all_leaves)


def _assert_consistency_safe(payload: Any) -> None:
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
        assert_merkle_safe(redacted)
        assert_inclusion_safe(redacted)
        if redacted != payload:
            raise EvidenceMerkleConsistencyError("MERKLE_CONSISTENCY_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, EvidenceMerkleConsistencyError):
            raise
        raise EvidenceMerkleConsistencyError("MERKLE_CONSISTENCY_DIAGNOSTICS_UNSAFE") from exc


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise EvidenceMerkleConsistencyError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EvidenceMerkleConsistencyError(failure_code) from exc
    if not isinstance(payload, dict):
        raise EvidenceMerkleConsistencyError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise EvidenceMerkleConsistencyError("MERKLE_CONSISTENCY_PATH_INVALID") from exc


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
