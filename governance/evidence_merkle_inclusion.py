from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from governance.evidence_merkle_checkpoint import (
    MODULE_VERSIONS as CHECKPOINT_MODULE_VERSIONS,
    assert_merkle_safe,
    verify_merkle_checkpoint,
)
from governance.policy_pack import assert_policy_diagnostics_safe, redacted_policy_payload
from governance.policy_parity import assert_parity_diagnostics_safe
from governance.policy_proof_bundle import assert_proof_bundle_safe
from governance.policy_simulation import assert_simulation_diagnostics_safe
from governance.proof_timestamp_anchor import assert_timestamp_anchor_safe
from governance.rfc3161_timestamp import assert_rfc3161_safe
from governance.worm_evidence_manifest import assert_worm_safe
from governance.evidence_chain import assert_evidence_chain_safe

MERKLE_INCLUSION_SCHEMA = "usbay.governance_evidence_merkle_inclusion.v1"
MERKLE_INCLUSION_ERROR_REGISTRY_PATH = Path("governance/evidence_merkle_inclusion_errors.json")
MERKLE_INCLUSION_ERROR_SCHEMA = "usbay.governance_evidence_merkle_inclusion_error_registry.v1"
MERKLE_INCLUSION_ERROR_CODES = (
    "MERKLE_INCLUSION_LEAF_MISSING",
    "MERKLE_INCLUSION_INDEX_INVALID",
    "MERKLE_INCLUSION_PATH_INVALID",
    "MERKLE_INCLUSION_ROOT_MISMATCH",
    "MERKLE_INCLUSION_CHECKPOINT_MISMATCH",
    "MERKLE_INCLUSION_DIAGNOSTICS_UNSAFE",
)
MODULE_VERSIONS = {
    **CHECKPOINT_MODULE_VERSIONS,
    "evidence_merkle_inclusion": MERKLE_INCLUSION_SCHEMA,
}


class EvidenceMerkleInclusionError(RuntimeError):
    pass


@dataclass(frozen=True)
class MerkleInclusionVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    checkpoint_id: str
    leaf_hash: str
    leaf_index: int
    merkle_root: str
    evidence_chain_head_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "checkpoint_id": self.checkpoint_id,
            "leaf_hash": self.leaf_hash,
            "leaf_index": self.leaf_index,
            "merkle_root": self.merkle_root,
            "evidence_chain_head_hash": self.evidence_chain_head_hash,
        }


def load_merkle_inclusion_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / MERKLE_INCLUSION_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EvidenceMerkleInclusionError("merkle_inclusion_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != MERKLE_INCLUSION_ERROR_SCHEMA:
        raise EvidenceMerkleInclusionError("merkle_inclusion_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise EvidenceMerkleInclusionError("merkle_inclusion_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise EvidenceMerkleInclusionError("merkle_inclusion_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(MERKLE_INCLUSION_ERROR_CODES) - set(registry))
    if missing:
        raise EvidenceMerkleInclusionError("merkle_inclusion_error_registry_incomplete:" + ",".join(missing))
    return registry


def create_merkle_inclusion_proof(checkpoint: dict[str, Any], *, leaf_index: int) -> dict[str, Any]:
    checkpoint_verification = verify_merkle_checkpoint(checkpoint)
    if not checkpoint_verification.valid:
        raise EvidenceMerkleInclusionError("MERKLE_INCLUSION_CHECKPOINT_MISMATCH")
    leaf_hashes = checkpoint.get("leaf_hashes", []) if isinstance(checkpoint, dict) else []
    if not isinstance(leaf_hashes, list) or not leaf_hashes:
        raise EvidenceMerkleInclusionError("MERKLE_INCLUSION_LEAF_MISSING")
    if not isinstance(leaf_index, int) or leaf_index < 0 or leaf_index >= len(leaf_hashes):
        raise EvidenceMerkleInclusionError("MERKLE_INCLUSION_INDEX_INVALID")
    leaf_hash = str(leaf_hashes[leaf_index])
    if not _is_sha256_hex(leaf_hash):
        raise EvidenceMerkleInclusionError("MERKLE_INCLUSION_LEAF_MISSING")
    proof = {
        "schema": MERKLE_INCLUSION_SCHEMA,
        "checkpoint_id": checkpoint_verification.checkpoint_id,
        "leaf_hash": leaf_hash,
        "leaf_index": leaf_index,
        "sibling_path": _sibling_path([str(leaf) for leaf in leaf_hashes], leaf_index),
        "merkle_root": checkpoint_verification.merkle_root,
        "evidence_chain_head_hash": checkpoint_verification.evidence_chain_head_hash,
        "checkpoint_range": {
            "chain_start_position": checkpoint_verification.chain_start_position,
            "chain_end_position": checkpoint_verification.chain_end_position,
        },
        "governance_module_versions": dict(MODULE_VERSIONS),
    }
    _assert_inclusion_safe(proof)
    return proof


def create_merkle_inclusion_proof_file(checkpoint_path: Path, output_path: Path, *, leaf_index: int) -> dict[str, Any]:
    proof = create_merkle_inclusion_proof(_load_json_object(checkpoint_path, "merkle_checkpoint_invalid"), leaf_index=leaf_index)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(proof) + "\n", encoding="utf-8")
    return proof


def verify_merkle_inclusion_proof(
    proof: dict[str, Any],
    *,
    checkpoint: dict[str, Any] | None = None,
) -> MerkleInclusionVerificationResult:
    errors: list[str] = []
    if not isinstance(proof, dict) or proof.get("schema") != MERKLE_INCLUSION_SCHEMA:
        errors.append("MERKLE_INCLUSION_CHECKPOINT_MISMATCH")
    checkpoint_id = str(proof.get("checkpoint_id", "")) if isinstance(proof, dict) else ""
    leaf_hash = str(proof.get("leaf_hash", "")) if isinstance(proof, dict) else ""
    leaf_index = proof.get("leaf_index") if isinstance(proof, dict) else None
    sibling_path = proof.get("sibling_path") if isinstance(proof, dict) else None
    merkle_root = str(proof.get("merkle_root", "")) if isinstance(proof, dict) else ""
    chain_head = str(proof.get("evidence_chain_head_hash", "")) if isinstance(proof, dict) else ""
    checkpoint_range = proof.get("checkpoint_range") if isinstance(proof, dict) else None
    if not _is_sha256_hex(leaf_hash):
        errors.append("MERKLE_INCLUSION_LEAF_MISSING")
    if not isinstance(leaf_index, int) or leaf_index < 0:
        errors.append("MERKLE_INCLUSION_INDEX_INVALID")
    if not _path_valid(sibling_path):
        errors.append("MERKLE_INCLUSION_PATH_INVALID")
        sibling_path = []
    if not _is_sha256_hex(merkle_root) or _root_from_path(leaf_hash, int(leaf_index) if isinstance(leaf_index, int) else 0, sibling_path or []) != merkle_root:
        errors.append("MERKLE_INCLUSION_ROOT_MISMATCH")
    if not _is_sha256_hex(checkpoint_id) or not _is_sha256_hex(chain_head):
        errors.append("MERKLE_INCLUSION_CHECKPOINT_MISMATCH")
    if not isinstance(checkpoint_range, dict) or not isinstance(checkpoint_range.get("chain_start_position"), int) or not isinstance(checkpoint_range.get("chain_end_position"), int):
        errors.append("MERKLE_INCLUSION_CHECKPOINT_MISMATCH")
    if checkpoint is not None:
        checkpoint_verification = verify_merkle_checkpoint(checkpoint)
        leaves = checkpoint.get("leaf_hashes", []) if isinstance(checkpoint, dict) else []
        if not checkpoint_verification.valid or checkpoint_verification.checkpoint_id != checkpoint_id:
            errors.append("MERKLE_INCLUSION_CHECKPOINT_MISMATCH")
        elif not isinstance(leaf_index, int) or leaf_index >= len(leaves):
            errors.append("MERKLE_INCLUSION_INDEX_INVALID")
        elif leaves[leaf_index] != leaf_hash:
            errors.append("MERKLE_INCLUSION_CHECKPOINT_MISMATCH")
        elif merkle_root != checkpoint_verification.merkle_root or chain_head != checkpoint_verification.evidence_chain_head_hash:
            errors.append("MERKLE_INCLUSION_CHECKPOINT_MISMATCH")
    try:
        _assert_inclusion_safe(proof)
    except EvidenceMerkleInclusionError:
        errors.append("MERKLE_INCLUSION_DIAGNOSTICS_UNSAFE")
    return MerkleInclusionVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        checkpoint_id=checkpoint_id,
        leaf_hash=leaf_hash,
        leaf_index=int(leaf_index) if isinstance(leaf_index, int) else -1,
        merkle_root=merkle_root,
        evidence_chain_head_hash=chain_head,
    )


def verify_merkle_inclusion_proof_file(
    proof_path: Path,
    *,
    checkpoint_path: Path | None = None,
) -> MerkleInclusionVerificationResult:
    checkpoint = _load_json_object(checkpoint_path, "merkle_checkpoint_invalid") if checkpoint_path else None
    return verify_merkle_inclusion_proof(
        _load_json_object(proof_path, "merkle_inclusion_proof_invalid"),
        checkpoint=checkpoint,
    )


def explain_merkle_inclusion_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_merkle_inclusion_error_registry(root)
    if code not in registry:
        raise EvidenceMerkleInclusionError("merkle_inclusion_error_unknown:" + code)
    return {"code": code, **registry[code]}


def merkle_inclusion_summary(proof: dict[str, Any]) -> dict[str, Any]:
    verification = verify_merkle_inclusion_proof(proof)
    return {
        "valid": verification.valid,
        "error_codes": list(verification.errors),
        "checkpoint_id": verification.checkpoint_id,
        "leaf_hash": verification.leaf_hash,
        "leaf_index": verification.leaf_index,
        "merkle_root": verification.merkle_root,
        "evidence_chain_head_hash": verification.evidence_chain_head_hash,
    }


def redacted_inclusion_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_inclusion_safe(payload: Any) -> None:
    _assert_inclusion_safe(payload)


def _sibling_path(leaf_hashes: list[str], leaf_index: int) -> list[dict[str, str]]:
    path: list[dict[str, str]] = []
    level = list(leaf_hashes)
    index = leaf_index
    while len(level) > 1:
        sibling_index = index - 1 if index % 2 else index + 1
        if sibling_index >= len(level):
            sibling_index = index
        direction = "left" if sibling_index < index else "right"
        path.append({"direction": direction, "hash": level[sibling_index]})
        next_level: list[str] = []
        for pair_index in range(0, len(level), 2):
            left = level[pair_index]
            right = level[pair_index + 1] if pair_index + 1 < len(level) else left
            next_level.append(_sha256_hex((left + right).encode("utf-8")))
        index //= 2
        level = next_level
    return path


def _root_from_path(leaf_hash: str, leaf_index: int, sibling_path: list[dict[str, str]]) -> str:
    current = leaf_hash
    index = leaf_index
    for step in sibling_path:
        sibling_hash = str(step.get("hash", ""))
        direction = str(step.get("direction", ""))
        if direction == "left":
            current = _sha256_hex((sibling_hash + current).encode("utf-8"))
        elif direction == "right":
            current = _sha256_hex((current + sibling_hash).encode("utf-8"))
        else:
            raise EvidenceMerkleInclusionError("MERKLE_INCLUSION_PATH_INVALID")
        index //= 2
    return current


def _path_valid(path: Any) -> bool:
    return isinstance(path, list) and all(
        isinstance(step, dict)
        and step.get("direction") in {"left", "right"}
        and isinstance(step.get("hash"), str)
        and _is_sha256_hex(str(step.get("hash")))
        for step in path
    )


def _assert_inclusion_safe(payload: Any) -> None:
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
        if redacted != payload:
            raise EvidenceMerkleInclusionError("MERKLE_INCLUSION_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, EvidenceMerkleInclusionError):
            raise
        raise EvidenceMerkleInclusionError("MERKLE_INCLUSION_DIAGNOSTICS_UNSAFE") from exc


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise EvidenceMerkleInclusionError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EvidenceMerkleInclusionError(failure_code) from exc
    if not isinstance(payload, dict):
        raise EvidenceMerkleInclusionError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise EvidenceMerkleInclusionError("MERKLE_INCLUSION_CHECKPOINT_MISMATCH") from exc


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
