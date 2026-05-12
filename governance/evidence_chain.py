from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from governance.policy_pack import assert_policy_diagnostics_safe, redacted_policy_payload
from governance.policy_parity import assert_parity_diagnostics_safe
from governance.policy_proof_bundle import assert_proof_bundle_safe
from governance.policy_simulation import assert_simulation_diagnostics_safe
from governance.proof_timestamp_anchor import assert_timestamp_anchor_safe
from governance.rfc3161_timestamp import assert_rfc3161_safe
from governance.worm_evidence_manifest import (
    MODULE_VERSIONS as WORM_MODULE_VERSIONS,
    assert_worm_safe,
    verify_worm_manifest,
)

EVIDENCE_CHAIN_SCHEMA = "usbay.governance_evidence_chain.v1"
EVIDENCE_CHAIN_ERROR_REGISTRY_PATH = Path("governance/evidence_chain_errors.json")
EVIDENCE_CHAIN_ERROR_SCHEMA = "usbay.governance_evidence_chain_error_registry.v1"
EVIDENCE_CHAIN_ERROR_CODES = (
    "EVIDENCE_CHAIN_PREVIOUS_HASH_MISSING",
    "EVIDENCE_CHAIN_MANIFEST_HASH_MISSING",
    "EVIDENCE_CHAIN_POSITION_INVALID",
    "EVIDENCE_CHAIN_REPLAY_DETECTED",
    "EVIDENCE_CHAIN_CONTINUITY_BROKEN",
    "EVIDENCE_CHAIN_DIAGNOSTICS_UNSAFE",
)
GENESIS_CHAIN_HASH = "0" * 64
MODULE_VERSIONS = {
    **WORM_MODULE_VERSIONS,
    "evidence_chain": EVIDENCE_CHAIN_SCHEMA,
}


class EvidenceChainError(RuntimeError):
    pass


@dataclass(frozen=True)
class EvidenceChainVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    chain_length: int
    latest_chain_hash: str
    latest_worm_manifest_hash: str
    retention_policy_label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "chain_length": self.chain_length,
            "latest_chain_hash": self.latest_chain_hash,
            "latest_worm_manifest_hash": self.latest_worm_manifest_hash,
            "retention_policy_label": self.retention_policy_label,
        }


def load_evidence_chain_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / EVIDENCE_CHAIN_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EvidenceChainError("evidence_chain_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != EVIDENCE_CHAIN_ERROR_SCHEMA:
        raise EvidenceChainError("evidence_chain_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise EvidenceChainError("evidence_chain_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise EvidenceChainError("evidence_chain_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(EVIDENCE_CHAIN_ERROR_CODES) - set(registry))
    if missing:
        raise EvidenceChainError("evidence_chain_error_registry_incomplete:" + ",".join(missing))
    return registry


def append_evidence_chain(
    existing_chain: dict[str, Any] | None,
    worm_manifest: dict[str, Any],
    *,
    timestamp: str | None = None,
) -> dict[str, Any]:
    chain = _normalized_chain(existing_chain)
    existing_verification = verify_evidence_chain(chain)
    if not existing_verification.valid:
        raise EvidenceChainError("EVIDENCE_CHAIN_CONTINUITY_BROKEN")
    worm_verification = verify_worm_manifest(worm_manifest)
    if not worm_verification.valid:
        raise EvidenceChainError("EVIDENCE_CHAIN_MANIFEST_HASH_MISSING")
    if any(entry.get("WORM_manifest_hash") == worm_verification.manifest_hash for entry in chain["entries"]):
        raise EvidenceChainError("EVIDENCE_CHAIN_REPLAY_DETECTED")
    position = len(chain["entries"])
    previous_hash = chain["entries"][-1]["current_manifest_hash"] if chain["entries"] else GENESIS_CHAIN_HASH
    timestamp_value = timestamp or _utc_now()
    if not _timestamp_is_valid(timestamp_value):
        raise EvidenceChainError("EVIDENCE_CHAIN_POSITION_INVALID")
    entry_payload = _entry_payload(
        previous_chain_hash=previous_hash,
        proof_bundle_hash=worm_verification.proof_bundle_hash,
        timestamp_anchor_hash=worm_verification.timestamp_anchor_hash,
        rfc3161_request_digest=worm_verification.rfc3161_request_digest,
        worm_manifest_hash=worm_verification.manifest_hash,
        chain_position=position,
        timestamp=timestamp_value,
        retention_policy_label=worm_verification.retention_policy_label,
    )
    entry = {
        **entry_payload,
        "current_manifest_hash": _sha256_hex(_canonical_json(entry_payload).encode("utf-8")),
    }
    chain["entries"].append(entry)
    chain["chain_hash"] = _chain_hash(chain["entries"])
    _assert_evidence_chain_safe(chain)
    return chain


def append_evidence_chain_file(
    worm_manifest_path: Path,
    output_path: Path,
    *,
    existing_chain_path: Path | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    existing_chain = _load_json_object(existing_chain_path, "evidence_chain_invalid") if existing_chain_path and existing_chain_path.is_file() else None
    chain = append_evidence_chain(
        existing_chain,
        _load_json_object(worm_manifest_path, "evidence_chain_worm_manifest_invalid"),
        timestamp=timestamp,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(chain) + "\n", encoding="utf-8")
    return chain


def verify_evidence_chain(chain: dict[str, Any]) -> EvidenceChainVerificationResult:
    errors: list[str] = []
    if not isinstance(chain, dict) or chain.get("schema") != EVIDENCE_CHAIN_SCHEMA:
        errors.append("EVIDENCE_CHAIN_CONTINUITY_BROKEN")
    entries = chain.get("entries") if isinstance(chain, dict) else None
    if not isinstance(entries, list):
        errors.append("EVIDENCE_CHAIN_CONTINUITY_BROKEN")
        entries = []
    seen_entry_hashes: set[str] = set()
    seen_worm_hashes: set[str] = set()
    expected_previous = GENESIS_CHAIN_HASH
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append("EVIDENCE_CHAIN_CONTINUITY_BROKEN")
            continue
        previous_hash = str(entry.get("previous_chain_hash", ""))
        current_hash = str(entry.get("current_manifest_hash", ""))
        worm_hash = str(entry.get("WORM_manifest_hash", ""))
        position = entry.get("chain_position")
        if not _is_sha256_hex(previous_hash):
            errors.append("EVIDENCE_CHAIN_PREVIOUS_HASH_MISSING")
        if not _is_sha256_hex(current_hash):
            errors.append("EVIDENCE_CHAIN_MANIFEST_HASH_MISSING")
        if position != index:
            errors.append("EVIDENCE_CHAIN_POSITION_INVALID")
        if previous_hash != expected_previous:
            errors.append("EVIDENCE_CHAIN_CONTINUITY_BROKEN")
        if current_hash in seen_entry_hashes or worm_hash in seen_worm_hashes:
            errors.append("EVIDENCE_CHAIN_REPLAY_DETECTED")
        seen_entry_hashes.add(current_hash)
        seen_worm_hashes.add(worm_hash)
        payload = {key: value for key, value in entry.items() if key != "current_manifest_hash"}
        if current_hash != _sha256_hex(_canonical_json(payload).encode("utf-8")):
            errors.append("EVIDENCE_CHAIN_CONTINUITY_BROKEN")
        if not _entry_fields_valid(entry):
            errors.append("EVIDENCE_CHAIN_MANIFEST_HASH_MISSING")
        expected_previous = current_hash
    chain_hash = str(chain.get("chain_hash", "")) if isinstance(chain, dict) else ""
    if chain_hash != _chain_hash(entries):
        errors.append("EVIDENCE_CHAIN_CONTINUITY_BROKEN")
    try:
        _assert_evidence_chain_safe(chain)
    except EvidenceChainError:
        errors.append("EVIDENCE_CHAIN_DIAGNOSTICS_UNSAFE")
    latest = entries[-1] if entries else {}
    return EvidenceChainVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        chain_length=len(entries),
        latest_chain_hash=str(latest.get("current_manifest_hash", "")),
        latest_worm_manifest_hash=str(latest.get("WORM_manifest_hash", "")),
        retention_policy_label=str(latest.get("retention_policy_label", "")),
    )


def verify_evidence_chain_file(path: Path) -> EvidenceChainVerificationResult:
    return verify_evidence_chain(_load_json_object(path, "evidence_chain_invalid"))


def explain_evidence_chain_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_evidence_chain_error_registry(root)
    if code not in registry:
        raise EvidenceChainError("evidence_chain_error_unknown:" + code)
    return {"code": code, **registry[code]}


def evidence_chain_summary(chain: dict[str, Any]) -> dict[str, Any]:
    verification = verify_evidence_chain(chain)
    return {
        "valid": verification.valid,
        "error_codes": list(verification.errors),
        "chain_length": verification.chain_length,
        "latest_chain_hash": verification.latest_chain_hash,
        "latest_worm_manifest_hash": verification.latest_worm_manifest_hash,
        "retention_policy_label": verification.retention_policy_label,
    }


def redacted_evidence_chain_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_evidence_chain_safe(payload: Any) -> None:
    _assert_evidence_chain_safe(payload)


def _normalized_chain(existing_chain: dict[str, Any] | None) -> dict[str, Any]:
    if existing_chain is None:
        return {"schema": EVIDENCE_CHAIN_SCHEMA, "entries": [], "chain_hash": _chain_hash([])}
    if not isinstance(existing_chain, dict):
        raise EvidenceChainError("EVIDENCE_CHAIN_CONTINUITY_BROKEN")
    return {
        "schema": existing_chain.get("schema"),
        "entries": list(existing_chain.get("entries", [])) if isinstance(existing_chain.get("entries"), list) else [],
        "chain_hash": existing_chain.get("chain_hash", ""),
    }


def _entry_payload(
    *,
    previous_chain_hash: str,
    proof_bundle_hash: str,
    timestamp_anchor_hash: str,
    rfc3161_request_digest: str,
    worm_manifest_hash: str,
    chain_position: int,
    timestamp: str,
    retention_policy_label: str,
) -> dict[str, Any]:
    return {
        "previous_chain_hash": previous_chain_hash,
        "proof_bundle_hash": proof_bundle_hash,
        "timestamp_anchor_hash": timestamp_anchor_hash,
        "RFC3161_request_digest": rfc3161_request_digest,
        "WORM_manifest_hash": worm_manifest_hash,
        "chain_position": chain_position,
        "utc_timestamp": timestamp,
        "governance_module_versions": dict(MODULE_VERSIONS),
        "retention_policy_label": retention_policy_label,
    }


def _entry_fields_valid(entry: dict[str, Any]) -> bool:
    return (
        _is_sha256_hex(str(entry.get("proof_bundle_hash", "")))
        and _is_sha256_hex(str(entry.get("timestamp_anchor_hash", "")))
        and _is_sha256_hex(str(entry.get("RFC3161_request_digest", "")))
        and _is_sha256_hex(str(entry.get("WORM_manifest_hash", "")))
        and _timestamp_is_valid(str(entry.get("utc_timestamp", "")))
        and bool(str(entry.get("retention_policy_label", "")))
        and isinstance(entry.get("governance_module_versions"), dict)
    )


def _assert_evidence_chain_safe(payload: Any) -> None:
    try:
        redacted = redacted_policy_payload(payload)
        assert_policy_diagnostics_safe(redacted)
        assert_simulation_diagnostics_safe(redacted)
        assert_parity_diagnostics_safe(redacted)
        assert_proof_bundle_safe(redacted)
        assert_timestamp_anchor_safe(redacted)
        assert_rfc3161_safe(redacted)
        assert_worm_safe(redacted)
        if redacted != payload:
            raise EvidenceChainError("EVIDENCE_CHAIN_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, EvidenceChainError):
            raise
        raise EvidenceChainError("EVIDENCE_CHAIN_DIAGNOSTICS_UNSAFE") from exc


def _load_json_object(path: Path, failure_code: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EvidenceChainError(failure_code) from exc
    if not isinstance(payload, dict):
        raise EvidenceChainError(failure_code)
    return payload


def _chain_hash(entries: list[Any]) -> str:
    return _sha256_hex(_canonical_json({"entries": entries, "schema": EVIDENCE_CHAIN_SCHEMA}).encode("utf-8"))


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise EvidenceChainError("EVIDENCE_CHAIN_CONTINUITY_BROKEN") from exc


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
