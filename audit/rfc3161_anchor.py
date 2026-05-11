from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from audit.anchor import MockTSAClient, TimestampAuthorityClient, timestamp_event


class TimestampVerificationError(RuntimeError):
    pass


def tsa_mode() -> str:
    mode = (os.getenv("TSA_MODE") or os.getenv("USBAY_TSA_MODE") or "mock").lower()
    if mode not in {"mock", "external"}:
        raise TimestampVerificationError("invalid_tsa_mode")
    return mode


def tsa_policy_oid() -> str:
    return os.getenv("TSA_POLICY_OID") or os.getenv("USBAY_TSA_POLICY_OID") or MockTSAClient.policy_oid


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def component_hashes(
    *,
    audit_jsonl: str,
    ledger_sha256: str,
    signatures: dict[str, Any],
    consensus_evidence: dict[str, Any],
    deployment_provenance: dict[str, Any] | None = None,
) -> dict[str, str]:
    components = {
        "audit.jsonl": sha256_text(audit_jsonl),
        "ledger.sha256": sha256_text(ledger_sha256 + "\n"),
        "signatures.json": sha256_text(canonical_json(signatures)),
        "consensus_evidence.json": sha256_text(canonical_json(consensus_evidence)),
    }
    if deployment_provenance is not None:
        components["governance_release.json"] = sha256_text(canonical_json(deployment_provenance))
    return components


def message_imprint(components: dict[str, str]) -> str:
    return sha256_text(canonical_json(components))


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise TimestampVerificationError("timestamp_malformed") from exc
    if parsed.tzinfo is None:
        raise TimestampVerificationError("timestamp_malformed")
    return parsed.astimezone(timezone.utc)


def _decode_token(token: str) -> dict[str, Any]:
    try:
        decoded = base64.b64decode(token.encode("ascii"), validate=True)
        payload = json.loads(decoded.decode("utf-8"))
    except Exception as exc:
        raise TimestampVerificationError("timestamp_token_malformed") from exc
    if not isinstance(payload, dict):
        raise TimestampVerificationError("timestamp_token_malformed")
    return payload


def _mock_signature_valid(token_payload: dict[str, Any]) -> bool:
    signature = token_payload.get("signature")
    if not isinstance(signature, str) or not signature:
        return False
    unsigned = dict(token_payload)
    unsigned.pop("signature", None)
    body = canonical_json(unsigned)
    expected = hashlib.sha256(f"{body}:{MockTSAClient.signing_seed}".encode("utf-8")).hexdigest()
    return signature == expected


def timestamp_hash(proof: dict[str, Any]) -> str:
    return sha256_text(canonical_json(proof))


def create_timestamp_proof(
    message_hash: str,
    *,
    previous_timestamp_hash: str | None = None,
    tsa_client: TimestampAuthorityClient | None = None,
) -> dict[str, Any]:
    proof = timestamp_event(message_hash, tsa_client=tsa_client)
    proof["previous_timestamp_hash"] = previous_timestamp_hash or "GENESIS"
    proof["timestamp_hash"] = timestamp_hash({
        key: value for key, value in proof.items() if key != "timestamp_hash"
    })
    return proof


def verify_timestamp_proof(
    proof: dict[str, Any],
    expected_message_hash: str,
    *,
    previous_timestamp_hash: str | None = None,
    seen_token_hashes: set[str] | None = None,
    now: datetime | None = None,
    mode: str | None = None,
) -> dict[str, Any]:
    result = {
        "valid": False,
        "message_imprint_valid": False,
        "token_signature_valid": False,
        "certificate_chain_valid": False,
        "policy_oid_valid": False,
        "revocation_valid": False,
        "timestamp_fresh": False,
        "timestamp_continuity_valid": False,
        "timestamp_replay_detected": False,
        "timestamp_hash": None,
        "message_imprint": None,
        "policy_oid": None,
        "tsa_cert_not_before": None,
        "tsa_cert_not_after": None,
        "revocation_status": None,
        "created_at": None,
        "mode": None,
        "errors": [],
    }
    try:
        if not isinstance(proof, dict) or proof.get("type") != "RFC3161":
            raise TimestampVerificationError("timestamp_token_malformed")
        if proof.get("message_imprint_algorithm") not in {"sha256", None}:
            raise TimestampVerificationError("message_imprint_algorithm_invalid")
        effective_mode = mode or tsa_mode()
        if effective_mode == "external" and proof.get("mode") == "mock":
            raise TimestampVerificationError("mock_tsa_rejected_in_production")
        token_payload = _decode_token(str(proof.get("token", "")))
        proof_imprint = proof.get("message_imprint", proof.get("hash"))
        token_imprint = token_payload.get("message_imprint", token_payload.get("hash"))
        result["message_imprint"] = proof_imprint
        result["mode"] = proof.get("mode")
        if proof_imprint != expected_message_hash or token_imprint != expected_message_hash:
            raise TimestampVerificationError("message_imprint_mismatch")
        result["message_imprint_valid"] = True
        proof_policy_oid = proof.get("policy_oid") or token_payload.get("policy")
        result["policy_oid"] = proof_policy_oid
        if proof_policy_oid != tsa_policy_oid():
            raise TimestampVerificationError("tsa_policy_oid_mismatch")
        result["policy_oid_valid"] = True
        if proof.get("mode") == "mock":
            if not _mock_signature_valid(token_payload):
                raise TimestampVerificationError("tsa_signature_invalid")
        elif not proof.get("token_signature"):
            raise TimestampVerificationError("tsa_signature_invalid")
        result["token_signature_valid"] = True
        if proof.get("tsa_certificate_chain_valid") is not True:
            raise TimestampVerificationError("tsa_certificate_chain_invalid")
        if effective_mode == "external" and not proof.get("tsa_certificate_chain_pem"):
            raise TimestampVerificationError("tsa_certificate_chain_invalid")
        cert_not_after = str(proof.get("tsa_cert_not_after", ""))
        result["tsa_cert_not_after"] = cert_not_after
        if not cert_not_after:
            raise TimestampVerificationError("tsa_certificate_chain_invalid")
        current_time = now or datetime.now(timezone.utc)
        cert_not_before = str(proof.get("tsa_cert_not_before", "1970-01-01T00:00:00Z"))
        result["tsa_cert_not_before"] = cert_not_before
        if _parse_utc(cert_not_before) > current_time:
            raise TimestampVerificationError("tsa_certificate_not_yet_valid")
        if _parse_utc(cert_not_after) <= current_time:
            raise TimestampVerificationError("tsa_certificate_expired")
        result["certificate_chain_valid"] = True
        if proof.get("revocation_status") != "valid":
            raise TimestampVerificationError("tsa_revocation_status_invalid")
        result["revocation_status"] = proof.get("revocation_status")
        result["revocation_valid"] = True
        created_at = _parse_utc(str(proof.get("created_at", "")))
        result["created_at"] = proof.get("created_at")
        freshness_seconds = int(os.getenv("TSA_TIMESTAMP_FRESHNESS_SECONDS") or os.getenv("USBAY_TSA_TIMESTAMP_FRESHNESS_SECONDS") or "300")
        if abs((current_time - created_at).total_seconds()) > freshness_seconds:
            raise TimestampVerificationError("timestamp_freshness_invalid")
        result["timestamp_fresh"] = True
        expected_previous = previous_timestamp_hash or "GENESIS"
        if proof.get("previous_timestamp_hash") != expected_previous:
            raise TimestampVerificationError("timestamp_continuity_invalid")
        computed_timestamp_hash = timestamp_hash({
            key: value for key, value in proof.items() if key != "timestamp_hash"
        })
        if proof.get("timestamp_hash") != computed_timestamp_hash:
            raise TimestampVerificationError("timestamp_hash_mismatch")
        token_hash = sha256_text(str(proof.get("token", "")))
        if seen_token_hashes is not None and token_hash in seen_token_hashes:
            result["timestamp_replay_detected"] = True
            raise TimestampVerificationError("timestamp_replay_detected")
        result["timestamp_continuity_valid"] = True
        result["timestamp_hash"] = computed_timestamp_hash
        result["valid"] = True
        return result
    except TimestampVerificationError as exc:
        result["errors"].append(str(exc))
        return result


def write_timestamp_files(export_dir: Path, proof: dict[str, Any], verification: dict[str, Any]) -> None:
    export_dir.mkdir(parents=True, exist_ok=True)
    if not verification.get("valid"):
        raise TimestampVerificationError("timestamp_verification_failed")
    token = proof.get("token")
    if not isinstance(token, str) or not token:
        raise TimestampVerificationError("timestamp_token_malformed")
    (export_dir / "rfc3161_timestamp.tsr").write_text(token + "\n", encoding="utf-8")
    (export_dir / "timestamp_verification.json").write_text(canonical_json(verification), encoding="utf-8")
    (export_dir / "tsa_certificate_chain.pem").write_text(str(proof.get("tsa_certificate_chain_pem", "")), encoding="utf-8")
    (export_dir / "tsa_policy_oid.txt").write_text(str(proof.get("policy_oid") or tsa_policy_oid()) + "\n", encoding="utf-8")
