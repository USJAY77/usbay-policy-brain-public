#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.verify_production_readiness import (
    CI_EVIDENCE_MANIFEST_PATH,
    CI_EVIDENCE_TRUST_POLICY,
    CI_EVIDENCE_TRUST_POLICY_AUDIT,
    CI_EVIDENCE_TRUST_POLICY_AUTHORITY,
    CI_EVIDENCE_TRUST_POLICY_SIGNATURE,
    CI_SBOM_ARTIFACT_PATH,
    PRODUCTION_READINESS_WORKFLOW,
    REQUIRED_CI_REQUIREMENTS,
)
from audit.anchor import MockTSAClient
from audit.rfc3161_anchor import create_timestamp_proof, sha256_text, verify_timestamp_proof
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from governance.chronology import validate_chronology_consensus_interface
from governance.evidence import validate_evidence_manifest_interface
from governance.interfaces import TrustPolicyValidationResult
from governance.telemetry import measure_governance_validation
from governance.timestamping import validate_timestamp_verification_interface
from governance.trust_policy import validate_trust_policy_interface

EVIDENCE_SCHEMA = "usbay.production_readiness_ci_evidence_chain.v1"
GENESIS_HASH = "GENESIS"
SIGNATURE_ALGORITHM = "Ed25519"
SIGNATURE_PREFIX = "ed25519:"
PRIVATE_KEY_ENV = "USBAY_CI_EVIDENCE_PRIVATE_KEY_PEM"
PUBLIC_KEY_ENV = "USBAY_CI_EVIDENCE_PUBLIC_KEY_PEM"
SIGNER_ID_ENV = "USBAY_CI_EVIDENCE_SIGNER_ID"
TRUST_POLICY_ENV = "USBAY_CI_EVIDENCE_TRUST_POLICY"
DEFAULT_SIGNER_ID = "github-actions-production-readiness"
TRUST_POLICY_SIGNATURE_ALGORITHM = "Ed25519"
WORKFLOW_VERSION = "production-readiness-v1"
DEFAULT_EVIDENCE_PATHS = (
    CI_SBOM_ARTIFACT_PATH,
    PRODUCTION_READINESS_WORKFLOW,
    REQUIRED_CI_REQUIREMENTS,
    "scripts/generate_ci_dependency_sbom.py",
    "scripts/generate_ci_evidence_manifest.py",
    "scripts/verify_production_readiness.py",
    "evidence/production-readiness-guard-output.txt",
    "evidence/production-readiness-tests-output.txt",
)
TIMESTAMP_PROOFS_FILE = "timestamp_proofs.json"
TIMESTAMP_VERIFICATION_FILE = "timestamp_verification.json"
TRANSPARENCY_LOG_FILE = "transparency_log.jsonl"
CHRONOLOGY_CONSENSUS_FILE = "chronology_consensus.json"
CHRONOLOGY_CONSENSUS_AUDIT_FILE = "chronology_consensus_audit.jsonl"
DEFAULT_CHRONOLOGY_AUTHORITIES = ("mock-rfc3161-primary", "mock-rfc3161-secondary", "mock-rfc3161-backup")
DEFAULT_CHRONOLOGY_QUORUM = 2
DEFAULT_CHRONOLOGY_MAX_SKEW_SECONDS = 300
TRANSPARENCY_ANCHOR_FILE = "transparency_anchor.json"
WITNESS_PROOFS_FILE = "witness_proofs.json"
WITNESS_VERIFICATION_FILE = "witness_verification.json"
WITNESS_AUDIT_FILE = "witness_audit.jsonl"
WITNESS_TRUST_AUDIT_FILE = "witness_trust_audit.jsonl"
WITNESS_REPUTATION_HISTORY_FILE = "witness_reputation_history.jsonl"
DEFAULT_WITNESS_IDS = ("external-witness-alpha", "external-witness-beta", "external-witness-gamma")
DEFAULT_WITNESS_QUORUM = 2
DEFAULT_WITNESS_FRESHNESS_SECONDS = 300
DEFAULT_WITNESS_TRUST_THRESHOLD = 2.0
DEFAULT_WITNESS_MIN_REPUTATION = 0.75
DEFAULT_WITNESS_CONFLICT_TOLERANCE = 0
DEFAULT_WITNESS_INVALID_ATTESTATION_QUARANTINE_THRESHOLD = 2
DEFAULT_WITNESS_INACTIVITY_DECAY_AFTER_SECONDS = 300
DEFAULT_WITNESS_REPUTATION_DECAY_FACTOR = 0.5


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _record_hash(record: dict[str, Any]) -> str:
    unsigned = dict(record)
    unsigned.pop("current_record_hash", None)
    return hashlib.sha256(_canonical_json(unsigned).encode("utf-8")).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _signature_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    payload = copy.deepcopy(manifest)
    signature = payload.get("signature")
    if isinstance(signature, dict):
        signature.pop("signature", None)
    else:
        payload.pop("signature", None)
    return payload


def _run_openssl(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["openssl", *args], text=True, capture_output=True, check=False)


def generate_ed25519_keypair() -> tuple[str, str]:
    with tempfile.TemporaryDirectory(prefix="usbay-ci-evidence-key-") as tmp:
        private_path = Path(tmp) / "private.pem"
        public_path = Path(tmp) / "public.pem"
        generated = _run_openssl(["genpkey", "-algorithm", "ed25519", "-out", str(private_path)])
        if generated.returncode != 0:
            raise SystemExit("EVIDENCE_ED25519_KEYGEN_FAILED")
        exported = _run_openssl(["pkey", "-in", str(private_path), "-pubout", "-out", str(public_path)])
        if exported.returncode != 0:
            raise SystemExit("EVIDENCE_ED25519_PUBLIC_KEY_EXPORT_FAILED")
        return private_path.read_text(encoding="utf-8"), public_path.read_text(encoding="utf-8")


def _resolve_private_key(allow_test_key: bool = False) -> str:
    key = os.getenv(PRIVATE_KEY_ENV, "")
    if key:
        return key
    if allow_test_key:
        private_key, _public_key = generate_ed25519_keypair()
        return private_key
    raise SystemExit(f"EVIDENCE_PRIVATE_KEY_MISSING:{PRIVATE_KEY_ENV}")


def public_key_from_private_key(private_key_pem: str) -> str:
    with tempfile.TemporaryDirectory(prefix="usbay-ci-evidence-public-") as tmp:
        tmp_path = Path(tmp)
        private_path = tmp_path / "private.pem"
        public_path = tmp_path / "public.pem"
        private_path.write_text(private_key_pem, encoding="utf-8")
        private_path.chmod(0o600)
        exported = _run_openssl(["pkey", "-in", str(private_path), "-pubout", "-out", str(public_path)])
        if exported.returncode != 0:
            raise SystemExit("EVIDENCE_ED25519_PUBLIC_KEY_EXPORT_FAILED")
        return public_path.read_text(encoding="utf-8")


def _resolve_public_key(allow_manifest_public_key: dict[str, Any] | None = None, allow_test_key: bool = False) -> str:
    key = os.getenv(PUBLIC_KEY_ENV, "")
    if key:
        return key
    private_key = os.getenv(PRIVATE_KEY_ENV, "")
    if private_key:
        return public_key_from_private_key(private_key)
    if allow_test_key and allow_manifest_public_key:
        signature = allow_manifest_public_key.get("signature")
        if isinstance(signature, dict) and isinstance(signature.get("public_key_pem"), str):
            return str(signature["public_key_pem"])
    raise SystemExit(f"EVIDENCE_PUBLIC_KEY_MISSING:{PUBLIC_KEY_ENV}")


def _resolve_signer_id() -> str:
    return os.getenv(SIGNER_ID_ENV, DEFAULT_SIGNER_ID)


def _resolve_trust_policy_path(root: Path, trust_policy_path: Path | None = None) -> Path:
    configured = os.getenv(TRUST_POLICY_ENV, "")
    path = trust_policy_path or (Path(configured) if configured else Path(CI_EVIDENCE_TRUST_POLICY))
    return path if path.is_absolute() else root / path


def _parse_timestamp(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise ValueError(value) from exc


def normalize_public_key_pem(public_key_pem: str) -> str:
    if not isinstance(public_key_pem, str) or not public_key_pem.strip():
        raise SystemExit("EVIDENCE_PUBLIC_KEY_MISSING")
    normalized = public_key_pem.strip().replace("\\r\\n", "\n").replace("\\n", "\n").replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.strip() for line in normalized.split("\n") if line.strip()]
    normalized = "\n".join(lines) + "\n"
    try:
        key = serialization.load_pem_public_key(normalized.encode("utf-8"))
    except Exception as exc:
        raise SystemExit("EVIDENCE_PUBLIC_KEY_INVALID") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SystemExit("EVIDENCE_PUBLIC_KEY_ALGORITHM_INVALID")
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def public_key_der(public_key_pem: str) -> bytes:
    normalized = normalize_public_key_pem(public_key_pem)
    key = serialization.load_pem_public_key(normalized.encode("utf-8"))
    if not isinstance(key, Ed25519PublicKey):
        raise SystemExit("EVIDENCE_PUBLIC_KEY_ALGORITHM_INVALID")
    return key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def signer_key_id(public_key_pem: str) -> str:
    return hashlib.sha256(public_key_der(public_key_pem)).hexdigest()


def load_trust_policy(root: Path, trust_policy_path: Path | None = None) -> dict[str, Any]:
    path = _resolve_trust_policy_path(root, trust_policy_path)
    verification = verify_trust_policy_governance(root, path)
    if verification["valid"] is not True:
        raise SystemExit("EVIDENCE_TRUST_POLICY_GOVERNANCE_INVALID:" + ",".join(verification["failures"]))
    if not path.is_file():
        raise SystemExit(f"EVIDENCE_TRUST_POLICY_MISSING:{path}")
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit("EVIDENCE_TRUST_POLICY_INVALID_JSON") from exc
    if not isinstance(policy, dict):
        raise SystemExit("EVIDENCE_TRUST_POLICY_INVALID")
    interface_state, _interface_metric = measure_governance_validation(
        "trust_policy",
        "load_trust_policy",
        validate_trust_policy_interface,
        policy,
    )
    if interface_state.valid is not True:
        raise SystemExit("EVIDENCE_TRUST_POLICY_INTERFACE_INVALID:" + ",".join(interface_state.failures))
    return policy


def _trust_policy_governance_paths(root: Path, trust_policy_path: Path) -> tuple[Path, Path, Path]:
    if trust_policy_path.name == Path(CI_EVIDENCE_TRUST_POLICY).name and trust_policy_path.parent == (root / "governance"):
        return (
            root / CI_EVIDENCE_TRUST_POLICY_SIGNATURE,
            root / CI_EVIDENCE_TRUST_POLICY_AUTHORITY,
            root / CI_EVIDENCE_TRUST_POLICY_AUDIT,
        )
    return (
        trust_policy_path.with_suffix(trust_policy_path.suffix + ".sig"),
        trust_policy_path.with_suffix(trust_policy_path.suffix + ".authority.json"),
        trust_policy_path.with_suffix(trust_policy_path.suffix + ".audit.jsonl"),
    )


def _load_json_file(path: Path, failure_code: str) -> dict[str, Any]:
    if not path.is_file():
        raise SystemExit(f"{failure_code}:{path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"{failure_code}_INVALID_JSON:{path}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"{failure_code}_INVALID:{path}")
    return payload


def _trust_policy_hash(policy: dict[str, Any]) -> str:
    return _sha256_text(_canonical_json(policy))


def _trust_policy_audit_hash(record: dict[str, Any]) -> str:
    unsigned = dict(record)
    unsigned.pop("current_record_hash", None)
    return _sha256_text(_canonical_json(unsigned))


def _transparency_record_hash(record: dict[str, Any]) -> str:
    unsigned = dict(record)
    unsigned.pop("current_record_hash", None)
    return _sha256_text(_canonical_json(unsigned))


def _consensus_record_hash(record: dict[str, Any]) -> str:
    unsigned = dict(record)
    unsigned.pop("current_record_hash", None)
    return _sha256_text(_canonical_json(unsigned))


def _anchor_record_hash(record: dict[str, Any]) -> str:
    unsigned = dict(record)
    unsigned.pop("current_anchor_hash", None)
    return _sha256_text(_canonical_json(unsigned))


def _witness_audit_hash(record: dict[str, Any]) -> str:
    unsigned = dict(record)
    unsigned.pop("current_record_hash", None)
    return _sha256_text(_canonical_json(unsigned))


def _witness_trust_audit_hash(record: dict[str, Any]) -> str:
    unsigned = dict(record)
    unsigned.pop("current_record_hash", None)
    return _sha256_text(_canonical_json(unsigned))


def _witness_reputation_history_hash(record: dict[str, Any]) -> str:
    unsigned = dict(record)
    unsigned.pop("current_record_hash", None)
    return _sha256_text(_canonical_json(unsigned))


def _resolve_chronology_authorities(authorities: list[str] | tuple[str, ...] | None = None) -> list[str]:
    if authorities is not None:
        resolved = [str(authority).strip() for authority in authorities if str(authority).strip()]
    else:
        configured = os.getenv("USBAY_CHRONOLOGY_AUTHORITIES", "")
        resolved = [item.strip() for item in configured.split(",") if item.strip()] if configured else list(DEFAULT_CHRONOLOGY_AUTHORITIES)
    if not resolved:
        raise SystemExit("GOVERNANCE_CHRONOLOGY_AUTHORITIES_MISSING")
    if len(set(resolved)) != len(resolved):
        raise SystemExit("GOVERNANCE_CHRONOLOGY_AUTHORITY_DUPLICATE")
    return resolved


def _resolve_chronology_quorum(authorities: list[str], quorum: int | None = None) -> int:
    value = quorum if quorum is not None else int(os.getenv("USBAY_CHRONOLOGY_QUORUM") or DEFAULT_CHRONOLOGY_QUORUM)
    if value < 1 or value > len(authorities):
        raise SystemExit("GOVERNANCE_CHRONOLOGY_QUORUM_INVALID")
    return value


def _resolve_chronology_skew_seconds(max_skew_seconds: int | None = None) -> int:
    value = max_skew_seconds if max_skew_seconds is not None else int(os.getenv("USBAY_CHRONOLOGY_MAX_SKEW_SECONDS") or DEFAULT_CHRONOLOGY_MAX_SKEW_SECONDS)
    if value < 0:
        raise SystemExit("GOVERNANCE_CHRONOLOGY_SKEW_INVALID")
    return value


def _resolve_witness_ids(witness_ids: list[str] | tuple[str, ...] | None = None) -> list[str]:
    if witness_ids is not None:
        resolved = [str(witness).strip() for witness in witness_ids if str(witness).strip()]
    else:
        configured = os.getenv("USBAY_TRANSPARENCY_WITNESSES", "")
        resolved = [item.strip() for item in configured.split(",") if item.strip()] if configured else list(DEFAULT_WITNESS_IDS)
    if not resolved:
        raise SystemExit("GOVERNANCE_WITNESS_IDENTITIES_MISSING")
    if len(set(resolved)) != len(resolved):
        raise SystemExit("GOVERNANCE_WITNESS_IDENTITY_DUPLICATE")
    return resolved


def _resolve_witness_quorum(witness_ids: list[str], quorum: int | None = None) -> int:
    value = quorum if quorum is not None else int(os.getenv("USBAY_TRANSPARENCY_WITNESS_QUORUM") or DEFAULT_WITNESS_QUORUM)
    if value < 1 or value > len(witness_ids):
        raise SystemExit("GOVERNANCE_WITNESS_QUORUM_INVALID")
    return value


def _resolve_witness_freshness_seconds(freshness_seconds: int | None = None) -> int:
    value = freshness_seconds if freshness_seconds is not None else int(os.getenv("USBAY_TRANSPARENCY_WITNESS_FRESHNESS_SECONDS") or DEFAULT_WITNESS_FRESHNESS_SECONDS)
    if value < 0:
        raise SystemExit("GOVERNANCE_WITNESS_FRESHNESS_INVALID")
    return value


def _resolve_witness_trust_threshold(threshold: float | None = None) -> float:
    value = threshold if threshold is not None else float(os.getenv("USBAY_TRANSPARENCY_WITNESS_TRUST_THRESHOLD") or DEFAULT_WITNESS_TRUST_THRESHOLD)
    if value <= 0:
        raise SystemExit("GOVERNANCE_WITNESS_TRUST_THRESHOLD_INVALID")
    return value


def _resolve_witness_min_reputation(min_reputation: float | None = None) -> float:
    value = min_reputation if min_reputation is not None else float(os.getenv("USBAY_TRANSPARENCY_WITNESS_MIN_REPUTATION") or DEFAULT_WITNESS_MIN_REPUTATION)
    if value < 0 or value > 1:
        raise SystemExit("GOVERNANCE_WITNESS_MIN_REPUTATION_INVALID")
    return value


def _resolve_witness_conflict_tolerance(tolerance: int | None = None) -> int:
    value = tolerance if tolerance is not None else int(os.getenv("USBAY_TRANSPARENCY_WITNESS_CONFLICT_TOLERANCE") or DEFAULT_WITNESS_CONFLICT_TOLERANCE)
    if value < 0:
        raise SystemExit("GOVERNANCE_WITNESS_CONFLICT_TOLERANCE_INVALID")
    return value


def _default_witness_trust_policy(witness_ids: list[str]) -> dict[str, Any]:
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "schema": "usbay.witness_trust_policy.v1",
        "trust_threshold": DEFAULT_WITNESS_TRUST_THRESHOLD,
        "minimum_reputation": DEFAULT_WITNESS_MIN_REPUTATION,
        "conflict_tolerance": DEFAULT_WITNESS_CONFLICT_TOLERANCE,
        "invalid_attestation_quarantine_threshold": DEFAULT_WITNESS_INVALID_ATTESTATION_QUARANTINE_THRESHOLD,
        "inactivity_decay_after_seconds": DEFAULT_WITNESS_INACTIVITY_DECAY_AFTER_SECONDS,
        "reputation_decay_factor": DEFAULT_WITNESS_REPUTATION_DECAY_FACTOR,
        "witnesses": [
            {
                "witness_id": witness_id,
                "trust_weight": 1.0,
                "reputation_score": 1.0,
                "invalid_attestation_count": 0,
                "quarantined": False,
                "last_seen_at": timestamp,
                "recovery_requested": False,
                "probation_until": None,
            }
            for witness_id in witness_ids
        ],
    }


def _witness_policy_entries(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    witnesses = policy.get("witnesses")
    if not isinstance(witnesses, list):
        return {}
    return {str(entry.get("witness_id")): entry for entry in witnesses if isinstance(entry, dict) and entry.get("witness_id")}


class _NamedMockTSAClient(MockTSAClient):
    def __init__(self, tsa_name: str) -> None:
        self.tsa_name = tsa_name


def _parse_created_at(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _validate_trust_policy_audit(audit_path: Path, policy: dict[str, Any], signature_payload: dict[str, Any]) -> list[str]:
    if not audit_path.is_file():
        return [f"EVIDENCE_TRUST_POLICY_AUDIT_MISSING:{audit_path}"]
    failures: list[str] = []
    previous_hash = GENESIS_HASH
    previous_policy_version = "GENESIS"
    previous_policy_hash = GENESIS_HASH
    records: list[dict[str, Any]] = []
    for index, line in enumerate(audit_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except Exception:
            failures.append(f"EVIDENCE_TRUST_POLICY_AUDIT_INVALID_JSON:{index}")
            continue
        if not isinstance(record, dict):
            failures.append(f"EVIDENCE_TRUST_POLICY_AUDIT_RECORD_INVALID:{index}")
            continue
        records.append(record)
        if record.get("previous_record_hash") != previous_hash:
            failures.append(f"EVIDENCE_TRUST_POLICY_AUDIT_CHAIN_BREAK:{index}")
        if record.get("previous_policy_version") != previous_policy_version:
            failures.append(f"EVIDENCE_TRUST_POLICY_VERSION_CONTINUITY_BREAK:{index}")
        if record.get("previous_policy_hash") != previous_policy_hash:
            failures.append(f"EVIDENCE_TRUST_POLICY_HASH_CONTINUITY_BREAK:{index}")
        expected_hash = _trust_policy_audit_hash(record)
        if record.get("current_record_hash") != expected_hash:
            failures.append(f"EVIDENCE_TRUST_POLICY_AUDIT_HASH_INVALID:{index}")
        previous_hash = str(record.get("current_record_hash", ""))
        previous_policy_version = str(record.get("policy_version", ""))
        previous_policy_hash = str(record.get("policy_hash", ""))
    if not records:
        failures.append("EVIDENCE_TRUST_POLICY_AUDIT_EMPTY")
        return failures
    current = records[-1]
    policy_hash = _trust_policy_hash(policy)
    if current.get("policy_hash") != policy_hash:
        failures.append("EVIDENCE_TRUST_POLICY_AUDIT_POLICY_HASH_MISMATCH")
    if current.get("policy_version") != policy.get("policy_version"):
        failures.append("EVIDENCE_TRUST_POLICY_AUDIT_POLICY_VERSION_MISMATCH")
    if current.get("signature_hash") != _trust_policy_hash(signature_payload):
        failures.append("EVIDENCE_TRUST_POLICY_AUDIT_SIGNATURE_HASH_MISMATCH")
    return failures


def verify_trust_policy_governance(root: Path, trust_policy_path: Path | None = None) -> dict[str, Any]:
    root = root.resolve()
    policy_path = _resolve_trust_policy_path(root, trust_policy_path)
    signature_path, authority_path, audit_path = _trust_policy_governance_paths(root, policy_path)
    failures: list[str] = []
    if not policy_path.is_file():
        failures.append(f"EVIDENCE_TRUST_POLICY_MISSING:{policy_path}")
        return {"valid": False, "failures": failures}
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except Exception:
        failures.append("EVIDENCE_TRUST_POLICY_INVALID_JSON")
        return {"valid": False, "failures": failures}
    if not isinstance(policy, dict):
        failures.append("EVIDENCE_TRUST_POLICY_INVALID")
        return {"valid": False, "failures": failures}
    interface_state, interface_metric = measure_governance_validation(
        "trust_policy",
        "verify_trust_policy_governance",
        validate_trust_policy_interface,
        policy,
    )
    failures.extend(interface_state.failures)
    try:
        signature_payload = _load_json_file(signature_path, "EVIDENCE_TRUST_POLICY_SIGNATURE_MISSING")
        authority = _load_json_file(authority_path, "EVIDENCE_TRUST_POLICY_AUTHORITY_MISSING")
    except SystemExit as exc:
        failures.append(str(exc))
        return {"valid": False, "failures": failures}
    policy_hash = _trust_policy_hash(policy)
    if signature_payload.get("policy_hash") != policy_hash:
        failures.append("EVIDENCE_TRUST_POLICY_HASH_MISMATCH")
    signer_id = signature_payload.get("signer_id")
    signer_fingerprint = signature_payload.get("signer_key_id")
    signature = signature_payload.get("signature")
    allowed = authority.get("allowed_policy_signers")
    revoked = set(authority.get("revoked_policy_signer_fingerprints", []))
    if signer_fingerprint in revoked:
        failures.append("EVIDENCE_TRUST_POLICY_SIGNER_REVOKED")
    if not isinstance(allowed, list) or not allowed:
        failures.append("EVIDENCE_TRUST_POLICY_AUTHORITY_EMPTY")
    signer_entries = [
        entry
        for entry in allowed or []
        if isinstance(entry, dict)
        and entry.get("signer_id") == signer_id
        and entry.get("public_key_fingerprint") == signer_fingerprint
    ]
    if not signer_entries:
        failures.append("EVIDENCE_TRUST_POLICY_SIGNER_UNAUTHORIZED")
        public_key = ""
    else:
        public_key = str(signer_entries[0].get("public_key_pem", ""))
        try:
            public_key_fingerprint = signer_key_id(public_key)
        except SystemExit:
            public_key_fingerprint = ""
        if public_key_fingerprint != signer_fingerprint:
            failures.append("EVIDENCE_TRUST_POLICY_AUTHORITY_PUBLIC_KEY_MISMATCH")
    if signature_payload.get("algorithm") != TRUST_POLICY_SIGNATURE_ALGORITHM:
        failures.append("EVIDENCE_TRUST_POLICY_SIGNATURE_ALGORITHM_INVALID")
    if not isinstance(signature, str) or not signature.startswith(SIGNATURE_PREFIX):
        failures.append("EVIDENCE_TRUST_POLICY_SIGNATURE_INVALID")
    elif public_key:
        signature_b64 = signature[len(SIGNATURE_PREFIX) :]
        if not _ed25519_verify(_canonical_json(policy), signature_b64, public_key):
            failures.append("EVIDENCE_TRUST_POLICY_SIGNATURE_INVALID")
    failures.extend(_validate_trust_policy_audit(audit_path, policy, signature_payload))
    result = TrustPolicyValidationResult(
        valid=not failures,
        failures=tuple(sorted(set(failures))),
        policy_hash=policy_hash,
        policy_version=str(policy.get("policy_version")) if policy.get("policy_version") is not None else None,
        policy_signer_id=str(signer_id) if signer_id is not None else None,
        policy_signer_fingerprint=str(signer_fingerprint) if signer_fingerprint is not None else None,
    ).to_dict()
    result["telemetry"] = {
        "trust_policy_validation_duration_ns": interface_metric.validation_latency_ns,
        "artifact_counts": {"allowed_signers": interface_metric.artifact_count},
    }
    return result


def trusted_public_key_for_manifest(manifest: dict[str, Any], trust_policy: dict[str, Any]) -> tuple[str | None, list[str]]:
    signature = manifest.get("signature")
    if not isinstance(signature, dict):
        return None, ["EVIDENCE_SIGNATURE_MISSING"]
    signer_id = signature.get("signer_id")
    fingerprint = signature.get("public_key_fingerprint") or signature.get("signer_key_id")
    signed_at = signature.get("signed_at")
    if not isinstance(signer_id, str) or not signer_id:
        return None, ["EVIDENCE_SIGNER_ID_MISSING"]
    if not isinstance(fingerprint, str) or not fingerprint:
        return None, ["EVIDENCE_SIGNER_IDENTITY_MISSING"]
    if not isinstance(signed_at, str) or not signed_at:
        return None, ["EVIDENCE_SIGNATURE_TIMESTAMP_MISSING"]
    revoked = set(trust_policy.get("revoked_fingerprints", []))
    if fingerprint in revoked:
        return None, ["EVIDENCE_SIGNER_FINGERPRINT_REVOKED"]
    allowed_signers = trust_policy.get("allowed_signers")
    if not isinstance(allowed_signers, list) or not allowed_signers:
        return None, ["EVIDENCE_TRUST_POLICY_EMPTY"]
    matches = [
        entry
        for entry in allowed_signers
        if isinstance(entry, dict)
        and entry.get("signer_id") == signer_id
        and entry.get("public_key_fingerprint") == fingerprint
    ]
    if not matches:
        return None, ["EVIDENCE_SIGNER_NOT_TRUSTED"]
    entry = matches[0]
    public_key_pem = entry.get("public_key_pem")
    valid_from = entry.get("valid_from")
    valid_until = entry.get("valid_until")
    try:
        normalized_public_key = normalize_public_key_pem(str(public_key_pem))
        public_key_fingerprint = signer_key_id(normalized_public_key)
    except SystemExit:
        return None, ["EVIDENCE_TRUST_POLICY_PUBLIC_KEY_MISMATCH"]
    if not isinstance(public_key_pem, str) or public_key_fingerprint != fingerprint:
        return None, ["EVIDENCE_TRUST_POLICY_PUBLIC_KEY_MISMATCH"]
    try:
        signed_timestamp = _parse_timestamp(signed_at)
        from_timestamp = _parse_timestamp(str(valid_from))
        until_timestamp = _parse_timestamp(str(valid_until))
    except ValueError:
        return None, ["EVIDENCE_TRUST_POLICY_VALIDITY_INVALID"]
    if signed_timestamp < from_timestamp:
        return None, ["EVIDENCE_SIGNER_KEY_NOT_YET_VALID"]
    if signed_timestamp > until_timestamp:
        return None, ["EVIDENCE_SIGNER_KEY_EXPIRED"]
    return normalized_public_key, []


def trust_policy_fingerprint_for_signer(trust_policy: dict[str, Any], signer_id: str) -> str:
    allowed_signers = trust_policy.get("allowed_signers")
    if not isinstance(allowed_signers, list) or not allowed_signers:
        return ""
    signer_entries = [
        entry
        for entry in allowed_signers
        if isinstance(entry, dict)
        and entry.get("signer_id") == signer_id
    ]
    if not signer_entries:
        return ""
    return str(signer_entries[0].get("public_key_fingerprint", ""))


def validate_signing_key_trusted(
    public_key_pem: str,
    signer_id: str,
    trust_policy: dict[str, Any],
    emit_telemetry: bool = False,
) -> list[str]:
    try:
        normalized_public_key = normalize_public_key_pem(public_key_pem)
        fingerprint = signer_key_id(normalized_public_key)
        normalization_valid = True
    except SystemExit:
        fingerprint = ""
        normalization_valid = False
    trust_policy_fingerprint = trust_policy_fingerprint_for_signer(trust_policy, signer_id)
    if emit_telemetry:
        emit_trust_telemetry(signer_id, fingerprint, trust_policy_fingerprint, normalization_valid)
    if not normalization_valid:
        return ["EVIDENCE_PUBLIC_KEY_INVALID"]
    allowed_signers = trust_policy.get("allowed_signers")
    if not isinstance(allowed_signers, list) or not allowed_signers:
        return ["EVIDENCE_TRUST_POLICY_EMPTY"]
    signer_entries = [
        entry
        for entry in allowed_signers
        if isinstance(entry, dict)
        and entry.get("signer_id") == signer_id
    ]
    if not signer_entries:
        return ["EVIDENCE_SIGNER_NOT_TRUSTED"]
    matching_entries = [
        entry
        for entry in signer_entries
        if entry.get("public_key_fingerprint") == fingerprint
    ]
    if not matching_entries:
        return ["EVIDENCE_SIGNER_NOT_TRUSTED", "EVIDENCE_PUBLIC_KEY_FINGERPRINT_MISMATCH"]
    public_key_entry = matching_entries[0]
    try:
        trusted_public_key = normalize_public_key_pem(str(public_key_entry.get("public_key_pem", "")))
    except SystemExit:
        return ["EVIDENCE_TRUST_POLICY_PUBLIC_KEY_MISMATCH"]
    if trusted_public_key != normalized_public_key:
        return ["EVIDENCE_TRUST_POLICY_PUBLIC_KEY_MISMATCH"]
    if signer_key_id(trusted_public_key) != fingerprint:
        return ["EVIDENCE_TRUST_POLICY_PUBLIC_KEY_MISMATCH"]
    return []


def trusted_fingerprint_for_signer(trust_policy: dict[str, Any], signer_id: str, fingerprint: str) -> str:
    allowed_signers = trust_policy.get("allowed_signers")
    if not isinstance(allowed_signers, list):
        raise SystemExit("EVIDENCE_TRUST_POLICY_EMPTY")
    matches = [
        entry
        for entry in allowed_signers
        if isinstance(entry, dict)
        and entry.get("signer_id") == signer_id
        and entry.get("public_key_fingerprint") == fingerprint
    ]
    if not matches:
        raise SystemExit("EVIDENCE_SIGNER_NOT_TRUSTED")
    return str(matches[0].get("public_key_fingerprint", ""))


def emit_trust_telemetry(
    signer_id: str,
    normalized_fingerprint: str,
    trust_policy_fingerprint: str,
    normalization_valid: bool = True,
) -> None:
    lines = (
        f"CI_EVIDENCE_SIGNER_ID={signer_id}",
        f"CI_EVIDENCE_NORMALIZED_PUBLIC_KEY_SHA256={normalized_fingerprint}",
        f"CI_EVIDENCE_NORMALIZED_PUBLIC_KEY_SHA256_FINGERPRINT={normalized_fingerprint}",
        f"CI_EVIDENCE_TRUST_POLICY_FINGERPRINT={trust_policy_fingerprint}",
        f"CI_EVIDENCE_CANONICAL_DER_NORMALIZATION_VALID={str(normalization_valid).lower()}",
        f"CI_EVIDENCE_FINGERPRINT_MATCH={str(normalized_fingerprint == trust_policy_fingerprint).lower()}",
    )
    for line in lines:
        print(line, flush=True)
        print(line, file=sys.stderr, flush=True)


def print_fingerprint_audit(
    signer_id: str,
    normalized_fingerprint: str,
    trust_policy_fingerprint: str,
    normalization_valid: bool = True,
) -> None:
    emit_trust_telemetry(signer_id, normalized_fingerprint, trust_policy_fingerprint, normalization_valid)


def _ed25519_sign(payload: str, private_key_pem: str) -> str:
    with tempfile.TemporaryDirectory(prefix="usbay-ci-evidence-sign-") as tmp:
        tmp_path = Path(tmp)
        private_path = tmp_path / "private.pem"
        payload_path = tmp_path / "payload.json"
        signature_path = tmp_path / "signature.bin"
        private_path.write_text(private_key_pem, encoding="utf-8")
        private_path.chmod(0o600)
        payload_path.write_text(payload, encoding="utf-8")
        signed = _run_openssl(
            [
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_path),
                "-in",
                str(payload_path),
                "-out",
                str(signature_path),
            ]
        )
        if signed.returncode != 0:
            raise SystemExit("EVIDENCE_ED25519_SIGN_FAILED")
        return base64.b64encode(signature_path.read_bytes()).decode("ascii")


def _ed25519_verify(payload: str, signature_b64: str, public_key_pem: str) -> bool:
    try:
        signature_bytes = base64.b64decode(signature_b64, validate=True)
    except Exception:
        return False
    with tempfile.TemporaryDirectory(prefix="usbay-ci-evidence-verify-") as tmp:
        tmp_path = Path(tmp)
        public_path = tmp_path / "public.pem"
        payload_path = tmp_path / "payload.json"
        signature_path = tmp_path / "signature.bin"
        public_path.write_text(normalize_public_key_pem(public_key_pem), encoding="utf-8")
        payload_path.write_text(payload, encoding="utf-8")
        signature_path.write_bytes(signature_bytes)
        verified = _run_openssl(
            [
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(public_path),
                "-sigfile",
                str(signature_path),
                "-in",
                str(payload_path),
            ]
        )
        return verified.returncode == 0


def sign_manifest(
    manifest: dict[str, Any],
    private_key_pem: str,
    public_key_pem: str,
    signer_id: str | None = None,
    signed_at: str | None = None,
) -> dict[str, Any]:
    signed = dict(manifest)
    signing_timestamp = signed_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    normalized_public_key = normalize_public_key_pem(public_key_pem)
    fingerprint = signer_key_id(normalized_public_key)
    signed["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "signer_id": signer_id or _resolve_signer_id(),
        "signer_key_id": fingerprint,
        "public_key_fingerprint": fingerprint,
        "public_key_pem": normalized_public_key,
        "signed_at": signing_timestamp,
    }
    raw_signature = _ed25519_sign(_canonical_json(_signature_payload(signed)), private_key_pem)
    signed["signature"]["signature"] = f"{SIGNATURE_PREFIX}{raw_signature}"
    return signed


def verify_manifest_signature(manifest: dict[str, Any], public_key_pem: str, expected_signer_id: str | None = None) -> list[str]:
    signature = manifest.get("signature")
    if not isinstance(signature, dict):
        return ["EVIDENCE_SIGNATURE_MISSING"]
    signer_id = signature.get("signer_id")
    if expected_signer_id is not None and signer_id != expected_signer_id:
        return ["EVIDENCE_SIGNER_ID_MISMATCH"]
    failures: list[str] = []
    if signature.get("algorithm") != SIGNATURE_ALGORITHM:
        failures.append("EVIDENCE_SIGNATURE_ALGORITHM_INVALID")
    try:
        normalized_public_key = normalize_public_key_pem(public_key_pem)
        expected_fingerprint = signer_key_id(normalized_public_key)
    except SystemExit:
        failures.append("EVIDENCE_PUBLIC_KEY_INVALID")
        return failures
    if signature.get("public_key_pem") != normalized_public_key:
        failures.append("EVIDENCE_PUBLIC_KEY_MISMATCH")
    if signature.get("signer_key_id") != expected_fingerprint:
        failures.append("EVIDENCE_SIGNER_IDENTITY_MISMATCH")
    if signature.get("public_key_fingerprint") != expected_fingerprint:
        failures.append("EVIDENCE_PUBLIC_KEY_FINGERPRINT_MISMATCH")
    raw_signature = signature.get("signature")
    if not isinstance(raw_signature, str) or not raw_signature.startswith(SIGNATURE_PREFIX):
        failures.append("EVIDENCE_SIGNATURE_INVALID")
    if not signature.get("signed_at"):
        failures.append("EVIDENCE_SIGNATURE_TIMESTAMP_MISSING")
    if failures:
        return failures
    unsigned = _signature_payload(manifest)
    signature_b64 = str(raw_signature)[len(SIGNATURE_PREFIX) :]
    if not _ed25519_verify(_canonical_json(unsigned), signature_b64, public_key_pem):
        failures.append("EVIDENCE_SIGNATURE_INVALID")
    return failures


def _evidence_type(path: str) -> str:
    if path.endswith("production-readiness-ci-sbom.json"):
        return "sbom_artifact"
    if path.endswith(".yml") or path.endswith(".yaml"):
        return "workflow_definition"
    if path.endswith("requirements-ci.txt"):
        return "dependency_lock"
    if path.endswith("-output.txt"):
        return "workflow_output"
    if path.endswith(".py"):
        return "governance_script"
    return "governance_evidence"


def build_manifest(root: Path, evidence_paths: list[str], generated_at: str | None = None) -> dict[str, Any]:
    root = root.resolve()
    timestamp = generated_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    previous_hash = GENESIS_HASH
    records: list[dict[str, Any]] = []
    for index, evidence_path in enumerate(evidence_paths):
        normalized = evidence_path.strip()
        if not normalized:
            raise SystemExit("EVIDENCE_PATH_EMPTY")
        absolute = root / normalized
        if not absolute.is_file():
            raise SystemExit(f"EVIDENCE_FILE_MISSING:{normalized}")
        record = {
            "record_id": f"ci-evidence-{index + 1:04d}",
            "evidence_path": normalized,
            "evidence_type": _evidence_type(normalized),
            "evidence_sha256": _sha256_file(absolute),
            "previous_record_hash": previous_hash,
            "timestamp": timestamp,
        }
        record["current_record_hash"] = _record_hash(record)
        previous_hash = str(record["current_record_hash"])
        records.append(record)
    if not records:
        raise SystemExit("EVIDENCE_CHAIN_EMPTY")
    return {
        "evidence_schema": EVIDENCE_SCHEMA,
        "workflow_version": WORKFLOW_VERSION,
        "generated_at": timestamp,
        "chain_head": previous_hash,
        "records": records,
    }


def validate_manifest(
    root: Path,
    manifest: dict[str, Any],
    public_key_pem: str | None = None,
    expected_signer_id: str | None = None,
    trust_policy: dict[str, Any] | None = None,
) -> list[str]:
    failures: list[str] = []
    interface_state, _interface_metric = measure_governance_validation(
        "evidence",
        "validate_manifest",
        validate_evidence_manifest_interface,
        manifest,
    )
    failures.extend(interface_state.failures)
    if manifest.get("evidence_schema") != EVIDENCE_SCHEMA:
        failures.append("EVIDENCE_SCHEMA_INVALID")
    records = manifest.get("records")
    if not isinstance(records, list) or not records:
        failures.append("EVIDENCE_CHAIN_EMPTY")
        return failures
    previous_hash = GENESIS_HASH
    seen_paths: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            failures.append(f"EVIDENCE_RECORD_INVALID:{index}")
            continue
        path = record.get("evidence_path")
        if not isinstance(path, str) or not path:
            failures.append(f"EVIDENCE_RECORD_PATH_INVALID:{index}")
            continue
        if path in seen_paths:
            failures.append(f"EVIDENCE_RECORD_DUPLICATE:{path}")
        seen_paths.add(path)
        absolute = root / path
        if not absolute.is_file():
            failures.append(f"EVIDENCE_FILE_MISSING:{path}")
            continue
        if record.get("previous_record_hash") != previous_hash:
            failures.append(f"EVIDENCE_CHAIN_PREVIOUS_HASH_MISMATCH:{path}")
        expected_file_hash = _sha256_file(absolute)
        if record.get("evidence_sha256") != expected_file_hash:
            failures.append(f"EVIDENCE_HASH_MISMATCH:{path}")
        expected_record_hash = _record_hash(record)
        if record.get("current_record_hash") != expected_record_hash:
            failures.append(f"EVIDENCE_RECORD_HASH_MISMATCH:{path}")
        if not record.get("timestamp"):
            failures.append(f"EVIDENCE_TIMESTAMP_MISSING:{path}")
        previous_hash = str(record.get("current_record_hash", ""))
    if manifest.get("chain_head") != previous_hash:
        failures.append("EVIDENCE_CHAIN_HEAD_MISMATCH")
    trusted_key = public_key_pem
    if trust_policy is not None:
        trusted_key, trust_failures = trusted_public_key_for_manifest(manifest, trust_policy)
        failures.extend(trust_failures)
    if trusted_key is None:
        failures.append("EVIDENCE_PUBLIC_KEY_MISSING")
    else:
        failures.extend(verify_manifest_signature(manifest, trusted_key, expected_signer_id=expected_signer_id))
    return sorted(set(failures))


def write_manifest(
    root: Path,
    output: Path,
    evidence_paths: list[str],
    allow_test_key: bool = False,
    trust_policy_path: Path | None = None,
) -> None:
    if allow_test_key and not os.getenv(PRIVATE_KEY_ENV) and not os.getenv(PUBLIC_KEY_ENV):
        private_key, public_key = generate_ed25519_keypair()
    else:
        private_key = _resolve_private_key(allow_test_key=allow_test_key)
        public_key = _resolve_public_key(allow_test_key=allow_test_key)
    signer_id = _resolve_signer_id()
    trust_policy_state = verify_trust_policy_governance(root.resolve(), trust_policy_path)
    if trust_policy_state["valid"] is not True:
        raise SystemExit("EVIDENCE_TRUST_POLICY_GOVERNANCE_INVALID:" + ",".join(trust_policy_state["failures"]))
    trust_policy = load_trust_policy(root.resolve(), trust_policy_path)
    trust_failures = validate_signing_key_trusted(public_key, signer_id, trust_policy, emit_telemetry=True)
    if trust_failures:
        raise SystemExit("EVIDENCE_MANIFEST_INVALID:" + ",".join(sorted(set(trust_failures))))
    manifest = build_manifest(root, evidence_paths)
    manifest = sign_manifest(manifest, private_key, public_key, signer_id=signer_id)
    failures = validate_manifest(root.resolve(), manifest, expected_signer_id=signer_id, trust_policy=trust_policy)
    if failures:
        raise SystemExit("EVIDENCE_MANIFEST_INVALID:" + ",".join(failures))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"CI_EVIDENCE_MANIFEST_GENERATED={output}")
    print(f"CI_EVIDENCE_RECORDS={len(manifest['records'])}")
    print(f"CI_EVIDENCE_CHAIN_HEAD={manifest['chain_head']}")
    print(f"CI_EVIDENCE_SIGNATURE_VERIFIED=true")
    print(f"CI_EVIDENCE_VERIFICATION_METHOD={SIGNATURE_ALGORITHM}")
    normalized_fingerprint = signer_key_id(public_key)
    trusted_fingerprint = trusted_fingerprint_for_signer(trust_policy, signer_id, normalized_fingerprint)
    print_fingerprint_audit(signer_id, normalized_fingerprint, trusted_fingerprint)
    print(f"CI_EVIDENCE_TRUST_POLICY_VALID=true")
    print(f"CI_EVIDENCE_TRUST_POLICY_VERSION={trust_policy_state.get('policy_version')}")
    print(f"CI_EVIDENCE_TRUST_POLICY_HASH={trust_policy_state.get('policy_hash')}")
    print(
        "CI_EVIDENCE_TRUST_POLICY_VALIDATION_DURATION_NS="
        + str(trust_policy_state.get("telemetry", {}).get("trust_policy_validation_duration_ns", 0))
    )


def verify_manifest(root: Path, manifest_path: Path, allow_test_key: bool = False, trust_policy_path: Path | None = None) -> None:
    if not manifest_path.is_file():
        raise SystemExit(f"EVIDENCE_MANIFEST_MISSING:{manifest_path}")
    signer_id = _resolve_signer_id()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    trust_policy_state = verify_trust_policy_governance(root.resolve(), trust_policy_path)
    if trust_policy_state["valid"] is not True:
        raise SystemExit("EVIDENCE_TRUST_POLICY_GOVERNANCE_INVALID:" + ",".join(trust_policy_state["failures"]))
    trust_policy = load_trust_policy(root.resolve(), trust_policy_path)
    failures = validate_manifest(root.resolve(), manifest, expected_signer_id=signer_id, trust_policy=trust_policy)
    if failures:
        raise SystemExit("EVIDENCE_MANIFEST_INVALID:" + ",".join(failures))
    print(f"CI_EVIDENCE_MANIFEST_VALID={manifest_path}")
    print(f"CI_EVIDENCE_RECORDS={len(manifest['records'])}")
    print(f"CI_EVIDENCE_SIGNATURE_VERIFIED=true")
    print(f"CI_EVIDENCE_VERIFICATION_METHOD={SIGNATURE_ALGORITHM}")
    signature = manifest.get("signature", {})
    if isinstance(signature, dict):
        normalized_fingerprint = signer_key_id(str(signature.get("public_key_pem", "")))
        trusted_fingerprint = trusted_fingerprint_for_signer(trust_policy, signer_id, normalized_fingerprint)
        print_fingerprint_audit(signer_id, normalized_fingerprint, trusted_fingerprint)
    print(f"CI_EVIDENCE_TRUST_POLICY_VALID=true")
    print(f"CI_EVIDENCE_TRUST_POLICY_VERSION={trust_policy_state.get('policy_version')}")
    print(f"CI_EVIDENCE_TRUST_POLICY_HASH={trust_policy_state.get('policy_hash')}")
    print(
        "CI_EVIDENCE_TRUST_POLICY_VALIDATION_DURATION_NS="
        + str(trust_policy_state.get("telemetry", {}).get("trust_policy_validation_duration_ns", 0))
    )


def _timestamp_targets(root: Path, manifest_path: Path, trust_policy_path: Path) -> list[dict[str, str]]:
    root = root.resolve()
    signature_path, authority_path, audit_path = _trust_policy_governance_paths(root, trust_policy_path)
    targets = [
        ("trust_policy", trust_policy_path),
        ("trust_policy_signature", signature_path),
        ("trust_policy_authority", authority_path),
        ("trust_policy_audit_chain", audit_path),
        ("evidence_manifest", manifest_path),
    ]
    normalized: list[dict[str, str]] = []
    for name, path in targets:
        if not path.is_file():
            raise SystemExit(f"GOVERNANCE_TIMESTAMP_TARGET_MISSING:{path}")
        try:
            relative = str(path.resolve().relative_to(root))
        except ValueError:
            relative = str(path.resolve())
        normalized.append(
            {
                "target_name": name,
                "target_path": relative,
                "target_sha256": _sha256_file(path),
            }
        )
    return normalized


def _write_transparency_log(output_dir: Path, proofs: list[dict[str, Any]], targets: list[dict[str, str]]) -> None:
    if len(proofs) != len(targets):
        raise SystemExit("GOVERNANCE_TRANSPARENCY_RECORD_COUNT_MISMATCH")
    previous_hash = GENESIS_HASH
    lines: list[str] = []
    for index, (proof, target) in enumerate(zip(proofs, targets), start=1):
        record = {
            "record_id": f"governance-transparency-{index:04d}",
            "target_name": target["target_name"],
            "target_path": target["target_path"],
            "target_sha256": target["target_sha256"],
            "timestamp_hash": proof["timestamp_hash"],
            "timestamp_created_at": proof["created_at"],
            "previous_record_hash": previous_hash,
        }
        record["current_record_hash"] = _transparency_record_hash(record)
        previous_hash = str(record["current_record_hash"])
        lines.append(_canonical_json(record))
    (output_dir / TRANSPARENCY_LOG_FILE).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _consensus_audit_from_consensus(consensus: dict[str, Any]) -> list[dict[str, Any]]:
    targets = consensus.get("targets")
    if not isinstance(targets, list) or not targets:
        raise SystemExit("GOVERNANCE_CHRONOLOGY_CONSENSUS_EMPTY")
    previous_hash = GENESIS_HASH
    records: list[dict[str, Any]] = []
    for index, target_consensus in enumerate(targets, start=1):
        if not isinstance(target_consensus, dict):
            raise SystemExit(f"GOVERNANCE_CHRONOLOGY_CONSENSUS_TARGET_INVALID:{index}")
        target = target_consensus.get("target")
        if not isinstance(target, dict):
            raise SystemExit(f"GOVERNANCE_CHRONOLOGY_CONSENSUS_TARGET_INVALID:{index}")
        authority_results = target_consensus.get("authority_results")
        if not isinstance(authority_results, list):
            raise SystemExit(f"GOVERNANCE_CHRONOLOGY_CONSENSUS_AUTHORITIES_INVALID:{target.get('target_name', index)}")
        record = {
            "record_id": f"governance-chronology-consensus-{index:04d}",
            "target_name": target.get("target_name"),
            "target_path": target.get("target_path"),
            "target_sha256": target.get("target_sha256"),
            "consensus_result": target_consensus.get("consensus_result"),
            "quorum_required": consensus.get("quorum_required"),
            "valid_authority_count": target_consensus.get("valid_authority_count"),
            "authority_ids": sorted(str(item.get("authority_id", "")) for item in authority_results),
            "authority_timestamp_hashes": sorted(str(item.get("timestamp_hash", "")) for item in authority_results),
            "previous_consensus_hash": target_consensus.get("previous_consensus_hash"),
            "timestamp_window": target_consensus.get("timestamp_window"),
            "previous_record_hash": previous_hash,
        }
        record["current_record_hash"] = _consensus_record_hash(record)
        previous_hash = str(record["current_record_hash"])
        records.append(record)
    return records


def _write_consensus_audit(output_dir: Path, consensus: dict[str, Any]) -> None:
    records = _consensus_audit_from_consensus(consensus)
    (output_dir / CHRONOLOGY_CONSENSUS_AUDIT_FILE).write_text(
        "\n".join(_canonical_json(record) for record in records) + "\n",
        encoding="utf-8",
    )


def _load_consensus_audit(output_dir: Path) -> list[dict[str, Any]]:
    path = output_dir / CHRONOLOGY_CONSENSUS_AUDIT_FILE
    if not path.is_file():
        raise SystemExit(f"GOVERNANCE_CHRONOLOGY_CONSENSUS_AUDIT_MISSING:{path}")
    records: list[dict[str, Any]] = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except Exception as exc:
            raise SystemExit(f"GOVERNANCE_CHRONOLOGY_CONSENSUS_AUDIT_INVALID_JSON:{index}") from exc
        if not isinstance(record, dict):
            raise SystemExit(f"GOVERNANCE_CHRONOLOGY_CONSENSUS_AUDIT_RECORD_INVALID:{index}")
        records.append(record)
    if not records:
        raise SystemExit("GOVERNANCE_CHRONOLOGY_CONSENSUS_AUDIT_EMPTY")
    return records


def build_chronology_consensus(
    targets: list[dict[str, str]],
    *,
    authorities: list[str] | tuple[str, ...] | None = None,
    quorum: int | None = None,
    max_skew_seconds: int | None = None,
) -> dict[str, Any]:
    authority_ids = _resolve_chronology_authorities(authorities)
    quorum_required = _resolve_chronology_quorum(authority_ids, quorum)
    skew_seconds = _resolve_chronology_skew_seconds(max_skew_seconds)
    previous_consensus_hash = GENESIS_HASH
    authority_previous_hashes = {authority_id: None for authority_id in authority_ids}
    consensus_targets: list[dict[str, Any]] = []
    for target in targets:
        message_hash = sha256_text(_canonical_json(target))
        authority_results: list[dict[str, Any]] = []
        valid_created_at: list[datetime] = []
        for authority_id in authority_ids:
            proof = create_timestamp_proof(
                message_hash,
                previous_timestamp_hash=authority_previous_hashes[authority_id],
                tsa_client=_NamedMockTSAClient(authority_id),
            )
            verification = verify_timestamp_proof(
                proof,
                message_hash,
                previous_timestamp_hash=authority_previous_hashes[authority_id],
            )
            result = {
                "authority_id": authority_id,
                "proof": proof,
                "verification": verification,
                "timestamp_hash": verification.get("timestamp_hash") or proof.get("timestamp_hash"),
            }
            if verification.get("valid") is True:
                authority_previous_hashes[authority_id] = str(verification["timestamp_hash"])
                valid_created_at.append(_parse_created_at(str(proof["created_at"])))
            authority_results.append(result)
        valid_count = sum(1 for result in authority_results if result["verification"].get("valid") is True)
        timestamp_window = {
            "earliest": min(valid_created_at).isoformat().replace("+00:00", "Z") if valid_created_at else None,
            "latest": max(valid_created_at).isoformat().replace("+00:00", "Z") if valid_created_at else None,
            "max_skew_seconds": skew_seconds,
        }
        record_payload = {
            "target": target,
            "message_imprint": message_hash,
            "authority_ids": authority_ids,
            "authority_timestamp_hashes": [str(result["timestamp_hash"]) for result in authority_results],
            "quorum_required": quorum_required,
            "valid_authority_count": valid_count,
            "previous_consensus_hash": previous_consensus_hash,
            "timestamp_window": timestamp_window,
        }
        consensus_hash = _sha256_text(_canonical_json(record_payload))
        target_consensus = {
            **record_payload,
            "consensus_result": "ALLOW" if valid_count >= quorum_required else "DENY",
            "consensus_hash": consensus_hash,
            "authority_results": authority_results,
        }
        previous_consensus_hash = consensus_hash
        consensus_targets.append(target_consensus)
    return {
        "schema": "usbay.governance_chronology_consensus.v1",
        "authority_ids": authority_ids,
        "quorum_required": quorum_required,
        "max_authority_skew_seconds": skew_seconds,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "targets": consensus_targets,
        "chain_head": previous_consensus_hash,
    }


def _write_chronology_consensus(output_dir: Path, consensus: dict[str, Any]) -> None:
    (output_dir / CHRONOLOGY_CONSENSUS_FILE).write_text(json.dumps(consensus, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_consensus_audit(output_dir, consensus)


def _load_chronology_consensus(output_dir: Path) -> dict[str, Any]:
    path = output_dir / CHRONOLOGY_CONSENSUS_FILE
    if not path.is_file():
        raise SystemExit(f"GOVERNANCE_CHRONOLOGY_CONSENSUS_MISSING:{path}")
    try:
        consensus = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit("GOVERNANCE_CHRONOLOGY_CONSENSUS_INVALID_JSON") from exc
    if not isinstance(consensus, dict):
        raise SystemExit("GOVERNANCE_CHRONOLOGY_CONSENSUS_INVALID")
    return consensus


def verify_chronology_consensus(
    targets: list[dict[str, str]],
    output_dir: Path,
    *,
    authorities: list[str] | tuple[str, ...] | None = None,
    quorum: int | None = None,
    max_skew_seconds: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    failures: list[str] = []
    try:
        consensus = _load_chronology_consensus(output_dir)
        audit_records = _load_consensus_audit(output_dir)
        expected_authorities = _resolve_chronology_authorities(authorities)
        quorum_required = _resolve_chronology_quorum(expected_authorities, quorum)
        skew_seconds = _resolve_chronology_skew_seconds(max_skew_seconds)
    except SystemExit as exc:
        return {"valid": False, "failures": [str(exc)], "consensus_targets": []}
    interface_state, chronology_metric = measure_governance_validation(
        "chronology",
        "verify_chronology_consensus",
        validate_chronology_consensus_interface,
        consensus,
    )
    failures.extend(interface_state.failures)
    if consensus.get("schema") != "usbay.governance_chronology_consensus.v1":
        failures.append("GOVERNANCE_CHRONOLOGY_CONSENSUS_SCHEMA_INVALID")
    authority_ids = consensus.get("authority_ids")
    if authority_ids != expected_authorities:
        failures.append("GOVERNANCE_CHRONOLOGY_AUTHORITY_SET_MISMATCH")
    if consensus.get("quorum_required") != quorum_required:
        failures.append("GOVERNANCE_CHRONOLOGY_QUORUM_MISMATCH")
    if consensus.get("max_authority_skew_seconds") != skew_seconds:
        failures.append("GOVERNANCE_CHRONOLOGY_SKEW_POLICY_MISMATCH")
    consensus_targets = consensus.get("targets")
    if not isinstance(consensus_targets, list) or not consensus_targets:
        failures.append("GOVERNANCE_CHRONOLOGY_CONSENSUS_EMPTY")
        consensus_targets = []
    if len(consensus_targets) != len(targets):
        failures.append("GOVERNANCE_CHRONOLOGY_TARGET_COUNT_MISMATCH")
    if len(audit_records) != len(consensus_targets):
        failures.append("GOVERNANCE_CHRONOLOGY_AUDIT_COUNT_MISMATCH")
    previous_consensus_hash = GENESIS_HASH
    authority_previous_hashes = {authority_id: None for authority_id in expected_authorities}
    seen_tokens: set[str] = set()
    previous_audit_hash = GENESIS_HASH
    verification_results: list[dict[str, Any]] = []
    for index, target in enumerate(targets):
        if index >= len(consensus_targets):
            break
        target_consensus = consensus_targets[index]
        if not isinstance(target_consensus, dict):
            failures.append(f"GOVERNANCE_CHRONOLOGY_TARGET_INVALID:{index}")
            continue
        if target_consensus.get("target") != target:
            failures.append(f"GOVERNANCE_CHRONOLOGY_TARGET_MISMATCH:{target.get('target_name')}")
        message_hash = sha256_text(_canonical_json(target))
        if target_consensus.get("message_imprint") != message_hash:
            failures.append(f"GOVERNANCE_CHRONOLOGY_MESSAGE_IMPRINT_MISMATCH:{target.get('target_name')}")
        if target_consensus.get("previous_consensus_hash") != previous_consensus_hash:
            failures.append(f"GOVERNANCE_CHRONOLOGY_CONTINUITY_BREAK:{target.get('target_name')}")
        authority_results = target_consensus.get("authority_results")
        if not isinstance(authority_results, list):
            failures.append(f"GOVERNANCE_CHRONOLOGY_AUTHORITY_RESULTS_MISSING:{target.get('target_name')}")
            authority_results = []
        present_authorities = [str(result.get("authority_id", "")) for result in authority_results if isinstance(result, dict)]
        if set(present_authorities) != set(expected_authorities):
            failures.append(f"GOVERNANCE_CHRONOLOGY_AUTHORITY_MEMBER_MISSING:{target.get('target_name')}")
        if len(present_authorities) != len(set(present_authorities)):
            failures.append(f"GOVERNANCE_CHRONOLOGY_AUTHORITY_DUPLICATE:{target.get('target_name')}")
        valid_count = 0
        valid_created_at: list[datetime] = []
        authority_timestamp_hashes: list[str] = []
        for result in authority_results:
            if not isinstance(result, dict):
                failures.append(f"GOVERNANCE_CHRONOLOGY_AUTHORITY_RESULT_INVALID:{target.get('target_name')}")
                continue
            authority_id = str(result.get("authority_id", ""))
            proof = result.get("proof")
            if authority_id not in authority_previous_hashes:
                failures.append(f"GOVERNANCE_CHRONOLOGY_AUTHORITY_UNEXPECTED:{target.get('target_name')}:{authority_id}")
                continue
            verification = verify_timestamp_proof(
                proof if isinstance(proof, dict) else {},
                message_hash,
                previous_timestamp_hash=authority_previous_hashes[authority_id],
                seen_token_hashes=seen_tokens,
                now=now,
            )
            token_hash = sha256_text(str(proof.get("token", ""))) if isinstance(proof, dict) else ""
            if token_hash:
                seen_tokens.add(token_hash)
            verification_results.append({"target": target, "authority_id": authority_id, "verification": verification})
            if verification.get("valid") is not True:
                failures.extend(
                    f"GOVERNANCE_CHRONOLOGY_AUTHORITY_INVALID:{target.get('target_name')}:{authority_id}:{error}"
                    for error in verification.get("errors", [])
                )
                continue
            if result.get("timestamp_hash") != verification.get("timestamp_hash"):
                failures.append(f"GOVERNANCE_CHRONOLOGY_AUTHORITY_HASH_MISMATCH:{target.get('target_name')}:{authority_id}")
            authority_previous_hashes[authority_id] = str(verification["timestamp_hash"])
            authority_timestamp_hashes.append(str(verification["timestamp_hash"]))
            valid_created_at.append(_parse_created_at(str(verification["created_at"])))
            valid_count += 1
        if valid_count < quorum_required:
            failures.append(f"GOVERNANCE_CHRONOLOGY_QUORUM_NOT_REACHED:{target.get('target_name')}")
        if valid_created_at and (max(valid_created_at) - min(valid_created_at)).total_seconds() > skew_seconds:
            failures.append(f"GOVERNANCE_CHRONOLOGY_DIVERGENCE:{target.get('target_name')}")
        expected_payload = {
            "target": target,
            "message_imprint": message_hash,
            "authority_ids": expected_authorities,
            "authority_timestamp_hashes": [str(result.get("timestamp_hash", "")) for result in authority_results if isinstance(result, dict)],
            "quorum_required": quorum_required,
            "valid_authority_count": target_consensus.get("valid_authority_count"),
            "previous_consensus_hash": target_consensus.get("previous_consensus_hash"),
            "timestamp_window": target_consensus.get("timestamp_window"),
        }
        expected_consensus_hash = _sha256_text(_canonical_json(expected_payload))
        if target_consensus.get("consensus_hash") != expected_consensus_hash:
            failures.append(f"GOVERNANCE_CHRONOLOGY_CONSENSUS_HASH_MISMATCH:{target.get('target_name')}")
        if target_consensus.get("valid_authority_count") != valid_count:
            failures.append(f"GOVERNANCE_CHRONOLOGY_VALID_COUNT_MISMATCH:{target.get('target_name')}")
        if valid_count >= quorum_required and target_consensus.get("consensus_result") != "ALLOW":
            failures.append(f"GOVERNANCE_CHRONOLOGY_CONSENSUS_RESULT_MISMATCH:{target.get('target_name')}")
        if valid_count < quorum_required and target_consensus.get("consensus_result") != "DENY":
            failures.append(f"GOVERNANCE_CHRONOLOGY_CONSENSUS_RESULT_MISMATCH:{target.get('target_name')}")
        if index < len(audit_records):
            record = audit_records[index]
            if record.get("previous_record_hash") != previous_audit_hash:
                failures.append(f"GOVERNANCE_CHRONOLOGY_AUDIT_CHAIN_BREAK:{target.get('target_name')}")
            expected_audit = {
                "record_id": f"governance-chronology-consensus-{index + 1:04d}",
                "target_name": target.get("target_name"),
                "target_path": target.get("target_path"),
                "target_sha256": target.get("target_sha256"),
                "consensus_result": target_consensus.get("consensus_result"),
                "quorum_required": quorum_required,
                "valid_authority_count": target_consensus.get("valid_authority_count"),
                "authority_ids": sorted(str(item.get("authority_id", "")) for item in authority_results if isinstance(item, dict)),
                "authority_timestamp_hashes": sorted(str(item.get("timestamp_hash", "")) for item in authority_results if isinstance(item, dict)),
                "previous_consensus_hash": target_consensus.get("previous_consensus_hash"),
                "timestamp_window": target_consensus.get("timestamp_window"),
                "previous_record_hash": previous_audit_hash,
            }
            expected_audit["current_record_hash"] = _consensus_record_hash(expected_audit)
            if record != expected_audit:
                failures.append(f"GOVERNANCE_CHRONOLOGY_AUDIT_MISMATCH:{target.get('target_name')}")
            previous_audit_hash = str(record.get("current_record_hash", ""))
        previous_consensus_hash = str(target_consensus.get("consensus_hash", ""))
    if consensus.get("chain_head") != previous_consensus_hash:
        failures.append("GOVERNANCE_CHRONOLOGY_CHAIN_HEAD_MISMATCH")
    return {
        "valid": not failures,
        "failures": sorted(set(failures)),
        "consensus_targets": consensus_targets,
        "timestamp_verifications": verification_results,
        "quorum_required": quorum_required,
        "authority_ids": expected_authorities,
        "telemetry": {
            "chronology_verification_duration_ns": chronology_metric.validation_latency_ns,
            "artifact_counts": {"chronology_targets": chronology_metric.artifact_count},
        },
    }


def _transparency_anchor_targets(root: Path, output_dir: Path, manifest_path: Path, trust_policy_path: Path) -> list[dict[str, Any]]:
    trust_policy = _load_json_file(trust_policy_path, "GOVERNANCE_TRANSPARENCY_TRUST_POLICY_MISSING")
    evidence_manifest = _load_json_file(manifest_path, "GOVERNANCE_TRANSPARENCY_EVIDENCE_MANIFEST_MISSING")
    targets = [
        {
            "anchor_type": "chronology_consensus",
            "path": CHRONOLOGY_CONSENSUS_FILE,
            "absolute_path": output_dir / CHRONOLOGY_CONSENSUS_FILE,
        },
        {
            "anchor_type": "chronology_consensus_audit",
            "path": CHRONOLOGY_CONSENSUS_AUDIT_FILE,
            "absolute_path": output_dir / CHRONOLOGY_CONSENSUS_AUDIT_FILE,
        },
        {
            "anchor_type": "trust_policy_version",
            "path": str(trust_policy_path.resolve().relative_to(root)),
            "absolute_path": trust_policy_path,
            "policy_version": trust_policy.get("policy_version"),
            "policy_hash": _trust_policy_hash(trust_policy),
        },
        {
            "anchor_type": "evidence_manifest",
            "path": str(manifest_path.resolve().relative_to(root)),
            "absolute_path": manifest_path,
            "chain_head": evidence_manifest.get("chain_head"),
        },
    ]
    records: list[dict[str, Any]] = []
    previous_hash = GENESIS_HASH
    for index, target in enumerate(targets, start=1):
        absolute_path = Path(target["absolute_path"])
        if not absolute_path.is_file():
            raise SystemExit(f"GOVERNANCE_TRANSPARENCY_ANCHOR_TARGET_MISSING:{absolute_path}")
        record = {
            "anchor_id": f"governance-transparency-anchor-{index:04d}",
            "anchor_type": target["anchor_type"],
            "target_path": target["path"],
            "target_sha256": _sha256_file(absolute_path),
            "previous_anchor_hash": previous_hash,
        }
        for key in ("policy_version", "policy_hash", "chain_head"):
            if key in target:
                record[key] = target[key]
        record["current_anchor_hash"] = _anchor_record_hash(record)
        previous_hash = str(record["current_anchor_hash"])
        records.append(record)
    return records


def _write_transparency_anchor(root: Path, output_dir: Path, manifest_path: Path, trust_policy_path: Path) -> dict[str, Any]:
    records = _transparency_anchor_targets(root, output_dir, manifest_path, trust_policy_path)
    anchor = {
        "schema": "usbay.immutable_transparency_anchor.v1",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "records": records,
        "chain_head": records[-1]["current_anchor_hash"],
    }
    (output_dir / TRANSPARENCY_ANCHOR_FILE).write_text(json.dumps(anchor, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return anchor


def _load_transparency_anchor(output_dir: Path) -> dict[str, Any]:
    return _load_json_file(output_dir / TRANSPARENCY_ANCHOR_FILE, "GOVERNANCE_TRANSPARENCY_ANCHOR_MISSING")


def verify_transparency_anchor(root: Path, output_dir: Path, manifest_path: Path, trust_policy_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    try:
        anchor = _load_transparency_anchor(output_dir)
        expected_records = _transparency_anchor_targets(root, output_dir, manifest_path, trust_policy_path)
    except SystemExit as exc:
        return {"valid": False, "failures": [str(exc)]}
    if anchor.get("schema") != "usbay.immutable_transparency_anchor.v1":
        failures.append("GOVERNANCE_TRANSPARENCY_ANCHOR_SCHEMA_INVALID")
    records = anchor.get("records")
    if not isinstance(records, list) or not records:
        failures.append("GOVERNANCE_TRANSPARENCY_ANCHOR_EMPTY")
        records = []
    if records != expected_records:
        failures.append("GOVERNANCE_TRANSPARENCY_ANCHOR_MISMATCH")
    previous_hash = GENESIS_HASH
    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            failures.append(f"GOVERNANCE_TRANSPARENCY_ANCHOR_RECORD_INVALID:{index}")
            continue
        if record.get("previous_anchor_hash") != previous_hash:
            failures.append(f"GOVERNANCE_TRANSPARENCY_ANCHOR_CHAIN_BREAK:{index}")
        expected_hash = _anchor_record_hash(record)
        if record.get("current_anchor_hash") != expected_hash:
            failures.append(f"GOVERNANCE_TRANSPARENCY_ANCHOR_HASH_INVALID:{index}")
        previous_hash = str(record.get("current_anchor_hash", ""))
    if anchor.get("chain_head") != previous_hash:
        failures.append("GOVERNANCE_TRANSPARENCY_ANCHOR_CHAIN_HEAD_MISMATCH")
    return {"valid": not failures, "failures": sorted(set(failures)), "anchor": anchor}


def _witness_signature_payload(proof: dict[str, Any]) -> dict[str, Any]:
    payload = dict(proof)
    payload.pop("signature", None)
    payload.pop("public_key_pem", None)
    return payload


def _write_witness_audit(output_dir: Path, proofs: list[dict[str, Any]]) -> None:
    previous_hash = GENESIS_HASH
    lines: list[str] = []
    for index, proof in enumerate(proofs, start=1):
        record = {
            "record_id": f"governance-witness-{index:04d}",
            "witness_id": proof.get("witness_id"),
            "witness_key_id": proof.get("witness_key_id"),
            "chronology_consensus_hash": proof.get("chronology_consensus_hash"),
            "transparency_anchor_hash": proof.get("transparency_anchor_hash"),
            "attestation_result": proof.get("attestation_result"),
            "signed_at": proof.get("signed_at"),
            "proof_hash": _sha256_text(_canonical_json(proof)),
            "previous_record_hash": previous_hash,
        }
        record["current_record_hash"] = _witness_audit_hash(record)
        previous_hash = str(record["current_record_hash"])
        lines.append(_canonical_json(record))
    (output_dir / WITNESS_AUDIT_FILE).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_witness_trust_audit(output_dir: Path, trust_records: list[dict[str, Any]]) -> None:
    previous_hash = GENESIS_HASH
    lines: list[str] = []
    for index, record_payload in enumerate(trust_records, start=1):
        record = {
            "record_id": f"governance-witness-trust-{index:04d}",
            **record_payload,
            "previous_record_hash": previous_hash,
        }
        record["current_record_hash"] = _witness_trust_audit_hash(record)
        previous_hash = str(record["current_record_hash"])
        lines.append(_canonical_json(record))
    (output_dir / WITNESS_TRUST_AUDIT_FILE).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _load_witness_trust_audit(output_dir: Path) -> list[dict[str, Any]]:
    path = output_dir / WITNESS_TRUST_AUDIT_FILE
    if not path.is_file():
        raise SystemExit(f"GOVERNANCE_WITNESS_TRUST_AUDIT_MISSING:{path}")
    records: list[dict[str, Any]] = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except Exception as exc:
            raise SystemExit(f"GOVERNANCE_WITNESS_TRUST_AUDIT_INVALID_JSON:{index}") from exc
        if not isinstance(record, dict):
            raise SystemExit(f"GOVERNANCE_WITNESS_TRUST_AUDIT_RECORD_INVALID:{index}")
        records.append(record)
    if not records:
        raise SystemExit("GOVERNANCE_WITNESS_TRUST_AUDIT_EMPTY")
    return records


def _write_witness_reputation_history(output_dir: Path, trust_policy: dict[str, Any]) -> None:
    previous_hash = GENESIS_HASH
    lines: list[str] = []
    for index, entry in enumerate(trust_policy.get("witnesses", []), start=1):
        if not isinstance(entry, dict):
            continue
        record = {
            "record_id": f"governance-witness-reputation-{index:04d}",
            "witness_id": entry.get("witness_id"),
            "event_type": "reputation_initialized",
            "effective_at": entry.get("last_seen_at"),
            "previous_reputation_score": None,
            "reputation_score": entry.get("reputation_score"),
            "trust_weight": entry.get("trust_weight"),
            "invalid_attestation_count": entry.get("invalid_attestation_count"),
            "quarantined": entry.get("quarantined"),
            "recovery_requested": entry.get("recovery_requested"),
            "probation_until": entry.get("probation_until"),
            "last_seen_at": entry.get("last_seen_at"),
            "previous_record_hash": previous_hash,
        }
        record["current_record_hash"] = _witness_reputation_history_hash(record)
        previous_hash = str(record["current_record_hash"])
        lines.append(_canonical_json(record))
    (output_dir / WITNESS_REPUTATION_HISTORY_FILE).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _load_witness_reputation_history(output_dir: Path) -> list[dict[str, Any]]:
    path = output_dir / WITNESS_REPUTATION_HISTORY_FILE
    if not path.is_file():
        raise SystemExit(f"GOVERNANCE_WITNESS_REPUTATION_HISTORY_MISSING:{path}")
    records: list[dict[str, Any]] = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except Exception as exc:
            raise SystemExit(f"GOVERNANCE_WITNESS_REPUTATION_HISTORY_INVALID_JSON:{index}") from exc
        if not isinstance(record, dict):
            raise SystemExit(f"GOVERNANCE_WITNESS_REPUTATION_HISTORY_RECORD_INVALID:{index}")
        records.append(record)
    if not records:
        raise SystemExit("GOVERNANCE_WITNESS_REPUTATION_HISTORY_EMPTY")
    return records


def _load_witness_audit(output_dir: Path) -> list[dict[str, Any]]:
    path = output_dir / WITNESS_AUDIT_FILE
    if not path.is_file():
        raise SystemExit(f"GOVERNANCE_WITNESS_AUDIT_MISSING:{path}")
    records: list[dict[str, Any]] = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except Exception as exc:
            raise SystemExit(f"GOVERNANCE_WITNESS_AUDIT_INVALID_JSON:{index}") from exc
        if not isinstance(record, dict):
            raise SystemExit(f"GOVERNANCE_WITNESS_AUDIT_RECORD_INVALID:{index}")
        records.append(record)
    if not records:
        raise SystemExit("GOVERNANCE_WITNESS_AUDIT_EMPTY")
    return records


def _write_witness_proofs(
    output_dir: Path,
    *,
    witness_ids: list[str] | tuple[str, ...] | None = None,
    quorum: int | None = None,
) -> dict[str, Any]:
    witness_id_list = _resolve_witness_ids(witness_ids)
    quorum_required = _resolve_witness_quorum(witness_id_list, quorum)
    trust_policy = _default_witness_trust_policy(witness_id_list)
    consensus = _load_chronology_consensus(output_dir)
    anchor = _load_transparency_anchor(output_dir)
    consensus_hash = _sha256_text(_canonical_json(consensus))
    anchor_hash = _sha256_text(_canonical_json(anchor))
    proofs: list[dict[str, Any]] = []
    for witness_id in witness_id_list:
        private_key, public_key = generate_ed25519_keypair()
        proof = {
            "schema": "usbay.external_witness_attestation.v1",
            "witness_id": witness_id,
            "witness_key_id": signer_key_id(public_key),
            "chronology_consensus_hash": consensus_hash,
            "transparency_anchor_hash": anchor_hash,
            "attestation_result": "ALLOW",
            "signed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "public_key_pem": public_key,
        }
        proof["signature"] = SIGNATURE_PREFIX + _ed25519_sign(_canonical_json(_witness_signature_payload(proof)), private_key)
        proofs.append(proof)
    payload = {
        "schema": "usbay.external_witness_quorum.v1",
        "witness_ids": witness_id_list,
        "quorum_required": quorum_required,
        "trust_policy": trust_policy,
        "chronology_consensus_hash": consensus_hash,
        "transparency_anchor_hash": anchor_hash,
        "proofs": proofs,
    }
    (output_dir / WITNESS_PROOFS_FILE).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_witness_audit(output_dir, proofs)
    _write_witness_reputation_history(output_dir, trust_policy)
    _write_witness_trust_audit(
        output_dir,
        [
            {
                "witness_id": entry["witness_id"],
                "trust_weight": entry["trust_weight"],
                "reputation_score": entry["reputation_score"],
                "raw_reputation_score": entry["reputation_score"],
                "invalid_attestation_count": entry["invalid_attestation_count"],
                "quarantined": entry["quarantined"],
                "recovery_requested": entry["recovery_requested"],
                "probation_until": entry["probation_until"],
                "trust_decision": "trusted",
                "failure_count": 0,
                "proof_hash": _sha256_text(_canonical_json(proofs[index])),
            }
            for index, entry in enumerate(trust_policy["witnesses"])
        ],
    )
    return payload


def _load_witness_proofs(output_dir: Path) -> dict[str, Any]:
    return _load_json_file(output_dir / WITNESS_PROOFS_FILE, "GOVERNANCE_WITNESS_PROOFS_MISSING")


def _latest_reputation_records(records: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    failures: list[str] = []
    latest: dict[str, dict[str, Any]] = {}
    previous_hash = GENESIS_HASH
    seen_transitions: dict[str, list[str]] = {}
    for index, record in enumerate(records, start=1):
        witness_id = str(record.get("witness_id", ""))
        if record.get("previous_record_hash") != previous_hash:
            failures.append(f"GOVERNANCE_WITNESS_REPUTATION_CONTINUITY_BREAK:{index}")
        expected_hash = _witness_reputation_history_hash(record)
        if record.get("current_record_hash") != expected_hash:
            failures.append(f"GOVERNANCE_WITNESS_REPUTATION_TAMPERING_DETECTED:{witness_id or index}")
        if not witness_id:
            failures.append(f"GOVERNANCE_WITNESS_REPUTATION_WITNESS_MISSING:{index}")
        else:
            latest[witness_id] = record
            seen_transitions.setdefault(witness_id, []).append(str(record.get("event_type", "")))
        previous_hash = str(record.get("current_record_hash", ""))
    for witness_id, transitions in seen_transitions.items():
        joined = ",".join(transitions)
        if "malicious_detected,recovered,malicious_detected" in joined or "quarantined,recovered,quarantined" in joined:
            failures.append(f"GOVERNANCE_WITNESS_OSCILLATION_DETECTED:{witness_id}")
    return latest, failures


def _effective_reputation(entry: dict[str, Any], current_time: datetime, inactivity_decay_after_seconds: int, decay_factor: float) -> float:
    reputation_score = float(entry.get("reputation_score", 0.0) or 0.0)
    try:
        last_seen_at = _parse_created_at(str(entry.get("last_seen_at", "")))
    except Exception:
        return 0.0
    if (current_time - last_seen_at).total_seconds() > inactivity_decay_after_seconds:
        return reputation_score * decay_factor
    return reputation_score


def _reputation_recovery_state(entry: dict[str, Any], current_time: datetime, quarantine_threshold: int) -> tuple[bool, list[str]]:
    failures: list[str] = []
    invalid_attestations = int(entry.get("invalid_attestation_count", 0) or 0)
    base_quarantined = bool(entry.get("quarantined")) or invalid_attestations >= quarantine_threshold
    if not base_quarantined:
        return False, failures
    if entry.get("recovery_requested") is not True:
        return True, failures
    probation_until_raw = entry.get("probation_until")
    if not probation_until_raw:
        failures.append(f"GOVERNANCE_WITNESS_PROBATION_MISSING:{entry.get('witness_id')}")
        return True, failures
    try:
        probation_until = _parse_created_at(str(probation_until_raw))
    except Exception:
        failures.append(f"GOVERNANCE_WITNESS_PROBATION_INVALID:{entry.get('witness_id')}")
        return True, failures
    if probation_until <= current_time:
        failures.append(f"GOVERNANCE_WITNESS_PROBATION_EXPIRED:{entry.get('witness_id')}")
        return True, failures
    return False, failures


def verify_witness_proofs(
    output_dir: Path,
    *,
    witness_ids: list[str] | tuple[str, ...] | None = None,
    quorum: int | None = None,
    freshness_seconds: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    failures: list[str] = []
    try:
        witness_id_list = _resolve_witness_ids(witness_ids)
        quorum_required = _resolve_witness_quorum(witness_id_list, quorum)
        freshness = _resolve_witness_freshness_seconds(freshness_seconds)
        witness_payload = _load_witness_proofs(output_dir)
        audit_records = _load_witness_audit(output_dir)
        trust_audit_records = _load_witness_trust_audit(output_dir)
        reputation_history = _load_witness_reputation_history(output_dir)
        consensus = _load_chronology_consensus(output_dir)
        anchor = _load_transparency_anchor(output_dir)
    except SystemExit as exc:
        return {"valid": False, "failures": [str(exc)]}
    expected_consensus_hash = _sha256_text(_canonical_json(consensus))
    expected_anchor_hash = _sha256_text(_canonical_json(anchor))
    if witness_payload.get("schema") != "usbay.external_witness_quorum.v1":
        failures.append("GOVERNANCE_WITNESS_SCHEMA_INVALID")
    if witness_payload.get("witness_ids") != witness_id_list:
        failures.append("GOVERNANCE_WITNESS_SET_MISMATCH")
    if witness_payload.get("quorum_required") != quorum_required:
        failures.append("GOVERNANCE_WITNESS_QUORUM_MISMATCH")
    trust_policy = witness_payload.get("trust_policy")
    if not isinstance(trust_policy, dict):
        failures.append("GOVERNANCE_WITNESS_TRUST_POLICY_MISSING")
        trust_policy = _default_witness_trust_policy(witness_id_list)
    if trust_policy.get("schema") != "usbay.witness_trust_policy.v1":
        failures.append("GOVERNANCE_WITNESS_TRUST_POLICY_SCHEMA_INVALID")
    trust_threshold = float(trust_policy.get("trust_threshold", _resolve_witness_trust_threshold()))
    min_reputation = float(trust_policy.get("minimum_reputation", _resolve_witness_min_reputation()))
    conflict_tolerance = int(trust_policy.get("conflict_tolerance", _resolve_witness_conflict_tolerance()))
    quarantine_threshold = int(
        trust_policy.get(
            "invalid_attestation_quarantine_threshold",
            DEFAULT_WITNESS_INVALID_ATTESTATION_QUARANTINE_THRESHOLD,
        )
    )
    trust_entries = _witness_policy_entries(trust_policy)
    if set(trust_entries) != set(witness_id_list):
        failures.append("GOVERNANCE_WITNESS_TRUST_POLICY_MEMBER_MISMATCH")
    latest_reputation, reputation_failures = _latest_reputation_records(reputation_history)
    failures.extend(reputation_failures)
    if set(latest_reputation) != set(witness_id_list):
        failures.append("GOVERNANCE_WITNESS_REPUTATION_HISTORY_MEMBER_MISMATCH")
    inactivity_decay_after = int(
        trust_policy.get(
            "inactivity_decay_after_seconds",
            DEFAULT_WITNESS_INACTIVITY_DECAY_AFTER_SECONDS,
        )
    )
    reputation_decay_factor = float(
        trust_policy.get(
            "reputation_decay_factor",
            DEFAULT_WITNESS_REPUTATION_DECAY_FACTOR,
        )
    )
    if witness_payload.get("chronology_consensus_hash") != expected_consensus_hash:
        failures.append("GOVERNANCE_WITNESS_CONSENSUS_HASH_MISMATCH")
    if witness_payload.get("transparency_anchor_hash") != expected_anchor_hash:
        failures.append("GOVERNANCE_WITNESS_TRANSPARENCY_ANCHOR_HASH_MISMATCH")
    proofs = witness_payload.get("proofs")
    if not isinstance(proofs, list) or not proofs:
        failures.append("GOVERNANCE_WITNESS_PROOFS_EMPTY")
        proofs = []
    proof_ids = [str(proof.get("witness_id", "")) for proof in proofs if isinstance(proof, dict)]
    if set(proof_ids) != set(witness_id_list):
        failures.append("GOVERNANCE_WITNESS_MEMBER_MISSING")
    if len(proof_ids) != len(set(proof_ids)):
        failures.append("GOVERNANCE_WITNESS_DUPLICATE")
    valid_count = 0
    weighted_trust = 0.0
    conflict_count = 0
    quarantined_witnesses: list[str] = []
    witness_trust_records: list[dict[str, Any]] = []
    seen_proof_hashes: set[str] = set()
    seen_signatures: set[str] = set()
    current_time = now or datetime.now(timezone.utc)
    for proof in proofs:
        if not isinstance(proof, dict):
            failures.append("GOVERNANCE_WITNESS_PROOF_INVALID")
            continue
        witness_id = str(proof.get("witness_id", ""))
        public_key = str(proof.get("public_key_pem", ""))
        signature = str(proof.get("signature", ""))
        witness_failures: list[str] = []
        trust_entry = trust_entries.get(witness_id, {})
        reputation_record = latest_reputation.get(witness_id, {})
        if reputation_record:
            for key in (
                "reputation_score",
                "trust_weight",
                "invalid_attestation_count",
                "quarantined",
                "recovery_requested",
                "probation_until",
                "last_seen_at",
            ):
                if reputation_record.get(key) != trust_entry.get(key):
                    witness_failures.append(f"GOVERNANCE_WITNESS_REPUTATION_CONTINUITY_MISMATCH:{witness_id}:{key}")
        else:
            witness_failures.append(f"GOVERNANCE_WITNESS_REPUTATION_HISTORY_MISSING:{witness_id}")
        trust_weight = float(trust_entry.get("trust_weight", 0.0) or 0.0)
        reputation_score = _effective_reputation(trust_entry, current_time, inactivity_decay_after, reputation_decay_factor)
        invalid_attestations = int(trust_entry.get("invalid_attestation_count", 0) or 0)
        quarantined, recovery_failures = _reputation_recovery_state(trust_entry, current_time, quarantine_threshold)
        witness_failures.extend(recovery_failures)
        proof_hash = _sha256_text(_canonical_json(proof))
        if proof_hash in seen_proof_hashes or signature in seen_signatures:
            witness_failures.append(f"GOVERNANCE_WITNESS_REPLAY_DETECTED:{witness_id}")
        seen_proof_hashes.add(proof_hash)
        if signature:
            seen_signatures.add(signature)
        if witness_id not in witness_id_list:
            witness_failures.append(f"GOVERNANCE_WITNESS_UNEXPECTED:{witness_id}")
        if proof.get("schema") != "usbay.external_witness_attestation.v1":
            witness_failures.append(f"GOVERNANCE_WITNESS_PROOF_SCHEMA_INVALID:{witness_id}")
        if proof.get("witness_key_id") != signer_key_id(public_key):
            witness_failures.append(f"GOVERNANCE_WITNESS_KEY_MISMATCH:{witness_id}")
        if proof.get("chronology_consensus_hash") != expected_consensus_hash:
            witness_failures.append(f"GOVERNANCE_WITNESS_CONFLICT:{witness_id}:chronology_consensus")
        if proof.get("transparency_anchor_hash") != expected_anchor_hash:
            witness_failures.append(f"GOVERNANCE_WITNESS_CONFLICT:{witness_id}:transparency_anchor")
        if proof.get("attestation_result") != "ALLOW":
            witness_failures.append(f"GOVERNANCE_WITNESS_CONFLICT:{witness_id}:attestation_result")
        try:
            signed_at = _parse_created_at(str(proof.get("signed_at", "")))
            if abs((current_time - signed_at).total_seconds()) > freshness:
                witness_failures.append(f"GOVERNANCE_WITNESS_STALE:{witness_id}")
        except Exception:
            witness_failures.append(f"GOVERNANCE_WITNESS_TIMESTAMP_INVALID:{witness_id}")
        if trust_weight <= 0:
            witness_failures.append(f"GOVERNANCE_WITNESS_TRUST_WEIGHT_INVALID:{witness_id}")
        if reputation_score < min_reputation:
            witness_failures.append(f"GOVERNANCE_WITNESS_REPUTATION_BELOW_MINIMUM:{witness_id}")
        if quarantined:
            witness_failures.append(f"GOVERNANCE_WITNESS_QUARANTINED:{witness_id}")
            quarantined_witnesses.append(witness_id)
        if not signature.startswith(SIGNATURE_PREFIX):
            witness_failures.append(f"GOVERNANCE_WITNESS_SIGNATURE_INVALID:{witness_id}")
        elif not _ed25519_verify(_canonical_json(_witness_signature_payload(proof)), signature[len(SIGNATURE_PREFIX) :], public_key):
            witness_failures.append(f"GOVERNANCE_WITNESS_SIGNATURE_INVALID:{witness_id}")
        if any("GOVERNANCE_WITNESS_CONFLICT" in failure for failure in witness_failures):
            conflict_count += 1
        if not witness_failures:
            valid_count += 1
            weighted_trust += trust_weight * reputation_score
            trust_decision = "trusted"
        elif quarantined or any("REPUTATION_BELOW_MINIMUM" in failure for failure in witness_failures):
            trust_decision = "quarantined"
        else:
            trust_decision = "rejected"
        witness_trust_records.append(
            {
                "witness_id": witness_id,
                "trust_weight": trust_weight,
                "reputation_score": reputation_score,
                "raw_reputation_score": float(trust_entry.get("reputation_score", 0.0) or 0.0),
                "invalid_attestation_count": invalid_attestations + (1 if witness_failures else 0),
                "quarantined": trust_decision == "quarantined",
                "recovery_requested": trust_entry.get("recovery_requested"),
                "probation_until": trust_entry.get("probation_until"),
                "trust_decision": trust_decision,
                "failure_count": len(witness_failures),
                "proof_hash": proof_hash,
            }
        )
        failures.extend(witness_failures)
    if valid_count < quorum_required:
        failures.append("GOVERNANCE_WITNESS_QUORUM_NOT_REACHED")
    if weighted_trust < trust_threshold:
        failures.append("GOVERNANCE_WITNESS_TRUST_THRESHOLD_NOT_MET")
    if conflict_count > conflict_tolerance:
        failures.append("GOVERNANCE_WITNESS_CONFLICT_TOLERANCE_EXCEEDED")
    if quarantined_witnesses:
        failures.append("GOVERNANCE_WITNESS_QUARANTINE_ACTIVE:" + ",".join(sorted(set(quarantined_witnesses))))
    if len(audit_records) != len(proofs):
        failures.append("GOVERNANCE_WITNESS_AUDIT_COUNT_MISMATCH")
    previous_hash = GENESIS_HASH
    for index, proof in enumerate(proofs):
        if index >= len(audit_records) or not isinstance(proof, dict):
            break
        expected_record = {
            "record_id": f"governance-witness-{index + 1:04d}",
            "witness_id": proof.get("witness_id"),
            "witness_key_id": proof.get("witness_key_id"),
            "chronology_consensus_hash": proof.get("chronology_consensus_hash"),
            "transparency_anchor_hash": proof.get("transparency_anchor_hash"),
            "attestation_result": proof.get("attestation_result"),
            "signed_at": proof.get("signed_at"),
            "proof_hash": _sha256_text(_canonical_json(proof)),
            "previous_record_hash": previous_hash,
        }
        expected_record["current_record_hash"] = _witness_audit_hash(expected_record)
        if audit_records[index] != expected_record:
            failures.append(f"GOVERNANCE_WITNESS_AUDIT_MISMATCH:{proof.get('witness_id')}")
        previous_hash = str(audit_records[index].get("current_record_hash", ""))
    if len(trust_audit_records) != len(witness_trust_records):
        failures.append("GOVERNANCE_WITNESS_TRUST_AUDIT_COUNT_MISMATCH")
    previous_trust_hash = GENESIS_HASH
    for index, record_payload in enumerate(witness_trust_records):
        if index >= len(trust_audit_records):
            break
        expected_record = {
            "record_id": f"governance-witness-trust-{index + 1:04d}",
            **record_payload,
            "previous_record_hash": previous_trust_hash,
        }
        expected_record["current_record_hash"] = _witness_trust_audit_hash(expected_record)
        if trust_audit_records[index] != expected_record:
            failures.append(f"GOVERNANCE_WITNESS_TRUST_AUDIT_MISMATCH:{record_payload.get('witness_id')}")
        previous_trust_hash = str(trust_audit_records[index].get("current_record_hash", ""))
    return {
        "valid": not failures,
        "failures": sorted(set(failures)),
        "valid_witness_count": valid_count,
        "quorum_required": quorum_required,
        "witness_ids": witness_id_list,
        "weighted_trust": weighted_trust,
        "trust_threshold": trust_threshold,
        "conflict_count": conflict_count,
        "conflict_tolerance": conflict_tolerance,
        "quarantined_witnesses": sorted(set(quarantined_witnesses)),
        "reputation_history_records": len(reputation_history),
    }


def generate_governance_timestamps(
    root: Path,
    output_dir: Path,
    manifest_path: Path,
    trust_policy_path: Path | None = None,
) -> None:
    root = root.resolve()
    manifest_path = manifest_path if manifest_path.is_absolute() else root / manifest_path
    trust_policy_path = _resolve_trust_policy_path(root, trust_policy_path)
    trust_policy_state = verify_trust_policy_governance(root, trust_policy_path)
    if trust_policy_state["valid"] is not True:
        raise SystemExit("GOVERNANCE_TIMESTAMP_TRUST_POLICY_INVALID:" + ",".join(trust_policy_state["failures"]))
    if not manifest_path.is_file():
        raise SystemExit(f"GOVERNANCE_TIMESTAMP_MANIFEST_MISSING:{manifest_path}")
    output_dir.mkdir(parents=True, exist_ok=True)
    targets = _timestamp_targets(root, manifest_path, trust_policy_path)
    proofs: list[dict[str, Any]] = []
    verifications: list[dict[str, Any]] = []
    previous_timestamp_hash: str | None = None
    seen_tokens: set[str] = set()
    for target in targets:
        message_hash = sha256_text(_canonical_json(target))
        proof = create_timestamp_proof(message_hash, previous_timestamp_hash=previous_timestamp_hash)
        verification = verify_timestamp_proof(
            proof,
            message_hash,
            previous_timestamp_hash=previous_timestamp_hash,
            seen_token_hashes=seen_tokens,
        )
        timestamp_interface, _timestamp_metric = measure_governance_validation(
            "timestamping",
            "generate_governance_timestamps",
            validate_timestamp_verification_interface,
            verification,
        )
        if timestamp_interface.valid is not True:
            raise SystemExit("GOVERNANCE_TIMESTAMP_VERIFICATION_INTERFACE_INVALID:" + ",".join(timestamp_interface.failures))
        if verification.get("valid") is not True:
            raise SystemExit("GOVERNANCE_TIMESTAMP_VERIFICATION_FAILED:" + ",".join(verification.get("errors", [])))
        seen_tokens.add(sha256_text(str(proof.get("token", ""))))
        previous_timestamp_hash = str(verification["timestamp_hash"])
        proofs.append(proof)
        verifications.append({"target": target, "verification": verification})
    chronology_consensus = build_chronology_consensus(targets)
    _write_chronology_consensus(output_dir, chronology_consensus)
    _write_transparency_log(output_dir, proofs, targets)
    _write_transparency_anchor(root, output_dir, manifest_path, trust_policy_path)
    _write_witness_proofs(output_dir)
    (output_dir / TIMESTAMP_PROOFS_FILE).write_text(json.dumps(proofs, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = verify_governance_timestamps(root, output_dir, manifest_path, trust_policy_path=trust_policy_path)
    if summary["valid"] is not True:
        raise SystemExit("GOVERNANCE_TIMESTAMP_TRANSPARENCY_INVALID:" + ",".join(summary["failures"]))
    (output_dir / TIMESTAMP_VERIFICATION_FILE).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    witness_summary = verify_witness_proofs(output_dir)
    if witness_summary["valid"] is not True:
        raise SystemExit("GOVERNANCE_WITNESS_VERIFICATION_FAILED:" + ",".join(witness_summary["failures"]))
    (output_dir / WITNESS_VERIFICATION_FILE).write_text(json.dumps(witness_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"CI_GOVERNANCE_TIMESTAMPS_GENERATED={output_dir}")
    print(f"CI_GOVERNANCE_TIMESTAMP_TARGETS={len(targets)}")
    print("CI_GOVERNANCE_TIMESTAMP_VERIFIED=true")
    print("CI_GOVERNANCE_TRANSPARENCY_LOG_VALID=true")
    print("CI_GOVERNANCE_CHRONOLOGY_CONSENSUS_VALID=true")
    print("CI_GOVERNANCE_WITNESS_QUORUM_VALID=true")


def _load_timestamp_proofs(output_dir: Path) -> list[dict[str, Any]]:
    path = output_dir / TIMESTAMP_PROOFS_FILE
    if not path.is_file():
        raise SystemExit(f"GOVERNANCE_TIMESTAMP_PROOFS_MISSING:{path}")
    try:
        proofs = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit("GOVERNANCE_TIMESTAMP_PROOFS_INVALID_JSON") from exc
    if not isinstance(proofs, list) or not proofs:
        raise SystemExit("GOVERNANCE_TIMESTAMP_PROOFS_EMPTY")
    return proofs


def _load_transparency_records(output_dir: Path) -> list[dict[str, Any]]:
    path = output_dir / TRANSPARENCY_LOG_FILE
    if not path.is_file():
        raise SystemExit(f"GOVERNANCE_TRANSPARENCY_LOG_MISSING:{path}")
    records: list[dict[str, Any]] = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except Exception as exc:
            raise SystemExit(f"GOVERNANCE_TRANSPARENCY_LOG_INVALID_JSON:{index}") from exc
        if not isinstance(record, dict):
            raise SystemExit(f"GOVERNANCE_TRANSPARENCY_RECORD_INVALID:{index}")
        records.append(record)
    if not records:
        raise SystemExit("GOVERNANCE_TRANSPARENCY_LOG_EMPTY")
    return records


def verify_governance_timestamps(
    root: Path,
    output_dir: Path,
    manifest_path: Path,
    *,
    trust_policy_path: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    output_dir = output_dir if output_dir.is_absolute() else root / output_dir
    manifest_path = manifest_path if manifest_path.is_absolute() else root / manifest_path
    trust_policy_path = _resolve_trust_policy_path(root, trust_policy_path)
    failures: list[str] = []
    try:
        targets = _timestamp_targets(root, manifest_path, trust_policy_path)
        proofs = _load_timestamp_proofs(output_dir)
        records = _load_transparency_records(output_dir)
    except SystemExit as exc:
        return {"valid": False, "failures": [str(exc)], "timestamp_targets": []}
    if len(proofs) != len(targets):
        failures.append("GOVERNANCE_TIMESTAMP_PROOF_COUNT_MISMATCH")
    if len(records) != len(targets):
        failures.append("GOVERNANCE_TRANSPARENCY_RECORD_COUNT_MISMATCH")
    previous_timestamp_hash: str | None = None
    seen_tokens: set[str] = set()
    verification_results: list[dict[str, Any]] = []
    for index, target in enumerate(targets):
        if index >= len(proofs):
            break
        message_hash = sha256_text(_canonical_json(target))
        verification = verify_timestamp_proof(
            proofs[index],
            message_hash,
            previous_timestamp_hash=previous_timestamp_hash,
            seen_token_hashes=seen_tokens,
            now=now,
        )
        timestamp_interface, timestamp_metric = measure_governance_validation(
            "timestamping",
            "verify_governance_timestamps",
            validate_timestamp_verification_interface,
            verification,
        )
        if timestamp_interface.valid is not True:
            failures.extend(f"GOVERNANCE_TIMESTAMP_VERIFICATION_INTERFACE_INVALID:{target['target_name']}:{failure}" for failure in timestamp_interface.failures)
        verification_results.append(
            {
                "target": target,
                "verification": verification,
                "telemetry": {
                    "timestamp_verification_duration_ns": timestamp_metric.validation_latency_ns,
                    "artifact_counts": {"timestamp_verifications": timestamp_metric.artifact_count},
                },
            }
        )
        if verification.get("valid") is not True:
            failures.extend(f"GOVERNANCE_TIMESTAMP_INVALID:{target['target_name']}:{error}" for error in verification.get("errors", []))
        token_hash = sha256_text(str(proofs[index].get("token", "")))
        seen_tokens.add(token_hash)
        previous_timestamp_hash = str(verification.get("timestamp_hash") or proofs[index].get("timestamp_hash", ""))
    previous_record_hash = GENESIS_HASH
    for index, target in enumerate(targets):
        if index >= len(records) or index >= len(proofs):
            break
        record = records[index]
        if record.get("previous_record_hash") != previous_record_hash:
            failures.append(f"GOVERNANCE_TRANSPARENCY_CHAIN_BREAK:{target['target_name']}")
        if record.get("target_name") != target["target_name"] or record.get("target_sha256") != target["target_sha256"]:
            failures.append(f"GOVERNANCE_TRANSPARENCY_TARGET_MISMATCH:{target['target_name']}")
        if record.get("timestamp_hash") != proofs[index].get("timestamp_hash"):
            failures.append(f"GOVERNANCE_TRANSPARENCY_TIMESTAMP_MISMATCH:{target['target_name']}")
        expected_record_hash = _transparency_record_hash(record)
        if record.get("current_record_hash") != expected_record_hash:
            failures.append(f"GOVERNANCE_TRANSPARENCY_HASH_INVALID:{target['target_name']}")
        previous_record_hash = str(record.get("current_record_hash", ""))
    chronology_summary = verify_chronology_consensus(targets, output_dir, now=now)
    if chronology_summary["valid"] is not True:
        failures.extend(f"GOVERNANCE_CHRONOLOGY_INVALID:{failure}" for failure in chronology_summary["failures"])
    anchor_summary = verify_transparency_anchor(root, output_dir, manifest_path, trust_policy_path)
    if anchor_summary["valid"] is not True:
        failures.extend(f"GOVERNANCE_TRANSPARENCY_ANCHOR_INVALID:{failure}" for failure in anchor_summary["failures"])
    witness_summary = verify_witness_proofs(output_dir, now=now)
    if witness_summary["valid"] is not True:
        failures.extend(f"GOVERNANCE_WITNESS_INVALID:{failure}" for failure in witness_summary["failures"])
    timestamp_duration_ns = sum(
        int(result.get("telemetry", {}).get("timestamp_verification_duration_ns", 0))
        for result in verification_results
    )
    chronology_telemetry = chronology_summary.get("telemetry", {}) if isinstance(chronology_summary, dict) else {}
    return {
        "valid": not failures,
        "failures": sorted(set(failures)),
        "timestamp_targets": targets,
        "timestamp_verifications": verification_results,
        "transparency_records": len(records),
        "chronology_consensus": {
            "valid": chronology_summary["valid"],
            "quorum_required": chronology_summary.get("quorum_required"),
            "authority_ids": chronology_summary.get("authority_ids", []),
        },
        "transparency_anchor": {"valid": anchor_summary["valid"]},
        "witness_verification": {
            "valid": witness_summary["valid"],
            "valid_witness_count": witness_summary.get("valid_witness_count"),
            "quorum_required": witness_summary.get("quorum_required"),
            "weighted_trust": witness_summary.get("weighted_trust"),
            "trust_threshold": witness_summary.get("trust_threshold"),
            "quarantined_witnesses": witness_summary.get("quarantined_witnesses", []),
        },
        "telemetry": {
            "validation_latency_ns": timestamp_duration_ns + int(chronology_telemetry.get("chronology_verification_duration_ns", 0)),
            "timestamp_verification_duration_ns": timestamp_duration_ns,
            "chronology_verification_duration_ns": chronology_telemetry.get("chronology_verification_duration_ns", 0),
            "artifact_counts": {
                "timestamp_targets": len(targets),
                "timestamp_verifications": len(verification_results),
                "transparency_records": len(records),
                "chronology_targets": len(chronology_summary.get("consensus_targets", [])),
            },
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate or verify CI governance evidence chain manifest")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, default=Path(CI_EVIDENCE_MANIFEST_PATH))
    parser.add_argument("--evidence", action="append", default=[])
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--timestamp-output", type=Path)
    parser.add_argument("--verify-timestamps", type=Path)
    parser.add_argument("--allow-test-key", action="store_true")
    parser.add_argument("--trust-policy", type=Path)
    args = parser.parse_args(argv)
    if args.timestamp_output:
        output_dir = args.timestamp_output if args.timestamp_output.is_absolute() else args.root / args.timestamp_output
        generate_governance_timestamps(args.root, output_dir, Path(CI_EVIDENCE_MANIFEST_PATH), trust_policy_path=args.trust_policy)
        return 0
    if args.verify_timestamps:
        output_dir = args.verify_timestamps if args.verify_timestamps.is_absolute() else args.root / args.verify_timestamps
        summary = verify_governance_timestamps(args.root, output_dir, Path(CI_EVIDENCE_MANIFEST_PATH), trust_policy_path=args.trust_policy)
        if summary["valid"] is not True:
            raise SystemExit("GOVERNANCE_TIMESTAMP_VERIFICATION_FAILED:" + ",".join(summary["failures"]))
        print(f"CI_GOVERNANCE_TIMESTAMPS_VALID={output_dir}")
        print(f"CI_GOVERNANCE_TIMESTAMP_TARGETS={len(summary['timestamp_targets'])}")
        telemetry = summary.get("telemetry", {})
        print(f"CI_GOVERNANCE_VALIDATION_LATENCY_NS={telemetry.get('validation_latency_ns', 0)}")
        print(f"CI_GOVERNANCE_TIMESTAMP_VERIFICATION_DURATION_NS={telemetry.get('timestamp_verification_duration_ns', 0)}")
        print(f"CI_GOVERNANCE_CHRONOLOGY_VERIFICATION_DURATION_NS={telemetry.get('chronology_verification_duration_ns', 0)}")
        print("CI_GOVERNANCE_TRANSPARENCY_LOG_VALID=true")
        print("CI_GOVERNANCE_CHRONOLOGY_CONSENSUS_VALID=true")
        print("CI_GOVERNANCE_WITNESS_TRUST_VALID=true")
        return 0
    if args.verify:
        manifest_path = args.verify if args.verify.is_absolute() else args.root / args.verify
        verify_manifest(args.root, manifest_path, allow_test_key=args.allow_test_key, trust_policy_path=args.trust_policy)
        return 0
    output = args.output if args.output.is_absolute() else args.root / args.output
    evidence_paths = args.evidence or list(DEFAULT_EVIDENCE_PATHS)
    write_manifest(args.root, output, evidence_paths, allow_test_key=args.allow_test_key, trust_policy_path=args.trust_policy)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
