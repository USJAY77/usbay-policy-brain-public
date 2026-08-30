#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.verify_decision import verify_decision_export
from scripts.verify_reset_log import verify_reset_log


AUDIT_VALID = "VALID"
AUDIT_INVALID = "INVALID"
AUDIT_DISPUTED = "DISPUTED"
VERIFICATION_RESULTS = {AUDIT_VALID, AUDIT_INVALID}
REQUIRED_VERIFIER_NODES = 3
QUORUM = 2
DEFAULT_SIGNATURE_POLICY_MODE = "STRICT"
VERIFIER_REGISTRY_PATH = REPO_ROOT / "governance" / "verifier_node_registry.json"
POLICY_REGISTRY_PATH = REPO_ROOT / "governance" / "policy_registry.json"

_NODE_SEEDS = {
    "audit-verifier-1": b"usbay-audit-verifier-1-dev-seed",
    "audit-verifier-2": b"usbay-audit-verifier-2-dev-seed",
    "audit-verifier-3": b"usbay-audit-verifier-3-dev-seed",
}


@dataclass(frozen=True)
class AuditVerifierNodeResult:
    node_id: str
    trust_domain: str
    verifier_pubkey_id: str
    verifier_signature: str
    verified_at_epoch: int
    verification_result: str
    verified_audit_hash: str
    signature_policy_mode: str
    policy_version: str
    policy_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "trust_domain": self.trust_domain,
            "verifier_pubkey_id": self.verifier_pubkey_id,
            "verifier_signature": self.verifier_signature,
            "verified_at_epoch": self.verified_at_epoch,
            "verification_result": self.verification_result,
            "verified_audit_hash": self.verified_audit_hash,
            "signature_policy_mode": self.signature_policy_mode,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditVerifierNodeResult":
        return cls(
            node_id=str(data.get("node_id", "")),
            trust_domain=str(data.get("trust_domain", "")),
            verifier_pubkey_id=str(data.get("verifier_pubkey_id", "")),
            verifier_signature=str(data.get("verifier_signature", "")),
            verified_at_epoch=int(data.get("verified_at_epoch", 0)),
            verification_result=str(data.get("verification_result", "")),
            verified_audit_hash=str(data.get("verified_audit_hash", "")),
            signature_policy_mode=str(data.get("signature_policy_mode", "")),
            policy_version=str(data.get("policy_version", "")),
            policy_hash=str(data.get("policy_hash", "")),
        )


def _canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _canonical_text(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _private_key_for_node(node_id: str) -> Ed25519PrivateKey:
    seed = _NODE_SEEDS.get(node_id)
    if seed is None:
        raise ValueError("unknown_verifier_node")
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed).digest())


def _public_key_for_node(node_id: str) -> Ed25519PublicKey:
    return _private_key_for_node(node_id).public_key()


def verifier_pubkey_id_for_node(node_id: str) -> str:
    public_key = _public_key_for_node(node_id)
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(public_bytes).hexdigest()


def verifier_key_registry() -> dict[str, Ed25519PublicKey]:
    return {
        verifier_pubkey_id_for_node(node_id): _public_key_for_node(node_id)
        for node_id in _NODE_SEEDS
    }


def load_verifier_node_registry(path: Path | None = None) -> dict[str, Any]:
    registry_path = path or VERIFIER_REGISTRY_PATH
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    if not isinstance(registry, dict) or not isinstance(registry.get("nodes"), list):
        raise ValueError("verifier_node_registry_invalid")
    if not isinstance(registry.get("max_clock_skew_seconds", 300), int):
        raise ValueError("verifier_node_registry_invalid")
    nodes = {}
    for node in registry["nodes"]:
        if not isinstance(node, dict):
            raise ValueError("verifier_node_registry_invalid")
        node_id = node.get("node_id")
        pubkey_id = node.get("verifier_pubkey_id")
        if node_id not in _NODE_SEEDS:
            raise ValueError("unknown_verifier_node")
        if pubkey_id != verifier_pubkey_id_for_node(node_id):
            raise ValueError("verifier_pubkey_mismatch")
        if node.get("status") not in {"active", "revoked"}:
            raise ValueError("verifier_status_invalid")
        if not isinstance(node.get("trust_domain"), str) or not node.get("trust_domain"):
            raise ValueError("verifier_trust_domain_invalid")
        if int(node.get("quorum_weight", 0)) <= 0:
            raise ValueError("verifier_weight_invalid")
        if int(node.get("valid_from_epoch", 0)) <= 0 or int(node.get("valid_until_epoch", 0)) <= 0:
            raise ValueError("verifier_key_validity_invalid")
        nodes[node_id] = node
    if set(nodes) != set(_NODE_SEEDS):
        raise ValueError("verifier_node_registry_incomplete")
    registry["_nodes_by_id"] = nodes
    return registry


def load_policy_signature_mode(path: Path | None = None) -> str:
    try:
        policy = json.loads((path or POLICY_REGISTRY_PATH).read_text(encoding="utf-8"))
    except Exception:
        return DEFAULT_SIGNATURE_POLICY_MODE
    mode = str(policy.get("signature_policy_mode", DEFAULT_SIGNATURE_POLICY_MODE)).upper()
    if mode not in {"STRICT", "COMPAT", "TRANSITION"}:
        raise ValueError("signature_policy_mode_invalid")
    return mode


def _signature_payload(result: AuditVerifierNodeResult | dict[str, Any]) -> dict[str, Any]:
    data = result.to_dict() if isinstance(result, AuditVerifierNodeResult) else result
    return {
        "node_id": data.get("node_id"),
        "trust_domain": data.get("trust_domain"),
        "verifier_pubkey_id": data.get("verifier_pubkey_id"),
        "verified_at_epoch": data.get("verified_at_epoch"),
        "verification_result": data.get("verification_result"),
        "verified_audit_hash": data.get("verified_audit_hash"),
        "signature_policy_mode": data.get("signature_policy_mode"),
        "policy_version": data.get("policy_version"),
        "policy_hash": data.get("policy_hash"),
    }


def _target_audit_hash(export: dict[str, Any]) -> str:
    if isinstance(export.get("decision_record"), dict):
        return str(export["decision_record"].get("audit_hash", ""))
    if isinstance(export.get("records"), list) and export["records"]:
        return str(export["records"][-1].get("audit_hash", ""))
    return str(export.get("audit_hash", ""))


def sign_verifier_result(
    node_id: str,
    verification_result: str,
    verified_audit_hash: str,
    verified_at_epoch: int | None = None,
    signature_policy_mode: str | None = None,
    policy_version: str = "",
    policy_hash: str = "",
    trust_domain: str | None = None,
) -> AuditVerifierNodeResult:
    if verification_result not in VERIFICATION_RESULTS:
        raise ValueError("invalid_verification_result")
    registry_node = load_verifier_node_registry()["_nodes_by_id"][node_id]
    pubkey_id = verifier_pubkey_id_for_node(node_id)
    unsigned = AuditVerifierNodeResult(
        node_id=node_id,
        trust_domain=trust_domain or str(registry_node["trust_domain"]),
        verifier_pubkey_id=pubkey_id,
        verifier_signature="",
        verified_at_epoch=verified_at_epoch if verified_at_epoch is not None else int(time.time()),
        verification_result=verification_result,
        verified_audit_hash=verified_audit_hash,
        signature_policy_mode=(signature_policy_mode or load_policy_signature_mode()).upper(),
        policy_version=policy_version,
        policy_hash=policy_hash,
    )
    signature = _private_key_for_node(node_id).sign(_canonical_json(_signature_payload(unsigned)))
    return AuditVerifierNodeResult(
        node_id=unsigned.node_id,
        trust_domain=unsigned.trust_domain,
        verifier_pubkey_id=unsigned.verifier_pubkey_id,
        verifier_signature=base64.b64encode(signature).decode("ascii"),
        verified_at_epoch=unsigned.verified_at_epoch,
        verification_result=unsigned.verification_result,
        verified_audit_hash=unsigned.verified_audit_hash,
        signature_policy_mode=unsigned.signature_policy_mode,
        policy_version=unsigned.policy_version,
        policy_hash=unsigned.policy_hash,
    )


def verify_verifier_result(
    result: AuditVerifierNodeResult | dict[str, Any],
    registry: dict[str, Ed25519PublicKey] | None = None,
    node_registry: dict[str, Any] | None = None,
    expected_signature_policy_mode: str | None = None,
    now_epoch: int | None = None,
) -> bool:
    try:
        node_result = result if isinstance(result, AuditVerifierNodeResult) else AuditVerifierNodeResult.from_dict(result)
        verifier_nodes = node_registry or load_verifier_node_registry()
        registry_node = verifier_nodes["_nodes_by_id"].get(node_result.node_id)
        if registry_node is None:
            return False
        if registry_node.get("status") != "active":
            return False
        if node_result.trust_domain != registry_node.get("trust_domain"):
            return False
        expected_pubkey_id = registry_node.get("verifier_pubkey_id")
        if node_result.verifier_pubkey_id != expected_pubkey_id:
            return False
        current_time = int(now_epoch if now_epoch is not None else time.time())
        max_skew = int(verifier_nodes.get("max_clock_skew_seconds", 300))
        if node_result.verified_at_epoch > current_time + max_skew:
            return False
        valid_from = int(registry_node.get("valid_from_epoch", 0))
        valid_until = int(registry_node.get("valid_until_epoch", 0))
        if node_result.verified_at_epoch < valid_from - max_skew:
            return False
        if node_result.verified_at_epoch > valid_until + max_skew:
            return False
        if node_result.verification_result not in VERIFICATION_RESULTS:
            return False
        if not isinstance(node_result.verified_audit_hash, str) or len(node_result.verified_audit_hash) != 64:
            return False
        policy_mode = (expected_signature_policy_mode or load_policy_signature_mode()).upper()
        if node_result.signature_policy_mode != policy_mode:
            return False
        if not node_result.policy_version or not node_result.policy_hash:
            return False
        public_key = (registry or verifier_key_registry()).get(node_result.verifier_pubkey_id)
        if public_key is None:
            return False
        public_key.verify(
            base64.b64decode(node_result.verifier_signature, validate=True),
            _canonical_json(_signature_payload(node_result)),
        )
        return True
    except (InvalidSignature, Exception):
        return False


def audit_final_allows_execution(audit_final: str) -> bool:
    return audit_final == AUDIT_VALID


def audit_final_requires_human_review(audit_final: str) -> bool:
    return audit_final == AUDIT_DISPUTED


def evaluate_hydra_audit_results(
    results: list[AuditVerifierNodeResult | dict[str, Any]],
    expected_signature_policy_mode: str | None = None,
    now_epoch: int | None = None,
) -> str:
    if not isinstance(results, list) or len(results) != REQUIRED_VERIFIER_NODES:
        return AUDIT_INVALID

    normalized: list[AuditVerifierNodeResult] = []
    seen_nodes: set[str] = set()
    seen_trust_domains: set[str] = set()
    try:
        node_registry = load_verifier_node_registry()
        policy_mode = (expected_signature_policy_mode or load_policy_signature_mode()).upper()
    except Exception:
        return AUDIT_INVALID
    for result in results:
        try:
            node_result = result if isinstance(result, AuditVerifierNodeResult) else AuditVerifierNodeResult.from_dict(result)
        except Exception:
            return AUDIT_INVALID
        if node_result.node_id in seen_nodes:
            return AUDIT_INVALID
        if node_result.trust_domain in seen_trust_domains:
            return AUDIT_INVALID
        seen_nodes.add(node_result.node_id)
        seen_trust_domains.add(node_result.trust_domain)
        if not verify_verifier_result(
            node_result,
            node_registry=node_registry,
            expected_signature_policy_mode=policy_mode,
            now_epoch=now_epoch,
        ):
            return AUDIT_INVALID
        normalized.append(node_result)

    if seen_nodes != set(_NODE_SEEDS):
        return AUDIT_INVALID
    if len(seen_trust_domains) < QUORUM:
        return AUDIT_INVALID

    verified_hashes = {result.verified_audit_hash for result in normalized}
    if len(verified_hashes) != 1:
        return AUDIT_DISPUTED

    valid_votes = sum(1 for result in normalized if result.verification_result == AUDIT_VALID)
    invalid_votes = sum(1 for result in normalized if result.verification_result == AUDIT_INVALID)
    if valid_votes >= QUORUM:
        return AUDIT_VALID
    if invalid_votes >= QUORUM:
        return AUDIT_INVALID
    return AUDIT_INVALID


def simulate_verifier_nodes(
    export: dict[str, Any],
    public_key_path: Path | None = None,
    verification_results: list[str] | None = None,
    audit_hashes: list[str] | None = None,
) -> list[AuditVerifierNodeResult]:
    public_key = public_key_path or REPO_ROOT / "governance" / "policy_public.key"
    base_result = AUDIT_VALID if verify_decision_export(export, public_key) else AUDIT_INVALID
    base_hash = _target_audit_hash(export)
    target_record = export.get("decision_record") if isinstance(export.get("decision_record"), dict) else export
    policy_version = str(target_record.get("policy_version", ""))
    policy_hash = str(target_record.get("policy_hash", ""))
    signature_mode = load_policy_signature_mode()
    results = verification_results or [base_result, base_result, base_result]
    hashes = audit_hashes or [base_hash, base_hash, base_hash]
    if len(results) != REQUIRED_VERIFIER_NODES or len(hashes) != REQUIRED_VERIFIER_NODES:
        raise ValueError("invalid_verifier_simulation_shape")
    return [
        sign_verifier_result(
            node_id,
            results[index],
            hashes[index],
            signature_policy_mode=signature_mode,
            policy_version=policy_version,
            policy_hash=policy_hash,
        )
        for index, node_id in enumerate(_NODE_SEEDS)
    ]


def hydra_audit_evidence(
    export: dict[str, Any],
    public_key_path: Path | None = None,
    verification_results: list[str] | None = None,
    audit_hashes: list[str] | None = None,
) -> dict[str, Any]:
    results = simulate_verifier_nodes(
        export,
        public_key_path=public_key_path,
        verification_results=verification_results,
        audit_hashes=audit_hashes,
    )
    audit_final = evaluate_hydra_audit_results(results)
    return {
        "audit_final": audit_final,
        "human_review_required": audit_final_requires_human_review(audit_final),
        "execution_allowed": audit_final_allows_execution(audit_final),
        "verifier_results": [result.to_dict() for result in results],
    }


def hydra_reset_log_evidence(log_path: Path) -> dict[str, Any]:
    artifact_hash = hashlib.sha256(log_path.read_bytes()).hexdigest() if log_path.exists() else "0" * 64
    base_result = AUDIT_VALID if verify_reset_log(log_path) else AUDIT_INVALID
    results = [
        sign_verifier_result(
            node_id,
            base_result,
            artifact_hash,
            policy_version="edgeguard-reset-audit-v1",
            policy_hash=artifact_hash,
        )
        for node_id in _NODE_SEEDS
    ]
    audit_final = evaluate_hydra_audit_results(results)
    return {
        "audit_final": audit_final,
        "human_review_required": audit_final_requires_human_review(audit_final),
        "execution_allowed": audit_final_allows_execution(audit_final),
        "verifier_results": [result.to_dict() for result in results],
    }


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[1] == "--reset-log":
        try:
            final = str(hydra_reset_log_evidence(Path(argv[2]))["audit_final"])
        except Exception:
            print(AUDIT_INVALID)
            return 1
        print(final)
        return 0 if final == AUDIT_VALID else 1
    if len(argv) not in {2, 3}:
        print(
            "usage: python scripts/hydra_verify_audit.py <decision_export_json> [policy_public_key]\n"
            "       python scripts/hydra_verify_audit.py --reset-log <reset_audit_log>",
            file=sys.stderr,
        )
        return 2
    try:
        export = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    except Exception:
        print(AUDIT_INVALID)
        return 1
    public_key_path = Path(argv[2]) if len(argv) == 3 else REPO_ROOT / "governance" / "policy_public.key"
    try:
        evidence = hydra_audit_evidence(export, public_key_path)
        final = str(evidence["audit_final"])
    except Exception:
        print(AUDIT_INVALID)
        return 1
    print(final)
    return 0 if final == AUDIT_VALID else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
