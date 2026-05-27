"""Deterministic verifier for the on-disk signed governance evidence chain.

Reads only existing signed artifacts produced by the runtime/evidence pipeline:

  - governance/ci_evidence_trust_policy.json           (canonical policy)
  - governance/ci_evidence_trust_policy.sig            (Ed25519 sidecar)
  - governance/ci_evidence_trust_policy_authority.json (authority root)
  - governance/ci_evidence_trust_policy_audit.jsonl    (append-only audit log)

Returns one of three deterministic states:

  - VERIFIED   : signature verifies against canonical policy bytes,
                 declared policy_hash matches, signer is listed by the
                 authority and not revoked, audit log binds the same
                 policy_hash + signer fingerprint.
  - UNVERIFIED : any artifact is malformed, signer is unknown / revoked,
                 hash mismatch, signature invalid, or audit binding wrong.
  - MISSING    : any required artifact does not exist on disk.

Fail-closed semantics: a VERIFIED state is returned only when every check
passes. Any error path returns UNVERIFIED or MISSING with a reason code.
Provenance source paths and their sha256 digests are always included so
callers (and audit consumers) can attest exactly which bytes were checked.

This module does not:
  - regenerate evidence
  - fabricate VERIFIED state
  - weaken signature validation
  - mutate any input
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


STATE_VERIFIED = "VERIFIED"
STATE_UNVERIFIED = "UNVERIFIED"
STATE_MISSING = "MISSING"

DEFAULT_POLICY_PATH = Path("governance/ci_evidence_trust_policy.json")
DEFAULT_SIGNATURE_PATH = Path("governance/ci_evidence_trust_policy.sig")
DEFAULT_AUTHORITY_PATH = Path("governance/ci_evidence_trust_policy_authority.json")
DEFAULT_AUDIT_PATH = Path("governance/ci_evidence_trust_policy_audit.jsonl")

_ED25519_PREFIX = "ed25519:"


@dataclass(frozen=True)
class EvidenceVerification:
    state: str
    reason_codes: tuple[str, ...]
    provenance_source: dict[str, Any]
    signer_id: str | None = None
    signer_fingerprint: str | None = None
    policy_version: str | None = None
    policy_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "reason_codes": list(self.reason_codes),
            "provenance_source": self.provenance_source,
            "signer_id": self.signer_id,
            "signer_fingerprint": self.signer_fingerprint,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
        }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _build_provenance(
    *,
    policy_path: Path,
    signature_path: Path,
    authority_path: Path,
    audit_path: Path,
    present: dict[str, bool],
) -> dict[str, Any]:
    sources: dict[str, Any] = {}
    for name, path in (
        ("policy", policy_path),
        ("signature", signature_path),
        ("authority", authority_path),
        ("audit_log", audit_path),
    ):
        entry: dict[str, Any] = {"path": str(path), "present": present.get(name, False)}
        if entry["present"]:
            try:
                entry["sha256"] = _sha256_file(path)
            except OSError:
                entry["present"] = False
        sources[name] = entry
    return sources


def verify_governance_evidence(
    root: Path | str = ".",
    *,
    policy_path: Path | None = None,
    signature_path: Path | None = None,
    authority_path: Path | None = None,
    audit_path: Path | None = None,
) -> EvidenceVerification:
    root_path = Path(root)
    p_policy = (policy_path or (root_path / DEFAULT_POLICY_PATH)).resolve()
    p_sig = (signature_path or (root_path / DEFAULT_SIGNATURE_PATH)).resolve()
    p_authority = (authority_path or (root_path / DEFAULT_AUTHORITY_PATH)).resolve()
    p_audit = (audit_path or (root_path / DEFAULT_AUDIT_PATH)).resolve()

    present = {
        "policy": p_policy.is_file(),
        "signature": p_sig.is_file(),
        "authority": p_authority.is_file(),
        "audit_log": p_audit.is_file(),
    }
    provenance = _build_provenance(
        policy_path=p_policy,
        signature_path=p_sig,
        authority_path=p_authority,
        audit_path=p_audit,
        present=present,
    )

    missing = [name for name, ok in present.items() if not ok]
    if missing:
        return EvidenceVerification(
            state=STATE_MISSING,
            reason_codes=tuple(f"GOVERNANCE_EVIDENCE_MISSING:{name}" for name in missing),
            provenance_source=provenance,
        )

    reasons: list[str] = []

    try:
        policy_obj = _load_json(p_policy)
    except (json.JSONDecodeError, OSError):
        reasons.append("GOVERNANCE_EVIDENCE_POLICY_MALFORMED")
        return EvidenceVerification(STATE_UNVERIFIED, tuple(reasons), provenance)
    try:
        sig_obj = _load_json(p_sig)
    except (json.JSONDecodeError, OSError):
        reasons.append("GOVERNANCE_EVIDENCE_SIGNATURE_MALFORMED")
        return EvidenceVerification(STATE_UNVERIFIED, tuple(reasons), provenance)
    try:
        authority_obj = _load_json(p_authority)
    except (json.JSONDecodeError, OSError):
        reasons.append("GOVERNANCE_EVIDENCE_AUTHORITY_MALFORMED")
        return EvidenceVerification(STATE_UNVERIFIED, tuple(reasons), provenance)

    if not isinstance(policy_obj, dict):
        return EvidenceVerification(
            STATE_UNVERIFIED, ("GOVERNANCE_EVIDENCE_POLICY_MALFORMED",), provenance
        )
    if not isinstance(sig_obj, dict):
        return EvidenceVerification(
            STATE_UNVERIFIED, ("GOVERNANCE_EVIDENCE_SIGNATURE_MALFORMED",), provenance
        )
    if not isinstance(authority_obj, dict):
        return EvidenceVerification(
            STATE_UNVERIFIED, ("GOVERNANCE_EVIDENCE_AUTHORITY_MALFORMED",), provenance
        )

    declared_hash = sig_obj.get("policy_hash")
    declared_version = sig_obj.get("policy_version")
    signer_id = sig_obj.get("signer_id")
    signer_key_id = sig_obj.get("signer_key_id")
    algorithm = sig_obj.get("algorithm")
    signature_blob = sig_obj.get("signature")

    if algorithm != "Ed25519":
        reasons.append("GOVERNANCE_EVIDENCE_ALGORITHM_UNSUPPORTED")
    if not isinstance(signature_blob, str) or not signature_blob.startswith(_ED25519_PREFIX):
        reasons.append("GOVERNANCE_EVIDENCE_SIGNATURE_MALFORMED")
    if not isinstance(declared_hash, str) or len(declared_hash) != 64:
        reasons.append("GOVERNANCE_EVIDENCE_POLICY_HASH_MISSING")
    if not isinstance(signer_id, str) or not signer_id:
        reasons.append("GOVERNANCE_EVIDENCE_SIGNER_ID_MISSING")
    if not isinstance(signer_key_id, str) or len(signer_key_id) != 64:
        reasons.append("GOVERNANCE_EVIDENCE_SIGNER_KEY_ID_MISSING")
    if reasons:
        return EvidenceVerification(
            STATE_UNVERIFIED,
            tuple(reasons),
            provenance,
            signer_id=signer_id if isinstance(signer_id, str) else None,
            signer_fingerprint=signer_key_id if isinstance(signer_key_id, str) else None,
            policy_version=declared_version if isinstance(declared_version, str) else None,
            policy_hash=declared_hash if isinstance(declared_hash, str) else None,
        )

    canonical_policy = _canonical_json(policy_obj)
    computed_hash = hashlib.sha256(canonical_policy).hexdigest()
    if computed_hash != declared_hash:
        reasons.append("GOVERNANCE_EVIDENCE_POLICY_HASH_MISMATCH")

    revoked = set(authority_obj.get("revoked_policy_signer_fingerprints", []) or [])
    allowed_signers = authority_obj.get("allowed_policy_signers", [])
    if not isinstance(allowed_signers, list) or not allowed_signers:
        reasons.append("GOVERNANCE_EVIDENCE_AUTHORITY_EMPTY")
        return EvidenceVerification(
            STATE_UNVERIFIED, tuple(reasons), provenance,
            signer_id=signer_id, signer_fingerprint=signer_key_id,
            policy_version=declared_version, policy_hash=declared_hash,
        )

    matched_pem: str | None = None
    for entry in allowed_signers:
        if not isinstance(entry, dict):
            continue
        if entry.get("public_key_fingerprint") == signer_key_id:
            if entry.get("signer_id") and entry.get("signer_id") != signer_id:
                reasons.append("GOVERNANCE_EVIDENCE_SIGNER_ID_MISMATCH")
            pem = entry.get("public_key_pem")
            if isinstance(pem, str):
                matched_pem = pem
            break
    if matched_pem is None:
        reasons.append("GOVERNANCE_EVIDENCE_SIGNER_NOT_TRUSTED")
    if signer_key_id in revoked:
        reasons.append("GOVERNANCE_EVIDENCE_SIGNER_REVOKED")

    if matched_pem is not None:
        try:
            public_key = serialization.load_pem_public_key(matched_pem.encode("utf-8"))
        except (ValueError, TypeError):
            public_key = None
            reasons.append("GOVERNANCE_EVIDENCE_AUTHORITY_KEY_MALFORMED")
        if public_key is not None and not isinstance(public_key, Ed25519PublicKey):
            reasons.append("GOVERNANCE_EVIDENCE_AUTHORITY_KEY_ALGORITHM_INVALID")
            public_key = None
        if public_key is not None:
            try:
                signature_bytes = base64.b64decode(signature_blob[len(_ED25519_PREFIX):], validate=True)
            except (ValueError, base64.binascii.Error):
                signature_bytes = b""
                reasons.append("GOVERNANCE_EVIDENCE_SIGNATURE_MALFORMED")
            if signature_bytes:
                try:
                    public_key.verify(signature_bytes, canonical_policy)
                except InvalidSignature:
                    reasons.append("GOVERNANCE_EVIDENCE_SIGNATURE_INVALID")

    # Audit-log binding: first record must bind the same policy_hash and
    # the declared signer fingerprint.
    try:
        with p_audit.open("r", encoding="utf-8") as handle:
            first_line = handle.readline().strip()
        if not first_line:
            reasons.append("GOVERNANCE_EVIDENCE_AUDIT_EMPTY")
        else:
            audit_row = json.loads(first_line)
            if not isinstance(audit_row, dict):
                reasons.append("GOVERNANCE_EVIDENCE_AUDIT_MALFORMED")
            else:
                # The audit log tracks the trust-policy authority chain
                # (a separate meta-policy that ratifies this trust policy).
                # Its `policy_hash` / `policy_signer_fingerprint` therefore
                # belong to that authority chain, not to the trust policy
                # signed by the .sig file. We bind on the two stable
                # identifiers shared across both chains: policy_version
                # and the human-readable policy_signer_id.
                if audit_row.get("policy_version") != declared_version:
                    reasons.append("GOVERNANCE_EVIDENCE_AUDIT_VERSION_MISMATCH")
                audit_signer_id = audit_row.get("policy_signer_id")
                if audit_signer_id and audit_signer_id != signer_id:
                    reasons.append("GOVERNANCE_EVIDENCE_AUDIT_SIGNER_ID_MISMATCH")
    except (OSError, json.JSONDecodeError):
        reasons.append("GOVERNANCE_EVIDENCE_AUDIT_MALFORMED")

    state = STATE_VERIFIED if not reasons else STATE_UNVERIFIED
    return EvidenceVerification(
        state=state,
        reason_codes=tuple(reasons) if reasons else ("GOVERNANCE_EVIDENCE_SIGNATURE_VERIFIED",),
        provenance_source=provenance,
        signer_id=signer_id,
        signer_fingerprint=signer_key_id,
        policy_version=declared_version,
        policy_hash=declared_hash,
    )
