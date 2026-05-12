from __future__ import annotations

from typing import Any

from governance.interfaces import GovernanceValidationResult


def validate_trust_policy_interface(payload: dict[str, Any]) -> GovernanceValidationResult:
    """Validate trust-policy shape at the trust boundary.

    Governance scope: public signer entries, signer IDs, fingerprints, and
    validity windows. Signature, audit-chain, and public-key fingerprint checks
    remain in the trust-policy governance verifier.
    Fail-closed expectation: malformed policy shape denies signer trust.
    Sensitive-data handling: trust policies must contain public material only.
    """

    failures: list[str] = []
    if not isinstance(payload, dict):
        return GovernanceValidationResult(False, ("EVIDENCE_TRUST_POLICY_INVALID",))
    if not payload.get("policy_version"):
        failures.append("EVIDENCE_TRUST_POLICY_VERSION_MISSING")
    allowed = payload.get("allowed_signers")
    if not isinstance(allowed, list) or not allowed:
        failures.append("EVIDENCE_TRUST_POLICY_EMPTY")
        allowed = []
    for index, entry in enumerate(allowed):
        if not isinstance(entry, dict):
            failures.append(f"EVIDENCE_TRUST_POLICY_SIGNER_INVALID:{index}")
            continue
        for field in ("signer_id", "public_key_fingerprint", "public_key_pem", "valid_from", "valid_until"):
            if not entry.get(field):
                failures.append(f"EVIDENCE_TRUST_POLICY_SIGNER_FIELD_MISSING:{index}:{field}")
    revoked = payload.get("revoked_fingerprints", [])
    if not isinstance(revoked, list):
        failures.append("EVIDENCE_TRUST_POLICY_REVOKED_INVALID")
    return GovernanceValidationResult(not failures, tuple(sorted(set(failures))))

