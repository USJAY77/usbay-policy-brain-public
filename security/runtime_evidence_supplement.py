"""Non-production detached-evidence verification contract PROPOSAL.

Generated evidence is not inserted into committed source or the v1 source
manifest. This verifier authenticates a separate signed claim and its exact
source-artifact link, using existing independently supplied producer trust.
It issues no authority, performs no signing and changes no producer policy.

Authenticity is not truth, freshness, authorization or image/runtime parity.
The current clean-source builder remains unchanged and does not emit this form.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from security.runtime_artifact_authority import load_runtime_artifact_authority
from security.runtime_artifact_provenance import (
    ProducerTrust, RuntimeArtifactError, canonical_bytes, manifest_digest,
    signature_payload, _decode_base64, _pairs_without_duplicates, _reject_constant,
)

SCHEMA = "usbay.non_production_runtime_evidence_supplement.proposal.v1"
PURPOSE = "non_production_evidence_review"
MAX_BYTES = 65536
FIELDS = {
    "schema_version", "purpose", "producer_key_id", "producer_scope",
    "source_artifact_digest", "source_commit", "source_tree_reference",
    "evidence_references", "manifest_digest", "signature",
}
REFERENCE_FIELDS = {"python", "dependencies", "lock", "source_overlay", "image_claim"}
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def _require(value, code="runtime_supplement_invalid"):
    if not value:
        raise RuntimeArtifactError(code)


@dataclass(frozen=True)
class AuthenticatedEvidenceSupplement:
    source_artifact_digest: str
    supplement_digest: str
    evidence_references_digest: str
    source_commit: str
    source_tree_reference: str
    # These fixed limits cannot be enabled by a constructor/caller option.
    status: str = field(default="AUTHENTICATED_CLAIM_ONLY", init=False)
    contract_status: str = field(default="PROPOSAL_REVIEW_REQUIRED", init=False)
    execution_authorized: bool = field(default=False, init=False)
    evidence_truth_verified: bool = field(default=False, init=False)
    freshness_verified: bool = field(default=False, init=False)
    image_identity_verified: bool = field(default=False, init=False)
    runtime_equivalence_proven: bool = field(default=False, init=False)


def verify_evidence_supplement(raw: bytes, artifact_root: Path, *,
                               trust: ProducerTrust, expected_source_commit: str,
                               expected_source_tree: str) -> AuthenticatedEvidenceSupplement:
    """Verify a detached claim without creating files or modifying authority.

    The expected source pins are comparison constraints, not grants. Both the
    source artifact and supplement must verify under the same existing test
    producer. Production mode/scope is rejected before any artifact access.
    No claim-reference digest is treated as proof of the referenced claim.
    """
    try:
        _require(type(trust) is ProducerTrust and trust.mode == "test"
                 and trust.producer_scope == "test", "runtime_supplement_non_production_only")
        trust.validate()
        _require(type(expected_source_commit) is str and _COMMIT.fullmatch(expected_source_commit)
                 and type(expected_source_tree) is str and _COMMIT.fullmatch(expected_source_tree))
        _require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES,
                 "runtime_supplement_size_invalid")
        data = json.loads(raw.decode("utf-8", errors="strict"),
                          object_pairs_hook=_pairs_without_duplicates,
                          parse_constant=_reject_constant)
        _require(type(data) is dict and set(data) == FIELDS)
        _require(data["schema_version"] == SCHEMA and data["purpose"] == PURPOSE,
                 "runtime_supplement_contract_mismatch")
        _require(data["producer_key_id"] == trust.key_id
                 and data["producer_scope"] == trust.producer_scope,
                 "runtime_supplement_producer_mismatch")
        signature = _decode_base64(data["signature"], 64, "runtime_supplement_signature_invalid")
        try:
            Ed25519PublicKey.from_public_bytes(trust.public_key).verify(signature, signature_payload(data))
        except (InvalidSignature, ValueError):
            raise RuntimeArtifactError("runtime_supplement_signature_invalid") from None
        _require(data["manifest_digest"] == manifest_digest(data),
                 "runtime_supplement_digest_mismatch")
        references = data["evidence_references"]
        _require(type(references) is dict and set(references) == REFERENCE_FIELDS)
        for name, value in references.items():
            _require((name == "image_claim" and value is None)
                     or (type(value) is str and _SHA.fullmatch(value)),
                     "runtime_supplement_reference_invalid")
        _require(data["source_commit"] == expected_source_commit
                 and data["source_tree_reference"] == expected_source_tree,
                 "runtime_supplement_source_mismatch")
        authority = load_runtime_artifact_authority(artifact_root, trust=trust)
        _require(authority.verified.source_commit == expected_source_commit
                 and authority.verified.source_tree_reference == expected_source_tree
                 and data["source_artifact_digest"] == authority.verified.manifest_digest,
                 "runtime_supplement_artifact_mismatch")
        authority.assert_fresh()
        return AuthenticatedEvidenceSupplement(
            authority.verified.manifest_digest, data["manifest_digest"],
            hashlib.sha256(canonical_bytes(references)).hexdigest(),
            expected_source_commit, expected_source_tree)
    except RuntimeArtifactError:
        raise
    except Exception:
        raise RuntimeArtifactError("runtime_supplement_invalid") from None
