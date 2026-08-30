"""Canonical cross-repository publication of the Gateway Authorization Request contract.

Publishes ``usbay.enforcement_gateway.authorization_request.v1`` — the exact
contract merged in PR #316 (`governance/euria_gateway_authorization_request.py`
plus its canonical schema) — through the existing cross-repository contract
registry so an independent Enforcement Gateway checkout can pin
``contract_id`` / ``version`` / ``canonical hash`` and verify them
deterministically.

The publication is metadata-only. It never grants execution authority.
All validation is fail-closed: any missing file, malformed payload, field
drift, hash mismatch, version mismatch, or authority-invariant violation
raises :class:`CrossRepositoryContractError`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from governance.cross_repository_contracts import (
    CrossRepositoryContractError,
    _load_json,
    _require_hash_contract,
    canonical_contract_hash,
)

PUBLICATION_PATH = "governance/contracts/gateway_authorization_request_v1_publication.json"
REGISTRY_PATH = "governance/contracts/cross_repository_contract_registry.json"

SUPPORTED_PUBLICATION_SCHEMA_VERSION = "usbay.cross_repo.contract_publication.v1"
CANONICAL_CONTRACT_ID = "usbay.enforcement_gateway.authorization_request.v1"
CANONICAL_CONTRACT_VERSION = "v1"

_PUBLICATION_REQUIRED_FIELDS = {
    "publication_schema_version",
    "contract_id",
    "contract_version",
    "immutable",
    "canonical_schema_path",
    "canonical_schema_hash",
    "producer_schema_path",
    "producer_contract_version",
    "producer_module",
    "producer_authority",
    "compatibility_target",
    "hash_contract",
    "request_hash_rule",
    "publication_metadata",
    "authority_invariants",
}

_REQUIRED_FALSE_INVARIANTS = (
    "grants_execution_authority",
    "execution_authorized",
    "runtime_allow",
    "policy_brain_execution_authority",
    "euria_execution_authority",
    "euria_policy_authority",
    "euria_approval_authority",
    "euria_deployment_authority",
)


def validate_gateway_authorization_contract_publication(root: Path = Path(".")) -> dict[str, Any]:
    """Validate the canonical publication end to end. Fail closed on any doubt."""
    publication = _load_json(root, PUBLICATION_PATH)

    fields = set(publication.keys())
    if fields != _PUBLICATION_REQUIRED_FIELDS:
        raise CrossRepositoryContractError(
            "PUBLICATION_FIELD_DRIFT", "Publication fields do not match the canonical field set"
        )
    if publication["publication_schema_version"] != SUPPORTED_PUBLICATION_SCHEMA_VERSION:
        raise CrossRepositoryContractError(
            "PUBLICATION_VERSION_UNSUPPORTED", "Publication schema version is unsupported"
        )
    if publication["contract_id"] != CANONICAL_CONTRACT_ID:
        raise CrossRepositoryContractError(
            "PUBLICATION_CONTRACT_ID_MISMATCH", "Publication contract id is not canonical"
        )
    if publication["contract_version"] != CANONICAL_CONTRACT_VERSION:
        raise CrossRepositoryContractError(
            "PUBLICATION_CONTRACT_VERSION_MISMATCH", "Publication contract version is not canonical v1"
        )
    if publication["immutable"] is not True:
        raise CrossRepositoryContractError(
            "PUBLICATION_NOT_IMMUTABLE", "Canonical publication must be immutable"
        )
    _require_hash_contract(publication["hash_contract"])

    invariants = publication["authority_invariants"]
    if not isinstance(invariants, Mapping):
        raise CrossRepositoryContractError(
            "PUBLICATION_AUTHORITY_INVALID", "Authority invariants are malformed"
        )
    for key in _REQUIRED_FALSE_INVARIANTS:
        if invariants.get(key) is not False:
            raise CrossRepositoryContractError(
                "PUBLICATION_GRANTS_AUTHORITY", f"Authority invariant {key} must be exactly false"
            )
    if invariants.get("enforcement_gateway_final_authority") is not True:
        raise CrossRepositoryContractError(
            "PUBLICATION_AUTHORITY_INVALID", "Enforcement Gateway must remain the final authority"
        )

    # Recompute the canonical schema hash from the referenced artifact.
    schema_path = publication["canonical_schema_path"]
    if not isinstance(schema_path, str) or not schema_path:
        raise CrossRepositoryContractError(
            "PUBLICATION_SCHEMA_PATH_INVALID", "Canonical schema path is invalid"
        )
    schema_payload = _load_json(root, schema_path)
    actual_schema_hash = canonical_contract_hash(schema_payload)
    if actual_schema_hash != publication["canonical_schema_hash"]:
        raise CrossRepositoryContractError(
            "PUBLICATION_SCHEMA_HASH_MISMATCH",
            "Canonical schema hash does not match the referenced schema artifact",
        )

    # Bind the published artifact to the exact PR #316 producer schema when it
    # is present in this checkout: the two must be hash-identical. A missing
    # producer schema in a partial checkout is tolerated because the canonical
    # artifact above is already hash-pinned by the registry.
    producer_schema_path = publication["producer_schema_path"]
    if not isinstance(producer_schema_path, str) or not producer_schema_path:
        raise CrossRepositoryContractError(
            "PUBLICATION_SCHEMA_PATH_INVALID", "Producer schema path is invalid"
        )
    if (root / producer_schema_path).exists():
        producer_hash = canonical_contract_hash(_load_json(root, producer_schema_path))
        if producer_hash != actual_schema_hash:
            raise CrossRepositoryContractError(
                "PUBLICATION_SCHEMA_DIVERGENCE",
                "Canonical publication schema diverges from the PR #316 producer schema",
            )

    # The registry must pin BOTH the publication artifact and the schema, and
    # the pinned hashes must match recomputation (immutability control: a
    # mutated artifact cannot masquerade as canonical v1).
    registry = _load_json(root, REGISTRY_PATH)
    schema_hashes = registry.get("canonical_schema_hashes")
    if not isinstance(schema_hashes, Mapping):
        raise CrossRepositoryContractError(
            "REGISTRY_PIN_MISSING", "Registry canonical schema hashes are missing"
        )
    publication_pin = schema_hashes.get("gateway_authorization_request_v1_publication")
    schema_pin = schema_hashes.get("gateway_authorization_request_v1_schema")
    if not isinstance(publication_pin, Mapping) or not isinstance(schema_pin, Mapping):
        raise CrossRepositoryContractError(
            "REGISTRY_PIN_MISSING", "Registry does not pin the canonical publication"
        )
    if publication_pin.get("path") != PUBLICATION_PATH or schema_pin.get("path") != schema_path:
        raise CrossRepositoryContractError(
            "REGISTRY_PIN_PATH_MISMATCH", "Registry pin paths do not match the canonical artifacts"
        )
    actual_publication_hash = canonical_contract_hash(publication)
    if publication_pin.get("hash") != actual_publication_hash:
        raise CrossRepositoryContractError(
            "REGISTRY_PIN_HASH_MISMATCH", "Registry publication pin does not match recomputed hash"
        )
    if schema_pin.get("hash") != actual_schema_hash:
        raise CrossRepositoryContractError(
            "REGISTRY_PIN_HASH_MISMATCH", "Registry schema pin does not match recomputed hash"
        )

    return {
        "status": "PASS",
        "contract_id": CANONICAL_CONTRACT_ID,
        "contract_version": CANONICAL_CONTRACT_VERSION,
        "canonical_schema_path": schema_path,
        "canonical_schema_hash": actual_schema_hash,
        "publication_hash": actual_publication_hash,
        "execution_authorized": False,
        "runtime_allow": False,
    }


def resolve_canonical_contract(
    contract_id: str,
    contract_version: str,
    root: Path = Path("."),
    *,
    expected_schema_hash: str | None = None,
    expected_publication_hash: str | None = None,
) -> dict[str, Any]:
    """Consumer-facing resolution: pin exactly (contract_id, version, hash).

    Unknown contract id or version fails closed.

    An INDEPENDENT checkout must supply its out-of-band pinned
    ``expected_schema_hash`` (and optionally ``expected_publication_hash``).
    Hashes recomputed from a checkout are trustworthy against unilateral
    drift only; a coordinated artifact+registry mutation inside a hostile
    checkout can only be detected against the consumer's own pin, so a
    mismatch with the supplied pins fails closed."""
    if contract_id != CANONICAL_CONTRACT_ID:
        raise CrossRepositoryContractError(
            "CONTRACT_UNKNOWN", "Requested contract id is not canonically published"
        )
    if contract_version != CANONICAL_CONTRACT_VERSION:
        raise CrossRepositoryContractError(
            "CONTRACT_VERSION_UNKNOWN", "Requested contract version is not canonically published"
        )
    validated = validate_gateway_authorization_contract_publication(root)
    if expected_schema_hash is not None and expected_schema_hash != validated["canonical_schema_hash"]:
        raise CrossRepositoryContractError(
            "CONTRACT_PIN_MISMATCH",
            "Canonical schema hash does not match the consumer-pinned hash",
        )
    if expected_publication_hash is not None and expected_publication_hash != validated["publication_hash"]:
        raise CrossRepositoryContractError(
            "CONTRACT_PIN_MISMATCH",
            "Publication hash does not match the consumer-pinned hash",
        )
    return {
        "contract_id": validated["contract_id"],
        "contract_version": validated["contract_version"],
        "canonical_schema_path": validated["canonical_schema_path"],
        "canonical_schema_hash": validated["canonical_schema_hash"],
        "publication_hash": validated["publication_hash"],
        "execution_authorized": False,
        "runtime_allow": False,
    }
