from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from governance.cross_repository_contracts import (
    CrossRepositoryContractError,
    canonical_contract_hash,
    canonical_contract_json,
    validate_registry,
)
from governance.gateway_authorization_contract_publication import (
    CANONICAL_CONTRACT_ID,
    CANONICAL_CONTRACT_VERSION,
    PUBLICATION_PATH,
    REGISTRY_PATH,
    resolve_canonical_contract,
    validate_gateway_authorization_contract_publication,
)

SCHEMA_PATH = "governance/contracts/gateway_authorization_request_v1.schema.json"
PRODUCER_SCHEMA_PATH = "governance/evidence/euria_gateway_authorization_request_v1_schema.json"

SENSITIVE_MARKERS = (
    "pass" + "word",
    "sec" + "ret",
    "cred" + "ential",
    "api" + "_key",
    "private" + "_key",
    "access" + "_token",
    "refresh" + "_token",
    "bearer ",
)


def _copy_tree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    for relative in (PUBLICATION_PATH, REGISTRY_PATH, SCHEMA_PATH):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(Path(relative), target)
    return root


def _rewrite(root: Path, relative: str, mutate) -> None:
    path = root / relative
    payload = json.loads(path.read_text(encoding="utf-8"))
    mutate(payload)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_canonical_v1_resolves_successfully() -> None:
    result = validate_gateway_authorization_contract_publication(Path("."))

    assert result["status"] == "PASS"
    assert result["contract_id"] == "usbay.enforcement_gateway.authorization_request.v1"
    assert result["contract_version"] == "v1"
    assert result["canonical_schema_hash"].startswith("sha256:")
    assert result["publication_hash"].startswith("sha256:")


def test_expected_schema_hash_matches_registry_pin_and_artifact() -> None:
    publication = json.loads(Path(PUBLICATION_PATH).read_text(encoding="utf-8"))
    schema = json.loads(Path(SCHEMA_PATH).read_text(encoding="utf-8"))
    registry = json.loads(Path(REGISTRY_PATH).read_text(encoding="utf-8"))

    recomputed = canonical_contract_hash(schema)
    assert publication["canonical_schema_hash"] == recomputed
    pins = registry["canonical_schema_hashes"]
    assert pins["gateway_authorization_request_v1_schema"]["hash"] == recomputed
    assert pins["gateway_authorization_request_v1_publication"]["hash"] == canonical_contract_hash(
        publication
    )


def test_registry_still_validates_with_new_pins() -> None:
    result = validate_registry(Path("."))

    assert result["status"] == "PASS"
    assert result["production_ready"] is False


def test_altered_schema_fails_verification(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _rewrite(root, SCHEMA_PATH, lambda schema: schema["properties"].update({"injected": {"type": "string"}}))

    with pytest.raises(CrossRepositoryContractError) as exc:
        validate_gateway_authorization_contract_publication(root)

    assert exc.value.code == "PUBLICATION_SCHEMA_HASH_MISMATCH"


def test_altered_publication_cannot_masquerade_as_v1(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _rewrite(
        root,
        PUBLICATION_PATH,
        lambda pub: pub["publication_metadata"].update({"published_at": "2030-01-01T00:00:00Z"}),
    )

    with pytest.raises(CrossRepositoryContractError) as exc:
        validate_gateway_authorization_contract_publication(root)

    assert exc.value.code == "REGISTRY_PIN_HASH_MISMATCH"


def test_altered_version_fails_verification(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _rewrite(root, PUBLICATION_PATH, lambda pub: pub.update({"contract_version": "v2"}))

    with pytest.raises(CrossRepositoryContractError) as exc:
        validate_gateway_authorization_contract_publication(root)

    assert exc.value.code == "PUBLICATION_CONTRACT_VERSION_MISMATCH"


def test_altered_contract_id_fails_verification(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _rewrite(root, PUBLICATION_PATH, lambda pub: pub.update({"contract_id": "usbay.other.contract.v1"}))

    with pytest.raises(CrossRepositoryContractError) as exc:
        validate_gateway_authorization_contract_publication(root)

    assert exc.value.code == "PUBLICATION_CONTRACT_ID_MISMATCH"


def test_field_drift_fails_closed(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _rewrite(root, PUBLICATION_PATH, lambda pub: pub.update({"extra_field": True}))

    with pytest.raises(CrossRepositoryContractError) as exc:
        validate_gateway_authorization_contract_publication(root)

    assert exc.value.code == "PUBLICATION_FIELD_DRIFT"


def test_missing_registry_pin_fails_closed(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _rewrite(
        root,
        REGISTRY_PATH,
        lambda reg: reg["canonical_schema_hashes"].pop("gateway_authorization_request_v1_publication"),
    )

    with pytest.raises(CrossRepositoryContractError) as exc:
        validate_gateway_authorization_contract_publication(root)

    assert exc.value.code == "REGISTRY_PIN_MISSING"


def test_unknown_contract_fails_closed() -> None:
    with pytest.raises(CrossRepositoryContractError) as exc:
        resolve_canonical_contract("usbay.unknown.contract.v1", "v1")
    assert exc.value.code == "CONTRACT_UNKNOWN"

    with pytest.raises(CrossRepositoryContractError) as exc:
        resolve_canonical_contract(CANONICAL_CONTRACT_ID, "v2")
    assert exc.value.code == "CONTRACT_VERSION_UNKNOWN"


def test_canonical_serialization_is_deterministic() -> None:
    left = {"b": [1, 2], "a": {"y": 1, "x": 2}}
    right = {"a": {"x": 2, "y": 1}, "b": [1, 2]}

    assert canonical_contract_json(left) == canonical_contract_json(right)
    assert canonical_contract_hash(left) == canonical_contract_hash(right)


def test_consumer_can_pin_contract_id_version_hash() -> None:
    pinned = resolve_canonical_contract(CANONICAL_CONTRACT_ID, CANONICAL_CONTRACT_VERSION)

    assert pinned["contract_id"] == CANONICAL_CONTRACT_ID
    assert pinned["contract_version"] == CANONICAL_CONTRACT_VERSION
    assert pinned["canonical_schema_hash"].startswith("sha256:")
    assert pinned["publication_hash"].startswith("sha256:")


def test_publication_does_not_create_execution_authority() -> None:
    publication = json.loads(Path(PUBLICATION_PATH).read_text(encoding="utf-8"))
    invariants = publication["authority_invariants"]

    for key in (
        "grants_execution_authority",
        "execution_authorized",
        "runtime_allow",
        "policy_brain_execution_authority",
        "euria_execution_authority",
        "euria_policy_authority",
        "euria_approval_authority",
        "euria_deployment_authority",
    ):
        assert invariants[key] is False
    assert invariants["enforcement_gateway_final_authority"] is True

    result = validate_gateway_authorization_contract_publication(Path("."))
    assert result["execution_authorized"] is False
    assert result["runtime_allow"] is False


def test_authority_flip_blocks(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)

    def flip(pub):
        pub["authority_invariants"]["grants_execution_authority"] = True

    _rewrite(root, PUBLICATION_PATH, flip)

    with pytest.raises(CrossRepositoryContractError) as exc:
        validate_gateway_authorization_contract_publication(root)

    assert exc.value.code == "PUBLICATION_GRANTS_AUTHORITY"


def test_no_sensitive_data_in_registry_metadata() -> None:
    for relative in (PUBLICATION_PATH, REGISTRY_PATH):
        text = Path(relative).read_text(encoding="utf-8").lower()
        for marker in SENSITIVE_MARKERS:
            assert marker not in text, f"{relative} contains sensitive marker {marker!r}"


def test_coordinated_artifact_and_registry_mutation_fails_consumer_pin(tmp_path: Path) -> None:
    # Attacker mutates the schema AND updates the registry pin consistently:
    # local validation alone passes, but a consumer holding an out-of-band
    # pinned hash must still detect the mutation and fail closed.
    trusted = resolve_canonical_contract(CANONICAL_CONTRACT_ID, CANONICAL_CONTRACT_VERSION)

    root = _copy_tree(tmp_path)
    schema_file = root / SCHEMA_PATH
    schema = json.loads(schema_file.read_text(encoding="utf-8"))
    schema["properties"]["injected"] = {"type": "string"}
    schema_file.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    new_schema_hash = canonical_contract_hash(schema)
    _rewrite(root, PUBLICATION_PATH, lambda pub: pub.update({"canonical_schema_hash": new_schema_hash}))
    publication = json.loads((root / PUBLICATION_PATH).read_text(encoding="utf-8"))

    def repin(reg):
        reg["canonical_schema_hashes"]["gateway_authorization_request_v1_schema"]["hash"] = new_schema_hash
        reg["canonical_schema_hashes"]["gateway_authorization_request_v1_publication"]["hash"] = (
            canonical_contract_hash(publication)
        )

    _rewrite(root, REGISTRY_PATH, repin)

    # Local-only validation cannot detect the coordinated mutation...
    assert validate_gateway_authorization_contract_publication(root)["status"] == "PASS"

    # ...but the consumer's out-of-band pin does, and resolution fails closed.
    with pytest.raises(CrossRepositoryContractError) as exc:
        resolve_canonical_contract(
            CANONICAL_CONTRACT_ID,
            CANONICAL_CONTRACT_VERSION,
            root,
            expected_schema_hash=trusted["canonical_schema_hash"],
        )
    assert exc.value.code == "CONTRACT_PIN_MISMATCH"

    with pytest.raises(CrossRepositoryContractError) as exc:
        resolve_canonical_contract(
            CANONICAL_CONTRACT_ID,
            CANONICAL_CONTRACT_VERSION,
            root,
            expected_publication_hash=trusted["publication_hash"],
        )
    assert exc.value.code == "CONTRACT_PIN_MISMATCH"


def test_consumer_pin_matching_passes() -> None:
    trusted = resolve_canonical_contract(CANONICAL_CONTRACT_ID, CANONICAL_CONTRACT_VERSION)
    pinned = resolve_canonical_contract(
        CANONICAL_CONTRACT_ID,
        CANONICAL_CONTRACT_VERSION,
        expected_schema_hash=trusted["canonical_schema_hash"],
        expected_publication_hash=trusted["publication_hash"],
    )
    assert pinned["canonical_schema_hash"] == trusted["canonical_schema_hash"]


def test_canonical_artifact_is_hash_identical_to_pr316_schema() -> None:
    canonical = json.loads(Path(SCHEMA_PATH).read_text(encoding="utf-8"))
    producer = json.loads(Path(PRODUCER_SCHEMA_PATH).read_text(encoding="utf-8"))

    assert canonical_contract_hash(canonical) == canonical_contract_hash(producer)


def test_divergence_from_producer_schema_blocks(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    target = root / PRODUCER_SCHEMA_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    producer = json.loads(Path(PRODUCER_SCHEMA_PATH).read_text(encoding="utf-8"))
    producer["properties"]["injected"] = {"type": "string"}
    target.write_text(json.dumps(producer, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(CrossRepositoryContractError) as exc:
        validate_gateway_authorization_contract_publication(root)

    assert exc.value.code == "PUBLICATION_SCHEMA_DIVERGENCE"
