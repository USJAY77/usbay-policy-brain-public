from __future__ import annotations

import hashlib
import importlib
import json

import pytest

from governance.audit_evidence import ZERO_AUDIT_CHAIN_HASH, canonical_audit_json, sha256_audit_hash
from governance.hashing import (
    ZERO_SHA256_REFERENCE,
    canonical_json,
    is_sha256_hex,
    is_sha256_reference,
    sha256_json,
    sha256_reference,
    sha256_text,
)


def test_canonical_json_is_stable_and_ascii_ordered() -> None:
    payload = {"z": "snowman-\u2603", "a": [3, 2, 1]}

    serialized = canonical_json(payload)

    assert serialized == '{"a":[3,2,1],"z":"snowman-\\u2603"}'
    assert json.loads(serialized) == payload
    assert serialized == canonical_json({"a": [3, 2, 1], "z": "snowman-\u2603"})


def test_sha256_helpers_preserve_hex_and_reference_contracts() -> None:
    payload = {"b": 2, "a": 1}

    digest = sha256_json(payload)
    reference = sha256_reference(payload)

    assert digest == sha256_text(canonical_json(payload))
    assert is_sha256_hex(digest)
    assert reference == "sha256:" + digest
    assert is_sha256_reference(reference)


def test_audit_evidence_hashing_remains_backward_compatible() -> None:
    payload = {"result": "PASS", "validator": "evidence"}

    assert canonical_audit_json(payload) == canonical_json(payload)
    assert sha256_audit_hash(payload) == sha256_reference(payload)
    assert ZERO_AUDIT_CHAIN_HASH == ZERO_SHA256_REFERENCE


def test_invalid_hash_references_fail_closed() -> None:
    assert is_sha256_reference("sha256:" + ("a" * 64))
    assert not is_sha256_reference("sha256:" + ("A" * 64))
    assert not is_sha256_reference("sha256:" + ("a" * 63))
    assert not is_sha256_reference("a" * 64)
    assert not is_sha256_reference("")
    assert not is_sha256_reference(None)


def test_default_to_str_preserves_legacy_contract_for_non_json_values() -> None:
    class Marker:
        def __str__(self) -> str:
            return "marker"

    assert canonical_json({"marker": Marker()}, default_to_str=True) == '{"marker":"marker"}'


@pytest.mark.parametrize(
    "module_name",
    (
        "governance.runtime.agent_runtime",
        "governance.runtime.runtime_health",
        "governance.runtime.runtime_coordinator",
        "governance.runtime.runtime_evidence_aggregator",
        "governance.runtime.runtime_policy_binding",
        "governance.runtime.runtime_approval_gate",
        "governance.runtime.runtime_replay_verifier",
        "governance.runtime.runtime_release_gate_adapter",
        "governance.runtime.human_approval_gateway",
    ),
)
def test_migrated_runtime_canonical_hash_wrappers_preserve_legacy_output(module_name: str) -> None:
    class Marker:
        def __str__(self) -> str:
            return "legacy-marker"

    payload = {"z": Marker(), "a": ["tenant", 7]}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    expected = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    module = importlib.import_module(module_name)

    assert module._canonical_hash(payload) == expected
