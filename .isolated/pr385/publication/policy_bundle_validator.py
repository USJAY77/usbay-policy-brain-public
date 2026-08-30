"""Fail-closed validation for local publication policy bundles."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from publication.models import PolicyBundleValidationResult, hash_payload


POLICY_BUNDLE_VERSION = "1.0"
POLICY_BUNDLE_VALIDATOR_VERSION = "USBAY-PUBGOV-025"

REQUIRED_POLICY_ORDER = (
    "registry_schema",
    "registry_record",
    "classification_policy",
    "approval_policy",
)

REQUIRED_POLICY_FILES = {
    "registry_schema": "publication_registry_schema.json",
    "registry_record": "publication_registry_record.example.json",
    "classification_policy": "publication_classification_policy.json",
    "approval_policy": "publication_approval_policy.json",
}


def load_publication_policy_bundle(base_path: str | Path = "policy/publication") -> dict[str, dict[str, Any]]:
    root = Path(base_path)
    bundle: dict[str, dict[str, Any]] = {}
    for name in REQUIRED_POLICY_ORDER:
        path = root / REQUIRED_POLICY_FILES[name]
        with path.open("r", encoding="utf-8") as handle:
            bundle[name] = json.load(handle)
    return bundle


def validate_policy_bundle(
    bundle: Mapping[str, Mapping[str, Any]] | None,
    *,
    expected_hashes: Mapping[str, str] | None = None,
    supported_version: str = POLICY_BUNDLE_VERSION,
) -> PolicyBundleValidationResult:
    if bundle is None:
        return _blocked(reason="MISSING_POLICY_BUNDLE", rejected_policy="BUNDLE")

    key_tuple = tuple(bundle.keys())
    if key_tuple != REQUIRED_POLICY_ORDER:
        missing = tuple(name for name in REQUIRED_POLICY_ORDER if name not in bundle)
        if missing:
            return _blocked(reason="MISSING_POLICY", rejected_policy=missing[0])
        if len(set(key_tuple)) != len(key_tuple):
            return _blocked(reason="DUPLICATE_POLICY", rejected_policy="BUNDLE")
        return _blocked(reason="POLICY_ORDER_INVALID", rejected_policy="BUNDLE")

    policy_ids = tuple(_policy_identifier(name, dict(bundle[name])) for name in REQUIRED_POLICY_ORDER)
    if len(set(policy_ids)) != len(policy_ids):
        return _blocked(reason="DUPLICATE_POLICY", rejected_policy="BUNDLE")

    for name in REQUIRED_POLICY_ORDER:
        policy = dict(bundle[name])
        field_result = _validate_required_fields(name, policy, supported_version=supported_version)
        if field_result is not None:
            return field_result

    dependency_result = _validate_dependency_consistency(bundle, supported_version=supported_version)
    if dependency_result is not None:
        return dependency_result

    hash_result = _validate_expected_hashes(bundle, expected_hashes)
    if hash_result is not None:
        return hash_result

    bundle_evidence = _bundle_evidence(bundle)
    bundle_hash = hash_payload(bundle_evidence)
    return _result(
        valid=True,
        reason="POLICY_BUNDLE_VALID",
        rejected_policy="",
        policy_version=supported_version,
        bundle_hash=bundle_hash,
        evidence_payload={
            "bundle_hash": bundle_hash,
            "policy_order": REQUIRED_POLICY_ORDER,
            "policy_ids": policy_ids,
            "policy_version": supported_version,
            "raw_policy_content_stored": False,
        },
    )


def _validate_required_fields(
    name: str,
    policy: Mapping[str, Any],
    *,
    supported_version: str,
) -> PolicyBundleValidationResult | None:
    if name == "registry_schema":
        required = ("$schema", "$id", "type", "required", "properties")
        if any(field not in policy for field in required):
            return _blocked(reason="MALFORMED_SCHEMA", rejected_policy=name)
        if not isinstance(policy.get("required"), list) or not isinstance(policy.get("properties"), dict):
            return _blocked(reason="MALFORMED_SCHEMA", rejected_policy=name)
        return None

    if name == "registry_record":
        required = ("artifact_id", "target_channel", "classification", "version", "policy_version")
        if any(not policy.get(field) for field in required):
            return _blocked(reason="MALFORMED_SCHEMA", rejected_policy=name)
        if policy.get("policy_version") != supported_version:
            return _blocked(reason="VERSION_MISMATCH", rejected_policy=name)
        return None

    required = ("policy_id", "version", "status", "mode")
    if any(not policy.get(field) for field in required):
        return _blocked(reason="MALFORMED_SCHEMA", rejected_policy=name)
    if policy.get("version") != supported_version:
        return _blocked(reason="VERSION_MISMATCH", rejected_policy=name)
    if policy.get("mode") != "fail_closed":
        return _blocked(reason="MALFORMED_SCHEMA", rejected_policy=name)
    return None


def _validate_dependency_consistency(
    bundle: Mapping[str, Mapping[str, Any]],
    *,
    supported_version: str,
) -> PolicyBundleValidationResult | None:
    schema = bundle["registry_schema"]
    record = bundle["registry_record"]
    classification_policy = bundle["classification_policy"]
    approval_policy = bundle["approval_policy"]

    required_fields = set(schema.get("required", ()))
    missing_record_fields = tuple(field for field in required_fields if field not in record)
    if missing_record_fields:
        return _blocked(reason="DEPENDENCY_INCONSISTENT", rejected_policy="registry_record")

    allowed_classes = set(classification_policy.get("allowed_classes", ()))
    if record.get("classification") not in allowed_classes:
        return _blocked(reason="DEPENDENCY_INCONSISTENT", rejected_policy="classification_policy")

    publish_eligible_classes = set(classification_policy.get("publish_eligible_classes", ()))
    if record.get("classification") not in publish_eligible_classes:
        return _blocked(reason="DEPENDENCY_INCONSISTENT", rejected_policy="classification_policy")

    approval_states = set(approval_policy.get("approval_states", ()))
    if "APPROVED" not in approval_states or not approval_policy.get("human_approval_required"):
        return _blocked(reason="DEPENDENCY_INCONSISTENT", rejected_policy="approval_policy")

    if record.get("policy_version") != supported_version:
        return _blocked(reason="VERSION_MISMATCH", rejected_policy="registry_record")
    return None


def _validate_expected_hashes(
    bundle: Mapping[str, Mapping[str, Any]],
    expected_hashes: Mapping[str, str] | None,
) -> PolicyBundleValidationResult | None:
    if expected_hashes is None:
        return None
    for name in REQUIRED_POLICY_ORDER:
        expected_hash = expected_hashes.get(name)
        if not expected_hash or expected_hash != hash_payload(dict(bundle[name])):
            return _blocked(reason="HASH_MISMATCH", rejected_policy=name)
    return None


def _policy_identifier(name: str, policy: Mapping[str, Any]) -> str:
    if name == "registry_schema":
        return str(policy.get("$id", "MISSING_SCHEMA_ID"))
    if name == "registry_record":
        return str(policy.get("artifact_id", "MISSING_ARTIFACT_ID"))
    return str(policy.get("policy_id", f"MISSING_POLICY_ID:{name}"))


def _bundle_evidence(bundle: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "policy_order": REQUIRED_POLICY_ORDER,
        "policy_hashes": tuple((name, hash_payload(dict(bundle[name]))) for name in REQUIRED_POLICY_ORDER),
        "raw_policy_content_stored": False,
    }


def _blocked(
    *,
    reason: str,
    rejected_policy: str,
    policy_version: str = POLICY_BUNDLE_VALIDATOR_VERSION,
) -> PolicyBundleValidationResult:
    return _result(
        valid=False,
        reason=reason,
        rejected_policy=rejected_policy,
        policy_version=policy_version,
        bundle_hash="",
        evidence_payload={
            "reason": reason,
            "rejected_policy": rejected_policy,
            "policy_version": policy_version,
            "raw_policy_content_stored": False,
        },
    )


def _result(
    *,
    valid: bool,
    reason: str,
    rejected_policy: str,
    policy_version: str,
    bundle_hash: str,
    evidence_payload: dict[str, Any],
) -> PolicyBundleValidationResult:
    return PolicyBundleValidationResult(
        valid=valid,
        policy_version=policy_version,
        bundle_hash=bundle_hash,
        rejected_policy=rejected_policy,
        reason=reason,
        evidence_hash=hash_payload(evidence_payload),
    )
