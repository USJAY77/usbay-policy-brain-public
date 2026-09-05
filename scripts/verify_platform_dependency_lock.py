#!/usr/bin/env python3
"""Offline, fail-closed validator for governed platform dependency locks."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from governance.dependency_artifact_provenance import (
    EligibilityDecision,
    UnavailableArtifactAttestationVerifier,
    evaluate_artifact_evidence,
)


HASH_PATTERN = re.compile(r"--hash=sha256:([0-9a-f]{64})(?:\s|$)")
REQUIREMENT_PATTERN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s]+)(.*)$")


@dataclass(frozen=True)
class LockedRequirement:
    name: str
    version: str
    hashes: tuple[str, ...]


@dataclass(frozen=True)
class LockValidationResult:
    valid: bool
    decision: str
    reason_codes: tuple[str, ...]


def normalize_project_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def parse_hash_locked_requirements(text: str) -> dict[str, LockedRequirement]:
    logical_lines: list[str] = []
    pending = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        continuation = stripped.endswith("\\")
        piece = stripped[:-1].strip() if continuation else stripped
        pending = f"{pending} {piece}".strip()
        if not continuation:
            logical_lines.append(pending)
            pending = ""
    if pending:
        raise ValueError("DEPENDENCY_ARTIFACT_LOCK_MALFORMED")

    locked: dict[str, LockedRequirement] = {}
    for line in logical_lines:
        match = REQUIREMENT_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError("DEPENDENCY_ARTIFACT_LOCK_MALFORMED")
        raw_name, version, remainder = match.groups()
        hashes = tuple(HASH_PATTERN.findall(remainder))
        without_hashes = HASH_PATTERN.sub("", remainder).strip()
        if not hashes or without_hashes:
            raise ValueError("DEPENDENCY_ARTIFACT_LOCK_MALFORMED")
        name = normalize_project_name(raw_name)
        if name in locked or not version or any(token in version for token in (";", "@", "/", "\\")):
            raise ValueError("DEPENDENCY_ARTIFACT_LOCK_MALFORMED")
        locked[name] = LockedRequirement(name, version, tuple(sorted(set(hashes))))
    if not locked:
        raise ValueError("DEPENDENCY_ARTIFACT_LOCK_MALFORMED")
    return locked


def validate_lock_parity(
    linux: Mapping[str, LockedRequirement],
    macos: Mapping[str, LockedRequirement],
    policy: Mapping[str, Any],
) -> LockValidationResult:
    reasons: list[str] = []
    parity = policy.get("parity", {})
    exceptions = {
        (normalize_project_name(str(item.get("package", ""))), str(item.get("side", "")), str(item.get("version", "")))
        for item in parity.get("platform_exceptions", [])
        if isinstance(item, Mapping) and item.get("approval_id")
    }
    for name in sorted(set(linux) | set(macos)):
        left = linux.get(name)
        right = macos.get(name)
        if left is not None and right is not None:
            if parity.get("shared_versions_must_match") is True and left.version != right.version:
                reasons.append("DEPENDENCY_ARTIFACT_UNAUTHORIZED_PLATFORM_EXCEPTION")
            continue
        side = "linux-only" if left is not None else "macos-only"
        version = left.version if left is not None else right.version  # type: ignore[union-attr]
        if (name, side, version) not in exceptions:
            reasons.append("DEPENDENCY_ARTIFACT_UNAUTHORIZED_PLATFORM_EXCEPTION")
    return _result(reasons)


def validate_platform_lock(
    *,
    linux_text: str,
    macos_text: str,
    manifest: Mapping[str, Any],
    records: Mapping[str, Mapping[str, Any]],
    decisions: Mapping[str, EligibilityDecision],
    policy: Mapping[str, Any],
) -> LockValidationResult:
    reasons: list[str] = []
    try:
        linux = parse_hash_locked_requirements(linux_text)
        macos = parse_hash_locked_requirements(macos_text)
    except ValueError:
        return _result(["DEPENDENCY_ARTIFACT_LOCK_MALFORMED"])

    linux_hash = hashlib.sha256(linux_text.encode("utf-8")).hexdigest()
    macos_hash = hashlib.sha256(macos_text.encode("utf-8")).hexdigest()
    if linux_hash != policy.get("parity", {}).get("linux_lock_sha256"):
        reasons.append("DEPENDENCY_ARTIFACT_INTEGRITY_FAILURE")
    if not _manifest_shape_valid(manifest):
        reasons.append("DEPENDENCY_ARTIFACT_LOCK_MALFORMED")
        return _result(reasons)
    if manifest.get("lock_id") != policy.get("target_lock_id"):
        reasons.append("DEPENDENCY_ARTIFACT_PLATFORM_MISMATCH")
    if manifest.get("platform") != policy.get("target"):
        reasons.append("DEPENDENCY_ARTIFACT_PLATFORM_MISMATCH")
    if manifest.get("linux_reference_lock_sha256") != linux_hash:
        reasons.append("DEPENDENCY_ARTIFACT_INTEGRITY_FAILURE")
    if manifest.get("generated_requirements_sha256") != macos_hash:
        reasons.append("DEPENDENCY_ARTIFACT_INTEGRITY_FAILURE")
    if manifest.get("policy_version") != policy.get("policy_version"):
        reasons.append("DEPENDENCY_ARTIFACT_POLICY_INACTIVE")
    if not manifest.get("approval_event_ids") or not manifest.get("external_checkpoint_references"):
        reasons.append("DEPENDENCY_ARTIFACT_EXTERNAL_CHECKPOINT_MISSING")

    entries = manifest.get("artifact_records", [])
    by_package: dict[str, Mapping[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            reasons.append("DEPENDENCY_ARTIFACT_LOCK_MALFORMED")
            continue
        package = normalize_project_name(str(entry.get("package", "")))
        if not package or package in by_package:
            reasons.append("DEPENDENCY_ARTIFACT_LOCK_INCOMPLETE")
            continue
        by_package[package] = entry
    if set(by_package) != set(macos):
        reasons.append("DEPENDENCY_ARTIFACT_LOCK_INCOMPLETE")

    for package, requirement in macos.items():
        entry = by_package.get(package)
        if entry is None:
            continue
        record_id = str(entry.get("record_id", ""))
        record = records.get(record_id)
        decision = decisions.get(record_id)
        if record is None or decision is None or not decision.eligible:
            reasons.append("DEPENDENCY_ARTIFACT_PROVENANCE_NOT_PROVEN")
            continue
        if (
            entry.get("version") != requirement.version
            or entry.get("sha256") not in requirement.hashes
            or record.get("package", {}).get("normalized_project_name") != package
            or record.get("package", {}).get("version") != requirement.version
            or record.get("artifact", {}).get("sha256") != entry.get("sha256")
            or decision.record_hash != record.get("record_hash")
        ):
            reasons.append("DEPENDENCY_ARTIFACT_BINDING_MISMATCH")

    parity_result = validate_lock_parity(linux, macos, policy)
    reasons.extend(parity_result.reason_codes)
    return _result(reasons)


def _manifest_shape_valid(manifest: Mapping[str, Any]) -> bool:
    required = {
        "schema", "lock_id", "platform", "logical_dependency_graph_sha256",
        "linux_reference_lock_sha256", "generated_requirements_sha256", "artifact_records",
        "platform_exception_ids", "approval_event_ids", "external_checkpoint_references",
        "created_at", "policy_version", "previous_manifest_hash", "manifest_hash",
    }
    return bool(
        isinstance(manifest, Mapping)
        and set(manifest) == required
        and manifest.get("schema") == "usbay.platform_dependency_lock.v1"
        and isinstance(manifest.get("artifact_records"), list)
    )


def _result(reasons: Sequence[str]) -> LockValidationResult:
    unique = tuple(dict.fromkeys(reasons))
    return LockValidationResult(not unique, "ALLOW" if not unique else "DENY", unique)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a governed platform dependency lock offline")
    parser.add_argument("--linux-lock", type=Path, required=True)
    parser.add_argument("--platform-lock", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--evaluated-at", required=True)
    args = parser.parse_args(argv)
    try:
        linux_text = args.linux_lock.read_text(encoding="utf-8")
        macos_text = args.platform_lock.read_text(encoding="utf-8")
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        record_list = json.loads(args.records.read_text(encoding="utf-8"))
        policy = json.loads(args.policy.read_text(encoding="utf-8"))
        if not isinstance(record_list, list):
            raise ValueError
        records = {str(item["record_id"]): item for item in record_list if isinstance(item, Mapping)}
        verifier = UnavailableArtifactAttestationVerifier()
        decisions = {
            record_id: evaluate_artifact_evidence(record, policy, verifier, evaluated_at=args.evaluated_at)
            for record_id, record in records.items()
        }
        result = validate_platform_lock(
            linux_text=linux_text,
            macos_text=macos_text,
            manifest=manifest,
            records=records,
            decisions=decisions,
            policy=policy,
        )
    except Exception:
        print("decision=DENY")
        print("reason=DEPENDENCY_ARTIFACT_LOCK_MALFORMED")
        return 1
    print(f"decision={result.decision}")
    for reason in result.reason_codes:
        print(f"reason={reason}")
    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
