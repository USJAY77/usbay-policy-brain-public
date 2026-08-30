from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from audit.anchor import sign_event, timestamp_event, verify_event
from audit.immutable_ledger import append_evidence_event, export_evidence_bundle
from audit.keys import DEFAULT_KEY_VERSION, get_signing_key, resolve_public_key
from audit.worm_archive import DEFAULT_MANIFEST_NAME, DEFAULT_RETENTION_POLICY_PATH, WORMArchive
from audit.immutable_ledger import canonical_json as evidence_canonical_json
from audit.immutable_ledger import ledger_sha256
from audit.worm_archive import sha256_file
from scripts.verify_evidence_bundle import verify_bundle
from security.deployment_attestation import (
    RuntimeProvenanceAuthority,
    assert_runtime_provenance_authority,
    resolve_runtime_provenance_authority,
    validate_release_manifest,
    verify_release_signature,
)
from security.tenant_context import tenant_hash, validate_tenant_id


GENESIS_HASH = "GENESIS"
DEFAULT_EXPORT_FILE = Path("tmp/audit_exports.jsonl")
DEFAULT_TENANT_PACKAGE_DIR = Path("/private/tmp/usbay_tenant_audit_package")
DEFAULT_TENANT_PACKAGE_SOURCE_DIR = Path("/private/tmp/usbay_tenant_audit_package_source")
SAFE_AUDIT_FIELDS = (
    "event_type",
    "decision_id",
    "request_hash",
    "policy_version",
    "reason_code",
    "nonce_hash",
    "created_at",
    "expires_at",
    "used",
)
TENANT_PACKAGE_EVIDENCE_FILES = (
    "audit.jsonl",
    "ledger.sha256",
    "signatures.json",
    "consensus_evidence.json",
    "rfc3161_timestamp.tsr",
    "timestamp_verification.json",
    "tsa_certificate_chain.pem",
    "tsa_policy_oid.txt",
    "governance_release.json",
    "tenant_context.json",
)
TENANT_PACKAGE_MANIFEST = "verification_manifest.json"
TENANT_PACKAGE_SIGNATURE = "package_signature.json"
TENANT_PACKAGE_EVIDENCE_INDEX = "evidence_index.json"
TENANT_PACKAGE_VERIFICATION_REPORT = "verification_report.md"
TENANT_PACKAGE_AUTHORITY_IDENTITY = "runtime_authority_identity.json"
FORBIDDEN_PACKAGE_MARKERS = (
    "BEGIN " + "PRIVATE " + "KEY",
    "raw_nonce",
    "raw_payload",
    "approval_contents",
    "approval_material",
    "private" + "_" + "key",
    "secret",
)


class AuditExportPackageError(RuntimeError):
    pass


def _canonical_json(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _sha256_json(data: dict) -> str:
    return hashlib.sha256(_canonical_json(data).encode("utf-8")).hexdigest()


def _chain_hash(previous_hash: str, event: dict) -> str:
    return hashlib.sha256((previous_hash + _canonical_json(event)).encode("utf-8")).hexdigest()


def _safe_audit_event(event: dict, previous_hash: str) -> dict:
    decision = event.get("decision") if isinstance(event.get("decision"), dict) else {}
    source = {**event, **decision}
    safe = {field: source.get(field) for field in SAFE_AUDIT_FIELDS}
    safe["event_type"] = safe.get("event_type") or event.get("action", "")
    safe["previous_hash"] = previous_hash
    safe["current_hash"] = _chain_hash(previous_hash, safe)
    return safe


def _normalize_decision(value) -> str:
    if isinstance(value, dict):
        value = value.get("decision", value.get("final_decision", "DENY"))
    normalized = str(value or "DENY").upper()
    if normalized in {"ALLOW", "ALLOWED"}:
        return "ALLOW"
    return "DENY"


def _hydra_metadata(event: dict) -> dict:
    decision = event.get("decision")
    if isinstance(decision, dict):
        consensus = decision.get("consensus", {})
        consensus_value = decision.get("consensus_reached", "")
        if isinstance(consensus, dict):
            consensus_value = consensus.get("consensus_reached", consensus_value)
        elif consensus_value == "":
            consensus_value = consensus
        return {
            "consensus": str(consensus_value),
            "allow_votes": int(
                decision.get("votes_allow", decision.get("allow_votes", consensus.get("votes_allow", 0)))
                if isinstance(consensus, dict)
                else decision.get("votes_allow", decision.get("allow_votes", 0))
            ),
            "deny_votes": int(
                decision.get("votes_deny", decision.get("deny_votes", consensus.get("votes_deny", 0)))
                if isinstance(consensus, dict)
                else decision.get("votes_deny", decision.get("deny_votes", 0))
            ),
        }

    return {
        "consensus": str(event.get("consensus", "")),
        "allow_votes": int(event.get("allow_votes", 0)),
        "deny_votes": int(event.get("deny_votes", 0)),
    }


def _last_hash(filepath: Path) -> str:
    if not filepath.exists():
        return GENESIS_HASH

    last_hash = GENESIS_HASH
    for line in filepath.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        last_hash = str(record["event_hash"])
    return last_hash


def build_export_event(event: dict) -> dict:
    decision = event.get("decision")
    export = {
        "audit_id": str(event.get("audit_id", event.get("hash_current", ""))),
        "timestamp": str(event.get("timestamp", datetime.utcnow().isoformat() + "Z")),
        "action": str(event.get("action", "")),
        "decision": _normalize_decision(decision),
        "reason": str(event.get("reason", "")),
        "policy_version": str(event.get("policy_version", "")),
        "hydra": _hydra_metadata(event),
        "signature_valid": bool(event.get("signature_valid", True)),
        "nonce_valid": bool(event.get("nonce_valid", True)),
    }

    if isinstance(decision, dict) and decision.get("command_hash"):
        export["command_hash"] = str(decision["command_hash"])
    elif event.get("command_hash"):
        export["command_hash"] = str(event["command_hash"])

    return export


def export_audit_event(event: dict, filepath: str):
    export_path = Path(filepath)
    export_path.parent.mkdir(parents=True, exist_ok=True)

    export_event = build_export_event(event)
    prev_hash = _last_hash(export_path)
    event_hash = _sha256_json(export_event)
    signing_key = get_signing_key(str(event.get("key_version", DEFAULT_KEY_VERSION)))
    record = {
        **export_event,
        "event_hash": event_hash,
        "signature": sign_event(event_hash, signing_key["private_key"]),
        "public_key_id": signing_key["public_key_id"],
        "key_version": signing_key["key_version"],
        "timestamp_proof": timestamp_event(event_hash),
        "prev_hash": prev_hash,
    }

    with export_path.open("a", encoding="utf-8") as handle:
        handle.write(_canonical_json(record) + "\n")

    return record


def load_export_records(filepath: str) -> list[dict]:
    export_path = Path(filepath)
    if not export_path.exists():
        return []
    return [
        json.loads(line)
        for line in export_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def verify_export_chain(filepath: str) -> bool:
    prev_hash = GENESIS_HASH
    try:
        for record in load_export_records(filepath):
            if record.get("prev_hash") != prev_hash:
                return False
            event = dict(record)
            event_hash = event.pop("event_hash", None)
            event.pop("signature", None)
            event.pop("public_key_id", None)
            event.pop("key_version", None)
            event.pop("timestamp_proof", None)
            event.pop("prev_hash", None)
            if _sha256_json(event) != event_hash:
                return False
            prev_hash = str(event_hash)
    except Exception:
        return False

    return True


def export_audit_chain(events: list[dict], filepath: str) -> dict:
    previous_hash = GENESIS_HASH
    safe_events = []
    for event in events:
        safe = _safe_audit_event(event, previous_hash)
        previous_hash = safe["current_hash"]
        safe_events.append(safe)

    export = {
        "events": safe_events,
        "root_hash": previous_hash,
        "algorithm": "sha256(previous_hash + canonical_event_json)",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "event_count": len(safe_events),
    }
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_canonical_json(export), encoding="utf-8")
    return export


def verify_audit_chain_export(filepath: str) -> bool:
    try:
        export = json.loads(Path(filepath).read_text(encoding="utf-8"))
        events = export.get("events")
        if not isinstance(events, list):
            return False
        if export.get("event_count") != len(events):
            return False
        previous_hash = GENESIS_HASH
        for event in events:
            if event.get("previous_hash") != previous_hash:
                return False
            event_without_hash = dict(event)
            current_hash = event_without_hash.pop("current_hash", None)
            if _chain_hash(previous_hash, event_without_hash) != current_hash:
                return False
            previous_hash = str(current_hash)
        return export.get("root_hash") == previous_hash
    except Exception:
        return False


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_json(path: Path, reason: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise AuditExportPackageError(reason) from exc


def _package_file_hashes(package_dir: Path, names: tuple[str, ...]) -> dict[str, str]:
    hashes = {}
    for name in names:
        path = package_dir / name
        if not path.is_file():
            raise AuditExportPackageError(f"package_file_missing:{name}")
        hashes[name] = sha256_file(path)
    return dict(sorted(hashes.items()))


def _optional_package_file_hashes(package_dir: Path) -> dict[str, str]:
    hashes = {}
    for path in sorted(package_dir.iterdir()):
        if path.is_file() and path.name != TENANT_PACKAGE_VERIFICATION_REPORT:
            hashes[path.name] = sha256_file(path)
    return hashes


def _contains_forbidden_package_data(package_dir: Path) -> bool:
    text_parts = []
    for path in package_dir.iterdir():
        if path.is_file() and path.name != TENANT_PACKAGE_VERIFICATION_REPORT:
            text_parts.append(path.read_text(encoding="utf-8", errors="ignore"))
    combined = "\n".join(text_parts).lower()
    return any(marker.lower() in combined for marker in FORBIDDEN_PACKAGE_MARKERS)


def _tenant_context_from_package(package_dir: Path) -> dict[str, str]:
    context = _read_json(package_dir / "tenant_context.json", "tenant_context_invalid")
    if not isinstance(context, dict):
        raise AuditExportPackageError("tenant_context_invalid")
    tenant_id = validate_tenant_id(context.get("tenant_id"))
    expected_hash = tenant_hash(tenant_id)
    if context.get("tenant_hash") != expected_hash or context.get("tenant_scope") != f"tenant/{tenant_id}":
        raise AuditExportPackageError("tenant_mismatch")
    return {
        "tenant_id": tenant_id,
        "tenant_hash": expected_hash,
        "tenant_scope": f"tenant/{tenant_id}",
    }


def _audit_records(package_dir: Path) -> list[dict[str, Any]]:
    records = []
    for line in (package_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def _copy_evidence_files(source: Path, package_dir: Path) -> None:
    for name in TENANT_PACKAGE_EVIDENCE_FILES:
        src = source / name
        if not src.is_file():
            raise AuditExportPackageError(f"package_file_missing:{name}")
        shutil.copy2(src, package_dir / name)


def _resolve_worm_manifest(bundle_dir: Path, worm_manifest_path: Path | str | None) -> Path:
    if worm_manifest_path is not None:
        path = Path(worm_manifest_path)
        if not path.is_file():
            raise AuditExportPackageError("worm_manifest_missing")
        return path
    direct = bundle_dir / DEFAULT_MANIFEST_NAME
    if direct.is_file():
        return direct
    matches = sorted(bundle_dir.parent.glob(f"**/{DEFAULT_MANIFEST_NAME}"))
    if len(matches) != 1:
        raise AuditExportPackageError("worm_manifest_missing")
    return matches[0]


def _require_runtime_provenance_authority(
    authority: RuntimeProvenanceAuthority | None,
    release_path: Path | str | None = None,
) -> RuntimeProvenanceAuthority:
    if authority is None:
        raise AuditExportPackageError("runtime_provenance_authority_required")
    return assert_runtime_provenance_authority(authority, release_path)


def _authority_identity_payload(authority: RuntimeProvenanceAuthority) -> dict[str, Any]:
    context = authority.context_dict()
    return {
        "format": "USBAY_RUNTIME_PROVENANCE_AUTHORITY_IDENTITY_V1",
        "authority_instance_id": authority.authority_id,
        "release_hash": authority.release_hash,
        "policy_bundle_hash": authority.policy_bundle_hash,
        "tenant_id": authority.tenant_id,
        "canonical_bootstrap_lineage_summary": {
            "expected_commit": context.get("expected_commit"),
            "current_commit": context.get("current_commit"),
            "ci_mode": context.get("ci_mode"),
            "accepted_commit_set": sorted(str(item) for item in context.get("accepted_commit_set", [])),
            "ancestor_continuity": context.get("ancestor_continuity"),
            "release_lineage": context.get("release_lineage", []),
        },
        "authority_reuse_verified": True,
        "secondary_authority_resolution_allowed": False,
    }


def _write_authority_identity(package_dir: Path, authority: RuntimeProvenanceAuthority) -> dict[str, Any]:
    payload = _authority_identity_payload(authority)
    (package_dir / TENANT_PACKAGE_AUTHORITY_IDENTITY).write_text(evidence_canonical_json(payload), encoding="utf-8")
    return payload


def _verify_authority_identity(
    package_dir: Path,
    *,
    provenance_context: dict[str, Any],
    authority: RuntimeProvenanceAuthority | None = None,
) -> dict[str, Any]:
    identity = _read_json(package_dir / TENANT_PACKAGE_AUTHORITY_IDENTITY, "RUNTIME_AUTHORITY_IDENTITY_MISSING")
    if not isinstance(identity, dict):
        raise AuditExportPackageError("RUNTIME_AUTHORITY_IDENTITY_MALFORMED")
    summary = identity.get("canonical_bootstrap_lineage_summary")
    if not isinstance(summary, dict):
        raise AuditExportPackageError("RUNTIME_AUTHORITY_IDENTITY_MALFORMED")
    expected_summary = {
        "expected_commit": provenance_context.get("expected_commit"),
        "current_commit": provenance_context.get("current_commit"),
        "ci_mode": provenance_context.get("ci_mode"),
        "accepted_commit_set": sorted(str(item) for item in provenance_context.get("accepted_commit_set", [])),
        "ancestor_continuity": provenance_context.get("ancestor_continuity"),
        "release_lineage": provenance_context.get("release_lineage", []),
    }
    if summary != expected_summary:
        raise AuditExportPackageError("RUNTIME_AUTHORITY_IDENTITY_MISMATCH")
    if identity.get("authority_reuse_verified") is not True:
        raise AuditExportPackageError("RUNTIME_AUTHORITY_REUSE_UNVERIFIED")
    if identity.get("secondary_authority_resolution_allowed") is not False:
        raise AuditExportPackageError("SECONDARY_AUTHORITY_RESOLUTION_ALLOWED")
    if authority is not None:
        authority = _require_runtime_provenance_authority(authority, package_dir / "governance_release.json")
        expected_identity = _authority_identity_payload(authority)
        if identity != expected_identity:
            raise AuditExportPackageError("RUNTIME_AUTHORITY_IDENTITY_MISMATCH")
    return identity


def _verify_worm_manifest(package_dir: Path, tenant_context: dict[str, str]) -> dict[str, Any]:
    manifest = _read_json(package_dir / DEFAULT_MANIFEST_NAME, "worm_manifest_malformed")
    if not isinstance(manifest, dict):
        raise AuditExportPackageError("worm_manifest_malformed")
    if manifest.get("tenant_id") != tenant_context["tenant_id"]:
        raise AuditExportPackageError("tenant_mismatch")
    if manifest.get("tenant_hash") != tenant_context["tenant_hash"]:
        raise AuditExportPackageError("tenant_mismatch")
    if manifest.get("tenant_scope") != tenant_context["tenant_scope"]:
        raise AuditExportPackageError("tenant_mismatch")
    object_hashes = manifest.get("object_hashes")
    if not isinstance(object_hashes, dict) or not object_hashes:
        raise AuditExportPackageError("worm_manifest_malformed")
    for name, digest in object_hashes.items():
        path = package_dir / name
        if path.is_file() and sha256_file(path) != digest:
            raise AuditExportPackageError("worm_manifest_hash_mismatch")
    return manifest


def _canonical_source_decision(tenant_id: str, policy_hash: str) -> dict[str, Any]:
    tenant = validate_tenant_id(tenant_id)
    tenant_digest = tenant_hash(tenant)
    return {
        "node_id": "gateway-1",
        "tenant_id": tenant,
        "tenant_hash": tenant_digest,
        "policy_hash": policy_hash,
        "consensus_result": "ALLOW",
        "nonce_hash": _sha256_bytes(f"{tenant}:canonical-package-source:nonce".encode("utf-8")),
        "request_hash": _sha256_bytes(f"{tenant}:canonical-package-source:request".encode("utf-8")),
        "consensus_evidence_bundle": {
            "node_ids": ["node-1", "node-2", "node-3"],
            "timestamps": {"node-1": 1, "node-2": 1, "node-3": 1},
            "policy_hash": policy_hash,
            "tenant_id": tenant,
            "tenant_hash": tenant_digest,
            "consensus_result": "allow",
            "attestation_evidence": [
                {
                    "logical_node_id": "gateway-1",
                    "node_id": "attested-gateway-1",
                    "node_role": "gateway",
                    "tenant_id": tenant,
                    "tenant_hash": tenant_digest,
                    "provider_mode": "mock_local",
                    "hardware_backed": False,
                    "attestation_hash": _sha256_bytes(f"{tenant}:canonical-package-source:attestation".encode("utf-8")),
                    "attestation_timestamp": 1,
                }
            ],
            "attestation_evidence_hash": _sha256_bytes(f"{tenant}:canonical-package-source:attestation-evidence".encode("utf-8")),
            "sha256_evidence_hash": _sha256_bytes(f"{tenant}:canonical-package-source:consensus".encode("utf-8")),
            "consensus_signature": "canonical-package-source-signature",
        },
    }


def validate_package_source(
    source_dir: Path | str,
    *,
    tenant_id: str | None = None,
    provenance_authority: RuntimeProvenanceAuthority | None = None,
) -> dict[str, Any]:
    source = Path(source_dir)
    if not source.is_dir():
        raise AuditExportPackageError("package_source_missing")
    for name in TENANT_PACKAGE_EVIDENCE_FILES + (DEFAULT_MANIFEST_NAME,):
        if not (source / name).is_file():
            raise AuditExportPackageError(f"package_source_file_missing:{name}")
    if _contains_forbidden_package_data(source):
        raise AuditExportPackageError("package_secret_leakage_detected")
    report = verify_bundle(source)
    if report.get("result") != "PASS":
        raise AuditExportPackageError("package_source_invalid")
    tenant_context = _tenant_context_from_package(source)
    if tenant_id is not None and tenant_context["tenant_id"] != validate_tenant_id(tenant_id):
        raise AuditExportPackageError("tenant_mismatch")
    release = _read_json(source / "governance_release.json", "release_manifest_malformed")
    if not isinstance(release, dict):
        raise AuditExportPackageError("release_manifest_malformed")
    if release.get("tenant_id") != tenant_context["tenant_id"]:
        raise AuditExportPackageError("tenant_mismatch")
    if not verify_release_signature(release):
        raise AuditExportPackageError("release_signature_invalid")
    authority = _require_runtime_provenance_authority(provenance_authority, source / "governance_release.json")
    provenance_context = authority.context_dict()
    validate_release_manifest(
        source / "governance_release.json",
        expected_tenant_id=tenant_context["tenant_id"],
        expected_provenance_context=provenance_context,
    )
    worm_manifest = _verify_worm_manifest(source, tenant_context)
    return {
        "tenant_id": tenant_context["tenant_id"],
        "tenant_hash": tenant_context["tenant_hash"],
        "release_id": str(release.get("release_id", "")),
        "git_commit": str(release.get("git_commit", "")),
        "provenance_context": provenance_context,
        "worm_object_id": str(worm_manifest.get("object_id", "")),
        "offline_verification": report,
    }


def build_package_source(
    *,
    tenant_id: str,
    source_dir: Path | str = DEFAULT_TENANT_PACKAGE_SOURCE_DIR,
    retention_policy_path: Path | str = DEFAULT_RETENTION_POLICY_PATH,
    provenance_context: dict[str, Any] | None = None,
    provenance_authority: RuntimeProvenanceAuthority | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    tenant = validate_tenant_id(tenant_id)
    source = Path(source_dir)
    if source.exists():
        shutil.rmtree(source)
    source.mkdir(parents=True, exist_ok=False)
    authority = _require_runtime_provenance_authority(provenance_authority)
    context = provenance_context or authority.context_dict()
    if context != authority.context_dict():
        raise AuditExportPackageError("runtime_provenance_authority_mismatch")
    release_summary = validate_release_manifest(
        expected_tenant_id=tenant,
        expected_provenance_context=context,
    )
    if context != release_summary["provenance_context"]:
        raise AuditExportPackageError("provenance_context_mismatch")
    ledger_path = source / "_canonical_source_ledger.jsonl"
    append_evidence_event(
        ledger_path,
        action="tenant_audit_package_source",
        decision=_canonical_source_decision(tenant, release_summary["policy_bundle_hash"]),
    )
    export_evidence_bundle(ledger_path, source, provenance_context=context, provenance_authority=authority)
    archive_root = source.parent / f"{source.name}_worm"
    if archive_root.exists():
        shutil.rmtree(archive_root)
    archive = WORMArchive(archive_root, retention_policy_path=retention_policy_path)
    manifest = archive.archive_bundle(source, now=now, provenance_context=context, provenance_authority=authority)
    manifest_path = archive_root / "tenant" / tenant / manifest["object_id"] / DEFAULT_MANIFEST_NAME
    shutil.copy2(manifest_path, source / DEFAULT_MANIFEST_NAME)
    summary = validate_package_source(source, tenant_id=tenant, provenance_authority=authority)
    return {"source_dir": str(source), **summary}


def _verification_manifest_payload(
    *,
    package_dir: Path,
    tenant_context: dict[str, str],
    release: dict[str, Any],
    worm_manifest: dict[str, Any],
    provenance_context: dict[str, Any],
) -> dict[str, Any]:
    evidence_hashes = _package_file_hashes(package_dir, TENANT_PACKAGE_EVIDENCE_FILES + (DEFAULT_MANIFEST_NAME,))
    records = _audit_records(package_dir)
    ledger_hash = ledger_sha256(records)
    if (package_dir / "ledger.sha256").read_text(encoding="utf-8").strip() != ledger_hash:
        raise AuditExportPackageError("ledger_sha256_mismatch")
    release_signature = str(release.get("release_signature", ""))
    package_basis = {
        "evidence_hashes": evidence_hashes,
        "git_commit": str(release.get("git_commit", "")),
        "ledger_sha256": ledger_hash,
        "provenance_context": provenance_context,
        "release_id": str(release.get("release_id", "")),
        "release_signature_ref": _sha256_bytes(release_signature.encode("utf-8")),
        "tenant_hash": tenant_context["tenant_hash"],
        "tenant_id": tenant_context["tenant_id"],
        "worm_object_id": str(worm_manifest.get("object_id", "")),
    }
    return {
        "format": "USBAY_TENANT_AUDIT_PACKAGE_V1",
        "tenant_id": tenant_context["tenant_id"],
        "tenant_hash": tenant_context["tenant_hash"],
        "tenant_scope": tenant_context["tenant_scope"],
        "release_id": package_basis["release_id"],
        "git_commit": package_basis["git_commit"],
        "release_signature_ref": package_basis["release_signature_ref"],
        "ledger_sha256": ledger_hash,
        "provenance_context": provenance_context,
        "worm_object_id": package_basis["worm_object_id"],
        "evidence_hashes": evidence_hashes,
        "package_hash": _sha256_bytes(evidence_canonical_json(package_basis).encode("utf-8")),
    }


def _evidence_index_payload(package_dir: Path, verification_manifest: dict[str, Any]) -> dict[str, Any]:
    evidence_hashes = verification_manifest.get("evidence_hashes")
    if not isinstance(evidence_hashes, dict):
        raise AuditExportPackageError("VERIFICATION_MANIFEST_MALFORMED")
    required_hashes = {
        "audit_jsonl": sha256_file(package_dir / "audit.jsonl"),
        "worm_manifest": sha256_file(package_dir / DEFAULT_MANIFEST_NAME),
        "rfc3161_timestamp_proof": sha256_file(package_dir / "rfc3161_timestamp.tsr"),
        "governance_release": sha256_file(package_dir / "governance_release.json"),
        "verification_manifest": sha256_file(package_dir / TENANT_PACKAGE_MANIFEST),
    }
    return {
        "format": "USBAY_TENANT_AUDIT_EVIDENCE_INDEX_V1",
        "tenant_id": str(verification_manifest.get("tenant_id", "")),
        "tenant_hash": str(verification_manifest.get("tenant_hash", "")),
        "release_id": str(verification_manifest.get("release_id", "")),
        "git_commit": str(verification_manifest.get("git_commit", "")),
        "package_hash": str(verification_manifest.get("package_hash", "")),
        "audit_ledger_hash": str(verification_manifest.get("ledger_sha256", "")),
        "worm_manifest_hash": required_hashes["worm_manifest"],
        "rfc3161_timestamp_proof_hash": required_hashes["rfc3161_timestamp_proof"],
        "governance_release_hash": required_hashes["governance_release"],
        "verification_manifest_hash": required_hashes["verification_manifest"],
        "evidence_hashes": dict(sorted(evidence_hashes.items())),
    }


def _write_evidence_index(package_dir: Path, verification_manifest: dict[str, Any]) -> dict[str, Any]:
    index = _evidence_index_payload(package_dir, verification_manifest)
    (package_dir / TENANT_PACKAGE_EVIDENCE_INDEX).write_text(evidence_canonical_json(index), encoding="utf-8")
    return index


def _control_status(failures: list[str], keywords: tuple[str, ...]) -> str:
    if any(any(keyword in failure.upper() for keyword in keywords) for failure in failures):
        return "FAIL"
    return "PASS"


def _verification_report_markdown(report: dict[str, Any]) -> str:
    failures = [str(item) for item in report.get("failed_control_ids", [])]
    evidence_hashes = report.get("evidence_file_hashes")
    if not isinstance(evidence_hashes, dict):
        evidence_hashes = {}
    index = report.get("evidence_index")
    if not isinstance(index, dict):
        index = {}
    timestamp_summary = report.get("timestamp_verification_summary")
    if not isinstance(timestamp_summary, dict):
        timestamp_summary = {}
    lines = [
        "# USBAY Tenant Audit Package Verification Report",
        "",
        f"Result: {report.get('result', 'FAIL')}",
        f"Tenant ID: {index.get('tenant_id', '')}",
        f"Tenant Hash: {index.get('tenant_hash', '')}",
        f"Release ID: {index.get('release_id', '')}",
        f"Git Commit: {index.get('git_commit', '')}",
        f"Package Hash: {index.get('package_hash', '')}",
        "",
        "## Control Results",
        f"- Tenant binding: {_control_status(failures, ('TENANT',))}",
        f"- Release signature: {_control_status(failures, ('RELEASE_SIGNATURE',))}",
        f"- WORM verification: {_control_status(failures, ('WORM',))}",
        f"- Ledger continuity: {_control_status(failures, ('LEDGER', 'AUDIT'))}",
        f"- RFC3161 timestamp: {_control_status(failures, ('RFC3161', 'TIMESTAMP', 'TSA', 'MESSAGEIMPRINT'))}",
        f"- No secret leakage: {_control_status(failures, ('SECRET', 'NO_SECRET_LEAKAGE'))}",
        "",
        "## Failure Reason Codes",
    ]
    if failures:
        lines.extend(f"- {failure}" for failure in failures)
    else:
        lines.append("- NONE")
    lines.extend(["", "## Evidence Hashes"])
    if evidence_hashes:
        lines.extend(f"- {name}: {digest}" for name, digest in sorted(evidence_hashes.items()))
    else:
        lines.append("- NONE")
    lines.extend(
        [
            "",
            "## Evidence Index",
            f"- Audit ledger hash: {index.get('audit_ledger_hash', '')}",
            f"- WORM manifest hash: {index.get('worm_manifest_hash', '')}",
            f"- RFC3161 timestamp proof hash: {index.get('rfc3161_timestamp_proof_hash', '')}",
            f"- Governance release hash: {index.get('governance_release_hash', '')}",
            f"- Verification manifest hash: {index.get('verification_manifest_hash', '')}",
            "",
            "## Timestamp Verification Summary",
            f"- Result: {'PASS' if timestamp_summary.get('valid') is True else timestamp_summary.get('result', 'FAIL')}",
            f"- Policy OID: {timestamp_summary.get('policy_oid', '')}",
            f"- Message imprint hash: {timestamp_summary.get('message_imprint', timestamp_summary.get('message_imprint_hash', ''))}",
        ]
    )
    return "\n".join(lines) + "\n"


def _write_verification_report(package_dir: Path, report: dict[str, Any]) -> None:
    (package_dir / TENANT_PACKAGE_VERIFICATION_REPORT).write_text(_verification_report_markdown(report), encoding="utf-8")


def build_tenant_package(
    *,
    tenant_id: str,
    package_path: Path | str = DEFAULT_TENANT_PACKAGE_DIR,
    evidence_bundle_dir: Path | str = Path("tmp/evidence_bundle"),
    worm_manifest_path: Path | str | None = None,
    key_version: str = DEFAULT_KEY_VERSION,
    provenance_authority: RuntimeProvenanceAuthority | None = None,
) -> dict[str, Any]:
    tenant_id = validate_tenant_id(tenant_id)
    authority = _require_runtime_provenance_authority(provenance_authority)
    source = Path(evidence_bundle_dir)
    if not source.is_dir():
        build_package_source(tenant_id=tenant_id, source_dir=source, provenance_authority=authority)
    elif worm_manifest_path is not None and not (source / DEFAULT_MANIFEST_NAME).is_file():
        manifest_path = _resolve_worm_manifest(source, worm_manifest_path)
        shutil.copy2(manifest_path, source / DEFAULT_MANIFEST_NAME)
    try:
        source_summary = validate_package_source(source, tenant_id=tenant_id, provenance_authority=authority)
    except AuditExportPackageError as exc:
        raise AuditExportPackageError("evidence_bundle_invalid") from exc
    provenance_context = source_summary["provenance_context"]
    package_dir = Path(package_path)
    if package_dir.exists():
        shutil.rmtree(package_dir)
    package_dir.mkdir(parents=True, exist_ok=False)
    _copy_evidence_files(source, package_dir)
    worm_manifest = _read_json(_resolve_worm_manifest(source, worm_manifest_path), "worm_manifest_malformed")
    (package_dir / DEFAULT_MANIFEST_NAME).write_text(evidence_canonical_json(worm_manifest), encoding="utf-8")
    if _contains_forbidden_package_data(package_dir):
        raise AuditExportPackageError("package_secret_leakage_detected")
    tenant_context = _tenant_context_from_package(package_dir)
    if tenant_context["tenant_id"] != tenant_id:
        raise AuditExportPackageError("tenant_mismatch")
    release = _read_json(package_dir / "governance_release.json", "release_manifest_malformed")
    if release.get("tenant_id") != tenant_id:
        raise AuditExportPackageError("tenant_mismatch")
    if not verify_release_signature(release):
        raise AuditExportPackageError("release_signature_invalid")
    validate_release_manifest(
        package_dir / "governance_release.json",
        expected_tenant_id=tenant_id,
        expected_provenance_context=provenance_context,
    )
    worm_manifest = _verify_worm_manifest(package_dir, tenant_context)
    verification_manifest = _verification_manifest_payload(
        package_dir=package_dir,
        tenant_context=tenant_context,
        release=release,
        worm_manifest=worm_manifest,
        provenance_context=provenance_context,
    )
    (package_dir / TENANT_PACKAGE_MANIFEST).write_text(evidence_canonical_json(verification_manifest), encoding="utf-8")
    signing_key = get_signing_key(key_version)
    signature = sign_event(verification_manifest["package_hash"], signing_key["private_key"])
    package_signature = {
        "package_hash": verification_manifest["package_hash"],
        "signature": signature,
        "public_key_id": signing_key["public_key_id"],
        "key_version": signing_key["key_version"],
    }
    (package_dir / TENANT_PACKAGE_SIGNATURE).write_text(evidence_canonical_json(package_signature), encoding="utf-8")
    _write_authority_identity(package_dir, authority)
    _write_evidence_index(package_dir, verification_manifest)
    verify_tenant_package(package_dir, provenance_authority=authority)
    return verification_manifest


def verify_tenant_package(
    package_path: Path | str,
    *,
    provenance_authority: RuntimeProvenanceAuthority | None = None,
) -> dict[str, Any]:
    package_dir = Path(package_path)
    failures: list[str] = []
    if not package_dir.is_dir():
        failures.append("PACKAGE_MISSING")
        return {"result": "FAIL", "failed_control_ids": failures}
    evidence_index: dict[str, Any] = {}
    timestamp_summary: dict[str, Any] = {}
    try:
        if _contains_forbidden_package_data(package_dir):
            raise AuditExportPackageError("PACKAGE_SECRET_LEAKAGE")
        bundle_report = verify_bundle(package_dir)
        if bundle_report.get("result") != "PASS":
            failures.extend(f"BUNDLE:{control}" for control in bundle_report.get("failed_control_ids", []))
        timestamp_summary = _read_json(package_dir / "timestamp_verification.json", "TIMESTAMP_VERIFICATION_MALFORMED")
        if not isinstance(timestamp_summary, dict):
            raise AuditExportPackageError("TIMESTAMP_VERIFICATION_MALFORMED")
        tenant_context = _tenant_context_from_package(package_dir)
        release = _read_json(package_dir / "governance_release.json", "RELEASE_MANIFEST_MALFORMED")
        if not isinstance(release, dict):
            raise AuditExportPackageError("RELEASE_MANIFEST_MALFORMED")
        if release.get("tenant_id") != tenant_context["tenant_id"]:
            raise AuditExportPackageError("TENANT_MISMATCH")
        if not verify_release_signature(release):
            raise AuditExportPackageError("RELEASE_SIGNATURE_INVALID")
        observed_manifest = _read_json(package_dir / TENANT_PACKAGE_MANIFEST, "VERIFICATION_MANIFEST_MALFORMED")
        if not isinstance(observed_manifest, dict):
            raise AuditExportPackageError("VERIFICATION_MANIFEST_MALFORMED")
        provenance_context = observed_manifest.get("provenance_context")
        if not isinstance(provenance_context, dict):
            raise AuditExportPackageError("PROVENANCE_CONTEXT_MISSING")
        if provenance_authority is not None:
            authority = _require_runtime_provenance_authority(
                provenance_authority,
                package_dir / "governance_release.json",
            )
            if provenance_context != authority.context_dict():
                raise AuditExportPackageError("RUNTIME_AUTHORITY_CONTEXT_MISMATCH")
        validate_release_manifest(
            package_dir / "governance_release.json",
            expected_tenant_id=tenant_context["tenant_id"],
            expected_provenance_context=provenance_context,
        )
        worm_manifest = _verify_worm_manifest(package_dir, tenant_context)
        expected_manifest = _verification_manifest_payload(
            package_dir=package_dir,
            tenant_context=tenant_context,
            release=release,
            worm_manifest=worm_manifest,
            provenance_context=provenance_context,
        )
        if observed_manifest != expected_manifest:
            raise AuditExportPackageError("VERIFICATION_MANIFEST_MISMATCH")
        expected_index = _evidence_index_payload(package_dir, expected_manifest)
        observed_index = _read_json(package_dir / TENANT_PACKAGE_EVIDENCE_INDEX, "EVIDENCE_INDEX_MALFORMED")
        if observed_index != expected_index:
            raise AuditExportPackageError("EVIDENCE_INDEX_MISMATCH")
        _verify_authority_identity(
            package_dir,
            provenance_context=provenance_context,
            authority=provenance_authority,
        )
        evidence_index = expected_index
        package_signature = _read_json(package_dir / TENANT_PACKAGE_SIGNATURE, "PACKAGE_SIGNATURE_MALFORMED")
        if not isinstance(package_signature, dict):
            raise AuditExportPackageError("PACKAGE_SIGNATURE_MALFORMED")
        if package_signature.get("package_hash") != expected_manifest["package_hash"]:
            raise AuditExportPackageError("PACKAGE_HASH_MISMATCH")
        public_key = resolve_public_key(str(package_signature.get("public_key_id", "")))
        if not verify_event(expected_manifest["package_hash"], str(package_signature.get("signature", "")), public_key):
            raise AuditExportPackageError("PACKAGE_SIGNATURE_INVALID")
    except AuditExportPackageError as exc:
        failures.append(str(exc))
    except Exception as exc:
        failures.append(str(exc) or "PACKAGE_VERIFICATION_FAILED")
    if not evidence_index:
        try:
            observed_manifest = _read_json(package_dir / TENANT_PACKAGE_MANIFEST, "VERIFICATION_MANIFEST_MALFORMED")
            if isinstance(observed_manifest, dict):
                evidence_index = _evidence_index_payload(package_dir, observed_manifest)
        except Exception:
            evidence_index = {}
    if not timestamp_summary:
        try:
            loaded_timestamp_summary = _read_json(package_dir / "timestamp_verification.json", "TIMESTAMP_VERIFICATION_MALFORMED")
            if isinstance(loaded_timestamp_summary, dict):
                timestamp_summary = loaded_timestamp_summary
        except Exception:
            timestamp_summary = {}
    result = {
        "result": "FAIL" if failures else "PASS",
        "failed_control_ids": sorted(set(failures)),
        "evidence_file_hashes": _optional_package_file_hashes(package_dir),
        "evidence_index": evidence_index,
        "timestamp_verification_summary": timestamp_summary,
    }
    _write_verification_report(package_dir, result)
    return result


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="USBAY audit export package tools")
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build-tenant-package")
    build.add_argument("--tenant-id", required=True)
    build.add_argument("--evidence-bundle-dir", type=Path, default=DEFAULT_TENANT_PACKAGE_SOURCE_DIR)
    build.add_argument("--worm-manifest", type=Path)
    build.add_argument("--package-path", type=Path, default=DEFAULT_TENANT_PACKAGE_DIR)
    verify = subparsers.add_parser("verify-tenant-package")
    verify.add_argument("package_path", type=Path)
    args = parser.parse_args(argv)
    if args.command == "build-tenant-package":
        authority = resolve_runtime_provenance_authority()
        manifest = build_tenant_package(
            tenant_id=args.tenant_id,
            package_path=args.package_path,
            evidence_bundle_dir=args.evidence_bundle_dir,
            worm_manifest_path=args.worm_manifest,
            provenance_authority=authority,
        )
        print(evidence_canonical_json({"result": "PASS", "package_hash": manifest["package_hash"], "package_path": str(args.package_path)}))
        return 0
    report = verify_tenant_package(args.package_path)
    print(evidence_canonical_json(report))
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(_main())
