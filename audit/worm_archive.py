from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from audit.immutable_ledger import canonical_json
from audit.rfc3161_anchor import component_hashes, message_imprint


DEFAULT_RETENTION_POLICY_PATH = Path("governance/evidence_retention_policy.json")
DEFAULT_MANIFEST_NAME = "evidence_archive_manifest.json"
REQUIRED_BUNDLE_FILES = (
    "audit.jsonl",
    "ledger.sha256",
    "signatures.json",
    "rfc3161_timestamp.tsr",
    "timestamp_verification.json",
    "tsa_certificate_chain.pem",
    "tsa_policy_oid.txt",
    "governance_release.json",
)
FORBIDDEN_MARKERS = (
    "BEGIN " + "PRIVATE " + "KEY",
    "raw_nonce",
    "raw_payload",
    "approval_contents",
    "approval_material",
    "private" + "_" + "key",
    "secret",
)


class WORMArchiveError(RuntimeError):
    pass


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception as exc:
        raise WORMArchiveError("invalid_retention_policy:delete_prohibited_before") from exc
    if parsed.tzinfo is None:
        raise WORMArchiveError("invalid_retention_policy:delete_prohibited_before")
    return parsed.astimezone(timezone.utc)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def environment_mode() -> str:
    raw = os.getenv("USBAY_ENV", os.getenv("USBAY_ENVIRONMENT", "test")).strip().lower()
    return "production" if raw in {"prod", "production"} else "test"


def load_retention_policy(path: Path | str = DEFAULT_RETENTION_POLICY_PATH) -> dict[str, Any]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise WORMArchiveError("invalid_retention_policy:unreadable") from exc
    if not isinstance(raw, dict):
        raise WORMArchiveError("invalid_retention_policy:root")
    try:
        retention_days = int(raw.get("default_retention_days"))
    except Exception as exc:
        raise WORMArchiveError("invalid_retention_policy:default_retention_days") from exc
    if retention_days <= 0:
        raise WORMArchiveError("invalid_retention_policy:default_retention_days")
    if not isinstance(raw.get("legal_hold"), bool):
        raise WORMArchiveError("invalid_retention_policy:legal_hold")
    delete_before = _parse_utc(str(raw.get("delete_prohibited_before", "")))
    retention_class = str(raw.get("export_retention_class", "")).strip()
    if not retention_class:
        raise WORMArchiveError("invalid_retention_policy:export_retention_class")
    return {
        "default_retention_days": retention_days,
        "legal_hold": raw["legal_hold"],
        "delete_prohibited_before": delete_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "export_retention_class": retention_class,
    }


def _read_required_bundle(bundle_dir: Path) -> dict[str, bytes]:
    files = {}
    for name in REQUIRED_BUNDLE_FILES:
        path = bundle_dir / name
        if not path.is_file():
            raise WORMArchiveError(f"archive_bundle_missing:{name}")
        files[name] = path.read_bytes()
    return files


def _contains_secret(files: dict[str, bytes]) -> bool:
    text = "\n".join(data.decode("utf-8", errors="ignore") for data in files.values()).lower()
    return any(marker.lower() in text for marker in FORBIDDEN_MARKERS)


def object_id_for_bundle(bundle_dir: Path | str) -> str:
    bundle_path = Path(bundle_dir)
    files = _read_required_bundle(bundle_path)
    hashes = {name: sha256_bytes(data) for name, data in sorted(files.items())}
    return hashlib.sha256(canonical_json(hashes).encode("utf-8")).hexdigest()


def _object_hashes(files: dict[str, bytes]) -> dict[str, str]:
    return {name: sha256_bytes(data) for name, data in sorted(files.items())}


def _retention_until(policy: dict[str, Any], now: datetime | None = None) -> str:
    current = now or _utc_now()
    by_days = current + timedelta(days=int(policy["default_retention_days"]))
    delete_before = _parse_utc(policy["delete_prohibited_before"])
    return max(by_days, delete_before).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bundle_message_imprint(bundle_dir: Path, files: dict[str, bytes]) -> str:
    signatures = json.loads(files["signatures.json"].decode("utf-8"))
    consensus_path = bundle_dir / "consensus_evidence.json"
    consensus_evidence = json.loads(consensus_path.read_text(encoding="utf-8")) if consensus_path.exists() else {}
    components = component_hashes(
        audit_jsonl=files["audit.jsonl"].decode("utf-8"),
        ledger_sha256=files["ledger.sha256"].decode("utf-8").strip(),
        signatures=signatures,
        consensus_evidence=consensus_evidence,
        deployment_provenance=json.loads(files["governance_release.json"].decode("utf-8")),
    )
    return message_imprint(components)


def _attestation_evidence_hash(bundle_dir: Path) -> str:
    consensus_path = bundle_dir / "consensus_evidence.json"
    if not consensus_path.exists():
        return ""
    try:
        consensus_evidence = json.loads(consensus_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise WORMArchiveError("archive_consensus_evidence_invalid") from exc
    attestation_evidence = []
    if isinstance(consensus_evidence, dict):
        for evidence in consensus_evidence.values():
            if isinstance(evidence, dict) and isinstance(evidence.get("attestation_evidence"), list):
                attestation_evidence.extend(evidence["attestation_evidence"])
    return hashlib.sha256(canonical_json(attestation_evidence).encode("utf-8")).hexdigest()


class WORMArchive:
    def __init__(
        self,
        root: Path | str,
        *,
        primary_region: str = "usbay-primary",
        secondary_region: str = "usbay-secondary",
        archive_mode: str = "local_mock",
        retention_policy_path: Path | str = DEFAULT_RETENTION_POLICY_PATH,
    ) -> None:
        self.root = Path(root)
        self.primary_region = primary_region
        self.secondary_region = secondary_region
        self.archive_mode = archive_mode
        self.retention_policy_path = Path(retention_policy_path)
        if self.archive_mode not in {"local_mock", "external_worm"}:
            raise WORMArchiveError("invalid_archive_mode")
        if self.archive_mode == "local_mock" and environment_mode() == "production":
            raise WORMArchiveError("worm_archive_unavailable_in_production")

    def _region_dir(self, region: str, object_id: str) -> Path:
        return self.root / region / object_id

    def _manifest_path(self, object_id: str) -> Path:
        return self.root / DEFAULT_MANIFEST_NAME if object_id == "" else self.root / object_id / DEFAULT_MANIFEST_NAME

    def archive_bundle(self, bundle_dir: Path | str, *, now: datetime | None = None) -> dict[str, Any]:
        source = Path(bundle_dir)
        policy = load_retention_policy(self.retention_policy_path)
        files = _read_required_bundle(source)
        if _contains_secret(files):
            raise WORMArchiveError("archive_secret_leakage_detected")
        object_id = object_id_for_bundle(source)
        primary_dir = self._region_dir(self.primary_region, object_id)
        secondary_dir = self._region_dir(self.secondary_region, object_id)
        if primary_dir.exists() or secondary_dir.exists():
            raise WORMArchiveError("worm_overwrite_rejected")
        for region_dir in (primary_dir, secondary_dir):
            region_dir.mkdir(parents=True, exist_ok=False)
            for name in REQUIRED_BUNDLE_FILES:
                (region_dir / name).write_bytes(files[name])
            consensus_path = source / "consensus_evidence.json"
            if consensus_path.exists():
                shutil.copy2(consensus_path, region_dir / "consensus_evidence.json")
        primary_hashes = _object_hashes({path.name: path.read_bytes() for path in primary_dir.iterdir() if path.is_file()})
        secondary_hashes = _object_hashes({path.name: path.read_bytes() for path in secondary_dir.iterdir() if path.is_file()})
        if primary_hashes != secondary_hashes:
            raise WORMArchiveError("replica_hash_mismatch")
        manifest = {
            "object_id": object_id,
            "primary_region": self.primary_region,
            "secondary_region": self.secondary_region,
            "object_hashes": primary_hashes,
            "retention_until": _retention_until(policy, now=now),
            "archive_mode": self.archive_mode,
            "replication_status": "verified",
            "retention_policy": policy,
            "message_imprint": _bundle_message_imprint(source, files),
            "attestation_evidence_hash": _attestation_evidence_hash(source),
        }
        manifest_path = self.root / object_id / DEFAULT_MANIFEST_NAME
        manifest_path.parent.mkdir(parents=True, exist_ok=False)
        manifest_path.write_text(canonical_json(manifest), encoding="utf-8")
        return manifest

    def load_manifest(self, object_id: str) -> dict[str, Any]:
        manifest_path = self.root / object_id / DEFAULT_MANIFEST_NAME
        if not manifest_path.is_file():
            raise WORMArchiveError("archive_manifest_missing")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise WORMArchiveError("archive_manifest_invalid") from exc
        if not isinstance(manifest, dict):
            raise WORMArchiveError("archive_manifest_invalid")
        return manifest

    def validate_archive(self, object_id: str) -> bool:
        manifest = self.load_manifest(object_id)
        required = {
            "primary_region",
            "secondary_region",
            "object_hashes",
            "retention_until",
            "archive_mode",
            "replication_status",
        }
        if any(manifest.get(field) in (None, "") for field in required):
            raise WORMArchiveError("archive_manifest_invalid")
        primary_dir = self._region_dir(str(manifest["primary_region"]), object_id)
        secondary_dir = self._region_dir(str(manifest["secondary_region"]), object_id)
        primary_files = {path.name: path.read_bytes() for path in primary_dir.iterdir() if path.is_file()}
        secondary_files = {path.name: path.read_bytes() for path in secondary_dir.iterdir() if path.is_file()}
        primary_hashes = _object_hashes(primary_files)
        secondary_hashes = _object_hashes(secondary_files)
        if primary_hashes != manifest["object_hashes"]:
            raise WORMArchiveError("archive_object_hash_mismatch")
        if primary_hashes != secondary_hashes:
            raise WORMArchiveError("replica_hash_mismatch")
        if _contains_secret(primary_files) or _contains_secret(secondary_files):
            raise WORMArchiveError("archive_secret_leakage_detected")
        if manifest.get("replication_status") != "verified":
            raise WORMArchiveError("replica_hash_mismatch")
        return True

    def delete_archive(self, object_id: str, *, now: datetime | None = None) -> None:
        manifest = self.load_manifest(object_id)
        policy = manifest.get("retention_policy")
        if not isinstance(policy, dict):
            raise WORMArchiveError("invalid_retention_policy:missing")
        if policy.get("legal_hold") is True:
            raise WORMArchiveError("legal_hold_active")
        current = now or _utc_now()
        retention_until = _parse_utc(str(manifest.get("retention_until", "")))
        if current < retention_until:
            raise WORMArchiveError("retention_window_active")
        raise WORMArchiveError("worm_delete_not_supported")
