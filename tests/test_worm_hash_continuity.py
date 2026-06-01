from __future__ import annotations

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "governance" / "worm" / "evidence_manifest_schema.yaml"
RETENTION_REQUIREMENTS = ROOT / "docs" / "governance" / "WORM_RETENTION_REQUIREMENTS.md"
PROVIDER_CHECKLIST = ROOT / "docs" / "governance" / "WORM_PROVIDER_EVIDENCE_CHECKLIST.md"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hash_continuity_valid(*, local_hash: str, provider_hash: str, export_hash: str) -> bool:
    return bool(local_hash and local_hash == provider_hash == export_hash)


def test_hash_continuity_requires_matching_local_provider_and_export_hashes() -> None:
    digest = _sha256(b"pilot evidence")

    assert _hash_continuity_valid(local_hash=digest, provider_hash=digest, export_hash=digest) is True
    assert _hash_continuity_valid(local_hash=digest, provider_hash=_sha256(b"tampered"), export_hash=digest) is False


def test_schema_blocks_missing_or_mismatched_sha256_evidence() -> None:
    text = SCHEMA.read_text(encoding="utf-8")

    assert "sha256_evidence_hash" in text
    assert "sha256_hash_missing" in text
    assert "sha256_hash_mismatch" in text
    assert "default_decision: BLOCKED" in text


def test_retention_and_provider_docs_require_delete_and_overwrite_denial() -> None:
    retention_text = RETENTION_REQUIREMENTS.read_text(encoding="utf-8")
    checklist_text = PROVIDER_CHECKLIST.read_text(encoding="utf-8")

    assert "Evidence that delete is denied during retention." in retention_text
    assert "Evidence that overwrite is denied during retention." in retention_text
    assert "Delete attempt is denied." in checklist_text
    assert "Overwrite attempt is denied." in checklist_text
