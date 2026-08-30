from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "governance" / "media_crypto_authority_policy.json"
MANIFEST_PATH = ROOT / "artifacts" / "media-crypto-authority-manifest.json"


def load_media_crypto_authority_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_media_crypto_authority_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def valid_crypto_authority_manifest() -> dict[str, Any]:
    return load_media_crypto_authority_manifest()


def verify_media_crypto_authority(
    manifest: dict[str, Any] | None,
    *,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_policy = policy or load_media_crypto_authority_policy()
    if resolved_policy.get("non_production_scaffolding") is not True:
        return _fail_closed("MEDIA_CRYPTO_AUTHORITY_POLICY_SCOPE_UNCLEAR")
    if manifest is None:
        return _fail_closed("MEDIA_CRYPTO_AUTHORITY_MANIFEST_MISSING")
    if not isinstance(manifest, dict):
        return _fail_closed("MEDIA_CRYPTO_AUTHORITY_MANIFEST_MALFORMED")
    if manifest.get("non_production_demo") is not True or manifest.get("reference_only") is not True:
        return _fail_closed("MEDIA_CRYPTO_AUTHORITY_SCOPE_UNCLEAR")
    for field in (
        "approval_signature_reference",
        "recovery_signature_reference",
        "escalation_signature_reference",
        "manifest_signature_reference",
    ):
        if not manifest.get(field):
            return _fail_closed("MEDIA_CRYPTO_SIGNATURE_REFERENCE_MISSING")
    if manifest.get("signing_authority") not in resolved_policy["trusted_placeholder_authorities"]:
        return _fail_closed("MEDIA_CRYPTO_SIGNING_AUTHORITY_UNKNOWN")
    if manifest.get("key_reference_fresh") is not True:
        return _fail_closed("MEDIA_CRYPTO_KEY_REFERENCE_STALE")
    if manifest.get("signature_scope_bound") is not True:
        return _fail_closed("MEDIA_CRYPTO_SIGNATURE_SCOPE_UNBOUND")

    return {
        "crypto_authority_reference_only": True,
        "decision": "PASS",
        "fail_closed": False,
        "non_production_scaffolding": True,
        "reason": "MEDIA_CRYPTO_AUTHORITY_VALID",
    }


def _fail_closed(reason: str) -> dict[str, Any]:
    return {"decision": "FAIL_CLOSED", "fail_closed": True, "reason": reason, "silent_pass": False}
