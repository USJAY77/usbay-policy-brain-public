from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "governance" / "media_release_token_policy.json"


def load_media_release_token_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def valid_release_token(media_asset_id: str) -> dict[str, Any]:
    return {
        "approval_chain_bound": True,
        "expires_at": "2027-05-25T00:00:00Z",
        "media_asset_id": media_asset_id,
        "non_production_release_token": "MEDIA_RELEASE_TOKEN_PLACEHOLDER_NON_PRODUCTION",
        "provenance_hash_bound": True,
        "rights_consent_bound": True,
        "timestamp_bound": True,
    }


def verify_media_release_token(
    token: dict[str, Any] | None,
    *,
    media_asset_id: str,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_policy = policy or load_media_release_token_policy()
    if resolved_policy.get("release_token_required") is not True:
        return _fail_closed("MEDIA_RELEASE_TOKEN_POLICY_DISABLED")
    if resolved_policy.get("release_token_scope") != "media_asset_id":
        return _fail_closed("MEDIA_RELEASE_TOKEN_SCOPE_POLICY_INVALID")
    if resolved_policy.get("non_production_scaffolding") is not True:
        return _fail_closed("MEDIA_RELEASE_TOKEN_POLICY_SCOPE_UNCLEAR")
    if token is None:
        return _fail_closed("MEDIA_RELEASE_TOKEN_MISSING")
    if not isinstance(token, dict):
        return _fail_closed("MEDIA_RELEASE_TOKEN_MALFORMED")
    if token.get("media_asset_id") != media_asset_id:
        return _fail_closed("MEDIA_RELEASE_TOKEN_SCOPE_INVALID")
    if token.get("expires_at") <= "2026-05-25T00:00:00Z":
        return _fail_closed("MEDIA_RELEASE_TOKEN_EXPIRED")
    if token.get("approval_chain_bound") is not True:
        return _fail_closed("MEDIA_RELEASE_TOKEN_APPROVAL_CHAIN_MISSING")
    if token.get("timestamp_bound") is not True:
        return _fail_closed("MEDIA_RELEASE_TOKEN_TIMESTAMP_MISSING")
    if token.get("provenance_hash_bound") is not True:
        return _fail_closed("MEDIA_RELEASE_TOKEN_PROVENANCE_HASH_MISSING")
    if token.get("rights_consent_bound") is not True:
        return _fail_closed("MEDIA_RELEASE_TOKEN_RIGHTS_CONSENT_MISSING")
    if token.get("non_production_release_token") != "MEDIA_RELEASE_TOKEN_PLACEHOLDER_NON_PRODUCTION":
        return _fail_closed("MEDIA_RELEASE_TOKEN_NOT_PLACEHOLDER_SCAFFOLDING")

    return {
        "decision": "PASS",
        "fail_closed": False,
        "media_asset_id": media_asset_id,
        "non_production_scaffolding": True,
        "production_release_token": False,
        "reason": "MEDIA_RELEASE_TOKEN_VALID",
    }


def _fail_closed(reason: str) -> dict[str, Any]:
    return {"decision": "FAIL_CLOSED", "fail_closed": True, "reason": reason, "silent_pass": False}
