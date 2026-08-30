from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "governance" / "media_distribution_gateway_policy.json"


def load_media_distribution_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def valid_distribution_authorization(media_asset_id: str, platform: str = "spotify") -> dict[str, Any]:
    return {
        "approval_chain_bound": True,
        "distribution_authority": "PLACEHOLDER_DISTRIBUTOR_AUTHORITY_NON_PRODUCTION",
        "media_asset_id": media_asset_id,
        "platform": platform,
        "platform_scope": platform,
        "provenance_bound": True,
        "release_token_bound": True,
        "request_signature_state": "SIGNED_PLACEHOLDER",
        "rights_consent_bound": True,
        "timestamp_bound": True,
    }


def verify_distribution_authorization(
    authorization: dict[str, Any] | None,
    *,
    media_asset_id: str,
    platform: str,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_policy = policy or load_media_distribution_policy()
    if resolved_policy.get("non_production_scaffolding") is not True:
        return _fail_closed("MEDIA_DISTRIBUTION_POLICY_SCOPE_UNCLEAR")
    if resolved_policy.get("distributor_authorization_required") is not True:
        return _fail_closed("MEDIA_DISTRIBUTION_AUTHORITY_POLICY_DISABLED")
    if platform not in resolved_policy["supported_placeholder_platforms"]:
        return _fail_closed("MEDIA_DISTRIBUTION_PLATFORM_UNKNOWN")
    if authorization is None:
        return _fail_closed("MEDIA_DISTRIBUTION_AUTHORITY_MISSING")
    if not isinstance(authorization, dict):
        return _fail_closed("MEDIA_DISTRIBUTION_AUTHORITY_MALFORMED")
    if authorization.get("media_asset_id") != media_asset_id:
        return _fail_closed("MEDIA_DISTRIBUTION_MEDIA_ASSET_SCOPE_MISMATCH")
    if authorization.get("platform") != platform or authorization.get("platform_scope") != platform:
        return _fail_closed("MEDIA_DISTRIBUTION_PLATFORM_SCOPE_MISMATCH")
    if authorization.get("request_signature_state") != "SIGNED_PLACEHOLDER":
        return _fail_closed("MEDIA_DISTRIBUTION_REQUEST_UNSIGNED")
    if authorization.get("distribution_authority") != "PLACEHOLDER_DISTRIBUTOR_AUTHORITY_NON_PRODUCTION":
        return _fail_closed("MEDIA_DISTRIBUTION_AUTHORITY_UNKNOWN")
    if authorization.get("release_token_bound") is not True:
        return _fail_closed("MEDIA_DISTRIBUTION_RELEASE_TOKEN_MISSING")
    if authorization.get("approval_chain_bound") is not True:
        return _fail_closed("MEDIA_DISTRIBUTION_APPROVAL_CHAIN_MISSING")
    if authorization.get("timestamp_bound") is not True:
        return _fail_closed("MEDIA_DISTRIBUTION_TIMESTAMP_MISSING")
    if authorization.get("provenance_bound") is not True:
        return _fail_closed("MEDIA_DISTRIBUTION_PROVENANCE_MISSING")
    if authorization.get("rights_consent_bound") is not True:
        return _fail_closed("MEDIA_DISTRIBUTION_RIGHTS_CONSENT_MISSING")

    return {
        "decision": "PASS",
        "distribution_authorized": True,
        "fail_closed": False,
        "media_asset_id": media_asset_id,
        "non_production_scaffolding": True,
        "platform": platform,
        "production_distribution_authority": False,
        "reason": "MEDIA_DISTRIBUTION_AUTHORIZATION_VALID",
    }


def _fail_closed(reason: str) -> dict[str, Any]:
    return {"decision": "FAIL_CLOSED", "fail_closed": True, "reason": reason, "silent_pass": False}
