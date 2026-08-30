from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "governance" / "media_revocation_policy.json"
PASS_STATES = {"VERIFIED_RELEASE", "DISTRIBUTION_AUTHORIZED"}


def load_media_revocation_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def valid_revocation_state(media_asset_id: str) -> dict[str, Any]:
    return {
        "distribution_authority_active": True,
        "distribution_authority_expires_at": "2027-05-25T00:00:00Z",
        "media_asset_id": media_asset_id,
        "release_state": "DISTRIBUTION_AUTHORIZED",
        "release_token_revoked": False,
        "rights_consent_revoked": False,
        "takedown_review_status": "NOT_REQUIRED",
    }


def verify_media_revocation_state(
    state: dict[str, Any] | None,
    *,
    media_asset_id: str,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_policy = policy or load_media_revocation_policy()
    if resolved_policy.get("non_production_scaffolding") is not True:
        return _fail_closed("MEDIA_REVOCATION_POLICY_SCOPE_UNCLEAR")
    if resolved_policy.get("emergency_freeze_enabled") is not True:
        return _fail_closed("MEDIA_EMERGENCY_FREEZE_DISABLED")
    if resolved_policy.get("release_revocation_supported") is not True:
        return _fail_closed("MEDIA_RELEASE_REVOCATION_UNSUPPORTED")
    if state is None:
        return _fail_closed("MEDIA_REVOCATION_STATE_MISSING")
    if not isinstance(state, dict):
        return _fail_closed("MEDIA_REVOCATION_STATE_MALFORMED")
    if state.get("media_asset_id") != media_asset_id:
        return _fail_closed("MEDIA_REVOCATION_MEDIA_ASSET_SCOPE_MISMATCH")

    release_state = state.get("release_state")
    if release_state not in resolved_policy["revocation_states"]:
        return _fail_closed("MEDIA_REVOCATION_STATE_UNKNOWN")
    if state.get("release_token_revoked") is True:
        return _fail_closed("MEDIA_RELEASE_TOKEN_REVOKED")
    if state.get("rights_consent_revoked") is True:
        return _fail_closed("MEDIA_RIGHTS_CONSENT_REVOKED")
    if state.get("distribution_authority_active") is not True:
        return _fail_closed("MEDIA_DISTRIBUTION_AUTHORITY_REVOKED")
    if state.get("distribution_authority_expires_at") <= "2026-05-26T00:00:00Z":
        return _fail_closed("MEDIA_DISTRIBUTION_AUTHORITY_EXPIRED")
    if release_state == "RELEASE_REVOKED":
        return _fail_closed("MEDIA_RELEASE_REVOKED")
    if release_state == "EMERGENCY_FROZEN":
        return _fail_closed("MEDIA_EMERGENCY_FROZEN")
    if release_state == "LEGAL_DISPUTE_HOLD":
        return _fail_closed("MEDIA_LEGAL_DISPUTE_HOLD")
    if release_state == "PLATFORM_TAKEDOWN_REQUIRED":
        return _fail_closed("MEDIA_PLATFORM_TAKEDOWN_REQUIRED")
    if release_state not in PASS_STATES:
        return _fail_closed("MEDIA_REVOCATION_STATE_NOT_DISTRIBUTABLE")

    return {
        "decision": "PASS",
        "fail_closed": False,
        "media_asset_id": media_asset_id,
        "non_production_scaffolding": True,
        "reason": "MEDIA_REVOCATION_STATE_DISTRIBUTABLE",
        "release_state": release_state,
        "revocation_override_active": False,
    }


def _fail_closed(reason: str) -> dict[str, Any]:
    return {"decision": "FAIL_CLOSED", "fail_closed": True, "reason": reason, "silent_pass": False}
