from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tests.helpers.media_audit_export_policy import (
    valid_audit_export_manifest,
    verify_media_audit_export_manifest,
)
from tests.helpers.media_jurisdiction_policy import (
    load_media_jurisdiction_export_manifest,
    valid_jurisdiction_evidence,
    verify_jurisdiction_export_manifest,
    verify_media_jurisdiction,
)
from tests.helpers.media_model_drift_policy import valid_drift_evidence, verify_media_model_drift
from tests.helpers.media_governance_watchtower_policy import (
    valid_watchtower_metrics,
    verify_governance_watchtower,
)
from tests.helpers.media_distribution_gateway_policy import (
    valid_distribution_authorization,
    verify_distribution_authorization,
)
from tests.helpers.media_release_token_policy import valid_release_token, verify_media_release_token
from tests.helpers.media_revocation_policy import valid_revocation_state, verify_media_revocation_state
from tests.helpers.media_rights_consent_policy import (
    valid_rights_consent_evidence,
    verify_media_rights_consent,
)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "artifacts" / "media-governance-demo-manifest.json"
ALLOWED_ASSET_TYPES = {"music", "film", "voice", "image", "trailer"}
RELEASE_STATES = {"BLOCKED", "REVIEW_REQUIRED", "VERIFIED_RELEASE"}
FORBIDDEN_LOG_MARKERS = (
    "BEGIN " + "PRIVATE KEY",
    "api_key",
    "credentials",
    "legal_contract",
    "oauth" + "_token",
    "token",
    "raw_audio",
    "raw_video",
    "raw_voice",
    "raw_image",
    "script:",
    "copyrighted_content",
    "lyrics:",
    "voice_sample",
)


def _manifest(**overrides: Any) -> dict[str, Any]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    manifest.update(overrides)
    return manifest


def _approval_evidence() -> dict[str, Any]:
    return {"approved": True, "approver_count": 2, "approval_chain_reference": "governance/approved_github_actions_policy.approvals.json"}


def _timestamp_evidence() -> dict[str, Any]:
    return {"timestamp_verified": True, "timestamp_policy_reference": "governance/rfc3161_timestamp_policy.json"}


def _release_decision(
    manifest: dict[str, Any],
    *,
    approval: dict[str, Any] | None = None,
    timestamp: dict[str, Any] | None = None,
    rights_consent: dict[str, Any] | None = None,
    release_token: dict[str, Any] | None = None,
    distribution_authorization: dict[str, Any] | None = None,
    revocation_state: dict[str, Any] | None = None,
    jurisdiction_evidence: dict[str, Any] | None = None,
    drift_evidence: dict[str, Any] | None = None,
    watchtower_metrics: dict[str, Any] | None = None,
    platform: str = "spotify",
    observed_provenance_hash: str | None = None,
    logs: list[str] | None = None,
) -> dict[str, Any]:
    if manifest.get("asset_type") not in ALLOWED_ASSET_TYPES:
        return _fail_closed("MEDIA_ASSET_TYPE_UNSUPPORTED")
    if manifest.get("release_status") not in RELEASE_STATES:
        return _fail_closed("MEDIA_RELEASE_STATUS_UNSUPPORTED")
    if manifest.get("human_approval_required") is not True:
        return _fail_closed("MEDIA_HUMAN_APPROVAL_POLICY_MISSING")
    if manifest.get("fail_closed_on_missing_approval") is not True:
        return _fail_closed("MEDIA_APPROVAL_FAIL_CLOSED_DISABLED")
    if manifest.get("fail_closed_on_missing_timestamp") is not True:
        return _fail_closed("MEDIA_TIMESTAMP_FAIL_CLOSED_DISABLED")
    if manifest.get("non_production_demo") is not True:
        return _fail_closed("MEDIA_DEMO_SCOPE_UNCLEAR")

    if _logs_contain_raw_media(logs or []):
        return _fail_closed("MEDIA_RAW_PAYLOAD_LOGGED")
    if manifest["release_status"] in {"BLOCKED", "REVIEW_REQUIRED"}:
        return _fail_closed(f"MEDIA_RELEASE_{manifest['release_status']}")
    if not approval or approval.get("approved") is not True or approval.get("approver_count", 0) < 2:
        return _fail_closed("MEDIA_APPROVAL_MISSING")
    if not timestamp or timestamp.get("timestamp_verified") is not True:
        return _fail_closed("MEDIA_TIMESTAMP_MISSING")
    if observed_provenance_hash != manifest.get("provenance_hash_placeholder"):
        return _fail_closed("MEDIA_PROVENANCE_HASH_MISMATCH")
    rights_decision = verify_media_rights_consent(rights_consent)
    if rights_decision["decision"] != "PASS":
        return rights_decision
    token_decision = verify_media_release_token(release_token, media_asset_id=manifest["media_asset_id"])
    if token_decision["decision"] != "PASS":
        return token_decision
    distribution_decision = verify_distribution_authorization(
        distribution_authorization,
        media_asset_id=manifest["media_asset_id"],
        platform=platform,
    )
    if distribution_decision["decision"] != "PASS":
        return distribution_decision
    revocation_decision = verify_media_revocation_state(revocation_state, media_asset_id=manifest["media_asset_id"])
    if revocation_decision["decision"] != "PASS":
        return revocation_decision
    jurisdiction_decision = verify_media_jurisdiction(
        jurisdiction_evidence,
        media_asset_id=manifest["media_asset_id"],
        platform=platform,
    )
    if jurisdiction_decision["decision"] != "PASS":
        return jurisdiction_decision
    drift_decision = verify_media_model_drift(drift_evidence, media_asset_id=manifest["media_asset_id"])
    if drift_decision["decision"] != "PASS":
        return drift_decision
    watchtower_decision = verify_governance_watchtower(watchtower_metrics)
    if watchtower_decision["decision"] != "PASS":
        return watchtower_decision

    return {
        "distribution_authorized": True,
        "decision": "PASS",
        "jurisdiction_scope": jurisdiction_decision["jurisdiction_scope"],
        "media_asset_id": manifest["media_asset_id"],
        "model_drift_clear": True,
        "platform": platform,
        "release_status": "VERIFIED_RELEASE",
        "release_token_verified": True,
        "revocation_clear": True,
        "rights_consent_verified": True,
        "watchtower_state": watchtower_decision["escalation_state"],
        "raw_media_stored": False,
        "reason": "MEDIA_RELEASE_GOVERNANCE_VERIFIED",
    }


def _audit_export_decision(export_manifest: dict[str, Any] | None, *, logs: list[str] | None = None) -> dict[str, Any]:
    if _logs_contain_raw_media(logs or []):
        return _fail_closed("MEDIA_AUDIT_EXPORT_SENSITIVE_PAYLOAD_DETECTED")
    return verify_media_audit_export_manifest(export_manifest)


def _logs_contain_raw_media(logs: list[str]) -> bool:
    combined = "\n".join(logs).lower()
    return any(marker.lower() in combined for marker in FORBIDDEN_LOG_MARKERS)


def _fail_closed(reason: str) -> dict[str, Any]:
    return {"decision": "FAIL_CLOSED", "fail_closed": True, "reason": reason, "silent_pass": False}


def test_media_release_without_approval_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")

    decision = _release_decision(
        manifest,
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_APPROVAL_MISSING"
    assert decision["silent_pass"] is False


def test_media_release_without_timestamp_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_TIMESTAMP_MISSING"
    assert decision["silent_pass"] is False


def test_provenance_mismatch_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=valid_watchtower_metrics(),
        observed_provenance_hash="b" * 64,
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_PROVENANCE_HASH_MISMATCH"
    assert decision["silent_pass"] is False


def test_review_required_status_blocks_release() -> None:
    manifest = _manifest(release_status="REVIEW_REQUIRED")

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=valid_watchtower_metrics(),
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_RELEASE_REVIEW_REQUIRED"
    assert decision["silent_pass"] is False


def test_verified_release_requires_approval_timestamp_and_provenance_hash() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=valid_watchtower_metrics(),
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "PASS"
    assert decision["distribution_authorized"] is True
    assert decision["jurisdiction_scope"] == "eu_ai_act"
    assert decision["model_drift_clear"] is True
    assert decision["platform"] == "spotify"
    assert decision["release_status"] == "VERIFIED_RELEASE"
    assert decision["release_token_verified"] is True
    assert decision["revocation_clear"] is True
    assert decision["rights_consent_verified"] is True
    assert decision["raw_media_stored"] is False


def test_verified_release_requires_release_token() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=valid_watchtower_metrics(),
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_RELEASE_TOKEN_MISSING"
    assert decision["silent_pass"] is False


def test_verified_release_blocks_expired_release_token() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    token = valid_release_token(manifest["media_asset_id"])
    token["expires_at"] = "2026-05-24T00:00:00Z"

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=token,
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=valid_watchtower_metrics(),
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_RELEASE_TOKEN_EXPIRED"
    assert decision["silent_pass"] is False


def test_verified_release_blocks_wrong_media_asset_release_token() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token("other-media-asset"),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=valid_watchtower_metrics(),
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_RELEASE_TOKEN_SCOPE_INVALID"
    assert decision["silent_pass"] is False


def test_verified_release_requires_rights_and_consent_evidence() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    token = valid_release_token(manifest["media_asset_id"])
    token["rights_consent_bound"] = False

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        release_token=token,
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=valid_watchtower_metrics(),
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_RIGHTS_CONSENT_EVIDENCE_MISSING"
    assert decision["silent_pass"] is False


def test_verified_release_blocks_missing_legal_review() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    rights = valid_rights_consent_evidence()
    rights["legal_reviewer_approval"]["approved"] = False

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=rights,
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=valid_watchtower_metrics(),
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_LEGAL_REVIEW_MISSING"
    assert decision["silent_pass"] is False


def test_no_raw_media_audio_or_video_is_stored_in_manifest_or_logs() -> None:
    manifest_text = MANIFEST_PATH.read_text(encoding="utf-8").lower()
    decision = _release_decision(_manifest(), logs=["hash_only_provenance=aaaaaaaa"])

    for marker in FORBIDDEN_LOG_MARKERS:
        assert marker.lower() not in manifest_text
    assert decision["reason"] == "MEDIA_RELEASE_REVIEW_REQUIRED"


def test_raw_media_marker_in_logs_fails_closed() -> None:
    decision = _release_decision(_manifest(release_status="VERIFIED_RELEASE"), logs=["raw_audio=..."])

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_RAW_PAYLOAD_LOGGED"
    assert decision["silent_pass"] is False


def test_no_raw_media_legal_contracts_oauth_tokens_or_copyright_payloads_are_stored() -> None:
    manifest_text = MANIFEST_PATH.read_text(encoding="utf-8").lower()

    for marker in (
        "raw_audio",
        "raw_video",
        "lyrics:",
        "script:",
        "voice_sample",
        "copyrighted_content",
        "credentials",
        "legal_contract",
        "oauth" + "_token",
    ):
        assert marker not in manifest_text


def test_release_token_without_timestamp_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    token = valid_release_token(manifest["media_asset_id"])
    token["timestamp_bound"] = False

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=token,
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=valid_watchtower_metrics(),
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_RELEASE_TOKEN_TIMESTAMP_MISSING"
    assert decision["silent_pass"] is False


def test_release_token_without_rights_consent_binding_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    token = valid_release_token(manifest["media_asset_id"])
    token["rights_consent_bound"] = False

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=token,
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=valid_watchtower_metrics(),
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_RELEASE_TOKEN_RIGHTS_CONSENT_MISSING"
    assert decision["silent_pass"] is False


def test_release_token_without_approval_chain_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    token = valid_release_token(manifest["media_asset_id"])
    token["approval_chain_bound"] = False

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=token,
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=valid_watchtower_metrics(),
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_RELEASE_TOKEN_APPROVAL_CHAIN_MISSING"
    assert decision["silent_pass"] is False


def test_verified_release_still_blocked_without_distributor_authorization() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=valid_watchtower_metrics(),
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_DISTRIBUTION_AUTHORITY_MISSING"
    assert decision["silent_pass"] is False


def test_unknown_distribution_platform_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"], "unapproved_platform"),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=valid_watchtower_metrics(),
        platform="unapproved_platform",
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_DISTRIBUTION_PLATFORM_UNKNOWN"
    assert decision["silent_pass"] is False


def test_wrong_distribution_platform_scope_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    authorization = valid_distribution_authorization(manifest["media_asset_id"], "spotify")
    authorization["platform_scope"] = "youtube"

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=authorization,
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=valid_watchtower_metrics(),
        platform="spotify",
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_DISTRIBUTION_PLATFORM_SCOPE_MISMATCH"
    assert decision["silent_pass"] is False


def test_unsigned_distribution_request_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    authorization = valid_distribution_authorization(manifest["media_asset_id"], "spotify")
    authorization["request_signature_state"] = "UNSIGNED"

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=authorization,
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=valid_watchtower_metrics(),
        platform="spotify",
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_DISTRIBUTION_REQUEST_UNSIGNED"
    assert decision["silent_pass"] is False


def test_distribution_authorization_missing_rights_consent_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    authorization = valid_distribution_authorization(manifest["media_asset_id"], "spotify")
    authorization["rights_consent_bound"] = False

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=authorization,
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=valid_watchtower_metrics(),
        platform="spotify",
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_DISTRIBUTION_RIGHTS_CONSENT_MISSING"
    assert decision["silent_pass"] is False


def test_revoked_release_token_blocks_distribution() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    revocation = valid_revocation_state(manifest["media_asset_id"])
    revocation["release_token_revoked"] = True

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=revocation,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_RELEASE_TOKEN_REVOKED"
    assert decision["silent_pass"] is False


def test_emergency_freeze_overrides_verified_release() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    revocation = valid_revocation_state(manifest["media_asset_id"])
    revocation["release_state"] = "EMERGENCY_FROZEN"

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=revocation,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_EMERGENCY_FROZEN"
    assert decision["silent_pass"] is False


def test_revoked_rights_consent_fails_closed_after_release() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    revocation = valid_revocation_state(manifest["media_asset_id"])
    revocation["rights_consent_revoked"] = True

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=revocation,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_RIGHTS_CONSENT_REVOKED"
    assert decision["silent_pass"] is False


def test_platform_takedown_state_blocks_publication() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    revocation = valid_revocation_state(manifest["media_asset_id"])
    revocation["release_state"] = "PLATFORM_TAKEDOWN_REQUIRED"

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=revocation,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_PLATFORM_TAKEDOWN_REQUIRED"
    assert decision["silent_pass"] is False


def test_dispute_hold_blocks_distribution() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    revocation = valid_revocation_state(manifest["media_asset_id"])
    revocation["release_state"] = "LEGAL_DISPUTE_HOLD"

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=revocation,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_LEGAL_DISPUTE_HOLD"
    assert decision["silent_pass"] is False


def test_revoked_distribution_authority_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    revocation = valid_revocation_state(manifest["media_asset_id"])
    revocation["distribution_authority_active"] = False

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=revocation,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_DISTRIBUTION_AUTHORITY_REVOKED"
    assert decision["silent_pass"] is False


def test_audit_export_without_scope_fails_closed() -> None:
    export_manifest = valid_audit_export_manifest()
    export_manifest["export_scope"] = ""

    decision = _audit_export_decision(export_manifest)

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_AUDIT_EXPORT_SCOPE_MISSING"
    assert decision["silent_pass"] is False


def test_audit_export_without_provenance_chain_fails_closed() -> None:
    export_manifest = valid_audit_export_manifest()
    export_manifest["provenance_reference"] = ""

    decision = _audit_export_decision(export_manifest)

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_AUDIT_EXPORT_LINEAGE_MISSING"
    assert decision["silent_pass"] is False


def test_audit_export_without_approval_chain_fails_closed() -> None:
    export_manifest = valid_audit_export_manifest()
    export_manifest["approval_chain_reference"] = ""

    decision = _audit_export_decision(export_manifest)

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_AUDIT_EXPORT_LINEAGE_MISSING"
    assert decision["silent_pass"] is False


def test_audit_export_with_revoked_authority_fails_closed() -> None:
    export_manifest = valid_audit_export_manifest()
    export_manifest["revocation_reference"] = ""

    decision = _audit_export_decision(export_manifest)

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_AUDIT_EXPORT_LINEAGE_MISSING"
    assert decision["silent_pass"] is False


def test_audit_export_sensitive_payload_marker_fails_closed() -> None:
    export_manifest = valid_audit_export_manifest()
    export_manifest["payload"] = "legal_contract=..."

    decision = _audit_export_decision(export_manifest)

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_AUDIT_EXPORT_SENSITIVE_PAYLOAD_DETECTED"
    assert decision["silent_pass"] is False


def test_unsigned_audit_export_manifest_fails_closed() -> None:
    export_manifest = valid_audit_export_manifest()
    export_manifest["signature_placeholder"] = ""

    decision = _audit_export_decision(export_manifest)

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_AUDIT_EXPORT_MANIFEST_UNSIGNED"
    assert decision["silent_pass"] is False


def test_regulator_export_contains_references_only_not_payloads() -> None:
    export_manifest = valid_audit_export_manifest()

    decision = _audit_export_decision(export_manifest)

    assert decision["decision"] == "PASS"
    assert decision["export_contains_references_only"] is True
    for forbidden_field in (
        "raw_media",
        "raw_audio",
        "raw_video",
        "oauth" + "_token",
        "legal_contract",
        "personal_data",
    ):
        assert forbidden_field not in export_manifest


def test_verified_release_cannot_bypass_jurisdiction_governance() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_JURISDICTION_SCOPE_MISSING"
    assert decision["silent_pass"] is False


def test_unknown_jurisdiction_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"], jurisdiction="unknown_region"),
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_JURISDICTION_UNKNOWN"
    assert decision["silent_pass"] is False


def test_revoked_rights_in_region_block_distribution_in_that_region() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    jurisdiction = valid_jurisdiction_evidence(manifest["media_asset_id"], jurisdiction="us_media_rights")
    jurisdiction["regional_rights_active"] = False

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=jurisdiction,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_REGIONAL_RIGHTS_REVOKED"
    assert decision["silent_pass"] is False


def test_cross_region_policy_conflict_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    jurisdiction = valid_jurisdiction_evidence(manifest["media_asset_id"])
    jurisdiction["cross_jurisdiction_conflict"] = True

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=jurisdiction,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_CROSS_JURISDICTION_CONFLICT"
    assert decision["silent_pass"] is False


def test_restricted_platform_distribution_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    jurisdiction = valid_jurisdiction_evidence(manifest["media_asset_id"])
    jurisdiction["platform_restricted"] = True

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=jurisdiction,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_RESTRICTED_PLATFORM_DISTRIBUTION"
    assert decision["silent_pass"] is False


def test_audit_export_without_jurisdiction_scope_fails_closed() -> None:
    export_manifest = load_media_jurisdiction_export_manifest()
    export_manifest["jurisdiction_scope"] = ""

    decision = verify_jurisdiction_export_manifest(export_manifest)

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_AUDIT_EXPORT_JURISDICTION_SCOPE_MISSING"
    assert decision["silent_pass"] is False


def test_emergency_freeze_propagates_across_linked_jurisdictions() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    jurisdiction = valid_jurisdiction_evidence(manifest["media_asset_id"])
    jurisdiction["linked_emergency_freeze"] = True

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=jurisdiction,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_JURISDICTION_EMERGENCY_FREEZE_PROPAGATED"
    assert decision["silent_pass"] is False


def test_verified_release_cannot_bypass_model_drift_governance() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_MODEL_DRIFT_EVIDENCE_MISSING"
    assert decision["silent_pass"] is False


def test_model_version_mismatch_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    drift = valid_drift_evidence(manifest["media_asset_id"])
    drift["model_version"] = "media-demo-model-v2"

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=drift,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_MODEL_VERSION_DRIFT"
    assert decision["silent_pass"] is False


def test_provenance_continuity_gap_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    drift = valid_drift_evidence(manifest["media_asset_id"])
    drift["provenance_continuity"] = False

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=drift,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_PROVENANCE_CHAIN_GAP"
    assert decision["silent_pass"] is False


def test_approval_chain_regression_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    drift = valid_drift_evidence(manifest["media_asset_id"])
    drift["approval_chain_regression"] = True

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=drift,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_APPROVAL_CHAIN_REGRESSION"
    assert decision["silent_pass"] is False


def test_export_schema_drift_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    drift = valid_drift_evidence(manifest["media_asset_id"])
    drift["export_schema_drift"] = True

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=drift,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_EXPORT_SCHEMA_DRIFT"
    assert decision["silent_pass"] is False


def test_jurisdiction_drift_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    drift = valid_drift_evidence(manifest["media_asset_id"])
    drift["jurisdiction_policy_drift"] = True

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=drift,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_JURISDICTION_POLICY_DRIFT"
    assert decision["silent_pass"] is False


def test_revocation_override_loss_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    drift = valid_drift_evidence(manifest["media_asset_id"])
    drift["revocation_override_present"] = False

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=drift,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_REVOCATION_OVERRIDE_LOST"
    assert decision["silent_pass"] is False


def test_stale_policy_lineage_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    drift = valid_drift_evidence(manifest["media_asset_id"])
    drift["policy_lineage_valid"] = False

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=drift,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_POLICY_LINEAGE_BROKEN"
    assert decision["silent_pass"] is False


def test_repeated_drift_events_degrade_governance_score() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    metrics = valid_watchtower_metrics()
    metrics["drift_event_count"] = 3

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=metrics,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_WATCHTOWER_REPEATED_DRIFT_EVENTS"
    assert decision["escalation_state"] == "GOVERNANCE_DEGRADED"
    assert decision["silent_pass"] is False


def test_unresolved_jurisdiction_conflicts_fail_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    metrics = valid_watchtower_metrics()
    metrics["jurisdiction_conflicts"] = 1

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=metrics,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_WATCHTOWER_UNRESOLVED_JURISDICTION_CONFLICTS"
    assert decision["silent_pass"] is False


def test_excessive_revocations_trigger_governance_degradation() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    metrics = valid_watchtower_metrics()
    metrics["revocation_frequency"] = 3

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=metrics,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_WATCHTOWER_REPEATED_REVOCATION_EVENTS"
    assert decision["escalation_state"] == "GOVERNANCE_DEGRADED"
    assert decision["silent_pass"] is False


def test_export_instability_affects_governance_health() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    metrics = valid_watchtower_metrics()
    metrics["export_failures"] = 2

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=metrics,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_WATCHTOWER_EXPORT_FAILURE_PATTERN"
    assert decision["silent_pass"] is False


def test_lineage_instability_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    metrics = valid_watchtower_metrics()
    metrics["lineage_breaks"] = 1

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=metrics,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_WATCHTOWER_LINEAGE_INSTABILITY"
    assert decision["silent_pass"] is False


def test_governance_critical_state_blocks_verified_release() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    metrics = valid_watchtower_metrics()
    metrics["governance_health_score"] = 40

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=metrics,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_WATCHTOWER_GOVERNANCE_CRITICAL"
    assert decision["escalation_state"] == "GOVERNANCE_CRITICAL"
    assert decision["silent_pass"] is False


def test_governance_fail_closed_state_overrides_all_prior_pass_states() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    metrics = valid_watchtower_metrics()
    metrics["governance_visibility_present"] = False

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(manifest["media_asset_id"]),
        distribution_authorization=valid_distribution_authorization(manifest["media_asset_id"]),
        revocation_state=valid_revocation_state(manifest["media_asset_id"]),
        jurisdiction_evidence=valid_jurisdiction_evidence(manifest["media_asset_id"]),
        drift_evidence=valid_drift_evidence(manifest["media_asset_id"]),
        watchtower_metrics=metrics,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_WATCHTOWER_VISIBILITY_MISSING"
    assert decision["silent_pass"] is False
