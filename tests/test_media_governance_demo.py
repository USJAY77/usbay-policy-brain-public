from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tests.helpers.media_release_token_policy import valid_release_token, verify_media_release_token
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

    return {
        "decision": "PASS",
        "media_asset_id": manifest["media_asset_id"],
        "release_status": "VERIFIED_RELEASE",
        "release_token_verified": True,
        "rights_consent_verified": True,
        "raw_media_stored": False,
        "reason": "MEDIA_RELEASE_GOVERNANCE_VERIFIED",
    }


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
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "PASS"
    assert decision["release_status"] == "VERIFIED_RELEASE"
    assert decision["release_token_verified"] is True
    assert decision["rights_consent_verified"] is True
    assert decision["raw_media_stored"] is False


def test_verified_release_requires_release_token() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")

    decision = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
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


def test_no_raw_media_lyrics_scripts_voice_samples_or_copyright_payloads_are_stored() -> None:
    manifest_text = MANIFEST_PATH.read_text(encoding="utf-8").lower()

    for marker in ("raw_audio", "raw_video", "lyrics:", "script:", "voice_sample", "copyrighted_content"):
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
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "MEDIA_RELEASE_TOKEN_APPROVAL_CHAIN_MISSING"
    assert decision["silent_pass"] is False
