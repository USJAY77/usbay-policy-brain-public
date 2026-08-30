from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "governance" / "media_rights_consent_policy.json"
REQUIRED_CONSENT_FIELDS = (
    "actor_consent",
    "voice_consent",
    "music_sample_clearance",
    "dataset_source_authorization",
    "royalty_review",
    "legal_reviewer_approval",
)


def load_media_rights_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def valid_rights_consent_evidence() -> dict[str, Any]:
    return {
        "actor_consent": _approved_evidence("actor_consent"),
        "dataset_source_authorization": _approved_evidence("dataset_source_authorization"),
        "legal_reviewer_approval": _approved_evidence("legal_reviewer_approval"),
        "music_sample_clearance": _approved_evidence("music_sample_clearance"),
        "royalty_review": _approved_evidence("royalty_review"),
        "voice_consent": _approved_evidence("voice_consent"),
    }


def verify_media_rights_consent(
    evidence: dict[str, Any] | None,
    *,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_policy = policy or load_media_rights_policy()
    if evidence is None:
        return _fail_closed("MEDIA_RIGHTS_CONSENT_EVIDENCE_MISSING")
    if not isinstance(evidence, dict):
        return _fail_closed("MEDIA_RIGHTS_CONSENT_EVIDENCE_MALFORMED")

    if resolved_policy.get("fail_closed_on_missing_consent") is not True:
        return _fail_closed("MEDIA_RIGHTS_MISSING_CONSENT_FAIL_CLOSED_DISABLED")
    if resolved_policy.get("fail_closed_on_expired_consent") is not True:
        return _fail_closed("MEDIA_RIGHTS_EXPIRED_CONSENT_FAIL_CLOSED_DISABLED")
    if resolved_policy.get("non_production_scaffolding") is not True:
        return _fail_closed("MEDIA_RIGHTS_POLICY_SCOPE_UNCLEAR")

    missing = [field for field in REQUIRED_CONSENT_FIELDS if field not in evidence]
    if missing:
        return _fail_closed("MEDIA_RIGHTS_CONSENT_EVIDENCE_MISSING", missing_fields=missing)

    field_reason_map = {
        "actor_consent": "MEDIA_ACTOR_CONSENT_MISSING",
        "voice_consent": "MEDIA_VOICE_CONSENT_MISSING",
        "music_sample_clearance": "MEDIA_SAMPLE_CLEARANCE_MISSING",
        "dataset_source_authorization": "MEDIA_DATASET_SOURCE_AUTHORIZATION_MISSING",
        "royalty_review": "MEDIA_ROYALTY_REVIEW_MISSING",
        "legal_reviewer_approval": "MEDIA_LEGAL_REVIEW_MISSING",
    }
    for field, reason in field_reason_map.items():
        result = _validate_approved_field(evidence[field], reason)
        if result["decision"] == "FAIL_CLOSED":
            return result

    return {
        "decision": "PASS",
        "fail_closed": False,
        "non_production_scaffolding": True,
        "reason": "MEDIA_RIGHTS_CONSENT_VALID",
        "rights_release_authority": "NON_PRODUCTION_PLACEHOLDER",
    }


def _approved_evidence(evidence_type: str) -> dict[str, Any]:
    return {
        "approved": True,
        "evidence_type": evidence_type,
        "expires_at": "2027-05-25T00:00:00Z",
        "reviewer_placeholder": "human-reviewer-placeholder",
    }


def _validate_approved_field(value: Any, missing_reason: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        return _fail_closed("MEDIA_RIGHTS_CONSENT_EVIDENCE_MALFORMED")
    if value.get("approved") is not True:
        return _fail_closed(missing_reason)
    if value.get("expires_at") <= "2026-05-25T00:00:00Z":
        return _fail_closed("MEDIA_CONSENT_EXPIRED")
    return {"decision": "PASS"}


def _fail_closed(reason: str, **details: Any) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "decision": "FAIL_CLOSED",
        "fail_closed": True,
        "reason": reason,
        "silent_pass": False,
    }
    evidence.update(details)
    return evidence
