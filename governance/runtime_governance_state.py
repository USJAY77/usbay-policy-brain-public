from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


EVIDENCE_DIR = Path("governance/evidence")
FRESHNESS_REPORT = "pb020_freshness_report.json"
STALENESS_REPORT = "pb020_staleness_report.json"
VERSION_REPORT = "pb020_version_alignment_report.json"
SCORECARD = "pb020_evidence_freshness_scorecard.json"

EXPECTED_SCHEMAS = {
    FRESHNESS_REPORT: "usbay.pb020.freshness_report.v1",
    STALENESS_REPORT: "usbay.pb020.staleness_report.v1",
    VERSION_REPORT: "usbay.pb020.version_alignment_report.v1",
    SCORECARD: "usbay.pb020.evidence_freshness_scorecard.v1",
}

READY = "READY"
BLOCKED = "BLOCKED"
PROMOTE_READY = "PROMOTE_READY"
PROMOTE_BLOCKED = "PROMOTE_BLOCKED"
PB019_NOT_APPLICABLE_STATE = "NOT_APPLICABLE_NO_FAILURE_TO_EXPLAIN"
DEFAULT_MAX_AGE_HOURS = 168.0


class RuntimeGovernanceStateError(RuntimeError):
    pass


@dataclass(frozen=True)
class RuntimeGovernanceState:
    status: str
    reason: str
    promote_state: str
    pb020_decision: str
    pb016_decision: str
    pb017_decision: str
    pb018_decision: str
    pb019_requirement: str
    evidence_hash: str
    evidence_generated_at: str
    max_age_hours: float
    fail_closed: bool
    reason_codes: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return self.status == READY and not self.fail_closed

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "usbay.runtime_governance_state.v1",
            "status": self.status,
            "reason": self.reason,
            "promote_state": self.promote_state,
            "pb020_decision": self.pb020_decision,
            "pb016_decision": self.pb016_decision,
            "pb017_decision": self.pb017_decision,
            "pb018_decision": self.pb018_decision,
            "pb019_requirement": self.pb019_requirement,
            "evidence_hash": self.evidence_hash,
            "evidence_generated_at": self.evidence_generated_at,
            "max_age_hours": self.max_age_hours,
            "fail_closed": self.fail_closed,
            "reason_codes": list(self.reason_codes),
        }


def _blocked(reason: str, *, reason_codes: list[str] | None = None, max_age_hours: float) -> RuntimeGovernanceState:
    return RuntimeGovernanceState(
        status=BLOCKED,
        reason=reason,
        promote_state=PROMOTE_BLOCKED,
        pb020_decision="UNKNOWN",
        pb016_decision="UNKNOWN",
        pb017_decision="UNKNOWN",
        pb018_decision="UNKNOWN",
        pb019_requirement="UNKNOWN",
        evidence_hash="",
        evidence_generated_at="",
        max_age_hours=max_age_hours,
        fail_closed=True,
        reason_codes=tuple(reason_codes or [reason]),
    )


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeGovernanceStateError(f"PB020_EVIDENCE_MISSING:{path.name}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeGovernanceStateError(f"PB020_EVIDENCE_INVALID:{path.name}:{exc.msg}") from exc
    except OSError as exc:
        raise RuntimeGovernanceStateError(f"PB020_EVIDENCE_UNREADABLE:{path.name}") from exc
    if not isinstance(payload, dict):
        raise RuntimeGovernanceStateError(f"PB020_EVIDENCE_OBJECT_REQUIRED:{path.name}")
    return payload


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _evidence_hash(payloads: dict[str, dict[str, Any]]) -> str:
    seed = {name: payloads[name] for name in sorted(payloads)}
    return hashlib.sha256(_canonical_json(seed).encode("utf-8")).hexdigest()


def _extract_errors(payloads: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for name, payload in sorted(payloads.items()):
        raw_errors = payload.get("errors", [])
        if isinstance(raw_errors, list):
            errors.extend(f"{name}:{error}" for error in raw_errors)
        elif raw_errors:
            errors.append(f"{name}:PB020_ERRORS_INVALID")
    return errors


def evaluate_runtime_governance_state(
    *,
    root: Path,
    max_age_hours: float = DEFAULT_MAX_AGE_HOURS,
    now: datetime | None = None,
) -> RuntimeGovernanceState:
    evidence_dir = root / EVIDENCE_DIR
    if not evidence_dir.is_dir():
        return _blocked(
            "PB020_EVIDENCE_DIR_MISSING",
            reason_codes=["PB020_EVIDENCE_DIR_MISSING"],
            max_age_hours=max_age_hours,
        )

    try:
        payloads = {
            filename: _load_json(evidence_dir / filename)
            for filename in (FRESHNESS_REPORT, STALENESS_REPORT, VERSION_REPORT, SCORECARD)
        }
    except RuntimeGovernanceStateError as exc:
        return _blocked(str(exc), max_age_hours=max_age_hours)

    reason_codes: list[str] = []
    for filename, expected_schema in EXPECTED_SCHEMAS.items():
        if payloads[filename].get("schema") != expected_schema:
            reason_codes.append(f"PB020_SCHEMA_MISMATCH:{filename}")

    for filename, payload in sorted(payloads.items()):
        if payload.get("decision") != "VERIFIED":
            reason_codes.append(f"PB020_DECISION_NOT_VERIFIED:{filename}")
        if payload.get("fail_closed") is not False:
            reason_codes.append(f"PB020_FAIL_CLOSED:{filename}")

    errors = _extract_errors(payloads)
    if errors:
        reason_codes.extend(f"PB020_ERROR:{error}" for error in errors)

    scorecard = payloads[SCORECARD]
    freshness = payloads[FRESHNESS_REPORT]
    staleness = payloads[STALENESS_REPORT]
    version = payloads[VERSION_REPORT]

    pb016_decision = str(scorecard.get("pb016_decision", "UNKNOWN"))
    pb017_decision = str(scorecard.get("pb017_decision", "UNKNOWN"))
    pb018_decision = str(scorecard.get("pb018_decision", "UNKNOWN"))
    pb019_requirement = str(scorecard.get("pb019_requirement", "UNKNOWN"))

    if pb016_decision != "VERIFIED":
        reason_codes.append("PB016_DECISION_NOT_VERIFIED")
    if pb017_decision != "VERIFIED":
        reason_codes.append("PB017_DECISION_NOT_VERIFIED")
    if pb018_decision != "VERIFIED":
        reason_codes.append("PB018_DECISION_NOT_VERIFIED")
    if scorecard.get("maturity_report_trusted") is not True:
        reason_codes.append("PB016_MATURITY_REPORT_UNTRUSTED")
    if scorecard.get("action_tracker_trusted") is not True:
        reason_codes.append("PB017_ACTION_TRACKER_UNTRUSTED")
    if scorecard.get("certification_result_trusted") is not True:
        reason_codes.append("PB018_CERTIFICATION_RESULT_UNTRUSTED")

    if staleness.get("stale_artifact_count") not in (0, None):
        reason_codes.append("PB020_STALE_EVIDENCE_PRESENT")
    stale_records = staleness.get("stale_artifacts", [])
    if stale_records not in ([], None):
        reason_codes.append("PB020_STALE_EVIDENCE_PRESENT")
    if version.get("version_mismatches") not in (0, None):
        reason_codes.append("PB020_VERSION_MISMATCH_PRESENT")
    if freshness.get("fresh_artifacts") != freshness.get("total_artifacts"):
        reason_codes.append("PB020_FRESHNESS_COUNT_MISMATCH")

    generated_at = str(scorecard.get("generated_at", ""))
    parsed_generated_at = _parse_timestamp(generated_at)
    if parsed_generated_at is None:
        reason_codes.append("PB020_GENERATED_AT_INVALID")
    else:
        effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        age_hours = (effective_now - parsed_generated_at).total_seconds() / 3600
        if age_hours < 0 or age_hours > max_age_hours:
            reason_codes.append("PB020_RUNTIME_EVIDENCE_STALE")

    if reason_codes:
        return RuntimeGovernanceState(
            status=BLOCKED,
            reason=reason_codes[0],
            promote_state=PROMOTE_BLOCKED,
            pb020_decision=str(scorecard.get("decision", "UNKNOWN")),
            pb016_decision=pb016_decision,
            pb017_decision=pb017_decision,
            pb018_decision=pb018_decision,
            pb019_requirement=pb019_requirement,
            evidence_hash=_evidence_hash(payloads),
            evidence_generated_at=generated_at,
            max_age_hours=max_age_hours,
            fail_closed=True,
            reason_codes=tuple(sorted(dict.fromkeys(reason_codes))),
        )

    return RuntimeGovernanceState(
        status=READY,
        reason="PB020_EVIDENCE_VERIFIED",
        promote_state=PROMOTE_READY,
        pb020_decision="VERIFIED",
        pb016_decision=pb016_decision,
        pb017_decision=pb017_decision,
        pb018_decision=pb018_decision,
        pb019_requirement=pb019_requirement,
        evidence_hash=_evidence_hash(payloads),
        evidence_generated_at=generated_at,
        max_age_hours=max_age_hours,
        fail_closed=False,
        reason_codes=("PB020_EVIDENCE_VERIFIED",),
    )


def runtime_governance_state_snapshot(*, root: Path, max_age_hours: float = DEFAULT_MAX_AGE_HOURS) -> dict[str, Any]:
    return evaluate_runtime_governance_state(root=root, max_age_hours=max_age_hours).to_dict()


def assert_runtime_governance_ready(*, root: Path, max_age_hours: float = DEFAULT_MAX_AGE_HOURS) -> RuntimeGovernanceState:
    state = evaluate_runtime_governance_state(root=root, max_age_hours=max_age_hours)
    if not state.ready:
        raise RuntimeGovernanceStateError(state.reason)
    return state
