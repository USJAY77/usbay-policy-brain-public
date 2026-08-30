from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

INCIDENT_REGISTRY_PATH = Path("governance/incident_runbooks.json")
INCIDENT_SCHEMA = "usbay.governance_incident_runbooks.v1"
REQUIRED_INCIDENT_CODES = (
    "GOV_SIGNER_DRIFT",
    "GOV_DEPENDENCY_DRIFT",
    "GOV_RELEASE_MISMATCH",
    "GOV_ROLLBACK_INVALID",
    "GOV_TRUST_POLICY_MISMATCH",
    "GOV_TELEMETRY_UNSAFE",
)
SECRET_MARKERS = (
    "BEGIN " + "PRIVATE KEY",
    "BEGIN RSA " + "PRIVATE KEY",
    "BEGIN OPENSSH " + "PRIVATE KEY",
    "PRIVATE " + "KEY",
    "raw_secret",
    "approval_contents",
    "private_key",
    "USBAY_SECRET",
)


class GovernanceIncidentError(RuntimeError):
    pass


@dataclass(frozen=True)
class GovernanceIncidentRunbook:
    code: str
    title: str
    mapped_failures: tuple[str, ...]
    fail_closed_reason: str
    recommended_operator_action: str
    recovery_checklist: tuple[str, ...]
    human_approval_required: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "title": self.title,
            "mapped_failures": list(self.mapped_failures),
            "fail_closed_reason": self.fail_closed_reason,
            "recommended_operator_action": self.recommended_operator_action,
            "recovery_checklist": list(self.recovery_checklist),
            "human_approval_required": self.human_approval_required,
        }


def load_incident_runbooks(root: Path) -> dict[str, GovernanceIncidentRunbook]:
    path = root / INCIDENT_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise GovernanceIncidentError("incident_code_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != INCIDENT_SCHEMA:
        raise GovernanceIncidentError("incident_code_registry_invalid")
    raw_codes = payload.get("incident_codes")
    if not isinstance(raw_codes, list):
        raise GovernanceIncidentError("incident_code_registry_invalid")
    runbooks: dict[str, GovernanceIncidentRunbook] = {}
    for entry in raw_codes:
        if not isinstance(entry, dict):
            raise GovernanceIncidentError("incident_runbook_invalid")
        try:
            runbook = GovernanceIncidentRunbook(
                code=str(entry["code"]),
                title=str(entry["title"]),
                mapped_failures=tuple(str(item) for item in entry["mapped_failures"]),
                fail_closed_reason=str(entry["fail_closed_reason"]),
                recommended_operator_action=str(entry["recommended_operator_action"]),
                recovery_checklist=tuple(str(item) for item in entry["recovery_checklist"]),
                human_approval_required=bool(entry["human_approval_required"]),
            )
        except Exception as exc:
            raise GovernanceIncidentError("incident_runbook_invalid") from exc
        if runbook.code in runbooks:
            raise GovernanceIncidentError("incident_code_duplicate")
        runbooks[runbook.code] = runbook
    missing = sorted(set(REQUIRED_INCIDENT_CODES) - set(runbooks))
    if missing:
        raise GovernanceIncidentError("incident_code_registry_incomplete:" + ",".join(missing))
    return runbooks


def incident_code_for_failure(failure: str, runbooks: dict[str, GovernanceIncidentRunbook]) -> str:
    for code, runbook in sorted(runbooks.items()):
        for marker in runbook.mapped_failures:
            if failure == marker or failure.startswith(marker):
                return code
    raise GovernanceIncidentError("incident_runbook_missing:" + failure)


def incident_summary(root: Path, failures: tuple[str, ...] | list[str]) -> dict[str, Any]:
    runbooks = load_incident_runbooks(root)
    incidents: dict[str, dict[str, Any]] = {}
    for failure in failures:
        code = incident_code_for_failure(str(failure), runbooks)
        runbook = runbooks[code]
        incidents.setdefault(
            code,
            {
                "code": code,
                "title": runbook.title,
                "failures": [],
                "fail_closed_reason": runbook.fail_closed_reason,
                "human_approval_required": runbook.human_approval_required,
            },
        )
        incidents[code]["failures"].append(str(failure))
    return {"incident_count": len(incidents), "incidents": [redact_payload(value) for value in incidents.values()]}


def recommended_operator_action(root: Path, incident_code: str) -> dict[str, Any]:
    runbook = _runbook(root, incident_code)
    return redact_payload(
        {
            "code": runbook.code,
            "recommended_operator_action": runbook.recommended_operator_action,
            "human_approval_required": runbook.human_approval_required,
        }
    )


def fail_closed_reason(root: Path, incident_code: str) -> dict[str, Any]:
    runbook = _runbook(root, incident_code)
    return redact_payload({"code": runbook.code, "fail_closed_reason": runbook.fail_closed_reason})


def recovery_checklist(root: Path, incident_code: str) -> dict[str, Any]:
    runbook = _runbook(root, incident_code)
    return redact_payload(
        {
            "code": runbook.code,
            "recovery_checklist": list(runbook.recovery_checklist),
            "human_approval_required": runbook.human_approval_required,
        }
    )


def validate_recovery_path(root: Path, incident_code: str, *, human_approval_confirmed: bool) -> dict[str, Any]:
    runbook = _runbook(root, incident_code)
    if runbook.human_approval_required and not human_approval_confirmed:
        raise GovernanceIncidentError("incident_recovery_human_approval_required")
    return {"code": runbook.code, "recovery_path_valid": True}


def validate_runbook_coverage(root: Path, fail_closed_failures: tuple[str, ...] | list[str]) -> dict[str, Any]:
    runbooks = load_incident_runbooks(root)
    missing: list[str] = []
    for failure in fail_closed_failures:
        try:
            incident_code_for_failure(str(failure), runbooks)
        except GovernanceIncidentError:
            missing.append(str(failure))
    if missing:
        raise GovernanceIncidentError("incident_runbook_missing:" + ",".join(sorted(missing)))
    return {"incident_runbook_coverage_valid": True, "covered_failure_count": len(fail_closed_failures)}


def assert_audit_safe_payload(payload: Any) -> None:
    encoded = json.dumps(payload, sort_keys=True, default=str)
    for marker in SECRET_MARKERS:
        if marker in encoded:
            raise GovernanceIncidentError("GOVERNANCE_TELEMETRY_UNSAFE")


def redact_payload(payload: Any) -> Any:
    if isinstance(payload, dict):
        return {str(key): redact_payload(value) for key, value in payload.items()}
    if isinstance(payload, list):
        return [redact_payload(value) for value in payload]
    if isinstance(payload, tuple):
        return [redact_payload(value) for value in payload]
    if isinstance(payload, str):
        redacted = payload
        for marker in SECRET_MARKERS:
            redacted = redacted.replace(marker, "[REDACTED]")
        return redacted
    return payload


def _runbook(root: Path, incident_code: str) -> GovernanceIncidentRunbook:
    runbooks = load_incident_runbooks(root)
    try:
        return runbooks[incident_code]
    except KeyError as exc:
        raise GovernanceIncidentError("incident_code_unknown:" + incident_code) from exc
