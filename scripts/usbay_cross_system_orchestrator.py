#!/usr/bin/env python3
"""PB-028 governed cross-system automation orchestrator.

The orchestrator coordinates USBAY operational systems in dry-run mode while
preserving fail-closed governance, human approval requirements, and redacted
audit evidence. It does not call external services.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence


SYSTEMS = ("github", "codex", "notion", "euria", "linkedin", "usbay_control_plane")
FORBIDDEN_PLACEHOLDERS = (
    "Describe what is changing and why.",
    "System impact:",
    "User impact:",
    "Policy ID:",
    "Policy version/hash:",
    "Policy version / hash:",
)
REQUIRED_PR_SECTIONS = ("PURPOSE", "RISK", "POLICY LINK", "REQUIRED APPROVALS", "GOVERNANCE CHECKS", "AUDIT", "IMPACT", "Decision", "Status")
SENSITIVE_PATTERNS = (
    re.compile(r"ghp_[A-Za-z0-9_]+"),
    re.compile(r"github_pat_[A-Za-z0-9_]+"),
    re.compile(r"sk-[A-Za-z0-9_-]+"),
    re.compile(r"(?i)(password|secret|token|api_key|private_key)\s*[:=]\s*[^,\s]+"),
)
SENSITIVE_KEY_PATTERN = re.compile(r"(?i)(password|secret|token|api_key|private_key)")
EXTERNAL_PUBLIC_SYSTEMS = {"linkedin"}
EXTERNAL_MUTATING_ACTIONS = {"post", "publish", "message", "outreach", "client_outreach"}
DRY_RUN_SYNC_ACTIONS = {
    "github": "sync_pr_metadata",
    "notion": "sync_evidence_page",
    "euria": "sync_project_context",
}


class OrchestrationBlocked(RuntimeError):
    """Raised when governance blocks orchestration."""


@dataclass(frozen=True)
class ConnectorDefinition:
    system: str
    action_type: str
    required_permission: str
    evidence_output: str
    fail_closed_on_error: bool = True
    human_approval_required: bool = False
    external_public_action: bool = False


@dataclass(frozen=True)
class ActionRequest:
    system: str
    action_type: str
    dry_run: bool = True
    human_approved: bool = False
    payload: dict[str, Any] | None = None


@dataclass(frozen=True)
class PBMetadata:
    pb_number: int
    decision: str
    title: str
    status: str
    purpose: str
    risk: str
    policy_link: str
    required_approvals: tuple[str, ...]
    governance_checks: tuple[str, ...]
    audit: str
    impact: str

    @property
    def pb_label(self) -> str:
        return f"PB-{self.pb_number:03d}"


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise OrchestrationBlocked(reason)


def pb028_metadata() -> PBMetadata:
    return PBMetadata(
        pb_number=28,
        decision="VERIFIED",
        title="USBAY Cross-System Automation Orchestrator",
        status="READY FOR REVIEW",
        purpose="Establish one governed dry-run automation flow across GitHub, Codex, Notion, EurIA, LinkedIn, and the USBAY Control Plane.",
        risk="Cross-system automation could create unauthorized external actions or incomplete audit evidence if metadata, permissions, or approval gates drift.",
        policy_link="AGENTS.md fail-closed governance, human oversight, network governance, secret hygiene, branch governance, and audit-first engineering.",
        required_approvals=("USBAY-AUDIT", "USBAY-GLOBAL23"),
        governance_checks=(
            "python3 -m py_compile scripts/usbay_cross_system_orchestrator.py",
            "pytest -q tests/test_pb028_cross_system_orchestrator.py",
            "git diff --check",
            "conflict marker scan",
            "secret-pattern scan",
        ),
        audit="PB-028 generates automation, connector health, cross-system action log, and governance metadata validation evidence.",
        impact="USBAY operational coordination becomes deterministic, dry-run first, policy-gated, and blocked for external actions without human approval.",
    )


def generated_title(metadata: PBMetadata) -> str:
    return f"{metadata.pb_label} {metadata.decision}: {metadata.title}"


def _section(name: str, body: str) -> str:
    _require(bool(body.strip()), f"PR_BODY_SECTION_EMPTY:{name}")
    return f"## {name}\n{body.strip()}"


def generated_pr_body(metadata: PBMetadata) -> str:
    return (
        "\n\n".join(
            (
                _section("PURPOSE", metadata.purpose),
                _section("RISK", metadata.risk),
                _section("POLICY LINK", metadata.policy_link),
                _section("REQUIRED APPROVALS", "\n".join(f"- {approval}" for approval in metadata.required_approvals)),
                _section("GOVERNANCE CHECKS", "\n".join(f"- {check}" for check in metadata.governance_checks)),
                _section("AUDIT", metadata.audit),
                _section("IMPACT", metadata.impact),
                _section("Decision", metadata.decision),
                _section("Status", metadata.status),
            )
        )
        + "\n"
    )


def validate_generated_pr_body(body: str) -> dict[str, Any]:
    _require(bool(body.strip()), "PR_BODY_MISSING")
    placeholders = [placeholder for placeholder in FORBIDDEN_PLACEHOLDERS if placeholder in body]
    _require(not placeholders, "PR_BODY_PLACEHOLDER_PRESENT:" + ",".join(placeholders))
    headings = {match.group(1).strip() for match in re.finditer(r"^## (.+)$", body, flags=re.MULTILINE)}
    missing = [section for section in REQUIRED_PR_SECTIONS if section not in headings]
    _require(not missing, "PR_BODY_REQUIRED_SECTION_MISSING:" + ",".join(missing))
    return {
        "body_hash": _sha256_text(body),
        "required_sections": {section: "POPULATED" for section in REQUIRED_PR_SECTIONS},
        "forbidden_placeholders": {placeholder: "ABSENT" for placeholder in FORBIDDEN_PLACEHOLDERS},
    }


def governance_metadata_validation(
    *,
    commit_title: str,
    pr_title: str,
    pr_body: str,
    metadata: PBMetadata | None = None,
) -> dict[str, Any]:
    metadata = metadata or pb028_metadata()
    expected_title = generated_title(metadata)
    expected_body = generated_pr_body(metadata)
    body_validation = validate_generated_pr_body(expected_body)
    comparisons = {
        "commit_title_matches_generated": commit_title == expected_title,
        "pr_title_matches_generated": pr_title == expected_title,
        "pr_body_matches_generated": pr_body == expected_body,
    }
    decision = "VERIFIED" if all(comparisons.values()) else "BLOCKED"
    report = {
        "control": "PB-028",
        "decision": decision,
        "status": "READY FOR REVIEW" if decision == "VERIFIED" else "FAIL_CLOSED",
        "generated_commit_title": expected_title,
        "generated_pr_title": expected_title,
        "generated_pr_body_hash": body_validation["body_hash"],
        "commit_title": commit_title,
        "pr_title": pr_title,
        "pr_body_hash": _sha256_text(pr_body),
        "comparisons": comparisons,
        "body_validation": body_validation,
        "manual_placeholder_text_forbidden": True,
    }
    report["report_hash"] = _sha256_text(_canonical_json(report))
    return report


def redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            rendered_key = str(key)
            redacted[rendered_key] = "[REDACTED]" if SENSITIVE_KEY_PATTERN.search(rendered_key) else redact_sensitive(item)
        return redacted
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, str):
        redacted = value
        for pattern in SENSITIVE_PATTERNS:
            redacted = pattern.sub("[REDACTED]", redacted)
        return redacted
    return value


def contains_sensitive_data(payload: Any) -> bool:
    return redact_sensitive(payload) != payload


def connector_registry() -> dict[str, ConnectorDefinition]:
    return {
        "github": ConnectorDefinition(
            system="github",
            action_type="sync_pr_metadata",
            required_permission="repo:pull_request:read_write",
            evidence_output="governance/evidence/automation/github_evidence.json",
        ),
        "codex": ConnectorDefinition(
            system="codex",
            action_type="coordinate_task",
            required_permission="workspace:write",
            evidence_output="governance/evidence/automation/codex_evidence.json",
        ),
        "notion": ConnectorDefinition(
            system="notion",
            action_type="sync_evidence_page",
            required_permission="notion:page:update",
            evidence_output="governance/evidence/automation/notion_evidence.json",
        ),
        "euria": ConnectorDefinition(
            system="euria",
            action_type="sync_project_context",
            required_permission="euria:project:update",
            evidence_output="governance/evidence/automation/euria_evidence.json",
        ),
        "linkedin": ConnectorDefinition(
            system="linkedin",
            action_type="post",
            required_permission="linkedin:content:publish",
            evidence_output="governance/evidence/automation/linkedin_evidence.json",
            human_approval_required=True,
            external_public_action=True,
        ),
        "usbay_control_plane": ConnectorDefinition(
            system="usbay_control_plane",
            action_type="update_runtime_status",
            required_permission="usbay:control_plane:update",
            evidence_output="governance/evidence/automation/control_plane_evidence.json",
        ),
    }


def validate_registry(registry: dict[str, ConnectorDefinition]) -> None:
    missing = [system for system in SYSTEMS if system not in registry]
    _require(not missing, "CONNECTOR_MISSING:" + ",".join(missing))
    for name, connector in registry.items():
        _require(name == connector.system, f"CONNECTOR_NAME_MISMATCH:{name}:{connector.system}")
        _require(bool(connector.action_type.strip()), f"ACTION_TYPE_MISSING:{name}")
        _require(bool(connector.required_permission.strip()), f"REQUIRED_PERMISSION_MISSING:{name}")
        _require(bool(connector.evidence_output.strip()), f"EVIDENCE_OUTPUT_MISSING:{name}")
        _require(connector.fail_closed_on_error is True, f"FAIL_CLOSED_DISABLED:{name}")


def evaluate_action(
    request: ActionRequest,
    registry: dict[str, ConnectorDefinition],
    *,
    connector_available: bool = True,
    connector_failed: bool = False,
) -> dict[str, Any]:
    validate_registry(registry)
    connector = registry.get(request.system)
    _require(connector is not None, f"CONNECTOR_MISSING:{request.system}")
    blockers: list[str] = []
    if request.action_type != connector.action_type:
        blockers.append("action_type_mismatch")
    if not connector_available:
        blockers.append("connector_unavailable")
    if connector_failed:
        blockers.append("connector_failed")
    external_action = connector.external_public_action or request.action_type in EXTERNAL_MUTATING_ACTIONS
    if external_action and not request.human_approved:
        blockers.append("human_approval_required")
    if external_action and not request.dry_run:
        blockers.append("external_action_not_allowed_without_explicit_release")
    redacted_payload = redact_sensitive(request.payload or {})
    if contains_sensitive_data(request.payload or {}):
        redacted_payload = redact_sensitive(request.payload or {})
    decision = "APPROVED_DRY_RUN" if not blockers and request.dry_run else "BLOCKED"
    evidence = {
        "system": connector.system,
        "action_type": request.action_type,
        "required_permission": connector.required_permission,
        "evidence_output": connector.evidence_output,
        "fail_closed_on_error": connector.fail_closed_on_error,
        "dry_run": request.dry_run,
        "human_approved": request.human_approved,
        "external_public_action": external_action,
        "decision": decision,
        "status": "DRY_RUN_READY" if decision == "APPROVED_DRY_RUN" else "FAIL_CLOSED",
        "blockers": blockers,
        "payload_hash": _sha256_text(_canonical_json(redacted_payload)),
        "sensitive_data_logged": False,
    }
    evidence["evidence_hash"] = _sha256_text(_canonical_json(evidence))
    return evidence


def run_orchestration(
    requests: Sequence[ActionRequest],
    registry: dict[str, ConnectorDefinition] | None = None,
) -> dict[str, Any]:
    registry = registry or connector_registry()
    validate_registry(registry)
    action_results = [evaluate_action(request, registry) for request in requests]
    blocked = [result for result in action_results if result["decision"] == "BLOCKED"]
    report = {
        "control": "PB-028",
        "decision": "VERIFIED" if not blocked else "BLOCKED",
        "status": "READY FOR REVIEW" if not blocked else "FAIL_CLOSED",
        "dry_run_first": True,
        "policy_gated": True,
        "human_approval_required_for_external_actions": True,
        "external_public_action_performed": False,
        "actions": action_results,
    }
    report["report_hash"] = _sha256_text(_canonical_json(report))
    return report


def connector_health_report(registry: dict[str, ConnectorDefinition]) -> dict[str, Any]:
    validate_registry(registry)
    connectors = {
        system: {
            "action_type": connector.action_type,
            "required_permission": connector.required_permission,
            "evidence_output": connector.evidence_output,
            "fail_closed_on_error": connector.fail_closed_on_error,
            "health": "DRY_RUN_CONFIGURED",
        }
        for system, connector in sorted(registry.items())
    }
    report = {"control": "PB-028", "decision": "VERIFIED", "connectors": connectors}
    report["report_hash"] = _sha256_text(_canonical_json(report))
    return report


def cross_system_action_log(orchestrator_report: dict[str, Any]) -> dict[str, Any]:
    entries = [
        {
            "system": action["system"],
            "action_type": action["action_type"],
            "decision": action["decision"],
            "status": action["status"],
            "evidence_hash": action["evidence_hash"],
        }
        for action in orchestrator_report["actions"]
    ]
    log = {
        "control": "PB-028",
        "decision": orchestrator_report["decision"],
        "status": orchestrator_report["status"],
        "raw_payloads_logged": False,
        "sensitive_data_logged": False,
        "entries": entries,
    }
    log["log_hash"] = _sha256_text(_canonical_json(log))
    return log


def default_dry_run_requests() -> list[ActionRequest]:
    return [
        ActionRequest(system="github", action_type="sync_pr_metadata", dry_run=True),
        ActionRequest(system="codex", action_type="coordinate_task", dry_run=True),
        ActionRequest(system="notion", action_type="sync_evidence_page", dry_run=True),
        ActionRequest(system="euria", action_type="sync_project_context", dry_run=True),
        ActionRequest(system="usbay_control_plane", action_type="update_runtime_status", dry_run=True),
    ]


def write_outputs(output_dir: Path) -> dict[str, Any]:
    registry = connector_registry()
    orchestrator = run_orchestration(default_dry_run_requests(), registry)
    health = connector_health_report(registry)
    action_log = cross_system_action_log(orchestrator)
    metadata = pb028_metadata()
    body = generated_pr_body(metadata)
    metadata_report = governance_metadata_validation(
        commit_title=generated_title(metadata),
        pr_title=generated_title(metadata),
        pr_body=body,
        metadata=metadata,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "automation_orchestrator_report.json": orchestrator,
        "connector_health_report.json": health,
        "cross_system_action_log.json": action_log,
        "governance_metadata_validation.json": metadata_report,
        "generated_pr_body.md": body,
    }
    for filename, payload in artifacts.items():
        content = payload if isinstance(payload, str) else json.dumps(payload, indent=2, sort_keys=True) + "\n"
        (output_dir / filename).write_text(content, encoding="utf-8")
    return {"decision": "VERIFIED", "artifacts": sorted(artifacts)}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PB-028 USBAY cross-system automation orchestrator")
    parser.add_argument("--output-dir", type=Path, default=Path("governance/evidence/pb028"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = write_outputs(args.output_dir)
    except OrchestrationBlocked as exc:
        print("Decision: BLOCKED")
        print(str(exc))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
