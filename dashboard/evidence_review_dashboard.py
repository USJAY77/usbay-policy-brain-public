#!/usr/bin/env python3
"""Render a read-only AWS Object Lock evidence review dashboard.

This dashboard is local-only. It does not call AWS, load credentials, create
resources, change blocker status, or make certification claims.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVIDENCE_DIR = ROOT / "governance" / "evidence" / "aws-object-lock" / "provider-submissions"

DEFAULT_REQUIRED_EVIDENCE = {
    "object_lock_write_receipt": "object_lock_write_receipt.json",
    "retention_configuration_evidence": "retention_configuration_evidence.json",
    "legal_hold_evidence": "legal_hold_evidence.json",
    "export_verification_record": "export_verification_record.json",
    "provider_audit_reference": "provider_audit_reference.md",
    "chain_of_custody": "chain_of_custody.md",
    "evidence_manifest": "evidence_manifest.json",
}

PILOT_REQUIRED_EVIDENCE = {
    "object_lock_write_receipt": "pilot_object_lock_write_receipt.json",
    "retention_configuration_evidence": "pilot_retention_configuration.json",
    "legal_hold_evidence": "pilot_legal_hold_evidence.json",
    "export_verification_record": "pilot_export_verification_record.json",
    "provider_audit_reference": "pilot_provider_audit_reference.md",
    "chain_of_custody": "pilot_chain_of_custody.md",
    "evidence_manifest": "pilot_evidence_manifest.json",
}

PLACEHOLDERS = {"", "Information not provided.", "BLOCKED", "OPEN"}
FORBIDDEN_MARKERS = (
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_session_token",
    "private_key",
    "raw_payload",
    "approval_contents",
    "raw_regulator_export",
)


@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str
    filename: str
    path: Path
    exists: bool
    placeholder: bool
    forbidden_content: bool

    @property
    def received_status(self) -> str:
        if not self.exists:
            return "MISSING"
        if self.placeholder:
            return "PLACEHOLDER"
        if self.forbidden_content:
            return "REJECTED"
        return "RECEIVED"


def _load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"json_status": "INVALID"}
    return payload if isinstance(payload, dict) else {"json_status": "INVALID"}


def _contains_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        return value in PLACEHOLDERS
    if isinstance(value, bool):
        return value is False
    if isinstance(value, list):
        return any(_contains_placeholder(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_placeholder(item) for item in value.values())
    return value is None


def _has_forbidden_content(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in FORBIDDEN_MARKERS)


def _required_evidence(evidence_dir: Path) -> dict[str, str]:
    if evidence_dir.name == "pilot-submission":
        return PILOT_REQUIRED_EVIDENCE
    return DEFAULT_REQUIRED_EVIDENCE


def _inventory(evidence_dir: Path, required_evidence: dict[str, str]) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    for evidence_id, filename in required_evidence.items():
        path = evidence_dir / filename
        text = _load_text(path)
        payload = _load_json(path) if filename.endswith(".json") else {}
        placeholder = "Information not provided." in text or _contains_placeholder(payload)
        items.append(
            EvidenceItem(
                evidence_id=evidence_id,
                filename=filename,
                path=path,
                exists=path.is_file(),
                placeholder=placeholder,
                forbidden_content=_has_forbidden_content(text),
            )
        )
    return items


def _manifest_status(evidence_dir: Path, required_evidence: dict[str, str]) -> str:
    manifest_filename = required_evidence["evidence_manifest"]
    manifest = _load_json(evidence_dir / manifest_filename)
    if not manifest:
        return "MISSING"
    if manifest.get("required_files") != list(required_evidence.values()):
        return "BLOCKED"
    if manifest.get("decision") != "BLOCKED":
        return "BLOCKED"
    if manifest.get("blocker_003_status") != "OPEN":
        return "BLOCKED"
    if manifest.get("certification_status") != "BLOCKED":
        return "BLOCKED"
    return "PLACEHOLDER" if _contains_placeholder(manifest) else "READY_FOR_REVIEW"


def _chain_status(evidence_dir: Path, required_evidence: dict[str, str]) -> str:
    text = _load_text(evidence_dir / required_evidence["chain_of_custody"])
    if not text:
        return "MISSING"
    required = (
        "Package identifier.",
        "Artifact names.",
        "Artifact hashes.",
        "Collection actor.",
        "Submission actor.",
        "Review actor.",
        "Decision: BLOCKED.",
    )
    if any(field not in text for field in required):
        return "BLOCKED"
    return "PLACEHOLDER" if "Information not provided." in text else "READY_FOR_REVIEW"


def build_dashboard(evidence_dir: Path = DEFAULT_EVIDENCE_DIR) -> dict[str, Any]:
    evidence_dir = evidence_dir.resolve()
    required_evidence = _required_evidence(evidence_dir)
    inventory = _inventory(evidence_dir, required_evidence)
    received = [item.filename for item in inventory if item.exists]
    missing = [item.filename for item in inventory if not item.exists]
    placeholder = [item.filename for item in inventory if item.placeholder]
    rejected = [item.filename for item in inventory if item.forbidden_content]

    manifest_status = _manifest_status(evidence_dir, required_evidence)
    chain_status = _chain_status(evidence_dir, required_evidence)
    validation_status = "BLOCKED" if missing or placeholder or rejected else "READY_FOR_REVIEW"
    hash_status = "BLOCKED" if placeholder or missing else "READY_FOR_REVIEW"
    review_status = "BLOCKED"
    approval_status = "BLOCKED"
    rejection_status = "ACTIVE" if missing or placeholder or rejected else "NOT_TRIGGERED"
    blocker_003_status = "OPEN"
    certification_status = "BLOCKED"

    return {
        "dashboard_schema": "usbay.aws_object_lock_evidence_review_dashboard.v1",
        "read_only": True,
        "aws_resource_creation": False,
        "credentials_allowed": False,
        "certification_claim": False,
        "evidence_directory": evidence_dir.as_posix(),
        "evidence_inventory": {
            "required": list(required_evidence.values()),
            "received": received,
            "missing": missing,
            "placeholder": placeholder,
            "rejected": rejected,
            "items": [
                {
                    "evidence_id": item.evidence_id,
                    "filename": item.filename,
                    "status": item.received_status,
                    "path": item.path.as_posix(),
                }
                for item in inventory
            ],
        },
        "validation": {
            "validation_status": validation_status,
            "hash_verification_status": hash_status,
            "manifest_status": manifest_status,
            "chain_of_custody_status": chain_status,
        },
        "review": {
            "reviewer_assignments": "Information not provided.",
            "review_status": review_status,
            "approval_status": approval_status,
            "rejection_status": rejection_status,
        },
        "governance": {
            "BLOCKER-001": "CLOSED",
            "BLOCKER-002": "PARTIAL",
            "BLOCKER-003": blocker_003_status,
            "Certification": certification_status,
        },
        "decision": {
            "decision": "BLOCKED",
            "reason": "Required evidence is missing, placeholder, rejected, validation incomplete, or review incomplete.",
            "blocker_003_rule": "If required evidence missing, validation fails, or review incomplete, BLOCKER-003 remains OPEN.",
            "certification_rule": "Certification remains BLOCKED unless human governance review explicitly changes status with evidence.",
        },
    }


def render_markdown(state: dict[str, Any]) -> str:
    inventory = state["evidence_inventory"]
    validation = state["validation"]
    review = state["review"]
    governance = state["governance"]
    decision = state["decision"]
    rows = [
        "| Evidence | Status |",
        "|---|---|",
    ]
    for item in inventory["items"]:
        rows.append(f"| `{item['filename']}` | {item['status']} |")
    return "\n".join(
        [
            "# AWS Object Lock Evidence Review Dashboard",
            "",
            "Read-only: true.",
            "",
            "AWS resource creation: false.",
            "",
            "Credentials allowed: false.",
            "",
            "Certification claim: false.",
            "",
            "## Evidence Inventory",
            "",
            *rows,
            "",
            f"Missing evidence: {', '.join(inventory['missing']) if inventory['missing'] else 'None'}.",
            "",
            f"Placeholder evidence: {', '.join(inventory['placeholder']) if inventory['placeholder'] else 'None'}.",
            "",
            "## Validation",
            "",
            f"Validation status: {validation['validation_status']}.",
            "",
            f"Hash verification status: {validation['hash_verification_status']}.",
            "",
            f"Manifest status: {validation['manifest_status']}.",
            "",
            f"Chain-of-custody status: {validation['chain_of_custody_status']}.",
            "",
            "## Review",
            "",
            f"Reviewer assignments: {review['reviewer_assignments']}",
            "",
            f"Review status: {review['review_status']}.",
            "",
            f"Approval status: {review['approval_status']}.",
            "",
            f"Rejection status: {review['rejection_status']}.",
            "",
            "## Governance",
            "",
            f"BLOCKER-001: {governance['BLOCKER-001']}.",
            "",
            f"BLOCKER-002: {governance['BLOCKER-002']}.",
            "",
            f"BLOCKER-003: {governance['BLOCKER-003']}.",
            "",
            f"Certification: {governance['Certification']}.",
            "",
            "## Decision",
            "",
            f"Decision: {decision['decision']}.",
            "",
            f"Reason: {decision['reason']}",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Render AWS Object Lock evidence review dashboard.")
    parser.add_argument("--evidence-dir", default=DEFAULT_EVIDENCE_DIR.as_posix())
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    args = parser.parse_args()

    state = build_dashboard(Path(args.evidence_dir))
    if args.format == "json":
        print(json.dumps(state, indent=2, sort_keys=True))
    else:
        print(render_markdown(state))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
