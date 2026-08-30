from __future__ import annotations

from pathlib import Path
from typing import Any

from audit.audit_writer import AuditWriteError, write_audit_record
from evaluators.policy_evaluator import evaluate_pr


ADAPTER_VERSION = "pb210-gateway-contract-adapter-v1"
REQUIRED_REQUEST_FIELDS = ("repository", "pull_request", "diff")


def validate_pr_evaluation_request(payload: dict[str, Any]) -> list[str]:
    if not isinstance(payload, dict):
        return ["MALFORMED_REQUEST"]
    gaps: list[str] = []
    for field in REQUIRED_REQUEST_FIELDS:
        if field not in payload:
            gaps.append(f"MISSING_{field.upper()}")
    pr = payload.get("pull_request")
    if not isinstance(pr, dict):
        gaps.append("MALFORMED_PULL_REQUEST")
    else:
        if not isinstance(pr.get("number"), int):
            gaps.append("MISSING_PR_NUMBER")
        if not isinstance(pr.get("head_sha"), str) or not pr.get("head_sha"):
            gaps.append("MISSING_HEAD_SHA")
        if not isinstance(pr.get("base_sha"), str) or not pr.get("base_sha"):
            gaps.append("MISSING_BASE_SHA")
    diff = payload.get("diff")
    if not isinstance(diff, dict) or not isinstance(diff.get("changed_files"), list):
        gaps.append("MALFORMED_DIFF")
    return sorted(set(gaps))


def evaluate_governed_pr_request(
    payload: dict[str, Any],
    *,
    policy_registry_path: str | Path = "governance/policy_registry.json",
    audit_path: str | Path = "tmp/pb210_gateway_contract_audit.json",
) -> dict[str, Any]:
    request_gaps = validate_pr_evaluation_request(payload)
    if request_gaps:
        return {
            "decision": "FAIL",
            "gaps": request_gaps,
            "policy_hash": None,
            "evaluator_version": None,
            "adapter_version": ADAPTER_VERSION,
            "audit": None,
        }

    evaluation = evaluate_pr(payload, policy_registry_path=policy_registry_path)
    try:
        audit = write_audit_record(
            "governed_pr_evaluation",
            {
                "repository": payload.get("repository"),
                "pull_request": payload.get("pull_request"),
                "changed_files_count": len(payload.get("diff", {}).get("changed_files", [])),
                "evaluation": evaluation,
                "decision": "ALLOW" if evaluation.get("decision") == "PASS" else "DENY",
                "policy_hash": evaluation.get("policy_hash") or "UNKNOWN_POLICY_HASH",
                "tenant_id": payload.get("tenant_id", "t1"),
            },
            audit_path=audit_path,
        )
    except AuditWriteError:
        return {
            "decision": "FAIL",
            "gaps": ["AUDIT_WRITE_FAILED"],
            "policy_hash": evaluation.get("policy_hash"),
            "evaluator_version": evaluation.get("evaluator_version"),
            "adapter_version": ADAPTER_VERSION,
            "audit": None,
        }

    return {
        "decision": evaluation["decision"],
        "gaps": evaluation["gaps"],
        "policy_hash": evaluation["policy_hash"],
        "evaluator_version": evaluation["evaluator_version"],
        "adapter_version": ADAPTER_VERSION,
        "audit": {
            "audit_hash": audit["audit_hash"],
            "payload_hash": audit["payload_hash"],
            "timestamp": audit["timestamp"],
        },
    }
