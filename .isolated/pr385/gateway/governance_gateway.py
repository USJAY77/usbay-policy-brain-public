from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request

from audit.audit_writer import AuditWriteError, write_audit_record
from evaluators.policy_evaluator import evaluate_pr
from gateway.failure_triage import governed_fail_response
from governance.policy_signature_registry import validate_policy_registry_file


GATEWAY_VERSION = "pb212-live-governance-gateway-readiness-v1"
DEFAULT_POLICY_REGISTRY_PATH = Path("governance/policy_registry.json")
DEFAULT_AUDIT_PATH = Path("tmp/pb212_governance_gateway_audit.json")
EVALUATION_TIMEOUT_SECONDS = 5.0
REQUIRED_FIELDS = ("diff", "pr_number", "policy_hash", "actor", "source")

app = FastAPI(title="USBAY Governance Gateway Readiness", version=GATEWAY_VERSION)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _fail_closed(gaps: list[str], *, policy_hash: str | None = None, audit: dict[str, Any] | None = None) -> dict[str, Any]:
    return governed_fail_response(gaps, policy_hash=policy_hash, audit=audit, gateway_version=GATEWAY_VERSION)


def validate_gateway_request(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return ["MALFORMED_REQUEST"]
    gaps: list[str] = []
    for field in REQUIRED_FIELDS:
        if field not in payload:
            gaps.append(f"MISSING_{field.upper()}")
    if "diff" in payload:
        diff = payload.get("diff")
        if not isinstance(diff, dict):
            gaps.append("MALFORMED_DIFF")
        else:
            changed_files = diff.get("changed_files")
            if changed_files is not None and (
                not isinstance(changed_files, list) or not all(isinstance(item, str) for item in changed_files)
            ):
                gaps.append("MALFORMED_DIFF")
    if "pr_number" in payload and not isinstance(payload.get("pr_number"), int):
        gaps.append("MALFORMED_PR_NUMBER")
    for field in ("policy_hash", "actor", "source"):
        if field in payload and (not isinstance(payload.get(field), str) or not payload.get(field)):
            gaps.append(f"MALFORMED_{field.upper()}")
    return gaps


def _evaluator_payload(payload: dict[str, Any]) -> dict[str, Any]:
    changed_files = payload.get("diff", {}).get("changed_files", [])
    if not isinstance(changed_files, list):
        changed_files = []
    return {
        "repository": payload.get("repository", "USJAY77/usbay-policy-brain"),
        "pull_request": {
            "number": payload["pr_number"],
            "head_sha": payload.get("head_sha", "readiness-head-sha"),
            "base_sha": payload.get("base_sha", "readiness-base-sha"),
        },
        "diff": {"changed_files": changed_files},
        "policy_hash": payload["policy_hash"],
    }


def _evaluate_with_timeout(
    evaluator_payload: dict[str, Any],
    *,
    policy_registry_path: str | Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = executor.submit(evaluate_pr, evaluator_payload, policy_registry_path=policy_registry_path)
    try:
        return future.result(timeout=timeout_seconds)
    except concurrent.futures.TimeoutError:
        future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    finally:
        if future.done():
            executor.shutdown(wait=False, cancel_futures=True)


def evaluate_gateway_request(
    payload: Any,
    *,
    policy_registry_path: str | Path = DEFAULT_POLICY_REGISTRY_PATH,
    audit_path: str | Path = DEFAULT_AUDIT_PATH,
    timeout_seconds: float = EVALUATION_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    request_gaps = validate_gateway_request(payload)
    if request_gaps:
        return _fail_closed(request_gaps)

    assert isinstance(payload, dict)
    policy_hash = str(payload["policy_hash"])
    signature_validation = validate_policy_registry_file(policy_registry_path)
    if signature_validation.get("decision") != "VERIFIED":
        return _fail_closed(
            list(signature_validation.get("gaps", [])) or ["SIGNATURE_INVALID"],
            policy_hash=signature_validation.get("policy_hash") or policy_hash,
        )
    try:
        evaluation = _evaluate_with_timeout(
            _evaluator_payload(payload),
            policy_registry_path=policy_registry_path,
            timeout_seconds=timeout_seconds,
        )
    except concurrent.futures.TimeoutError:
        return _fail_closed(["EVALUATOR_TIMEOUT"], policy_hash=policy_hash)
    except Exception:
        return _fail_closed(["EVALUATION_EXCEPTION"], policy_hash=policy_hash)

    decision = "APPROVE" if evaluation.get("decision") == "PASS" else "DENY"
    audit_payload = {
        "actor": payload["actor"],
        "device": payload["source"],
        "decision": decision,
        "timestamp": utc_now(),
        "policy_version": "1.0.0",
        "policy_hash": evaluation.get("policy_hash") or policy_hash,
        "pr_number": payload["pr_number"],
        "source": payload["source"],
        "changed_files_count": len(payload.get("diff", {}).get("changed_files", [])),
        "evaluation": evaluation,
        "gateway_version": GATEWAY_VERSION,
        "external_calls_performed": False,
        "production_automation_activated": False,
    }
    try:
        audit = write_audit_record("pb212_gateway_evaluation", audit_payload, audit_path=audit_path)
    except AuditWriteError:
        return _fail_closed(["AUDIT_WRITE_FAILED"], policy_hash=evaluation.get("policy_hash") or policy_hash)

    audit_summary = {
        "audit_hash": audit["audit_hash"],
        "payload_hash": audit["payload_hash"],
        "timestamp": audit["timestamp"],
    }
    if evaluation.get("decision") != "PASS":
        return _fail_closed(
            list(evaluation.get("gaps", [])) or ["POLICY_EVALUATION_FAILED"],
            policy_hash=evaluation.get("policy_hash") or policy_hash,
            audit=audit_summary,
        )

    return {
        "decision": "VERIFIED",
        "approved": True,
        "gaps": [],
        "policy_hash": evaluation["policy_hash"],
        "gateway_version": GATEWAY_VERSION,
        "audit": audit_summary,
        "external_calls_performed": False,
        "production_automation_activated": False,
    }


@app.post("/evaluate")
async def evaluate(request: Request) -> dict[str, Any]:
    try:
        payload = await request.json()
    except Exception:
        return _fail_closed(["MALFORMED_REQUEST"])
    return evaluate_gateway_request(payload)
