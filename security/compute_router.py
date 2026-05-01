from __future__ import annotations

from typing import Any

from security.compute_governance import validate_compute_request


class ComputeRoutingError(RuntimeError):
    pass


def _executor_for_target(compute_target: str):
    if compute_target == "cpu":
        from executors import cpu_executor

        return cpu_executor
    if compute_target == "npu":
        from executors import npu_executor

        return npu_executor
    raise ComputeRoutingError(f"{compute_target}_executor_unavailable")


def route_execution(payload: dict[str, Any], decision_record: dict[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ComputeRoutingError("compute_routing_payload_invalid")

    decision, reason, evidence = validate_compute_request(payload)
    if decision != "ALLOW":
        raise ComputeRoutingError(reason)

    requested_target = str(evidence.get("compute_target", "")).lower()
    stored_target = str((decision_record or {}).get("compute_target", requested_target)).lower()
    if requested_target != stored_target:
        raise ComputeRoutingError("compute_target_mismatch")

    if requested_target == "tpu" and payload.get("human_review") is not True:
        raise ComputeRoutingError("human_review_required")

    executor = _executor_for_target(requested_target)
    result = executor.execute(payload)
    if not isinstance(result, dict):
        raise ComputeRoutingError("compute_executor_invalid_result")

    actual_target = str(result.get("actual_execution_target", "")).lower()
    if actual_target != requested_target:
        raise ComputeRoutingError("compute_execution_mismatch")
    if result.get("execution_verified") is not True:
        raise ComputeRoutingError("compute_execution_unverified")

    return {
        "actual_execution_target": actual_target,
        "execution_verified": True,
        "compute_target": requested_target,
        "routing_status": "executed",
    }
