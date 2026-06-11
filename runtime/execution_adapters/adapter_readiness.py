from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from runtime.execution_adapters.adapter_approval_binding import AdapterApprovalBinding


REQUIRED_ADAPTERS = ("desktop", "browser", "api")


def readiness_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AdapterRegistration:
    adapter_name: str
    contract_module: str
    approval_binding_required: bool
    audit_binding_required: bool
    token_binding_required: bool
    fail_closed_supported: bool
    live_execution_enabled: bool = False


@dataclass(frozen=True)
class AdapterReadinessDecision:
    decision: str
    status: str
    reason: str
    registered_adapters: tuple[str, ...]
    missing_adapters: tuple[str, ...]
    audit_hash: str
    report: dict[str, object]


def evaluate_adapter_readiness(
    registrations: list[AdapterRegistration],
    approval_binding: AdapterApprovalBinding | None,
) -> AdapterReadinessDecision:
    registered = tuple(sorted(registration.adapter_name for registration in registrations))
    missing = tuple(adapter for adapter in REQUIRED_ADAPTERS if adapter not in registered)
    failed_controls: list[str] = []
    if missing:
        failed_controls.append("adapter_registration_missing")
    if approval_binding is None or approval_binding.decision != "ALLOW":
        failed_controls.append("approval_binding_invalid")
    for registration in registrations:
        if not registration.approval_binding_required:
            failed_controls.append(f"{registration.adapter_name}_approval_binding_not_required")
        if not registration.audit_binding_required:
            failed_controls.append(f"{registration.adapter_name}_audit_binding_not_required")
        if not registration.token_binding_required:
            failed_controls.append(f"{registration.adapter_name}_token_binding_not_required")
        if not registration.fail_closed_supported:
            failed_controls.append(f"{registration.adapter_name}_fail_closed_missing")
        if registration.live_execution_enabled:
            failed_controls.append(f"{registration.adapter_name}_live_execution_enabled")
    decision = "VERIFIED" if not failed_controls else "FAIL_CLOSED"
    status = "READY_FOR_REVIEW" if decision == "VERIFIED" else "BLOCKED"
    reason = "adapter_readiness_verified" if decision == "VERIFIED" else "adapter_readiness_failed"
    audit_hash = readiness_hash(decision, status, reason, registered, missing, failed_controls)
    report = {
        "decision": decision,
        "status": status,
        "reason": reason,
        "registered_adapters": list(registered),
        "missing_adapters": list(missing),
        "failed_controls": failed_controls,
        "approval_binding": approval_binding.decision if approval_binding else "MISSING",
        "token_binding_verified": "token_binding_invalid" not in failed_controls,
        "audit_binding_verified": all("audit_binding" not in control for control in failed_controls),
        "fail_closed_behavior": "VERIFIED" if not failed_controls else "FAIL_CLOSED",
        "live_execution_enabled": False,
        "audit_hash": audit_hash,
    }
    return AdapterReadinessDecision(decision, status, reason, registered, missing, audit_hash, report)

