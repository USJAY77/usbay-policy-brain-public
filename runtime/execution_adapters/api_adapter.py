from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from runtime.execution_adapters.adapter_approval_binding import AdapterApprovalBinding


API_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def api_audit_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ApiRequestContract:
    request_id: str
    method: str
    endpoint: str
    policy_version: str | None
    audit_id: str | None
    approval_binding: AdapterApprovalBinding | None = None
    dry_run: bool = True


@dataclass(frozen=True)
class ApiResponseContract:
    request_id: str
    status: str
    reason: str
    audit_hash: str
    outbound_request_performed: bool = False


class ApiAdapterContract:
    adapter_name = "api"

    def validate(self, request: ApiRequestContract | None) -> ApiResponseContract:
        if request is None:
            return self._response(None, "FAIL_CLOSED", "request_missing")
        if request.dry_run is not True:
            return self._response(request, "FAIL_CLOSED", "live_api_request_forbidden")
        if not request.policy_version:
            return self._response(request, "FAIL_CLOSED", "policy_version_missing")
        if not request.audit_id:
            return self._response(request, "FAIL_CLOSED", "audit_id_missing")
        if request.method.upper() not in API_METHODS:
            return self._response(request, "BLOCK", "unsupported_api_method")
        if request.method.upper() in MUTATING_METHODS:
            if request.approval_binding is None:
                return self._response(request, "HUMAN_REVIEW", "api_mutation_requires_approval")
            if request.approval_binding.decision != "ALLOW":
                return self._response(request, "FAIL_CLOSED", "approval_binding_invalid")
        return self._response(request, "ALLOW", "api_adapter_request_validated")

    def _response(self, request: ApiRequestContract | None, status: str, reason: str) -> ApiResponseContract:
        request_id = request.request_id if request else None
        policy_version = request.policy_version if request else None
        audit_hash = api_audit_hash(self.adapter_name, request_id, status, reason, policy_version)
        return ApiResponseContract(request_id or "", status, reason, audit_hash)

