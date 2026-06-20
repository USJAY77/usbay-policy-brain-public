from __future__ import annotations

from typing import Any

from security.compute_router import ComputeRoutingError, validate_canonical_gate_proof


EXECUTION_DISABLED = "EXECUTION_DISABLED"
EXECUTION_BLOCKED = "EXECUTION_BLOCKED"
ADAPTER_NOT_IMPLEMENTED = "ADAPTER_NOT_IMPLEMENTED"
ADAPTER_CONTRACT_SCHEMA = "usbay.execution.adapter_contract.v1"
ADAPTER_CONTRACT_OWNER = "execution.adapters.base"
ADAPTER_CONTRACT_VERSION = "usbay.pb-adapter-001.canonical-execution-adapter-contract.v1"
REASON_ADAPTER_CONTRACT_MALFORMED = "ADAPTER_CONTRACT_MALFORMED"
REASON_UNKNOWN_ADAPTER = "UNKNOWN_ADAPTER"
REASON_UNKNOWN_CAPABILITY = "UNKNOWN_CAPABILITY"
REASON_UNKNOWN_ACTION_TYPE = "UNKNOWN_ACTION_TYPE"
REASON_CANONICAL_GATE_PROOF_MISSING = "MISSING_CANONICAL_GATE_PROOF"
REASON_CANONICAL_GATE_PROOF_INVALID = "INVALID_CANONICAL_GATE_PROOF"


ADAPTER_CAPABILITY_DECLARATIONS: tuple[dict[str, Any], ...] = (
    {
        "adapter_name": "browser",
        "capability": "READ_ONLY_NAVIGATION",
        "action_types": ("open_url_preview", "read_page_metadata"),
        "required_gate_proof": True,
    },
    {
        "adapter_name": "filesystem",
        "capability": "FILE_READ",
        "action_types": ("preview_file", "read_file_metadata"),
        "required_gate_proof": True,
    },
    {
        "adapter_name": "github",
        "capability": "ISSUE_COMMENT_DRAFT",
        "action_types": ("draft_issue_comment",),
        "required_gate_proof": True,
    },
    {
        "adapter_name": "github",
        "capability": "PR_DESCRIPTION_DRAFT",
        "action_types": ("draft_pr_description",),
        "required_gate_proof": True,
    },
    {
        "adapter_name": "shell",
        "capability": "REPORT_GENERATION",
        "action_types": ("generate_report",),
        "required_gate_proof": True,
    },
    {
        "adapter_name": "shell",
        "capability": "GOVERNANCE_STATUS_READ",
        "action_types": ("read_governance_status",),
        "required_gate_proof": True,
    },
)


def adapter_capability_map() -> dict[str, Any]:
    return {
        "schema": "usbay.execution.adapter_capability_map.v1",
        "canonical_owner": ADAPTER_CONTRACT_OWNER,
        "contract_version": ADAPTER_CONTRACT_VERSION,
        "adapters": [
            {
                "adapter_name": str(record["adapter_name"]),
                "capability": str(record["capability"]),
                "action_types": tuple(str(action) for action in record["action_types"]),
                "required_gate_proof": record["required_gate_proof"] is True,
            }
            for record in ADAPTER_CAPABILITY_DECLARATIONS
        ],
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
    }


def build_adapter_action_contract(*, adapter_name: str, capability: str, action_type: str, request_id: str) -> dict[str, str]:
    return {
        "schema": ADAPTER_CONTRACT_SCHEMA,
        "contract_version": ADAPTER_CONTRACT_VERSION,
        "adapter_name": str(adapter_name),
        "capability": str(capability),
        "action_type": str(action_type),
        "request_id": str(request_id),
    }


def _matching_declaration(adapter_name: str, capability: str) -> dict[str, Any] | None:
    for declaration in ADAPTER_CAPABILITY_DECLARATIONS:
        if declaration["adapter_name"] == adapter_name and declaration["capability"] == capability:
            return declaration
    return None


def validate_adapter_action_contract(
    contract: dict[str, Any] | None,
    *,
    canonical_gate_proof: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(contract, dict):
        return _adapter_contract_result(contract, [REASON_ADAPTER_CONTRACT_MALFORMED])
    if contract.get("schema") != ADAPTER_CONTRACT_SCHEMA:
        reasons.append(REASON_ADAPTER_CONTRACT_MALFORMED)
    if contract.get("contract_version") != ADAPTER_CONTRACT_VERSION:
        reasons.append(REASON_ADAPTER_CONTRACT_MALFORMED)
    for field in ("adapter_name", "capability", "action_type", "request_id"):
        if not str(contract.get(field, "")).strip():
            reasons.append(f"ADAPTER_CONTRACT_{field.upper()}_MISSING")

    adapter_name = str(contract.get("adapter_name", ""))
    capability = str(contract.get("capability", ""))
    action_type = str(contract.get("action_type", ""))
    known_adapters = {str(record["adapter_name"]) for record in ADAPTER_CAPABILITY_DECLARATIONS}
    if adapter_name and adapter_name not in known_adapters:
        reasons.append(REASON_UNKNOWN_ADAPTER)
    adapter_capabilities = {
        str(record["capability"])
        for record in ADAPTER_CAPABILITY_DECLARATIONS
        if str(record["adapter_name"]) == adapter_name
    }
    if adapter_name in known_adapters and capability and capability not in adapter_capabilities:
        reasons.append(REASON_UNKNOWN_CAPABILITY)
    declaration = _matching_declaration(adapter_name, capability)
    if declaration is not None and action_type not in declaration["action_types"]:
        reasons.append(REASON_UNKNOWN_ACTION_TYPE)
    if declaration is not None and declaration["required_gate_proof"] is True:
        if canonical_gate_proof is None:
            reasons.append(REASON_CANONICAL_GATE_PROOF_MISSING)
        else:
            try:
                validate_canonical_gate_proof(canonical_gate_proof)
            except ComputeRoutingError:
                reasons.append(REASON_CANONICAL_GATE_PROOF_INVALID)

    return _adapter_contract_result(contract, reasons)


def _adapter_contract_result(contract: dict[str, Any] | None, reasons: list[str]) -> dict[str, Any]:
    clean_reasons = sorted(set(str(reason) for reason in reasons if reason))
    safe_contract = contract if isinstance(contract, dict) else {}
    return {
        "schema": "usbay.execution.adapter_contract_validation.v1",
        "adapter_contract_status": "VALID" if not clean_reasons else "BLOCKED",
        "adapter_name": str(safe_contract.get("adapter_name", "")),
        "capability": str(safe_contract.get("capability", "")),
        "action_type": str(safe_contract.get("action_type", "")),
        "required_gate_proof": True,
        "reason_codes": clean_reasons,
        "fail_closed": bool(clean_reasons),
        "canonical_owner": ADAPTER_CONTRACT_OWNER,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
    }


class DisabledExecutionAdapter:
    adapter_name = "base"

    def evaluate(self, request: dict[str, Any] | None = None) -> dict[str, str]:
        contract = (request or {}).get("adapter_contract") if isinstance(request, dict) else None
        canonical_gate_proof = (request or {}).get("canonical_gate_proof") if isinstance(request, dict) else None
        if contract is not None:
            validation = validate_adapter_action_contract(contract, canonical_gate_proof=canonical_gate_proof)
            if validation["adapter_contract_status"] != "VALID":
                return {
                    "adapter": self.adapter_name,
                    "status": EXECUTION_DISABLED,
                    "decision": EXECUTION_BLOCKED,
                    "reason": ",".join(validation["reason_codes"]),
                }
        return {
            "adapter": self.adapter_name,
            "status": EXECUTION_DISABLED,
            "decision": EXECUTION_BLOCKED,
            "reason": ADAPTER_NOT_IMPLEMENTED,
        }
