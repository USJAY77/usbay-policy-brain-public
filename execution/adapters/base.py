from __future__ import annotations

from hashlib import sha256
from typing import Any

from security.compute_router import ComputeRoutingError, validate_canonical_gate_proof


EXECUTION_DISABLED = "EXECUTION_DISABLED"
EXECUTION_BLOCKED = "EXECUTION_BLOCKED"
ADAPTER_NOT_IMPLEMENTED = "ADAPTER_NOT_IMPLEMENTED"
ADAPTER_CONTRACT_SCHEMA = "usbay.execution.adapter_contract.v1"
ADAPTER_CONTRACT_OWNER = "execution.adapters.base"
ADAPTER_CONTRACT_VERSION = "usbay.pb-adapter-003.adapter-action-scope-enforcement.v1"
ADAPTER_GOVERNANCE_GATE_REFERENCE = "gateway.app.canonical_execution_governance_gate"
ADAPTER_ACTION_SCOPE_OWNER = ADAPTER_CONTRACT_OWNER
REASON_ADAPTER_CONTRACT_MALFORMED = "ADAPTER_CONTRACT_MALFORMED"
REASON_ADAPTER_ACTION_CONTRACT_MISSING = "ADAPTER_ACTION_CONTRACT_MISSING"
REASON_UNKNOWN_ADAPTER = "UNKNOWN_ADAPTER"
REASON_UNKNOWN_CAPABILITY = "UNKNOWN_CAPABILITY"
REASON_UNKNOWN_ACTION_TYPE = "UNKNOWN_ACTION_TYPE"
REASON_ADAPTER_ACTION_SCOPE_MISSING = "ADAPTER_ACTION_SCOPE_MISSING"
REASON_ADAPTER_ACTION_SCOPE_MISMATCH = "ADAPTER_ACTION_SCOPE_MISMATCH"
REASON_ADAPTER_ACTION_SCOPE_OWNER_MISSING = "ADAPTER_ACTION_SCOPE_OWNER_MISSING"
REASON_ADAPTER_ACTION_SCOPE_OWNER_MISMATCH = "ADAPTER_ACTION_SCOPE_OWNER_MISMATCH"
REASON_ADAPTER_ACTION_SCOPE_HASH_MISSING = "ADAPTER_ACTION_SCOPE_HASH_MISSING"
REASON_ADAPTER_ACTION_SCOPE_HASH_MISMATCH = "ADAPTER_ACTION_SCOPE_HASH_MISMATCH"
REASON_ADAPTER_OWNERSHIP_MISSING = "ADAPTER_OWNERSHIP_MISSING"
REASON_ADAPTER_OWNERSHIP_MISMATCH = "ADAPTER_OWNERSHIP_MISMATCH"
REASON_ADAPTER_GATE_REFERENCE_MISSING = "ADAPTER_GATE_REFERENCE_MISSING"
REASON_ADAPTER_GATE_REFERENCE_MISMATCH = "ADAPTER_GATE_REFERENCE_MISMATCH"
REASON_CANONICAL_GATE_PROOF_MISSING = "MISSING_CANONICAL_GATE_PROOF"
REASON_CANONICAL_GATE_PROOF_INVALID = "INVALID_CANONICAL_GATE_PROOF"


ADAPTER_CAPABILITY_DECLARATIONS: tuple[dict[str, Any], ...] = (
    {
        "adapter_name": "browser",
        "capability": "READ_ONLY_NAVIGATION",
        "action_types": ("open_url_preview", "read_page_metadata"),
        "owner": ADAPTER_CONTRACT_OWNER,
        "action_scope_owner": ADAPTER_ACTION_SCOPE_OWNER,
        "governance_gate_reference": ADAPTER_GOVERNANCE_GATE_REFERENCE,
        "required_gate_proof": True,
    },
    {
        "adapter_name": "filesystem",
        "capability": "FILE_READ",
        "action_types": ("preview_file", "read_file_metadata"),
        "owner": ADAPTER_CONTRACT_OWNER,
        "action_scope_owner": ADAPTER_ACTION_SCOPE_OWNER,
        "governance_gate_reference": ADAPTER_GOVERNANCE_GATE_REFERENCE,
        "required_gate_proof": True,
    },
    {
        "adapter_name": "github",
        "capability": "ISSUE_COMMENT_DRAFT",
        "action_types": ("draft_issue_comment",),
        "owner": ADAPTER_CONTRACT_OWNER,
        "action_scope_owner": ADAPTER_ACTION_SCOPE_OWNER,
        "governance_gate_reference": ADAPTER_GOVERNANCE_GATE_REFERENCE,
        "required_gate_proof": True,
    },
    {
        "adapter_name": "github",
        "capability": "PR_DESCRIPTION_DRAFT",
        "action_types": ("draft_pr_description",),
        "owner": ADAPTER_CONTRACT_OWNER,
        "action_scope_owner": ADAPTER_ACTION_SCOPE_OWNER,
        "governance_gate_reference": ADAPTER_GOVERNANCE_GATE_REFERENCE,
        "required_gate_proof": True,
    },
    {
        "adapter_name": "shell",
        "capability": "REPORT_GENERATION",
        "action_types": ("generate_report",),
        "owner": ADAPTER_CONTRACT_OWNER,
        "action_scope_owner": ADAPTER_ACTION_SCOPE_OWNER,
        "governance_gate_reference": ADAPTER_GOVERNANCE_GATE_REFERENCE,
        "required_gate_proof": True,
    },
    {
        "adapter_name": "shell",
        "capability": "GOVERNANCE_STATUS_READ",
        "action_types": ("read_governance_status",),
        "owner": ADAPTER_CONTRACT_OWNER,
        "action_scope_owner": ADAPTER_ACTION_SCOPE_OWNER,
        "governance_gate_reference": ADAPTER_GOVERNANCE_GATE_REFERENCE,
        "required_gate_proof": True,
    },
)


def _action_scope_id(adapter_name: str, capability: str) -> str:
    return f"{adapter_name}:{capability}"


def _action_scope_hash(declaration: dict[str, Any]) -> str:
    actions = ",".join(str(action) for action in declaration["action_types"])
    scope_material = "|".join(
        (
            str(declaration["adapter_name"]),
            str(declaration["capability"]),
            actions,
            str(declaration["action_scope_owner"]),
            str(declaration["governance_gate_reference"]),
        )
    )
    return sha256(scope_material.encode("utf-8")).hexdigest()


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
                "owner": str(record["owner"]),
                "action_scope_owner": str(record["action_scope_owner"]),
                "action_scope_id": _action_scope_id(str(record["adapter_name"]), str(record["capability"])),
                "action_scope_hash": _action_scope_hash(record),
                "governance_gate_reference": str(record["governance_gate_reference"]),
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
    declaration = _matching_declaration(str(adapter_name), str(capability))
    action_scope_hash = _action_scope_hash(declaration) if declaration is not None else ""
    return {
        "schema": ADAPTER_CONTRACT_SCHEMA,
        "contract_version": ADAPTER_CONTRACT_VERSION,
        "adapter_name": str(adapter_name),
        "capability": str(capability),
        "action_type": str(action_type),
        "owner": ADAPTER_CONTRACT_OWNER,
        "action_scope_owner": ADAPTER_ACTION_SCOPE_OWNER,
        "action_scope_id": _action_scope_id(str(adapter_name), str(capability)),
        "action_scope_hash": action_scope_hash,
        "governance_gate_reference": ADAPTER_GOVERNANCE_GATE_REFERENCE,
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
    expected_adapter_name: str | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(contract, dict):
        return _adapter_contract_result(contract, [REASON_ADAPTER_ACTION_CONTRACT_MISSING])
    if contract.get("schema") != ADAPTER_CONTRACT_SCHEMA:
        reasons.append(REASON_ADAPTER_CONTRACT_MALFORMED)
    if contract.get("contract_version") != ADAPTER_CONTRACT_VERSION:
        reasons.append(REASON_ADAPTER_CONTRACT_MALFORMED)
    for field in (
        "adapter_name",
        "capability",
        "action_type",
        "owner",
        "action_scope_owner",
        "action_scope_id",
        "action_scope_hash",
        "governance_gate_reference",
        "request_id",
    ):
        if not str(contract.get(field, "")).strip():
            reasons.append(f"ADAPTER_CONTRACT_{field.upper()}_MISSING")

    adapter_name = str(contract.get("adapter_name", ""))
    capability = str(contract.get("capability", ""))
    action_type = str(contract.get("action_type", ""))
    owner = str(contract.get("owner", ""))
    action_scope_owner = str(contract.get("action_scope_owner", ""))
    action_scope_id = str(contract.get("action_scope_id", ""))
    action_scope_hash = str(contract.get("action_scope_hash", ""))
    governance_gate_reference = str(contract.get("governance_gate_reference", ""))
    if expected_adapter_name and adapter_name and adapter_name != expected_adapter_name:
        reasons.append(REASON_ADAPTER_OWNERSHIP_MISMATCH)
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
    if not action_scope_owner:
        reasons.append(REASON_ADAPTER_ACTION_SCOPE_OWNER_MISSING)
    elif declaration is not None and action_scope_owner != declaration["action_scope_owner"]:
        reasons.append(REASON_ADAPTER_ACTION_SCOPE_OWNER_MISMATCH)
    if not action_scope_id:
        reasons.append(REASON_ADAPTER_ACTION_SCOPE_MISSING)
    elif declaration is not None and action_scope_id != _action_scope_id(adapter_name, capability):
        reasons.append(REASON_ADAPTER_ACTION_SCOPE_MISMATCH)
    if not action_scope_hash:
        reasons.append(REASON_ADAPTER_ACTION_SCOPE_HASH_MISSING)
    elif declaration is not None and action_scope_hash != _action_scope_hash(declaration):
        reasons.append(REASON_ADAPTER_ACTION_SCOPE_HASH_MISMATCH)
    if not owner:
        reasons.append(REASON_ADAPTER_OWNERSHIP_MISSING)
    elif declaration is not None and owner != declaration["owner"]:
        reasons.append(REASON_ADAPTER_OWNERSHIP_MISMATCH)
    if not governance_gate_reference:
        reasons.append(REASON_ADAPTER_GATE_REFERENCE_MISSING)
    elif declaration is not None and governance_gate_reference != declaration["governance_gate_reference"]:
        reasons.append(REASON_ADAPTER_GATE_REFERENCE_MISMATCH)
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
        "owner": str(safe_contract.get("owner", "")),
        "action_scope_owner": str(safe_contract.get("action_scope_owner", "")),
        "action_scope_id": str(safe_contract.get("action_scope_id", "")),
        "action_scope_hash": str(safe_contract.get("action_scope_hash", "")),
        "governance_gate_reference": str(safe_contract.get("governance_gate_reference", "")),
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
        requires_contract = isinstance(request, dict) and any(
            key in request for key in ("adapter_action", "action_type", "capability", "execute")
        )
        if contract is not None or requires_contract:
            validation = validate_adapter_action_contract(
                contract,
                canonical_gate_proof=canonical_gate_proof,
                expected_adapter_name=self.adapter_name,
            )
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
