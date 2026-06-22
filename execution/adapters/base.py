from __future__ import annotations

from hashlib import sha256
from typing import Any

from security.compute_router import ComputeRoutingError, validate_canonical_gate_proof


EXECUTION_DISABLED = "EXECUTION_DISABLED"
EXECUTION_BLOCKED = "EXECUTION_BLOCKED"
ADAPTER_NOT_IMPLEMENTED = "ADAPTER_NOT_IMPLEMENTED"
ADAPTER_CONTRACT_SCHEMA = "usbay.execution.adapter_contract.v1"
ADAPTER_CONTRACT_OWNER = "execution.adapters.base"
ADAPTER_CONTRACT_VERSION = "usbay.pb-adapter-010.adapter-governance-reconciliation-authority.v1"
ADAPTER_GOVERNANCE_GATE_REFERENCE = "gateway.app.canonical_execution_governance_gate"
ADAPTER_GOVERNANCE_CONSISTENCY_AUTHORITY = "usbay.execution.adapters.governance_consistency_authority"
ADAPTER_GOVERNANCE_RECONCILIATION_AUTHORITY = "usbay.execution.adapters.governance_reconciliation_authority"
POLICY_BRAIN_BINDING_AUTHORITY = "usbay.policy_brain.adapter_binding_authority"
POLICY_BRAIN_BINDING_OWNER = "runtime.policy_validator"
POLICY_BRAIN_BINDING_REFERENCE = "runtime/policy_validator.py"
POLICY_BRAIN_BINDING_LINEAGE = "docs/governance/AUDIT_LINEAGE_FRAMEWORK.md"
POLICY_BRAIN_BINDING_STATUS = "POLICY_BOUND"
GATEWAY_ADAPTER_BINDING_AUTHORITY = "usbay.gateway.adapter_reconciliation_binding_authority"
GATEWAY_ADAPTER_BINDING_OWNER = "gateway.app.canonical_execution_governance_gate"
GATEWAY_ADAPTER_BINDING_REFERENCE = "docs/audits/EXECUTION_SURFACE_MAP.md"
GATEWAY_ADAPTER_BINDING_LINEAGE = "docs/audits/CANONICAL_GATE_AUDIT.md"
GATEWAY_ADAPTER_BINDING_STATUS = "GATEWAY_RECONCILED"
SIMULATOR_RUNTIME_BINDING_AUTHORITY = "usbay.simulator.runtime_proof_binding_authority"
SIMULATOR_RUNTIME_BINDING_OWNER = "tests.test_simulation_governance"
SIMULATOR_RUNTIME_BINDING_REFERENCE = "tests/test_simulation_governance.py"
SIMULATOR_RUNTIME_BINDING_LINEAGE = "tests/test_runtime_parity_validator.py"
SIMULATOR_RUNTIME_BINDING_STATUS = "SIMULATOR_RUNTIME_BOUND"
ADAPTER_ACTION_SCOPE_OWNER = ADAPTER_CONTRACT_OWNER
ADAPTER_IDENTITY_OWNER = ADAPTER_CONTRACT_OWNER
ADAPTER_PROVENANCE_OWNER = ADAPTER_CONTRACT_OWNER
ADAPTER_PROVENANCE_SOURCE = "usbay.execution.adapters.registry"
ADAPTER_PROVENANCE_REGISTERED_AT = "2026-06-21T00:00:00Z"
ADAPTER_REGISTRATION_OWNER = ADAPTER_CONTRACT_OWNER
ADAPTER_REGISTRATION_AUTHORITY = "usbay.execution.adapters.registration_authority"
ADAPTER_REGISTRATION_STATES = ("REGISTERED", "APPROVED", "ACTIVE", "REVOKED", "SUSPENDED")
ADAPTER_ALLOWED_REGISTRATION_STATE = "ACTIVE"
ADAPTER_REVOCATION_OWNER = ADAPTER_CONTRACT_OWNER
ADAPTER_REVOCATION_AUTHORITY = "usbay.execution.adapters.revocation_authority"
ADAPTER_REVOCATION_REASONS = (
    "NOT_REVOKED",
    "SECURITY_COMPROMISE",
    "OWNER_REVOKED",
    "POLICY_VIOLATION",
    "PROVENANCE_INVALID",
    "REGISTRATION_REVOKED",
)
ADAPTER_NOT_REVOKED_REASON = "NOT_REVOKED"
ADAPTER_NOT_REVOKED_ACTOR = "NONE"
ADAPTER_NOT_REVOKED_TIMESTAMP = "NONE"
ADAPTER_APPROVAL_OWNER = ADAPTER_CONTRACT_OWNER
ADAPTER_APPROVAL_AUTHORITY = "usbay.execution.adapters.approval_authority"
ADAPTER_APPROVAL_STATES = ("PENDING", "APPROVED", "REJECTED", "EXPIRED", "REVOKED")
ADAPTER_ALLOWED_APPROVAL_STATE = "APPROVED"
ADAPTER_APPROVED_BY = "adapter-governance-board"
ADAPTER_APPROVED_AT = "2026-06-21T00:00:00Z"
ADAPTER_RECONCILIATION_OWNER = ADAPTER_CONTRACT_OWNER
ADAPTER_RECONCILIATION_STATUS = "RECONCILED"
ADAPTER_RECONCILED_AT = "2026-06-21T00:00:00Z"
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
REASON_ADAPTER_ID_MISSING = "ADAPTER_ID_MISSING"
REASON_ADAPTER_ID_MISMATCH = "ADAPTER_ID_MISMATCH"
REASON_ADAPTER_OWNER_MISSING = "ADAPTER_OWNER_MISSING"
REASON_ADAPTER_OWNER_MISMATCH = "ADAPTER_OWNER_MISMATCH"
REASON_ADAPTER_IDENTITY_HASH_MISSING = "ADAPTER_IDENTITY_HASH_MISSING"
REASON_ADAPTER_IDENTITY_HASH_MISMATCH = "ADAPTER_IDENTITY_HASH_MISMATCH"
REASON_ADAPTER_ATTESTATION_REFERENCE_MISSING = "ADAPTER_ATTESTATION_REFERENCE_MISSING"
REASON_ADAPTER_ATTESTATION_REFERENCE_MISMATCH = "ADAPTER_ATTESTATION_REFERENCE_MISMATCH"
REASON_ADAPTER_PROVENANCE_MISSING = "ADAPTER_PROVENANCE_MISSING"
REASON_ADAPTER_PROVENANCE_OWNER_MISMATCH = "ADAPTER_PROVENANCE_OWNER_MISMATCH"
REASON_ADAPTER_PROVENANCE_SOURCE_MISMATCH = "ADAPTER_PROVENANCE_SOURCE_MISMATCH"
REASON_ADAPTER_PROVENANCE_REGISTRATION_MISMATCH = "ADAPTER_PROVENANCE_REGISTRATION_MISMATCH"
REASON_ADAPTER_PROVENANCE_CHAIN_HASH_MISMATCH = "ADAPTER_PROVENANCE_CHAIN_HASH_MISMATCH"
REASON_ADAPTER_PROVENANCE_ATTESTATION_MISMATCH = "ADAPTER_PROVENANCE_ATTESTATION_MISMATCH"
REASON_ADAPTER_REGISTRATION_MISSING = "ADAPTER_REGISTRATION_MISSING"
REASON_ADAPTER_REGISTRATION_STATE_INVALID = "ADAPTER_REGISTRATION_STATE_INVALID"
REASON_ADAPTER_REGISTRATION_NOT_ACTIVE = "ADAPTER_REGISTRATION_NOT_ACTIVE"
REASON_ADAPTER_REGISTRATION_REVOKED = "ADAPTER_REGISTRATION_REVOKED"
REASON_ADAPTER_REGISTRATION_SUSPENDED = "ADAPTER_REGISTRATION_SUSPENDED"
REASON_ADAPTER_REGISTRATION_OWNER_MISMATCH = "ADAPTER_REGISTRATION_OWNER_MISMATCH"
REASON_ADAPTER_REGISTRATION_REFERENCE_MISMATCH = "ADAPTER_REGISTRATION_REFERENCE_MISMATCH"
REASON_ADAPTER_REVOKED = "ADAPTER_REVOKED"
REASON_ADAPTER_REVOCATION_MISSING = "ADAPTER_REVOCATION_MISSING"
REASON_ADAPTER_REVOCATION_REASON_INVALID = "ADAPTER_REVOCATION_REASON_INVALID"
REASON_ADAPTER_REVOCATION_OWNER_MISMATCH = "ADAPTER_REVOCATION_OWNER_MISMATCH"
REASON_ADAPTER_REVOCATION_REFERENCE_MISMATCH = "ADAPTER_REVOCATION_REFERENCE_MISMATCH"
REASON_ADAPTER_REVOCATION_TIMESTAMP_INVALID = "ADAPTER_REVOCATION_TIMESTAMP_INVALID"
REASON_ADAPTER_APPROVAL_MISSING = "ADAPTER_APPROVAL_MISSING"
REASON_ADAPTER_APPROVAL_STATE_INVALID = "ADAPTER_APPROVAL_STATE_INVALID"
REASON_ADAPTER_APPROVAL_PENDING = "ADAPTER_APPROVAL_PENDING"
REASON_ADAPTER_APPROVAL_REJECTED = "ADAPTER_APPROVAL_REJECTED"
REASON_ADAPTER_APPROVAL_EXPIRED = "ADAPTER_APPROVAL_EXPIRED"
REASON_ADAPTER_APPROVAL_REVOKED = "ADAPTER_APPROVAL_REVOKED"
REASON_ADAPTER_APPROVAL_OWNER_MISMATCH = "ADAPTER_APPROVAL_OWNER_MISMATCH"
REASON_ADAPTER_APPROVAL_REFERENCE_MISMATCH = "ADAPTER_APPROVAL_REFERENCE_MISMATCH"
REASON_ADAPTER_CONSISTENCY_AUTHORITY_OWNER_MISMATCH = "ADAPTER_CONSISTENCY_AUTHORITY_OWNER_MISMATCH"
REASON_ADAPTER_CONSISTENCY_AUTHORITY_REFERENCE_MISMATCH = "ADAPTER_CONSISTENCY_AUTHORITY_REFERENCE_MISMATCH"
REASON_ADAPTER_CONSISTENCY_CAPABILITY_ACTION_DRIFT = "ADAPTER_CONSISTENCY_CAPABILITY_ACTION_DRIFT"
REASON_ADAPTER_CONSISTENCY_IDENTITY_PROVENANCE_DRIFT = "ADAPTER_CONSISTENCY_IDENTITY_PROVENANCE_DRIFT"
REASON_ADAPTER_CONSISTENCY_REGISTRATION_APPROVAL_DRIFT = "ADAPTER_CONSISTENCY_REGISTRATION_APPROVAL_DRIFT"
REASON_ADAPTER_CONSISTENCY_APPROVAL_REVOCATION_CONFLICT = "ADAPTER_CONSISTENCY_APPROVAL_REVOCATION_CONFLICT"
REASON_ADAPTER_CONSISTENCY_DUPLICATE_AUTHORITY_IDENTIFIER = "ADAPTER_CONSISTENCY_DUPLICATE_AUTHORITY_IDENTIFIER"
REASON_ADAPTER_CONSISTENCY_LINKAGE_MISSING = "ADAPTER_CONSISTENCY_LINKAGE_MISSING"
REASON_ADAPTER_RECONCILIATION_MISSING = "ADAPTER_RECONCILIATION_MISSING"
REASON_ADAPTER_RECONCILIATION_ORPHAN_AUTHORITY_RECORD = "ADAPTER_RECONCILIATION_ORPHAN_AUTHORITY_RECORD"
REASON_ADAPTER_RECONCILIATION_STALE_STATE = "ADAPTER_RECONCILIATION_STALE_STATE"
REASON_ADAPTER_RECONCILIATION_UNRESOLVED_CONFLICT = "ADAPTER_RECONCILIATION_UNRESOLVED_CONFLICT"
REASON_ADAPTER_RECONCILIATION_TIMESTAMP_DRIFT = "ADAPTER_RECONCILIATION_TIMESTAMP_DRIFT"
REASON_ADAPTER_RECONCILIATION_OWNERSHIP_DIVERGENCE = "ADAPTER_RECONCILIATION_OWNERSHIP_DIVERGENCE"
REASON_ADAPTER_RECONCILIATION_REFERENCE_DIVERGENCE = "ADAPTER_RECONCILIATION_REFERENCE_DIVERGENCE"
REASON_ADAPTER_RECONCILIATION_LINKAGE_MISSING = "ADAPTER_RECONCILIATION_LINKAGE_MISSING"
REASON_ADAPTER_RECONCILIATION_EVIDENCE_MISMATCH = "ADAPTER_RECONCILIATION_EVIDENCE_MISMATCH"
REASON_ADAPTER_RECONCILIATION_DUPLICATE_RECORD = "ADAPTER_RECONCILIATION_DUPLICATE_RECORD"
REASON_POLICY_BINDING_MISSING = "POLICY_BINDING_MISSING"
REASON_POLICY_REFERENCE_MISSING = "POLICY_REFERENCE_MISSING"
REASON_POLICY_LINEAGE_MISSING = "POLICY_LINEAGE_MISSING"
REASON_POLICY_OWNER_MISMATCH = "POLICY_OWNER_MISMATCH"
REASON_POLICY_REFERENCE_MISMATCH = "POLICY_REFERENCE_MISMATCH"
REASON_POLICY_HASH_MISMATCH = "POLICY_HASH_MISMATCH"
REASON_POLICY_BINDING_STALE = "POLICY_BINDING_STALE"
REASON_POLICY_BINDING_DUPLICATE = "POLICY_BINDING_DUPLICATE"
REASON_POLICY_BINDING_ORPHAN = "POLICY_BINDING_ORPHAN"
REASON_GATEWAY_BINDING_MISSING = "GATEWAY_BINDING_MISSING"
REASON_GATEWAY_REFERENCE_MISSING = "GATEWAY_REFERENCE_MISSING"
REASON_GATEWAY_LINEAGE_MISSING = "GATEWAY_LINEAGE_MISSING"
REASON_GATEWAY_OWNER_MISMATCH = "GATEWAY_OWNER_MISMATCH"
REASON_GATEWAY_REFERENCE_MISMATCH = "GATEWAY_REFERENCE_MISMATCH"
REASON_GATEWAY_HASH_MISMATCH = "GATEWAY_HASH_MISMATCH"
REASON_GATEWAY_BINDING_STALE = "GATEWAY_BINDING_STALE"
REASON_GATEWAY_BINDING_DUPLICATE = "GATEWAY_BINDING_DUPLICATE"
REASON_GATEWAY_BINDING_ORPHAN = "GATEWAY_BINDING_ORPHAN"
REASON_SIMULATOR_BINDING_MISSING = "SIMULATOR_BINDING_MISSING"
REASON_SIMULATOR_REFERENCE_MISSING = "SIMULATOR_REFERENCE_MISSING"
REASON_SIMULATOR_LINEAGE_MISSING = "SIMULATOR_LINEAGE_MISSING"
REASON_SIMULATOR_OWNER_MISMATCH = "SIMULATOR_OWNER_MISMATCH"
REASON_SIMULATOR_REFERENCE_MISMATCH = "SIMULATOR_REFERENCE_MISMATCH"
REASON_SIMULATOR_HASH_MISMATCH = "SIMULATOR_HASH_MISMATCH"
REASON_SIMULATOR_BINDING_STALE = "SIMULATOR_BINDING_STALE"
REASON_SIMULATOR_BINDING_DUPLICATE = "SIMULATOR_BINDING_DUPLICATE"
REASON_SIMULATOR_BINDING_ORPHAN = "SIMULATOR_BINDING_ORPHAN"
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
        "adapter_id": "adapter.browser.v1",
        "adapter_owner": ADAPTER_IDENTITY_OWNER,
        "attestation_reference": "usbay.adapter.browser.identity.v1",
        "provenance_owner": ADAPTER_PROVENANCE_OWNER,
        "provenance_source": ADAPTER_PROVENANCE_SOURCE,
        "provenance_registered_at": ADAPTER_PROVENANCE_REGISTERED_AT,
        "provenance_attestation_reference": "usbay.adapter.browser.provenance.v1",
        "registration_id": "adapter-registration.browser.v1",
        "registration_state": ADAPTER_ALLOWED_REGISTRATION_STATE,
        "registration_owner": ADAPTER_REGISTRATION_OWNER,
        "registration_reference": "usbay.adapter.browser.registration.v1",
        "revocation_id": "adapter-revocation.browser.none.v1",
        "revocation_reason": ADAPTER_NOT_REVOKED_REASON,
        "revocation_owner": ADAPTER_REVOCATION_OWNER,
        "revoked_by": ADAPTER_NOT_REVOKED_ACTOR,
        "revoked_at": ADAPTER_NOT_REVOKED_TIMESTAMP,
        "revocation_reference": "usbay.adapter.browser.revocation.none.v1",
        "approval_id": "adapter-approval.browser.v1",
        "approval_state": ADAPTER_ALLOWED_APPROVAL_STATE,
        "approval_owner": ADAPTER_APPROVAL_OWNER,
        "approved_by": ADAPTER_APPROVED_BY,
        "approved_at": ADAPTER_APPROVED_AT,
        "approval_reference": "usbay.adapter.browser.approval.v1",
        "reconciliation_id": "adapter-reconciliation.browser.v1",
        "reconciliation_status": ADAPTER_RECONCILIATION_STATUS,
        "reconciliation_owner": ADAPTER_RECONCILIATION_OWNER,
        "reconciled_at": ADAPTER_RECONCILED_AT,
        "reconciliation_reference": "usbay.adapter.browser.reconciliation.v1",
        "governance_gate_reference": ADAPTER_GOVERNANCE_GATE_REFERENCE,
        "required_gate_proof": True,
    },
    {
        "adapter_name": "filesystem",
        "capability": "FILE_READ",
        "action_types": ("preview_file", "read_file_metadata"),
        "owner": ADAPTER_CONTRACT_OWNER,
        "action_scope_owner": ADAPTER_ACTION_SCOPE_OWNER,
        "adapter_id": "adapter.filesystem.v1",
        "adapter_owner": ADAPTER_IDENTITY_OWNER,
        "attestation_reference": "usbay.adapter.filesystem.identity.v1",
        "provenance_owner": ADAPTER_PROVENANCE_OWNER,
        "provenance_source": ADAPTER_PROVENANCE_SOURCE,
        "provenance_registered_at": ADAPTER_PROVENANCE_REGISTERED_AT,
        "provenance_attestation_reference": "usbay.adapter.filesystem.provenance.v1",
        "registration_id": "adapter-registration.filesystem.v1",
        "registration_state": ADAPTER_ALLOWED_REGISTRATION_STATE,
        "registration_owner": ADAPTER_REGISTRATION_OWNER,
        "registration_reference": "usbay.adapter.filesystem.registration.v1",
        "revocation_id": "adapter-revocation.filesystem.none.v1",
        "revocation_reason": ADAPTER_NOT_REVOKED_REASON,
        "revocation_owner": ADAPTER_REVOCATION_OWNER,
        "revoked_by": ADAPTER_NOT_REVOKED_ACTOR,
        "revoked_at": ADAPTER_NOT_REVOKED_TIMESTAMP,
        "revocation_reference": "usbay.adapter.filesystem.revocation.none.v1",
        "approval_id": "adapter-approval.filesystem.v1",
        "approval_state": ADAPTER_ALLOWED_APPROVAL_STATE,
        "approval_owner": ADAPTER_APPROVAL_OWNER,
        "approved_by": ADAPTER_APPROVED_BY,
        "approved_at": ADAPTER_APPROVED_AT,
        "approval_reference": "usbay.adapter.filesystem.approval.v1",
        "reconciliation_id": "adapter-reconciliation.filesystem.v1",
        "reconciliation_status": ADAPTER_RECONCILIATION_STATUS,
        "reconciliation_owner": ADAPTER_RECONCILIATION_OWNER,
        "reconciled_at": ADAPTER_RECONCILED_AT,
        "reconciliation_reference": "usbay.adapter.filesystem.reconciliation.v1",
        "governance_gate_reference": ADAPTER_GOVERNANCE_GATE_REFERENCE,
        "required_gate_proof": True,
    },
    {
        "adapter_name": "github",
        "capability": "ISSUE_COMMENT_DRAFT",
        "action_types": ("draft_issue_comment",),
        "owner": ADAPTER_CONTRACT_OWNER,
        "action_scope_owner": ADAPTER_ACTION_SCOPE_OWNER,
        "adapter_id": "adapter.github.v1",
        "adapter_owner": ADAPTER_IDENTITY_OWNER,
        "attestation_reference": "usbay.adapter.github.identity.v1",
        "provenance_owner": ADAPTER_PROVENANCE_OWNER,
        "provenance_source": ADAPTER_PROVENANCE_SOURCE,
        "provenance_registered_at": ADAPTER_PROVENANCE_REGISTERED_AT,
        "provenance_attestation_reference": "usbay.adapter.github.provenance.v1",
        "registration_id": "adapter-registration.github.v1",
        "registration_state": ADAPTER_ALLOWED_REGISTRATION_STATE,
        "registration_owner": ADAPTER_REGISTRATION_OWNER,
        "registration_reference": "usbay.adapter.github.registration.v1",
        "revocation_id": "adapter-revocation.github.none.v1",
        "revocation_reason": ADAPTER_NOT_REVOKED_REASON,
        "revocation_owner": ADAPTER_REVOCATION_OWNER,
        "revoked_by": ADAPTER_NOT_REVOKED_ACTOR,
        "revoked_at": ADAPTER_NOT_REVOKED_TIMESTAMP,
        "revocation_reference": "usbay.adapter.github.revocation.none.v1",
        "approval_id": "adapter-approval.github.v1",
        "approval_state": ADAPTER_ALLOWED_APPROVAL_STATE,
        "approval_owner": ADAPTER_APPROVAL_OWNER,
        "approved_by": ADAPTER_APPROVED_BY,
        "approved_at": ADAPTER_APPROVED_AT,
        "approval_reference": "usbay.adapter.github.approval.v1",
        "reconciliation_id": "adapter-reconciliation.github.v1",
        "reconciliation_status": ADAPTER_RECONCILIATION_STATUS,
        "reconciliation_owner": ADAPTER_RECONCILIATION_OWNER,
        "reconciled_at": ADAPTER_RECONCILED_AT,
        "reconciliation_reference": "usbay.adapter.github.reconciliation.v1",
        "governance_gate_reference": ADAPTER_GOVERNANCE_GATE_REFERENCE,
        "required_gate_proof": True,
    },
    {
        "adapter_name": "github",
        "capability": "PR_DESCRIPTION_DRAFT",
        "action_types": ("draft_pr_description",),
        "owner": ADAPTER_CONTRACT_OWNER,
        "action_scope_owner": ADAPTER_ACTION_SCOPE_OWNER,
        "adapter_id": "adapter.github.v1",
        "adapter_owner": ADAPTER_IDENTITY_OWNER,
        "attestation_reference": "usbay.adapter.github.identity.v1",
        "provenance_owner": ADAPTER_PROVENANCE_OWNER,
        "provenance_source": ADAPTER_PROVENANCE_SOURCE,
        "provenance_registered_at": ADAPTER_PROVENANCE_REGISTERED_AT,
        "provenance_attestation_reference": "usbay.adapter.github.provenance.v1",
        "registration_id": "adapter-registration.github.v1",
        "registration_state": ADAPTER_ALLOWED_REGISTRATION_STATE,
        "registration_owner": ADAPTER_REGISTRATION_OWNER,
        "registration_reference": "usbay.adapter.github.registration.v1",
        "revocation_id": "adapter-revocation.github.none.v1",
        "revocation_reason": ADAPTER_NOT_REVOKED_REASON,
        "revocation_owner": ADAPTER_REVOCATION_OWNER,
        "revoked_by": ADAPTER_NOT_REVOKED_ACTOR,
        "revoked_at": ADAPTER_NOT_REVOKED_TIMESTAMP,
        "revocation_reference": "usbay.adapter.github.revocation.none.v1",
        "approval_id": "adapter-approval.github.v1",
        "approval_state": ADAPTER_ALLOWED_APPROVAL_STATE,
        "approval_owner": ADAPTER_APPROVAL_OWNER,
        "approved_by": ADAPTER_APPROVED_BY,
        "approved_at": ADAPTER_APPROVED_AT,
        "approval_reference": "usbay.adapter.github.approval.v1",
        "reconciliation_id": "adapter-reconciliation.github.v1",
        "reconciliation_status": ADAPTER_RECONCILIATION_STATUS,
        "reconciliation_owner": ADAPTER_RECONCILIATION_OWNER,
        "reconciled_at": ADAPTER_RECONCILED_AT,
        "reconciliation_reference": "usbay.adapter.github.reconciliation.v1",
        "governance_gate_reference": ADAPTER_GOVERNANCE_GATE_REFERENCE,
        "required_gate_proof": True,
    },
    {
        "adapter_name": "shell",
        "capability": "REPORT_GENERATION",
        "action_types": ("generate_report",),
        "owner": ADAPTER_CONTRACT_OWNER,
        "action_scope_owner": ADAPTER_ACTION_SCOPE_OWNER,
        "adapter_id": "adapter.shell.v1",
        "adapter_owner": ADAPTER_IDENTITY_OWNER,
        "attestation_reference": "usbay.adapter.shell.identity.v1",
        "provenance_owner": ADAPTER_PROVENANCE_OWNER,
        "provenance_source": ADAPTER_PROVENANCE_SOURCE,
        "provenance_registered_at": ADAPTER_PROVENANCE_REGISTERED_AT,
        "provenance_attestation_reference": "usbay.adapter.shell.provenance.v1",
        "registration_id": "adapter-registration.shell.v1",
        "registration_state": ADAPTER_ALLOWED_REGISTRATION_STATE,
        "registration_owner": ADAPTER_REGISTRATION_OWNER,
        "registration_reference": "usbay.adapter.shell.registration.v1",
        "revocation_id": "adapter-revocation.shell.none.v1",
        "revocation_reason": ADAPTER_NOT_REVOKED_REASON,
        "revocation_owner": ADAPTER_REVOCATION_OWNER,
        "revoked_by": ADAPTER_NOT_REVOKED_ACTOR,
        "revoked_at": ADAPTER_NOT_REVOKED_TIMESTAMP,
        "revocation_reference": "usbay.adapter.shell.revocation.none.v1",
        "approval_id": "adapter-approval.shell.v1",
        "approval_state": ADAPTER_ALLOWED_APPROVAL_STATE,
        "approval_owner": ADAPTER_APPROVAL_OWNER,
        "approved_by": ADAPTER_APPROVED_BY,
        "approved_at": ADAPTER_APPROVED_AT,
        "approval_reference": "usbay.adapter.shell.approval.v1",
        "reconciliation_id": "adapter-reconciliation.shell.v1",
        "reconciliation_status": ADAPTER_RECONCILIATION_STATUS,
        "reconciliation_owner": ADAPTER_RECONCILIATION_OWNER,
        "reconciled_at": ADAPTER_RECONCILED_AT,
        "reconciliation_reference": "usbay.adapter.shell.reconciliation.v1",
        "governance_gate_reference": ADAPTER_GOVERNANCE_GATE_REFERENCE,
        "required_gate_proof": True,
    },
    {
        "adapter_name": "shell",
        "capability": "GOVERNANCE_STATUS_READ",
        "action_types": ("read_governance_status",),
        "owner": ADAPTER_CONTRACT_OWNER,
        "action_scope_owner": ADAPTER_ACTION_SCOPE_OWNER,
        "adapter_id": "adapter.shell.v1",
        "adapter_owner": ADAPTER_IDENTITY_OWNER,
        "attestation_reference": "usbay.adapter.shell.identity.v1",
        "provenance_owner": ADAPTER_PROVENANCE_OWNER,
        "provenance_source": ADAPTER_PROVENANCE_SOURCE,
        "provenance_registered_at": ADAPTER_PROVENANCE_REGISTERED_AT,
        "provenance_attestation_reference": "usbay.adapter.shell.provenance.v1",
        "registration_id": "adapter-registration.shell.v1",
        "registration_state": ADAPTER_ALLOWED_REGISTRATION_STATE,
        "registration_owner": ADAPTER_REGISTRATION_OWNER,
        "registration_reference": "usbay.adapter.shell.registration.v1",
        "revocation_id": "adapter-revocation.shell.none.v1",
        "revocation_reason": ADAPTER_NOT_REVOKED_REASON,
        "revocation_owner": ADAPTER_REVOCATION_OWNER,
        "revoked_by": ADAPTER_NOT_REVOKED_ACTOR,
        "revoked_at": ADAPTER_NOT_REVOKED_TIMESTAMP,
        "revocation_reference": "usbay.adapter.shell.revocation.none.v1",
        "approval_id": "adapter-approval.shell.v1",
        "approval_state": ADAPTER_ALLOWED_APPROVAL_STATE,
        "approval_owner": ADAPTER_APPROVAL_OWNER,
        "approved_by": ADAPTER_APPROVED_BY,
        "approved_at": ADAPTER_APPROVED_AT,
        "approval_reference": "usbay.adapter.shell.approval.v1",
        "reconciliation_id": "adapter-reconciliation.shell.v1",
        "reconciliation_status": ADAPTER_RECONCILIATION_STATUS,
        "reconciliation_owner": ADAPTER_RECONCILIATION_OWNER,
        "reconciled_at": ADAPTER_RECONCILED_AT,
        "reconciliation_reference": "usbay.adapter.shell.reconciliation.v1",
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


def _adapter_identity_hash(declaration: dict[str, Any]) -> str:
    identity_material = "|".join(
        (
            str(declaration["adapter_name"]),
            str(declaration["adapter_id"]),
            str(declaration["adapter_owner"]),
            str(declaration["attestation_reference"]),
            str(declaration["governance_gate_reference"]),
        )
    )
    return sha256(identity_material.encode("utf-8")).hexdigest()


def _adapter_provenance_chain_hash(declaration: dict[str, Any]) -> str:
    provenance_material = "|".join(
        (
            str(declaration["adapter_name"]),
            str(declaration["adapter_id"]),
            str(declaration["adapter_owner"]),
            _adapter_identity_hash(declaration),
            str(declaration["provenance_owner"]),
            str(declaration["provenance_source"]),
            str(declaration["provenance_registered_at"]),
            str(declaration["provenance_attestation_reference"]),
            str(declaration["governance_gate_reference"]),
        )
    )
    return sha256(provenance_material.encode("utf-8")).hexdigest()


def _policy_binding_id(adapter_name: str, capability: str) -> str:
    safe_capability = capability.lower().replace("_", "-")
    return f"policy-binding.{adapter_name}.{safe_capability}.v1"


def _policy_binding_reference(adapter_name: str, capability: str) -> str:
    safe_capability = capability.lower().replace("_", "-")
    return f"runtime/policy_validator.py#{adapter_name}.{safe_capability}"


def _policy_binding_hash(declaration: dict[str, Any]) -> str:
    binding_material = "|".join(
        (
            _policy_binding_id(str(declaration["adapter_name"]), str(declaration["capability"])),
            POLICY_BRAIN_BINDING_OWNER,
            _policy_binding_reference(str(declaration["adapter_name"]), str(declaration["capability"])),
            POLICY_BRAIN_BINDING_LINEAGE,
            POLICY_BRAIN_BINDING_STATUS,
            str(declaration["adapter_name"]),
            str(declaration["capability"]),
            _adapter_provenance_chain_hash(declaration),
            str(declaration["governance_gate_reference"]),
        )
    )
    return sha256(binding_material.encode("utf-8")).hexdigest()


def _gateway_binding_id(adapter_name: str, capability: str) -> str:
    safe_capability = capability.lower().replace("_", "-")
    return f"gateway-binding.{adapter_name}.{safe_capability}.v1"


def _gateway_binding_reference(adapter_name: str, capability: str) -> str:
    safe_capability = capability.lower().replace("_", "-")
    return f"docs/audits/EXECUTION_SURFACE_MAP.md#{adapter_name}.{safe_capability}"


def _gateway_binding_hash(declaration: dict[str, Any]) -> str:
    binding_material = "|".join(
        (
            _gateway_binding_id(str(declaration["adapter_name"]), str(declaration["capability"])),
            GATEWAY_ADAPTER_BINDING_OWNER,
            _gateway_binding_reference(str(declaration["adapter_name"]), str(declaration["capability"])),
            GATEWAY_ADAPTER_BINDING_LINEAGE,
            GATEWAY_ADAPTER_BINDING_STATUS,
            str(declaration["adapter_name"]),
            str(declaration["capability"]),
            str(declaration["governance_gate_reference"]),
            _adapter_reconciliation_material_without_gateway(declaration),
        )
    )
    return sha256(binding_material.encode("utf-8")).hexdigest()


def _simulator_binding_id(adapter_name: str, capability: str) -> str:
    safe_capability = capability.lower().replace("_", "-")
    return f"simulator-runtime-binding.{adapter_name}.{safe_capability}.v1"


def _simulator_binding_reference(adapter_name: str, capability: str) -> str:
    safe_capability = capability.lower().replace("_", "-")
    return f"tests/test_simulation_governance.py#{adapter_name}.{safe_capability}"


def _simulator_binding_hash(declaration: dict[str, Any]) -> str:
    binding_material = "|".join(
        (
            _simulator_binding_id(str(declaration["adapter_name"]), str(declaration["capability"])),
            SIMULATOR_RUNTIME_BINDING_OWNER,
            _simulator_binding_reference(str(declaration["adapter_name"]), str(declaration["capability"])),
            SIMULATOR_RUNTIME_BINDING_LINEAGE,
            SIMULATOR_RUNTIME_BINDING_STATUS,
            str(declaration["adapter_name"]),
            str(declaration["capability"]),
            _gateway_binding_hash(declaration),
            str(declaration["governance_gate_reference"]),
        )
    )
    return sha256(binding_material.encode("utf-8")).hexdigest()


def _adapter_reconciliation_material_without_gateway(declaration: dict[str, Any]) -> str:
    return "|".join(
        (
            str(declaration["adapter_name"]),
            str(declaration["capability"]),
            str(declaration["adapter_id"]),
            _action_scope_hash(declaration),
            _adapter_identity_hash(declaration),
            _adapter_provenance_chain_hash(declaration),
            _policy_binding_hash(declaration),
            str(declaration["registration_id"]),
            str(declaration["registration_state"]),
            str(declaration["approval_id"]),
            str(declaration["approval_state"]),
            str(declaration["revocation_id"]),
            str(declaration["revocation_reason"]),
            str(declaration["reconciliation_id"]),
            str(declaration["reconciliation_status"]),
            str(declaration["reconciliation_owner"]),
            str(declaration["reconciled_at"]),
            str(declaration["reconciliation_reference"]),
            str(declaration["governance_gate_reference"]),
        )
    )


def _adapter_reconciliation_hash(declaration: dict[str, Any]) -> str:
    reconciliation_material = "|".join(
        (
            _adapter_reconciliation_material_without_gateway(declaration),
            _gateway_binding_hash(declaration),
            _simulator_binding_hash(declaration),
        )
    )
    return sha256(reconciliation_material.encode("utf-8")).hexdigest()


def _adapter_suffix(adapter_name: str) -> str:
    return f".{adapter_name}."


def _governance_consistency_reasons(contract: dict[str, Any], declaration: dict[str, Any] | None) -> list[str]:
    adapter_name = str(contract.get("adapter_name", ""))
    capability = str(contract.get("capability", ""))
    action_type = str(contract.get("action_type", ""))
    owners = (
        str(contract.get("owner", "")),
        str(contract.get("action_scope_owner", "")),
        str(contract.get("adapter_owner", "")),
        str(contract.get("provenance_owner", "")),
        str(contract.get("registration_owner", "")),
        str(contract.get("revocation_owner", "")),
        str(contract.get("approval_owner", "")),
    )
    references = (
        str(contract.get("attestation_reference", "")),
        str(contract.get("provenance_attestation_reference", "")),
        str(contract.get("registration_reference", "")),
        str(contract.get("revocation_reference", "")),
        str(contract.get("approval_reference", "")),
    )
    identifiers = (
        str(contract.get("adapter_id", "")),
        str(contract.get("registration_id", "")),
        str(contract.get("revocation_id", "")),
        str(contract.get("approval_id", "")),
    )
    required_linkages = owners + references + identifiers + (
        str(contract.get("action_scope_id", "")),
        str(contract.get("action_scope_hash", "")),
        str(contract.get("adapter_identity_hash", "")),
        str(contract.get("provenance_chain_hash", "")),
        str(contract.get("policy_binding_id", "")),
        str(contract.get("policy_binding_owner", "")),
        str(contract.get("policy_binding_reference", "")),
        str(contract.get("policy_binding_lineage", "")),
        str(contract.get("policy_binding_hash", "")),
        str(contract.get("gateway_binding_id", "")),
        str(contract.get("gateway_binding_owner", "")),
        str(contract.get("gateway_binding_reference", "")),
        str(contract.get("gateway_binding_lineage", "")),
        str(contract.get("gateway_binding_hash", "")),
        str(contract.get("simulator_binding_id", "")),
        str(contract.get("simulator_binding_owner", "")),
        str(contract.get("simulator_binding_reference", "")),
        str(contract.get("simulator_binding_lineage", "")),
        str(contract.get("simulator_binding_hash", "")),
        str(contract.get("governance_gate_reference", "")),
    )

    reasons: list[str] = []
    if not all(required_linkages):
        reasons.append(REASON_ADAPTER_CONSISTENCY_LINKAGE_MISSING)
    if any(owner != ADAPTER_CONTRACT_OWNER for owner in owners if owner):
        reasons.append(REASON_ADAPTER_CONSISTENCY_AUTHORITY_OWNER_MISMATCH)
    if adapter_name and any(_adapter_suffix(adapter_name) not in reference for reference in references if reference):
        reasons.append(REASON_ADAPTER_CONSISTENCY_AUTHORITY_REFERENCE_MISMATCH)
    if len(set(identifier for identifier in identifiers if identifier)) != len([identifier for identifier in identifiers if identifier]):
        reasons.append(REASON_ADAPTER_CONSISTENCY_DUPLICATE_AUTHORITY_IDENTIFIER)
    if declaration is not None and action_type and action_type not in declaration["action_types"]:
        reasons.append(REASON_ADAPTER_CONSISTENCY_CAPABILITY_ACTION_DRIFT)
    if declaration is not None and capability and contract.get("action_scope_id") != _action_scope_id(adapter_name, capability):
        reasons.append(REASON_ADAPTER_CONSISTENCY_CAPABILITY_ACTION_DRIFT)
    if declaration is not None:
        identity_reference = str(contract.get("attestation_reference", ""))
        provenance_reference = str(contract.get("provenance_attestation_reference", ""))
        if adapter_name and (
            _adapter_suffix(adapter_name) not in identity_reference
            or _adapter_suffix(adapter_name) not in provenance_reference
        ):
            reasons.append(REASON_ADAPTER_CONSISTENCY_IDENTITY_PROVENANCE_DRIFT)
        if contract.get("adapter_identity_hash") != _adapter_identity_hash(declaration):
            reasons.append(REASON_ADAPTER_CONSISTENCY_IDENTITY_PROVENANCE_DRIFT)
        if contract.get("provenance_chain_hash") != _adapter_provenance_chain_hash(declaration):
            reasons.append(REASON_ADAPTER_CONSISTENCY_IDENTITY_PROVENANCE_DRIFT)
    if contract.get("approval_state") == ADAPTER_ALLOWED_APPROVAL_STATE and contract.get("registration_state") != ADAPTER_ALLOWED_REGISTRATION_STATE:
        reasons.append(REASON_ADAPTER_CONSISTENCY_REGISTRATION_APPROVAL_DRIFT)
    if contract.get("approval_state") == ADAPTER_ALLOWED_APPROVAL_STATE and contract.get("revocation_reason") != ADAPTER_NOT_REVOKED_REASON:
        reasons.append(REASON_ADAPTER_CONSISTENCY_APPROVAL_REVOCATION_CONFLICT)
    if contract.get("governance_gate_reference") != ADAPTER_GOVERNANCE_GATE_REFERENCE:
        reasons.append(REASON_ADAPTER_CONSISTENCY_AUTHORITY_REFERENCE_MISMATCH)
    return sorted(set(reasons))


def _policy_binding_reasons(contract: dict[str, Any], declaration: dict[str, Any] | None) -> list[str]:
    policy_binding_id = str(contract.get("policy_binding_id", ""))
    policy_binding_owner = str(contract.get("policy_binding_owner", ""))
    policy_binding_reference = str(contract.get("policy_binding_reference", ""))
    policy_binding_lineage = str(contract.get("policy_binding_lineage", ""))
    policy_binding_status = str(contract.get("policy_binding_status", ""))
    policy_binding_hash = str(contract.get("policy_binding_hash", ""))
    identifiers = (
        str(contract.get("adapter_id", "")),
        str(contract.get("registration_id", "")),
        str(contract.get("revocation_id", "")),
        str(contract.get("approval_id", "")),
        str(contract.get("reconciliation_id", "")),
    )

    reasons: list[str] = []
    if declaration is None and any(
        (policy_binding_id, policy_binding_owner, policy_binding_reference, policy_binding_lineage, policy_binding_hash)
    ):
        reasons.append(REASON_POLICY_BINDING_ORPHAN)
    if not all((policy_binding_id, policy_binding_owner, policy_binding_status, policy_binding_hash)):
        reasons.append(REASON_POLICY_BINDING_MISSING)
    if not policy_binding_reference:
        reasons.append(REASON_POLICY_REFERENCE_MISSING)
    if not policy_binding_lineage:
        reasons.append(REASON_POLICY_LINEAGE_MISSING)
    if policy_binding_owner and policy_binding_owner != POLICY_BRAIN_BINDING_OWNER:
        reasons.append(REASON_POLICY_OWNER_MISMATCH)
    if policy_binding_status and policy_binding_status != POLICY_BRAIN_BINDING_STATUS:
        reasons.append(REASON_POLICY_BINDING_STALE)
    if policy_binding_id and policy_binding_id in {identifier for identifier in identifiers if identifier}:
        reasons.append(REASON_POLICY_BINDING_DUPLICATE)
    if declaration is not None:
        expected_reference = _policy_binding_reference(str(declaration["adapter_name"]), str(declaration["capability"]))
        if policy_binding_id and policy_binding_id != _policy_binding_id(
            str(declaration["adapter_name"]), str(declaration["capability"])
        ):
            reasons.append(REASON_POLICY_REFERENCE_MISMATCH)
        if policy_binding_reference and policy_binding_reference != expected_reference:
            reasons.append(REASON_POLICY_REFERENCE_MISMATCH)
        if policy_binding_lineage and policy_binding_lineage != POLICY_BRAIN_BINDING_LINEAGE:
            reasons.append(REASON_POLICY_LINEAGE_MISSING)
        if policy_binding_hash and policy_binding_hash != _policy_binding_hash(declaration):
            reasons.append(REASON_POLICY_HASH_MISMATCH)
    return sorted(set(reasons))


def _gateway_binding_reasons(contract: dict[str, Any], declaration: dict[str, Any] | None) -> list[str]:
    gateway_binding_id = str(contract.get("gateway_binding_id", ""))
    gateway_binding_owner = str(contract.get("gateway_binding_owner", ""))
    gateway_binding_reference = str(contract.get("gateway_binding_reference", ""))
    gateway_binding_lineage = str(contract.get("gateway_binding_lineage", ""))
    gateway_binding_status = str(contract.get("gateway_binding_status", ""))
    gateway_binding_hash = str(contract.get("gateway_binding_hash", ""))
    identifiers = (
        str(contract.get("adapter_id", "")),
        str(contract.get("registration_id", "")),
        str(contract.get("revocation_id", "")),
        str(contract.get("approval_id", "")),
        str(contract.get("reconciliation_id", "")),
        str(contract.get("policy_binding_id", "")),
    )

    reasons: list[str] = []
    if declaration is None and any(
        (gateway_binding_id, gateway_binding_owner, gateway_binding_reference, gateway_binding_lineage, gateway_binding_hash)
    ):
        reasons.append(REASON_GATEWAY_BINDING_ORPHAN)
    if not all((gateway_binding_id, gateway_binding_owner, gateway_binding_status, gateway_binding_hash)):
        reasons.append(REASON_GATEWAY_BINDING_MISSING)
    if not gateway_binding_reference:
        reasons.append(REASON_GATEWAY_REFERENCE_MISSING)
    if not gateway_binding_lineage:
        reasons.append(REASON_GATEWAY_LINEAGE_MISSING)
    if gateway_binding_owner and gateway_binding_owner != GATEWAY_ADAPTER_BINDING_OWNER:
        reasons.append(REASON_GATEWAY_OWNER_MISMATCH)
    if gateway_binding_status and gateway_binding_status != GATEWAY_ADAPTER_BINDING_STATUS:
        reasons.append(REASON_GATEWAY_BINDING_STALE)
    if gateway_binding_id and gateway_binding_id in {identifier for identifier in identifiers if identifier}:
        reasons.append(REASON_GATEWAY_BINDING_DUPLICATE)
    if declaration is not None:
        expected_reference = _gateway_binding_reference(str(declaration["adapter_name"]), str(declaration["capability"]))
        if gateway_binding_id and gateway_binding_id != _gateway_binding_id(
            str(declaration["adapter_name"]), str(declaration["capability"])
        ):
            reasons.append(REASON_GATEWAY_REFERENCE_MISMATCH)
        if gateway_binding_reference and gateway_binding_reference != expected_reference:
            reasons.append(REASON_GATEWAY_REFERENCE_MISMATCH)
        if gateway_binding_lineage and gateway_binding_lineage != GATEWAY_ADAPTER_BINDING_LINEAGE:
            reasons.append(REASON_GATEWAY_LINEAGE_MISSING)
        if gateway_binding_hash and gateway_binding_hash != _gateway_binding_hash(declaration):
            reasons.append(REASON_GATEWAY_HASH_MISMATCH)
    return sorted(set(reasons))


def _simulator_binding_reasons(contract: dict[str, Any], declaration: dict[str, Any] | None) -> list[str]:
    simulator_binding_id = str(contract.get("simulator_binding_id", ""))
    simulator_binding_owner = str(contract.get("simulator_binding_owner", ""))
    simulator_binding_reference = str(contract.get("simulator_binding_reference", ""))
    simulator_binding_lineage = str(contract.get("simulator_binding_lineage", ""))
    simulator_binding_status = str(contract.get("simulator_binding_status", ""))
    simulator_binding_hash = str(contract.get("simulator_binding_hash", ""))
    identifiers = (
        str(contract.get("adapter_id", "")),
        str(contract.get("registration_id", "")),
        str(contract.get("revocation_id", "")),
        str(contract.get("approval_id", "")),
        str(contract.get("reconciliation_id", "")),
        str(contract.get("policy_binding_id", "")),
        str(contract.get("gateway_binding_id", "")),
    )

    reasons: list[str] = []
    if declaration is None and any(
        (
            simulator_binding_id,
            simulator_binding_owner,
            simulator_binding_reference,
            simulator_binding_lineage,
            simulator_binding_hash,
        )
    ):
        reasons.append(REASON_SIMULATOR_BINDING_ORPHAN)
    if not all((simulator_binding_id, simulator_binding_owner, simulator_binding_status, simulator_binding_hash)):
        reasons.append(REASON_SIMULATOR_BINDING_MISSING)
    if not simulator_binding_reference:
        reasons.append(REASON_SIMULATOR_REFERENCE_MISSING)
    if not simulator_binding_lineage:
        reasons.append(REASON_SIMULATOR_LINEAGE_MISSING)
    if simulator_binding_owner and simulator_binding_owner != SIMULATOR_RUNTIME_BINDING_OWNER:
        reasons.append(REASON_SIMULATOR_OWNER_MISMATCH)
    if simulator_binding_status and simulator_binding_status != SIMULATOR_RUNTIME_BINDING_STATUS:
        reasons.append(REASON_SIMULATOR_BINDING_STALE)
    if simulator_binding_id and simulator_binding_id in {identifier for identifier in identifiers if identifier}:
        reasons.append(REASON_SIMULATOR_BINDING_DUPLICATE)
    if declaration is not None:
        expected_reference = _simulator_binding_reference(str(declaration["adapter_name"]), str(declaration["capability"]))
        if simulator_binding_id and simulator_binding_id != _simulator_binding_id(
            str(declaration["adapter_name"]), str(declaration["capability"])
        ):
            reasons.append(REASON_SIMULATOR_REFERENCE_MISMATCH)
        if simulator_binding_reference and simulator_binding_reference != expected_reference:
            reasons.append(REASON_SIMULATOR_REFERENCE_MISMATCH)
        if simulator_binding_lineage and simulator_binding_lineage != SIMULATOR_RUNTIME_BINDING_LINEAGE:
            reasons.append(REASON_SIMULATOR_LINEAGE_MISSING)
        if simulator_binding_hash and simulator_binding_hash != _simulator_binding_hash(declaration):
            reasons.append(REASON_SIMULATOR_HASH_MISMATCH)
    return sorted(set(reasons))


def validate_adapter_governance_consistency(contract: dict[str, Any] | None) -> dict[str, Any]:
    declaration = None
    if isinstance(contract, dict):
        declaration = _matching_declaration(str(contract.get("adapter_name", "")), str(contract.get("capability", "")))
    reasons = _governance_consistency_reasons(contract if isinstance(contract, dict) else {}, declaration)
    return {
        "schema": "usbay.execution.adapter_governance_consistency_validation.v1",
        "governance_consistency_status": "CONSISTENT" if not reasons else "BLOCKED",
        "authority": ADAPTER_GOVERNANCE_CONSISTENCY_AUTHORITY,
        "canonical_owner": ADAPTER_CONTRACT_OWNER,
        "reason_codes": reasons,
        "fail_closed": bool(reasons),
        "read_only": True,
    }


def _governance_reconciliation_reasons(
    contract: dict[str, Any],
    declaration: dict[str, Any] | None,
    consistency_reasons: list[str] | None = None,
) -> list[str]:
    adapter_name = str(contract.get("adapter_name", ""))
    owners = (
        str(contract.get("owner", "")),
        str(contract.get("action_scope_owner", "")),
        str(contract.get("adapter_owner", "")),
        str(contract.get("provenance_owner", "")),
        str(contract.get("registration_owner", "")),
        str(contract.get("revocation_owner", "")),
        str(contract.get("approval_owner", "")),
        str(contract.get("reconciliation_owner", "")),
    )
    references = (
        str(contract.get("attestation_reference", "")),
        str(contract.get("provenance_attestation_reference", "")),
        str(contract.get("registration_reference", "")),
        str(contract.get("revocation_reference", "")),
        str(contract.get("approval_reference", "")),
        str(contract.get("reconciliation_reference", "")),
    )
    identifiers = (
        str(contract.get("adapter_id", "")),
        str(contract.get("registration_id", "")),
        str(contract.get("revocation_id", "")),
        str(contract.get("approval_id", "")),
        str(contract.get("reconciliation_id", "")),
    )
    reconciliation_fields = (
        str(contract.get("reconciliation_id", "")),
        str(contract.get("reconciliation_status", "")),
        str(contract.get("reconciliation_owner", "")),
        str(contract.get("reconciled_at", "")),
        str(contract.get("reconciliation_reference", "")),
        str(contract.get("reconciliation_hash", "")),
    )

    reasons: list[str] = []
    if declaration is None and adapter_name:
        reasons.append(REASON_ADAPTER_RECONCILIATION_ORPHAN_AUTHORITY_RECORD)
    if not all(reconciliation_fields):
        reasons.append(REASON_ADAPTER_RECONCILIATION_MISSING)
    if not all(owners + references + identifiers):
        reasons.append(REASON_ADAPTER_RECONCILIATION_LINKAGE_MISSING)
    if any(owner != ADAPTER_CONTRACT_OWNER for owner in owners if owner):
        reasons.append(REASON_ADAPTER_RECONCILIATION_OWNERSHIP_DIVERGENCE)
    if adapter_name and any(_adapter_suffix(adapter_name) not in reference for reference in references if reference):
        reasons.append(REASON_ADAPTER_RECONCILIATION_REFERENCE_DIVERGENCE)
    if len(set(identifier for identifier in identifiers if identifier)) != len([identifier for identifier in identifiers if identifier]):
        reasons.append(REASON_ADAPTER_RECONCILIATION_DUPLICATE_RECORD)
    if contract.get("reconciliation_status") and contract.get("reconciliation_status") != ADAPTER_RECONCILIATION_STATUS:
        reasons.append(REASON_ADAPTER_RECONCILIATION_STALE_STATE)
    if contract.get("reconciled_at") and (
        contract.get("reconciled_at") != contract.get("approved_at")
        or contract.get("reconciled_at") != contract.get("provenance_registered_at")
    ):
        reasons.append(REASON_ADAPTER_RECONCILIATION_TIMESTAMP_DRIFT)
    if consistency_reasons:
        reasons.append(REASON_ADAPTER_RECONCILIATION_UNRESOLVED_CONFLICT)
    if declaration is not None:
        if contract.get("reconciliation_owner") and contract.get("reconciliation_owner") != declaration["reconciliation_owner"]:
            reasons.append(REASON_ADAPTER_RECONCILIATION_OWNERSHIP_DIVERGENCE)
        if (
            contract.get("reconciliation_reference")
            and contract.get("reconciliation_reference") != declaration["reconciliation_reference"]
        ):
            reasons.append(REASON_ADAPTER_RECONCILIATION_REFERENCE_DIVERGENCE)
        if contract.get("reconciliation_hash") and contract.get("reconciliation_hash") != _adapter_reconciliation_hash(declaration):
            reasons.append(REASON_ADAPTER_RECONCILIATION_EVIDENCE_MISMATCH)
    return sorted(set(reasons))


def validate_adapter_governance_reconciliation(contract: dict[str, Any] | None) -> dict[str, Any]:
    declaration = None
    if isinstance(contract, dict):
        declaration = _matching_declaration(str(contract.get("adapter_name", "")), str(contract.get("capability", "")))
    safe_contract = contract if isinstance(contract, dict) else {}
    consistency = validate_adapter_governance_consistency(safe_contract)
    reasons = _governance_reconciliation_reasons(safe_contract, declaration, consistency["reason_codes"])
    return {
        "schema": "usbay.execution.adapter_governance_reconciliation_validation.v1",
        "governance_reconciliation_status": "RECONCILED" if not reasons else "BLOCKED",
        "authority": ADAPTER_GOVERNANCE_RECONCILIATION_AUTHORITY,
        "canonical_owner": ADAPTER_CONTRACT_OWNER,
        "reason_codes": reasons,
        "fail_closed": bool(reasons),
        "read_only": True,
    }


def adapter_capability_map() -> dict[str, Any]:
    return {
        "schema": "usbay.execution.adapter_capability_map.v1",
        "canonical_owner": ADAPTER_CONTRACT_OWNER,
        "contract_version": ADAPTER_CONTRACT_VERSION,
        "governance_consistency_authority": ADAPTER_GOVERNANCE_CONSISTENCY_AUTHORITY,
        "governance_reconciliation_authority": ADAPTER_GOVERNANCE_RECONCILIATION_AUTHORITY,
        "adapters": [
            {
                "adapter_name": str(record["adapter_name"]),
                "capability": str(record["capability"]),
                "action_types": tuple(str(action) for action in record["action_types"]),
                "owner": str(record["owner"]),
                "action_scope_owner": str(record["action_scope_owner"]),
                "action_scope_id": _action_scope_id(str(record["adapter_name"]), str(record["capability"])),
                "action_scope_hash": _action_scope_hash(record),
                "adapter_id": str(record["adapter_id"]),
                "adapter_owner": str(record["adapter_owner"]),
                "adapter_identity_hash": _adapter_identity_hash(record),
                "attestation_reference": str(record["attestation_reference"]),
                "provenance_owner": str(record["provenance_owner"]),
                "provenance_source": str(record["provenance_source"]),
                "provenance_registered_at": str(record["provenance_registered_at"]),
                "provenance_attestation_reference": str(record["provenance_attestation_reference"]),
                "provenance_chain_hash": _adapter_provenance_chain_hash(record),
                "policy_binding_id": _policy_binding_id(str(record["adapter_name"]), str(record["capability"])),
                "policy_binding_owner": POLICY_BRAIN_BINDING_OWNER,
                "policy_binding_authority": POLICY_BRAIN_BINDING_AUTHORITY,
                "policy_binding_reference": _policy_binding_reference(
                    str(record["adapter_name"]), str(record["capability"])
                ),
                "policy_binding_lineage": POLICY_BRAIN_BINDING_LINEAGE,
                "policy_binding_status": POLICY_BRAIN_BINDING_STATUS,
                "policy_binding_hash": _policy_binding_hash(record),
                "gateway_binding_id": _gateway_binding_id(str(record["adapter_name"]), str(record["capability"])),
                "gateway_binding_owner": GATEWAY_ADAPTER_BINDING_OWNER,
                "gateway_binding_authority": GATEWAY_ADAPTER_BINDING_AUTHORITY,
                "gateway_binding_reference": _gateway_binding_reference(
                    str(record["adapter_name"]), str(record["capability"])
                ),
                "gateway_binding_lineage": GATEWAY_ADAPTER_BINDING_LINEAGE,
                "gateway_binding_status": GATEWAY_ADAPTER_BINDING_STATUS,
                "gateway_binding_hash": _gateway_binding_hash(record),
                "simulator_binding_id": _simulator_binding_id(str(record["adapter_name"]), str(record["capability"])),
                "simulator_binding_owner": SIMULATOR_RUNTIME_BINDING_OWNER,
                "simulator_binding_authority": SIMULATOR_RUNTIME_BINDING_AUTHORITY,
                "simulator_binding_reference": _simulator_binding_reference(
                    str(record["adapter_name"]), str(record["capability"])
                ),
                "simulator_binding_lineage": SIMULATOR_RUNTIME_BINDING_LINEAGE,
                "simulator_binding_status": SIMULATOR_RUNTIME_BINDING_STATUS,
                "simulator_binding_hash": _simulator_binding_hash(record),
                "registration_id": str(record["registration_id"]),
                "registration_state": str(record["registration_state"]),
                "registration_owner": str(record["registration_owner"]),
                "registration_authority": ADAPTER_REGISTRATION_AUTHORITY,
                "registration_reference": str(record["registration_reference"]),
                "revocation_id": str(record["revocation_id"]),
                "revocation_reason": str(record["revocation_reason"]),
                "revocation_owner": str(record["revocation_owner"]),
                "revocation_authority": ADAPTER_REVOCATION_AUTHORITY,
                "revoked_by": str(record["revoked_by"]),
                "revoked_at": str(record["revoked_at"]),
                "revocation_reference": str(record["revocation_reference"]),
                "approval_id": str(record["approval_id"]),
                "approval_state": str(record["approval_state"]),
                "approval_owner": str(record["approval_owner"]),
                "approval_authority": ADAPTER_APPROVAL_AUTHORITY,
                "approved_by": str(record["approved_by"]),
                "approved_at": str(record["approved_at"]),
                "approval_reference": str(record["approval_reference"]),
                "reconciliation_id": str(record["reconciliation_id"]),
                "reconciliation_status": str(record["reconciliation_status"]),
                "reconciliation_owner": str(record["reconciliation_owner"]),
                "reconciliation_authority": ADAPTER_GOVERNANCE_RECONCILIATION_AUTHORITY,
                "reconciled_at": str(record["reconciled_at"]),
                "reconciliation_reference": str(record["reconciliation_reference"]),
                "reconciliation_hash": _adapter_reconciliation_hash(record),
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
    adapter_id = str(declaration["adapter_id"]) if declaration is not None else ""
    adapter_owner = str(declaration["adapter_owner"]) if declaration is not None else ""
    adapter_identity_hash = _adapter_identity_hash(declaration) if declaration is not None else ""
    attestation_reference = str(declaration["attestation_reference"]) if declaration is not None else ""
    provenance_owner = str(declaration["provenance_owner"]) if declaration is not None else ""
    provenance_source = str(declaration["provenance_source"]) if declaration is not None else ""
    provenance_registered_at = str(declaration["provenance_registered_at"]) if declaration is not None else ""
    provenance_attestation_reference = (
        str(declaration["provenance_attestation_reference"]) if declaration is not None else ""
    )
    provenance_chain_hash = _adapter_provenance_chain_hash(declaration) if declaration is not None else ""
    policy_binding_id = _policy_binding_id(str(adapter_name), str(capability)) if declaration is not None else ""
    policy_binding_owner = POLICY_BRAIN_BINDING_OWNER if declaration is not None else ""
    policy_binding_reference = _policy_binding_reference(str(adapter_name), str(capability)) if declaration is not None else ""
    policy_binding_lineage = POLICY_BRAIN_BINDING_LINEAGE if declaration is not None else ""
    policy_binding_status = POLICY_BRAIN_BINDING_STATUS if declaration is not None else ""
    policy_binding_hash = _policy_binding_hash(declaration) if declaration is not None else ""
    gateway_binding_id = _gateway_binding_id(str(adapter_name), str(capability)) if declaration is not None else ""
    gateway_binding_owner = GATEWAY_ADAPTER_BINDING_OWNER if declaration is not None else ""
    gateway_binding_reference = _gateway_binding_reference(str(adapter_name), str(capability)) if declaration is not None else ""
    gateway_binding_lineage = GATEWAY_ADAPTER_BINDING_LINEAGE if declaration is not None else ""
    gateway_binding_status = GATEWAY_ADAPTER_BINDING_STATUS if declaration is not None else ""
    gateway_binding_hash = _gateway_binding_hash(declaration) if declaration is not None else ""
    simulator_binding_id = _simulator_binding_id(str(adapter_name), str(capability)) if declaration is not None else ""
    simulator_binding_owner = SIMULATOR_RUNTIME_BINDING_OWNER if declaration is not None else ""
    simulator_binding_reference = _simulator_binding_reference(str(adapter_name), str(capability)) if declaration is not None else ""
    simulator_binding_lineage = SIMULATOR_RUNTIME_BINDING_LINEAGE if declaration is not None else ""
    simulator_binding_status = SIMULATOR_RUNTIME_BINDING_STATUS if declaration is not None else ""
    simulator_binding_hash = _simulator_binding_hash(declaration) if declaration is not None else ""
    registration_id = str(declaration["registration_id"]) if declaration is not None else ""
    registration_state = str(declaration["registration_state"]) if declaration is not None else ""
    registration_owner = str(declaration["registration_owner"]) if declaration is not None else ""
    registration_reference = str(declaration["registration_reference"]) if declaration is not None else ""
    revocation_id = str(declaration["revocation_id"]) if declaration is not None else ""
    revocation_reason = str(declaration["revocation_reason"]) if declaration is not None else ""
    revocation_owner = str(declaration["revocation_owner"]) if declaration is not None else ""
    revoked_by = str(declaration["revoked_by"]) if declaration is not None else ""
    revoked_at = str(declaration["revoked_at"]) if declaration is not None else ""
    revocation_reference = str(declaration["revocation_reference"]) if declaration is not None else ""
    approval_id = str(declaration["approval_id"]) if declaration is not None else ""
    approval_state = str(declaration["approval_state"]) if declaration is not None else ""
    approval_owner = str(declaration["approval_owner"]) if declaration is not None else ""
    approved_by = str(declaration["approved_by"]) if declaration is not None else ""
    approved_at = str(declaration["approved_at"]) if declaration is not None else ""
    approval_reference = str(declaration["approval_reference"]) if declaration is not None else ""
    reconciliation_id = str(declaration["reconciliation_id"]) if declaration is not None else ""
    reconciliation_status = str(declaration["reconciliation_status"]) if declaration is not None else ""
    reconciliation_owner = str(declaration["reconciliation_owner"]) if declaration is not None else ""
    reconciled_at = str(declaration["reconciled_at"]) if declaration is not None else ""
    reconciliation_reference = str(declaration["reconciliation_reference"]) if declaration is not None else ""
    reconciliation_hash = _adapter_reconciliation_hash(declaration) if declaration is not None else ""
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
        "adapter_id": adapter_id,
        "adapter_owner": adapter_owner,
        "adapter_identity_hash": adapter_identity_hash,
        "attestation_reference": attestation_reference,
        "provenance_owner": provenance_owner,
        "provenance_source": provenance_source,
        "provenance_registered_at": provenance_registered_at,
        "provenance_attestation_reference": provenance_attestation_reference,
        "provenance_chain_hash": provenance_chain_hash,
        "policy_binding_id": policy_binding_id,
        "policy_binding_owner": policy_binding_owner,
        "policy_binding_reference": policy_binding_reference,
        "policy_binding_lineage": policy_binding_lineage,
        "policy_binding_status": policy_binding_status,
        "policy_binding_hash": policy_binding_hash,
        "gateway_binding_id": gateway_binding_id,
        "gateway_binding_owner": gateway_binding_owner,
        "gateway_binding_reference": gateway_binding_reference,
        "gateway_binding_lineage": gateway_binding_lineage,
        "gateway_binding_status": gateway_binding_status,
        "gateway_binding_hash": gateway_binding_hash,
        "simulator_binding_id": simulator_binding_id,
        "simulator_binding_owner": simulator_binding_owner,
        "simulator_binding_reference": simulator_binding_reference,
        "simulator_binding_lineage": simulator_binding_lineage,
        "simulator_binding_status": simulator_binding_status,
        "simulator_binding_hash": simulator_binding_hash,
        "registration_id": registration_id,
        "registration_state": registration_state,
        "registration_owner": registration_owner,
        "registration_reference": registration_reference,
        "revocation_id": revocation_id,
        "revocation_reason": revocation_reason,
        "revocation_owner": revocation_owner,
        "revoked_by": revoked_by,
        "revoked_at": revoked_at,
        "revocation_reference": revocation_reference,
        "approval_id": approval_id,
        "approval_state": approval_state,
        "approval_owner": approval_owner,
        "approved_by": approved_by,
        "approved_at": approved_at,
        "approval_reference": approval_reference,
        "reconciliation_id": reconciliation_id,
        "reconciliation_status": reconciliation_status,
        "reconciliation_owner": reconciliation_owner,
        "reconciled_at": reconciled_at,
        "reconciliation_reference": reconciliation_reference,
        "reconciliation_hash": reconciliation_hash,
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
        "adapter_id",
        "adapter_owner",
        "adapter_identity_hash",
        "attestation_reference",
        "provenance_owner",
        "provenance_source",
        "provenance_registered_at",
        "provenance_attestation_reference",
        "provenance_chain_hash",
        "policy_binding_id",
        "policy_binding_owner",
        "policy_binding_reference",
        "policy_binding_lineage",
        "policy_binding_status",
        "policy_binding_hash",
        "gateway_binding_id",
        "gateway_binding_owner",
        "gateway_binding_reference",
        "gateway_binding_lineage",
        "gateway_binding_status",
        "gateway_binding_hash",
        "simulator_binding_id",
        "simulator_binding_owner",
        "simulator_binding_reference",
        "simulator_binding_lineage",
        "simulator_binding_status",
        "simulator_binding_hash",
        "registration_id",
        "registration_state",
        "registration_owner",
        "registration_reference",
        "revocation_id",
        "revocation_reason",
        "revocation_owner",
        "revoked_by",
        "revoked_at",
        "revocation_reference",
        "approval_id",
        "approval_state",
        "approval_owner",
        "approved_by",
        "approved_at",
        "approval_reference",
        "reconciliation_id",
        "reconciliation_status",
        "reconciliation_owner",
        "reconciled_at",
        "reconciliation_reference",
        "reconciliation_hash",
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
    adapter_id = str(contract.get("adapter_id", ""))
    adapter_owner = str(contract.get("adapter_owner", ""))
    adapter_identity_hash = str(contract.get("adapter_identity_hash", ""))
    attestation_reference = str(contract.get("attestation_reference", ""))
    provenance_owner = str(contract.get("provenance_owner", ""))
    provenance_source = str(contract.get("provenance_source", ""))
    provenance_registered_at = str(contract.get("provenance_registered_at", ""))
    provenance_attestation_reference = str(contract.get("provenance_attestation_reference", ""))
    provenance_chain_hash = str(contract.get("provenance_chain_hash", ""))
    policy_binding_id = str(contract.get("policy_binding_id", ""))
    policy_binding_owner = str(contract.get("policy_binding_owner", ""))
    policy_binding_reference = str(contract.get("policy_binding_reference", ""))
    policy_binding_lineage = str(contract.get("policy_binding_lineage", ""))
    policy_binding_status = str(contract.get("policy_binding_status", ""))
    policy_binding_hash = str(contract.get("policy_binding_hash", ""))
    gateway_binding_id = str(contract.get("gateway_binding_id", ""))
    gateway_binding_owner = str(contract.get("gateway_binding_owner", ""))
    gateway_binding_reference = str(contract.get("gateway_binding_reference", ""))
    gateway_binding_lineage = str(contract.get("gateway_binding_lineage", ""))
    gateway_binding_status = str(contract.get("gateway_binding_status", ""))
    gateway_binding_hash = str(contract.get("gateway_binding_hash", ""))
    simulator_binding_id = str(contract.get("simulator_binding_id", ""))
    simulator_binding_owner = str(contract.get("simulator_binding_owner", ""))
    simulator_binding_reference = str(contract.get("simulator_binding_reference", ""))
    simulator_binding_lineage = str(contract.get("simulator_binding_lineage", ""))
    simulator_binding_status = str(contract.get("simulator_binding_status", ""))
    simulator_binding_hash = str(contract.get("simulator_binding_hash", ""))
    registration_id = str(contract.get("registration_id", ""))
    registration_state = str(contract.get("registration_state", ""))
    registration_owner = str(contract.get("registration_owner", ""))
    registration_reference = str(contract.get("registration_reference", ""))
    revocation_id = str(contract.get("revocation_id", ""))
    revocation_reason = str(contract.get("revocation_reason", ""))
    revocation_owner = str(contract.get("revocation_owner", ""))
    revoked_by = str(contract.get("revoked_by", ""))
    revoked_at = str(contract.get("revoked_at", ""))
    revocation_reference = str(contract.get("revocation_reference", ""))
    approval_id = str(contract.get("approval_id", ""))
    approval_state = str(contract.get("approval_state", ""))
    approval_owner = str(contract.get("approval_owner", ""))
    approved_by = str(contract.get("approved_by", ""))
    approved_at = str(contract.get("approved_at", ""))
    approval_reference = str(contract.get("approval_reference", ""))
    reconciliation_id = str(contract.get("reconciliation_id", ""))
    reconciliation_status = str(contract.get("reconciliation_status", ""))
    reconciliation_owner = str(contract.get("reconciliation_owner", ""))
    reconciled_at = str(contract.get("reconciled_at", ""))
    reconciliation_reference = str(contract.get("reconciliation_reference", ""))
    reconciliation_hash = str(contract.get("reconciliation_hash", ""))
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
    if not adapter_id:
        reasons.append(REASON_ADAPTER_ID_MISSING)
    elif declaration is not None and adapter_id != declaration["adapter_id"]:
        reasons.append(REASON_ADAPTER_ID_MISMATCH)
    if not adapter_owner:
        reasons.append(REASON_ADAPTER_OWNER_MISSING)
    elif declaration is not None and adapter_owner != declaration["adapter_owner"]:
        reasons.append(REASON_ADAPTER_OWNER_MISMATCH)
    if not adapter_identity_hash:
        reasons.append(REASON_ADAPTER_IDENTITY_HASH_MISSING)
    elif declaration is not None and adapter_identity_hash != _adapter_identity_hash(declaration):
        reasons.append(REASON_ADAPTER_IDENTITY_HASH_MISMATCH)
    if not attestation_reference:
        reasons.append(REASON_ADAPTER_ATTESTATION_REFERENCE_MISSING)
    elif declaration is not None and attestation_reference != declaration["attestation_reference"]:
        reasons.append(REASON_ADAPTER_ATTESTATION_REFERENCE_MISMATCH)
    provenance_fields_missing = not all(
        (
            provenance_owner,
            provenance_source,
            provenance_registered_at,
            provenance_attestation_reference,
            provenance_chain_hash,
        )
    )
    if provenance_fields_missing:
        reasons.append(REASON_ADAPTER_PROVENANCE_MISSING)
    elif declaration is not None:
        if provenance_owner != declaration["provenance_owner"]:
            reasons.append(REASON_ADAPTER_PROVENANCE_OWNER_MISMATCH)
        if provenance_source != declaration["provenance_source"]:
            reasons.append(REASON_ADAPTER_PROVENANCE_SOURCE_MISMATCH)
        if provenance_registered_at != declaration["provenance_registered_at"]:
            reasons.append(REASON_ADAPTER_PROVENANCE_REGISTRATION_MISMATCH)
        if provenance_attestation_reference != declaration["provenance_attestation_reference"]:
            reasons.append(REASON_ADAPTER_PROVENANCE_ATTESTATION_MISMATCH)
        if provenance_chain_hash != _adapter_provenance_chain_hash(declaration):
            reasons.append(REASON_ADAPTER_PROVENANCE_CHAIN_HASH_MISMATCH)
    reasons.extend(_policy_binding_reasons(contract, declaration))
    reasons.extend(_gateway_binding_reasons(contract, declaration))
    reasons.extend(_simulator_binding_reasons(contract, declaration))
    registration_missing = not all((registration_id, registration_state, registration_owner, registration_reference))
    if registration_missing:
        reasons.append(REASON_ADAPTER_REGISTRATION_MISSING)
    else:
        if registration_state not in ADAPTER_REGISTRATION_STATES:
            reasons.append(REASON_ADAPTER_REGISTRATION_STATE_INVALID)
        elif registration_state == "REVOKED":
            reasons.append(REASON_ADAPTER_REGISTRATION_REVOKED)
        elif registration_state == "SUSPENDED":
            reasons.append(REASON_ADAPTER_REGISTRATION_SUSPENDED)
        elif registration_state != ADAPTER_ALLOWED_REGISTRATION_STATE:
            reasons.append(REASON_ADAPTER_REGISTRATION_NOT_ACTIVE)
    if declaration is not None and not registration_missing:
        if registration_id != declaration["registration_id"]:
            reasons.append(REASON_ADAPTER_REGISTRATION_REFERENCE_MISMATCH)
        if registration_owner != declaration["registration_owner"]:
            reasons.append(REASON_ADAPTER_REGISTRATION_OWNER_MISMATCH)
        if registration_reference != declaration["registration_reference"]:
            reasons.append(REASON_ADAPTER_REGISTRATION_REFERENCE_MISMATCH)
    revocation_missing = not all((revocation_id, revocation_reason, revocation_owner, revoked_by, revoked_at, revocation_reference))
    if revocation_missing:
        reasons.append(REASON_ADAPTER_REVOCATION_MISSING)
    else:
        if revocation_reason not in ADAPTER_REVOCATION_REASONS:
            reasons.append(REASON_ADAPTER_REVOCATION_REASON_INVALID)
        if revoked_at != ADAPTER_NOT_REVOKED_TIMESTAMP and not (revoked_at.endswith("Z") and "T" in revoked_at):
            reasons.append(REASON_ADAPTER_REVOCATION_TIMESTAMP_INVALID)
        if (
            revocation_reason != ADAPTER_NOT_REVOKED_REASON
            or revoked_by != ADAPTER_NOT_REVOKED_ACTOR
            or revoked_at != ADAPTER_NOT_REVOKED_TIMESTAMP
        ):
            reasons.append(REASON_ADAPTER_REVOKED)
    if declaration is not None and not revocation_missing:
        if revocation_id != declaration["revocation_id"]:
            reasons.append(REASON_ADAPTER_REVOCATION_REFERENCE_MISMATCH)
        if revocation_owner != declaration["revocation_owner"]:
            reasons.append(REASON_ADAPTER_REVOCATION_OWNER_MISMATCH)
        if revocation_reference != declaration["revocation_reference"]:
            reasons.append(REASON_ADAPTER_REVOCATION_REFERENCE_MISMATCH)
    approval_missing = not all((approval_id, approval_state, approval_owner, approved_by, approved_at, approval_reference))
    if approval_missing:
        reasons.append(REASON_ADAPTER_APPROVAL_MISSING)
    else:
        if approval_state not in ADAPTER_APPROVAL_STATES:
            reasons.append(REASON_ADAPTER_APPROVAL_STATE_INVALID)
        elif approval_state == "PENDING":
            reasons.append(REASON_ADAPTER_APPROVAL_PENDING)
        elif approval_state == "REJECTED":
            reasons.append(REASON_ADAPTER_APPROVAL_REJECTED)
        elif approval_state == "EXPIRED":
            reasons.append(REASON_ADAPTER_APPROVAL_EXPIRED)
        elif approval_state == "REVOKED":
            reasons.append(REASON_ADAPTER_APPROVAL_REVOKED)
    if declaration is not None and not approval_missing:
        if approval_id != declaration["approval_id"]:
            reasons.append(REASON_ADAPTER_APPROVAL_REFERENCE_MISMATCH)
        if approval_owner != declaration["approval_owner"]:
            reasons.append(REASON_ADAPTER_APPROVAL_OWNER_MISMATCH)
        if approval_reference != declaration["approval_reference"]:
            reasons.append(REASON_ADAPTER_APPROVAL_REFERENCE_MISMATCH)
    reconciliation_missing = not all(
        (
            reconciliation_id,
            reconciliation_status,
            reconciliation_owner,
            reconciled_at,
            reconciliation_reference,
            reconciliation_hash,
        )
    )
    if reconciliation_missing:
        reasons.append(REASON_ADAPTER_RECONCILIATION_MISSING)
    consistency = validate_adapter_governance_consistency(contract)
    reasons.extend(consistency["reason_codes"])
    reconciliation = validate_adapter_governance_reconciliation(contract)
    reasons.extend(reconciliation["reason_codes"])
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
        "adapter_id": str(safe_contract.get("adapter_id", "")),
        "adapter_owner": str(safe_contract.get("adapter_owner", "")),
        "adapter_identity_hash": str(safe_contract.get("adapter_identity_hash", "")),
        "attestation_reference": str(safe_contract.get("attestation_reference", "")),
        "provenance_owner": str(safe_contract.get("provenance_owner", "")),
        "provenance_source": str(safe_contract.get("provenance_source", "")),
        "provenance_registered_at": str(safe_contract.get("provenance_registered_at", "")),
        "provenance_attestation_reference": str(safe_contract.get("provenance_attestation_reference", "")),
        "provenance_chain_hash": str(safe_contract.get("provenance_chain_hash", "")),
        "policy_binding_id": str(safe_contract.get("policy_binding_id", "")),
        "policy_binding_owner": str(safe_contract.get("policy_binding_owner", "")),
        "policy_binding_authority": POLICY_BRAIN_BINDING_AUTHORITY,
        "policy_binding_reference": str(safe_contract.get("policy_binding_reference", "")),
        "policy_binding_lineage": str(safe_contract.get("policy_binding_lineage", "")),
        "policy_binding_status": POLICY_BRAIN_BINDING_STATUS
        if not any(reason.startswith("POLICY_") for reason in clean_reasons)
        else "BLOCKED",
        "policy_binding_hash": str(safe_contract.get("policy_binding_hash", "")),
        "gateway_binding_id": str(safe_contract.get("gateway_binding_id", "")),
        "gateway_binding_owner": str(safe_contract.get("gateway_binding_owner", "")),
        "gateway_binding_authority": GATEWAY_ADAPTER_BINDING_AUTHORITY,
        "gateway_binding_reference": str(safe_contract.get("gateway_binding_reference", "")),
        "gateway_binding_lineage": str(safe_contract.get("gateway_binding_lineage", "")),
        "gateway_binding_status": GATEWAY_ADAPTER_BINDING_STATUS
        if not any(reason.startswith("GATEWAY_") for reason in clean_reasons)
        else "BLOCKED",
        "gateway_binding_hash": str(safe_contract.get("gateway_binding_hash", "")),
        "simulator_binding_id": str(safe_contract.get("simulator_binding_id", "")),
        "simulator_binding_owner": str(safe_contract.get("simulator_binding_owner", "")),
        "simulator_binding_authority": SIMULATOR_RUNTIME_BINDING_AUTHORITY,
        "simulator_binding_reference": str(safe_contract.get("simulator_binding_reference", "")),
        "simulator_binding_lineage": str(safe_contract.get("simulator_binding_lineage", "")),
        "simulator_binding_status": SIMULATOR_RUNTIME_BINDING_STATUS
        if not any(reason.startswith("SIMULATOR_") for reason in clean_reasons)
        else "BLOCKED",
        "simulator_binding_hash": str(safe_contract.get("simulator_binding_hash", "")),
        "registration_id": str(safe_contract.get("registration_id", "")),
        "registration_state": str(safe_contract.get("registration_state", "")),
        "registration_owner": str(safe_contract.get("registration_owner", "")),
        "registration_reference": str(safe_contract.get("registration_reference", "")),
        "revocation_id": str(safe_contract.get("revocation_id", "")),
        "revocation_reason": str(safe_contract.get("revocation_reason", "")),
        "revocation_owner": str(safe_contract.get("revocation_owner", "")),
        "revoked_by": str(safe_contract.get("revoked_by", "")),
        "revoked_at": str(safe_contract.get("revoked_at", "")),
        "revocation_reference": str(safe_contract.get("revocation_reference", "")),
        "approval_id": str(safe_contract.get("approval_id", "")),
        "approval_state": str(safe_contract.get("approval_state", "")),
        "approval_owner": str(safe_contract.get("approval_owner", "")),
        "approved_by": str(safe_contract.get("approved_by", "")),
        "approved_at": str(safe_contract.get("approved_at", "")),
        "approval_reference": str(safe_contract.get("approval_reference", "")),
        "reconciliation_id": str(safe_contract.get("reconciliation_id", "")),
        "reconciliation_status": str(safe_contract.get("reconciliation_status", "")),
        "reconciliation_owner": str(safe_contract.get("reconciliation_owner", "")),
        "reconciled_at": str(safe_contract.get("reconciled_at", "")),
        "reconciliation_reference": str(safe_contract.get("reconciliation_reference", "")),
        "reconciliation_hash": str(safe_contract.get("reconciliation_hash", "")),
        "governance_gate_reference": str(safe_contract.get("governance_gate_reference", "")),
        "required_gate_proof": True,
        "reason_codes": clean_reasons,
        "governance_consistency_status": "CONSISTENT"
        if not any(reason.startswith("ADAPTER_CONSISTENCY_") for reason in clean_reasons)
        else "BLOCKED",
        "governance_consistency_authority": ADAPTER_GOVERNANCE_CONSISTENCY_AUTHORITY,
        "governance_reconciliation_status": "RECONCILED"
        if not any(reason.startswith("ADAPTER_RECONCILIATION_") for reason in clean_reasons)
        else "BLOCKED",
        "governance_reconciliation_authority": ADAPTER_GOVERNANCE_RECONCILIATION_AUTHORITY,
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
