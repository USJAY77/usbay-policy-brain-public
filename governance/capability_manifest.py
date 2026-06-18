from __future__ import annotations

from typing import Any

from governance.control_registry import control_ids
from governance.reason_code_registry import REASON_CODE_NAMESPACES


CAPABILITY_MANIFEST_SCHEMA = "usbay.governance.capability_manifest.v1"

DEFAULT_REQUIRED_CONTROLS = (
    "audit_linkage",
    "evidence_linkage",
    "lineage_validation",
    "tenant_isolation",
    "workspace_isolation",
    "fail_closed",
    "read_only_dashboard",
)

CAPABILITY_MANIFEST: tuple[dict[str, Any], ...] = (
    {
        "capability_id": "execution_framework",
        "display_name": "Governed Execution Framework",
        "modules": ("governance.execution_governance", "governance.execution_contracts"),
        "controls": DEFAULT_REQUIRED_CONTROLS + ("human_approval", "execution_forbidden", "deployment_forbidden"),
        "dashboard_states": ("execution_engine_status", "adapter_status", "latest_execution_decision", "execution_reason_codes"),
        "reason_namespace": "execution",
    },
    {
        "capability_id": "vision_agent_control",
        "display_name": "Governed Vision Agent Control",
        "modules": ("governance.vision_governance", "governance.vision_agent_contracts"),
        "controls": DEFAULT_REQUIRED_CONTROLS + ("human_approval", "execution_forbidden"),
        "dashboard_states": ("latest_observation_status", "latest_action_proposal_status", "vision_reason_codes"),
        "reason_namespace": "vision",
    },
    {
        "capability_id": "operator_review_queue",
        "display_name": "Governed Operator Review Queue",
        "modules": ("governance.operator_queue", "governance.operator_governance"),
        "controls": DEFAULT_REQUIRED_CONTROLS + ("human_approval",),
        "dashboard_states": ("review_state", "decision", "operator_reason_codes"),
        "reason_namespace": "operator",
    },
    {
        "capability_id": "audit_registry",
        "display_name": "Cryptographic Governance Registry",
        "modules": ("governance.audit_registry", "governance.audit_registry_contracts"),
        "controls": DEFAULT_REQUIRED_CONTROLS,
        "dashboard_states": ("audit_registry_status", "audit_registry_tamper_status", "audit_registry_reason_codes"),
        "reason_namespace": "audit",
    },
    {
        "capability_id": "policy_registry",
        "display_name": "Governed Policy Lifecycle Registry",
        "modules": ("governance.policy_registry", "governance.policy_registry_contracts"),
        "controls": DEFAULT_REQUIRED_CONTROLS + ("policy_binding",),
        "dashboard_states": ("policy_registry_status", "promotion_status", "policy_reason_codes"),
        "reason_namespace": "policy",
    },
    {
        "capability_id": "release_gate",
        "display_name": "Governed Release Control",
        "modules": ("governance.release_gate", "governance.release_gate_contracts"),
        "controls": DEFAULT_REQUIRED_CONTROLS + ("human_approval", "deployment_forbidden"),
        "dashboard_states": ("release_gate_status", "release_readiness_status", "release_reason_codes"),
        "reason_namespace": "release",
    },
    {
        "capability_id": "tenant_boundary",
        "display_name": "Governed Tenant Isolation",
        "modules": ("governance.tenant_boundary", "governance.tenant_boundary_contracts"),
        "controls": DEFAULT_REQUIRED_CONTROLS,
        "dashboard_states": ("tenant_boundary_status", "cross_tenant_access_status", "tenant_boundary_reason_codes"),
        "reason_namespace": "tenant",
    },
    {
        "capability_id": "document_governance",
        "display_name": "Governed Document Lifecycle",
        "modules": ("governance.document_registry", "governance.document_contracts"),
        "controls": DEFAULT_REQUIRED_CONTROLS + ("human_approval",),
        "dashboard_states": ("document_registry_status", "document_lineage_status", "document_reason_codes"),
        "reason_namespace": "document",
    },
    {
        "capability_id": "production_readiness",
        "display_name": "Governed Production Readiness",
        "modules": ("governance.production_readiness", "governance.production_readiness_contracts"),
        "controls": DEFAULT_REQUIRED_CONTROLS + ("human_approval", "deployment_forbidden"),
        "dashboard_states": ("production_readiness_status", "production_release_readiness_status", "production_reason_codes"),
        "reason_namespace": "production",
    },
    {
        "capability_id": "connector_security",
        "display_name": "Governed Connector Layer",
        "modules": ("governance.connector_registry", "governance.connector_contracts"),
        "controls": DEFAULT_REQUIRED_CONTROLS + ("human_approval", "connector_write_forbidden", "auto_approval_forbidden"),
        "dashboard_states": ("connector_status", "connector_registry_status", "connector_reason_codes"),
        "reason_namespace": "connector",
    },
    {
        "capability_id": "api_security",
        "display_name": "Governed API Security",
        "modules": ("governance.api_security_registry", "governance.api_security_contracts"),
        "controls": DEFAULT_REQUIRED_CONTROLS + ("execution_forbidden", "deployment_forbidden", "connector_write_forbidden"),
        "dashboard_states": ("api_security_status", "api_inventory_status", "api_reason_codes"),
        "reason_namespace": "api",
    },
    {
        "capability_id": "computer_use",
        "display_name": "Governed Computer Use",
        "modules": ("governance.computer_use_registry", "governance.computer_use_contracts"),
        "controls": DEFAULT_REQUIRED_CONTROLS + ("human_approval", "execution_forbidden", "connector_write_forbidden"),
        "dashboard_states": ("computer_use_status", "operator_status", "computer_use_reason_codes"),
        "reason_namespace": "computer_use",
    },
    {
        "capability_id": "model_governance",
        "display_name": "Governed Model Layer",
        "modules": ("governance.model_registry", "governance.model_contracts"),
        "controls": DEFAULT_REQUIRED_CONTROLS + ("human_approval", "policy_binding", "registration", "execution_forbidden"),
        "dashboard_states": ("model_status", "model_registry_status", "model_reason_codes"),
        "reason_namespace": "model",
    },
    {
        "capability_id": "prompt_governance",
        "display_name": "Governed Prompt Layer",
        "modules": ("governance.prompt_registry", "governance.prompt_contracts"),
        "controls": DEFAULT_REQUIRED_CONTROLS + ("human_approval", "policy_binding", "registration", "execution_forbidden"),
        "dashboard_states": ("prompt_status", "prompt_registry_status", "prompt_reason_codes"),
        "reason_namespace": "prompt",
    },
    {
        "capability_id": "lifecycle_governance",
        "display_name": "Governed Operational Lifecycle",
        "modules": ("governance.lifecycle_registry", "governance.lifecycle_contracts"),
        "controls": DEFAULT_REQUIRED_CONTROLS + ("human_approval", "policy_binding", "registration", "deployment_forbidden", "auto_remediation_forbidden", "auto_approval_forbidden"),
        "dashboard_states": ("lifecycle_status", "change_status", "lifecycle_reason_codes"),
        "reason_namespace": "lifecycle",
    },
    {
        "capability_id": "commercial_governance",
        "display_name": "Governed Commercial Layer",
        "modules": ("governance.commercial_registry", "governance.commercial_contracts"),
        "controls": DEFAULT_REQUIRED_CONTROLS + ("human_approval", "policy_binding", "registration", "connector_write_forbidden", "auto_remediation_forbidden", "auto_approval_forbidden"),
        "dashboard_states": ("commercial_status", "customer_commercial_status", "commercial_reason_codes"),
        "reason_namespace": "commercial",
    },
)


def list_capabilities() -> list[dict[str, Any]]:
    return [dict(capability) for capability in CAPABILITY_MANIFEST]


def capability_ids() -> tuple[str, ...]:
    return tuple(str(capability["capability_id"]) for capability in CAPABILITY_MANIFEST)


def validate_capability_manifest() -> dict[str, Any]:
    ids = capability_ids()
    duplicate_ids = sorted({capability_id for capability_id in ids if ids.count(capability_id) > 1})
    known_controls = set(control_ids())
    known_namespaces = set(REASON_CODE_NAMESPACES)
    unknown_controls = sorted(
        {
            str(control)
            for capability in CAPABILITY_MANIFEST
            for control in capability.get("controls", ())
            if control not in known_controls
        }
    )
    unknown_namespaces = sorted(
        str(capability.get("reason_namespace", ""))
        for capability in CAPABILITY_MANIFEST
        if capability.get("reason_namespace") not in known_namespaces
    )
    missing_dashboard = sorted(
        str(capability.get("capability_id", ""))
        for capability in CAPABILITY_MANIFEST
        if not capability.get("dashboard_states")
    )
    valid = not duplicate_ids and not unknown_controls and not unknown_namespaces and not missing_dashboard
    return {
        "schema": CAPABILITY_MANIFEST_SCHEMA,
        "valid": valid,
        "status": "VALID" if valid else "BLOCKED",
        "capability_count": len(CAPABILITY_MANIFEST),
        "duplicate_capability_ids": duplicate_ids,
        "unknown_controls": unknown_controls,
        "unknown_reason_namespaces": unknown_namespaces,
        "missing_dashboard_states": missing_dashboard,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
    }
