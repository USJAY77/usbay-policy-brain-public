from __future__ import annotations

from typing import Any


REASON_CODE_REGISTRY_SCHEMA = "usbay.governance.reason_code_registry.v1"

REASON_CODE_NAMESPACES: dict[str, tuple[str, ...]] = {
    "api": ("UNKNOWN_API", "UNREGISTERED_API", "API_GOVERNANCE_BYPASS"),
    "audit": ("AUDIT_REGISTRY_EMPTY", "AUDIT_REGISTRY_TAMPERED", "AUDIT_LINKAGE_MISSING"),
    "common": (
        "MISSING_AUDIT_LINKAGE",
        "MISSING_EVIDENCE_LINKAGE",
        "MISSING_LINEAGE",
        "MISSING_POLICY_BINDING",
    ),
    "commercial": (
        "UNKNOWN_COMMERCIAL_RECORD",
        "UNREGISTERED_COMMERCIAL_RECORD",
        "MISSING_HUMAN_APPROVAL",
        "CROSS_TENANT_COMMERCIAL_ACTION",
        "COMMERCIAL_GOVERNANCE_BYPASS",
    ),
    "computer_use": ("UNKNOWN_AGENT", "UNKNOWN_ACTION", "COMPUTER_USE_GOVERNANCE_BYPASS"),
    "connector": ("UNKNOWN_CONNECTOR", "UNREGISTERED_CONNECTOR", "CONNECTOR_GOVERNANCE_BYPASS"),
    "customer": ("UNKNOWN_CUSTOMER", "MISSING_CUSTOMER_APPROVAL", "CUSTOMER_GOVERNANCE_BYPASS"),
    "document": ("UNKNOWN_DOCUMENT", "MISSING_DOCUMENT_LINEAGE", "DOCUMENT_GOVERNANCE_BYPASS"),
    "evidence": ("EVIDENCE_MISSING", "EVIDENCE_MALFORMED", "EVIDENCE_STALE"),
    "execution": ("EXECUTION_DISABLED", "EXECUTION_BLOCKED", "EXECUTION_FORBIDDEN"),
    "hydra": ("HYDRA_CONSENSUS_MISSING", "HYDRA_QUORUM_FAILED", "HYDRA_GOVERNANCE_BYPASS"),
    "license": ("MISSING_LICENSE", "LICENSE_EXPIRED", "LICENSE_GOVERNANCE_BYPASS"),
    "lifecycle": (
        "UNKNOWN_CHANGE",
        "UNREGISTERED_CHANGE",
        "CROSS_TENANT_CHANGE",
        "LIFECYCLE_GOVERNANCE_BYPASS",
    ),
    "malware": ("UNKNOWN_ARTIFACT", "MALWARE_SCAN_MISSING", "MALWARE_GOVERNANCE_BYPASS"),
    "model": (
        "UNKNOWN_MODEL",
        "UNREGISTERED_MODEL",
        "CROSS_TENANT_MODEL",
        "MODEL_GOVERNANCE_BYPASS",
    ),
    "operator": ("OPERATOR_REVIEW_MISSING", "OPERATOR_APPROVAL_MISSING", "OPERATOR_GOVERNANCE_BYPASS"),
    "policy": ("POLICY_REGISTRY_EMPTY", "POLICY_GOVERNANCE_BYPASS"),
    "production": ("PRODUCTION_READINESS_MISSING", "RELEASE_APPROVAL_MISSING", "PRODUCTION_GOVERNANCE_BYPASS"),
    "prompt": (
        "UNKNOWN_PROMPT",
        "UNREGISTERED_PROMPT",
        "CROSS_TENANT_PROMPT",
        "PROMPT_GOVERNANCE_BYPASS",
    ),
    "release": ("RELEASE_GATE_BLOCKED", "RELEASE_MANIFEST_MISSING", "RELEASE_GOVERNANCE_BYPASS"),
    "sovereign": ("SOVEREIGN_DEPLOYMENT_BLOCKED", "NODE_GOVERNANCE_MISSING", "SOVEREIGN_GOVERNANCE_BYPASS"),
    "tenant": ("UNKNOWN_TENANT", "CROSS_TENANT_ACCESS", "TENANT_GOVERNANCE_BYPASS"),
    "vision": ("VISION_OBSERVATION_MISSING", "VISION_ACTION_BLOCKED", "VISION_GOVERNANCE_BYPASS"),
    "work": ("WORK_ITEM_MISSING", "WORK_OWNER_MISSING", "WORK_GOVERNANCE_BYPASS"),
}


def list_reason_code_namespaces() -> dict[str, tuple[str, ...]]:
    return {namespace: tuple(codes) for namespace, codes in REASON_CODE_NAMESPACES.items()}


def validate_reason_code_registry() -> dict[str, Any]:
    all_codes = [code for codes in REASON_CODE_NAMESPACES.values() for code in codes]
    duplicate_codes = sorted({code for code in all_codes if all_codes.count(code) > 1})
    empty_namespaces = sorted(namespace for namespace, codes in REASON_CODE_NAMESPACES.items() if not codes)
    return {
        "schema": REASON_CODE_REGISTRY_SCHEMA,
        "valid": not duplicate_codes and not empty_namespaces,
        "status": "VALID" if not duplicate_codes and not empty_namespaces else "BLOCKED",
        "namespace_count": len(REASON_CODE_NAMESPACES),
        "reason_code_count": len(all_codes),
        "duplicate_reason_codes": duplicate_codes,
        "empty_namespaces": empty_namespaces,
        "read_only": True,
    }
