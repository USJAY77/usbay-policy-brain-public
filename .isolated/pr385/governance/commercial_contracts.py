from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from governance.execution_contracts import sha256_json


COMMERCIAL_GOVERNANCE_SCHEMA = "usbay.commercial.governance.v1"
COMMERCIAL_GOVERNANCE_POLICY_VERSION = "usbay.pb-commercial-governance.governed-commercial.v1"
COMMERCIAL_REASON_CODES = frozenset(
    {
        "UNKNOWN_COMMERCIAL_RECORD",
        "UNREGISTERED_COMMERCIAL_RECORD",
        "MISSING_CUSTOMER_COMMERCIAL_RECORD",
        "MISSING_CONTRACT_RECORD",
        "MISSING_SUBSCRIPTION_RECORD",
        "MISSING_BILLING_RECORD",
        "MISSING_INVOICE_RECORD",
        "MISSING_PRICING_RECORD",
        "MISSING_RENEWAL_RECORD",
        "MISSING_HUMAN_APPROVAL",
        "MISSING_AUDIT_LINKAGE",
        "MISSING_EVIDENCE_LINKAGE",
        "MISSING_LINEAGE",
        "MISSING_POLICY_BINDING",
        "CROSS_TENANT_COMMERCIAL_ACTION",
        "UNAUTHORIZED_CUSTOMER_ACTIVATION",
        "UNAUTHORIZED_CONTRACT_ACTION",
        "UNAUTHORIZED_SUBSCRIPTION_ACTION",
        "UNAUTHORIZED_BILLING_ACTION",
        "UNAUTHORIZED_INVOICE_ACTION",
        "UNAUTHORIZED_PRICING_ACTION",
        "UNAUTHORIZED_RENEWAL_ACTION",
        "BILLING_EXECUTION_FORBIDDEN",
        "PAYMENT_PROCESSING_FORBIDDEN",
        "INVOICE_SENDING_FORBIDDEN",
        "CONTRACT_SIGNING_FORBIDDEN",
        "CUSTOMER_ACTIVATION_FORBIDDEN",
        "SUBSCRIPTION_ACTIVATION_FORBIDDEN",
        "RENEWAL_EXECUTION_FORBIDDEN",
        "PRICING_MODIFICATION_FORBIDDEN",
        "EMAIL_SENDING_FORBIDDEN",
        "CONNECTOR_WRITE_FORBIDDEN",
        "AUTO_REMEDIATION_FORBIDDEN",
        "AUTO_APPROVAL_FORBIDDEN",
        "COMMERCIAL_GOVERNANCE_BYPASS",
    }
)


@dataclass(frozen=True)
class CommercialGovernanceValidation:
    valid: bool
    status: str
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "status": self.status, "reason_codes": list(self.reason_codes)}


def canonical_commercial_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "commercial_id": str(record.get("commercial_id", "")),
        "tenant_id": str(record.get("tenant_id", "")),
        "workspace_id": str(record.get("workspace_id", "")),
        "registered_commercial_record": record.get("registered_commercial_record") is True,
        "customer_commercial_record": record.get("customer_commercial_record") is True,
        "contract_record": record.get("contract_record") is True,
        "subscription_record": record.get("subscription_record") is True,
        "billing_record": record.get("billing_record") is True,
        "invoice_record": record.get("invoice_record") is True,
        "pricing_record": record.get("pricing_record") is True,
        "renewal_record": record.get("renewal_record") is True,
        "human_approval": record.get("human_approval") is True,
        "policy_binding": record.get("policy_binding") is True,
        "audit_hash": str(record.get("audit_hash", "")),
        "evidence_hash": str(record.get("evidence_hash", "")),
        "lineage_hash": str(record.get("lineage_hash", "")),
        "customer_commercial_status": str(record.get("customer_commercial_status", "")),
        "contract_status": str(record.get("contract_status", "")),
        "subscription_status": str(record.get("subscription_status", "")),
        "billing_status": str(record.get("billing_status", "")),
        "invoice_status": str(record.get("invoice_status", "")),
        "pricing_status": str(record.get("pricing_status", "")),
        "renewal_status": str(record.get("renewal_status", "")),
        "policy_version": str(record.get("policy_version", "")),
        "reason_codes": sorted(str(code) for code in record.get("reason_codes", []) if code),
        "fail_closed": record.get("fail_closed") is True,
    }


def compute_commercial_governance_hash(record: dict[str, Any]) -> str:
    return sha256_json(canonical_commercial_payload(record))


def validate_commercial_record(record: dict[str, Any] | None) -> CommercialGovernanceValidation:
    if not isinstance(record, dict):
        return CommercialGovernanceValidation(False, "BLOCKED", ("UNKNOWN_COMMERCIAL_RECORD",))

    reasons: list[str] = []
    if record.get("schema") != COMMERCIAL_GOVERNANCE_SCHEMA or not str(record.get("commercial_id", "")).strip():
        reasons.append("UNKNOWN_COMMERCIAL_RECORD")
    required_booleans = {
        "registered_commercial_record": "UNREGISTERED_COMMERCIAL_RECORD",
        "customer_commercial_record": "MISSING_CUSTOMER_COMMERCIAL_RECORD",
        "contract_record": "MISSING_CONTRACT_RECORD",
        "subscription_record": "MISSING_SUBSCRIPTION_RECORD",
        "billing_record": "MISSING_BILLING_RECORD",
        "invoice_record": "MISSING_INVOICE_RECORD",
        "pricing_record": "MISSING_PRICING_RECORD",
        "renewal_record": "MISSING_RENEWAL_RECORD",
        "human_approval": "MISSING_HUMAN_APPROVAL",
    }
    for field, reason in required_booleans.items():
        if record.get(field) is not True:
            reasons.append(reason)
    if record.get("policy_binding") is not True or not str(record.get("policy_version", "")).strip():
        reasons.append("MISSING_POLICY_BINDING")
    if not str(record.get("audit_hash", "")).strip():
        reasons.append("MISSING_AUDIT_LINKAGE")
    if not str(record.get("evidence_hash", "")).strip():
        reasons.append("MISSING_EVIDENCE_LINKAGE")
    if not str(record.get("lineage_hash", "")).strip():
        reasons.append("MISSING_LINEAGE")

    expected_statuses = {
        "customer_commercial_status": "AUTHORIZED",
        "contract_status": "AUTHORIZED",
        "subscription_status": "AUTHORIZED",
        "billing_status": "AUTHORIZED",
        "invoice_status": "AUTHORIZED",
        "pricing_status": "AUTHORIZED",
        "renewal_status": "AUTHORIZED",
    }
    status_reasons = {
        "customer_commercial_status": "UNAUTHORIZED_CUSTOMER_ACTIVATION",
        "contract_status": "UNAUTHORIZED_CONTRACT_ACTION",
        "subscription_status": "UNAUTHORIZED_SUBSCRIPTION_ACTION",
        "billing_status": "UNAUTHORIZED_BILLING_ACTION",
        "invoice_status": "UNAUTHORIZED_INVOICE_ACTION",
        "pricing_status": "UNAUTHORIZED_PRICING_ACTION",
        "renewal_status": "UNAUTHORIZED_RENEWAL_ACTION",
    }
    for field, expected in expected_statuses.items():
        if str(record.get(field, "")) != expected:
            reasons.append(status_reasons[field])
    if record.get("tenant_id") and record.get("requesting_tenant_id") and record.get("tenant_id") != record.get("requesting_tenant_id"):
        reasons.append("CROSS_TENANT_COMMERCIAL_ACTION")
    if record.get("workspace_id") and record.get("requesting_workspace_id") and record.get("workspace_id") != record.get("requesting_workspace_id"):
        reasons.append("CROSS_TENANT_COMMERCIAL_ACTION")

    forbidden_flags = {
        "billing_execution": "BILLING_EXECUTION_FORBIDDEN",
        "payment_processing": "PAYMENT_PROCESSING_FORBIDDEN",
        "invoice_sending": "INVOICE_SENDING_FORBIDDEN",
        "contract_signing": "CONTRACT_SIGNING_FORBIDDEN",
        "customer_activation": "CUSTOMER_ACTIVATION_FORBIDDEN",
        "subscription_activation": "SUBSCRIPTION_ACTIVATION_FORBIDDEN",
        "renewal_execution": "RENEWAL_EXECUTION_FORBIDDEN",
        "pricing_modification": "PRICING_MODIFICATION_FORBIDDEN",
        "email_sending": "EMAIL_SENDING_FORBIDDEN",
        "connector_write": "CONNECTOR_WRITE_FORBIDDEN",
        "deployment": "COMMERCIAL_GOVERNANCE_BYPASS",
        "auto_remediation": "AUTO_REMEDIATION_FORBIDDEN",
        "auto_approval": "AUTO_APPROVAL_FORBIDDEN",
        "governance_bypass": "COMMERCIAL_GOVERNANCE_BYPASS",
    }
    for field, reason in forbidden_flags.items():
        if record.get(field) is True:
            reasons.append(reason)
    if not isinstance(record.get("reason_codes"), list):
        reasons.append("COMMERCIAL_GOVERNANCE_BYPASS")
    if record.get("commercial_governance_hash") and record.get("commercial_governance_hash") != compute_commercial_governance_hash(record):
        return CommercialGovernanceValidation(False, "TAMPER_DETECTED", ("COMMERCIAL_GOVERNANCE_BYPASS",))

    clean = tuple(sorted(set(reasons)))
    return CommercialGovernanceValidation(not clean, "GOVERNED" if not clean else "BLOCKED", clean)


def build_commercial_record(
    *,
    commercial_id: str,
    tenant_id: str,
    workspace_id: str,
    registered_commercial_record: bool,
    customer_commercial_record: bool,
    contract_record: bool,
    subscription_record: bool,
    billing_record: bool,
    invoice_record: bool,
    pricing_record: bool,
    renewal_record: bool,
    human_approval: bool,
    policy_binding: bool,
    audit_hash: str,
    evidence_hash: str,
    lineage_hash: str,
    customer_commercial_status: str,
    contract_status: str,
    subscription_status: str,
    billing_status: str,
    invoice_status: str,
    pricing_status: str,
    renewal_status: str,
    policy_version: str,
    billing_execution: bool = False,
    payment_processing: bool = False,
    invoice_sending: bool = False,
    contract_signing: bool = False,
    customer_activation: bool = False,
    subscription_activation: bool = False,
    renewal_execution: bool = False,
    pricing_modification: bool = False,
    email_sending: bool = False,
    connector_write: bool = False,
    deployment: bool = False,
    auto_remediation: bool = False,
    auto_approval: bool = False,
    governance_bypass: bool = False,
    reason_codes: list[str] | tuple[str, ...] = (),
    fail_closed: bool = False,
) -> dict[str, Any]:
    record = {
        "schema": COMMERCIAL_GOVERNANCE_SCHEMA,
        "commercial_id": str(commercial_id),
        "tenant_id": str(tenant_id),
        "workspace_id": str(workspace_id),
        "registered_commercial_record": bool(registered_commercial_record),
        "customer_commercial_record": bool(customer_commercial_record),
        "contract_record": bool(contract_record),
        "subscription_record": bool(subscription_record),
        "billing_record": bool(billing_record),
        "invoice_record": bool(invoice_record),
        "pricing_record": bool(pricing_record),
        "renewal_record": bool(renewal_record),
        "human_approval": bool(human_approval),
        "policy_binding": bool(policy_binding),
        "audit_hash": str(audit_hash),
        "evidence_hash": str(evidence_hash),
        "lineage_hash": str(lineage_hash),
        "customer_commercial_status": str(customer_commercial_status),
        "contract_status": str(contract_status),
        "subscription_status": str(subscription_status),
        "billing_status": str(billing_status),
        "invoice_status": str(invoice_status),
        "pricing_status": str(pricing_status),
        "renewal_status": str(renewal_status),
        "policy_version": str(policy_version),
        "billing_execution": bool(billing_execution),
        "payment_processing": bool(payment_processing),
        "invoice_sending": bool(invoice_sending),
        "contract_signing": bool(contract_signing),
        "customer_activation": bool(customer_activation),
        "subscription_activation": bool(subscription_activation),
        "renewal_execution": bool(renewal_execution),
        "pricing_modification": bool(pricing_modification),
        "email_sending": bool(email_sending),
        "connector_write": bool(connector_write),
        "deployment": bool(deployment),
        "auto_remediation": bool(auto_remediation),
        "auto_approval": bool(auto_approval),
        "governance_bypass": bool(governance_bypass),
        "reason_codes": sorted(str(code) for code in reason_codes if code),
        "fail_closed": bool(fail_closed),
        "commercial_governance_hash": "",
    }
    record["commercial_governance_hash"] = compute_commercial_governance_hash(record)
    return record
