"""Gateway-specific lifecycle bindings and hash-only, committed outcome evidence.

This is an explicit variant, not a governed_execution_authorization adapter.
Only the Gateway calls this module, after decision and consumer validation.
An audit hash identifies evidence; it does not grant authority.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

from governance.hashing import is_sha256_reference, sha256_reference
from security.tenant_context import tenant_hash

SCHEMA = "usbay.gateway.execution_lifecycle_binding.v1"
OUTCOME_SCHEMA = "usbay.gateway.execution_outcome.v1"
AUTHORITY_KIND = "gateway_consumer_allow"
ADAPTER_CONTRACT = {
    "schema": "usbay.gateway.compute_adapter.v1",
    "targets": ["cpu", "npu"],
    "success": "validated_adapter_return",
    "external_effect_proven": False,
}
FIELDS = (
    "schema", "authority_kind", "authority_reference", "gateway_request_hash",
    "request_id", "nonce_reference", "decision_id", "decision_request_hash",
    "tenant_reference", "environment_reference", "policy_id", "policy_version",
    "policy_hash", "action_hash", "adapter_contract_hash", "tenant_hash",
)
HASH_FIELDS = tuple(field for field in FIELDS if field.endswith("_hash")) + (
    "authority_reference", "nonce_reference", "tenant_reference", "environment_reference", "policy_id",
)
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)


class GatewayLifecycleError(RuntimeError):
    pass


def reference(value: Any) -> str:
    if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value):
        return "sha256:" + value
    if not is_sha256_reference(value):
        raise GatewayLifecycleError("gateway_lifecycle_hash_invalid")
    return value


def binding_hash(binding: Mapping[str, Any]) -> str:
    return sha256_reference({field: binding.get(field) for field in FIELDS})


def valid_binding(binding: Mapping[str, Any]) -> bool:
    return (
        set(binding) == set(FIELDS) | {"binding_hash"}
        and binding.get("schema") == SCHEMA
        and binding.get("authority_kind") == AUTHORITY_KIND
        and all(is_sha256_reference(binding.get(field)) for field in HASH_FIELDS)
        and all(isinstance(binding.get(field), str) and IDENTIFIER.fullmatch(binding[field])
                for field in ("request_id", "decision_id", "policy_version"))
        and binding.get("binding_hash") == binding_hash(binding)
        and binding.get("adapter_contract_hash") == sha256_reference(ADAPTER_CONTRACT)
    )


def committed_audit_event(audit_path: str | Path, *, audit_hash: str) -> Mapping[str, Any]:
    """Resolve an actual signed, integrity-checked durable ledger event."""
    from audit.immutable_ledger import ledger_path_for, verified_ledger_records

    digest = reference(audit_hash).removeprefix("sha256:")
    matches = [event for event in verified_ledger_records(ledger_path_for(Path(audit_path)))
               if event.get("current_event_hash") == digest]
    if len(matches) != 1:
        raise GatewayLifecycleError("gateway_lifecycle_evidence_missing")
    return matches[0]


def writer_evidence(audit_path: str | Path, audit: Mapping[str, Any]) -> Mapping[str, Any]:
    """Correlate legacy consumer audit metadata with its durable signed event.

    The consumer's audit_hash addresses the legacy JSON chain. The actual
    lifecycle reference is the corresponding signed ledger event hash.
    """
    from audit.hash_chain import compute_hash
    from audit.immutable_ledger import ledger_path_for, verified_ledger_records

    reference(audit.get("audit_hash"))
    matches = []
    for event in verified_ledger_records(ledger_path_for(Path(audit_path))):
        record = event.get("decision", {})
        if (event.get("action") != audit.get("event_type")
                or event.get("timestamp") != audit.get("timestamp")
                or not isinstance(record, Mapping)):
            continue
        legacy_record = dict(record)
        # Immutable-ledger append adds this derived field to its own copy;
        # audit_writer's original legacy record does not contain it.
        legacy_record.pop("tenant_hash", None)
        legacy_event = {"timestamp": event["timestamp"], "action": event["action"],
                        "decision": legacy_record, "hash_prev": audit.get("hash_prev")}
        if compute_hash(legacy_event, audit.get("hash_prev")) != audit.get("audit_hash"):
            continue
        payload = record.get("payload")
        if not isinstance(payload, Mapping):
            continue
        if (record.get("payload_hash") != audit.get("payload_hash")
                or hashlib.sha256(json.dumps(dict(payload), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                != audit.get("payload_hash")):
            continue
        matches.append(event)
    if len(matches) != 1:
        raise GatewayLifecycleError("gateway_lifecycle_consumer_evidence_invalid")
    return matches[0]


def consumer_evidence(audit_path: str | Path, result: Mapping[str, Any]) -> Mapping[str, Any]:
    audit = result.get("audit")
    if (result.get("decision") != "ALLOW" or result.get("execution_authorized") is not True
            or not isinstance(audit, Mapping)):
        raise GatewayLifecycleError("gateway_lifecycle_consumer_not_allowed")
    event = writer_evidence(audit_path, audit)
    payload = event["decision"]["payload"]
    if (audit.get("event_type") != "GATEWAY_AUTHORIZATION_REQUEST_DECISION"
            or any(payload.get(field) != result.get(field) for field in
                   ("decision", "request_id", "request_hash", "gateway_decision_hash", "consumer_version"))
            or payload.get("tenant_attributed") is not True
            or payload.get("enforcement_gateway_final_authority") is not True):
        raise GatewayLifecycleError("gateway_lifecycle_consumer_evidence_invalid")
    return event


def build_binding(payload: Mapping[str, Any], decision: Mapping[str, Any],
                  consumer: Mapping[str, Any], *, audit_path: str | Path) -> dict[str, Any]:
    from governance.euria_gateway_authorization_request import compute_gateway_authorization_request_hash

    event = consumer_evidence(audit_path, consumer)
    proof = event["decision"]["payload"]
    request = payload.get("gateway_authorization_request")
    if not isinstance(request, dict):
        raise GatewayLifecycleError("gateway_lifecycle_request_invalid")
    unsigned = dict(payload)
    for field in ("signature", "decision_id", "decision_signature", "decision_signature_classic", "decision_signature_pqc"):
        unsigned.pop(field, None)
    original_hash = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if (decision.get("decision") != "ALLOW" or decision.get("decision_id") != payload.get("decision_id")
            or original_hash != decision.get("request_hash")
            or payload.get("tenant_id") != decision.get("tenant_id")
            or proof.get("tenant_id") != decision.get("tenant_id")
            or payload.get("policy_version") != decision.get("policy_version")
            or compute_gateway_authorization_request_hash(request) != request.get("request_hash")):
        raise GatewayLifecycleError("gateway_lifecycle_decision_mismatch")
    for field in ("request_id", "request_hash", "tenant_reference", "environment_reference", "policy_reference", "policy_hash"):
        if request.get(field) != proof.get(field):
            raise GatewayLifecycleError("gateway_lifecycle_authority_mismatch")
    if reference(request.get("policy_hash")) != reference(decision.get("policy_hash")):
        raise GatewayLifecycleError("gateway_lifecycle_policy_mismatch")
    if str(payload.get("compute_target", "")).lower() not in ADAPTER_CONTRACT["targets"]:
        raise GatewayLifecycleError("gateway_lifecycle_adapter_unsupported")
    binding = {
        "schema": SCHEMA, "authority_kind": AUTHORITY_KIND,
        "authority_reference": reference(event["current_event_hash"]),
        "gateway_request_hash": reference(request["request_hash"]),
        "request_id": request["request_id"], "nonce_reference": request.get("nonce_reference"),
        "decision_id": decision["decision_id"], "decision_request_hash": reference(original_hash),
        "tenant_reference": request["tenant_reference"], "environment_reference": request["environment_reference"],
        # The registry-validated opaque policy reference is the policy identifier;
        # it is not a newly generated policy or execution-authorization hash.
        "policy_id": request["policy_reference"], "policy_version": decision["policy_version"],
        "policy_hash": reference(decision["policy_hash"]),
        "tenant_hash": reference(tenant_hash(decision["tenant_id"])),
        "action_hash": sha256_reference({"action": payload.get("action"), "command": payload.get("command"),
                                         "compute_target": payload.get("compute_target"),
                                         "decision_request_hash": reference(original_hash)}),
        "adapter_contract_hash": sha256_reference(ADAPTER_CONTRACT),
    }
    binding["binding_hash"] = binding_hash(binding)
    if not valid_binding(binding):
        raise GatewayLifecycleError("gateway_lifecycle_binding_invalid")
    return binding


def authority_proof_valid(binding: Mapping[str, Any], *, audit_path: str | Path) -> bool:
    """A well-shaped hash alone is never sufficient to acquire a Gateway start."""
    try:
        event = committed_audit_event(audit_path, audit_hash=binding["authority_reference"])
        proof = event["decision"]["payload"]
        expected = {
            "decision": "ALLOW", "tenant_attributed": True,
            "enforcement_gateway_final_authority": True,
            "request_id": binding["request_id"], "request_hash": binding["gateway_request_hash"],
            "tenant_reference": binding["tenant_reference"],
            "environment_reference": binding["environment_reference"],
            "policy_reference": binding["policy_id"], "policy_hash": binding["policy_hash"],
        }
        return (event.get("action") == "GATEWAY_AUTHORIZATION_REQUEST_DECISION"
                and all(proof.get(field) == value for field, value in expected.items())
                and reference(tenant_hash(proof.get("tenant_id"))) == binding["tenant_hash"])
    except Exception:
        return False


def terminal_payload(binding: Mapping[str, Any], *, state: str, outcome_hash: str) -> dict[str, Any]:
    return {"schema": OUTCOME_SCHEMA, "binding_hash": binding_hash(binding),
            "authority_reference": binding["authority_reference"], "state": state, "decision": state,
            "outcome_hash": outcome_hash, "policy_hash": binding["policy_hash"],
            "external_effect_proven": False}


def terminal_proof_valid(binding: Mapping[str, Any], *, audit_path: str | Path,
                         state: str, outcome_hash: str, evidence_hash: str) -> bool:
    try:
        event = committed_audit_event(audit_path, audit_hash=evidence_hash)
        record = event["decision"]
        payload = record.get("payload", {})
        return (event.get("action") == "GATEWAY_EXECUTION_OUTCOME"
                and isinstance(payload, Mapping)
                and reference(tenant_hash(payload.get("tenant_id"))) == binding["tenant_hash"]
                and payload == {**terminal_payload(binding, state=state, outcome_hash=outcome_hash),
                                "tenant_id": payload.get("tenant_id")})
    except Exception:
        return False


def record_outcome(binding: Mapping[str, Any], *, state: str, outcome_hash: str,
                   tenant_id: str, audit_path: str | Path) -> str:
    from audit.audit_writer import write_audit_record

    if (not valid_binding(binding) or state not in {"COMPLETED", "FAILED", "PARTIAL_UNKNOWN"}
            or not is_sha256_reference(outcome_hash)
            or reference(tenant_hash(tenant_id)) != binding["tenant_hash"]):
        raise GatewayLifecycleError("gateway_lifecycle_outcome_invalid")
    proof = terminal_payload(binding, state=state, outcome_hash=outcome_hash)
    # The governed writer needs the established tenant identifier for ledger
    # isolation. No raw request, adapter output, nonce or signature is included.
    result = write_audit_record("GATEWAY_EXECUTION_OUTCOME", {**proof, "tenant_id": tenant_id}, audit_path=audit_path)
    event = writer_evidence(audit_path, result)
    return reference(event["current_event_hash"])
