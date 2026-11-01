"""Explicit opt-in boundary for an already authenticated request, not execution.

No endpoint or feature gate is changed. The complete flat declaration plus
operation must be covered by the existing Gateway request signature. Only
sealed identities created by authenticate_gateway_request are accepted.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from gateway.request_identity import is_authenticated_request_identity
from governance.hashing import canonical_json, is_sha256_reference, sha256_reference
from security.declared_intent import (
    FIELDS, IntentError, parse_identity_time, parse_object, validate_declaration, validate_operation,
)
from security.intent_replay_store import IntentReplayStore, IntentStoreError

RESULT_SCHEMA = "usbay.intent_governance.result.v1"
FLAGS = ("execution_authorized", "provider_authorized", "deployment_authorized",
         "activation_authorized", "policy_authoring_authorized")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def consume_declared_intent(
    raw_request: Any, *, authenticated_identity: object, replay_store: IntentReplayStore,
    prior_decision: str, policy_hash: str, decision_reference: str,
    now: datetime | None = None,
) -> dict:
    """Narrow a prior decision; receipt is never policy/approval/execution authority.

    prior_decision and references come from the trusted integrating caller;
    they are correlated here, not independently adopted or authorized here.
    Every successful first-use persists minimal evidence with its reservation.
    """
    try:
        comparison_time = now if now is not None else _utc_now()
        if (not isinstance(comparison_time, datetime) or comparison_time.tzinfo is None
                or comparison_time.utcoffset() is None):
            raise IntentError("INTENT_TIME_INVALID")
        decision_timestamp = comparison_time.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        # An invalid injected comparison time cannot validate an intent. A fresh
        # UTC receipt time records the BLOCK; it does not repair that input.
        comparison_time = None
        decision_timestamp = _utc_now().isoformat().replace("+00:00", "Z")
    references = {"timestamp": decision_timestamp}

    def result(decision, reason):
        evidence = {"schema_version": RESULT_SCHEMA, "decision": decision, "reason_code": reason,
                    **references, **{flag: False for flag in FLAGS}}
        # No hash chain or signature is claimed for this standalone receipt.
        evidence["evidence_hash"] = sha256_reference(evidence)
        return evidence

    try:
        if comparison_time is None:
            raise IntentError("INTENT_TIME_INVALID")
        if not is_authenticated_request_identity(authenticated_identity):
            raise IntentError("INTENT_IDENTITY_UNVERIFIED")
        context = authenticated_identity
        if not parse_identity_time(context.valid_from) <= comparison_time < parse_identity_time(context.valid_until):
            raise IntentError("INTENT_IDENTITY_NOT_CURRENT")
        request = parse_object(raw_request)
        if set(request) != FIELDS | {"operation"}:
            raise IntentError("INTENT_FIELDS_INVALID")
        if sha256_reference(request) != context.request_body_hash:
            raise IntentError("INTENT_REQUEST_BINDING_MISMATCH")
        intent = validate_declaration({k: v for k, v in request.items() if k != "operation"}, now=comparison_time)
        for field in ("tenant_id", "actor_id", "request_id", "correlation_id", "environment"):
            if intent[field] != getattr(context, field):
                raise IntentError("INTENT_IDENTITY_BINDING_MISMATCH")
        validate_operation(request["operation"], intent)
        if not is_sha256_reference(policy_hash) or not is_sha256_reference(decision_reference):
            raise IntentError("INTENT_POLICY_BINDING_INVALID")
        references.update(intent_reference=sha256_reference({"intent_id": intent["intent_id"]}),
                          intent_hash=intent["intent_hash"], request_reference=sha256_reference({"request_id":context.request_id}),
                          correlation_reference=sha256_reference({"correlation_id":context.correlation_id}),
                          tenant_reference=sha256_reference({"tenant_id":context.tenant_id}),
                          actor_reference=sha256_reference({"actor_id":context.actor_id}),
                          authenticated_request_digest=context.authenticated_request_digest,
                          policy_hash=policy_hash, decision_reference=decision_reference)
        if prior_decision in {"BLOCK", "REVIEW"}:
            return result(prior_decision, "INTENT_PRIOR_DECISION_PRESERVED")
        if prior_decision != "ALLOW":
            raise IntentError("INTENT_PRIOR_DECISION_INVALID")
        accepted = result("ALLOW", "DECLARED_INTENT_BOUND_NON_EXECUTING")
        # Tenant-scoped identifiers; neither actor changes nor request re-signing
        # can reuse an intent ID/nonce within that tenant.
        first = replay_store.reserve(
            intent_reference=sha256_reference({"tenant":context.tenant_id,"intent_id":intent["intent_id"]}),
            nonce_reference=sha256_reference({"tenant":context.tenant_id,"nonce":intent["nonce"]}),
            evidence=canonical_json(accepted),
        )
        if not first:
            return result("BLOCK", "INTENT_REPLAY")
        return accepted
    except IntentError as error:
        return result("BLOCK", error.code)
    except IntentStoreError:
        return result("BLOCK", "INTENT_STORE_UNAVAILABLE")
    except Exception:
        # Bounded public error; never stringify the request or storage exception.
        return result("BLOCK", "INTENT_CONSUMPTION_UNCERTAIN")
