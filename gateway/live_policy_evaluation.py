from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from fastapi import Request
from fastapi.responses import JSONResponse

from audit.immutable_ledger import LedgerIntegrityError, append_evidence_event, verified_ledger_records
from gateway.request_identity import (
    RequestIdentityError,
    authenticate_gateway_request,
    parse_unique_json_object,
    revalidate_gateway_request_identity,
)
from gateway.request_identity_replay_store import (
    RESERVED,
    RequestIdentityReplayStore,
    RequestIdentityReplayStoreError,
)
from governance.durable_authority_registries import DurableAuthorityRegistry
from runtime.computer_use.ai_act_live_policy_engine import (
    evaluate_live_policy,
    load_adopted_human_policy_authority,
    revalidate_adopted_human_policy_authority,
)
from security.policy_authority_replay_registry import SQLitePolicyAuthorityReplayRegistry
from security.tenant_context import TenantIsolationError, tenant_scoped_path


ENDPOINT_PATH = "/api/governance/live-policy/evaluate"
EXPECTED_AUDIENCE = "usbay.gateway"
EXPECTED_PURPOSE = "live_policy_evaluation"


@dataclass(frozen=True)
class LivePolicyEvaluationDependencies:
    request_key_config_path: Path
    authority_registry: DurableAuthorityRegistry
    request_replay_store: RequestIdentityReplayStore
    adoption_store: SQLitePolicyAuthorityReplayRegistry
    evidence_root: Path
    environment: str
    before_evidence_commit: Callable[[], None] = lambda: None


def default_dependencies() -> LivePolicyEvaluationDependencies:
    required = {
        "request_key_config_path": os.environ.get("USBAY_REQUEST_SIGNING_KEY_CONFIG_PATH"),
        "authority_registry_path": os.environ.get("USBAY_GATEWAY_AUTHORITY_REGISTRY"),
        "request_replay_path": os.environ.get("USBAY_GATEWAY_REQUEST_IDENTITY_REPLAY_DB"),
        "adoption_store_path": os.environ.get("USBAY_POLICY_AUTHORITY_REPLAY_SQLITE_PATH"),
        "evidence_root": os.environ.get("USBAY_LIVE_POLICY_EVIDENCE_ROOT"),
        "environment": os.environ.get("USBAY_RUNTIME_ENVIRONMENT"),
    }
    if any(not value for value in required.values()):
        raise RuntimeError("LIVE_POLICY_CONFIGURATION_UNAVAILABLE")
    return LivePolicyEvaluationDependencies(
        request_key_config_path=Path(required["request_key_config_path"]),
        authority_registry=DurableAuthorityRegistry(Path(required["authority_registry_path"])),
        request_replay_store=RequestIdentityReplayStore(Path(required["request_replay_path"])),
        adoption_store=SQLitePolicyAuthorityReplayRegistry(Path(required["adoption_store_path"])),
        evidence_root=Path(required["evidence_root"]),
        environment=str(required["environment"]),
    )


async def handle_live_policy_evaluation(
    request: Request,
    *,
    dependencies: LivePolicyEvaluationDependencies | None = None,
) -> JSONResponse:
    # The feature gate intentionally precedes body access and all stateful dependencies.
    if os.environ.get("USBAY_LIVE_POLICY_EVALUATION_ENABLED", "").lower() not in {"1", "true", "yes"}:
        return _response(503, "BLOCK", "LIVE_POLICY_EVALUATION_DISABLED")

    try:
        deps = dependencies or default_dependencies()
        body_bytes = await request.body()
        body = parse_unique_json_object(body_bytes, reason_code="LIVE_POLICY_REQUEST_MALFORMED")
        credential = request.headers.get("x-usbay-request-identity")
        if not credential:
            return _response(401, "BLOCK", "REQUEST_IDENTITY_MISSING")
        now = datetime.now(timezone.utc)
        identity = authenticate_gateway_request(
            credential_json=credential,
            request_body_json=body_bytes,
            method=request.method,
            path=request.url.path,
            expected_audience=EXPECTED_AUDIENCE,
            expected_purpose=EXPECTED_PURPOSE,
            expected_environment=deps.environment,
            request_key_config_path=deps.request_key_config_path,
            authority_registry=deps.authority_registry,
            now=now,
        )
        reservation = deps.request_replay_store.reserve(
            identity,
            reserved_at=now.isoformat().replace("+00:00", "Z"),
        )
        if reservation.status != RESERVED:
            return _response(409, "BLOCK", reservation.reason_code)

        governed_request, load_arguments = _bind_request(body, identity, deps, now)
        authority = load_adopted_human_policy_authority(**load_arguments)
        evaluation = evaluate_live_policy(
            governed_request,
            policy_authority_loader=lambda: authority,
            clock=lambda: now.isoformat().replace("+00:00", "Z"),
        )

        deps.before_evidence_commit()
        revalidate_gateway_request_identity(
            identity,
            credential_json=credential,
            request_body_json=body_bytes,
            method=request.method,
            path=request.url.path,
            request_key_config_path=deps.request_key_config_path,
            authority_registry=deps.authority_registry,
            now=datetime.now(timezone.utc),
        )
        revalidate_adopted_human_policy_authority(authority, **load_arguments)

        ledger_path = tenant_scoped_path(deps.evidence_root, identity.tenant_id) / "live-policy-evidence.jsonl"
        decision_evidence = {
            "node_id": "live-policy-gateway",
            "tenant_id": identity.tenant_id,
            "actor_id": identity.actor_id,
            "identity_reference": identity.identity_reference,
            "identity_record_hash": identity.identity_record_hash,
            "request_id": identity.request_id,
            "correlation_id": identity.correlation_id,
            "request_hash": identity.request_body_hash,
            "decision_id": evaluation.decision_id,
            "decision": evaluation.decision,
            "reason_code": evaluation.reason_code,
            "policy_id": evaluation.policy_id,
            "policy_version": evaluation.policy_version,
            "policy_hash": evaluation.policy_hash,
            "authority_state_reference": authority.authority_state_reference,
            "evidence_hash": evaluation.evidence["current_evidence_hash"],
            "execution_authorized": False,
            "provider_authorized": False,
            "deployment_authorized": False,
            "activation_authorized": False,
            "policy_authoring_authorized": False,
        }
        block = append_evidence_event(
            ledger_path,
            action="live_policy_evaluated",
            decision=decision_evidence,
            timestamp=evaluation.timestamp,
        )
        persisted = [
            record
            for record in verified_ledger_records(ledger_path)
            if record.get("event_id") == block.get("event_id")
        ]
        if len(persisted) != 1 or persisted[0].get("current_event_hash") != block.get("current_event_hash"):
            raise LedgerIntegrityError("ledger_post_append_verification_failed")
        stored_decision = persisted[0].get("decision")
        if not isinstance(stored_decision, dict) or any(
            stored_decision.get(key) != value for key, value in decision_evidence.items()
        ):
            raise LedgerIntegrityError("ledger_post_append_binding_failed")

        status = 200 if evaluation.decision == "ALLOW" else 202 if evaluation.decision == "REVIEW" else 403
        return _response(
            status,
            evaluation.decision,
            evaluation.reason_code,
            decision_id=evaluation.decision_id,
            correlation_id=identity.correlation_id,
            policy_id=evaluation.policy_id,
            policy_version=evaluation.policy_version,
            policy_hash=evaluation.policy_hash,
            evidence_id=block["event_id"],
            evidence_hash=block["current_event_hash"],
        )
    except RequestIdentityError as exc:
        return _response(401, "BLOCK", exc.code)
    except RequestIdentityReplayStoreError as exc:
        return _response(503, "BLOCK", exc.code)
    except (LedgerIntegrityError, TenantIsolationError):
        return _response(503, "BLOCK", "LIVE_POLICY_EVIDENCE_COMMIT_FAILED")
    except Exception:
        return _response(503, "BLOCK", "LIVE_POLICY_EVALUATION_FAILED")


def _bind_request(body: dict[str, Any], identity: Any, deps: LivePolicyEvaluationDependencies, now: datetime):
    required = ("adoption_id", "policy_id", "policy_version", "policy_hash", "input_metadata")
    if any(field not in body for field in required):
        raise RequestIdentityError("LIVE_POLICY_REQUEST_MALFORMED")
    for field, expected in (
        ("tenant_id", identity.tenant_id),
        ("actor_id", identity.actor_id),
        ("environment", identity.environment),
        ("request_id", identity.request_id),
        ("correlation_id", identity.correlation_id),
    ):
        if field in body and body[field] != expected:
            raise RequestIdentityError("REQUEST_IDENTITY_BINDING_MISMATCH")
    governed = dict(body)
    governed.update(
        tenant_id=identity.tenant_id,
        actor_id=identity.actor_id,
        environment=identity.environment,
        request_id=identity.request_id,
        correlation_id=identity.correlation_id,
    )
    adoption_id = governed.pop("adoption_id")
    return governed, {
        "adoption_id": adoption_id,
        "policy_id": governed["policy_id"],
        "policy_hash": governed["policy_hash"],
        "policy_version": governed["policy_version"],
        "tenant_reference": identity.tenant_reference,
        "environment_reference": identity.environment_reference,
        "environment": identity.environment,
        "adoption_store": deps.adoption_store,
        "now": now,
    }


def _response(status: int, decision: str, reason_code: str, **values: Any) -> JSONResponse:
    content = {
        "decision": decision,
        "reason_code": reason_code,
        "execution_authorized": False,
        "provider_authorized": False,
        "deployment_authorized": False,
        "activation_authorized": False,
        "policy_authoring_authorized": False,
        **values,
    }
    return JSONResponse(status_code=status, content=content)


__all__ = ["LivePolicyEvaluationDependencies", "handle_live_policy_evaluation"]
