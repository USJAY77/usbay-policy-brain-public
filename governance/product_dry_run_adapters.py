"""Local integration adapters; no live product or provider authorization.

The signed approval database must be provisioned by operator-controlled issuer
tooling. The evaluator only reads it. Issuer public-key enrollment remains a
local trust bootstrap, not authenticated human identity or a production IdP.
"""
from __future__ import annotations

from datetime import datetime
import json
import re
from pathlib import Path
import sqlite3
import time
from typing import Callable
from urllib.parse import quote

from audit.audit_writer import write_audit_record
from governance.approval_issuance import (
    ISSUANCE_REQUIRED_FIELDS, validate_issuance_schema, verify_issuance_signature,
)
from governance.connector_framework import sha256_payload
from governance.product_dry_run import DryRunGrant, DryRunRequest
from security.policy_authority_replay_registry import SQLitePolicyAuthorityReplayRegistry
from security.tenant_context import validate_tenant_id


class SignedDryRunApprovals:
    """Read-only SQLite snapshot per lookup; no approval-issuance API.

Schema: approvals(binding TEXT PRIMARY KEY, payload TEXT, signature TEXT,
revoked INTEGER); issuers(id TEXT PRIMARY KEY, public_key TEXT, tenant TEXT,
capability TEXT, revoked INTEGER). Issuer data is never accepted from requests.
"""

    def __init__(self, path: Path):
        self.path = Path(path)

    def __call__(self, request: DryRunRequest) -> DryRunGrant | None:
        uri = "file:" + quote(str(self.path.resolve()), safe="/") + "?mode=ro"
        # One transaction gives the grant and issuer a consistent local view.
        with sqlite3.connect(uri, uri=True) as conn:
            conn.execute("BEGIN")
            row = conn.execute(
                "SELECT payload, signature, revoked FROM approvals WHERE binding=?",
                (request.binding,),
            ).fetchone()
            if row is None or type(row[2]) is not int or row[2] != 0:
                return None
            payload = json.loads(row[0])
            if not isinstance(payload, dict) or set(payload) != set(ISSUANCE_REQUIRED_FIELDS):
                return None
            if validate_issuance_schema(payload, row[1]):
                return None
            issuer = conn.execute(
                "SELECT public_key, tenant, capability, revoked FROM issuers WHERE id=?",
                (payload["issuer_id"],),
            ).fetchone()
            if issuer is None or type(issuer[3]) is not int or issuer[3] != 0:
                return None
            if issuer[1:3] != (request.tenant, request.capability):
                return None
            if (payload["actor_id"] != request.actor
                    or payload["tenant_reference"] != request.tenant
                    or payload["execution_id"] != request.action_id
                    or payload["authorization_id"] != "offline-product-dry-run-v1"
                    or payload["binding_hash"] != request.binding
                    or not verify_issuance_signature(issuer[0], payload, row[1])):
                return None
            issued = datetime.strptime(payload["issued_at"], "%Y-%m-%dT%H:%M:%SZ")
            expires = datetime.strptime(payload["expires_at"], "%Y-%m-%dT%H:%M:%SZ")
            from datetime import timezone
            return DryRunGrant(request.binding, payload["issuer_id"],
                               issued.replace(tzinfo=timezone.utc),
                               expires.replace(tzinfo=timezone.utc))


class PersistentDryRunAttempts:
    def __init__(self, path: Path, *, clock: Callable[[], float] = time.time):
        # Consumed attempts are retained history, not expiring authority. Do
        # not inherit the registry's 300-second freshness cache default.
        # Keep integrity/schema/backward-clock checks; never reset the DB.
        self.store = SQLitePolicyAuthorityReplayRegistry(
            path, max_state_age_seconds=2**63 - 1, now_fn=clock,
        )

    def __call__(self, attempt_hash: str, binding: str) -> bool:
        from datetime import timezone
        result = self.store.consume_if_unused(
            (sha256_payload(["product-attempt", attempt_hash]),
             sha256_payload(["product-binding", binding])),
            registry_evidence_hash="sha256:" + sha256_payload("product-dry-run-replay-v1"),
            consumed_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        return result.state == "CONSUMED"


class ProductAuditWriter:
    """Hash-only request identity inside an explicitly separate audit partition.

    audit_tenant is an operator-selected non-sensitive ledger routing ID. The
    existing writer requires a policy-registered tenant, so a hash cannot be
    substituted there. It must differ from the request tenant and must never
    be derived from it. No tenant policy or writer contract is widened.
    """

    def __init__(self, *, tenant: str, audit_tenant: str, policy_hash: str, path: Path):
        self.tenant = validate_tenant_id(tenant)
        self.audit_tenant = validate_tenant_id(audit_tenant)
        if self.tenant == self.audit_tenant:
            raise ValueError("DISTINCT_AUDIT_PARTITION_REQUIRED")
        if len(policy_hash) != 64 or any(c not in "0123456789abcdef" for c in policy_hash):
            raise ValueError("INVALID_POLICY_HASH")
        self.policy_hash = policy_hash
        self.path = Path(path)

    def __call__(self, event: dict) -> dict:
        validate_tenant_id(self.tenant)
        validate_tenant_id(self.audit_tenant)
        expected = {"schema", "request_hash", "action_hash", "tenant_hash",
                    "decision", "blockers", "external_mutation_performed", "execution_authorized"}
        if set(event) != expected or event.get("schema") != "usbay.product_dry_run.v1":
            raise ValueError("INVALID_PRODUCT_AUDIT_EVENT")
        if any(not isinstance(event.get(k), str) or not re.fullmatch(r"[0-9a-f]{64}", event[k])
               for k in ("request_hash", "action_hash", "tenant_hash")):
            raise ValueError("INVALID_PRODUCT_AUDIT_HASH")
        if event.get("decision") not in {"BLOCKED", "PREPARED_DRY_RUN"}:
            raise ValueError("INVALID_PRODUCT_AUDIT_DECISION")
        codes = {"MALFORMED_REQUEST", "INVALID_CONTENT_HASH", "LIVE_EXECUTION_DISABLED",
                 "POLICY_MISMATCH", "ACTOR_TENANT_MISMATCH", "AGENT_TENANT_MISMATCH",
                 "AGENT_NOT_READY_OR_CAPABILITY_DENIED", "AGENT_LOOKUP_FAILED",
                 "SCOPED_REVIEW_MISSING_OR_INVALID", "HUMAN_REVIEW_BLOCKED", "ACTION_ID_REUSED",
                 "PERSISTENT_REPLAY_BLOCKED", "PERSISTENT_REPLAY_UNAVAILABLE"}
        if not isinstance(event.get("blockers"), list) or any(not isinstance(c, str) or c not in codes for c in event["blockers"]):
            raise ValueError("INVALID_PRODUCT_AUDIT_CODES")
        if event.get("tenant_hash") != sha256_payload(self.tenant):
            raise ValueError("AUDIT_TENANT_MISMATCH")
        if (event.get("execution_authorized") is not False
                or event.get("external_mutation_performed") is not False):
            raise ValueError("OFFLINE_BOUNDARY_VIOLATION")
        return write_audit_record("product_dry_run", {
            **event, "tenant_id": self.audit_tenant, "policy_hash": self.policy_hash,
        }, audit_path=self.path)

