"""Human-issued Hydra transport grants; no runtime issuance or activation.

The existing durable human-approval registry is the trusted local bootstrap.
Only explicitly scoped governance_owner records containing a public Ed25519
key may authorize transport. Registry/database rollback and revocation between
reservation and network I/O remain external trusted-storage limitations.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
import math
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from urllib import request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from governance.durable_authority_registries import (
    DurableAuthorityRegistry, HUMAN_APPROVAL, _time_validity_reason,
)

CONTRACT = "usbay.hydra.transport_mandate.v1"
FIELDS = frozenset({
    "contract_version", "authorization_id", "issuer_reference", "tenant_reference",
    "environment_reference", "policy_reference", "policy_hash", "node_id",
    "endpoint_url_hash", "request_hash", "policy_version", "decision", "nonce",
    "issued_at", "expires_at",
})


class NoTransportRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise _deny("redirect_blocked")


def open_hydra_transport(req, *, timeout):
    # A grant for one endpoint must not authorize an HTTP redirect elsewhere.
    # Preserve urllib's configured proxy routing; only redirects are overridden.
    opener = request.build_opener(NoTransportRedirect())
    return opener.open(req, timeout=timeout)


def mandate_bytes(mandate: dict) -> bytes:
    return json.dumps({k: mandate[k] for k in sorted(FIELDS)}, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode()


def _deny(reason: str) -> ValueError:
    return ValueError("hydra_remote_transport_authorization_" + reason)


def transport_context(context: dict | None, request_hash: str) -> dict:
    """Read detached, human-signed mandates from trusted server configuration.

    Detached grants avoid a circular hash when the original signed Gateway
    request is itself bound into the transport mandate. No caller path is used.
    """
    result = dict(context or {})
    configured = os.environ.get("USBAY_HYDRA_TRANSPORT_MANDATES_PATH")
    if not configured:
        return result
    try:
        payload = json.loads(Path(configured).read_text(encoding="utf-8"))
        result["hydra_transport_mandates"] = payload[request_hash]
    except Exception:
        result["hydra_transport_mandates"] = None
    return result


def node_transport_context(context: dict | None, node_id: str) -> dict:
    result = deepcopy(context or {})
    mandates = result.pop("hydra_transport_mandates", None)
    if isinstance(mandates, dict):
        result["hydra_remote_transport_authorization"] = mandates.get(node_id)
    return result


def _validate_time(mandate: dict, current: float) -> None:
    issued, expires = mandate["issued_at"], mandate["expires_at"]
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v)
           for v in (issued, expires, current)):
        raise _deny("time_malformed")
    if issued > current or expires <= current or expires <= issued or current - issued > 300:
        raise _deny("expired")


def _scope_list(record: dict, name: str) -> list[str]:
    values = record.get(name)
    if not isinstance(values, list) or not values:
        raise _deny("issuer_scope_invalid")
    if any(not isinstance(v, str) or not v.strip() for v in values):
        raise _deny("issuer_scope_invalid")
    if len(values) != len(set(values)):
        raise _deny("issuer_scope_invalid")
    if name == "allowed_endpoint_hashes" and any(re.fullmatch(r"[0-9a-f]{64}", v) is None for v in values):
        raise _deny("issuer_scope_invalid")
    return values


def reserve_transport(mandate: dict, context: dict, *, now: float) -> dict:
    """Verify independent authority, then atomically reserve and record evidence.

    A committed reservation is never released on network failure or restart.
    This is at-most-once admission, not atomic network/evidence execution.
    """
    try:
        mandate, context = deepcopy(mandate), deepcopy(context)
        started = time.monotonic()

        def current_time():
            # Re-read wall time after storage waits. Monotonic elapsed time also
            # prevents a backwards wall-clock adjustment from extending a grant.
            current = max(time.time(), now + time.monotonic() - started)
            _validate_time(mandate, current)
            return current

        if set(mandate) != FIELDS | {"signature"}:
            raise _deny("unsigned_or_malformed")
        if mandate["contract_version"] != CONTRACT:
            raise _deny("contract_invalid")
        string_fields = FIELDS - {"issued_at", "expires_at"}
        if any(not isinstance(mandate[k], str) or not mandate[k].strip() for k in string_fields):
            raise _deny("unsigned_or_malformed")
        if any(re.fullmatch(r"[0-9a-f]{64}", mandate[k]) is None
               for k in ("request_hash", "endpoint_url_hash")):
            raise _deny("hash_invalid")
        # Tenant comes from Gateway's validated request context, never the grant.
        tenant = context.get("tenant_id")
        if not isinstance(tenant, str) or not tenant:
            raise _deny("tenant_missing")
        tenant_ref = "sha256:" + hashlib.sha256(tenant.encode()).hexdigest()
        environment = os.environ.get("USBAY_HYDRA_ENVIRONMENT_REFERENCE")
        if not environment or mandate["environment_reference"] != environment:
            raise _deny("environment_mismatch")
        if mandate["tenant_reference"] != tenant_ref:
            raise _deny("tenant_mismatch")
        policy_hash = context.get("policy_hash")
        if isinstance(policy_hash, str) and len(policy_hash) == 64:
            policy_hash = "sha256:" + policy_hash
        if mandate["policy_hash"] != policy_hash:
            raise _deny("policy_hash_mismatch")
        _validate_time(mandate, now)
        registry_path = os.environ.get("USBAY_GATEWAY_AUTHORITY_REGISTRY")
        replay_path = os.environ.get("USBAY_HYDRA_TRANSPORT_REPLAY_DB")
        if not registry_path or not replay_path:
            raise _deny("trust_unavailable")
        registry = DurableAuthorityRegistry(registry_path)
        criteria = dict(tenant_reference=tenant_ref, environment_reference=environment,
                        policy_reference=mandate["policy_reference"], policy_hash=mandate["policy_hash"])

        def trusted_record():
            resolution = registry.resolve_human_approval(
                mandate["issuer_reference"], **criteria,
                now=datetime.fromtimestamp(current_time(), timezone.utc))
            if resolution.get("status") != "VALID":
                raise _deny("issuer_invalid")
            event = registry._latest(HUMAN_APPROVAL, mandate["issuer_reference"])
            if not event or event["record"].get("record_hash") != resolution["record_hash"]:
                raise _deny("issuer_changed")
            record = event["record"]
            if record.get("issuer_role") != "governance_owner" or record.get("transport_contract") != CONTRACT:
                raise _deny("issuer_scope_invalid")
            if mandate["node_id"] not in _scope_list(record, "allowed_node_ids"):
                raise _deny("issuer_scope_invalid")
            if mandate["endpoint_url_hash"] not in _scope_list(record, "allowed_endpoint_hashes"):
                raise _deny("issuer_scope_invalid")
            # Registry reads can wait on their own lock, independently of SQLite.
            # Reuse canonical validity rules with time sampled after those reads.
            if _time_validity_reason(record, datetime.fromtimestamp(current_time(), timezone.utc)):
                raise _deny("issuer_invalid")
            return record

        record = trusted_record()
        key = serialization.load_pem_public_key(record["issuer_public_key_pem"].encode())
        if not isinstance(key, Ed25519PublicKey):
            raise _deny("signature_invalid")
        encoded = mandate_bytes(mandate)
        try:
            key.verify(bytes.fromhex(mandate["signature"]), encoded)
        except Exception:
            raise _deny("signature_invalid") from None
        evidence_hash = hashlib.sha256(encoded).hexdigest()
        nonce_hash = hashlib.sha256((mandate["issuer_reference"] + ":" + mandate["nonce"]).encode()).hexdigest()
        id_hash = hashlib.sha256((mandate["issuer_reference"] + ":" + mandate["authorization_id"]).encode()).hexdigest()
        conn = sqlite3.connect(replay_path, timeout=5, isolation_level=None)
        try:
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("CREATE TABLE IF NOT EXISTS hydra_transport_reservations (nonce_hash TEXT PRIMARY KEY, authorization_hash TEXT UNIQUE NOT NULL, evidence_hash TEXT NOT NULL, reserved_at REAL NOT NULL, receipt TEXT NOT NULL)")
            if trusted_record()["record_hash"] != record["record_hash"]:
                raise _deny("issuer_changed")
            reserved_at = current_time()
            receipt = json.dumps({
                "state": "START_RESERVED", "mandate_hash": evidence_hash,
                "issuer_record_hash": record["record_hash"],
                "tenant_reference": tenant_ref, "environment_reference": environment,
                "endpoint_url_hash": mandate["endpoint_url_hash"],
                "request_hash": mandate["request_hash"], "policy_hash": mandate["policy_hash"],
                "node_id": mandate["node_id"], "reserved_at": reserved_at,
            }, sort_keys=True, separators=(",", ":"))
            try:
                conn.execute("INSERT INTO hydra_transport_reservations VALUES (?, ?, ?, ?, ?)",
                             (nonce_hash, id_hash, evidence_hash, reserved_at, receipt))
            except sqlite3.IntegrityError:
                raise _deny("replayed") from None
            conn.commit()
        finally:
            conn.close()
        # A commit may itself wait. If authority expired/revoked meanwhile,
        # deny transport while retaining the committed reservation.
        if trusted_record()["record_hash"] != record["record_hash"]:
            raise _deny("issuer_changed")
        current_time()
        return {"authorization_id_hash": id_hash, "evidence_hash": evidence_hash,
                "node_id": mandate["node_id"], "decision": "ALLOW"}
    except ValueError as exc:
        if str(exc).startswith("hydra_remote_transport_authorization_"):
            raise
        raise _deny("trust_unavailable") from None
    except Exception:
        raise _deny("trust_unavailable") from None
