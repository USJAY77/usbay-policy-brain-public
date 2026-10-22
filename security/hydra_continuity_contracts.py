"""Closed synthetic continuity contracts. No operational enrollment authority."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

VERSION = "usbay.hydra.continuity.v1"
MANDATE = "usbay.hydra.transport_mandate.v2"
SCOPE = ("continuity_identity", "witness_identity", "store_identity", "generation",
         "authority_epoch", "tenant_reference", "environment_reference", "policy_reference", "policy_hash")
TRUST_FIELDS = set(SCOPE) | {"schema", "mode", "control_public_key", "service_public_key",
                           "witness_public_key", "service_url", "witness_url"}
MANDATE_FIELDS = frozenset({"contract_version", "authorization_id", "issuer_reference",
    "tenant_reference", "environment_reference", "policy_reference", "policy_hash", "node_id",
    "endpoint_url_hash", "request_hash", "policy_version", "decision", "nonce", "issued_at", "expires_at",
    "continuity_identity", "store_identity", "generation", "authority_epoch"})


class ContinuityDenied(ValueError):
    def __init__(self, code="STOPPED_UNVERIFIED_HEAD"):
        # Never propagate input, storage errors, keys or request bodies.
        self.code = code
        super().__init__(code)


def require(condition, code="STOPPED_UNVERIFIED_HEAD"):
    if not condition:
        raise ContinuityDenied(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False))


def exact(value, fields):
    require(type(value) is dict and set(value) == set(fields))


def integer(value, minimum=0):
    require(type(value) is int and value >= minimum)


def timestamp(value):
    require(type(value) in (int, float) and math.isfinite(value))


def scope(config):
    return {key: config[key] for key in SCOPE}


def check_scope(value, config):
    for key in SCOPE:
        require(type(value.get(key)) is type(config[key]) and value[key] == config[key])


def public_key(pem):
    key = serialization.load_pem_public_key(pem.encode())
    require(isinstance(key, Ed25519PublicKey))
    return key


def key_bytes(pem):
    return public_key(pem).public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def check_issuer_key(record, config):
    # A runtime signing key cannot become a human mandate issuer via aliasing.
    require(key_bytes(record["issuer_public_key_pem"]) not in
            {key_bytes(config["service_public_key"]), key_bytes(config["witness_public_key"])})


def sign(private_pem, payload):
    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    require(isinstance(key, Ed25519PrivateKey))
    return {"payload": payload, "signature": key.sign(canonical(payload)).hex()}


def verify(packet, public_pem):
    exact(packet, {"payload", "signature"})
    require(type(packet["signature"]) is str and len(packet["signature"]) == 128)
    try:
        public_key(public_pem).verify(bytes.fromhex(packet["signature"]), canonical(packet["payload"]))
    except Exception:
        raise ContinuityDenied() from None
    return packet["payload"]


def trust(config):
    exact(config, TRUST_FIELDS)
    # This reference backend is intentionally non-operational. A role name,
    # reviewer or GitHub approval cannot enable it outside the synthetic lane.
    require(os.getenv("USBAY_ENV") == "test" and config["mode"] == "synthetic_reference_only")
    require(config["schema"] == VERSION)
    for name in ("generation", "authority_epoch"):
        integer(config[name], 1)
    for name in set(SCOPE) - {"generation", "authority_epoch"}:
        require(type(config[name]) is str and config[name].startswith("sha256:") and
                len(config[name]) == 71 and all(c in "0123456789abcdef" for c in config[name][7:]))
    keys = [key_bytes(config[name]) for name in ("control_public_key", "service_public_key", "witness_public_key")]
    require(len(set(keys)) == 3)
    for name in ("service_url", "witness_url"):
        url = urlsplit(config[name])
        require(url.scheme == "http" and url.hostname == "127.0.0.1" and url.port is not None
                and not url.username and not url.password and not url.query and not url.fragment
                and url.path in ("", "/"))
    return config


def load_trust():
    path = os.environ.get("USBAY_HYDRA_CONTINUITY_TRUST")
    require(bool(path))
    return trust(decode(Path(path).read_bytes()))


def binding(mandate):
    return {key: mandate[key] for key in ("continuity_identity", "store_identity", "generation",
        "authority_epoch", "tenant_reference", "environment_reference", "policy_reference", "policy_hash",
        "issuer_reference", "node_id", "endpoint_url_hash", "request_hash", "policy_version")} | {
        "mandate_hash": digest({key: mandate[key] for key in sorted(MANDATE_FIELDS)}),
        "nonce_hash": hashlib.sha256((mandate["issuer_reference"] + ":" + mandate["nonce"]).encode()).hexdigest(),
        "authorization_hash": hashlib.sha256((mandate["issuer_reference"] + ":" + mandate["authorization_id"]).encode()).hexdigest()}


def verify_mandate(mandate, record, config, now):
    exact(mandate, MANDATE_FIELDS | {"signature"})
    require(mandate["contract_version"] == MANDATE and mandate["decision"] == "ALLOW")
    for key in MANDATE_FIELDS - {"issued_at", "expires_at", "generation", "authority_epoch"}:
        require(type(mandate[key]) is str and bool(mandate[key]))
    for key in ("generation", "authority_epoch"):
        integer(mandate[key], 1)
    for key in ("request_hash", "endpoint_url_hash"):
        require(len(mandate[key]) == 64 and all(c in "0123456789abcdef" for c in mandate[key]))
    for key in SCOPE:
        if key != "witness_identity":
            require(type(mandate[key]) is type(config[key]) and mandate[key] == config[key])
    timestamp(now); timestamp(mandate["issued_at"]); timestamp(mandate["expires_at"])
    require(mandate["issued_at"] <= now < mandate["expires_at"] and
            now - mandate["issued_at"] <= 300 and mandate["expires_at"] > mandate["issued_at"])
    from datetime import datetime, timezone
    from governance.durable_authority_registries import (
        _time_validity_reason, _record_malformed_reason, ACTIVE_STATUSES, HUMAN_APPROVAL,
    )
    require(record.get("authority_reference") == mandate["issuer_reference"] and
            record.get("issuer_role") == "governance_owner" and record.get("transport_contract") == MANDATE and
            str(record.get("current_status", "")).upper() in ACTIVE_STATUSES and not record.get("revoked") and
            record.get("ai_generated_only") is not True and record.get("source_system") != "EURIA" and
            record.get("evidence_write_status") != "FAILED" and record.get("domain") == HUMAN_APPROVAL and
            not _record_malformed_reason(record) and
            not _time_validity_reason(record, datetime.fromtimestamp(now, timezone.utc)), "issuer_invalid")
    for key in ("tenant_reference", "environment_reference", "policy_reference", "policy_hash"):
        require(record.get(key) == config[key], "issuer_invalid")
    for field, wanted in (("allowed_node_ids", mandate["node_id"]),
                          ("allowed_endpoint_hashes", mandate["endpoint_url_hash"])):
        values = record.get(field)
        require(type(values) is list and bool(values) and all(type(v) is str for v in values)
                and len(set(values)) == len(values) and wanted in values, "issuer_invalid")
    check_issuer_key(record, config)
    public_key(record["issuer_public_key_pem"]).verify(bytes.fromhex(mandate["signature"]),
        canonical({key: mandate[key] for key in sorted(MANDATE_FIELDS)}))
