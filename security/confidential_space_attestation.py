"""Disabled-by-default Confidential Space producer and RS256 relying party.

Tokens never grant USBAY roles: server-owned enrollment supplies those bindings.
No discovery, JWKS download, provisioning, recovery or authority issuance here.
"""
from __future__ import annotations

import base64
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import http.client
import json
import logging
import math
import os
from pathlib import Path
import re
import socket
import sqlite3
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from security.decision_evidence_consumption_store import (
    FIRST_CONSUMPTION, SQLiteDecisionEvidenceConsumptionStore,
)
from security.hydra_consensus import HydraNodeDecision, EXPECTED_NODE_ROLES, replay_registry_hash
from security.node_identity import load_node_attestation_policy
from security.runtime_attestation import challenge_nonce
from security.tenant_context import tenant_execution_context
from security.request_signing import request_signature_message, validate_request_signature, DEFAULT_REQUEST_KEY_CONFIG_PATH
from security.policy_registry import validate_policy_registry_shape, policy_hash as registry_policy_hash

PROFILE = "google-confidential-space-oidc-rs256-v1"
ISSUER = "https://confidentialcomputing.googleapis.com"
SOCKET = "/run/container_launcher/teeserver.sock"
DOMAIN = "USBAY/ConfidentialSpace/NodeResponse/v1"
LIMIT = 65536
EXCLUDED = frozenset({"signature", "attestation_timestamp", "attestation_hash",
                      "attestation_node_id", "attestation_provider_mode", "hardware_backed"})
MODELS = frozenset({"GCP_AMD_SEV", "GCP_AMD_SEV_ES", "GCP_INTEL_TDX"})


class AttestationRejected(ValueError):
    def __init__(self, code, stage):
        self.code, self.stage = code, stage
        super().__init__("CS_" + code)


def require(condition, code, stage):
    if not condition:
        raise AttestationRejected(code, stage)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def decode(raw):
    require(type(raw) in (str, bytes) and len(raw) <= LIMIT, "SIZE", "parse")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "DUPLICATE", "parse")
            result[key] = value
        return result
    def invalid(_):
        raise AttestationRejected("JSON", "parse")
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
        remaining = [8192]
        def bound(item, depth=0):
            remaining[0] -= 1
            require(depth <= 12 and remaining[0] >= 0, "SIZE", "parse")
            if isinstance(item, str):
                require(len(item) <= 8192, "SIZE", "parse")
            elif isinstance(item, dict):
                for key, child in item.items():
                    require(len(key) <= 128, "SIZE", "parse"); bound(child, depth + 1)
            elif isinstance(item, list):
                require(len(item) <= 256, "SIZE", "parse")
                for child in item: bound(child, depth + 1)
            else:
                require(item is None or type(item) in (bool, int, float), "JSON", "parse")
                if type(item) in (int, float):
                    require(math.isfinite(item) and abs(item) <= 2**53-1, "JSON", "parse")
        bound(value)
        return value
    except AttestationRejected:
        raise
    except Exception:
        raise AttestationRejected("JSON", "parse") from None


def enabled():
    value = os.environ.get("USBAY_NODE_ATTESTATION_ADAPTER", "")
    require(value in ("", PROFILE), "PROFILE", "configuration")
    return value == PROFILE


def settings():
    try:
        require(not os.getenv("HYDRA_NODE_URLS") and os.getenv("USBAY_HYDRA_BACKEND", "").lower() != "services", "BACKEND_CONFLICT", "configuration")
        path = Path(os.environ["USBAY_CONFIDENTIAL_SPACE_TRUST_PATH"])
        require(path.is_file() and not path.is_symlink(), "TRUST", "configuration")
        metadata = path.stat()
        require(metadata.st_uid in (0, os.getuid()) and not metadata.st_mode & 0o022, "TRUST_PERMISSIONS", "configuration")
        config = decode(path.read_bytes())
        require(isinstance(config, dict) and config.get("profile") == PROFILE and config.get("issuer") == ISSUER,
                "TRUST", "configuration")
        validate_config(config)
        synthetic = config.get("synthetic_fixture", False)
        require(type(synthetic) is bool and (not synthetic or os.getenv("USBAY_ENV") == "test"), "SYNTHETIC_PROFILE", "configuration")
        require(synthetic or config.get("launcher_socket") == SOCKET, "SOCKET", "configuration")
        policy = load_node_attestation_policy()
        require(policy["required_attestation_mode"] == "external_attestation_service", "POLICY_NOT_APPROVED", "configuration")
        return config, policy
    except AttestationRejected:
        raise
    except Exception:
        raise AttestationRejected("TRUST", "configuration") from None


def validate_config(config):
    require(isinstance(config, dict), "TRUST", "configuration")
    require(type(config.get("audience")) is str and 0 < len(config["audience"].encode()) <= 512 and
            config["audience"] not in ("https://sts.googleapis.com", "https://sts.google.com"), "TRUST", "configuration")
    for field in ("snapshot_issued_at", "snapshot_expires_at", "max_token_lifetime_seconds"):
        require(type(config.get(field)) is int, "TRUST", "configuration")
    require(0 <= config["snapshot_issued_at"] < config["snapshot_expires_at"] and
            0 < config["max_token_lifetime_seconds"] <= 3600, "TRUST", "configuration")
    require(type(config.get("issuer")) is str and bool(config["issuer"]), "TRUST", "configuration")
    require(isinstance(config.get("keys"), dict) and 0 < len(config["keys"]) <= 16 and
            isinstance(config.get("nodes"), dict) and 0 < len(config["nodes"]) <= 3, "TRUST", "configuration")
    require(type(config.get("replay_db")) is str and Path(config["replay_db"]).is_absolute(), "TRUST", "configuration")
    for kid, key in config["keys"].items():
        require(type(kid) is str and 0 < len(kid) <= 128 and isinstance(key, dict), "TRUST", "configuration")
        require(set(key) == {"public_pem","not_before","not_after","revoked"} and
                type(key["public_pem"]) is str and type(key["not_before"]) is int and
                type(key["not_after"]) is int and key["not_before"] < key["not_after"] and
                type(key["revoked"]) is bool, "TRUST", "configuration")
    for node, entry in config["nodes"].items():
        require(node in EXPECTED_NODE_ROLES and isinstance(entry, dict) and entry.get("role") == EXPECTED_NODE_ROLES[node], "TRUST", "configuration")
        for field in ("project_id","project_number","service_account","image_digest","image_reference"):
            require(type(entry.get(field)) is str and bool(entry[field]), "TRUST", "configuration")
        for field in ("subjects","tenants","args","swversions","hardware_models"):
            require(type(entry.get(field)) is list and bool(entry[field]) and
                    all(type(x) is str and x for x in entry[field]), "TRUST", "configuration")
        require(set(entry["hardware_models"]) <= MODELS and isinstance(entry.get("env"), dict) and
                all(type(k) is str and type(v) is str for k,v in entry["env"].items()), "TRUST", "configuration")


def scope(node_id, request_hash, policy_version, context):
    require(isinstance(context, dict), "CONTEXT", "binding")
    require(not any(key in context for key in ("response_hash", "response", "eat_nonce", "audience")), "ORACLE_INPUT", "binding")
    values = {key: context.get(key) for key in ("policy_hash", "nonce_hash", "tenant_id")}
    for value in (request_hash, values["policy_hash"], values["nonce_hash"]):
        require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "CONTEXT", "binding")
    require(node_id in EXPECTED_NODE_ROLES and type(policy_version) is str and 0 < len(policy_version) <= 128, "CONTEXT", "binding")
    try:
        tenant = tenant_execution_context(values["tenant_id"])
    except Exception:
        raise AttestationRejected("CONTEXT", "binding") from None
    timestamp = context.get("attestation_timestamp")
    require(type(timestamp) in (int, float) and math.isfinite(timestamp) and timestamp > 0, "CONTEXT", "binding")
    return dict(node_id=node_id, role=EXPECTED_NODE_ROLES[node_id], request_hash=request_hash,
                policy_version=policy_version, policy_hash=values["policy_hash"], nonce_hash=values["nonce_hash"],
                tenant_id=tenant["tenant_id"], tenant_hash=tenant["tenant_hash"],
                challenge=challenge_nonce(request_hash=request_hash, logical_node_id=node_id, timestamp=timestamp))


def commitment(response, expected):
    return digest({"domain": DOMAIN, "scope": expected,
                   "response": {key: value for key, value in response.items() if key not in EXCLUDED}})


class LauncherClient:
    """Only the documented local launcher UDS; no proxy, redirect or IP transport."""
    def __init__(self, path, timeout):
        self.path, self.timeout = path, timeout

    def acquire(self, audience, nonce):
        connection = http.client.HTTPConnection("localhost", timeout=self.timeout)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout); sock.connect(self.path)
            connection.sock = sock
            connection.request("POST", "/v1/token", canonical({"audience": audience, "token_type": "OIDC", "nonces": [nonce]}),
                               {"Content-Type": "application/json"})
            response = connection.getresponse()
            raw = response.read(LIMIT + 1)
            require(response.status == 200 and len(raw) <= LIMIT, "PROVIDER_REPLY", "acquisition")
            # Documented OIDC response is the raw compact JWT, not a JSON wrapper.
            token = raw.decode("ascii").strip()
            require(token.count(".") == 2, "PROVIDER_REPLY", "acquisition")
            return token
        except AttestationRejected:
            raise
        except Exception:
            raise AttestationRejected("PROVIDER_UNAVAILABLE", "acquisition") from None
        finally:
            connection.close(); sock.close()


def produce(node_id, request_hash, policy_version, context, config, policy, *, acquire=None):
    """Measured producer evaluates the node itself. No caller-supplied response/hash API."""
    expected = scope(node_id, request_hash, policy_version, context)
    try:
        registry_path = Path(os.getenv("USBAY_POLICY_REGISTRY_PATH", "governance/policy_registry.json"))
        registry = validate_policy_registry_shape(decode(registry_path.read_bytes()))
        require(registry["version"] == policy_version and registry_policy_hash(registry) == expected["policy_hash"], "POLICY_BINDING", "producer")
        require(context.get("nonce_state", "unused") == "unused" and
                context.get("replay_registry_hash", replay_registry_hash(expected["policy_hash"], expected["nonce_hash"])) ==
                replay_registry_hash(expected["policy_hash"], expected["nonce_hash"]), "REQUEST_BINDING", "producer")
    except AttestationRejected:
        raise
    except Exception:
        raise AttestationRejected("POLICY_BINDING", "producer") from None
    signed_request = context.get("confidential_space_signed_request")
    require(isinstance(signed_request, dict), "REQUEST_SIGNATURE", "producer")
    key_config = Path(os.getenv("USBAY_REQUEST_SIGNING_KEY_CONFIG_PATH", str(DEFAULT_REQUEST_KEY_CONFIG_PATH)))
    valid, _ = validate_request_signature(signed_request, key_config)
    require(valid, "REQUEST_SIGNATURE", "producer")
    require(hashlib.sha256(request_signature_message(signed_request).encode()).hexdigest() == request_hash and
            signed_request.get("policy_version") == policy_version and signed_request.get("tenant_id") == expected["tenant_id"] and
            hashlib.sha256(str(signed_request.get("nonce", "")).encode()).hexdigest() == expected["nonce_hash"] and
            bool(signed_request.get("actor_id")), "REQUEST_BINDING", "producer")
    try:
        replay_policy = decode(Path("governance/replay_policy.json").read_bytes())
        timestamp = int(signed_request["timestamp"])
        current = time.time()
        require(current - replay_policy["nonce_ttl_seconds"] <= timestamp <= current + replay_policy["timestamp_skew_seconds"], "REQUEST_FRESHNESS", "producer")
    except AttestationRejected:
        raise
    except Exception:
        raise AttestationRejected("REQUEST_FRESHNESS", "producer") from None
    require(node_id in policy["enrolled_nodes"], "NODE", "producer")
    now = time.time()
    # Preserve the existing in-process policy result; only its attestation path changes.
    response = HydraNodeDecision(node_id=node_id, node_role=expected["role"], request_hash=request_hash,
        policy_version=policy_version, decision="allow", reason="in_process_policy_allow", timestamp=now,
        policy_hash=expected["policy_hash"], nonce_hash=expected["nonce_hash"], nonce_state="unused",
        replay_registry_hash=replay_registry_hash(expected["policy_hash"], expected["nonce_hash"]),
        tenant_id=expected["tenant_id"], tenant_hash=expected["tenant_hash"]).to_dict()
    require(type(config.get("audience")) is str and 0 < len(config["audience"].encode()) <= 512, "TRUST", "configuration")
    timeout = config.get("acquisition_timeout_seconds")
    require(type(timeout) in (int, float) and 0 < timeout <= 0.75, "DEADLINE", "configuration")
    client = acquire or LauncherClient(config["launcher_socket"], timeout).acquire
    token = client(config["audience"], commitment(response, expected))
    return canonical({"response": response, "token": token})


def b64(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]+", value), "JWT", "parse")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        require(base64.urlsafe_b64encode(raw).decode().rstrip("=") == value, "JWT", "parse")
        return raw
    except AttestationRejected:
        raise
    except Exception:
        raise AttestationRejected("JWT", "parse") from None


class AdmissionStore(SQLiteDecisionEvidenceConsumptionStore):
    """Reuse atomic unique-key consumption; open-only, no implicit schema/provisioning."""
    def _connect(self):
        require(self._db_path.is_file() and not self._db_path.is_symlink(), "STORE_UNAVAILABLE", "replay")
        connection = sqlite3.connect(self._db_path.resolve().as_uri() + "?mode=rw", uri=True, timeout=0.1)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            columns = connection.execute("PRAGMA table_info(decision_evidence_consumption)").fetchall()
            require([(r[1], r[2], r[5]) for r in columns] == [
                ("replay_key", "TEXT", 1), ("replay_key_hash", "TEXT", 0),
                ("consumed_decision_evidence_hash", "TEXT", 0), ("consumed_at", "TEXT", 0),
                ("retention_seconds", "INTEGER", 0)], "STORE_SCHEMA", "replay")
            require(connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "STORE_CORRUPT", "replay")
            require(not connection.execute("SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view')").fetchone(), "STORE_SCHEMA", "replay")
            return connection
        except Exception:
            connection.close(); raise


def verify(packet, expected, config, policy, *, now=None):
    """Verifier-controlled context/trust; authentication precedes durable consumption."""
    now = time.time() if now is None else now
    try:
        validate_config(config)
        require(type(now) in (float,int) and math.isfinite(now), "TIME", "claims")
        value = decode(packet)
        require(isinstance(value, dict) and set(value) == {"response", "token"}, "ENVELOPE", "parse")
        response, token = value["response"], value["token"]
        fields = set(HydraNodeDecision("", "", "", "", "", 0).to_dict())
        require(isinstance(response, dict) and set(response) == fields, "RESPONSE", "binding")
        for key, item in response.items():
            if key in ("timestamp", "attestation_timestamp"):
                require(type(item) in (int, float) and math.isfinite(item), "RESPONSE", "binding")
            elif key == "hardware_backed": require(type(item) is bool, "RESPONSE", "binding")
            elif key == "signature": require(item is None, "RESPONSE", "binding")
            else: require(type(item) is str, "RESPONSE", "binding")
        require(response["hardware_backed"] is False and response["attestation_timestamp"] == 0 and
                all(response[k] == "" for k in ("attestation_hash","attestation_node_id","attestation_provider_mode")), "UNVERIFIED_HARDWARE", "binding")
        for key in ("node_id", "request_hash", "policy_version", "policy_hash", "nonce_hash", "tenant_id", "tenant_hash"):
            require(response[key] == expected[key], "SCOPE", "binding")
        require(response["node_role"] == expected["role"] and response["nonce_state"] == "unused" and
                response["replay_registry_hash"] == replay_registry_hash(expected["policy_hash"], expected["nonce_hash"]), "SCOPE", "binding")
        require(response["decision"] in ("allow", "deny") and len(response["reason"]) <= 128, "RESPONSE", "binding")
        require(type(token) is str and len(token) <= LIMIT and token.count(".") == 2, "JWT", "parse")
        parts = token.split(".")
        header, claims = decode(b64(parts[0])), decode(b64(parts[1]))
        require(isinstance(header, dict) and set(header) == {"alg","kid","typ"} and header["alg"] == "RS256" and header["typ"] == "JWT", "ALGORITHM", "signature")
        require(isinstance(claims, dict), "CLAIMS", "claims")
        require(config["snapshot_issued_at"] <= now < config["snapshot_expires_at"], "TRUST_STALE", "trust")
        key = config["keys"].get(header["kid"])
        require(isinstance(key, dict) and key.get("revoked") is False, "KEY", "trust")
        require(key["not_before"] <= now < key["not_after"], "KEY_STALE", "trust")
        public = serialization.load_pem_public_key(key["public_pem"].encode())
        require(isinstance(public, rsa.RSAPublicKey) and 2048 <= public.key_size <= 4096, "KEY", "signature")
        try: public.verify(b64(parts[2]), (parts[0]+"."+parts[1]).encode(), padding.PKCS1v15(), hashes.SHA256())
        except Exception: raise AttestationRejected("SIGNATURE", "signature") from None
        require(claims.get("iss") == config["issuer"] and claims.get("aud") == config["audience"], "ISSUER_AUDIENCE", "claims")
        for field in ("iat","nbf","exp"):
            require(type(claims.get(field)) is int, "TIME", "claims")
        ttl = policy["attestation_ttl_seconds"]
        require(claims["nbf"] <= now and claims["iat"] <= now < claims["exp"] and claims["exp"] > claims["iat"] and
                now - claims["iat"] <= ttl and claims["exp"] - claims["iat"] <= config["max_token_lifetime_seconds"] and
                key["not_before"] <= claims["iat"] < key["not_after"] and 0 <= now - response["timestamp"] <= ttl,
                "TIME", "claims")
        nonce = claims.get("eat_nonce")
        require(nonce == commitment(response, expected) or nonce == [commitment(response, expected)], "CHALLENGE_RESPONSE", "binding")
        enrollment = config["nodes"].get(expected["node_id"])
        require(isinstance(enrollment, dict) and enrollment["role"] == expected["role"] and expected["tenant_id"] in enrollment["tenants"], "ENROLLMENT", "identity")
        submods = claims.get("submods", {})
        require(isinstance(submods, dict), "MEASUREMENT", "identity")
        container, gce, space = submods.get("container",{}), submods.get("gce",{}), submods.get("confidential_space",{})
        image = enrollment["image_digest"]
        require(type(image) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", image), "TRUST", "identity")
        require(claims.get("sub") in enrollment["subjects"] and gce.get("project_id") == enrollment["project_id"] and
                gce.get("project_number") == enrollment["project_number"] and
                claims.get("google_service_accounts") == [enrollment["service_account"]], "WORKLOAD", "identity")
        require(container.get("image_digest") == image and container.get("image_reference") == enrollment["image_reference"] and
                container.get("args") == enrollment["args"] and container.get("cmd_override") == [] and
                container.get("env_override") == {} and container.get("env") == enrollment["env"], "MEASUREMENT", "identity")
        require(claims.get("dbgstat") == "disabled-since-boot" and claims.get("secboot") is True and claims.get("swname") == "CONFIDENTIAL_SPACE" and
                type(claims.get("swversion")) is list and len(claims["swversion"]) == 1 and
                claims["swversion"][0] in enrollment["swversions"] and claims.get("hwmodel") in enrollment["hardware_models"] and
                set(enrollment["hardware_models"]) <= MODELS and claims.get("oemid") == 11129 and
                isinstance(space.get("support_attributes"), list) and {"STABLE","USABLE"} <= set(space["support_attributes"]), "PLATFORM", "identity")
        require(expected["node_id"] in policy["enrolled_nodes"] and policy["required_attestation_mode"] == "external_attestation_service" and
                policy["enrolled_nodes"][expected["node_id"]]["role"] == expected["role"], "POLICY_NOT_APPROVED", "identity")
        replay_key = "sha256:" + digest({"domain":DOMAIN+"/admission", "scope":{k:v for k,v in expected.items() if k != "challenge"}})
        store = AdmissionStore(config["replay_db"])
        consumed = store.consume_if_unused(replay_key, replay_key_hash=replay_key,
            consumed_decision_evidence_hash="sha256:"+hashlib.sha256(packet if isinstance(packet,bytes) else packet.encode()).hexdigest(),
            retention_seconds=None, consumed_at=datetime.fromtimestamp(now,timezone.utc).isoformat())
        require(consumed.result == FIRST_CONSUMPTION, "REPLAY_OR_STORE_"+consumed.result, "replay")
        return replace(HydraNodeDecision.from_dict(response), attestation_timestamp=claims["iat"],
            attestation_hash=hashlib.sha256(token.encode()).hexdigest(), attestation_node_id=policy["enrolled_nodes"][expected["node_id"]]["node_id"],
            attestation_provider_mode="external_attestation_service", hardware_backed=True)
    except AttestationRejected:
        raise
    except Exception:
        raise AttestationRejected("INVALID_EVIDENCE_OR_TRUST", "verification") from None


def diagnostic(code, stage, node_id, request_hash, *, evidence=b"", worker_exit=None):
    safe = dict(code=code, stage=stage, node_id=node_id if type(node_id) is str and node_id in EXPECTED_NODE_ROLES else "unknown",
                correlation_hash=digest({"request_hash":request_hash,"node_id":node_id}),
                evidence_digest=hashlib.sha256(evidence).hexdigest(), worker_exit=worker_exit)
    logging.getLogger(__name__).warning("USBAY_CS_DIAGNOSTIC %s", canonical(safe).decode())


def worker_failure(raw, node_id, request_hash, returncode):
    diagnostic("WORKER_EXIT", "worker", node_id, request_hash, evidence=raw.encode(), worker_exit=returncode)
    try:
        value = decode(raw)
        require(set(value) == {"error"} and set(value["error"]) == {"code","stage"}, "WORKER_REPLY", "worker")
        code, stage = value["error"]["code"], value["error"]["stage"]
        require(type(code) is str and code in {"PROFILE","TRUST","TRUST_PERMISSIONS","SYNTHETIC_PROFILE","SOCKET","BACKEND_CONFLICT",
                "POLICY_NOT_APPROVED","CONTEXT","ORACLE_INPUT","NODE","REQUEST_SIGNATURE","REQUEST_BINDING",
                "REQUEST_FRESHNESS","POLICY_BINDING","DEADLINE","PROVIDER_REPLY","PROVIDER_UNAVAILABLE","JSON","DUPLICATE","SIZE","WORKER_REPLY"} and
                stage in {"configuration","producer","acquisition","parse","binding","claims","trust","signature","identity","verification","replay"}, "WORKER_REPLY", "worker")
        diagnostic(code, stage, node_id, request_hash, evidence=raw.encode(), worker_exit=returncode)
    except Exception:
        pass  # Never print untrusted stdout or exception text.


def evaluate(node_id, request_hash, policy_version, context):
    config, policy = settings()
    packet = produce(node_id, request_hash, policy_version, context, config, policy)
    verifier_config, verifier_policy = settings()  # re-read revocation/trust after acquisition
    result = verify(packet, scope(node_id, request_hash, policy_version, context), verifier_config, verifier_policy)
    diagnostic("VERIFIED", "admission", node_id, request_hash, evidence=packet)
    return result
