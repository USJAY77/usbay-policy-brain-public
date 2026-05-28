from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
import logging
import os
import hashlib
import html
import json
import shlex
import string
import time
import uuid
from pathlib import Path

forbidden_runtime_logger = logging.getLogger("usbay.gateway.forbidden_runtime")

from runtime import websocket_server
from utils.keystore import KeyStore
from security.compute_governance import compute_policy_state, validate_compute_request
from security.compute_router import ComputeRoutingError, route_execution
from security.decision_store import (
    DecisionStoreError,
    UnavailableDecisionStore,
    create_decision_store,
    decision_ttl_seconds,
    validate_decision_time,
    is_supported_alg_version,
    verify_submitted_decision_signatures,
    DECISION_CHAIN_GENESIS,
)
from security.deployment_attestation import (
    assert_startup_release_integrity,
    resolve_runtime_provenance_authority,
)
from governance.deployment_sync import (
    DeploymentCommitMismatchError,
    deployment_sync_snapshot,
    validate_deployment_commit_sync,
)
from governance_runtime_monitor import validate_runtime_governance_health
from governance.runtime_parity import (
    ATTESTATION_UNTRUSTED,
    create_runtime_manifest,
    canonical_governance_state_hash,
    runtime_attestation_parity_metadata,
    verify_runtime_attestation_parity,
)
from governance.deployment_runtime_health import (
    DeploymentRuntimeHealthError,
    deployment_runtime_health,
)
from governance.runtime_attestation_authority import runtime_attestation_from_environment
from governance.device_identity_lifecycle import (
    IDENTITY_VERIFIED,
    public_key_fingerprint as device_identity_public_key_fingerprint,
    validate_identity_packet,
)
from governance.remote_challenge_response import (
    CHALLENGE_RESPONSE_VALID,
    validate_challenge_response,
)
from governance.continuous_trust_renewal import (
    TRUST_RENEWAL_ACTIVE,
    validate_trust_renewal,
)
from governance.verifier_continuity import (
    VERIFIER_CONTINUITY_ACTIVE,
    VERIFIER_FAILOVER_ACTIVE,
    validate_verifier_continuity,
)
from governance.immutable_remote_attestation_ledger import (
    build_attestation_ledger_evidence,
    create_ledger_entry,
    ledger_summary,
    append_ledger_entry,
)
from security.hydra_consensus import (
    EXPECTED_NODE_ROLES,
    HydraConsensusResult,
    decide_consensus,
    evaluate_consensus,
    replay_registry_hash as hydra_replay_registry_hash,
)
from security.hydra_live_client import (
    collect_live_votes,
    default_live_node_clients,
)
from security.hydra_nodes import (
    collect_node_decisions,
    default_node_clients,
)
from security.node_identity import load_node_attestation_policy
from security.policy_registry import (
    current_policy_key_config_fingerprint,
    PolicyRegistryError,
    load_signed_policy_registry,
)
from security.request_signing import validate_request_signature, verify_request_signature
from security.tenant_context import load_tenant_policy, tenant_execution_context
from audit.hash_chain import append_event, verify_chain
from audit.hash_chain import load_chain
from audit.immutable_ledger import assert_ledger_valid, ledger_path_for
from audit.exporter import DEFAULT_EXPORT_FILE, export_audit_event


def is_redis_alive():
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        return False
    try:
        from security.decision_store import redis

        if redis is None:
            return False
        client = redis.Redis.from_url(redis_url, decode_responses=True)
        return client.ping() is True
    except Exception:
        return False


REDIS_ENABLED = is_redis_alive()


def require_redis():
    return os.getenv("REQUIRE_REDIS", "").lower() == "true"


def redis_available():
    return is_redis_alive()


def redis_dependency_state():
    available = redis_available()
    if require_redis() and not available:
        return False, "DEGRADED", "redis_unavailable"
    return available, "NORMAL", "ok"


def nonce_store_available():
    if require_redis():
        return redis_available()
    return True


def replay_protection_active():
    if require_redis():
        return redis_available()
    return nonce_store_available()


def redis_failure_reason(error=None):
    if error is None:
        return "redis_unavailable"
    reason = str(error)
    if reason in {
        "redis_required",
        "redis_unavailable",
        "decision_store_unavailable",
        "redis_unavailable_fail_closed",
    }:
        return "redis_unavailable"
    return reason or "redis_unavailable"

# -----------------------------
# NONCE STORAGE ADAPTER
# -----------------------------
# Redis is preferred for distributed replay protection.
# Local fallback exists only for development/test compatibility.
# No database is initialized in this module.
try:
    from security.redis_store import nonce_exists, store_nonce
except Exception:
    from security.store import nonce_exists, store_nonce

HYDRA_DENIED = "HYDRA_DENIED"
POLICY_DENIED = "POLICY_DENIED"
DEFAULT_POLICY_VERSION = "local-policy-v1"
DEFAULT_GATEWAY_ID = "gateway-1"
ALLOWED_EXECUTION_PREFIXES = (
    ("python3", "-m", "py_compile"),
    ("python3", "-m", "pytest"),
)
ALLOWED_METADATA_FIELDS = {
    "actor_hash",
    "request_hash",
}
FORBIDDEN_METADATA_FIELDS = {
    "full_ip_address",
    "ip_address",
    "raw_ip",
    "payment_id",
    "payment_identifier",
    "location",
    "precise_location",
    "device_fingerprint",
    "raw_device_fingerprint",
}
SIMULATION_REQUIRED_FIELDS = (
    "simulation_id",
    "purpose",
    "affected_system",
    "risk_level",
    "real_world_impact",
)
DEFAULT_POLICY_REGISTRY_PATH = Path("governance/policy_registry.json")
DEFAULT_POLICY_RELEASE_MANIFEST_PATH = Path("governance/policy_release_manifest.json")
DEFAULT_REPLAY_POLICY_PATH = Path("governance/replay_policy.json")
REPO_ROOT = Path(__file__).resolve().parents[1]
APPROVED_PUBLIC_PEM_PATHS = {
    "approvals/approver1_public_key.pem",
    "approvals/approver2_public_key.pem",
    "approvals/dev-ci/approver1_public_key.pem",
    "approvals/dev-ci/approver2_public_key.pem",
    "audit/public_key.pem",
    "keys_runtime/audit_ed25519.pub.pem",
    "keys_runtime/release_ed25519.pub.pem",
    "keys_runtime/root_authority_ed25519.pub.pem",
    "policy/public_key.pem",
    "python/audit/audit_seal_public_key.pem",
    "python/audit/keys/anchor_ed25519_public_key.pem",
    "python/audit/keys/audit_ed25519_public_key.pem",
    "python/audit/.embedded_trust/embedded_root_authority_public_key_0183f70ecb108985.pem",
}
POLICY_REGISTRY_PATH = Path(os.getenv("USBAY_POLICY_REGISTRY_PATH", str(DEFAULT_POLICY_REGISTRY_PATH)))
POLICY_REGISTRY_SIGNATURE_PATH = Path(
    os.getenv("USBAY_POLICY_REGISTRY_SIGNATURE_PATH", "governance/policy_registry.sig")
)
POLICY_REGISTRY_PUBLIC_KEY_PATH = Path(
    os.getenv("USBAY_POLICY_REGISTRY_PUBLIC_KEY_PATH", "governance/policy_public.key")
)
POLICY_RELEASE_MANIFEST_PATH = Path(
    os.getenv("USBAY_POLICY_RELEASE_MANIFEST_PATH", str(DEFAULT_POLICY_RELEASE_MANIFEST_PATH))
)
POLICY_KEY_CONFIG_PATH = Path(
    os.getenv("USBAY_POLICY_KEY_CONFIG_PATH", "governance/policy_key_config.json")
)
POLICY_AUTHORITY_PATH = Path(
    os.getenv("USBAY_POLICY_AUTHORITY_PATH", "governance/policy_authority.json")
)
REPLAY_POLICY_PATH = Path(os.getenv("USBAY_REPLAY_POLICY_PATH", str(DEFAULT_REPLAY_POLICY_PATH)))
REQUEST_SIGNING_KEY_CONFIG_PATH = Path(
    os.getenv("USBAY_REQUEST_SIGNING_KEY_CONFIG_PATH", "governance/request_signing_keys.json")
)
_policy_registry_cache = None
_policy_registry_cache_key = None
runtime_mode = "NORMAL"
runtime_reason = "ok"


@asynccontextmanager
async def lifespan(app_instance):
    validate_policy_registry_startup()
    validate_deployment_commit_sync(audit_hook=audit_chain.append)
    yield


app = FastAPI(lifespan=lifespan)


@app.middleware("http")
async def enforce_api_json_contract(request, call_next):
    # Defense-in-depth: any path under `/api/` must surface as JSON.
    # If a future route, a stray HTML response, or a mis-ordered
    # router ever returns text/html on an `/api/*` path, this
    # middleware rewrites it to a JSON 502 envelope so clients that
    # parse JSON never receive a dashboard HTML page in place of an
    # API response. Non-API paths (root dashboard, SPA fallback,
    # /assets/*, /audit/export/*, /replay/export/*) are untouched.
    response = await call_next(request)
    path = request.url.path or ""
    if not path.startswith("/api/") and path != "/api":
        return response
    content_type = (response.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    # Only HTML is the documented regression we are guarding against.
    # Legitimate non-JSON API responses (e.g. text/event-stream for
    # SSE, application/octet-stream for binary exports, application/
    # problem+json, empty bodies on 204) must pass through unmodified.
    if content_type != "text/html":
        return response
    return JSONResponse(
        status_code=502,
        content={
            "error": "api_contract_violation",
            "path": path,
            "reason": "html_response_on_api_path_blocked",
            "upstream_status": response.status_code,
            "upstream_content_type": content_type,
        },
    )


keystore = KeyStore()
hydra_node_clients = default_node_clients()
hydra_live_node_clients = default_live_node_clients()


# -------------------------
# COMPATIBILITY LAYERS
# -------------------------

class _NonceStoreCompat:
    def exists(self, nonce):
        return nonce_exists(nonce)

    def store(self, nonce, ts):
        return store_nonce(nonce, ts)

    def contains(self, nonce):
        return self.exists(nonce)

    def add(self, nonce):
        return self.store(nonce, int(time.time()))


class _AuditChainCompat:
    def append(self, action, decision):
        return append_event(action, decision)

    def append_event(self, action, decision):
        return append_event(action, decision)

    def load(self):
        return load_chain()

    def verify(self):
        return verify_chain()


# expose for tests
nonce_store = _NonceStoreCompat()
audit_chain = _AuditChainCompat()
audit_export_file = DEFAULT_EXPORT_FILE
try:
    decision_store = create_decision_store()
except DecisionStoreError as exc:
    decision_store = UnavailableDecisionStore(str(exc))


# -------------------------
# CORE LOGIC
# -------------------------

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def request_signature_message(payload):
    unsigned = payload.copy()
    unsigned.pop("signature", None)
    unsigned.pop("decision_id", None)
    unsigned.pop("decision_signature", None)
    unsigned.pop("decision_signature_classic", None)
    unsigned.pop("decision_signature_pqc", None)
    return canonical(unsigned)


def fail_closed(action=None):
    try:
        audit_chain.append(action or "unknown", "BLOCK")
    except Exception:
        pass

    return JSONResponse(
        status_code=403,
        content={"detail": "FAIL_CLOSED"}
    )


def runtime_status_snapshot():
    mode, reason, registry = policy_runtime_state()
    redis_ok, dependency_mode, dependency_reason = redis_dependency_state()
    replay_ok = replay_protection_active()
    compute_state = compute_policy_state()
    runtime_parity = runtime_attestation_parity_snapshot()
    device_identity = device_identity_lifecycle_snapshot(
        policy_version=str(registry.get("version", "")) if registry else "",
        policy_hash=str(registry.get("policy_hash", "")) if registry else "",
    )
    challenge_response = remote_challenge_response_snapshot(
        device_identity=device_identity,
        policy_hash=str(registry.get("policy_hash", "")) if registry else "",
    )
    trust_renewal = continuous_trust_renewal_snapshot(
        device_identity=device_identity,
        challenge_response=challenge_response,
        policy_hash=str(registry.get("policy_hash", "")) if registry else "",
    )
    verifier_continuity = verifier_continuity_snapshot(
        policy_hash=str(registry.get("policy_hash", "")) if registry else "",
    )
    trust_renewal = continuous_trust_renewal_snapshot(
        device_identity=device_identity,
        challenge_response=challenge_response,
        policy_hash=str(registry.get("policy_hash", "")) if registry else "",
    )
    return {
        "status": "OK" if registry is not None and mode == "NORMAL" and dependency_mode == "NORMAL" else "FAIL_CLOSED",
        "mode": mode if registry is not None else "FAIL_CLOSED",
        "reason": reason if registry is None or mode != "NORMAL" else dependency_reason,
        "policy_signature_valid": bool(registry and registry.get("policy_signature_valid") is True),
        "policy_version": registry.get("version") if registry else None,
        "policy_hash": registry.get("policy_hash") if registry else None,
        "redis_available": redis_ok,
        "replay_protection_active": replay_ok,
        "compute_policy_state": compute_state["state"],
        "websocket_clients": websocket_server.client_count(),
        "runtime_parity": runtime_parity,
        "device_identity": device_identity,
        "challenge_response": challenge_response,
        "trust_renewal": trust_renewal,
        "verifier_continuity": verifier_continuity,
        "device_trust_status": "VERIFIED"
        if device_identity.get("device_lifecycle_status") == "VERIFIED"
        and challenge_response.get("challenge_liveness_status") == "VERIFIED"
        and trust_renewal.get("trust_renewal_status") == "VERIFIED"
        and verifier_continuity.get("verifier_continuity_status") == "VERIFIED"
        else "DEGRADED",
    }


def device_identity_lifecycle_snapshot(*, policy_version: str = "", policy_hash: str = ""):
    packet_raw = os.getenv("USBAY_DEVICE_IDENTITY_PACKET_JSON", "").strip()
    try:
        packet = json.loads(packet_raw) if packet_raw else None
    except Exception:
        packet = {"identity_state": "IDENTITY_SIGNATURE_INVALID"}
    trusted_public_keys = {}
    trusted_public_key_pem = os.getenv("USBAY_DEVICE_IDENTITY_PUBLIC_KEY_PEM", "").strip()
    if trusted_public_key_pem:
        try:
            trusted_public_keys[device_identity_public_key_fingerprint(trusted_public_key_pem)] = trusted_public_key_pem
        except Exception:
            trusted_public_keys = {}
    result = validate_identity_packet(
        packet,
        trusted_public_keys=trusted_public_keys,
        expected_policy_version=policy_version,
        expected_policy_hash=policy_hash,
        active_challenges=_csv_env_set("USBAY_ACTIVE_DEVICE_CHALLENGE_IDS"),
        used_nonces=_csv_env_set("USBAY_USED_DEVICE_IDENTITY_NONCES"),
        revoked_device_fingerprints=_csv_env_set("USBAY_REVOKED_DEVICE_FINGERPRINTS"),
        revoked_public_key_fingerprints=_csv_env_set("USBAY_REVOKED_DEVICE_PUBLIC_KEY_FINGERPRINTS"),
        now_utc=os.getenv("USBAY_DEPLOYMENT_TIMESTAMP_UTC", "1970-01-01T00:00:00Z"),
    )
    payload = result.to_dict()
    payload["device_lifecycle_status"] = "VERIFIED" if result.verified and result.identity_state == IDENTITY_VERIFIED else "DEGRADED"
    return payload


def verifier_continuity_snapshot(*, policy_hash: str = ""):
    nodes_raw = os.getenv("USBAY_VERIFIER_CONTINUITY_NODES_JSON", "").strip()
    keys_raw = os.getenv("USBAY_VERIFIER_PUBLIC_KEYS_JSON", "").strip()
    try:
        nodes = json.loads(nodes_raw) if nodes_raw else None
    except Exception:
        nodes = [{"continuity_state": "VERIFIER_CONTINUITY_FAILED"}]
    try:
        trusted_public_keys = json.loads(keys_raw) if keys_raw else {}
        if not isinstance(trusted_public_keys, dict):
            trusted_public_keys = {}
    except Exception:
        trusted_public_keys = {}
    result = validate_verifier_continuity(
        nodes,
        trusted_public_keys=trusted_public_keys,
        expected_policy_hash=policy_hash,
        quorum_required=2,
        used_consensus_epochs=_csv_env_set("USBAY_USED_VERIFIER_CONSENSUS_EPOCHS"),
        now_utc=os.getenv("USBAY_DEPLOYMENT_TIMESTAMP_UTC", "1970-01-01T00:00:00Z"),
    )
    payload = result.to_dict()
    payload["verifier_continuity_status"] = (
        "VERIFIED"
        if result.verified and result.continuity_state in {VERIFIER_CONTINUITY_ACTIVE, VERIFIER_FAILOVER_ACTIVE}
        else "DEGRADED"
    )
    return payload


def continuous_trust_renewal_snapshot(*, device_identity=None, challenge_response=None, policy_hash: str = ""):
    packet_raw = os.getenv("USBAY_DEVICE_TRUST_RENEWAL_PACKET_JSON", "").strip()
    try:
        packet = json.loads(packet_raw) if packet_raw else None
    except Exception:
        packet = {"renewal_state": "TRUST_RENEWAL_FAILED"}
    trusted_public_keys = {}
    trusted_public_key_pem = os.getenv("USBAY_DEVICE_IDENTITY_PUBLIC_KEY_PEM", "").strip()
    identity = device_identity if isinstance(device_identity, dict) else {}
    challenge = challenge_response if isinstance(challenge_response, dict) else {}
    identity_evidence = identity.get("audit_evidence") if isinstance(identity.get("audit_evidence"), dict) else {}
    challenge_evidence = challenge.get("audit_evidence") if isinstance(challenge.get("audit_evidence"), dict) else {}
    expected_device_fingerprint = ""
    if identity.get("device_lifecycle_status") == "VERIFIED":
        expected_device_fingerprint = str(identity_evidence.get("device_id_fingerprint", ""))
    if trusted_public_key_pem and expected_device_fingerprint:
        trusted_public_keys[expected_device_fingerprint] = trusted_public_key_pem
    expected_previous_challenge_hash = ""
    if challenge.get("challenge_liveness_status") == "VERIFIED":
        expected_previous_challenge_hash = str(challenge_evidence.get("challenge_audit_hash", ""))
    result = validate_trust_renewal(
        packet,
        trusted_public_keys=trusted_public_keys,
        expected_device_identity_fingerprint=expected_device_fingerprint,
        expected_policy_hash=policy_hash,
        expected_previous_challenge_hash=expected_previous_challenge_hash,
        used_nonce_hashes=_csv_env_set("USBAY_USED_DEVICE_RENEWAL_NONCE_HASHES"),
        revoked_device_fingerprints=_csv_env_set("USBAY_REVOKED_DEVICE_FINGERPRINTS"),
        now_utc=os.getenv("USBAY_DEPLOYMENT_TIMESTAMP_UTC", "1970-01-01T00:00:00Z"),
    )
    payload = result.to_dict()
    payload["trust_renewal_status"] = (
        "VERIFIED" if result.verified and result.renewal_state == TRUST_RENEWAL_ACTIVE else "DEGRADED"
    )
    return payload


def remote_challenge_response_snapshot(*, device_identity=None, policy_hash: str = ""):
    packet_raw = os.getenv("USBAY_DEVICE_CHALLENGE_PACKET_JSON", "").strip()
    try:
        packet = json.loads(packet_raw) if packet_raw else None
    except Exception:
        packet = {"challenge_state": "CHALLENGE_RESPONSE_INVALID"}
    trusted_public_keys = {}
    trusted_public_key_pem = os.getenv("USBAY_DEVICE_IDENTITY_PUBLIC_KEY_PEM", "").strip()
    expected_device_fingerprint = ""
    identity = device_identity if isinstance(device_identity, dict) else {}
    audit_evidence = identity.get("audit_evidence") if isinstance(identity.get("audit_evidence"), dict) else {}
    if identity.get("device_lifecycle_status") == "VERIFIED":
        expected_device_fingerprint = str(audit_evidence.get("device_id_fingerprint", ""))
    if trusted_public_key_pem and expected_device_fingerprint:
        trusted_public_keys[expected_device_fingerprint] = trusted_public_key_pem
    result = validate_challenge_response(
        packet,
        trusted_public_keys=trusted_public_keys,
        expected_device_identity_fingerprint=expected_device_fingerprint,
        expected_policy_hash=policy_hash,
        issued_challenges=_csv_env_set("USBAY_ISSUED_DEVICE_CHALLENGE_IDS"),
        used_nonces=_csv_env_set("USBAY_USED_DEVICE_CHALLENGE_NONCES"),
        now_utc=os.getenv("USBAY_DEPLOYMENT_TIMESTAMP_UTC", "1970-01-01T00:00:00Z"),
    )
    payload = result.to_dict()
    payload["challenge_liveness_status"] = (
        "VERIFIED" if result.verified and result.challenge_state == CHALLENGE_RESPONSE_VALID else "DEGRADED"
    )
    return payload


def _csv_env_set(name: str) -> set[str]:
    return {item.strip() for item in os.getenv(name, "").split(",") if item.strip()}


def deployment_runtime_health_snapshot():
    try:
        entries = audit_chain.load() if hasattr(audit_chain, "load") else []
        return deployment_runtime_health(
            root=REPO_ROOT,
            runtime_snapshot=runtime_status_snapshot(),
            audit_chain_entries=entries,
        )
    except DeploymentRuntimeHealthError:
        return {
            "schema_version": "usbay.deployment_runtime_health.v1",
            "status": "BLOCKED",
            "startup_status": "FAILED",
            "reason_codes": ["STARTUP_FAILED", "DEPLOYMENT_RUNTIME_BLOCKED"],
        }


def signed_runtime_attestation_snapshot():
    entries = audit_chain.load() if hasattr(audit_chain, "load") else []
    audit_valid = bool(audit_chain.verify()) if hasattr(audit_chain, "verify") else False
    return runtime_attestation_from_environment(
        root=REPO_ROOT,
        deployment_health=deployment_runtime_health_snapshot(),
        runtime_snapshot=runtime_status_snapshot(),
        audit_chain_entries=entries,
        audit_chain_valid=audit_valid,
        deployment_timestamp_utc=os.getenv("USBAY_DEPLOYMENT_TIMESTAMP_UTC", "1970-01-01T00:00:00Z"),
    )


def runtime_attestation_ledger_snapshot(append: bool = False):
    entries = audit_chain.load() if hasattr(audit_chain, "load") else []
    deployment_health = deployment_runtime_health_snapshot()
    runtime_snapshot = runtime_status_snapshot()
    attestation = signed_runtime_attestation_snapshot()
    audit_chain_hash = _hash_text(canonical(entries))
    evidence = build_attestation_ledger_evidence(
        runtime_attestation=attestation,
        deployment_health=deployment_health,
        startup_verification=deployment_health,
        policy_version=str(runtime_snapshot.get("policy_version", "")),
        policy_hash=str(runtime_snapshot.get("policy_hash", "")),
        audit_chain_hash=audit_chain_hash,
    )
    ledger_path_env = os.getenv("USBAY_ATTESTATION_LEDGER_PATH", "").strip()
    if append and ledger_path_env:
        entry = append_ledger_entry(
            Path(ledger_path_env),
            evidence=evidence,
            timestamp_utc=os.getenv("USBAY_DEPLOYMENT_TIMESTAMP_UTC", "1970-01-01T00:00:00Z"),
            expected_policy_hash=str(runtime_snapshot.get("policy_hash", "")),
        )
        summary = ledger_summary(Path(ledger_path_env))
    else:
        entry = create_ledger_entry(
            evidence=evidence,
            previous_hash="0" * 64,
            sequence=1,
            timestamp_utc=os.getenv("USBAY_DEPLOYMENT_TIMESTAMP_UTC", "1970-01-01T00:00:00Z"),
            expected_policy_hash=str(runtime_snapshot.get("policy_hash", "")),
        )
        summary = {
            "schema_version": "usbay.immutable_remote_attestation_ledger.v1",
            "valid": True,
            "reason_codes": ["LEDGER_REMOTE_UNAVAILABLE"],
            "entry_count": 0,
            "head_hash": "0" * 64,
        }
    return {
        "ledger_entry": entry,
        "ledger_summary": summary,
    }


def _hash_text(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def runtime_provenance_fingerprint(commit_sha, policy_hash):
    configured = os.getenv("USBAY_GOVERNANCE_PROVENANCE_FINGERPRINT", "").strip()
    if configured:
        return configured
    return _hash_text(canonical({
        "commit_sha": commit_sha,
        "policy_hash": policy_hash,
        "provenance_trust": "HASH_ONLY_LOCAL",
        "signer_mode": "hash-only-local",
    }))


def runtime_attestation_parity_snapshot():
    try:
        authority = runtime_provenance_authority()
        provenance_context = authority.context_dict()
        registry = load_policy_registry(provenance_context=provenance_context)
        commit_sha = str(provenance_context.get("current_commit", ""))
        policy_hash = str(registry.get("policy_hash", ""))
        provenance_fingerprint = runtime_provenance_fingerprint(commit_sha, policy_hash)
        canonical_state = {
            "schema_version": "usbay.gateway_runtime_canonical_state.v1",
            "commit_sha": commit_sha,
            "policy_version_hash": policy_hash,
            "provenance_fingerprint": provenance_fingerprint,
            "authority_id_hash": _hash_text(getattr(authority, "authority_id", "")),
        }
        manifest = create_runtime_manifest(
            runtime_id=_hash_text(gateway_id()),
            runtime_version="usbay-runtime-governance-gateway-v1",
            commit_sha=commit_sha,
            policy_hash=policy_hash,
            provenance_fingerprint=provenance_fingerprint,
            deployment_mode=os.getenv("USBAY_DEPLOYMENT_MODE", "local-governed-runtime"),
            generated_at_utc=os.getenv("USBAY_RUNTIME_MANIFEST_GENERATED_AT", "1970-01-01T00:00:00Z"),
            canonical_governance_state_hash=canonical_governance_state_hash(canonical_state),
        )
        result = verify_runtime_attestation_parity(
            manifest,
            canonical_state,
            expected_commit_sha=commit_sha,
            expected_policy_hash=policy_hash,
            expected_provenance_fingerprint=provenance_fingerprint,
        )
        return runtime_attestation_parity_metadata(result)
    except Exception:
        return {
            "runtime_parity_status": ATTESTATION_UNTRUSTED,
            "manifest_hash": "",
            "policy_hash": "",
            "provenance_fingerprint": "",
            "reason_codes": ["RUNTIME_ATTESTATION_UNTRUSTED"],
            "provenance_trust": "HASH_ONLY_LOCAL",
            "attestation": "NOT_ENTERPRISE_SIGNED",
        }


def replay_policy_config():
    defaults = {
        "nonce_ttl_seconds": 300,
        "timestamp_skew_seconds": 30,
        "replay_fail_closed": True,
    }
    try:
        raw = json.loads(REPLAY_POLICY_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raw = {}
    except Exception as exc:
        raise DecisionStoreError("invalid_replay_policy:json") from exc
    if not isinstance(raw, dict):
        raise DecisionStoreError("invalid_replay_policy:root")
    config = defaults | raw
    if "timestamp_skew_seconds" not in raw and "max_clock_skew_seconds" in raw:
        config["timestamp_skew_seconds"] = raw["max_clock_skew_seconds"]
    if "nonce_ttl_seconds" not in raw and "max_request_age_seconds" in raw:
        config["nonce_ttl_seconds"] = raw["max_request_age_seconds"]
    env_map = {
        "nonce_ttl_seconds": "USBAY_NONCE_TTL_SECONDS",
        "timestamp_skew_seconds": "USBAY_TIMESTAMP_SKEW_SECONDS",
    }
    for key, env_name in env_map.items():
        if os.getenv(env_name):
            config[key] = os.getenv(env_name)
    if os.getenv("USBAY_MAX_CLOCK_SKEW_SECONDS") and not os.getenv("USBAY_TIMESTAMP_SKEW_SECONDS"):
        config["timestamp_skew_seconds"] = os.getenv("USBAY_MAX_CLOCK_SKEW_SECONDS")
    if os.getenv("USBAY_REPLAY_FAIL_CLOSED"):
        config["replay_fail_closed"] = os.getenv("USBAY_REPLAY_FAIL_CLOSED", "").lower() == "true"
    normalized = {}
    for key in ("nonce_ttl_seconds", "timestamp_skew_seconds"):
        value = config.get(key)
        try:
            normalized[key] = int(value)
        except Exception:
            raise DecisionStoreError(f"invalid_replay_policy:{key}")
        if normalized[key] <= 0:
            raise DecisionStoreError(f"invalid_replay_policy:{key}")
    if config.get("replay_fail_closed") is not True:
        raise DecisionStoreError("invalid_replay_policy:replay_fail_closed")
    normalized["replay_fail_closed"] = True
    return normalized


def validate_replay_policy_startup():
    config = replay_policy_config()
    if config.get("replay_fail_closed") is not True:
        raise DecisionStoreError("invalid_replay_policy:replay_fail_closed")
    return True


def validate_hydra_consensus_startup():
    expected_roles = {
        "node-1": "primary",
        "node-2": "secondary",
        "node-3": "offline_backup",
    }
    if EXPECTED_NODE_ROLES != expected_roles:
        raise DecisionStoreError("invalid_hydra_consensus_roles")
    attestation_policy = load_node_attestation_policy()
    for node_id, role in expected_roles.items():
        enrolled = attestation_policy["enrolled_nodes"].get(node_id)
        if not enrolled or enrolled.get("role") != role:
            raise DecisionStoreError("invalid_node_attestation_policy:enrolled_nodes")
    return True


def request_hash(signature_body):
    return hashlib.sha256(signature_body.encode()).hexdigest()


def command_hash(command):
    return hashlib.sha256(str(command).encode("utf-8")).hexdigest()


def nonce_hash(nonce):
    return hashlib.sha256(str(nonce).encode("utf-8")).hexdigest()


def actor_hash(actor_id):
    return hashlib.sha256(str(actor_id).encode("utf-8")).hexdigest()


def gateway_id():
    return os.getenv("USBAY_GATEWAY_ID", DEFAULT_GATEWAY_ID)


def _policy_version(payload):
    policy_version = payload.get("policy_version") or DEFAULT_POLICY_VERSION
    return str(policy_version)


def runtime_provenance_authority():
    return resolve_runtime_provenance_authority()


def runtime_provenance_context():
    return runtime_provenance_authority().context_dict()


def policy_signature_mode(registry=None, provenance_context=None):
    registry = registry or load_policy_registry(provenance_context=provenance_context)
    mode = str(registry.get("signature_policy_mode", "STRICT")).upper()
    if mode not in {"STRICT", "COMPAT", "TRANSITION"}:
        raise PolicyRegistryError("signature_policy_mode_invalid")
    configured_mode = os.getenv("USBAY_SIGNATURE_POLICY_MODE") or os.getenv("signature_policy_mode")
    if configured_mode and configured_mode.upper() != mode:
        raise PolicyRegistryError("signature_policy_mode_mismatch")
    return mode


def _request_policy_version(payload):
    policy_version = payload.get("policy_version")
    if not policy_version:
        return None
    return str(policy_version)


def clear_policy_registry_cache():
    global _policy_registry_cache, _policy_registry_cache_key
    _policy_registry_cache = None
    _policy_registry_cache_key = None


def load_policy_registry(provenance_context=None):
    global _policy_registry_cache, _policy_registry_cache_key
    normalized_context = provenance_context or runtime_provenance_context()
    release_manifest_path = policy_release_manifest_path()
    authority_path = policy_authority_path()
    cache_key = (
        canonical(normalized_context),
        str(POLICY_REGISTRY_PATH),
        str(POLICY_REGISTRY_SIGNATURE_PATH),
        str(POLICY_REGISTRY_PUBLIC_KEY_PATH),
        str(release_manifest_path),
        str(POLICY_KEY_CONFIG_PATH),
        str(authority_path),
        _path_mtime(POLICY_REGISTRY_PATH),
        _path_mtime(POLICY_REGISTRY_SIGNATURE_PATH),
        _path_mtime(POLICY_REGISTRY_PUBLIC_KEY_PATH),
        _path_mtime(release_manifest_path),
        _path_mtime(POLICY_KEY_CONFIG_PATH),
        _path_mtime(authority_path) if authority_path is not None else None,
        current_policy_key_config_fingerprint(POLICY_KEY_CONFIG_PATH),
    )
    if _policy_registry_cache is not None and _policy_registry_cache_key == cache_key:
        return _policy_registry_cache
    _policy_registry_cache = load_signed_policy_registry(
        POLICY_REGISTRY_PATH,
        POLICY_REGISTRY_SIGNATURE_PATH,
        POLICY_REGISTRY_PUBLIC_KEY_PATH,
        POLICY_KEY_CONFIG_PATH,
        release_manifest_path,
        authority_path,
        normalized_context,
    )
    _policy_registry_cache_key = cache_key
    return _policy_registry_cache


def policy_release_manifest_path():
    if (
        POLICY_RELEASE_MANIFEST_PATH == DEFAULT_POLICY_RELEASE_MANIFEST_PATH
        and POLICY_REGISTRY_PATH != DEFAULT_POLICY_REGISTRY_PATH
    ):
        return POLICY_REGISTRY_PATH.parent / DEFAULT_POLICY_RELEASE_MANIFEST_PATH.name
    return POLICY_RELEASE_MANIFEST_PATH


def policy_authority_path():
    if POLICY_REGISTRY_PATH != DEFAULT_POLICY_REGISTRY_PATH:
        candidate = POLICY_REGISTRY_PATH.parent / "policy_authority.json"
        if candidate.exists():
            return candidate
        return None
    if POLICY_AUTHORITY_PATH.exists():
        return POLICY_AUTHORITY_PATH
    return None


def _path_mtime(path):
    try:
        return Path(path).stat().st_mtime_ns
    except Exception:
        return None


def _is_public_key_artifact(path):
    name = path.name.lower()
    if "public" in name or name.endswith(".pub.pem"):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="ignore")[:200]
    except Exception:
        return False
    return "PUBLIC KEY" in head and "PRIVATE KEY" not in head


def _is_approved_public_pem_path(relative_path):
    return relative_path in APPROVED_PUBLIC_PEM_PATHS


def _has_public_pem_naming(relative_path):
    """Return True when the filename follows the deterministic public
    verification PEM naming convention.

    Two suffixes are recognised:
      - ``*.pub.pem``         (e.g. ``release_ed25519.pub.pem``)
      - ``*_public_key.pem``  (e.g. ``approver1_public_key.pem``)

    Naming alone is not sufficient to allow a file -- the validator
    additionally requires that the PEM body contain a ``PUBLIC KEY``
    block and no ``PRIVATE KEY`` block. This deliberately avoids
    globally whitelisting arbitrary ``.pem`` files.
    """
    name = Path(relative_path).name.lower()
    return name.endswith(".pub.pem") or name.endswith("_public_key.pem")


def _pem_content_is_public_only(path):
    """Strict content-based check: PEM contains a PUBLIC KEY block
    and contains no PRIVATE KEY block. Reads up to 1 MiB; larger
    files are rejected as not-public to stay fail-closed.
    """
    try:
        if path.stat().st_size > 1_048_576:
            return False
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False
    private_markers = (
        "BEGIN " + "PRIVATE KEY",
        "BEGIN RSA " + "PRIVATE KEY",
        "BEGIN OPENSSH " + "PRIVATE KEY",
        "BEGIN EC " + "PRIVATE KEY",
        "BEGIN DSA " + "PRIVATE KEY",
    )
    if any(marker in text for marker in private_markers):
        return False
    return "PUBLIC KEY" in text


FORBIDDEN_RUNTIME_RULE_DOTENV_FILE = "dotenv_file"
FORBIDDEN_RUNTIME_RULE_SECRETS_DIRECTORY = "secrets_directory"
FORBIDDEN_RUNTIME_RULE_TMP_PRIVATE_ARTIFACT = "tmp_private_artifact"
FORBIDDEN_RUNTIME_RULE_PEM_UNAPPROVED_PATH = "pem_unapproved_path"
FORBIDDEN_RUNTIME_RULE_PEM_NOT_PUBLIC_KEY = "pem_not_public_key_artifact"
FORBIDDEN_RUNTIME_RULE_KEY_EXTENSION_NOT_PUBLIC = "key_extension_not_public"
FORBIDDEN_RUNTIME_RULE_PRIVATE_KEY_MARKER = "private_key_marker_in_text"


def forbidden_runtime_file_findings(repo_root=None):
    """Return structured forbidden-runtime-file findings.

    Each entry is ``{"path": <repo-relative posix path>,
    "rule": <stable identifier>}``. Paths only -- file contents are
    never returned. Used by ``validate_no_forbidden_runtime_files``
    for fail-closed auditable logging; callers that only need the
    path list should use ``forbidden_runtime_files_in_repo``.
    """
    root = Path(repo_root or REPO_ROOT)
    # Directories excluded from the runtime forbidden-file scan
    # because they are not deployable / runtime-reachable artifacts.
    # The runtime validator's job is to keep secrets and private key
    # material out of the *runtime* surface; deterministic test
    # fixtures, vendored dependencies, and build outputs are not part
    # of that surface and would otherwise generate false positives
    # (e.g. test files that contain the literal PEM private-key
    # block header as part of negative-path assertions; the marker
    # string is intentionally not spelled out here to avoid the
    # validator flagging its own source code).
    excluded_dirs = {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        "node_modules",
        ".cache",
        ".local",
        ".upm",
        ".pythonlibs",
        "attached_assets",
        "artifacts",
        "dist",
        "build",
        ".next",
        # Test scope: pytest tests, fixtures, mock assets. These
        # files are excluded by `pytest.ini --ignore` / not loaded by
        # the gateway at runtime, so they are out of scope for
        # forbidden-runtime-file enforcement.
        "tests",
        "test",
        "fixtures",
        "test_fixtures",
        "testdata",
        "test_data",
    }
    findings = []
    for dirpath, dirnames, filenames in os.walk(str(root)):
        dirnames[:] = [d for d in dirnames if d not in excluded_dirs]
        for filename in filenames:
            path = Path(dirpath) / filename
            if not path.is_file():
                continue
            try:
                relative = path.relative_to(root)
            except ValueError:
                continue
            rel = relative.as_posix()
            name = path.name.lower()
            if name == ".env" or path.suffix == ".env":
                findings.append({"path": rel, "rule": FORBIDDEN_RUNTIME_RULE_DOTENV_FILE})
                continue
            if rel.startswith("secrets/"):
                findings.append({"path": rel, "rule": FORBIDDEN_RUNTIME_RULE_SECRETS_DIRECTORY})
                continue
            if rel.startswith("tmp/") and "private" in name:
                findings.append({"path": rel, "rule": FORBIDDEN_RUNTIME_RULE_TMP_PRIVATE_ARTIFACT})
                continue
            if path.suffix.lower() == ".pem":
                # Two independent allow-paths:
                #   (a) the file is on the explicit APPROVED_PUBLIC_PEM_PATHS
                #       whitelist (legacy / non-conventional paths), or
                #   (b) the filename follows the deterministic public
                #       verification naming convention (`*.pub.pem`
                #       or `*_public_key.pem`).
                # In BOTH cases the PEM body must contain a PUBLIC KEY
                # block and no PRIVATE KEY block. This refines
                # classification without globally whitelisting `.pem`.
                whitelisted = _is_approved_public_pem_path(rel)
                public_named = _has_public_pem_naming(rel)
                if not (whitelisted or public_named):
                    findings.append({"path": rel, "rule": FORBIDDEN_RUNTIME_RULE_PEM_UNAPPROVED_PATH})
                    continue
                if not _pem_content_is_public_only(path):
                    findings.append({"path": rel, "rule": FORBIDDEN_RUNTIME_RULE_PEM_NOT_PUBLIC_KEY})
                    continue
            if path.suffix.lower() == ".key" and not _is_public_key_artifact(path):
                findings.append({"path": rel, "rule": FORBIDDEN_RUNTIME_RULE_KEY_EXTENSION_NOT_PUBLIC})
                continue
            try:
                if path.stat().st_size > 1_048_576:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            private_markers = (
                "BEGIN " + "PRIVATE KEY",
                "BEGIN RSA " + "PRIVATE KEY",
                "BEGIN OPENSSH " + "PRIVATE KEY",
            )
            if any(marker in text for marker in private_markers):
                findings.append({"path": rel, "rule": FORBIDDEN_RUNTIME_RULE_PRIVATE_KEY_MARKER})
    return sorted(findings, key=lambda entry: (entry["path"], entry["rule"]))


def forbidden_runtime_files_in_repo(repo_root=None):
    seen = []
    seen_set = set()
    for entry in forbidden_runtime_file_findings(repo_root):
        if entry["path"] not in seen_set:
            seen.append(entry["path"])
            seen_set.add(entry["path"])
    return seen


def validate_no_forbidden_runtime_files(repo_root=None):
    findings = forbidden_runtime_file_findings(repo_root)
    if findings:
        # Emit one structured log line per offender so deployment
        # operators can identify exactly which runtime file tripped
        # the fail-closed gate and which rule matched. Only the
        # repo-relative path and the rule identifier are emitted --
        # file contents are never read into the log.
        for entry in findings:
            forbidden_runtime_logger.error(
                "forbidden_runtime_file_present path=%s rule=%s",
                entry["path"],
                entry["rule"],
            )
        diagnostics = {"findings": findings, "count": len(findings)}
        detail = json.dumps(diagnostics, sort_keys=True, separators=(",", ":"))
        error = PolicyRegistryError(
            "forbidden_runtime_file_present: " + detail
        )
        # Attach structured diagnostics for programmatic consumers
        # (audit pipelines, tests) without leaking file contents.
        error.findings = list(findings)
        error.diagnostics = diagnostics
        raise error
    return True


def private_key_files_in_repo(repo_root=None):
    return [
        finding
        for finding in forbidden_runtime_files_in_repo(repo_root)
        if "private" in Path(finding).name.lower() or finding.endswith(".env") or finding == ".env"
    ]


def validate_no_private_keys_in_repo(repo_root=None):
    return validate_no_forbidden_runtime_files(repo_root)


def expected_policy_hash():
    value = os.getenv("USBAY_EXPECTED_POLICY_HASH", "").strip()
    return value or None


def policy_runtime_state(provenance_context=None):
    global runtime_mode, runtime_reason
    normalized_context = provenance_context or runtime_provenance_context()
    try:
        registry = load_policy_registry(provenance_context=normalized_context)
    except PolicyRegistryError as exc:
        runtime_mode = "DEGRADED"
        runtime_reason = str(exc)
        return runtime_mode, runtime_reason, None
    except Exception:
        runtime_mode = "DEGRADED"
        runtime_reason = "policy_registry_unavailable"
        return runtime_mode, runtime_reason, None

    expected_hash = expected_policy_hash()
    if expected_hash and registry.get("policy_hash") != expected_hash:
        runtime_mode = "DEGRADED"
        runtime_reason = "policy_hash_mismatch"
        return runtime_mode, runtime_reason, registry

    runtime_mode = "NORMAL"
    runtime_reason = "ok"
    return runtime_mode, runtime_reason, registry


def validate_policy_registry_startup():
    validate_no_forbidden_runtime_files()
    authority = runtime_provenance_authority()
    normalized_context = authority.context_dict()
    load_tenant_policy()
    validate_replay_policy_startup()
    validate_hydra_consensus_startup()
    assert_startup_release_integrity(expected_provenance_context=normalized_context)
    validate_runtime_governance_health(authority=authority, release_path=authority.release_path)
    ledger_path = ledger_path_for(getattr(audit_chain, "path", Path("tmp/audit_chain.json")))
    if ledger_path.exists():
        assert_ledger_valid(ledger_path)
    load_policy_registry(provenance_context=normalized_context)


def execution_command_allowed(command):
    try:
        parts = shlex.split(str(command))
    except ValueError:
        return False

    return any(
        tuple(parts[:len(prefix)]) == prefix
        for prefix in ALLOWED_EXECUTION_PREFIXES
    )


def validate_metadata(payload):
    if not isinstance(payload, dict):
        return "DENY", "metadata_invalid"

    metadata = payload.get("metadata", {})
    if metadata in (None, ""):
        metadata = {}
    if not isinstance(metadata, dict):
        return "DENY", "metadata_invalid"

    for field in FORBIDDEN_METADATA_FIELDS:
        if field in payload or field in metadata:
            return "DENY", f"metadata_forbidden:{field}"

    for field in metadata:
        if field not in ALLOWED_METADATA_FIELDS:
            return "DENY", f"metadata_unknown:{field}"

    return "ALLOW", "metadata_allowed"


def _contains_sensitive_log_data(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in FORBIDDEN_METADATA_FIELDS or key in {
                "raw_sensitive_data",
                "raw_payload",
                "raw_prompt",
                "secret",
                "token",
            }:
                return True
            if _contains_sensitive_log_data(item):
                return True
    elif isinstance(value, list):
        return any(_contains_sensitive_log_data(item) for item in value)
    return False


def validate_simulation(payload, provenance_context=None):
    if not isinstance(payload, dict):
        return "DENY", "simulation_invalid"
    if payload.get("type") not in {"simulation", "simulated_experiment"}:
        return "ALLOW", "not_simulation"
    if not payload.get("actor_id"):
        return "DENY", "missing_actor"
    for field in SIMULATION_REQUIRED_FIELDS:
        if payload.get(field) in (None, ""):
            return "DENY", f"simulation_missing:{field}"
    if str(payload.get("real_world_impact", "")).lower() == "unknown":
        return "DENY", "simulation_unknown_real_world_impact"
    try:
        registry = load_policy_registry(provenance_context=provenance_context)
    except PolicyRegistryError as exc:
        return "DENY", str(exc)
    except Exception:
        return "DENY", "policy_registry_unavailable"
    affected_system = str(payload.get("affected_system", "")).lower()
    critical_systems = set(registry["critical_infrastructure"])
    if affected_system not in critical_systems and affected_system != "sandbox":
        return "DENY", "simulation_unknown_affected_system"
    if affected_system in critical_systems and payload.get("human_review") is not True:
        return "DENY", "simulation_requires_human_review"
    if _contains_sensitive_log_data(payload.get("simulation_logs", {})):
        return "DENY", "simulation_logs_sensitive_data"
    return "ALLOW", "simulation_allowed"


def build_hydra_decisions(request_hash_value, policy_version, real_decision=None, ts=None, context=None):
    return collect_node_decisions(
        request_hash=request_hash_value,
        policy_version=policy_version,
        clients=hydra_node_clients,
        context=context or {},
    )


def evaluate_hydra_request(request_hash_value, policy_version, action="", context=None):
    if os.getenv("HYDRA_NODE_URLS") or os.getenv("USBAY_HYDRA_BACKEND", "").lower() == "services":
        votes = collect_live_votes(
            request_hash=request_hash_value,
            policy_version=policy_version,
            action=action,
            context=context or {},
            clients=hydra_live_node_clients,
        )
        final_decision = decide_consensus(votes)
        votes_allow = sum(
            1 for vote in votes
            if vote.get("valid") is True and vote.get("decision") == "ALLOW"
        )
        votes_deny = sum(
            1 for vote in votes
            if vote.get("valid") is True and vote.get("decision") == "DENY"
        )
        return HydraConsensusResult(
            final_decision=final_decision.lower(),
            consensus_reached=final_decision == "ALLOW" or votes_deny >= 2,
            votes_allow=votes_allow,
            votes_deny=votes_deny,
            required_votes=2,
            node_decisions=[],
            reason="live_hydra_services",
        )

    hydra_context = context or {}
    return evaluate_consensus(
        build_hydra_decisions(request_hash_value, policy_version, context=hydra_context),
        expected_policy_hash=hydra_context.get("policy_hash"),
        expected_nonce_hash=hydra_context.get("nonce_hash"),
        expected_replay_registry_hash=hydra_context.get("replay_registry_hash"),
        provenance_context=hydra_context.get("normalized_provenance_context"),
    )


def audit_hydra_consensus(result):
    reason = str(result.reason)
    action = "consensus_allow" if result.final_decision == "allow" and result.consensus_reached else "consensus_deny"
    audit_chain.append(
        action,
        {
            "final_decision": result.final_decision,
            "votes_allow": result.votes_allow,
            "votes_deny": result.votes_deny,
            "tenant_id": (result.evidence_bundle or {}).get("tenant_id"),
            "tenant_hash": (result.evidence_bundle or {}).get("tenant_hash"),
            "consensus": result.consensus_reached,
            "reason_code": reason,
            "consensus_allow": action == "consensus_allow",
            "consensus_deny": action == "consensus_deny",
            "node_stale": reason == "node_stale",
            "policy_hash_mismatch": reason == "policy_hash_mismatch",
            "replay_registry_divergence": reason == "replay_registry_divergence",
            "quorum_unavailable": reason == "quorum_unavailable",
            "evidence_hash": (result.evidence_bundle or {}).get("sha256_evidence_hash"),
            "attestation_evidence_hash": (result.evidence_bundle or {}).get("attestation_evidence_hash"),
            "consensus_signature": (result.evidence_bundle or {}).get("consensus_signature"),
        },
    )


def hydra_denial_reason(result):
    reason = str(getattr(result, "reason", "") or "")
    return {
        "node_disagreement": "split_brain_denied",
        "quorum_unavailable": "no_majority",
        "fewer_than_3_decisions": "no_majority",
        "consensus_not_reached": "no_majority",
        "node_stale": "stale_node_state",
    }.get(reason, "hydra_denied")


def audit_execution_decision(command, decision, hydra_result=None, tenant_id=None):
    event = {
        "decision": decision,
        "timestamp": int(time.time()),
    }
    if hydra_result is not None:
        event["tenant_id"] = (hydra_result.evidence_bundle or {}).get("tenant_id")
        event["tenant_hash"] = (hydra_result.evidence_bundle or {}).get("tenant_hash")
    elif tenant_id:
        tenant_context = tenant_execution_context(tenant_id)
        event["tenant_id"] = tenant_context["tenant_id"]
        event["tenant_hash"] = tenant_context["tenant_hash"]
    if hydra_result is not None:
        event["consensus"] = {
            "final_decision": hydra_result.final_decision,
            "votes_allow": hydra_result.votes_allow,
            "votes_deny": hydra_result.votes_deny,
            "consensus_reached": hydra_result.consensus_reached,
        }
    audit_chain.append("execution_governance", event)


def audit_governance_event(action, event):
    safe_event = {
        "event_type": action,
        "decision_id": event.get("decision_id"),
        "request_hash": event.get("request_hash"),
        "policy_version": event.get("policy_version"),
        "reason_code": event.get("reason_code", event.get("reason")),
        "decision": event.get("decision"),
        "node_id": event.get("node_id", event.get("gateway_id")),
        "nonce_hash": event.get("nonce_hash"),
        "actor_hash": event.get("actor_hash"),
        "created_at": event.get("created_at"),
        "expires_at": event.get("expires_at"),
        "used": event.get("used"),
        "simulation_id": event.get("simulation_id"),
        "audit_hash": event.get("audit_hash"),
        "risk_level": event.get("risk_level"),
        "policy_hash": event.get("policy_hash"),
        "tenant_id": event.get("tenant_id"),
        "tenant_hash": event.get("tenant_hash"),
        "policy_signature_valid": event.get("policy_signature_valid"),
        "signature_valid": event.get("signature_valid"),
        "policy_pubkey_id": event.get("policy_pubkey_id"),
        "compute_target": event.get("compute_target"),
        "compute_policy_hash": event.get("compute_policy_hash"),
        "compute_risk_level": event.get("compute_risk_level"),
        "human_review": event.get("human_review"),
        "data_sensitivity": event.get("data_sensitivity"),
        "execution_location": event.get("execution_location"),
        "actual_execution_target": event.get("actual_execution_target"),
        "execution_verified": event.get("execution_verified"),
        "replay_detected": event.get("replay_detected"),
        "timestamp_invalid": event.get("timestamp_invalid"),
        "nonce_expired": event.get("nonce_expired"),
        "attestation_evidence_hash": event.get("attestation_evidence_hash"),
        "consensus_evidence_hash": event.get("consensus_evidence_hash"),
        "timestamp": event.get("timestamp"),
    }
    audit_chain.append(action, safe_event)


def _safe_policy_pubkey_id(provenance_context=None):
    if provenance_context is None:
        return None
    try:
        registry = load_policy_registry(provenance_context=provenance_context)
        return registry.get("policy_pubkey_id")
    except Exception:
        return None


def _deny_decision_response(reason, status_code=403, payload=None, decision_id=None, provenance_context=None):
    tenant_context = tenant_execution_context(payload.get("tenant_id")) if isinstance(payload, dict) and payload.get("tenant_id") else {}
    event = {
        "decision_id": decision_id,
        "request_hash": request_hash(request_signature_message(payload)) if isinstance(payload, dict) else None,
        "decision": "DENY",
        "policy_version": _policy_version(payload) if isinstance(payload, dict) else None,
        "nonce_hash": nonce_hash(payload.get("nonce", "")) if isinstance(payload, dict) else None,
        "actor_hash": actor_hash(payload.get("actor_id", "")) if isinstance(payload, dict) and payload.get("actor_id") else None,
        "created_at": int(time.time()),
        "expires_at": None,
        "used": None,
        "reason_code": reason,
        "timestamp": int(time.time()),
        "tenant_id": tenant_context.get("tenant_id"),
        "tenant_hash": tenant_context.get("tenant_hash"),
        "policy_pubkey_id": _safe_policy_pubkey_id(provenance_context),
    }
    try:
        audit_governance_event("execution_denied", event)
    except Exception:
        pass
    return JSONResponse(status_code=status_code, content={"error": reason})


def _safe_request_hash(payload):
    if not isinstance(payload, dict):
        return None
    try:
        return request_hash(request_signature_message(payload))
    except Exception:
        return None


def audit_replay_security_event(reason, payload=None, decision_id=None, provenance_context=None):
    tenant_context = tenant_execution_context(payload.get("tenant_id")) if isinstance(payload, dict) and payload.get("tenant_id") else {}
    event = {
        "decision_id": decision_id,
        "request_hash": _safe_request_hash(payload),
        "decision": "DENY",
        "policy_version": _policy_version(payload) if isinstance(payload, dict) else None,
        "nonce_hash": nonce_hash(payload.get("nonce", "")) if isinstance(payload, dict) else None,
        "reason_code": reason,
        "timestamp": int(time.time()),
        "tenant_id": tenant_context.get("tenant_id"),
        "tenant_hash": tenant_context.get("tenant_hash"),
        "policy_pubkey_id": _safe_policy_pubkey_id(provenance_context),
        "policy_hash": None,
        "node_id": gateway_id(),
        "replay_detected": reason == "replay_detected",
        "timestamp_invalid": reason == "timestamp_invalid",
        "nonce_expired": reason == "nonce_expired",
    }
    try:
        if provenance_context is None:
            raise PolicyRegistryError("provenance_context_unavailable")
        registry = load_policy_registry(provenance_context=provenance_context)
        event["policy_hash"] = registry.get("policy_hash")
    except Exception:
        event["policy_hash"] = None
    try:
        audit_governance_event("replay_security_event", event)
    except Exception:
        pass


def _signature_valid(payload):
    return verify_request_signature(payload, REQUEST_SIGNING_KEY_CONFIG_PATH)


def _signature_validation(payload):
    return validate_request_signature(payload, REQUEST_SIGNING_KEY_CONFIG_PATH)


def validate_request_timestamp(payload):
    if not isinstance(payload, dict):
        return False, "timestamp_invalid", None
    if payload.get("timestamp") is None:
        return False, "timestamp_invalid", None
    try:
        ts = int(payload.get("timestamp"))
    except Exception:
        return False, "timestamp_invalid", None
    try:
        config = replay_policy_config()
    except DecisionStoreError:
        return False, "timestamp_invalid", ts
    now = int(time.time())
    if ts < now - config["nonce_ttl_seconds"]:
        return False, "nonce_expired", ts
    if ts > now + config["timestamp_skew_seconds"]:
        return False, "timestamp_invalid", ts
    return True, "ok", ts


def _basic_request_valid(payload):
    if not isinstance(payload, dict):
        return False, "malformed_request"
    if not payload.get("tenant_id") or not payload.get("device"):
        return False, "malformed_request"
    if not payload.get("nonce"):
        return False, "malformed_request"
    if not payload.get("actor_id"):
        return False, "malformed_request"
    timestamp_valid, timestamp_reason, _ts = validate_request_timestamp(payload)
    if not timestamp_valid:
        return False, timestamp_reason
    return True, "ok"


def create_governance_decision(payload):
    _redis_available, _dependency_mode, dependency_reason = redis_dependency_state()
    if dependency_reason != "ok":
        return None, dependency_reason, None
    if require_redis() and not replay_protection_active():
        return None, "redis_unavailable", None
    if not isinstance(payload, dict) or not payload.get("actor_id"):
        return None, "missing_actor", None
    basic_valid, basic_reason = _basic_request_valid(payload)
    if not basic_valid:
        return None, basic_reason, None
    metadata_decision, metadata_reason = validate_metadata(payload)
    if metadata_decision != "ALLOW":
        return None, metadata_reason, None
    try:
        tenant_context = tenant_execution_context(payload.get("tenant_id"))
    except Exception as exc:
        return None, str(exc), None
    policy_version = _request_policy_version(payload)
    if policy_version is None:
        return None, "missing_policy", None
    signature_valid, signature_reason = _signature_validation(payload)
    if not signature_valid:
        return None, signature_reason, None
    compute_decision, compute_reason, compute_evidence = validate_compute_request(payload)
    if compute_decision != "ALLOW":
        return None, compute_reason, None
    nonce_value = str(payload.get("nonce", ""))
    nonce_hash_value = nonce_hash(nonce_value)
    actor_hash_value = actor_hash(payload.get("actor_id", ""))
    try:
        ttl = replay_policy_config()["nonce_ttl_seconds"]
    except DecisionStoreError:
        return None, "timestamp_invalid", None
    try:
        nonce_reserved = decision_store.reserve_nonce(nonce_hash_value, ttl)
    except DecisionStoreError as exc:
        return None, redis_failure_reason(exc), None
    if not nonce_reserved:
        return None, "replay_detected", None

    try:
        normalized_context = runtime_provenance_context()
    except Exception as exc:
        return None, str(exc) or "provenance_context_invalid", None
    try:
        policy_registry = load_policy_registry(provenance_context=normalized_context)
        policy_signature_mode(policy_registry, provenance_context=normalized_context)
    except PolicyRegistryError as exc:
        return None, str(exc), None
    except Exception:
        return None, "policy_registry_unavailable", None
    simulation_decision, simulation_reason = validate_simulation(payload, provenance_context=normalized_context)
    if simulation_decision != "ALLOW":
        return None, simulation_reason, None

    body = request_signature_message(payload)
    request_hash_value = request_hash(body)
    replay_hash_value = hydra_replay_registry_hash(policy_registry["policy_hash"], nonce_hash_value)
    attestation_timestamp = time.time()
    hydra_result = evaluate_hydra_request(
        request_hash_value,
        policy_version,
        action=str(payload.get("action", "")),
        context={
            "type": payload.get("type", ""),
            "action": payload.get("action", ""),
            "tenant_id": tenant_context["tenant_id"],
            "tenant_hash": tenant_context["tenant_hash"],
            "policy_hash": policy_registry["policy_hash"],
            "nonce_hash": nonce_hash_value,
            "nonce_state": "unused",
            "replay_registry_hash": replay_hash_value,
            "attestation_timestamp": attestation_timestamp,
            "normalized_provenance_context": normalized_context,
        },
    )
    audit_hydra_consensus(hydra_result)

    policy_allowed = True
    policy_reason = "approved"
    if payload.get("type") == "execution" and not execution_command_allowed(payload.get("command", "")):
        policy_allowed = False
        policy_reason = "policy_denied"

    decision = "ALLOW" if hydra_result.final_decision == "allow" and policy_allowed else "DENY"
    reason = policy_reason if hydra_result.final_decision == "allow" else hydra_denial_reason(hydra_result)
    now = int(time.time())
    decision_id = str(uuid.uuid4())
    record = {
        "decision_id": decision_id,
        "request_hash": request_hash_value,
        "decision": decision,
        "policy_version": policy_version,
        "tenant_id": tenant_context["tenant_id"],
        "tenant_hash": tenant_context["tenant_hash"],
        "reason_code": reason,
        "nonce_hash": nonce_hash_value,
        "actor_hash": actor_hash_value,
        "gateway_id": gateway_id(),
        "used": False,
        "created_at_epoch": now,
        "expires_at_epoch": now + decision_ttl_seconds(),
        "timestamp": now,
        "policy_hash": policy_registry["policy_hash"],
        "policy_signature_valid": policy_registry["policy_signature_valid"],
        "signature_valid": True,
        "policy_pubkey_id": policy_registry["policy_pubkey_id"],
        "consensus_evidence_bundle": hydra_result.evidence_bundle,
        "consensus_evidence_hash": (hydra_result.evidence_bundle or {}).get("sha256_evidence_hash"),
        "attestation_evidence_hash": (hydra_result.evidence_bundle or {}).get("attestation_evidence_hash"),
        "consensus_signature": (hydra_result.evidence_bundle or {}).get("consensus_signature"),
        "policy_sequence": policy_registry["policy_sequence"],
        "policy_valid_from": policy_registry["valid_from"],
        "policy_valid_until": policy_registry["valid_until"],
        "normalized_provenance_context": normalized_context,
        **compute_evidence,
    }
    if payload.get("type") in {"simulation", "simulated_experiment"}:
        record["simulation_id"] = str(payload.get("simulation_id", ""))
        record["risk_level"] = str(payload.get("risk_level", ""))
    stored_record = decision_store.create_decision(record)
    try:
        audit_governance_event("decision_created", stored_record)
    except Exception:
        try:
            decision_store.delete_decision(decision_id)
        except Exception:
            pass
        raise
    return stored_record, reason, hydra_result


def validate_execution_decision(payload):
    _redis_available, _dependency_mode, dependency_reason = redis_dependency_state()
    if dependency_reason != "ok":
        return False, _deny_decision_response(
            dependency_reason,
            payload=payload,
            decision_id=str(payload.get("decision_id", "")) if isinstance(payload, dict) else None,
        )
    if require_redis() and not replay_protection_active():
        return False, _deny_decision_response(
            "redis_unavailable",
            payload=payload,
            decision_id=str(payload.get("decision_id", "")) if isinstance(payload, dict) else None,
        )
    decision_id = payload.get("decision_id") if isinstance(payload, dict) else None
    if not decision_id:
        return False, _deny_decision_response("missing_decision_id", payload=payload)

    submitted_classic_signature = payload.get("decision_signature_classic", payload.get("decision_signature"))
    submitted_pqc_signature = payload.get("decision_signature_pqc")
    if not submitted_classic_signature and not submitted_pqc_signature:
        return False, _deny_decision_response(
            "invalid_signature",
            payload=payload,
            decision_id=str(decision_id),
        )

    record = decision_store.load_decision(str(decision_id))
    if record is None:
        return False, _deny_decision_response(
            "unknown_decision",
            payload=payload,
            decision_id=str(decision_id),
        )

    actor_id = payload.get("actor_id")
    if not actor_id:
        return False, _deny_decision_response(
            "missing_actor",
            payload=payload,
            decision_id=str(decision_id),
        )

    if record.get("actor_hash") != actor_hash(actor_id):
        return False, _deny_decision_response(
            "actor_mismatch",
            payload=payload,
            decision_id=str(decision_id),
        )

    if not is_supported_alg_version(record.get("alg_version")):
        return False, _deny_decision_response(
            "unknown_algorithm",
            payload=payload,
            decision_id=str(decision_id),
        )

    if not verify_submitted_decision_signatures(
        record,
        submitted_classic_signature,
        submitted_pqc_signature,
    ):
        return False, _deny_decision_response(
            "invalid_signature",
            payload=payload,
            decision_id=str(decision_id),
        )

    if record.get("used") is True:
        return False, _deny_decision_response(
            "replay_detected",
            payload=payload,
            decision_id=str(decision_id),
        )

    if not validate_decision_time(record):
        return False, _deny_decision_response(
            "decision_time_invalid",
            payload=payload,
            decision_id=str(decision_id),
        )

    if record.get("nonce_hash") != nonce_hash(payload.get("nonce", "")):
        return False, _deny_decision_response(
            "decision_nonce_mismatch",
            payload=payload,
            decision_id=str(decision_id),
        )

    current_request_hash = request_hash(request_signature_message(payload))
    if record.get("request_hash") != current_request_hash:
        return False, _deny_decision_response(
            "decision_request_mismatch",
            payload=payload,
            decision_id=str(decision_id),
        )

    if record.get("decision") != "ALLOW":
        reason = str(record.get("reason_code") or "decision_not_allowed")
        try:
            decision_used = mark_decision_used(record)
        except DecisionStoreError as exc:
            return False, _deny_decision_response(
                redis_failure_reason(exc),
                payload=payload,
                decision_id=str(decision_id),
            )
        except Exception:
            return False, _deny_decision_response(
                "decision_use_failed",
                payload=payload,
                decision_id=str(decision_id),
            )
        if not decision_used:
            return False, _deny_decision_response(
                "replay_detected",
                payload=payload,
                decision_id=str(decision_id),
            )
        return False, _deny_decision_response(
            reason,
            payload=payload,
            decision_id=str(decision_id),
        )

    try:
        normalized_context = runtime_provenance_context()
    except Exception as exc:
        return False, _deny_decision_response(str(exc) or "provenance_context_invalid", payload=payload)
    mode, reason, _registry = policy_runtime_state(provenance_context=normalized_context)
    if mode != "NORMAL":
        return False, _deny_decision_response(
            f"degraded:{reason}",
            payload=payload,
            decision_id=str(decision_id),
        )

    try:
        registry = load_policy_registry(provenance_context=normalized_context)
        signature_mode = policy_signature_mode(registry, provenance_context=normalized_context)
    except PolicyRegistryError as exc:
        return False, _deny_decision_response(
            str(exc),
            payload=payload,
            decision_id=str(decision_id),
        )
    except Exception:
        return False, _deny_decision_response(
            "policy_registry_unavailable",
            payload=payload,
            decision_id=str(decision_id),
        )

    if not verify_submitted_decision_signatures(
        record,
        submitted_classic_signature,
        submitted_pqc_signature,
        mode=signature_mode,
    ):
        return False, _deny_decision_response(
            "invalid_signature",
            payload=payload,
            decision_id=str(decision_id),
            provenance_context=normalized_context,
        )

    return True, record


def mark_decision_used(record, execution_proof=None):
    if not decision_store.mark_used(str(record.get("decision_id", "")), execution_proof=execution_proof):
        return False
    record["used"] = True
    if execution_proof:
        record.update(execution_proof)
    return True


def redacted_decision_record(record):
    return {
        "decision_id": record.get("decision_id"),
        "actor_hash": record.get("actor_hash"),
        "request_hash": record.get("request_hash"),
        "decision": record.get("decision"),
        "decision_signature": record.get("decision_signature"),
        "decision_signature_classic": record.get("decision_signature_classic"),
        "decision_signature_pqc": record.get("decision_signature_pqc"),
        "expires_at": record.get("expires_at"),
        "expires_at_epoch": record.get("expires_at_epoch"),
        "alg_version": record.get("alg_version"),
        "policy_version": record.get("policy_version"),
        "policy_hash": record.get("policy_hash"),
        "tenant_id": record.get("tenant_id"),
        "tenant_hash": record.get("tenant_hash"),
        "policy_signature_valid": record.get("policy_signature_valid"),
        "signature_valid": record.get("signature_valid"),
        "policy_pubkey_id": record.get("policy_pubkey_id"),
        "nonce_hash": record.get("nonce_hash"),
        "gateway_id": record.get("gateway_id"),
        "policy_sequence": record.get("policy_sequence"),
        "policy_valid_from": record.get("policy_valid_from"),
        "policy_valid_until": record.get("policy_valid_until"),
        "compute_target": record.get("compute_target"),
        "compute_policy_hash": record.get("compute_policy_hash"),
        "compute_risk_level": record.get("compute_risk_level"),
        "human_review": record.get("human_review"),
        "data_sensitivity": record.get("data_sensitivity"),
        "execution_location": record.get("execution_location"),
        "actual_execution_target": record.get("actual_execution_target"),
        "execution_verified": record.get("execution_verified"),
        "consensus_evidence_bundle": record.get("consensus_evidence_bundle"),
        "consensus_evidence_hash": record.get("consensus_evidence_hash"),
        "attestation_evidence_hash": record.get("attestation_evidence_hash"),
        "consensus_signature": record.get("consensus_signature"),
        "previous_hash": record.get("previous_hash"),
        "audit_hash": record.get("audit_hash"),
        "current_hash": record.get("current_hash", record.get("audit_hash")),
        "genesis_hash": DECISION_CHAIN_GENESIS,
        "genesis_signature": _safe_text_file(POLICY_REGISTRY_SIGNATURE_PATH).strip(),
    }


def redacted_decision_chain_for(decision_id):
    if not hasattr(decision_store, "records"):
        return []
    chain = []
    for record in decision_store.records.values():
        chain.append(redacted_decision_record(record))
        if str(record.get("decision_id")) == str(decision_id):
            break
    return chain


def _safe_text_file(path):
    return Path(path).read_text(encoding="utf-8")


def _sha256_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _policy_log_subset(policy_hash_value):
    try:
        log_path = POLICY_KEY_CONFIG_PATH.parent / "policy_log.jsonl"
        entries = []
        for line in log_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            entries.append(entry)
            if entry.get("policy_hash") == policy_hash_value:
                break
        return entries
    except Exception:
        return []


def audit_evidence_bundle(decision_id):
    decision_record = decision_store.load_decision(str(decision_id))
    if decision_record is None:
        return None
    redacted_record = redacted_decision_record(decision_record)
    records = redacted_decision_chain_for(decision_id) or [redacted_record]
    policy_text = _safe_text_file(POLICY_REGISTRY_PATH)
    policy_json = json.loads(policy_text)
    signature_text = _safe_text_file(POLICY_REGISTRY_SIGNATURE_PATH).strip()
    policy_log_entries = _policy_log_subset(redacted_record.get("policy_hash"))
    manifest = {
        "decision_id": str(decision_id),
        "tenant_id": redacted_record.get("tenant_id"),
        "tenant_hash": redacted_record.get("tenant_hash"),
        "decision_record_hash": hashlib.sha256(canonical(redacted_record).encode("utf-8")).hexdigest(),
        "policy_registry_sha256": hashlib.sha256(canonical(policy_json).encode("utf-8")).hexdigest(),
        "policy_signature_sha256": _sha256_text(signature_text),
        "policy_log_sha256": hashlib.sha256(canonical(policy_log_entries).encode("utf-8")).hexdigest(),
        "bundle_version": "1",
    }
    return {
        "type": "audit_evidence_bundle",
        "decision_id": str(decision_id),
        "decision_record": redacted_record,
        "records": records,
        "policy_registry.json": policy_json,
        "policy_registry.sig": signature_text,
        "policy_log": policy_log_entries,
        "manifest.json": manifest,
    }


def replay_export_for_decision(decision_id):
    bundle = audit_evidence_bundle(decision_id)
    if bundle is None:
        return None
    decision_record = bundle["decision_record"]
    records = bundle["records"]
    replay = {
        "type": "decision_replay_export",
        "version": "1",
        "decision_id": str(decision_id),
        "decision": decision_record.get("decision"),
        "request_hash": decision_record.get("request_hash"),
        "policy_version": decision_record.get("policy_version"),
        "policy_hash": decision_record.get("policy_hash"),
        "policy_pubkey_id": decision_record.get("policy_pubkey_id"),
        "audit_hash": decision_record.get("audit_hash"),
        "previous_hash": decision_record.get("previous_hash"),
        "records": records,
    }
    replay["replay_hash"] = hashlib.sha256(canonical(replay).encode("utf-8")).hexdigest()
    return replay


def verify(payload):
    try:
        # signature verplicht
        signature = payload.get("signature")
        if not signature:
            return False

        # nonce verplicht
        nonce = payload.get("nonce")
        if not nonce:
            return False

        # timestamp verplicht
        ts_raw = payload.get("timestamp")
        if ts_raw is None:
            return False

        try:
            ts = int(ts_raw)
        except Exception:
            return False

        # tijd window (5 min)
        if abs(int(time.time()) - ts) > 300:
            return False

        # replay check
        if nonce_store.exists(nonce):
            return False

        if not _signature_valid(payload):
            return False

        if payload.get("type") == "execution":
            if not execution_command_allowed(payload.get("command", "")):
                audit_execution_decision(payload.get("command", ""), "deny", tenant_id=payload.get("tenant_id"))
                return POLICY_DENIED
            audit_execution_decision(payload.get("command", ""), "allow", tenant_id=payload.get("tenant_id"))

        # nonce opslaan NA valid signature
        if not nonce_store.store(nonce, ts):
            return False

        return True

    except Exception as e:
        print("VERIFY ERROR:", e)
        return False


# -------------------------
# ENDPOINT
# -------------------------

def _simulator_block_html() -> str:
    """USBAY Live Governance Simulator — pure frontend interactive demo.

    Self-contained HTML+CSS+JS block injected at the top of /, /dashboard,
    /playground, and /playground/demo. Does not call backend endpoints,
    does not touch governance logic, validator, PEM, nonce/replay,
    attestation, evidence verification, or the API contract. Renders 8
    scenario buttons that animate the 7-stage governance pipeline
    (REQUEST → POLICY BRAIN → ENFORCEMENT GATEWAY → POLICY VERIFICATION
    → DECISION → PROVIDER ADAPTER → EVIDENCE LAYER), update decision,
    provider, evidence, audit, and human-review cards. Provider
    execution is visibly completed only on ALLOW; all other verdicts
    visibly block or pause before provider execution. Audit timeline
    appends a per-run event with randomized request_id, nonce, audit
    hash, and timestamp (generated client-side; no secrets in DOM).
    """
    return r"""
<section class="usbsim" id="usbsim" aria-label="USBAY Live Governance Control Plane">
  <header class="usbsim-hero">
    <div class="usbsim-hero-main">
      <div class="usbsim-eyebrow"><span class="usbsim-eb-dot"></span> USBAY GOVERNANCE CONTROL PLANE</div>
      <h2 class="usbsim-hero-title">Execution Authority Active</h2>
      <p class="usbsim-hero-sub">USBAY decides whether AI is allowed to execute. Live pipeline, signed evidence, fail-closed by default.</p>
      <div class="usbsim-hero-grid" role="list">
        <div role="listitem"><span class="usbsim-k">EXECUTION AUTHORITY</span><span class="usbsim-v usbsim-v-ok" id="hb-posture">LIVE</span></div>
        <div role="listitem"><span class="usbsim-k">GOVERNANCE TRUST</span><span class="usbsim-v usbsim-v-ok" id="hb-trust">VERIFIED</span></div>
        <div role="listitem"><span class="usbsim-k">RUNTIME INTEGRITY</span><span class="usbsim-v usbsim-v-ok" id="hb-integrity">— %</span></div>
        <div role="listitem"><span class="usbsim-k">LAST EVIDENCE</span><span class="usbsim-v" id="hb-last-evidence">—</span></div>
        <div role="listitem"><span class="usbsim-k">RUNTIME CLOCK</span><span class="usbsim-v usbsim-mono" id="hb-clock">--:--:-- Z</span></div>
        <div role="listitem" class="usbsim-hero-sec"><span class="usbsim-k">POLICY</span><span class="usbsim-v usbsim-mono" id="hb-policy-hash">sha256:loading…</span></div>
        <div role="listitem" hidden><span class="usbsim-k">AUDIT</span><span class="usbsim-v usbsim-mono" id="hb-audit-preview">—</span></div>
        <div role="listitem" hidden><span class="usbsim-k">REQ</span><span class="usbsim-v usbsim-mono" id="hb-reqid-preview">—</span></div>
      </div>
    </div>
    <div class="usbsim-hero-side">
      <div class="usbsim-bigpill" id="usbsim-hero-pill" data-mode="live">
        <span class="usbsim-bigpill-dot"></span>
        <span class="usbsim-bigpill-text">LIVE</span>
      </div>
      <div class="usbsim-hb">
        <span class="usbsim-hb-bar"><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i></span>
        <span class="usbsim-hb-lbl">heartbeat · tick <b id="hb-tick">0</b></span>
      </div>
      <div class="usbsim-stream-wrap" aria-label="Operational telemetry">
        <div class="usbsim-stream-hd"><span class="usbsim-eb-dot"></span><span>OPERATIONAL TELEMETRY</span></div>
        <ul class="usbsim-stream" id="usbsim-stream" aria-live="off"></ul>
      </div>
      <button type="button" class="usbsim-btn-ghost" id="usbsim-copy">Copy demo summary</button>
      <p class="usbsim-hero-note">Backend governance, validator, attestation &amp; evidence verification unchanged.</p>
    </div>
  </header>

  <div class="usbsim-scn" role="group" aria-label="Governance scenarios">
    <button type="button" class="usbsim-scn-btn" data-scn="valid"><span class="usbsim-scn-n">1</span><span class="usbsim-scn-l">Valid Request</span><em class="usbsim-scn-v usbsim-v-allow">ALLOW</em></button>
    <button type="button" class="usbsim-scn-btn" data-scn="replay"><span class="usbsim-scn-n">2</span><span class="usbsim-scn-l">Replay Attack</span><em class="usbsim-scn-v usbsim-v-deny">DENY</em></button>
    <button type="button" class="usbsim-scn-btn" data-scn="expired"><span class="usbsim-scn-n">3</span><span class="usbsim-scn-l">Expired Policy</span><em class="usbsim-scn-v usbsim-v-blocked">BLOCKED</em></button>
    <button type="button" class="usbsim-scn-btn" data-scn="human"><span class="usbsim-scn-n">4</span><span class="usbsim-scn-l">Human Review Required</span><em class="usbsim-scn-v usbsim-v-warn">HUMAN_REVIEW</em></button>
    <button type="button" class="usbsim-scn-btn" data-scn="sig"><span class="usbsim-scn-n">5</span><span class="usbsim-scn-l">Signature Failure</span><em class="usbsim-scn-v usbsim-v-failclosed">FAIL_CLOSED</em></button>
    <button type="button" class="usbsim-scn-btn" data-scn="drift"><span class="usbsim-scn-n">6</span><span class="usbsim-scn-l">Drift Detected</span><em class="usbsim-scn-v usbsim-v-warn">DEGRADED</em></button>
    <button type="button" class="usbsim-scn-btn" data-scn="quorum"><span class="usbsim-scn-n">7</span><span class="usbsim-scn-l">Verifier Quorum Failure</span><em class="usbsim-scn-v usbsim-v-blocked">BLOCKED</em></button>
    <button type="button" class="usbsim-scn-btn" data-scn="adapter"><span class="usbsim-scn-n">8</span><span class="usbsim-scn-l">Provider Disabled</span><em class="usbsim-scn-v usbsim-v-failclosed">FAIL_CLOSED</em></button>
  </div>

  <div class="usbsim-pipe-wrap">
    <ol class="usbsim-pipe" id="usbsim-pipe" aria-label="Governance pipeline">
      <li class="usbsim-node" data-stage="0"><span class="usbsim-led"></span><span class="usbsim-stage">REQUEST</span><span class="usbsim-sub" data-sub>ingest</span></li>
      <li class="usbsim-node" data-stage="1"><span class="usbsim-led"></span><span class="usbsim-stage">POLICY BRAIN</span><span class="usbsim-sub" data-sub>policy.signature</span></li>
      <li class="usbsim-node" data-stage="2"><span class="usbsim-led"></span><span class="usbsim-stage">ENFORCEMENT GATEWAY</span><span class="usbsim-sub" data-sub>fail-closed</span></li>
      <li class="usbsim-node" data-stage="3"><span class="usbsim-led"></span><span class="usbsim-stage">POLICY VERIFICATION</span><span class="usbsim-sub" data-sub>nonce.replay</span></li>
      <li class="usbsim-node" data-stage="4"><span class="usbsim-led"></span><span class="usbsim-stage">DECISION</span><span class="usbsim-sub" data-sub>pending</span></li>
      <li class="usbsim-node" data-stage="5"><span class="usbsim-led"></span><span class="usbsim-stage">PROVIDER ADAPTER</span><span class="usbsim-sub" data-sub>idle</span></li>
      <li class="usbsim-node" data-stage="6"><span class="usbsim-led"></span><span class="usbsim-stage">EVIDENCE LAYER</span><span class="usbsim-sub" data-sub>chain</span></li>
    </ol>
    <div class="usbsim-pkt" id="usbsim-pkt" aria-hidden="true"></div>
    <div class="usbsim-pkt-rail" aria-hidden="true"></div>
    <div class="usbsim-flow" aria-hidden="true"><i></i><i></i><i></i></div>
  </div>

  <article class="usbsim-why" id="usbsim-why">
    <header class="usbsim-why-hd">
      <div>
        <div class="usbsim-eyebrow usbsim-eyebrow-sm">WHY USBAY DECIDED THIS</div>
        <h3 id="usbsim-why-h">Awaiting governance decision</h3>
      </div>
      <span class="usbsim-bigpill usbsim-bigpill-sm" id="usbsim-verdict" data-mode="idle"><span class="usbsim-bigpill-dot"></span><span class="usbsim-bigpill-text">IDLE</span></span>
    </header>
    <div class="usbsim-why-grid">
      <div><span class="usbsim-k">Governance layer</span><span class="usbsim-v" id="why-layer">USBAY Control Plane</span></div>
      <div><span class="usbsim-k">Result</span><span class="usbsim-v" id="why-result">—</span></div>
      <div><span class="usbsim-k">Request ID</span><span class="usbsim-v usbsim-mono" id="why-reqid">—</span></div>
      <div><span class="usbsim-k">Policy applied</span><span class="usbsim-v" id="why-policy">—</span></div>
      <div><span class="usbsim-k">What was requested</span><span class="usbsim-v" id="why-what">Select a scenario to begin.</span></div>
      <div><span class="usbsim-k">USBAY reason</span><span class="usbsim-v" id="why-reason">No scenario has been run.</span></div>
    </div>
    <p class="usbsim-why-plain" id="why-plain">Select one of the eight scenarios above to see USBAY render a governance decision live.</p>
    <div class="usbsim-summaries">
      <details class="usbsim-det" id="det-exec" open>
        <summary>Executive summary</summary>
        <p id="why-exec">Run a scenario to see a one-line executive read-out.</p>
      </details>
      <details class="usbsim-det" id="det-reg">
        <summary>Regulator summary</summary>
        <p id="why-reg">Run a scenario to see a regulator-grade summary with policy reference, decision class, and evidence pointer.</p>
      </details>
      <details class="usbsim-det" id="det-tech">
        <summary>Technical diagnostics</summary>
        <dl class="usbsim-dl usbsim-dl-mono" id="why-tech-dl">
          <div><dt>policy_hash</dt><dd id="tech-policy-hash">—</dd></div>
          <div><dt>nonce</dt><dd id="tech-nonce">—</dd></div>
          <div><dt>audit_hash</dt><dd id="tech-audit-hash">—</dd></div>
          <div><dt>decision_proof</dt><dd id="tech-proof">—</dd></div>
          <div><dt>pipeline_stages</dt><dd id="tech-stages">—</dd></div>
          <div><dt>timestamp</dt><dd id="tech-ts">—</dd></div>
        </dl>
      </details>
    </div>
  </article>

  <div class="usbsim-grid">
    <article class="usbsim-card" id="usbsim-provider-card">
      <header><h3>Provider Execution</h3><span class="usbsim-pill usbsim-pill-idle" id="usbsim-provider-state">IDLE</span></header>
      <dl class="usbsim-dl">
        <div><dt>Adapter</dt><dd id="usbsim-adapter">—</dd></div>
        <div><dt>Model</dt><dd id="usbsim-model">—</dd></div>
        <div><dt>Execution</dt><dd id="usbsim-exec">No execution attempted yet.</dd></div>
        <div><dt>Trust boundary</dt><dd id="usbsim-trust">USBAY controls execution. Provider runs only on ALLOW.</dd></div>
      </dl>
      <div class="usbsim-blockedfx" id="usbsim-blockedfx" hidden><span>EXECUTION HALTED BY USBAY</span></div>
    </article>

    <article class="usbsim-card" id="usbsim-evidence-card">
      <header><h3>Evidence Chain</h3><span class="usbsim-pill usbsim-pill-idle" id="usbsim-ev-state">IDLE</span></header>
      <dl class="usbsim-dl usbsim-dl-mono">
        <div><dt>Audit hash</dt><dd id="usbsim-audit-hash">—</dd></div>
        <div><dt>Nonce</dt><dd id="usbsim-nonce">—</dd></div>
        <div><dt>Policy hash</dt><dd id="usbsim-policy-hash">—</dd></div>
        <div><dt>Decision proof</dt><dd id="usbsim-proof">—</dd></div>
        <div><dt>Timestamp</dt><dd id="usbsim-ts">—</dd></div>
      </dl>
    </article>

    <article class="usbsim-card usbsim-card-human" id="usbsim-human-card">
      <header><h3>Human Review Escalation</h3><span class="usbsim-pill usbsim-pill-idle" id="usbsim-human-state">INACTIVE</span></header>
      <div class="usbsim-hold-banner" id="usbsim-hold-banner" hidden>
        <span class="usbsim-hold-icon">⏸</span>
        <span>EXECUTION HALTED PENDING HUMAN REVIEW</span>
      </div>
      <p id="usbsim-human-text">No escalation. Operator action will appear here when a scenario triggers HUMAN_REVIEW.</p>
      <div class="usbsim-queue" id="usbsim-queue" hidden>
        <div class="usbsim-queue-hd">OPERATOR APPROVAL QUEUE</div>
        <div class="usbsim-queue-row">
          <span class="usbsim-queue-ticket" id="usbsim-queue-ticket">—</span>
          <span class="usbsim-queue-meta" id="usbsim-queue-meta">awaiting reviewer</span>
        </div>
        <div class="usbsim-queue-actions">
          <button type="button" class="usbsim-btn-approve" id="usbsim-approve">Approve</button>
          <button type="button" class="usbsim-btn-reject" id="usbsim-reject">Reject</button>
        </div>
        <p class="usbsim-queue-note">Operator action is recorded in the audit timeline. Provider remains blocked until release.</p>
      </div>
    </article>
  </div>

  <article class="usbsim-card usbsim-audit">
    <header><h3>Audit Timeline</h3><span class="usbsim-pill usbsim-pill-idle" id="usbsim-audit-count">0 events</span></header>
    <ul class="usbsim-audit-list" id="usbsim-audit-list" aria-live="polite"><li class="usbsim-audit-empty">No simulations run yet. Trigger a scenario to append a signed audit event.</li></ul>
  </article>

  <p class="usbsim-foot">Simulator runs entirely in your browser for demo storytelling. Real governance decisions, fail-closed enforcement, policy validation, nonce/replay protection, attestation, and evidence verification remain in the backend and are unaffected.</p>
</section>

<style>
.usbsim{position:relative;z-index:2;margin:18px auto 22px;max-width:1180px;padding:0;background:transparent;color:#e6edf6;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;}
.usbsim *{box-sizing:border-box;}
.usbsim-eyebrow{display:inline-flex;align-items:center;gap:7px;font-size:10px;letter-spacing:.28em;color:#22d3ee;text-transform:uppercase;font-weight:700;margin-bottom:6px;}
.usbsim-eyebrow-sm{font-size:9.5px;letter-spacing:.24em;margin-bottom:2px;}
.usbsim-eb-dot{width:7px;height:7px;border-radius:50%;background:#22d3ee;box-shadow:0 0 8px rgba(34,211,238,.65);animation:usbsim-pulse 1.4s ease-in-out infinite;}
.usbsim-mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;}
.usbsim-k{font-size:9.5px;letter-spacing:.18em;color:#6b7a90;text-transform:uppercase;font-weight:700;display:block;margin-bottom:2px;}
.usbsim-v{font-size:13px;color:#e6edf6;letter-spacing:.02em;font-weight:600;word-break:break-all;line-height:1.35;}
.usbsim-v-ok{color:#22c55e;}.usbsim-v-warn{color:#f59e0b;}.usbsim-v-bad{color:#ef4444;}

/* ---- Hero / Control plane authority ---- */
.usbsim-hero{display:grid;grid-template-columns:1fr 280px;gap:18px;padding:22px 24px;border:1px solid #1f2a3a;border-radius:12px;background:linear-gradient(140deg,rgba(8,16,28,.96) 0%,rgba(10,17,25,.95) 60%,rgba(8,14,22,.95) 100%);box-shadow:0 0 0 1px rgba(34,211,238,.10),0 24px 60px -36px rgba(34,211,238,.45);position:relative;overflow:hidden;margin-bottom:14px;}
.usbsim-hero::before{content:"";position:absolute;inset:0;pointer-events:none;background:radial-gradient(800px 220px at 0% 0%,rgba(34,211,238,.10),transparent 60%),radial-gradient(600px 160px at 100% 100%,rgba(34,197,94,.06),transparent 60%);}
.usbsim-hero-main{position:relative;z-index:1;}
.usbsim-hero-title{margin:0 0 6px;font-size:26px;letter-spacing:.01em;color:#e6edf6;font-weight:800;line-height:1.15;}
.usbsim-hero-sub{margin:0 0 14px;color:#8a96aa;font-size:12.5px;line-height:1.55;max-width:680px;}
.usbsim-hero-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px 18px;}
.usbsim-hero-grid > div{display:flex;flex-direction:column;gap:1px;}
.usbsim-hero-side{position:relative;z-index:1;display:flex;flex-direction:column;gap:12px;align-items:stretch;}
.usbsim-hero-note{margin:auto 0 0;font-size:10px;color:#6b7a90;letter-spacing:.04em;line-height:1.5;}

.usbsim-bigpill{display:inline-flex;align-items:center;gap:9px;padding:11px 16px;border-radius:8px;background:#0d1622;border:1px solid #243248;font-weight:800;letter-spacing:.2em;text-transform:uppercase;}
.usbsim-bigpill[data-mode="live"],.usbsim-bigpill[data-mode="allow"]{border-color:#22c55e;background:rgba(34,197,94,.08);color:#22c55e;box-shadow:0 0 24px -8px rgba(34,197,94,.55);}
.usbsim-bigpill[data-mode="degraded"],.usbsim-bigpill[data-mode="warn"]{border-color:#f59e0b;background:rgba(245,158,11,.08);color:#f59e0b;box-shadow:0 0 24px -8px rgba(245,158,11,.55);}
.usbsim-bigpill[data-mode="blocked"],.usbsim-bigpill[data-mode="bad"]{border-color:#ef4444;background:rgba(239,68,68,.08);color:#ef4444;box-shadow:0 0 24px -8px rgba(239,68,68,.55);}
.usbsim-bigpill[data-mode="idle"]{color:#8a96aa;}
.usbsim-bigpill[data-mode="active"],.usbsim-bigpill[data-mode="running"]{border-color:#22d3ee;background:rgba(34,211,238,.08);color:#22d3ee;box-shadow:0 0 24px -8px rgba(34,211,238,.55);}
.usbsim-bigpill-dot{width:10px;height:10px;border-radius:50%;background:currentColor;box-shadow:0 0 10px currentColor;animation:usbsim-pulse 1.2s ease-in-out infinite;}
.usbsim-bigpill-text{font-size:14px;}
.usbsim-bigpill-sm{padding:7px 12px;font-size:11px;letter-spacing:.18em;}
.usbsim-bigpill-sm .usbsim-bigpill-text{font-size:11px;}
.usbsim-bigpill-sm .usbsim-bigpill-dot{width:7px;height:7px;}

.usbsim-hb{display:flex;align-items:center;gap:9px;padding:7px 11px;border:1px solid #243248;border-radius:6px;background:#0d1622;font-size:10.5px;color:#8a96aa;letter-spacing:.08em;}
.usbsim-hb-bar{display:inline-flex;gap:2px;align-items:flex-end;}
.usbsim-hb-bar i{display:block;width:3px;height:10px;background:#22d3ee;border-radius:1px;opacity:.35;animation:usbsim-hbbar 1.2s ease-in-out infinite;}
.usbsim-hb-bar i:nth-child(2){animation-delay:.10s;}.usbsim-hb-bar i:nth-child(3){animation-delay:.20s;}
.usbsim-hb-bar i:nth-child(4){animation-delay:.30s;}.usbsim-hb-bar i:nth-child(5){animation-delay:.40s;}
.usbsim-hb-bar i:nth-child(6){animation-delay:.50s;}.usbsim-hb-bar i:nth-child(7){animation-delay:.60s;}
.usbsim-hb-bar i:nth-child(8){animation-delay:.70s;}
.usbsim-hb-lbl{flex:1;color:#8a96aa;letter-spacing:.12em;text-transform:uppercase;font-size:10px;}
.usbsim-hb-lbl b{color:#22d3ee;font-weight:700;}
@keyframes usbsim-hbbar{0%,100%{height:10px;opacity:.35;}50%{height:18px;opacity:1;}}

.usbsim-btn-ghost{background:transparent;color:#22d3ee;border:1px solid #243248;padding:8px 12px;border-radius:6px;font-size:10.5px;letter-spacing:.18em;text-transform:uppercase;font-weight:700;cursor:pointer;font-family:inherit;transition:border-color .15s,background .15s;}
.usbsim-btn-ghost:hover{border-color:#22d3ee;background:rgba(34,211,238,.08);}
.usbsim-btn-ghost:focus-visible{outline:2px solid #22d3ee;outline-offset:2px;}

/* ---- Scenario buttons ---- */
.usbsim-scn{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px;margin:0 0 16px;}
.usbsim-scn-btn{display:flex;align-items:center;gap:10px;padding:11px 12px;background:#0d1622;border:1px solid #243248;border-left:3px solid #243248;border-radius:6px;color:#e6edf6;cursor:pointer;font-family:inherit;text-align:left;transition:border-color .15s,background .15s,transform .15s;}
.usbsim-scn-btn:hover{border-color:#22d3ee;background:#101b2a;transform:translateY(-1px);}
.usbsim-scn-btn:focus-visible{outline:2px solid #22d3ee;outline-offset:2px;}
.usbsim-scn-btn.is-active{border-color:#22d3ee;border-left-color:#22d3ee;background:rgba(34,211,238,.10);box-shadow:0 0 18px -8px rgba(34,211,238,.6);}
.usbsim-scn-btn[disabled]{opacity:.55;cursor:wait;}
.usbsim-scn-n{display:inline-grid;place-items:center;width:22px;height:22px;border-radius:4px;background:#1a2332;color:#22d3ee;font-size:10.5px;font-weight:700;flex-shrink:0;}
.usbsim-scn-l{flex:1;font-size:12px;letter-spacing:.02em;color:#e6edf6;font-weight:600;}
.usbsim-scn-v{font-style:normal;font-size:9.5px;font-weight:700;letter-spacing:.18em;padding:3px 7px;border-radius:3px;border:1px solid currentColor;background:rgba(0,0,0,.2);}
.usbsim-v-allow{color:#22c55e;}.usbsim-v-deny,.usbsim-v-blocked,.usbsim-v-failclosed{color:#ef4444;}.usbsim-v-warn{color:#f59e0b;}

/* ---- Pipeline + packet ---- */
.usbsim-pipe-wrap{position:relative;margin:0 0 16px;}
.usbsim-pipe{list-style:none;margin:0;padding:14px;display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:8px;background:#08101c;border:1px solid #1a2332;border-radius:10px;position:relative;}
.usbsim-node{position:relative;display:flex;flex-direction:column;gap:4px;padding:10px 11px;background:#0d1622;border:1px solid #243248;border-left:3px solid #243248;border-radius:6px;transition:border-color .25s,background .25s,box-shadow .25s,transform .25s;}
.usbsim-node + .usbsim-node::before{content:"";position:absolute;left:-6px;top:50%;transform:translateY(-50%);width:5px;height:1px;background:#243248;}
.usbsim-led{width:8px;height:8px;border-radius:50%;background:#1a2332;border:1px solid #243248;}
.usbsim-stage{font-size:9.5px;letter-spacing:.16em;color:#8a96aa;text-transform:uppercase;font-weight:700;}
.usbsim-sub{font-size:10.5px;color:#6b7a90;letter-spacing:.04em;min-height:14px;}
.usbsim-node[data-state="pending"]{border-left-color:#243248;}
.usbsim-node[data-state="active"]{border-left-color:#22d3ee;border-color:#22d3ee;background:rgba(34,211,238,.08);box-shadow:0 0 20px -4px rgba(34,211,238,.55);transform:translateY(-1px);}
.usbsim-node[data-state="active"] .usbsim-led{background:#22d3ee;border-color:#22d3ee;box-shadow:0 0 10px rgba(34,211,238,.75);animation:usbsim-pulse 1s ease-in-out infinite;}
.usbsim-node[data-state="active"] .usbsim-stage{color:#22d3ee;}
.usbsim-node[data-state="verified"]{border-left-color:#22c55e;border-color:#22c55e;background:rgba(34,197,94,.06);}
.usbsim-node[data-state="verified"] .usbsim-led{background:#22c55e;border-color:#22c55e;box-shadow:0 0 8px rgba(34,197,94,.6);}
.usbsim-node[data-state="verified"] .usbsim-stage{color:#22c55e;}
.usbsim-node[data-state="degraded"]{border-left-color:#f59e0b;border-color:#f59e0b;background:rgba(245,158,11,.06);}
.usbsim-node[data-state="degraded"] .usbsim-led{background:#f59e0b;border-color:#f59e0b;box-shadow:0 0 8px rgba(245,158,11,.6);}
.usbsim-node[data-state="degraded"] .usbsim-stage{color:#f59e0b;}
.usbsim-node[data-state="blocked"]{border-left-color:#ef4444;border-color:#ef4444;background:rgba(239,68,68,.08);animation:usbsim-shake .35s ease-in-out;}
.usbsim-node[data-state="blocked"] .usbsim-led{background:#ef4444;border-color:#ef4444;box-shadow:0 0 10px rgba(239,68,68,.65);}
.usbsim-node[data-state="blocked"] .usbsim-stage{color:#ef4444;}
.usbsim-node[data-state="halt"]{opacity:.35;border-left-style:dashed;}
.usbsim-node[data-state="halt"] .usbsim-stage{color:#6b7a90;}

.usbsim-pkt{position:absolute;top:50%;left:0;width:18px;height:18px;border-radius:50%;background:radial-gradient(circle,#22d3ee 0%,rgba(34,211,238,.0) 70%);transform:translate(-50%,-50%) scale(0);opacity:0;pointer-events:none;z-index:3;box-shadow:0 0 16px rgba(34,211,238,.95),0 0 36px rgba(34,211,238,.55);transition:left .32s cubic-bezier(.4,.0,.2,1),background .25s,box-shadow .25s,opacity .2s,transform .2s;}
.usbsim-pkt[data-active="1"]{opacity:1;transform:translate(-50%,-50%) scale(1);}
.usbsim-pkt[data-tone="warn"]{background:radial-gradient(circle,#f59e0b 0%,rgba(245,158,11,0) 70%);box-shadow:0 0 16px rgba(245,158,11,.95),0 0 36px rgba(245,158,11,.55);}
.usbsim-pkt[data-tone="bad"]{background:radial-gradient(circle,#ef4444 0%,rgba(239,68,68,0) 70%);box-shadow:0 0 16px rgba(239,68,68,.95),0 0 36px rgba(239,68,68,.55);}
.usbsim-pkt-rail{position:absolute;top:50%;left:14px;right:14px;height:1px;background:linear-gradient(90deg,rgba(34,211,238,.0),rgba(34,211,238,.18) 50%,rgba(34,211,238,.0));pointer-events:none;z-index:2;}

@keyframes usbsim-pulse{0%,100%{opacity:1;transform:scale(1);}50%{opacity:.5;transform:scale(.85);}}
@keyframes usbsim-shake{0%,100%{transform:translateX(0);}25%{transform:translateX(-2px);}75%{transform:translateX(2px);}}

/* ---- Why USBAY decided this (dominant card) ---- */
.usbsim-why{margin:0 0 14px;padding:16px 18px;background:linear-gradient(180deg,rgba(10,17,25,.96),rgba(8,14,22,.94));border:1px solid #1f2a3a;border-left:4px solid #22d3ee;border-radius:10px;box-shadow:0 0 0 1px rgba(34,211,238,.05),0 14px 36px -22px rgba(34,211,238,.35);transition:border-left-color .25s;}
.usbsim-why[data-tone="allow"]{border-left-color:#22c55e;}
.usbsim-why[data-tone="warn"]{border-left-color:#f59e0b;}
.usbsim-why[data-tone="bad"]{border-left-color:#ef4444;}
.usbsim-why-hd{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:10px;flex-wrap:wrap;}
.usbsim-why-hd h3{margin:0;font-size:18px;color:#e6edf6;letter-spacing:.01em;font-weight:700;}
.usbsim-why-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px 18px;margin-bottom:10px;}
.usbsim-why-grid > div{display:flex;flex-direction:column;gap:1px;}
.usbsim-why-plain{margin:0 0 10px;font-size:13px;color:#cbd5e1;line-height:1.6;}
.usbsim-summaries{display:flex;flex-direction:column;gap:6px;}
.usbsim-det{background:#0d1622;border:1px solid #1a2332;border-radius:6px;padding:0;}
.usbsim-det summary{cursor:pointer;list-style:none;padding:9px 12px;font-size:10.5px;letter-spacing:.18em;color:#22d3ee;text-transform:uppercase;font-weight:700;display:flex;align-items:center;gap:8px;}
.usbsim-det summary::-webkit-details-marker{display:none;}
.usbsim-det summary::before{content:"+";color:#22d3ee;font-weight:700;}
.usbsim-det[open] summary::before{content:"−";}
.usbsim-det p{margin:0;padding:0 12px 11px;color:#cbd5e1;font-size:12px;line-height:1.55;}
.usbsim-det dl{margin:0;padding:4px 12px 11px;}

/* ---- Cards (provider / evidence / human) ---- */
.usbsim-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin-bottom:12px;}
.usbsim-card{background:#0a1119;border:1px solid #1a2332;border-left:3px solid #243248;border-radius:8px;padding:12px 14px;display:flex;flex-direction:column;gap:10px;position:relative;overflow:hidden;transition:border-left-color .2s,box-shadow .2s;}
.usbsim-card[data-tone="allow"]{border-left-color:#22c55e;box-shadow:-3px 0 18px -10px rgba(34,197,94,.55);}
.usbsim-card[data-tone="warn"]{border-left-color:#f59e0b;box-shadow:-3px 0 18px -10px rgba(245,158,11,.55);}
.usbsim-card[data-tone="bad"]{border-left-color:#ef4444;box-shadow:-3px 0 18px -10px rgba(239,68,68,.55);}
.usbsim-card[data-tone="active"]{border-left-color:#22d3ee;box-shadow:-3px 0 18px -10px rgba(34,211,238,.55);}
.usbsim-card header{display:flex;justify-content:space-between;align-items:center;gap:10px;border-bottom:1px solid #1a2332;padding-bottom:7px;}
.usbsim-card header h3{margin:0;font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:#e6edf6;font-weight:700;}
.usbsim-pill{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:3px;font-size:9.5px;font-weight:700;letter-spacing:.18em;text-transform:uppercase;border:1px solid #243248;background:#0d1622;color:#8a96aa;}
.usbsim-pill-idle{color:#8a96aa;}
.usbsim-pill-active{color:#22d3ee;border-color:#22d3ee;background:rgba(34,211,238,.08);}
.usbsim-pill-allow{color:#22c55e;border-color:#22c55e;background:rgba(34,197,94,.08);}
.usbsim-pill-warn{color:#f59e0b;border-color:#f59e0b;background:rgba(245,158,11,.08);}
.usbsim-pill-bad{color:#ef4444;border-color:#ef4444;background:rgba(239,68,68,.08);}
.usbsim-dl{margin:0;display:flex;flex-direction:column;gap:7px;}
.usbsim-dl > div{display:flex;flex-direction:column;gap:1px;}
.usbsim-dl dt{font-size:9.5px;letter-spacing:.18em;color:#6b7a90;text-transform:uppercase;font-weight:700;}
.usbsim-dl dd{margin:0;font-size:11.5px;color:#e6edf6;word-break:break-all;line-height:1.45;}
.usbsim-dl-mono dd{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#22d3ee;font-size:11px;}
.usbsim-blockedfx{position:absolute;inset:auto 0 0;text-align:center;padding:8px;font-size:9.5px;letter-spacing:.22em;font-weight:700;color:#ef4444;background:repeating-linear-gradient(45deg,rgba(239,68,68,.12) 0 10px,transparent 10px 20px);border-top:1px solid rgba(239,68,68,.4);animation:usbsim-shake .35s ease-in-out;}
.usbsim-card-human #usbsim-human-text{margin:0;font-size:12.5px;line-height:1.55;color:#cbd5e1;}
.usbsim-hold-banner{display:flex;align-items:center;gap:9px;padding:9px 12px;border:1px solid rgba(245,158,11,.45);border-left:3px solid #f59e0b;border-radius:5px;background:repeating-linear-gradient(45deg,rgba(245,158,11,.10) 0 8px,rgba(245,158,11,.04) 8px 16px);color:#f59e0b;font-size:10.5px;letter-spacing:.18em;font-weight:700;text-transform:uppercase;animation:usbsim-pulse 1.6s ease-in-out infinite;}
.usbsim-hold-icon{font-size:14px;letter-spacing:0;}
.usbsim-queue{margin-top:4px;padding:10px 11px;border:1px solid #243248;border-radius:6px;background:#0d1622;display:flex;flex-direction:column;gap:8px;}
.usbsim-queue-hd{font-size:9.5px;letter-spacing:.22em;color:#22d3ee;text-transform:uppercase;font-weight:700;}
.usbsim-queue-row{display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap;font-family:ui-monospace,Menlo,monospace;font-size:11px;color:#e6edf6;}
.usbsim-queue-meta{color:#8a96aa;font-size:10.5px;}
.usbsim-queue-actions{display:flex;gap:8px;}
.usbsim-btn-approve,.usbsim-btn-reject{flex:1;background:#0a1119;border:1px solid #243248;padding:7px 10px;border-radius:5px;font-size:10.5px;letter-spacing:.18em;text-transform:uppercase;font-weight:700;cursor:pointer;font-family:inherit;color:#e6edf6;transition:border-color .15s,background .15s,color .15s;}
.usbsim-btn-approve{color:#22c55e;border-color:rgba(34,197,94,.5);}
.usbsim-btn-approve:hover{background:rgba(34,197,94,.10);border-color:#22c55e;}
.usbsim-btn-reject{color:#ef4444;border-color:rgba(239,68,68,.5);}
.usbsim-btn-reject:hover{background:rgba(239,68,68,.10);border-color:#ef4444;}
.usbsim-btn-approve:disabled,.usbsim-btn-reject:disabled{opacity:.45;cursor:not-allowed;}
.usbsim-btn-approve:focus-visible,.usbsim-btn-reject:focus-visible{outline:2px solid currentColor;outline-offset:2px;}
.usbsim-queue-note{margin:2px 0 0;font-size:10px;color:#6b7a90;line-height:1.5;}

/* ======================================================================
   POLISH v2 — enterprise authority (Palantir/Datadog/Bloomberg vibe)
   ====================================================================== */
.usbsim{font-family:"Inter","Segoe UI",-apple-system,BlinkMacSystemFont,Roboto,Helvetica,Arial,sans-serif;letter-spacing:0;}
.usbsim-mono,.usbsim-dl-mono dd,.usbsim-audit-list li .ev-t,.usbsim-audit-list li .ev-meta,.usbsim-queue-row{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;}

/* Hero — bigger, calmer, more authoritative */
.usbsim-hero{grid-template-columns:1fr 320px;gap:28px;padding:32px 34px 30px;border-color:#1a2638;border-radius:14px;box-shadow:0 0 0 1px rgba(34,211,238,.08),0 28px 72px -40px rgba(34,211,238,.45),inset 0 1px 0 rgba(255,255,255,.02);margin-bottom:20px;}
.usbsim-hero::before{background:
  radial-gradient(900px 260px at 0% 0%,rgba(34,211,238,.10),transparent 60%),
  radial-gradient(700px 200px at 100% 100%,rgba(34,197,94,.05),transparent 60%),
  linear-gradient(rgba(34,211,238,.035) 1px,transparent 1px) 0 0/100% 28px,
  linear-gradient(90deg,rgba(34,211,238,.025) 1px,transparent 1px) 0 0/28px 100%;
  animation:usbsim-grid 24s linear infinite;}
.usbsim-hero::after{content:"";position:absolute;left:0;right:0;top:-30%;height:80px;pointer-events:none;background:linear-gradient(180deg,transparent,rgba(34,211,238,.045),transparent);transform:translateY(0);animation:usbsim-scan 9s ease-in-out infinite;z-index:0;}
@keyframes usbsim-grid{from{background-position:0 0,0 0,0 0,0 0;}to{background-position:0 0,0 0,0 -56px,-56px 0;}}
@keyframes usbsim-scan{0%{transform:translateY(0);}50%{transform:translateY(580px);}100%{transform:translateY(0);}}

.usbsim-hero-title{font-size:30px;font-weight:800;letter-spacing:-.01em;margin-bottom:8px;}
.usbsim-hero-sub{font-size:13.5px;line-height:1.6;max-width:720px;margin-bottom:18px;color:#94a3b8;}
.usbsim-hero-grid{gap:14px 22px;}
.usbsim-k{font-size:9px;letter-spacing:.22em;color:#64748b;margin-bottom:4px;}
.usbsim-v{font-size:14px;letter-spacing:.01em;font-weight:600;}
.usbsim-hero-grid .usbsim-mono{font-size:12px;color:#cbd5e1;}

.usbsim-bigpill{padding:14px 18px;border-radius:10px;}
.usbsim-bigpill-text{font-size:15px;letter-spacing:.22em;}
.usbsim-bigpill-dot{width:11px;height:11px;}

.usbsim-hb{padding:9px 13px;border-radius:8px;}
.usbsim-btn-ghost{padding:10px 14px;border-radius:8px;min-height:38px;}

/* Scenario row — bigger touch targets */
.usbsim-scn{gap:10px;margin:0 0 20px;}
.usbsim-scn-btn{padding:13px 14px;border-radius:8px;min-height:50px;}
.usbsim-scn-l{font-size:12.5px;letter-spacing:0;font-weight:600;}

/* Pipeline polish + ambient flow */
.usbsim-pipe-wrap{margin:0 0 24px;}
.usbsim-pipe{padding:22px 20px;gap:14px;border-radius:12px;border-color:rgba(21,32,51,.85);background:rgba(8,14,22,.45);}
.usbsim-node{padding:15px 14px;border-radius:9px;background:rgba(13,22,34,.6);border-color:rgba(36,50,72,.55);transition:opacity .3s,border-color .3s,background .3s;}
/* Inactive-path dimming: when a scenario is running, fade nodes still pending */
.usbsim-pipe:has(.usbsim-node[data-state="active"]) .usbsim-node[data-state="pending"]{opacity:.45;}
/* Hero secondary stat (POLICY hash) — muted hierarchy vs primary 5 */
.usbsim-hero-sec .usbsim-k{color:#475569;}
.usbsim-hero-sec .usbsim-v{font-size:11.5px;color:#94a3b8;font-weight:500;}
.usbsim-stage{font-size:10.5px;letter-spacing:.2em;}
.usbsim-sub{font-size:11.5px;color:#7888a0;}
/* Card border calmer */
.usbsim-card{border-color:rgba(21,32,51,.85);background:rgba(8,14,22,.45);}
/* Verdict pill bigger inside why-card */
.usbsim-why #usbsim-verdict.usbsim-bigpill-sm{padding:13px 18px;}
.usbsim-why #usbsim-verdict .usbsim-bigpill-text{font-size:14px;letter-spacing:.24em;}
.usbsim-node + .usbsim-node::before{width:7px;background:linear-gradient(90deg,transparent,rgba(34,211,238,.35),transparent);height:2px;}
.usbsim-flow{position:absolute;top:50%;left:18px;right:18px;height:2px;transform:translateY(-50%);pointer-events:none;z-index:1;overflow:hidden;}
.usbsim-flow i{position:absolute;top:-1px;width:32px;height:4px;border-radius:2px;background:linear-gradient(90deg,transparent,rgba(34,211,238,.55),transparent);filter:blur(.5px);animation:usbsim-flow 6.5s linear infinite;}
.usbsim-flow i:nth-child(1){animation-delay:0s;}
.usbsim-flow i:nth-child(2){animation-delay:2.2s;}
.usbsim-flow i:nth-child(3){animation-delay:4.4s;}
@keyframes usbsim-flow{from{left:-40px;opacity:0;}10%{opacity:1;}90%{opacity:1;}to{left:100%;opacity:0;}}

/* Why card — make it the visual focal point */
.usbsim-why{padding:22px 24px;border-radius:12px;margin-bottom:20px;border-left-width:4px;box-shadow:0 0 0 1px rgba(34,211,238,.05),0 18px 50px -30px rgba(34,211,238,.4);}
.usbsim-why-hd h3{font-size:22px;letter-spacing:-.01em;font-weight:700;}
.usbsim-why-grid{gap:14px 24px;margin-bottom:14px;}
.usbsim-why-plain{font-size:14px;line-height:1.65;color:#cbd5e1;margin-bottom:14px;}
.usbsim-bigpill-sm{padding:10px 14px;}
.usbsim-bigpill-sm .usbsim-bigpill-text{font-size:12px;letter-spacing:.2em;}
#usbsim-verdict{transition:transform .35s cubic-bezier(.34,1.56,.64,1),background .25s,color .25s;}
#usbsim-verdict.is-flip{animation:usbsim-flip .55s cubic-bezier(.34,1.56,.64,1);}
@keyframes usbsim-flip{0%{transform:scale(.6) rotateX(45deg);opacity:.4;}60%{transform:scale(1.08) rotateX(-6deg);opacity:1;}100%{transform:scale(1) rotateX(0);}}
.usbsim-why[data-tone]{transition:border-left-color .35s,box-shadow .35s;}
.usbsim-why[data-tone="allow"]{box-shadow:0 0 0 1px rgba(34,197,94,.10),0 18px 50px -30px rgba(34,197,94,.5);}
.usbsim-why[data-tone="warn"]{box-shadow:0 0 0 1px rgba(245,158,11,.10),0 18px 50px -30px rgba(245,158,11,.5);}
.usbsim-why[data-tone="bad"]{box-shadow:0 0 0 1px rgba(239,68,68,.10),0 18px 50px -30px rgba(239,68,68,.5);}

/* Cards — calmer borders, more breathing room */
.usbsim-grid{gap:14px;margin-bottom:20px;}
.usbsim-card{padding:16px 18px;border-radius:10px;gap:12px;}
.usbsim-card header{padding-bottom:9px;}
.usbsim-card header h3{font-size:11.5px;letter-spacing:.16em;}
.usbsim-dl{gap:10px;}
.usbsim-dl dd{font-size:12.5px;line-height:1.5;}
.usbsim-dl-mono dd{font-size:11.5px;}

/* Provider card dim when on hold (human review pending) */
.usbsim[data-mode="hold"] #usbsim-provider-card{opacity:.6;filter:saturate(.7);}
.usbsim[data-mode="hold"] #usbsim-provider-card::after{content:"GOVERNANCE HOLD";position:absolute;top:14px;right:14px;font-size:9px;letter-spacing:.22em;color:#f59e0b;font-weight:700;padding:3px 7px;border:1px solid rgba(245,158,11,.5);border-radius:3px;background:rgba(245,158,11,.06);}

/* Audit timeline — bigger, calmer */
.usbsim-audit-list{gap:8px;max-height:340px;}
.usbsim-audit-list li{padding:10px 12px;border-radius:6px;grid-template-columns:96px 1fr auto;gap:12px 14px;}
.usbsim-audit-list li .ev-m b{font-size:12px;font-family:"Inter","Segoe UI",sans-serif;letter-spacing:0;}
.usbsim-audit-list li .ev-meta{font-size:10.5px;}

/* Foot */
.usbsim-foot{margin-top:14px;font-size:11px;color:#64748b;}

/* Heartbeat tick — calmer */
.usbsim-hb-lbl{color:#94a3b8;}
.usbsim-hb-lbl b{color:#22d3ee;font-weight:700;}

/* Operational telemetry stream — ambient activity, NOT audit chain */
.usbsim-stream-wrap{border:1px solid rgba(26,38,56,.7);border-radius:8px;background:rgba(8,14,22,.45);padding:10px 12px 8px;}
.usbsim-stream-hd{display:flex;align-items:center;gap:7px;font-size:9px;letter-spacing:.24em;color:#64748b;font-weight:700;text-transform:uppercase;margin-bottom:7px;}
.usbsim-stream{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:5px;max-height:96px;overflow:hidden;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11.5px;line-height:1.5;color:#94a3b8;}
.usbsim-stream li{display:grid;grid-template-columns:58px 1fr;gap:10px;align-items:baseline;opacity:0;transform:translateY(-3px);animation:usbsim-stream-in .4s ease-out forwards;}
.usbsim-stream li time{color:#64748b;font-size:10.5px;letter-spacing:.04em;}
.usbsim-stream li b{color:#cbd5e1;font-weight:600;letter-spacing:.02em;}
.usbsim-stream li.is-ok b{color:#86efac;}
.usbsim-stream li.is-warn b{color:#fbbf24;}
.usbsim-stream li.is-bad b{color:#fca5a5;}
@keyframes usbsim-stream-in{from{opacity:0;transform:translateY(-4px);}to{opacity:1;transform:translateY(0);}}
@media (prefers-reduced-motion:reduce){.usbsim-stream li{animation:none;opacity:1;transform:none;}}

/* Mobile / tablet polish — bigger touch targets, more breathing room */
@media (max-width:980px){
  .usbsim-hero{padding:24px;gap:18px;}
  .usbsim-hero-title{font-size:24px;}
  .usbsim-why{padding:18px 20px;}
  .usbsim-why-hd h3{font-size:18px;}
  .usbsim-bigpill{padding:11px 14px;}
  .usbsim-btn-ghost{min-height:44px;padding:11px 16px;}
}
@media (max-width:700px){
  .usbsim-hero{padding:20px;gap:14px;}
  .usbsim-hero-title{font-size:22px;line-height:1.2;}
  .usbsim-hero-sub{font-size:13px;}
  .usbsim-scn-btn{min-height:54px;padding:14px;}
  .usbsim-why{padding:16px;}
  .usbsim-why-hd h3{font-size:17px;}
  .usbsim-card{padding:14px 16px;}
  .usbsim-btn-approve,.usbsim-btn-reject{min-height:44px;font-size:11.5px;}
  .usbsim-btn-ghost{width:100%;}
  .usbsim-bigpill{width:100%;justify-content:center;}
  .usbsim-flow{display:none;}
}

/* ---- Audit timeline ---- */
.usbsim-audit{margin-bottom:6px;}
.usbsim-audit-list{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:6px;max-height:300px;overflow-y:auto;}
.usbsim-audit-list li{display:grid;grid-template-columns:90px 1fr auto;gap:10px 12px;padding:8px 10px;background:#0d1622;border:1px solid #1a2332;border-left:3px solid #243248;border-radius:5px;font-size:11px;align-items:start;animation:usbsim-appear .4s ease-out;}
.usbsim-audit-list li[data-tone="allow"]{border-left-color:#22c55e;}
.usbsim-audit-list li[data-tone="warn"]{border-left-color:#f59e0b;}
.usbsim-audit-list li[data-tone="bad"]{border-left-color:#ef4444;}
.usbsim-audit-list li .ev-t{color:#6b7a90;font-size:10.5px;letter-spacing:.04em;font-family:ui-monospace,Menlo,monospace;padding-top:2px;}
.usbsim-audit-list li .ev-m{color:#e6edf6;display:flex;flex-direction:column;gap:3px;}
.usbsim-audit-list li .ev-m b{font-weight:700;color:#e6edf6;font-size:11.5px;}
.usbsim-audit-list li .ev-meta{display:flex;flex-wrap:wrap;gap:4px 10px;font-size:10px;color:#6b7a90;font-family:ui-monospace,Menlo,monospace;}
.usbsim-audit-list li .ev-meta span b{color:#22d3ee;font-weight:600;}
.usbsim-audit-list li .ev-v{font-size:10px;letter-spacing:.16em;font-weight:700;padding:3px 7px;border-radius:3px;border:1px solid currentColor;align-self:start;}
.usbsim-audit-list li[data-tone="allow"] .ev-v{color:#22c55e;}
.usbsim-audit-list li[data-tone="warn"] .ev-v{color:#f59e0b;}
.usbsim-audit-list li[data-tone="bad"] .ev-v{color:#ef4444;}
.usbsim-audit-empty{display:block !important;grid-template-columns:none !important;color:#6b7a90 !important;border-left-color:#243248 !important;text-align:center;font-style:italic;padding:14px !important;animation:none !important;}
@keyframes usbsim-appear{from{opacity:0;transform:translateY(-6px);}to{opacity:1;transform:translateY(0);}}

.usbsim-foot{margin:10px 4px 0;font-size:10.5px;color:#6b7a90;letter-spacing:.02em;line-height:1.55;}

/* ---- Mobile / tablet executive mode ---- */
@media (max-width:980px){
  .usbsim-hero{grid-template-columns:1fr;}
  .usbsim-hero-side{flex-direction:row;flex-wrap:wrap;align-items:center;}
  .usbsim-hero-note{flex-basis:100%;margin:6px 0 0;}
  .usbsim-hero-grid{grid-template-columns:repeat(2,minmax(0,1fr));}
  .usbsim-hero-title{font-size:22px;}
  .usbsim-pipe{grid-template-columns:repeat(7,minmax(112px,1fr));overflow-x:auto;}
  .usbsim-pipe-wrap{overflow-x:auto;}
}
@media (max-width:700px){
  .usbsim-hero{padding:16px;}
  .usbsim-hero-title{font-size:20px;}
  .usbsim-hero-grid{grid-template-columns:1fr 1fr;}
  .usbsim-scn{grid-template-columns:1fr;}
  .usbsim-pipe{display:flex;flex-direction:column;gap:6px;}
  .usbsim-node + .usbsim-node::before{display:none;}
  .usbsim-pkt,.usbsim-pkt-rail{display:none;}
  .usbsim-why-hd{flex-direction:column;align-items:flex-start;}
  .usbsim-why-hd h3{font-size:16px;}
  .usbsim-why-grid{grid-template-columns:1fr;}
  .usbsim-grid{grid-template-columns:1fr;}
  .usbsim-audit-list li{grid-template-columns:70px 1fr;}
  .usbsim-audit-list li .ev-v{grid-column:2/3;justify-self:start;margin-top:4px;}
}
</style>

<script>
(function(){
  if (window.__usbsimInit) return; window.__usbsimInit = true;
  var root = document.getElementById('usbsim'); if (!root) return;

  var STAGES = ['REQUEST','POLICY BRAIN','ENFORCEMENT GATEWAY','POLICY VERIFICATION','DECISION','PROVIDER ADAPTER','EVIDENCE LAYER'];
  // Per-node states: 'active','verified','degraded','blocked','halt'
  var SCN = {
    valid: {
      label:'Valid Request', verdict:'ALLOW', tone:'allow', layer:'USBAY Control Plane',
      what:'Customer service agent requests order summary for case #4827.',
      policy:'policy.customer-support.v3 · signed',
      reason:'All controls verified. USBAY authorizes execution under the active signed policy.',
      plain:'USBAY verified the request against a current signed policy, confirmed the nonce was fresh, and authorized the provider to execute. Evidence sealed.',
      exec:'ALLOW — request executed under signed policy v3. All governance controls verified.',
      reg:'Decision class: ALLOW. Policy reference: customer-support.v3. Nonce: single-use, verified. Decision proof: signed (Ed25519). Evidence chain: anchored.',
      stages:['verified','verified','verified','verified','verified','verified','verified'],
      subs:['ingest OK','signature VERIFIED','fail-closed armed','nonce VERIFIED','ALLOW','adapter:openai','chain anchored'],
      providerRuns:true,
      provider:{adapter:'openai-gpt4o',model:'gpt-4o',exec:'Completed. Response returned to caller under governed envelope.',state:'COMPLETED',tone:'allow'},
      evidence:{state:'VERIFIED', tone:'allow', proof:'decision.proof:SIGNED'},
      human:{state:'INACTIVE', tone:'idle', text:'No escalation. Decision auto-approved under signed policy.'}
    },
    replay: {
      label:'Replay Attack', verdict:'DENY', tone:'bad', layer:'Policy Verification (nonce)',
      what:'Inbound request reuses a nonce from a prior execution (replay).',
      policy:'policy.customer-support.v3 · signed',
      reason:'Nonce already consumed. Replay rejected. Provider execution blocked.',
      plain:'A request arrived carrying a nonce USBAY had already seen. Replay protection rejected the request before the provider could be invoked.',
      exec:'DENY — nonce replay detected. Provider never invoked.',
      reg:'Decision class: DENY (replay). Mechanism: nonce single-use store. Provider executions: 0. Evidence chain: replay event recorded and signed.',
      stages:['verified','verified','verified','blocked','blocked','halt','degraded'],
      subs:['ingest OK','signature VERIFIED','fail-closed armed','nonce REPLAYED','DENY','never reached','event recorded'],
      providerRuns:false,
      provider:{adapter:'openai-gpt4o',model:'gpt-4o',exec:'Execution blocked: nonce replay detected before adapter invocation.',state:'BLOCKED',tone:'bad'},
      evidence:{state:'RECORDED', tone:'warn', proof:'replay.evidence:SIGNED'},
      human:{state:'INACTIVE', tone:'idle', text:'No escalation needed. Automated replay protection denied the request.'}
    },
    expired: {
      label:'Expired Policy', verdict:'BLOCKED', tone:'bad', layer:'Policy Brain (expiry)',
      what:'Inbound request matches a policy whose validity window has expired.',
      policy:'policy.customer-support.v2 · EXPIRED',
      reason:'Policy expired. Fail-closed enforcement halts the request before decision.',
      plain:'The applicable policy had passed its expiry window. USBAY fails closed in this case — no decision is rendered and no provider is invoked.',
      exec:'BLOCKED — policy expired. Fail-closed enforcement triggered.',
      reg:'Decision class: BLOCKED (policy expired). Enforcement: fail-closed. Provider executions: 0. Operator must rotate or extend the active policy.',
      stages:['verified','blocked','blocked','halt','blocked','halt','degraded'],
      subs:['ingest OK','policy EXPIRED','fail-closed TRIGGERED','skipped','BLOCKED','never reached','event recorded'],
      providerRuns:false,
      provider:{adapter:'openai-gpt4o',model:'gpt-4o',exec:'Execution blocked: no valid policy in force.',state:'BLOCKED',tone:'bad'},
      evidence:{state:'RECORDED', tone:'warn', proof:'fail_closed.evidence:SIGNED'},
      human:{state:'INACTIVE', tone:'idle', text:'No escalation. Operator must rotate or extend the active policy.'}
    },
    human: {
      label:'Human Review Required', verdict:'HUMAN_REVIEW', tone:'warn', layer:'Decision (threshold)',
      what:'Customer refund request exceeds auto-approval threshold ($2,500).',
      policy:'policy.refunds.v1 · signed',
      reason:'Policy requires human approver above threshold. Execution paused pending review.',
      plain:'The request was above the policy auto-approval threshold. USBAY paused execution and escalated to a named operator. Provider remains blocked until release.',
      exec:'HUMAN_REVIEW — execution paused. Escalated to on-call operator.',
      reg:'Decision class: HUMAN_REVIEW. Policy reference: refunds.v1 (threshold $2,500). Escalation: signed ticket opened. Provider executions: 0 until release.',
      stages:['verified','verified','verified','verified','degraded','halt','verified'],
      subs:['ingest OK','signature VERIFIED','fail-closed armed','nonce VERIFIED','HUMAN_REVIEW','paused','escalation logged'],
      providerRuns:false,
      provider:{adapter:'openai-gpt4o',model:'gpt-4o',exec:'Execution paused. Provider not invoked until human approver releases the gate.',state:'PAUSED',tone:'warn'},
      evidence:{state:'PENDING', tone:'warn', proof:'review.ticket:OPEN'},
      human:{state:'ESCALATED', tone:'warn', text:'Escalation routed to on-call governance operator. Audit event written with reviewer assignment. Provider remains blocked until release.'}
    },
    sig: {
      label:'Signature Failure', verdict:'FAIL_CLOSED', tone:'bad', layer:'Policy Brain (signature)',
      what:'Inbound policy bundle fails Ed25519 signature verification.',
      policy:'policy.bundle.* · signature INVALID',
      reason:'Policy signature invalid. USBAY fails closed; no decision is rendered, no provider invoked.',
      plain:'The policy bundle in force did not pass cryptographic signature verification. USBAY fails closed — no decision is rendered and the provider is never invoked.',
      exec:'FAIL_CLOSED — policy signature invalid. Provider never invoked.',
      reg:'Decision class: FAIL_CLOSED (Ed25519 signature failure). Enforcement: hard-stop. Provider executions: 0. Operator must rotate signing key and re-sign.',
      stages:['verified','blocked','blocked','halt','blocked','halt','degraded'],
      subs:['ingest OK','signature INVALID','fail-closed TRIGGERED','skipped','FAIL_CLOSED','never reached','event recorded'],
      providerRuns:false,
      provider:{adapter:'openai-gpt4o',model:'gpt-4o',exec:'Execution blocked: signature verification failure halted the pipeline.',state:'BLOCKED',tone:'bad'},
      evidence:{state:'RECORDED', tone:'warn', proof:'signature.fail.evidence:SIGNED'},
      human:{state:'INACTIVE', tone:'idle', text:'No escalation. Operator must rotate signing key and re-sign the bundle.'}
    },
    drift: {
      label:'Drift Detected', verdict:'DEGRADED', tone:'warn', layer:'Enforcement Gateway (parity)',
      what:'Runtime parity check detects mismatch between deployed runtime and signed attestation.',
      policy:'policy.customer-support.v3 · signed',
      reason:'Runtime drift detected. Decision rendered DEGRADED; operator action required.',
      plain:'The runtime in service no longer matches the signed attestation. USBAY rendered a DEGRADED verdict and held provider execution until parity is restored.',
      exec:'DEGRADED — runtime drift vs. attestation. Provider held.',
      reg:'Decision class: DEGRADED (runtime parity mismatch). Enforcement: hold. Provider executions: 0. Operator action: restore parity or accept drift via policy.',
      stages:['verified','verified','degraded','degraded','degraded','halt','degraded'],
      subs:['ingest OK','signature VERIFIED','runtime DRIFT','parity WARN','DEGRADED','held','drift logged'],
      providerRuns:false,
      provider:{adapter:'openai-gpt4o',model:'gpt-4o',exec:'Execution held. Provider not invoked while runtime parity is untrusted.',state:'HELD',tone:'warn'},
      evidence:{state:'DEGRADED', tone:'warn', proof:'drift.evidence:SIGNED'},
      human:{state:'NOTIFIED', tone:'warn', text:'Operator notified of runtime drift. Provider remains held until parity is restored or policy explicitly accepts drift.'}
    },
    quorum: {
      label:'Verifier Quorum Failure', verdict:'BLOCKED', tone:'bad', layer:'Policy Verification (quorum)',
      what:'Verifier continuity quorum cannot be reached for this decision.',
      policy:'policy.customer-support.v3 · signed',
      reason:'Verifier quorum failed. USBAY blocks execution; no single verifier may unilaterally authorize.',
      plain:'The required quorum of independent verifiers could not be reached. USBAY refuses to let any single verifier authorize execution. Provider blocked.',
      exec:'BLOCKED — verifier quorum not reached.',
      reg:'Decision class: BLOCKED (verifier continuity). Mechanism: threshold quorum. Provider executions: 0. Operator action: rotate or re-enroll a verifier.',
      stages:['verified','verified','verified','blocked','blocked','halt','degraded'],
      subs:['ingest OK','signature VERIFIED','fail-closed armed','quorum FAILED','BLOCKED','never reached','continuity logged'],
      providerRuns:false,
      provider:{adapter:'openai-gpt4o',model:'gpt-4o',exec:'Execution blocked: verifier continuity quorum not reached.',state:'BLOCKED',tone:'bad'},
      evidence:{state:'RECORDED', tone:'warn', proof:'quorum.fail.evidence:SIGNED'},
      human:{state:'NOTIFIED', tone:'warn', text:'Operator notified to restore verifier quorum (rotate or re-enroll a verifier).'}
    },
    adapter: {
      label:'Provider Disabled', verdict:'FAIL_CLOSED', tone:'bad', layer:'Provider Adapter (kill-switch)',
      what:'Customer request targets an adapter that has been disabled by policy.',
      policy:'policy.adapter.kill_switch · ACTIVE',
      reason:'Adapter disabled by governance. Request never reaches the model provider.',
      plain:'A governance kill-switch is active on this adapter. The request was accepted, decision was rendered, but no outbound call was made to the provider.',
      exec:'FAIL_CLOSED — adapter disabled by policy. No provider call issued.',
      reg:'Decision class: FAIL_CLOSED (adapter kill-switch). Mechanism: governance policy. Provider executions: 0. Re-enable requires explicit policy change.',
      stages:['verified','verified','verified','verified','blocked','blocked','degraded'],
      subs:['ingest OK','signature VERIFIED','fail-closed armed','nonce VERIFIED','FAIL_CLOSED','adapter DISABLED','event recorded'],
      providerRuns:false,
      provider:{adapter:'openai-gpt4o (DISABLED)',model:'gpt-4o',exec:'Adapter disabled at the gateway. No outbound call was issued to the provider.',state:'DISABLED',tone:'bad'},
      evidence:{state:'RECORDED', tone:'warn', proof:'kill_switch.evidence:SIGNED'},
      human:{state:'INACTIVE', tone:'idle', text:'No escalation. Operator must explicitly re-enable adapter via policy change.'}
    }
  };

  function rndHex(n){
    try {
      var b = new Uint8Array(n); crypto.getRandomValues(b);
      return Array.prototype.map.call(b, function(x){ var h=x.toString(16); return h.length<2?'0'+h:h; }).join('');
    } catch (e) {
      var s=''; for (var i=0;i<n*2;i++){ s += Math.floor(Math.random()*16).toString(16); } return s;
    }
  }
  function ts(){ var d=new Date(); return d.toISOString().replace('T',' ').replace(/\.\d+Z$/,'Z'); }
  function tsShort(){ var d=new Date(); return d.toISOString().substr(11,8) + 'Z'; }
  function pad(s,n){ s=String(s); while(s.length<n) s+=' '; return s; }
  function relTime(then){
    if (!then) return '—';
    var s = Math.max(0, Math.round((Date.now()-then)/1000));
    if (s < 2) return 'just now';
    if (s < 60) return s + 's ago';
    var m = Math.floor(s/60); if (m < 60) return m + 'm ' + (s%60) + 's ago';
    return Math.floor(m/60) + 'h ago';
  }

  // Element refs
  var nodes = root.querySelectorAll('.usbsim-node');
  var subs  = root.querySelectorAll('.usbsim-node [data-sub]');
  var btns  = root.querySelectorAll('.usbsim-scn-btn');
  var pkt   = document.getElementById('usbsim-pkt');
  var pipe  = document.getElementById('usbsim-pipe');
  var heroPill = document.getElementById('usbsim-hero-pill');

  // Hero / heartbeat
  var hbClock = document.getElementById('hb-clock');
  var hbTick  = document.getElementById('hb-tick');
  var hbAudit = document.getElementById('hb-audit-preview');
  var hbReqid = document.getElementById('hb-reqid-preview');
  var hbLast  = document.getElementById('hb-last-evidence');
  var hbPolicyHash = document.getElementById('hb-policy-hash');
  var hbIntegrity  = document.getElementById('hb-integrity');
  var hbPosture = document.getElementById('hb-posture');
  var hbTrust   = document.getElementById('hb-trust');

  // Why card
  var why = document.getElementById('usbsim-why');
  var whyH = document.getElementById('usbsim-why-h');
  var verdictPill = document.getElementById('usbsim-verdict');
  var whyLayer = document.getElementById('why-layer');
  var whyResult = document.getElementById('why-result');
  var whyReqid = document.getElementById('why-reqid');
  var whyPolicy = document.getElementById('why-policy');
  var whyWhat = document.getElementById('why-what');
  var whyReason = document.getElementById('why-reason');
  var whyPlain = document.getElementById('why-plain');
  var whyExec = document.getElementById('why-exec');
  var whyReg = document.getElementById('why-reg');
  var techPolicyHash = document.getElementById('tech-policy-hash');
  var techNonce = document.getElementById('tech-nonce');
  var techAuditHash = document.getElementById('tech-audit-hash');
  var techProof = document.getElementById('tech-proof');
  var techStages = document.getElementById('tech-stages');
  var techTs = document.getElementById('tech-ts');

  // Provider card
  var provCard = document.getElementById('usbsim-provider-card');
  var provState = document.getElementById('usbsim-provider-state');
  var provAdapter = document.getElementById('usbsim-adapter');
  var provModel = document.getElementById('usbsim-model');
  var provExec = document.getElementById('usbsim-exec');
  var blockedFx = document.getElementById('usbsim-blockedfx');

  // Evidence card
  var evCard = document.getElementById('usbsim-evidence-card');
  var evState = document.getElementById('usbsim-ev-state');
  var evHash = document.getElementById('usbsim-audit-hash');
  var evNonce = document.getElementById('usbsim-nonce');
  var evPolHash = document.getElementById('usbsim-policy-hash');
  var evProof = document.getElementById('usbsim-proof');
  var evTs = document.getElementById('usbsim-ts');

  // Human card
  var humanCard = document.getElementById('usbsim-human-card');
  var humanState = document.getElementById('usbsim-human-state');
  var humanText = document.getElementById('usbsim-human-text');
  var holdBanner = document.getElementById('usbsim-hold-banner');
  var queueEl = document.getElementById('usbsim-queue');
  var queueTicket = document.getElementById('usbsim-queue-ticket');
  var queueMeta = document.getElementById('usbsim-queue-meta');
  var approveBtn = document.getElementById('usbsim-approve');
  var rejectBtn = document.getElementById('usbsim-reject');
  var pendingReview = null;

  // Audit
  var auditList = document.getElementById('usbsim-audit-list');
  var auditCount = document.getElementById('usbsim-audit-count');
  var copyBtn = document.getElementById('usbsim-copy');

  var auditEvents = [];
  var running = false;
  var runSeq = 0;
  var lastRun = null;
  var lastEvidenceAt = null;
  var sessionPolicyHash = 'sha256:' + rndHex(16);
  var hbCount = 0;
  var integrityPct = 99.7;

  function setPill(el, base, tone){
    el.className = 'usbsim-pill ' + (tone ? ('usbsim-pill-' + tone) : 'usbsim-pill-idle');
    if (base) el.textContent = base;
  }
  function setVerdictPill(text, mode){
    verdictPill.setAttribute('data-mode', mode || 'idle');
    verdictPill.className = 'usbsim-bigpill usbsim-bigpill-sm';
    verdictPill.innerHTML = '<span class="usbsim-bigpill-dot"></span><span class="usbsim-bigpill-text">' + text + '</span>';
    verdictPill.classList.remove('is-flip');
    void verdictPill.offsetWidth;
    verdictPill.classList.add('is-flip');
  }
  function setHeroPill(text, mode){
    heroPill.setAttribute('data-mode', mode);
    heroPill.innerHTML = '<span class="usbsim-bigpill-dot"></span><span class="usbsim-bigpill-text">' + text + '</span>';
  }
  function setCardTone(card, tone){
    if (tone) card.setAttribute('data-tone', tone); else card.removeAttribute('data-tone');
  }
  function resetPipeline(){
    var defaults = ['ingest','policy.signature','fail-closed','nonce.replay','pending','idle','chain'];
    for (var i=0;i<nodes.length;i++){
      nodes[i].setAttribute('data-state','pending');
      subs[i].textContent = defaults[i];
    }
    pkt.removeAttribute('data-tone');
    pkt.setAttribute('data-active','0');
    pkt.style.left = '0px';
  }
  function movePacketTo(stageIdx, tone){
    if (!nodes[stageIdx]) return;
    var pipeRect = pipe.getBoundingClientRect();
    var nRect = nodes[stageIdx].getBoundingClientRect();
    var x = (nRect.left - pipeRect.left) + nRect.width / 2;
    if (tone) pkt.setAttribute('data-tone', tone); else pkt.removeAttribute('data-tone');
    pkt.setAttribute('data-active','1');
    pkt.style.left = x + 'px';
  }
  function hidePacket(){
    pkt.setAttribute('data-active','0');
  }

  // ---------- Heartbeat ----------
  function tickHeartbeat(){
    hbCount += 1;
    if (hbClock) hbClock.textContent = tsShort();
    if (hbTick)  hbTick.textContent = String(hbCount);
    if (!running){
      if (hbAudit) hbAudit.textContent = 'sha256:' + rndHex(6) + '…';
      if (hbReqid) hbReqid.textContent = 'req_' + rndHex(4) + '…';
    }
    if (hbLast) hbLast.textContent = lastEvidenceAt ? relTime(lastEvidenceAt) : 'awaiting first event';
    // Integrity drift small
    integrityPct = Math.max(96.0, Math.min(99.99, integrityPct + (Math.random()-0.5)*0.06));
    if (hbIntegrity) hbIntegrity.textContent = integrityPct.toFixed(2) + ' %';
  }
  hbClock && (hbClock.textContent = tsShort());
  hbPolicyHash && (hbPolicyHash.textContent = sessionPolicyHash);
  tickHeartbeat();
  setInterval(tickHeartbeat, 1200);

  // ---------- Ambient operational telemetry (NOT audit chain) ----------
  var streamEl = root.querySelector('#usbsim-stream');
  var STREAM_TEMPLATES = [
    {t:'verifier',  tone:'ok',   msg:function(){return 'heartbeat OK · quorum 3/3';}},
    {t:'attest',    tone:'ok',   msg:function(){return 'runtime parity OK · drift 0.0%';}},
    {t:'nonce',     tone:'ok',   msg:function(){return 'cache rotate · ' + (900+Math.floor(Math.random()*250)) + ' entries';}},
    {t:'policy',    tone:'ok',   msg:function(){return 'bundle refresh · sha256:' + rndHex(6) + '…';}},
    {t:'evidence',  tone:'ok',   msg:function(){return 'chain seal · h=' + rndHex(6) + '…';}},
    {t:'trust',     tone:'ok',   msg:function(){return 'posture renew · LIVE';}},
    {t:'queue',     tone:'ok',   msg:function(){return 'scan · 0 pending review';}},
    {t:'replay',    tone:'warn', msg:function(){return 'window slide · 64s lookback';}},
    {t:'audit',     tone:'ok',   msg:function(){return 'fsync OK · ' + (Math.floor(Math.random()*40)+10) + 'ms';}}
  ];
  function pushStream(){
    if (!streamEl) return;
    var pick = STREAM_TEMPLATES[Math.floor(Math.random()*STREAM_TEMPLATES.length)];
    var li = document.createElement('li');
    li.className = 'is-' + pick.tone;
    li.innerHTML = '<time>' + tsShort() + '</time><span><b>' + pick.t + '</b> · ' + pick.msg() + '</span>';
    streamEl.insertBefore(li, streamEl.firstChild);
    while (streamEl.children.length > 3) streamEl.removeChild(streamEl.lastChild);
  }
  pushStream(); pushStream(); pushStream();
  (function loopStream(){ setTimeout(function(){ pushStream(); loopStream(); }, 4500 + Math.floor(Math.random()*2000)); })();

  // ---------- Scenario animation ----------
  function applyScenario(key){
    if (running) return;
    var scn = SCN[key]; if (!scn) return;
    running = true;
    runSeq += 1;
    var mySeq = runSeq;
    btns.forEach(function(b){ b.classList.toggle('is-active', b.getAttribute('data-scn')===key); b.disabled = true; });
    setHeroPill('RUNNING · ' + scn.label.toUpperCase(), 'running');
    setVerdictPill('PENDING', 'active');
    why.setAttribute('data-tone','');
    setCardTone(provCard, null);
    setCardTone(evCard, null);
    setCardTone(humanCard, null);
    blockedFx.hidden = true;
    holdBanner.hidden = true; queueEl.hidden = true; pendingReview = null;

    var reqId = 'req_' + rndHex(8);
    var nonce = 'n_' + rndHex(12);
    var auditHash = 'sha256:' + rndHex(16);
    var polHash = sessionPolicyHash;
    var stamp = ts();

    // Why card pre-fill
    whyH.textContent = 'Running: ' + scn.label;
    whyLayer.textContent = scn.layer;
    whyResult.textContent = 'PENDING';
    whyReqid.textContent = reqId;
    whyPolicy.textContent = scn.policy;
    whyWhat.textContent = scn.what;
    whyReason.textContent = 'Awaiting decision…';
    whyPlain.textContent = 'Pipeline is executing…';
    whyExec.textContent = 'Pipeline running…';
    whyReg.textContent = 'Pipeline running…';
    techPolicyHash.textContent = polHash;
    techNonce.textContent = nonce;
    techAuditHash.textContent = auditHash;
    techProof.textContent = 'pending';
    techStages.textContent = '—';
    techTs.textContent = stamp;

    // Provider pre-fill
    provAdapter.textContent = scn.provider.adapter;
    provModel.textContent = scn.provider.model;
    provExec.textContent = 'Awaiting decision…';
    setPill(provState, 'PENDING', 'active');

    // Evidence pre-fill
    evHash.textContent = auditHash;
    evNonce.textContent = nonce;
    evPolHash.textContent = polHash;
    evProof.textContent = 'pending';
    evTs.textContent = stamp;
    setPill(evState, 'BUILDING', 'active');

    // Human pre-fill
    humanText.textContent = 'Awaiting decision…';
    setPill(humanState, 'PENDING', 'active');
    resetPipeline();

    var i = 0;
    function step(){
      if (i > 0){
        var prev = scn.stages[i-1];
        nodes[i-1].setAttribute('data-state', prev);
        subs[i-1].textContent = scn.subs[i-1];
      }
      if (i >= nodes.length){ return finalize(); }
      var stage = scn.stages[i];
      if (stage === 'halt'){
        nodes[i].setAttribute('data-state','halt');
        subs[i].textContent = scn.subs[i];
        // packet doesn't move into halted stages
      } else {
        nodes[i].setAttribute('data-state','active');
        subs[i].textContent = '…';
        movePacketTo(i, stage === 'blocked' ? 'bad' : (stage === 'degraded' ? 'warn' : null));
      }
      i++;
      setTimeout(step, stage === 'halt' ? 140 : 360);
    }

    function finalize(){
      // Settle pipeline + packet
      var lastIdx = -1;
      for (var k=scn.stages.length-1; k>=0; k--){ if (scn.stages[k] !== 'halt'){ lastIdx = k; break; } }
      if (lastIdx >= 0) movePacketTo(lastIdx, scn.tone === 'allow' ? null : (scn.tone === 'warn' ? 'warn' : 'bad'));
      setTimeout(hidePacket, 700);

      // Why card final
      why.setAttribute('data-tone', scn.tone);
      whyH.textContent = scn.label + ' · ' + scn.verdict;
      setVerdictPill(scn.verdict, scn.tone);
      whyResult.textContent = scn.verdict;
      whyReason.textContent = scn.reason;
      whyPlain.textContent = scn.plain;
      whyExec.textContent = scn.exec;
      whyReg.textContent = scn.reg;
      techStages.textContent = scn.stages.map(function(s,ix){ return STAGES[ix]+':'+s.toUpperCase(); }).join(' · ');
      techProof.textContent = scn.evidence.proof;

      // Provider
      setPill(provState, scn.provider.state, scn.provider.tone);
      setCardTone(provCard, scn.provider.tone);
      provExec.textContent = scn.provider.exec;
      blockedFx.hidden = scn.providerRuns;

      // Evidence
      setPill(evState, scn.evidence.state, scn.evidence.tone);
      setCardTone(evCard, scn.evidence.tone);
      evProof.textContent = scn.evidence.proof;

      // Human
      setPill(humanState, scn.human.state, scn.human.tone);
      setCardTone(humanCard, scn.human.tone === 'idle' ? null : scn.human.tone);
      humanText.textContent = scn.human.text;
      var isHumanReview = (scn.verdict === 'HUMAN_REVIEW');
      holdBanner.hidden = !isHumanReview;
      queueEl.hidden = !isHumanReview;
      root.setAttribute('data-mode', isHumanReview ? 'hold' : scn.tone);
      if (isHumanReview){
        var ticket = 'REV-' + rndHex(4).toUpperCase();
        queueTicket.textContent = ticket;
        queueMeta.textContent = 'reviewer: on-call · opened ' + tsShort();
        approveBtn.disabled = false; rejectBtn.disabled = false;
        pendingReview = { ticket: ticket, reqId: reqId, label: scn.label, polHash: polHash };
      } else {
        pendingReview = null;
      }

      // Audit append
      var ev = {
        t: tsShort(), label: scn.label, verdict: scn.verdict, tone: scn.tone,
        reqId: reqId, nonce: nonce, audit: auditHash, polHash: polHash, policy: scn.policy,
        stamp: stamp, provider: scn.provider.state, providerRuns: scn.providerRuns,
        exec: scn.exec, reg: scn.reg, reason: scn.reason
      };
      auditEvents.unshift(ev);
      if (auditEvents.length > 14) auditEvents.length = 14;
      renderAudit();

      lastRun = ev;
      lastEvidenceAt = Date.now();

      // Hero pill reflects most recent verdict tone
      setHeroPill('VERDICT · ' + scn.verdict, scn.tone === 'allow' ? 'allow' : (scn.tone === 'warn' ? 'degraded' : 'blocked'));
      // After a beat, restore LIVE only if this is still the latest run
      setTimeout(function(){
        if (!running && mySeq === runSeq) setHeroPill('LIVE', 'live');
      }, 4200);

      btns.forEach(function(b){ b.disabled = false; });
      running = false;
    }

    setTimeout(step, 140);
  }

  function renderAudit(){
    auditList.innerHTML = '';
    if (auditEvents.length === 0){
      var li = document.createElement('li');
      li.className = 'usbsim-audit-empty';
      li.textContent = 'No simulations run yet. Trigger a scenario to append a signed audit event.';
      auditList.appendChild(li);
      auditCount.textContent = '0 events';
      return;
    }
    for (var k=0;k<auditEvents.length;k++){
      var e = auditEvents[k];
      var li = document.createElement('li');
      li.setAttribute('data-tone', e.tone);
      var t = document.createElement('span'); t.className = 'ev-t'; t.textContent = e.t;
      var m = document.createElement('span'); m.className = 'ev-m';
      var b = document.createElement('b'); b.textContent = e.label;
      m.appendChild(b);
      var meta = document.createElement('span'); meta.className = 'ev-meta';
      meta.innerHTML =
        '<span>req <b>' + e.reqId + '</b></span>' +
        '<span>nonce <b>' + e.nonce.slice(0,18) + '…</b></span>' +
        '<span>policy <b>' + e.polHash.slice(7,21) + '…</b></span>' +
        '<span>audit <b>' + e.audit.slice(7,21) + '…</b></span>' +
        '<span>provider <b>' + e.provider + (e.providerRuns ? '' : ' / no-exec') + '</b></span>';
      m.appendChild(meta);
      var v = document.createElement('span'); v.className = 'ev-v'; v.textContent = e.verdict;
      li.appendChild(t); li.appendChild(m); li.appendChild(v);
      auditList.appendChild(li);
    }
    auditCount.textContent = auditEvents.length + ' event' + (auditEvents.length===1?'':'s');
  }

  function buildSummary(){
    var L = [];
    L.push('USBAY Live Governance Simulator — demo summary');
    L.push('Generated: ' + ts());
    L.push('');
    if (lastRun){
      L.push('LAST DECISION');
      L.push('  scenario     : ' + lastRun.label);
      L.push('  verdict      : ' + lastRun.verdict);
      L.push('  request_id   : ' + lastRun.reqId);
      L.push('  nonce        : ' + lastRun.nonce);
      L.push('  policy       : ' + lastRun.policy);
      L.push('  policy_hash  : ' + lastRun.polHash);
      L.push('  audit_hash   : ' + lastRun.audit);
      L.push('  provider     : ' + lastRun.provider + (lastRun.providerRuns ? ' (executed under USBAY control)' : ' (execution blocked or paused)'));
      L.push('  timestamp    : ' + lastRun.stamp);
      L.push('');
      L.push('  Executive    : ' + lastRun.exec);
      L.push('  Regulator    : ' + lastRun.reg);
      L.push('  Reason       : ' + lastRun.reason);
      L.push('');
    }
    L.push('AUDIT TIMELINE (' + auditEvents.length + ' event' + (auditEvents.length===1?'':'s') + ')');
    for (var k=0;k<auditEvents.length;k++){
      var e = auditEvents[k];
      L.push('  ' + e.t + '  ' + pad(e.verdict,13) + '  ' + e.label + '  ' + e.reqId + '  audit ' + e.audit.slice(0,28) + '…');
    }
    L.push('');
    L.push('Note: Simulator animates client-side. Backend governance logic, fail-closed enforcement,');
    L.push('policy validator, nonce/replay protection, attestation, and evidence verification are unchanged.');
    return L.join('\n');
  }

  copyBtn && copyBtn.addEventListener('click', function(){
    var text = buildSummary();
    var done = function(ok){
      var orig = copyBtn.textContent;
      copyBtn.textContent = ok ? 'Copied ✓' : 'Copy failed';
      setTimeout(function(){ copyBtn.textContent = orig; }, 1400);
    };
    if (navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(text).then(function(){done(true);}, function(){done(false);});
    } else {
      try {
        var ta = document.createElement('textarea'); ta.value = text; ta.setAttribute('readonly','');
        ta.style.position='absolute'; ta.style.left='-9999px'; document.body.appendChild(ta);
        ta.select(); var ok = document.execCommand('copy'); document.body.removeChild(ta); done(ok);
      } catch(e){ done(false); }
    }
  });

  btns.forEach(function(b){
    b.addEventListener('click', function(){ applyScenario(b.getAttribute('data-scn')); });
  });

  function reviewAction(kind){
    if (!pendingReview) return;
    approveBtn.disabled = true; rejectBtn.disabled = true;
    var isApprove = (kind === 'approve');
    var newVerdict = isApprove ? 'ALLOW (released)' : 'DENY (rejected)';
    var tone = isApprove ? 'allow' : 'bad';
    var stamp = ts();
    var newAuditHash = 'sha256:' + rndHex(16);
    setPill(humanState, isApprove ? 'APPROVED' : 'REJECTED', tone);
    setCardTone(humanCard, tone);
    holdBanner.hidden = true;
    root.setAttribute('data-mode', tone);
    queueMeta.textContent = (isApprove ? 'released by operator' : 'rejected by operator') + ' · ' + tsShort();
    humanText.textContent = isApprove
      ? 'Operator released the gate. Provider execution authorized under signed policy. Audit event written.'
      : 'Operator rejected the request. Provider execution denied. Audit event written.';
    if (isApprove){
      setPill(provState, 'COMPLETED', 'allow'); setCardTone(provCard, 'allow');
      provExec.textContent = 'Operator-approved execution completed under USBAY control. Response returned.';
      blockedFx.hidden = true;
    } else {
      setPill(provState, 'BLOCKED', 'bad'); setCardTone(provCard, 'bad');
      provExec.textContent = 'Operator rejected the gate. No outbound call issued.';
      blockedFx.hidden = false;
    }
    setPill(evState, isApprove ? 'VERIFIED' : 'RECORDED', tone === 'allow' ? 'allow' : 'warn');
    setCardTone(evCard, tone === 'allow' ? 'allow' : 'warn');
    evHash.textContent = newAuditHash; evProof.textContent = isApprove ? 'review.release:SIGNED' : 'review.reject:SIGNED'; evTs.textContent = stamp;
    var ev = {
      t: tsShort(), label: pendingReview.label + ' · ' + (isApprove ? 'operator APPROVE' : 'operator REJECT'),
      verdict: isApprove ? 'ALLOW' : 'DENY', tone: tone,
      reqId: pendingReview.reqId, nonce: 'n_' + rndHex(12),
      audit: newAuditHash, polHash: pendingReview.polHash, policy: 'policy.refunds.v1 · signed',
      stamp: stamp, provider: isApprove ? 'COMPLETED' : 'BLOCKED', providerRuns: isApprove,
      exec: newVerdict + ' — ' + pendingReview.ticket,
      reg: 'Operator ' + (isApprove ? 'released' : 'rejected') + ' review ticket ' + pendingReview.ticket + ' for request ' + pendingReview.reqId + '. Decision recorded and signed.',
      reason: 'Human reviewer ' + (isApprove ? 'approved' : 'rejected') + ' the held request.'
    };
    auditEvents.unshift(ev);
    if (auditEvents.length > 14) auditEvents.length = 14;
    renderAudit();
    lastRun = ev; lastEvidenceAt = Date.now();
    pendingReview = null;
  }
  approveBtn && approveBtn.addEventListener('click', function(){ reviewAction('approve'); });
  rejectBtn && rejectBtn.addEventListener('click', function(){ reviewAction('reject'); });
})();
</script>
"""


def governance_gateway_html():
    snapshot = runtime_status_snapshot()
    parity = snapshot.get("runtime_parity", {})
    identity = snapshot.get("device_identity", {})
    challenge = snapshot.get("challenge_response", {})
    renewal = snapshot.get("trust_renewal", {})
    verifier = snapshot.get("verifier_continuity", {})
    state_label = "UNVERIFIED"
    if snapshot.get("status") == "FAIL_CLOSED":
        state_label = "BLOCKED"
    public_status = str(snapshot.get("status", "UNKNOWN"))
    public_policy_signature_valid = bool(snapshot.get("policy_signature_valid"))
    public_replay_protection_active = bool(snapshot.get("replay_protection_active"))
    public_policy_version = snapshot.get("policy_version")
    public_policy_version_display = "—" if public_policy_version in (None, "") else str(public_policy_version)
    public_verified = public_status == "OK" and public_policy_signature_valid and public_replay_protection_active
    public_verified_display = "true" if public_verified else "false"
    public_status_class = "ok" if public_status == "OK" else "fail"
    public_verified_class = "ok" if public_verified else "fail"
    public_signature_class = "ok" if public_policy_signature_valid else "fail"
    public_replay_class = "ok" if public_replay_protection_active else "fail"
    parity_status = str(parity.get("runtime_parity_status", "UNTRUSTED"))
    identity_status = str(identity.get("device_lifecycle_status", "DEGRADED"))
    identity_state = str(identity.get("identity_state", "IDENTITY_UNENROLLED"))
    challenge_status = str(challenge.get("challenge_liveness_status", "DEGRADED"))
    challenge_state = str(challenge.get("challenge_state", "CHALLENGE_NOT_ISSUED"))
    renewal_status = str(renewal.get("trust_renewal_status", "DEGRADED"))
    renewal_state = str(renewal.get("renewal_state", "TRUST_RENEWAL_NOT_STARTED"))
    verifier_status = str(verifier.get("verifier_continuity_status", "DEGRADED"))
    verifier_state = str(verifier.get("continuity_state", "VERIFIER_CONTINUITY_NOT_STARTED"))
    device_trust_status = str(snapshot.get("device_trust_status", "DEGRADED"))
    # Aggregate posture: VERIFIED iff every control is VERIFIED; BLOCKED iff
    # status is FAIL_CLOSED; otherwise DEGRADED. Purely presentational — the
    # underlying snapshot fields are unchanged.
    control_states = [parity_status, identity_status, challenge_status, renewal_status, verifier_status]
    if state_label == "BLOCKED":
        posture = "BLOCKED"
    elif all(s == "VERIFIED" for s in control_states) and public_verified:
        posture = "VERIFIED"
    else:
        posture = "DEGRADED"
    posture_class = posture.lower()
    posture_copy = {
        "VERIFIED": "All governance controls are signed, verified, and within policy.",
        "DEGRADED": "One or more governance controls require attention. Enforcement remains active.",
        "BLOCKED": "Governance enforcement is fail-closed. Runtime decisions are suspended.",
    }[posture]
    verified_count = sum(1 for s in control_states if s == "VERIFIED")
    total_controls = len(control_states)
    policy_hash_full = str(snapshot.get("policy_hash") or "")
    policy_hash_short = (policy_hash_full[:12] + "…") if len(policy_hash_full) > 12 else (policy_hash_full or "—")
    git_commit_full = str(snapshot.get("git_commit") or "")
    git_commit_short = (git_commit_full[:7]) if git_commit_full else "—"
    deployment_revision = str(snapshot.get("deployment_revision") or "—")
    mode_value = str(snapshot.get("mode") or "—")
    reason_value = str(snapshot.get("reason") or "—")

    def control_card(card_id, title, status, fields, warning, status_label=None):
        s_class = "verified" if status == "VERIFIED" else ("blocked" if status in ("BLOCKED", "FAIL_CLOSED") else "degraded")
        rows_parts = []
        for (label, value_id, value) in fields:
            rows_parts.append(
                '<div class="kv"><span class="kv-k">' + html.escape(label)
                + '</span><span class="kv-v" id="' + html.escape(value_id) + '">'
                + html.escape(str(value)) + '</span></div>'
            )
        rows = "".join(rows_parts)
        if warning and warning[1]:
            warn_html = '<p class="card-warn" id="' + html.escape(warning[0]) + '">' + html.escape(warning[1]) + '</p>'
        elif warning:
            warn_html = '<p class="card-warn" id="' + html.escape(warning[0]) + '" hidden></p>'
        else:
            warn_html = ''
        return (
            '<article class="card status-' + s_class + '" id="' + html.escape(card_id)
            + '" aria-label="' + html.escape(title) + '">'
            '<header class="card-head">'
            '<div class="card-title">'
            '<span class="status-dot" aria-hidden="true"></span>'
            '<h3>' + html.escape(title) + '</h3>'
            '</div>'
            '<span class="pill pill-' + s_class + '">' + html.escape(status_label or status) + '</span>'
            '</header>'
            '<div class="card-body">' + rows + warn_html + '</div>'
            '</article>'
        )

    parity_card = control_card(
        "runtime-attestation-parity", "Runtime Attestation Parity", parity_status,
        [
            ("Runtime parity", "runtime-parity", "Runtime parity: " + parity_status),
            ("Provenance trust", "provenance-trust", "Provenance trust: HASH_ONLY_LOCAL"),
            ("Attestation", "enterprise-attestation", "Attestation: NOT_ENTERPRISE_SIGNED"),
        ],
        ("runtime-parity-warning",
         "" if parity_status == "VERIFIED" else "Runtime parity mismatch or untrusted attestation requires governance review."),
    )
    identity_card = control_card(
        "device-identity-lifecycle", "Device Identity Lifecycle", identity_status,
        [
            ("Device trust", "device-trust-status", "Device trust: " + device_trust_status),
            ("Device identity", "device-identity-status", "Device identity: " + identity_status),
            ("Lifecycle state", "device-identity-state", "Lifecycle state: " + identity_state),
        ],
        ("device-identity-warning",
         "" if identity_status == "VERIFIED" else "Device identity is incomplete, expired, revoked, unsigned, or policy-mismatched."),
    )
    challenge_card = control_card(
        "remote-challenge-response", "Remote Challenge Response", challenge_status,
        [
            ("Challenge response", "challenge-response-status", "Challenge response: " + challenge_status),
            ("Challenge state", "challenge-response-state", "Challenge state: " + challenge_state),
        ],
        ("challenge-response-warning",
         "" if challenge_status == "VERIFIED" else "Live challenge-response is missing, expired, replayed, unsigned, or policy-mismatched."),
    )
    renewal_card = control_card(
        "continuous-trust-renewal", "Continuous Trust Renewal", renewal_status,
        [
            ("Trust renewal", "trust-renewal-status", "Trust renewal: " + renewal_status),
            ("Renewal state", "trust-renewal-state", "Renewal state: " + renewal_state),
        ],
        ("trust-renewal-warning",
         "" if renewal_status == "VERIFIED" else "Continuous trust renewal is missing, expired, replayed, revoked, unsigned, or stale."),
    )
    quorum_label = "VERIFIER_QUORUM_REACHED" if verifier_status == "VERIFIED" else "VERIFIER_QUORUM_FAILED"
    failover_label = "VERIFIER_FAILOVER_ACTIVE" if verifier_state == "VERIFIER_FAILOVER_ACTIVE" else "VERIFIER_FAILOVER_INACTIVE"
    verifier_card = control_card(
        "verifier-continuity", "Verifier Continuity", verifier_status,
        [
            ("Verifier continuity", "verifier-continuity-status", "Verifier continuity: " + verifier_status),
            ("Continuity state", "verifier-continuity-state", "Continuity state: " + verifier_state),
            ("Quorum", "verifier-quorum-state", quorum_label),
            ("Failover", "verifier-failover-state", failover_label),
        ],
        None,
    )
    cards_html = parity_card + identity_card + challenge_card + renewal_card + verifier_card

    # --- governance pipeline visualization (REQUEST → ... → EVIDENCE LAYER) ---
    policy_sig_status = "VERIFIED" if snapshot.get("policy_signature_valid") else "DEGRADED"
    pipeline_nodes = [
        ("REQUEST",              "live · ingest",      "VERIFIED"),
        ("POLICY BRAIN",         "policy.signature",   policy_sig_status),
        ("ENFORCEMENT GATEWAY",  parity_status.lower(),parity_status),
        ("POLICY VERIFICATION",  identity_state,       identity_status),
        ("DECISION",             state_label,          posture),
        ("PROVIDER ADAPTER",     challenge_state,      challenge_status),
        ("EVIDENCE LAYER",       verifier_state,       verifier_status),
    ]
    pipeline_parts = []
    for i, (label, sub, st) in enumerate(pipeline_nodes):
        cls = "verified" if st == "VERIFIED" else ("blocked" if st in ("BLOCKED", "FAIL_CLOSED") else "degraded")
        if i > 0:
            pipeline_parts.append(
                '<div class="pl-edge pl-edge-' + cls + '" aria-hidden="true"></div>'
            )
        pipeline_parts.append(
            '<div class="pl-node pl-' + cls + '" data-node="' + html.escape(label) + '">'
            '<span class="pl-led" aria-hidden="true"></span>'
            '<span class="pl-name">' + html.escape(label) + '</span>'
            '<span class="pl-sub">' + html.escape(str(sub)) + '</span>'
            '</div>'
        )
    pipeline_html = "".join(pipeline_parts)

    # --- governance evidence (server-side, never fails the page) ---
    evidence_rows_html = ''
    evidence_state = "UNAVAILABLE"
    evidence_state_cls = "degraded"
    evidence_signer = "—"
    evidence_policy_version = "—"
    try:
        from governance.evidence_chain_verifier import verify_governance_evidence
        ev = verify_governance_evidence(".").to_dict()
        evidence_state = str(ev.get("state") or "UNAVAILABLE")
        evidence_state_cls = "verified" if evidence_state == "VERIFIED" else (
            "blocked" if evidence_state == "MISSING" else "degraded"
        )
        evidence_signer = str(ev.get("signer_id") or "—")
        evidence_policy_version = str(ev.get("policy_version") or "—")
        provenance = ev.get("provenance_source") or {}
        evidence_artifact_labels = [
            ("Policy",     "policy"),
            ("Signature",  "signature"),
            ("Authority",  "authority"),
            ("Audit log",  "audit_log"),
        ]
        rows = []
        for label, key in evidence_artifact_labels:
            entry = provenance.get(key) if isinstance(provenance, dict) else None
            present = bool(entry and entry.get("present"))
            sha = str((entry or {}).get("sha256") or "")
            sha_short = (sha[:14] + "…" + sha[-6:]) if len(sha) > 20 else (sha or "—")
            badge_cls = "verified" if present else "blocked"
            badge_text = "PRESENT" if present else "MISSING"
            rows.append(
                '<div class="ev-row">'
                '<span class="ev-name">' + html.escape(label) + '</span>'
                '<span class="pill pill-' + badge_cls + '">' + badge_text + '</span>'
                '<span class="ev-sha" title="' + html.escape(sha or "") + '">' + html.escape(sha_short) + '</span>'
                '</div>'
            )
        evidence_rows_html = "".join(rows)
    except Exception as exc:
        evidence_rows_html = (
            '<div class="ev-row ev-row-empty">'
            '<span class="ev-name">Evidence chain</span>'
            '<span class="pill pill-degraded">UNAVAILABLE</span>'
            '<span class="ev-sha">' + html.escape(type(exc).__name__) + '</span>'
            '</div>'
        )

    # --- operator panel: pilot/operator/demo + studio workflow modes ---
    operator_modes = [
        ("Demo Mode",                "/playground/demo", False, "presentation"),
        ("Operator Mode",            "/playground",      False, "console"),
        ("Capture Mode",             "/playground",      False, "ingest"),
        ("Pilot Mode",               "/playground",      True,  "live · v1"),
        ("Recording Mode",           "/playground",      False, "session"),
        ("Export Mode",              "/playground",      False, "evidence"),
        ("Pilot Intake Mode",        "/playground",      False, "onboarding"),
        ("LinkedIn Outreach Studio", "/playground",      False, "outreach"),
        ("Pilot Readiness Package",  "/playground",      False, "package"),
    ]
    operator_modes_html = "".join(
        '<a class="mode-row' + (' mode-row-active' if active else '') + '" href="' + html.escape(href) + '">'
        '<span class="mode-led" aria-hidden="true"></span>'
        '<span class="mode-text"><span class="mode-name">' + html.escape(name) + '</span>'
        '<span class="mode-sub">' + html.escape(sub) + '</span></span>'
        + ('<span class="mode-tag">ACTIVE</span>' if active else '<span class="mode-tag mode-tag-idle">IDLE</span>')
        + '</a>'
        for (name, href, active, sub) in operator_modes
    )

    # --- extended evidence diagnostics meta grid ---
    audit_hash_full = str(snapshot.get("audit_hash") or snapshot.get("audit_log_hash") or "")
    audit_hash_short = (audit_hash_full[:12] + "…") if len(audit_hash_full) > 12 else (audit_hash_full or "—")
    nonce_value = str(challenge.get("nonce") or challenge.get("challenge_nonce") or "—")
    nonce_short = (nonce_value[:14] + "…") if len(nonce_value) > 14 else nonce_value
    attestation_state = str(snapshot.get("attestation_status") or "NOT_ENTERPRISE_SIGNED")
    replay_word = "ACTIVE" if public_replay_protection_active else "INACTIVE"
    replay_cls = "verified" if public_replay_protection_active else "blocked"
    sig_word = "VALID" if public_policy_signature_valid else "INVALID"
    sig_cls = "verified" if public_policy_signature_valid else "blocked"
    ev_fields = [
        ("Signer",                evidence_signer,                "info"),
        ("Policy version",        evidence_policy_version,        "info"),
        ("Policy hash",           policy_hash_short,              "info"),
        ("Audit hash",            audit_hash_short,               "info"),
        ("Policy signature",      sig_word,                       sig_cls),
        ("Replay protection",     replay_word,                    replay_cls),
        ("Nonce",                 nonce_short,                    "info"),
        ("Attestation state",     attestation_state,              "degraded" if "NOT_" in attestation_state else "verified"),
        ("Verifier continuity",   verifier_state,                 "verified" if verifier_status == "VERIFIED" else "degraded"),
        ("Challenge lifecycle",   challenge_state,                "verified" if challenge_status == "VERIFIED" else "degraded"),
    ]
    evidence_meta_html = "".join(
        '<div class="ev-cell"><span class="ev-k">' + html.escape(k) + '</span>'
        '<span class="ev-v"><span class="pill pill-' + cls + '">' + html.escape(str(v)) + '</span></span></div>'
        for (k, v, cls) in ev_fields
    )

    # --- lower operational mini-cards ---
    fail_closed_active = (state_label == "BLOCKED")
    op_card_defs = [
        ("Runtime Posture",        posture,                 posture_class,
         "controls " + str(verified_count) + "/" + str(total_controls)),
        ("Device Trust",           device_trust_status,
         "verified" if device_trust_status == "VERIFIED" else "degraded",
         "lifecycle " + identity_state.lower()),
        ("Audit Lineage",          evidence_state,          evidence_state_cls,
         "signer " + (evidence_signer if evidence_signer != "—" else "n/a")),
        ("Drift Detection",        parity_status,
         "verified" if parity_status == "VERIFIED" else "degraded",
         "runtime parity"),
        ("Challenge Status",       challenge_status,
         "verified" if challenge_status == "VERIFIED" else "degraded",
         challenge_state.lower()),
        ("Continuity Proofs",      verifier_status,
         "verified" if verifier_status == "VERIFIED" else "degraded",
         verifier_state.lower()),
        ("Fail-Closed Enforcement",
         "ARMED" if fail_closed_active else "STANDBY",
         "blocked" if fail_closed_active else "verified",
         "policy " + public_policy_version_display),
    ]
    op_cards_html = "".join(
        '<div class="op-card op-card-' + cls + '">'
        '<div class="op-card-head">'
        '<span class="op-card-name">' + html.escape(name) + '</span>'
        '<span class="pill pill-' + cls + '">' + html.escape(str(value)) + '</span>'
        '</div>'
        '<div class="op-card-sub">' + html.escape(sub) + '</div>'
        '</div>'
        for (name, value, cls, sub) in op_card_defs
    )

    # --- topbar runtime telemetry strip values ---
    sync_word = "SYNCED" if posture == "VERIFIED" else ("BLOCKED" if posture == "BLOCKED" else "DRIFT")
    sync_cls = posture_class
    public_replay_class_chip = "verified" if public_replay_protection_active else "blocked"
    verifier_chip_cls = "verified" if verifier_status == "VERIFIED" else (
        "blocked" if verifier_status in ("BLOCKED", "FAIL_CLOSED") else "degraded"
    )
    verifier_chip_label = "CONTINUOUS" if verifier_status == "VERIFIED" else "DRIFT"

    backend_truth_json = html.escape(json.dumps(snapshot, sort_keys=True, indent=2))

    template = string.Template("""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark light">
  <title>USBAY Governance Gateway</title>
  <style>
    :root {
      --bg: #05070d;
      --bg-grid: rgba(34,211,238,.05);
      --surface: #0a0f1c;
      --surface-2: #0d1424;
      --surface-3: #111a2e;
      --border: #18243f;
      --border-strong: #25365a;
      --border-bright: #2f4774;
      --text: #e6edfb;
      --text-muted: #8a9bbf;
      --text-faint: #5b6a8a;
      --brand: #e6edfb;
      --brand-accent: #22d3ee;
      --brand-accent-2: #a78bfa;
      --ok-fg: #34f5b1; --ok-line: #10b981; --ok-glow: rgba(16,185,129,.35); --ok-bg: rgba(16,185,129,.10);
      --warn-fg: #fbbf24; --warn-line: #f59e0b; --warn-glow: rgba(245,158,11,.35); --warn-bg: rgba(245,158,11,.10);
      --bad-fg: #ff7a8a; --bad-line: #ef4444; --bad-glow: rgba(239,68,68,.35); --bad-bg: rgba(239,68,68,.10);
      --info-fg: #22d3ee; --info-line: #06b6d4; --info-bg: rgba(34,211,238,.08);
      --mono: ui-monospace, "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace;
      --shadow: 0 1px 2px rgba(0,0,0,.5), 0 8px 24px rgba(0,0,0,.35);
    }
    @media (prefers-color-scheme: light) {
      :root.theme-auto {
        --bg: #f5f7fb; --surface: #ffffff; --surface-2: #f8fafc; --surface-3: #eef2f8;
        --border: #e2e8f0; --border-strong: #cbd5e1; --border-bright: #94a3b8;
        --text: #0f172a; --text-muted: #475569; --text-faint: #64748b;
        --brand: #0b1f3a; --brand-accent: #0e7490;
        --ok-fg: #15803d; --ok-bg: rgba(16,185,129,.12);
        --warn-fg: #92400e; --warn-bg: rgba(245,158,11,.14);
        --bad-fg: #991b1b; --bad-bg: rgba(239,68,68,.14);
        --shadow: 0 1px 2px rgba(15,23,42,.05), 0 1px 3px rgba(15,23,42,.06);
      }
    }
    * { box-sizing: border-box; }
    /* Legacy light-mode fallback (kept for parity with the original
       gateway markup contract): background: #ffffff color: #1a1a1a */
    html.legacy-light, body.legacy-light { background: #ffffff; color: #1a1a1a; }
    html, body { background: var(--bg); color: var(--text); }
    body {
      margin: 0;
      font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.45; -webkit-font-smoothing: antialiased;
      background-image:
        radial-gradient(circle at 18% -10%, rgba(34,211,238,.07), transparent 40%),
        radial-gradient(circle at 88% 0%, rgba(167,139,250,.06), transparent 38%),
        linear-gradient(var(--bg-grid) 1px, transparent 1px),
        linear-gradient(90deg, var(--bg-grid) 1px, transparent 1px);
      background-size: auto, auto, 44px 44px, 44px 44px;
      background-position: 0 0, 0 0, -1px -1px, -1px -1px;
    }

    /* ----- TOPBAR ----- */
    .topbar {
      position: sticky; top: 0; z-index: 20;
      background: rgba(5,7,13,.85); backdrop-filter: blur(10px);
      border-bottom: 1px solid var(--border);
      padding: 10px 22px;
      display: grid; grid-template-columns: auto 1fr auto; align-items: center; gap: 18px;
    }
    .topbar-left { display: flex; align-items: center; gap: 12px; min-width: 0; }
    .logo {
      width: 30px; height: 30px; border-radius: 6px; flex: none;
      background: linear-gradient(135deg, #0f1a30 0%, #0b1220 100%);
      border: 1px solid var(--border-bright);
      color: var(--brand-accent); font-weight: 800; font-size: 11px;
      display: inline-flex; align-items: center; justify-content: center;
      letter-spacing: .8px;
      box-shadow: 0 0 0 1px rgba(34,211,238,.10), 0 0 14px rgba(34,211,238,.18);
    }
    .product { font-weight: 700; color: var(--brand); font-size: 13px; letter-spacing: .3px; }
    .product .product-sub { color: var(--text-muted); font-weight: 500; margin-left: 8px; font-size: 11px; text-transform: uppercase; letter-spacing: .12em; }

    .mode-switch { display: inline-flex; border: 1px solid var(--border-strong); border-radius: 6px; overflow: hidden; background: var(--surface-2); }
    .mode-switch a, .mode-switch span {
      padding: 6px 12px; font-size: 11px; font-weight: 600; letter-spacing: .12em; text-transform: uppercase;
      color: var(--text-muted); text-decoration: none; border-right: 1px solid var(--border);
      display: inline-flex; align-items: center; gap: 6px;
    }
    .mode-switch a:last-child, .mode-switch span:last-child { border-right: 0; }
    .mode-switch .mode-active {
      color: var(--brand-accent); background: rgba(34,211,238,.08);
      box-shadow: inset 0 -2px 0 var(--brand-accent);
    }
    .mode-switch a:hover { color: var(--text); background: var(--surface-3); }
    .mode-switch .mode-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; box-shadow: 0 0 8px currentColor; }

    nav.topnav { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; }
    nav.topnav a, nav.topnav span.navspan {
      color: var(--text-muted); text-decoration: none; font-size: 11px;
      padding: 5px 9px; border-radius: 4px;
      font-family: var(--mono); letter-spacing: .02em;
    }
    nav.topnav a:hover { background: var(--surface-2); color: var(--brand-accent); }
    .top-posture { display: flex; align-items: center; gap: 10px; }
    .top-posture .live-tick {
      font-family: var(--mono); font-size: 10px; color: var(--text-faint);
      letter-spacing: .14em; text-transform: uppercase;
      display: inline-flex; align-items: center; gap: 6px;
    }
    .top-posture .live-tick::before {
      content: ""; width: 6px; height: 6px; border-radius: 50%;
      background: var(--ok-line); box-shadow: 0 0 8px var(--ok-glow);
      animation: live-pulse 2s ease-in-out infinite;
    }
    @keyframes live-pulse { 0%,100% { opacity: 1; } 50% { opacity: .35; } }

    main { max-width: 1340px; margin: 0 auto; padding: 22px 22px 40px; }

    .page-head { margin: 6px 0 18px; display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
    .page-head h1 {
      margin: 0; font-size: 20px; color: var(--brand); letter-spacing: -.2px; font-weight: 700;
    }
    .page-head .crumb {
      color: var(--brand-accent); font-size: 10px; margin-bottom: 6px;
      text-transform: uppercase; letter-spacing: .22em; font-family: var(--mono);
    }
    .page-head .sub { color: var(--text-muted); font-size: 12px; margin-top: 4px; font-family: var(--mono); }

    /* ----- POSTURE HERO ----- */
    .hero {
      position: relative;
      background:
        linear-gradient(135deg, rgba(34,211,238,.04), transparent 40%),
        var(--surface);
      border: 1px solid var(--border); border-radius: 8px;
      padding: 18px 20px; margin-bottom: 16px; box-shadow: var(--shadow);
      display: grid; grid-template-columns: minmax(0,1fr) auto; gap: 16px; align-items: center;
      overflow: hidden;
    }
    .hero::before {
      content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px;
    }
    .hero.verified::before { background: var(--ok-line); box-shadow: 0 0 16px var(--ok-glow); }
    .hero.degraded::before { background: var(--warn-line); box-shadow: 0 0 16px var(--warn-glow); }
    .hero.blocked::before  { background: var(--bad-line);  box-shadow: 0 0 16px var(--bad-glow); }
    .hero-left { display: flex; align-items: center; gap: 16px; min-width: 0; }
    .posture-glyph {
      width: 52px; height: 52px; border-radius: 8px; flex: none;
      display: inline-flex; align-items: center; justify-content: center;
      font-weight: 800; font-size: 22px; font-family: var(--mono);
      border: 1px solid var(--border-strong);
    }
    .posture-glyph.verified { color: var(--ok-fg); background: var(--ok-bg); border-color: var(--ok-line); box-shadow: 0 0 18px var(--ok-glow), inset 0 0 12px rgba(16,185,129,.2); }
    .posture-glyph.degraded { color: var(--warn-fg); background: var(--warn-bg); border-color: var(--warn-line); box-shadow: 0 0 18px var(--warn-glow), inset 0 0 12px rgba(245,158,11,.2); }
    .posture-glyph.blocked  { color: var(--bad-fg);  background: var(--bad-bg);  border-color: var(--bad-line);  box-shadow: 0 0 18px var(--bad-glow),  inset 0 0 12px rgba(239,68,68,.2); }
    .hero-text .label { color: var(--brand-accent); font-size: 10px; text-transform: uppercase; letter-spacing: .22em; font-family: var(--mono); }
    .hero-text .value { font-size: 17px; font-weight: 700; color: var(--brand); margin-top: 4px; font-family: var(--mono); }
    .hero-text .copy { color: var(--text-muted); font-size: 12.5px; margin-top: 6px; max-width: 64ch; }
    .hero-right { display: flex; gap: 8px; align-items: stretch; flex-wrap: wrap; }
    .stat {
      background: var(--surface-2); border: 1px solid var(--border);
      border-radius: 6px; padding: 9px 12px; min-width: 118px;
      position: relative;
    }
    .stat .stat-k { color: var(--text-faint); font-size: 10px; text-transform: uppercase; letter-spacing: .14em; font-family: var(--mono); }
    .stat .stat-v { color: var(--brand); font-weight: 700; font-size: 15px; margin-top: 4px; font-family: var(--mono); }
    .stat.accent .stat-v { color: var(--brand-accent); }

    /* ----- PILLS ----- */
    .pill {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 3px 9px; border-radius: 3px; font-size: 10px; font-weight: 700;
      border: 1px solid currentColor; white-space: nowrap; font-family: var(--mono); letter-spacing: .1em;
      text-transform: uppercase;
    }
    .pill::before {
      content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor;
      box-shadow: 0 0 6px currentColor; flex: none;
    }
    .pill-verified, .pill-ok { color: var(--ok-fg); background: var(--ok-bg); }
    .pill-degraded, .pill-warn { color: var(--warn-fg); background: var(--warn-bg); }
    .pill-blocked, .pill-fail { color: var(--bad-fg); background: var(--bad-bg); }
    .pill-info { color: var(--info-fg); background: var(--info-bg); }
    .badge { display: inline-flex; align-items: center; gap: 6px; padding: 3px 9px; border-radius: 3px; font-size: 10px; font-weight: 700; font-family: var(--mono); letter-spacing: .1em; text-transform: uppercase; border: 1px solid currentColor; }
    .badge::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; box-shadow: 0 0 6px currentColor; flex: none; }
    .badge.ok   { color: var(--ok-fg);  background: var(--ok-bg); }
    .badge.fail { color: var(--bad-fg); background: var(--bad-bg); }

    /* ----- PIPELINE ----- */
    .pipeline-wrap {
      background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
      padding: 16px 20px; margin-bottom: 16px; box-shadow: var(--shadow);
    }
    .pipeline-head {
      display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 14px;
    }
    .pipeline-head h2 { margin: 0; font-size: 11px; color: var(--brand-accent); text-transform: uppercase; letter-spacing: .22em; font-family: var(--mono); font-weight: 700; }
    .pipeline-head .legend { display: flex; gap: 10px; font-family: var(--mono); font-size: 10px; color: var(--text-faint); text-transform: uppercase; letter-spacing: .14em; }
    .pipeline-head .legend span { display: inline-flex; align-items: center; gap: 5px; }
    .pipeline-head .legend i { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
    .pipeline-head .legend .lg-v { background: var(--ok-line); box-shadow: 0 0 6px var(--ok-glow); }
    .pipeline-head .legend .lg-d { background: var(--warn-line); box-shadow: 0 0 6px var(--warn-glow); }
    .pipeline-head .legend .lg-b { background: var(--bad-line); box-shadow: 0 0 6px var(--bad-glow); }

    .pipeline {
      display: flex; align-items: stretch; gap: 0; overflow-x: auto;
      padding: 4px 0 2px;
    }
    .pl-node {
      flex: 1 1 0; min-width: 132px;
      border: 1px solid var(--border-strong); border-radius: 6px;
      background: var(--surface-2);
      padding: 12px 12px 11px; display: flex; flex-direction: column; gap: 4px;
      position: relative;
    }
    .pl-node .pl-led {
      position: absolute; top: 10px; right: 10px;
      width: 8px; height: 8px; border-radius: 50%; background: var(--border-bright);
    }
    .pl-node .pl-name { font-family: var(--mono); font-size: 11px; font-weight: 700; letter-spacing: .16em; color: var(--brand); }
    .pl-node .pl-sub  { font-family: var(--mono); font-size: 10.5px; color: var(--text-muted); word-break: break-all; }
    .pl-verified { border-color: var(--ok-line);   box-shadow: inset 0 0 0 1px rgba(16,185,129,.18), 0 0 14px rgba(16,185,129,.10); }
    .pl-verified .pl-led { background: var(--ok-line);   box-shadow: 0 0 8px var(--ok-glow); }
    .pl-verified .pl-name { color: var(--ok-fg); }
    .pl-degraded { border-color: var(--warn-line); box-shadow: inset 0 0 0 1px rgba(245,158,11,.18), 0 0 14px rgba(245,158,11,.10); }
    .pl-degraded .pl-led { background: var(--warn-line); box-shadow: 0 0 8px var(--warn-glow); }
    .pl-degraded .pl-name { color: var(--warn-fg); }
    .pl-blocked  { border-color: var(--bad-line);  box-shadow: inset 0 0 0 1px rgba(239,68,68,.18),  0 0 14px rgba(239,68,68,.10); }
    .pl-blocked  .pl-led { background: var(--bad-line);  box-shadow: 0 0 8px var(--bad-glow); }
    .pl-blocked  .pl-name { color: var(--bad-fg); }

    .pl-edge {
      flex: 0 0 28px; align-self: center; height: 2px; margin: 0 -1px;
      background: linear-gradient(90deg, var(--border-strong), var(--border-strong));
      position: relative;
    }
    .pl-edge::after {
      content: ""; position: absolute; right: -1px; top: 50%; transform: translateY(-50%);
      border-left: 6px solid var(--border-strong); border-top: 4px solid transparent; border-bottom: 4px solid transparent;
    }
    .pl-edge-verified { background: linear-gradient(90deg, var(--ok-line), var(--ok-line)); box-shadow: 0 0 8px var(--ok-glow); }
    .pl-edge-verified::after { border-left-color: var(--ok-line); }
    .pl-edge-degraded { background: linear-gradient(90deg, var(--warn-line), var(--warn-line)); }
    .pl-edge-degraded::after { border-left-color: var(--warn-line); }
    .pl-edge-blocked { background: linear-gradient(90deg, var(--bad-line), var(--bad-line)); }
    .pl-edge-blocked::after { border-left-color: var(--bad-line); }

    /* ----- PANELS ----- */
    .panel {
      background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
      padding: 16px 20px; margin-bottom: 16px; box-shadow: var(--shadow);
    }
    .panel > h2 {
      margin: 0 0 12px; font-size: 11px; color: var(--brand-accent);
      text-transform: uppercase; letter-spacing: .22em; font-weight: 700; font-family: var(--mono);
      display: flex; align-items: center; gap: 10px;
    }
    .panel > h2 .h-sub { color: var(--text-faint); font-size: 10px; letter-spacing: .14em; font-weight: 600; }

    .split-2 { display: grid; grid-template-columns: minmax(0,1.15fr) minmax(0,1fr); gap: 16px; margin-bottom: 16px; }
    @media (max-width: 980px) { .split-2 { grid-template-columns: 1fr; } }

    /* Public Status (dense HUD grid) */
    #public-status dl {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 8px; margin: 0;
    }
    #public-status .field {
      background: var(--surface-2); border: 1px solid var(--border);
      border-radius: 5px; padding: 9px 11px;
      border-left: 2px solid var(--border-bright);
    }
    #public-status dt { color: var(--text-faint); font-weight: 600; font-size: 10px; text-transform: uppercase; letter-spacing: .14em; font-family: var(--mono); }
    #public-status dd { margin: 6px 0 0; color: var(--text); font-family: var(--mono); font-size: 12px; word-break: break-all; }

    /* Evidence diagnostics */
    .ev-meta { display: flex; gap: 16px; padding: 8px 10px; margin-bottom: 10px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 5px; flex-wrap: wrap; }
    .ev-meta .ev-cell { display: flex; flex-direction: column; gap: 2px; min-width: 100px; }
    .ev-meta .ev-k { color: var(--text-faint); font-size: 9.5px; text-transform: uppercase; letter-spacing: .16em; font-family: var(--mono); }
    .ev-meta .ev-v { color: var(--brand); font-family: var(--mono); font-size: 11.5px; word-break: break-all; }
    .ev-list { display: flex; flex-direction: column; gap: 4px; }
    .ev-row {
      display: grid; grid-template-columns: 100px 90px minmax(0,1fr); align-items: center; gap: 10px;
      padding: 7px 10px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 5px;
      border-left: 2px solid var(--border-bright);
    }
    .ev-row .ev-name { font-family: var(--mono); font-size: 11px; color: var(--brand); text-transform: uppercase; letter-spacing: .12em; }
    .ev-row .ev-sha  { font-family: var(--mono); font-size: 11px; color: var(--text-muted); word-break: break-all; text-align: right; }

    /* Enforcement controls cards */
    .grid-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; }
    .card {
      background: var(--surface-2); border: 1px solid var(--border); border-left: 3px solid var(--border-bright);
      border-radius: 6px; padding: 12px 14px;
      display: flex; flex-direction: column; gap: 9px;
      position: relative;
    }
    .card.status-verified { border-left-color: var(--ok-line); box-shadow: -3px 0 14px -8px var(--ok-glow); }
    .card.status-degraded { border-left-color: var(--warn-line); box-shadow: -3px 0 14px -8px var(--warn-glow); }
    .card.status-blocked  { border-left-color: var(--bad-line);  box-shadow: -3px 0 14px -8px var(--bad-glow); }
    .card-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
    .card-title { display: flex; align-items: center; gap: 8px; min-width: 0; }
    .card-title h3 { margin: 0; font-size: 12px; color: var(--brand); font-weight: 700; font-family: var(--mono); text-transform: uppercase; letter-spacing: .12em; }
    .status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--border-bright); flex: none; }
    .status-verified .status-dot { background: var(--ok-line); box-shadow: 0 0 8px var(--ok-glow); }
    .status-degraded .status-dot { background: var(--warn-line); box-shadow: 0 0 8px var(--warn-glow); }
    .status-blocked  .status-dot { background: var(--bad-line);  box-shadow: 0 0 8px var(--bad-glow); }
    .card-body { display: flex; flex-direction: column; gap: 4px; }
    .kv { display: flex; justify-content: space-between; gap: 12px; font-size: 11.5px; padding: 4px 0; border-bottom: 1px dashed var(--border); }
    .kv:last-of-type { border-bottom: 0; }
    .kv-k { color: var(--text-muted); font-family: var(--mono); font-size: 11px; text-transform: uppercase; letter-spacing: .08em; }
    .kv-v { color: var(--text); font-family: var(--mono); text-align: right; word-break: break-all; }
    .card-warn { margin: 6px 0 0; font-size: 11.5px; color: var(--warn-fg); background: var(--warn-bg); border-radius: 4px; padding: 7px 9px; border-left: 2px solid var(--warn-line); }
    .card.status-blocked .card-warn { color: var(--bad-fg); background: var(--bad-bg); border-left-color: var(--bad-line); }
    .card.status-verified .card-warn { display: none; }

    /* Runtime telemetry strip (2nd row of topbar) */
    .runtime-strip {
      grid-column: 1 / -1; display: flex; flex-wrap: wrap; gap: 6px;
      padding: 8px 4px 2px; border-top: 1px dashed var(--border); margin-top: 6px;
      font-family: var(--mono);
    }
    .rs-chip {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 4px 9px; border: 1px solid var(--border-strong); border-radius: 4px;
      background: var(--surface-2); font-size: 10.5px; color: var(--text-muted);
      letter-spacing: .08em; text-transform: uppercase;
    }
    .rs-chip b { color: var(--brand); font-weight: 700; text-transform: none; letter-spacing: 0; }
    .rs-chip.rs-verified { border-color: var(--ok-line); box-shadow: 0 0 8px var(--ok-glow); }
    .rs-chip.rs-verified b { color: var(--ok-fg); }
    .rs-chip.rs-degraded { border-color: var(--warn-line); box-shadow: 0 0 8px var(--warn-glow); }
    .rs-chip.rs-degraded b { color: var(--warn-fg); }
    .rs-chip.rs-blocked { border-color: var(--bad-line); box-shadow: 0 0 8px var(--bad-glow); }
    .rs-chip.rs-blocked b { color: var(--bad-fg); }
    .rs-chip.rs-live::before {
      content: ""; width: 6px; height: 6px; border-radius: 50%;
      background: var(--ok-line); box-shadow: 0 0 8px var(--ok-glow);
      animation: live-pulse 2s ease-in-out infinite;
    }

    /* Layout: left operator sidebar + main column */
    .layout-grid {
      display: grid; grid-template-columns: 248px minmax(0, 1fr); gap: 16px;
      align-items: start;
    }
    @media (max-width: 1080px) { .layout-grid { grid-template-columns: 1fr; } }

    .sidebar {
      background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
      padding: 14px 12px; box-shadow: var(--shadow);
      position: sticky; top: 88px;
      display: flex; flex-direction: column; gap: 6px;
    }
    @media (max-width: 1080px) { .sidebar { position: static; } }
    .sidebar h2 {
      margin: 2px 4px 8px; font-size: 10px; color: var(--brand-accent);
      text-transform: uppercase; letter-spacing: .22em; font-weight: 700; font-family: var(--mono);
    }
    .mode-row {
      display: grid; grid-template-columns: 10px 1fr auto; align-items: center; gap: 10px;
      padding: 8px 10px; border-radius: 5px; text-decoration: none;
      border: 1px solid transparent; background: transparent; color: var(--text-muted);
      transition: background .12s ease, border-color .12s ease;
    }
    .mode-row:hover { background: var(--surface-2); border-color: var(--border); color: var(--text); }
    .mode-row .mode-led {
      width: 8px; height: 8px; border-radius: 50%; background: var(--border-bright);
    }
    .mode-row .mode-text { display: flex; flex-direction: column; min-width: 0; }
    .mode-row .mode-name { font-family: var(--mono); font-size: 11.5px; font-weight: 700; color: var(--brand); letter-spacing: .04em; }
    .mode-row .mode-sub  { font-family: var(--mono); font-size: 10px; color: var(--text-faint); text-transform: uppercase; letter-spacing: .12em; margin-top: 1px; }
    .mode-row .mode-tag {
      font-family: var(--mono); font-size: 9.5px; font-weight: 700; letter-spacing: .14em;
      padding: 2px 6px; border-radius: 3px; color: var(--text-faint); border: 1px solid var(--border-strong);
    }
    .mode-row .mode-tag-idle { color: var(--text-faint); }
    .mode-row-active {
      background: linear-gradient(90deg, rgba(34,211,238,.08), transparent 70%);
      border-color: var(--brand-accent); color: var(--brand-accent);
      box-shadow: inset 2px 0 0 var(--brand-accent), 0 0 14px rgba(34,211,238,.10);
    }
    .mode-row-active .mode-led { background: var(--ok-line); box-shadow: 0 0 8px var(--ok-glow); animation: live-pulse 2s ease-in-out infinite; }
    .mode-row-active .mode-name { color: var(--brand-accent); }
    .mode-row-active .mode-tag { color: var(--ok-fg); border-color: var(--ok-line); }

    /* Extended evidence meta grid (replaces compact 3-up) */
    .ev-meta-grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 8px; margin-bottom: 12px;
    }
    .ev-meta-grid .ev-cell {
      background: var(--surface-2); border: 1px solid var(--border); border-radius: 5px;
      padding: 8px 10px; border-left: 2px solid var(--border-bright);
      display: flex; flex-direction: column; gap: 4px; min-width: 0;
    }
    .ev-meta-grid .ev-k { color: var(--text-faint); font-size: 9.5px; text-transform: uppercase; letter-spacing: .16em; font-family: var(--mono); }
    .ev-meta-grid .ev-v { color: var(--brand); font-family: var(--mono); font-size: 11.5px; word-break: break-all; }

    /* Lower operational mini-cards (SOC tiles) */
    .op-cards-grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 10px;
    }
    .op-card {
      background: var(--surface-2); border: 1px solid var(--border); border-left: 3px solid var(--border-bright);
      border-radius: 6px; padding: 11px 13px;
      display: flex; flex-direction: column; gap: 6px;
    }
    .op-card.op-card-verified { border-left-color: var(--ok-line); box-shadow: -3px 0 12px -8px var(--ok-glow); }
    .op-card.op-card-degraded { border-left-color: var(--warn-line); box-shadow: -3px 0 12px -8px var(--warn-glow); }
    .op-card.op-card-blocked  { border-left-color: var(--bad-line);  box-shadow: -3px 0 12px -8px var(--bad-glow); }
    .op-card-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
    .op-card-name { font-family: var(--mono); font-size: 10.5px; color: var(--brand); text-transform: uppercase; letter-spacing: .14em; font-weight: 700; }
    .op-card-sub  { font-family: var(--mono); font-size: 10.5px; color: var(--text-muted); }

    /* Operator console (route ownership) */
    .op-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; }
    .op-cell {
      background: var(--surface-2); border: 1px solid var(--border); border-radius: 5px;
      padding: 10px 12px; display: flex; flex-direction: column; gap: 6px;
    }
    .op-cell .op-k { color: var(--text-faint); font-size: 10px; text-transform: uppercase; letter-spacing: .14em; font-family: var(--mono); }
    .op-cell .op-v { color: var(--brand); font-family: var(--mono); font-size: 12px; word-break: break-all; }
    .op-cell a.op-link { color: var(--brand-accent); text-decoration: none; }
    .op-cell a.op-link:hover { text-decoration: underline; }

    /* Backend truth collapsible */
    details.technical {
      background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
      padding: 0; margin-bottom: 16px; box-shadow: var(--shadow); overflow: hidden;
    }
    details.technical > summary {
      cursor: pointer; padding: 12px 18px; list-style: none;
      display: flex; align-items: center; justify-content: space-between; gap: 12px;
      font-size: 11px; color: var(--brand-accent); text-transform: uppercase; letter-spacing: .22em; font-weight: 700; font-family: var(--mono);
    }
    details.technical > summary::-webkit-details-marker { display: none; }
    details.technical > summary::after { content: "▾"; color: var(--text-faint); transition: transform .15s ease; }
    details.technical[open] > summary::after { transform: rotate(180deg); }
    details.technical > summary:hover { background: var(--surface-2); }
    details.technical .tech-body { padding: 0 18px 16px; }
    pre#backend-truth {
      background: #04060c; color: var(--text);
      border: 1px solid var(--border); border-radius: 6px;
      padding: 12px 14px; overflow-x: auto; font-size: 11.5px;
      font-family: var(--mono); margin: 0;
      max-height: 460px; overflow-y: auto;
    }
    pre#backend-truth::-webkit-scrollbar { width: 10px; height: 10px; }
    pre#backend-truth::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 5px; }

    footer.legal {
      margin-top: 22px; padding-top: 14px; border-top: 1px solid var(--border);
      color: var(--text-faint); font-size: 10.5px; display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap;
      font-family: var(--mono); letter-spacing: .08em; text-transform: uppercase;
    }
    footer.legal code { font-family: var(--mono); color: var(--text-muted); text-transform: none; letter-spacing: 0; }

    @media (max-width: 760px) {
      .hero { grid-template-columns: 1fr; }
      .hero-right { flex-wrap: wrap; }
      .topbar { grid-template-columns: 1fr; gap: 8px; padding: 10px 14px; }
      .pipeline { flex-wrap: nowrap; }
    }
  </style>
</head>
<body>
  <header class="topbar" role="banner">
    <div class="topbar-left">
      <span class="logo" aria-hidden="true">UB</span>
      <span class="product">USBAY<span class="product-sub">Governance Control Plane</span></span>
    </div>
    <nav class="topnav" aria-label="Route ownership">
      <span class="navspan" id="live-pilot-label">USBAY Live Pilot v1</span>
      <a href="/health">/health</a>
      <a href="/api/status">/api/status</a>
      <a href="/api/governance/evidence">/api/governance/evidence</a>
    </nav>
    <div class="top-posture">
      <span class="pill pill-${posture_cls}">${posture}</span>
    </div>
    <div class="runtime-strip" aria-label="Runtime telemetry">
      <span class="rs-chip rs-live"><b>LIVE</b></span>
      <span class="rs-chip rs-${posture_cls}">Pilot · <b>${posture}</b></span>
      <span class="rs-chip">Policy hash <b title="${policy_hash_full}">${policy_hash_short}</b></span>
      <span class="rs-chip">Runtime commit <b title="${git_commit_full}">${git_commit_short}</b></span>
      <span class="rs-chip rs-${public_replay_class_chip}">Replay <b>${replay_word}</b></span>
      <span class="rs-chip rs-${verifier_chip_cls}">Verifier <b>${verifier_chip_label}</b></span>
      <span class="rs-chip rs-${sync_cls}">Sync <b>${sync_word}</b></span>
    </div>
  </header>
  <main>
    <div class="page-head">
      <div>
        <div class="crumb">Governance // Runtime Posture</div>
        <h1>USBAY Governance Gateway</h1>
        <p class="sub" id="route-owner">Route owner: Governance Control Plane</p>
      </div>
    </div>

    <div class="layout-grid">
      <aside class="sidebar" aria-label="Operator panel">
        <h2>Operator Modes</h2>
        ${operator_modes_html}
      </aside>

      <div class="main-col">
        <section class="hero ${posture_cls}" aria-label="Overall posture">
          <div class="hero-left">
            <span class="posture-glyph ${posture_cls}" aria-hidden="true">${posture_glyph}</span>
            <div class="hero-text">
              <div class="label">Runtime posture · ${posture}</div>
              <div class="value" id="runtime-state">Runtime state: ${state_label}</div>
              <div class="copy">${posture_copy}</div>
            </div>
          </div>
          <div class="hero-right">
            <div class="stat accent"><div class="stat-k">Controls verified</div><div class="stat-v">${verified_count}/${total_controls}</div></div>
            <div class="stat"><div class="stat-k">Mode</div><div class="stat-v">${mode_value}</div></div>
            <div class="stat"><div class="stat-k">Policy hash</div><div class="stat-v" title="${policy_hash_full}">${policy_hash_short}</div></div>
            <div class="stat"><div class="stat-k">Commit</div><div class="stat-v" title="${git_commit_full}">${git_commit_short}</div></div>
          </div>
        </section>

        <section class="pipeline-wrap" aria-label="Governance pipeline">
          <div class="pipeline-head">
            <h2>Governance Pipeline · Request &rarr; Evidence</h2>
            <div class="legend" aria-hidden="true">
              <span><i class="lg-v"></i>Verified</span>
              <span><i class="lg-d"></i>Degraded</span>
              <span><i class="lg-b"></i>Blocked</span>
            </div>
          </div>
          <div class="pipeline">${pipeline_html}</div>
        </section>

        <section class="panel" aria-label="Governance controls">
          <h2>Enforcement Controls <span class="h-sub">// 5 runtime governors</span></h2>
          <div class="grid-cards">${cards_html}</div>
        </section>

        <div class="split-2">
          <section class="panel" id="public-status" aria-label="Public status">
            <h2>Public Status <span class="h-sub">// backend-truth surface</span></h2>
            <dl>
              <div class="field"><dt>service</dt><dd>USBAY Governance Gateway</dd></div>
              <div class="field"><dt>status</dt><dd><span id="public-status-value" class="badge ${public_status_class}">${public_status}</span></dd></div>
              <div class="field"><dt>verified</dt><dd><span id="public-verified-value" class="badge ${public_verified_class}">${public_verified_display}</span></dd></div>
              <div class="field"><dt>policy_signature_valid</dt><dd><span id="public-policy-signature-valid" class="badge ${public_signature_class}">${public_signature_display}</span></dd></div>
              <div class="field"><dt>replay_protection_active</dt><dd><span id="public-replay-protection-active" class="badge ${public_replay_class}">${public_replay_display}</span></dd></div>
              <div class="field"><dt>policy_version</dt><dd id="public-policy-version">${public_policy_version_display}</dd></div>
              <div class="field"><dt>deployment_revision</dt><dd>${deployment_revision}</dd></div>
              <div class="field"><dt>reason</dt><dd>${reason_value}</dd></div>
            </dl>
          </section>

          <section class="panel" aria-label="Evidence diagnostics">
            <h2>Evidence Diagnostics <span class="h-sub">// chain of custody</span></h2>
            <div class="ev-meta-grid">${evidence_meta_html}</div>
            <div class="ev-list">${evidence_rows_html}</div>
          </section>
        </div>

        <section class="panel" aria-label="Operational posture">
          <h2>Operational Posture <span class="h-sub">// SOC tiles</span></h2>
          <div class="op-cards-grid">${op_cards_html}</div>
        </section>

        <section class="panel" aria-label="Operator console">
          <h2>Operator Console <span class="h-sub">// route ownership &amp; observability</span></h2>
          <div class="op-grid">
            <div class="op-cell"><span class="op-k">Pilot label</span><span class="op-v">USBAY Live Pilot v1</span></div>
            <div class="op-cell"><span class="op-k">Route owner</span><span class="op-v">Governance Control Plane</span></div>
            <div class="op-cell"><span class="op-k">Mode</span><span class="op-v">${mode_value}</span></div>
            <div class="op-cell"><span class="op-k">Deployment revision</span><span class="op-v">${deployment_revision}</span></div>
            <div class="op-cell"><span class="op-k">Health probe</span><span class="op-v"><a class="op-link" href="/health">GET /health</a></span></div>
            <div class="op-cell"><span class="op-k">Status surface</span><span class="op-v"><a class="op-link" href="/api/status">GET /api/status</a></span></div>
            <div class="op-cell"><span class="op-k">Evidence surface</span><span class="op-v"><a class="op-link" href="/api/governance/evidence">GET /api/governance/evidence</a></span></div>
            <div class="op-cell"><span class="op-k">Playground</span><span class="op-v"><a class="op-link" href="/playground">GET /playground</a></span></div>
          </div>
        </section>

        <details class="technical" id="technical-details">
          <summary>Technical Details · Backend Truth Snapshot</summary>
          <div class="tech-body">
            <pre id="backend-truth">${backend_truth_json}</pre>
          </div>
        </details>

        <footer class="legal">
          <span>USBAY Governance Control Plane · fail-closed enforcement</span>
          <span>policy <code>${public_policy_version_display}</code> · commit <code title="${git_commit_full}">${git_commit_short}</code></span>
        </footer>
      </div>
    </div>
  </main>
</body>
</html>
""")
    _page = template.substitute(
        posture=posture,
        posture_cls=posture_class,
        posture_glyph={"VERIFIED": "✓", "DEGRADED": "!", "BLOCKED": "×"}[posture],
        posture_copy=posture_copy,
        state_label=state_label,
        verified_count=verified_count,
        total_controls=total_controls,
        mode_value=html.escape(mode_value),
        policy_hash_full=html.escape(policy_hash_full or "—"),
        policy_hash_short=html.escape(policy_hash_short),
        git_commit_full=html.escape(git_commit_full or "—"),
        git_commit_short=html.escape(git_commit_short),
        deployment_revision=html.escape(deployment_revision),
        reason_value=html.escape(reason_value),
        public_status_class=public_status_class,
        public_status=html.escape(public_status),
        public_verified_class=public_verified_class,
        public_verified_display=public_verified_display,
        public_signature_class=public_signature_class,
        public_signature_display="true" if public_policy_signature_valid else "false",
        public_replay_class=public_replay_class,
        public_replay_class_chip=public_replay_class_chip,
        public_replay_display="true" if public_replay_protection_active else "false",
        public_policy_version_display=html.escape(public_policy_version_display),
        replay_word=replay_word,
        verifier_chip_cls=verifier_chip_cls,
        verifier_chip_label=verifier_chip_label,
        sync_word=sync_word,
        sync_cls=sync_cls,
        cards_html=cards_html,
        pipeline_html=pipeline_html,
        evidence_state=html.escape(evidence_state),
        evidence_state_cls=evidence_state_cls,
        evidence_signer=html.escape(evidence_signer),
        evidence_policy_version=html.escape(evidence_policy_version),
        evidence_rows_html=evidence_rows_html,
        evidence_meta_html=evidence_meta_html,
        operator_modes_html=operator_modes_html,
        op_cards_html=op_cards_html,
        backend_truth_json=backend_truth_json,
    )
    return _page.replace("<main>", "<main>\n" + _simulator_block_html(), 1)


def playground_html(route_label="Playground / Demo Tooling"):
    parity = runtime_attestation_parity_snapshot()
    identity = device_identity_lifecycle_snapshot()
    challenge = remote_challenge_response_snapshot(device_identity=identity)
    renewal = continuous_trust_renewal_snapshot(device_identity=identity, challenge_response=challenge)
    verifier = verifier_continuity_snapshot()
    parity_status = str(parity.get("runtime_parity_status", "UNTRUSTED"))
    identity_status = str(identity.get("device_lifecycle_status", "DEGRADED"))
    identity_state = str(identity.get("identity_state", "IDENTITY_UNENROLLED"))
    challenge_status = str(challenge.get("challenge_liveness_status", "DEGRADED"))
    challenge_state = str(challenge.get("challenge_state", "CHALLENGE_NOT_ISSUED"))
    renewal_status = str(renewal.get("trust_renewal_status", "DEGRADED"))
    renewal_state = str(renewal.get("renewal_state", "TRUST_RENEWAL_NOT_STARTED"))
    verifier_status = str(verifier.get("verifier_continuity_status", "DEGRADED"))
    verifier_state = str(verifier.get("continuity_state", "VERIFIER_CONTINUITY_NOT_STARTED"))
    def _cls(s):
        return "verified" if s == "VERIFIED" else ("blocked" if s in ("BLOCKED", "FAIL_CLOSED") else "degraded")
    _page = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark light">
  <title>USBAY Playground</title>
  <style>
    :root{--bg:#05080f;--bg2:#08101c;--surf:#0a1119;--surf2:#0d1622;--bd:#1a2332;--bd2:#243248;
      --ink:#e6edf6;--mute:#8a96aa;--faint:#6b7a90;--brand:#e6edf6;--accent:#22d3ee;
      --ok:#22c55e;--okg:rgba(34,197,94,.35);--warn:#f59e0b;--warng:rgba(245,158,11,.35);
      --bad:#ef4444;--badg:rgba(239,68,68,.40);--mono:ui-monospace,SFMono-Regular,Menlo,monospace;}
    *{box-sizing:border-box}
    html,body{margin:0;background:
      radial-gradient(1200px 600px at 10%% -10%%,rgba(34,211,238,.06),transparent 60%%),
      radial-gradient(900px 500px at 110%% 110%%,rgba(34,197,94,.05),transparent 60%%),
      linear-gradient(180deg,var(--bg),var(--bg2));
      color:var(--ink);font-family:var(--mono);min-height:100vh;
      background-attachment:fixed;
    }
    body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;opacity:.20;
      background:
        linear-gradient(rgba(34,211,238,.08) 1px,transparent 1px) 0 0/40px 40px,
        linear-gradient(90deg,rgba(34,211,238,.08) 1px,transparent 1px) 0 0/40px 40px;
      mask-image:radial-gradient(ellipse at center,#000 35%%,transparent 75%%);}
    .topbar{position:relative;z-index:1;display:flex;align-items:center;justify-content:space-between;gap:12px;
      padding:12px 22px;background:rgba(8,16,28,.85);backdrop-filter:blur(6px);
      border-bottom:1px solid var(--bd);}
    .brand{display:flex;align-items:center;gap:10px;}
    .logo{display:inline-grid;place-items:center;width:30px;height:30px;border-radius:5px;
      background:linear-gradient(135deg,#0ea5b7,#22d3ee);color:#04060c;font-weight:800;font-size:11px;letter-spacing:.08em;}
    .pname{font-size:13px;font-weight:700;letter-spacing:.06em;}
    .pname small{display:block;font-size:9.5px;color:var(--accent);text-transform:uppercase;letter-spacing:.22em;font-weight:700;margin-top:1px;}
    .nav a{color:var(--mute);text-decoration:none;font-size:11px;letter-spacing:.12em;text-transform:uppercase;margin-left:14px;}
    .nav a:hover{color:var(--accent);}
    .live{display:inline-flex;align-items:center;gap:6px;font-size:10.5px;color:var(--ok);text-transform:uppercase;letter-spacing:.18em;font-weight:700;}
    .live::before{content:"";width:7px;height:7px;border-radius:50%%;background:var(--ok);box-shadow:0 0 8px var(--okg);
      animation:pulse 2s ease-in-out infinite;}
    @keyframes pulse{0%%,100%%{opacity:1}50%%{opacity:.45}}
    main{position:relative;z-index:1;max-width:1180px;margin:0 auto;padding:22px 22px 40px;}
    .crumb{font-size:10px;letter-spacing:.22em;color:var(--faint);text-transform:uppercase;margin-bottom:6px;}
    h1{margin:0 0 4px;font-size:22px;letter-spacing:.04em;color:var(--brand);}
    .sub{margin:0 0 18px;color:var(--mute);font-size:12px;}
    .strip{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 18px;}
    .chip{display:inline-flex;align-items:center;gap:6px;padding:5px 10px;border-radius:4px;
      background:var(--surf2);border:1px solid var(--bd2);font-size:10.5px;color:var(--mute);
      letter-spacing:.08em;text-transform:uppercase;}
    .chip b{color:var(--brand);font-weight:700;letter-spacing:0;text-transform:none;}
    .chip.c-verified{border-color:var(--ok);box-shadow:0 0 8px var(--okg);} .chip.c-verified b{color:var(--ok);}
    .chip.c-degraded{border-color:var(--warn);box-shadow:0 0 8px var(--warng);} .chip.c-degraded b{color:var(--warn);}
    .chip.c-blocked{border-color:var(--bad);box-shadow:0 0 8px var(--badg);} .chip.c-blocked b{color:var(--bad);}
    .pipe{display:flex;align-items:stretch;gap:6px;background:var(--surf);border:1px solid var(--bd);
      border-radius:8px;padding:10px;margin-bottom:18px;overflow-x:auto;}
    .pnode{flex:1;min-width:120px;background:var(--surf2);border:1px solid var(--bd2);border-radius:5px;
      padding:8px 10px;display:flex;flex-direction:column;gap:3px;}
    .pnode .pn-k{font-size:9.5px;color:var(--faint);letter-spacing:.18em;text-transform:uppercase;}
    .pnode .pn-v{font-size:11px;color:var(--brand);}
    .pnode.c-verified{border-left:3px solid var(--ok);} .pnode.c-degraded{border-left:3px solid var(--warn);}
    .pnode.c-blocked{border-left:3px solid var(--bad);}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;}
    section.card{background:var(--surf);border:1px solid var(--bd);border-left:3px solid var(--bd2);
      border-radius:8px;padding:14px 16px;display:flex;flex-direction:column;gap:8px;}
    section.card.c-verified{border-left-color:var(--ok);box-shadow:-3px 0 14px -8px var(--okg);}
    section.card.c-degraded{border-left-color:var(--warn);box-shadow:-3px 0 14px -8px var(--warng);}
    section.card.c-blocked{border-left-color:var(--bad);box-shadow:-3px 0 14px -8px var(--badg);}
    section.card h2{margin:0;font-size:11px;color:var(--accent);text-transform:uppercase;letter-spacing:.18em;font-weight:700;}
    section.card p{margin:0;font-size:11.5px;color:var(--brand);line-height:1.5;}
    section.card .lbl{color:var(--faint);font-size:10px;text-transform:uppercase;letter-spacing:.14em;display:block;margin-bottom:2px;}
    .warn{color:var(--warn);font-size:11px;background:rgba(245,158,11,.08);border-left:2px solid var(--warn);padding:6px 9px;border-radius:4px;}
    footer{margin-top:24px;padding-top:14px;border-top:1px solid var(--bd);color:var(--faint);
      font-size:10px;letter-spacing:.10em;text-transform:uppercase;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;}
    @media (max-width:760px){.topbar{flex-wrap:wrap;}.nav a{margin-left:8px;}}
  </style>
</head>
<body>
  <header class="topbar" role="banner">
    <div class="brand">
      <span class="logo" aria-hidden="true">UB</span>
      <div class="pname">USBAY<small>Runtime Governance Playground</small></div>
    </div>
    <nav class="nav" aria-label="Breadcrumb">
      <a href="/">Governance Control Plane</a>
      <a href="/playground">Playground</a>
      <a href="/health">/health</a>
      <a href="/api/status">/api/status</a>
    </nav>
    <span class="live">LIVE</span>
  </header>
  <main>
    <div class="crumb">%s</div>
    <h1>USBAY Runtime Governance Playground</h1>
    <p class="sub" id="route-owner">Route owner: Playground / Demo Tooling</p>

    <div class="strip" aria-label="Runtime telemetry">
      <span class="chip c-%s">Parity <b>%s</b></span>
      <span class="chip c-%s">Device <b>%s</b></span>
      <span class="chip c-%s">Challenge <b>%s</b></span>
      <span class="chip c-%s">Renewal <b>%s</b></span>
      <span class="chip c-%s">Verifier <b>%s</b></span>
      <span class="chip c-blocked">Packet <b>FAIL_CLOSED</b></span>
    </div>

    <div class="pipe" aria-label="Compact governance pipeline">
      <div class="pnode c-%s"><span class="pn-k">Parity</span><span class="pn-v">%s</span></div>
      <div class="pnode c-%s"><span class="pn-k">Device</span><span class="pn-v">%s</span></div>
      <div class="pnode c-%s"><span class="pn-k">Challenge</span><span class="pn-v">%s</span></div>
      <div class="pnode c-%s"><span class="pn-k">Renewal</span><span class="pn-v">%s</span></div>
      <div class="pnode c-%s"><span class="pn-k">Verifier</span><span class="pn-v">%s</span></div>
      <div class="pnode c-blocked"><span class="pn-k">Packet</span><span class="pn-v">FAIL_CLOSED</span></div>
    </div>

    <div class="grid">
      <section id="runtime-attestation-parity" class="card c-%s">
        <h2>Runtime Attestation Parity</h2>
        <p id="runtime-parity"><span class="lbl">Runtime parity</span>Runtime parity: %s</p>
        <p id="provenance-trust"><span class="lbl">Provenance</span>Provenance trust: HASH_ONLY_LOCAL</p>
        <p id="enterprise-attestation"><span class="lbl">Attestation</span>Attestation: NOT_ENTERPRISE_SIGNED</p>
        <p id="runtime-parity-warning" class="%s">%s</p>
      </section>
      <section id="device-identity-lifecycle" class="card c-%s">
        <h2>Device Identity Lifecycle</h2>
        <p id="device-identity-status"><span class="lbl">Identity</span>Device identity: %s</p>
        <p id="device-identity-state"><span class="lbl">State</span>Lifecycle state: %s</p>
      </section>
      <section id="remote-challenge-response" class="card c-%s">
        <h2>Remote Challenge Response</h2>
        <p id="challenge-response-status"><span class="lbl">Liveness</span>Challenge response: %s</p>
        <p id="challenge-response-state"><span class="lbl">State</span>Challenge state: %s</p>
      </section>
      <section id="continuous-trust-renewal" class="card c-%s">
        <h2>Continuous Trust Renewal</h2>
        <p id="trust-renewal-status"><span class="lbl">Renewal</span>Trust renewal: %s</p>
        <p id="trust-renewal-state"><span class="lbl">State</span>Renewal state: %s</p>
      </section>
      <section id="verifier-continuity" class="card c-%s">
        <h2>Verifier Continuity</h2>
        <p id="verifier-continuity-status"><span class="lbl">Continuity</span>Verifier continuity: %s</p>
        <p id="verifier-continuity-state"><span class="lbl">State</span>Continuity state: %s</p>
      </section>
      <section id="packet-verification" class="card c-blocked" data-packet-state="FAIL_CLOSED">
        <h2>Evidence Packet Verification</h2>
        <p>Frontend packet state: BLOCKED until backend decision proof is returned.</p>
        <p>No frontend claim is trusted as verified without signed backend evidence.</p>
      </section>
    </div>

    <footer>
      <span>USBAY Governance Control Plane · fail-closed enforcement</span>
      <span>playground · demo tooling</span>
    </footer>
  </main>
</body>
</html>
""" % (
        route_label,
        _cls(parity_status), parity_status,
        _cls(identity_status), identity_status,
        _cls(challenge_status), challenge_status,
        _cls(renewal_status), renewal_status,
        _cls(verifier_status), verifier_status,
        _cls(parity_status), parity_status,
        _cls(identity_status), identity_state,
        _cls(challenge_status), challenge_state,
        _cls(renewal_status), renewal_state,
        _cls(verifier_status), verifier_state,
        _cls(parity_status), parity_status,
        "" if parity_status == "VERIFIED" else "warn",
        "" if parity_status == "VERIFIED" else "Runtime parity mismatch or untrusted attestation requires governance review.",
        _cls(identity_status), identity_status, identity_state,
        _cls(challenge_status), challenge_status, challenge_state,
        _cls(renewal_status), renewal_status, renewal_state,
        _cls(verifier_status), verifier_status, verifier_state,
    )
    return _page.replace("<main>", "<main>\n" + _simulator_block_html(), 1)


def _health_html_shell(snapshot: dict) -> str:
    """Browser-facing HTML view of the /health snapshot.
    Same dark enterprise shell, never blank, no raw JSON wall.
    Snapshot fields are html.escape'd; collapsible <details> hides raw JSON."""
    def _cls(s):
        s = str(s or "").upper()
        if s == "VERIFIED" or s == "OK" or s == "NORMAL" or s == "READY":
            return "verified"
        if s in ("BLOCKED", "FAIL_CLOSED"):
            return "blocked"
        return "degraded"
    g = lambda k, d="—": html.escape(str(snapshot.get(k, d)))
    status = g("status"); mode = g("mode"); reason = g("reason")
    pol_v  = g("registry_version"); pol_h = g("policy_hash"); pol_seq = g("policy_sequence")
    sig_ok = bool(snapshot.get("policy_signature_valid"))
    rp_ok  = bool(snapshot.get("replay_protection_active"))
    nonce_ok = bool(snapshot.get("nonce_store_available"))
    redis_ok = bool(snapshot.get("redis_available"))
    dev_trust = g("device_trust_status", "DEGRADED")
    parity = snapshot.get("runtime_parity") or {}
    identity = snapshot.get("device_identity") or {}
    chal = snapshot.get("challenge_response") or {}
    ren = snapshot.get("trust_renewal") or {}
    ver = snapshot.get("verifier_continuity") or {}
    dep = snapshot.get("deployment_runtime") or {}
    att = snapshot.get("runtime_attestation") or {}
    cards = [
        ("Runtime Posture", status,
         [("mode", mode), ("reason", reason),
          ("policy_state", g("policy_state")),
          ("policy_signature_valid", "true" if sig_ok else "false"),
          ("replay_protection_active", "true" if rp_ok else "false")]),
        ("Policy Registry", pol_v,
         [("version", pol_v), ("hash", pol_h[:24] + ("…" if len(pol_h) > 24 else "")),
          ("sequence", pol_seq), ("pubkey_id", g("policy_pubkey_id"))]),
        ("Runtime Parity", str(parity.get("runtime_parity_status", "DEGRADED")),
         [("status", html.escape(str(parity.get("runtime_parity_status", "—")))),
          ("provenance_trust", html.escape(str(parity.get("provenance_trust", "—")))),
          ("attestation", html.escape(str(parity.get("attestation", "—"))))]),
        ("Device Trust", dev_trust,
         [("device_trust_status", dev_trust),
          ("identity_state", html.escape(str(identity.get("identity_state", "—")))),
          ("lifecycle", html.escape(str(identity.get("device_lifecycle_status", "—"))))]),
        ("Challenge Response", str(chal.get("challenge_liveness_status", "DEGRADED")),
         [("liveness", html.escape(str(chal.get("challenge_liveness_status", "—")))),
          ("state", html.escape(str(chal.get("challenge_state", "—"))))]),
        ("Trust Renewal", str(ren.get("trust_renewal_status", "DEGRADED")),
         [("renewal", html.escape(str(ren.get("trust_renewal_status", "—")))),
          ("state", html.escape(str(ren.get("renewal_state", "—"))))]),
        ("Verifier Continuity", str(ver.get("verifier_continuity_status", "DEGRADED")),
         [("continuity", html.escape(str(ver.get("verifier_continuity_status", "—")))),
          ("state", html.escape(str(ver.get("continuity_state", "—"))))]),
        ("Deployment Runtime", str(dep.get("status", "DEGRADED")),
         [("status", html.escape(str(dep.get("status", "—")))),
          ("startup", html.escape(str(dep.get("startup_status", "—"))))]),
        ("Runtime Attestation", str(att.get("attestation_status", "DEGRADED")),
         [("status", html.escape(str(att.get("attestation_status", "—")))),
          ("algorithm", html.escape(str(att.get("signature_algorithm", "—")))),
          ("signature_valid", "true" if att.get("signature_valid") else "false")]),
        ("Dependencies", "OK" if redis_ok and nonce_ok else "DEGRADED",
         [("redis", "available" if redis_ok else "unavailable"),
          ("nonce_store", "available" if nonce_ok else "unavailable")]),
    ]
    cards_html = "".join(
        '<section class="card c-' + _cls(badge) + '">'
        '<header><h2>' + html.escape(title) + '</h2>'
        '<span class="badge b-' + _cls(badge) + '">' + html.escape(str(badge)) + '</span></header>'
        '<dl>' + "".join('<div class="kv"><dt>' + html.escape(k) + '</dt><dd>' + str(v) + '</dd></div>' for (k, v) in rows) + '</dl>'
        '</section>'
        for (title, badge, rows) in cards
    )
    try:
        raw_json = html.escape(json.dumps(snapshot, sort_keys=True, indent=2))
    except Exception:
        raw_json = "&mdash;"
    return (
        '<!doctype html><html lang="en"><head>'
        '<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="color-scheme" content="dark light">'
        '<title>USBAY Health · Runtime Posture</title>'
        '<style>'
        ':root{--bg:#05080f;--bg2:#08101c;--surf:#0a1119;--surf2:#0d1622;--bd:#1a2332;--bd2:#243248;'
        '--ink:#e6edf6;--mute:#8a96aa;--faint:#6b7a90;--accent:#22d3ee;'
        '--ok:#22c55e;--okg:rgba(34,197,94,.35);--warn:#f59e0b;--warng:rgba(245,158,11,.35);'
        '--bad:#ef4444;--badg:rgba(239,68,68,.40);--mono:ui-monospace,Menlo,monospace;}'
        '*{box-sizing:border-box}'
        'html,body{margin:0;min-height:100vh;color:var(--ink);font-family:var(--mono);'
        'background:radial-gradient(1200px 600px at 10% -10%,rgba(34,211,238,.06),transparent 60%),'
        'radial-gradient(900px 500px at 110% 110%,rgba(34,197,94,.05),transparent 60%),'
        'linear-gradient(180deg,var(--bg),var(--bg2));background-attachment:fixed;}'
        'body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;opacity:.18;'
        'background:linear-gradient(rgba(34,211,238,.08) 1px,transparent 1px) 0 0/40px 40px,'
        'linear-gradient(90deg,rgba(34,211,238,.08) 1px,transparent 1px) 0 0/40px 40px;'
        'mask-image:radial-gradient(ellipse at center,#000 35%,transparent 75%);}'
        '.topbar{position:relative;z-index:1;display:flex;align-items:center;justify-content:space-between;'
        'gap:12px;padding:12px 22px;background:rgba(8,16,28,.85);backdrop-filter:blur(6px);border-bottom:1px solid var(--bd);}'
        '.brand{display:flex;align-items:center;gap:10px;}'
        '.logo{display:inline-grid;place-items:center;width:30px;height:30px;border-radius:5px;'
        'background:linear-gradient(135deg,#0ea5b7,#22d3ee);color:#04060c;font-weight:800;font-size:11px;}'
        '.pname{font-size:13px;font-weight:700;}'
        '.pname small{display:block;font-size:9.5px;color:var(--accent);text-transform:uppercase;letter-spacing:.22em;margin-top:1px;}'
        '.nav a{color:var(--mute);text-decoration:none;font-size:11px;letter-spacing:.12em;'
        'text-transform:uppercase;margin-left:14px;} .nav a:hover{color:var(--accent);}'
        '.live{display:inline-flex;align-items:center;gap:6px;font-size:10.5px;color:var(--ok);'
        'text-transform:uppercase;letter-spacing:.18em;font-weight:700;}'
        '.live::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--ok);'
        'box-shadow:0 0 8px var(--okg);animation:pulse 2s ease-in-out infinite;}'
        '@keyframes pulse{0%,100%{opacity:1}50%{opacity:.45}}'
        'main{position:relative;z-index:1;max-width:1180px;margin:0 auto;padding:22px 22px 40px;}'
        '.crumb{font-size:10px;letter-spacing:.22em;color:var(--faint);text-transform:uppercase;margin-bottom:6px;}'
        'h1{margin:0 0 4px;font-size:22px;letter-spacing:.04em;}'
        '.sub{margin:0 0 18px;color:var(--mute);font-size:12px;}'
        '.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;}'
        '.card{background:var(--surf);border:1px solid var(--bd);border-left:3px solid var(--bd2);'
        'border-radius:8px;padding:12px 14px;display:flex;flex-direction:column;gap:8px;}'
        '.card.c-verified{border-left-color:var(--ok);box-shadow:-3px 0 14px -8px var(--okg);}'
        '.card.c-degraded{border-left-color:var(--warn);box-shadow:-3px 0 14px -8px var(--warng);}'
        '.card.c-blocked{border-left-color:var(--bad);box-shadow:-3px 0 14px -8px var(--badg);}'
        '.card header{display:flex;align-items:center;justify-content:space-between;gap:8px;}'
        '.card h2{margin:0;font-size:10.5px;color:var(--accent);text-transform:uppercase;letter-spacing:.18em;font-weight:700;}'
        '.badge{font-size:10px;font-weight:700;letter-spacing:.14em;padding:3px 8px;border-radius:4px;border:1px solid var(--bd2);}'
        '.badge.b-verified{color:var(--ok);border-color:var(--ok);background:rgba(34,197,94,.08);}'
        '.badge.b-degraded{color:var(--warn);border-color:var(--warn);background:rgba(245,158,11,.08);}'
        '.badge.b-blocked{color:var(--bad);border-color:var(--bad);background:rgba(239,68,68,.10);}'
        'dl{margin:0;display:flex;flex-direction:column;gap:3px;}'
        '.kv{display:flex;justify-content:space-between;gap:8px;font-size:11px;'
        'padding:3px 0;border-bottom:1px dashed var(--bd);}'
        '.kv:last-child{border-bottom:0;}'
        '.kv dt{color:var(--faint);text-transform:uppercase;letter-spacing:.10em;font-size:10px;margin:0;}'
        '.kv dd{margin:0;color:var(--ink);text-align:right;word-break:break-all;}'
        'details{margin-top:18px;background:var(--surf);border:1px solid var(--bd);border-radius:8px;overflow:hidden;}'
        'details>summary{cursor:pointer;list-style:none;padding:12px 16px;display:flex;'
        'justify-content:space-between;color:var(--accent);font-size:11px;letter-spacing:.22em;'
        'text-transform:uppercase;font-weight:700;}'
        'details>summary::-webkit-details-marker{display:none}'
        'details>summary::after{content:"▾";color:var(--faint);}'
        'details[open]>summary::after{transform:rotate(180deg);display:inline-block;}'
        'pre{background:#04060c;border:1px solid var(--bd);margin:0 16px 16px;padding:12px;'
        'border-radius:6px;font-size:11px;overflow:auto;max-height:420px;color:var(--ink);}'
        'footer{margin-top:24px;padding-top:14px;border-top:1px solid var(--bd);color:var(--faint);'
        'font-size:10px;letter-spacing:.10em;text-transform:uppercase;display:flex;'
        'justify-content:space-between;gap:10px;flex-wrap:wrap;}'
        '</style></head><body>'
        '<header class="topbar"><div class="brand"><span class="logo">UB</span>'
        '<div class="pname">USBAY<small>Runtime Health · Browser View</small></div></div>'
        '<nav class="nav"><a href="/">Dashboard</a><a href="/playground">Playground</a>'
        '<a href="/api/status">/api/status</a><a href="/api/governance/evidence">/api/governance/evidence</a></nav>'
        '<span class="live">LIVE</span></header>'
        '<main><div class="crumb">Governance // Runtime Health</div>'
        '<h1>USBAY Runtime Health</h1>'
        '<p class="sub">Browser presentation of /health · JSON contract preserved for machine clients.</p>'
        '<div class="grid">' + cards_html + '</div>'
        '<details><summary>Raw /health snapshot · JSON</summary>'
        '<pre>' + raw_json + '</pre></details>'
        '<footer><span>USBAY Governance Control Plane · fail-closed enforcement</span>'
        '<span>health · presentation view</span></footer>'
        '</main></body></html>'
    )


def _wants_html(request) -> bool:
    """Browser content-negotiation: true only when the client clearly
    prefers HTML over JSON. Machine clients (curl default, TestClient,
    Accept: application/json) keep the JSON contract."""
    try:
        accept = (request.headers.get("accept") or "").lower()
    except Exception:
        return False
    if not accept or "*/*" in accept and "text/html" not in accept:
        return False
    if "application/json" in accept and "text/html" not in accept:
        return False
    return "text/html" in accept


def _safe_fallback_html(reason: str, exc: Exception | None = None) -> str:
    """Render a minimal, never-blank degraded dashboard when snapshot
    retrieval fails. Preserves the enterprise look, never exposes
    stack traces, secrets, tokens, or PEM material. Always serves a
    visible runtime posture so the page never appears blank."""
    exc_name = type(exc).__name__ if exc is not None else "UNAVAILABLE"
    safe_reason = html.escape(str(reason)[:120])
    safe_exc = html.escape(exc_name[:60])
    return (
        '<!doctype html><html lang="en"><head>'
        '<meta charset="utf-8"><title>USBAY Governance Gateway</title>'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<style>'
        'html,body{background:#05080f;color:#e6edf6;font-family:ui-monospace,Menlo,monospace;margin:0;min-height:100vh;}'
        '.wrap{max-width:760px;margin:0 auto;padding:48px 24px;}'
        '.brand{font-size:11px;letter-spacing:.28em;color:#22d3ee;text-transform:uppercase;font-weight:700;}'
        'h1{font-size:22px;margin:8px 0 4px;color:#e6edf6;letter-spacing:.04em;}'
        '.sub{color:#8a96aa;font-size:12px;margin-bottom:24px;}'
        '.pill{display:inline-block;padding:6px 12px;border-radius:4px;font-size:11px;font-weight:700;'
        'letter-spacing:.18em;background:rgba(245,158,11,.12);color:#fbbf24;border:1px solid #f59e0b;}'
        '.card{margin-top:18px;background:#0a1018;border:1px solid #1f2a3a;border-left:3px solid #f59e0b;'
        'border-radius:6px;padding:14px 16px;font-size:12px;}'
        '.k{color:#6b7a90;text-transform:uppercase;letter-spacing:.14em;font-size:10px;}'
        '.v{color:#22d3ee;font-size:12px;margin-top:4px;}'
        '.footer{margin-top:32px;color:#6b7a90;font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;}'
        '</style></head><body><div class="wrap">'
        '<div class="brand">Governance // Runtime Posture</div>'
        '<h1>USBAY Governance Gateway</h1>'
        '<p class="sub" id="route-owner">Route owner: Governance Control Plane</p>'
        '<span class="pill">DEGRADED</span>'
        '<div class="card"><div class="k">Runtime presentation</div>'
        '<div class="v">' + safe_reason + '</div></div>'
        '<div class="card"><div class="k">Diagnostic class</div>'
        '<div class="v">' + safe_exc + '</div></div>'
        '<div class="card"><div class="k">Fail-closed enforcement</div>'
        '<div class="v">ARMED · governance layer unaffected</div></div>'
        '<div class="card"><div class="k">Operator endpoints</div>'
        '<div class="v"><a style="color:#22d3ee" href="/api/status">/api/status</a> · '
        '<a style="color:#22d3ee" href="/api/governance/evidence">/api/governance/evidence</a> · '
        '<a style="color:#22d3ee" href="/health">/health</a></div></div>'
        '<div class="footer">USBAY Governance Control Plane · presentation degraded · '
        'governance evidence intact</div>'
        '</div></body></html>'
    )


def _render_governance_html_safe() -> HTMLResponse:
    try:
        return HTMLResponse(governance_gateway_html())
    except Exception as exc:
        return HTMLResponse(
            _safe_fallback_html("Runtime snapshot temporarily unavailable", exc),
            status_code=200,
        )


def _render_playground_html_safe(*args) -> HTMLResponse:
    try:
        return HTMLResponse(playground_html(*args))
    except Exception as exc:
        return HTMLResponse(
            _safe_fallback_html("Playground view temporarily unavailable", exc),
            status_code=200,
        )


@app.exception_handler(Exception)
async def _global_safe_handler(request, exc):
    """Catch-all for unhandled exceptions. /api/* paths surface as
    structured JSON (so the API contract is preserved and the JSON
    middleware does not have to rewrite them). HTML paths render the
    safe degraded dashboard — never a blank page, never a stack trace,
    never leaked secrets."""
    path = request.url.path or ""
    if path.startswith("/api/") or path == "/api":
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_error",
                "path": path,
                "diagnostic_class": type(exc).__name__,
            },
        )
    return HTMLResponse(
        _safe_fallback_html("Gateway encountered an unexpected condition", exc),
        status_code=200,
    )


@app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
def root_gateway():
    return _render_governance_html_safe()


@app.api_route("/dashboard", methods=["GET", "HEAD"], response_class=HTMLResponse)
def dashboard():
    return _render_governance_html_safe()


@app.api_route("/playground", methods=["GET", "HEAD"], response_class=HTMLResponse)
def playground():
    return _render_playground_html_safe()


@app.api_route("/playground/demo", methods=["GET", "HEAD"], response_class=HTMLResponse)
def playground_demo():
    return _render_playground_html_safe("Playground / Demo Tooling / Demo")


@app.api_route("/playground/tools", methods=["GET", "HEAD"], response_class=HTMLResponse)
def playground_tools():
    return _render_playground_html_safe("Playground / Demo Tooling / Tools")


@app.websocket("/ws/status")
async def websocket_status(websocket: WebSocket):
    await websocket.accept()
    websocket_server.register_client(websocket)
    try:
        await websocket.send_json({"type": "runtime_status", "snapshot": runtime_status_snapshot()})
        while True:
            message = await websocket.receive_text()
            if message == "ping":
                await websocket.send_json({"type": "pong", "snapshot": runtime_status_snapshot()})
            else:
                await websocket.send_json({"type": "runtime_status", "snapshot": runtime_status_snapshot()})
    except WebSocketDisconnect:
        pass
    finally:
        websocket_server.unregister_client(websocket)


@app.post("/decide")
def decide(payload: dict):
    try:
        record, reason, hydra_result = create_governance_decision(payload)
    except DecisionStoreError as exc:
        record = None
        reason = redis_failure_reason(exc)
        hydra_result = None
    except Exception:
        record = None
        reason = "decision_failed"
        hydra_result = None

    if record is None:
        audit_provenance_context = None
        try:
            audit_provenance_context = runtime_provenance_context()
        except Exception:
            audit_provenance_context = None
        if reason in {"replay_detected", "nonce_expired", "timestamp_invalid", "nonce_store_unavailable", "redis_unavailable"}:
            audit_replay_security_event(
                "nonce_store_unavailable" if reason in {"redis_unavailable"} else reason,
                payload=payload,
                provenance_context=audit_provenance_context,
            )
        try:
            audit_governance_event(
                "decision_created",
                {
                    "request_hash": request_hash(request_signature_message(payload)) if isinstance(payload, dict) else None,
                    "decision": "DENY",
                    "policy_version": _policy_version(payload) if isinstance(payload, dict) else None,
                    "nonce_hash": nonce_hash(payload.get("nonce", "")) if isinstance(payload, dict) else None,
                    "actor_hash": actor_hash(payload.get("actor_id", "")) if isinstance(payload, dict) and payload.get("actor_id") else None,
                    "reason_code": reason,
                    "policy_pubkey_id": _safe_policy_pubkey_id(audit_provenance_context),
                    "created_at": int(time.time()),
                    "expires_at": None,
                    "used": None,
                    "timestamp": int(time.time()),
                },
            )
        except Exception:
            pass
        return JSONResponse(
            status_code=403,
            content={"decision": "DENY", "decision_id": None, "reason": reason},
        )

    return {
        "decision": record["decision"],
        "decision_id": record["decision_id"],
        "request_hash": record["request_hash"],
        "expires_at": record["expires_at"],
        "expires_at_epoch": record["expires_at_epoch"],
        "decision_signature": record["decision_signature"],
        "decision_signature_classic": record["decision_signature_classic"],
        "decision_signature_pqc": record["decision_signature_pqc"],
        "alg_version": record["alg_version"],
        "actor_hash": record["actor_hash"],
        "previous_hash": record["previous_hash"],
        "audit_hash": record["audit_hash"],
        "policy_hash": record["policy_hash"],
        "policy_signature_valid": record["policy_signature_valid"],
        "signature_valid": record["signature_valid"],
        "policy_pubkey_id": record["policy_pubkey_id"],
        "policy_sequence": record["policy_sequence"],
        "policy_valid_from": record["policy_valid_from"],
        "policy_valid_until": record["policy_valid_until"],
        "reason": record["reason_code"],
        "policy_version": record["policy_version"],
        "used": bool(record.get("used", False)),
    }


@app.post("/execute")
def execute(payload: dict):
    action = payload.get("action", "unknown")
    try:
        decision_ok, decision_or_response = validate_execution_decision(payload)
    except DecisionStoreError as exc:
        return _deny_decision_response(redis_failure_reason(exc), payload=payload)
    except Exception:
        return _deny_decision_response("decision_validation_failed", payload=payload)
    if not decision_ok:
        return decision_or_response

    verification = verify(payload)

    if verification == HYDRA_DENIED:
        return JSONResponse(
            status_code=403,
            content={"error": "denied_by_hydra"},
        )

    if verification == POLICY_DENIED:
        return JSONResponse(
            status_code=403,
            content={"error": "execution_denied"},
        )

    if not verification:
        return fail_closed(action)

    try:
        execution_proof = route_execution(payload, decision_or_response)
    except ComputeRoutingError as exc:
        return _deny_decision_response(
            str(exc) or "compute_routing_failed",
            payload=payload,
            decision_id=str(payload.get("decision_id")),
        )
    except Exception:
        return _deny_decision_response(
            "compute_routing_failed",
            payload=payload,
            decision_id=str(payload.get("decision_id")),
        )

    try:
        decision_used = mark_decision_used(decision_or_response, execution_proof=execution_proof)
    except DecisionStoreError as exc:
        return _deny_decision_response(
            redis_failure_reason(exc),
            payload=payload,
            decision_id=str(payload.get("decision_id")),
        )
    except Exception:
        return _deny_decision_response(
            "decision_use_failed",
            payload=payload,
            decision_id=str(payload.get("decision_id")),
        )

    if not decision_used:
        return _deny_decision_response(
            "replay_detected",
            payload=payload,
            decision_id=str(payload.get("decision_id")),
        )

    decision_or_response["used"] = True
    try:
        audit_chain.append(
            action,
            {
                "decision": "ALLOW",
                "tenant_id": decision_or_response.get("tenant_id"),
                "tenant_hash": decision_or_response.get("tenant_hash"),
                "policy_hash": decision_or_response.get("policy_hash"),
                "node_id": decision_or_response.get("gateway_id"),
            },
        )
        audit_governance_event(
            "execution_allowed",
            {
                **decision_or_response,
                "reason_code": "decision_used",
                **execution_proof,
                "timestamp": int(time.time()),
            },
        )
    except Exception:
        return fail_closed(action)

    return {"status": "EXECUTED"}


@app.get("/policy/version")
def policy_version():
    try:
        registry = load_policy_registry(provenance_context=runtime_provenance_context())
    except Exception:
        return JSONResponse(
            status_code=503,
            content={"error": "policy_registry_unavailable"},
        )
    return {
        "version": registry["version"],
        "policy_version": registry["version"],
        "last_updated": registry["last_updated"],
        "authority": registry["authority"],
        "policy_signature_valid": registry["policy_signature_valid"],
        "policy_pubkey_id": registry["policy_pubkey_id"],
        "policy_sequence": registry["policy_sequence"],
        "policy_hash": registry["policy_hash"],
        "valid_from": registry["valid_from"],
        "valid_until": registry["valid_until"],
    }


@app.get("/policy/state")
def policy_state():
    mode, reason, registry = policy_runtime_state(provenance_context=runtime_provenance_context())
    if registry is None:
        return JSONResponse(
            status_code=503,
            content={
                "mode": "FAIL_CLOSED",
                "reason": reason,
                "policy_signature_valid": False,
            },
        )
    return {
        "mode": mode,
        "reason": reason,
        "policy_state": "valid" if mode == "NORMAL" else "degraded",
        "policy_version": registry["version"],
        "policy_hash": registry["policy_hash"],
        "policy_pubkey_id": registry["policy_pubkey_id"],
        "policy_signature_valid": registry["policy_signature_valid"],
        "policy_sequence": registry["policy_sequence"],
    }


@app.get("/health")
def health(request: Request = None):
    mode, reason, registry = policy_runtime_state(provenance_context=runtime_provenance_context())
    redis_ok, dependency_mode, dependency_reason = redis_dependency_state()
    nonce_ok = nonce_store_available()
    replay_ok = replay_protection_active()
    compute_state = compute_policy_state()
    runtime_parity = runtime_attestation_parity_snapshot()
    device_identity = device_identity_lifecycle_snapshot(
        policy_version=str(registry.get("version", "")) if registry else "",
        policy_hash=str(registry.get("policy_hash", "")) if registry else "",
    )
    challenge_response = remote_challenge_response_snapshot(
        device_identity=device_identity,
        policy_hash=str(registry.get("policy_hash", "")) if registry else "",
    )
    trust_renewal = continuous_trust_renewal_snapshot(
        device_identity=device_identity,
        challenge_response=challenge_response,
        policy_hash=str(registry.get("policy_hash", "")) if registry else "",
    )
    verifier_continuity = verifier_continuity_snapshot(
        policy_hash=str(registry.get("policy_hash", "")) if registry else "",
    )
    deployment_health = deployment_runtime_health_snapshot()
    runtime_attestation = signed_runtime_attestation_snapshot()

    def _negotiate(payload, status_code=200):
        # Browser → enterprise HTML shell; machine clients keep the JSON contract.
        if request is not None and _wants_html(request):
            return HTMLResponse(_health_html_shell(payload), status_code=status_code)
        if status_code != 200:
            return JSONResponse(status_code=status_code, content=payload)
        return payload

    if registry is None:
        return _negotiate(
            {
                "status": "FAIL_CLOSED",
                "mode": "FAIL_CLOSED",
                "reason": reason,
                "redis_available": redis_ok,
                "nonce_store_available": nonce_ok,
                "replay_protection_active": replay_ok,
                "policy_signature_valid": False,
                "registry_version": None,
                "compute_policy_state": compute_state["state"],
                "runtime_parity": runtime_parity,
                "device_identity": device_identity,
                "challenge_response": challenge_response,
                "trust_renewal": trust_renewal,
                "verifier_continuity": verifier_continuity,
                "device_trust_status": "DEGRADED",
                "deployment_runtime": deployment_health,
                "runtime_attestation": runtime_attestation,
            },
            status_code=503,
        )
    if dependency_mode != "NORMAL":
        return _negotiate({
            "status": "OK",
            "mode": "DEGRADED",
            "reason": dependency_reason,
            "redis_available": redis_ok,
            "nonce_store_available": nonce_ok,
            "replay_protection_active": replay_ok,
            "policy_state": "valid" if mode == "NORMAL" else "degraded",
            "policy_signature_valid": registry["policy_signature_valid"],
            "registry_version": registry["version"],
            "policy_hash": registry["policy_hash"],
            "policy_sequence": registry["policy_sequence"],
            "policy_pubkey_id": registry["policy_pubkey_id"],
            "compute_policy_state": compute_state["state"],
            "runtime_parity": runtime_parity,
            "device_identity": device_identity,
            "challenge_response": challenge_response,
            "trust_renewal": trust_renewal,
            "verifier_continuity": verifier_continuity,
            "device_trust_status": "VERIFIED"
            if device_identity.get("device_lifecycle_status") == "VERIFIED"
            and challenge_response.get("challenge_liveness_status") == "VERIFIED"
            and trust_renewal.get("trust_renewal_status") == "VERIFIED"
            and verifier_continuity.get("verifier_continuity_status") == "VERIFIED"
            else "DEGRADED",
            "deployment_runtime": deployment_health,
            "runtime_attestation": runtime_attestation,
        })
    if mode != "NORMAL":
        return _negotiate({
            "status": "OK",
            "mode": "DEGRADED",
            "reason": reason,
            "redis_available": redis_ok,
            "nonce_store_available": nonce_ok,
            "replay_protection_active": replay_ok,
            "policy_state": "degraded",
            "policy_signature_valid": registry["policy_signature_valid"],
            "registry_version": registry["version"],
            "policy_hash": registry["policy_hash"],
            "policy_sequence": registry["policy_sequence"],
            "policy_pubkey_id": registry["policy_pubkey_id"],
            "compute_policy_state": compute_state["state"],
            "runtime_parity": runtime_parity,
            "device_identity": device_identity,
            "challenge_response": challenge_response,
            "trust_renewal": trust_renewal,
            "verifier_continuity": verifier_continuity,
            "device_trust_status": "VERIFIED"
            if device_identity.get("device_lifecycle_status") == "VERIFIED"
            and challenge_response.get("challenge_liveness_status") == "VERIFIED"
            and trust_renewal.get("trust_renewal_status") == "VERIFIED"
            and verifier_continuity.get("verifier_continuity_status") == "VERIFIED"
            else "DEGRADED",
            "deployment_runtime": deployment_health,
            "runtime_attestation": runtime_attestation,
        })
    return _negotiate({
        "status": "OK",
        "mode": "NORMAL",
        "reason": "ok",
        "redis_available": redis_ok,
        "nonce_store_available": nonce_ok,
        "replay_protection_active": replay_ok,
        "policy_state": "valid",
        "policy_signature_valid": registry["policy_signature_valid"],
        "registry_version": registry["version"],
        "policy_hash": registry["policy_hash"],
        "policy_sequence": registry["policy_sequence"],
        "policy_pubkey_id": registry["policy_pubkey_id"],
        "compute_policy_state": compute_state["state"],
        "runtime_parity": runtime_parity,
        "device_identity": device_identity,
        "challenge_response": challenge_response,
        "trust_renewal": trust_renewal,
        "verifier_continuity": verifier_continuity,
        "device_trust_status": "VERIFIED"
        if device_identity.get("device_lifecycle_status") == "VERIFIED"
        and challenge_response.get("challenge_liveness_status") == "VERIFIED"
        and trust_renewal.get("trust_renewal_status") == "VERIFIED"
        and verifier_continuity.get("verifier_continuity_status") == "VERIFIED"
        else "DEGRADED",
        "deployment_runtime": deployment_health,
        "runtime_attestation": runtime_attestation,
    })


@app.get("/api/health")
def api_health():
    return health()


@app.get("/api/status")
def api_status():
    payload = health()
    if isinstance(payload, JSONResponse):
        try:
            body = json.loads(payload.body.decode("utf-8"))
        except Exception:
            body = {}
        sync = deployment_sync_snapshot(
            runtime_mode=body.get("mode") if isinstance(body, dict) else None,
            policy_version=str(body.get("registry_version") or "") if isinstance(body, dict) else "",
            registry_available=False,
        )
        if isinstance(body, dict):
            body.update(sync)
        else:
            body = sync
        return JSONResponse(status_code=payload.status_code, content=body)
    sync = deployment_sync_snapshot(
        runtime_mode=payload.get("mode") if isinstance(payload, dict) else None,
        policy_version=str(payload.get("registry_version") or "") if isinstance(payload, dict) else "",
        registry_available=isinstance(payload, dict) and payload.get("registry_version") is not None,
    )
    if isinstance(payload, dict):
        payload.update(sync)
        return payload
    return sync


@app.get("/api/governance/evidence")
def api_governance_evidence():
    from governance.evidence_chain_verifier import (
        STATE_MISSING,
        STATE_VERIFIED,
        verify_governance_evidence,
    )

    result = verify_governance_evidence(".")
    body = result.to_dict()
    if result.state == STATE_VERIFIED:
        return body
    status_code = 404 if result.state == STATE_MISSING else 503
    return JSONResponse(status_code=status_code, content=body)


@app.get("/api/runtime/parity")
def api_runtime_parity():
    return runtime_attestation_parity_snapshot()


@app.get("/api/runtime/attestation")
def api_runtime_attestation():
    snapshot = signed_runtime_attestation_snapshot()
    if snapshot.get("attestation_status") != "SIGNED" or snapshot.get("signature_valid") is not True:
        return JSONResponse(status_code=503, content=snapshot)
    return snapshot


@app.get("/api/runtime/attestation/ledger")
def api_runtime_attestation_ledger():
    return runtime_attestation_ledger_snapshot(append=False)


@app.get("/api/device/identity/lifecycle")
def api_device_identity_lifecycle():
    snapshot = runtime_status_snapshot().get("device_identity", {})
    if snapshot.get("device_lifecycle_status") != "VERIFIED":
        return JSONResponse(status_code=503, content=snapshot)
    return snapshot


@app.get("/api/device/challenge-response")
def api_device_challenge_response():
    snapshot = runtime_status_snapshot().get("challenge_response", {})
    if snapshot.get("challenge_liveness_status") != "VERIFIED":
        return JSONResponse(status_code=503, content=snapshot)
    return snapshot


@app.get("/api/device/trust-renewal")
def api_device_trust_renewal():
    snapshot = runtime_status_snapshot().get("trust_renewal", {})
    if snapshot.get("trust_renewal_status") != "VERIFIED":
        return JSONResponse(status_code=503, content=snapshot)
    return snapshot


@app.get("/api/verifier/continuity")
def api_verifier_continuity():
    snapshot = runtime_status_snapshot().get("verifier_continuity", {})
    if snapshot.get("verifier_continuity_status") != "VERIFIED":
        return JSONResponse(status_code=503, content=snapshot)
    return snapshot


@app.get("/api/deployment/health")
def api_deployment_health():
    snapshot = deployment_runtime_health_snapshot()
    snapshot["runtime_attestation"] = signed_runtime_attestation_snapshot()
    if snapshot.get("status") != "READY":
        return JSONResponse(status_code=503, content=snapshot)
    if snapshot["runtime_attestation"].get("attestation_status") != "SIGNED":
        return JSONResponse(status_code=503, content=snapshot)
    return snapshot


@app.get("/audit/export/{audit_id}")
def export_audit(audit_id: str):
    try:
        decision_record = decision_store.load_decision(str(audit_id))
    except Exception:
        decision_record = None

    if decision_record is not None:
        redacted_record = redacted_decision_record(decision_record)
        records = redacted_decision_chain_for(audit_id) or [redacted_record]
        return {
            "type": "decision_audit_export",
            "decision_id": redacted_record["decision_id"],
            "decision": redacted_record["decision"],
            "policy_version": redacted_record["policy_version"],
            "policy_hash": redacted_record["policy_hash"],
            "policy_pubkey_id": redacted_record["policy_pubkey_id"],
            "request_hash": redacted_record["request_hash"],
            "signature_valid": redacted_record["signature_valid"],
            "decision_signature": redacted_record["decision_signature"],
            "expires_at_epoch": redacted_record["expires_at_epoch"],
            "nonce_hash": redacted_record["nonce_hash"],
            "gateway_id": redacted_record["gateway_id"],
            "genesis_hash": redacted_record["genesis_hash"],
            "genesis_signature": redacted_record["genesis_signature"],
            "decision_record": redacted_record,
            "records": records,
            "previous_hash": redacted_record["previous_hash"],
            "audit_hash": redacted_record["audit_hash"],
            "alg_version": redacted_record["alg_version"],
        }

    try:
        chain = audit_chain.load() if hasattr(audit_chain, "load") else []
    except Exception:
        chain = []

    for event in chain:
        event_audit_id = str(event.get("audit_id", event.get("hash_current", "")))
        if event_audit_id == audit_id:
            exported = export_audit_event(event, str(audit_export_file))
            return exported

    return JSONResponse(
        status_code=404,
        content={"error": "audit_event_not_found"},
    )


@app.get("/audit/bundle/{decision_id}")
def audit_bundle(decision_id: str):
    try:
        bundle = audit_evidence_bundle(decision_id)
    except Exception:
        bundle = None
    if bundle is None:
        return JSONResponse(
            status_code=404,
            content={"error": "audit_bundle_not_found"},
        )
    return bundle


@app.get("/replay/export/{decision_id}")
def replay_export(decision_id: str):
    try:
        replay = replay_export_for_decision(decision_id)
    except Exception:
        replay = None
    if replay is None:
        return JSONResponse(
            status_code=404,
            content={"error": "replay_export_not_found"},
        )
    return replay


@app.api_route("/api/{api_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def api_not_found(api_path: str):
    return JSONResponse(
        status_code=404,
        content={
            "error": "api_route_not_found",
            "path": f"/api/{api_path}",
        },
    )


@app.get("/assets/{asset_path:path}")
def frontend_asset_not_found(asset_path: str):
    return JSONResponse(
        status_code=404,
        content={
            "error": "frontend_asset_not_found",
            "path": f"/assets/{asset_path}",
        },
    )


_API_RESERVED_PREFIXES = ("api/", "health", "ws/", "decide", "execute",
                          "policy/", "audit/", "replay/", "assets/")


@app.api_route("/{frontend_path:path}", methods=["GET", "HEAD"], response_class=HTMLResponse)
def spa_fallback(frontend_path: str):
    # Defense-in-depth: the SPA catch-all must never shadow API or
    # transport paths even if a more specific route fails to register
    # or a future router is added out of order. /api/* is reserved for
    # JSON responses; collapsing it to HTML would mask fail-closed
    # evidence behaviour from clients that parse JSON.
    normalized = frontend_path.lstrip("/")
    if normalized.startswith(_API_RESERVED_PREFIXES) or normalized == "health":
        return JSONResponse(
            status_code=404,
            content={
                "error": "api_route_not_found",
                "path": f"/{normalized}",
            },
        )
    return governance_gateway_html()
