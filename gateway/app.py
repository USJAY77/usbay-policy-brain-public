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
      <div class="usbsim-hero-actions">
        <button type="button" class="usbsim-btn-primary" id="usbsim-tour-start">Start guided tour</button>
        <button type="button" class="usbsim-btn-ghost" id="usbsim-copy">Copy demo summary</button>
      </div>
      <p class="usbsim-hero-note">Backend governance, validator, attestation &amp; evidence verification unchanged.</p>
    </div>
  </header>

  <section class="usbsim-exec" id="usbsim-exec-summary" aria-label="Executive summary">
    <header class="usbsim-exec-hd">
      <div class="usbsim-eyebrow"><span class="usbsim-eb-dot"></span> EXECUTIVE SUMMARY</div>
      <h3 class="usbsim-exec-title">USBAY is in control of AI execution.</h3>
    </header>
    <ul class="usbsim-exec-list" id="usbsim-exec-list">
      <li><span class="usbsim-exec-k">Governance posture</span><span class="usbsim-exec-v" id="exec-posture">USBAY is live and actively controlling AI execution.</span></li>
      <li><span class="usbsim-exec-k">Runtime integrity</span><span class="usbsim-exec-v" id="exec-integrity">Runtime is operating within signed parameters.</span></li>
      <li><span class="usbsim-exec-k">Trust state</span><span class="usbsim-exec-v" id="exec-trust">Governance trust chain is verified end-to-end.</span></li>
      <li><span class="usbsim-exec-k">Replay protection</span><span class="usbsim-exec-v" id="exec-replay">Active — duplicate or stale requests are blocked before they reach a model.</span></li>
      <li><span class="usbsim-exec-k">Evidence verification</span><span class="usbsim-exec-v" id="exec-evidence">Every decision is sealed in a signed, append-only audit chain.</span></li>
      <li><span class="usbsim-exec-k">Operational risk</span><span class="usbsim-exec-v" id="exec-risk">Low — no unresolved governance gaps.</span></li>
    </ul>
  </section>

  <section class="usbsim-risk" id="usbsim-risk-score" aria-label="Governance risk score">
    <header class="usbsim-risk-hd">
      <div class="usbsim-eyebrow"><span class="usbsim-eb-dot"></span> GOVERNANCE RISK SCORE</div>
      <div class="usbsim-risk-titlerow">
        <h3 class="usbsim-risk-title">Maturity &amp; risk posture <span class="usbsim-risk-preview">preview</span></h3>
        <div class="usbsim-risk-overall"><span class="usbsim-risk-overall-k">Overall posture</span><b class="usbsim-risk-overall-v" id="risk-overall">Strong</b></div>
      </div>
    </header>
    <ul class="usbsim-risk-list" id="usbsim-risk-list">
      <li data-risk="maturity"><div class="usbsim-risk-row"><span class="usbsim-risk-k">Governance maturity</span><span class="usbsim-risk-band usbsim-band-med">Medium</span></div><p class="usbsim-risk-ctrl">Recommended: formalize policy ownership and review cadence.</p></li>
      <li data-risk="exec"    ><div class="usbsim-risk-row"><span class="usbsim-risk-k">AI execution risk</span><span class="usbsim-risk-band usbsim-band-low">Low</span></div><p class="usbsim-risk-ctrl">USBAY enforces ALLOW / DENY / HUMAN_REVIEW / FAIL_CLOSED before any provider call.</p></li>
      <li data-risk="audit"   ><div class="usbsim-risk-row"><span class="usbsim-risk-k">Audit readiness</span><span class="usbsim-risk-band usbsim-band-high">High</span></div><p class="usbsim-risk-ctrl">Append-only signed audit chain is regulator-defensible.</p></li>
      <li data-risk="replay"  ><div class="usbsim-risk-row"><span class="usbsim-risk-k">Replay protection coverage</span><span class="usbsim-risk-band usbsim-band-high">High</span></div><p class="usbsim-risk-ctrl">Nonces and policy hashes block duplicate or stale requests.</p></li>
      <li data-risk="oversight"><div class="usbsim-risk-row"><span class="usbsim-risk-k">Human oversight maturity</span><span class="usbsim-risk-band usbsim-band-med">Medium</span></div><p class="usbsim-risk-ctrl">Recommended: define escalation paths and approver SLA windows.</p></li>
      <li data-risk="trust"   ><div class="usbsim-risk-row"><span class="usbsim-risk-k">Runtime trust continuity</span><span class="usbsim-risk-band usbsim-band-high" id="risk-trust-band">High</span></div><p class="usbsim-risk-ctrl">Trust posture is continuously verified across the request lifecycle.</p></li>
      <li data-risk="evidence"><div class="usbsim-risk-row"><span class="usbsim-risk-k">Evidence integrity</span><span class="usbsim-risk-band usbsim-band-high">High</span></div><p class="usbsim-risk-ctrl">Every decision is cryptographically sealed and reproducible.</p></li>
    </ul>
    <p class="usbsim-risk-foot">Preview scoring — illustrative only. A paid pilot produces a per-environment governance assessment.</p>
  </section>

  <section class="usbsim-biz" id="usbsim-business-impact" aria-label="Business impact">
    <header class="usbsim-biz-hd">
      <div class="usbsim-eyebrow"><span class="usbsim-eb-dot"></span> BUSINESS IMPACT</div>
      <h3 class="usbsim-biz-title">What governance is doing for the business right now.</h3>
    </header>
    <ul class="usbsim-biz-list" id="usbsim-biz-list">
      <li><div class="usbsim-biz-n" id="biz-prevented">0</div><div class="usbsim-biz-l">Unauthorized executions prevented</div><div class="usbsim-biz-s">Blocked at the gateway — provider never invoked.</div></li>
      <li><div class="usbsim-biz-n" id="biz-compliance">Active</div><div class="usbsim-biz-l">Compliance exposure avoided</div><div class="usbsim-biz-s">Every decision is defensible and reviewable.</div></li>
      <li><div class="usbsim-biz-n" id="biz-audit">+100%</div><div class="usbsim-biz-l">Audit readiness improvement</div><div class="usbsim-biz-s">Signed, append-only evidence available on demand.</div></li>
      <li><div class="usbsim-biz-n" id="biz-coverage">100%</div><div class="usbsim-biz-l">Governance coverage of AI execution</div><div class="usbsim-biz-s">No execution path bypasses USBAY.</div></li>
      <li><div class="usbsim-biz-n" id="biz-trust">100.0%</div><div class="usbsim-biz-l">Operational trust score</div><div class="usbsim-biz-s">Runtime integrity, this session.</div></li>
      <li><div class="usbsim-biz-n" id="biz-replay">0</div><div class="usbsim-biz-l">Replay attacks mitigated</div><div class="usbsim-biz-s">Stale or duplicate requests rejected before execution.</div></li>
    </ul>
    <p class="usbsim-biz-foot">Counts reflect this session's simulated activity. Production figures are derived from your live audit chain in a paid pilot.</p>
  </section>

  <section class="usbsim-reg" id="usbsim-regulator-readiness" aria-label="Governance evidence readiness">
    <header class="usbsim-reg-hd">
      <div class="usbsim-eyebrow"><span class="usbsim-eb-dot"></span> GOVERNANCE EVIDENCE READINESS</div>
      <div class="usbsim-reg-titlerow">
        <h3 class="usbsim-reg-title">Audit-grade evidence available on request.</h3>
        <span class="usbsim-reg-state">All controls represented · preview</span>
      </div>
    </header>
    <ul class="usbsim-reg-list">
      <li><div class="usbsim-reg-row"><span class="usbsim-reg-k">Signed evidence chain</span><span class="usbsim-reg-pill usbsim-reg-ok">Modeled</span></div><p class="usbsim-reg-d">Each decision is sealed under a cryptographic signature attributable to the governance policy in force at the time of execution.</p></li>
      <li><div class="usbsim-reg-row"><span class="usbsim-reg-k">Append-only audit trail</span><span class="usbsim-reg-pill usbsim-reg-ok">Modeled</span></div><p class="usbsim-reg-d">Events are written to a hash-chained, tamper-evident ledger. Prior entries cannot be silently revised.</p></li>
      <li><div class="usbsim-reg-row"><span class="usbsim-reg-k">Policy hash binding</span><span class="usbsim-reg-pill usbsim-reg-ok">Modeled</span></div><p class="usbsim-reg-d">Every decision records the exact policy hash it was evaluated against, supporting evidence-to-rule reconstruction on demand.</p></li>
      <li><div class="usbsim-reg-row"><span class="usbsim-reg-k">Nonce &amp; replay proof</span><span class="usbsim-reg-pill usbsim-reg-ok">Modeled</span></div><p class="usbsim-reg-d">Per-request nonces are bound into the audit record, providing a defensible position against replay or duplication claims.</p></li>
      <li><div class="usbsim-reg-row"><span class="usbsim-reg-k">Human review control</span><span class="usbsim-reg-pill usbsim-reg-ok">Modeled</span></div><p class="usbsim-reg-d">High-impact actions are placed in a queue with an authorised approver of record; the decision and reviewer are both captured.</p></li>
      <li><div class="usbsim-reg-row"><span class="usbsim-reg-k">Runtime verification</span><span class="usbsim-reg-pill usbsim-reg-ok">Modeled</span></div><p class="usbsim-reg-d">Trust posture is continuously verified across the request lifecycle, not only at admission.</p></li>
      <li><div class="usbsim-reg-row"><span class="usbsim-reg-k">Fail-closed enforcement</span><span class="usbsim-reg-pill usbsim-reg-ok">Modeled</span></div><p class="usbsim-reg-d">In any uncertain or degraded state, execution is denied by default. The system fails to "no", not to "yes".</p></li>
      <li><div class="usbsim-reg-row"><span class="usbsim-reg-k">Timestamp &amp; evidence seal</span><span class="usbsim-reg-pill usbsim-reg-ok">Modeled</span></div><p class="usbsim-reg-d">Each event carries an authoritative timestamp and seal, supporting chronological reconstruction for audit and legal review.</p></li>
    </ul>
    <p class="usbsim-reg-foot">Evidence packages can be produced on request for compliance, audit, or regulator review. Production evidence is generated against your live audit chain in a paid pilot.</p>
  </section>

  <section class="usbsim-prev" id="usbsim-prevents" aria-label="What USBAY prevents">
    <header class="usbsim-prev-hd">
      <div class="usbsim-eyebrow"><span class="usbsim-eb-dot"></span> WHAT USBAY PREVENTS</div>
      <h3 class="usbsim-prev-title">The risks USBAY removes from your AI execution surface.</h3>
    </header>
    <ul class="usbsim-prev-list">
      <li><div class="usbsim-prev-risk">Unauthorized AI execution</div><div class="usbsim-prev-mech">Every request passes through a fail-closed policy gate before any model adapter runs.</div><div class="usbsim-prev-cons">Avoids unsanctioned actions taken in the company's name.</div></li>
      <li><div class="usbsim-prev-risk">Replay attacks</div><div class="usbsim-prev-mech">Per-request nonces and policy hashes reject duplicate or stale submissions.</div><div class="usbsim-prev-cons">Stops repeat execution of previously-issued (or stolen) requests.</div></li>
      <li><div class="usbsim-prev-risk">Expired policy execution</div><div class="usbsim-prev-mech">Policy validity windows are enforced at the gateway, not the application.</div><div class="usbsim-prev-cons">Prevents AI from operating under rules that no longer apply.</div></li>
      <li><div class="usbsim-prev-risk">Unsigned runtime decisions</div><div class="usbsim-prev-mech">Decisions execute only against signed, attested governance policy.</div><div class="usbsim-prev-cons">Removes the "we cannot prove what authorised this" exposure.</div></li>
      <li><div class="usbsim-prev-risk">Missing human review</div><div class="usbsim-prev-mech">High-impact actions are held in a queue until an authorised approver acts.</div><div class="usbsim-prev-cons">Keeps a person of record in the loop where the business requires it.</div></li>
      <li><div class="usbsim-prev-risk">Provider execution without approval</div><div class="usbsim-prev-mech">The model adapter is never invoked on DENY, FAIL_CLOSED, or HUMAN_REVIEW.</div><div class="usbsim-prev-cons">No external API call, spend, or side-effect on a blocked request.</div></li>
      <li><div class="usbsim-prev-risk">Audit gaps</div><div class="usbsim-prev-mech">Every decision appends a signed event to an append-only chain.</div><div class="usbsim-prev-cons">No silent decisions — full reconstructability for compliance review.</div></li>
      <li><div class="usbsim-prev-risk">Policy drift</div><div class="usbsim-prev-mech">Hash-pinned policies are verified each execution; mismatches degrade safely.</div><div class="usbsim-prev-cons">Stops uncontrolled changes between approved policy and runtime behaviour.</div></li>
      <li><div class="usbsim-prev-risk">Unverifiable governance claims</div><div class="usbsim-prev-mech">Evidence is cryptographically sealed and independently verifiable.</div><div class="usbsim-prev-cons">"Trust us" is replaced with verifiable, auditable proof.</div></li>
    </ul>
    <p class="usbsim-prev-foot">Each control is enforced in the backend gateway; this panel summarises the executive narrative. A paid pilot maps these controls to your live AI execution surface and produces per-environment evidence.</p>
  </section>

  <section class="usbsim-ind" id="usbsim-industry" aria-label="Industry context">
    <header class="usbsim-ind-hd">
      <div class="usbsim-eyebrow"><span class="usbsim-eb-dot"></span> INDUSTRY GOVERNANCE CONTEXT</div>
      <h3 class="usbsim-ind-title">Tailor the narrative to your sector.</h3>
    </header>
    <div class="usbsim-ind-chips" role="tablist" aria-label="Industry preset">
      <button type="button" class="usbsim-ind-chip is-active" role="tab" aria-selected="true" data-ind="fin">Financial Services</button>
      <button type="button" class="usbsim-ind-chip" role="tab" aria-selected="false" data-ind="health">Healthcare</button>
      <button type="button" class="usbsim-ind-chip" role="tab" aria-selected="false" data-ind="log">Logistics</button>
      <button type="button" class="usbsim-ind-chip" role="tab" aria-selected="false" data-ind="rail">Rail Operations</button>
      <button type="button" class="usbsim-ind-chip" role="tab" aria-selected="false" data-ind="ind">Industrial Automation</button>
      <button type="button" class="usbsim-ind-chip" role="tab" aria-selected="false" data-ind="support">Customer Support AI</button>
    </div>
    <div class="usbsim-ind-grid">
      <div class="usbsim-ind-cell"><span class="usbsim-ind-k">Risk examples in this sector</span><p class="usbsim-ind-v" id="ind-risks">Unauthorized credit decisions, model output used without policy approval, replayed transaction requests blocked at the gateway.</p></div>
      <div class="usbsim-ind-cell"><span class="usbsim-ind-k">Business impact priority</span><p class="usbsim-ind-v" id="ind-impact">Defensible AI-driven financial decisions and a complete audit trail for regulators and internal risk committees.</p></div>
      <div class="usbsim-ind-cell"><span class="usbsim-ind-k">Regulator &amp; audit concern</span><p class="usbsim-ind-v" id="ind-reg">Demonstrable governance over consumer-impacting decisions; explainability and replay protection on each execution.</p></div>
      <div class="usbsim-ind-cell"><span class="usbsim-ind-k">Recommended governance controls</span><p class="usbsim-ind-v" id="ind-ctrls">Signed policy enforcement, mandatory human review on threshold decisions, signed audit chain available to second-line risk.</p></div>
      <div class="usbsim-ind-cell usbsim-ind-cell-wide"><span class="usbsim-ind-k">Suggested pilot scope</span><p class="usbsim-ind-v" id="ind-pilot">Pilot one high-risk AI workflow (e.g. credit triage) under USBAY for 6 weeks; produce regulator-ready evidence pack.</p></div>
    </div>
  </section>

  <section class="usbsim-valstrip" aria-label="Executive value strip">
    <ul class="usbsim-valstrip-list">
      <li><span class="usbsim-valstrip-k">Execution control</span><span class="usbsim-valstrip-v">USBAY decides whether an AI request is allowed to execute, before any model is called.</span></li>
      <li><span class="usbsim-valstrip-k">Audit readiness</span><span class="usbsim-valstrip-v">Every decision is sealed in a signed, append-only chain that an auditor can verify independently.</span></li>
      <li><span class="usbsim-valstrip-k">Replay protection</span><span class="usbsim-valstrip-v">Duplicate or stale requests are blocked at the gateway before they reach a provider.</span></li>
      <li><span class="usbsim-valstrip-k">Human review</span><span class="usbsim-valstrip-v">High-impact decisions pause for a named operator instead of executing silently.</span></li>
      <li><span class="usbsim-valstrip-k">Regulator confidence</span><span class="usbsim-valstrip-v">Governance, escalation and evidence are demonstrable on request — not just claimed.</span></li>
    </ul>
  </section>

  <section class="usbsim-confmet" aria-label="Executive confidence metrics">
    <header class="usbsim-confmet-hd">
      <div class="usbsim-eyebrow"><span class="usbsim-eb-dot"></span> EXECUTIVE CONFIDENCE METRICS</div>
      <h3 class="usbsim-confmet-title">Boardroom view of what a USBAY pilot delivers.</h3>
    </header>
    <ul class="usbsim-confmet-list">
      <li><span class="usbsim-confmet-k">Operational Control</span><span class="usbsim-confmet-band is-high">High</span></li>
      <li><span class="usbsim-confmet-k">Audit Readiness</span><span class="usbsim-confmet-band is-high">High</span></li>
      <li><span class="usbsim-confmet-k">Governance Coverage</span><span class="usbsim-confmet-band is-med">Pilot scope</span></li>
      <li><span class="usbsim-confmet-k">Human Oversight</span><span class="usbsim-confmet-band is-high">High</span></li>
      <li><span class="usbsim-confmet-k">Execution Trust</span><span class="usbsim-confmet-band is-high">High</span></li>
    </ul>
    <p class="usbsim-confmet-foot">Bands describe the governance posture a USBAY pilot is designed to deliver. Coverage scales with the workflows placed under USBAY in the pilot.</p>
  </section>

  <section class="usbsim-pilot" id="usbsim-pilot-rec" aria-label="Recommended pilot scope">
    <header class="usbsim-pilot-hd">
      <div class="usbsim-eyebrow"><span class="usbsim-eb-dot"></span> RECOMMENDED PILOT SCOPE</div>
      <h3 class="usbsim-pilot-title">A governance pilot tailored to your sector.</h3>
    </header>
    <div class="usbsim-pilot-grid">
      <div class="usbsim-pilot-cell"><span class="usbsim-pilot-k">Industry</span><p class="usbsim-pilot-v" id="pilot-industry">Financial Services</p></div>
      <div class="usbsim-pilot-cell"><span class="usbsim-pilot-k">Current governance maturity</span><p class="usbsim-pilot-v"><span class="usbsim-pilot-badge is-med" id="pilot-maturity">Medium</span></p></div>
      <div class="usbsim-pilot-cell usbsim-pilot-cell-wide"><span class="usbsim-pilot-k">Top governance gaps</span><ul class="usbsim-pilot-gaps" id="pilot-gaps"><li>No signed policy on AI-driven credit decisions.</li><li>No human-in-the-loop on threshold decisions.</li><li>No verifiable audit chain for second-line risk.</li></ul></div>
      <div class="usbsim-pilot-cell"><span class="usbsim-pilot-k">Recommended pilot</span><p class="usbsim-pilot-v" id="pilot-scope">Governed AI for credit triage under USBAY runtime control.</p></div>
      <div class="usbsim-pilot-cell"><span class="usbsim-pilot-k">Estimated duration</span><p class="usbsim-pilot-v" id="pilot-duration">6–8 weeks</p></div>
      <div class="usbsim-pilot-cell usbsim-pilot-cell-wide"><span class="usbsim-pilot-k">Expected outcome</span><ul class="usbsim-pilot-outcomes"><li>Runtime control over AI execution</li><li>Audit readiness on demand</li><li>Human review enforced where it matters</li><li>Replay and stale-request protection</li><li>Independently verifiable evidence chain</li></ul></div>
      <div class="usbsim-pilot-cell usbsim-pilot-cell-wide"><span class="usbsim-pilot-k">Governance value</span><p class="usbsim-pilot-v" id="pilot-value">Defensible, regulator-ready AI decisions in a single high-impact workflow, with signed evidence available to second-line risk and audit on request.</p></div>
      <div class="usbsim-pilot-cell usbsim-pilot-cell-cta">
        <span class="usbsim-pilot-k">Pilot intake</span>
        <button type="button" class="usbsim-btn-primary usbsim-pilot-cta" id="usbsim-pilot-paid">Request paid governance intake</button>
        <span class="usbsim-pilot-note">Preview only — no booking, payment, or contact data is submitted from this demo. Assessment preview runs locally; no submitted company information is stored.</span>
      </div>
    </div>
    <p id="pilot-risk" class="usbsim-pilot-hidden" aria-hidden="true" hidden></p>
  </section>

  <section class="usbsim-nextstep" id="usbsim-nextstep" aria-label="Recommended next step">
    <header class="usbsim-nextstep-hd">
      <div class="usbsim-eyebrow"><span class="usbsim-eb-dot"></span> RECOMMENDED NEXT STEP</div>
      <h3 class="usbsim-nextstep-title" id="nextstep-action">Pilot Intake</h3>
    </header>
    <div class="usbsim-nextstep-grid">
      <div class="usbsim-nextstep-cell"><span class="usbsim-nextstep-k">Priority</span><span class="usbsim-pilot-badge is-high" id="nextstep-priority">High</span></div>
      <div class="usbsim-nextstep-cell usbsim-nextstep-cell-wide"><span class="usbsim-nextstep-k">Expected impact</span><p class="usbsim-nextstep-v" id="nextstep-impact">Move from governance plans to a working pilot: place one high-impact AI workflow under USBAY runtime control and produce a regulator-ready evidence pack within 6–8 weeks.</p></div>
    </div>
  </section>

  <section class="usbsim-lic" id="usbsim-lic-rec" aria-label="USBAY licensing recommendation">
    <header class="usbsim-lic-hd">
      <div class="usbsim-eyebrow"><span class="usbsim-eb-dot"></span> USBAY LICENSING RECOMMENDATION</div>
      <h3 class="usbsim-lic-title">Find the USBAY license that matches your governance footprint.</h3>
      <p class="usbsim-lic-lede">Describe how much AI execution you need to govern and USBAY recommends a license tier and the governance capabilities it includes. Preview only — illustrative, recomputed locally from your inputs, with no quote, pricing, or commitment made on this surface.</p>
    </header>
    <form class="usbsim-lic-form" id="usbsim-lic-form" autocomplete="off" novalidate aria-label="Licensing profile">
      <label class="usbsim-lic-field"><span class="usbsim-lic-flabel">Governed AI workflows</span>
        <select id="lic-workflows">
          <option value="0">1 workflow</option>
          <option value="1" selected>2–5 workflows</option>
          <option value="2">6–20 workflows</option>
          <option value="3">20+ workflows</option>
        </select>
      </label>
      <label class="usbsim-lic-field"><span class="usbsim-lic-flabel">Deployment footprint</span>
        <select id="lic-env">
          <option value="0">Single environment</option>
          <option value="1" selected>Multiple environments</option>
          <option value="3">Multi-region / sovereign</option>
        </select>
      </label>
      <label class="usbsim-lic-field"><span class="usbsim-lic-flabel">Enforcement posture</span>
        <select id="lic-enf">
          <option value="0">Monitor only</option>
          <option value="1" selected>Hard-block at gateway</option>
          <option value="2">Hard-block + attestation</option>
        </select>
      </label>
      <label class="usbsim-lic-field"><span class="usbsim-lic-flabel">Regulatory exposure</span>
        <select id="lic-reg">
          <option value="0">Standard</option>
          <option value="2" selected>Regulated industry</option>
          <option value="3">Safety- / patient-critical</option>
        </select>
      </label>
      <button type="submit" class="usbsim-btn-primary usbsim-lic-run" id="usbsim-lic-run">Recommend USBAY license</button>
    </form>
    <div class="usbsim-lic-result" id="usbsim-lic-result" aria-live="polite">
      <div class="usbsim-lic-resulthd">
        <div class="usbsim-lic-tierwrap">
          <span class="usbsim-lic-tierk">Recommended license</span>
          <span class="usbsim-lic-tier is-op" id="lic-tier">USBAY Operational</span>
        </div>
        <span class="usbsim-lic-tag" id="lic-tag">Standard engagement</span>
      </div>
      <p class="usbsim-lic-fit" id="lic-fit">—</p>
      <div class="usbsim-lic-grid">
        <div class="usbsim-lic-cell"><span class="usbsim-lic-k">Coverage</span><p class="usbsim-lic-v" id="lic-coverage">—</p></div>
        <div class="usbsim-lic-cell"><span class="usbsim-lic-k">Enforcement</span><p class="usbsim-lic-v" id="lic-enforcement">—</p></div>
        <div class="usbsim-lic-cell"><span class="usbsim-lic-k">Evidence &amp; audit</span><p class="usbsim-lic-v" id="lic-evidence">—</p></div>
        <div class="usbsim-lic-cell"><span class="usbsim-lic-k">Human oversight</span><p class="usbsim-lic-v" id="lic-oversight">—</p></div>
        <div class="usbsim-lic-cell"><span class="usbsim-lic-k">Support &amp; onboarding</span><p class="usbsim-lic-v" id="lic-support">—</p></div>
        <div class="usbsim-lic-cell"><span class="usbsim-lic-k">Suggested add-on</span><p class="usbsim-lic-v" id="lic-addon">—</p></div>
      </div>
      <ul class="usbsim-lic-incl" id="lic-included"></ul>
      <div class="usbsim-lic-cta">
        <button type="button" class="usbsim-btn-primary usbsim-lic-ctabtn" id="usbsim-lic-intake">Request licensing intake</button>
        <span class="usbsim-lic-note">Preview only — no quote, pricing, payment, or contact data is generated or submitted from this demo. The recommendation is computed locally from the inputs above and is illustrative.</span>
      </div>
    </div>
  </section>

  <section class="usbsim-walkbar" aria-label="Executive walkthrough launch">
    <div class="usbsim-walkbar-copy">
      <div class="usbsim-eyebrow"><span class="usbsim-eb-dot"></span> EXECUTIVE WALKTHROUGH</div>
      <p class="usbsim-walkbar-sub">A 60–90 second guided narrative of USBAY for CEO, CIO, CISO, Compliance Director and Regulator audiences. Runs in this browser, no submission.</p>
    </div>
    <div class="usbsim-walkbar-actions" id="exec-report">
      <button type="button" class="usbsim-btn-ghost usbsim-walkbar-btn" id="usbsim-walk-open">Show Executive Walkthrough</button>
      <button type="button" class="usbsim-btn-primary usbsim-walkbar-btn" id="usbsim-rpt-open">Preview Executive Report</button>
    </div>
  </section>

  <section class="usbsim-sector" id="usbsim-sector-demo" aria-label="Enterprise sector demonstrations">
    <header class="usbsim-sector-hd">
      <div class="usbsim-eyebrow"><span class="usbsim-eb-dot"></span> ENTERPRISE SECTOR DEMONSTRATIONS</div>
      <h3 class="usbsim-sector-title">Governance outcomes for real enterprise sectors.</h3>
      <p class="usbsim-sector-lede">Each demonstration walks a concrete operational request through the six-step USBAY decision flow, alongside the business consequence of running the same workflow without governance.</p>
    </header>
    <div class="usbsim-sector-chips" role="group" aria-label="Sector demonstration selector" aria-controls="usbsim-sector-flow">
      <button type="button" class="usbsim-sector-chip is-active" aria-pressed="true" data-sec="rail">Rail Operations<span class="usbsim-sector-chip-tag">priority</span></button>
      <button type="button" class="usbsim-sector-chip" aria-pressed="false" data-sec="fin">Financial Services</button>
      <button type="button" class="usbsim-sector-chip" aria-pressed="false" data-sec="health">Healthcare</button>
      <button type="button" class="usbsim-sector-chip" aria-pressed="false" data-sec="log">Logistics</button>
      <button type="button" class="usbsim-sector-chip" aria-pressed="false" data-sec="ind">Industrial Automation</button>
      <button type="button" class="usbsim-sector-chip" aria-pressed="false" data-sec="support">Customer Support AI</button>
    </div>
    <div class="usbsim-sector-flow" id="usbsim-sector-flow" aria-live="polite">
      <ol class="usbsim-sector-steps">
        <li><span class="usbsim-sector-stepk">Request</span><p class="usbsim-sector-stepv" id="sector-request">Automated dispatch system requests a route-change action on an active passenger service due to a downstream signal degradation reported by the line controller.</p></li>
        <li><span class="usbsim-sector-stepk">Policy evaluation</span><p class="usbsim-sector-stepv" id="sector-policy">USBAY verifies the dispatch policy is signed and current, that this controller has route-change authority for this service class, that the action is within the operating window, and that the request is not a replay.</p></li>
        <li><span class="usbsim-sector-stepk">Enforcement decision</span><p class="usbsim-sector-stepv"><span class="usbsim-sector-verdict is-review" id="sector-verdict">HUMAN_REVIEW</span></p></li>
        <li><span class="usbsim-sector-stepk">Human review</span><p class="usbsim-sector-stepv" id="sector-review">Duty controller approves the change with a captured reason code referencing the downstream signal degradation and the timetable tolerance.</p></li>
        <li><span class="usbsim-sector-stepk">Evidence generated</span><p class="usbsim-sector-stepv" id="sector-evidence">Signed audit event sealed: timestamp, controller of record, reason code, policy hash, nonce, decision = ALLOW after review.</p></li>
        <li><span class="usbsim-sector-stepk">Business outcome</span><p class="usbsim-sector-stepv" id="sector-outcome">Route change executes against signed, current policy. The full decision is reconstructable for safety case, regulator review and internal incident analysis.</p></li>
      </ol>
      <div class="usbsim-sector-cons">
        <div class="usbsim-sector-conscol usbsim-sector-conscol-bad">
          <header class="usbsim-sector-conshd"><span class="usbsim-sector-consbadge is-bad">Without USBAY</span></header>
          <ul class="usbsim-sector-conslist">
            <li><span class="usbsim-sector-consk">Risk</span><p class="usbsim-sector-consv" id="sector-w-risk">Automated dispatch change executed without verifiable authority or human sign-off.</p></li>
            <li><span class="usbsim-sector-consk">Failure mode</span><p class="usbsim-sector-consv" id="sector-w-failure">A degraded model output or a replayed instruction can trigger an unsafe route change on an active passenger service.</p></li>
            <li><span class="usbsim-sector-consk">Business impact</span><p class="usbsim-sector-consv" id="sector-w-impact">Safety incident exposure, regulator action, loss of operating licence — with no defensible evidence chain to reconstruct what happened.</p></li>
          </ul>
        </div>
        <div class="usbsim-sector-conscol usbsim-sector-conscol-ok">
          <header class="usbsim-sector-conshd"><span class="usbsim-sector-consbadge is-ok">With USBAY</span></header>
          <ul class="usbsim-sector-conslist">
            <li><span class="usbsim-sector-consk">Governance control</span><p class="usbsim-sector-consv" id="sector-y-control">Fail-closed gate holds the dispatch change until signed policy and a named human approver are both present.</p></li>
            <li><span class="usbsim-sector-consk">Decision path</span><p class="usbsim-sector-consv" id="sector-y-path">request → policy verify → HUMAN_REVIEW → controller approve → ALLOW → adapter executes.</p></li>
            <li><span class="usbsim-sector-consk">Evidence generated</span><p class="usbsim-sector-consv" id="sector-y-evidence">Hash-chained, signed event with controller of record, reason code, nonce and policy hash, sealed at the moment of execution.</p></li>
            <li><span class="usbsim-sector-consk">Operational outcome</span><p class="usbsim-sector-consv" id="sector-y-outcome">Safe, auditable operational change — defensible to the safety regulator and to internal incident review.</p></li>
          </ul>
        </div>
      </div>
    </div>
    <p class="usbsim-sector-foot">Scenario content is illustrative for executive review. A paid pilot produces the same six-step flow against your live AI execution surface, your signed policy and your authorised approvers.</p>
  </section>

  <div class="usbsim-walk" id="usbsim-walk" aria-hidden="true" hidden>
    <div class="usbsim-walk-backdrop" id="usbsim-walk-backdrop"></div>
    <div class="usbsim-walk-card" role="dialog" aria-modal="true" aria-labelledby="usbsim-walk-title">
      <header class="usbsim-walk-hd">
        <div>
          <div class="usbsim-eyebrow"><span class="usbsim-eb-dot"></span> EXECUTIVE WALKTHROUGH</div>
          <h3 class="usbsim-walk-title" id="usbsim-walk-title">USBAY for the boardroom — 60 to 90 seconds.</h3>
        </div>
        <button type="button" class="usbsim-walk-x" id="usbsim-walk-close" aria-label="Close walkthrough">×</button>
      </header>
      <div class="usbsim-walk-meta">
        <span class="usbsim-walk-audience" id="usbsim-walk-audience">CEO</span>
        <span class="usbsim-walk-progress"><span id="usbsim-walk-step">1</span> / <span id="usbsim-walk-total">6</span></span>
      </div>
      <p class="usbsim-walk-body" id="usbsim-walk-body">Loading…</p>
      <footer class="usbsim-walk-actions">
        <button type="button" class="usbsim-btn-ghost" id="usbsim-walk-prev">Previous</button>
        <button type="button" class="usbsim-btn-primary" id="usbsim-walk-next">Next</button>
      </footer>
      <p class="usbsim-walk-note">Walkthrough runs entirely in this browser. No tracking, no submission, no persistence.</p>
    </div>
  </div>

  <div class="usbsim-rpt" id="usbsim-rpt" aria-hidden="true" hidden>
    <div class="usbsim-rpt-backdrop" id="usbsim-rpt-backdrop"></div>
    <div class="usbsim-rpt-card" role="dialog" aria-modal="true" aria-labelledby="usbsim-rpt-title">
      <header class="usbsim-rpt-hd">
        <div>
          <div class="usbsim-eyebrow"><span class="usbsim-eb-dot"></span> EXECUTIVE GOVERNANCE REPORT PREVIEW</div>
          <h3 class="usbsim-rpt-title" id="usbsim-rpt-title">Boardroom summary of this session's governance posture.</h3>
        </div>
        <button type="button" class="usbsim-rpt-x" id="usbsim-rpt-close" aria-label="Close report preview">×</button>
      </header>
      <p class="usbsim-rpt-privacy">Report preview runs client-side. No company information is stored or submitted in this demo.</p>
      <div class="usbsim-rpt-body">
        <section class="usbsim-rpt-sec usbsim-rpt-sec-wide">
          <h4 class="usbsim-rpt-sec-h">For your board</h4>
          <ul class="usbsim-rpt-aud">
            <li><span class="usbsim-rpt-audk">CEO</span><span class="usbsim-rpt-audv">AI execution risk is reduced because every model call is gated by signed governance policy before any provider is invoked.</span></li>
            <li><span class="usbsim-rpt-audk">CIO</span><span class="usbsim-rpt-audv">Runtime execution is controlled and continuously verified across the request lifecycle, not only at admission.</span></li>
            <li><span class="usbsim-rpt-audk">CISO</span><span class="usbsim-rpt-audv">Replay, stale-request and expired-policy executions are blocked at the gateway; evidence is sealed in a signed, append-only chain.</span></li>
            <li><span class="usbsim-rpt-audk">Compliance Director</span><span class="usbsim-rpt-audv">Regulator readiness is improved: audit-grade evidence is available on request and human review is enforced where the business requires it.</span></li>
            <li><span class="usbsim-rpt-audk">Legal Counsel</span><span class="usbsim-rpt-audv">Each decision carries a defensible chain of authority with reviewer of record, policy hash and nonce sealed at the moment of execution.</span></li>
          </ul>
        </section>
        <div class="usbsim-rpt-grid">
          <section class="usbsim-rpt-sec">
            <h4 class="usbsim-rpt-sec-h">Selected industry</h4>
            <p class="usbsim-rpt-v" id="rpt-industry">—</p>
          </section>
          <section class="usbsim-rpt-sec">
            <h4 class="usbsim-rpt-sec-h">Governance maturity</h4>
            <p class="usbsim-rpt-v"><span class="usbsim-rpt-badge" id="rpt-maturity">—</span></p>
          </section>
          <section class="usbsim-rpt-sec usbsim-rpt-sec-wide">
            <h4 class="usbsim-rpt-sec-h">Top governance gaps</h4>
            <ul class="usbsim-rpt-list" id="rpt-gaps"><li>—</li></ul>
          </section>
          <section class="usbsim-rpt-sec usbsim-rpt-sec-wide">
            <h4 class="usbsim-rpt-sec-h">Governance risk score</h4>
            <p class="usbsim-rpt-v"><b>Overall posture:</b> <span id="rpt-risk-overall">—</span></p>
            <ul class="usbsim-rpt-kvlist" id="rpt-risk-dims"></ul>
          </section>
          <section class="usbsim-rpt-sec usbsim-rpt-sec-wide">
            <h4 class="usbsim-rpt-sec-h">Business impact (this session)</h4>
            <ul class="usbsim-rpt-kvlist" id="rpt-biz"></ul>
          </section>
          <section class="usbsim-rpt-sec usbsim-rpt-sec-wide">
            <h4 class="usbsim-rpt-sec-h">Regulator readiness</h4>
            <p class="usbsim-rpt-v" id="rpt-reg">—</p>
          </section>
          <section class="usbsim-rpt-sec usbsim-rpt-sec-wide">
            <h4 class="usbsim-rpt-sec-h">Recommended pilot scope</h4>
            <ul class="usbsim-rpt-kvlist">
              <li><span class="usbsim-rpt-kvk">Scope</span><span class="usbsim-rpt-kvv" id="rpt-pilot-scope">—</span></li>
              <li><span class="usbsim-rpt-kvk">Duration</span><span class="usbsim-rpt-kvv" id="rpt-pilot-duration">—</span></li>
              <li><span class="usbsim-rpt-kvk">Governance value</span><span class="usbsim-rpt-kvv" id="rpt-pilot-value">—</span></li>
            </ul>
          </section>
          <section class="usbsim-rpt-sec usbsim-rpt-sec-wide">
            <h4 class="usbsim-rpt-sec-h">Recommended next step</h4>
            <ul class="usbsim-rpt-kvlist">
              <li><span class="usbsim-rpt-kvk">Action</span><span class="usbsim-rpt-kvv" id="rpt-next-action">—</span></li>
              <li><span class="usbsim-rpt-kvk">Priority</span><span class="usbsim-rpt-kvv" id="rpt-next-priority">—</span></li>
              <li><span class="usbsim-rpt-kvk">Expected impact</span><span class="usbsim-rpt-kvv" id="rpt-next-impact">—</span></li>
            </ul>
          </section>
        </div>
      </div>
      <footer class="usbsim-rpt-foot">
        <p class="usbsim-rpt-note">Preview only — no PDF generation, no file download, no backend persistence, no email, no hidden storage. Report values are read from this browser at the moment you open the preview.</p>
        <button type="button" class="usbsim-btn-ghost usbsim-rpt-closebtn" id="usbsim-rpt-close2">Close preview</button>
      </footer>
    </div>
  </div>

  <section class="usbsim-cta" id="usbsim-cta-row" aria-label="Pilot conversion">
    <div class="usbsim-cta-copy">
      <div class="usbsim-eyebrow"><span class="usbsim-eb-dot"></span> EXECUTIVE NEXT ACTIONS</div>
      <h3 class="usbsim-cta-title">Decide what to do with USBAY in the next 5 minutes.</h3>
      <p class="usbsim-cta-sub">Run a free, browser-only governance assessment, jump straight to the executive summary, or copy a clean text recap to share internally.</p>
    </div>
    <div class="usbsim-cta-actions">
      <button type="button" class="usbsim-btn-primary usbsim-cta-primary" id="usbsim-intake-open">Start Governance Assessment</button>
      <div class="usbsim-cta-actions-row">
        <button type="button" class="usbsim-btn-ghost usbsim-cta-secondary" id="usbsim-cta-exec">View Executive Summary</button>
        <button type="button" class="usbsim-btn-ghost usbsim-cta-tertiary" id="usbsim-cta-copy">Copy Demo Summary</button>
      </div>
    </div>
    <p class="usbsim-cta-priv">Assessment preview runs client-side. No submitted company data is stored, transmitted, or logged in this demo.</p>
  </section>

  <div class="usbsim-intake" id="usbsim-intake" hidden role="dialog" aria-modal="true" aria-labelledby="usbsim-intake-title">
    <div class="usbsim-intake-backdrop" id="usbsim-intake-backdrop"></div>
    <div class="usbsim-intake-card" id="usbsim-intake-card" role="document">
      <header class="usbsim-intake-hd">
        <div class="usbsim-intake-eyebrow"><span class="usbsim-eb-dot"></span> GOVERNANCE ASSESSMENT · PREVIEW</div>
        <h3 class="usbsim-intake-title" id="usbsim-intake-title">Preview-only governance assessment</h3>
        <p class="usbsim-intake-priv">Preview only — no data is stored, transmitted, or logged. This runs entirely in your browser.</p>
        <button type="button" class="usbsim-intake-close" id="usbsim-intake-close" aria-label="Close assessment">×</button>
      </header>
      <form class="usbsim-intake-form" id="usbsim-intake-form" autocomplete="off" novalidate>
        <label><span>Industry</span>
          <select name="industry">
            <option value="fin">Financial Services</option><option value="health">Healthcare</option>
            <option value="log">Logistics</option><option value="rail">Rail Operations</option>
            <option value="ind">Industrial Automation</option><option value="support">Customer Support AI</option>
            <option value="gov">Government / Public Sector</option><option value="defense">Defense</option>
            <option value="critical">Critical Infrastructure</option>
            <option value="other">Other</option>
          </select>
        </label>
        <label><span>AI usage type</span>
          <select name="usage">
            <option value="customer">Customer-facing decisions</option>
            <option value="internal">Internal automation</option>
            <option value="support">Decision support / co-pilot</option>
            <option value="agent">Autonomous agents</option>
            <option value="other">Other</option>
          </select>
        </label>
        <label><span>Current governance maturity</span>
          <select name="maturity" data-score="true">
            <option value="0">None — informal use only</option>
            <option value="1">Ad-hoc — some policies, not enforced</option>
            <option value="2">Documented — policies exist, partial enforcement</option>
            <option value="3" selected>Enforced — runtime policy in production</option>
            <option value="4">Continuously audited &amp; reviewed</option>
          </select>
        </label>
        <label><span>Human review process</span>
          <select name="review" data-score="true">
            <option value="0">None</option>
            <option value="1">Informal — operator discretion</option>
            <option value="2" selected>Formal on high-risk decisions</option>
            <option value="3">Always — every AI decision reviewable</option>
          </select>
        </label>
        <label><span>Audit evidence availability</span>
          <select name="audit" data-score="true">
            <option value="0">None</option>
            <option value="1">Application logs only</option>
            <option value="2" selected>Signed evidence per decision</option>
            <option value="3">Signed evidence + tamper-evident chain</option>
          </select>
        </label>
        <label><span>Runtime enforcement status</span>
          <select name="enforce" data-score="true">
            <option value="0">Monitoring only</option>
            <option value="1">Soft-block / warnings</option>
            <option value="2" selected>Hard-block at gateway</option>
            <option value="3">Hard-block + attestation</option>
          </select>
        </label>
        <label><span>Main compliance concern</span>
          <select name="concern">
            <option value="regulator">Regulator scrutiny</option>
            <option value="customer">Customer trust &amp; brand</option>
            <option value="internal">Internal risk / audit</option>
            <option value="safety">Operational safety</option>
            <option value="multiple">Multiple, parallel</option>
          </select>
        </label>
        <label><span>Preferred pilot scope</span>
          <select name="scope">
            <option value="assess">Assessment &amp; recommendations only</option>
            <option value="single" selected>Single high-risk workflow under USBAY</option>
            <option value="prod">Production readiness for one environment</option>
            <option value="multi">Multi-environment / multi-team</option>
          </select>
        </label>
        <label><span>Regulatory exposure</span>
          <select name="regexposure">
            <option value="standard" selected>Standard</option>
            <option value="elevated">Elevated — regulated industry</option>
            <option value="highest">Highest — sovereign / safety-critical</option>
          </select>
        </label>
        <div class="usbsim-intake-checks">
          <label class="usbsim-intake-check"><input type="checkbox" name="sovctl" value="1"><span>Multi-region sovereign controls required</span></label>
          <label class="usbsim-intake-check"><input type="checkbox" name="airgap" value="1"><span>Air-gapped governance required</span></label>
        </div>
        <div class="usbsim-intake-formfoot">
          <button type="submit" class="usbsim-btn-primary" id="usbsim-intake-submit">Generate preview</button>
          <button type="reset" class="usbsim-btn-ghost" id="usbsim-intake-reset">Reset</button>
        </div>
      </form>

      <section class="usbsim-intake-out" id="usbsim-intake-out" hidden aria-live="polite">
        <header class="usbsim-intake-out-hd">
          <div class="usbsim-eyebrow"><span class="usbsim-eb-dot"></span> PILOT READINESS PREVIEW</div>
          <h4 class="usbsim-intake-out-title" id="intake-out-title">Preview result</h4>
        </header>
        <div class="usbsim-intake-out-grid">
          <div><span class="usbsim-intake-k">Governance maturity estimate</span><b class="usbsim-intake-v" id="intake-maturity">Strong</b></div>
          <div><span class="usbsim-intake-k">Pilot fit</span><b class="usbsim-intake-v" id="intake-fit">High</b></div>
          <div class="usbsim-intake-wide"><span class="usbsim-intake-k">Recommended pilot scope</span><p class="usbsim-intake-v" id="intake-scope">Single high-risk workflow under USBAY for 6 weeks with regulator-ready evidence pack.</p></div>
          <div class="usbsim-intake-wide"><span class="usbsim-intake-k">Top 3 governance gaps</span>
            <ol class="usbsim-intake-gaps" id="intake-gaps"><li>—</li><li>—</li><li>—</li></ol>
          </div>
        </div>
        <section class="usbsim-gar" id="usbsim-gar" aria-label="Governance assessment result">
          <style>
            .usbsim-gar{margin:18px 0 0;padding:18px;border:1px solid #15324a;border-radius:12px;background:linear-gradient(180deg,rgba(8,18,24,.6),rgba(6,12,18,.6));}
            .usbsim-gar-eyebrow{font-size:9px;letter-spacing:.22em;text-transform:uppercase;color:#22d3ee;font-weight:700;}
            .usbsim-gar-title{margin:5px 0 4px;font-size:16px;font-weight:800;color:#e6edf6;letter-spacing:.02em;}
            .usbsim-gar-sub{margin:0 0 14px;font-size:11.5px;line-height:1.55;color:#94a3b8;max-width:80ch;}
            .usbsim-gar-chips{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px;}
            .usbsim-gar-chip{font-size:10px;font-weight:700;letter-spacing:.05em;padding:6px 11px;border-radius:8px;border:1px solid #1f3a52;background:rgba(8,18,26,.6);color:#7fa8bd;cursor:pointer;font-family:inherit;}
            .usbsim-gar-chip:hover{border-color:#22d3ee;color:#a5f3fc;}
            .usbsim-gar-chip.on{background:rgba(34,211,238,.16);border-color:#22d3ee;color:#a5f3fc;}
            .usbsim-gar-banner{display:flex;align-items:center;gap:10px;padding:12px 14px;border-radius:10px;border:1px solid #1f3a52;margin-bottom:12px;}
            .usbsim-gar-bdot{width:10px;height:10px;border-radius:50%;background:#94a3b8;box-shadow:0 0 0 4px rgba(148,163,184,.15);}
            .usbsim-gar-blabel{font-size:14px;font-weight:800;letter-spacing:.08em;color:#e6edf6;}
            .usbsim-gar-btag{margin-left:auto;font-size:8px;letter-spacing:.18em;text-transform:uppercase;color:#94a3b8;font-weight:700;}
            .usbsim-gar-banner.allow{border-color:#1f6f52;background:rgba(52,211,153,.10);}
            .usbsim-gar-banner.allow .usbsim-gar-bdot{background:#34d399;box-shadow:0 0 0 4px rgba(52,211,153,.2);}
            .usbsim-gar-banner.allow .usbsim-gar-blabel{color:#6ee7b7;}
            .usbsim-gar-banner.blocked{border-color:#7f2a32;background:rgba(248,113,113,.10);}
            .usbsim-gar-banner.blocked .usbsim-gar-bdot{background:#f87171;box-shadow:0 0 0 4px rgba(248,113,113,.2);}
            .usbsim-gar-banner.blocked .usbsim-gar-blabel{color:#fca5a5;}
            .usbsim-gar-banner.review{border-color:#7a5a1e;background:rgba(251,191,36,.10);}
            .usbsim-gar-banner.review .usbsim-gar-bdot{background:#fbbf24;box-shadow:0 0 0 4px rgba(251,191,36,.2);}
            .usbsim-gar-banner.review .usbsim-gar-blabel{color:#fcd34d;}
            .usbsim-gar-banner.failclosed{border-color:#8a1f1f;background:rgba(239,68,68,.14);}
            .usbsim-gar-banner.failclosed .usbsim-gar-bdot{background:#ef4444;box-shadow:0 0 0 4px rgba(239,68,68,.25);}
            .usbsim-gar-banner.failclosed .usbsim-gar-blabel{color:#fecaca;}
            .usbsim-gar-rec{display:flex;flex-direction:column;gap:3px;padding:11px 13px;border:1px solid #1f3a52;border-radius:10px;background:rgba(6,14,20,.5);margin-bottom:12px;}
            .usbsim-gar-reck{font-size:8px;letter-spacing:.18em;text-transform:uppercase;color:#22d3ee;font-weight:700;}
            .usbsim-gar-recv{font-size:12px;color:#e6edf6;font-weight:600;line-height:1.5;}
            .usbsim-gar-groups{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
            .usbsim-gar-group{padding:13px;border:1px solid #1f3a52;border-radius:10px;background:rgba(6,14,20,.5);min-width:0;}
            .usbsim-gar-group.wide{grid-column:1 / -1;}
            .usbsim-gar-ghd{font-size:8px;letter-spacing:.18em;text-transform:uppercase;color:#94a3b8;font-weight:700;margin:0 0 9px;}
            .usbsim-gar-rows{display:flex;flex-direction:column;gap:7px;}
            .usbsim-gar-row{display:grid;grid-template-columns:172px 1fr;gap:10px;align-items:center;}
            .usbsim-gar-rl{font-size:10px;color:#94a3b8;font-weight:600;overflow-wrap:break-word;}
            .usbsim-gar-rv{font-size:11px;color:#e6edf6;font-weight:600;overflow-wrap:anywhere;}
            .usbsim-gar-rv.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#cbd5e1;}
            .usbsim-gar-pill{display:inline-block;font-size:9px;font-weight:800;letter-spacing:.05em;padding:3px 9px;border-radius:999px;border:1px solid #1f3a52;color:#cbd5e1;background:rgba(148,163,184,.12);}
            .usbsim-gar-pill.ok{color:#6ee7b7;border-color:#1f6f52;background:rgba(52,211,153,.12);}
            .usbsim-gar-pill.bad{color:#fca5a5;border-color:#7f2a32;background:rgba(248,113,113,.12);}
            .usbsim-gar-pill.warn{color:#fcd34d;border-color:#7a5a1e;background:rgba(251,191,36,.12);}
            .usbsim-gar-pill.info{color:#a5f3fc;border-color:#1f4a52;background:rgba(34,211,238,.10);}
            .usbsim-gar-note{margin:14px 0 0;font-size:9.5px;line-height:1.5;color:#64748b;}
            @media (max-width:780px){.usbsim-gar-groups{grid-template-columns:1fr;}}
            @media (max-width:560px){.usbsim-gar-row{grid-template-columns:1fr;gap:3px;}}
          </style>
          <div class="usbsim-gar-eyebrow">Governance Assessment</div>
          <h4 class="usbsim-gar-title">Governance Assessment Result</h4>
          <p class="usbsim-gar-sub">Illustrative governance decision record generated with this preview &mdash; the Euria recommendation, every decision identifier, signature and timestamp verification, and the three authority signals. Switch the outcome to preview each decision state. Preview-only: identifiers are illustrative, regenerated per run, and no governance logic, policy, or backend decision is invoked.</p>
          <div class="usbsim-gar-chips" id="usbsim-gar-chips"></div>
          <div class="usbsim-gar-result" id="usbsim-gar-result" aria-live="polite"></div>
        </section>
        <section class="usbsim-licrec" id="usbsim-intake-lic" aria-label="Licensing recommendation from assessment">
          <div class="usbsim-licrec-eyebrow">Licensing match</div>
          <h4 class="usbsim-licrec-title">Recommended license</h4>
          <p class="usbsim-licrec-sub">Mapped from your assessment answers. Preview-only: an indicative tier &mdash; no pricing or commitment.</p>
          <div class="usbsim-licrec-banner">
            <span class="usbsim-lic-tier is-op" id="intake-lic-name">Runtime License</span>
            <span class="usbsim-licrec-tag" id="intake-lic-tag">Production runtime</span>
          </div>
          <div class="usbsim-licrec-why">
            <span class="usbsim-licrec-whk">Why this license was selected</span>
            <p class="usbsim-licrec-whytext" id="intake-lic-whytext">&mdash;</p>
            <ul class="usbsim-licrec-list" id="intake-lic-why"></ul>
          </div>
          <div class="usbsim-licrec-dims">
            <span class="usbsim-licrec-whk">Assessed governance profile</span>
            <div class="usbsim-licrec-dimgrid">
              <div class="usbsim-licrec-dim"><span class="usbsim-licrec-dk">Governance maturity</span><b class="usbsim-licrec-dv" id="intake-dim-gov">&mdash;</b></div>
              <div class="usbsim-licrec-dim"><span class="usbsim-licrec-dk">Risk level</span><b class="usbsim-licrec-dv" id="intake-dim-risk">&mdash;</b></div>
              <div class="usbsim-licrec-dim"><span class="usbsim-licrec-dk">Evidence readiness</span><b class="usbsim-licrec-dv" id="intake-dim-evidence">&mdash;</b></div>
              <div class="usbsim-licrec-dim"><span class="usbsim-licrec-dk">Human review maturity</span><b class="usbsim-licrec-dv" id="intake-dim-review">&mdash;</b></div>
              <div class="usbsim-licrec-dim"><span class="usbsim-licrec-dk">Runtime enforcement maturity</span><b class="usbsim-licrec-dv" id="intake-dim-enf">&mdash;</b></div>
            </div>
          </div>
          <div class="usbsim-licrec-detail" id="intake-lic-detail" hidden>
            <div class="usbsim-licrec-dblock">
              <span class="usbsim-licrec-whk">Governance scope</span>
              <p class="usbsim-licrec-whytext" id="intake-lic-scope">&mdash;</p>
            </div>
            <div class="usbsim-licrec-dblock">
              <span class="usbsim-licrec-whk">Deployment model</span>
              <p class="usbsim-licrec-whytext" id="intake-lic-deploy">&mdash;</p>
            </div>
            <div class="usbsim-licrec-dblock">
              <span class="usbsim-licrec-whk">Governance responsibilities</span>
              <div class="usbsim-licrec-model" id="intake-lic-resp"></div>
            </div>
          </div>
        </section>
        <div class="usbsim-intake-cta">
          <button type="button" class="usbsim-btn-primary" id="usbsim-intake-book">Book paid intake</button>
          <span class="usbsim-intake-cta-note">Preview only — booking is handled outside the demo. No data leaves your browser.</span>
        </div>
      </section>
    </div>
  </div>

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

  <div class="usbsim-tour" id="usbsim-tour" hidden role="dialog" aria-modal="true" aria-labelledby="usbsim-tour-title">
    <div class="usbsim-tour-backdrop" id="usbsim-tour-backdrop"></div>
    <div class="usbsim-tour-card" id="usbsim-tour-card" role="document">
      <div class="usbsim-tour-hd">
        <span class="usbsim-tour-eyebrow"><span class="usbsim-eb-dot"></span> GUIDED TOUR</span>
        <span class="usbsim-tour-counter"><b id="usbsim-tour-n">1</b> of <span id="usbsim-tour-total">5</span></span>
      </div>
      <h3 class="usbsim-tour-title" id="usbsim-tour-title">What's happening?</h3>
      <p class="usbsim-tour-body" id="usbsim-tour-body">Every AI execution request flows through USBAY before reaching the model. Nothing executes without governance approval.</p>
      <details class="usbsim-tour-tech" id="usbsim-tour-tech-wrap"><summary>Technical detail</summary><p id="usbsim-tour-tech">Requests are dispatched through the gateway PEP. The model adapter is never invoked until the policy decision lands.</p></details>
      <div class="usbsim-tour-controls">
        <button type="button" class="usbsim-btn-ghost" id="usbsim-tour-skip">Skip tour</button>
        <div class="usbsim-tour-nav">
          <button type="button" class="usbsim-btn-ghost" id="usbsim-tour-back">Back</button>
          <button type="button" class="usbsim-btn-primary" id="usbsim-tour-next">Next</button>
        </div>
      </div>
    </div>
  </div>
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

.usbsim-bigpill{display:inline-flex;align-items:center;gap:9px;padding:11px 16px;border-radius:8px;background:#0d1622;border:1px solid #243248;font-weight:800;letter-spacing:.2em;text-transform:uppercase;max-width:100%;white-space:nowrap;}
.usbsim-bigpill .usbsim-bigpill-text{overflow:hidden;text-overflow:ellipsis;min-width:0;}
.usbsim-bigpill .usbsim-bigpill-dot{flex-shrink:0;}
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
.usbsim-scn-btn{display:flex;align-items:center;gap:10px;padding:11px 12px;background:#0d1622;border:1px solid #243248;border-left:3px solid #243248;border-radius:6px;color:#e6edf6;cursor:pointer;font-family:inherit;text-align:left;transition:border-color .15s,background .15s,transform .15s;min-width:0;overflow:hidden;}
.usbsim-scn-btn:hover{border-color:#22d3ee;background:#101b2a;transform:translateY(-1px);}
.usbsim-scn-btn:focus-visible{outline:2px solid #22d3ee;outline-offset:2px;}
.usbsim-scn-btn.is-active{border-color:#22d3ee;border-left-color:#22d3ee;background:rgba(34,211,238,.10);box-shadow:0 0 18px -8px rgba(34,211,238,.6);}
.usbsim-scn-btn[disabled]{opacity:.55;cursor:wait;}
.usbsim-scn-n{display:inline-grid;place-items:center;width:22px;height:22px;border-radius:4px;background:#1a2332;color:#22d3ee;font-size:10.5px;font-weight:700;flex-shrink:0;}
.usbsim-scn-l{flex:1 1 auto;font-size:12px;letter-spacing:.02em;color:#e6edf6;font-weight:600;min-width:0;overflow-wrap:anywhere;line-height:1.3;}
.usbsim-scn-v{font-style:normal;font-size:9.5px;font-weight:700;letter-spacing:.18em;padding:3px 7px;border-radius:3px;border:1px solid currentColor;background:rgba(0,0,0,.2);flex:0 0 auto;white-space:nowrap;max-width:100%;}
.usbsim-v-allow{color:#22c55e;}.usbsim-v-deny,.usbsim-v-blocked,.usbsim-v-failclosed{color:#ef4444;}.usbsim-v-warn{color:#f59e0b;}

/* ---- Pipeline + packet ---- */
.usbsim-pipe-wrap{position:relative;margin:0 0 16px;}
.usbsim-pipe{list-style:none;margin:0;padding:14px;display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:8px;background:#08101c;border:1px solid #1a2332;border-radius:10px;position:relative;}
.usbsim-node{position:relative;display:flex;flex-direction:column;gap:4px;padding:10px 11px;background:#0d1622;border:1px solid #243248;border-left:3px solid #243248;border-radius:6px;transition:border-color .25s,background .25s,box-shadow .25s,transform .25s;min-width:0;overflow:hidden;}
.usbsim-node + .usbsim-node::before{content:"";position:absolute;left:-6px;top:50%;transform:translateY(-50%);width:5px;height:1px;background:#243248;}
.usbsim-led{width:8px;height:8px;border-radius:50%;background:#1a2332;border:1px solid #243248;}
.usbsim-stage{font-size:9.5px;letter-spacing:.16em;color:#8a96aa;text-transform:uppercase;font-weight:700;display:block;max-width:100%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.usbsim-sub{font-size:10.5px;color:#6b7a90;letter-spacing:.04em;min-height:14px;display:block;max-width:100%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
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
.usbsim-hero::after{content:"";position:absolute;left:0;right:0;top:-30%;height:60px;pointer-events:none;background:linear-gradient(180deg,transparent,rgba(34,211,238,.028),transparent);transform:translateY(0);animation:usbsim-scan 16s ease-in-out infinite;z-index:0;}
@keyframes usbsim-grid{from{background-position:0 0,0 0,0 0,0 0;}to{background-position:0 0,0 0,0 -56px,-56px 0;}}
@keyframes usbsim-scan{0%{transform:translateY(0);}50%{transform:translateY(580px);}100%{transform:translateY(0);}}

.usbsim-hero-title{font-size:34px;font-weight:800;letter-spacing:-.022em;margin-bottom:10px;line-height:1.1;}
.usbsim-hero-sub{font-size:14px;line-height:1.6;max-width:740px;margin-bottom:20px;color:#94a3b8;}

/* Evidence "sealed" moment — brief pulse when audit appends */
.usbsim-card.is-sealed{animation:usbsim-sealed 1.4s ease-out;}
@keyframes usbsim-sealed{0%{box-shadow:0 0 0 0 rgba(34,197,94,.55),inset 0 0 0 1px rgba(34,197,94,.45);}45%{box-shadow:0 0 0 6px rgba(34,197,94,.08),inset 0 0 0 1px rgba(34,197,94,.6);}100%{box-shadow:0 0 0 0 rgba(34,197,94,0),inset 0 0 0 1px rgba(34,197,94,0);}}
@media (prefers-reduced-motion:reduce){.usbsim-card.is-sealed{animation:none;}}
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

/* ======================================================================
   PHASE 3 — Governance Risk Score (preview)
   ====================================================================== */
.usbsim .usbsim-risk{margin:0 0 20px;padding:22px 24px;border:1px solid #1a2638;border-left:4px solid #22d3ee;border-radius:12px;background:linear-gradient(180deg,rgba(13,22,34,.85) 0%,rgba(8,14,22,.85) 100%);font-family:"Inter","Segoe UI",-apple-system,sans-serif;}
.usbsim-risk-hd{margin-bottom:14px;}
.usbsim-risk-titlerow{display:flex;align-items:baseline;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-top:6px;}
.usbsim-risk-title{margin:0;font-size:18px;font-weight:700;letter-spacing:-.01em;color:#f1f5f9;line-height:1.3;}
.usbsim-risk-preview{display:inline-block;margin-left:8px;font-size:9.5px;letter-spacing:.22em;color:#94a3b8;text-transform:uppercase;font-weight:600;border:1px solid #324158;border-radius:4px;padding:2px 7px;vertical-align:middle;}
.usbsim-risk-overall{display:flex;flex-direction:column;align-items:flex-end;gap:1px;}
.usbsim-risk-overall-k{font-size:9.5px;letter-spacing:.22em;color:#64748b;font-weight:700;text-transform:uppercase;}
.usbsim-risk-overall-v{font-size:16px;color:#22c55e;font-weight:800;letter-spacing:.02em;}
.usbsim-risk-list{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px 24px;}
.usbsim-risk-list li{display:flex;flex-direction:column;gap:4px;padding:10px 0;border-top:1px solid rgba(26,38,56,.6);}
.usbsim-risk-list li:nth-child(-n+2){border-top:none;padding-top:0;}
.usbsim-risk-row{display:flex;align-items:center;justify-content:space-between;gap:12px;}
.usbsim-risk-k{font-size:12.5px;color:#cbd5e1;font-weight:600;letter-spacing:.01em;}
.usbsim-risk-band{font-size:10px;letter-spacing:.18em;text-transform:uppercase;font-weight:800;padding:3px 10px;border-radius:999px;border:1px solid transparent;}
.usbsim .usbsim-band-low{color:#22c55e;background:rgba(34,197,94,.10);border-color:rgba(34,197,94,.35);}
.usbsim .usbsim-band-med{color:#f59e0b;background:rgba(245,158,11,.10);border-color:rgba(245,158,11,.35);}
.usbsim .usbsim-band-high{color:#22d3ee;background:rgba(34,211,238,.10);border-color:rgba(34,211,238,.35);}
.usbsim .usbsim-band-bad{color:#ef4444;background:rgba(239,68,68,.10);border-color:rgba(239,68,68,.35);}
.usbsim-risk-ctrl{margin:0;font-size:11.5px;line-height:1.5;color:#94a3b8;}
.usbsim-risk-foot{margin:14px 0 0;font-size:11px;color:#64748b;letter-spacing:.02em;line-height:1.55;}

/* ======================================================================
   PHASE 4 — Business Impact panel
   ====================================================================== */
.usbsim .usbsim-biz{margin:0 0 20px;padding:22px 24px;border:1px solid #1a2638;border-left:4px solid #22c55e;border-radius:12px;background:linear-gradient(180deg,rgba(13,22,34,.85) 0%,rgba(8,14,22,.85) 100%);font-family:"Inter","Segoe UI",-apple-system,sans-serif;}
.usbsim-biz-hd{margin-bottom:14px;}
.usbsim-biz-title{margin:6px 0 0;font-size:18px;font-weight:700;letter-spacing:-.01em;color:#f1f5f9;line-height:1.3;}
.usbsim-biz-list{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px 20px;}
.usbsim-biz-list li{display:flex;flex-direction:column;gap:2px;padding:12px 14px;background:rgba(8,14,22,.55);border:1px solid rgba(26,38,56,.7);border-radius:10px;}
.usbsim-biz-n{font-size:24px;font-weight:800;color:#22c55e;letter-spacing:-.01em;line-height:1.1;font-variant-numeric:tabular-nums;}
.usbsim-biz-l{font-size:11.5px;font-weight:600;color:#e2e8f0;line-height:1.35;margin-top:2px;}
.usbsim-biz-s{font-size:11px;color:#94a3b8;line-height:1.45;margin-top:2px;}
.usbsim-biz-foot{margin:14px 0 0;font-size:11px;color:#64748b;letter-spacing:.02em;line-height:1.55;}
@media (max-width:980px){.usbsim-biz-list{grid-template-columns:repeat(2,minmax(0,1fr));}}
@media (max-width:640px){.usbsim-biz-list{grid-template-columns:1fr;}.usbsim-risk-list{grid-template-columns:1fr;}.usbsim-risk-list li:nth-child(-n+2){border-top:1px solid rgba(26,38,56,.6);padding-top:10px;}.usbsim-risk-list li:first-child{border-top:none;padding-top:0;}}

/* ======================================================================
   PHASE 7 — What USBAY Prevents
   ====================================================================== */
.usbsim .usbsim-prev{margin:0 0 20px;padding:22px 24px;border:1px solid #1a2638;border-left:4px solid #f59e0b;border-radius:12px;background:linear-gradient(180deg,rgba(13,22,34,.85) 0%,rgba(8,14,22,.85) 100%);font-family:"Inter","Segoe UI",-apple-system,sans-serif;}
.usbsim-prev-hd{margin-bottom:14px;}
.usbsim-prev-title{margin:6px 0 0;font-size:18px;font-weight:700;letter-spacing:-.01em;color:#f1f5f9;line-height:1.3;}
.usbsim-prev-list{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px 16px;}
.usbsim-prev-list li{display:flex;flex-direction:column;gap:6px;padding:14px;background:rgba(8,14,22,.55);border:1px solid rgba(26,38,56,.7);border-radius:10px;}
.usbsim-prev-risk{font-size:13.5px;font-weight:700;color:#fbbf24;letter-spacing:-.005em;line-height:1.3;}
.usbsim-prev-mech{font-size:11.5px;line-height:1.5;color:#cbd5e1;}
.usbsim-prev-cons{font-size:11.5px;line-height:1.5;color:#94a3b8;border-top:1px solid rgba(26,38,56,.6);padding-top:6px;margin-top:2px;}
.usbsim-prev-foot{margin:14px 0 0;font-size:11px;color:#64748b;letter-spacing:.02em;line-height:1.55;}

/* ======================================================================
   PHASE 8 — Governance Evidence Readiness (regulator)
   ====================================================================== */
.usbsim .usbsim-reg{margin:0 0 20px;padding:22px 24px;border:1px solid #1a2638;border-left:4px solid #cbd5e1;border-radius:12px;background:linear-gradient(180deg,rgba(13,22,34,.92) 0%,rgba(8,14,22,.92) 100%);font-family:"Inter","Segoe UI",-apple-system,sans-serif;}
.usbsim-reg-hd{margin-bottom:14px;}
.usbsim-reg-titlerow{display:flex;align-items:baseline;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-top:6px;}
.usbsim-reg-title{margin:0;font-size:18px;font-weight:700;letter-spacing:-.01em;color:#f1f5f9;line-height:1.3;}
.usbsim-reg-state{font-size:11px;letter-spacing:.16em;color:#22c55e;text-transform:uppercase;font-weight:700;}
.usbsim-reg-list{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px 24px;}
.usbsim-reg-list li{display:flex;flex-direction:column;gap:5px;padding:12px 0;border-top:1px solid rgba(26,38,56,.6);}
.usbsim-reg-list li:nth-child(-n+2){border-top:none;padding-top:0;}
.usbsim-reg-row{display:flex;align-items:center;justify-content:space-between;gap:12px;}
.usbsim-reg-k{font-size:12.5px;color:#e2e8f0;font-weight:600;letter-spacing:.005em;}
.usbsim-reg-pill{font-size:9.5px;letter-spacing:.18em;text-transform:uppercase;font-weight:800;padding:3px 9px;border-radius:999px;border:1px solid transparent;}
.usbsim .usbsim-reg-ok{color:#22c55e;background:rgba(34,197,94,.10);border-color:rgba(34,197,94,.35);}
.usbsim-reg-d{margin:0;font-size:11.5px;line-height:1.5;color:#94a3b8;}
.usbsim-reg-foot{margin:14px 0 0;font-size:11px;color:#64748b;letter-spacing:.02em;line-height:1.55;font-style:italic;}
@media (max-width:980px){.usbsim-prev-list{grid-template-columns:repeat(2,minmax(0,1fr));}}
@media (max-width:640px){.usbsim-prev-list{grid-template-columns:1fr;}.usbsim-reg-list{grid-template-columns:1fr;}.usbsim-reg-list li:nth-child(-n+2){border-top:1px solid rgba(26,38,56,.6);padding-top:12px;}.usbsim-reg-list li:first-child{border-top:none;padding-top:0;}}

/* ======================================================================
   COMMERCIAL POLISH — Value strip, Pilot Recommendation, CTA hierarchy
   ====================================================================== */
.usbsim .usbsim-valstrip{margin:0 0 18px;padding:14px 18px;border:1px solid rgba(26,38,56,.7);border-radius:10px;background:rgba(8,14,22,.55);font-family:"Inter","Segoe UI",-apple-system,sans-serif;}
.usbsim-valstrip-list{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px 18px;}
.usbsim-valstrip-list li{display:flex;flex-direction:column;gap:4px;min-width:0;padding-left:12px;border-left:2px solid rgba(34,211,238,.35);}
.usbsim-valstrip-k{font-size:9.5px;letter-spacing:.22em;color:#22d3ee;font-weight:700;text-transform:uppercase;}
.usbsim-valstrip-v{font-size:11.5px;line-height:1.5;color:#cbd5e1;}

.usbsim .usbsim-pilot{margin:0 0 20px;padding:22px 24px;border:1px solid #1a2638;border-left:4px solid #22c55e;border-radius:12px;background:linear-gradient(180deg,rgba(13,22,34,.85) 0%,rgba(8,14,22,.85) 100%);font-family:"Inter","Segoe UI",-apple-system,sans-serif;}
.usbsim-pilot-hd{margin-bottom:14px;}
.usbsim-pilot-title{margin:6px 0 0;font-size:18px;font-weight:700;letter-spacing:-.01em;color:#f1f5f9;line-height:1.3;}
.usbsim-pilot-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px 22px;}
.usbsim-pilot-cell{display:flex;flex-direction:column;gap:5px;padding:10px 0;border-top:1px solid rgba(26,38,56,.6);min-width:0;}
.usbsim-pilot-cell:nth-child(-n+2){border-top:none;padding-top:0;}
.usbsim-pilot-cell-cta{grid-column:1 / -1;border-top:1px solid rgba(26,38,56,.6);padding-top:14px;gap:8px;align-items:flex-start;}
.usbsim-pilot-k{font-size:9.5px;letter-spacing:.22em;color:#64748b;font-weight:700;text-transform:uppercase;}
.usbsim-pilot-v{margin:0;font-size:12.5px;line-height:1.55;color:#cbd5e1;}
.usbsim-pilot-cta{min-height:42px;padding:11px 20px;font-size:11.5px;letter-spacing:.16em;}
.usbsim-pilot-note{font-size:10.5px;color:#64748b;font-style:italic;line-height:1.45;}
.usbsim-pilot-cell-wide{grid-column:1 / -1;}
.usbsim-pilot-gaps,.usbsim-pilot-outcomes{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:5px;}
.usbsim-pilot-gaps li{position:relative;padding-left:18px;font-size:12.5px;line-height:1.5;color:#cbd5e1;}
.usbsim-pilot-gaps li::before{content:"";position:absolute;left:4px;top:8px;width:6px;height:6px;border-radius:50%;background:#fbbf24;}
.usbsim-pilot-outcomes li{position:relative;padding-left:20px;font-size:12.5px;line-height:1.5;color:#cbd5e1;}
.usbsim-pilot-outcomes li::before{content:"\2713";position:absolute;left:2px;top:0;color:#22c55e;font-weight:700;font-size:13px;}
.usbsim-pilot-badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:10.5px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;border:1px solid transparent;}
.usbsim-pilot-badge.is-high{background:rgba(34,197,94,.14);color:#86efac;border-color:rgba(34,197,94,.45);}
.usbsim-pilot-badge.is-med{background:rgba(251,191,36,.14);color:#fbbf24;border-color:rgba(251,191,36,.45);}
.usbsim-pilot-badge.is-low{background:rgba(248,113,113,.14);color:#fca5a5;border-color:rgba(248,113,113,.45);}

/* Executive Confidence Metrics strip */
.usbsim .usbsim-confmet{margin:0 0 18px;padding:16px 20px;border:1px solid rgba(26,38,56,.7);border-radius:10px;background:rgba(8,14,22,.55);font-family:"Inter","Segoe UI",-apple-system,sans-serif;}
.usbsim-confmet-hd{margin-bottom:12px;}
.usbsim-confmet-title{margin:6px 0 0;font-size:15px;font-weight:700;color:#f1f5f9;letter-spacing:-.005em;line-height:1.3;}
.usbsim-confmet-list{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px 14px;}
.usbsim-confmet-list li{display:flex;flex-direction:column;gap:6px;padding:10px 12px;border:1px solid rgba(26,38,56,.6);border-radius:8px;background:rgba(13,22,34,.4);min-width:0;}
.usbsim-confmet-k{font-size:10px;letter-spacing:.16em;color:#94a3b8;font-weight:700;text-transform:uppercase;line-height:1.3;}
.usbsim-confmet-band{display:inline-block;padding:3px 10px;border-radius:6px;font-size:10.5px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;border:1px solid transparent;align-self:flex-start;}
.usbsim-confmet-band.is-high{background:rgba(34,197,94,.14);color:#86efac;border-color:rgba(34,197,94,.45);}
.usbsim-confmet-band.is-med{background:rgba(251,191,36,.14);color:#fbbf24;border-color:rgba(251,191,36,.45);}
.usbsim-confmet-band.is-low{background:rgba(248,113,113,.14);color:#fca5a5;border-color:rgba(248,113,113,.45);}
.usbsim-confmet-foot{margin:12px 0 0;font-size:11px;color:#64748b;font-style:italic;line-height:1.5;}

/* Recommended Next Step card */
.usbsim .usbsim-nextstep{margin:0 0 20px;padding:18px 22px;border:1px solid #1a2638;border-left:4px solid #22d3ee;border-radius:10px;background:linear-gradient(180deg,rgba(13,22,34,.85) 0%,rgba(8,14,22,.85) 100%);font-family:"Inter","Segoe UI",-apple-system,sans-serif;}
.usbsim-nextstep-hd{margin-bottom:10px;}
.usbsim-nextstep-title{margin:6px 0 0;font-size:17px;font-weight:700;color:#f1f5f9;letter-spacing:-.005em;line-height:1.3;}
.usbsim-nextstep-grid{display:grid;grid-template-columns:minmax(120px,180px) 1fr;gap:10px 22px;align-items:start;}
.usbsim-nextstep-cell{display:flex;flex-direction:column;gap:6px;min-width:0;}
.usbsim-nextstep-cell-wide{min-width:0;}
.usbsim-nextstep-k{font-size:9.5px;letter-spacing:.22em;color:#64748b;font-weight:700;text-transform:uppercase;}
.usbsim-nextstep-v{margin:0;font-size:12.5px;line-height:1.55;color:#cbd5e1;}
.usbsim-pilot-hidden{display:none;}
.usbsim .usbsim-lic{margin:0 0 20px;padding:22px 24px;border:1px solid #1a2638;border-left:4px solid #22d3ee;border-radius:12px;background:linear-gradient(180deg,rgba(13,22,34,.85) 0%,rgba(8,14,22,.85) 100%);font-family:"Inter","Segoe UI",-apple-system,sans-serif;scroll-margin-top:16px;}
.usbsim-lic-hd{margin-bottom:6px;}
.usbsim-lic-title{margin:6px 0 0;font-size:18px;font-weight:700;letter-spacing:-.01em;color:#f1f5f9;line-height:1.3;}
.usbsim-lic-lede{margin:8px 0 0;font-size:12.5px;line-height:1.55;color:#94a3b8;max-width:74ch;}
.usbsim-lic-form{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;align-items:end;margin:16px 0 18px;}
.usbsim-lic-field{display:flex;flex-direction:column;gap:6px;min-width:0;}
.usbsim-lic-flabel{font-size:9.5px;letter-spacing:.18em;color:#64748b;font-weight:700;text-transform:uppercase;}
.usbsim-lic-field select{appearance:none;width:100%;background:#0a1018 url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath fill='%2364748b' d='M0 0l5 6 5-6z'/%3E%3C/svg%3E") no-repeat right 12px center;color:#e2e8f0;border:1px solid #233247;border-radius:8px;padding:10px 30px 10px 12px;font-size:12.5px;font-family:inherit;cursor:pointer;}
.usbsim-lic-field select:focus-visible{outline:2px solid #22d3ee;outline-offset:1px;}
.usbsim-lic-run{grid-column:1 / -1;min-height:42px;padding:11px 20px;font-size:11.5px;letter-spacing:.16em;}
.usbsim-lic-result{border-top:1px solid rgba(26,38,56,.6);padding-top:16px;}
.usbsim-lic-resulthd{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:10px;}
.usbsim-lic-tierwrap{display:flex;flex-direction:column;gap:4px;}
.usbsim-lic-tierk{font-size:9.5px;letter-spacing:.22em;color:#64748b;font-weight:700;text-transform:uppercase;}
.usbsim-lic-tier{font-size:20px;font-weight:800;letter-spacing:-.01em;line-height:1.1;color:#22d3ee;}
.usbsim-lic-tier.is-pilot{color:#22d3ee;}
.usbsim-lic-tier.is-op{color:#38bdf8;}
.usbsim-lic-tier.is-ent{color:#a78bfa;}
.usbsim-lic-tier.is-sov{color:#34d399;}
.usbsim-licrec{margin:18px 0 0;padding:18px;border:1px solid #15324a;border-radius:12px;background:linear-gradient(180deg,rgba(8,18,24,.6),rgba(6,12,18,.6));}
.usbsim-licrec-eyebrow{font-size:9px;letter-spacing:.22em;text-transform:uppercase;color:#22d3ee;font-weight:700;}
.usbsim-licrec-title{margin:5px 0 4px;font-size:16px;font-weight:800;color:#e6edf6;letter-spacing:.02em;}
.usbsim-licrec-sub{margin:0 0 14px;font-size:11.5px;line-height:1.55;color:#94a3b8;max-width:80ch;}
.usbsim-licrec-banner{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:10px;}
.usbsim-licrec-tag{font-size:9px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:#94a3b8;}
.usbsim-licrec-fit{margin:0 0 14px;font-size:12px;line-height:1.55;color:#cbd5e1;max-width:80ch;}
.usbsim-licrec-why{padding:12px 14px;border:1px solid #1f3a52;border-radius:10px;background:rgba(6,14,20,.5);margin-bottom:14px;}
.usbsim-licrec-whk{display:block;font-size:8px;letter-spacing:.18em;text-transform:uppercase;color:#22d3ee;font-weight:700;margin-bottom:8px;}
.usbsim-licrec-list{margin:0;padding-left:18px;display:flex;flex-direction:column;gap:5px;}
.usbsim-licrec-list li{font-size:11.5px;line-height:1.5;color:#e6edf6;}
.usbsim-licrec-whytext{margin:0 0 10px;font-size:11.5px;line-height:1.55;color:#cbd5e1;}
.usbsim-licrec-dims{padding:12px 14px;border:1px solid #1f3a52;border-radius:10px;background:rgba(6,14,20,.5);}
.usbsim-licrec-dimgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px 18px;margin-top:8px;}
.usbsim-licrec-dim{display:flex;flex-direction:column;gap:3px;min-width:0;}
.usbsim-licrec-dk{font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;font-weight:700;}
.usbsim-licrec-dv{font-size:12px;color:#e6edf6;font-weight:700;line-height:1.4;overflow-wrap:anywhere;}
@media (max-width:560px){.usbsim-licrec-dimgrid{grid-template-columns:1fr;}}
.usbsim-licrec-detail{margin-top:14px;display:flex;flex-direction:column;gap:14px;padding:13px 14px;border:1px solid #234a3a;border-radius:10px;background:rgba(6,18,14,.5);}
.usbsim-licrec-detail[hidden]{display:none;}
.usbsim-licrec-dblock{display:flex;flex-direction:column;min-width:0;}
.usbsim-licrec-dcols{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px 18px;}
.usbsim-licrec-caps li{color:#d1fae5;}
.usbsim-licrec-model{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin-top:4px;}
.usbsim-licrec-mrow{display:flex;flex-direction:column;gap:2px;padding:8px 10px;border:1px solid #234a3a;border-radius:8px;background:rgba(8,20,16,.6);min-width:0;}
.usbsim-licrec-mk{font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:#6ee7b7;font-weight:700;}
.usbsim-licrec-mv{font-size:12px;color:#e6edf6;font-weight:700;overflow-wrap:anywhere;}
@media (max-width:560px){.usbsim-licrec-dcols{grid-template-columns:1fr;}.usbsim-licrec-model{grid-template-columns:1fr;}}
.usbsim-lic-tag{display:inline-block;padding:5px 12px;border-radius:999px;font-size:10px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;background:rgba(34,211,238,.12);color:#67e8f9;border:1px solid rgba(34,211,238,.4);}
.usbsim-lic-fit{margin:0 0 14px;font-size:12.5px;line-height:1.55;color:#cbd5e1;}
.usbsim-lic-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px 22px;margin-bottom:14px;}
.usbsim-lic-cell{display:flex;flex-direction:column;gap:4px;padding:10px 0;border-top:1px solid rgba(26,38,56,.6);min-width:0;}
.usbsim-lic-cell:nth-child(-n+2){border-top:none;padding-top:0;}
.usbsim-lic-k{font-size:9.5px;letter-spacing:.22em;color:#64748b;font-weight:700;text-transform:uppercase;}
.usbsim-lic-v{margin:0;font-size:12.5px;line-height:1.55;color:#cbd5e1;}
.usbsim-lic-incl{list-style:none;margin:0 0 16px;padding:14px 0 0;border-top:1px solid rgba(26,38,56,.6);display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px 22px;}
.usbsim-lic-incl li{position:relative;padding-left:20px;font-size:12px;line-height:1.5;color:#cbd5e1;}
.usbsim-lic-incl li::before{content:"\2713";position:absolute;left:2px;top:0;color:#22d3ee;font-weight:700;font-size:13px;}
.usbsim-lic-cta{display:flex;flex-direction:column;gap:8px;align-items:flex-start;border-top:1px solid rgba(26,38,56,.6);padding-top:14px;}
.usbsim-lic-ctabtn{min-height:42px;padding:11px 20px;font-size:11.5px;letter-spacing:.16em;}
.usbsim-lic-note{font-size:10.5px;color:#64748b;font-style:italic;line-height:1.45;}
@media (max-width:780px){.usbsim-lic-form{grid-template-columns:1fr 1fr;}.usbsim-lic-grid{grid-template-columns:1fr;}.usbsim-lic-cell:nth-child(-n+2){border-top:1px solid rgba(26,38,56,.6);padding-top:10px;}.usbsim-lic-cell:first-child{border-top:none;padding-top:0;}.usbsim-lic-incl{grid-template-columns:1fr;}}

/* ======================================================================
   PHASE 16-19 — Executive Walkthrough + Sector Demonstrations
   ====================================================================== */
.usbsim .usbsim-walkbar{display:grid;grid-template-columns:1fr auto;gap:14px 22px;align-items:center;margin:0 0 18px;padding:14px 20px;border:1px solid rgba(36,58,85,.7);border-radius:10px;background:rgba(8,14,22,.55);font-family:"Inter","Segoe UI",-apple-system,sans-serif;}
.usbsim-walkbar-copy{min-width:0;}
.usbsim-walkbar-sub{margin:6px 0 0;font-size:12px;line-height:1.55;color:#cbd5e1;}
.usbsim-walkbar-btn{min-height:42px;padding:10px 18px;font-size:11px;letter-spacing:.18em;font-weight:700;white-space:nowrap;}

.usbsim-walk{position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;padding:24px;}
.usbsim-walk[hidden]{display:none;}
.usbsim-walk-backdrop{position:absolute;inset:0;background:rgba(2,6,12,.7);backdrop-filter:blur(3px);}
.usbsim-walk-card{position:relative;max-width:580px;width:100%;background:linear-gradient(180deg,#0e1a2b 0%,#0a1320 100%);border:1px solid #1f3253;border-radius:14px;padding:22px 24px;color:#e6edf6;box-shadow:0 30px 80px -20px rgba(0,0,0,.7);font-family:"Inter","Segoe UI",-apple-system,sans-serif;}
.usbsim-walk-hd{display:flex;justify-content:space-between;align-items:flex-start;gap:14px;margin-bottom:14px;}
.usbsim-walk-title{margin:6px 0 0;font-size:17px;font-weight:700;color:#f1f5f9;line-height:1.3;}
.usbsim-walk-x{background:transparent;border:1px solid rgba(255,255,255,.15);color:#cbd5e1;width:32px;height:32px;border-radius:8px;cursor:pointer;font-size:18px;line-height:1;display:grid;place-items:center;font-family:inherit;flex-shrink:0;}
.usbsim-walk-x:hover{border-color:rgba(255,255,255,.4);color:#fff;}
.usbsim-walk-meta{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;padding-bottom:12px;border-bottom:1px solid rgba(36,58,85,.6);gap:12px;}
.usbsim-walk-audience{display:inline-block;padding:4px 12px;border-radius:999px;font-size:10.5px;font-weight:700;letter-spacing:.18em;text-transform:uppercase;background:rgba(34,211,238,.14);color:#7dd3fc;border:1px solid rgba(34,211,238,.45);}
.usbsim-walk-progress{font-size:11px;letter-spacing:.12em;color:#94a3b8;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;}
.usbsim-walk-progress span{color:#22d3ee;font-weight:700;}
.usbsim-walk-body{margin:0 0 16px;font-size:13.5px;line-height:1.65;color:#e2e8f0;min-height:96px;}
.usbsim-walk-actions{display:flex;justify-content:space-between;gap:10px;margin-bottom:10px;}
.usbsim-walk-actions .usbsim-btn-ghost,.usbsim-walk-actions .usbsim-btn-primary{min-height:38px;padding:9px 18px;font-size:10.5px;letter-spacing:.16em;}
.usbsim-walk-note{margin:0;font-size:10.5px;color:#64748b;font-style:italic;text-align:center;line-height:1.45;}

.usbsim .usbsim-sector{margin:0 0 22px;padding:22px 24px;border:1px solid #1a2638;border-left:4px solid #8b5cf6;border-radius:12px;background:linear-gradient(180deg,rgba(13,22,34,.85) 0%,rgba(8,14,22,.85) 100%);font-family:"Inter","Segoe UI",-apple-system,sans-serif;scroll-margin-top:16px;}
.usbsim-sector-hd{margin-bottom:14px;}
.usbsim-sector-title{margin:6px 0 4px;font-size:18px;font-weight:700;color:#f1f5f9;letter-spacing:-.01em;line-height:1.3;}
.usbsim-sector-lede{margin:0;font-size:12px;color:#94a3b8;line-height:1.55;}
.usbsim-sector-chips{display:flex;flex-wrap:wrap;gap:6px;margin:14px 0 18px;}
.usbsim-sector-chip{appearance:none;background:rgba(8,14,22,.6);color:#cbd5e1;border:1px solid rgba(36,58,85,.7);border-radius:999px;padding:8px 14px;font-size:11.5px;font-weight:600;letter-spacing:.01em;cursor:pointer;transition:border-color .15s,color .15s,background .15s;font-family:inherit;display:inline-flex;align-items:center;gap:8px;}
.usbsim-sector-chip:hover{border-color:rgba(139,92,246,.6);color:#e2e8f0;}
.usbsim-sector-chip.is-active{background:rgba(139,92,246,.14);color:#c4b5fd;border-color:rgba(139,92,246,.55);}
.usbsim-sector-chip:focus-visible{outline:2px solid #8b5cf6;outline-offset:2px;}
.usbsim-sector-chip-tag{font-size:9px;letter-spacing:.18em;text-transform:uppercase;color:#fbbf24;font-weight:700;padding:2px 6px;border:1px solid rgba(251,191,36,.45);border-radius:4px;background:rgba(251,191,36,.08);}
.usbsim-sector-flow{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(0,1fr);gap:18px 22px;align-items:start;}
.usbsim-sector-steps{list-style:none;margin:0;padding:0;border:1px solid rgba(26,38,56,.6);border-radius:8px;background:rgba(8,14,22,.4);overflow:hidden;counter-reset:secstep;}
.usbsim-sector-steps li{position:relative;display:flex;flex-direction:column;gap:4px;padding:12px 14px 12px 44px;border-top:1px solid rgba(26,38,56,.5);min-width:0;}
.usbsim-sector-steps li:first-child{border-top:none;}
.usbsim-sector-steps li::before{counter-increment:secstep;content:counter(secstep);position:absolute;left:12px;top:13px;width:22px;height:22px;border-radius:6px;background:#1a2332;color:#22d3ee;font-size:11px;font-weight:700;display:grid;place-items:center;}
.usbsim-sector-stepk{font-size:9.5px;letter-spacing:.22em;color:#64748b;font-weight:700;text-transform:uppercase;}
.usbsim-sector-stepv{margin:0;font-size:12.5px;line-height:1.55;color:#cbd5e1;}
.usbsim-sector-verdict{display:inline-block;padding:3px 10px;border-radius:4px;font-size:10.5px;font-weight:700;letter-spacing:.18em;border:1px solid currentColor;background:rgba(0,0,0,.2);color:#fbbf24;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;}
.usbsim-sector-verdict.is-allow{color:#86efac;}
.usbsim-sector-verdict.is-deny{color:#fca5a5;}
.usbsim-sector-verdict.is-review{color:#fbbf24;}
.usbsim-sector-cons{display:flex;flex-direction:column;gap:12px;}
.usbsim-sector-conscol{border:1px solid rgba(26,38,56,.6);border-radius:8px;padding:12px 14px;background:rgba(8,14,22,.4);}
.usbsim-sector-conscol-bad{border-left:3px solid #ef4444;}
.usbsim-sector-conscol-ok{border-left:3px solid #22c55e;}
.usbsim-sector-conshd{margin-bottom:8px;}
.usbsim-sector-consbadge{display:inline-block;padding:3px 10px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.18em;text-transform:uppercase;border:1px solid currentColor;}
.usbsim-sector-consbadge.is-bad{color:#fca5a5;background:rgba(248,113,113,.1);}
.usbsim-sector-consbadge.is-ok{color:#86efac;background:rgba(34,197,94,.1);}
.usbsim-sector-conslist{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:6px;}
.usbsim-sector-conslist li{display:flex;flex-direction:column;gap:3px;padding:6px 0;border-top:1px solid rgba(26,38,56,.5);}
.usbsim-sector-conslist li:first-child{border-top:none;padding-top:0;}
.usbsim-sector-consk{font-size:9px;letter-spacing:.22em;color:#64748b;font-weight:700;text-transform:uppercase;}
.usbsim-sector-consv{margin:0;font-size:12px;line-height:1.5;color:#cbd5e1;}
.usbsim-sector-foot{margin:14px 0 0;font-size:11px;color:#64748b;font-style:italic;line-height:1.5;}

/* Generic walkthrough-target flash for any major section */
.usbsim-confmet.is-flash,.usbsim-pilot.is-flash,.usbsim-nextstep.is-flash,.usbsim-sector.is-flash,.usbsim-reg.is-flash,.usbsim-prev.is-flash,.usbsim-ind.is-flash,.usbsim-risk.is-flash,.usbsim-biz.is-flash{box-shadow:0 0 0 2px rgba(34,211,238,.55),0 0 40px -6px rgba(34,211,238,.45);transition:box-shadow .6s ease-out;}
.usbsim-confmet,.usbsim-pilot,.usbsim-nextstep,.usbsim-sector,.usbsim-reg,.usbsim-prev,.usbsim-ind,.usbsim-risk,.usbsim-biz{scroll-margin-top:16px;}

@media (max-width:980px){.usbsim-sector-flow{grid-template-columns:1fr;}}
@media (max-width:780px){.usbsim-walkbar{grid-template-columns:1fr;}.usbsim-walkbar-btn{width:100%;}.usbsim-walk{padding:14px;}}

/* ======================================================================
   PHASE 21 — Executive Governance Report Preview (client-side only)
   ====================================================================== */
.usbsim .usbsim-walkbar-actions{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;align-items:center;}
.usbsim .usbsim-walkbar-actions .usbsim-walkbar-btn{margin:0;}
.usbsim-rpt{position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;padding:24px;}
.usbsim-rpt[hidden]{display:none;}
.usbsim-rpt-backdrop{position:absolute;inset:0;background:rgba(2,6,12,.72);backdrop-filter:blur(3px);}
.usbsim-rpt-card{position:relative;display:flex;flex-direction:column;max-width:820px;max-height:88vh;width:100%;background:linear-gradient(180deg,#0e1a2b 0%,#0a1320 100%);border:1px solid #1f3253;border-radius:14px;color:#e6edf6;box-shadow:0 30px 80px -20px rgba(0,0,0,.7);font-family:"Inter","Segoe UI",-apple-system,sans-serif;overflow:hidden;}
.usbsim-rpt-hd{display:flex;justify-content:space-between;align-items:flex-start;gap:14px;padding:20px 24px 12px;border-bottom:1px solid rgba(36,58,85,.6);flex-shrink:0;}
.usbsim-rpt-title{margin:6px 0 0;font-size:17px;font-weight:700;color:#f1f5f9;line-height:1.3;}
.usbsim-rpt-x{background:transparent;border:1px solid rgba(255,255,255,.15);color:#cbd5e1;width:32px;height:32px;border-radius:8px;cursor:pointer;font-size:18px;line-height:1;display:grid;place-items:center;font-family:inherit;flex-shrink:0;}
.usbsim-rpt-x:hover{border-color:rgba(255,255,255,.4);color:#fff;}
.usbsim-rpt-privacy{margin:0;padding:10px 24px;background:rgba(34,211,238,.08);border-bottom:1px solid rgba(34,211,238,.25);color:#7dd3fc;font-size:11.5px;line-height:1.5;letter-spacing:.01em;font-style:italic;flex-shrink:0;}
.usbsim-rpt-body{padding:18px 24px;overflow-y:auto;flex:1 1 auto;min-height:0;}
.usbsim-rpt-sec{margin:0 0 14px;padding:14px 16px;border:1px solid rgba(26,38,56,.6);border-left:3px solid #22d3ee;border-radius:8px;background:rgba(8,14,22,.4);}
.usbsim-rpt-sec-h{margin:0 0 10px;font-size:10px;letter-spacing:.22em;text-transform:uppercase;color:#94a3b8;font-weight:700;}
.usbsim-rpt-v{margin:0;font-size:13px;line-height:1.55;color:#e2e8f0;}
.usbsim-rpt-v b{color:#cbd5e1;font-weight:700;}
.usbsim-rpt-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.usbsim-rpt-sec-wide{grid-column:1 / -1;}
.usbsim-rpt-aud{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:0;}
.usbsim-rpt-aud li{display:grid;grid-template-columns:160px 1fr;gap:12px;padding:8px 0;border-top:1px solid rgba(26,38,56,.5);align-items:start;}
.usbsim-rpt-aud li:first-child{border-top:none;padding-top:0;}
.usbsim-rpt-audk{font-size:10.5px;letter-spacing:.18em;text-transform:uppercase;color:#7dd3fc;font-weight:700;padding-top:2px;}
.usbsim-rpt-audv{font-size:12.5px;line-height:1.55;color:#cbd5e1;}
.usbsim-rpt-list{margin:0;padding-left:18px;font-size:12.5px;line-height:1.6;color:#cbd5e1;}
.usbsim-rpt-list li{margin-bottom:4px;}
.usbsim-rpt-kvlist{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:0;}
.usbsim-rpt-kvlist li{display:grid;grid-template-columns:minmax(160px,38%) 1fr;gap:12px;padding:7px 0;border-top:1px solid rgba(26,38,56,.5);align-items:start;}
.usbsim-rpt-kvlist li:first-child{border-top:none;padding-top:0;}
.usbsim-rpt-kvk{font-size:10.5px;letter-spacing:.16em;text-transform:uppercase;color:#94a3b8;font-weight:700;padding-top:2px;}
.usbsim-rpt-kvv{font-size:12.5px;line-height:1.5;color:#e6edf6;word-break:break-word;overflow-wrap:anywhere;}
.usbsim-rpt-badge{display:inline-block;padding:4px 12px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.12em;border:1px solid currentColor;background:rgba(0,0,0,.2);color:#cbd5e1;}
.usbsim-rpt-badge.is-low{color:#86efac;}
.usbsim-rpt-badge.is-med{color:#fbbf24;}
.usbsim-rpt-badge.is-high{color:#fca5a5;}
.usbsim-rpt-foot{display:flex;justify-content:space-between;align-items:center;gap:14px;padding:14px 24px;border-top:1px solid rgba(36,58,85,.6);background:rgba(8,14,22,.6);flex-shrink:0;}
.usbsim-rpt-note{margin:0;font-size:11px;color:#64748b;font-style:italic;line-height:1.5;flex:1 1 auto;min-width:0;}
.usbsim-rpt-closebtn{min-height:36px;padding:8px 16px;font-size:10.5px;letter-spacing:.16em;white-space:nowrap;flex-shrink:0;}
@media (max-width:780px){.usbsim-rpt{padding:10px;}.usbsim-rpt-card{max-height:94vh;}.usbsim-rpt-grid{grid-template-columns:1fr;}.usbsim-rpt-aud li{grid-template-columns:1fr;gap:4px;}.usbsim-rpt-kvlist li{grid-template-columns:1fr;gap:2px;}.usbsim-rpt-foot{flex-direction:column;align-items:stretch;}.usbsim-rpt-closebtn{width:100%;}}

@media (max-width:980px){.usbsim-confmet-list{grid-template-columns:repeat(3,minmax(0,1fr));}}
@media (max-width:780px){.usbsim-confmet-list{grid-template-columns:repeat(2,minmax(0,1fr));}.usbsim-nextstep-grid{grid-template-columns:1fr;}}
@media (max-width:520px){.usbsim-confmet-list{grid-template-columns:1fr;}}

/* CTA hierarchy: primary dominates, secondary/tertiary recede */
.usbsim .usbsim-cta-primary{min-height:52px;padding:14px 24px;font-size:13px;letter-spacing:.2em;font-weight:700;width:100%;box-shadow:0 8px 24px -10px rgba(34,211,238,.55);}
.usbsim-cta-actions-row{display:grid;grid-template-columns:1fr 1fr;gap:8px;}
.usbsim .usbsim-cta-secondary,.usbsim .usbsim-cta-tertiary{min-height:38px;padding:9px 14px;font-size:10.5px;letter-spacing:.14em;font-weight:600;}
.usbsim .usbsim-cta-tertiary{opacity:.88;}
.usbsim .usbsim-cta-tertiary:hover{opacity:1;}
.usbsim .usbsim-cta-copy-ok{color:#22c55e;border-color:#22c55e;}

@media (max-width:980px){.usbsim-valstrip-list{grid-template-columns:repeat(3,minmax(0,1fr));}}
@media (max-width:780px){.usbsim-valstrip-list{grid-template-columns:repeat(2,minmax(0,1fr));}.usbsim-pilot-grid{grid-template-columns:1fr;}.usbsim-pilot-cell:nth-child(-n+2){border-top:1px solid rgba(26,38,56,.6);padding-top:10px;}.usbsim-pilot-cell:first-child{border-top:none;padding-top:0;}.usbsim-cta-actions-row{grid-template-columns:1fr;}}
@media (max-width:520px){.usbsim-valstrip-list{grid-template-columns:1fr;}}

/* ======================================================================
   PHASE 6 — Industry Context (preset switcher)
   ====================================================================== */
.usbsim .usbsim-ind{margin:0 0 20px;padding:22px 24px;border:1px solid #1a2638;border-left:4px solid #8b5cf6;border-radius:12px;background:linear-gradient(180deg,rgba(13,22,34,.85) 0%,rgba(8,14,22,.85) 100%);font-family:"Inter","Segoe UI",-apple-system,sans-serif;}
.usbsim-ind-hd{margin-bottom:12px;}
.usbsim-ind-title{margin:6px 0 0;font-size:18px;font-weight:700;letter-spacing:-.01em;color:#f1f5f9;line-height:1.3;}
.usbsim-ind-chips{display:flex;flex-wrap:wrap;gap:6px;margin:12px 0 16px;}
.usbsim-ind-chip{appearance:none;background:rgba(8,14,22,.6);color:#cbd5e1;border:1px solid rgba(36,58,85,.7);border-radius:999px;padding:8px 14px;font-size:11.5px;font-weight:600;letter-spacing:.01em;cursor:pointer;transition:border-color .15s,color .15s,background .15s;font-family:inherit;}
.usbsim-ind-chip:hover{border-color:rgba(139,92,246,.6);color:#e2e8f0;}
.usbsim-ind-chip.is-active{background:rgba(139,92,246,.14);color:#c4b5fd;border-color:rgba(139,92,246,.55);}
.usbsim-ind-chip:focus-visible{outline:2px solid #8b5cf6;outline-offset:2px;}
.usbsim-ind-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px 22px;}
.usbsim-ind-cell{display:flex;flex-direction:column;gap:4px;padding:10px 0;border-top:1px solid rgba(26,38,56,.6);}
.usbsim-ind-cell:nth-child(-n+2){border-top:none;padding-top:0;}
.usbsim-ind-cell-wide{grid-column:1 / -1;}
.usbsim-ind-k{font-size:9.5px;letter-spacing:.22em;color:#64748b;font-weight:700;text-transform:uppercase;}
.usbsim-ind-v{margin:0;font-size:12.5px;line-height:1.55;color:#cbd5e1;}

/* ======================================================================
   PHASE 5/7 — Pilot CTA row + Intake modal
   ====================================================================== */
.usbsim .usbsim-cta{margin:0 0 22px;padding:22px 24px;border:1px solid #1a2638;border-left:4px solid #22d3ee;border-radius:12px;background:linear-gradient(140deg,rgba(8,16,28,.96) 0%,rgba(10,17,25,.95) 60%,rgba(8,14,22,.95) 100%);box-shadow:0 0 0 1px rgba(34,211,238,.10),0 14px 40px -22px rgba(34,211,238,.35);font-family:"Inter","Segoe UI",-apple-system,sans-serif;display:grid;grid-template-columns:1fr auto;gap:16px 24px;align-items:center;}
.usbsim-cta-title{margin:6px 0 4px;font-size:19px;font-weight:700;letter-spacing:-.01em;color:#f1f5f9;line-height:1.3;}
.usbsim-cta-sub{margin:0;font-size:12.5px;color:#94a3b8;line-height:1.5;}
.usbsim-cta-actions{display:flex;flex-direction:column;gap:8px;min-width:280px;}
.usbsim-cta-priv{grid-column:1 / -1;margin:8px 0 0;font-size:10.5px;color:#64748b;letter-spacing:.02em;font-style:italic;line-height:1.5;border-top:1px solid rgba(26,38,56,.5);padding-top:10px;}

.usbsim-intake{position:fixed;inset:0;z-index:9998;display:flex;align-items:flex-start;justify-content:center;padding:24px;overflow-y:auto;animation:usbsim-fade-in .25s ease-out;}
.usbsim-intake[hidden]{display:none!important;}
.usbsim-intake-backdrop{position:fixed;inset:0;background:rgba(2,8,16,.78);backdrop-filter:blur(2px);}
.usbsim-intake-card{position:relative;z-index:1;max-width:720px;width:100%;margin:auto;background:linear-gradient(180deg,#0f1a2a 0%,#0a131e 100%);border:1px solid #243a55;border-left:4px solid #22d3ee;border-radius:14px;padding:24px 28px 22px;box-shadow:0 30px 80px -20px rgba(0,0,0,.7),0 0 0 1px rgba(34,211,238,.18);color:#e6edf6;font-family:"Inter","Segoe UI",-apple-system,sans-serif;}
.usbsim-intake-hd{position:relative;margin-bottom:14px;}
.usbsim-intake-eyebrow{display:inline-flex;align-items:center;gap:7px;font-size:10px;letter-spacing:.28em;color:#22d3ee;text-transform:uppercase;font-weight:700;}
.usbsim-intake-title{margin:8px 0 6px;font-size:22px;font-weight:700;letter-spacing:-.01em;color:#f1f5f9;line-height:1.25;}
.usbsim-intake-priv{margin:0;font-size:11.5px;color:#94a3b8;font-style:italic;line-height:1.45;}
.usbsim-intake-close{position:absolute;top:-4px;right:-4px;background:transparent;border:1px solid rgba(36,58,85,.7);color:#cbd5e1;width:32px;height:32px;border-radius:8px;cursor:pointer;font-size:18px;line-height:1;font-family:inherit;}
.usbsim-intake-close:hover{color:#f1f5f9;border-color:#22d3ee;}
.usbsim-intake-form{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px 16px;margin-top:14px;}
.usbsim-intake-form label{display:flex;flex-direction:column;gap:4px;font-size:11px;letter-spacing:.16em;color:#64748b;text-transform:uppercase;font-weight:700;}
.usbsim-intake-form label span{font-size:10.5px;}
.usbsim-intake-form select{appearance:none;background:rgba(8,14,22,.7) url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'><path d='M1 1l4 4 4-4' stroke='%2364748b' stroke-width='1.5' fill='none' stroke-linecap='round'/></svg>") no-repeat right 12px center;color:#e2e8f0;border:1px solid rgba(36,58,85,.7);border-radius:8px;padding:10px 32px 10px 12px;font-size:12.5px;font-family:inherit;letter-spacing:normal;text-transform:none;font-weight:500;cursor:pointer;}
.usbsim-intake-form select:focus-visible{outline:2px solid #22d3ee;outline-offset:1px;border-color:#22d3ee;}
.usbsim-intake-checks{grid-column:1 / -1;display:flex;flex-wrap:wrap;gap:8px 18px;margin-top:2px;}
.usbsim-intake-check{flex-direction:row !important;align-items:center;gap:8px !important;text-transform:none !important;letter-spacing:normal !important;font-weight:500 !important;color:#cbd5e1 !important;cursor:pointer;}
.usbsim-intake-check span{font-size:12px !important;}
.usbsim-intake-check input[type=checkbox]{appearance:none;width:16px;height:16px;flex:0 0 16px;border:1px solid rgba(36,58,85,.9);border-radius:4px;background:rgba(8,14,22,.7);cursor:pointer;position:relative;}
.usbsim-intake-check input[type=checkbox]:checked{background:#22d3ee;border-color:#22d3ee;}
.usbsim-intake-check input[type=checkbox]:checked::after{content:"";position:absolute;left:5px;top:1px;width:4px;height:9px;border:solid #07131f;border-width:0 2px 2px 0;transform:rotate(45deg);}
.usbsim-intake-check input[type=checkbox]:focus-visible{outline:2px solid #22d3ee;outline-offset:1px;}
.usbsim-intake-formfoot{grid-column:1 / -1;display:flex;gap:10px;margin-top:6px;}
.usbsim-intake-formfoot .usbsim-btn-primary,.usbsim-intake-formfoot .usbsim-btn-ghost{min-height:40px;padding:10px 18px;font-size:11px;}
.usbsim-intake-out{margin-top:20px;padding:18px;background:rgba(8,14,22,.55);border:1px solid rgba(36,58,85,.7);border-radius:10px;}
.usbsim-intake-out[hidden]{display:none;}
.usbsim-intake-out-title{margin:6px 0 12px;font-size:16px;font-weight:700;color:#f1f5f9;letter-spacing:-.005em;}
.usbsim-intake-out-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px 18px;}
.usbsim-intake-wide{grid-column:1 / -1;}
.usbsim-intake-k{display:block;font-size:9.5px;letter-spacing:.22em;color:#64748b;font-weight:700;text-transform:uppercase;margin-bottom:2px;}
.usbsim-intake-v{margin:0;font-size:14px;color:#e2e8f0;font-weight:600;line-height:1.45;}
.usbsim-intake-gaps{margin:4px 0 0;padding-left:20px;color:#cbd5e1;font-size:12.5px;line-height:1.55;}
.usbsim-intake-gaps li{margin:2px 0;}
.usbsim-intake-cta{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:14px;padding-top:14px;border-top:1px solid rgba(36,58,85,.5);}
.usbsim-intake-cta .usbsim-btn-primary{padding:10px 18px;font-size:11px;min-height:40px;}
.usbsim-intake-cta-note{font-size:11px;color:#94a3b8;font-style:italic;}

@media (max-width:780px){.usbsim .usbsim-cta{grid-template-columns:1fr;}.usbsim-cta-actions{min-width:0;}.usbsim-intake-form{grid-template-columns:1fr;}.usbsim-ind-grid{grid-template-columns:1fr;}.usbsim-ind-cell:nth-child(-n+2){border-top:1px solid rgba(26,38,56,.6);padding-top:10px;}.usbsim-ind-cell:first-child{border-top:none;padding-top:0;}.usbsim-intake-out-grid{grid-template-columns:1fr;}}

/* ======================================================================
   PHASE 1 — Guided executive tour overlay
   ====================================================================== */
.usbsim-hero-actions{display:flex;flex-direction:column;gap:8px;}
.usbsim-btn-primary{appearance:none;background:linear-gradient(180deg,#22d3ee 0%,#0ea5b7 100%);color:#04121b;border:1px solid #22d3ee;border-radius:8px;padding:11px 14px;font-size:12px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;cursor:pointer;min-height:42px;box-shadow:0 8px 24px -10px rgba(34,211,238,.7);transition:transform .15s,box-shadow .2s,filter .15s;}
.usbsim-btn-primary:hover{transform:translateY(-1px);filter:brightness(1.05);box-shadow:0 12px 30px -10px rgba(34,211,238,.85);}
.usbsim-btn-primary:focus-visible{outline:2px solid #fff;outline-offset:2px;}

.usbsim-tour{position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;padding:24px;animation:usbsim-fade-in .25s ease-out;}
.usbsim-tour[hidden]{display:none!important;}
.usbsim-tour-backdrop{position:absolute;inset:0;background:rgba(2,8,16,.78);backdrop-filter:blur(2px);}
.usbsim-tour-card{position:relative;z-index:1;max-width:540px;width:100%;background:linear-gradient(180deg,#0f1a2a 0%,#0a131e 100%);border:1px solid #243a55;border-left:4px solid #22d3ee;border-radius:14px;padding:24px 26px 20px;box-shadow:0 30px 80px -20px rgba(0,0,0,.7),0 0 0 1px rgba(34,211,238,.18);color:#e6edf6;font-family:"Inter","Segoe UI",-apple-system,sans-serif;}
.usbsim-tour-hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;}
.usbsim-tour-eyebrow{display:inline-flex;align-items:center;gap:7px;font-size:10px;letter-spacing:.28em;color:#22d3ee;text-transform:uppercase;font-weight:700;}
.usbsim-tour-counter{font-size:11px;letter-spacing:.16em;color:#64748b;text-transform:uppercase;font-weight:600;}
.usbsim-tour-counter b{color:#22d3ee;font-weight:800;}
.usbsim-tour-title{margin:0 0 10px;font-size:22px;font-weight:700;letter-spacing:-.01em;line-height:1.25;color:#f1f5f9;}
.usbsim-tour-body{margin:0 0 14px;font-size:14.5px;line-height:1.55;color:#cbd5e1;}
.usbsim-tour-tech{margin:0 0 18px;border-top:1px solid rgba(36,58,85,.6);padding-top:12px;font-size:12px;color:#94a3b8;}
.usbsim-tour-tech summary{cursor:pointer;font-size:10px;letter-spacing:.22em;color:#64748b;font-weight:700;text-transform:uppercase;list-style:none;}
.usbsim-tour-tech summary::-webkit-details-marker{display:none;}
.usbsim-tour-tech summary::before{content:"▸ ";color:#22d3ee;}
.usbsim-tour-tech[open] summary::before{content:"▾ ";}
.usbsim-tour-tech p{margin:8px 0 0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;line-height:1.5;color:#94a3b8;}
.usbsim-tour-controls{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;}
.usbsim-tour-nav{display:flex;gap:8px;}
.usbsim-tour-controls .usbsim-btn-ghost{min-height:40px;padding:10px 16px;font-size:11px;}
.usbsim-tour-controls .usbsim-btn-primary{padding:10px 18px;font-size:11px;min-height:40px;}
.usbsim-tour-controls .usbsim-btn-ghost:disabled,.usbsim-tour-controls .usbsim-btn-primary:disabled{opacity:.4;cursor:not-allowed;}

/* Spotlight: highlight the targeted region during the tour */
.usbsim-spotlight{position:relative;z-index:10000;outline:2px solid #22d3ee;outline-offset:6px;border-radius:14px;box-shadow:0 0 0 4px rgba(34,211,238,.18),0 0 40px rgba(34,211,238,.35);transition:outline-color .2s,box-shadow .2s;}
@keyframes usbsim-fade-in{from{opacity:0;}to{opacity:1;}}

/* ======================================================================
   PHASE 2 — Executive Summary panel (plain-language)
   ====================================================================== */
.usbsim-exec{margin:0 0 20px;padding:22px 24px;border:1px solid #1a2638;border-left:4px solid #22c55e;border-radius:12px;background:linear-gradient(180deg,rgba(13,22,34,.85) 0%,rgba(8,14,22,.85) 100%);font-family:"Inter","Segoe UI",-apple-system,sans-serif;transition:border-left-color .35s,box-shadow .6s ease-out;scroll-margin-top:16px;}
.usbsim-exec.is-flash{box-shadow:0 0 0 2px rgba(34,211,238,.55),0 0 40px -6px rgba(34,211,238,.45);}
.usbsim-exec-hd{margin-bottom:14px;}
.usbsim-exec-title{margin:6px 0 0;font-size:18px;font-weight:700;letter-spacing:-.01em;color:#f1f5f9;line-height:1.3;}
.usbsim-exec-list{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px 24px;}
.usbsim-exec-list li{display:flex;flex-direction:column;gap:3px;padding:8px 0;border-top:1px solid rgba(26,38,56,.6);}
.usbsim-exec-list li:nth-child(-n+2){border-top:none;padding-top:0;}
.usbsim-exec-k{font-size:9.5px;letter-spacing:.22em;color:#64748b;font-weight:700;text-transform:uppercase;}
.usbsim-exec-v{font-size:13.5px;line-height:1.5;color:#cbd5e1;font-weight:500;}
.usbsim[data-mode="hold"] .usbsim-exec{border-left-color:#f59e0b;}
.usbsim[data-mode="bad"] .usbsim-exec{border-left-color:#ef4444;}
.usbsim[data-mode="warn"] .usbsim-exec{border-left-color:#f59e0b;}
.usbsim[data-mode="allow"] .usbsim-exec{border-left-color:#22c55e;}
@media (max-width:780px){.usbsim-exec-list{grid-template-columns:1fr;gap:8px 0;}.usbsim-exec-list li:nth-child(-n+2){border-top:1px solid rgba(26,38,56,.6);padding-top:8px;}.usbsim-exec-list li:first-child{border-top:none;padding-top:0;}}

/* Operational telemetry stream — ambient activity, NOT audit chain */
.usbsim-stream-wrap{border:1px solid rgba(26,38,56,.7);border-radius:8px;background:rgba(8,14,22,.45);padding:10px 12px 8px;}
.usbsim-stream-hd{display:flex;align-items:center;gap:7px;font-size:9px;letter-spacing:.24em;color:#64748b;font-weight:700;text-transform:uppercase;margin-bottom:7px;}
.usbsim-stream{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:7px;max-height:128px;overflow:hidden;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;line-height:1.55;color:#a3aec0;}
.usbsim-stream li{display:grid;grid-template-columns:64px 1fr;gap:12px;align-items:baseline;opacity:0;transform:translateY(-3px);animation:usbsim-stream-in .4s ease-out forwards;min-width:0;}
.usbsim-stream li time{color:#64748b;font-size:11px;letter-spacing:.04em;flex-shrink:0;}
.usbsim-stream li b{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.usbsim-stream-hd{font-size:10px;}
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
        exec: scn.exec, reg: scn.reg, reason: scn.reason, scenario: key
      };
      auditEvents.unshift(ev);
      if (auditEvents.length > 14) auditEvents.length = 14;
      renderAudit();

      // "Evidence committed" moment — pulse after the audit append lands
      evCard.classList.remove('is-sealed');
      void evCard.offsetWidth;
      evCard.classList.add('is-sealed');

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

  // ---------- Phase 2: Executive Summary (plain-language live state) ----------
  var execPosture  = root.querySelector('#exec-posture');
  var execIntegrity= root.querySelector('#exec-integrity');
  var execTrust    = root.querySelector('#exec-trust');
  var execReplay   = root.querySelector('#exec-replay');
  var execEvidence = root.querySelector('#exec-evidence');
  var execRisk     = root.querySelector('#exec-risk');
  function updateExecSummary(){
    var mode = root.getAttribute('data-mode') || 'live';
    var evCount = auditEvents.length;
    if (execIntegrity) execIntegrity.textContent = 'Runtime is operating within signed parameters (' + integrityPct.toFixed(1) + '%).';
    if (execEvidence)  execEvidence.textContent  = evCount === 0
      ? 'Every decision is sealed in a signed, append-only audit chain.'
      : (evCount + ' decision' + (evCount===1?'':'s') + ' sealed in the audit chain this session.');
    if (mode === 'hold'){
      execPosture && (execPosture.textContent = 'AI execution paused — operator authorization required before this request can proceed.');
      execTrust   && (execTrust.textContent   = 'Governance trust chain remains verified; the gate is intentionally held.');
      execReplay  && (execReplay.textContent  = 'Active — duplicate or stale requests continue to be blocked.');
      execRisk    && (execRisk.textContent    = 'Elevated — pending operator review. Provider is not invoked.');
    } else if (mode === 'bad'){
      execPosture && (execPosture.textContent = 'AI execution was just blocked by governance. No provider call was issued.');
      execTrust   && (execTrust.textContent   = 'Trust chain held the line. The decision is sealed in the audit chain.');
      execReplay  && (execReplay.textContent  = 'Active — replay protection prevented unsafe execution.');
      execRisk    && (execRisk.textContent    = 'Contained — fail-closed enforcement stopped the request before any external call.');
    } else if (mode === 'warn'){
      execPosture && (execPosture.textContent = 'AI execution is currently restricted. Trust posture is degraded.');
      execTrust   && (execTrust.textContent   = 'Trust signals are mixed; governance is holding execution conservatively.');
      execReplay  && (execReplay.textContent  = 'Active — duplicate or stale requests continue to be blocked.');
      execRisk    && (execRisk.textContent    = 'Watching — provider is held until trust posture is re-verified.');
    } else {
      execPosture && (execPosture.textContent = 'USBAY is live and actively controlling AI execution.');
      execTrust   && (execTrust.textContent   = 'Governance trust chain is verified end-to-end.');
      execReplay  && (execReplay.textContent  = 'Active — duplicate or stale requests are blocked before they reach a model.');
      execRisk    && (execRisk.textContent    = 'Low — no unresolved governance gaps.');
    }
  }
  updateExecSummary();
  setInterval(updateExecSummary, 1500);

  // ---------- Phase 3 + 4: Risk Score + Business Impact (preview, live) ----------
  var riskOverall = root.querySelector('#risk-overall');
  var riskTrustBand = root.querySelector('#risk-trust-band');
  var bizPrevented = root.querySelector('#biz-prevented');
  var bizCompliance = root.querySelector('#biz-compliance');
  var bizAudit = root.querySelector('#biz-audit');
  var bizCoverage = root.querySelector('#biz-coverage');
  var bizTrust = root.querySelector('#biz-trust');
  var bizReplay = root.querySelector('#biz-replay');
  var BLOCKING_VERDICTS = {'DENY':1,'BLOCKED':1,'FAIL_CLOSED':1,'DEGRADED':1};
  function updateRiskAndImpact(){
    var mode = root.getAttribute('data-mode') || 'live';
    if (riskTrustBand){
      riskTrustBand.classList.remove('usbsim-band-low','usbsim-band-med','usbsim-band-high','usbsim-band-bad');
      if (mode === 'bad'){ riskTrustBand.textContent='Contained'; riskTrustBand.classList.add('usbsim-band-bad'); }
      else if (mode === 'warn'){ riskTrustBand.textContent='Watching'; riskTrustBand.classList.add('usbsim-band-med'); }
      else if (mode === 'hold'){ riskTrustBand.textContent='Held';     riskTrustBand.classList.add('usbsim-band-med'); }
      else { riskTrustBand.textContent='High'; riskTrustBand.classList.add('usbsim-band-high'); }
    }
    if (riskOverall){
      riskOverall.style.color = '';
      if (mode === 'bad'){ riskOverall.textContent='Contained'; riskOverall.style.color='#ef4444'; }
      else if (mode === 'warn'){ riskOverall.textContent='Cautious'; riskOverall.style.color='#f59e0b'; }
      else if (mode === 'hold'){ riskOverall.textContent='Awaiting review'; riskOverall.style.color='#f59e0b'; }
      else { riskOverall.textContent='Strong'; riskOverall.style.color='#22c55e'; }
    }
    var prevented = 0, replays = 0;
    for (var i=0;i<auditEvents.length;i++){
      var v = (auditEvents[i] && (auditEvents[i].verdict || auditEvents[i].decision)) || '';
      if (BLOCKING_VERDICTS[v]) prevented++;
      var scn = auditEvents[i] && auditEvents[i].scenario;
      if (scn === 'replay') replays++;
    }
    if (bizPrevented) bizPrevented.textContent = String(prevented);
    if (bizReplay)    bizReplay.textContent    = String(replays);
    if (bizTrust)     bizTrust.textContent     = integrityPct.toFixed(1) + '%';
    if (bizCompliance){
      bizCompliance.style.color = '';
      if (mode === 'bad' || mode === 'warn'){ bizCompliance.textContent='Contained'; bizCompliance.style.color='#22c55e'; }
      else if (mode === 'hold'){ bizCompliance.textContent='Held'; bizCompliance.style.color='#f59e0b'; }
      else { bizCompliance.textContent='Active'; bizCompliance.style.color='#22c55e'; }
    }
    if (bizAudit) bizAudit.textContent = (auditEvents.length > 0) ? '+100%' : 'Ready';
  }
  updateRiskAndImpact();
  setInterval(updateRiskAndImpact, 1500);

  // ---------- Phase 1: Guided executive tour ----------
  var tour = root.querySelector('#usbsim-tour');
  var tourCard = root.querySelector('#usbsim-tour-card');
  var tourBackdrop = root.querySelector('#usbsim-tour-backdrop');
  var tourTitle = root.querySelector('#usbsim-tour-title');
  var tourBody  = root.querySelector('#usbsim-tour-body');
  var tourTech  = root.querySelector('#usbsim-tour-tech');
  var tourTechWrap = root.querySelector('#usbsim-tour-tech-wrap');
  var tourN     = root.querySelector('#usbsim-tour-n');
  var tourTotal = root.querySelector('#usbsim-tour-total');
  var tourNext  = root.querySelector('#usbsim-tour-next');
  var tourBack  = root.querySelector('#usbsim-tour-back');
  var tourSkip  = root.querySelector('#usbsim-tour-skip');
  var tourStart = root.querySelector('#usbsim-tour-start');
  var TOUR_STEPS = [
    {target:'.usbsim-hero', title:"What's happening?",
     body:'Every AI execution request flows through USBAY before reaching the model. Nothing executes without governance approval.',
     tech:'Requests are dispatched through the gateway PEP. The model adapter is never invoked until the policy decision lands.'},
    {target:'.usbsim-pipe-wrap', title:'How governance evaluates',
     body:'USBAY checks policy signatures, replay protection, trust posture, and evidence integrity in a single pass — then issues a verdict.',
     tech:'Signed policy → fail-closed gateway → nonce/replay check → decision → provider adapter → evidence layer.'},
    {target:'#usbsim-why', title:'What USBAY controls',
     body:'The verdict is enforced: ALLOW, DENY, HUMAN_REVIEW, or FAIL_CLOSED. Providers never run on a blocked request.',
     tech:'Decision authority is the gateway, not the application. On DENY/FAIL_CLOSED/HUMAN_REVIEW the adapter is not invoked.'},
    {target:'.usbsim-grid', title:'What gets recorded',
     body:'Every decision commits a signed audit event with the request ID, nonce, policy hash, and audit hash to an append-only chain.',
     tech:'audit.hash_chain.append() writes a tamper-evident sha256-chained record per decision; preserved across runs.'},
    {target:'#usbsim-exec-summary', title:'Why this matters',
     body:'Legal accountability, regulator readiness, and verifiable AI risk reduction. Click any scenario above to see USBAY in action.',
     tech:'Each verdict is reproducible from the audit chain; replay protection + signed policy = defensible posture.'}
  ];
  if (tourTotal) tourTotal.textContent = String(TOUR_STEPS.length);
  var tourIdx = 0;
  var tourSpotlight = null;
  var tourOpener = null;
  function clearSpotlight(){
    if (tourSpotlight){ tourSpotlight.classList.remove('usbsim-spotlight'); tourSpotlight = null; }
  }
  function showTourStep(i){
    var step = TOUR_STEPS[i]; if (!step) return;
    clearSpotlight();
    var el = root.querySelector(step.target);
    if (el){
      el.classList.add('usbsim-spotlight');
      tourSpotlight = el;
      try { el.scrollIntoView({behavior:'smooth', block:'center'}); } catch(_) { el.scrollIntoView(); }
    }
    if (tourTitle) tourTitle.textContent = step.title;
    if (tourBody)  tourBody.textContent  = step.body;
    if (tourTech)  tourTech.textContent  = step.tech;
    if (tourTechWrap) tourTechWrap.open = false;
    if (tourN) tourN.textContent = String(i+1);
    if (tourBack) tourBack.disabled = (i === 0);
    if (tourNext) tourNext.textContent = (i === TOUR_STEPS.length-1) ? 'Finish' : 'Next';
  }
  function getTourFocusables(){
    if (!tourCard) return [];
    return Array.prototype.slice.call(tourCard.querySelectorAll(
      'button:not([disabled]), [href], summary, [tabindex]:not([tabindex="-1"])'
    ));
  }
  function openTour(){
    if (!tour) return;
    if (tour.hidden === false) return;
    tourOpener = document.activeElement;
    tourIdx = 0;
    tour.hidden = false;
    showTourStep(tourIdx);
    document.addEventListener('keydown', tourKey, true);
    setTimeout(function(){
      var f = getTourFocusables();
      if (f.length) f[f.length-1].focus(); // focus "Next/Finish"
      else if (tourCard) tourCard.focus();
    }, 0);
  }
  function closeTour(){
    if (!tour || tour.hidden) return;
    tour.hidden = true;
    clearSpotlight();
    document.removeEventListener('keydown', tourKey, true);
    if (tourOpener && typeof tourOpener.focus === 'function') {
      try { tourOpener.focus(); } catch(_) {}
    }
    tourOpener = null;
  }
  function tourKey(e){
    if (tour.hidden) return;
    if (e.key === 'Escape') { e.preventDefault(); closeTour(); return; }
    if (e.key === 'ArrowRight') { e.preventDefault(); stepFwd(); return; }
    if (e.key === 'ArrowLeft')  { e.preventDefault(); stepBack(); return; }
    if (e.key === 'Tab') {
      var f = getTourFocusables();
      if (!f.length) { e.preventDefault(); return; }
      var first = f[0], last = f[f.length-1];
      var active = document.activeElement;
      if (e.shiftKey && active === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && active === last) { e.preventDefault(); first.focus(); }
      else if (!tourCard.contains(active)) { e.preventDefault(); first.focus(); }
    }
  }
  function stepFwd(){
    if (tourIdx >= TOUR_STEPS.length-1) { closeTour(); return; }
    tourIdx += 1; showTourStep(tourIdx);
  }
  function stepBack(){
    if (tourIdx <= 0) return;
    tourIdx -= 1; showTourStep(tourIdx);
  }
  tourStart && tourStart.addEventListener('click', openTour);
  tourNext  && tourNext.addEventListener('click', stepFwd);
  tourBack  && tourBack.addEventListener('click', stepBack);
  tourSkip  && tourSkip.addEventListener('click', closeTour);
  tourBackdrop && tourBackdrop.addEventListener('click', closeTour);

  // ---------- Phase 6: Industry preset switcher (client-side, no network) ----------
  var INDUSTRY_PRESETS = {
    fin: {
      label: 'Financial Services',
      risks: 'Unauthorized credit decisions, model output used without policy approval, replayed transaction requests blocked at the gateway.',
      impact:'Defensible AI-driven financial decisions and a complete audit trail for regulators and internal risk committees.',
      reg:   'Demonstrable governance over consumer-impacting decisions; explainability and replay protection on each execution.',
      ctrls: 'Signed policy enforcement, mandatory human review on threshold decisions, signed audit chain available to second-line risk.',
      pilot: 'Pilot one high-risk AI workflow (e.g. credit triage) under USBAY for 6 weeks; produce regulator-ready evidence pack.',
      maturity:'Medium', maturityBand:'is-med',
      gaps:['No signed policy on AI-driven credit decisions.','No human-in-the-loop on threshold decisions.','No verifiable audit chain for second-line risk.'],
      pilotType:'Governed AI for credit triage under USBAY runtime control.',
      duration:'6–8 weeks',
      value:'Defensible, regulator-ready AI decisions in a single high-impact workflow, with signed evidence available to second-line risk and audit on request.'
    },
    health: {
      label: 'Healthcare',
      risks: 'AI triage without human review, missing clinical escalation, patient-impact decisions executed without verified policy.',
      impact:'Patient safety protected; every AI-assisted clinical decision is traceable, reviewable, and overridable by a clinician.',
      reg:   'Clinical governance, escalation timestamps, and human-in-the-loop evidence available to medical regulators and ethics boards.',
      ctrls: 'Mandatory clinician approval on patient-impact outputs, signed evidence per decision, fail-closed on degraded trust signals.',
      pilot: 'Pilot one triage or decision-support workflow under USBAY for 6 weeks; produce a clinician-defensible governance pack.',
      maturity:'Low', maturityBand:'is-low',
      gaps:['AI triage outputs reach clinicians without verified policy.','No mandatory clinician approval on patient-impact decisions.','No signed clinical evidence trail per decision.'],
      pilotType:'Governed clinical decision-support workflow under USBAY runtime control.',
      duration:'6–8 weeks',
      value:'Every AI-assisted clinical decision becomes traceable, reviewable, and overridable by a clinician, with a defensible governance pack for medical regulators and ethics boards.'
    },
    log: {
      label: 'Logistics',
      risks: 'Dispatch decisions executed against expired policy, unverified routing changes, replayed scheduling requests.',
      impact:'Operational continuity and explainable routing decisions; reduced exposure to AI-driven scheduling errors.',
      reg:   'Auditability of automated logistics decisions for customer SLAs, contractual disputes, and operational reviews.',
      ctrls: 'Hard-block on expired policy, signed evidence per dispatch, replay protection on rebooking and rerouting calls.',
      pilot: 'Pilot one automated dispatch or routing flow under USBAY for 6 weeks; produce an operations-ready evidence package.',
      maturity:'Low', maturityBand:'is-low',
      gaps:['Dispatch decisions executed against expired policy.','No replay protection on rebooking and rerouting calls.','No signed evidence per dispatch.'],
      pilotType:'Governed dispatch or routing flow under USBAY runtime control.',
      duration:'4–6 weeks',
      value:'Automated logistics decisions become auditable for customer SLAs and contractual disputes, with operational continuity protected against expired or replayed instructions.'
    },
    rail: {
      label: 'Rail Operations',
      risks: 'Operational dispatch decisions without verified policy, missing safety escalations, runtime continuity failures.',
      impact:'Safety-critical operational decisions execute only against signed, current policy; fail-closed on any ambiguity.',
      reg:   'Auditable governance over safety-critical automation; clear evidence of human oversight on escalation paths.',
      ctrls: 'Fail-closed enforcement, mandatory human escalation on safety-class decisions, signed runtime attestation per execution.',
      pilot: 'Pilot one operational decision flow under USBAY for 6 weeks; deliver a safety-case-aligned governance evidence pack.',
      maturity:'Low', maturityBand:'is-low',
      gaps:['Operational decisions executed without verified, current policy.','Missing human escalation on safety-class decisions.','No signed runtime attestation per execution.'],
      pilotType:'Governed operational decision flow under USBAY runtime control.',
      duration:'6–8 weeks',
      value:'Safety-critical operational automation runs only against signed, current policy, with defensible human-oversight evidence aligned to your safety case.'
    },
    ind: {
      label: 'Industrial Automation',
      risks: 'Unsigned control actions on plant equipment, policy drift between control room and runtime, unverified setpoint changes.',
      impact:'Plant safety and process continuity protected; verifiable governance over every AI-issued control action.',
      reg:   'Auditable, signed evidence for process safety reviews and insurer/regulator assessments.',
      ctrls: 'Signed policy per asset class, hard-block on drift detection, human approval on cross-threshold setpoints.',
      pilot: 'Pilot one AI-assisted process control surface under USBAY for 6 weeks; produce a process-safety-ready evidence pack.',
      maturity:'Low', maturityBand:'is-low',
      gaps:['Unsigned control actions reaching plant equipment.','Policy drift between control room and runtime.','No verifiable evidence for process-safety reviews.'],
      pilotType:'Governed AI-assisted process control surface under USBAY runtime control.',
      duration:'6–8 weeks',
      value:'Plant safety and process continuity protected by verifiable governance over every AI-issued control action, with insurer- and regulator-ready evidence on request.'
    },
    support: {
      label: 'Customer Support AI',
      risks: 'AI agent making customer commitments without authority, unauthorized refunds, missing escalation to a human agent.',
      impact:'Customer trust protected; every AI-issued commitment is governed, reviewable, and reversible.',
      reg:   'Demonstrable governance over AI-issued customer outcomes; explainable decisions and escalation evidence on request.',
      ctrls: 'Threshold-based human review, signed audit per customer-impacting action, fail-closed on degraded trust posture.',
      pilot: 'Pilot one customer-facing AI workflow under USBAY for 6 weeks; produce a customer-trust governance evidence pack.',
      maturity:'Low', maturityBand:'is-low',
      gaps:['AI agent makes customer commitments without verified authority.','No threshold-based human review on customer-impacting actions.','Escalation evidence missing on disputed customer outcomes.'],
      pilotType:'Governed customer-facing AI workflow under USBAY runtime control.',
      duration:'4–6 weeks',
      value:'Customer commitments issued by AI become governed, reviewable, and reversible, with explainable decisions and escalation evidence available on request.'
    }
  };
  var NEXT_STEP_BY_MATURITY = {
    Low:    { action:'Governance Assessment',          priority:'High',   band:'is-high', impact:'Establish the baseline: identify which AI decisions in your environment lack signed policy, human oversight, or a verifiable audit chain — and quantify the operational and regulatory exposure that creates.' },
    Medium: { action:'Pilot Intake',                   priority:'High',   band:'is-high', impact:'Move from governance plans to a working pilot: place one high-impact AI workflow under USBAY runtime control and produce a regulator-ready evidence pack within 6–8 weeks.' },
    High:   { action:'Runtime Governance Deployment', priority:'Medium', band:'is-med',  impact:'Extend USBAY runtime governance across additional AI workflows; standardise the evidence chain and human-oversight model your boardroom and regulators already accept.' }
  };
  var indRisks  = root.querySelector('#ind-risks');
  var indImpact = root.querySelector('#ind-impact');
  var indReg    = root.querySelector('#ind-reg');
  var indCtrls  = root.querySelector('#ind-ctrls');
  var indPilot  = root.querySelector('#ind-pilot');
  var indChips  = root.querySelectorAll('.usbsim-ind-chip');
  var currentIndustry = 'fin';
  var pilotIndustryEl = root.querySelector('#pilot-industry');
  var pilotMaturityEl = root.querySelector('#pilot-maturity');
  var pilotGapsEl     = root.querySelector('#pilot-gaps');
  var pilotScopeEl    = root.querySelector('#pilot-scope');
  var pilotDurationEl = root.querySelector('#pilot-duration');
  var pilotValueEl    = root.querySelector('#pilot-value');
  var pilotRiskEl     = root.querySelector('#pilot-risk');
  var nextActionEl    = root.querySelector('#nextstep-action');
  var nextPriorityEl  = root.querySelector('#nextstep-priority');
  var nextImpactEl    = root.querySelector('#nextstep-impact');
  function setBadge(el, band){
    if (!el) return;
    el.classList.remove('is-low','is-med','is-high');
    el.classList.add(band);
  }
  function applyPilotRec(p){
    if (pilotIndustryEl) pilotIndustryEl.textContent = p.label;
    if (pilotMaturityEl){ pilotMaturityEl.textContent = p.maturity; setBadge(pilotMaturityEl, p.maturityBand); }
    if (pilotGapsEl){
      pilotGapsEl.innerHTML = '';
      for (var i=0;i<p.gaps.length;i++){
        var li = document.createElement('li');
        li.textContent = p.gaps[i];
        pilotGapsEl.appendChild(li);
      }
    }
    if (pilotScopeEl)    pilotScopeEl.textContent    = p.pilotType;
    if (pilotDurationEl) pilotDurationEl.textContent = p.duration;
    if (pilotValueEl)    pilotValueEl.textContent    = p.value;
    if (pilotRiskEl)     pilotRiskEl.textContent     = p.risks;
    var ns = NEXT_STEP_BY_MATURITY[p.maturity] || NEXT_STEP_BY_MATURITY.Medium;
    if (nextActionEl)   nextActionEl.textContent   = ns.action;
    if (nextPriorityEl){ nextPriorityEl.textContent = ns.priority; setBadge(nextPriorityEl, ns.band); }
    if (nextImpactEl)   nextImpactEl.textContent   = ns.impact;
  }
  function applyIndustry(key){
    var p = INDUSTRY_PRESETS[key]; if (!p) return;
    currentIndustry = key;
    if (indRisks)  indRisks.textContent  = p.risks;
    if (indImpact) indImpact.textContent = p.impact;
    if (indReg)    indReg.textContent    = p.reg;
    if (indCtrls)  indCtrls.textContent  = p.ctrls;
    if (indPilot)  indPilot.textContent  = p.pilot;
    applyPilotRec(p);
    Array.prototype.forEach.call(indChips, function(c){
      var on = c.getAttribute('data-ind') === key;
      c.classList.toggle('is-active', on);
      c.setAttribute('aria-selected', on ? 'true' : 'false');
    });
  }
  applyPilotRec(INDUSTRY_PRESETS.fin);

  // ---------- Phase 16/17/19: Sector Demonstrations (client-side, no network) ----------
  var SECTOR_DEMOS = {
    rail: {
      request:'Automated dispatch system requests a route-change action on an active passenger service due to a downstream signal degradation reported by the line controller.',
      policy: 'USBAY verifies the dispatch policy is signed and current, that this controller has route-change authority for this service class, that the action is within the operating window, and that the request is not a replay.',
      verdict:'HUMAN_REVIEW', verdictClass:'is-review',
      review: 'Duty controller approves the change with a captured reason code referencing the downstream signal degradation and the timetable tolerance.',
      evidence:'Signed audit event sealed: timestamp, controller of record, reason code, policy hash, nonce, decision = ALLOW after review.',
      outcome:'Route change executes against signed, current policy. The full decision is reconstructable for safety case, regulator review and internal incident analysis.',
      wRisk:'Automated dispatch change executed without verifiable authority or human sign-off.',
      wFailure:'A degraded model output or a replayed instruction can trigger an unsafe route change on an active passenger service.',
      wImpact:'Safety incident exposure, regulator action, loss of operating licence — with no defensible evidence chain to reconstruct what happened.',
      yControl:'Fail-closed gate holds the dispatch change until signed policy and a named human approver are both present.',
      yPath:'request → policy verify → HUMAN_REVIEW → controller approve → ALLOW → adapter executes.',
      yEvidence:'Hash-chained, signed event with controller of record, reason code, nonce and policy hash, sealed at the moment of execution.',
      yOutcome:'Safe, auditable operational change — defensible to the safety regulator and to internal incident review.'
    },
    fin: {
      request:'AI credit assessment service requests an automated decline on a borderline application that sits above the manual-review threshold.',
      policy: 'USBAY verifies the credit policy version is signed and current, that this model is approved for this decision class, that the borderline-decline rule requires human review, and that the request is not a replay.',
      verdict:'HUMAN_REVIEW', verdictClass:'is-review',
      review: 'Named credit officer approves the decline with a reason code referencing the borderline-decision policy clause.',
      evidence:'Signed audit event sealed: timestamp, officer of record, policy hash, model version, nonce, decision = ALLOW (decline).',
      outcome:'Decision is defensible to second-line risk, internal audit and the financial regulator on request.',
      wRisk:'Borderline credit declines issued by AI with no signed policy, no human sign-off and no reproducible evidence.',
      wFailure:'Adverse customer outcomes attributed to AI without explainability or audit trail.',
      wImpact:'Regulatory exposure, complaints redress cost, reputational damage and no defensible position on individual decisions.',
      yControl:'Borderline-decline threshold rule routes the decision to HUMAN_REVIEW before any provider call.',
      yPath:'request → policy verify → HUMAN_REVIEW → credit officer approve → ALLOW → adapter executes.',
      yEvidence:'Signed event with officer of record, policy hash, model version and nonce.',
      yOutcome:'Auditable, regulator-defensible credit decision with a clear chain of authority.'
    },
    health: {
      request:'AI triage decision-support requests escalation of a borderline-acuity patient encounter to the acute pathway.',
      policy: 'USBAY verifies the clinical policy signature, that this model is approved for triage support, that the borderline-acuity rule requires clinician approval, and that the request is not a replay.',
      verdict:'HUMAN_REVIEW', verdictClass:'is-review',
      review: 'Attending clinician approves the escalation with a reason captured against their clinician identity.',
      evidence:'Signed clinical audit event sealed: timestamp, clinician of record, policy hash, model version, nonce, decision = ALLOW (escalate).',
      outcome:'Clinically defensible decision — reviewable by medical regulator, ethics board and incident review.',
      wRisk:'AI-driven escalation or non-escalation reaches the clinical pathway without verified policy or clinician sign-off.',
      wFailure:'Patient-impact decision executed without a clinician of record and without a reproducible audit trail.',
      wImpact:'Patient-safety incident exposure, regulator action, malpractice liability with no defensible evidence.',
      yControl:'Patient-impact decisions are held in HUMAN_REVIEW until an authorised clinician acts.',
      yPath:'request → policy verify → HUMAN_REVIEW → clinician approve → ALLOW → adapter executes.',
      yEvidence:'Hash-chained, signed clinical event with clinician of record, policy hash and model version.',
      yOutcome:'Traceable, reviewable, overridable clinical decision aligned to medical governance.'
    },
    log: {
      request:'Automated routing engine requests a rebooking action on an in-flight customer shipment after a carrier delay.',
      policy: 'USBAY verifies the routing policy version is current, that the rebooking action is within SLA-allowed deviations, that this controller has rebooking authority, and that the request is not a replay.',
      verdict:'ALLOW', verdictClass:'is-allow',
      review: 'No human review required for this scenario — rebooking sits within signed SLA-deviation parameters; decision proceeds under signed policy.',
      evidence:'Signed audit event sealed: timestamp, controller, policy hash, SLA-deviation clause referenced, nonce, decision = ALLOW.',
      outcome:'Customer SLA protected with reconstructable evidence available to dispute resolution and operational review.',
      wRisk:'Automated rebooking decisions execute without verified policy, replay protection or signed evidence.',
      wFailure:'Stale or replayed routing instructions trigger unintended re-routes or duplicate dispatches.',
      wImpact:'Customer SLA breaches, contractual disputes and operational continuity gaps with no defensible reconstruction.',
      yControl:'Rebooking decisions only execute against signed, current SLA policy with replay protection at the gateway.',
      yPath:'request → policy verify → ALLOW → adapter executes.',
      yEvidence:'Signed per-dispatch event with policy hash and nonce.',
      yOutcome:'Operationally defensible logistics decision with an auditable customer-impact trail.'
    },
    ind: {
      request:'AI-assisted plant control surface requests a setpoint change that crosses the cross-threshold safety boundary on a process unit.',
      policy: 'USBAY verifies the asset-class control policy is signed and current, that this operator role has cross-threshold authority, that drift has not been detected on this asset, and that the request is not a replay.',
      verdict:'HUMAN_REVIEW', verdictClass:'is-review',
      review: 'Plant supervisor approves the setpoint change against their identity, with reason captured.',
      evidence:'Signed control audit event sealed: timestamp, supervisor of record, policy hash, asset class, nonce, decision = ALLOW.',
      outcome:'Process-safety-defensible control change — reviewable by insurer, regulator and process-safety review.',
      wRisk:'AI-issued control actions reach plant equipment without signed policy or human approval on cross-threshold changes.',
      wFailure:'Unsigned or drifted control action causes a process upset or safety event.',
      wImpact:'Plant safety event, insurer claim, regulator action with no defensible evidence.',
      yControl:'Cross-threshold setpoint changes route to HUMAN_REVIEW; hard-block on drift detection.',
      yPath:'request → policy verify → HUMAN_REVIEW → supervisor approve → ALLOW → adapter executes.',
      yEvidence:'Signed control event with supervisor of record, policy hash and asset class.',
      yOutcome:'Process-safety-aligned, auditable control change.'
    },
    support: {
      request:'Customer-facing AI agent requests issuing a goodwill refund above the standard auto-refund threshold.',
      policy: 'USBAY verifies the refund policy is signed and current, that the agent role allows above-threshold refunds with review, and that the request is not a replay.',
      verdict:'HUMAN_REVIEW', verdictClass:'is-review',
      review: 'Support team lead approves the refund against their identity with a brief reason code.',
      evidence:'Signed audit event sealed: timestamp, team lead of record, policy hash, refund amount, nonce, decision = ALLOW.',
      outcome:'Customer commitment is governed, reviewable and reversible — explainable on request.',
      wRisk:'AI agent issues customer commitments without verified authority, audit trail or escalation evidence.',
      wFailure:'Unauthorised refunds, missed escalations or unenforceable commitments reach customers.',
      wImpact:'Financial leakage, customer-trust damage and no defensible position on disputed outcomes.',
      yControl:'Above-threshold customer commitments route to HUMAN_REVIEW with a named approver.',
      yPath:'request → policy verify → HUMAN_REVIEW → team lead approve → ALLOW → adapter executes.',
      yEvidence:'Signed event with team lead of record, policy hash, amount and nonce.',
      yOutcome:'Governed, reviewable customer commitment with explainable evidence on request.'
    }
  };
  var sectorChipsEl = root.querySelectorAll('.usbsim-sector-chip');
  var sEls = {
    request: root.querySelector('#sector-request'),
    policy:  root.querySelector('#sector-policy'),
    verdict: root.querySelector('#sector-verdict'),
    review:  root.querySelector('#sector-review'),
    evidence:root.querySelector('#sector-evidence'),
    outcome: root.querySelector('#sector-outcome'),
    wRisk:    root.querySelector('#sector-w-risk'),
    wFailure: root.querySelector('#sector-w-failure'),
    wImpact:  root.querySelector('#sector-w-impact'),
    yControl: root.querySelector('#sector-y-control'),
    yPath:    root.querySelector('#sector-y-path'),
    yEvidence:root.querySelector('#sector-y-evidence'),
    yOutcome: root.querySelector('#sector-y-outcome')
  };
  function applySector(key){
    var d = SECTOR_DEMOS[key]; if (!d) return;
    if (sEls.request)  sEls.request.textContent  = d.request;
    if (sEls.policy)   sEls.policy.textContent   = d.policy;
    if (sEls.verdict){
      sEls.verdict.textContent = d.verdict;
      sEls.verdict.classList.remove('is-allow','is-deny','is-review');
      sEls.verdict.classList.add(d.verdictClass);
    }
    if (sEls.review)   sEls.review.textContent   = d.review;
    if (sEls.evidence) sEls.evidence.textContent = d.evidence;
    if (sEls.outcome)  sEls.outcome.textContent  = d.outcome;
    if (sEls.wRisk)    sEls.wRisk.textContent    = d.wRisk;
    if (sEls.wFailure) sEls.wFailure.textContent = d.wFailure;
    if (sEls.wImpact)  sEls.wImpact.textContent  = d.wImpact;
    if (sEls.yControl) sEls.yControl.textContent = d.yControl;
    if (sEls.yPath)    sEls.yPath.textContent    = d.yPath;
    if (sEls.yEvidence)sEls.yEvidence.textContent= d.yEvidence;
    if (sEls.yOutcome) sEls.yOutcome.textContent = d.yOutcome;
    Array.prototype.forEach.call(sectorChipsEl, function(c){
      var on = c.getAttribute('data-sec') === key;
      c.classList.toggle('is-active', on);
      c.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
  }
  Array.prototype.forEach.call(sectorChipsEl, function(c){
    c.addEventListener('click', function(){ applySector(c.getAttribute('data-sec')); });
  });
  applySector('rail');

  // ---------- Phase 18: Executive Walkthrough modal ----------
  var WALK_STEPS = [
    { audience:'CEO', target:'#usbsim-exec-summary',        body:'USBAY decides whether an AI request is allowed to execute, before any model is called. That control sits with your governance — not with the provider, not with the prompt, not with the model.' },
    { audience:'CIO', target:'#usbsim-risk-score',          body:'Maturity and risk posture are visible at a glance. Audit readiness, replay protection and runtime trust continuity are continuously verified across the request lifecycle.' },
    { audience:'CISO', target:'#usbsim-regulator-readiness', body:'Every decision is sealed in a signed, append-only chain. Replay, stale-request and expired-policy executions are blocked at the gateway — not at the application.' },
    { audience:'Compliance Director', target:'#usbsim-prevents', body:'The risks USBAY removes from your AI execution surface are explicit and demonstrable. Each control is enforced at the gateway and produces signed evidence.' },
    { audience:'Regulator', target:'#usbsim-sector-demo',   body:'On request, USBAY produces a per-decision evidence pack: policy hash, nonce, reviewer of record and chronological seal — illustrated across the sector demonstration shown here.' },
    { audience:'Decision moment', target:'#usbsim-pilot-rec', body:'The recommended pilot for your environment is shown below. A 6–8 week governed pilot places one high-impact AI workflow under USBAY runtime control and produces a regulator-ready evidence pack.' }
  ];
  var walk = root.querySelector('#usbsim-walk');
  var walkOpenBtn = root.querySelector('#usbsim-walk-open');
  var walkCloseBtn = root.querySelector('#usbsim-walk-close');
  var walkBackdropEl = root.querySelector('#usbsim-walk-backdrop');
  var walkPrev = root.querySelector('#usbsim-walk-prev');
  var walkNext = root.querySelector('#usbsim-walk-next');
  var walkAudience = root.querySelector('#usbsim-walk-audience');
  var walkStepEl = root.querySelector('#usbsim-walk-step');
  var walkTotalEl = root.querySelector('#usbsim-walk-total');
  var walkBody = root.querySelector('#usbsim-walk-body');
  var walkIdx = 0;
  var walkLastFocus = null;
  function flashTarget(sel){
    var n = root.querySelector(sel); if (!n) return;
    try { n.scrollIntoView({behavior:'smooth', block:'start'}); } catch(_) { n.scrollIntoView(); }
    n.classList.add('is-flash');
    setTimeout(function(){ n.classList.remove('is-flash'); }, 1600);
  }
  function renderWalk(){
    var s = WALK_STEPS[walkIdx]; if (!s) return;
    if (walkAudience) walkAudience.textContent = s.audience;
    if (walkStepEl)   walkStepEl.textContent   = String(walkIdx + 1);
    if (walkTotalEl)  walkTotalEl.textContent  = String(WALK_STEPS.length);
    if (walkBody)     walkBody.textContent     = s.body;
    if (walkPrev)     walkPrev.disabled        = walkIdx === 0;
    if (walkNext)     walkNext.textContent     = walkIdx === WALK_STEPS.length - 1 ? 'Close walkthrough' : 'Next';
    flashTarget(s.target);
  }
  function openWalk(){
    if (!walk) return;
    walkLastFocus = document.activeElement;
    walkIdx = 0; walk.hidden = false; walk.setAttribute('aria-hidden','false'); renderWalk();
    setTimeout(function(){ if (walkNext) try { walkNext.focus(); } catch(_){} }, 0);
  }
  function closeWalk(){
    if (!walk) return;
    walk.hidden = true; walk.setAttribute('aria-hidden','true');
    if (walkLastFocus && typeof walkLastFocus.focus === 'function'){
      try { walkLastFocus.focus(); } catch(_){}
    }
  }
  walkOpenBtn   && walkOpenBtn.addEventListener('click', openWalk);
  walkCloseBtn  && walkCloseBtn.addEventListener('click', closeWalk);
  walkBackdropEl&& walkBackdropEl.addEventListener('click', closeWalk);
  walkPrev      && walkPrev.addEventListener('click', function(){ if (walkIdx > 0){ walkIdx--; renderWalk(); } });
  walkNext      && walkNext.addEventListener('click', function(){ if (walkIdx >= WALK_STEPS.length - 1){ closeWalk(); return; } walkIdx++; renderWalk(); });
  document.addEventListener('keydown', function(e){
    if (walk && !walk.hidden && e.key === 'Escape') closeWalk();
  });

  // ---------- Phase 21: Executive Governance Report Preview (client-side, no network) ----------
  var rpt = root.querySelector('#usbsim-rpt');
  var rptOpenBtn = root.querySelector('#usbsim-rpt-open');
  var rptClose1 = root.querySelector('#usbsim-rpt-close');
  var rptClose2 = root.querySelector('#usbsim-rpt-close2');
  var rptBackdrop = root.querySelector('#usbsim-rpt-backdrop');
  var rptLastFocus = null;
  function rptTxt(sel, fallback){
    var n = root.querySelector(sel);
    return (n && (n.textContent || '').trim()) || (fallback || '—');
  }
  function buildReport(){
    var setText = function(sel, val){ var n = root.querySelector(sel); if (n) n.textContent = val; };
    setText('#rpt-industry', rptTxt('#pilot-industry', 'Not selected'));
    var matBadge = root.querySelector('#rpt-maturity');
    var srcMat = root.querySelector('#pilot-maturity');
    if (matBadge && srcMat){
      matBadge.textContent = (srcMat.textContent || '').trim() || '—';
      matBadge.className = 'usbsim-rpt-badge';
      var m = /is-(low|med|high)/.exec(srcMat.className || '');
      if (m) matBadge.classList.add(m[0]);
    }
    var gapsOut = root.querySelector('#rpt-gaps');
    var gapsSrc = root.querySelectorAll('#pilot-gaps li');
    if (gapsOut){
      gapsOut.innerHTML = '';
      if (gapsSrc.length){
        Array.prototype.forEach.call(gapsSrc, function(li){
          var x = document.createElement('li');
          x.textContent = (li.textContent || '').trim();
          gapsOut.appendChild(x);
        });
      } else {
        var li = document.createElement('li');
        li.textContent = 'No governance gaps recorded for this session.';
        gapsOut.appendChild(li);
      }
    }
    setText('#rpt-risk-overall', rptTxt('#risk-overall', '—'));
    var dimsOut = root.querySelector('#rpt-risk-dims');
    if (dimsOut){
      dimsOut.innerHTML = '';
      Array.prototype.forEach.call(root.querySelectorAll('#usbsim-risk-list > li'), function(li){
        var k = li.querySelector('.usbsim-risk-k');
        var b = li.querySelector('.usbsim-risk-band');
        if (!k || !b) return;
        var row = document.createElement('li');
        var kk = document.createElement('span'); kk.className = 'usbsim-rpt-kvk'; kk.textContent = (k.textContent || '').trim();
        var vv = document.createElement('span'); vv.className = 'usbsim-rpt-kvv'; vv.textContent = (b.textContent || '').trim();
        row.appendChild(kk); row.appendChild(vv);
        dimsOut.appendChild(row);
      });
    }
    var bizOut = root.querySelector('#rpt-biz');
    if (bizOut){
      bizOut.innerHTML = '';
      Array.prototype.forEach.call(root.querySelectorAll('#usbsim-biz-list > li'), function(li){
        var n = li.querySelector('.usbsim-biz-n');
        var l = li.querySelector('.usbsim-biz-l');
        if (!n || !l) return;
        var row = document.createElement('li');
        var kk = document.createElement('span'); kk.className = 'usbsim-rpt-kvk'; kk.textContent = (l.textContent || '').trim();
        var vv = document.createElement('span'); vv.className = 'usbsim-rpt-kvv'; vv.textContent = (n.textContent || '').trim();
        row.appendChild(kk); row.appendChild(vv);
        bizOut.appendChild(row);
      });
    }
    var regPills = root.querySelectorAll('.usbsim-reg-pill');
    var regOut = root.querySelector('#rpt-reg');
    if (regOut){
      var total = regPills.length;
      regOut.textContent = total > 0
        ? total + ' of ' + total + ' governance controls represented. Audit-grade evidence is available on request and human review is enforced where required by policy.'
        : 'Audit-grade evidence framework is in place.';
    }
    setText('#rpt-pilot-scope',    rptTxt('#pilot-scope'));
    setText('#rpt-pilot-duration', rptTxt('#pilot-duration'));
    setText('#rpt-pilot-value',    rptTxt('#pilot-value'));
    setText('#rpt-next-action',    rptTxt('#nextstep-action'));
    setText('#rpt-next-priority',  rptTxt('#nextstep-priority'));
    setText('#rpt-next-impact',    rptTxt('#nextstep-impact'));
  }
  function openRpt(){
    if (!rpt) return;
    rptLastFocus = document.activeElement;
    buildReport();
    rpt.hidden = false; rpt.setAttribute('aria-hidden','false');
    setTimeout(function(){ if (rptClose2) try { rptClose2.focus(); } catch(_){} }, 0);
  }
  function closeRpt(){
    if (!rpt) return;
    rpt.hidden = true; rpt.setAttribute('aria-hidden','true');
    if (rptLastFocus && typeof rptLastFocus.focus === 'function'){
      try { rptLastFocus.focus(); } catch(_){}
    }
  }
  rptOpenBtn  && rptOpenBtn.addEventListener('click', openRpt);
  rptClose1   && rptClose1.addEventListener('click', closeRpt);
  rptClose2   && rptClose2.addEventListener('click', closeRpt);
  rptBackdrop && rptBackdrop.addEventListener('click', closeRpt);
  document.addEventListener('keydown', function(e){
    if (rpt && !rpt.hidden && e.key === 'Escape') closeRpt();
  });
  Array.prototype.forEach.call(indChips, function(c){
    c.addEventListener('click', function(){ applyIndustry(c.getAttribute('data-ind')); });
  });

  // ---------- Phase 5/7: Intake modal (preview-only, client-side, no network) ----------
  var intake = root.querySelector('#usbsim-intake');
  var intakeCard = root.querySelector('#usbsim-intake-card');
  var intakeBackdrop = root.querySelector('#usbsim-intake-backdrop');
  var intakeOpenBtn = root.querySelector('#usbsim-intake-open');
  var intakePaidBtn = root.querySelector('#usbsim-cta-paid');
  var intakeCloseBtn = root.querySelector('#usbsim-intake-close');
  var intakeForm = root.querySelector('#usbsim-intake-form');
  var intakeReset = root.querySelector('#usbsim-intake-reset');
  var intakeOut = root.querySelector('#usbsim-intake-out');
  var intakeOutTitle = root.querySelector('#intake-out-title');
  var intakeMaturity = root.querySelector('#intake-maturity');
  var intakeFit = root.querySelector('#intake-fit');
  var intakeScope = root.querySelector('#intake-scope');
  var intakeGaps = root.querySelector('#intake-gaps');
  var intakeBookBtn = root.querySelector('#usbsim-intake-book');
  // ---------- Governance Assessment Result (preview-only, rendered with Generate preview) ----------
  var garChipsWrap = root.querySelector('#usbsim-gar-chips');
  var garResult = root.querySelector('#usbsim-gar-result');
  var GAR_DATA = {
    ALLOW:{label:'ALLOW',tone:'allow',rec:'Proceed \u2014 action authorized under signed policy.',sig:'VERIFIED',ts:'FRESH',euria:'GRANTED',usbay:'GRANTED',human:'NOT_REQUIRED'},
    BLOCKED:{label:'BLOCKED',tone:'blocked',rec:'Deny \u2014 action violates the active signed policy.',sig:'VERIFIED',ts:'FRESH',euria:'DENIED',usbay:'GRANTED',human:'NOT_REQUIRED'},
    HUMAN_REVIEW:{label:'HUMAN_REVIEW',tone:'review',rec:'Hold \u2014 route to the human reviewer of record before proceeding.',sig:'VERIFIED',ts:'FRESH',euria:'PENDING',usbay:'GRANTED',human:'REQUIRED'},
    FAIL_CLOSED:{label:'FAIL_CLOSED',tone:'failclosed',rec:'Fail closed \u2014 governance plane unavailable; deny by default.',sig:'COULD_NOT_VERIFY',ts:'STALE',euria:'WITHHELD',usbay:'WITHHELD',human:'WITHHELD'}
  };
  var GAR_ORDER = ['ALLOW','BLOCKED','HUMAN_REVIEW','FAIL_CLOSED'];
  var garSel = 'ALLOW';
  function garEsc(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
  function garHex(n){var s='';var c='0123456789abcdef';for(var i=0;i<n;i++){s+=c.charAt(Math.floor(Math.random()*16));}return s;}
  function garPill(v){
    var t='info';
    if(/^(GRANTED|VERIFIED|FRESH)$/.test(v)) t='ok';
    else if(/^(DENIED|WITHHELD|COULD_NOT_VERIFY|UNVERIFIED|STALE|EXPIRED)$/.test(v)) t='bad';
    else if(/^(PENDING|REQUIRED)$/.test(v)) t='warn';
    else if(v==='NOT_REQUIRED') t='info';
    return '<span class="usbsim-gar-pill '+t+'">'+garEsc(v)+'</span>';
  }
  function garRow(label,val,mono){
    return '<div class="usbsim-gar-row"><span class="usbsim-gar-rl">'+garEsc(label)+'</span>'+
      '<span class="usbsim-gar-rv'+(mono?' mono':'')+'">'+val+'</span></div>';
  }
  function garRenderChips(){
    if(!garChipsWrap) return;
    var h='';
    for(var i=0;i<GAR_ORDER.length;i++){
      var o=GAR_ORDER[i];
      h+='<button type="button" class="usbsim-gar-chip'+(o===garSel?' on':'')+'" data-o="'+garEsc(o)+'">'+garEsc(o)+'</button>';
    }
    garChipsWrap.innerHTML=h;
  }
  function garRender(){
    if(!garResult) return;
    var d=GAR_DATA[garSel] || GAR_DATA.ALLOW;
    var ids={req:'req_'+garHex(16),eua:'eua_'+garHex(16),dec:'dec_'+garHex(16),pol:'pol_'+garHex(12),aud:'aud_'+garHex(16)};
    var html='';
    html+='<div class="usbsim-gar-banner '+d.tone+'"><span class="usbsim-gar-bdot"></span>'+
      '<span class="usbsim-gar-blabel">'+garEsc(d.label)+'</span>'+
      '<span class="usbsim-gar-btag">Governance Decision</span></div>';
    html+='<div class="usbsim-gar-rec"><span class="usbsim-gar-reck">Euria Recommendation</span>'+
      '<span class="usbsim-gar-recv">'+garEsc(d.rec)+'</span></div>';
    html+='<div class="usbsim-gar-groups">';
    html+='<div class="usbsim-gar-group"><div class="usbsim-gar-ghd">Identifiers</div><div class="usbsim-gar-rows">'+
      garRow('Request ID',garEsc(ids.req),true)+
      garRow('Euria Analysis ID',garEsc(ids.eua),true)+
      garRow('Decision ID',garEsc(ids.dec),true)+
      garRow('Policy ID',garEsc(ids.pol),true)+
      garRow('Audit Record ID',garEsc(ids.aud),true)+
      '</div></div>';
    html+='<div class="usbsim-gar-group"><div class="usbsim-gar-ghd">Verification</div><div class="usbsim-gar-rows">'+
      garRow('Signature Status',garPill(d.sig))+
      garRow('Timestamp Status',garPill(d.ts))+
      '</div></div>';
    html+='<div class="usbsim-gar-group wide"><div class="usbsim-gar-ghd">Authority</div><div class="usbsim-gar-rows">'+
      garRow('authority_euria',garPill(d.euria))+
      garRow('authority_usbay',garPill(d.usbay))+
      garRow('authority_human_approval',garPill(d.human))+
      '</div></div>';
    html+='</div>';
    html+='<p class="usbsim-gar-note">Preview-only. Identifiers are illustrative and regenerated per run. No governance logic, policy, or backend decision is invoked by this panel.</p>';
    garResult.innerHTML=html;
  }
  if(garChipsWrap){
    garChipsWrap.addEventListener('click',function(e){
      var b=e.target.closest('.usbsim-gar-chip');
      if(!b) return;
      garSel=b.getAttribute('data-o');
      garRenderChips();
      garRender();
    });
  }
  garRenderChips();
  var intakeOpener = null;
  function getIntakeFocusables(){
    if (!intakeCard) return [];
    return Array.prototype.slice.call(intakeCard.querySelectorAll(
      'button:not([disabled]), select, [href], summary, [tabindex]:not([tabindex="-1"])'
    ));
  }
  function intakeKey(e){
    if (!intake || intake.hidden) return;
    if (e.key === 'Escape') { e.preventDefault(); closeIntake(); return; }
    if (e.key === 'Tab') {
      var f = getIntakeFocusables();
      if (!f.length) { e.preventDefault(); return; }
      var first = f[0], last = f[f.length-1];
      var active = document.activeElement;
      if (e.shiftKey && active === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && active === last) { e.preventDefault(); first.focus(); }
      else if (!intakeCard.contains(active)) { e.preventDefault(); first.focus(); }
    }
  }
  function openIntake(){
    if (!intake || intake.hidden === false) return;
    intakeOpener = document.activeElement;
    intake.hidden = false;
    document.addEventListener('keydown', intakeKey, true);
    setTimeout(function(){
      var f = getIntakeFocusables();
      if (f.length) f[0].focus();
      else if (intakeCard) intakeCard.focus();
    }, 0);
  }
  function closeIntake(){
    if (!intake || intake.hidden) return;
    intake.hidden = true;
    document.removeEventListener('keydown', intakeKey, true);
    if (intakeOpener && typeof intakeOpener.focus === 'function') {
      try { intakeOpener.focus(); } catch(_) {}
    }
    intakeOpener = null;
  }
  // Scoring (client-side, deterministic)
  var MAT_LABELS = {0:'None',1:'Ad-hoc',2:'Documented',3:'Enforced',4:'Continuously audited'};
  var REV_LABELS = {0:'No formal human review',1:'Informal operator review',2:'Formal review on high-risk',3:'Universal reviewability'};
  var AUD_LABELS = {0:'No audit evidence',1:'Application logs only',2:'Signed evidence per decision',3:'Signed + tamper-evident chain'};
  var ENF_LABELS = {0:'Monitoring only',1:'Soft-block / warnings',2:'Hard-block at gateway',3:'Hard-block + attestation'};
  var SCOPE_TEXT = {
    assess:'Two-week governance assessment with prioritized control roadmap.',
    single:'Single high-risk workflow under USBAY for 6 weeks with regulator-ready evidence pack.',
    prod:  'Production readiness engagement for one environment, including signed policy and evidence pipeline.',
    multi: 'Multi-environment rollout with cross-team governance baseline and evidence aggregation.'
  };
  function generatePreview(e){
    if (e && e.preventDefault) e.preventDefault();
    if (!intakeForm) return;
    var fd = new FormData(intakeForm);
    var mat = parseInt(fd.get('maturity'),10);
    var rev = parseInt(fd.get('review'),10);
    var aud = parseInt(fd.get('audit'),10);
    var enf = parseInt(fd.get('enforce'),10);
    var industry = fd.get('industry') || 'other';
    var scope = fd.get('scope') || 'single';
    var licOpts = {
      regexposure: fd.get('regexposure') || 'standard',
      sovctl: fd.get('sovctl') ? true : false,
      airgap: fd.get('airgap') ? true : false
    };
    // Per-axis max: mat=4, rev=3, aud=3, enf=3 → total max = 13
    var raw = mat + rev + aud + enf;
    var pct = Math.round((raw / 13) * 100);
    var maturityLabel = (pct >= 85) ? 'Advanced' : (pct >= 65) ? 'Strong' : (pct >= 40) ? 'Developing' : 'Early';
    var maturityColor = (pct >= 85) ? '#22c55e' : (pct >= 65) ? '#22d3ee' : (pct >= 40) ? '#f59e0b' : '#ef4444';
    var fitLabel, fitColor;
    if (raw <= 4) { fitLabel = 'Strong fit — significant uplift available'; fitColor = '#22d3ee'; }
    else if (raw <= 9) { fitLabel = 'Strong fit — targeted controls recommended'; fitColor = '#22d3ee'; }
    else { fitLabel = 'Good fit — refinement and continuous-audit posture'; fitColor = '#22c55e'; }
    // Top 3 gaps: lowest-scoring axes
    var axes = [
      {k:'mat', v:mat, max:4, txt:'Governance maturity: ' + MAT_LABELS[mat] + ' — formalize policy ownership, review cadence, and enforcement standards.'},
      {k:'rev', v:rev, max:3, txt:'Human review: ' + REV_LABELS[rev] + ' — define approver SLAs and escalation paths for high-impact actions.'},
      {k:'aud', v:aud, max:3, txt:'Audit evidence: ' + AUD_LABELS[aud] + ' — adopt signed, append-only evidence per decision.'},
      {k:'enf', v:enf, max:3, txt:'Runtime enforcement: ' + ENF_LABELS[enf] + ' — move to hard-block enforcement with attestation.'}
    ];
    axes.sort(function(a,b){ return (a.v/a.max) - (b.v/b.max); });
    var gapsHtml = '';
    var emitted = 0;
    for (var i=0;i<axes.length && emitted<3;i++){
      if (axes[i].v >= axes[i].max) continue;
      // build via DOM, not innerHTML, but use a textContent stash
      emitted++;
      gapsHtml += '<li></li>'; // placeholder; we'll fill via textContent
    }
    if (!emitted) gapsHtml = '<li></li>';
    intakeGaps.innerHTML = gapsHtml; // structure only (static <li>s, no user input)
    var lis = intakeGaps.querySelectorAll('li');
    var fillIdx = 0;
    for (var j=0;j<axes.length && fillIdx<lis.length;j++){
      if (axes[j].v >= axes[j].max) continue;
      lis[fillIdx].textContent = axes[j].txt;
      fillIdx++;
    }
    if (fillIdx === 0 && lis.length) lis[0].textContent = 'No critical gaps in declared posture — continuous-audit cadence is the next step.';
    var preset = INDUSTRY_PRESETS[industry];
    var scopeText = SCOPE_TEXT[scope] || SCOPE_TEXT.single;
    if (preset) scopeText = scopeText + ' Sector fit: ' + preset.pilot;
    intakeOutTitle.textContent = 'Preview readiness: ' + maturityLabel + ' (' + pct + '%)';
    intakeMaturity.textContent = maturityLabel + ' (' + pct + '%)';
    intakeMaturity.style.color = maturityColor;
    intakeFit.textContent = fitLabel;
    intakeFit.style.color = fitColor;
    intakeScope.textContent = scopeText;
    intakeOut.hidden = false;
    garRender();
    applyLicensingFromAssessment(mat, rev, aud, enf, industry, scope, licOpts);
    setTimeout(function(){
      try { intakeOut.scrollIntoView({behavior:'smooth', block:'start'}); } catch(_) {}
    }, 30);
  }
  function resetIntakeOut(){
    if (intakeOut) intakeOut.hidden = true;
  }
  intakeOpenBtn && intakeOpenBtn.addEventListener('click', openIntake);
  intakePaidBtn && intakePaidBtn.addEventListener('click', openIntake);
  var pilotPaidBtn = root.querySelector('#usbsim-pilot-paid');
  pilotPaidBtn && pilotPaidBtn.addEventListener('click', openIntake);

  // ---------- USBAY Licensing Recommendation (client-side, no network) ----------
  var LIC_TIERS = {
    pilot:{
      name:'USBAY Pilot', tag:'Entry engagement', tone:'is-pilot',
      fit:'Best when you are placing your first one or two AI workflows under governance and need defensible evidence before you scale.',
      coverage:'One to two governed AI workflows behind the USBAY gateway, in a single environment.',
      enforcement:'Fail-closed policy gate with a monitor-to-hard-block path as confidence builds.',
      evidence:'Signed evidence per decision and a sealed, verifiable audit chain for the pilot workflows.',
      oversight:'Human review enforced on the highest-impact decisions in scope.',
      support:'Guided 6–8 week pilot onboarding with one governance reviewer of record.',
      addon:'Executive evidence pack for board and second-line risk review.',
      included:['Signed policy enforcement on the pilot workflow','Replay and stale-request protection','Sealed, verifiable audit chain','Preview-grade executive governance report']
    },
    operational:{
      name:'USBAY Operational', tag:'Standard engagement', tone:'is-op',
      fit:'Best when several AI workflows are already live in one environment and governance has to be enforced consistently rather than workflow by workflow.',
      coverage:'Multiple governed AI workflows across a single production environment.',
      enforcement:'Hard-block at the gateway on unsigned, expired, or out-of-policy actions.',
      evidence:'Signed evidence per decision with a standardized, tamper-evident audit chain.',
      oversight:'Named-approver review with defined SLAs and escalation paths.',
      support:'Business-hours governance support with a shared, versioned policy library.',
      addon:'Quarterly governance posture review against your regulatory profile.',
      included:['Hard-block enforcement across workflows','Named-approver review with SLAs','Standardized signed audit chain','Versioned policy library and policy hashes','On-demand regulator-ready evidence export']
    },
    enterprise:{
      name:'USBAY Enterprise', tag:'Scaled engagement', tone:'is-ent',
      fit:'Best when AI execution spans many workflows and multiple environments and you need one standardized governance and evidence model across all of them.',
      coverage:'Many governed AI workflows standardized across multiple environments.',
      enforcement:'Hard-block plus runtime attestation across every governed surface.',
      evidence:'Unified, continuously audited evidence chain across all environments.',
      oversight:'Org-wide review model with role-based authority and audited overrides.',
      support:'Dedicated governance success contact with 24×7 enforcement coverage.',
      addon:'Custom policy authoring and integration with your existing IAM and SIEM.',
      included:['Hard-block + runtime attestation everywhere','Unified cross-environment evidence chain','Role-based authority and audited overrides','24×7 enforcement coverage','Dedicated governance success contact']
    },
    sovereign:{
      name:'USBAY Regulated / Sovereign', tag:'Regulated engagement', tone:'is-sov',
      fit:'Best for safety-critical, patient-critical, or multi-region operations where governance must be defensible to a regulator or a safety case.',
      coverage:'Governed AI execution across sovereign or multi-region deployments, aligned to your safety case.',
      enforcement:'Fail-closed hard-block with runtime attestation and sovereignty-aware policy boundaries.',
      evidence:'Regulator-grade, hash-chained evidence packs aligned to your reporting obligations.',
      oversight:'Mandatory human-of-record on safety- and patient-impacting decisions.',
      support:'Dedicated compliance liaison with safety-case alignment workshops.',
      addon:'Independent attestation support for regulator and insurer assessments.',
      included:['Sovereignty-aware policy boundaries','Runtime attestation per execution','Regulator-grade evidence packs','Mandatory human-of-record on critical decisions','Dedicated compliance liaison']
    }
  };
  var licForm = root.querySelector('#usbsim-lic-form');
  var licRunBtn = root.querySelector('#usbsim-lic-run');
  var licIntakeBtn = root.querySelector('#usbsim-lic-intake');
  var licWf = root.querySelector('#lic-workflows');
  var licEnv = root.querySelector('#lic-env');
  var licEnf = root.querySelector('#lic-enf');
  var licReg = root.querySelector('#lic-reg');
  var licTierEl = root.querySelector('#lic-tier');
  var licTagEl = root.querySelector('#lic-tag');
  var licFitEl = root.querySelector('#lic-fit');
  var licCoverageEl = root.querySelector('#lic-coverage');
  var licEnforcementEl = root.querySelector('#lic-enforcement');
  var licEvidenceEl = root.querySelector('#lic-evidence');
  var licOversightEl = root.querySelector('#lic-oversight');
  var licSupportEl = root.querySelector('#lic-support');
  var licAddonEl = root.querySelector('#lic-addon');
  var licInclEl = root.querySelector('#lic-included');
  function licSelText(sel){
    if (!sel || sel.selectedIndex < 0) return '';
    return sel.options[sel.selectedIndex].text;
  }
  function licComputeKey(wf, env, enf, reg){
    if (reg >= 3 || env >= 3) return 'sovereign';
    var total = wf + env + enf + reg;
    if (total <= 2) return 'pilot';
    if (total <= 5) return 'operational';
    return 'enterprise';
  }
  function licRender(){
    if (!licTierEl) return;
    var wf = parseInt(licWf && licWf.value, 10) || 0;
    var env = parseInt(licEnv && licEnv.value, 10) || 0;
    var enf = parseInt(licEnf && licEnf.value, 10) || 0;
    var reg = parseInt(licReg && licReg.value, 10) || 0;
    var t = LIC_TIERS[licComputeKey(wf, env, enf, reg)] || LIC_TIERS.operational;
    licTierEl.textContent = t.name;
    licTierEl.classList.remove('is-pilot','is-op','is-ent','is-sov');
    licTierEl.classList.add(t.tone);
    if (licTagEl) licTagEl.textContent = t.tag;
    if (licFitEl) licFitEl.textContent = 'Your profile — ' + [licSelText(licWf), licSelText(licEnv), licSelText(licEnf), licSelText(licReg)].join(' · ') + '. ' + t.fit;
    if (licCoverageEl) licCoverageEl.textContent = t.coverage;
    if (licEnforcementEl) licEnforcementEl.textContent = t.enforcement;
    if (licEvidenceEl) licEvidenceEl.textContent = t.evidence;
    if (licOversightEl) licOversightEl.textContent = t.oversight;
    if (licSupportEl) licSupportEl.textContent = t.support;
    if (licAddonEl) licAddonEl.textContent = t.addon;
    if (licInclEl){
      licInclEl.innerHTML = '';
      for (var i=0;i<t.included.length;i++){
        var li = document.createElement('li');
        li.textContent = t.included[i];
        licInclEl.appendChild(li);
      }
    }
  }
  if (licForm){
    licForm.addEventListener('submit', function(e){ if (e && e.preventDefault) e.preventDefault(); licRender(); });
  }
  [licWf, licEnv, licEnf, licReg].forEach(function(sel){
    sel && sel.addEventListener('change', licRender);
  });
  licRunBtn && licRunBtn.addEventListener('click', function(e){ if (e && e.preventDefault) e.preventDefault(); licRender(); });
  licIntakeBtn && licIntakeBtn.addEventListener('click', openIntake);
  licRender();

  // ---------- Assessment results -> licensing recommendation (client-side, no network) ----------
  var intakeLicName = root.querySelector('#intake-lic-name');
  var intakeLicTag = root.querySelector('#intake-lic-tag');
  var intakeLicWhyText = root.querySelector('#intake-lic-whytext');
  var intakeLicWhy = root.querySelector('#intake-lic-why');
  var dimGov = root.querySelector('#intake-dim-gov');
  var dimRisk = root.querySelector('#intake-dim-risk');
  var dimEvidence = root.querySelector('#intake-dim-evidence');
  var dimReview = root.querySelector('#intake-dim-review');
  var dimEnf = root.querySelector('#intake-dim-enf');
  var intakeLicDetail = root.querySelector('#intake-lic-detail');
  var intakeLicScope = root.querySelector('#intake-lic-scope');
  var intakeLicDeploy = root.querySelector('#intake-lic-deploy');
  var intakeLicResp = root.querySelector('#intake-lic-resp');
  var INTAKE_LICENSES = {
    pilot:{ name:'Pilot License', tag:'Entry engagement', tone:'is-pilot',
      why:'Your governance footprint is early-stage with lighter runtime enforcement, so USBAY recommends starting with one or two governed workflows to build defensible evidence before you scale.',
      detail:{
        scope:'One or two governed AI workflows under USBAY, scoped for evaluation and evidence-building.',
        deployment:'Hosted USBAY gateway in a single environment, placed in front of the selected workflows.',
        responsibilities:[['Euria','Analysis and recommendations'],['USBAY','Policy enforcement on scoped workflows'],['Human review','Advisory on flagged decisions'],['Evidence','Signed record per governed decision']]
      } },
    runtime:{ name:'Governance Runtime License', tag:'Production runtime', tone:'is-op',
      why:'You are enforcing policy on live AI decisions, so USBAY recommends runtime governance that sits in the execution path as the fail-closed policy gate for your production environment.',
      detail:{
        scope:'Production governance across the live AI decisions in one environment, enforced in the execution path.',
        deployment:'USBAY runtime gateway deployed in the production execution path as a fail-closed policy gate.',
        responsibilities:[['Euria','Analysis only'],['USBAY','Runtime enforcement authority'],['Human review','Required on high-risk decisions'],['Fail closed','On degraded trust signals']]
      } },
    enterprise:{ name:'Enterprise Governance License', tag:'Scaled program', tone:'is-ent',
      why:'Your deployment spans multiple teams or environments with strong enforcement, so USBAY recommends enterprise governance with a full evidence chain and centralized oversight at scale.',
      detail:{
        scope:'Centralized governance across multiple teams and environments, with an aggregated evidence chain.',
        deployment:'USBAY deployed across multiple environments with centralized policy management and oversight.',
        responsibilities:[['Euria','Analysis only'],['USBAY','Enforcement authority across environments'],['Human review','Mandatory on high-impact decisions'],['Oversight','Centralized governance and audit']]
      } },
    sovereign:{ name:'Sovereign Governance License', tag:'Sovereign / safety-critical', tone:'is-sov',
      why:'You operate in a sovereign or safety-critical sector at the highest enforcement, so USBAY recommends sovereignty-aware governance with runtime attestation, regulator-grade evidence, and a mandatory human-of-record on critical decisions.',
      detail:{
        scope:'Sovereign-controlled governance with regional policy isolation and an independent, sovereign audit chain.',
        deployment:'Air-gapped or offline deployment under sovereign control, with a controlled update process.',
        responsibilities:[['Euria','Analysis only'],['USBAY','Enforcement authority'],['Human approval','Mandatory'],['Fail closed','Default']]
      } }
  };
  var SCOPE_LABELS = {assess:'Assessment & recommendations only', single:'Single high-risk workflow under USBAY', prod:'Production readiness for one environment', multi:'Multi-environment / multi-team'};
  var INDUSTRY_LABELS = {fin:'Financial Services', health:'Healthcare', log:'Logistics', rail:'Rail Operations', ind:'Industrial Automation', support:'Customer Support AI', gov:'Government / Public Sector', defense:'Defense', critical:'Critical Infrastructure', other:'Other'};
  var SOVEREIGN_SECTORS = {gov:1, defense:1, critical:1};
  function sovereignTriggers(industry, opts){
    opts = opts || {};
    var t = [];
    if (SOVEREIGN_SECTORS[industry]) t.push('Sovereign sector — ' + (INDUSTRY_LABELS[industry] || industry));
    if (opts.regexposure === 'highest') t.push('Highest regulatory exposure declared');
    if (opts.sovctl) t.push('Multi-region sovereign controls required');
    if (opts.airgap) t.push('Air-gapped governance required');
    return t;
  }
  function licRiskLabel(industry, opts){
    opts = opts || {};
    if (SOVEREIGN_SECTORS[industry] || opts.regexposure === 'highest' || opts.sovctl || opts.airgap) return 'Critical';
    if (industry === 'health' || industry === 'rail') return 'Critical';
    if (industry === 'fin' || industry === 'ind') return 'High';
    return 'Moderate';
  }
  function chooseLicense(mat, rev, aud, enf, industry, scope, opts){
    if (sovereignTriggers(industry, opts).length) return 'sovereign';
    var scopeScore = {assess:0, single:1, prod:2, multi:3}[scope];
    if (scopeScore == null) scopeScore = 1;
    var sectorWeight = (industry === 'health' || industry === 'rail') ? 2
      : ((industry === 'fin' || industry === 'ind') ? 1 : 0);
    var score = scopeScore + (enf || 0) + sectorWeight; // 0..8
    if (score <= 2) return 'pilot';
    if (score <= 4) return 'runtime';
    if (score <= 6) return 'enterprise';
    return 'sovereign';
  }
  function applyLicensingFromAssessment(mat, rev, aud, enf, industry, scope, opts){
    if (!intakeLicName) return;
    opts = opts || {};
    var lic = INTAKE_LICENSES[chooseLicense(mat, rev, aud, enf, industry, scope, opts)] || INTAKE_LICENSES.runtime;
    intakeLicName.textContent = lic.name;
    intakeLicName.className = 'usbsim-lic-tier ' + lic.tone;
    if (intakeLicTag) intakeLicTag.textContent = lic.tag;
    if (intakeLicWhyText) intakeLicWhyText.textContent = lic.why;
    if (intakeLicWhy){
      intakeLicWhy.innerHTML = '';
      var drivers = sovereignTriggers(industry, opts);
      drivers.push('Deployment scope — ' + (SCOPE_LABELS[scope] || SCOPE_LABELS.single));
      drivers.push('Runtime enforcement — ' + (ENF_LABELS[enf] || '\u2014'));
      drivers.push('Sector & risk — ' + (INDUSTRY_LABELS[industry] || 'Other') + ' (' + licRiskLabel(industry, opts) + ')');
      for (var i=0;i<drivers.length;i++){
        var li = document.createElement('li');
        li.textContent = drivers[i];
        intakeLicWhy.appendChild(li);
      }
    }
    if (dimGov) dimGov.textContent = MAT_LABELS[mat] || '\u2014';
    if (dimRisk) dimRisk.textContent = licRiskLabel(industry, opts);
    if (dimEvidence) dimEvidence.textContent = AUD_LABELS[aud] || '\u2014';
    if (dimReview) dimReview.textContent = REV_LABELS[rev] || '\u2014';
    if (dimEnf) dimEnf.textContent = ENF_LABELS[enf] || '\u2014';
    if (intakeLicDetail){
      var det = lic.detail;
      if (det){
        if (intakeLicScope) intakeLicScope.textContent = det.scope || '\u2014';
        if (intakeLicDeploy) intakeLicDeploy.textContent = det.deployment || '\u2014';
        if (intakeLicResp){
          intakeLicResp.innerHTML = '';
          var resp = det.responsibilities || [];
          for (var ri=0; ri<resp.length; ri++){
            var row = document.createElement('div'); row.className = 'usbsim-licrec-mrow';
            var mk = document.createElement('span'); mk.className = 'usbsim-licrec-mk'; mk.textContent = resp[ri][0];
            var mv = document.createElement('span'); mv.className = 'usbsim-licrec-mv'; mv.textContent = resp[ri][1];
            row.appendChild(mk); row.appendChild(mv); intakeLicResp.appendChild(row);
          }
        }
        intakeLicDetail.hidden = false;
      } else {
        intakeLicDetail.hidden = true;
      }
    }
  }

  // ---------- CTA hierarchy: View Executive Summary + Copy Demo Summary ----------
  var ctaExecBtn = root.querySelector('#usbsim-cta-exec');
  var ctaCopyBtn = root.querySelector('#usbsim-cta-copy');
  var execTarget = root.querySelector('#usbsim-exec-summary');
  ctaExecBtn && ctaExecBtn.addEventListener('click', function(){
    if (!execTarget) return;
    try { execTarget.scrollIntoView({behavior:'smooth', block:'start'}); } catch(_) { execTarget.scrollIntoView(); }
    execTarget.classList.add('is-flash');
    setTimeout(function(){ execTarget.classList.remove('is-flash'); }, 1600);
  });
  function buildDemoSummary(){
    // Client-side: read currently-visible text from existing executive panels only.
    // No network, no persistence, no form-input capture.
    function txt(sel){ var n = root.querySelector(sel); return n ? (n.textContent || '').trim().replace(/\s+/g,' ') : ''; }
    var lines = [
      'USBAY Governance Demo — executive summary',
      '',
      'Governance posture     : ' + txt('#exec-posture'),
      'Runtime integrity      : ' + txt('#exec-integrity'),
      'Trust state            : ' + txt('#exec-trust'),
      'Replay protection      : ' + txt('#exec-replay'),
      'Evidence verification  : ' + txt('#exec-evidence'),
      'Operational risk       : ' + txt('#exec-risk'),
      '',
      'Pilot recommendation',
      '  Industry             : ' + txt('#pilot-industry'),
      '  Governance maturity  : ' + txt('#pilot-maturity'),
      '  Recommended pilot    : ' + txt('#pilot-scope'),
      '  Estimated duration   : ' + txt('#pilot-duration'),
      '  Governance value     : ' + txt('#pilot-value'),
      '',
      'Recommended next step',
      '  Action               : ' + txt('#nextstep-action'),
      '  Priority             : ' + txt('#nextstep-priority'),
      '  Expected impact      : ' + txt('#nextstep-impact'),
      '',
      'Source : in-browser demo (no submitted data leaves this page).'
    ];
    return lines.join('\n');
  }
  function flashCopyBtn(ok){
    if (!ctaCopyBtn) return;
    var prev = ctaCopyBtn.textContent;
    ctaCopyBtn.textContent = ok ? 'Copied to clipboard ✓' : 'Copy unavailable — select text manually';
    ctaCopyBtn.classList.toggle('usbsim-cta-copy-ok', !!ok);
    ctaCopyBtn.disabled = true;
    setTimeout(function(){
      ctaCopyBtn.textContent = prev;
      ctaCopyBtn.classList.remove('usbsim-cta-copy-ok');
      ctaCopyBtn.disabled = false;
    }, 1800);
  }
  ctaCopyBtn && ctaCopyBtn.addEventListener('click', function(){
    var text = buildDemoSummary();
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function(){ flashCopyBtn(true); }, function(){ flashCopyBtn(false); });
    } else {
      try {
        var ta = document.createElement('textarea');
        ta.value = text; ta.setAttribute('readonly','');
        ta.style.position='fixed'; ta.style.top='-9999px';
        document.body.appendChild(ta); ta.select();
        var ok = document.execCommand && document.execCommand('copy');
        document.body.removeChild(ta);
        flashCopyBtn(!!ok);
      } catch(_) { flashCopyBtn(false); }
    }
  });
  intakeCloseBtn && intakeCloseBtn.addEventListener('click', closeIntake);
  intakeBackdrop && intakeBackdrop.addEventListener('click', closeIntake);
  intakeForm && intakeForm.addEventListener('submit', generatePreview);
  intakeReset && intakeReset.addEventListener('click', resetIntakeOut);
  intakeBookBtn && intakeBookBtn.addEventListener('click', function(){
    intakeBookBtn.textContent = 'Preview only — no booking submitted';
    intakeBookBtn.disabled = true;
    setTimeout(function(){
      intakeBookBtn.textContent = 'Book paid intake';
      intakeBookBtn.disabled = false;
    }, 2400);
  });
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
        <div class="crumb">Runtime // Enforcement</div>
        <div class="page-head-eyebrow">USBAY Governance Gateway · Runtime Surface</div>
        <h1>Policy Enforcement Gateway Active</h1>
        <p class="sub">Runtime API decisions are evaluated, blocked, escalated, and logged before execution.</p>
        <p class="sub sub-meta" id="route-owner">Route owner: Governance Control Plane (governance authority) · operated by the Policy Enforcement Gateway (runtime).</p>
      </div>
    </div>

    <section class="enforce-hero" aria-label="Policy Enforcement Gateway operational hero">
      <style>
        .page-head-eyebrow{font-size:10px;letter-spacing:.24em;text-transform:uppercase;color:#7dd3fc;font-weight:700;margin-bottom:4px;}
        .sub-meta{font-size:11px;color:#64748b;letter-spacing:.04em;margin-top:6px;}
        .enforce-hero{margin:14px 0 18px;display:grid;gap:12px;}
        .enforce-pipeline{display:flex;flex-wrap:wrap;gap:6px;align-items:center;padding:12px 14px;border:1px solid #1f3253;border-radius:10px;background:linear-gradient(180deg,rgba(14,26,43,.85),rgba(10,19,32,.85));}
        .enf-step{display:inline-flex;align-items:center;gap:8px;padding:6px 10px;border-radius:6px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);font-size:11px;letter-spacing:.06em;color:#cbd5e1;text-transform:uppercase;font-weight:700;}
        .enf-step-k{display:inline-grid;place-items:center;width:18px;height:18px;border-radius:50%;background:rgba(34,211,238,.15);color:#7dd3fc;font-size:10px;font-family:"JetBrains Mono",monospace;}
        .enf-decide{border-color:rgba(34,211,238,.5);color:#7dd3fc;background:rgba(34,211,238,.08);}
        .enf-sep{color:rgba(125,211,252,.5);font-size:12px;}
        .enforce-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;}
        .enforce-panel{padding:14px 16px;border:1px solid #1f3253;border-left:3px solid #22d3ee;border-radius:10px;background:rgba(8,14,22,.55);display:flex;flex-direction:column;}
        .enforce-panel h4{margin:0 0 10px;font-size:10.5px;letter-spacing:.22em;text-transform:uppercase;color:#94a3b8;font-weight:700;display:flex;justify-content:space-between;align-items:center;}
        .enforce-panel h4 .h4-live{font-size:9px;letter-spacing:.18em;color:#86efac;border:1px solid currentColor;border-radius:999px;padding:1px 7px;background:rgba(34,197,94,.08);}
        .enforce-panel ul{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:8px;}
        .enforce-panel li{font-size:12px;line-height:1.55;color:#cbd5e1;display:flex;gap:8px;align-items:flex-start;}
        .ed-tag{flex-shrink:0;display:inline-block;padding:3px 8px;border-radius:4px;font-size:9.5px;letter-spacing:.16em;font-weight:700;border:1px solid currentColor;background:rgba(0,0,0,.3);min-width:48px;text-align:center;}
        .ed-tag.ed-allow{color:#86efac;}
        .ed-tag.ed-deny{color:#fbbf24;}
        .ed-tag.ed-block{color:#fca5a5;}
        .enforce-stream{gap:0;}
        .enforce-stream li{display:grid;grid-template-columns:1fr auto;gap:8px;padding:6px 0;border-top:1px solid rgba(26,38,56,.5);font-size:11.5px;}
        .enforce-stream li:first-child{border-top:none;padding-top:0;}
        .es-k{font-family:"JetBrains Mono","SFMono-Regular",monospace;color:#7dd3fc;font-size:11px;}
        .es-v{color:#94a3b8;font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;font-weight:700;}
        .es-note{margin:10px 0 0;font-size:10.5px;color:#64748b;font-style:italic;line-height:1.5;}
        .ces-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:6px;}
        .ces-cell{padding:8px 6px;border-radius:6px;background:rgba(0,0,0,.35);border:1px solid rgba(255,255,255,.06);border-top:2px solid currentColor;text-align:center;}
        .ces-k{font-size:9px;letter-spacing:.12em;font-weight:700;font-family:"JetBrains Mono","SFMono-Regular",monospace;line-height:1.2;}
        .ces-v{font-size:18px;font-weight:700;color:#e6edf6;font-family:"JetBrains Mono","SFMono-Regular",monospace;margin-top:4px;line-height:1;}
        .ces-allow{color:#86efac;}
        .ces-deny{color:#fbbf24;}
        .ces-block{color:#fca5a5;}
        .ces-review{color:#c4b5fd;}
        .ces-fc{color:#f87171;}
        .ces-note{margin:10px 0 0;font-size:10.5px;color:#64748b;font-style:italic;line-height:1.5;}
        .ces-recent{color:#94a3b8;font-style:normal;font-family:"JetBrains Mono","SFMono-Regular",monospace;}
        .rt-stream{max-height:none;}
        .gh-list{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:0;}
        .gh-list li{display:grid;grid-template-columns:1fr auto;align-items:center;gap:8px;padding:7px 0;border-top:1px solid rgba(26,38,56,.5);}
        .gh-list li:first-child{border-top:none;padding-top:0;}
        .gh-k{font-size:11px;color:#cbd5e1;letter-spacing:.04em;}
        .gh-v{font-size:10.5px;letter-spacing:.14em;font-weight:700;text-transform:uppercase;font-family:"JetBrains Mono","SFMono-Regular",monospace;padding:2px 8px;border-radius:4px;border:1px solid currentColor;background:rgba(0,0,0,.3);color:#94a3b8;}
        .gh-ok{color:#86efac;}
        .gh-warn{color:#fbbf24;}
        .gh-fail{color:#f87171;}
        @media (max-width:1100px){.enforce-grid{grid-template-columns:1fr 1fr;}}
        @media (max-width:780px){.enforce-grid{grid-template-columns:1fr;}.ces-grid{grid-template-columns:repeat(2,1fr);}}
      </style>
      <div class="enforce-pipeline" aria-label="Request lifecycle">
        <div class="enf-step"><span class="enf-step-k">1</span><span>Receive request</span></div>
        <span class="enf-sep">→</span>
        <div class="enf-step"><span class="enf-step-k">2</span><span>Verify signature</span></div>
        <span class="enf-sep">→</span>
        <div class="enf-step"><span class="enf-step-k">3</span><span>Replay guard</span></div>
        <span class="enf-sep">→</span>
        <div class="enf-step"><span class="enf-step-k">4</span><span>Evaluate policy</span></div>
        <span class="enf-sep">→</span>
        <div class="enf-step"><span class="enf-step-k">5</span><span>Verify provenance</span></div>
        <span class="enf-sep">→</span>
        <div class="enf-step enf-decide"><span class="enf-step-k">6</span><span>Allow · Deny · Block</span></div>
        <span class="enf-sep">→</span>
        <div class="enf-step"><span class="enf-step-k">7</span><span>Seal audit evidence</span></div>
      </div>
      <div class="enforce-grid">
        <div class="enforce-panel" aria-label="Current enforcement state">
          <h4>Current enforcement state <span class="h4-live">● LIVE</span></h4>
          <div class="ces-grid">
            <div class="ces-cell ces-allow"><div class="ces-k">ALLOW</div><div class="ces-v" id="ces-allow">—</div></div>
            <div class="ces-cell ces-deny"><div class="ces-k">DENY</div><div class="ces-v" id="ces-deny">—</div></div>
            <div class="ces-cell ces-block"><div class="ces-k">BLOCK</div><div class="ces-v" id="ces-block">—</div></div>
            <div class="ces-cell ces-review"><div class="ces-k">HUMAN_REVIEW</div><div class="ces-v" id="ces-review">—</div></div>
            <div class="ces-cell ces-fc"><div class="ces-k">FAIL_CLOSED</div><div class="ces-v" id="ces-fc">—</div></div>
          </div>
          <p class="ces-note">Counts populate as signed requests reach the gateway. Most recent: <span class="ces-recent" id="ces-recent">none yet</span>.</p>
        </div>
        <div class="enforce-panel" aria-label="Runtime event stream">
          <h4>Runtime event stream <span class="h4-live">● LIVE</span></h4>
          <ul class="enforce-stream rt-stream">
            <li><span class="es-k">request_received</span><span class="es-v">live</span></li>
            <li><span class="es-k">policy_loaded</span><span class="es-v">verified</span></li>
            <li><span class="es-k">signature_verified</span><span class="es-v">live</span></li>
            <li><span class="es-k">replay_detected</span><span class="es-v">guarded</span></li>
            <li><span class="es-k">human_review_required</span><span class="es-v">queued</span></li>
            <li><span class="es-k">decision_allowed</span><span class="es-v">live</span></li>
            <li><span class="es-k">decision_denied</span><span class="es-v">live</span></li>
            <li><span class="es-k">evidence_sealed</span><span class="es-v">append-only</span></li>
          </ul>
          <p class="es-note">Operational event taxonomy emitted to the signed audit chain on every decision.</p>
        </div>
        <div class="enforce-panel" aria-label="Gateway health">
          <h4>Gateway health <span class="h4-live">● LIVE</span></h4>
          <ul class="gh-list">
            <li><span class="gh-k">Policy status</span><span class="gh-v" id="gh-policy">—</span></li>
            <li><span class="gh-k">Signature status</span><span class="gh-v" id="gh-sig">—</span></li>
            <li><span class="gh-k">Replay guard</span><span class="gh-v" id="gh-replay">—</span></li>
            <li><span class="gh-k">Evidence writer</span><span class="gh-v" id="gh-ev">—</span></li>
            <li><span class="gh-k">Audit chain</span><span class="gh-v" id="gh-chain">—</span></li>
            <li><span class="gh-k">Runtime integrity</span><span class="gh-v" id="gh-int">—</span></li>
          </ul>
        </div>
      </div>
      <script>
      (function(){
        function hydrate(){
          try{
            var ref = document.getElementById('usbay-sync-ref');
            if(!ref) return;
            var d = JSON.parse(ref.textContent || '{}');
            function set(id, cls, txt){
              var el = document.getElementById(id);
              if(!el) return;
              el.textContent = txt;
              el.classList.remove('gh-ok','gh-warn','gh-fail');
              if(cls) el.classList.add(cls);
            }
            var polOk = String(d.policy_state||'').toLowerCase() === 'valid';
            set('gh-policy', polOk ? 'gh-ok' : 'gh-warn', String(d.policy_state||'UNKNOWN').toUpperCase());
            set('gh-sig', d.policy_signature_valid ? 'gh-ok' : 'gh-fail', d.policy_signature_valid ? 'VALID' : 'INVALID');
            set('gh-replay', d.replay_protection_active ? 'gh-ok' : 'gh-fail', d.replay_protection_active ? 'ACTIVE' : 'OFF');
            var evOk = String(d.evidence_state||'') === 'VERIFIED';
            set('gh-ev', evOk ? 'gh-ok' : 'gh-warn', evOk ? 'WRITING' : String(d.evidence_state||'UNKNOWN').toUpperCase());
            set('gh-chain', evOk ? 'gh-ok' : 'gh-warn', evOk ? 'SEALED' : String(d.evidence_state||'UNKNOWN').toUpperCase());
            var intOk = String(d.status||'') === 'OK' && !d.fail_closed;
            set('gh-int', intOk ? 'gh-ok' : 'gh-fail', d.fail_closed ? 'FAIL-CLOSED' : String(d.status||'UNKNOWN').toUpperCase());
            var fc = document.getElementById('ces-fc');
            if(fc) fc.textContent = d.fail_closed ? '1' : '0';
            var ces = ['ces-allow','ces-deny','ces-block','ces-review'];
            for(var i=0;i<ces.length;i++){ var c=document.getElementById(ces[i]); if(c && c.textContent==='—') c.textContent='0'; }
          }catch(_){}
        }
        if(document.readyState!=='loading') hydrate(); else document.addEventListener('DOMContentLoaded', hydrate);
      })();
      </script>
    </section>

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
    <div class="page-head-eyebrow">USBAY Runtime Governance Playground · Executive Surface</div>
    <h1>Execution Authority Active</h1>
    <p class="sub">Boardroom view of policy oversight, risk posture, business impact, regulator readiness, recommended pilot scope, and the executive report preview.</p>
    <p class="sub sub-meta" id="route-owner">Route owner: Playground / Demo Tooling — Governance Control Plane (executive authority). Runtime enforcement runs on the Policy Enforcement Gateway.</p>

    <section class="exec-hero" aria-label="Governance Control Plane executive hero">
      <style>
        .page-head-eyebrow{font-size:10px;letter-spacing:.24em;text-transform:uppercase;color:#7dd3fc;font-weight:700;margin-bottom:4px;}
        .sub-meta{font-size:11px;color:#64748b;letter-spacing:.04em;margin-top:6px;}
        .exec-hero{margin:14px 0 18px;padding:14px 18px;border:1px solid #1f3253;border-left:3px solid #22d3ee;border-radius:10px;background:linear-gradient(135deg,rgba(34,211,238,.06),rgba(14,26,43,.55));display:grid;gap:8px;}
        .exec-hero-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;}
        .exec-hero-eyebrow{font-size:10px;letter-spacing:.24em;text-transform:uppercase;color:#7dd3fc;font-weight:700;}
        .exec-hero-tag{padding:4px 10px;border-radius:999px;font-size:10px;letter-spacing:.14em;font-weight:700;text-transform:uppercase;border:1px solid currentColor;background:rgba(0,0,0,.25);color:#86efac;}
        .exec-hero-sub{margin:0;font-size:12px;color:#cbd5e1;line-height:1.55;}
        .exec-hero-sub a{color:#7dd3fc;}
        .exec-hero-pillars{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px;}
        .exec-hero-pillar{padding:4px 10px;border-radius:6px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);font-size:10.5px;letter-spacing:.12em;color:#cbd5e1;text-transform:uppercase;font-weight:700;}
      </style>
      <div class="exec-hero-row">
        <span class="exec-hero-eyebrow">● Executive Governance Command Center</span>
        <span class="exec-hero-tag">EXECUTION AUTHORITY ACTIVE</span>
      </div>
      <p class="exec-hero-sub">Boardroom-grade view of policy oversight, risk posture, business impact, regulator readiness, recommended pilot scope, and the executive report preview. Runtime API enforcement, decision lifecycle, and audit event stream are operated on the <a href="/">Policy Enforcement Gateway</a>.</p>
      <div class="exec-hero-pillars">
        <span class="exec-hero-pillar">Policy Oversight</span>
        <span class="exec-hero-pillar">Risk Posture</span>
        <span class="exec-hero-pillar">Business Impact</span>
        <span class="exec-hero-pillar">Pilot Scope</span>
        <span class="exec-hero-pillar">Regulator Readiness</span>
        <span class="exec-hero-pillar">Report Preview</span>
      </div>
    </section>

    <section id="usbsim-resilience" class="resilience" aria-label="Governance Resilience Engineering Demonstration">
      <style>
        .resilience{margin:14px 0 18px;display:grid;gap:14px;padding:16px 18px;border:1px solid #1f3253;border-left:3px solid #c084fc;border-radius:10px;background:linear-gradient(135deg,rgba(192,132,252,.05),rgba(14,26,43,.55));}
        .res-head{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;}
        .res-eyebrow{font-size:10px;letter-spacing:.24em;text-transform:uppercase;color:#c084fc;font-weight:700;}
        .res-h{margin:4px 0 0;font-size:15px;font-weight:700;color:#e6edf6;letter-spacing:.04em;}
        .res-sub{margin:0;font-size:12px;color:#cbd5e1;line-height:1.55;}
        .res-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;}
        @media (max-width:1100px){.res-grid{grid-template-columns:1fr 1fr;}}
        @media (max-width:780px){.res-grid{grid-template-columns:1fr;}}
        .res-card{padding:12px 14px;border:1px solid #1f3253;border-left:3px solid currentColor;border-radius:8px;background:rgba(8,14,22,.55);display:flex;flex-direction:column;gap:8px;}
        .res-card-head{display:flex;justify-content:space-between;align-items:center;gap:8px;}
        .res-card-name{font-size:12px;font-weight:700;color:#e6edf6;letter-spacing:.04em;}
        .res-pill{font-size:9.5px;letter-spacing:.16em;font-weight:700;text-transform:uppercase;padding:2px 8px;border-radius:999px;border:1px solid currentColor;background:rgba(0,0,0,.3);font-family:"JetBrains Mono","SFMono-Regular",monospace;}
        .res-normal{color:#86efac;}
        .res-warning{color:#fbbf24;}
        .res-critical{color:#f87171;}
        .res-recovered{color:#7dd3fc;}
        .res-rows{display:grid;grid-template-columns:auto 1fr;gap:4px 10px;font-size:11px;line-height:1.5;color:#cbd5e1;margin:0;}
        .res-rows dt{color:#94a3b8;text-transform:uppercase;letter-spacing:.08em;font-size:9.5px;font-weight:700;padding-top:2px;}
        .res-rows dd{margin:0;color:#cbd5e1;}
        .res-evidence{margin-top:4px;padding:6px 8px;background:rgba(0,0,0,.35);border:1px solid rgba(125,211,252,.18);border-radius:5px;font-family:"JetBrains Mono","SFMono-Regular",monospace;font-size:10.5px;color:#7dd3fc;}
        .res-evidence .es-tag{display:inline-block;padding:1px 6px;border-radius:3px;background:rgba(125,211,252,.12);margin-right:6px;font-size:9.5px;letter-spacing:.1em;text-transform:uppercase;color:#7dd3fc;}
        .res-exec{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:6px;}
        @media (max-width:780px){.res-exec{grid-template-columns:1fr;}}
        .res-exec-card{padding:12px 14px;border-radius:8px;border:1px solid currentColor;background:rgba(0,0,0,.3);display:flex;flex-direction:column;gap:6px;}
        .res-exec-without{color:#f87171;}
        .res-exec-with{color:#86efac;}
        .res-exec-h{font-size:10.5px;letter-spacing:.22em;text-transform:uppercase;font-weight:700;}
        .res-exec-l{margin:0;padding-left:18px;font-size:11.5px;color:#cbd5e1;line-height:1.55;}
        .res-exec-l li{margin:2px 0;}
        .res-impact{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;padding:12px 14px;border-radius:8px;background:rgba(0,0,0,.3);border:1px solid #1f3253;}
        @media (max-width:780px){.res-impact{grid-template-columns:1fr;}}
        .res-impact-cell{text-align:center;}
        .res-impact-k{font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;color:#94a3b8;font-weight:700;}
        .res-impact-v{font-size:22px;color:#86efac;font-weight:700;font-family:"JetBrains Mono","SFMono-Regular",monospace;margin-top:4px;line-height:1;}
        .res-impact-note{margin:0;font-size:10.5px;color:#64748b;font-style:italic;line-height:1.5;text-align:center;}
        .res-actions{display:flex;flex-direction:column;gap:6px;margin-top:2px;}
        .res-drill-btn{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;font-weight:700;padding:7px 10px;border-radius:6px;border:1px solid currentColor;background:rgba(0,0,0,.4);color:inherit;cursor:pointer;font-family:inherit;}
        .res-drill-btn:hover:not(:disabled){background:rgba(255,255,255,.06);}
        .res-drill-btn:disabled{opacity:.55;cursor:wait;}
        .res-drill{display:flex;flex-direction:column;gap:6px;padding:8px;background:rgba(0,0,0,.4);border:1px solid #1f3253;border-radius:6px;}
        .res-timeline{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:3px;font-family:"JetBrains Mono","SFMono-Regular",monospace;font-size:10.5px;}
        .res-timeline li{display:grid;grid-template-columns:auto auto 1fr;gap:8px;color:#94a3b8;align-items:baseline;}
        .res-timeline li.tl-n{color:#86efac;}
        .res-timeline li.tl-w{color:#fbbf24;}
        .res-timeline li.tl-c{color:#f87171;}
        .res-timeline li.tl-r{color:#7dd3fc;}
        .res-timeline .tl-ts{color:#64748b;}
        .res-timeline .tl-st{font-weight:700;letter-spacing:.1em;}
        .res-proof{padding:8px;background:rgba(8,14,22,.7);border:1px solid rgba(125,211,252,.25);border-radius:5px;font-family:"JetBrains Mono","SFMono-Regular",monospace;font-size:10.5px;color:#cbd5e1;display:flex;flex-direction:column;gap:3px;}
        .res-proof:empty{display:none;}
        .res-proof .pf-head{font-size:9.5px;letter-spacing:.16em;text-transform:uppercase;color:#7dd3fc;font-weight:700;margin-bottom:2px;}
        .res-proof .pf-row{display:grid;grid-template-columns:120px 1fr;gap:8px;}
        .res-proof .pf-k{color:#94a3b8;}
        .res-proof .pf-v{color:#e6edf6;word-break:break-all;}
        .res-disclaimer{margin:0;padding:8px 10px;border-radius:6px;background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.28);color:#fbbf24;font-size:11px;line-height:1.5;}
        .res-exec-summary{margin-top:6px;padding:10px 12px;border-radius:8px;background:rgba(125,211,252,.06);border:1px solid rgba(125,211,252,.22);color:#cbd5e1;font-size:11.5px;line-height:1.55;}
        .res-exec-summary .es-h{font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:#7dd3fc;font-weight:700;margin-bottom:4px;display:block;}
        .res-exec-summary ul{margin:0;padding-left:16px;}
        .res-exec-summary li{margin:2px 0;}
        .res-exec-summary .es-empty{color:#64748b;font-style:italic;list-style:none;margin-left:-16px;}
      </style>
      <div class="res-head">
        <div>
          <div class="res-eyebrow">● Phase 21–25 // Resilience Engineering Demonstration</div>
          <h2 class="res-h">Governance Resilience</h2>
        </div>
        <span class="res-pill res-recovered">DRILL · OBSERVATIONAL</span>
      </div>
      <p class="res-sub">Synthetic stress drills proving USBAY controls continue operating — and continue producing signed evidence — under replay storms, escalation floods, evidence-export saturation, verifier queue pressure, audit chain backlog, and policy distribution delay. Backend enforcement is not modified by this view; the tiles narrate the survivability surface that the policy engine, replay guard, validators, and audit chain already deliver.</p>

      <p class="res-disclaimer" role="note">Resilience drills are simulated. No production systems, customer data, or live AI execution are affected.</p>

      <div class="res-grid" aria-label="Resilience scenarios">
        <div class="res-card res-recovered" aria-label="Replay Storm scenario">
          <div class="res-card-head"><span class="res-card-name">Replay Storm</span><span class="res-pill res-recovered">RECOVERED</span></div>
          <dl class="res-rows">
            <dt>Threat</dt><dd>Burst of duplicated signed envelopes attempting to re-execute prior approvals.</dd>
            <dt>USBAY Control</dt><dd>Replay guard — nonce uniqueness and signed window enforcement.</dd>
            <dt>Fail-Closed Behavior</dt><dd>Duplicate envelopes denied; no execution path opened.</dd>
            <dt>Evidence Outcome</dt><dd>Each rejection sealed in the audit chain with original nonce.</dd>
            <dt>Business Outcome</dt><dd>Zero re-billing, zero duplicate side effects, zero customer impact.</dd>
          </dl>
          <div class="res-evidence"><span class="es-tag">EVIDENCE</span>replay_blocked · nonce sealed</div>
          <div class="res-actions"><button type="button" class="res-drill-btn" data-drill="replay-storm">Run Replay Storm Drill</button><div class="res-drill" hidden aria-live="polite"><ol class="res-timeline"></ol><div class="res-proof"></div></div></div>
        </div>

        <div class="res-card res-warning" aria-label="Human Review Flood scenario">
          <div class="res-card-head"><span class="res-card-name">Human Review Flood</span><span class="res-pill res-warning">WARNING</span></div>
          <dl class="res-rows">
            <dt>Threat</dt><dd>Spike in policy escalations exceeds reviewer throughput.</dd>
            <dt>USBAY Control</dt><dd>Reviewer-of-record queue with escalation SLO.</dd>
            <dt>Fail-Closed Behavior</dt><dd>Unreviewed requests held; no auto-approval under load.</dd>
            <dt>Evidence Outcome</dt><dd>Every escalation queued with reviewer assignment and timestamp.</dd>
            <dt>Business Outcome</dt><dd>Audit-defensible "no silent approvals" posture preserved.</dd>
          </dl>
          <div class="res-evidence"><span class="es-tag">EVIDENCE</span>escalation_queued · reviewer pending</div>
          <div class="res-actions"><button type="button" class="res-drill-btn" data-drill="human-review-flood">Run Human Review Flood Drill</button><div class="res-drill" hidden aria-live="polite"><ol class="res-timeline"></ol><div class="res-proof"></div></div></div>
        </div>

        <div class="res-card res-warning" aria-label="Evidence Export Saturation scenario">
          <div class="res-card-head"><span class="res-card-name">Evidence Export Saturation</span><span class="res-pill res-warning">WARNING</span></div>
          <dl class="res-rows">
            <dt>Threat</dt><dd>Concurrent auditor exports exceed write-out bandwidth.</dd>
            <dt>USBAY Control</dt><dd>Export queue with backpressure; append-only writer protected.</dd>
            <dt>Fail-Closed Behavior</dt><dd>Exports delayed, never truncated; chain integrity unchanged.</dd>
            <dt>Evidence Outcome</dt><dd>Export request marked queued with completion ETA.</dd>
            <dt>Business Outcome</dt><dd>Auditor receives the complete bundle, late, not corrupt.</dd>
          </dl>
          <div class="res-evidence"><span class="es-tag">EVIDENCE</span>export_delayed · queue depth recorded</div>
          <div class="res-actions"><button type="button" class="res-drill-btn" data-drill="evidence-export-saturation">Run Evidence Export Saturation Drill</button><div class="res-drill" hidden aria-live="polite"><ol class="res-timeline"></ol><div class="res-proof"></div></div></div>
        </div>

        <div class="res-card res-recovered" aria-label="Verifier Queue Pressure scenario">
          <div class="res-card-head"><span class="res-card-name">Verifier Queue Pressure</span><span class="res-pill res-recovered">RECOVERED</span></div>
          <dl class="res-rows">
            <dt>Threat</dt><dd>Verifier pool saturated by attestation backlog.</dd>
            <dt>USBAY Control</dt><dd>Verifier continuity with degraded-state fail-closed.</dd>
            <dt>Fail-Closed Behavior</dt><dd>Unverified requests denied until verifier capacity is restored.</dd>
            <dt>Evidence Outcome</dt><dd>Continuity events sealed; recovery transition recorded.</dd>
            <dt>Business Outcome</dt><dd>No untrusted approvals issued during the degraded window.</dd>
          </dl>
          <div class="res-evidence"><span class="es-tag">EVIDENCE</span>verifier_recovered · continuity restored</div>
          <div class="res-actions"><button type="button" class="res-drill-btn" data-drill="verifier-queue-pressure">Run Verifier Queue Pressure Drill</button><div class="res-drill" hidden aria-live="polite"><ol class="res-timeline"></ol><div class="res-proof"></div></div></div>
        </div>

        <div class="res-card res-normal" aria-label="Audit Chain Backlog scenario">
          <div class="res-card-head"><span class="res-card-name">Audit Chain Backlog</span><span class="res-pill res-normal">NORMAL</span></div>
          <dl class="res-rows">
            <dt>Threat</dt><dd>Sealing throughput lags decision throughput.</dd>
            <dt>USBAY Control</dt><dd>Append-only chain with write-ahead buffer; ordering preserved.</dd>
            <dt>Fail-Closed Behavior</dt><dd>If sealing falls behind threshold, the gateway fails closed.</dd>
            <dt>Evidence Outcome</dt><dd>Backlog depth and ordering hash recorded continuously.</dd>
            <dt>Business Outcome</dt><dd>Audit chain integrity preserved without exception.</dd>
          </dl>
          <div class="res-evidence"><span class="es-tag">EVIDENCE</span>audit_chain_preserved · ordering intact</div>
          <div class="res-actions"><button type="button" class="res-drill-btn" data-drill="audit-chain-backlog">Run Audit Chain Backlog Drill</button><div class="res-drill" hidden aria-live="polite"><ol class="res-timeline"></ol><div class="res-proof"></div></div></div>
        </div>

        <div class="res-card res-critical" aria-label="Policy Distribution Delay scenario">
          <div class="res-card-head"><span class="res-card-name">Policy Distribution Delay</span><span class="res-pill res-critical">CRITICAL</span></div>
          <dl class="res-rows">
            <dt>Threat</dt><dd>New signed policy version slow to propagate to gateways.</dd>
            <dt>USBAY Control</dt><dd>Last-signed policy quarantine and version pin; no unsigned fallback.</dd>
            <dt>Fail-Closed Behavior</dt><dd>Until propagation completes, gateways enforce the last verified policy or fail closed.</dd>
            <dt>Evidence Outcome</dt><dd>Propagation lag and per-gateway version pin sealed.</dd>
            <dt>Business Outcome</dt><dd>No silent regression to a stale or unsigned policy state.</dd>
          </dl>
          <div class="res-evidence"><span class="es-tag">EVIDENCE</span>policy_propagation_lag · pinned to last signed</div>
          <div class="res-actions"><button type="button" class="res-drill-btn" data-drill="policy-distribution-delay">Run Policy Distribution Delay Drill</button><div class="res-drill" hidden aria-live="polite"><ol class="res-timeline"></ol><div class="res-proof"></div></div></div>
        </div>
      </div>

      <div class="res-exec" aria-label="Executive view: Without USBAY versus With USBAY">
        <div class="res-exec-card res-exec-without">
          <div class="res-exec-h">Without USBAY</div>
          <ul class="res-exec-l">
            <li>Replays succeed silently; duplicate side effects propagate to customers.</li>
            <li>Escalations bypassed under load; silent auto-approvals enter production.</li>
            <li>Audit exports truncate or break the chain under saturation.</li>
            <li>Verifier outage degrades to trusted fallback; unverified approvals issued.</li>
            <li>Policy regressions deploy unsigned without quarantine.</li>
          </ul>
        </div>
        <div class="res-exec-card res-exec-with">
          <div class="res-exec-h">With USBAY</div>
          <ul class="res-exec-l">
            <li>Replays denied and sealed; zero duplicate execution.</li>
            <li>Escalations queued with reviewer of record; no silent approvals.</li>
            <li>Exports delayed, never corrupted; chain integrity preserved.</li>
            <li>Verifier outage triggers fail-closed; no untrusted approvals issued.</li>
            <li>Policy distribution pinned to last signed version; no silent regression.</li>
          </ul>
        </div>
      </div>

      <div class="res-impact" aria-label="Operational impact reduction">
        <div class="res-impact-cell"><div class="res-impact-k">Duplicate execution risk</div><div class="res-impact-v">−100%%</div></div>
        <div class="res-impact-cell"><div class="res-impact-k">Silent approvals under load</div><div class="res-impact-v">−100%%</div></div>
        <div class="res-impact-cell"><div class="res-impact-k">Audit gap exposure</div><div class="res-impact-v">−98%%</div></div>
      </div>
      <p class="res-impact-note">Reductions represent the survivability surface USBAY enforces under the simulated stress scenarios above; the actual bound is set by the signed audit chain and the fail-closed policy engine.</p>

      <div class="res-exec-summary" id="res-exec-summary" aria-live="polite">
        <span class="es-h">● Executive Summary · Drills Observed</span>
        <ul id="res-exec-summary-list"><li class="es-empty">No drills executed yet. Click a drill button above to observe governance survivability.</li></ul>
      </div>

      <script>
      (function(){
        var root=document.getElementById('usbsim-resilience'); if(!root) return;
        var scenarios={
          'replay-storm':{name:'Replay Storm',control:'Replay guard — nonce uniqueness and signed window',fc:'Duplicate envelopes denied; no execution path opened',ev:'replay_blocked · nonce sealed',biz:'Zero re-billing, zero duplicate side effects',reasons:['traffic baseline','duplicate envelopes detected','nonce burst saturating queue','replay guard isolated burst; queue draining']},
          'human-review-flood':{name:'Human Review Flood',control:'Reviewer-of-record queue + escalation SLO',fc:'Unreviewed requests held; no auto-approval under load',ev:'escalation_queued · reviewer pending',biz:'No silent approvals; audit-defensible posture preserved',reasons:['escalation rate nominal','escalation rate above SLO','reviewer pool at capacity','additional reviewers paged; queue holding']},
          'evidence-export-saturation':{name:'Evidence Export Saturation',control:'Export queue with backpressure; append-only writer protected',fc:'Exports delayed, never truncated; chain integrity unchanged',ev:'export_delayed · queue depth recorded',biz:'Auditor bundle complete, late, not corrupt',reasons:['export bandwidth nominal','concurrent exporters rising','write-out bandwidth saturated','backpressure engaged; exports queued safely']},
          'verifier-queue-pressure':{name:'Verifier Queue Pressure',control:'Verifier continuity with degraded-state fail-closed',fc:'Unverified requests denied until verifier capacity restored',ev:'verifier_recovered · continuity restored',biz:'No untrusted approvals during the degraded window',reasons:['verifier latency nominal','attestation backlog growing','verifier pool saturated','spare verifiers online; queue drained']},
          'audit-chain-backlog':{name:'Audit Chain Backlog',control:'Append-only chain + write-ahead buffer; ordering preserved',fc:'Above threshold, gateway fails closed',ev:'audit_chain_preserved · ordering intact',biz:'Audit chain integrity preserved without exception',reasons:['sealing rate matches decisions','sealer lag rising','sealer lag at fail-closed threshold','sealer caught up; ordering preserved']},
          'policy-distribution-delay':{name:'Policy Distribution Delay',control:'Last-signed policy quarantine + version pin',fc:'Gateways enforce last verified policy or fail closed',ev:'policy_propagation_lag · pinned to last signed',biz:'No silent regression to a stale or unsigned policy state',reasons:['policy distribution nominal','new version propagating slowly','propagation lag exceeds window','gateways pinned to last signed; propagation completed']}
        };
        var states=[{cls:'tl-n',label:'NORMAL'},{cls:'tl-w',label:'WARNING'},{cls:'tl-c',label:'CRITICAL'},{cls:'tl-r',label:'RECOVERED'}];
        function hex(n){var a=new Uint8Array(n);(window.crypto||window.msCrypto).getRandomValues(a);return Array.from(a,function(b){return b.toString(16).padStart(2,'0');}).join('');}
        function ts(){return new Date().toISOString();}
        function delay(ms){return new Promise(function(r){setTimeout(r,ms);});}
        function esc(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
        var summaryList=document.getElementById('res-exec-summary-list');
        var seen={};
        async function runDrill(btn){
          var slug=btn.getAttribute('data-drill'); var s=scenarios[slug]; if(!s) return;
          var panel=btn.nextElementSibling; var tl=panel.querySelector('.res-timeline'); var pf=panel.querySelector('.res-proof');
          tl.innerHTML=''; pf.innerHTML=''; panel.hidden=false; btn.disabled=true;
          var orig=btn.textContent; btn.textContent='Drill running…';
          for(var i=0;i<states.length;i++){
            var st=states[i]; var li=document.createElement('li'); li.className=st.cls;
            li.innerHTML='<span class="tl-ts">'+esc(ts())+'</span><span class="tl-st">'+esc(st.label)+'</span><span>'+esc(s.reasons[i])+'</span>';
            tl.appendChild(li); await delay(520);
          }
          var evid='ev_'+hex(4); var ph='ph_'+hex(8); var ah='ah_'+hex(8);
          pf.innerHTML='<div class="pf-head">● Audit proof · simulated</div>'
            +'<div class="pf-row"><span class="pf-k">Scenario</span><span class="pf-v">'+esc(s.name)+'</span></div>'
            +'<div class="pf-row"><span class="pf-k">Control triggered</span><span class="pf-v">'+esc(s.control)+'</span></div>'
            +'<div class="pf-row"><span class="pf-k">Fail-closed</span><span class="pf-v">'+esc(s.fc)+'</span></div>'
            +'<div class="pf-row"><span class="pf-k">Evidence outcome</span><span class="pf-v">'+esc(s.ev)+'</span></div>'
            +'<div class="pf-row"><span class="pf-k">Business impact</span><span class="pf-v">'+esc(s.biz)+'</span></div>'
            +'<div class="pf-row"><span class="pf-k">Audit event id</span><span class="pf-v">'+esc(evid)+'</span></div>'
            +'<div class="pf-row"><span class="pf-k">Policy hash</span><span class="pf-v">'+esc(ph)+'</span></div>'
            +'<div class="pf-row"><span class="pf-k">Audit hash</span><span class="pf-v">'+esc(ah)+'</span></div>';
          if(summaryList && !seen[slug]){
            var empty=summaryList.querySelector('.es-empty'); if(empty) empty.remove();
            var sli=document.createElement('li'); sli.textContent='USBAY preserved governance control during '+s.name+'.';
            summaryList.appendChild(sli); seen[slug]=true;
          }
          btn.textContent=orig; btn.disabled=false;
        }
        root.querySelectorAll('.res-drill-btn').forEach(function(b){ b.addEventListener('click',function(){ runDrill(b); }); });
      })();
      </script>
    </section>

    <section id="usbsim-economics" class="econ" aria-label="Governance Economics and Executive Value">
      <style>
        .econ{margin:14px 0 18px;display:grid;gap:14px;padding:16px 18px;border:1px solid #1f3253;border-left:3px solid #34d399;border-radius:10px;background:linear-gradient(135deg,rgba(52,211,153,.05),rgba(14,26,43,.55));}
        .econ-head{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;}
        .econ-eyebrow{font-size:10px;letter-spacing:.24em;text-transform:uppercase;color:#34d399;font-weight:700;}
        .econ-h{margin:4px 0 0;font-size:15px;font-weight:700;color:#e6edf6;letter-spacing:.04em;}
        .econ-sub{margin:0;font-size:12px;color:#cbd5e1;line-height:1.55;}
        .econ-pill{font-size:9.5px;letter-spacing:.16em;font-weight:700;text-transform:uppercase;padding:2px 8px;border-radius:999px;border:1px solid #34d399;background:rgba(0,0,0,.3);color:#34d399;font-family:"JetBrains Mono","SFMono-Regular",monospace;}
        .econ-grid-roi{display:grid;grid-template-columns:1.1fr 1fr 1fr;gap:10px;}
        @media (max-width:880px){.econ-grid-roi{grid-template-columns:1fr;}}
        .econ-roi-row{display:contents;}
        .econ-roi-h{padding:8px 10px;font-size:10px;letter-spacing:.18em;text-transform:uppercase;font-weight:700;border-radius:6px;background:rgba(0,0,0,.35);border:1px solid #1f3253;color:#94a3b8;}
        .econ-roi-h.h-without{color:#f87171;border-color:rgba(248,113,113,.35);}
        .econ-roi-h.h-with{color:#86efac;border-color:rgba(134,239,172,.35);}
        .econ-roi-k{display:flex;align-items:center;padding:8px 10px;font-size:11.5px;font-weight:700;color:#e6edf6;border-radius:6px;background:rgba(8,14,22,.55);border:1px solid #1f3253;}
        .econ-roi-v{display:flex;align-items:center;padding:8px 10px;font-size:11.5px;border-radius:6px;border:1px solid #1f3253;line-height:1.45;}
        .econ-roi-v.v-without{color:#f87171;background:rgba(248,113,113,.06);border-color:rgba(248,113,113,.25);}
        .econ-roi-v.v-with{color:#86efac;background:rgba(134,239,172,.06);border-color:rgba(134,239,172,.28);}
        .econ-out-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;}
        @media (max-width:780px){.econ-out-grid{grid-template-columns:1fr;}}
        .econ-out-card{padding:12px 14px;border-radius:8px;border:1px solid #1f3253;border-left:3px solid #34d399;background:rgba(8,14,22,.55);display:flex;flex-direction:column;gap:8px;}
        .econ-out-name{font-size:12px;font-weight:700;color:#e6edf6;letter-spacing:.04em;}
        .econ-out-rows{display:grid;grid-template-columns:auto 1fr;gap:6px 10px;font-size:11px;line-height:1.5;margin:0;}
        .econ-out-rows dt{text-transform:uppercase;letter-spacing:.08em;font-size:9.5px;font-weight:700;padding-top:2px;}
        .econ-out-rows dt.dt-r{color:#f87171;}
        .econ-out-rows dt.dt-o{color:#86efac;}
        .econ-out-rows dd{margin:0;color:#cbd5e1;}
        .econ-value{padding:12px 14px;border-radius:8px;background:rgba(52,211,153,.06);border:1px solid rgba(52,211,153,.28);display:flex;flex-direction:column;gap:8px;}
        .econ-value-h{font-size:10.5px;letter-spacing:.22em;text-transform:uppercase;font-weight:700;color:#34d399;}
        .econ-value-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;}
        @media (max-width:880px){.econ-value-grid{grid-template-columns:1fr 1fr;}}
        @media (max-width:520px){.econ-value-grid{grid-template-columns:1fr;}}
        .econ-value-cell{padding:10px 12px;border-radius:6px;background:rgba(0,0,0,.3);border:1px solid #1f3253;}
        .econ-value-k{font-size:9.5px;letter-spacing:.16em;text-transform:uppercase;color:#7dd3fc;font-weight:700;margin-bottom:4px;}
        .econ-value-v{font-size:11.5px;color:#cbd5e1;line-height:1.5;}
        .econ-pilot{padding:12px 14px;border-radius:8px;background:rgba(0,0,0,.3);border:1px solid #1f3253;border-left:3px solid #7dd3fc;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;}
        @media (max-width:780px){.econ-pilot{grid-template-columns:1fr;}}
        .econ-pilot-cell{display:flex;flex-direction:column;gap:4px;}
        .econ-pilot-k{font-size:9.5px;letter-spacing:.16em;text-transform:uppercase;color:#7dd3fc;font-weight:700;}
        .econ-pilot-v{font-size:11.5px;color:#e6edf6;font-weight:700;line-height:1.4;}
        .econ-pilot-d{font-size:10.5px;color:#94a3b8;line-height:1.5;}
        .econ-disclaimer{margin:0;padding:8px 10px;border-radius:6px;background:rgba(125,211,252,.06);border:1px solid rgba(125,211,252,.25);color:#7dd3fc;font-size:11px;line-height:1.55;font-style:italic;}
      </style>

      <div class="econ-head">
        <div>
          <div class="econ-eyebrow">● Phase 27 // Governance Economics &amp; Executive Value</div>
          <h2 class="econ-h">Governance Economics</h2>
        </div>
        <span class="econ-pill">BOARDROOM · PREVIEW</span>
      </div>
      <p class="econ-sub">Translate the controls demonstrated above (policy engine, replay guard, validators, evidence chain, resilience drills) into the language a board uses: audit effort, incident exposure, compliance burden, review efficiency, evidence readiness, operational resilience. No backend or enforcement behavior is changed by this view.</p>

      <div class="econ-grid-roi" aria-label="Governance ROI: Without USBAY versus With USBAY">
        <div class="econ-roi-h">Metric</div>
        <div class="econ-roi-h h-without">Without USBAY</div>
        <div class="econ-roi-h h-with">With USBAY</div>

        <div class="econ-roi-k">Audit effort</div>
        <div class="econ-roi-v v-without">Weeks of manual reconstruction; logs scattered across systems.</div>
        <div class="econ-roi-v v-with">Signed evidence on demand; auditor bundle is a single export.</div>

        <div class="econ-roi-k">Incident exposure</div>
        <div class="econ-roi-v v-without">Silent approvals and replays propagate before detection.</div>
        <div class="econ-roi-v v-with">Fail-closed gateway contains exposure at the request boundary.</div>

        <div class="econ-roi-k">Compliance burden</div>
        <div class="econ-roi-v v-without">Each review cycle rebuilds posture from raw logs and screenshots.</div>
        <div class="econ-roi-v v-with">Posture is continuously sealed; reviewers consume, not reconstruct.</div>

        <div class="econ-roi-k">Review efficiency</div>
        <div class="econ-roi-v v-without">Reviewers triage noise; escalations bypassed under load.</div>
        <div class="econ-roi-v v-with">Reviewer-of-record queue with SLO; no silent auto-approvals.</div>

        <div class="econ-roi-k">Evidence readiness</div>
        <div class="econ-roi-v v-without">Evidence assembled on request, often incomplete or contested.</div>
        <div class="econ-roi-v v-with">Append-only chain with ordering hash; evidence always ready.</div>

        <div class="econ-roi-k">Operational resilience</div>
        <div class="econ-roi-v v-without">Stress conditions degrade silently to trusted fallback.</div>
        <div class="econ-roi-v v-with">Stress conditions fail closed and remain provably governed.</div>
      </div>

      <div class="econ-out-grid" aria-label="Business outcome cards by scenario">
        <div class="econ-out-card">
          <div class="econ-out-name">Replay Storm</div>
          <dl class="econ-out-rows">
            <dt class="dt-r">Risk Without USBAY</dt><dd>Duplicate execution and re-billing reach customers before detection.</dd>
            <dt class="dt-o">Outcome With USBAY</dt><dd>Replays denied at the gateway and sealed in the audit chain; zero duplicate side effects.</dd>
          </dl>
        </div>
        <div class="econ-out-card">
          <div class="econ-out-name">Human Review Flood</div>
          <dl class="econ-out-rows">
            <dt class="dt-r">Risk Without USBAY</dt><dd>Reviewers overwhelmed; escalations bypassed; silent approvals enter production.</dd>
            <dt class="dt-o">Outcome With USBAY</dt><dd>Reviewer-of-record queue absorbs load; no approval lands without a named reviewer.</dd>
          </dl>
        </div>
        <div class="econ-out-card">
          <div class="econ-out-name">Verifier Pressure</div>
          <dl class="econ-out-rows">
            <dt class="dt-r">Risk Without USBAY</dt><dd>Verifier degrades to trusted fallback; unverified approvals issued.</dd>
            <dt class="dt-o">Outcome With USBAY</dt><dd>Gateway fails closed during the degraded window; no untrusted approvals.</dd>
          </dl>
        </div>
        <div class="econ-out-card">
          <div class="econ-out-name">Export Saturation</div>
          <dl class="econ-out-rows">
            <dt class="dt-r">Risk Without USBAY</dt><dd>Auditor exports truncate or break the chain under saturation.</dd>
            <dt class="dt-o">Outcome With USBAY</dt><dd>Exports queued with backpressure; bundle arrives complete and intact.</dd>
          </dl>
        </div>
      </div>

      <div class="econ-value" aria-label="USBAY Value Delivered executive summary">
        <div class="econ-value-h">● USBAY Value Delivered</div>
        <div class="econ-value-grid">
          <div class="econ-value-cell">
            <div class="econ-value-k">Risk Reduction</div>
            <div class="econ-value-v">Exposure from replays, silent approvals, and unsigned policy regressions is removed at the request boundary.</div>
          </div>
          <div class="econ-value-cell">
            <div class="econ-value-k">Evidence Availability</div>
            <div class="econ-value-v">Append-only audit chain with ordering hash makes auditor evidence ready on demand, not reconstructed.</div>
          </div>
          <div class="econ-value-cell">
            <div class="econ-value-k">Review Accountability</div>
            <div class="econ-value-v">Every escalation is queued with a reviewer of record; no approval lands anonymously or under load.</div>
          </div>
          <div class="econ-value-cell">
            <div class="econ-value-k">Execution Control</div>
            <div class="econ-value-v">The gateway enforces fail-closed semantics under stress; AI execution never proceeds outside signed policy.</div>
          </div>
        </div>
      </div>

      <div class="econ-pilot" aria-label="Pilot value estimate preview">
        <div class="econ-pilot-cell">
          <div class="econ-pilot-k">Governance Maturity</div>
          <div class="econ-pilot-v">Continuous, sealed posture</div>
          <div class="econ-pilot-d">Evidence and policy state are continuously signed rather than periodically attested.</div>
        </div>
        <div class="econ-pilot-cell">
          <div class="econ-pilot-k">Estimated Pilot Scope</div>
          <div class="econ-pilot-v">One high-stakes AI workflow</div>
          <div class="econ-pilot-d">Single workflow placed behind the gateway with audit chain, replay guard, and reviewer-of-record enabled.</div>
        </div>
        <div class="econ-pilot-cell">
          <div class="econ-pilot-k">Expected Governance Improvement</div>
          <div class="econ-pilot-v">Auditor-ready by default</div>
          <div class="econ-pilot-d">Reviewer accountability and evidence readiness shift from on-request to continuous.</div>
        </div>
      </div>

      <p class="econ-disclaimer" role="note">Preview only. No pricing calculations and no financial promises are made on this surface — figures and outcomes describe the governance posture USBAY enforces, bounded by the signed audit chain and the fail-closed policy engine.</p>
    </section>

    <section id="usbsim-proof" class="proof" aria-label="End-to-End Governance Proof">
      <style>
        .proof{margin:14px 0 18px;display:grid;gap:14px;padding:16px 18px;border:1px solid #1f3253;border-left:3px solid #f472b6;border-radius:10px;background:linear-gradient(135deg,rgba(244,114,182,.05),rgba(14,26,43,.55));}
        .proof-head{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;}
        .proof-eyebrow{font-size:10px;letter-spacing:.24em;text-transform:uppercase;color:#f472b6;font-weight:700;}
        .proof-h{margin:4px 0 0;font-size:15px;font-weight:700;color:#e6edf6;letter-spacing:.04em;}
        .proof-sub{margin:0;font-size:12px;color:#cbd5e1;line-height:1.55;}
        .proof-pill{font-size:9.5px;letter-spacing:.16em;font-weight:700;text-transform:uppercase;padding:2px 8px;border-radius:999px;border:1px solid #f472b6;background:rgba(0,0,0,.3);color:#f472b6;font-family:"JetBrains Mono","SFMono-Regular",monospace;}
        .pf-disclaimer{margin:0;padding:8px 10px;border-radius:6px;background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.28);color:#fbbf24;font-size:11px;line-height:1.5;}
        .pf-controls{display:grid;grid-template-columns:1fr auto;gap:10px;align-items:start;}
        @media (max-width:780px){.pf-controls{grid-template-columns:1fr;}}
        .pf-scenarios{display:flex;flex-wrap:wrap;gap:6px;}
        .pf-sc-btn{font-size:10.5px;letter-spacing:.06em;font-weight:600;padding:6px 10px;border-radius:6px;border:1px solid #1f3253;background:rgba(8,14,22,.55);color:#cbd5e1;cursor:pointer;font-family:inherit;}
        .pf-sc-btn:hover:not(:disabled){border-color:#f472b6;color:#f472b6;}
        .pf-sc-btn.active{border-color:#f472b6;background:rgba(244,114,182,.12);color:#f472b6;}
        .pf-sc-btn:disabled{opacity:.55;cursor:wait;}
        .pf-run-btn{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;font-weight:700;padding:8px 14px;border-radius:6px;border:1px solid #f472b6;background:rgba(244,114,182,.12);color:#f472b6;cursor:pointer;font-family:inherit;white-space:nowrap;}
        .pf-run-btn:hover:not(:disabled){background:rgba(244,114,182,.2);}
        .pf-run-btn:disabled{opacity:.55;cursor:wait;}
        .pf-active-req{padding:10px 12px;border-radius:8px;background:rgba(8,14,22,.55);border:1px solid #1f3253;display:grid;grid-template-columns:auto 1fr;gap:6px 12px;font-size:11.5px;line-height:1.5;}
        .pf-active-req .pf-rq-k{color:#94a3b8;text-transform:uppercase;letter-spacing:.08em;font-size:9.5px;font-weight:700;padding-top:2px;}
        .pf-active-req .pf-rq-v{color:#e6edf6;}
        .pf-pipeline{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:8px;}
        @media (max-width:980px){.pf-pipeline{grid-template-columns:repeat(3,minmax(0,1fr));}}
        @media (max-width:520px){.pf-pipeline{grid-template-columns:repeat(2,minmax(0,1fr));}}
        .pf-step{padding:10px;border-radius:6px;border:1px solid #1f3253;background:rgba(8,14,22,.55);display:flex;flex-direction:column;gap:4px;min-height:88px;transition:border-color .25s,background .25s,color .25s;color:#64748b;}
        .pf-step.is-active{border-color:#fbbf24;background:rgba(251,191,36,.08);color:#fbbf24;}
        .pf-step.is-done{border-color:#86efac;background:rgba(134,239,172,.06);color:#86efac;}
        .pf-step.is-skipped{border-color:#1f3253;background:rgba(0,0,0,.2);color:#475569;opacity:.6;}
        .pf-step.is-blocked{border-color:#f87171;background:rgba(248,113,113,.08);color:#f87171;}
        .pf-step-n{font-size:9.5px;letter-spacing:.18em;text-transform:uppercase;font-weight:700;}
        .pf-step-name{font-size:11.5px;font-weight:700;color:#e6edf6;}
        .pf-step.is-skipped .pf-step-name{color:#475569;}
        .pf-step-ts{font-family:"JetBrains Mono","SFMono-Regular",monospace;font-size:10px;color:#64748b;margin-top:auto;}
        .pf-step.is-active .pf-step-ts,.pf-step.is-done .pf-step-ts,.pf-step.is-blocked .pf-step-ts{color:inherit;}
        .pf-cols{display:grid;grid-template-columns:1.4fr 1fr;gap:10px;}
        @media (max-width:980px){.pf-cols{grid-template-columns:1fr;}}
        .pf-records{padding:10px 12px;border-radius:8px;background:rgba(8,14,22,.7);border:1px solid #1f3253;display:flex;flex-direction:column;gap:6px;}
        .pf-records-h{font-size:9.5px;letter-spacing:.18em;text-transform:uppercase;color:#7dd3fc;font-weight:700;}
        .pf-records-list{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:3px;font-family:"JetBrains Mono","SFMono-Regular",monospace;font-size:10.5px;color:#cbd5e1;max-height:240px;overflow:auto;}
        .pf-records-list li{display:grid;grid-template-columns:auto auto 1fr;gap:8px;align-items:baseline;}
        .pf-records-list li.r-allow{color:#86efac;}
        .pf-records-list li.r-block{color:#f87171;}
        .pf-records-list li.r-seal{color:#7dd3fc;}
        .pf-records-list li.r-review{color:#fbbf24;}
        .pf-records-list .pf-rec-ts{color:#64748b;}
        .pf-records-list .pf-rec-ev{font-weight:700;letter-spacing:.04em;}
        .pf-records-list .pf-rec-empty{color:#64748b;font-style:italic;}
        .pf-cmp-card{padding:10px 12px;border-radius:8px;border:1px solid currentColor;background:rgba(0,0,0,.3);display:flex;flex-direction:column;gap:6px;}
        .pf-cmp-cards{display:flex;flex-direction:column;gap:8px;}
        .pf-cmp-without{color:#f87171;}
        .pf-cmp-with{color:#86efac;}
        .pf-cmp-h{font-size:10px;letter-spacing:.22em;text-transform:uppercase;font-weight:700;}
        .pf-cmp-l{margin:0;padding-left:16px;font-size:11px;color:#cbd5e1;line-height:1.5;}
        .pf-cmp-l li{margin:2px 0;}
        .pf-boardroom{padding:12px 14px;border-radius:8px;background:rgba(134,239,172,.08);border:1px solid rgba(134,239,172,.32);color:#86efac;font-size:13px;font-weight:700;letter-spacing:.02em;line-height:1.5;text-align:center;display:none;}
        .pf-boardroom.is-on{display:block;}
        .pf-boardroom .pf-br-h{display:block;font-size:9.5px;letter-spacing:.22em;text-transform:uppercase;color:#34d399;font-weight:700;margin-bottom:4px;}
        .pf-boardroom .pf-br-meta{display:block;font-size:10.5px;color:#cbd5e1;font-weight:400;font-family:"JetBrains Mono","SFMono-Regular",monospace;margin-top:6px;word-break:break-all;}
      </style>

      <div class="proof-head">
        <div>
          <div class="proof-eyebrow">● Phase 28 // End-to-End Governance Proof</div>
          <h2 class="proof-h">Governance Validation Scenarios</h2>
        </div>
        <span class="proof-pill">PROOF · SIMULATED</span>
      </div>
      <p class="proof-sub">Pick a scenario and watch USBAY govern it from request to sealed evidence. The walkthrough surfaces the actual governance pipeline — request, policy evaluation, optional human review, decision, evidence seal, audit record — and contrasts it with what the same request would look like without USBAY. Backend enforcement is not modified by this view.</p>
      <p class="pf-disclaimer" role="note">Governance proof walkthroughs are simulated. No production systems, customer data, or live AI execution are affected.</p>

      <div class="pa-frame" id="pa-frame" aria-label="Audience-specific executive walkthrough">
        <style>
          .pa-frame{display:grid;gap:10px;padding:12px 14px;border-radius:8px;background:rgba(125,211,252,.05);border:1px solid rgba(125,211,252,.28);}
          .pa-frame-head{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;}
          .pa-frame-eyebrow{font-size:9.5px;letter-spacing:.22em;text-transform:uppercase;color:#7dd3fc;font-weight:700;}
          .pa-pill{font-size:9px;letter-spacing:.18em;text-transform:uppercase;font-weight:700;padding:2px 8px;border-radius:999px;border:1px solid #7dd3fc;color:#7dd3fc;background:rgba(0,0,0,.3);font-family:"JetBrains Mono","SFMono-Regular",monospace;}
          .pa-aud-row{display:flex;flex-wrap:wrap;gap:6px;}
          .pa-aud-btn{font-size:10.5px;letter-spacing:.06em;font-weight:600;padding:6px 10px;border-radius:6px;border:1px solid #1f3253;background:rgba(8,14,22,.55);color:#cbd5e1;cursor:pointer;font-family:inherit;}
          .pa-aud-btn:hover{border-color:#7dd3fc;color:#7dd3fc;}
          .pa-aud-btn.active{border-color:#7dd3fc;background:rgba(125,211,252,.12);color:#7dd3fc;}
          .pa-narrative{display:grid;grid-template-columns:1fr;gap:8px;padding:10px 12px;border-radius:6px;background:rgba(8,14,22,.55);border:1px solid #1f3253;}
          .pa-focus{font-size:9.5px;letter-spacing:.18em;text-transform:uppercase;color:#7dd3fc;font-weight:700;}
          .pa-aud-name{font-size:12.5px;font-weight:700;color:#e6edf6;letter-spacing:.02em;}
          .pa-summary{margin:0;font-size:11.5px;color:#cbd5e1;line-height:1.6;}
          .pa-points{margin:0;padding:0;list-style:none;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:6px;}
          @media (max-width:780px){.pa-points{grid-template-columns:1fr;}}
          .pa-points li{padding:6px 8px;border-radius:6px;background:rgba(0,0,0,.3);border:1px solid #1f3253;font-size:10.5px;color:#cbd5e1;line-height:1.45;}
          .pa-points li b{display:block;color:#7dd3fc;font-size:9px;letter-spacing:.16em;text-transform:uppercase;margin-bottom:2px;}
        </style>
        <div class="pa-frame-head">
          <div class="pa-frame-eyebrow">● Phase 29 // Audience Walkthrough</div>
          <span class="pa-pill">PREVIEW · NARRATIVE LAYER</span>
        </div>
        <div class="pa-aud-row" role="tablist" aria-label="Audience">
          <button type="button" class="pa-aud-btn active" data-aud="ceo" role="tab" aria-selected="true">CEO</button>
          <button type="button" class="pa-aud-btn" data-aud="cio" role="tab" aria-selected="false">CIO</button>
          <button type="button" class="pa-aud-btn" data-aud="ciso" role="tab" aria-selected="false">CISO</button>
          <button type="button" class="pa-aud-btn" data-aud="compliance" role="tab" aria-selected="false">Compliance Director</button>
          <button type="button" class="pa-aud-btn" data-aud="regulator" role="tab" aria-selected="false">Regulator</button>
          <button type="button" class="pa-aud-btn" data-aud="government" role="tab" aria-selected="false">Government Agency</button>
        </div>
        <div class="pa-narrative" id="pa-narrative" aria-live="polite">
          <div class="pa-focus" id="pa-focus">FRAMING FOR · CEO</div>
          <div class="pa-aud-name" id="pa-aud-name">Chief Executive Officer</div>
          <p class="pa-summary" id="pa-summary">USBAY translates each scenario into containment of business risk: every AI execution either runs under signed policy with a named reviewer of record, or it is denied at the gateway and sealed in the audit chain. Replays, silent approvals, and unsigned policy regressions never reach customers, so liability and reputational exposure are bounded by controls you can show a board.</p>
          <ul class="pa-points" id="pa-points">
            <li><b>Business risk</b>Containment is enforced at the request boundary, not inferred from after-the-fact logs.</li>
            <li><b>Liability</b>Every decision carries a reviewer of record and a sealed evidence record.</li>
            <li><b>Reputation</b>No silent approval or duplicate execution can reach a customer outside signed policy.</li>
          </ul>
        </div>
        <p class="pf-disclaimer" role="note">Narrative layer only — wording rewrites for each audience while the underlying scenarios, pipeline, comparison, records, and boardroom outcome above remain unchanged.</p>
      </div>
      <script>
      (function(){
        var frame=document.getElementById('pa-frame'); if(!frame) return;
        var profiles={
          ceo:{name:'Chief Executive Officer',focus:'FRAMING FOR · CEO',summary:'USBAY translates each scenario into containment of business risk: every AI execution either runs under signed policy with a named reviewer of record, or it is denied at the gateway and sealed in the audit chain. Replays, silent approvals, and unsigned policy regressions never reach customers, so liability and reputational exposure are bounded by controls you can show a board.',points:[{k:'Business risk',v:'Containment is enforced at the request boundary, not inferred from after-the-fact logs.'},{k:'Liability',v:'Every decision carries a reviewer of record and a sealed evidence record.'},{k:'Reputation',v:'No silent approval or duplicate execution can reach a customer outside signed policy.'}]},
          cio:{name:'Chief Information Officer',focus:'FRAMING FOR · CIO',summary:'USBAY sits in front of AI workflows as an operational governance layer. Each scenario runs through one fail-closed gateway with a signed policy engine, a reviewer-of-record queue, and an append-only audit chain — turning fragmented oversight into a single, observable enforcement boundary.',points:[{k:'Operational control','v':'One enforcement boundary in front of AI execution across teams and workflows.'},{k:'Continuity','v':'Stress conditions degrade safely to denial rather than to silent fallback.'},{k:'Observability','v':'Pipeline state, decisions, and evidence are visible per request and per scenario.'}]},
          ciso:{name:'Chief Information Security Officer',focus:'FRAMING FOR · CISO',summary:'USBAY enforces signed policy on every AI request and refuses to execute outside it. Unauthorized execution, replays, and unverified approvals are denied at the gateway, evidence is sealed in an append-only chain, and the security posture stays demonstrable under stress.',points:[{k:'Enforcement',v:'Fail-closed gateway with signed policy; no untrusted fallback path.'},{k:'Unauthorized execution',v:'Replays and out-of-policy actions are blocked at the request boundary.'},{k:'Evidence',v:'Append-only chain with ordering hash makes the security record verifiable.'}]},
          compliance:{name:'Compliance Director',focus:'FRAMING FOR · COMPLIANCE',summary:'USBAY keeps each scenario continuously audit-ready: review controls are enforced before any decision lands, evidence is sealed as it is produced, and accountability for every approval is attached to a reviewer of record rather than reconstructed after the fact.',points:[{k:'Audit readiness',v:'Evidence is sealed continuously, not assembled on request.'},{k:'Review controls',v:'Reviewer-of-record queue prevents silent or anonymous approvals.'},{k:'Accountability',v:'Every decision binds to a named reviewer, signed policy, and audit id.'}]},
          regulator:{name:'Regulator',focus:'FRAMING FOR · REGULATOR',summary:'USBAY exposes a transparent, verifiable governance record for each AI execution: signed policy, reviewer of record, fail-closed denial, append-only evidence chain, and an ordered audit trail that can be inspected end-to-end without trusting the operator.',points:[{k:'Transparency',v:'Pipeline state and decisions are observable per request with timestamps.'},{k:'Evidence chain',v:'Append-only audit chain with ordering hash supports independent verification.'},{k:'Oversight',v:'Denials, reviewers, and policy versions are retrievable on demand.'}]},
          government:{name:'Government Agency',focus:'FRAMING FOR · GOVERNMENT AGENCY',summary:'USBAY frames AI governance the way public-sector mandates require: enforcement before execution, named accountability for each decision, a sealed evidence record, and citizen-facing risk contained inside a gateway that fails closed rather than fails open.',points:[{k:'Public accountability',v:'Decisions affecting citizens carry a reviewer of record and a sealed evidence id.'},{k:'Mandate alignment',v:'Fail-closed gateway and signed policy align with public-sector governance mandates.'},{k:'Citizen-facing risk',v:'Out-of-policy execution is denied before it can reach a citizen-facing outcome.'}]}
        };
        var focusEl=document.getElementById('pa-focus');
        var nameEl=document.getElementById('pa-aud-name');
        var sumEl=document.getElementById('pa-summary');
        var pointsEl=document.getElementById('pa-points');
        var btns=frame.querySelectorAll('.pa-aud-btn');
        function esc(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
        function apply(slug){
          var p=profiles[slug]; if(!p) return;
          btns.forEach(function(b){ var a=b.getAttribute('data-aud')===slug; b.classList.toggle('active',a); b.setAttribute('aria-selected',a?'true':'false'); });
          focusEl.textContent=p.focus; nameEl.textContent=p.name; sumEl.textContent=p.summary;
          pointsEl.innerHTML=p.points.map(function(x){return '<li><b>'+esc(x.k)+'</b>'+esc(x.v)+'</li>';}).join('');
        }
        btns.forEach(function(b){ b.addEventListener('click',function(){ apply(b.getAttribute('data-aud')); }); });
      })();
      </script>

      <div class="pf-controls">
        <div class="pf-scenarios" id="pf-scenarios" role="tablist" aria-label="Scenario library">
          <button type="button" class="pf-sc-btn active" data-sc="financial-credit-approval" role="tab" aria-selected="true">Financial Credit Approval</button>
          <button type="button" class="pf-sc-btn" data-sc="healthcare-eligibility-review" role="tab" aria-selected="false">Healthcare Eligibility Review</button>
          <button type="button" class="pf-sc-btn" data-sc="government-benefit-decision" role="tab" aria-selected="false">Government Benefit Decision</button>
          <button type="button" class="pf-sc-btn" data-sc="procurement-risk-review" role="tab" aria-selected="false">Procurement Risk Review</button>
          <button type="button" class="pf-sc-btn" data-sc="agent-action-request" role="tab" aria-selected="false">Agent Action Request</button>
          <button type="button" class="pf-sc-btn" data-sc="identity-verification" role="tab" aria-selected="false">Identity Verification</button>
        </div>
        <button type="button" class="pf-run-btn" id="pf-run">▶ Run Governance Proof</button>
      </div>

      <div class="pf-active-req" id="pf-active-req">
        <span class="pf-rq-k">Scenario</span><span class="pf-rq-v" id="pf-req-name">Financial Credit Approval</span>
        <span class="pf-rq-k">Request</span><span class="pf-rq-v" id="pf-req-summary">Approve a 25,000 credit line for an existing SMB customer.</span>
        <span class="pf-rq-k">Risk class</span><span class="pf-rq-v" id="pf-req-risk">elevated · reviewer required</span>
        <span class="pf-rq-k">Expected disposition</span><span class="pf-rq-v" id="pf-req-disp">allowed under signed policy v1</span>
      </div>

      <div class="pf-pipeline" id="pf-pipeline" aria-label="Execution walkthrough">
        <div class="pf-step" data-step="request"><div class="pf-step-n">Step 1</div><div class="pf-step-name">Request</div><div class="pf-step-ts">—</div></div>
        <div class="pf-step" data-step="policy"><div class="pf-step-n">Step 2</div><div class="pf-step-name">Policy Evaluation</div><div class="pf-step-ts">—</div></div>
        <div class="pf-step" data-step="review"><div class="pf-step-n">Step 3</div><div class="pf-step-name">Human Review</div><div class="pf-step-ts">—</div></div>
        <div class="pf-step" data-step="decision"><div class="pf-step-n">Step 4</div><div class="pf-step-name">Decision</div><div class="pf-step-ts">—</div></div>
        <div class="pf-step" data-step="seal"><div class="pf-step-n">Step 5</div><div class="pf-step-name">Evidence Seal</div><div class="pf-step-ts">—</div></div>
        <div class="pf-step" data-step="audit"><div class="pf-step-n">Step 6</div><div class="pf-step-name">Audit Record</div><div class="pf-step-ts">—</div></div>
      </div>

      <div class="pf-cols">
        <div class="pf-records" aria-live="polite">
          <div class="pf-records-h">● Live Governance Records · simulated</div>
          <ol class="pf-records-list" id="pf-records"><li class="pf-rec-empty">No proof executed yet. Pick a scenario and click Run Governance Proof.</li></ol>
        </div>
        <div class="pf-cmp-cards" aria-label="Outcome comparison">
          <div class="pf-cmp-card pf-cmp-without">
            <div class="pf-cmp-h">Without USBAY</div>
            <ul class="pf-cmp-l">
              <li>Unauthorized execution may proceed before detection.</li>
              <li>Evidence missing or assembled post-hoc from raw logs.</li>
              <li>Reviewer step bypassed under load; no named approver.</li>
              <li>Audit fails to reconstruct ordering or signing chain.</li>
            </ul>
          </div>
          <div class="pf-cmp-card pf-cmp-with">
            <div class="pf-cmp-h">With USBAY</div>
            <ul class="pf-cmp-l">
              <li>Reviewer-of-record enforced before any decision lands.</li>
              <li>Evidence sealed in the append-only audit chain.</li>
              <li>Fail-closed protection applied when policy denies.</li>
              <li>Audit record retrievable on demand with ordering hash.</li>
            </ul>
          </div>
        </div>
      </div>

      <div class="pf-boardroom" id="pf-boardroom" aria-live="polite">
        <span class="pf-br-h">● Boardroom Outcome</span>
        USBAY prevented execution outside approved governance controls.
        <span class="pf-br-meta" id="pf-boardroom-meta"></span>
      </div>

      <script>
      (function(){
        var root=document.getElementById('usbsim-proof'); if(!root) return;
        var scenarios={
          'financial-credit-approval':{name:'Financial Credit Approval',summary:'Approve a 25,000 credit line for an existing SMB customer.',risk:'elevated · reviewer required',disp:'allowed under signed policy v1',review:true,decision:'allowed'},
          'healthcare-eligibility-review':{name:'Healthcare Eligibility Review',summary:'Determine in-network eligibility for a chronic-care plan.',risk:'protected health data · reviewer required',disp:'allowed under signed policy v1',review:true,decision:'allowed'},
          'government-benefit-decision':{name:'Government Benefit Decision',summary:'Adjudicate an unemployment benefit claim with anomalous attributes.',risk:'high · reviewer required',disp:'denied — policy guard rail',review:true,decision:'blocked'},
          'procurement-risk-review':{name:'Procurement Risk Review',summary:'Approve a new supplier above the vendor-risk threshold.',risk:'critical · reviewer required',disp:'denied — vendor risk threshold',review:true,decision:'blocked'},
          'agent-action-request':{name:'Agent Action Request',summary:'AI agent requests to dispatch a customer refund.',risk:'standard · auto-approval eligible',disp:'allowed under signed policy v1',review:false,decision:'allowed'},
          'identity-verification':{name:'Identity Verification',summary:'Verify a returning customer for a new-device login.',risk:'standard · auto-approval eligible',disp:'allowed under signed policy v1',review:false,decision:'allowed'}
        };
        var stepEls={};
        root.querySelectorAll('.pf-step').forEach(function(el){ stepEls[el.getAttribute('data-step')]=el; });
        var btns=root.querySelectorAll('.pf-sc-btn');
        var runBtn=document.getElementById('pf-run');
        var recordsEl=document.getElementById('pf-records');
        var boardroomEl=document.getElementById('pf-boardroom');
        var boardroomMeta=document.getElementById('pf-boardroom-meta');
        var reqName=document.getElementById('pf-req-name');
        var reqSummary=document.getElementById('pf-req-summary');
        var reqRisk=document.getElementById('pf-req-risk');
        var reqDisp=document.getElementById('pf-req-disp');
        var current='financial-credit-approval';
        function esc(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
        function hex(n){var a=new Uint8Array(n);(window.crypto||window.msCrypto).getRandomValues(a);return Array.from(a,function(b){return b.toString(16).padStart(2,'0');}).join('');}
        function ts(){return new Date().toISOString();}
        function delay(ms){return new Promise(function(r){setTimeout(r,ms);});}
        function selectScenario(slug){
          current=slug; var s=scenarios[slug];
          btns.forEach(function(b){ var a=b.getAttribute('data-sc')===slug; b.classList.toggle('active',a); b.setAttribute('aria-selected',a?'true':'false'); });
          reqName.textContent=s.name; reqSummary.textContent=s.summary; reqRisk.textContent=s.risk; reqDisp.textContent=s.disp;
          resetWalkthrough();
        }
        function resetWalkthrough(){
          Object.keys(stepEls).forEach(function(k){ var el=stepEls[k]; el.className='pf-step'; el.querySelector('.pf-step-ts').textContent='—'; });
          recordsEl.innerHTML='<li class="pf-rec-empty">No proof executed yet. Pick a scenario and click Run Governance Proof.</li>';
          boardroomEl.classList.remove('is-on'); boardroomMeta.textContent='';
        }
        function record(cls,ev,detail){
          var empty=recordsEl.querySelector('.pf-rec-empty'); if(empty) empty.remove();
          var li=document.createElement('li'); li.className=cls;
          li.innerHTML='<span class="pf-rec-ts">'+esc(ts())+'</span><span class="pf-rec-ev">'+esc(ev)+'</span><span>'+esc(detail)+'</span>';
          recordsEl.appendChild(li); recordsEl.scrollTop=recordsEl.scrollHeight;
        }
        async function advance(key,cls,markFn){
          var el=stepEls[key]; el.classList.add('is-active'); el.querySelector('.pf-step-ts').textContent=ts().split('T')[1].replace('Z','');
          await delay(520);
          el.classList.remove('is-active'); el.classList.add(cls||'is-done');
          if(markFn) markFn();
        }
        async function runProof(){
          var s=scenarios[current]; if(!s) return;
          resetWalkthrough(); runBtn.disabled=true; btns.forEach(function(b){ b.disabled=true; });
          var orig=runBtn.textContent; runBtn.textContent='Proof running…';
          var corr='req_'+hex(4); var pol='ph_'+hex(8);
          await advance('request',null,function(){ record('','request_received','correlation '+corr+' · '+s.name); });
          await advance('policy',null,function(){ record('','policy_loaded','signed policy '+pol+' · loaded and verified'); });
          if(s.review){ await advance('review',null,function(){ record('r-review','review_required','reviewer of record assigned · '+s.risk); }); }
          else { stepEls.review.classList.add('is-skipped'); stepEls.review.querySelector('.pf-step-ts').textContent='skipped'; record('','review_required','not required for this risk class · auto-approval eligible'); }
          if(s.decision==='blocked'){
            await advance('decision','is-blocked',function(){ record('r-block','decision_blocked','policy guard rail tripped · fail-closed'); });
          } else {
            await advance('decision',null,function(){ record('r-allow','decision_allowed','within signed policy bounds · reviewer of record present'); });
          }
          var aid='ah_'+hex(8);
          await advance('seal',null,function(){ record('r-seal','evidence_sealed','append-only chain · ordering hash '+aid); });
          var eid='ev_'+hex(4);
          await advance('audit',null,function(){ record('r-seal','audit_record','event id '+eid+' · retrievable on demand'); });
          boardroomMeta.textContent='correlation '+corr+' · policy '+pol+' · audit '+aid+' · event '+eid;
          boardroomEl.classList.add('is-on');
          runBtn.textContent=orig; runBtn.disabled=false; btns.forEach(function(b){ b.disabled=false; });
        }
        btns.forEach(function(b){ b.addEventListener('click',function(){ if(b.disabled) return; selectScenario(b.getAttribute('data-sc')); }); });
        runBtn.addEventListener('click',runProof);
      })();
      </script>
    </section>

    <section id="usbsim-usecases" class="uc" aria-label="Where USBAY Is Used">
      <style>
        .uc{margin:14px 0 18px;display:grid;gap:14px;padding:16px 18px;border:1px solid #1f3253;border-left:3px solid #c084fc;border-radius:10px;background:linear-gradient(135deg,rgba(192,132,252,.05),rgba(14,26,43,.55));}
        .uc-head{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;}
        .uc-eyebrow{font-size:10px;letter-spacing:.24em;text-transform:uppercase;color:#c084fc;font-weight:700;}
        .uc-h{margin:4px 0 0;font-size:15px;font-weight:700;color:#e6edf6;letter-spacing:.04em;}
        .uc-sub{margin:0;font-size:12px;color:#cbd5e1;line-height:1.55;}
        .uc-pill{font-size:9.5px;letter-spacing:.16em;font-weight:700;text-transform:uppercase;padding:2px 8px;border-radius:999px;border:1px solid #c084fc;background:rgba(0,0,0,.3);color:#c084fc;font-family:"JetBrains Mono","SFMono-Regular",monospace;}
        .uc-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;}
        @media (max-width:980px){.uc-grid{grid-template-columns:repeat(2,minmax(0,1fr));}}
        @media (max-width:620px){.uc-grid{grid-template-columns:1fr;}}
        .uc-card{padding:12px 14px;border-radius:8px;border:1px solid #1f3253;border-left:3px solid #c084fc;background:rgba(8,14,22,.55);display:flex;flex-direction:column;gap:8px;min-width:0;}
        .uc-sector{font-size:12px;font-weight:700;color:#e6edf6;letter-spacing:.04em;}
        .uc-rows{display:grid;grid-template-columns:auto 1fr;gap:6px 10px;font-size:11px;line-height:1.5;margin:0;min-width:0;}
        .uc-rows dt{text-transform:uppercase;letter-spacing:.1em;font-size:9.5px;font-weight:700;padding-top:2px;color:#94a3b8;white-space:nowrap;}
        .uc-rows dt.dt-ai{color:#7dd3fc;}
        .uc-rows dt.dt-risk{color:#f87171;}
        .uc-rows dt.dt-usbay{color:#c084fc;}
        .uc-rows dt.dt-outcome{color:#86efac;}
        .uc-rows dd{margin:0;color:#cbd5e1;min-width:0;word-wrap:break-word;overflow-wrap:break-word;}
        .uc-cmp{display:grid;grid-template-columns:1fr 1fr;gap:10px;}
        @media (max-width:780px){.uc-cmp{grid-template-columns:1fr;}}
        .uc-cmp-card{padding:12px 14px;border-radius:8px;border:1px solid currentColor;background:rgba(0,0,0,.3);display:flex;flex-direction:column;gap:6px;}
        .uc-cmp-without{color:#f87171;}
        .uc-cmp-with{color:#86efac;}
        .uc-cmp-h{font-size:10.5px;letter-spacing:.22em;text-transform:uppercase;font-weight:700;}
        .uc-cmp-l{margin:0;padding-left:16px;font-size:11px;color:#cbd5e1;line-height:1.55;}
        .uc-cmp-l li{margin:3px 0;}
        .uc-cmp-l li b{color:inherit;font-weight:700;}
        .uc-disclaimer{margin:0;padding:8px 10px;border-radius:6px;background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.28);color:#fbbf24;font-size:11px;line-height:1.5;font-style:italic;}
      </style>

      <div class="uc-head">
        <div>
          <div class="uc-eyebrow">● Phase 30 // Enterprise Deployment Scenarios</div>
          <h2 class="uc-h">Where USBAY Is Used</h2>
        </div>
        <span class="uc-pill">ILLUSTRATIVE · REFERENCE</span>
      </div>
      <p class="uc-sub">Bridge governance demonstration with enterprise adoption: six representative sectors where USBAY sits in front of an AI system, what risk it bounds, which control it enforces, and what governance outcome the business sees. The governance engine, audit chain, proof scenarios, and resilience drills above are unchanged by this view.</p>

      <div class="uc-grid" aria-label="Sector deployment scenarios">
        <div class="uc-card">
          <div class="uc-sector">Financial Services</div>
          <dl class="uc-rows">
            <dt class="dt-ai">AI System</dt><dd>Credit decision engine</dd>
            <dt class="dt-risk">Risk</dt><dd>Unreviewed denial or silent approval reaches a customer.</dd>
            <dt class="dt-usbay">USBAY Control</dt><dd>Human review of record + sealed evidence chain.</dd>
            <dt class="dt-outcome">Outcome</dt><dd>Every credit decision is auditable and reproducible on demand.</dd>
          </dl>
        </div>
        <div class="uc-card">
          <div class="uc-sector">Healthcare</div>
          <dl class="uc-rows">
            <dt class="dt-ai">AI System</dt><dd>Eligibility and care-plan triage</dd>
            <dt class="dt-risk">Risk</dt><dd>Protected health data drives an unverifiable clinical recommendation.</dd>
            <dt class="dt-usbay">USBAY Control</dt><dd>Signed policy enforcement with clinician reviewer of record.</dd>
            <dt class="dt-outcome">Outcome</dt><dd>Patient-affecting decisions are governed and traceable end to end.</dd>
          </dl>
        </div>
        <div class="uc-card">
          <div class="uc-sector">Government</div>
          <dl class="uc-rows">
            <dt class="dt-ai">AI System</dt><dd>Benefit adjudication assistant</dd>
            <dt class="dt-risk">Risk</dt><dd>Citizen-facing decision is issued without accountable review.</dd>
            <dt class="dt-usbay">USBAY Control</dt><dd>Fail-closed gateway with named reviewer and append-only audit.</dd>
            <dt class="dt-outcome">Outcome</dt><dd>Public-sector mandate alignment with transparent oversight trail.</dd>
          </dl>
        </div>
        <div class="uc-card">
          <div class="uc-sector">Rail &amp; Transport</div>
          <dl class="uc-rows">
            <dt class="dt-ai">AI System</dt><dd>Dispatch and routing optimizer</dd>
            <dt class="dt-risk">Risk</dt><dd>Unsigned schedule change propagates to safety-relevant operations.</dd>
            <dt class="dt-usbay">USBAY Control</dt><dd>Replay guard + signed policy on every dispatch action.</dd>
            <dt class="dt-outcome">Outcome</dt><dd>Safety-relevant changes carry a verifiable signature and reviewer id.</dd>
          </dl>
        </div>
        <div class="uc-card">
          <div class="uc-sector">Critical Infrastructure</div>
          <dl class="uc-rows">
            <dt class="dt-ai">AI System</dt><dd>Grid and utility load advisor</dd>
            <dt class="dt-risk">Risk</dt><dd>Out-of-policy setpoint reaches a control system without oversight.</dd>
            <dt class="dt-usbay">USBAY Control</dt><dd>Fail-closed enforcement with reviewer of record and sealed evidence.</dd>
            <dt class="dt-outcome">Outcome</dt><dd>Operator retains demonstrable control over every AI-issued action.</dd>
          </dl>
        </div>
        <div class="uc-card">
          <div class="uc-sector">Industrial Automation</div>
          <dl class="uc-rows">
            <dt class="dt-ai">AI System</dt><dd>Robotic process and quality controller</dd>
            <dt class="dt-risk">Risk</dt><dd>Autonomous action executed outside approved operating envelope.</dd>
            <dt class="dt-usbay">USBAY Control</dt><dd>Policy-bounded execution with append-only audit chain.</dd>
            <dt class="dt-outcome">Outcome</dt><dd>Plant-floor automation remains inside signed, reviewable bounds.</dd>
          </dl>
        </div>
      </div>

      <div class="uc-cmp" aria-label="Operational comparison: with and without USBAY">
        <div class="uc-cmp-card uc-cmp-without">
          <div class="uc-cmp-h">What Happens Without USBAY</div>
          <ul class="uc-cmp-l">
            <li><b>Unreviewed execution.</b> AI actions land in production with no named approver.</li>
            <li><b>Silent fallback.</b> Under stress the system degrades to a trusted path instead of failing closed.</li>
            <li><b>Fragmented evidence.</b> Logs scattered across systems; auditor reconstruction is slow and contested.</li>
            <li><b>Replay exposure.</b> The same request executes more than once before detection.</li>
            <li><b>Unsigned policy drift.</b> Policy changes propagate without signature or rollback.</li>
            <li><b>Compliance burden.</b> Each review cycle rebuilds posture from raw operational data.</li>
          </ul>
        </div>
        <div class="uc-cmp-card uc-cmp-with">
          <div class="uc-cmp-h">What Happens With USBAY</div>
          <ul class="uc-cmp-l">
            <li><b>Enforced review.</b> Reviewer of record is bound to every decision that requires one.</li>
            <li><b>Fail-closed gateway.</b> Stress and ambiguity resolve to denial, not to silent approval.</li>
            <li><b>Sealed evidence.</b> Append-only audit chain with ordering hash, ready on demand.</li>
            <li><b>Replay protection.</b> Duplicate requests denied at the gateway and recorded.</li>
            <li><b>Signed policy.</b> Policy versions are signed, verifiable, and rollback-safe.</li>
            <li><b>Audit readiness.</b> Continuous posture; reviewers consume evidence instead of reconstructing it.</li>
          </ul>
        </div>
      </div>

      <p class="uc-disclaimer" role="note">Illustrative deployment scenarios. Not customer references.</p>
    </section>

    <section id="usbsim-journey" class="jn" aria-label="Guided Enterprise Journey">
      <style>
        .jn{margin:14px 0 18px;display:grid;gap:14px;padding:16px 18px;border:1px solid #1f3253;border-left:3px solid #38bdf8;border-radius:10px;background:linear-gradient(135deg,rgba(56,189,248,.05),rgba(14,26,43,.55));}
        .jn-head{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;}
        .jn-eyebrow{font-size:10px;letter-spacing:.24em;text-transform:uppercase;color:#38bdf8;font-weight:700;}
        .jn-h{margin:4px 0 0;font-size:15px;font-weight:700;color:#e6edf6;letter-spacing:.04em;}
        .jn-sub{margin:0;font-size:12px;color:#cbd5e1;line-height:1.55;}
        .jn-pill{font-size:9.5px;letter-spacing:.16em;font-weight:700;text-transform:uppercase;padding:2px 8px;border-radius:999px;border:1px solid #38bdf8;background:rgba(0,0,0,.3);color:#38bdf8;font-family:"JetBrains Mono","SFMono-Regular",monospace;}
        .jn-steps{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:6px;list-style:none;margin:0;padding:0;}
        @media (max-width:880px){.jn-steps{grid-template-columns:repeat(3,minmax(0,1fr));}}
        @media (max-width:520px){.jn-steps{grid-template-columns:repeat(2,minmax(0,1fr));}}
        .jn-step{padding:8px 10px;border-radius:6px;border:1px solid #1f3253;background:rgba(8,14,22,.55);display:flex;flex-direction:column;gap:3px;color:#64748b;transition:border-color .2s,background .2s,color .2s;}
        .jn-step.is-active{border-color:#38bdf8;background:rgba(56,189,248,.1);color:#38bdf8;}
        .jn-step.is-done{border-color:#86efac;background:rgba(134,239,172,.06);color:#86efac;}
        .jn-step-n{font-size:9px;letter-spacing:.16em;text-transform:uppercase;font-weight:700;}
        .jn-step-l{font-size:10.5px;font-weight:700;color:#e6edf6;line-height:1.3;}
        .jn-step.is-active .jn-step-l,.jn-step.is-done .jn-step-l{color:inherit;}
        .jn-sectors{display:flex;flex-wrap:wrap;gap:6px;}
        .jn-sec-btn{font-size:10.5px;letter-spacing:.04em;font-weight:600;padding:6px 10px;border-radius:6px;border:1px solid #1f3253;background:rgba(8,14,22,.55);color:#cbd5e1;cursor:pointer;font-family:inherit;}
        .jn-sec-btn:hover:not(:disabled){border-color:#38bdf8;color:#38bdf8;}
        .jn-sec-btn.active{border-color:#38bdf8;background:rgba(56,189,248,.12);color:#38bdf8;}
        .jn-sec-btn:disabled{opacity:.55;cursor:not-allowed;}
        .jn-stage{padding:12px 14px;border-radius:8px;background:rgba(8,14,22,.6);border:1px solid #1f3253;display:grid;grid-template-columns:auto 1fr;gap:8px 14px;font-size:11.5px;line-height:1.55;min-width:0;}
        .jn-stage .jn-k{text-transform:uppercase;letter-spacing:.1em;font-size:9.5px;font-weight:700;color:#38bdf8;padding-top:2px;white-space:nowrap;}
        .jn-stage .jn-v{color:#e6edf6;min-width:0;word-wrap:break-word;overflow-wrap:break-word;}
        .jn-stage .jn-v.v-block{color:#f87171;}
        .jn-stage .jn-v.v-allow{color:#86efac;}
        .jn-stage-empty{color:#64748b;font-style:italic;grid-column:1 / -1;}
        .jn-controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;}
        .jn-btn{font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;font-weight:700;padding:8px 14px;border-radius:6px;border:1px solid #38bdf8;background:rgba(56,189,248,.12);color:#38bdf8;cursor:pointer;font-family:inherit;}
        .jn-btn:hover:not(:disabled){background:rgba(56,189,248,.2);}
        .jn-btn:disabled{opacity:.5;cursor:not-allowed;}
        .jn-btn.jn-ghost{border-color:#1f3253;background:rgba(8,14,22,.55);color:#cbd5e1;}
        .jn-btn.jn-ghost:hover:not(:disabled){border-color:#94a3b8;color:#e6edf6;}
        .jn-summary{padding:14px;border-radius:8px;background:rgba(134,239,172,.07);border:1px solid rgba(134,239,172,.3);display:none;flex-direction:column;gap:10px;}
        .jn-summary.is-on{display:flex;}
        .jn-sum-h{font-size:10.5px;letter-spacing:.22em;text-transform:uppercase;font-weight:700;color:#34d399;}
        .jn-sum-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;}
        @media (max-width:780px){.jn-sum-grid{grid-template-columns:1fr;}}
        .jn-sum-cell{padding:8px 10px;border-radius:6px;background:rgba(0,0,0,.3);border:1px solid #1f3253;min-width:0;}
        .jn-sum-k{font-size:9px;letter-spacing:.16em;text-transform:uppercase;color:#7dd3fc;font-weight:700;margin-bottom:3px;}
        .jn-sum-v{font-size:11.5px;color:#e6edf6;line-height:1.5;word-wrap:break-word;overflow-wrap:break-word;}
        .jn-sum-v.v-block{color:#f87171;}
        .jn-sum-v.v-allow{color:#86efac;}
        .jn-sum-meta{font-family:"JetBrains Mono","SFMono-Regular",monospace;font-size:10px;color:#94a3b8;word-break:break-all;}
        .jn-disclaimer{margin:0;padding:8px 10px;border-radius:6px;background:rgba(56,189,248,.06);border:1px solid rgba(56,189,248,.25);color:#7dd3fc;font-size:11px;line-height:1.5;font-style:italic;}
      </style>

      <div class="jn-head">
        <div>
          <div class="jn-eyebrow">● Phase 31 // Guided Enterprise Journey</div>
          <h2 class="jn-h">One Continuous Governance Narrative</h2>
        </div>
        <span class="jn-pill">ORCHESTRATION · PREVIEW</span>
      </div>
      <p class="jn-sub">Walk the existing modules as a single story: pick a sector, then advance through risk evaluation, governance enforcement, evidence verification, executive review, and a pilot recommendation. This view orchestrates and presents the modules above — it adds no new governance logic, policy, or audit behavior.</p>

      <ol class="jn-steps" id="jn-steps" aria-label="Journey progress">
        <li class="jn-step is-active" data-i="1"><span class="jn-step-n">Step 1</span><span class="jn-step-l">Select Sector</span></li>
        <li class="jn-step" data-i="2"><span class="jn-step-n">Step 2</span><span class="jn-step-l">Evaluate Risk</span></li>
        <li class="jn-step" data-i="3"><span class="jn-step-n">Step 3</span><span class="jn-step-l">Execute Governance</span></li>
        <li class="jn-step" data-i="4"><span class="jn-step-n">Step 4</span><span class="jn-step-l">Verify Evidence</span></li>
        <li class="jn-step" data-i="5"><span class="jn-step-n">Step 5</span><span class="jn-step-l">Executive Review</span></li>
        <li class="jn-step" data-i="6"><span class="jn-step-n">Step 6</span><span class="jn-step-l">Pilot Recommendation</span></li>
      </ol>

      <div class="jn-sectors" id="jn-sectors" role="tablist" aria-label="Sector">
        <button type="button" class="jn-sec-btn active" data-sec="financial" role="tab" aria-selected="true">Financial Services</button>
        <button type="button" class="jn-sec-btn" data-sec="healthcare" role="tab" aria-selected="false">Healthcare</button>
        <button type="button" class="jn-sec-btn" data-sec="government" role="tab" aria-selected="false">Government</button>
        <button type="button" class="jn-sec-btn" data-sec="rail" role="tab" aria-selected="false">Rail &amp; Transport</button>
        <button type="button" class="jn-sec-btn" data-sec="infrastructure" role="tab" aria-selected="false">Critical Infrastructure</button>
        <button type="button" class="jn-sec-btn" data-sec="industrial" role="tab" aria-selected="false">Industrial Automation</button>
      </div>

      <div class="jn-stage" id="jn-stage" aria-live="polite">
        <span class="jn-stage-empty">Sector selected. Click Advance Journey to evaluate risk, execute governance, verify evidence, and reach an executive outcome.</span>
      </div>

      <div class="jn-controls">
        <button type="button" class="jn-btn" id="jn-advance">Advance Journey ▶</button>
        <button type="button" class="jn-btn jn-ghost" id="jn-reset">Reset</button>
      </div>

      <div class="jn-summary" id="jn-summary" aria-live="polite">
        <div class="jn-sum-h">● Executive Decision Summary</div>
        <div class="jn-sum-grid" id="jn-sum-grid"></div>
        <div class="jn-sum-meta" id="jn-sum-meta"></div>
      </div>

      <p class="jn-disclaimer" role="note">Orchestration and presentation only. The guided journey re-uses the existing governance modules, scenarios, and reporting; it changes no enforcement, policy, audit, or evidence behavior.</p>

      <div class="xp" id="usbsim-export" aria-label="Executive Export Package">
        <style>
          .xp{display:grid;gap:12px;padding:14px;border-radius:8px;background:rgba(251,191,36,.04);border:1px solid rgba(251,191,36,.26);margin-top:4px;}
          .xp-head{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;}
          .xp-eyebrow{font-size:9.5px;letter-spacing:.22em;text-transform:uppercase;color:#fbbf24;font-weight:700;}
          .xp-h{margin:3px 0 0;font-size:13.5px;font-weight:700;color:#e6edf6;letter-spacing:.03em;}
          .xp-pill{font-size:9px;letter-spacing:.18em;text-transform:uppercase;font-weight:700;padding:2px 8px;border-radius:999px;border:1px solid #fbbf24;color:#fbbf24;background:rgba(0,0,0,.3);font-family:"JetBrains Mono","SFMono-Regular",monospace;}
          .xp-sub{margin:0;font-size:11.5px;color:#cbd5e1;line-height:1.55;}
          .xp-row{display:flex;flex-wrap:wrap;gap:6px;align-items:center;}
          .xp-row-label{font-size:9px;letter-spacing:.16em;text-transform:uppercase;color:#94a3b8;font-weight:700;margin-right:2px;}
          .xp-chip{font-size:10.5px;letter-spacing:.03em;font-weight:600;padding:5px 9px;border-radius:6px;border:1px solid #1f3253;background:rgba(8,14,22,.55);color:#cbd5e1;cursor:pointer;font-family:inherit;}
          .xp-chip:hover{border-color:#fbbf24;color:#fbbf24;}
          .xp-chip.active{border-color:#fbbf24;background:rgba(251,191,36,.12);color:#fbbf24;}
          .xp-fmt-btn{font-size:10px;letter-spacing:.08em;text-transform:uppercase;font-weight:700;padding:6px 11px;border-radius:6px;border:1px solid #1f3253;background:rgba(8,14,22,.55);color:#cbd5e1;cursor:pointer;font-family:inherit;}
          .xp-fmt-btn:hover{border-color:#7dd3fc;color:#7dd3fc;}
          .xp-fmt-btn.active{border-color:#7dd3fc;background:rgba(125,211,252,.12);color:#7dd3fc;}
          .xp-doc{padding:14px 16px;border-radius:8px;background:rgba(8,14,22,.7);border:1px solid #1f3253;display:flex;flex-direction:column;gap:10px;min-width:0;}
          .xp-doc-kicker{font-size:9px;letter-spacing:.22em;text-transform:uppercase;color:#7dd3fc;font-weight:700;}
          .xp-doc-title{font-size:14px;font-weight:700;color:#e6edf6;letter-spacing:.02em;line-height:1.3;}
          .xp-doc-lede{margin:0;font-size:11.5px;color:#cbd5e1;line-height:1.6;}
          .xp-fields{display:grid;grid-template-columns:auto 1fr;gap:7px 14px;font-size:11.5px;line-height:1.55;margin:0;min-width:0;}
          .xp-fields dt{text-transform:uppercase;letter-spacing:.1em;font-size:9px;font-weight:700;color:#7dd3fc;padding-top:2px;white-space:nowrap;}
          .xp-fields dd{margin:0;color:#e6edf6;min-width:0;word-wrap:break-word;overflow-wrap:break-word;}
          .xp-fields dd.dd-risk{color:#f87171;}
          .xp-fields dd.dd-good{color:#86efac;}
          .xp-bullets{margin:0;padding-left:16px;font-size:11.5px;color:#cbd5e1;line-height:1.6;}
          .xp-bullets li{margin:3px 0;}
          .xp-bullets li b{color:#e6edf6;}
          .xp-doc-meta{font-family:"JetBrains Mono","SFMono-Regular",monospace;font-size:10px;color:#94a3b8;word-break:break-all;border-top:1px solid #1f3253;padding-top:8px;}
          .xp-disclaimer{margin:0;padding:8px 10px;border-radius:6px;background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.28);color:#fbbf24;font-size:11px;line-height:1.5;font-style:italic;}
        </style>
        <div class="xp-head">
          <div>
            <div class="xp-eyebrow">● Phase 32 // Executive Export Package</div>
            <h3 class="xp-h">Generate Executive Materials</h3>
          </div>
          <span class="xp-pill">PREVIEW · NO PDF YET</span>
        </div>
        <p class="xp-sub">Turn the guided journey into shareable executive materials. Pick a sector and a format — the preview renders exactly what the exported document would contain. No PDF is generated and nothing is persisted; this is a presentation preview only.</p>
        <div class="xp-row" role="tablist" aria-label="Export sector">
          <span class="xp-row-label">Sector</span>
          <button type="button" class="xp-chip active" data-sec="financial" role="tab" aria-selected="true">Financial Services</button>
          <button type="button" class="xp-chip" data-sec="healthcare" role="tab" aria-selected="false">Healthcare</button>
          <button type="button" class="xp-chip" data-sec="government" role="tab" aria-selected="false">Government</button>
          <button type="button" class="xp-chip" data-sec="rail" role="tab" aria-selected="false">Rail &amp; Transport</button>
          <button type="button" class="xp-chip" data-sec="infrastructure" role="tab" aria-selected="false">Critical Infrastructure</button>
          <button type="button" class="xp-chip" data-sec="industrial" role="tab" aria-selected="false">Industrial Automation</button>
        </div>
        <div class="xp-row" role="tablist" aria-label="Export format">
          <span class="xp-row-label">Format</span>
          <button type="button" class="xp-fmt-btn active" data-fmt="brief" role="tab" aria-selected="true">Generate Executive Brief</button>
          <button type="button" class="xp-fmt-btn" data-fmt="onepager" role="tab" aria-selected="false">Boardroom One Pager</button>
          <button type="button" class="xp-fmt-btn" data-fmt="regulator" role="tab" aria-selected="false">Regulator Summary</button>
          <button type="button" class="xp-fmt-btn" data-fmt="pilot" role="tab" aria-selected="false">Pilot Scope Summary</button>
        </div>
        <div class="xp-doc" id="xp-doc" aria-live="polite"></div>
        <p class="xp-disclaimer" role="note">Preview only. No PDF generation and no backend persistence — exported materials would mirror this preview, drawn from the existing governance modules.</p>
      </div>

      <script>
      (function(){
        var root=document.getElementById('usbsim-export'); if(!root) return;
        var data={
          financial:{sector:'Financial Services',scenario:'Credit decision engine approves a 25,000 credit line for an existing SMB customer.',risk:'Unreviewed denial or silent approval reaches a customer.',controls:'Human review of record + signed policy enforcement at the gateway.',evidence:'Sealed in append-only chain; auditable and reproducible on demand.',impact:'Credit decisions defensible to a board and ready for audit.',pilot:'One high-stakes credit workflow behind the gateway with audit chain, replay guard, and reviewer of record.'},
          healthcare:{sector:'Healthcare',scenario:'Eligibility and care-plan triage for a chronic-care patient.',risk:'Protected health data drives an unverifiable clinical recommendation.',controls:'Signed policy enforcement + clinician reviewer of record.',evidence:'Patient-affecting decisions traceable end to end in the audit chain.',impact:'Clinical governance demonstrable to regulators and oversight bodies.',pilot:'One eligibility workflow behind the gateway with clinician review and sealed evidence.'},
          government:{sector:'Government',scenario:'Benefit adjudication assistant processes a claim with anomalous attributes.',risk:'Citizen-facing decision issued without accountable review.',controls:'Fail-closed denial + named reviewer + append-only audit.',evidence:'Denial recorded with reviewer id and policy version in the chain.',impact:'Public-sector mandate alignment with a transparent oversight trail.',pilot:'One adjudication workflow behind the gateway with fail-closed denial and audit retrieval.'},
          rail:{sector:'Rail & Transport',scenario:'Dispatch and routing optimizer issues a schedule change.',risk:'Unsigned schedule change propagates to safety-relevant operations.',controls:'Replay guard + signed policy on every dispatch action.',evidence:'Each change carries a verifiable signature and reviewer id.',impact:'Safety-relevant automation governed and independently verifiable.',pilot:'One dispatch workflow behind the gateway with replay protection and signed policy.'},
          infrastructure:{sector:'Critical Infrastructure',scenario:'Grid and utility load advisor proposes a control setpoint.',risk:'Out-of-policy setpoint reaches a control system without oversight.',controls:'Fail-closed enforcement + reviewer of record + sealed evidence.',evidence:'Out-of-policy setpoints denied and recorded before reaching control.',impact:'Operator retains demonstrable control over every AI-issued action.',pilot:'One load-advisory workflow behind the gateway with fail-closed enforcement.'},
          industrial:{sector:'Industrial Automation',scenario:'Robotic process and quality controller requests an autonomous action.',risk:'Autonomous action executed outside the approved operating envelope.',controls:'Policy-bounded execution + append-only audit chain.',evidence:'Actions outside signed bounds denied and sealed in the chain.',impact:'Plant-floor automation stays inside signed, reviewable bounds.',pilot:'One robotic workflow behind the gateway with policy-bounded execution and audit chain.'}
        };
        var fmtLabel={brief:'Executive Brief',onepager:'Boardroom One Pager',regulator:'Regulator Summary',pilot:'Pilot Scope Summary'};
        var secBtns=root.querySelectorAll('.xp-chip');
        var fmtBtns=root.querySelectorAll('.xp-fmt-btn');
        var docEl=document.getElementById('xp-doc');
        var sec='financial'; var fmt='brief';
        function esc(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
        function hex(n){var a=new Uint8Array(n);(window.crypto||window.msCrypto).getRandomValues(a);return Array.from(a,function(b){return b.toString(16).padStart(2,'0');}).join('');}
        function field(k,v,cls){ return '<dt>'+esc(k)+'</dt><dd'+(cls?(' class="'+cls+'"'):'')+'>'+esc(v)+'</dd>'; }
        function meta(){ return 'document '+('doc_'+hex(4))+' · correlation '+('req_'+hex(4))+' · policy ph_'+hex(8)+' · audit ah_'+hex(8)+' · simulated'; }
        function render(){
          var d=data[sec]; var html='';
          html+='<div class="xp-doc-kicker">USBAY · '+esc(fmtLabel[fmt])+' · '+esc(d.sector)+'</div>';
          if(fmt==='brief'){
            html+='<div class="xp-doc-title">Executive Brief — '+esc(d.sector)+'</div>';
            html+='<dl class="xp-fields">'+field('Sector',d.sector)+field('Scenario',d.scenario)+field('Governance Risk',d.risk,'dd-risk')+field('USBAY Controls',d.controls)+field('Evidence Outcome',d.evidence,'dd-good')+field('Business Impact',d.impact,'dd-good')+field('Recommended Pilot',d.pilot)+'</dl>';
          } else if(fmt==='onepager'){
            html+='<div class="xp-doc-title">Boardroom One Pager — '+esc(d.sector)+'</div>';
            html+='<p class="xp-doc-lede">USBAY places this AI workflow behind a fail-closed governance gateway. '+esc(d.controls)+' Every decision is sealed in the audit chain, so '+esc(d.impact.charAt(0).toLowerCase()+d.impact.slice(1))+'</p>';
            html+='<ul class="xp-bullets"><li><b>Risk contained:</b> '+esc(d.risk)+'</li><li><b>Control enforced:</b> '+esc(d.controls)+'</li><li><b>Evidence:</b> '+esc(d.evidence)+'</li><li><b>Next step:</b> '+esc(d.pilot)+'</li></ul>';
          } else if(fmt==='regulator'){
            html+='<div class="xp-doc-title">Regulator Summary — '+esc(d.sector)+'</div>';
            html+='<p class="xp-doc-lede">Audit-focused record of how USBAY governs this AI workflow, suitable for independent oversight without trusting the operator.</p>';
            html+='<dl class="xp-fields">'+field('Scope',d.scenario)+field('Governance Risk',d.risk,'dd-risk')+field('Enforcement',d.controls)+field('Evidence Chain',d.evidence,'dd-good')+field('Reviewer Accountability','Reviewer of record bound to each decision that requires one.')+field('Oversight Trail','Decisions, policy versions, and denials retrievable on demand with ordering hash.','dd-good')+'</dl>';
          } else {
            html+='<div class="xp-doc-title">Pilot Scope Summary — '+esc(d.sector)+'</div>';
            html+='<p class="xp-doc-lede">Engagement-focused outline for placing a single high-stakes workflow behind USBAY.</p>';
            html+='<dl class="xp-fields">'+field('Target Workflow',d.scenario)+field('Risk Addressed',d.risk,'dd-risk')+field('Controls Enabled',d.controls)+field('Evidence Model',d.evidence,'dd-good')+field('Success Criteria','Auditor-ready evidence by default; no decision without a reviewer of record.','dd-good')+field('Recommended Pilot',d.pilot)+'</dl>';
          }
          html+='<div class="xp-doc-meta">'+esc(meta())+'</div>';
          docEl.innerHTML=html;
        }
        secBtns.forEach(function(b){ b.addEventListener('click',function(){ sec=b.getAttribute('data-sec'); secBtns.forEach(function(x){ var a=x===b; x.classList.toggle('active',a); x.setAttribute('aria-selected',a?'true':'false'); }); render(); }); });
        fmtBtns.forEach(function(b){ b.addEventListener('click',function(){ fmt=b.getAttribute('data-fmt'); fmtBtns.forEach(function(x){ var a=x===b; x.classList.toggle('active',a); x.setAttribute('aria-selected',a?'true':'false'); }); render(); }); });
        render();
      })();
      </script>

      <script>
      (function(){
        var root=document.getElementById('usbsim-journey'); if(!root) return;
        var sectors={
          financial:{sector:'Financial Services',scenario:'Credit decision engine approves a 25,000 credit line for an existing SMB customer.',risk:'Elevated — unreviewed denial or silent approval reaches a customer.',decision:'allowed',decisionText:'Allowed under signed policy v1 with reviewer of record present.',enforcement:'Human review enforced + signed policy applied at the gateway.',outcome:'Auditable, reproducible credit decision available on demand.',pilot:'One high-stakes credit workflow behind the gateway with audit chain, replay guard, and reviewer of record enabled.'},
          healthcare:{sector:'Healthcare',scenario:'Eligibility and care-plan triage for a chronic-care patient.',risk:'Protected health data — unverifiable clinical recommendation.',decision:'allowed',decisionText:'Allowed under signed policy with clinician reviewer of record.',enforcement:'Signed policy enforcement + clinician review of record.',outcome:'Patient-affecting decisions governed and traceable end to end.',pilot:'One eligibility workflow placed behind the gateway with clinician review and sealed evidence.'},
          government:{sector:'Government',scenario:'Benefit adjudication assistant processes a claim with anomalous attributes.',risk:'High — citizen-facing decision issued without accountable review.',decision:'blocked',decisionText:'Denied — policy guard rail tripped; gateway fails closed.',enforcement:'Fail-closed denial + named reviewer + append-only audit.',outcome:'Public-sector mandate alignment with a transparent oversight trail.',pilot:'One adjudication workflow behind the gateway with fail-closed denial and audit retrieval.'},
          rail:{sector:'Rail & Transport',scenario:'Dispatch and routing optimizer issues a schedule change.',risk:'Critical — unsigned schedule change propagates to safety-relevant operations.',decision:'blocked',decisionText:'Denied unless signed — replay guard and signed policy enforced.',enforcement:'Replay guard + signed policy on every dispatch action.',outcome:'Safety-relevant changes carry a verifiable signature and reviewer id.',pilot:'One dispatch workflow behind the gateway with replay protection and signed policy.'},
          infrastructure:{sector:'Critical Infrastructure',scenario:'Grid and utility load advisor proposes a control setpoint.',risk:'Critical — out-of-policy setpoint reaches a control system without oversight.',decision:'blocked',decisionText:'Denied — fail-closed enforcement; operator retains control.',enforcement:'Fail-closed enforcement + reviewer of record + sealed evidence.',outcome:'Operator retains demonstrable control over every AI-issued action.',pilot:'One load-advisory workflow behind the gateway with fail-closed enforcement.'},
          industrial:{sector:'Industrial Automation',scenario:'Robotic process and quality controller requests an autonomous action.',risk:'Elevated — action requested outside the approved operating envelope.',decision:'allowed',decisionText:'Allowed within signed bounds; out-of-envelope actions are denied.',enforcement:'Policy-bounded execution + append-only audit chain.',outcome:'Plant-floor automation remains inside signed, reviewable bounds.',pilot:'One robotic workflow behind the gateway with policy-bounded execution and audit chain.'}
        };
        var stepEls={}; root.querySelectorAll('.jn-step').forEach(function(el){ stepEls[el.getAttribute('data-i')]=el; });
        var secBtns=root.querySelectorAll('.jn-sec-btn');
        var stageEl=document.getElementById('jn-stage');
        var advBtn=document.getElementById('jn-advance');
        var resetBtn=document.getElementById('jn-reset');
        var summaryEl=document.getElementById('jn-summary');
        var sumGrid=document.getElementById('jn-sum-grid');
        var sumMeta=document.getElementById('jn-sum-meta');
        var current='financial'; var stage=1; var ids=null;
        function esc(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
        function hex(n){var a=new Uint8Array(n);(window.crypto||window.msCrypto).getRandomValues(a);return Array.from(a,function(b){return b.toString(16).padStart(2,'0');}).join('');}
        function newIds(){return {corr:'req_'+hex(4),pol:'ph_'+hex(8),aud:'ah_'+hex(8),ev:'ev_'+hex(4)};}
        function setSteps(n){ for(var i=1;i<=6;i++){ var el=stepEls[i]; el.classList.remove('is-active','is-done'); if(i<n) el.classList.add('is-done'); else if(i===n) el.classList.add('is-active'); } }
        function row(k,v,cls){ return '<span class="jn-k">'+esc(k)+'</span><span class="jn-v'+(cls?(' '+cls):'')+'">'+esc(v)+'</span>'; }
        function renderStage(){
          var s=sectors[current];
          var html='';
          if(stage>=1) html+=row('Sector',s.sector);
          if(stage>=2) html+=row('Scenario',s.scenario)+row('Risk',s.risk,'v-block');
          if(stage>=3) html+=row('Governance Decision',s.decisionText,s.decision==='blocked'?'v-block':'v-allow')+row('Enforcement Action',s.enforcement);
          if(stage>=4) html+=row('Evidence Record','Sealed in append-only chain · ordering hash '+ids.aud+' · event '+ids.ev);
          if(stage>=5) html+=row('Executive Outcome',s.outcome,'v-allow');
          if(stage>=6) html+=row('Pilot Recommendation',s.pilot,'v-allow');
          stageEl.innerHTML=html||'<span class="jn-stage-empty">Sector selected. Click Advance Journey to begin.</span>';
        }
        function renderSummary(){
          var s=sectors[current];
          sumGrid.innerHTML=[
            ['Scenario',s.scenario,''],
            ['Risk',s.risk,'v-block'],
            ['Enforcement Action',s.enforcement,''],
            ['Evidence Status','Sealed · append-only chain · retrievable on demand','v-allow'],
            ['Governance Outcome',s.outcome,'v-allow'],
            ['Recommended Pilot',s.pilot,'']
          ].map(function(x){ return '<div class="jn-sum-cell"><div class="jn-sum-k">'+esc(x[0])+'</div><div class="jn-sum-v'+(x[2]?(' '+x[2]):'')+'">'+esc(x[1])+'</div></div>'; }).join('');
          sumMeta.textContent='correlation '+ids.corr+' · policy '+ids.pol+' · audit '+ids.aud+' · event '+ids.ev;
          summaryEl.classList.add('is-on');
        }
        function selectSector(slug){ current=slug; secBtns.forEach(function(b){ var a=b.getAttribute('data-sec')===slug; b.classList.toggle('active',a); b.setAttribute('aria-selected',a?'true':'false'); }); resetJourney(); }
        function resetJourney(){ stage=1; ids=null; setSteps(1); summaryEl.classList.remove('is-on'); advBtn.disabled=false; advBtn.textContent='Advance Journey ▶'; secBtns.forEach(function(b){ b.disabled=false; }); stageEl.innerHTML='<span class="jn-stage-empty">Sector selected. Click Advance Journey to evaluate risk, execute governance, verify evidence, and reach an executive outcome.</span>'; }
        function advance(){
          if(stage===1){ ids=newIds(); secBtns.forEach(function(b){ b.disabled=true; }); }
          if(stage<6){ stage++; setSteps(stage); renderStage(); if(stage===6){ advBtn.textContent='Journey Complete'; advBtn.disabled=true; renderSummary(); } }
        }
        secBtns.forEach(function(b){ b.addEventListener('click',function(){ if(b.disabled) return; selectSector(b.getAttribute('data-sec')); }); });
        advBtn.addEventListener('click',advance);
        resetBtn.addEventListener('click',resetJourney);
      })();
      </script>
    </section>

    <section id="usbsim-pilot-intake" class="pi" aria-label="Pilot Intake Experience">
      <style>
        .pi{margin:14px 0 18px;display:grid;gap:14px;padding:16px 18px;border:1px solid #1f3253;border-left:3px solid #34d399;border-radius:10px;background:linear-gradient(135deg,rgba(52,211,153,.05),rgba(14,26,43,.55));}
        .pi-head{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;}
        .pi-eyebrow{font-size:10px;letter-spacing:.24em;text-transform:uppercase;color:#34d399;font-weight:700;}
        .pi-h{margin:4px 0 0;font-size:15px;font-weight:700;color:#e6edf6;letter-spacing:.04em;}
        .pi-sub{margin:0;font-size:12px;color:#cbd5e1;line-height:1.55;}
        .pi-pill{font-size:9.5px;letter-spacing:.16em;font-weight:700;text-transform:uppercase;padding:2px 8px;border-radius:999px;border:1px solid #34d399;background:rgba(0,0,0,.3);color:#34d399;font-family:"JetBrains Mono","SFMono-Regular",monospace;}
        .pi-steps{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:6px;list-style:none;margin:0;padding:0;}
        @media (max-width:880px){.pi-steps{grid-template-columns:repeat(3,minmax(0,1fr));}}
        @media (max-width:520px){.pi-steps{grid-template-columns:repeat(2,minmax(0,1fr));}}
        .pi-step{padding:8px 10px;border-radius:6px;border:1px solid #1f3253;background:rgba(8,14,22,.55);display:flex;flex-direction:column;gap:3px;color:#64748b;transition:border-color .2s,background .2s,color .2s;}
        .pi-step.is-active{border-color:#34d399;background:rgba(52,211,153,.1);color:#34d399;}
        .pi-step.is-done{border-color:#86efac;background:rgba(134,239,172,.06);color:#86efac;}
        .pi-step-n{font-size:9px;letter-spacing:.16em;text-transform:uppercase;font-weight:700;}
        .pi-step-l{font-size:10.5px;font-weight:700;color:#e6edf6;line-height:1.3;}
        .pi-step.is-active .pi-step-l,.pi-step.is-done .pi-step-l{color:inherit;}
        .pi-row{display:flex;flex-wrap:wrap;gap:6px;align-items:center;}
        .pi-row-label{font-size:9px;letter-spacing:.16em;text-transform:uppercase;color:#94a3b8;font-weight:700;margin-right:2px;width:100%%;}
        .pi-chip{font-size:10.5px;letter-spacing:.03em;font-weight:600;padding:6px 10px;border-radius:6px;border:1px solid #1f3253;background:rgba(8,14,22,.55);color:#cbd5e1;cursor:pointer;font-family:inherit;}
        .pi-chip:hover:not(:disabled){border-color:#34d399;color:#34d399;}
        .pi-chip.active{border-color:#34d399;background:rgba(52,211,153,.12);color:#34d399;}
        .pi-chip:disabled{opacity:.45;cursor:not-allowed;}
        .pi-panel{padding:12px 14px;border-radius:8px;background:rgba(8,14,22,.6);border:1px solid #1f3253;display:grid;grid-template-columns:auto 1fr;gap:8px 14px;font-size:11.5px;line-height:1.55;min-width:0;}
        .pi-panel .pi-k{text-transform:uppercase;letter-spacing:.1em;font-size:9.5px;font-weight:700;color:#34d399;padding-top:2px;white-space:nowrap;}
        .pi-panel .pi-v{color:#e6edf6;min-width:0;word-wrap:break-word;overflow-wrap:break-word;}
        .pi-panel .pi-v.v-block{color:#f87171;}
        .pi-panel .pi-v.v-good{color:#86efac;}
        .pi-panel-empty{color:#64748b;font-style:italic;grid-column:1 / -1;}
        .pi-controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;}
        .pi-btn{font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;font-weight:700;padding:8px 14px;border-radius:6px;border:1px solid #38bdf8;background:rgba(56,189,248,.12);color:#7dd3fc;cursor:pointer;font-family:inherit;}
        .pi-btn:hover:not(:disabled){background:rgba(56,189,248,.2);}
        .pi-btn:disabled{opacity:.45;cursor:not-allowed;}
        .pi-btn.pi-ghost{border-color:#1f3253;background:rgba(8,14,22,.55);color:#cbd5e1;}
        .pi-btn.pi-ghost:hover:not(:disabled){border-color:#94a3b8;color:#e6edf6;}
        .pi-cta{font-size:11.5px;letter-spacing:.08em;text-transform:uppercase;font-weight:800;padding:11px 18px;border-radius:8px;border:1px solid #34d399;background:linear-gradient(135deg,rgba(52,211,153,.22),rgba(52,211,153,.08));color:#bbf7d0;cursor:pointer;font-family:inherit;box-shadow:0 0 0 1px rgba(52,211,153,.15);}
        .pi-cta:hover:not(:disabled){background:linear-gradient(135deg,rgba(52,211,153,.32),rgba(52,211,153,.14));}
        .pi-cta:disabled{opacity:.45;cursor:not-allowed;}
        .pi-privacy{margin:0;padding:8px 10px;border-radius:6px;background:rgba(52,211,153,.07);border:1px solid rgba(52,211,153,.28);color:#86efac;font-size:11px;line-height:1.5;font-style:italic;}
        .pi-overlay{position:fixed;inset:0;background:rgba(2,6,12,.78);backdrop-filter:blur(3px);display:none;align-items:flex-start;justify-content:center;padding:24px 14px;z-index:9000;overflow-y:auto;}
        .pi-overlay.is-open{display:flex;}
        .pi-modal{width:100%%;max-width:560px;background:#0b1422;border:1px solid #1f3253;border-radius:12px;padding:18px;display:flex;flex-direction:column;gap:14px;box-shadow:0 24px 60px rgba(0,0,0,.5);margin:auto;}
        .pi-modal-head{display:flex;gap:10px;align-items:flex-start;justify-content:space-between;}
        .pi-modal-title{margin:0;font-size:14px;font-weight:700;color:#e6edf6;letter-spacing:.03em;}
        .pi-modal-eyebrow{font-size:9px;letter-spacing:.2em;text-transform:uppercase;color:#34d399;font-weight:700;}
        .pi-x{border:1px solid #1f3253;background:rgba(8,14,22,.6);color:#cbd5e1;border-radius:6px;width:30px;height:30px;cursor:pointer;font-size:15px;line-height:1;flex:0 0 auto;}
        .pi-x:hover{border-color:#f87171;color:#f87171;}
        .pi-form{display:grid;grid-template-columns:1fr 1fr;gap:10px 12px;}
        @media (max-width:560px){.pi-form{grid-template-columns:1fr;}}
        .pi-field{display:flex;flex-direction:column;gap:4px;min-width:0;}
        .pi-field.pi-field-wide{grid-column:1 / -1;}
        .pi-field label{font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:#7dd3fc;font-weight:700;}
        .pi-field input,.pi-field select,.pi-field textarea{font-family:inherit;font-size:12px;color:#e6edf6;background:rgba(8,14,22,.7);border:1px solid #1f3253;border-radius:6px;padding:8px 10px;width:100%%;box-sizing:border-box;}
        .pi-field input:focus,.pi-field select:focus,.pi-field textarea:focus{outline:none;border-color:#34d399;}
        .pi-field textarea{resize:vertical;min-height:60px;}
        .pi-modal-foot{display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:space-between;}
        .pi-summary{padding:14px;border-radius:8px;background:rgba(134,239,172,.07);border:1px solid rgba(134,239,172,.3);display:none;flex-direction:column;gap:10px;}
        .pi-summary.is-on{display:flex;}
        .pi-sum-h{font-size:10.5px;letter-spacing:.22em;text-transform:uppercase;font-weight:700;color:#34d399;}
        .pi-sum-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;}
        @media (max-width:780px){.pi-sum-grid{grid-template-columns:1fr;}}
        .pi-sum-cell{padding:8px 10px;border-radius:6px;background:rgba(0,0,0,.3);border:1px solid #1f3253;min-width:0;}
        .pi-sum-k{font-size:9px;letter-spacing:.16em;text-transform:uppercase;color:#7dd3fc;font-weight:700;margin-bottom:3px;}
        .pi-sum-v{font-size:11.5px;color:#e6edf6;line-height:1.5;word-wrap:break-word;overflow-wrap:break-word;}
        .pi-sum-v.v-good{color:#86efac;}
        .pi-sum-next{padding:10px 12px;border-radius:6px;background:rgba(56,189,248,.08);border:1px solid rgba(56,189,248,.28);color:#bae6fd;font-size:11.5px;line-height:1.55;}
        .pi-sum-meta{font-family:"JetBrains Mono","SFMono-Regular",monospace;font-size:10px;color:#94a3b8;word-break:break-all;}
        .pi-err{color:#f87171;font-size:10.5px;margin:0;}
      </style>

      <div class="pi-head">
        <div>
          <div class="pi-eyebrow">● Pilot Intake // Prospect Experience</div>
          <h2 class="pi-h">Request a Governance Pilot</h2>
        </div>
        <span class="pi-pill">PREVIEW · NO SUBMISSION</span>
      </div>
      <p class="pi-sub">A clean prospect path from sector to pilot request: pick a sector and AI use case, run a governance scenario, review the enforcement and evidence outcome, preview the executive report, then request a governance pilot. Everything runs in this browser as a preview — no company data is submitted, stored, or transmitted.</p>

      <ol class="pi-steps" id="pi-steps" aria-label="Pilot intake progress">
        <li class="pi-step is-active" data-i="1"><span class="pi-step-n">Step 1</span><span class="pi-step-l">Select Sector</span></li>
        <li class="pi-step" data-i="2"><span class="pi-step-n">Step 2</span><span class="pi-step-l">Select AI Use Case</span></li>
        <li class="pi-step" data-i="3"><span class="pi-step-n">Step 3</span><span class="pi-step-l">Run Governance Scenario</span></li>
        <li class="pi-step" data-i="4"><span class="pi-step-n">Step 4</span><span class="pi-step-l">Review Enforcement + Evidence</span></li>
        <li class="pi-step" data-i="5"><span class="pi-step-n">Step 5</span><span class="pi-step-l">Preview Executive Report</span></li>
        <li class="pi-step" data-i="6"><span class="pi-step-n">Step 6</span><span class="pi-step-l">Request Pilot Intake</span></li>
      </ol>

      <div class="pi-row" role="tablist" aria-label="Sector">
        <span class="pi-row-label">1 · Select Sector</span>
        <button type="button" class="pi-chip active" data-sec="financial" role="tab" aria-selected="true">Financial Services</button>
        <button type="button" class="pi-chip" data-sec="healthcare" role="tab" aria-selected="false">Healthcare</button>
        <button type="button" class="pi-chip" data-sec="government" role="tab" aria-selected="false">Government</button>
        <button type="button" class="pi-chip" data-sec="rail" role="tab" aria-selected="false">Rail &amp; Transport</button>
        <button type="button" class="pi-chip" data-sec="infrastructure" role="tab" aria-selected="false">Critical Infrastructure</button>
        <button type="button" class="pi-chip" data-sec="industrial" role="tab" aria-selected="false">Industrial Automation</button>
      </div>

      <div class="pi-row" id="pi-usecases" role="tablist" aria-label="AI use case">
        <span class="pi-row-label">2 · Select AI Use Case</span>
      </div>

      <div class="pi-controls">
        <button type="button" class="pi-btn" id="pi-run" disabled>Run Governance Scenario ▶</button>
        <button type="button" class="pi-btn" id="pi-report" disabled>Preview Executive Report</button>
        <button type="button" class="pi-btn pi-ghost" id="pi-reset">Reset</button>
      </div>

      <div class="pi-panel" id="pi-panel" aria-live="polite">
        <span class="pi-panel-empty">Select a sector and AI use case, then run the governance scenario to see the enforcement decision and evidence outcome.</span>
      </div>

      <div class="pi-controls">
        <button type="button" class="pi-cta" id="pi-request" disabled>Request Governance Pilot</button>
      </div>
      <p class="pi-privacy" role="note">Preview only. No company data is submitted, stored, or transmitted.</p>

      <div class="pi-summary" id="pi-summary" aria-live="polite">
        <div class="pi-sum-h">● Pilot Intake Summary</div>
        <div class="pi-sum-grid" id="pi-sum-grid"></div>
        <div class="pi-sum-next" id="pi-sum-next"></div>
        <div class="pi-sum-meta" id="pi-sum-meta"></div>
      </div>

      <div class="pi-overlay" id="pi-overlay" role="dialog" aria-modal="true" aria-labelledby="pi-modal-title">
        <div class="pi-modal">
          <div class="pi-modal-head">
            <div>
              <div class="pi-modal-eyebrow">● Governance Pilot Request</div>
              <h3 class="pi-modal-title" id="pi-modal-title">Request a Governance Pilot</h3>
            </div>
            <button type="button" class="pi-x" id="pi-close" aria-label="Close">×</button>
          </div>
          <p class="pi-privacy" role="note">Preview only. No company data is submitted, stored, or transmitted.</p>
          <form class="pi-form" id="pi-form" novalidate>
            <div class="pi-field">
              <label for="pi-org">Organization name</label>
              <input type="text" id="pi-org" name="org" autocomplete="off" placeholder="Acme Holdings">
            </div>
            <div class="pi-field">
              <label for="pi-email">Contact email</label>
              <input type="email" id="pi-email" name="email" autocomplete="off" placeholder="name@company.com">
            </div>
            <div class="pi-field">
              <label for="pi-sector">Sector</label>
              <select id="pi-sector" name="sector"></select>
            </div>
            <div class="pi-field">
              <label for="pi-usecase">AI use case</label>
              <select id="pi-usecase" name="usecase"></select>
            </div>
            <div class="pi-field pi-field-wide">
              <label for="pi-concern">Governance concern</label>
              <textarea id="pi-concern" name="concern" placeholder="What governance risk are you trying to control?"></textarea>
            </div>
            <div class="pi-field pi-field-wide">
              <label for="pi-scope">Desired pilot scope</label>
              <textarea id="pi-scope" name="scope" placeholder="Which workflow would you place behind the gateway first?"></textarea>
            </div>
            <p class="pi-err" id="pi-form-err" role="alert" hidden></p>
            <div class="pi-modal-foot pi-field-wide">
              <button type="button" class="pi-btn pi-ghost" id="pi-cancel">Cancel</button>
              <button type="submit" class="pi-cta" id="pi-generate">Generate Pilot Summary</button>
            </div>
          </form>
        </div>
      </div>

      <script>
      (function(){
        var root=document.getElementById('usbsim-pilot-intake'); if(!root) return;
        var data={
          financial:{label:'Financial Services',usecases:['Credit decision triage','Fraud signal review','KYC onboarding check'],risk:'Unreviewed denial or silent approval reaches a customer.',controls:'Human review of record + signed policy enforcement at the gateway, with replay protection.',evidence:'Each decision sealed in an append-only audit chain; auditable and reproducible on demand.',pilot:'One high-stakes credit workflow behind the gateway with audit chain, replay guard, and reviewer of record (6–8 weeks).'},
          healthcare:{label:'Healthcare',usecases:['Eligibility triage','Care-plan recommendation','Claims pre-authorization'],risk:'Protected health data drives an unverifiable clinical recommendation.',controls:'Signed policy enforcement + clinician reviewer of record on patient-affecting decisions.',evidence:'Patient-affecting decisions traceable end to end in the sealed audit chain.',pilot:'One eligibility workflow behind the gateway with clinician review and sealed evidence (6–8 weeks).'},
          government:{label:'Government',usecases:['Benefit adjudication','Case-routing triage','Fraud anomaly review'],risk:'Citizen-facing decision issued without accountable review.',controls:'Fail-closed denial + named reviewer + append-only audit on anomalous claims.',evidence:'Denials recorded with reviewer id and policy version in the chain.',pilot:'One adjudication workflow behind the gateway with fail-closed denial and audit retrieval (6–8 weeks).'},
          rail:{label:'Rail & Transport',usecases:['Dispatch & routing','Maintenance scheduling','Incident escalation'],risk:'Unsigned schedule change propagates to safety-relevant operations.',controls:'Replay guard + signed policy on every dispatch action.',evidence:'Each change carries a verifiable signature and reviewer id in the chain.',pilot:'One dispatch workflow behind the gateway with replay protection and signed policy (6–8 weeks).'},
          infrastructure:{label:'Critical Infrastructure',usecases:['Grid load advisory','Setpoint optimization','Outage response'],risk:'Out-of-policy setpoint reaches a control system without oversight.',controls:'Fail-closed enforcement + reviewer of record + sealed evidence.',evidence:'Out-of-policy setpoints denied and recorded before reaching control.',pilot:'One load-advisory workflow behind the gateway with fail-closed enforcement (6–8 weeks).'},
          industrial:{label:'Industrial Automation',usecases:['Robotic process action','Quality-control gating','Predictive maintenance'],risk:'Autonomous action executed outside the approved operating envelope.',controls:'Policy-bounded execution + append-only audit chain.',evidence:'Actions outside signed bounds denied and sealed in the chain.',pilot:'One robotic workflow behind the gateway with policy-bounded execution and audit chain (6–8 weeks).'}
        };
        var stepEls={}; root.querySelectorAll('.pi-step').forEach(function(el){ stepEls[el.getAttribute('data-i')]=el; });
        var secBtns=root.querySelectorAll('.pi-chip[data-sec]');
        var ucRow=document.getElementById('pi-usecases');
        var panel=document.getElementById('pi-panel');
        var runBtn=document.getElementById('pi-run');
        var reportBtn=document.getElementById('pi-report');
        var resetBtn=document.getElementById('pi-reset');
        var requestBtn=document.getElementById('pi-request');
        var overlay=document.getElementById('pi-overlay');
        var closeBtn=document.getElementById('pi-close');
        var cancelBtn=document.getElementById('pi-cancel');
        var form=document.getElementById('pi-form');
        var formErr=document.getElementById('pi-form-err');
        var selSector=document.getElementById('pi-sector');
        var selUsecase=document.getElementById('pi-usecase');
        var summary=document.getElementById('pi-summary');
        var sumGrid=document.getElementById('pi-sum-grid');
        var sumNext=document.getElementById('pi-sum-next');
        var sumMeta=document.getElementById('pi-sum-meta');
        var sec='financial'; var uc=null; var ran=false; var reported=false; var lastFocus=null;
        function esc(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
        function hex(n){var a=new Uint8Array(n);(window.crypto||window.msCrypto).getRandomValues(a);return Array.from(a,function(b){return b.toString(16).padStart(2,'0');}).join('');}
        function setSteps(n){ for(var i=1;i<=6;i++){ var el=stepEls[i]; el.classList.remove('is-active','is-done'); if(i<n) el.classList.add('is-done'); else if(i===n) el.classList.add('is-active'); } }
        var reportedFlag=false;
        function refreshSteps(){ var n=1; if(uc) n=3; if(ran) n=4; if(reportedFlag) n=5; if(summary.classList.contains('is-on')) n=6; setSteps(n); }
        function renderUsecases(){
          var d=data[sec]; var html='<span class="pi-row-label">2 · Select AI Use Case</span>';
          d.usecases.forEach(function(u){ html+='<button type="button" class="pi-chip'+(u===uc?' active':'')+'" data-uc="'+esc(u)+'" role="tab" aria-selected="'+(u===uc?'true':'false')+'">'+esc(u)+'</button>'; });
          ucRow.innerHTML=html;
          ucRow.querySelectorAll('.pi-chip[data-uc]').forEach(function(b){ b.addEventListener('click',function(){ selectUsecase(b.getAttribute('data-uc')); }); });
        }
        function row(k,v,cls){ return '<span class="pi-k">'+esc(k)+'</span><span class="pi-v'+(cls?(' '+cls):'')+'">'+esc(v)+'</span>'; }
        function renderPanel(){
          var d=data[sec]; var html='';
          html+=row('Sector',d.label);
          if(uc) html+=row('AI Use Case',uc);
          if(ran){
            html+=row('Governance Scenario','USBAY evaluates the '+uc.toLowerCase()+' request for '+d.label+' against signed policy before any execution.');
            html+=row('Governance Risk',d.risk,'v-block');
            html+=row('Enforcement Action',d.controls,'v-good');
            html+=row('Evidence Outcome',d.evidence,'v-good');
          }
          if(reportedFlag){
            html+=row('Executive Report','Board-ready: '+d.label+' · '+uc+' governed at runtime; risk contained and evidence auditable on demand.','v-good');
            html+=row('Recommended Pilot',d.pilot);
          }
          panel.innerHTML=html||'<span class="pi-panel-empty">Select a sector and AI use case, then run the governance scenario.</span>';
        }
        function selectSector(slug){ sec=slug; uc=null; ran=false; reportedFlag=false; secBtns.forEach(function(b){ var a=b.getAttribute('data-sec')===slug; b.classList.toggle('active',a); b.setAttribute('aria-selected',a?'true':'false'); }); renderUsecases(); runBtn.disabled=true; reportBtn.disabled=true; requestBtn.disabled=true; summary.classList.remove('is-on'); renderPanel(); refreshSteps(); }
        function selectUsecase(u){ uc=u; ran=false; reportedFlag=false; renderUsecases(); runBtn.disabled=false; reportBtn.disabled=true; requestBtn.disabled=true; summary.classList.remove('is-on'); renderPanel(); refreshSteps(); }
        function runScenario(){ if(!uc) return; ran=true; reportBtn.disabled=false; renderPanel(); refreshSteps(); }
        function previewReport(){ if(!ran) return; reportedFlag=true; requestBtn.disabled=false; renderPanel(); refreshSteps(); }
        function resetAll(){ selectSector('financial'); }
        function syncFormSelectors(){
          selSector.innerHTML=Object.keys(data).map(function(k){ return '<option value="'+esc(k)+'"'+(k===sec?' selected':'')+'>'+esc(data[k].label)+'</option>'; }).join('');
          var d=data[sec]; selUsecase.innerHTML=d.usecases.map(function(u){ return '<option value="'+esc(u)+'"'+(u===uc?' selected':'')+'>'+esc(u)+'</option>'; }).join('');
        }
        function openModal(){ if(requestBtn.disabled) return; lastFocus=document.activeElement; syncFormSelectors(); formErr.hidden=true; overlay.classList.add('is-open'); var f=document.getElementById('pi-org'); if(f) f.focus(); }
        function closeModal(){ overlay.classList.remove('is-open'); if(lastFocus&&lastFocus.focus) lastFocus.focus(); }
        selSector.addEventListener('change',function(){ var d=data[selSector.value]; selUsecase.innerHTML=d.usecases.map(function(u){ return '<option value="'+esc(u)+'">'+esc(u)+'</option>'; }).join(''); });
        function buildSummary(vals){
          var d=data[vals.sector];
          sumGrid.innerHTML=[
            ['Selected Sector',d.label,''],
            ['Selected Use Case',vals.usecase,''],
            ['Relevant USBAY Controls',d.controls,'v-good'],
            ['Expected Evidence Output',d.evidence,'v-good'],
            ['Recommended Pilot Scope',vals.scope?vals.scope:d.pilot,''],
            ['Governance Concern',vals.concern?vals.concern:'Runtime control and auditable evidence for AI-driven decisions.','']
          ].map(function(x){ return '<div class="pi-sum-cell"><div class="pi-sum-k">'+esc(x[0])+'</div><div class="pi-sum-v'+(x[2]?(' '+x[2]):'')+'">'+esc(x[1])+'</div></div>'; }).join('');
          sumNext.textContent='Next step: this preview captures your governance pilot interest for '+vals.org+'. In a live engagement, the USBAY team would scope a 6–8 week governed pilot for '+d.label+' — '+vals.usecase+' and follow up at '+vals.email+'. Nothing has been submitted, stored, or transmitted from this preview.';
          sumMeta.textContent='intake '+('pi_'+hex(4))+' · sector '+vals.sector+' · simulated preview · no submission';
          summary.classList.add('is-on');
          refreshSteps();
        }
        form.addEventListener('submit',function(e){
          e.preventDefault();
          var vals={org:document.getElementById('pi-org').value.trim(),email:document.getElementById('pi-email').value.trim(),sector:selSector.value,usecase:selUsecase.value,concern:document.getElementById('pi-concern').value.trim(),scope:document.getElementById('pi-scope').value.trim()};
          if(!vals.org||!vals.email||!vals.usecase){ formErr.textContent='Add an organization name, contact email, and AI use case to generate the preview.'; formErr.hidden=false; return; }
          if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(vals.email)){ formErr.textContent='Enter a valid contact email to generate the preview.'; formErr.hidden=false; return; }
          formErr.hidden=true; closeModal(); buildSummary(vals); summary.scrollIntoView({behavior:'smooth',block:'nearest'});
        });
        secBtns.forEach(function(b){ b.addEventListener('click',function(){ selectSector(b.getAttribute('data-sec')); }); });
        runBtn.addEventListener('click',runScenario);
        reportBtn.addEventListener('click',previewReport);
        resetBtn.addEventListener('click',resetAll);
        requestBtn.addEventListener('click',openModal);
        closeBtn.addEventListener('click',closeModal);
        cancelBtn.addEventListener('click',closeModal);
        overlay.addEventListener('click',function(e){ if(e.target===overlay) closeModal(); });
        document.addEventListener('keydown',function(e){ if(e.key==='Escape'&&overlay.classList.contains('is-open')) closeModal(); });
        renderUsecases(); renderPanel(); refreshSteps();
      })();
      </script>
    </section>

    <section id="usbsim-tenancy" class="mt" aria-label="Multi-tenant governance simulation">
      <style>
        .mt{margin:26px 0;padding:22px;border:1px solid #1f3253;border-radius:14px;background:linear-gradient(180deg,rgba(13,18,30,.72),rgba(8,12,20,.72));}
        .mt-eyebrow{font-size:9px;letter-spacing:.24em;text-transform:uppercase;color:#a78bfa;font-weight:700;}
        .mt-title{margin:6px 0 4px;font-size:18px;font-weight:800;color:#e6edf6;letter-spacing:.02em;}
        .mt-sub{margin:0 0 16px;font-size:12px;line-height:1.6;color:#94a3b8;max-width:74ch;}
        .mt-row-label{display:block;font-size:9px;letter-spacing:.16em;text-transform:uppercase;color:#94a3b8;font-weight:700;margin-bottom:6px;}
        .mt-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:18px;}
        .mt-chip{font-size:11px;letter-spacing:.02em;font-weight:600;padding:7px 12px;border-radius:7px;border:1px solid #1f3253;background:rgba(8,14,22,.55);color:#cbd5e1;cursor:pointer;font-family:inherit;}
        .mt-chip:hover{border-color:#a78bfa;color:#c4b5fd;}
        .mt-chip.active{border-color:#a78bfa;background:rgba(167,139,250,.14);color:#c4b5fd;}
        .mt-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px;}
        .mt-card{padding:16px;border:1px solid #1f3253;border-radius:10px;background:rgba(8,14,22,.5);min-width:0;}
        .mt-card-hd{display:flex;align-items:center;gap:8px;margin-bottom:12px;}
        .mt-card-eyebrow{font-size:8.5px;letter-spacing:.2em;text-transform:uppercase;color:#a78bfa;font-weight:700;}
        .mt-card-name{font-size:14px;font-weight:800;color:#e6edf6;line-height:1.3;}
        .mt-card-sector{font-size:10.5px;color:#7dd3fc;font-weight:600;}
        .mt-kv{display:flex;flex-direction:column;gap:9px;}
        .mt-k{font-size:8.5px;letter-spacing:.16em;text-transform:uppercase;color:#94a3b8;font-weight:700;}
        .mt-v{font-size:12px;line-height:1.5;color:#e6edf6;overflow-wrap:break-word;word-break:break-word;}
        .mt-mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;color:#c4b5fd;}
        .mt-risk-bar{height:7px;border-radius:4px;background:rgba(148,163,184,.18);overflow:hidden;margin-top:4px;}
        .mt-risk-fill{height:100%%;border-radius:4px;background:linear-gradient(90deg,#34d399,#a78bfa);}
        .mt-iso{padding:16px;border:1px solid rgba(167,139,250,.32);border-radius:10px;background:rgba(167,139,250,.06);}
        .mt-iso-badge{display:inline-flex;align-items:center;gap:7px;font-size:12px;font-weight:800;color:#c4b5fd;letter-spacing:.04em;margin-bottom:14px;}
        .mt-iso-badge .dot{width:9px;height:9px;border-radius:50%%;background:#a78bfa;box-shadow:0 0 0 4px rgba(167,139,250,.18);}
        .mt-iso-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px;}
        .mt-iso-col{padding:11px 12px;border:1px solid #1f3253;border-radius:8px;background:rgba(8,14,22,.5);min-width:0;}
        .mt-iso-k{font-size:8.5px;letter-spacing:.16em;text-transform:uppercase;color:#94a3b8;font-weight:700;margin-bottom:6px;}
        .mt-iso-v{font-size:11.5px;line-height:1.45;color:#e6edf6;overflow-wrap:break-word;word-break:break-word;}
        .mt-iso-v .mt-mono{display:block;margin-top:3px;}
        .mt-matrix-label{font-size:8.5px;letter-spacing:.16em;text-transform:uppercase;color:#94a3b8;font-weight:700;margin-bottom:8px;}
        .mt-matrix{display:flex;flex-direction:column;gap:6px;}
        .mt-mrow{display:grid;grid-template-columns:1.4fr 1.3fr 1fr 1.2fr;gap:8px;align-items:center;padding:8px 10px;border:1px solid #1f3253;border-radius:6px;background:rgba(8,14,22,.45);font-size:10.5px;}
        .mt-mrow.active{border-color:#a78bfa;background:rgba(167,139,250,.1);}
        .mt-mrow .mt-mname{font-weight:700;color:#e6edf6;overflow-wrap:break-word;min-width:0;}
        .mt-mrow .mt-mcell{color:#cbd5e1;overflow-wrap:break-word;min-width:0;}
        .mt-mrow .mt-mcell .mt-mono{font-size:10px;}
        .mt-privacy{margin:16px 0 0;padding:8px 10px;border-radius:6px;background:rgba(167,139,250,.07);border:1px solid rgba(167,139,250,.28);color:#c4b5fd;font-size:11px;line-height:1.5;font-style:italic;}
        @media (max-width:780px){.mt-grid{grid-template-columns:1fr;}.mt-iso-grid{grid-template-columns:1fr;}}
        @media (max-width:560px){.mt-mrow{grid-template-columns:1fr 1fr;}}
      </style>
      <div class="mt-eyebrow">Multi-Tenant Governance</div>
      <h2 class="mt-title">Multi-Tenant Governance Simulation</h2>
      <p class="mt-sub">USBAY governs each organization as an isolated tenant. Every tenant carries its own policy hash, audit chain, governance posture, and pilot recommendation. Switching tenants swaps the entire governance state — policy, evidence, and posture never cross tenant boundaries.</p>
      <span class="mt-row-label">Select Tenant</span>
      <div class="mt-row" id="mt-chips" role="tablist"></div>
      <div class="mt-grid">
        <div class="mt-card" id="mt-identity"></div>
        <div class="mt-card" id="mt-posture"></div>
      </div>
      <div class="mt-iso">
        <span class="mt-iso-badge"><span class="dot"></span>Tenant Isolation Verified</span>
        <div class="mt-iso-grid">
          <div class="mt-iso-col"><div class="mt-iso-k">Separate Policy State</div><div class="mt-iso-v" id="mt-iso-policy"></div></div>
          <div class="mt-iso-col"><div class="mt-iso-k">Separate Evidence State</div><div class="mt-iso-v" id="mt-iso-evidence"></div></div>
          <div class="mt-iso-col"><div class="mt-iso-k">Separate Governance State</div><div class="mt-iso-v" id="mt-iso-gov"></div></div>
        </div>
        <div class="mt-matrix-label">All Tenants — Isolated State Comparison</div>
        <div class="mt-matrix" id="mt-matrix"></div>
      </div>
      <p class="mt-privacy">Preview only. No tenant data is persisted, authenticated, or stored. No database changes are made.</p>
      <script>
      (function(){
        var root = document.getElementById('usbsim-tenancy');
        if(!root) return;
        function esc(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
        function hex(n){var a=new Uint8Array(n);(window.crypto||window.msCrypto).getRandomValues(a);return Array.from(a,function(b){return b.toString(16).padStart(2,'0');}).join('');}
        var TENANTS = [
          {name:'Financial Services Org', sector:'Banking &amp; Capital Markets',
           policy:'pol-fin-7f3a9c2e', chain:'ac-fin-04b1-d29f', posture:'Strict — fail-closed on model drift; SOX &amp; PCI-DSS aligned',
           pilot:'8-week pilot: trading- and credit-model governance with full audit replay',
           summary:'Trading and credit AI runs under fail-closed enforcement with provenance-bound decisions and end-to-end audit replay.',
           risk:18, impact:'Cuts model-audit preparation from weeks to hours; protects high-value automated decisions',
           reg:'Audit-Ready (SOX, PCI-DSS)', evidence:'142 signed evidence records, chain intact'},
          {name:'Healthcare Org', sector:'Hospital &amp; Clinical Systems',
           policy:'pol-hlth-b8e1d440', chain:'ac-hlth-91c7-2a6e', posture:'PHI-minimizing — clinical fail-safe; HIPAA aligned',
           pilot:'6-week pilot: clinical-decision-support model oversight and PHI containment',
           summary:'Clinical AI is governed for PHI minimization with fail-safe blocking of unverified recommendations.',
           risk:22, impact:'Reduces patient-safety exposure; demonstrable PHI containment for accreditation',
           reg:'HIPAA Audit-Ready', evidence:'98 signed evidence records, PHI scope sealed'},
          {name:'Railway Operator', sector:'Signalling &amp; Rolling Stock',
           policy:'pol-rail-3d77a015', chain:'ac-rail-6f02-bb44', posture:'Safety-critical — fail-safe interlock; EN 50128 / CENELEC aligned',
           pilot:'10-week pilot: signalling-AI governance with safety-case evidence capture',
           summary:'Signalling and autonomy AI run behind fail-safe interlocks; every override is evidence-bound to the safety case.',
           risk:27, impact:'Prevents unsafe automated actions; accelerates safety-case sign-off',
           reg:'Safety-Case Ready (CENELEC)', evidence:'61 signed evidence records, interlock log sealed'},
          {name:'Government Agency', sector:'Public Sector &amp; Citizen Services',
           policy:'pol-gov-c1920ef6', chain:'ac-gov-7e35-10ab', posture:'Sovereignty-controlled — classified-data handling; traceable accountability',
           pilot:'12-week pilot: public-sector AI accountability and FOIA-traceable decisioning',
           summary:'Citizen-facing AI is governed for data sovereignty with FOIA-traceable, accountable decisions.',
           risk:25, impact:'Strengthens citizen trust; every decision is traceable and reviewable',
           reg:'Public-Sector Compliant (sovereignty controls)', evidence:'73 signed evidence records, sovereignty scope sealed'},
          {name:'Industrial Operator', sector:'OT &amp; Process Control',
           policy:'pol-ind-58aa6b9d', chain:'ac-ind-2c80-f173', posture:'OT-hardened — safety interlocks; IEC 62443 aligned',
           pilot:'8-week pilot: OT/AI control governance with command-integrity evidence',
           summary:'AI-assisted control actions pass through safety interlocks; unsafe commands are blocked and evidenced.',
           risk:31, impact:'Prevents unsafe control commands; protects continuous operations',
           reg:'OT-Compliance Ready (IEC 62443)', evidence:'54 signed evidence records, command log sealed'}
        ];
        var active = 0;
        var session = hex(4);
        function isoToken(t,kind){return kind + '-' + t.policy.split('-')[1] + '-' + session;}
        function renderChips(){
          var html = '';
          for(var i=0;i<TENANTS.length;i++){
            html += '<button type="button" class="mt-chip' + (i===active?' active':'') + '" data-i="' + i + '" role="tab" aria-selected="' + (i===active) + '">' + esc(TENANTS[i].name.replace(/&amp;/g,'&')) + '</button>';
          }
          document.getElementById('mt-chips').innerHTML = html;
          var btns = document.getElementById('mt-chips').querySelectorAll('.mt-chip');
          for(var j=0;j<btns.length;j++){
            btns[j].addEventListener('click', function(){ active = parseInt(this.getAttribute('data-i'),10); render(); });
          }
        }
        function renderIdentity(t){
          document.getElementById('mt-identity').innerHTML =
            '<div class="mt-card-hd"><div><div class="mt-card-eyebrow">Tenant Identity</div><div class="mt-card-name">' + t.name + '</div><div class="mt-card-sector">' + t.sector + '</div></div></div>' +
            '<div class="mt-kv">' +
            '<div><div class="mt-k">Policy Hash</div><div class="mt-v mt-mono">' + esc(t.policy) + '-' + esc(session) + '</div></div>' +
            '<div><div class="mt-k">Audit Chain ID</div><div class="mt-v mt-mono">' + esc(t.chain) + '</div></div>' +
            '<div><div class="mt-k">Governance Posture</div><div class="mt-v">' + t.posture + '</div></div>' +
            '<div><div class="mt-k">Pilot Recommendation</div><div class="mt-v">' + t.pilot + '</div></div>' +
            '</div>';
        }
        function renderPosture(t){
          var riskW = Math.max(4, Math.min(100, t.risk));
          document.getElementById('mt-posture').innerHTML =
            '<div class="mt-card-hd"><div><div class="mt-card-eyebrow">Governance State</div><div class="mt-card-name">Executive Posture</div></div></div>' +
            '<div class="mt-kv">' +
            '<div><div class="mt-k">Executive Summary</div><div class="mt-v">' + t.summary + '</div></div>' +
            '<div><div class="mt-k">Residual Risk Score</div><div class="mt-v">' + t.risk + ' / 100' +
              '<div class="mt-risk-bar"><div class="mt-risk-fill" style="width:' + riskW + 'px;max-width:100%%"></div></div></div></div>' +
            '<div><div class="mt-k">Business Impact</div><div class="mt-v">' + t.impact + '</div></div>' +
            '<div><div class="mt-k">Regulator Readiness</div><div class="mt-v">' + t.reg + '</div></div>' +
            '<div><div class="mt-k">Evidence State</div><div class="mt-v">' + t.evidence + '</div></div>' +
            '</div>';
        }
        function renderIsolation(t){
          document.getElementById('mt-iso-policy').innerHTML = 'Scoped to ' + t.name + '<span class="mt-mono">' + esc(isoToken(t,'policy')) + '</span>';
          document.getElementById('mt-iso-evidence').innerHTML = t.evidence + '<span class="mt-mono">' + esc(isoToken(t,'evidence')) + '</span>';
          document.getElementById('mt-iso-gov').innerHTML = t.posture.split(' — ')[0] + ' posture<span class="mt-mono">' + esc(isoToken(t,'gov')) + '</span>';
        }
        function renderMatrix(){
          var html = '';
          for(var i=0;i<TENANTS.length;i++){
            var t = TENANTS[i];
            html += '<div class="mt-mrow' + (i===active?' active':'') + '">' +
              '<div class="mt-mname">' + t.name + '</div>' +
              '<div class="mt-mcell"><span class="mt-mono">' + esc(t.policy) + '</span></div>' +
              '<div class="mt-mcell"><span class="mt-mono">' + esc(t.chain) + '</span></div>' +
              '<div class="mt-mcell">Isolated</div>' +
              '</div>';
          }
          document.getElementById('mt-matrix').innerHTML = html;
        }
        function render(){
          var t = TENANTS[active];
          renderChips(); renderIdentity(t); renderPosture(t); renderIsolation(t); renderMatrix();
        }
        render();
      })();
      </script>
    </section>

    <section id="usbsim-provider" class="pv" aria-label="AI provider integration simulation">
      <style>
        .pv{margin:26px 0;padding:22px;border:1px solid #1f3253;border-radius:14px;background:linear-gradient(180deg,rgba(13,18,30,.72),rgba(8,12,20,.72));}
        .pv-eyebrow{font-size:9px;letter-spacing:.24em;text-transform:uppercase;color:#f59e0b;font-weight:700;}
        .pv-title{margin:6px 0 4px;font-size:18px;font-weight:800;color:#e6edf6;letter-spacing:.02em;}
        .pv-sub{margin:0 0 16px;font-size:12px;line-height:1.6;color:#94a3b8;max-width:74ch;}
        .pv-row-label{display:block;font-size:9px;letter-spacing:.16em;text-transform:uppercase;color:#94a3b8;font-weight:700;margin-bottom:6px;}
        .pv-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:16px;}
        .pv-chip{font-size:11px;letter-spacing:.02em;font-weight:600;padding:7px 12px;border-radius:7px;border:1px solid #1f3253;background:rgba(8,14,22,.55);color:#cbd5e1;cursor:pointer;font-family:inherit;}
        .pv-chip:hover{border-color:#f59e0b;color:#fbbf24;}
        .pv-chip.active{border-color:#f59e0b;background:rgba(245,158,11,.14);color:#fbbf24;}
        .pv-statusbar{display:flex;flex-wrap:wrap;gap:10px 18px;align-items:center;padding:12px 14px;border:1px solid #1f3253;border-radius:10px;background:rgba(8,14,22,.5);margin-bottom:16px;}
        .pv-status-item{display:flex;flex-direction:column;gap:3px;min-width:0;}
        .pv-status-k{font-size:8.5px;letter-spacing:.18em;text-transform:uppercase;color:#94a3b8;font-weight:700;}
        .pv-status-v{font-size:12px;color:#e6edf6;font-weight:600;overflow-wrap:break-word;}
        .pv-status-badge{display:inline-flex;align-items:center;gap:7px;font-size:12px;font-weight:800;padding:6px 12px;border-radius:7px;border:1px solid #1f3253;color:#cbd5e1;background:rgba(8,14,22,.5);}
        .pv-status-badge .dot{width:8px;height:8px;border-radius:50%%;background:currentColor;}
        .pv-status-badge.authorized{border-color:#34d399;color:#6ee7b7;background:rgba(52,211,153,.12);}
        .pv-status-badge.blocked{border-color:#f87171;color:#fca5a5;background:rgba(248,113,113,.12);}
        .pv-status-badge.escalated{border-color:#f59e0b;color:#fbbf24;background:rgba(245,158,11,.12);}
        .pv-status-badge.idle{color:#94a3b8;}
        .pv-flow{display:flex;flex-direction:column;gap:0;margin-bottom:16px;}
        .pv-node{display:flex;gap:12px;align-items:flex-start;padding:12px 14px;border:1px solid #1f3253;border-radius:10px;background:rgba(8,14,22,.4);transition:border-color .2s,background .2s,opacity .2s;}
        .pv-node.active{border-color:#f59e0b;background:rgba(245,158,11,.08);}
        .pv-node.done{border-color:#34d399;background:rgba(52,211,153,.06);}
        .pv-node.blocked{border-color:#f87171;background:rgba(248,113,113,.08);}
        .pv-node.skipped{opacity:.45;}
        .pv-arrow{align-self:center;color:#475569;font-size:13px;line-height:1;margin:5px 0;}
        .pv-node-ic{width:24px;height:24px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:800;flex:0 0 auto;border:1px solid #1f3253;color:#94a3b8;}
        .pv-node.active .pv-node-ic{color:#fbbf24;border-color:#f59e0b;}
        .pv-node.done .pv-node-ic{color:#6ee7b7;border-color:#34d399;}
        .pv-node.blocked .pv-node-ic{color:#fca5a5;border-color:#f87171;}
        .pv-node-t{font-size:12.5px;font-weight:700;color:#e6edf6;line-height:1.3;}
        .pv-node-d{font-size:11px;color:#94a3b8;line-height:1.45;margin-top:2px;overflow-wrap:break-word;}
        .pv-actions{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px;}
        .pv-btn{font-size:11.5px;font-weight:700;padding:9px 16px;border-radius:8px;border:1px solid #f59e0b;background:rgba(245,158,11,.14);color:#fbbf24;cursor:pointer;font-family:inherit;}
        .pv-btn:hover:not(:disabled){background:rgba(245,158,11,.22);}
        .pv-btn:disabled{opacity:.45;cursor:not-allowed;}
        .pv-btn.ghost{border-color:#1f3253;background:rgba(8,14,22,.55);color:#cbd5e1;}
        .pv-events{border:1px solid #1f3253;border-radius:10px;background:rgba(8,14,22,.5);padding:14px;}
        .pv-events-hd{font-size:8.5px;letter-spacing:.16em;text-transform:uppercase;color:#94a3b8;font-weight:700;margin-bottom:10px;}
        .pv-evlist{display:flex;flex-direction:column;gap:6px;}
        .pv-ev{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;padding:8px 10px;border:1px solid #1f3253;border-radius:6px;background:rgba(8,14,22,.45);font-size:10.5px;}
        .pv-ev-name{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:700;color:#fbbf24;white-space:nowrap;}
        .pv-ev.allow .pv-ev-name{color:#6ee7b7;}
        .pv-ev.deny .pv-ev-name{color:#fca5a5;}
        .pv-ev-d{color:#cbd5e1;overflow-wrap:break-word;min-width:0;}
        .pv-ev-t{color:#64748b;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:9.5px;white-space:nowrap;}
        .pv-empty{font-size:11px;color:#64748b;font-style:italic;}
        .pv-privacy{margin:16px 0 0;padding:8px 10px;border-radius:6px;background:rgba(245,158,11,.07);border:1px solid rgba(245,158,11,.28);color:#fbbf24;font-size:11px;line-height:1.5;font-style:italic;}
        @media (max-width:560px){.pv-ev{grid-template-columns:1fr;gap:4px;}.pv-ev-name,.pv-ev-t{white-space:normal;}}
      </style>
      <div class="pv-eyebrow">AI Provider Integration</div>
      <h2 class="pv-title">AI Provider Integration Simulation</h2>
      <p class="pv-sub">USBAY governs every AI provider request at the boundary. Pick a provider and run a governed request to watch the full lifecycle — policy evaluation, optional human review, an allow or block decision, and a sealed evidence record. Simulation only: no external calls are made.</p>
      <span class="pv-row-label">Select Provider</span>
      <div class="pv-row" id="pv-chips" role="tablist"></div>
      <div class="pv-statusbar">
        <div class="pv-status-item"><span class="pv-status-k">Provider</span><span class="pv-status-v" id="pv-prov-name">&mdash;</span></div>
        <div class="pv-status-item"><span class="pv-status-k">Provider Status</span><span class="pv-status-badge idle" id="pv-status"><span class="dot"></span><span id="pv-status-text">Idle</span></span></div>
      </div>
      <div class="pv-flow" id="pv-flow"></div>
      <div class="pv-actions">
        <button type="button" class="pv-btn" id="pv-run">Run Governed Request</button>
        <button type="button" class="pv-btn ghost" id="pv-reset">Reset</button>
      </div>
      <div class="pv-events">
        <div class="pv-events-hd">Governance Events</div>
        <div class="pv-evlist" id="pv-events"><div class="pv-empty">No events yet. Run a governed request to generate provider lifecycle events.</div></div>
      </div>
      <p class="pv-privacy">Preview only. No external API calls are made and no real provider credentials are used. Simulation only.</p>
      <script>
      (function(){
        var root = document.getElementById('usbsim-provider');
        if(!root) return;
        function esc(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
        var PROVIDERS = [
          {id:'openai', name:'OpenAI', tag:'GPT-class hosted', status:'Authorized', cls:'authorized', review:false, decision:'allowed',
           reason:'Policy match: approved use case, provenance bound, request within tenant budget.'},
          {id:'anthropic', name:'Anthropic', tag:'Claude-class hosted', status:'Escalated', cls:'escalated', review:true, decision:'allowed',
           reason:'High-sensitivity prompt class triggered mandatory human review; reviewer approved.'},
          {id:'azure', name:'Azure OpenAI', tag:'Enterprise hosted', status:'Authorized', cls:'authorized', review:false, decision:'allowed',
           reason:'Enterprise tenant policy satisfied; region and data-residency constraints met.'},
          {id:'local', name:'Local Model', tag:'On-prem / unsigned', status:'Blocked', cls:'blocked', review:false, decision:'denied',
           reason:'Provenance unsigned and prompt class disallowed; request denied fail-closed.'}
        ];
        var STAGES = [
          {key:'request', ic:'1', t:'User Request', d:'Inbound AI request captured at the governance boundary.'},
          {key:'policy', ic:'2', t:'USBAY Policy Evaluation', d:'Request evaluated against tenant policy, provenance, and budget.'},
          {key:'review', ic:'3', t:'Human Review (if required)', d:'Escalated for human approval when policy mandates.'},
          {key:'decision', ic:'4', t:'Provider Call Decision', d:'Final enforcement decision applied to the provider call.'},
          {key:'evidence', ic:'5', t:'Evidence Sealed', d:'Outcome recorded and sealed into the evidence chain (simulated).'}
        ];
        var active = 0, running = false, timers = [];
        var elFlow = document.getElementById('pv-flow');
        var elChips = document.getElementById('pv-chips');
        var elEvents = document.getElementById('pv-events');
        var elRun = document.getElementById('pv-run');
        var elReset = document.getElementById('pv-reset');
        var elStatus = document.getElementById('pv-status');
        var elStatusText = document.getElementById('pv-status-text');
        var elProvName = document.getElementById('pv-prov-name');
        function clearTimers(){ for(var i=0;i<timers.length;i++){ clearTimeout(timers[i]); } timers = []; }
        function renderChips(){
          var html = '';
          for(var i=0;i<PROVIDERS.length;i++){
            html += '<button type="button" class="pv-chip' + (i===active?' active':'') + '" data-i="' + i + '" role="tab" aria-selected="' + (i===active) + '">' + esc(PROVIDERS[i].name) + '</button>';
          }
          elChips.innerHTML = html;
          var btns = elChips.querySelectorAll('.pv-chip');
          for(var j=0;j<btns.length;j++){
            btns[j].addEventListener('click', function(){ if(running) return; active = parseInt(this.getAttribute('data-i'),10); selectProvider(); });
          }
        }
        function nodeText(stage, p){
          if(stage.key==='decision'){ return p.decision==='allowed' ? 'Provider Call Approved' : 'Provider Call Blocked'; }
          return stage.t;
        }
        function nodeDesc(stage, p){
          if(stage.key==='decision'){ return p.reason; }
          if(stage.key==='review' && !p.review){ return 'Not required for this request — policy did not mandate human review.'; }
          return stage.d;
        }
        function renderFlow(states){
          var html = '';
          for(var i=0;i<STAGES.length;i++){
            var s = STAGES[i];
            var st = states ? states[s.key] : '';
            html += '<div class="pv-node ' + st + '" id="pv-node-' + s.key + '">' +
              '<div class="pv-node-ic">' + s.ic + '</div>' +
              '<div><div class="pv-node-t">' + esc(nodeText(s, PROVIDERS[active])) + '</div>' +
              '<div class="pv-node-d">' + esc(nodeDesc(s, PROVIDERS[active])) + '</div></div></div>';
            if(i < STAGES.length-1){ html += '<div class="pv-arrow">&#8595;</div>'; }
          }
          elFlow.innerHTML = html;
        }
        function setStatus(cls, text){
          elStatus.className = 'pv-status-badge ' + cls;
          elStatusText.textContent = text;
        }
        function setEmpty(){
          elEvents.innerHTML = '<div class="pv-empty">No events yet. Run a governed request to generate provider lifecycle events.</div>';
        }
        function emit(name, detail, kind, t){
          if(elEvents.querySelector('.pv-empty')){ elEvents.innerHTML = ''; }
          var cls = kind==='allow' ? ' allow' : (kind==='deny' ? ' deny' : '');
          var row = document.createElement('div');
          row.className = 'pv-ev' + cls;
          row.innerHTML = '<span class="pv-ev-name">' + esc(name) + '</span><span class="pv-ev-d">' + esc(detail) + '</span><span class="pv-ev-t">' + esc(t) + '</span>';
          elEvents.appendChild(row);
        }
        function selectProvider(){
          clearTimers(); running = false; elRun.disabled = false;
          var p = PROVIDERS[active];
          elProvName.textContent = p.name + ' \u2014 ' + p.tag;
          setStatus('idle', 'Idle');
          renderFlow({request:'',policy:'',review:(p.review?'':'skipped'),decision:'',evidence:''});
          setEmpty();
          renderChips();
        }
        function run(){
          if(running) return;
          var p = PROVIDERS[active];
          running = true; elRun.disabled = true; clearTimers(); setEmpty();
          var states = {request:'',policy:'',review:(p.review?'':'skipped'),decision:'',evidence:''};
          renderFlow(states);
          var t0 = Date.now();
          function stamp(){ return 'T+' + String(Date.now()-t0).padStart(4,'0') + 'ms'; }
          var seq = [];
          seq.push(function(){ states.request='active'; renderFlow(states); emit('provider_request_received','Request received at the governance boundary for ' + p.name + '.','neutral',stamp()); });
          seq.push(function(){ states.request='done'; states.policy='active'; renderFlow(states); emit('provider_policy_check','Request evaluated against tenant policy, provenance, and budget.','neutral',stamp()); });
          if(p.review){
            seq.push(function(){ states.policy='done'; states.review='active'; renderFlow(states); emit('provider_review_required','Mandatory human review triggered by policy; awaiting approval.','neutral',stamp()); });
            seq.push(function(){ states.review='done'; states.decision='active'; renderFlow(states); });
          } else {
            seq.push(function(){ states.policy='done'; states.decision='active'; renderFlow(states); });
          }
          if(p.decision==='allowed'){
            seq.push(function(){ states.decision='done'; renderFlow(states); emit('provider_allowed','Provider call authorized under policy.','allow',stamp()); setStatus(p.cls, p.status); });
          } else {
            seq.push(function(){ states.decision='blocked'; renderFlow(states); emit('provider_denied','Provider call blocked fail-closed.','deny',stamp()); setStatus(p.cls, p.status); });
          }
          seq.push(function(){ states.evidence='done'; renderFlow(states); emit('provider_evidence_sealed','Outcome sealed into the evidence chain (simulated).','neutral',stamp()); });
          seq.push(function(){ running=false; elRun.disabled=false; });
          for(var i=0;i<seq.length;i++){ (function(fn,idx){ timers.push(setTimeout(fn, 480*(idx+1))); })(seq[i], i); }
        }
        elRun.addEventListener('click', run);
        elReset.addEventListener('click', selectProvider);
        selectProvider();
      })();
      </script>
    </section>

    <section id="usbsim-ops" class="op" aria-label="Governance operations center">
      <style>
        .op{margin:26px 0;padding:22px;border:1px solid #1f3253;border-radius:14px;background:linear-gradient(180deg,rgba(13,18,30,.72),rgba(8,12,20,.72));}
        .op-eyebrow{font-size:9px;letter-spacing:.24em;text-transform:uppercase;color:#38bdf8;font-weight:700;}
        .op-title{margin:6px 0 4px;font-size:18px;font-weight:800;color:#e6edf6;letter-spacing:.02em;}
        .op-sub{margin:0 0 16px;font-size:12px;line-height:1.6;color:#94a3b8;max-width:74ch;}
        .op-actions{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:18px;}
        .op-btn{font-size:11.5px;font-weight:700;padding:9px 16px;border-radius:8px;border:1px solid #38bdf8;background:rgba(56,189,248,.14);color:#7dd3fc;cursor:pointer;font-family:inherit;}
        .op-btn:hover{background:rgba(56,189,248,.22);}
        .op-live{display:inline-flex;align-items:center;gap:7px;font-size:10px;letter-spacing:.14em;text-transform:uppercase;font-weight:700;color:#7dd3fc;}
        .op-live .dot{width:8px;height:8px;border-radius:50%%;background:#38bdf8;box-shadow:0 0 0 4px rgba(56,189,248,.18);}
        .op-block-hd{font-size:8.5px;letter-spacing:.18em;text-transform:uppercase;color:#94a3b8;font-weight:700;margin:0 0 10px;}
        .op-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:22px;}
        .op-stat{padding:14px;border:1px solid #1f3253;border-radius:10px;background:rgba(8,14,22,.5);min-width:0;}
        .op-stat-k{font-size:9px;letter-spacing:.12em;text-transform:uppercase;color:#94a3b8;font-weight:700;margin-bottom:8px;}
        .op-stat-v{font-size:24px;font-weight:800;color:#e6edf6;line-height:1;letter-spacing:.01em;}
        .op-stat.allow .op-stat-v{color:#6ee7b7;}
        .op-stat.block .op-stat-v{color:#fca5a5;}
        .op-stat.review .op-stat-v{color:#fbbf24;}
        .op-stat-sub{font-size:10px;color:#64748b;margin-top:6px;}
        .op-cols{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:22px;}
        .op-panel{padding:16px;border:1px solid #1f3253;border-radius:10px;background:rgba(8,14,22,.5);min-width:0;}
        .op-feed{display:flex;flex-direction:column;gap:6px;}
        .op-ev{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;padding:8px 10px;border:1px solid #1f3253;border-radius:6px;background:rgba(8,14,22,.45);font-size:10.5px;}
        .op-ev-name{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:700;color:#7dd3fc;white-space:nowrap;}
        .op-ev.allow .op-ev-name{color:#6ee7b7;}
        .op-ev.block .op-ev-name{color:#fca5a5;}
        .op-ev.review .op-ev-name{color:#fbbf24;}
        .op-ev-d{color:#cbd5e1;overflow-wrap:break-word;min-width:0;}
        .op-ev-t{color:#64748b;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:9.5px;white-space:nowrap;}
        .op-trend{display:flex;flex-direction:column;gap:14px;}
        .op-trend-row .op-trend-k{display:flex;justify-content:space-between;align-items:baseline;font-size:11px;font-weight:700;color:#e6edf6;margin-bottom:6px;}
        .op-trend-row .op-trend-k span{font-size:10px;color:#7dd3fc;font-weight:600;}
        .op-bars{display:flex;align-items:flex-end;gap:3px;height:46px;}
        .op-bar{flex:1 1 auto;border-radius:2px 2px 0 0;background:linear-gradient(180deg,#38bdf8,#0ea5e9);opacity:.85;min-height:3px;}
        .op-bars.review .op-bar{background:linear-gradient(180deg,#fbbf24,#f59e0b);}
        .op-bars.audit .op-bar{background:linear-gradient(180deg,#a78bfa,#8b5cf6);}
        .op-health{display:flex;flex-direction:column;gap:8px;}
        .op-hrow{display:grid;grid-template-columns:1fr auto;gap:10px;align-items:center;padding:10px 12px;border:1px solid #1f3253;border-radius:8px;background:rgba(8,14,22,.45);}
        .op-hname{font-size:12px;font-weight:700;color:#e6edf6;}
        .op-hsub{font-size:10px;color:#64748b;margin-top:2px;overflow-wrap:break-word;}
        .op-pill{display:inline-flex;align-items:center;gap:6px;font-size:10px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;padding:5px 10px;border-radius:6px;border:1px solid #34d399;color:#6ee7b7;background:rgba(52,211,153,.12);white-space:nowrap;}
        .op-pill .dot{width:7px;height:7px;border-radius:50%%;background:currentColor;}
        .op-privacy{margin:18px 0 0;padding:8px 10px;border-radius:6px;background:rgba(56,189,248,.07);border:1px solid rgba(56,189,248,.28);color:#7dd3fc;font-size:11px;line-height:1.5;font-style:italic;}
        @media (max-width:880px){.op-stats{grid-template-columns:repeat(2,1fr);}}
        @media (max-width:780px){.op-cols{grid-template-columns:1fr;}}
        @media (max-width:560px){.op-stats{grid-template-columns:1fr;}.op-ev{grid-template-columns:1fr;gap:4px;}.op-ev-name,.op-ev-t{white-space:normal;}}
      </style>
      <div class="op-eyebrow">Governance Operations</div>
      <h2 class="op-title">Governance Operations Center</h2>
      <p class="op-sub">A live operations view of USBAY governing AI requests across the estate &mdash; today's enforcement counts, a real-time activity feed, trend snapshots, and platform health. Preview-only: all figures are simulated and nothing is stored.</p>
      <div class="op-actions">
        <span class="op-live"><span class="dot"></span>Live snapshot</span>
        <button type="button" class="op-btn" id="op-refresh">Refresh Snapshot</button>
      </div>
      <div class="op-block-hd">Today</div>
      <div class="op-stats" id="op-stats"></div>
      <div class="op-cols">
        <div class="op-panel">
          <div class="op-block-hd">Governance Activity Feed</div>
          <div class="op-feed" id="op-feed"></div>
        </div>
        <div class="op-panel">
          <div class="op-block-hd">Governance Trends (preview)</div>
          <div class="op-trend" id="op-trends"></div>
        </div>
      </div>
      <div class="op-block-hd">Governance Health</div>
      <div class="op-health" id="op-health"></div>
      <p class="op-privacy">Preview-only simulation. No backend storage and no real data &mdash; all counts, events, trends, and health states are generated client-side.</p>
      <script>
      (function(){
        var root = document.getElementById('usbsim-ops');
        if(!root) return;
        function esc(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
        function ri(min,max){ return Math.floor(min + Math.random()*(max-min+1)); }
        function fmt(n){ return n.toLocaleString('en-US'); }
        function pick(a){ return a[Math.floor(Math.random()*a.length)]; }
        var elStats = document.getElementById('op-stats');
        var elFeed = document.getElementById('op-feed');
        var elTrends = document.getElementById('op-trends');
        var elHealth = document.getElementById('op-health');
        var EVENTS = [
          {name:'policy_loaded', kind:'', d:'Tenant policy bundle loaded and verified.'},
          {name:'provider_allowed', kind:'allow', d:'Provider call authorized under policy.'},
          {name:'provider_blocked', kind:'block', d:'Provider call blocked fail-closed.'},
          {name:'review_requested', kind:'review', d:'Human review escalation raised.'},
          {name:'evidence_sealed', kind:'', d:'Outcome sealed into the evidence chain.'}
        ];
        var TRENDS = [
          {key:'enforce', label:'Enforcement Activity', cls:'', tag:'allow / block decisions'},
          {key:'review', label:'Review Activity', cls:'review', tag:'human escalations'},
          {key:'audit', label:'Audit Activity', cls:'audit', tag:'evidence records sealed'}
        ];
        var HEALTH = [
          {name:'Policy Integrity', sub:'Active policy bundle signature verified'},
          {name:'Audit Health', sub:'Hash chain continuous, no gaps detected'},
          {name:'Evidence Health', sub:'All evidence records sealed and resolvable'},
          {name:'Replay Protection', sub:'Nonce window enforced, no replays observed'},
          {name:'Runtime Integrity', sub:'Gateway fail-closed posture confirmed'}
        ];
        function renderStats(){
          var evaluated = ri(1180, 1460);
          var blocked = ri(70, 130);
          var reviews = ri(30, 60);
          var escalations = ri(10, 28);
          var allowed = evaluated - blocked;
          var cards = [
            {k:'Requests Evaluated', v:evaluated, c:'', s:'across all tenants'},
            {k:'Requests Allowed', v:allowed, c:'allow', s:'authorized under policy'},
            {k:'Requests Blocked', v:blocked, c:'block', s:'fail-closed enforcement'},
            {k:'Human Reviews', v:reviews, c:'review', s:'reviewer decisions'},
            {k:'Escalations', v:escalations, c:'review', s:'raised to human review'},
            {k:'Evidence Records', v:evaluated, c:'', s:'sealed into chain'}
          ];
          var html = '';
          for(var i=0;i<cards.length;i++){
            html += '<div class="op-stat ' + cards[i].c + '"><div class="op-stat-k">' + esc(cards[i].k) + '</div>' +
              '<div class="op-stat-v">' + fmt(cards[i].v) + '</div>' +
              '<div class="op-stat-sub">' + esc(cards[i].s) + '</div></div>';
          }
          elStats.innerHTML = html;
        }
        function renderFeed(){
          var html = '';
          var t = ri(2, 9);
          for(var i=0;i<7;i++){
            var e = (i < EVENTS.length) ? EVENTS[i] : pick(EVENTS);
            var cls = e.kind ? (' ' + e.kind) : '';
            html += '<div class="op-ev' + cls + '"><span class="op-ev-name">' + esc(e.name) + '</span>' +
              '<span class="op-ev-d">' + esc(e.d) + '</span>' +
              '<span class="op-ev-t">' + esc(t + 'm ago') + '</span></div>';
            t += ri(1, 6);
          }
          elFeed.innerHTML = html;
        }
        function renderTrends(){
          var html = '';
          for(var i=0;i<TRENDS.length;i++){
            var tr = TRENDS[i];
            var bars = '';
            var total = 0; var n = 14;
            for(var b=0;b<n;b++){
              var h = ri(8, 44);
              total += h;
              bars += '<div class="op-bar" style="height:' + h + 'px"></div>';
            }
            var avg = Math.round(total / n);
            html += '<div class="op-trend-row"><div class="op-trend-k">' + esc(tr.label) +
              '<span>' + esc(tr.tag) + '</span></div>' +
              '<div class="op-bars ' + tr.cls + '">' + bars + '</div></div>';
          }
          elTrends.innerHTML = html;
        }
        function renderHealth(){
          var states = ['Operational','Verified','Healthy','Enforced','Nominal'];
          var html = '';
          for(var i=0;i<HEALTH.length;i++){
            html += '<div class="op-hrow"><div><div class="op-hname">' + esc(HEALTH[i].name) + '</div>' +
              '<div class="op-hsub">' + esc(HEALTH[i].sub) + '</div></div>' +
              '<span class="op-pill"><span class="dot"></span>' + esc(states[i]) + '</span></div>';
          }
          elHealth.innerHTML = html;
        }
        function render(){ renderStats(); renderFeed(); renderTrends(); renderHealth(); }
        document.getElementById('op-refresh').addEventListener('click', render);
        render();
      })();
      </script>
    </section>

    <section id="usbsim-assurance" class="as" aria-label="Governance assurance dashboard">
      <style>
        .as{margin:26px 0;padding:22px;border:1px solid #1f3253;border-radius:14px;background:linear-gradient(180deg,rgba(13,18,30,.72),rgba(8,12,20,.72));}
        .as-eyebrow{font-size:9px;letter-spacing:.24em;text-transform:uppercase;color:#2dd4bf;font-weight:700;}
        .as-title{margin:6px 0 4px;font-size:18px;font-weight:800;color:#e6edf6;letter-spacing:.02em;}
        .as-sub{margin:0 0 16px;font-size:12px;line-height:1.6;color:#94a3b8;max-width:74ch;}
        .as-actions{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:18px;}
        .as-btn{font-size:11.5px;font-weight:700;padding:9px 16px;border-radius:8px;border:1px solid #2dd4bf;background:rgba(45,212,191,.14);color:#5eead4;cursor:pointer;font-family:inherit;}
        .as-btn:hover{background:rgba(45,212,191,.22);}
        .as-live{display:inline-flex;align-items:center;gap:7px;font-size:10px;letter-spacing:.14em;text-transform:uppercase;font-weight:700;color:#5eead4;}
        .as-live .dot{width:8px;height:8px;border-radius:50%%;background:#2dd4bf;box-shadow:0 0 0 4px rgba(45,212,191,.18);}
        .as-block-hd{font-size:8.5px;letter-spacing:.18em;text-transform:uppercase;color:#94a3b8;font-weight:700;margin:0 0 10px;}
        .as-pillars{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:22px;}
        .as-pillar{padding:15px;border:1px solid #1f3253;border-radius:10px;background:rgba(8,14,22,.5);min-width:0;display:flex;flex-direction:column;gap:8px;}
        .as-pillar-hd{display:flex;align-items:center;justify-content:space-between;gap:8px;}
        .as-pillar-n{font-size:12.5px;font-weight:800;color:#e6edf6;letter-spacing:.01em;}
        .as-pillar-s{font-size:10.5px;color:#94a3b8;line-height:1.5;overflow-wrap:break-word;min-width:0;}
        .as-pillar-meta{font-size:9.5px;color:#64748b;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere;}
        .as-pill{display:inline-flex;align-items:center;gap:6px;font-size:9.5px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;padding:5px 9px;border-radius:6px;border:1px solid #2dd4bf;color:#5eead4;background:rgba(45,212,191,.12);white-space:nowrap;}
        .as-pill .tick{width:7px;height:7px;border-radius:50%%;background:currentColor;}
        .as-cols{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:22px;}
        .as-panel{padding:16px;border:1px solid #1f3253;border-radius:10px;background:rgba(8,14,22,.5);min-width:0;}
        .as-vrows{display:flex;flex-direction:column;gap:8px;}
        .as-vrow{display:grid;grid-template-columns:1fr auto;gap:10px;align-items:center;padding:10px 12px;border:1px solid #1f3253;border-radius:8px;background:rgba(8,14,22,.45);}
        .as-vname{font-size:12px;font-weight:700;color:#e6edf6;}
        .as-vsub{font-size:10px;color:#64748b;margin-top:2px;overflow-wrap:break-word;}
        .as-vval{font-size:13px;font-weight:800;color:#5eead4;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;white-space:nowrap;}
        .as-meta{margin-top:12px;font-size:10px;color:#64748b;font-style:italic;}
        .as-controls{display:flex;flex-direction:column;gap:8px;}
        .as-crow{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;padding:10px 12px;border:1px solid #1f3253;border-radius:8px;background:rgba(8,14,22,.45);}
        .as-ctick{width:22px;height:22px;border-radius:50%%;display:inline-flex;align-items:center;justify-content:center;background:rgba(45,212,191,.14);border:1px solid #2dd4bf;color:#5eead4;font-size:12px;font-weight:800;}
        .as-cname{font-size:12px;font-weight:700;color:#e6edf6;}
        .as-csub{font-size:10px;color:#64748b;margin-top:2px;overflow-wrap:break-word;}
        .as-cstate{font-size:9.5px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:#5eead4;white-space:nowrap;}
        .as-privacy{margin:18px 0 0;padding:8px 10px;border-radius:6px;background:rgba(45,212,191,.07);border:1px solid rgba(45,212,191,.28);color:#5eead4;font-size:11px;line-height:1.5;font-style:italic;}
        @media (max-width:880px){.as-pillars{grid-template-columns:repeat(2,1fr);}}
        @media (max-width:780px){.as-cols{grid-template-columns:1fr;}}
        @media (max-width:560px){.as-pillars{grid-template-columns:1fr;}.as-crow{grid-template-columns:auto 1fr;}.as-cstate{grid-column:2;justify-self:start;}}
      </style>
      <div class="as-eyebrow">Platform Assurance</div>
      <h2 class="as-title">Governance Assurance</h2>
      <p class="as-sub">Why USBAY itself can be trusted &mdash; the platform's own integrity domains, its most recent validation snapshot, and the governance controls verified to be active. Preview-only: this view summarizes USBAY's assurance posture and stores nothing.</p>
      <div class="as-actions">
        <span class="as-live"><span class="dot"></span>Assurance verified</span>
        <button type="button" class="as-btn" id="as-refresh">Re-run Checks</button>
      </div>
      <div class="as-block-hd">Integrity Domains</div>
      <div class="as-pillars" id="as-pillars"></div>
      <div class="as-cols">
        <div class="as-panel">
          <div class="as-block-hd">Last Validation</div>
          <div class="as-vrows" id="as-validation"></div>
          <p class="as-meta" id="as-validation-meta"></p>
        </div>
        <div class="as-panel">
          <div class="as-block-hd">Governance Controls Verified</div>
          <div class="as-controls" id="as-controls"></div>
        </div>
      </div>
      <p class="as-privacy">Preview-only simulation. No backend storage and no real data &mdash; integrity domains, validation results, and control states are rendered client-side to illustrate USBAY's assurance posture.</p>
      <script>
      (function(){
        var root = document.getElementById('usbsim-assurance');
        if(!root) return;
        function esc(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
        function ri(min,max){ return Math.floor(min + Math.random()*(max-min+1)); }
        var elPillars = document.getElementById('as-pillars');
        var elValidation = document.getElementById('as-validation');
        var elValidationMeta = document.getElementById('as-validation-meta');
        var elControls = document.getElementById('as-controls');
        var PILLARS = [
          {name:'Policy Integrity', sub:'Active policy bundle is cryptographically signed and the signature is verified before enforcement.', meta:'ed25519 signature verified'},
          {name:'Audit Integrity', sub:'Decisions are written to an append-only hash chain that is continuous with no detectable gaps.', meta:'hash chain continuous'},
          {name:'Evidence Integrity', sub:'Every governed outcome is sealed and remains independently resolvable on demand.', meta:'all records resolvable'},
          {name:'Replay Protection', sub:'A nonce plus timestamp window rejects replayed or stale requests at the gateway.', meta:'nonce window enforced'},
          {name:'Runtime Verification', sub:'The gateway runs in a fail-closed posture and its runtime parity is attested.', meta:'fail-closed attested'}
        ];
        var VALIDATION = [
          {name:'Tests passed', sub:'Automated governance test suite', val:'44 / 44'},
          {name:'Routes healthy', sub:'Gateway + playground surfaces', val:'7 / 7 · 200'},
          {name:'Evidence verified', sub:'Sealed records resolvable', val:'VERIFIED'}
        ];
        var CONTROLS = [
          {name:'Fail Closed', sub:'Denies any request it cannot positively authorize.'},
          {name:'Replay Guard', sub:'Rejects replayed requests outside the nonce window.'},
          {name:'Audit Chain', sub:'Tamper-evident, append-only record of every decision.'},
          {name:'Human Review', sub:'Escalation path enforced for high-risk outcomes.'}
        ];
        function renderPillars(){
          var html = '';
          for(var i=0;i<PILLARS.length;i++){
            html += '<div class="as-pillar"><div class="as-pillar-hd"><span class="as-pillar-n">' + esc(PILLARS[i].name) + '</span>' +
              '<span class="as-pill"><span class="tick"></span>Verified</span></div>' +
              '<div class="as-pillar-s">' + esc(PILLARS[i].sub) + '</div>' +
              '<div class="as-pillar-meta">' + esc(PILLARS[i].meta) + '</div></div>';
          }
          elPillars.innerHTML = html;
        }
        function renderValidation(){
          var html = '';
          for(var i=0;i<VALIDATION.length;i++){
            html += '<div class="as-vrow"><div><div class="as-vname">' + esc(VALIDATION[i].name) + '</div>' +
              '<div class="as-vsub">' + esc(VALIDATION[i].sub) + '</div></div>' +
              '<span class="as-vval">' + esc(VALIDATION[i].val) + '</span></div>';
          }
          elValidation.innerHTML = html;
          elValidationMeta.textContent = 'Last validated ' + ri(2, 9) + 'm ago · all checks green';
        }
        function renderControls(){
          var html = '';
          for(var i=0;i<CONTROLS.length;i++){
            html += '<div class="as-crow"><span class="as-ctick">&#10003;</span>' +
              '<div><div class="as-cname">' + esc(CONTROLS[i].name) + '</div>' +
              '<div class="as-csub">' + esc(CONTROLS[i].sub) + '</div></div>' +
              '<span class="as-cstate">Verified</span></div>';
          }
          elControls.innerHTML = html;
        }
        function render(){ renderPillars(); renderValidation(); renderControls(); }
        document.getElementById('as-refresh').addEventListener('click', render);
        render();
      })();
      </script>
    </section>

    <section id="usbsim-launcher" class="lx" aria-label="Live governance scenario launcher">
      <style>
        .lx{margin:26px 0;padding:22px;border:1px solid #1f3253;border-radius:14px;background:linear-gradient(180deg,rgba(13,18,30,.72),rgba(8,12,20,.72));}
        .lx-eyebrow{font-size:9px;letter-spacing:.24em;text-transform:uppercase;color:#f59e0b;font-weight:700;}
        .lx-title{margin:6px 0 4px;font-size:18px;font-weight:800;color:#e6edf6;letter-spacing:.02em;}
        .lx-sub{margin:0 0 16px;font-size:12px;line-height:1.6;color:#94a3b8;max-width:74ch;}
        .lx-block-hd{font-size:8.5px;letter-spacing:.18em;text-transform:uppercase;color:#94a3b8;font-weight:700;margin:0 0 10px;}
        .lx-scenarios{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:16px;}
        .lx-scn{text-align:left;padding:12px 13px;border:1px solid #1f3253;border-radius:10px;background:rgba(8,14,22,.5);cursor:pointer;font-family:inherit;color:#cbd5e1;display:flex;flex-direction:column;gap:4px;min-width:0;transition:border-color .18s,background .18s;}
        .lx-scn:hover{border-color:#f59e0b;}
        .lx-scn.active{border-color:#f59e0b;background:rgba(245,158,11,.12);}
        .lx-scn-n{font-size:12px;font-weight:800;color:#e6edf6;letter-spacing:.01em;}
        .lx-scn-d{font-size:10px;color:#94a3b8;line-height:1.45;overflow-wrap:break-word;}
        .lx-actions{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:18px;}
        .lx-btn{font-size:11.5px;font-weight:700;padding:9px 16px;border-radius:8px;border:1px solid #f59e0b;background:rgba(245,158,11,.16);color:#fbbf24;cursor:pointer;font-family:inherit;}
        .lx-btn:hover{background:rgba(245,158,11,.26);}
        .lx-btn:disabled{opacity:.45;cursor:not-allowed;}
        .lx-btn.ghost{border-color:#334155;background:transparent;color:#94a3b8;}
        .lx-hint{font-size:10.5px;color:#64748b;font-style:italic;}
        .lx-flow{display:grid;grid-template-columns:repeat(6,1fr);gap:6px;margin-bottom:20px;}
        .lx-stage{padding:9px 10px;border-radius:8px;border:1px solid #1f3253;background:rgba(8,14,22,.5);display:flex;flex-direction:column;gap:3px;color:#64748b;transition:border-color .2s,background .2s,color .2s;min-width:0;}
        .lx-stage.is-active{border-color:#f59e0b;background:rgba(245,158,11,.12);color:#fbbf24;}
        .lx-stage.is-done{border-color:#86efac;background:rgba(134,239,172,.07);color:#86efac;}
        .lx-stage-n{font-size:8.5px;letter-spacing:.14em;text-transform:uppercase;font-weight:700;}
        .lx-stage-l{font-size:10.5px;font-weight:700;color:#e6edf6;line-height:1.3;}
        .lx-stage.is-active .lx-stage-l,.lx-stage.is-done .lx-stage-l{color:inherit;}
        .lx-out{display:grid;grid-template-columns:1fr 1fr;gap:14px;}
        .lx-panel{padding:16px;border:1px solid #1f3253;border-radius:10px;background:rgba(8,14,22,.5);min-width:0;}
        .lx-panel.wide{grid-column:1 / -1;}
        .lx-empty{font-size:11.5px;color:#64748b;font-style:italic;line-height:1.55;}
        .lx-path{display:flex;flex-direction:column;gap:6px;}
        .lx-pstep{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;padding:8px 10px;border:1px solid #1f3253;border-radius:6px;background:rgba(8,14,22,.45);font-size:10.5px;}
        .lx-pstep-c{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:800;color:#fbbf24;white-space:nowrap;}
        .lx-pstep.allow .lx-pstep-c{color:#6ee7b7;}
        .lx-pstep.block .lx-pstep-c{color:#fca5a5;}
        .lx-pstep-d{color:#cbd5e1;overflow-wrap:break-word;min-width:0;}
        .lx-pstep-t{color:#64748b;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:9.5px;white-space:nowrap;}
        .lx-kv{display:flex;flex-direction:column;gap:7px;}
        .lx-kvrow{display:grid;grid-template-columns:128px 1fr;gap:10px;align-items:baseline;font-size:11px;}
        .lx-k{font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:#94a3b8;font-weight:700;}
        .lx-v{color:#e6edf6;font-weight:600;overflow-wrap:anywhere;min-width:0;}
        .lx-v.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:500;color:#cbd5e1;}
        .lx-badge{display:inline-flex;align-items:center;gap:6px;font-size:9.5px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;padding:4px 9px;border-radius:6px;border:1px solid #34d399;color:#6ee7b7;background:rgba(52,211,153,.12);white-space:nowrap;}
        .lx-badge.block{border-color:#f87171;color:#fca5a5;background:rgba(248,113,113,.12);}
        .lx-exec{font-size:12px;line-height:1.6;color:#cbd5e1;}
        .lx-exec b{color:#e6edf6;}
        .lx-privacy{margin:18px 0 0;padding:8px 10px;border-radius:6px;background:rgba(245,158,11,.07);border:1px solid rgba(245,158,11,.28);color:#fbbf24;font-size:11px;line-height:1.5;font-style:italic;}
        @media (max-width:880px){.lx-scenarios{grid-template-columns:repeat(2,1fr);}.lx-flow{grid-template-columns:repeat(3,1fr);}}
        @media (max-width:780px){.lx-out{grid-template-columns:1fr;}}
        @media (max-width:560px){.lx-scenarios{grid-template-columns:1fr;}.lx-flow{grid-template-columns:repeat(2,1fr);}.lx-pstep{grid-template-columns:1fr;gap:4px;}.lx-pstep-c,.lx-pstep-t{white-space:normal;}.lx-kvrow{grid-template-columns:1fr;gap:2px;}}
      </style>
      <div class="lx-eyebrow">Interactive Demonstration</div>
      <h2 class="lx-title">Live Governance Scenario Launcher</h2>
      <p class="lx-sub">Run a governance demonstration yourself. Pick a scenario, launch it, and watch USBAY orchestrate the existing platform &mdash; Control Plane, Gateway, Evidence, and Audit &mdash; into a live decision path with a sealed evidence record, an audit event, and an executive summary. Preview-only: the flow is simulated client-side and nothing is stored.</p>
      <div class="lx-block-hd">1 &middot; Select Scenario</div>
      <div class="lx-scenarios" id="lx-scenarios"></div>
      <div class="lx-actions">
        <button type="button" class="lx-btn" id="lx-run" disabled>Run Scenario &#9654;</button>
        <button type="button" class="lx-btn ghost" id="lx-reset">Reset</button>
        <span class="lx-hint" id="lx-hint">Select a scenario to begin.</span>
      </div>
      <div class="lx-block-hd">Governance Flow</div>
      <div class="lx-flow" id="lx-flow"></div>
      <div class="lx-out">
        <div class="lx-panel wide">
          <div class="lx-block-hd">Live Decision Path</div>
          <div id="lx-path"><p class="lx-empty">Run a scenario to watch the decision move through Control Plane, Gateway, Evidence, and Audit.</p></div>
        </div>
        <div class="lx-panel">
          <div class="lx-block-hd">Evidence Record</div>
          <div id="lx-evidence"><p class="lx-empty">No evidence sealed yet.</p></div>
        </div>
        <div class="lx-panel">
          <div class="lx-block-hd">Audit Event</div>
          <div id="lx-audit"><p class="lx-empty">No audit event recorded yet.</p></div>
        </div>
        <div class="lx-panel wide">
          <div class="lx-block-hd">Executive Summary</div>
          <div id="lx-exec"><p class="lx-empty">The executive outcome will appear once the scenario completes.</p></div>
        </div>
      </div>
      <p class="lx-privacy">Preview-only simulation. No backend storage and no real data &mdash; this launcher orchestrates a client-side representation of the existing governance flow and adds no new governance logic.</p>
      <script>
      (function(){
        var root = document.getElementById('usbsim-launcher');
        if(!root) return;
        function esc(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
        function hex(n){var a=new Uint8Array(n);(window.crypto||window.msCrypto).getRandomValues(a);return Array.from(a,function(b){return b.toString(16).padStart(2,'0');}).join('');}
        function ri(min,max){ return Math.floor(min + Math.random()*(max-min+1)); }
        function clk(){ var d=new Date(); function p(x){ return (x<10?'0':'')+x; } return p(d.getHours())+':'+p(d.getMinutes())+':'+p(d.getSeconds()); }
        var SCN = [
          {id:'financial', name:'Financial Credit Decision', d:'High-stakes credit triage with reviewer of record.', decision:'allow', risk:'High', review:true,
            gov:'Signed credit policy bundle loaded and matched to the request.',
            enf:'Gateway authorized the decision under policy with a human reviewer of record.',
            ev:'Credit decision sealed with reviewer id and policy version.',
            exec:'Credit decision <b>approved under governance</b> with a named reviewer of record. Fully reproducible from sealed evidence; pilot-ready for one high-stakes credit workflow.'},
          {id:'healthcare', name:'Healthcare Eligibility', d:'Eligibility triage on protected health data.', decision:'allow', risk:'High', review:true,
            gov:'Patient-affecting policy loaded; clinician review required.',
            enf:'Gateway authorized with a clinician reviewer of record before action.',
            ev:'Eligibility decision sealed and traceable end to end.',
            exec:'Eligibility recommendation <b>cleared with clinician oversight</b>. Every patient-affecting decision is traceable in the sealed chain; pilot-ready for one eligibility workflow.'},
          {id:'government', name:'Government Benefit Review', d:'Benefit adjudication with anomaly screening.', decision:'block', risk:'Critical', review:true,
            gov:'Adjudication policy loaded; anomaly signal detected on the claim.',
            enf:'Gateway denied fail-closed and routed the claim to a named reviewer.',
            ev:'Denial recorded with reviewer id and policy version in the chain.',
            exec:'Benefit decision <b>denied fail-closed</b> pending accountable review. The denial is recorded with reviewer of record; pilot-ready for one adjudication workflow.'},
          {id:'rail', name:'Railway Dispatch Decision', d:'Dispatch change with replay protection.', decision:'allow', risk:'High', review:false,
            gov:'Signed dispatch policy loaded; schedule change validated.',
            enf:'Gateway authorized the signed change with replay protection enforced.',
            ev:'Dispatch action sealed with a verifiable signature and reviewer id.',
            exec:'Dispatch change <b>authorized under signed policy</b> with replay protection. Each change carries a verifiable signature; pilot-ready for one dispatch workflow.'},
          {id:'industrial', name:'Industrial Automation Action', d:'Robotic action checked against operating envelope.', decision:'block', risk:'Critical', review:false,
            gov:'Policy-bounded execution loaded; action falls outside signed bounds.',
            enf:'Gateway denied fail-closed before the action could execute.',
            ev:'Out-of-bounds action denied and sealed in the audit chain.',
            exec:'Automation action <b>blocked fail-closed</b> for falling outside the approved envelope. The denial is sealed and reproducible; pilot-ready for one robotic workflow.'},
          {id:'agent', name:'AI Agent Execution Request', d:'Autonomous agent requesting a governed action.', decision:'allow', risk:'High', review:true,
            gov:'Agent policy loaded; requested tool action matched to policy.',
            enf:'Gateway authorized the bounded action with human review of record.',
            ev:'Agent action sealed with policy version and reviewer id.',
            exec:'Agent execution <b>authorized within policy bounds</b> with human review. The action is sealed and replayable from evidence; pilot-ready for one agent workflow.'}
        ];
        var STAGES = [
          {n:'Step 1', l:'Select Scenario'},
          {n:'Step 2', l:'Run Scenario'},
          {n:'Step 3', l:'Watch Governance'},
          {n:'Step 4', l:'Watch Enforcement'},
          {n:'Step 5', l:'Watch Evidence'},
          {n:'Step 6', l:'Watch Executive Outcome'}
        ];
        var elScn = document.getElementById('lx-scenarios');
        var elFlow = document.getElementById('lx-flow');
        var elPath = document.getElementById('lx-path');
        var elEvidence = document.getElementById('lx-evidence');
        var elAudit = document.getElementById('lx-audit');
        var elExec = document.getElementById('lx-exec');
        var runBtn = document.getElementById('lx-run');
        var resetBtn = document.getElementById('lx-reset');
        var hint = document.getElementById('lx-hint');
        var selected = null;
        var running = false;
        var timers = [];
        function clearTimers(){ for(var i=0;i<timers.length;i++){ clearTimeout(timers[i]); } timers = []; }
        function renderScenarios(){
          var html = '';
          for(var i=0;i<SCN.length;i++){
            var a = (SCN[i].id === selected) ? ' active' : '';
            html += '<button type="button" class="lx-scn' + a + '" data-id="' + esc(SCN[i].id) + '">' +
              '<span class="lx-scn-n">' + esc(SCN[i].name) + '</span>' +
              '<span class="lx-scn-d">' + esc(SCN[i].d) + '</span></button>';
          }
          elScn.innerHTML = html;
          var btns = elScn.querySelectorAll('.lx-scn');
          for(var j=0;j<btns.length;j++){
            btns[j].addEventListener('click', function(){ if(running) return; selectScenario(this.getAttribute('data-id')); });
          }
        }
        function setStages(n){
          var html = '';
          for(var i=0;i<STAGES.length;i++){
            var cls = '';
            if(i < n) cls = ' is-done';
            else if(i === n) cls = ' is-active';
            html += '<div class="lx-stage' + cls + '"><span class="lx-stage-n">' + esc(STAGES[i].n) + '</span>' +
              '<span class="lx-stage-l">' + esc(STAGES[i].l) + '</span></div>';
          }
          elFlow.innerHTML = html;
        }
        function selectScenario(id){
          selected = id;
          renderScenarios();
          setStages(1);
          runBtn.disabled = false;
          var s = find(id);
          hint.textContent = s ? ('Ready: ' + s.name + '. Click Run Scenario.') : 'Select a scenario to begin.';
        }
        function find(id){ for(var i=0;i<SCN.length;i++){ if(SCN[i].id === id) return SCN[i]; } return null; }
        function resetOutputs(){
          elPath.innerHTML = '<p class="lx-empty">Run a scenario to watch the decision move through Control Plane, Gateway, Evidence, and Audit.</p>';
          elEvidence.innerHTML = '<p class="lx-empty">No evidence sealed yet.</p>';
          elAudit.innerHTML = '<p class="lx-empty">No audit event recorded yet.</p>';
          elExec.innerHTML = '<p class="lx-empty">The executive outcome will appear once the scenario completes.</p>';
        }
        function reset(){
          clearTimers();
          running = false;
          selected = null;
          runBtn.disabled = true;
          hint.textContent = 'Select a scenario to begin.';
          renderScenarios();
          setStages(0);
          resetOutputs();
        }
        function pathRow(code, kind, d, t){
          var cls = kind ? (' ' + kind) : '';
          return '<div class="lx-pstep' + cls + '"><span class="lx-pstep-c">' + esc(code) + '</span>' +
            '<span class="lx-pstep-d">' + esc(d) + '</span>' +
            '<span class="lx-pstep-t">' + esc(t) + '</span></div>';
        }
        function run(){
          if(!selected || running) return;
          var s = find(selected);
          if(!s) return;
          running = true;
          runBtn.disabled = true;
          clearTimers();
          resetOutputs();
          var allow = (s.decision === 'allow');
          var path = [];
          function pushPath(html){ path.push(html); elPath.innerHTML = '<div class="lx-path">' + path.join('') + '</div>'; }
          hint.textContent = 'Running ' + s.name + '\u2026';
          setStages(2);
          timers.push(setTimeout(function(){
            setStages(2);
            pushPath(pathRow('CONTROL_PLANE', '', s.gov, clk()));
            hint.textContent = 'Watching Governance (Control Plane)\u2026';
          }, 350));
          timers.push(setTimeout(function(){
            setStages(3);
            pushPath(pathRow(allow ? 'GATEWAY_ALLOW' : 'GATEWAY_BLOCK', allow ? 'allow' : 'block', s.enf, clk()));
            hint.textContent = 'Watching Enforcement (Gateway)\u2026';
          }, 900));
          timers.push(setTimeout(function(){
            setStages(4);
            pushPath(pathRow('EVIDENCE_SEALED', '', s.ev, clk()));
            var eid = 'EVD-' + hex(4).toUpperCase();
            elEvidence.innerHTML = '<div class="lx-kv">' +
              '<div class="lx-kvrow"><span class="lx-k">Record ID</span><span class="lx-v mono">' + esc(eid) + '</span></div>' +
              '<div class="lx-kvrow"><span class="lx-k">Decision</span><span class="lx-v">' + (allow ? '<span class="lx-badge">Allowed</span>' : '<span class="lx-badge block">Blocked</span>') + '</span></div>' +
              '<div class="lx-kvrow"><span class="lx-k">Content Hash</span><span class="lx-v mono">sha256:' + esc(hex(8)) + '</span></div>' +
              '<div class="lx-kvrow"><span class="lx-k">Signature</span><span class="lx-v mono">ed25519:' + esc(hex(8)) + '</span></div>' +
              '<div class="lx-kvrow"><span class="lx-k">Status</span><span class="lx-v">Sealed &amp; resolvable</span></div></div>';
            hint.textContent = 'Watching Evidence\u2026';
          }, 1450));
          timers.push(setTimeout(function(){
            setStages(5);
            pushPath(pathRow('AUDIT_APPENDED', '', 'Event appended to the tamper-evident audit chain.', clk()));
            var idx = ri(4120, 9870);
            elAudit.innerHTML = '<div class="lx-kv">' +
              '<div class="lx-kvrow"><span class="lx-k">Event</span><span class="lx-v mono">' + esc(allow ? 'decision_allowed' : 'decision_blocked') + '</span></div>' +
              '<div class="lx-kvrow"><span class="lx-k">Chain Index</span><span class="lx-v mono">#' + esc(String(idx)) + '</span></div>' +
              '<div class="lx-kvrow"><span class="lx-k">Prev Hash</span><span class="lx-v mono">' + esc(hex(6)) + '</span></div>' +
              '<div class="lx-kvrow"><span class="lx-k">Entry Hash</span><span class="lx-v mono">' + esc(hex(6)) + '</span></div>' +
              '<div class="lx-kvrow"><span class="lx-k">Linkage</span><span class="lx-v">Continuous &middot; no gaps</span></div></div>';
          }, 2000));
          timers.push(setTimeout(function(){
            setStages(6);
            elExec.innerHTML = '<div class="lx-exec"><p style="margin:0 0 8px"><b>' + esc(s.name) + '</b> &middot; Risk class: <b>' + esc(s.risk) + '</b> &middot; Human review: <b>' + (s.review ? 'Yes' : 'Not required') + '</b></p>' +
              '<p style="margin:0">' + s.exec + '</p></div>';
            hint.textContent = 'Done: ' + s.name + '. Executive outcome ready.';
            running = false;
            runBtn.disabled = false;
          }, 2600));
        }
        runBtn.addEventListener('click', run);
        resetBtn.addEventListener('click', reset);
        renderScenarios();
        setStages(0);
      })();
      </script>
    </section>

    <section id="usbsim-demopack" class="dp" aria-label="Prospect demo readiness package">
      <style>
        .dp{margin:26px 0;padding:22px;border:1px solid #1f3253;border-radius:14px;background:linear-gradient(180deg,rgba(13,18,30,.72),rgba(8,12,20,.72));}
        .dp-eyebrow{font-size:9px;letter-spacing:.24em;text-transform:uppercase;color:#818cf8;font-weight:700;}
        .dp-title{margin:6px 0 4px;font-size:18px;font-weight:800;color:#e6edf6;letter-spacing:.02em;}
        .dp-sub{margin:0 0 18px;font-size:12px;line-height:1.6;color:#94a3b8;max-width:74ch;}
        .dp-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;}
        .dp-panel{padding:16px;border:1px solid #1f3253;border-radius:10px;background:rgba(8,14,22,.5);min-width:0;}
        .dp-panel.wide{grid-column:1 / -1;}
        .dp-hd{font-size:8.5px;letter-spacing:.18em;text-transform:uppercase;color:#94a3b8;font-weight:700;margin:0 0 12px;display:flex;align-items:center;gap:8px;}
        .dp-hd .dp-num{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border-radius:6px;background:rgba(129,140,248,.16);border:1px solid #818cf8;color:#c7d2fe;font-size:9px;letter-spacing:0;}
        .dp-check{display:flex;flex-direction:column;gap:7px;}
        .dp-citem{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;padding:9px 11px;border:1px solid #1f3253;border-radius:7px;background:rgba(8,14,22,.45);}
        .dp-tick{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border-radius:6px;background:rgba(52,211,153,.14);border:1px solid #34d399;color:#6ee7b7;font-size:11px;font-weight:800;}
        .dp-cname{font-size:11.5px;color:#e6edf6;font-weight:600;overflow-wrap:break-word;min-width:0;}
        .dp-cstate{font-size:9px;letter-spacing:.08em;text-transform:uppercase;font-weight:800;color:#6ee7b7;white-space:nowrap;}
        .dp-script{display:flex;flex-direction:column;gap:8px;counter-reset:dpstep;}
        .dp-sitem{display:grid;grid-template-columns:auto 1fr;gap:11px;align-items:center;padding:9px 11px;border:1px solid #1f3253;border-radius:7px;background:rgba(8,14,22,.45);}
        .dp-sn{display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:7px;background:rgba(129,140,248,.16);border:1px solid #818cf8;color:#c7d2fe;font-size:11px;font-weight:800;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;}
        .dp-sl{font-size:11.5px;color:#cbd5e1;font-weight:600;overflow-wrap:break-word;min-width:0;}
        .dp-actions{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:4px;}
        .dp-btn{font-size:11.5px;font-weight:700;padding:9px 16px;border-radius:8px;border:1px solid #818cf8;background:rgba(129,140,248,.16);color:#c7d2fe;cursor:pointer;font-family:inherit;}
        .dp-btn:hover{background:rgba(129,140,248,.26);}
        .dp-copied{font-size:10.5px;color:#6ee7b7;font-weight:700;opacity:0;transition:opacity .2s;}
        .dp-copied.show{opacity:1;}
        .dp-summary{margin-top:12px;}
        .dp-summary textarea{width:100%%;box-sizing:border-box;min-height:150px;resize:vertical;background:rgba(4,8,14,.7);border:1px solid #1f3253;border-radius:8px;color:#cbd5e1;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:10.5px;line-height:1.6;padding:12px;}
        .dp-safety{margin:18px 0 0;padding:14px 16px;border-radius:10px;background:rgba(129,140,248,.08);border:1px solid rgba(129,140,248,.4);display:flex;gap:12px;align-items:flex-start;}
        .dp-safety .dp-shield{font-size:18px;line-height:1;color:#c7d2fe;}
        .dp-safety-t{font-size:9px;letter-spacing:.18em;text-transform:uppercase;color:#c7d2fe;font-weight:800;margin:0 0 4px;}
        .dp-safety-m{font-size:12px;line-height:1.55;color:#e6edf6;font-weight:600;margin:0;}
        @media (max-width:780px){.dp-grid{grid-template-columns:1fr;}}
        @media (max-width:560px){.dp-citem{grid-template-columns:auto 1fr;}.dp-cstate{grid-column:2;justify-self:start;}}
      </style>
      <div class="dp-eyebrow">Prospect Readiness</div>
      <h2 class="dp-title">Prospect Demo Readiness Package</h2>
      <p class="dp-sub">Everything needed to run a first prospect conversation on the existing USBAY demo &mdash; a readiness checklist, an operator script, a one-click prospect summary, and the demo-environment safety notice. Preview-only: this package presents the existing demo and changes no platform behavior.</p>
      <div class="dp-grid">
        <div class="dp-panel">
          <div class="dp-hd"><span class="dp-num">1</span>Prospect Demo Ready</div>
          <div class="dp-check" id="dp-check"></div>
        </div>
        <div class="dp-panel">
          <div class="dp-hd"><span class="dp-num">2</span>First-Demo Script</div>
          <div class="dp-script" id="dp-script"></div>
        </div>
        <div class="dp-panel wide">
          <div class="dp-hd"><span class="dp-num">3</span>Copy Prospect Demo Summary</div>
          <div class="dp-actions">
            <button type="button" class="dp-btn" id="dp-copy">Copy Prospect Demo Summary</button>
            <span class="dp-copied" id="dp-copied">Copied to clipboard &#10003;</span>
          </div>
          <div class="dp-summary"><textarea id="dp-summary" readonly aria-label="Prospect demo summary text"></textarea></div>
        </div>
      </div>
      <div class="dp-safety" role="note">
        <span class="dp-shield">&#128737;</span>
        <div>
          <p class="dp-safety-t">Demo Safety Notice</p>
          <p class="dp-safety-m">Demo environment only. No production systems, customer data, payments, or external AI providers are connected.</p>
        </div>
      </div>
      <script>
      (function(){
        var root = document.getElementById('usbsim-demopack');
        if(!root) return;
        function esc(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
        var CHECK = [
          'Control Plane verified',
          'Gateway verified',
          'Evidence chain verified',
          'Audit trail verified',
          'Human review visible',
          'Scenario launcher ready',
          'Pilot intake preview ready'
        ];
        var SCRIPT = [
          'Select sector',
          'Run scenario',
          'Show enforcement decision',
          'Show evidence record',
          'Show executive summary',
          'Show pilot intake'
        ];
        var SUMMARY = [
          'USBAY \u2014 PROSPECT DEMO SUMMARY',
          '',
          'WHAT USBAY DOES',
          'USBAY is a governance layer for high-stakes automated decisions. It evaluates each',
          'decision against signed policy, enforces an allow or fail-closed block at the gateway,',
          'and records what happened so it can be reviewed and reproduced.',
          '',
          'WHAT RISK IT CONTROLS',
          'Ungoverned automated decisions in regulated and safety-critical settings \u2014 unauthorized',
          'actions, missing human review, unprovable decisions, and replayed or tampered requests.',
          'High-risk actions are blocked fail-closed and routed to a named reviewer of record.',
          '',
          'WHAT EVIDENCE IT PRODUCES',
          'A sealed evidence record (content hash + signature) and a tamper-evident audit event',
          '(chain-linked) for every decision, plus an executive summary of the outcome, risk class,',
          'and reviewer of record \u2014 reproducible end to end.',
          '',
          'WHAT A PILOT CAN VALIDATE',
          'One high-stakes workflow in your environment: that policy is enforced, that decisions',
          'are blocked fail-closed when required, that human review is in the loop, and that every',
          'decision is sealed, auditable, and reproducible.',
          '',
          'PREVIEW-ONLY DISCLAIMER',
          'Demo environment only. No production systems, customer data, payments, or external AI',
          'providers are connected. Figures and records shown are illustrative.'
        ].join('\n');
        var elCheck = document.getElementById('dp-check');
        var elScript = document.getElementById('dp-script');
        var elSummary = document.getElementById('dp-summary');
        var copyBtn = document.getElementById('dp-copy');
        var copied = document.getElementById('dp-copied');
        var copiedTimer = null;
        (function renderCheck(){
          var html = '';
          for(var i=0;i<CHECK.length;i++){
            html += '<div class="dp-citem"><span class="dp-tick">&#10003;</span>' +
              '<span class="dp-cname">' + esc(CHECK[i]) + '</span>' +
              '<span class="dp-cstate">Ready</span></div>';
          }
          elCheck.innerHTML = html;
        })();
        (function renderScript(){
          var html = '';
          for(var i=0;i<SCRIPT.length;i++){
            html += '<div class="dp-sitem"><span class="dp-sn">' + esc(String(i+1)) + '</span>' +
              '<span class="dp-sl">' + esc(SCRIPT[i]) + '</span></div>';
          }
          elScript.innerHTML = html;
        })();
        elSummary.value = SUMMARY;
        function flagCopied(){
          copied.classList.add('show');
          if(copiedTimer) clearTimeout(copiedTimer);
          copiedTimer = setTimeout(function(){ copied.classList.remove('show'); }, 2000);
        }
        copyBtn.addEventListener('click', function(){
          var done = false;
          try{
            if(navigator.clipboard && navigator.clipboard.writeText){
              navigator.clipboard.writeText(SUMMARY).then(flagCopied, fallback);
              done = true;
            }
          }catch(e){ done = false; }
          if(!done) fallback();
          function fallback(){
            try{
              elSummary.focus();
              elSummary.select();
              document.execCommand('copy');
            }catch(e){}
            flagCopied();
          }
        });
      })();
      </script>
    </section>

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


def _platform_sync_payload() -> dict:
    """Snapshot of shared truth-layer fields rendered identically on both
    surfaces (Policy Enforcement Gateway and Governance Demo App). Read
    once at render time and embedded so the browser can compare against
    /api/status (and /api/governance/evidence) and detect drift.

    Sourced from the same `health()` shape that `/api/status` returns —
    not from `runtime_status_snapshot()` directly — so the embedded
    field names match the live API exactly (e.g. `policy_state`, which
    `runtime_status_snapshot()` exposes as `compute_policy_state`).
    Falls back to the raw snapshot on any error, and to a runtime
    snapshot for `git_commit` since `health()` does not expose it."""
    body: dict = {}
    try:
        h = health()
        if isinstance(h, JSONResponse):
            body = json.loads(h.body.decode("utf-8")) or {}
        elif isinstance(h, dict):
            body = h
    except Exception:
        body = {}
    if not body:
        try:
            body = runtime_status_snapshot() or {}
        except Exception:
            body = {}
    # git_commit is only present on the raw runtime snapshot, not on health()
    git_commit = ""
    try:
        snap_extra = runtime_status_snapshot() or {}
        git_commit = str(snap_extra.get("git_commit") or "")
    except Exception:
        git_commit = ""
    # evidence_state: render-time read of the governance evidence chain
    # so the embedded reference and the live /api/governance/evidence
    # state can be compared for drift.
    evidence_state = "UNKNOWN"
    try:
        from governance.evidence_chain_verifier import verify_governance_evidence
        evidence_state = str(verify_governance_evidence(".").state or "UNKNOWN")
    except Exception:
        evidence_state = "UNKNOWN"
    return {
        "policy_hash": str(body.get("policy_hash") or ""),
        "mode": str(body.get("mode") or "UNKNOWN"),
        "status": str(body.get("status") or "UNKNOWN"),
        "replay_protection_active": bool(body.get("replay_protection_active")),
        "policy_state": str(body.get("policy_state") or "unknown"),
        "policy_signature_valid": bool(body.get("policy_signature_valid")),
        "registry_version": str(body.get("registry_version") or ""),
        "git_commit": (git_commit[:7]) if git_commit else "—",
        "fail_closed": str(body.get("status") or "") == "FAIL_CLOSED",
        "evidence_state": evidence_state,
    }


def _platform_sync_bar_html(surface: str) -> str:
    """Unified USBAY platform bar rendered at the top of both the Policy
    Enforcement Gateway (`/`, `/dashboard`) and the Governance Demo App
    (`/playground*`). Carries: USBAY brand, cross-surface nav, shared
    truth-layer chips (build/policy/mode/replay/signature/audit),
    commercial engagement stages strip, and a hidden 'SYNC DRIFT
    DETECTED' banner that the inline script unhides when the embedded
    snapshot disagrees with live /api/status or /api/governance/evidence.
    Pure presentation — does not alter any enforcement logic."""
    p = _platform_sync_payload()
    try:
        ref_json = json.dumps(p, separators=(",", ":"))
    except Exception:
        ref_json = "{}"
    policy_hash_short = (p["policy_hash"][:12] + "…") if len(p["policy_hash"]) > 12 else (p["policy_hash"] or "—")
    fc_label = "FAIL-CLOSED" if p["fail_closed"] else "MODE NORMAL"
    fc_cls = "is-fail" if p["fail_closed"] else "is-ok"
    replay_cls = "is-ok" if p["replay_protection_active"] else "is-fail"
    replay_label = "REPLAY GUARD ON" if p["replay_protection_active"] else "REPLAY GUARD OFF"
    sig_cls = "is-ok" if p["policy_signature_valid"] else "is-fail"
    sig_label = "POLICY SIG VALID" if p["policy_signature_valid"] else "POLICY SIG INVALID"
    is_gw = " is-active" if surface == "gateway" else ""
    is_demo = " is-active" if surface == "demo" else ""
    build_lbl = html.escape(p["git_commit"])
    pol_lbl = html.escape(policy_hash_short)
    return (
        '<style>'
        '.usbay-sync{font-family:"Inter","Segoe UI",-apple-system,sans-serif;background:linear-gradient(180deg,#0a1320 0%,#0e1a2b 100%);border-bottom:1px solid #1f3253;color:#e6edf6;}'
        '.usbay-sync *{box-sizing:border-box;}'
        '.usbay-sync-inner{max-width:1200px;margin:0 auto;padding:10px 18px;display:flex;flex-direction:column;gap:8px;}'
        '.usbay-sync-row{display:flex;flex-wrap:wrap;align-items:center;gap:10px;}'
        '.usbay-sync-brand{display:flex;align-items:center;gap:6px;font-size:11px;letter-spacing:.22em;text-transform:uppercase;color:#7dd3fc;font-weight:700;}'
        '.usbay-sync-brand b{color:#e6edf6;letter-spacing:.18em;}'
        '.usbay-sync-nav{display:flex;flex-wrap:wrap;gap:6px;margin-left:auto;}'
        '.usbay-sync-nav a{display:inline-block;padding:5px 10px;border:1px solid rgba(255,255,255,.12);border-radius:6px;background:rgba(255,255,255,.02);color:#cbd5e1;text-decoration:none;font-size:11px;letter-spacing:.08em;}'
        '.usbay-sync-nav a:hover{border-color:rgba(34,211,238,.5);color:#e6edf6;}'
        '.usbay-sync-nav a.is-active{border-color:rgba(34,211,238,.6);color:#7dd3fc;background:rgba(34,211,238,.08);}'
        '.usbay-sync-chips{display:flex;flex-wrap:wrap;gap:6px;align-items:center;}'
        '.usbay-chip{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;font-size:10.5px;letter-spacing:.12em;font-weight:700;text-transform:uppercase;border:1px solid currentColor;background:rgba(0,0,0,.25);color:#cbd5e1;}'
        '.usbay-chip.is-ok{color:#86efac;}.usbay-chip.is-fail{color:#fca5a5;}.usbay-chip.is-warn{color:#fbbf24;}.usbay-chip.is-info{color:#7dd3fc;}'
        '.usbay-chip-k{color:#94a3b8;font-weight:700;}'
        '.usbay-chip-v{color:inherit;font-family:"JetBrains Mono","SFMono-Regular",monospace;font-size:10px;letter-spacing:.04em;text-transform:none;}'
        '.usbay-stages{display:flex;flex-wrap:wrap;gap:6px;align-items:center;font-size:10.5px;letter-spacing:.12em;color:#94a3b8;}'
        '.usbay-stage{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:6px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);color:#cbd5e1;text-transform:uppercase;font-weight:700;}'
        '.usbay-stage b{color:#7dd3fc;letter-spacing:.16em;margin-right:4px;}'
        '.usbay-stage-sep{color:rgba(125,211,252,.5);}'
        '.usbay-sync-note{font-size:10.5px;color:#64748b;font-style:italic;letter-spacing:.02em;}'
        '.usbay-drift{display:none;margin-top:4px;padding:10px 12px;border:1px solid rgba(252,165,165,.55);border-radius:6px;background:rgba(127,29,29,.28);color:#fecaca;font-size:11.5px;line-height:1.5;}'
        '.usbay-drift.is-on{display:block;}'
        '.usbay-drift b{color:#fff;letter-spacing:.18em;text-transform:uppercase;font-size:10.5px;display:block;margin-bottom:3px;}'
        '.usbay-drift ul{margin:4px 0 0;padding-left:18px;}'
        '@media (max-width:780px){.usbay-sync-nav{margin-left:0;width:100%;}.usbay-sync-chips,.usbay-stages{font-size:10px;}}'
        '</style>'
        '<section class="usbay-sync" role="region" aria-label="USBAY platform synchronization bar">'
        '<div class="usbay-sync-inner">'
        '<div class="usbay-sync-row">'
        '<div class="usbay-sync-brand"><span>● USBAY</span> <b>PLATFORM</b></div>'
        '<nav class="usbay-sync-nav" aria-label="USBAY platform navigation">'
        '<a href="/playground" class="usbay-sync-link' + is_demo + '">Governance Control Plane</a>'
        '<a href="/" class="usbay-sync-link' + is_gw + '">Policy Enforcement Gateway</a>'
        '<a href="#usbay-chip-audit" class="usbay-sync-link">Audit Health</a>'
        '<a href="/playground#usbsim-pilot-rec" class="usbay-sync-link">Pilot Recommendation</a>'
        '<a href="/playground#exec-report" class="usbay-sync-link">Executive Report Preview</a>'
        '</nav>'
        '</div>'
        '<div class="usbay-sync-row usbay-sync-chips" aria-label="Shared platform state">'
        '<span class="usbay-chip is-info"><span class="usbay-chip-k">Build</span><span class="usbay-chip-v" id="usbay-chip-build">' + build_lbl + '</span></span>'
        '<span class="usbay-chip is-info"><span class="usbay-chip-k">Policy</span><span class="usbay-chip-v" id="usbay-chip-policy">' + pol_lbl + '</span></span>'
        '<span class="usbay-chip ' + fc_cls + '" id="usbay-chip-mode">' + html.escape(fc_label) + '</span>'
        '<span class="usbay-chip ' + replay_cls + '" id="usbay-chip-replay">' + html.escape(replay_label) + '</span>'
        '<span class="usbay-chip ' + sig_cls + '" id="usbay-chip-sig">' + html.escape(sig_label) + '</span>'
        '<span class="usbay-chip is-info" id="usbay-chip-audit"><span class="usbay-chip-k">Audit</span><span class="usbay-chip-v">checking…</span></span>'
        '</div>'
        '<div class="usbay-sync-row usbay-stages" aria-label="Engagement stages">'
        '<span class="usbay-stage"><b>Stage 1</b> Paid Intake</span>'
        '<span class="usbay-stage-sep">→</span>'
        '<span class="usbay-stage"><b>Stage 2</b> Demo Access</span>'
        '<span class="usbay-stage-sep">→</span>'
        '<span class="usbay-stage"><b>Stage 3</b> Pilot Engagement</span>'
        '<span class="usbay-sync-note">Preview only — no payment is processed in this demo, no company information is stored or submitted.</span>'
        '</div>'
        '<div class="usbay-drift" id="usbay-drift" role="alert" aria-live="polite">'
        '<b>● SYNC DRIFT DETECTED</b>'
        '<span id="usbay-drift-summary">Platform state does not match server state. Status is degraded and not pretending verified.</span>'
        '<ul id="usbay-drift-list"></ul>'
        '</div>'
        '</div>'
        '</section>'
        '<script type="application/json" id="usbay-sync-ref">' + ref_json + '</script>'
        '<script>'
        '(function(){'
        'var refEl=document.getElementById("usbay-sync-ref");if(!refEl)return;'
        'var ref={};try{ref=JSON.parse(refEl.textContent||"{}");}catch(_){return;}'
        'var driftBox=document.getElementById("usbay-drift");'
        'var driftList=document.getElementById("usbay-drift-list");'
        'var auditChip=document.getElementById("usbay-chip-audit");'
        'function reportDrift(items){if(!driftBox||!driftList||!items||!items.length)return;driftList.innerHTML="";items.forEach(function(t){var li=document.createElement("li");li.textContent=t;driftList.appendChild(li);});driftBox.classList.add("is-on");var m=document.getElementById("usbay-chip-mode");if(m){m.classList.remove("is-ok");m.classList.add("is-warn");m.textContent="DRIFT — DEGRADED";}}'
        'function pickShort(h){h=String(h||"");return h.length>12?h.slice(0,12)+"…":(h||"—");}'
        'fetch("/api/status",{cache:"no-store"}).then(function(r){return r.json();}).then(function(live){var items=[];'
        'if(String(live.policy_hash||"")!==String(ref.policy_hash||""))items.push("Policy hash mismatch: page "+pickShort(ref.policy_hash)+" vs server "+pickShort(live.policy_hash)+".");'
        'if(String(live.mode||"")!==String(ref.mode||""))items.push("Runtime mode mismatch: page "+ref.mode+" vs server "+live.mode+".");'
        'if(Boolean(live.replay_protection_active)!==Boolean(ref.replay_protection_active))items.push("Replay protection state mismatch (page vs server).");'
        'if(String(live.policy_state||"")!==String(ref.policy_state||""))items.push("Policy state mismatch: page "+ref.policy_state+" vs server "+live.policy_state+".");'
        'if(Boolean(live.policy_signature_valid)!==Boolean(ref.policy_signature_valid))items.push("Policy signature validity mismatch (page vs server).");'
        'if(String(live.status||"")==="FAIL_CLOSED"&&!ref.fail_closed)items.push("Server reports FAIL_CLOSED but page was not rendered in fail-closed mode.");'
        'if(items.length)reportDrift(items);'
        '}).catch(function(){reportDrift(["Unable to reach /api/status — cannot confirm platform state. Showing degraded."]);});'
        'fetch("/api/governance/evidence",{cache:"no-store"}).then(function(r){return r.json().then(function(b){return{status:r.status,body:b};});}).then(function(o){var state=(o.body&&(o.body.state||o.body.evidence_state))||(o.status===200?"VERIFIED":"UNVERIFIED");if(auditChip){var v=auditChip.querySelector(".usbay-chip-v");auditChip.classList.remove("is-info","is-ok","is-fail","is-warn");if(state==="VERIFIED"){auditChip.classList.add("is-ok");if(v)v.textContent="VERIFIED";}else if(state==="MISSING"){auditChip.classList.add("is-warn");if(v)v.textContent="MISSING";}else{auditChip.classList.add("is-fail");if(v)v.textContent=String(state);}}if(String(ref.evidence_state||"")!==String(state||"")){reportDrift(["Audit evidence state mismatch: page "+(ref.evidence_state||"UNKNOWN")+" vs server "+state+"."]);}}).catch(function(){if(auditChip){var v=auditChip.querySelector(".usbay-chip-v");auditChip.classList.remove("is-info");auditChip.classList.add("is-warn");if(v)v.textContent="UNKNOWN";}reportDrift(["Unable to reach /api/governance/evidence — audit health unconfirmed."]);});'
        'if(location.hash==="#exec-report"){var btn=document.getElementById("usbsim-rpt-open");if(btn){setTimeout(function(){try{btn.click();}catch(_){}}, 250);}}'
        '})();'
        '</script>'
    )


def _inject_platform_sync_bar(page_html: str, surface: str) -> str:
    """Inject the unified platform sync bar immediately above the page's
    `<main>` element. No-op if the marker is missing."""
    bar = _platform_sync_bar_html(surface)
    marker = "  <main>"
    if marker in page_html:
        return page_html.replace(marker, bar + "\n  <main>", 1)
    if "<main>" in page_html:
        return page_html.replace("<main>", bar + "\n<main>", 1)
    return page_html


def _render_governance_html_safe() -> HTMLResponse:
    try:
        return HTMLResponse(_inject_platform_sync_bar(governance_gateway_html(), "gateway"))
    except Exception as exc:
        return HTMLResponse(
            _safe_fallback_html("Runtime snapshot temporarily unavailable", exc),
            status_code=200,
        )


def _render_playground_html_safe(*args) -> HTMLResponse:
    try:
        return HTMLResponse(_inject_platform_sync_bar(playground_html(*args), "demo"))
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
