from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from datetime import datetime, timezone
import os
import hashlib
import html
import json
import shlex
import time
import uuid
from pathlib import Path

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
from security.persistent_nonce_store import (
    NONCE_RESULT_EXPIRED,
    NONCE_RESULT_REPLAY,
    NONCE_RESULT_RESERVED,
    REASON_NONCE_STORE_CORRUPTED,
    REASON_NONCE_STORE_UNAVAILABLE,
    LocalPersistentNonceStore,
    PersistentNonceStoreError,
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
from governance.demo_dashboard_state import build_governance_demo_state
from governance.runtime_governance_state import runtime_governance_state_snapshot
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
from governance.runtime_revocation_registry import (
    DECISION_DENY as REVOCATION_DECISION_DENY,
    REASON_REGISTRY_UNAVAILABLE,
    RuntimeRevocationRegistryError,
    evaluate_runtime_revocation,
    load_runtime_revocation_registry,
    runtime_revocation_result,
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
from intake.gateway import (
    INTAKE_NOTIFICATION_RECIPIENT,
    IntakeGatewayError,
    audit_admin_access,
    client_identity_hash,
    create_intake_submission,
    email_delivery_policy,
    enforce_rate_limit,
    intake_admin_export,
    intake_audit_export,
    production_readiness_report,
    resolve_admin_identity,
    retention_policy_export,
)


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
DEFAULT_GOVERNANCE_DASHBOARD_AUDIT_PATH = Path("artifacts/governance-dashboard-audit.json")
DEFAULT_RUNTIME_REVOCATION_REGISTRY_PATH = Path("governance/runtime_revocation_registry.json")
DEFAULT_RUNTIME_NONCE_STORE_PATH = Path("tmp/runtime_nonce_store.json")
DEFAULT_RUNTIME_ATTESTATION_MAX_AGE_SECONDS = 14 * 24 * 60 * 60
RUNTIME_ENFORCEMENT_DENY = "DENY"
RUNTIME_ENFORCEMENT_NEXT_CHECK = "NEXT_CHECK"
RUNTIME_ENFORCEMENT_OK = "ok"
RUNTIME_DENY_NONCE_MISSING = "nonce_missing"
RUNTIME_DENY_REPLAY_DETECTED = "replay_detected"
RUNTIME_DENY_NONCE_STORE_UNAVAILABLE = "nonce_store_unavailable"
RUNTIME_DENY_NONCE_STORE_CORRUPTED = "nonce_store_corrupted"
RUNTIME_DENY_NONCE_EXPIRED = "nonce_expired"
RUNTIME_DENY_ATTESTATION_MISSING = "runtime_attestation_missing"
RUNTIME_DENY_ATTESTATION_UNVERIFIABLE = "runtime_attestation_unverifiable"
RUNTIME_DENY_ATTESTATION_TIMESTAMP_MISSING = "runtime_attestation_timestamp_missing"
RUNTIME_DENY_ATTESTATION_TIMESTAMP_MALFORMED = "runtime_attestation_timestamp_malformed"
RUNTIME_DENY_ATTESTATION_TIMESTAMP_INVALID = "runtime_attestation_timestamp_invalid"
RUNTIME_DENY_ATTESTATION_STALE = "runtime_attestation_stale"
RUNTIME_DENY_ATTESTATION_FRESHNESS_POLICY_INVALID = "runtime_attestation_freshness_policy_invalid"
RUNTIME_DENY_RUNTIME_REVOKED = "runtime_revoked"
RUNTIME_DENY_POLICY_REVOKED = "policy_revoked"
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
GOVERNANCE_DASHBOARD_AUDIT_PATH = Path(
    os.getenv("USBAY_GOVERNANCE_DASHBOARD_AUDIT_PATH", str(DEFAULT_GOVERNANCE_DASHBOARD_AUDIT_PATH))
)
RUNTIME_REVOCATION_REGISTRY_PATH = Path(
    os.getenv("USBAY_RUNTIME_REVOCATION_REGISTRY_PATH", str(DEFAULT_RUNTIME_REVOCATION_REGISTRY_PATH))
)
RUNTIME_NONCE_STORE_PATH = Path(
    os.getenv("USBAY_RUNTIME_NONCE_STORE_PATH", str(DEFAULT_RUNTIME_NONCE_STORE_PATH))
)
_policy_registry_cache = None
_policy_registry_cache_key = None
runtime_mode = "NORMAL"
runtime_reason = "ok"


@asynccontextmanager
async def lifespan(app_instance):
    validate_policy_registry_startup()
    yield


app = FastAPI(lifespan=lifespan)
keystore = KeyStore()


def hydra_live_mode_enabled():
    return bool(os.getenv("HYDRA_NODE_URLS")) or os.getenv("USBAY_HYDRA_BACKEND", "").lower() == "services"


def default_hydra_clients():
    if hydra_live_mode_enabled():
        return default_live_node_clients()
    return default_node_clients()


hydra_node_clients = default_hydra_clients()
hydra_live_node_clients = hydra_node_clients


@app.middleware("http")
async def enforce_api_json_boundary(request, call_next):
    path = request.url.path
    if path == "/api/status":
        try:
            return JSONResponse(content=health())
        except Exception:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "FAIL_CLOSED",
                    "mode": "FAIL_CLOSED",
                    "reason": "api_status_unavailable",
                },
            )
    if path == "/api/governance/evidence":
        try:
            evidence = governance_evidence_state()
        except Exception:
            evidence = {
                "schema": "usbay.governance_evidence_state.v1",
                "fetch_status": "GOVERNANCE_FETCH_FAILED",
                "signature_status": "GOVERNANCE_EVIDENCE_SIGNATURE_UNVERIFIED",
                "governance_verdict": "UNKNOWN",
                "evidence_verdict": "UNKNOWN",
                "euria_governance_outputs": _euria_governance_outputs(),
                "fail_closed": True,
            }
        status_code = 200 if (
            evidence.get("fetch_status") == "GOVERNANCE_FETCH_OK"
            and evidence.get("signature_status") == "VERIFIED"
        ) else 503
        return JSONResponse(status_code=status_code, content=evidence)
    response = await call_next(request)
    if path == "/api" or path.startswith("/api/"):
        content_type = response.headers.get("content-type", "")
        if content_type.startswith("text/html"):
            return JSONResponse(
                status_code=404,
                content={
                    "error": "api_route_not_found",
                    "path": path,
                },
            )
    return response


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
    runtime_governance = runtime_governance_state_snapshot(root=REPO_ROOT)
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
    return {
        "status": "OK" if (
            registry is not None
            and mode == "NORMAL"
            and dependency_mode == "NORMAL"
            and runtime_governance.get("status") == "READY"
        ) else "FAIL_CLOSED",
        "mode": mode if registry is not None else "FAIL_CLOSED",
        "reason": runtime_governance.get("reason")
        if runtime_governance.get("status") != "READY"
        else reason if registry is None or mode != "NORMAL" else dependency_reason,
        "policy_signature_valid": bool(registry and registry.get("policy_signature_valid") is True),
        "policy_version": registry.get("version") if registry else None,
        "policy_hash": registry.get("policy_hash") if registry else None,
        "redis_available": redis_ok,
        "replay_protection_active": replay_ok,
        "compute_policy_state": compute_state["state"],
        "runtime_governance": runtime_governance,
        "promote_state": runtime_governance.get("promote_state", "PROMOTE_BLOCKED"),
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


def deployment_runtime_health_snapshot(runtime_snapshot=None):
    try:
        entries = audit_chain.load() if hasattr(audit_chain, "load") else []
        runtime_governance = runtime_governance_state_snapshot(root=REPO_ROOT)
        return deployment_runtime_health(
            root=REPO_ROOT,
            runtime_snapshot=runtime_snapshot if runtime_snapshot is not None else runtime_status_snapshot(),
            runtime_governance_state=runtime_governance,
            audit_chain_entries=entries,
        )
    except DeploymentRuntimeHealthError:
        return {
            "schema_version": "usbay.deployment_runtime_health.v1",
            "status": "BLOCKED",
            "startup_status": "FAILED",
            "reason_codes": ["STARTUP_FAILED", "DEPLOYMENT_RUNTIME_BLOCKED"],
        }


def signed_runtime_attestation_snapshot(runtime_snapshot=None, deployment_health=None):
    entries = audit_chain.load() if hasattr(audit_chain, "load") else []
    audit_valid = bool(audit_chain.verify()) if hasattr(audit_chain, "verify") else False
    snapshot = runtime_snapshot if runtime_snapshot is not None else runtime_status_snapshot()
    health = deployment_health if deployment_health is not None else deployment_runtime_health_snapshot(runtime_snapshot=snapshot)
    return runtime_attestation_from_environment(
        root=REPO_ROOT,
        deployment_health=health,
        runtime_snapshot=snapshot,
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


def _runtime_enforcement_timestamp():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _runtime_enforcement_audit_hash(evidence):
    return hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _runtime_enforcement_evidence(reason_code, payload=None, record=None, timestamp=None):
    safe_payload = payload if isinstance(payload, dict) else {}
    safe_record = record if isinstance(record, dict) else {}
    nonce_value = safe_payload.get("nonce", "")
    computed_nonce_hash = nonce_hash(nonce_value) if nonce_value else ""
    evidence = {
        "reason_code": str(reason_code),
        "decision_id": str(safe_record.get("decision_id") or safe_payload.get("decision_id") or ""),
        "nonce_hash": str(safe_record.get("nonce_hash") or computed_nonce_hash),
        "request_hash": str(safe_record.get("request_hash") or ""),
        "policy_hash": str(safe_record.get("policy_hash") or ""),
        "policy_version": str(safe_record.get("policy_version") or safe_payload.get("policy_version") or ""),
        "timestamp": str(timestamp or _runtime_enforcement_timestamp()),
    }
    evidence["audit_hash"] = _runtime_enforcement_audit_hash(evidence)
    return evidence


def runtime_enforcement_deny(reason_code, payload=None, record=None, timestamp=None):
    evidence = _runtime_enforcement_evidence(reason_code, payload=payload, record=record, timestamp=timestamp)
    return {
        "decision": RUNTIME_ENFORCEMENT_DENY,
        "reason_code": str(reason_code),
        "execution_allowed": False,
        "audit_evidence": evidence,
    }


def runtime_enforcement_next_check(payload=None, record=None, timestamp=None):
    evidence = _runtime_enforcement_evidence(RUNTIME_ENFORCEMENT_OK, payload=payload, record=record, timestamp=timestamp)
    return {
        "decision": RUNTIME_ENFORCEMENT_NEXT_CHECK,
        "reason_code": RUNTIME_ENFORCEMENT_OK,
        "execution_allowed": False,
        "audit_evidence": evidence,
    }


def _runtime_nonce_store_from_environment():
    store_path = Path(os.getenv("USBAY_RUNTIME_NONCE_STORE_PATH", str(RUNTIME_NONCE_STORE_PATH)))
    try:
        ttl_seconds = replay_policy_config()["nonce_ttl_seconds"]
    except Exception as exc:
        raise PersistentNonceStoreError(REASON_NONCE_STORE_UNAVAILABLE) from exc
    return LocalPersistentNonceStore(store_path, ttl_seconds=ttl_seconds)


def _persistent_nonce_deny_reason(error):
    reason = str(error)
    if reason == REASON_NONCE_STORE_CORRUPTED:
        return RUNTIME_DENY_NONCE_STORE_CORRUPTED
    return RUNTIME_DENY_NONCE_STORE_UNAVAILABLE


def validate_nonce_replay_for_runtime(
    payload,
    record,
    nonce_store_adapter=None,
    timestamp=None,
    persistent_nonce_store_adapter=None,
):
    safe_payload = payload if isinstance(payload, dict) else {}
    safe_record = record if isinstance(record, dict) else {}
    nonce_value = safe_payload.get("nonce")
    if nonce_value in (None, ""):
        return runtime_enforcement_deny(
            RUNTIME_DENY_NONCE_MISSING,
            payload=safe_payload,
            record=safe_record,
            timestamp=timestamp,
        )

    if persistent_nonce_store_adapter is not None or os.getenv("USBAY_RUNTIME_NONCE_STORE_PATH"):
        try:
            store = (
                persistent_nonce_store_adapter
                if persistent_nonce_store_adapter is not None
                else _runtime_nonce_store_from_environment()
            )
            nonce_hash_value = str(safe_record.get("nonce_hash") or nonce_hash(nonce_value))
            outcome = store.reserve(
                nonce_hash_value,
                decision_id=str(safe_record.get("decision_id") or safe_payload.get("decision_id") or ""),
                timestamp=str(timestamp or _runtime_enforcement_timestamp()),
            )
        except PersistentNonceStoreError as exc:
            return runtime_enforcement_deny(
                _persistent_nonce_deny_reason(exc),
                payload=safe_payload,
                record=safe_record,
                timestamp=timestamp,
            )
        except Exception:
            return runtime_enforcement_deny(
                RUNTIME_DENY_NONCE_STORE_UNAVAILABLE,
                payload=safe_payload,
                record=safe_record,
                timestamp=timestamp,
            )
        if outcome.get("state") == NONCE_RESULT_REPLAY:
            return runtime_enforcement_deny(
                RUNTIME_DENY_REPLAY_DETECTED,
                payload=safe_payload,
                record=safe_record,
                timestamp=timestamp,
            )
        if outcome.get("state") == NONCE_RESULT_EXPIRED:
            return runtime_enforcement_deny(
                RUNTIME_DENY_NONCE_EXPIRED,
                payload=safe_payload,
                record=safe_record,
                timestamp=timestamp,
            )
        if outcome.get("state") != NONCE_RESULT_RESERVED:
            return runtime_enforcement_deny(
                RUNTIME_DENY_NONCE_STORE_UNAVAILABLE,
                payload=safe_payload,
                record=safe_record,
                timestamp=timestamp,
            )
        return runtime_enforcement_next_check(payload=safe_payload, record=safe_record, timestamp=timestamp)

    try:
        store = nonce_store_adapter if nonce_store_adapter is not None else nonce_store
        if store.exists(str(nonce_value)):
            return runtime_enforcement_deny(
                RUNTIME_DENY_REPLAY_DETECTED,
                payload=safe_payload,
                record=safe_record,
                timestamp=timestamp,
            )
    except Exception:
        return runtime_enforcement_deny(
            RUNTIME_DENY_NONCE_STORE_UNAVAILABLE,
            payload=safe_payload,
            record=safe_record,
            timestamp=timestamp,
        )

    return runtime_enforcement_next_check(payload=safe_payload, record=safe_record, timestamp=timestamp)


def _parse_runtime_timestamp(timestamp_value):
    value = str(timestamp_value or "").strip()
    if not value:
        raise ValueError("missing_timestamp")
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("naive_timestamp")
    return parsed.astimezone(timezone.utc)


def _runtime_attestation_max_age(max_age_seconds=None):
    raw_value = (
        max_age_seconds
        if max_age_seconds is not None
        else os.getenv("USBAY_RUNTIME_ATTESTATION_MAX_AGE_SECONDS", str(DEFAULT_RUNTIME_ATTESTATION_MAX_AGE_SECONDS))
    )
    value = int(raw_value)
    if value <= 0:
        raise ValueError("invalid_max_age")
    return value


def validate_attestation_freshness_for_runtime(
    attestation,
    *,
    max_age_seconds=None,
    now_epoch=None,
    timestamp_skew_seconds=300,
    payload=None,
    record=None,
    timestamp=None,
):
    safe_record = record if isinstance(record, dict) else {}
    if not isinstance(attestation, dict):
        return runtime_enforcement_deny(
            RUNTIME_DENY_ATTESTATION_MISSING,
            payload=payload,
            record=safe_record,
            timestamp=timestamp,
        )
    if attestation.get("attestation_status") != "SIGNED" or attestation.get("signature_valid") is not True:
        return runtime_enforcement_deny(
            RUNTIME_DENY_ATTESTATION_UNVERIFIABLE,
            payload=payload,
            record=safe_record,
            timestamp=timestamp,
        )

    timestamp_value = attestation.get("deployment_timestamp_utc") or attestation.get("signed_at")
    if not timestamp_value:
        return runtime_enforcement_deny(
            RUNTIME_DENY_ATTESTATION_TIMESTAMP_MISSING,
            payload=payload,
            record=safe_record,
            timestamp=timestamp,
        )

    try:
        attested_at = _parse_runtime_timestamp(timestamp_value)
    except Exception:
        return runtime_enforcement_deny(
            RUNTIME_DENY_ATTESTATION_TIMESTAMP_MALFORMED,
            payload=payload,
            record=safe_record,
            timestamp=timestamp,
        )

    try:
        max_age = _runtime_attestation_max_age(max_age_seconds=max_age_seconds)
        skew = int(timestamp_skew_seconds)
        now = (
            datetime.fromtimestamp(int(now_epoch), tz=timezone.utc)
            if now_epoch is not None
            else datetime.now(timezone.utc)
        )
    except Exception:
        return runtime_enforcement_deny(
            RUNTIME_DENY_ATTESTATION_FRESHNESS_POLICY_INVALID,
            payload=payload,
            record=safe_record,
            timestamp=timestamp,
        )

    attestation_epoch = int(attested_at.timestamp())
    now_value = int(now.timestamp())
    if attestation_epoch > now_value + skew:
        return runtime_enforcement_deny(
            RUNTIME_DENY_ATTESTATION_TIMESTAMP_INVALID,
            payload=payload,
            record=safe_record,
            timestamp=timestamp,
        )
    if now_value - attestation_epoch > max_age:
        return runtime_enforcement_deny(
            RUNTIME_DENY_ATTESTATION_STALE,
            payload=payload,
            record=safe_record,
            timestamp=timestamp,
        )

    return runtime_enforcement_next_check(payload=payload, record=safe_record, timestamp=timestamp)


def validate_runtime_revocation_state_for_runtime(
    record,
    payload=None,
    *,
    runtime_state=None,
    revoked_policy_hashes=None,
    revoked_policy_versions=None,
    timestamp=None,
):
    safe_record = record if isinstance(record, dict) else {}
    safe_payload = payload if isinstance(payload, dict) else {}
    state = str(
        runtime_state
        or safe_payload.get("runtime_revocation_state")
        or os.getenv("USBAY_RUNTIME_REVOCATION_STATE", "")
    ).strip().upper()
    if state in {"REVOKED", "FROZEN", "BLOCKED", "DISABLED"}:
        return runtime_enforcement_deny(
            RUNTIME_DENY_RUNTIME_REVOKED,
            payload=safe_payload,
            record=safe_record,
            timestamp=timestamp,
        )

    policy_hashes = (
        {str(value).strip() for value in revoked_policy_hashes if str(value).strip()}
        if revoked_policy_hashes is not None
        else _csv_env_set("USBAY_REVOKED_POLICY_HASHES")
    )
    policy_versions = (
        {str(value).strip() for value in revoked_policy_versions if str(value).strip()}
        if revoked_policy_versions is not None
        else _csv_env_set("USBAY_REVOKED_POLICY_VERSIONS")
    )
    if str(safe_record.get("policy_hash", "")) in policy_hashes:
        return runtime_enforcement_deny(
            RUNTIME_DENY_POLICY_REVOKED,
            payload=safe_payload,
            record=safe_record,
            timestamp=timestamp,
        )
    if str(safe_record.get("policy_version", "")) in policy_versions:
        return runtime_enforcement_deny(
            RUNTIME_DENY_POLICY_REVOKED,
            payload=safe_payload,
            record=safe_record,
            timestamp=timestamp,
        )

    return runtime_enforcement_next_check(payload=safe_payload, record=safe_record, timestamp=timestamp)


def _runtime_attestation_id(runtime_attestation):
    if not isinstance(runtime_attestation, dict):
        return ""
    verification = runtime_attestation.get("verification")
    if isinstance(verification, dict) and verification.get("attestation_hash"):
        return str(verification.get("attestation_hash"))
    return str(runtime_attestation.get("attestation_id") or runtime_attestation.get("attestation_hash") or "")


def _runtime_revocation_subjects(payload, record, runtime_attestation):
    safe_payload = payload if isinstance(payload, dict) else {}
    safe_record = record if isinstance(record, dict) else {}
    return {
        "runtime_id": str(safe_record.get("runtime_id") or safe_payload.get("runtime_id") or gateway_id()),
        "device_id": str(safe_record.get("device_id") or safe_payload.get("device_id") or safe_payload.get("device") or ""),
        "attestation_id": _runtime_attestation_id(runtime_attestation),
        "operator_id": str(
            safe_record.get("operator_id")
            or safe_payload.get("operator_id")
            or safe_payload.get("actor_id")
            or ""
        ),
    }


def _runtime_revocation_audit_payload(revocation_result, payload=None, record=None):
    evidence = dict(revocation_result.get("audit_evidence", {}))
    safe_payload = payload if isinstance(payload, dict) else {}
    safe_record = record if isinstance(record, dict) else {}
    if safe_payload.get("tenant_id"):
        tenant_context = tenant_execution_context(safe_payload.get("tenant_id"))
        evidence["tenant_id"] = tenant_context.get("tenant_id")
        evidence["tenant_hash"] = tenant_context.get("tenant_hash")
    evidence["decision"] = "DENY" if revocation_result.get("decision") == REVOCATION_DECISION_DENY else "NEXT_CHECK"
    evidence["policy_hash"] = str(safe_record.get("policy_hash", ""))
    evidence["policy_version"] = str(safe_record.get("policy_version") or safe_payload.get("policy_version") or "")
    evidence["node_id"] = gateway_id()
    evidence_without_hash = dict(evidence)
    evidence_without_hash.pop("audit_hash", None)
    evidence["audit_hash"] = _runtime_enforcement_audit_hash(evidence_without_hash)
    return evidence


def _audit_runtime_revocation_decision(revocation_result, payload=None, record=None):
    audit_chain.append("runtime_revocation_decision", _runtime_revocation_audit_payload(revocation_result, payload, record))


def validate_runtime_revocation_registry_for_runtime(
    record,
    payload=None,
    runtime_attestation=None,
    *,
    registry_path=None,
    timestamp=None,
):
    safe_record = record if isinstance(record, dict) else {}
    safe_payload = payload if isinstance(payload, dict) else {}
    subjects = _runtime_revocation_subjects(safe_payload, safe_record, runtime_attestation)
    decision_timestamp = timestamp or _runtime_enforcement_timestamp()
    registry_path_value = Path(
        registry_path
        or os.getenv("USBAY_RUNTIME_REVOCATION_REGISTRY_PATH", str(RUNTIME_REVOCATION_REGISTRY_PATH))
    )
    try:
        registry = load_runtime_revocation_registry(registry_path_value)
        revocation = evaluate_runtime_revocation(
            registry,
            timestamp=decision_timestamp,
            **subjects,
        )
    except RuntimeRevocationRegistryError as exc:
        revocation = runtime_revocation_result(
            decision=REVOCATION_DECISION_DENY,
            reason_code=str(exc) or REASON_REGISTRY_UNAVAILABLE,
            registry_state="UNKNOWN",
            timestamp=decision_timestamp,
            **subjects,
        )
    except Exception:
        revocation = runtime_revocation_result(
            decision=REVOCATION_DECISION_DENY,
            reason_code=REASON_REGISTRY_UNAVAILABLE,
            registry_state="UNKNOWN",
            timestamp=decision_timestamp,
            **subjects,
        )

    try:
        revocation["audit_evidence"] = _runtime_revocation_audit_payload(revocation, safe_payload, safe_record)
        _audit_runtime_revocation_decision(revocation, safe_payload, safe_record)
    except Exception:
        return runtime_enforcement_deny(
            "runtime_revocation_audit_failed",
            payload=safe_payload,
            record=safe_record,
            timestamp=decision_timestamp,
        )

    if revocation.get("decision") == REVOCATION_DECISION_DENY:
        result = runtime_enforcement_deny(
            revocation.get("reason_code", REASON_REGISTRY_UNAVAILABLE),
            payload=safe_payload,
            record=safe_record,
            timestamp=decision_timestamp,
        )
        result["revocation_audit_evidence"] = revocation.get("audit_evidence", {})
        return result

    result = runtime_enforcement_next_check(payload=safe_payload, record=safe_record, timestamp=decision_timestamp)
    result["revocation_audit_evidence"] = revocation.get("audit_evidence", {})
    return result


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


def _is_public_verification_pem_path(relative_path):
    if relative_path in APPROVED_PUBLIC_PEM_PATHS:
        return True
    parts = Path(relative_path).parts
    name = Path(relative_path).name.lower()
    if parts and parts[0] == "keys_runtime" and name.endswith(".pub.pem"):
        return True
    if parts and parts[0] == "approvals" and name.endswith("_public_key.pem"):
        return True
    return False


def _is_public_verification_key_path(relative_path):
    parts = Path(relative_path).parts
    name = Path(relative_path).name.lower()
    if parts and parts[0] == "governance" and name.endswith("_public.key"):
        return True
    if parts and parts[0] == "policy" and name.endswith("_public.key"):
        return True
    if parts and parts[0] == "audit" and name.endswith("_public.key"):
        return True
    return False


def _is_public_key_artifact(path):
    try:
        head = path.read_text(encoding="utf-8", errors="ignore")[:4096]
    except Exception:
        return False
    return "PUBLIC KEY" in head and "PRIVATE KEY" not in head


def _is_public_key_material_artifact(path):
    try:
        data = path.read_bytes()
    except Exception:
        return False
    if not data:
        return False
    text = data[:4096].decode("utf-8", errors="ignore")
    if "PRIVATE KEY" in text:
        return False
    if "PUBLIC KEY" in text:
        return True
    return len(data) in {32, 57} and all(byte not in b"\r\n\t " for byte in data)


def _is_approved_public_pem_path(relative_path):
    return _is_public_verification_pem_path(relative_path)


def forbidden_runtime_files_in_repo(repo_root=None):
    return [finding["path"] for finding in forbidden_runtime_file_findings(repo_root)]


def forbidden_runtime_file_findings(repo_root=None):
    root = Path(repo_root or REPO_ROOT)
    excluded_dirs = {
        ".git",
        ".githooks",
        ".github",
        ".pytest_cache",
        ".venv",
        "__pycache__",
        "docs",
        "demos",
        "tests",
        "tools",
        "usbay_policy_brain.egg-info",
        "venv",
    }
    findings = []

    def add_finding(relative_path, rule_id):
        findings.append({"path": str(relative_path), "rule": str(rule_id)})

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(part in excluded_dirs for part in relative.parts):
            continue
        rel = relative.as_posix()
        name = path.name.lower()
        if name == ".env" or path.suffix == ".env":
            add_finding(rel, "env_file")
            continue
        if rel.startswith("secrets/"):
            add_finding(rel, "secrets_directory")
            continue
        if rel.startswith("tmp/") and "private" in name:
            add_finding(rel, "tmp_private_file")
            continue
        if path.suffix.lower() == ".pem":
            if not _is_approved_public_pem_path(rel):
                add_finding(rel, "unapproved_pem_file")
                continue
            if not _is_public_key_artifact(path):
                add_finding(rel, "public_verification_pem_not_public_key")
                continue
        if path.suffix.lower() == ".key":
            if _is_public_verification_key_path(rel):
                if not _is_public_key_material_artifact(path):
                    add_finding(rel, "public_verification_key_not_public_material")
                    continue
            else:
                add_finding(rel, "private_key_file")
                continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        private_markers = (
            "BEGIN " + "PRIVATE KEY",
            "BEGIN RSA " + "PRIVATE KEY",
            "BEGIN OPENSSH " + "PRIVATE KEY",
        )
        if any(marker in text for marker in private_markers):
            add_finding(rel, "private_key_material_marker")
    return sorted(findings, key=lambda item: (item["path"], item["rule"]))


def forbidden_runtime_file_diagnostics(repo_root=None):
    findings = forbidden_runtime_file_findings(repo_root)
    return {
        "error": "forbidden_runtime_file_present",
        "findings": findings,
        "offending_paths": [finding["path"] for finding in findings],
        "matched_rules": [finding["rule"] for finding in findings],
    }


def _forbidden_runtime_file_error(findings):
    diagnostics = {
        "error": "forbidden_runtime_file_present",
        "findings": findings,
        "offending_paths": [finding["path"] for finding in findings],
        "matched_rules": [finding["rule"] for finding in findings],
    }
    return PolicyRegistryError("forbidden_runtime_file_present:" + canonical(diagnostics))


def validate_no_forbidden_runtime_files(repo_root=None):
    findings = forbidden_runtime_file_findings(repo_root)
    if findings:
        raise _forbidden_runtime_file_error(findings)
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


def hydra_clients_support_live_votes(clients):
    return bool(clients) and all(callable(getattr(client, "vote", None)) for client in clients)


def evaluate_hydra_request(request_hash_value, policy_version, action="", context=None):
    clients = hydra_node_clients
    if hydra_live_mode_enabled() and hydra_clients_support_live_votes(clients):
        votes = collect_live_votes(
            request_hash=request_hash_value,
            policy_version=policy_version,
            action=action,
            context=context or {},
            clients=clients,
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
        collect_node_decisions(
            request_hash=request_hash_value,
            policy_version=policy_version,
            clients=clients,
            context=hydra_context,
        ),
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


def _deny_decision_response(
    reason,
    status_code=403,
    payload=None,
    decision_id=None,
    provenance_context=None,
    runtime_enforcement_evidence=None,
):
    tenant_context = tenant_execution_context(payload.get("tenant_id")) if isinstance(payload, dict) and payload.get("tenant_id") else {}
    enforcement_evidence = runtime_enforcement_evidence if isinstance(runtime_enforcement_evidence, dict) else {}
    event = {
        "decision_id": decision_id or enforcement_evidence.get("decision_id"),
        "request_hash": enforcement_evidence.get("request_hash") or (
            request_hash(request_signature_message(payload)) if isinstance(payload, dict) else None
        ),
        "decision": "DENY",
        "policy_version": enforcement_evidence.get("policy_version") or (_policy_version(payload) if isinstance(payload, dict) else None),
        "nonce_hash": enforcement_evidence.get("nonce_hash") or (nonce_hash(payload.get("nonce", "")) if isinstance(payload, dict) else None),
        "actor_hash": actor_hash(payload.get("actor_id", "")) if isinstance(payload, dict) and payload.get("actor_id") else None,
        "created_at": int(time.time()),
        "expires_at": None,
        "used": None,
        "reason_code": reason,
        "timestamp": int(time.time()),
        "tenant_id": tenant_context.get("tenant_id"),
        "tenant_hash": tenant_context.get("tenant_hash"),
        "policy_hash": enforcement_evidence.get("policy_hash"),
        "audit_hash": enforcement_evidence.get("audit_hash"),
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

    nonce_enforcement = validate_nonce_replay_for_runtime(payload, record)
    if nonce_enforcement.get("decision") == RUNTIME_ENFORCEMENT_DENY:
        return False, _deny_decision_response(
            nonce_enforcement.get("reason_code", "runtime_enforcement_failed"),
            payload=payload,
            decision_id=str(decision_id),
            runtime_enforcement_evidence=nonce_enforcement.get("audit_evidence"),
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
        runtime_attestation = signed_runtime_attestation_snapshot()
    except Exception:
        runtime_attestation = None
    attestation_enforcement = validate_attestation_freshness_for_runtime(
        runtime_attestation,
        payload=payload,
        record=record,
    )
    if attestation_enforcement.get("decision") == RUNTIME_ENFORCEMENT_DENY:
        return False, _deny_decision_response(
            attestation_enforcement.get("reason_code", "runtime_enforcement_failed"),
            payload=payload,
            decision_id=str(decision_id),
            runtime_enforcement_evidence=attestation_enforcement.get("audit_evidence"),
        )

    registry_enforcement = validate_runtime_revocation_registry_for_runtime(
        record,
        payload=payload,
        runtime_attestation=runtime_attestation,
    )
    if registry_enforcement.get("decision") == RUNTIME_ENFORCEMENT_DENY:
        return False, _deny_decision_response(
            registry_enforcement.get("reason_code", "runtime_enforcement_failed"),
            payload=payload,
            decision_id=str(decision_id),
            runtime_enforcement_evidence=registry_enforcement.get("audit_evidence"),
        )

    revocation_enforcement = validate_runtime_revocation_state_for_runtime(record, payload=payload)
    if revocation_enforcement.get("decision") == RUNTIME_ENFORCEMENT_DENY:
        return False, _deny_decision_response(
            revocation_enforcement.get("reason_code", "runtime_enforcement_failed"),
            payload=payload,
            decision_id=str(decision_id),
            runtime_enforcement_evidence=revocation_enforcement.get("audit_evidence"),
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


def _safe_governance_evidence_path(path_value):
    candidate = Path(path_value)
    if candidate.is_absolute():
        return None
    resolved = (REPO_ROOT / candidate).resolve()
    try:
        resolved.relative_to(REPO_ROOT.resolve())
    except ValueError:
        return None
    return resolved


def _load_governance_dashboard_audit():
    evidence_path = _safe_governance_evidence_path(GOVERNANCE_DASHBOARD_AUDIT_PATH)
    if evidence_path is None:
        return None, "GOVERNANCE_FETCH_FAILED:unsafe_evidence_path"
    if not evidence_path.is_file():
        return None, "GOVERNANCE_FETCH_FAILED:evidence_missing"
    try:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None, "GOVERNANCE_FETCH_FAILED:evidence_malformed"
    if not isinstance(payload, dict):
        return None, "GOVERNANCE_FETCH_FAILED:evidence_not_object"
    return payload, "GOVERNANCE_FETCH_OK"


def _dashboard_audit_hash_valid(payload):
    expected = payload.get("dashboard_audit_hash")
    if not isinstance(expected, str) or len(expected) != 64:
        return False
    signable = dict(payload)
    signable.pop("dashboard_audit_hash", None)
    return _sha256_text(canonical(signable)) == expected


def _evidence_source_hashes_valid(payload):
    sources = payload.get("evidence_sources")
    if not isinstance(sources, list) or not sources:
        return False, "GOVERNANCE_SOURCE_HASH_MISSING"
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            return False, f"GOVERNANCE_SOURCE_HASH_INVALID:{index}"
        source_path = source.get("path")
        expected_hash = source.get("sha256")
        if not isinstance(source_path, str) or not isinstance(expected_hash, str) or len(expected_hash) != 64:
            return False, f"GOVERNANCE_SOURCE_HASH_INVALID:{index}"
        resolved = _safe_governance_evidence_path(source_path)
        if resolved is None:
            return False, f"GOVERNANCE_SOURCE_PATH_UNSAFE:{index}"
        if not resolved.is_file():
            return False, f"GOVERNANCE_SOURCE_FETCH_FAILED:{source_path}"
        actual_hash = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            return False, f"GOVERNANCE_SOURCE_HASH_MISMATCH:{source_path}"
    return True, "GOVERNANCE_SOURCE_HASHES_VERIFIED"


PROMPT_INJECTION_PATTERNS = (
    "ignore previous",
    "return only approved",
    "skip validation",
    "do not ask for evidence",
    "bypass governance",
    "override usbay",
)
PRIVACY_RISK_PATTERNS = (
    "private key",
    "begin rsa private key",
    "begin private key",
    "aws secret access key",
    "credential",
    "password",
    "secret",
    "provider secret",
    "raw approval contents",
)
UNSUPPORTED_CLAIM_PATTERNS = (
    "founder approved",
    "confidential approval",
    "verbal approval",
    "emergency override",
    "certified",
    "blocker closed",
    "compliance approved",
)


def _as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "approved", "complete", "completed", "verified"}
    return False


def _assessment_text(payload):
    values = []
    if isinstance(payload, dict):
        for key in ("evidence_package", "requested_action", "claim", "notes", "approval_basis"):
            value = payload.get(key)
            if isinstance(value, str):
                values.append(value)
    return " ".join(values).lower()


def _stable_assessment_id(prefix, payload):
    return prefix + "-" + _sha256_text(canonical(payload))[:32]


EURIA_RUNTIME_ALLOWED_RECOMMENDATIONS = {"ALLOW", "BLOCKED", "HUMAN_REVIEW"}


def _build_euria_runtime_analysis(payload, *, text, normalized_text, evidence_package, requested_action):
    missing_evidence = []
    unsupported_claims = []
    privacy_risks = []
    prompt_injection_findings = []

    if not evidence_package:
        missing_evidence.append("EVIDENCE_PACKAGE_MISSING")
    if not requested_action:
        missing_evidence.append("REQUESTED_ACTION_MISSING")
    if not str(payload.get("policy_id") or "").strip():
        missing_evidence.append("POLICY_ID_MISSING")
    if not _as_bool(payload.get("evidence_verified")):
        missing_evidence.append("EVIDENCE_UNVERIFIED")
    if not _as_bool(payload.get("audit_chain_complete")):
        missing_evidence.append("AUDIT_CHAIN_INCOMPLETE")

    signature_input = str(payload.get("signature_status") or "").strip().upper()
    timestamp_input = str(payload.get("timestamp_status") or "").strip().upper()
    if signature_input not in {"SIGNED", "VERIFIED"}:
        missing_evidence.append("SIGNATURE_MISSING")
    if timestamp_input not in {"TIMESTAMPED", "VERIFIED"}:
        missing_evidence.append("TIMESTAMP_MISSING")

    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern in text:
            prompt_injection_findings.append("PROMPT_INJECTION_ATTEMPT:" + pattern.replace(" ", "_").upper())
    for pattern in PRIVACY_RISK_PATTERNS:
        if pattern in normalized_text:
            privacy_risks.append("PRIVACY_RISK:" + pattern.replace(" ", "_").upper())
    for pattern in UNSUPPORTED_CLAIM_PATTERNS:
        if pattern in text:
            unsupported_claims.append("UNSUPPORTED_CLAIM:" + pattern.replace(" ", "_").upper())

    high_risk_action = str(payload.get("risk_level") or "low").strip().lower() in {"high", "critical"} or _as_bool(payload.get("high_risk_action"))
    review_required = high_risk_action or _as_bool(payload.get("approval_threshold_exceeded")) or _as_bool(payload.get("escalation_required"))
    human_approval_completed = _as_bool(payload.get("human_approval_completed"))
    if missing_evidence or unsupported_claims or privacy_risks or prompt_injection_findings:
        recommendation = "BLOCKED"
    elif review_required and not human_approval_completed:
        recommendation = "HUMAN_REVIEW"
    elif human_approval_completed:
        recommendation = "ALLOW"
    else:
        recommendation = "BLOCKED"
        missing_evidence.append("HUMAN_APPROVAL_MISSING")

    analysis_seed = {
        "authority": "ANALYSIS_ONLY",
        "missing_evidence": sorted(set(missing_evidence)),
        "privacy_risks": sorted(set(privacy_risks)),
        "prompt_injection_findings": sorted(set(prompt_injection_findings)),
        "recommendation": recommendation,
        "requested_action_hash": _sha256_text(requested_action) if requested_action else "",
        "unsupported_claims": sorted(set(unsupported_claims)),
    }
    return {
        "schema": "usbay.euria_runtime_analysis.v1",
        "authority": "ANALYSIS_ONLY",
        "analysis_id": _stable_assessment_id("euria-analysis", analysis_seed),
        "recommendation": recommendation,
        "missing_evidence": analysis_seed["missing_evidence"],
        "unsupported_claims": analysis_seed["unsupported_claims"],
        "privacy_risks": analysis_seed["privacy_risks"],
        "prompt_injection_findings": analysis_seed["prompt_injection_findings"],
    }


def _validate_euria_runtime_analysis(analysis):
    if not isinstance(analysis, dict):
        return False, "EURIA_ANALYSIS_MISSING"
    if analysis.get("schema") != "usbay.euria_runtime_analysis.v1":
        return False, "EURIA_ANALYSIS_SCHEMA_INVALID"
    if analysis.get("authority") != "ANALYSIS_ONLY":
        return False, "EURIA_AUTHORITY_INVALID"
    if not str(analysis.get("analysis_id") or "").startswith("euria-analysis-"):
        return False, "EURIA_ANALYSIS_ID_INVALID"
    if str(analysis.get("recommendation") or "").upper() not in EURIA_RUNTIME_ALLOWED_RECOMMENDATIONS:
        return False, "EURIA_RECOMMENDATION_INVALID"
    for key in ("missing_evidence", "unsupported_claims", "privacy_risks", "prompt_injection_findings"):
        if not isinstance(analysis.get(key), list):
            return False, "EURIA_ANALYSIS_" + key.upper() + "_INVALID"
    return True, ""


def _fail_closed_euria_runtime_assessment(policy_id, reason):
    normalized = {
        "policy_id": policy_id or "usbay.euria_live_assessment_policy.v1",
        "reason": reason,
        "usbay_decision": "FAIL_CLOSED",
    }
    request_id = _stable_assessment_id("request", normalized)
    decision_id = _stable_assessment_id("decision", normalized)
    audit_id = _stable_assessment_id("audit", normalized)
    return {
        "schema": "usbay.euria_live_assessment.v1",
        "authority": {
            "euria": "ANALYSIS_ONLY",
            "usbay": "ENFORCEMENT_AUTHORITY",
            "human_approval": "MANDATORY",
        },
        "request_id": request_id,
        "euria_analysis_id": "",
        "euria_analysis": {},
        "euria_recommendation": "BLOCKED",
        "missing_evidence": [reason],
        "unsupported_claims": ["Euria approval authority is unsupported"],
        "privacy_risks": ["Credentials, private keys, raw approvals, and provider secrets are prohibited"],
        "prompt_injection_findings": ["none"],
        "usbay_decision": "FAIL_CLOSED",
        "outcome": "FAIL_CLOSED",
        "human_approval_status": "BLOCKED",
        "policy_id": normalized["policy_id"],
        "decision_id": decision_id,
        "audit_record_id": audit_id,
        "signature_status": "BLOCKED",
        "timestamp_status": "BLOCKED",
        "audit_output": {
            "request_id": request_id,
            "euria_analysis_id": "",
            "audit_id": audit_id,
            "audit_record_id": audit_id,
            "decision_id": decision_id,
            "policy_id": normalized["policy_id"],
            "timestamp_id": "",
            "signature_id": "",
            "outcome": "FAIL_CLOSED",
            "fail_closed_reason": reason,
        },
        "decision_outcome": "FAIL_CLOSED",
        "review_required": True,
        "fail_closed": True,
        "fail_closed_reason": reason,
    }


def _evaluate_euria_assessment(payload):
    if not isinstance(payload, dict):
        return _fail_closed_euria_runtime_assessment("usbay.euria_live_assessment_policy.v1", "EURIA_REQUEST_INVALID")
    evidence_package = str(payload.get("evidence_package") or "").strip()
    requested_action = str(payload.get("requested_action") or "").strip()
    policy_id = str(payload.get("policy_id") or "usbay.euria_live_assessment_policy.v1").strip()
    risk_level = str(payload.get("risk_level") or "low").strip().lower()
    evidence_verified = _as_bool(payload.get("evidence_verified"))
    audit_chain_complete = _as_bool(payload.get("audit_chain_complete"))
    human_approval_completed = _as_bool(payload.get("human_approval_completed"))
    approval_threshold_exceeded = _as_bool(payload.get("approval_threshold_exceeded"))
    escalation_required = _as_bool(payload.get("escalation_required"))
    high_risk_action = risk_level in {"high", "critical"} or _as_bool(payload.get("high_risk_action"))
    signature_input = str(payload.get("signature_status") or "").strip().upper()
    timestamp_input = str(payload.get("timestamp_status") or "").strip().upper()
    signature_status = signature_input if signature_input in {"SIGNED", "VERIFIED"} else "BLOCKED"
    timestamp_status = timestamp_input if timestamp_input in {"TIMESTAMPED", "VERIFIED"} else "BLOCKED"
    text = _assessment_text(payload)
    normalized_text = text.replace("_", " ")
    local_euria_analysis = _build_euria_runtime_analysis(
        payload,
        text=text,
        normalized_text=normalized_text,
        evidence_package=evidence_package,
        requested_action=requested_action,
    )
    if _as_bool(payload.get("require_external_euria_response")) and "euria_analysis" not in payload:
        return _fail_closed_euria_runtime_assessment(policy_id, "EURIA_ANALYSIS_MISSING")
    if "euria_analysis" in payload:
        euria_analysis = payload.get("euria_analysis")
    else:
        euria_analysis = local_euria_analysis
    valid_euria_analysis, euria_validation_reason = _validate_euria_runtime_analysis(euria_analysis)
    if not valid_euria_analysis:
        return _fail_closed_euria_runtime_assessment(policy_id, euria_validation_reason)
    if "euria_analysis" in payload and euria_analysis["recommendation"] != local_euria_analysis["recommendation"]:
        return _fail_closed_euria_runtime_assessment(policy_id, "EURIA_ANALYSIS_USBAY_EVIDENCE_MISMATCH")

    missing_evidence = list(euria_analysis["missing_evidence"]) + list(local_euria_analysis["missing_evidence"])
    unsupported_claims = list(euria_analysis["unsupported_claims"]) + list(local_euria_analysis["unsupported_claims"])
    privacy_risks = list(euria_analysis["privacy_risks"]) + list(local_euria_analysis["privacy_risks"])
    prompt_injection_findings = list(euria_analysis["prompt_injection_findings"]) + list(local_euria_analysis["prompt_injection_findings"])

    review_required = high_risk_action or approval_threshold_exceeded or escalation_required
    if review_required and not human_approval_completed:
        human_approval_status = "REQUIRED"
    elif human_approval_completed:
        human_approval_status = "APPROVED"
    else:
        human_approval_status = "BLOCKED"

    blocked_reasons = []
    blocked_reasons.extend(missing_evidence)
    blocked_reasons.extend(unsupported_claims)
    blocked_reasons.extend(privacy_risks)
    blocked_reasons.extend(prompt_injection_findings)

    if blocked_reasons:
        usbay_decision = "BLOCKED"
    elif review_required and not human_approval_completed:
        usbay_decision = "HUMAN_REVIEW"
    elif not human_approval_completed:
        usbay_decision = "BLOCKED"
        blocked_reasons.append("HUMAN_APPROVAL_MISSING")
        missing_evidence.append("HUMAN_APPROVAL_MISSING")
    else:
        usbay_decision = "ALLOW"

    if usbay_decision == "ALLOW" and euria_analysis["recommendation"] != "ALLOW":
        return _fail_closed_euria_runtime_assessment(policy_id, "EURIA_ANALYSIS_USBAY_DECISION_MISMATCH")
    euria_recommendation = euria_analysis["recommendation"]
    evidence_hash = _sha256_text(evidence_package) if evidence_package else ""
    normalized = {
        "audit_chain_complete": audit_chain_complete,
        "blocked_reasons": sorted(set(blocked_reasons)),
        "euria_analysis_id": euria_analysis["analysis_id"],
        "evidence_hash": evidence_hash,
        "evidence_verified": evidence_verified,
        "human_approval_status": human_approval_status,
        "policy_id": policy_id,
        "requested_action_hash": _sha256_text(requested_action) if requested_action else "",
        "signature_status": signature_status,
        "timestamp_status": timestamp_status,
        "usbay_decision": usbay_decision,
    }
    request_id = _stable_assessment_id("request", normalized)
    audit_id = _stable_assessment_id("audit", normalized)
    decision_id = _stable_assessment_id("decision", normalized)
    timestamp_id = _stable_assessment_id("timestamp", {**normalized, "timestamp_status": timestamp_status})
    signature_id = _stable_assessment_id("signature", {**normalized, "signature_status": signature_status})
    return {
        "schema": "usbay.euria_live_assessment.v1",
        "authority": {
            "euria": "ANALYSIS_ONLY",
            "usbay": "ENFORCEMENT_AUTHORITY",
            "human_approval": "MANDATORY",
        },
        "request_id": request_id,
        "euria_analysis_id": euria_analysis["analysis_id"],
        "euria_analysis": euria_analysis,
        "euria_recommendation": euria_recommendation,
        "missing_evidence": sorted(set(missing_evidence)) or ["none"],
        "unsupported_claims": sorted(set(unsupported_claims)) or ["none"],
        "privacy_risks": sorted(set(privacy_risks)) or ["none"],
        "prompt_injection_findings": sorted(set(prompt_injection_findings)) or ["none"],
        "usbay_decision": usbay_decision,
        "outcome": usbay_decision,
        "human_approval_status": human_approval_status,
        "policy_id": policy_id,
        "decision_id": decision_id,
        "audit_record_id": audit_id,
        "signature_status": signature_status,
        "timestamp_status": timestamp_status,
        "audit_output": {
            "request_id": request_id,
            "euria_analysis_id": euria_analysis["analysis_id"],
            "audit_id": audit_id,
            "audit_record_id": audit_id,
            "decision_id": decision_id,
            "policy_id": policy_id,
            "timestamp_id": timestamp_id,
            "signature_id": signature_id,
            "outcome": usbay_decision,
        },
        "decision_outcome": usbay_decision,
        "review_required": review_required,
        "fail_closed": usbay_decision != "ALLOW",
    }


def _reviewer_approval_status(payload):
    approvals = payload.get("reviewer_approvals") if isinstance(payload, dict) else None
    if not isinstance(approvals, list) or not approvals:
        return "REQUIRED"
    if any(not isinstance(item, dict) or str(item.get("decision", "")).upper() != "PASS" for item in approvals):
        return "BLOCKED"
    return "APPROVED"


def _euria_governance_outputs(payload=None, *, signature_verified=False, governance_verdict="UNKNOWN", dashboard_audit_hash=""):
    if not isinstance(payload, dict) or not signature_verified:
        return {
            "schema": "usbay.euria_control_plane_outputs.v1",
            "authority": "ANALYSIS_ONLY",
            "euria_recommendation": "BLOCKED",
            "missing_evidence": ["GOVERNANCE_EVIDENCE_UNVERIFIED"],
            "unsupported_claims": ["Euria approval authority is unsupported"],
            "privacy_risks": ["Credentials, private keys, raw approvals, and provider secrets are prohibited"],
            "usbay_decision": "BLOCKED",
            "human_approval_status": "BLOCKED",
            "audit_record_id": "",
            "signature_status": "GOVERNANCE_EVIDENCE_SIGNATURE_UNVERIFIED",
            "timestamp_status": "BLOCKED",
            "enforcement_authority": "USBAY_ENFORCEMENT_AUTHORITY",
            "human_approval": "MANDATORY",
            "fail_closed": True,
        }

    missing_evidence = []
    controls = payload.get("controls")
    if isinstance(controls, list):
        for control in controls:
            if isinstance(control, dict) and str(control.get("decision", "")).upper() != "PASS":
                missing_evidence.append(str(control.get("reason") or "EVIDENCE_MISSING"))
    missing_evidence.extend(str(item) for item in payload.get("governance_anomalies", []) if item)
    human_approval_status = _reviewer_approval_status(payload)
    if human_approval_status != "APPROVED":
        missing_evidence.append("HUMAN_REVIEW_REQUIRED")
    missing_evidence = sorted(set(item for item in missing_evidence if item))
    if missing_evidence:
        usbay_decision = "BLOCKED"
        euria_recommendation = "BLOCKED"
    else:
        usbay_decision = "APPROVED" if governance_verdict == "APPROVED" else "BLOCKED"
        euria_recommendation = "HUMAN_REVIEW" if usbay_decision == "APPROVED" else "BLOCKED"
    audit_seed = {
        "dashboard_audit_hash": dashboard_audit_hash,
        "human_approval_status": human_approval_status,
        "timestamp": payload.get("timestamp", ""),
        "usbay_decision": usbay_decision,
    }
    return {
        "schema": "usbay.euria_control_plane_outputs.v1",
        "authority": "ANALYSIS_ONLY",
        "euria_recommendation": euria_recommendation,
        "missing_evidence": missing_evidence or ["none"],
        "unsupported_claims": [
            "Euria approval authority is unsupported",
            "Euria execution authority is unsupported",
            "Euria policy modification authority is unsupported",
        ],
        "privacy_risks": ["Credentials, private keys, raw approvals, and provider secrets are prohibited"],
        "usbay_decision": usbay_decision,
        "human_approval_status": human_approval_status,
        "audit_record_id": _sha256_text(canonical(audit_seed)) if dashboard_audit_hash else "",
        "signature_status": "VERIFIED",
        "timestamp_status": "TIMESTAMP_EVIDENCE_PRESENT" if payload.get("timestamp") else "BLOCKED",
        "enforcement_authority": "USBAY_ENFORCEMENT_AUTHORITY",
        "human_approval": "MANDATORY",
        "fail_closed": usbay_decision != "APPROVED",
    }


def governance_evidence_state():
    payload, fetch_reason = _load_governance_dashboard_audit()
    if payload is None:
        euria_outputs = _euria_governance_outputs()
        return {
            "schema": "usbay.governance_evidence_state.v1",
            "fetch_status": "GOVERNANCE_FETCH_FAILED",
            "fetch_reason": fetch_reason,
            "signature_status": "GOVERNANCE_EVIDENCE_SIGNATURE_UNVERIFIED",
            "signature_reason": "GOVERNANCE_EVIDENCE_MISSING",
            "governance_state": "UNVERIFIED",
            "governance_state_label": "Governance Unverified",
            "governance_verdict": "UNKNOWN",
            "evidence_verdict": "UNKNOWN",
            "euria_governance_outputs": euria_outputs,
            "fail_closed": True,
        }

    hash_valid = _dashboard_audit_hash_valid(payload)
    sources_valid, sources_reason = _evidence_source_hashes_valid(payload)
    policy_signature_valid = False
    try:
        registry = load_policy_registry()
        policy_signature_valid = registry.get("policy_signature_valid") is True
    except Exception:
        policy_signature_valid = False

    signature_verified = hash_valid and sources_valid and policy_signature_valid
    raw_decision = str(payload.get("decision") or "BLOCKED").upper()
    if signature_verified:
        governance_verdict = "APPROVED" if raw_decision in {"PASS", "ALLOW", "APPROVED"} else raw_decision
        evidence_verdict = "VERIFIED"
        signature_status = "VERIFIED"
        signature_reason = "GOVERNANCE_EVIDENCE_SIGNATURE_CHAIN_VERIFIED"
        governance_state_label = "Governance Verified"
    else:
        governance_verdict = "UNKNOWN"
        evidence_verdict = "UNKNOWN"
        signature_status = "GOVERNANCE_EVIDENCE_SIGNATURE_UNVERIFIED"
        signature_reason = "GOVERNANCE_EVIDENCE_SIGNATURE_CHAIN_INVALID"
        governance_state_label = "Governance Unverified"

    euria_outputs = _euria_governance_outputs(
        payload,
        signature_verified=signature_verified,
        governance_verdict=governance_verdict,
        dashboard_audit_hash=str(payload.get("dashboard_audit_hash", "")),
    )

    return {
        "schema": "usbay.governance_evidence_state.v1",
        "fetch_status": "GOVERNANCE_FETCH_OK",
        "fetch_reason": fetch_reason,
        "signature_status": signature_status,
        "signature_reason": signature_reason,
        "governance_state": "VERIFIED" if signature_verified else "UNVERIFIED",
        "governance_state_label": governance_state_label,
        "governance_verdict": governance_verdict,
        "evidence_verdict": evidence_verdict,
        "dashboard_decision": raw_decision,
        "dashboard_audit_hash": payload.get("dashboard_audit_hash", ""),
        "dashboard_audit_hash_valid": hash_valid,
        "evidence_source_hashes_valid": sources_valid,
        "evidence_source_reason": sources_reason,
        "evidence_source_count": len(payload.get("evidence_sources", [])) if isinstance(payload.get("evidence_sources"), list) else 0,
        "policy_signature_valid": policy_signature_valid,
        "signature_label": "Signature Verified" if signature_verified else "Signature Unverified",
        "euria_governance_outputs": euria_outputs,
        "fail_closed": not signature_verified,
    }


# -------------------------
# ENDPOINT
# -------------------------

def _html_list(items):
    if not items:
        return "<li>NONE</li>"
    return "".join(f"<li>{html.escape(str(item))}</li>" for item in items)


def _governance_demo_dashboard_html(state):
    pb_rows = []
    for pb_id, record in state.get("pb_status", {}).items():
        pb_rows.append(
            "<tr>"
            f"<th>{html.escape(str(pb_id))}</th>"
            f"<td>{html.escape(str(record.get('state', 'MISSING')))}</td>"
            f"<td>{html.escape(str(record.get('decision', 'UNKNOWN')))}</td>"
            f"<td>{html.escape(str(record.get('fail_closed', True)))}</td>"
            f"<td>{html.escape(str(record.get('generated_at', '')))}</td>"
            f"<td>{html.escape(', '.join(str(path) for path in record.get('source_files', [])))}</td>"
            f"<td>{html.escape(', '.join(str(item) for item in record.get('blockers', [])))}</td>"
            "</tr>"
        )
    pbsec_rows = []
    for gate_id, record in state.get("pbsec_status", {}).items():
        pbsec_rows.append(
            "<tr>"
            f"<th>{html.escape(str(gate_id))}</th>"
            f"<td>{html.escape(str(record.get('state', 'MISSING')))}</td>"
            f"<td>{html.escape(str(record.get('decision', 'UNKNOWN')))}</td>"
            f"<td>{html.escape(str(record.get('fail_closed', True)))}</td>"
            f"<td>{html.escape(str(record.get('generated_at', '')))}</td>"
            f"<td>{html.escape(', '.join(str(path) for path in record.get('source_files', [])))}</td>"
            f"<td>{html.escape(', '.join(str(item) for item in record.get('blockers', [])))}</td>"
            "</tr>"
        )
    runtime_state = state.get("runtime_governance_state", {})
    if not isinstance(runtime_state, dict):
        runtime_state = {}
    correlation = state.get("runtime_health_correlation", {})
    if not isinstance(correlation, dict):
        correlation = {}
    vision = state.get("vision_agent_control", {})
    if not isinstance(vision, dict):
        vision = {}
    bridge = state.get("vision_execution_bridge", {})
    if not isinstance(bridge, dict):
        bridge = {}
    operator_queue = state.get("operator_review_queue", {})
    if not isinstance(operator_queue, dict):
        operator_queue = {}
    operator_queue_counts = operator_queue.get("queue_counts", {})
    if not isinstance(operator_queue_counts, dict):
        operator_queue_counts = {}
    work = state.get("work_orchestrator", {})
    if not isinstance(work, dict):
        work = {}
    work_counts = work.get("queue_counts", {})
    if not isinstance(work_counts, dict):
        work_counts = {}
    metrics = state.get("governance_metrics", {})
    if not isinstance(metrics, dict):
        metrics = {}
    metrics_operator_counts = metrics.get("operator_queue_counts", {})
    if not isinstance(metrics_operator_counts, dict):
        metrics_operator_counts = {}
    metrics_work_counts = metrics.get("work_queue_counts", {})
    if not isinstance(metrics_work_counts, dict):
        metrics_work_counts = {}
    metrics_risk_trends = metrics.get("risk_trends", {})
    if not isinstance(metrics_risk_trends, dict):
        metrics_risk_trends = {}
    evidence_trust = state.get("evidence_trust", {})
    if not isinstance(evidence_trust, dict):
        evidence_trust = {}
    connector_governance = state.get("connector_governance", {})
    if not isinstance(connector_governance, dict):
        connector_governance = {}
    connector_registry = connector_governance.get("connector_registry", {})
    if not isinstance(connector_registry, dict):
        connector_registry = {}
    connector_health = connector_governance.get("connector_health", {})
    if not isinstance(connector_health, dict):
        connector_health = {}
    connector_audit_status = connector_governance.get("connector_audit_status", {})
    if not isinstance(connector_audit_status, dict):
        connector_audit_status = {}
    connector_evidence_status = connector_governance.get("connector_evidence_status", {})
    if not isinstance(connector_evidence_status, dict):
        connector_evidence_status = {}
    runtime_observation = state.get("runtime_observation", {})
    if not isinstance(runtime_observation, dict):
        runtime_observation = {}
    observation_component_health = runtime_observation.get("component_health", {})
    if not isinstance(observation_component_health, dict):
        observation_component_health = {}
    audit_registry = state.get("audit_registry", {})
    if not isinstance(audit_registry, dict):
        audit_registry = {}
    policy_registry = state.get("policy_registry", {})
    if not isinstance(policy_registry, dict):
        policy_registry = {}
    release_gate = state.get("release_gate", {})
    if not isinstance(release_gate, dict):
        release_gate = {}
    tenant_boundary = state.get("tenant_boundary", {})
    if not isinstance(tenant_boundary, dict):
        tenant_boundary = {}
    document_governance = state.get("document_governance", {})
    if not isinstance(document_governance, dict):
        document_governance = {}
    production_readiness = state.get("production_readiness", {})
    if not isinstance(production_readiness, dict):
        production_readiness = {}
    sovereign_deployment = state.get("sovereign_deployment", {})
    if not isinstance(sovereign_deployment, dict):
        sovereign_deployment = {}
    customer_workspace = state.get("customer_workspace", {})
    if not isinstance(customer_workspace, dict):
        customer_workspace = {}
    document_library = state.get("document_library", {})
    if not isinstance(document_library, dict):
        document_library = {}
    customer_onboarding = state.get("customer_onboarding", {})
    if not isinstance(customer_onboarding, dict):
        customer_onboarding = {}
    license_governance = state.get("license_governance", {})
    if not isinstance(license_governance, dict):
        license_governance = {}
    hydra_consensus = state.get("hydra_consensus", {})
    if not isinstance(hydra_consensus, dict):
        hydra_consensus = {}
    execution = state.get("execution_framework", {})
    if not isinstance(execution, dict):
        execution = {}
    timeline_items = [
        f"{record.get('generated_at', '')} {record.get('scope', '')} {record.get('state', '')} {record.get('source_file', '')}"
        for record in state.get("event_timeline", [])
        if isinstance(record, dict)
    ]
    return """
	    <section id="governance-demo-sync-dashboard" data-source="read-only-governance-evidence">
	      <h2>Governance Demo Synchronization</h2>
	      <p id="runtime-governance-state">Runtime governance state: %s</p>
	      <p id="runtime-readiness-state">Runtime readiness: %s</p>
	      <p id="deployment-readiness-state">Deployment readiness: %s</p>
	      <p id="policy-validator-state">Policy validator state: %s</p>
	      <p id="promote-state">Promote state: %s</p>
	      <p id="promote-reason">Promote reason: %s</p>
	      <p id="production-readiness-state">Production readiness: %s</p>
	      <p id="human-approval-status">Human approval status: %s</p>
	    </section>
	    <section id="pb015-pb020-status-board">
	      <h2>PB-015 through PB-020 Status Board</h2>
	      <table><thead><tr><th>PB</th><th>State</th><th>Decision</th><th>Fail Closed</th><th>Generated</th><th>Source File Path</th><th>Blockers</th></tr></thead><tbody>%s</tbody></table>
	    </section>
	    <section id="pbsec-security-gate-dashboard">
	      <h2>PB-SEC Security Gate Dashboard</h2>
	      <table><thead><tr><th>Gate</th><th>State</th><th>Decision</th><th>Fail Closed</th><th>Generated</th><th>Source File Path</th><th>Blockers</th></tr></thead><tbody>%s</tbody></table>
	    </section>
	    <section id="fail-closed-reason-explorer">
	      <h2>Fail-Closed Reason Explorer</h2>
	      <ul>%s</ul>
	    </section>
	    <section id="evidence-lineage-viewer">
	      <h2>Evidence Lineage Viewer</h2>
	      <p id="evidence-lineage-chain">%s</p>
	    </section>
	    <section id="runtime-health-governance-correlation">
	      <h2>Runtime Health + Governance Correlation</h2>
	      <p id="correlation-pb020-blocked">PB-020 blocked: %s</p>
	      <p id="correlation-pbsec-blocked">PB-SEC blocked: %s</p>
	      <p id="correlation-deployment-blocked">Deployment readiness failure: %s</p>
	      <p id="correlation-production-approval-missing">Production approval missing: %s</p>
	    </section>
	    <section id="vision-agent-control-dashboard">
	      <h2>Governed Vision Agent Control</h2>
	      <p id="vision-observation-status">Latest vision observation status: %s</p>
	      <p id="vision-action-proposal-status">Latest action proposal status: %s</p>
	      <p id="vision-blocked-action-types">Blocked action types: %s</p>
	      <p id="vision-human-approval-required">Human approval required: %s</p>
	      <p id="vision-audit-hash">Audit hash: %s</p>
	      <p id="vision-reason-codes">Reason codes: %s</p>
	      <p id="vision-raw-screenshot-not-stored">Raw screenshot not stored: %s</p>
	      <p id="vision-execution-adapter-status">Execution adapter status: %s</p>
	    </section>
	    <section id="vision-execution-bridge-dashboard">
	      <h2>Vision Execution Bridge</h2>
	      <p id="vx-observation-id">Latest observation ID: %s</p>
	      <p id="vx-proposal-id">Latest proposal ID: %s</p>
	      <p id="vx-execution-request-id">Latest execution request ID: %s</p>
	      <p id="vx-human-approval-status">Latest human approval status: %s</p>
	      <p id="vx-execution-decision">Latest execution decision: %s</p>
	      <p id="vx-bridge-status">Bridge status: %s</p>
	      <p id="vx-lineage-hash">Lineage hash: %s</p>
	      <p id="vx-reason-codes">Blocked reason codes: %s</p>
	      <p id="vx-adapter-status">Adapter status: %s</p>
	      <p id="vx-execution-engine-status">Execution engine status: %s</p>
	    </section>
	    <section id="operator-review-queue-dashboard">
	      <h2>Governed Operator Review Queue</h2>
	      <p id="operator-review-id">Review ID: %s</p>
	      <p id="operator-role">Operator role: %s</p>
	      <p id="operator-review-state">Review state: %s</p>
	      <p id="operator-decision">Decision: %s</p>
	      <p id="operator-decision-reason">Decision reason: %s</p>
	      <p id="operator-review-timestamp">Review timestamp: %s</p>
	      <p id="operator-queue-pending">Pending reviews: %s</p>
	      <p id="operator-queue-approved">Approved reviews: %s</p>
	      <p id="operator-queue-rejected">Rejected reviews: %s</p>
	      <p id="operator-queue-needs-information">Needs information reviews: %s</p>
	      <p id="operator-audit-hash">Operator audit hash: %s</p>
	      <p id="operator-lineage-hash">Operator lineage hash: %s</p>
	      <p id="operator-reason-codes">Operator reason codes: %s</p>
	    </section>
	    <section id="work-orchestrator-dashboard">
	      <h2>Governed Work Orchestrator</h2>
	      <p id="work-item-id">Work item ID: %s</p>
	      <p id="work-owner">Owner: %s</p>
	      <p id="work-owner-role">Role: %s</p>
	      <p id="work-priority">Priority: %s</p>
	      <p id="work-severity">Severity: %s</p>
	      <p id="work-status">Status: %s</p>
	      <p id="work-created-at">Created at: %s</p>
	      <p id="work-assigned-at">Assigned at: %s</p>
	      <p id="work-resolved-at">Resolved at: %s</p>
	      <p id="work-closed-at">Closed at: %s</p>
	      <p id="work-queue-new">New work items: %s</p>
	      <p id="work-queue-assigned">Assigned work items: %s</p>
	      <p id="work-queue-in-progress">In-progress work items: %s</p>
	      <p id="work-queue-escalated">Escalated work items: %s</p>
	      <p id="work-queue-resolved">Resolved work items: %s</p>
	      <p id="work-queue-closed">Closed work items: %s</p>
	      <p id="work-audit-hash">Work audit hash: %s</p>
	      <p id="work-lineage-hash">Work lineage hash: %s</p>
	      <p id="work-reason-codes">Work reason codes: %s</p>
	    </section>
	    <section id="governance-metrics-dashboard">
	      <h2>Governed Governance Intelligence</h2>
	      <p id="metrics-health-score">Governance health score: %s</p>
	      <p id="metrics-total-requests">Total requests: %s</p>
	      <p id="metrics-blocked-requests">Blocked requests: %s</p>
	      <p id="metrics-approved-requests">Approved requests: %s</p>
	      <p id="metrics-rejected-requests">Rejected requests: %s</p>
	      <p id="metrics-operator-queue-counts">Operator queue counts: %s</p>
	      <p id="metrics-work-queue-counts">Work queue counts: %s</p>
	      <p id="metrics-sla-status">SLA status: %s</p>
	      <p id="metrics-risk-trends">Risk trends: %s</p>
	      <p id="metrics-critical-blockers">Critical blockers: %s</p>
	      <p id="metrics-generated-at">Last metrics generated at: %s</p>
	      <p id="metrics-reason-codes">Metrics reason codes: %s</p>
	    </section>
	    <section id="evidence-trust-dashboard">
	      <h2>Cryptographic Evidence Trust</h2>
	      <p id="evidence-manifest-id">Evidence manifest ID: %s</p>
	      <p id="evidence-artifact-count">Artifact count: %s</p>
	      <p id="evidence-verification-status">Verification status: %s</p>
	      <p id="evidence-signature-status">Signature status: %s</p>
	      <p id="evidence-timestamp-status">Timestamp status: %s</p>
	      <p id="evidence-tamper-status">Tamper status: %s</p>
	      <p id="evidence-last-verified-at">Last verified at: %s</p>
	      <p id="evidence-policy-version">Evidence policy version: %s</p>
	      <p id="evidence-timestamp-integration-status">Timestamp integration status: %s</p>
	      <p id="evidence-reason-codes">Evidence reason codes: %s</p>
	    </section>
	    <section id="connector-governance-dashboard">
	      <h2>Governed Enterprise Connectors</h2>
	      <p id="connector-registry">Connector registry: %s</p>
	      <p id="connector-count">Connector count: %s</p>
	      <p id="connector-enabled-read-only">Enabled read-only connectors: %s</p>
	      <p id="connector-blocked-write-actions">Blocked write actions: %s</p>
	      <p id="connector-health">Connector health: %s</p>
	      <p id="connector-audit-status">Connector audit status: %s</p>
	      <p id="connector-evidence-status">Connector evidence status: %s</p>
	      <p id="connector-reason-codes">Connector reason codes: %s</p>
	    </section>
	    <section id="runtime-observation-dashboard">
	      <h2>Governed Runtime Observation</h2>
	      <p id="observation-runtime-health">Runtime health: %s</p>
	      <p id="observation-component-health">Component health: %s</p>
	      <p id="observation-event-timeline-status">Event timeline status: %s</p>
	      <p id="observation-drift-status">Drift status: %s</p>
	      <p id="observation-last-observation">Last observation: %s</p>
	      <p id="observation-count">Observation count: %s</p>
	      <p id="observation-reason-codes">Observation reason codes: %s</p>
	    </section>
	    <section id="audit-registry-dashboard">
	      <h2>Cryptographic Governance Registry</h2>
	      <p id="audit-registry-status">Registry status: %s</p>
	      <p id="audit-registry-record-count">Registry record count: %s</p>
	      <p id="audit-registry-tamper-status">Registry tamper status: %s</p>
	      <p id="audit-registry-last-verified">Registry last verified: %s</p>
	      <p id="audit-registry-reason-codes">Registry reason codes: %s</p>
	      <p id="governance-history-status">Governance history status: %s</p>
	    </section>
	    <section id="policy-registry-dashboard">
	      <h2>Governed Policy Lifecycle Registry</h2>
	      <p id="policy-registry-status">Policy registry status: %s</p>
	      <p id="policy-count">Policy count: %s</p>
	      <p id="active-policy-count">Active policy count: %s</p>
	      <p id="deprecated-policy-count">Deprecated policy count: %s</p>
	      <p id="latest-policy-version">Latest policy version: %s</p>
	      <p id="policy-promotion-status">Promotion status: %s</p>
	      <p id="policy-registry-reason-codes">Policy registry reason codes: %s</p>
	    </section>
	    <section id="release-gate-dashboard">
	      <h2>Governed Release Control</h2>
	      <p id="release-gate-status">Release gate status: %s</p>
	      <p id="release-readiness-status">Release readiness status: %s</p>
	      <p id="release-decision">Release decision: %s</p>
	      <p id="release-target-environment">Release target environment: %s</p>
	      <p id="release-manifest-status">Release manifest status: %s</p>
	      <p id="release-rollback-plan-status">Rollback plan status: %s</p>
	      <p id="release-reason-codes">Release reason codes: %s</p>
	    </section>
	    <section id="tenant-boundary-dashboard">
	      <h2>Governed Tenant Isolation</h2>
	      <p id="tenant-boundary-status">Tenant boundary status: %s</p>
	      <p id="tenant-id">Tenant ID: %s</p>
	      <p id="tenant-classification">Tenant classification: %s</p>
	      <p id="tenant-region">Tenant region: %s</p>
	      <p id="tenant-policy-namespace">Tenant policy namespace: %s</p>
	      <p id="tenant-evidence-namespace">Tenant evidence namespace: %s</p>
	      <p id="tenant-audit-namespace">Tenant audit namespace: %s</p>
	      <p id="tenant-release-namespace">Tenant release namespace: %s</p>
	      <p id="tenant-document-namespace">Tenant document namespace: %s</p>
	      <p id="cross-tenant-access-status">Cross-tenant access status: %s</p>
	      <p id="tenant-boundary-reason-codes">Tenant boundary reason codes: %s</p>
	    </section>
	    <section id="document-governance-dashboard">
	      <h2>Governed Document Lifecycle</h2>
	      <p id="document-registry-status">Document registry status: %s</p>
	      <p id="document-count">Document count: %s</p>
	      <p id="document-review-status">Document review status: %s</p>
	      <p id="document-version-status">Document version status: %s</p>
	      <p id="document-classification-status">Document classification status: %s</p>
	      <p id="document-lineage-status">Document lineage status: %s</p>
	      <p id="document-reason-codes">Document reason codes: %s</p>
	    </section>
	    <section id="production-readiness-dashboard">
	      <h2>Governed Production Readiness</h2>
	      <p id="production-readiness-status">Production readiness status: %s</p>
	      <p id="backup-validation-status">Backup validation status: %s</p>
	      <p id="recovery-validation-status">Recovery validation status: %s</p>
	      <p id="production-runbook-status">Runbook status: %s</p>
	      <p id="production-release-readiness-status">Release readiness status: %s</p>
	      <p id="production-reason-codes">Production reason codes: %s</p>
	    </section>
	    <section id="sovereign-deployment-dashboard">
	      <h2>Governed Sovereign Deployment</h2>
	      <p id="sovereign-deployment-status">Sovereign deployment status: %s</p>
	      <p id="node-governance-status">Node governance status: %s</p>
	      <p id="cluster-governance-status">Cluster governance status: %s</p>
	      <p id="airgap-status">Air-gap status: %s</p>
	      <p id="mesh-status">Mesh status: %s</p>
	      <p id="sovereignty-level">Sovereignty level: %s</p>
	      <p id="sovereign-reason-codes">Sovereign reason codes: %s</p>
	    </section>
	    <section id="customer-workspace-dashboard">
	      <h2>Governed Customer Workspace</h2>
	      <p id="customer-workspace-status">Customer workspace status: %s</p>
	      <p id="workspace-count">Workspace count: %s</p>
	      <p id="workspace-tenant-status">Workspace tenant status: %s</p>
	      <p id="workspace-access-status">Workspace access status: %s</p>
	      <p id="workspace-lifecycle-status">Workspace lifecycle status: %s</p>
	      <p id="workspace-reason-codes">Workspace reason codes: %s</p>
	    </section>
	    <section id="document-library-dashboard">
	      <h2>Governed Document Library</h2>
	      <p id="document-library-status">Document library status: %s</p>
	      <p id="document-library-count">Document library count: %s</p>
	      <p id="document-library-workspace-status">Document library workspace status: %s</p>
	      <p id="document-library-index-status">Document library index status: %s</p>
	      <p id="document-library-review-status">Document library review status: %s</p>
	      <p id="document-library-reason-codes">Document library reason codes: %s</p>
	    </section>
	    <section id="customer-onboarding-dashboard">
	      <h2>Governed Customer Onboarding</h2>
	      <p id="customer-onboarding-status">Customer onboarding status: %s</p>
	      <p id="customer-intake-status">Customer intake status: %s</p>
	      <p id="customer-verification-status">Customer verification status: %s</p>
	      <p id="customer-readiness-status">Customer readiness status: %s</p>
	      <p id="pending-customer-count">Pending customer count: %s</p>
	      <p id="customer-onboarding-reason-codes">Customer onboarding reason codes: %s</p>
	    </section>
	    <section id="license-governance-dashboard">
	      <h2>Governed License &amp; Entitlements</h2>
	      <p id="license-status">License status: %s</p>
	      <p id="license-tier">License tier: %s</p>
	      <p id="license-expiry-status">License expiry status: %s</p>
	      <p id="license-entitlement-status">License entitlement status: %s</p>
	      <p id="active-license-count">Active license count: %s</p>
	      <p id="license-reason-codes">License reason codes: %s</p>
	    </section>
	    <section id="hydra-consensus-dashboard">
	      <h2>Governed Hydra Consensus</h2>
	      <p id="hydra-consensus-status">Hydra consensus status: %s</p>
	      <p id="hydra-quorum-status">Quorum status: %s</p>
	      <p id="hydra-node-attestation-status">Node attestation status: %s</p>
	      <p id="hydra-consensus-evidence-status">Consensus evidence status: %s</p>
	      <p id="hydra-consensus-lineage-status">Consensus lineage status: %s</p>
	      <p id="hydra-reason-codes">Hydra reason codes: %s</p>
	    </section>
	    <section id="execution-framework-dashboard">
	      <h2>Governed Execution Framework</h2>
	      <p id="execution-engine-status">Execution engine status: %s</p>
	      <p id="execution-adapter-status">Adapter status: %s</p>
	      <p id="execution-latest-decision">Latest execution decision: %s</p>
	      <p id="execution-blocked-capabilities">Blocked capabilities: %s</p>
	      <p id="execution-preview-capabilities">Preview-only capabilities: %s</p>
	      <p id="execution-human-approval-required">Required human approval: %s</p>
	      <p id="execution-reason-codes">Reason codes: %s</p>
	      <p id="execution-audit-hash">Audit hash: %s</p>
	      <p id="execution-production-release-blocked">Production release blocked: %s</p>
	    </section>
	    <section id="governance-event-timeline">
	      <h2>Governance Event Timeline</h2>
	      <ol>%s</ol>
	    </section>
	    <pre id="governance-demo-state-json">%s</pre>
    """ % (
        html.escape(str(runtime_state.get("status", "BLOCKED"))),
        html.escape(str(state.get("runtime_readiness", "BLOCKED"))),
        html.escape(str(state.get("deployment_readiness", "UNKNOWN"))),
        html.escape(str(state.get("policy_validator_state", "BLOCKED"))),
        html.escape(str(state.get("promote_state", "PROMOTE_BLOCKED"))),
        html.escape(str(state.get("promote_reason", "UNKNOWN"))),
        html.escape(str(state.get("production_readiness_state", "RELEASE_BLOCKED"))),
        html.escape(str(state.get("human_approval_status", "MISSING"))),
        "".join(pb_rows),
        "".join(pbsec_rows),
        _html_list(state.get("fail_closed_blockers", [])),
        html.escape(" -> ".join(str(item) for item in state.get("evidence_lineage", []))),
        html.escape(str(correlation.get("pb020_blocked", True))),
        html.escape(str(correlation.get("pbsec_blocked", True))),
        html.escape(str(correlation.get("deployment_readiness_failure", True))),
        html.escape(str(correlation.get("production_approval_missing", True))),
        html.escape(str(vision.get("latest_observation_status", "BLOCKED"))),
        html.escape(str(vision.get("latest_action_proposal_status", "BLOCKED"))),
        html.escape(", ".join(str(item) for item in vision.get("blocked_action_types", []))),
        html.escape(str(vision.get("human_approval_required", True))),
        html.escape(str(vision.get("audit_hash", ""))),
        html.escape(", ".join(str(item) for item in vision.get("reason_codes", []))),
        html.escape(str(vision.get("raw_screenshot_not_stored", False))),
        html.escape(str(vision.get("execution_adapter_status", "DISABLED"))),
        html.escape(str(bridge.get("latest_observation_id", ""))),
        html.escape(str(bridge.get("latest_proposal_id", ""))),
        html.escape(str(bridge.get("latest_execution_request_id", ""))),
        html.escape(str(bridge.get("latest_human_approval_status", "MISSING"))),
        html.escape(str(bridge.get("latest_execution_decision", "EXECUTION_BLOCKED"))),
        html.escape(str(bridge.get("bridge_status", "EXECUTION_BLOCKED"))),
        html.escape(str(bridge.get("lineage_hash", ""))),
        html.escape(", ".join(str(item) for item in bridge.get("reason_codes", []))),
        html.escape(str(bridge.get("adapter_status", "NOT_IMPLEMENTED"))),
        html.escape(str(bridge.get("execution_engine_status", "DISABLED"))),
        html.escape(str(operator_queue.get("review_id", ""))),
        html.escape(str(operator_queue.get("operator_role", ""))),
        html.escape(str(operator_queue.get("review_state", "BLOCKED"))),
        html.escape(str(operator_queue.get("decision", "BLOCKED"))),
        html.escape(str(operator_queue.get("decision_reason", ""))),
        html.escape(str(operator_queue.get("review_timestamp", ""))),
        html.escape(str(operator_queue_counts.get("pending", 0))),
        html.escape(str(operator_queue_counts.get("approved", 0))),
        html.escape(str(operator_queue_counts.get("rejected", 0))),
        html.escape(str(operator_queue_counts.get("needs_information", 0))),
        html.escape(str(operator_queue.get("audit_hash", ""))),
        html.escape(str(operator_queue.get("lineage_hash", ""))),
        html.escape(", ".join(str(item) for item in operator_queue.get("reason_codes", []))),
        html.escape(str(work.get("work_item_id", ""))),
        html.escape(str(work.get("owner", ""))),
        html.escape(str(work.get("role", ""))),
        html.escape(str(work.get("priority", ""))),
        html.escape(str(work.get("severity", ""))),
        html.escape(str(work.get("status", "BLOCKED"))),
        html.escape(str(work.get("created_at", ""))),
        html.escape(str(work.get("assigned_at", ""))),
        html.escape(str(work.get("resolved_at", ""))),
        html.escape(str(work.get("closed_at", ""))),
        html.escape(str(work_counts.get("new", 0))),
        html.escape(str(work_counts.get("assigned", 0))),
        html.escape(str(work_counts.get("in_progress", 0))),
        html.escape(str(work_counts.get("escalated", 0))),
        html.escape(str(work_counts.get("resolved", 0))),
        html.escape(str(work_counts.get("closed", 0))),
        html.escape(str(work.get("audit_hash", ""))),
        html.escape(str(work.get("lineage_hash", ""))),
        html.escape(", ".join(str(item) for item in work.get("reason_codes", []))),
        html.escape(str(metrics.get("governance_health_score", 0))),
        html.escape(str(metrics.get("total_requests", 0))),
        html.escape(str(metrics.get("blocked_requests", 0))),
        html.escape(str(metrics.get("approved_requests", 0))),
        html.escape(str(metrics.get("rejected_requests", 0))),
        html.escape(json.dumps(metrics_operator_counts, sort_keys=True)),
        html.escape(json.dumps(metrics_work_counts, sort_keys=True)),
        html.escape(str(metrics.get("sla_status", "BLOCKED"))),
        html.escape(json.dumps(metrics_risk_trends, sort_keys=True)),
        html.escape(", ".join(str(item) for item in metrics.get("critical_blockers", []))),
        html.escape(str(metrics.get("last_metrics_generated_at", ""))),
        html.escape(", ".join(str(item) for item in metrics.get("reason_codes", []))),
        html.escape(str(evidence_trust.get("evidence_manifest_id", ""))),
        html.escape(str(evidence_trust.get("artifact_count", 0))),
        html.escape(str(evidence_trust.get("verification_status", "BLOCKED"))),
        html.escape(str(evidence_trust.get("signature_status", "BLOCKED"))),
        html.escape(str(evidence_trust.get("timestamp_status", "BLOCKED"))),
        html.escape(str(evidence_trust.get("tamper_status", "NOT_DETECTED"))),
        html.escape(str(evidence_trust.get("last_verified_at", ""))),
        html.escape(str(evidence_trust.get("policy_version", ""))),
        html.escape(str(evidence_trust.get("timestamp_integration_status", "NOT_IMPLEMENTED"))),
        html.escape(", ".join(str(item) for item in evidence_trust.get("reason_codes", []))),
        html.escape(json.dumps(connector_registry, sort_keys=True)),
        html.escape(str(connector_governance.get("connector_count", 0))),
        html.escape(", ".join(str(item) for item in connector_governance.get("enabled_read_only_connectors", []))),
        html.escape(str(connector_governance.get("blocked_write_actions", True))),
        html.escape(json.dumps(connector_health, sort_keys=True)),
        html.escape(json.dumps(connector_audit_status, sort_keys=True)),
        html.escape(json.dumps(connector_evidence_status, sort_keys=True)),
        html.escape(", ".join(str(item) for item in connector_governance.get("reason_codes", []))),
        html.escape(str(runtime_observation.get("runtime_health", "BLOCKED"))),
        html.escape(json.dumps(observation_component_health, sort_keys=True)),
        html.escape(str(runtime_observation.get("event_timeline_status", "BLOCKED"))),
        html.escape(str(runtime_observation.get("drift_status", "BLOCKED"))),
        html.escape(str(runtime_observation.get("last_observation", ""))),
        html.escape(str(runtime_observation.get("observation_count", 0))),
        html.escape(", ".join(str(item) for item in runtime_observation.get("reason_codes", []))),
        html.escape(str(audit_registry.get("audit_registry_status", "BLOCKED"))),
        html.escape(str(audit_registry.get("audit_registry_record_count", 0))),
        html.escape(str(audit_registry.get("audit_registry_tamper_status", "NOT_EVALUATED"))),
        html.escape(str(audit_registry.get("audit_registry_last_verified", ""))),
        html.escape(", ".join(str(item) for item in audit_registry.get("audit_registry_reason_codes", []))),
        html.escape(str(audit_registry.get("governance_history_status", "BLOCKED"))),
        html.escape(str(policy_registry.get("policy_registry_status", "BLOCKED"))),
        html.escape(str(policy_registry.get("policy_count", 0))),
        html.escape(str(policy_registry.get("active_policy_count", 0))),
        html.escape(str(policy_registry.get("deprecated_policy_count", 0))),
        html.escape(str(policy_registry.get("latest_policy_version", ""))),
        html.escape(str(policy_registry.get("promotion_status", "BLOCKED"))),
        html.escape(", ".join(str(item) for item in policy_registry.get("reason_codes", []))),
        html.escape(str(release_gate.get("release_gate_status", "BLOCKED"))),
        html.escape(str(release_gate.get("release_readiness_status", "BLOCKED"))),
        html.escape(str(release_gate.get("release_decision", "BLOCKED"))),
        html.escape(str(release_gate.get("release_target_environment", ""))),
        html.escape(str(release_gate.get("release_manifest_status", "BLOCKED"))),
        html.escape(str(release_gate.get("rollback_plan_status", "MISSING"))),
        html.escape(", ".join(str(item) for item in release_gate.get("release_reason_codes", []))),
        html.escape(str(tenant_boundary.get("tenant_boundary_status", "BLOCKED"))),
        html.escape(str(tenant_boundary.get("tenant_id", ""))),
        html.escape(str(tenant_boundary.get("tenant_classification", ""))),
        html.escape(str(tenant_boundary.get("tenant_region", ""))),
        html.escape(str(tenant_boundary.get("tenant_policy_namespace", ""))),
        html.escape(str(tenant_boundary.get("tenant_evidence_namespace", ""))),
        html.escape(str(tenant_boundary.get("tenant_audit_namespace", ""))),
        html.escape(str(tenant_boundary.get("tenant_release_namespace", ""))),
        html.escape(str(tenant_boundary.get("tenant_document_namespace", ""))),
        html.escape(str(tenant_boundary.get("cross_tenant_access_status", "BLOCKED"))),
        html.escape(", ".join(str(item) for item in tenant_boundary.get("tenant_boundary_reason_codes", []))),
        html.escape(str(document_governance.get("document_registry_status", "BLOCKED"))),
        html.escape(str(document_governance.get("document_count", 0))),
        html.escape(str(document_governance.get("document_review_status", "BLOCKED"))),
        html.escape(str(document_governance.get("document_version_status", "BLOCKED"))),
        html.escape(str(document_governance.get("document_classification_status", "BLOCKED"))),
        html.escape(str(document_governance.get("document_lineage_status", "BLOCKED"))),
        html.escape(", ".join(str(item) for item in document_governance.get("document_reason_codes", []))),
        html.escape(str(production_readiness.get("production_readiness_status", "BLOCKED"))),
        html.escape(str(production_readiness.get("backup_validation_status", "BLOCKED"))),
        html.escape(str(production_readiness.get("recovery_validation_status", "BLOCKED"))),
        html.escape(str(production_readiness.get("runbook_status", "BLOCKED"))),
        html.escape(str(production_readiness.get("release_readiness_status", "BLOCKED"))),
        html.escape(", ".join(str(item) for item in production_readiness.get("production_reason_codes", []))),
        html.escape(str(sovereign_deployment.get("sovereign_deployment_status", "BLOCKED"))),
        html.escape(str(sovereign_deployment.get("node_governance_status", "BLOCKED"))),
        html.escape(str(sovereign_deployment.get("cluster_governance_status", "BLOCKED"))),
        html.escape(str(sovereign_deployment.get("airgap_status", "BLOCKED"))),
        html.escape(str(sovereign_deployment.get("mesh_status", "BLOCKED"))),
        html.escape(str(sovereign_deployment.get("sovereignty_level", "UNKNOWN"))),
        html.escape(", ".join(str(item) for item in sovereign_deployment.get("reason_codes", []))),
        html.escape(str(customer_workspace.get("customer_workspace_status", "BLOCKED"))),
        html.escape(str(customer_workspace.get("workspace_count", 0))),
        html.escape(str(customer_workspace.get("workspace_tenant_status", "BLOCKED"))),
        html.escape(str(customer_workspace.get("workspace_access_status", "BLOCKED"))),
        html.escape(str(customer_workspace.get("workspace_lifecycle_status", "BLOCKED"))),
        html.escape(", ".join(str(item) for item in customer_workspace.get("workspace_reason_codes", []))),
        html.escape(str(document_library.get("document_library_status", "BLOCKED"))),
        html.escape(str(document_library.get("document_library_count", 0))),
        html.escape(str(document_library.get("document_library_workspace_status", "BLOCKED"))),
        html.escape(str(document_library.get("document_library_index_status", "BLOCKED"))),
        html.escape(str(document_library.get("document_library_review_status", "BLOCKED"))),
        html.escape(", ".join(str(item) for item in document_library.get("document_library_reason_codes", []))),
        html.escape(str(customer_onboarding.get("customer_onboarding_status", "BLOCKED"))),
        html.escape(str(customer_onboarding.get("customer_intake_status", "BLOCKED"))),
        html.escape(str(customer_onboarding.get("customer_verification_status", "BLOCKED"))),
        html.escape(str(customer_onboarding.get("customer_readiness_status", "BLOCKED"))),
        html.escape(str(customer_onboarding.get("pending_customer_count", 0))),
        html.escape(", ".join(str(item) for item in customer_onboarding.get("customer_onboarding_reason_codes", []))),
        html.escape(str(license_governance.get("license_status", "BLOCKED"))),
        html.escape(str(license_governance.get("license_tier", "UNKNOWN"))),
        html.escape(str(license_governance.get("license_expiry_status", "BLOCKED"))),
        html.escape(str(license_governance.get("license_entitlement_status", "BLOCKED"))),
        html.escape(str(license_governance.get("active_license_count", 0))),
        html.escape(", ".join(str(item) for item in license_governance.get("license_reason_codes", []))),
        html.escape(str(hydra_consensus.get("hydra_consensus_status", "BLOCKED"))),
        html.escape(str(hydra_consensus.get("quorum_status", "BLOCKED"))),
        html.escape(str(hydra_consensus.get("node_attestation_status", "BLOCKED"))),
        html.escape(str(hydra_consensus.get("consensus_evidence_status", "BLOCKED"))),
        html.escape(str(hydra_consensus.get("consensus_lineage_status", "BLOCKED"))),
        html.escape(", ".join(str(item) for item in hydra_consensus.get("hydra_reason_codes", []))),
        html.escape(str(execution.get("execution_engine_status", "DISABLED"))),
        html.escape(str(execution.get("adapter_status", "NOT_IMPLEMENTED"))),
        html.escape(str(execution.get("latest_execution_decision", "EXECUTION_BLOCKED"))),
        html.escape(", ".join(str(item) for item in execution.get("blocked_capabilities", []))),
        html.escape(", ".join(str(item) for item in execution.get("preview_only_capabilities", []))),
        html.escape(str(execution.get("required_human_approval", True))),
        html.escape(", ".join(str(item) for item in execution.get("reason_codes", []))),
        html.escape(str(execution.get("audit_hash", ""))),
        html.escape(str(execution.get("production_release_blocked", True))),
        _html_list(timeline_items),
        html.escape(json.dumps(state, sort_keys=True)),
    )


def governance_gateway_html():
    snapshot = runtime_status_snapshot()
    deployment_health = deployment_runtime_health_snapshot(runtime_snapshot=snapshot)
    demo_state = build_governance_demo_state(
        root=REPO_ROOT,
        runtime_snapshot=snapshot,
        deployment_snapshot=deployment_health,
    )
    governance_evidence = governance_evidence_state()
    parity = snapshot.get("runtime_parity", {})
    identity = snapshot.get("device_identity", {})
    challenge = snapshot.get("challenge_response", {})
    renewal = snapshot.get("trust_renewal", {})
    verifier = snapshot.get("verifier_continuity", {})
    state_label = "UNVERIFIED"
    if snapshot["status"] == "FAIL_CLOSED":
        state_label = "BLOCKED"
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
    governance_fetch_status = str(governance_evidence.get("fetch_status", "GOVERNANCE_FETCH_FAILED"))
    governance_signature_label = str(governance_evidence.get("signature_label", "Signature Unverified"))
    governance_state_label = str(governance_evidence.get("governance_state_label", "Governance Unverified"))
    governance_verdict = str(governance_evidence.get("governance_verdict", "UNKNOWN"))
    euria_outputs = governance_evidence.get("euria_governance_outputs")
    if not isinstance(euria_outputs, dict):
        euria_outputs = _euria_governance_outputs()
    euria_missing_evidence = euria_outputs.get("missing_evidence")
    if not isinstance(euria_missing_evidence, list):
        euria_missing_evidence = ["GOVERNANCE_EVIDENCE_UNVERIFIED"]
    euria_unsupported_claims = euria_outputs.get("unsupported_claims")
    if not isinstance(euria_unsupported_claims, list):
        euria_unsupported_claims = ["Euria approval authority is unsupported"]
    euria_privacy_risks = euria_outputs.get("privacy_risks")
    if not isinstance(euria_privacy_risks, list):
        euria_privacy_risks = ["Credentials, private keys, raw approvals, and provider secrets are prohibited"]
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>USBAY Governance Gateway</title>
</head>
<body>
  <main>
    <nav aria-label="Route ownership">
      <span>Governance Control Plane</span>
      <a href="/playground">Playground / Demo Tooling</a>
    </nav>
    <h1>USBAY Governance Gateway</h1>
    <p id="live-pilot-label">USBAY Live Pilot v1</p>
    <p id="route-owner">Route owner: Governance Control Plane</p>
    <p id="runtime-state">Runtime state: %s</p>
	    <section id="governance-evidence-state">
	      <h2>Governance Evidence</h2>
	      <p id="governance-fetch-status">%s</p>
	      <p id="governance-state-label">%s</p>
	      <p id="governance-signature-status">%s</p>
	      <p id="governance-verdict">Governance verdict: %s</p>
	    </section>
	    %s
	    <section id="euria-governance-outputs" data-authority="analysis-only">
      <h2>Euria Governance Outputs</h2>
      <p>Euria remains analysis only. USBAY remains enforcement authority. Human approval remains mandatory.</p>
      <p id="euria-recommendation">Euria Recommendation: %s</p>
      <p id="euria-missing-evidence">Missing Evidence: %s</p>
      <p id="euria-unsupported-claims">Unsupported Claims: %s</p>
      <p id="euria-privacy-risks">Privacy Risks: %s</p>
      <p id="euria-usbay-decision">USBAY Decision: %s</p>
      <p id="euria-human-approval-status">Human Approval Status: %s</p>
      <p id="euria-audit-record-id">Audit Record ID: %s</p>
      <p id="euria-signature-status">Signature Status: %s</p>
      <p id="euria-timestamp-status">Timestamp Status: %s</p>
    </section>
    <section id="euria-live-assessment">
      <h2>Live Euria Governance Assessment</h2>
      <p>Euria remains ANALYSIS_ONLY. USBAY remains ENFORCEMENT_AUTHORITY. Human approval is mandatory.</p>
      <form id="euria-assessment-form">
        <label>Evidence Package
          <textarea name="evidence_package" rows="4" required></textarea>
        </label>
        <label>Requested Action
          <input name="requested_action" type="text" required>
        </label>
        <label>Policy ID
          <input name="policy_id" type="text" value="usbay.euria_live_assessment_policy.v1">
        </label>
        <label>Risk Level
          <select name="risk_level">
            <option value="low">low</option>
            <option value="medium">medium</option>
            <option value="high">high</option>
            <option value="critical">critical</option>
          </select>
        </label>
        <label><input name="evidence_verified" type="checkbox"> Evidence verified</label>
        <label><input name="human_approval_completed" type="checkbox"> Human approval completed</label>
        <label><input name="audit_chain_complete" type="checkbox"> Audit chain complete</label>
        <label><input name="approval_threshold_exceeded" type="checkbox"> Approval threshold exceeded</label>
        <label><input name="escalation_required" type="checkbox"> Escalation required</label>
        <label>Signature Status
          <select name="signature_status">
            <option value="">missing</option>
            <option value="SIGNED">SIGNED</option>
            <option value="VERIFIED">VERIFIED</option>
          </select>
        </label>
        <label>Timestamp Status
          <select name="timestamp_status">
            <option value="">missing</option>
            <option value="TIMESTAMPED">TIMESTAMPED</option>
            <option value="VERIFIED">VERIFIED</option>
          </select>
        </label>
        <button type="submit">Run USBAY Governance Assessment</button>
      </form>
      <div id="euria-assessment-result" data-decision="BLOCKED">
        <p id="euria-live-recommendation">Euria Recommendation: BLOCKED</p>
        <p id="euria-live-missing-evidence">Missing Evidence: NOT_SUBMITTED</p>
        <p id="euria-live-unsupported-claims">Unsupported Claims: NOT_SUBMITTED</p>
        <p id="euria-live-privacy-risks">Privacy Risks: NOT_SUBMITTED</p>
        <p id="euria-live-request-id">Request ID: NOT_GENERATED</p>
        <p id="euria-live-analysis-id">Euria Analysis ID: NOT_GENERATED</p>
        <p id="euria-live-decision-id">Decision ID: NOT_GENERATED</p>
        <p id="euria-live-policy-id">Policy ID: NOT_GENERATED</p>
        <p id="euria-live-usbay-decision">USBAY Decision: BLOCKED</p>
        <p id="euria-live-human-approval-status">Human Approval Status: BLOCKED</p>
        <p id="euria-live-audit-record-id">Audit Record ID: NOT_GENERATED</p>
        <p id="euria-live-signature-status">Signature Status: BLOCKED</p>
        <p id="euria-live-timestamp-status">Timestamp Status: BLOCKED</p>
        <pre id="euria-live-audit-output">Audit Output: NOT_GENERATED</pre>
      </div>
    </section>
    <section id="runtime-attestation-parity">
      <h2>Runtime Attestation Parity</h2>
      <p id="runtime-parity">Runtime parity: %s</p>
      <p id="provenance-trust">Provenance trust: HASH_ONLY_LOCAL</p>
      <p id="enterprise-attestation">Attestation: NOT_ENTERPRISE_SIGNED</p>
      <p id="runtime-parity-warning">%s</p>
    </section>
    <section id="device-identity-lifecycle">
      <h2>Device Identity Lifecycle</h2>
      <p id="device-trust-status">Device trust: %s</p>
      <p id="device-identity-status">Device identity: %s</p>
      <p id="device-identity-state">Lifecycle state: %s</p>
      <p id="device-identity-warning">%s</p>
    </section>
    <section id="remote-challenge-response">
      <h2>Remote Challenge Response</h2>
      <p id="challenge-response-status">Challenge response: %s</p>
      <p id="challenge-response-state">Challenge state: %s</p>
      <p id="challenge-response-warning">%s</p>
    </section>
    <section id="continuous-trust-renewal">
      <h2>Continuous Trust Renewal</h2>
      <p id="trust-renewal-status">Trust renewal: %s</p>
      <p id="trust-renewal-state">Renewal state: %s</p>
      <p id="trust-renewal-warning">%s</p>
    </section>
    <section id="verifier-continuity">
      <h2>Verifier Continuity</h2>
      <p id="verifier-continuity-status">Verifier continuity: %s</p>
      <p id="verifier-continuity-state">Continuity state: %s</p>
      <p id="verifier-quorum-state">Quorum state: %s</p>
      <p id="verifier-failover-state">Failover state: %s</p>
    </section>
    <pre id="backend-truth">%s</pre>
  </main>
  <script>
    const euriaForm = document.getElementById("euria-assessment-form");
    const euriaResult = document.getElementById("euria-assessment-result");
    const setText = (id, label, value) => {
      document.getElementById(id).textContent = label + ": " + value;
    };
    euriaForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      euriaResult.dataset.decision = "BLOCKED";
      setText("euria-live-usbay-decision", "USBAY Decision", "BLOCKED");
      setText("euria-live-human-approval-status", "Human Approval Status", "PENDING_BACKEND_DECISION");
      const formData = new FormData(euriaForm);
      const payload = {
        evidence_package: formData.get("evidence_package") || "",
        requested_action: formData.get("requested_action") || "",
        policy_id: formData.get("policy_id") || "",
        risk_level: formData.get("risk_level") || "low",
        evidence_verified: formData.get("evidence_verified") === "on",
        human_approval_completed: formData.get("human_approval_completed") === "on",
        audit_chain_complete: formData.get("audit_chain_complete") === "on",
        approval_threshold_exceeded: formData.get("approval_threshold_exceeded") === "on",
        escalation_required: formData.get("escalation_required") === "on",
        signature_status: formData.get("signature_status") || "",
        timestamp_status: formData.get("timestamp_status") || ""
      };
      try {
        const response = await fetch("/api/euria/assessment", {
          method: "POST",
          headers: {"content-type": "application/json"},
          body: JSON.stringify(payload)
        });
        const body = await response.json();
        euriaResult.dataset.decision = body.usbay_decision || "BLOCKED";
        setText("euria-live-recommendation", "Euria Recommendation", body.euria_recommendation || "BLOCKED");
        setText("euria-live-missing-evidence", "Missing Evidence", (body.missing_evidence || ["EVIDENCE_MISSING"]).join(", "));
        setText("euria-live-unsupported-claims", "Unsupported Claims", (body.unsupported_claims || ["UNVERIFIED"]).join(", "));
        setText("euria-live-privacy-risks", "Privacy Risks", (body.privacy_risks || ["UNVERIFIED"]).join(", "));
        setText("euria-live-request-id", "Request ID", body.request_id || "NOT_GENERATED");
        setText("euria-live-analysis-id", "Euria Analysis ID", body.euria_analysis_id || "NOT_GENERATED");
        setText("euria-live-decision-id", "Decision ID", body.decision_id || "NOT_GENERATED");
        setText("euria-live-policy-id", "Policy ID", body.policy_id || "NOT_GENERATED");
        setText("euria-live-usbay-decision", "USBAY Decision", body.usbay_decision || "BLOCKED");
        setText("euria-live-human-approval-status", "Human Approval Status", body.human_approval_status || "BLOCKED");
        setText("euria-live-audit-record-id", "Audit Record ID", body.audit_record_id || "NOT_GENERATED");
        setText("euria-live-signature-status", "Signature Status", body.signature_status || "BLOCKED");
        setText("euria-live-timestamp-status", "Timestamp Status", body.timestamp_status || "BLOCKED");
        document.getElementById("euria-live-audit-output").textContent = "Audit Output: " + JSON.stringify(body.audit_output || {}, null, 2);
      } catch (error) {
        euriaResult.dataset.decision = "BLOCKED";
        setText("euria-live-recommendation", "Euria Recommendation", "BLOCKED");
        setText("euria-live-usbay-decision", "USBAY Decision", "BLOCKED");
        setText("euria-live-human-approval-status", "Human Approval Status", "BLOCKED");
        document.getElementById("euria-live-audit-output").textContent = "Audit Output: ASSESSMENT_API_UNAVAILABLE";
      }
    });
  </script>
</body>
</html>
""" % (
        state_label,
        governance_fetch_status,
        governance_state_label,
	        governance_signature_label,
	        governance_verdict,
	        _governance_demo_dashboard_html(demo_state),
	        html.escape(str(euria_outputs.get("euria_recommendation", "BLOCKED"))),
        html.escape(", ".join(str(item) for item in euria_missing_evidence)),
        html.escape(", ".join(str(item) for item in euria_unsupported_claims)),
        html.escape(", ".join(str(item) for item in euria_privacy_risks)),
        html.escape(str(euria_outputs.get("usbay_decision", "BLOCKED"))),
        html.escape(str(euria_outputs.get("human_approval_status", "BLOCKED"))),
        html.escape(str(euria_outputs.get("audit_record_id", ""))),
        html.escape(str(euria_outputs.get("signature_status", "GOVERNANCE_EVIDENCE_SIGNATURE_UNVERIFIED"))),
        html.escape(str(euria_outputs.get("timestamp_status", "BLOCKED"))),
        parity_status,
        "" if parity_status == "VERIFIED" else "Runtime parity mismatch or untrusted attestation requires governance review.",
        device_trust_status,
        identity_status,
        identity_state,
        "" if identity_status == "VERIFIED" else "Device identity is incomplete, expired, revoked, unsigned, or policy-mismatched.",
        challenge_status,
        challenge_state,
        "" if challenge_status == "VERIFIED" else "Live challenge-response is missing, expired, replayed, unsigned, or policy-mismatched.",
        renewal_status,
        renewal_state,
        "" if renewal_status == "VERIFIED" else "Continuous trust renewal is missing, expired, replayed, revoked, unsigned, or stale.",
        verifier_status,
        verifier_state,
        "VERIFIER_QUORUM_REACHED" if verifier_status == "VERIFIED" else "VERIFIER_QUORUM_FAILED",
        "VERIFIER_FAILOVER_ACTIVE" if verifier_state == "VERIFIER_FAILOVER_ACTIVE" else "VERIFIER_FAILOVER_INACTIVE",
        json.dumps(snapshot, sort_keys=True),
    )


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
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>USBAY Playground</title>
</head>
<body>
  <main>
    <nav aria-label="Breadcrumb">
      <a href="/">Governance Control Plane</a>
      <span>%s</span>
    </nav>
    <h1>USBAY Runtime Governance Playground</h1>
    <p id="route-owner">Route owner: Playground / Demo Tooling</p>
    <section id="runtime-attestation-parity">
      <h2>Runtime Attestation Parity</h2>
      <p id="runtime-parity">Runtime parity: %s</p>
      <p id="provenance-trust">Provenance trust: HASH_ONLY_LOCAL</p>
      <p id="enterprise-attestation">Attestation: NOT_ENTERPRISE_SIGNED</p>
      <p id="runtime-parity-warning">%s</p>
    </section>
    <section id="device-identity-lifecycle">
      <h2>Device Identity Lifecycle</h2>
      <p id="device-identity-status">Device identity: %s</p>
      <p id="device-identity-state">Lifecycle state: %s</p>
    </section>
    <section id="remote-challenge-response">
      <h2>Remote Challenge Response</h2>
      <p id="challenge-response-status">Challenge response: %s</p>
      <p id="challenge-response-state">Challenge state: %s</p>
    </section>
    <section id="continuous-trust-renewal">
      <h2>Continuous Trust Renewal</h2>
      <p id="trust-renewal-status">Trust renewal: %s</p>
      <p id="trust-renewal-state">Renewal state: %s</p>
    </section>
    <section id="verifier-continuity">
      <h2>Verifier Continuity</h2>
      <p id="verifier-continuity-status">Verifier continuity: %s</p>
      <p id="verifier-continuity-state">Continuity state: %s</p>
    </section>
    <section id="packet-verification" data-packet-state="FAIL_CLOSED">
      <h2>Evidence Packet Verification</h2>
      <p>Frontend packet state: BLOCKED until backend decision proof is returned.</p>
      <p>No frontend claim is trusted as verified without signed backend evidence.</p>
    </section>
  </main>
</body>
</html>
""" % (
        route_label,
        parity_status,
        "" if parity_status == "VERIFIED" else "Runtime parity mismatch or untrusted attestation requires governance review.",
        identity_status,
        identity_state,
        challenge_status,
        challenge_state,
        renewal_status,
        renewal_state,
        verifier_status,
        verifier_state,
    )


def intake_gateway_html():
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>USBAY Intake Gateway</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #07111f;
      --panel: #0d2239;
      --line: #385d82;
      --text: #f8fbff;
      --muted: #cfe1f5;
      --accent: #7db7ff;
      --ok: #7fb069;
      --blocked: #d88c7a;
    }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Arial, Helvetica, sans-serif;
    }
    main {
      max-width: 960px;
      margin: 0 auto;
      padding: 40px 24px 56px;
    }
    h1 {
      margin: 0 0 8px;
      font-size: 34px;
    }
    h2 {
      color: var(--muted);
      font-size: 18px;
      margin: 28px 0 10px;
    }
    p, label {
      color: var(--muted);
      line-height: 1.5;
    }
    form {
      border: 1px solid var(--line);
      background: var(--panel);
      padding: 22px;
      border-radius: 8px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 16px;
    }
    .field, .checks {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    input, select, textarea, button {
      font: inherit;
    }
    input, select, textarea {
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #081524;
      color: var(--text);
      padding: 10px;
    }
    textarea {
      min-height: 110px;
      resize: vertical;
    }
    .checks label {
      display: flex;
      gap: 10px;
      align-items: flex-start;
    }
    button {
      margin-top: 18px;
      border: 1px solid var(--accent);
      background: #102842;
      color: var(--text);
      padding: 11px 16px;
      border-radius: 6px;
      cursor: pointer;
    }
    .status {
      margin-top: 16px;
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #081524;
      white-space: pre-wrap;
    }
    .blocked {
      color: var(--blocked);
    }
    .accepted {
      color: var(--ok);
    }
    @media (max-width: 720px) {
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main>
    <p>USBAY</p>
    <h1>Governance Assessment Request</h1>
    <p>Submissions are accepted only when required governance fields validate. Missing evidence blocks the request.</p>
    <form id="intake-form">
      <div class="grid">
        <label class="field">Organization
          <input name="organization" autocomplete="organization" required>
        </label>
        <label class="field">Contact name
          <input name="contact_name" autocomplete="name" required>
        </label>
        <label class="field">Contact email
          <input name="contact_email" type="email" autocomplete="email" required>
        </label>
        <label class="field">Role
          <select name="role" required>
            <option value="">Select role</option>
            <option>CISO</option>
            <option>Compliance Officer</option>
            <option>AI Governance Lead</option>
            <option>Enterprise Risk Manager</option>
            <option>Internal Audit</option>
            <option>Legal</option>
            <option>Security Engineering</option>
            <option>Other</option>
          </select>
        </label>
      </div>
      <label class="field">Governance scope
        <textarea name="governance_scope" required></textarea>
      </label>
      <label class="field">Target timeline
        <input name="target_timeline">
      </label>
      <section class="checks" aria-label="Governance requirements">
        <h2>Required Control Context</h2>
        <label><input type="checkbox" name="regulated_industry"> Regulated industry</label>
        <label><input type="checkbox" name="high_risk_ai"> AI-assisted action is high-risk or enterprise-critical</label>
        <label><input type="checkbox" name="policy_validation_required" required> Policy validation required before execution</label>
        <label><input type="checkbox" name="human_oversight_required" required> Human oversight required</label>
        <label><input type="checkbox" name="audit_evidence_required" required> Audit evidence required</label>
        <label><input type="checkbox" name="provenance_required" required> Provenance required</label>
        <label><input type="checkbox" name="fail_closed_required" required> Fail-closed enforcement required</label>
      </section>
      <button type="submit">Submit governance assessment request</button>
      <div id="intake-status" class="status" role="status">No submission has been sent.</div>
    </form>
  </main>
  <script>
    const form = document.getElementById("intake-form");
    const statusBox = document.getElementById("intake-status");
    const boolFields = [
      "regulated_industry",
      "high_risk_ai",
      "policy_validation_required",
      "human_oversight_required",
      "audit_evidence_required",
      "provenance_required",
      "fail_closed_required"
    ];
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      statusBox.className = "status";
      statusBox.textContent = "Submitting for backend validation.";
      const data = new FormData(form);
      const payload = {};
      for (const [key, value] of data.entries()) {
        payload[key] = value;
      }
      for (const field of boolFields) {
        payload[field] = data.has(field);
      }
      try {
        const response = await fetch("/intake/api", {
          method: "POST",
          headers: {"content-type": "application/json"},
          body: JSON.stringify(payload)
        });
        const body = await response.json();
        if (!response.ok) {
          statusBox.className = "status blocked";
          statusBox.textContent = "BLOCKED\\n" + JSON.stringify(body, null, 2);
          return;
        }
        statusBox.className = "status accepted";
        statusBox.textContent = "ACCEPTED FOR GOVERNANCE REVIEW\\n" + JSON.stringify(body, null, 2);
        form.reset();
      } catch (error) {
        statusBox.className = "status blocked";
        statusBox.textContent = "BLOCKED\\nINTAKE_API_UNAVAILABLE";
      }
    });
  </script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def root_gateway():
    return governance_gateway_html()


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return governance_gateway_html()


@app.get("/playground", response_class=HTMLResponse)
def playground():
    return playground_html()


@app.get("/playground/demo", response_class=HTMLResponse)
def playground_demo():
    return playground_html("Playground / Demo Tooling / Demo")


@app.get("/playground/tools", response_class=HTMLResponse)
def playground_tools():
    return playground_html("Playground / Demo Tooling / Tools")


@app.get("/intake", response_class=HTMLResponse)
def intake_gateway():
    return intake_gateway_html()


async def _intake_request_payload(request: Request):
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        return await request.json()
    form = await request.form()
    payload = dict(form)
    for field in (
        "regulated_industry",
        "high_risk_ai",
        "policy_validation_required",
        "human_oversight_required",
        "audit_evidence_required",
        "provenance_required",
        "fail_closed_required",
    ):
        payload[field] = field in form
    return payload


@app.post("/intake/api")
async def intake_api(request: Request):
    try:
        client_hash = client_identity_hash(request.headers.get("x-forwarded-for") or request.client.host if request.client else "")
        rate_limit = enforce_rate_limit(client_hash)
        payload = await _intake_request_payload(request)
        result = create_intake_submission(payload)
        result.update(rate_limit)
    except IntakeGatewayError as exc:
        return JSONResponse(
            status_code=422,
            content={
                "decision": "BLOCKED",
                "reason": str(exc),
                "notification_recipient": INTAKE_NOTIFICATION_RECIPIENT,
            },
        )
    except Exception:
        return JSONResponse(
            status_code=503,
            content={
                "decision": "BLOCKED",
                "reason": "INTAKE_GATEWAY_UNAVAILABLE",
                "notification_recipient": INTAKE_NOTIFICATION_RECIPIENT,
            },
        )
    return result


@app.get("/intake/api")
def intake_api_contract():
    return {
        "schema": "usbay.intake_api_contract.v1",
        "method": "POST",
        "path": "/intake/api",
        "notification_recipient": INTAKE_NOTIFICATION_RECIPIENT,
        "required_fields": [
            "organization",
            "contact_name",
            "contact_email",
            "role",
            "governance_scope",
            "policy_validation_required",
            "human_oversight_required",
            "audit_evidence_required",
            "provenance_required",
            "fail_closed_required",
        ],
        "fail_closed": True,
    }


@app.get("/intake/audit")
def intake_audit(request: Request):
    identity = resolve_admin_identity(request.headers.get("x-usbay-admin-token", ""), required_scope="intake:audit")
    if identity is None:
        return JSONResponse(
            status_code=403,
            content={"decision": "BLOCKED", "reason": "INTAKE_ADMIN_AUTH_REQUIRED"},
        )
    try:
        audit_admin_access("/intake/audit", identity)
    except IntakeGatewayError as exc:
        return JSONResponse(status_code=503, content={"decision": "BLOCKED", "reason": str(exc)})
    export = intake_audit_export()
    if export.get("chain_valid") is not True:
        return JSONResponse(status_code=503, content=export)
    return export


@app.get("/intake/admin")
def intake_admin(request: Request):
    identity = resolve_admin_identity(request.headers.get("x-usbay-admin-token", ""), required_scope="intake:read")
    if identity is None:
        return JSONResponse(
            status_code=403,
            content={"decision": "BLOCKED", "reason": "INTAKE_ADMIN_AUTH_REQUIRED"},
        )
    try:
        audit_admin_access("/intake/admin", identity)
    except IntakeGatewayError as exc:
        return JSONResponse(status_code=503, content={"decision": "BLOCKED", "reason": str(exc)})
    export = intake_admin_export()
    if export.get("audit_chain_valid") is not True:
        return JSONResponse(status_code=503, content=export)
    return export


@app.get("/intake/retention")
def intake_retention_policy(request: Request):
    identity = resolve_admin_identity(request.headers.get("x-usbay-admin-token", ""), required_scope="intake:policy")
    if identity is None:
        return JSONResponse(
            status_code=403,
            content={"decision": "BLOCKED", "reason": "INTAKE_ADMIN_AUTH_REQUIRED"},
        )
    try:
        audit_admin_access("/intake/retention", identity)
    except IntakeGatewayError as exc:
        return JSONResponse(status_code=503, content={"decision": "BLOCKED", "reason": str(exc)})
    return retention_policy_export()


@app.get("/intake/email-policy")
def intake_email_policy(request: Request):
    identity = resolve_admin_identity(request.headers.get("x-usbay-admin-token", ""), required_scope="intake:policy")
    if identity is None:
        return JSONResponse(
            status_code=403,
            content={"decision": "BLOCKED", "reason": "INTAKE_ADMIN_AUTH_REQUIRED"},
        )
    try:
        audit_admin_access("/intake/email-policy", identity)
    except IntakeGatewayError as exc:
        return JSONResponse(status_code=503, content={"decision": "BLOCKED", "reason": str(exc)})
    return email_delivery_policy()


@app.get("/intake/readiness")
def intake_readiness(request: Request):
    identity = resolve_admin_identity(request.headers.get("x-usbay-admin-token", ""), required_scope="intake:policy")
    if identity is None:
        return JSONResponse(
            status_code=403,
            content={"decision": "BLOCKED", "reason": "INTAKE_ADMIN_AUTH_REQUIRED"},
        )
    try:
        audit_admin_access("/intake/readiness", identity)
        report = production_readiness_report()
    except IntakeGatewayError as exc:
        return JSONResponse(status_code=503, content={"decision": "BLOCKED", "reason": str(exc)})
    status_code = 200 if report.get("status") == "READY_FOR_CONTROLLED_PHASE2_REVIEW" else 503
    return JSONResponse(status_code=status_code, content=report)


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
def health():
    mode, reason, registry = policy_runtime_state(provenance_context=runtime_provenance_context())
    redis_ok, dependency_mode, dependency_reason = redis_dependency_state()
    nonce_ok = nonce_store_available()
    replay_ok = replay_protection_active()
    compute_state = compute_policy_state()
    runtime_governance = runtime_governance_state_snapshot(root=REPO_ROOT)
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
    device_trust_status = (
        "VERIFIED"
        if device_identity.get("device_lifecycle_status") == "VERIFIED"
        and challenge_response.get("challenge_liveness_status") == "VERIFIED"
        and trust_renewal.get("trust_renewal_status") == "VERIFIED"
        and verifier_continuity.get("verifier_continuity_status") == "VERIFIED"
        else "DEGRADED"
    )
    runtime_snapshot = {
        "status": "OK" if (
            registry is not None
            and mode == "NORMAL"
            and dependency_mode == "NORMAL"
            and runtime_governance.get("status") == "READY"
        ) else "FAIL_CLOSED",
        "mode": mode if registry is not None else "FAIL_CLOSED",
        "reason": runtime_governance.get("reason")
        if runtime_governance.get("status") != "READY"
        else reason if registry is None or mode != "NORMAL" else dependency_reason,
        "policy_signature_valid": bool(registry and registry.get("policy_signature_valid") is True),
        "policy_version": registry.get("version") if registry else None,
        "policy_hash": registry.get("policy_hash") if registry else None,
        "redis_available": redis_ok,
        "replay_protection_active": replay_ok,
        "compute_policy_state": compute_state["state"],
        "runtime_governance": runtime_governance,
        "promote_state": runtime_governance.get("promote_state", "PROMOTE_BLOCKED"),
        "websocket_clients": websocket_server.client_count(),
        "runtime_parity": runtime_parity,
        "device_identity": device_identity,
        "challenge_response": challenge_response,
        "trust_renewal": trust_renewal,
        "verifier_continuity": verifier_continuity,
        "device_trust_status": device_trust_status,
    }
    deployment_health = deployment_runtime_health_snapshot(runtime_snapshot=runtime_snapshot)
    runtime_attestation = signed_runtime_attestation_snapshot(
        runtime_snapshot=runtime_snapshot,
        deployment_health=deployment_health,
    )
    if registry is None:
        return JSONResponse(
            status_code=503,
            content={
                "status": "FAIL_CLOSED",
                "mode": "FAIL_CLOSED",
                "reason": reason,
                "redis_available": redis_ok,
                "nonce_store_available": nonce_ok,
                "replay_protection_active": replay_ok,
                "policy_signature_valid": False,
                "registry_version": None,
                "compute_policy_state": compute_state["state"],
                "runtime_governance": runtime_governance,
                "promote_state": runtime_governance.get("promote_state", "PROMOTE_BLOCKED"),
                "runtime_parity": runtime_parity,
                "device_identity": device_identity,
                "challenge_response": challenge_response,
                "trust_renewal": trust_renewal,
                "verifier_continuity": verifier_continuity,
                "device_trust_status": "DEGRADED",
                "deployment_runtime": deployment_health,
                "runtime_attestation": runtime_attestation,
            },
        )
    if runtime_governance.get("status") != "READY":
        return {
            "status": "FAIL_CLOSED",
            "mode": "FAIL_CLOSED",
            "reason": runtime_governance.get("reason", "runtime_governance_blocked"),
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
            "runtime_governance": runtime_governance,
            "promote_state": runtime_governance.get("promote_state", "PROMOTE_BLOCKED"),
            "runtime_parity": runtime_parity,
            "device_identity": device_identity,
            "challenge_response": challenge_response,
            "trust_renewal": trust_renewal,
            "verifier_continuity": verifier_continuity,
            "device_trust_status": device_trust_status,
            "deployment_runtime": deployment_health,
            "runtime_attestation": runtime_attestation,
        }
    if dependency_mode != "NORMAL":
        return {
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
            "runtime_governance": runtime_governance,
            "promote_state": runtime_governance.get("promote_state", "PROMOTE_BLOCKED"),
            "runtime_parity": runtime_parity,
            "device_identity": device_identity,
            "challenge_response": challenge_response,
            "trust_renewal": trust_renewal,
            "verifier_continuity": verifier_continuity,
            "device_trust_status": device_trust_status,
            "deployment_runtime": deployment_health,
            "runtime_attestation": runtime_attestation,
        }
    if mode != "NORMAL":
        return {
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
            "runtime_governance": runtime_governance,
            "promote_state": runtime_governance.get("promote_state", "PROMOTE_BLOCKED"),
            "runtime_parity": runtime_parity,
            "device_identity": device_identity,
            "challenge_response": challenge_response,
            "trust_renewal": trust_renewal,
            "verifier_continuity": verifier_continuity,
            "device_trust_status": device_trust_status,
            "deployment_runtime": deployment_health,
            "runtime_attestation": runtime_attestation,
        }
    return {
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
        "runtime_governance": runtime_governance,
        "promote_state": runtime_governance.get("promote_state", "PROMOTE_BLOCKED"),
        "runtime_parity": runtime_parity,
        "device_identity": device_identity,
        "challenge_response": challenge_response,
        "trust_renewal": trust_renewal,
        "verifier_continuity": verifier_continuity,
        "device_trust_status": device_trust_status,
        "deployment_runtime": deployment_health,
        "runtime_attestation": runtime_attestation,
    }


@app.get("/api/health")
def api_health():
    return health()


@app.get("/api/status")
def api_status():
    return health()


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


@app.get("/api/governance/demo-state")
def api_governance_demo_state():
    snapshot = runtime_status_snapshot()
    deployment_health = deployment_runtime_health_snapshot(runtime_snapshot=snapshot)
    return build_governance_demo_state(
        root=REPO_ROOT,
        runtime_snapshot=snapshot,
        deployment_snapshot=deployment_health,
    )


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


@app.get("/api/governance/evidence")
def api_governance_evidence():
    evidence = governance_evidence_state()
    if evidence.get("fetch_status") != "GOVERNANCE_FETCH_OK" or evidence.get("signature_status") != "VERIFIED":
        return JSONResponse(status_code=503, content=evidence)
    return evidence


@app.post("/api/euria/assessment")
async def api_euria_assessment(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    assessment = _evaluate_euria_assessment(payload)
    status_code = 200 if assessment.get("usbay_decision") == "ALLOW" else 202
    if assessment.get("usbay_decision") == "FAIL_CLOSED":
        status_code = 503
    if assessment.get("usbay_decision") == "BLOCKED":
        status_code = 403
    return JSONResponse(status_code=status_code, content=assessment)


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


@app.get("/{frontend_path:path}", response_class=HTMLResponse)
def spa_fallback(frontend_path: str):
    if frontend_path == "api" or frontend_path.startswith("api/"):
        return JSONResponse(
            status_code=404,
            content={
                "error": "api_route_not_found",
                "path": f"/{frontend_path}",
            },
        )
    return governance_gateway_html()
