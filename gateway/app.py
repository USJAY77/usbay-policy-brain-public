from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse
import os
import hashlib
import json
import shlex
import time
import uuid
from pathlib import Path

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
from security.hydra_consensus import HydraConsensusResult, decide_consensus, evaluate_consensus
from security.hydra_live_client import (
    collect_live_votes,
    default_live_node_clients,
)
from security.hydra_nodes import (
    collect_node_decisions,
    default_node_clients,
)
from security.policy_registry import (
    current_policy_key_config_fingerprint,
    PolicyRegistryError,
    load_signed_policy_registry,
)
from security.request_signing import validate_request_signature, verify_request_signature
from audit.hash_chain import append_event, verify_chain
from audit.hash_chain import load_chain
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
REPO_ROOT = Path(__file__).resolve().parents[1]
APPROVED_PUBLIC_PEM_PATHS = {
    "approvals/approver1_public_key.pem",
    "approvals/approver2_public_key.pem",
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
    yield


app = FastAPI(lifespan=lifespan)
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


def policy_signature_mode(registry=None):
    registry = registry or load_policy_registry()
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


def load_policy_registry():
    global _policy_registry_cache, _policy_registry_cache_key
    release_manifest_path = policy_release_manifest_path()
    authority_path = policy_authority_path()
    cache_key = (
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


def forbidden_runtime_files_in_repo(repo_root=None):
    root = Path(repo_root or REPO_ROOT)
    excluded_dirs = {".git", ".venv", "venv", "__pycache__", ".pytest_cache"}
    findings = []
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
            findings.append(rel)
            continue
        if rel.startswith("secrets/"):
            findings.append(rel)
            continue
        if rel.startswith("tmp/") and "private" in name:
            findings.append(rel)
            continue
        if path.suffix.lower() == ".pem":
            if not _is_approved_public_pem_path(rel):
                findings.append(rel)
                continue
            if not _is_public_key_artifact(path):
                findings.append(rel)
                continue
        if path.suffix.lower() == ".key" and not _is_public_key_artifact(path):
            findings.append(rel)
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
            findings.append(rel)
    return sorted(findings)


def validate_no_forbidden_runtime_files(repo_root=None):
    findings = forbidden_runtime_files_in_repo(repo_root)
    if findings:
        raise PolicyRegistryError("forbidden_runtime_file_present")
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


def policy_runtime_state():
    global runtime_mode, runtime_reason
    try:
        registry = load_policy_registry()
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
    load_policy_registry()


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


def validate_simulation(payload):
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
        registry = load_policy_registry()
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


def build_hydra_decisions(request_hash_value, policy_version, real_decision=None, ts=None):
    return collect_node_decisions(
        request_hash=request_hash_value,
        policy_version=policy_version,
        clients=hydra_node_clients,
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

    return evaluate_consensus(build_hydra_decisions(request_hash_value, policy_version))


def audit_hydra_consensus(result):
    audit_chain.append(
        "hydra_consensus",
        {
            "final_decision": result.final_decision,
            "votes_allow": result.votes_allow,
            "votes_deny": result.votes_deny,
            "consensus": result.consensus_reached,
        },
    )


def audit_execution_decision(command, decision, hydra_result=None):
    event = {
        "decision": decision,
        "timestamp": int(time.time()),
    }
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
        "actor_hash": event.get("actor_hash"),
        "created_at": event.get("created_at"),
        "expires_at": event.get("expires_at"),
        "used": event.get("used"),
        "simulation_id": event.get("simulation_id"),
        "audit_hash": event.get("audit_hash"),
        "risk_level": event.get("risk_level"),
        "policy_hash": event.get("policy_hash"),
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
        "timestamp": event.get("timestamp"),
    }
    audit_chain.append(action, safe_event)


def _safe_policy_pubkey_id():
    try:
        registry = load_policy_registry()
        return registry.get("policy_pubkey_id")
    except Exception:
        return None


def _deny_decision_response(reason, status_code=403, payload=None, decision_id=None):
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
        "policy_pubkey_id": _safe_policy_pubkey_id(),
    }
    try:
        audit_governance_event("execution_denied", event)
    except Exception:
        pass
    return JSONResponse(status_code=status_code, content={"error": reason})


def _signature_valid(payload):
    return verify_request_signature(payload, REQUEST_SIGNING_KEY_CONFIG_PATH)


def _signature_validation(payload):
    return validate_request_signature(payload, REQUEST_SIGNING_KEY_CONFIG_PATH)


def _basic_request_valid(payload):
    if not isinstance(payload, dict):
        return False
    if not payload.get("tenant_id") or not payload.get("device"):
        return False
    if not payload.get("nonce"):
        return False
    if not payload.get("actor_id"):
        return False
    if payload.get("timestamp") is None:
        return False
    try:
        ts = int(payload.get("timestamp"))
    except Exception:
        return False
    if abs(int(time.time()) - ts) > 300:
        return False
    return True


def create_governance_decision(payload):
    _redis_available, _dependency_mode, dependency_reason = redis_dependency_state()
    if dependency_reason != "ok":
        return None, dependency_reason, None
    if require_redis() and not replay_protection_active():
        return None, "redis_unavailable", None
    if not isinstance(payload, dict) or not payload.get("actor_id"):
        return None, "missing_actor", None
    if not _basic_request_valid(payload):
        return None, "malformed_request", None
    metadata_decision, metadata_reason = validate_metadata(payload)
    if metadata_decision != "ALLOW":
        return None, metadata_reason, None
    try:
        policy_registry = load_policy_registry()
        policy_signature_mode(policy_registry)
    except PolicyRegistryError as exc:
        return None, str(exc), None
    except Exception:
        return None, "policy_registry_unavailable", None
    policy_version = _request_policy_version(payload)
    if policy_version is None:
        return None, "missing_policy", None
    signature_valid, signature_reason = _signature_validation(payload)
    if not signature_valid:
        return None, signature_reason, None
    simulation_decision, simulation_reason = validate_simulation(payload)
    if simulation_decision != "ALLOW":
        return None, simulation_reason, None
    compute_decision, compute_reason, compute_evidence = validate_compute_request(payload)
    if compute_decision != "ALLOW":
        return None, compute_reason, None
    nonce_value = str(payload.get("nonce", ""))
    nonce_hash_value = nonce_hash(nonce_value)
    actor_hash_value = actor_hash(payload.get("actor_id", ""))
    if not decision_store.reserve_nonce(nonce_hash_value, decision_ttl_seconds()):
        return None, "replay_detected", None

    body = request_signature_message(payload)
    request_hash_value = request_hash(body)
    hydra_result = evaluate_hydra_request(
        request_hash_value,
        policy_version,
        action=str(payload.get("action", "")),
        context={
            "type": payload.get("type", ""),
            "action": payload.get("action", ""),
        },
    )
    audit_hydra_consensus(hydra_result)

    policy_allowed = True
    policy_reason = "approved"
    if payload.get("type") == "execution" and not execution_command_allowed(payload.get("command", "")):
        policy_allowed = False
        policy_reason = "policy_denied"

    decision = "ALLOW" if hydra_result.final_decision == "allow" and policy_allowed else "DENY"
    reason = policy_reason if hydra_result.final_decision == "allow" else "hydra_denied"
    now = int(time.time())
    decision_id = str(uuid.uuid4())
    record = {
        "decision_id": decision_id,
        "request_hash": request_hash_value,
        "decision": decision,
        "policy_version": policy_version,
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
        "policy_sequence": policy_registry["policy_sequence"],
        "policy_valid_from": policy_registry["valid_from"],
        "policy_valid_until": policy_registry["valid_until"],
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
    mode, reason, _registry = policy_runtime_state()
    if mode != "NORMAL":
        return False, _deny_decision_response(
            f"degraded:{reason}",
            payload=payload,
            decision_id=str(payload.get("decision_id", "")),
        )

    decision_id = payload.get("decision_id")
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

    try:
        registry = load_policy_registry()
        signature_mode = policy_signature_mode(registry)
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
                audit_execution_decision(payload.get("command", ""), "deny")
                return POLICY_DENIED
            audit_execution_decision(payload.get("command", ""), "allow")

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
                    "policy_pubkey_id": _safe_policy_pubkey_id(),
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
        audit_chain.append(action, "ALLOW")
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
        registry = load_policy_registry()
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
    mode, reason, registry = policy_runtime_state()
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
    mode, reason, registry = policy_runtime_state()
    redis_ok, dependency_mode, dependency_reason = redis_dependency_state()
    nonce_ok = nonce_store_available()
    replay_ok = replay_protection_active()
    compute_state = compute_policy_state()
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
            },
        )
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
    }


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
