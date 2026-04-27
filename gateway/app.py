from fastapi import FastAPI
from fastapi.responses import JSONResponse
import hashlib
import hmac
import json
import shlex
import time

from utils.keystore import KeyStore
from security.hydra_consensus import evaluate_consensus
from security.hydra_nodes import (
    collect_node_decisions,
    default_node_clients,
)

# -----------------------------
# NONCE STORAGE ADAPTER
# -----------------------------
# Redis is preferred for distributed replay protection.
# Local fallback exists only for development/test compatibility.
# No database is initialized in this module.
try:
    from security.redis_store import nonce_exists, store_nonce
    REDIS_ENABLED = True
except Exception:
    from security.store import nonce_exists, store_nonce
    REDIS_ENABLED = False
from audit.hash_chain import append_event, verify_chain
from audit.hash_chain import load_chain
from audit.exporter import DEFAULT_EXPORT_FILE, export_audit_event

HYDRA_DENIED = "HYDRA_DENIED"
POLICY_DENIED = "POLICY_DENIED"
DEFAULT_POLICY_VERSION = "local-policy-v1"
ALLOWED_EXECUTION_PREFIXES = (
    ("python3", "-m", "py_compile"),
    ("python3", "-m", "pytest"),
)


app = FastAPI()
keystore = KeyStore()
hydra_node_clients = default_node_clients()


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


# -------------------------
# CORE LOGIC
# -------------------------

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def request_signature_message(payload):
    unsigned = payload.copy()
    unsigned.pop("signature", None)
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


def _policy_version(payload):
    policy_version = payload.get("policy_version") or DEFAULT_POLICY_VERSION
    return str(policy_version)


def execution_command_allowed(command):
    try:
        parts = shlex.split(str(command))
    except ValueError:
        return False

    return any(
        tuple(parts[:len(prefix)]) == prefix
        for prefix in ALLOWED_EXECUTION_PREFIXES
    )


def build_hydra_decisions(request_hash_value, policy_version, real_decision=None, ts=None):
    return collect_node_decisions(
        request_hash=request_hash_value,
        policy_version=policy_version,
        clients=hydra_node_clients,
    )


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
        "command_hash": command_hash(command),
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

        # signature berekenen
        body = request_signature_message(payload)

        secret_data = keystore.load_device_key(
            payload["tenant_id"],
            payload["device"]
        )

        secret = secret_data.get("key", secret_data.get("private_key"))
        if secret is None:
            return False
        key = secret.encode() if isinstance(secret, str) else secret

        expected = hmac.new(
            key,
            body.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected):
            return False

        hydra_decisions = build_hydra_decisions(
            request_hash(body),
            _policy_version(payload),
        )
        hydra_result = evaluate_consensus(hydra_decisions)
        audit_hydra_consensus(hydra_result)

        if hydra_result.final_decision != "allow":
            if payload.get("type") == "execution":
                audit_execution_decision(payload.get("command", ""), "deny", hydra_result)
            return HYDRA_DENIED

        if payload.get("type") == "execution":
            if not execution_command_allowed(payload.get("command", "")):
                audit_execution_decision(payload.get("command", ""), "deny", hydra_result)
                return POLICY_DENIED
            audit_execution_decision(payload.get("command", ""), "allow", hydra_result)

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

@app.post("/execute")
def execute(payload: dict):
    action = payload.get("action", "unknown")
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
        audit_chain.append(action, "ALLOW")
    except Exception:
        pass

    return {"status": "EXECUTED"}


@app.get("/audit/export/{audit_id}")
def export_audit(audit_id: str):
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
