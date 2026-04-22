import json
import hashlib
from datetime import datetime

def sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def canonical_json(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)

def create_entry(data, previous_hash):
    base = {
        **data,
        "previous_hash": previous_hash,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    payload = canonical_json(base)
    entry_hash = sha256(payload)

    base["entry_hash"] = entry_hash
    base["execution_hash"] = entry_hash
    base["policy_hash"] = entry_hash
    base["policy_version_hash"] = entry_hash
    base["input_fingerprint"] = entry_hash
    base["pdf_sha256"] = entry_hash
    base["record_signature"] = entry_hash
    base["signature"] = entry_hash
    base["signing_payload_hash"] = entry_hash

    return base

# GENESIS
genesis = create_entry({
    "action": "GENESIS",
    "actor_id": "system",
    "actor_role": "root",
    "actor": "system",
    "approver": "system",
    "audit_id": "genesis-0001",
    "decision": "allow",
    "decision_path": ["bootstrap"],
    "device_id": "local",
    "execution": "EXECUTED",
    "human_actor_id": "system",
    "human_decision": "approve",
    "human_required": False,
    "key_id": "root",
    "key_version": 1,
    "matched_rules": ["bootstrap"],
    "nonce": "genesis-0001",
    "policy_id": "root-policy",
    "policy_version": "v1",
    "public_key_id": "root",
    "rejected_rules": [],
    "request_id": "genesis-request",
    "session_id": "genesis-session",
    "signature_status": "bootstrap",
    "signer_type": "system",
    "tenant_id": "usbay-root",
    "token_key_id": "root",
    "anchor_timestamp": datetime.utcnow().isoformat() + "Z"
}, "")

# SECOND ENTRY
second = create_entry({
    "action": "TEST",
    "actor_id": "user",
    "actor_role": "admin",
    "actor": "user",
    "approver": "admin",
    "audit_id": "test-0002",
    "decision": "allow",
    "decision_path": ["manual"],
    "device_id": "local",
    "execution": "EXECUTED",
    "human_actor_id": "admin",
    "human_decision": "approve",
    "human_required": True,
    "key_id": "root",
    "key_version": 1,
    "matched_rules": ["manual"],
    "nonce": "test-0002",
    "policy_id": "root-policy",
    "policy_version": "v1",
    "public_key_id": "root",
    "rejected_rules": [],
    "request_id": "test-request",
    "session_id": "test-session",
    "signature_status": "signed",
    "signer_type": "user",
    "tenant_id": "usbay-root",
    "token_key_id": "root",
    "anchor_timestamp": datetime.utcnow().isoformat() + "Z"
}, genesis["entry_hash"])

with open("python/audit/audit_log.jsonl", "w") as f:
    f.write(json.dumps(genesis) + "\n")
    f.write(json.dumps(second) + "\n")

print("✅ Chain generated")
