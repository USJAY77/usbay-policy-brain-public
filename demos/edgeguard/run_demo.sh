#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
export PYTHONPATH="${PYTHONPATH:-$(pwd)}"

python3 - <<'PY'
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import gateway.app as gateway_app
from audit.hash_chain import AuditHashChain
from security.decision_store import InMemoryDecisionStore
from security.hydra_consensus import HydraNodeDecision
from security.hydra_nodes import sign_hydra_node_decision
from security.nonce_store import NonceStore
from security.request_signing import (
    sign_request_payload,
)


class AllowClient:
    def __init__(self, node_id: str) -> None:
        self.node_id = node_id

    def evaluate(self, request_hash: str, policy_version: str) -> HydraNodeDecision:
        return sign_hydra_node_decision(
            HydraNodeDecision(
                node_id=self.node_id,
                request_hash=request_hash,
                policy_version=policy_version,
                decision="allow",
                reason="edgeguard_demo_allow",
                timestamp=time.time(),
            )
        )


repo = Path.cwd()
demo_dir = repo / "demos" / "edgeguard"
out_dir = demo_dir / "out"
out_dir.mkdir(parents=True, exist_ok=True)
local_key_dir = out_dir / "local_keys"
local_key_dir.mkdir(parents=True, exist_ok=True)
request_private_key = Ed25519PrivateKey.generate()
request_private_key_pem = request_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
request_public_key_pem = request_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
request_public_key_path = local_key_dir / "request_public.key"
request_config_path = local_key_dir / "request_signing_keys.json"
request_public_key_path.write_bytes(request_public_key_pem)
request_config_path.write_text(
    json.dumps(
        {
            "active_keys": ["edgeguard_demo_request_key"],
            "revoked_keys": [],
            "key_map": {"edgeguard_demo_request_key": request_public_key_path.name},
            "default_pubkey_id": "edgeguard_demo_request_key",
        },
        sort_keys=True,
    ),
    encoding="utf-8",
)

gateway_app.decision_store = InMemoryDecisionStore()
gateway_app.nonce_store = gateway_app._NonceStoreCompat()
gateway_app.audit_chain = AuditHashChain(out_dir / "audit_chain.json")
gateway_app.hydra_node_clients = [AllowClient("node-1"), AllowClient("node-2"), AllowClient("node-3")]
gateway_app.REQUEST_SIGNING_KEY_CONFIG_PATH = request_config_path
gateway_app.clear_policy_registry_cache()


def load_and_sign(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["nonce"] = uuid.uuid4().hex
    payload["timestamp"] = int(time.time())
    return sign_request_payload(payload, request_private_key_pem, "edgeguard_demo_request_key")


client = TestClient(gateway_app.app, raise_server_exceptions=False)
cloud_payload = load_and_sign(demo_dir / "payload_cloud_denied.json")
npu_payload = load_and_sign(demo_dir / "payload_npu_allowed.json")

cloud_response = client.post("/decide", json=cloud_payload)
npu_response = client.post("/decide", json=npu_payload)

cloud_body = cloud_response.json()
npu_body = npu_response.json()
print("DENY_JSON=" + json.dumps(cloud_body, sort_keys=True))
print("ALLOW_JSON=" + json.dumps(npu_body, sort_keys=True))

if cloud_body.get("decision") != "DENY":
    raise SystemExit("cloud_high_sensitivity_expected_deny")
if npu_body.get("decision") != "ALLOW" or not npu_body.get("decision_id"):
    raise SystemExit("npu_local_high_sensitivity_expected_allow")

export_response = client.get(f"/audit/export/{npu_body['decision_id']}")
export_body = export_response.json()
export_path = out_dir / "edgeguard_npu_allowed_export.json"
export_path.write_text(json.dumps(export_body, sort_keys=True), encoding="utf-8")
acceptance_export_path = out_dir / "npu_allowed_audit.json"
acceptance_export_path.write_text(json.dumps(export_body, sort_keys=True), encoding="utf-8")

record = export_body.get("decision_record", {})
required = [
    "compute_target",
    "execution_location",
    "data_sensitivity",
    "compute_policy_hash",
    "policy_hash",
    "request_hash",
    "signature_valid",
]
missing = [field for field in required if record.get(field) in (None, "")]
if missing:
    raise SystemExit("missing_audit_fields:" + ",".join(missing))

verify = subprocess.run(
    [sys.executable, "scripts/verify_decision.py", str(export_path), "governance/policy_public.key"],
    cwd=repo,
    text=True,
    capture_output=True,
    check=False,
)
hydra = subprocess.run(
    [sys.executable, "scripts/hydra_verify_audit.py", str(export_path), "governance/policy_public.key"],
    cwd=repo,
    text=True,
    capture_output=True,
    check=False,
)
print("VERIFY_DECISION=" + verify.stdout.strip())
print("HYDRA_VERIFY_AUDIT=" + hydra.stdout.strip())
print("AUDIT_EXPORT=" + str(export_path))

if verify.returncode != 0 or verify.stdout.strip() != "VALID":
    raise SystemExit("verify_decision_failed")
if hydra.returncode != 0 or hydra.stdout.strip() != "VALID":
    raise SystemExit("hydra_verify_audit_failed")
PY
