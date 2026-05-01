from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

from fastapi import FastAPI


NODE_IDS = ("node1", "node2", "node3")
NODE_KEY_ENVS = {
    "node1": "USBAY_HYDRA_NODE_1_KEY",
    "node2": "USBAY_HYDRA_NODE_2_KEY",
    "node3": "USBAY_HYDRA_NODE_3_KEY",
}
DEFAULT_NODE_KEYS = {
    "node1": "usbay-live-hydra-node-1-dev-key",
    "node2": "usbay-live-hydra-node-2-dev-key",
    "node3": "usbay-live-hydra-node-3-dev-key",
}
VALID_DECISIONS = {"ALLOW", "DENY"}

app = FastAPI()


def current_node_id() -> str:
    node_id = os.getenv("USBAY_HYDRA_NODE_ID", "node1")
    return node_id if node_id in NODE_IDS else "node1"


def node_secret(node_id: str) -> str:
    env_name = NODE_KEY_ENVS.get(node_id)
    if env_name:
        return os.getenv(env_name, DEFAULT_NODE_KEYS[node_id])
    return os.getenv("USBAY_HYDRA_UNKNOWN_NODE_KEY", f"usbay-live-{node_id}-dev-key")


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def signature_payload(vote: dict[str, Any]) -> str:
    return canonical_json(
        {
            "decision": vote.get("decision", ""),
            "node_id": vote.get("node_id", ""),
            "policy_version": vote.get("policy_version", ""),
            "request_hash": vote.get("request_hash", ""),
            "valid": vote.get("valid") is True,
        }
    )


def sign_vote(vote: dict[str, Any], secret: str | None = None) -> str:
    node_id = str(vote.get("node_id", ""))
    signing_secret = secret or node_secret(node_id)
    return hmac.new(
        signing_secret.encode("utf-8"),
        signature_payload(vote).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_vote_signature(vote: dict[str, Any], secret: str | None = None) -> bool:
    signature = vote.get("signature")
    if not isinstance(signature, str) or not signature:
        return False
    expected = sign_vote(vote, secret)
    return hmac.compare_digest(signature, expected)


def build_vote_response(
    *,
    node_id: str,
    decision: str,
    request_hash: str,
    policy_version: str,
    valid: bool = True,
) -> dict[str, Any]:
    vote = {
        "node_id": node_id,
        "decision": decision if decision in VALID_DECISIONS else "DENY",
        "request_hash": request_hash,
        "policy_version": policy_version,
        "valid": valid,
    }
    vote["signature"] = sign_vote(vote)
    return vote


def _context_decision(node_id: str, context: dict[str, Any]) -> str | None:
    node_decisions = context.get("node_decisions")
    if isinstance(node_decisions, dict):
        decision = node_decisions.get(node_id)
        if decision in VALID_DECISIONS:
            return decision

    forced_decision = context.get("force_decision")
    if forced_decision in VALID_DECISIONS:
        return forced_decision

    return None


def evaluate_node_vote(payload: dict[str, Any], node_id: str | None = None) -> dict[str, Any]:
    active_node_id = node_id or current_node_id()
    request_hash = str(payload.get("request_hash", ""))
    policy_version = str(payload.get("policy_version", ""))
    action = str(payload.get("action", ""))
    context = payload.get("context") if isinstance(payload.get("context"), dict) else {}

    decision = _context_decision(active_node_id, context) or "ALLOW"
    if action.upper() == "DENY":
        decision = "DENY"

    if not request_hash or not policy_version:
        decision = "DENY"

    return build_vote_response(
        node_id=active_node_id,
        decision=decision,
        request_hash=request_hash,
        policy_version=policy_version,
        valid=True,
    )


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "node_id": current_node_id()}


@app.post("/vote")
def vote(payload: dict[str, Any]) -> dict[str, Any]:
    return evaluate_node_vote(payload)
