from __future__ import annotations

import json
import os
from typing import Any
from urllib import error, request

from security.hydra_consensus import decide_consensus
from security.hydra_node_service import NODE_IDS, VALID_DECISIONS, node_secret, verify_vote_signature


DEFAULT_NODE_URLS = {
    "node1": "http://127.0.0.1:8001/vote",
    "node2": "http://127.0.0.1:8002/vote",
    "node3": "http://127.0.0.1:8003/vote",
}
NODE_URL_ENVS = {
    "node1": "USBAY_HYDRA_NODE_1_URL",
    "node2": "USBAY_HYDRA_NODE_2_URL",
    "node3": "USBAY_HYDRA_NODE_3_URL",
}
DEFAULT_TIMEOUT_SECONDS = 1.0


class HydraLiveNodeClient:
    def __init__(
        self,
        node_id: str,
        url: str | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.node_id = node_id
        self.url = url or os.getenv(NODE_URL_ENVS[node_id], DEFAULT_NODE_URLS[node_id])
        self.timeout_seconds = timeout_seconds

    def vote(
        self,
        request_hash: str,
        policy_version: str,
        action: str = "",
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body = json.dumps(
            {
                "request_hash": request_hash,
                "policy_version": policy_version,
                "action": action,
                "context": context or {},
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        hydra_request = request.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with request.urlopen(hydra_request, timeout=self.timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return validate_vote_response(
            payload,
            expected_node_id=self.node_id,
            request_hash=request_hash,
            policy_version=policy_version,
        )


def invalid_vote(node_id: str) -> dict[str, Any]:
    return {"node": node_id, "decision": "DENY", "valid": False}


def validate_vote_response(
    payload: Any,
    *,
    expected_node_id: str,
    request_hash: str,
    policy_version: str,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return invalid_vote(expected_node_id)

    node_id = payload.get("node_id")
    decision = payload.get("decision")
    valid = payload.get("valid")

    if node_id != expected_node_id:
        return invalid_vote(expected_node_id)
    if decision not in VALID_DECISIONS:
        return invalid_vote(expected_node_id)
    if valid is not True:
        return invalid_vote(expected_node_id)
    if payload.get("request_hash") != request_hash:
        return invalid_vote(expected_node_id)
    if payload.get("policy_version") != policy_version:
        return invalid_vote(expected_node_id)
    if not verify_vote_signature(payload, node_secret(expected_node_id)):
        return invalid_vote(expected_node_id)

    return {"node": expected_node_id, "decision": decision, "valid": True}


def default_live_node_clients() -> list[HydraLiveNodeClient]:
    timeout_ms = os.getenv("USBAY_HYDRA_NODE_TIMEOUT_MS")
    timeout = (
        float(timeout_ms) / 1000.0
        if timeout_ms is not None
        else float(os.getenv("USBAY_HYDRA_NODE_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS))
    )
    urls = [
        item.strip()
        for item in os.getenv("HYDRA_NODE_URLS", "").split(",")
        if item.strip()
    ]
    if urls:
        return [
            HydraLiveNodeClient(node_id, url=urls[index], timeout_seconds=timeout)
            for index, node_id in enumerate(NODE_IDS)
            if index < len(urls)
        ]
    return [
        HydraLiveNodeClient(node_id, timeout_seconds=timeout)
        for node_id in NODE_IDS
    ]


def collect_live_votes(
    request_hash: str,
    policy_version: str,
    action: str = "",
    context: dict[str, Any] | None = None,
    clients: list[HydraLiveNodeClient] | None = None,
) -> list[dict[str, Any]]:
    live_clients = clients or default_live_node_clients()
    votes: list[dict[str, Any]] = []
    seen_nodes: set[str] = set()

    for client in live_clients[: len(NODE_IDS)]:
        node_id = getattr(client, "node_id", f"node{len(votes) + 1}")
        seen_nodes.add(node_id)
        try:
            votes.append(client.vote(request_hash, policy_version, action, context or {}))
        except (
            OSError,
            TimeoutError,
            error.URLError,
            ValueError,
            json.JSONDecodeError,
        ):
            votes.append(invalid_vote(node_id))
        except Exception:
            votes.append(invalid_vote(node_id))

    for node_id in NODE_IDS:
        if node_id not in seen_nodes:
            votes.append(invalid_vote(node_id))

    return votes[: len(NODE_IDS)]


def decide_live_consensus(
    request_hash: str,
    policy_version: str,
    action: str = "",
    context: dict[str, Any] | None = None,
    clients: list[HydraLiveNodeClient] | None = None,
) -> str:
    votes = collect_live_votes(request_hash, policy_version, action, context, clients)
    return decide_consensus(votes)
