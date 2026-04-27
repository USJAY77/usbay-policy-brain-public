from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from urllib import error, request

from security.hydra_consensus import (
    ALLOW,
    DENY,
    DEFAULT_TIMEOUT_SECONDS,
    HydraNodeDecision,
    sign_node_decision,
    verify_node_decision_signature,
)


DEFAULT_REMOTE_URL = "http://localhost:8001/hydra/evaluate"
NODE_KEY_ENVS = {
    "node-1": "USBAY_HYDRA_NODE_1_KEY",
    "node-2": "USBAY_HYDRA_NODE_2_KEY",
    "node-3": "USBAY_HYDRA_NODE_3_KEY",
}
DEFAULT_NODE_KEYS = {
    "node-1": "usbay-local-hydra-node-1-dev-key",
    "node-2": "usbay-local-hydra-node-2-dev-key",
    "node-3": "usbay-local-hydra-node-3-dev-key",
}
EXPECTED_NODE_IDS = ("node-1", "node-2", "node-3")


class HydraNodeClient:
    def evaluate(self, request_hash: str, policy_version: str) -> HydraNodeDecision:
        raise NotImplementedError


def hydra_node_key(node_id: str) -> str:
    env_name = NODE_KEY_ENVS.get(node_id)
    if env_name:
        return os.getenv(env_name, DEFAULT_NODE_KEYS[node_id])
    return os.getenv("USBAY_HYDRA_UNKNOWN_NODE_KEY", f"usbay-{node_id}-dev-key")


def sign_hydra_node_decision(decision: HydraNodeDecision) -> HydraNodeDecision:
    return sign_node_decision(decision, hydra_node_key(decision.node_id))


def verify_hydra_node_decision(decision: HydraNodeDecision) -> bool:
    return verify_node_decision_signature(decision, hydra_node_key(decision.node_id))


def deny_decision(
    node_id: str,
    request_hash: str,
    policy_version: str,
    reason: str,
) -> HydraNodeDecision:
    return sign_hydra_node_decision(
        HydraNodeDecision(
            node_id=node_id,
            request_hash=request_hash,
            policy_version=policy_version,
            decision=DENY,
            reason=reason,
            timestamp=time.time(),
        )
    )


class InProcessHydraNode(HydraNodeClient):
    def __init__(self, node_id: str = "node-1") -> None:
        self.node_id = node_id

    def evaluate(self, request_hash: str, policy_version: str) -> HydraNodeDecision:
        return sign_hydra_node_decision(
            HydraNodeDecision(
                node_id=self.node_id,
                request_hash=request_hash,
                policy_version=policy_version,
                decision=ALLOW,
                reason="in_process_policy_allow",
                timestamp=time.time(),
            )
        )


class SubprocessHydraNode(HydraNodeClient):
    def __init__(
        self,
        node_id: str = "node-2",
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.node_id = node_id
        self.timeout_seconds = timeout_seconds

    def evaluate(self, request_hash: str, policy_version: str) -> HydraNodeDecision:
        payload = {
            "node_id": self.node_id,
            "request_hash": request_hash,
            "policy_version": policy_version,
        }
        completed = subprocess.run(
            [sys.executable, "-m", "security.hydra_nodes", "--worker"],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            timeout=self.timeout_seconds,
            check=True,
        )
        return HydraNodeDecision.from_dict(json.loads(completed.stdout))


class RemoteHydraNode(HydraNodeClient):
    def __init__(
        self,
        url: str | None = None,
        node_id: str = "node-3",
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.url = url or os.getenv("USBAY_HYDRA_REMOTE_URL", DEFAULT_REMOTE_URL)
        self.node_id = node_id
        self.timeout_seconds = timeout_seconds

    def evaluate(self, request_hash: str, policy_version: str) -> HydraNodeDecision:
        body = json.dumps(
            {
                "node_id": self.node_id,
                "request_hash": request_hash,
                "policy_version": policy_version,
            }
        ).encode("utf-8")
        hydra_request = request.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with request.urlopen(hydra_request, timeout=self.timeout_seconds) as response:
            return HydraNodeDecision.from_dict(json.loads(response.read().decode("utf-8")))


def default_node_clients() -> list[HydraNodeClient]:
    timeout = float(os.getenv("USBAY_HYDRA_NODE_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS))
    return [
        InProcessHydraNode("node-1"),
        SubprocessHydraNode("node-2", timeout_seconds=timeout),
        RemoteHydraNode(node_id="node-3", timeout_seconds=timeout),
    ]


def collect_node_decisions(
    request_hash: str,
    policy_version: str,
    clients: list[HydraNodeClient],
) -> list[HydraNodeDecision]:
    decisions: list[HydraNodeDecision] = []
    seen_node_ids: set[str] = set()

    for client in clients[: len(EXPECTED_NODE_IDS)]:
        node_id = getattr(client, "node_id", f"node-{len(decisions) + 1}")
        seen_node_ids.add(node_id)
        try:
            decision = client.evaluate(request_hash, policy_version)
        except (
            OSError,
            subprocess.SubprocessError,
            TimeoutError,
            error.URLError,
            ValueError,
            json.JSONDecodeError,
        ):
            decisions.append(deny_decision(node_id, request_hash, policy_version, "node_unavailable"))
            continue
        except Exception:
            decisions.append(deny_decision(node_id, request_hash, policy_version, "node_failure"))
            continue

        if not verify_hydra_node_decision(decision):
            decisions.append(deny_decision(node_id, request_hash, policy_version, "invalid_node_signature"))
            continue

        decisions.append(decision)

    for node_id in EXPECTED_NODE_IDS:
        if node_id not in seen_node_ids:
            decisions.append(deny_decision(node_id, request_hash, policy_version, "missing_node"))

    return decisions[: len(EXPECTED_NODE_IDS)]


def _worker() -> None:
    payload = json.loads(sys.stdin.read())
    node = InProcessHydraNode(node_id=str(payload.get("node_id", "node-2")))
    decision = node.evaluate(
        request_hash=str(payload.get("request_hash", "")),
        policy_version=str(payload.get("policy_version", "")),
    )
    print(json.dumps(decision.to_dict(), sort_keys=True, separators=(",", ":")))


def main() -> None:
    if "--worker" in sys.argv:
        _worker()


if __name__ == "__main__":
    main()
