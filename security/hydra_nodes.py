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
    EXPECTED_NODE_ROLES,
    HydraNodeDecision,
    replay_registry_hash,
    sign_node_decision,
    verify_node_decision_signature,
)
from security.node_identity import DEFAULT_NODE_ATTESTATION_POLICY_PATH, load_node_attestation_policy
from security.runtime_attestation import (
    challenge_nonce,
    create_attestation_document,
    validate_attestation_document,
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
    def evaluate(self, request_hash: str, policy_version: str, context: dict | None = None) -> HydraNodeDecision:
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
            node_role=EXPECTED_NODE_ROLES.get(node_id, ""),
        )
    )


def _state_fields(node_id: str, request_hash: str, context: dict | None) -> dict:
    safe_context = context if isinstance(context, dict) else {}
    policy_hash = str(safe_context.get("policy_hash", ""))
    nonce_hash = str(safe_context.get("nonce_hash", ""))
    attestation_timestamp = float(safe_context.get("attestation_timestamp", time.time()))
    attestation_policy = load_node_attestation_policy(DEFAULT_NODE_ATTESTATION_POLICY_PATH)
    enrolled = attestation_policy["enrolled_nodes"].get(node_id)
    if enrolled is None:
        raise ValueError("node_attestation_identity_unknown")
    attestation_challenge = challenge_nonce(
        request_hash=request_hash,
        logical_node_id=node_id,
        timestamp=attestation_timestamp,
    )
    attestation_document = create_attestation_document(
        logical_node_id=node_id,
        node_role=EXPECTED_NODE_ROLES.get(node_id, ""),
        challenge=attestation_challenge,
        provider_mode=attestation_policy["required_attestation_mode"],
        hardware_backed=bool(attestation_policy["require_hardware_backing"]),
        public_identity=enrolled["public_identity"],
        timestamp=attestation_timestamp,
    )
    attestation_evidence = validate_attestation_document(
        attestation_document,
        expected_challenge=attestation_challenge,
        now=attestation_timestamp,
        mark_nonce_used=False,
    )
    return {
        "node_role": EXPECTED_NODE_ROLES.get(node_id, ""),
        "policy_hash": policy_hash,
        "nonce_hash": nonce_hash,
        "replay_registry_hash": str(
            safe_context.get("replay_registry_hash")
            or replay_registry_hash(policy_hash, nonce_hash)
        ),
        "nonce_state": str(safe_context.get("nonce_state", "unused")),
        "attestation_timestamp": attestation_evidence["attestation_timestamp"],
        "attestation_hash": attestation_evidence["attestation_hash"],
        "attestation_node_id": attestation_evidence["node_id"],
        "attestation_provider_mode": attestation_evidence["provider_mode"],
        "hardware_backed": attestation_evidence["hardware_backed"],
    }


class InProcessHydraNode(HydraNodeClient):
    def __init__(self, node_id: str = "node-1") -> None:
        self.node_id = node_id

    def evaluate(self, request_hash: str, policy_version: str, context: dict | None = None) -> HydraNodeDecision:
        state = _state_fields(self.node_id, request_hash, context)
        return sign_hydra_node_decision(
            HydraNodeDecision(
                node_id=self.node_id,
                request_hash=request_hash,
                policy_version=policy_version,
                decision=ALLOW,
                reason="in_process_policy_allow",
                timestamp=time.time(),
                **state,
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

    def evaluate(self, request_hash: str, policy_version: str, context: dict | None = None) -> HydraNodeDecision:
        payload = {
            "node_id": self.node_id,
            "request_hash": request_hash,
            "policy_version": policy_version,
            "context": context or {},
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

    def evaluate(self, request_hash: str, policy_version: str, context: dict | None = None) -> HydraNodeDecision:
        body = json.dumps(
            {
                "node_id": self.node_id,
                "request_hash": request_hash,
                "policy_version": policy_version,
                "context": context or {},
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
    context: dict | None = None,
) -> list[HydraNodeDecision]:
    decisions: list[HydraNodeDecision] = []
    seen_node_ids: set[str] = set()

    for client in clients[: len(EXPECTED_NODE_IDS)]:
        node_id = getattr(client, "node_id", f"node-{len(decisions) + 1}")
        seen_node_ids.add(node_id)
        try:
            try:
                decision = client.evaluate(request_hash, policy_version, context=context)
            except TypeError:
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
        context=payload.get("context") if isinstance(payload.get("context"), dict) else {},
    )
    print(json.dumps(decision.to_dict(), sort_keys=True, separators=(",", ":")))


def main() -> None:
    if "--worker" in sys.argv:
        _worker()


if __name__ == "__main__":
    main()
