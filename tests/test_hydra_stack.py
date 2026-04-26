from __future__ import annotations

from integrations.openclaw_gateway import OpenClawGateway
from memory.governed_memory import GovernedMemory
from security.node_consensus import (
    ALLOW,
    BLOCK,
    ConsensusVote,
    HydraConsensus,
    HydraNode,
    LocalReviewLayer,
)


def _policy_result(**overrides):
    payload = {
        "decision": ALLOW,
        "risk": "LOW",
        "signature": "signed-policy-result",
    }
    payload.update(overrides)
    return payload


def test_hydra_allows_low_risk_signed_policy() -> None:
    result = HydraConsensus().evaluate(_policy_result())

    assert result["decision"] == ALLOW
    assert result["allow_votes"] == 3


def test_hydra_denies_missing_signature() -> None:
    result = HydraConsensus().evaluate(_policy_result(signature=""))

    assert result["decision"] == BLOCK
    assert result["allow_votes"] == 0


def test_hydra_node_failure_does_not_bypass_consensus() -> None:
    def failed_node(policy_result):
        raise RuntimeError("node unavailable")

    nodes = [
        HydraNode("node-1", failed_node),
        HydraNode("node-2", lambda policy: ConsensusVote("node-2", ALLOW, "ok")),
        HydraNode("node-3", lambda policy: ConsensusVote("node-3", ALLOW, "ok")),
    ]

    result = HydraConsensus(nodes=nodes).evaluate(_policy_result())

    assert result["decision"] == ALLOW
    assert result["allow_votes"] == 2
    assert result["votes"][0]["decision"] == BLOCK


def test_openclaw_blocks_missing_token() -> None:
    gateway = OpenClawGateway()

    result = gateway.authorize(
        request={},
        hydra_consensus={"decision": ALLOW},
        local_review={"clearance": True},
    )

    assert result["status"] == "BLOCKED"
    assert result["reason"] == "missing_governance_token"


def test_openclaw_blocks_denied_consensus() -> None:
    gateway = OpenClawGateway()

    result = gateway.authorize(
        request={"governance_token": "present"},
        hydra_consensus={"decision": BLOCK},
        local_review={"clearance": True},
    )

    assert result["status"] == "BLOCKED"
    assert result["reason"] == "hydra_consensus_denied"


def test_local_review_blocks_critical_risk() -> None:
    review = LocalReviewLayer().analyze(_policy_result(risk="CRITICAL"))

    assert review["clearance"] is False
    assert review["decision"] == BLOCK


def test_full_stack_allows_when_all_layers_clear() -> None:
    policy = _policy_result()
    hydra = HydraConsensus().evaluate(policy)
    review = LocalReviewLayer().analyze(policy)

    result = OpenClawGateway().authorize(
        request={"governance_token": "present"},
        hydra_consensus=hydra,
        local_review=review,
    )

    assert result["status"] == "READY"
    assert result["execution_allowed"] is True


def test_governed_memory_risk_escalation_and_secret_redaction(tmp_path) -> None:
    memory = GovernedMemory(device_id="hydra-test", memory_dir=str(tmp_path / "store"))

    for idx in range(3):
        memory.remember_decision(
            action="deploy",
            decision="DENY",
            risk="LOW",
            audit_id=f"audit-{idx}",
            ai_explanation="blocked token=secret-value",
        )

    assert memory.risk_from_history("deploy") == "MEDIUM"
    records = memory.recall_history(action="deploy")
    assert records[-1]["ai_explanation"] == "[REDACTED]"
    assert "secret-value" not in memory.memory_file.read_text(encoding="utf-8")
