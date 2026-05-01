#!/usr/bin/env bash
set -u

status=0

pass() {
  echo "PASS $1"
}

fail() {
  echo "FAIL $1"
  status=1
}

for port in 8001 8002 8003; do
  if curl -fsS "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
    pass "node_${port}=healthy"
  else
    fail "node_${port}=unhealthy"
  fi
done

if PYTHONPATH="$(pwd)" python3 - <<'PY'
from security.hydra_consensus import decide_consensus
from security.hydra_live_client import (
    HydraLiveNodeClient,
    collect_live_votes,
    validate_vote_response,
)
from security.hydra_node_service import build_vote_response

request_hash = "live-test-request-hash"
policy_version = "live-policy-v1"
clients = [
    HydraLiveNodeClient("node1", "http://127.0.0.1:8001/vote"),
    HydraLiveNodeClient("node2", "http://127.0.0.1:8002/vote"),
    HydraLiveNodeClient("node3", "http://127.0.0.1:8003/vote"),
]

votes = collect_live_votes(
    request_hash,
    policy_version,
    context={"node_decisions": {"node1": "ALLOW", "node2": "ALLOW", "node3": "DENY"}},
    clients=clients,
)
assert decide_consensus(votes) == "ALLOW", votes

votes = collect_live_votes(
    request_hash,
    policy_version,
    context={"node_decisions": {"node1": "ALLOW", "node2": "ALLOW", "node3": "DENY"}},
    clients=clients[:2],
)
assert decide_consensus(votes) == "ALLOW", votes

votes = collect_live_votes(
    request_hash,
    policy_version,
    context={"node_decisions": {"node1": "ALLOW", "node2": "ALLOW", "node3": "DENY"}},
    clients=clients[:1],
)
assert decide_consensus(votes) == "DENY", votes

bad_signature = build_vote_response(
    node_id="node1",
    decision="ALLOW",
    request_hash=request_hash,
    policy_version=policy_version,
)
bad_signature["signature"] = "bad"
vote = validate_vote_response(
    bad_signature,
    expected_node_id="node1",
    request_hash=request_hash,
    policy_version=policy_version,
)
assert vote["valid"] is False, vote
assert decide_consensus([vote]) == "DENY"

wrong_hash = build_vote_response(
    node_id="node1",
    decision="ALLOW",
    request_hash="other-hash",
    policy_version=policy_version,
)
vote = validate_vote_response(
    wrong_hash,
    expected_node_id="node1",
    request_hash=request_hash,
    policy_version=policy_version,
)
assert vote["valid"] is False, vote
assert decide_consensus([vote]) == "DENY"

wrong_policy = build_vote_response(
    node_id="node1",
    decision="ALLOW",
    request_hash=request_hash,
    policy_version="other-policy",
)
vote = validate_vote_response(
    wrong_policy,
    expected_node_id="node1",
    request_hash=request_hash,
    policy_version=policy_version,
)
assert vote["valid"] is False, vote
assert decide_consensus([vote]) == "DENY"
PY
then
  pass "hydra_live_consensus=verified"
else
  fail "hydra_live_consensus=failed"
fi

exit "$status"
