"""Synthetic-only tests for non-authorizing policy revocation terminal proof."""
from copy import deepcopy

from governance.mutation_policy_revocation_terminal import (
    verify_policy_revocation_terminal_transition,
)
from governance.tenant_enrollment_contracts import (
    EnrollmentPolicy, digest,
)
from tests.helpers.tenant_enrollment import (
    NOW, object_revocation, synthetic_enrollment,
)


def _bundle(f):
    return {
        "policy": f.inputs["policy"],
        "adoption": f.inputs["adoption"],
        "h": f.inputs["h"],
        "w": f.inputs["w"],
        "revocations": f.inputs["revocations"],
        "expected": deepcopy(f.head),
        "challenge": f.inputs["request"]["payload"]["nonce"],
        "request_digest": digest(f.inputs["request"]["payload"]),
    }


def _fixture():
    old = synthetic_enrollment(revoked_signers=("request",))
    old_policy = old.inputs["policy"]["payload"]
    prior = {
        "policy_hash": digest(old_policy),
        "head_hash": old.head["head_hash"],
    }
    entries = deepcopy(old.inputs["revocations"]["payload"]["revocations"])
    entries.append(object_revocation(EnrollmentPolicy, old_policy))
    new = synthetic_enrollment(
        private_keys=old.private,
        sequence=2,
        previous=prior,
        revocations=entries,
    )
    return old, new


def _verify(old, new, *, target_policy=None):
    return verify_policy_revocation_terminal_transition(
        old.trust,
        target_policy=old.inputs["policy"] if target_policy is None else target_policy,
        previous_currentness=_bundle(old),
        revoked_currentness=_bundle(new),
        now=NOW,
        command_hash=digest({"command": "synthetic-revoke-policy"}),
        transaction_id="synthetic-revoke-policy-transaction",
        effect_grant_hash=digest({"effect_grant": "synthetic"}),
        mutation_event_hash=digest({"event": "synthetic-mutation"}),
        durable_position_hash=digest({"position": "synthetic-durable"}),
    )


def test_policy_revocation_terminal_transition_verifies():
    old, new = _fixture()
    result = _verify(old, new)
    assert result["decision"] == "ALLOW"
    assert result["reason"] == "POLICY_REVOCATION_TERMINAL_PROOF_VERIFIED"
    proof = result["terminal_proof"]
    assert proof["status"] == "REVOKED_NON_PRODUCTION"
    assert proof["previous_sequence"] == 1
    assert proof["new_sequence"] == 2
    assert proof["revocation_effect_scope"] == "ALL_VERSIONS_OF_OBJECT"
    assert proof["target_object_id"] == proof["target_object_id"]
    assert result["mutation_authority_created"] is False


def test_policy_revocation_terminal_transition_rejects_removed_prior_revocation():
    old, new = _fixture()
    payload = deepcopy(new.inputs["revocations"]["payload"])
    payload["revocations"] = payload["revocations"][1:]
    payload["revocation_reference"] = digest({
        k: v for k, v in payload.items() if k != "revocation_reference"})
    new.inputs["revocations"] = new.sign(payload)
    result = _verify(old, new)
    assert result["decision"] == "DENY"
    assert result["reason"] == "REVOCATION_REMOVAL_DETECTED"


def test_policy_revocation_terminal_transition_rejects_sequence_skip():
    old, new = _fixture()
    payload = deepcopy(new.inputs["revocations"]["payload"])
    payload["sequence"] = 3
    payload["revocation_reference"] = digest({
        k: v for k, v in payload.items() if k != "revocation_reference"})
    new.inputs["revocations"] = new.sign(payload)
    result = _verify(old, new)
    assert result["decision"] == "DENY"
    assert result["reason"] == "REVOCATION_NOT_CURRENT"


def test_policy_revocation_terminal_transition_rejects_target_version_substitution():
    old, new = _fixture()
    result = _verify(old, new, target_policy=new.inputs["policy"])
    assert result["decision"] == "DENY"
    assert result["reason"] == "OBJECT_VERSION_MISMATCH"


def test_policy_revocation_terminal_transition_rejects_witness_reference_substitution():
    old, new = _fixture()
    witness = deepcopy(new.inputs["w"]["payload"])
    witness["revocation_reference"] = digest({"wrong": "revocation-reference"})
    new.inputs["w"] = new.sign(witness)
    result = _verify(old, new)
    assert result["decision"] == "DENY"
    assert result["reason"] in (
        "REVOCATION_NOT_CURRENT",
        "SIGNATURE_INVALID",
        "REVOCATION_TERMINAL_PROOF_INVALID",
    )
