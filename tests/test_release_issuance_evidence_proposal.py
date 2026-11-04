"""Synthetic public bindings only; role labels are not human approvals."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from governance.release_issuance_evidence_proposal import (
    CONTEXT, KEY_SCOPE, SCHEMA, EvidenceInspection, EvidenceKey,
    inspect_release_issuance_evidence,
)
from governance.tenant_enrollment_contracts import canonical, digest

NOW = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)
H = "sha256:" + "a" * 64


@pytest.fixture
def evidence():
    p = dict(schema_version=SCHEMA, action="ISSUE_RELEASE_MANIFEST",
             resource_type="GOVERNANCE_RELEASE", tenant_id="synthetic-tenant",
             actor_id="synthetic-requester", purpose="release_provenance",
             environment="non-production", tool_id="synthetic-release-writer",
             resource_id=H, issuer_id="synthetic-issuer", issuer_key_id="issuer-key",
             source_commit="b" * 40, source_tree="c" * 40, policy_bundle_hash=H,
             release_core_hash=H, predecessor_hash=H, parent_authority_hash=H,
             issuer_grant_hash=H, review_policy_hash=H, currentness_reference=H,
             nonce="d" * 64, issued_at="2026-11-04T11:59:50Z",
             valid_from="2026-11-04T11:59:00Z", valid_until="2026-11-04T12:01:00Z",
             redelegation_allowed=False)
    subjects = [p["issuer_id"], "USBAY-AUDIT", "USBAY-GLOBAL23"]
    roles = ["release_issuer", "review:USBAY-AUDIT", "review:USBAY-GLOBAL23"]
    ids = ["issuer-key", "review-a-key", "review-b-key"]
    private = tuple(Ed25519PrivateKey.generate() for _ in range(3))
    keys = tuple(EvidenceKey(i, s, r, tuple(p[n] for n in KEY_SCOPE),
                 key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                 "2026-11-04T11:00:00Z", "2026-11-04T13:00:00Z")
                 for i, s, r, key in zip(ids, subjects, roles, private))

    def seal(payload=None, reviewers=None):
        payload = deepcopy(p if payload is None else payload)
        envelope = dict(payload=payload, signature=private[0].sign(canonical(payload)).hex())
        reviews = []
        for index in (1, 2):
            review = dict(reviewer_id=subjects[index], key_id=ids[index],
                          decision="APPROVE", request_hash=digest(envelope))
            if reviewers is not None:
                reviewers(index, review)
            review["signature"] = private[index].sign(canonical(review)).hex()
            reviews.append(review)
        return dict(request=envelope, reviews=reviews)

    return p, keys, private, seal


def inspect(fixture, data=None, **overrides):
    p, keys, private, seal = fixture
    args = dict(expected={n: p[n] for n in CONTEXT}, keys=keys, now=NOW)
    args.update(overrides)
    return inspect_release_issuance_evidence(canonical(seal() if data is None else data), **args)


def test_valid_signatures_are_data_and_never_authority(evidence):
    result = inspect(evidence)
    assert result.signed_bindings_valid
    assert result.outcome == "DENY"
    assert result.reason == "LIVE_ISSUANCE_AUTHORITY_NOT_ESTABLISHED"
    assert result.evidence_reference.startswith("sha256:")
    assert not any((result.issuance_authorized, result.execution_authorized,
                    result.deployment_authorized, result.activation_authorized,
                    result.human_identity_verified, result.parent_currentness_verified,
                    result.replay_consumed))


def test_repeated_inspection_does_not_claim_replay_consumption(evidence):
    assert inspect(evidence).outcome == inspect(evidence).outcome == "DENY"
    assert not inspect(evidence).replay_consumed


@pytest.mark.parametrize("name", CONTEXT)
def test_signed_scope_or_binding_substitution_fails(evidence, name):
    p, keys, private, seal = evidence
    changed = dict(p, **{name: "substituted"})
    assert not inspect(evidence, seal(changed)).signed_bindings_valid


@pytest.mark.parametrize("change", [
    {"unexpected": "field"}, {"redelegation_allowed": True}, {"environment": "production"},
    {"action": "DEPLOY"}, {"purpose": "*"}, {"tool_id": "writer?"},
    {"source_tree": "z" * 40}, {"resource_type": "OTHER"},
    {"valid_from": "2026-11-04T12:00:01Z"}, {"valid_until": "2026-11-04T12:00:00Z"},
    {"issued_at": "2026-11-04T12:00:01Z"}, {"issued_at": "2026-11-04T11:58:59Z"},
    {"valid_until": "invalid"}, {"valid_until": "2026-11-04T14:00:00Z"},
])
def test_even_resigned_malformed_or_broad_contract_denies(evidence, change):
    p, keys, private, seal = evidence
    changed = dict(p, **change)
    expected = {n: changed[n] for n in CONTEXT}
    assert not inspect(evidence, seal(changed), expected=expected).signed_bindings_valid


@pytest.mark.parametrize("part", ["issuer", "review_a", "review_b", "review_binding", "rejection", "duplicate"])
def test_signature_and_review_bindings(evidence, part):
    p, keys, private, seal = evidence
    if part in {"review_binding", "rejection"}:
        def modify(index, r):
            if index == 1:
                r["request_hash" if part == "review_binding" else "decision"] = H if part == "review_binding" else "REJECT"
        data = seal(reviewers=modify)
    else:
        data = seal()
        if part == "issuer":
            data["request"]["signature"] = "0" * 128
        elif part == "duplicate":
            data["reviews"][1] = deepcopy(data["reviews"][0])
        else:
            data["reviews"][0 if part == "review_a" else 1]["signature"] = "0" * 128
    assert not inspect(evidence, data).signed_bindings_valid


@pytest.mark.parametrize("kind", ["missing", "same_public", "duplicate_id", "wrong_role", "wrong_scope", "expired"])
def test_independent_public_key_bindings_required(evidence, kind):
    p, keys, private, seal = evidence
    changed = list(keys)
    if kind == "missing":
        changed = []
    elif kind == "same_public":
        changed[2] = replace(keys[2], public_key=keys[1].public_key)
    elif kind == "duplicate_id":
        changed[2] = replace(keys[2], key_id=keys[1].key_id)
    elif kind == "wrong_role":
        changed[1] = replace(keys[1], role="release_issuer")
    elif kind == "wrong_scope":
        changed[1] = replace(keys[1], scope=("other", *keys[1].scope[1:]))
    else:
        changed[1] = replace(keys[1], valid_until="2026-11-04T11:59:59Z")
    assert not inspect(evidence, keys=tuple(changed)).signed_bindings_valid


def test_shared_reviewer_key_cannot_pass_with_valid_signatures(evidence):
    p, keys, private, seal = evidence
    data = seal()
    review = data["reviews"][1]
    review["signature"] = private[1].sign(canonical({k: v for k, v in review.items() if k != "signature"})).hex()
    changed = (keys[0], keys[1], replace(keys[2], public_key=keys[1].public_key))
    assert inspect(evidence, data, keys=changed).reason == "RELEASE_REVIEW_NOT_INDEPENDENT"


@pytest.mark.parametrize("raw", [b'{"request":{},"request":{},"reviews":[]}', b'{"request":NaN}',
                                 b'\xff', b'[]', b'{}', b' ' * 65537])
def test_untrusted_json_is_bounded_and_fail_closed(evidence, raw):
    p, keys, private, seal = evidence
    result = inspect_release_issuance_evidence(raw, expected={n:p[n] for n in CONTEXT}, keys=keys, now=NOW)
    assert result.outcome == "DENY" and not result.signed_bindings_valid


def test_no_keys_means_no_positive_evidence(evidence):
    assert not inspect(evidence, keys=()).signed_bindings_valid


def test_non_authorizing_fields_cannot_be_overridden(evidence):
    with pytest.raises(TypeError):
        EvidenceInspection("fake", issuance_authorized=True)
    with pytest.raises(ValueError):
        replace(inspect(evidence), outcome="ALLOW")
    with pytest.raises(FrozenInstanceError):
        inspect(evidence).issuance_authorized = True


def test_payload_and_expected_context_remain_unchanged(evidence):
    p, keys, private, seal = evidence
    data = seal()
    expected = {n:p[n] for n in CONTEXT}
    before = canonical(data), canonical(expected)
    inspect(evidence, data, expected=expected)
    assert (canonical(data), canonical(expected)) == before


def test_issuer_cannot_review_its_own_request(evidence):
    p, keys, private, seal = evidence
    changed = dict(p, issuer_id="USBAY-AUDIT")
    new_keys = (replace(keys[0], subject_id="USBAY-AUDIT"), *keys[1:])
    result = inspect(evidence, seal(changed), keys=new_keys,
                     expected={n:changed[n] for n in CONTEXT})
    assert result.reason == "RELEASE_REVIEW_INVALID"


def test_issuer_key_cannot_double_as_a_reviewer_key(evidence):
    p, keys, private, seal = evidence
    data = seal()
    review = data["reviews"][0]
    review["signature"] = private[0].sign(canonical({k:v for k,v in review.items() if k != "signature"})).hex()
    new_keys = (keys[0], replace(keys[1], public_key=keys[0].public_key), keys[2])
    assert inspect(evidence, data, keys=new_keys).reason == "RELEASE_REVIEW_NOT_INDEPENDENT"


@pytest.mark.parametrize("overrides", [{"max_age_seconds": True}, {"max_age_seconds": 0},
                                       {"now": datetime(2026, 11, 4, 12, 0)},
                                       {"now": datetime(2026, 11, 4, 12, 2, tzinfo=timezone.utc)}])
def test_invalid_or_stale_clock_context_denies(evidence, overrides):
    assert not inspect(evidence, **overrides).signed_bindings_valid


def test_empty_call_fails_closed():
    result = inspect_release_issuance_evidence(b"{}", expected={})
    assert result.outcome == "DENY" and not result.issuance_authorized
