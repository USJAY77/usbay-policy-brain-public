"""GAP-1 — authenticated approval issuance (fail-closed).

TEST-FIRST evidence (pre-fix, recorded before implementation):
a caller with mere access to the registry could call register_actor +
register_approval with NO issuer authentication and obtain a usable
approval (verify_authority -> ALLOW_AUTHORITY). ATTACK_REPRODUCIBLE: True.

Post-fix: register_approval REQUIRES a signed (Ed25519) issuance envelope
from a registered, non-revoked, authorized issuer. Every deny path raises
ApprovalIssuanceDenied, leaves NO usable approval, and appends a
hash-chained issuance audit event. Assurance level:
LOCAL_ED25519_KEY_REGISTRY (no PKI/IdP/HSM claimed).
"""

from __future__ import annotations

import hashlib
import threading
import uuid

import pytest

from governance.approval_issuance import (
    ApprovalIssuanceDenied,
    build_issuance_payload,
    generate_issuer_keypair,
    sign_issuance,
)
from governance.authority_registry import (
    MediaAuthorityRegistry,
    authorization_binding_hash,
    build_issuer_registration_payload,
    sign_issuer_registration,
)
from governance.media_execution import (
    MediaExecutionConsumptionStore,
    build_media_authorization,
    build_media_execution_contract,
)
from governance.media_provider_adapter import (
    StubMediaProviderAdapter,
    execute_media_contract,
)

from tests.issuance_helpers import (
    DEFAULT_ISSUER,
    DEFAULT_TENANT,
    issue_approval,
    register_test_issuer,
    signed_issuance,
)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


PROMPT_HASH = _hash("issuance test prompt")


def _authorization(**overrides):
    base = dict(
        authorization_id="authz-is-0001",
        provider="higgsfield",
        action="video.generate",
        model_identifier="model-x",
        prompt_hash=PROMPT_HASH,
        max_outputs=1,
        max_duration_seconds=10,
        budget_ceiling=5.0,
        policy_decision_id="policy-is-0001",
        publication_authorized=False,
    )
    base.update(overrides)
    return build_media_authorization(**base)


def _contract(**overrides):
    base = dict(
        execution_id="exec-is-0001",
        actor_id="human-actor-1",
        tenant_reference="tenant-alpha",
        provider="higgsfield",
        action="video.generate",
        model_identifier="model-x",
        prompt_hash=PROMPT_HASH,
        input_asset_hashes=(),
        requested_duration_seconds=8,
        output_type="video",
        max_outputs=1,
        budget_ceiling=5.0,
        timeout_seconds=60,
        authorization_id="authz-is-0001",
        policy_decision_id="policy-is-0001",
        evidence_id="evidence-is-0001",
    )
    base.update(overrides)
    return build_media_execution_contract(**base)


@pytest.fixture()
def registry(tmp_path):
    reg = MediaAuthorityRegistry(tmp_path / "authority.db")
    reg.test_private_pem = register_test_issuer(reg)
    reg.register_actor("human-actor-1")
    return reg


def _assert_denied(registry, reason_code, *, payload, signature, **kw):
    with pytest.raises(ApprovalIssuanceDenied) as excinfo:
        registry.register_approval(
            authorization=kw.pop("authorization", _authorization()),
            actor_id=kw.pop("actor_id", "human-actor-1"),
            issuance_payload=payload,
            issuance_signature=signature,
            **kw,
        )
    assert excinfo.value.reason_code == reason_code
    # NO usable approval may remain after a denied issuance
    decision = registry.verify_authority(_contract(), _authorization())
    assert decision["decision"] == "BLOCK"
    return excinfo.value


# A. NO_ISSUER_AUTH -> BLOCK (this was the pre-fix defect)
def test_no_issuer_auth_blocks(registry):
    _assert_denied(registry, "ISSUANCE_PAYLOAD_MISSING", payload=None, signature=None)


# B. UNKNOWN_ISSUER -> BLOCK (valid self-signed envelope, unregistered key)
def test_unknown_issuer_blocks(registry):
    rogue_private, _ = generate_issuer_keypair()
    payload, signature = signed_issuance(
        private_pem=rogue_private,
        authorization=_authorization(),
        actor_id="human-actor-1",
        issuer_id="issuer-rogue",
    )
    _assert_denied(registry, "ISSUER_UNKNOWN", payload=payload, signature=signature)


# C. issuer identity mismatch: envelope claims registered issuer id but is
#    signed with a different key -> BAD_AUTH_PROOF
def test_issuer_identity_mismatch_blocks(registry):
    rogue_private, _ = generate_issuer_keypair()
    payload, signature = signed_issuance(
        private_pem=rogue_private,  # not the registered issuer's key
        authorization=_authorization(),
        actor_id="human-actor-1",
        issuer_id=DEFAULT_ISSUER,
    )
    _assert_denied(registry, "AUTHENTICATION_FAILED", payload=payload, signature=signature)


# D. UNAUTHORIZED_ISSUER: actor outside the issuer's authorized scope
def test_unauthorized_issuer_actor_scope_blocks(registry):
    registry.register_actor("actor-outside-scope")
    payload, signature = signed_issuance(
        private_pem=registry.test_private_pem,
        authorization=_authorization(),
        actor_id="actor-outside-scope",
    )
    _assert_denied(
        registry, "ISSUER_UNAUTHORIZED",
        payload=payload, signature=signature, actor_id="actor-outside-scope",
    )


# D2. WRONG_SCOPE: provider outside the issuer's authorized providers
def test_unauthorized_provider_scope_blocks(tmp_path):
    reg = MediaAuthorityRegistry(tmp_path / "authority.db")
    private_pem = register_test_issuer(reg, authorized_providers=("other-provider",))
    reg.register_actor("human-actor-1")
    payload, signature = signed_issuance(
        private_pem=private_pem,
        authorization=_authorization(),
        actor_id="human-actor-1",
    )
    with pytest.raises(ApprovalIssuanceDenied) as excinfo:
        reg.register_approval(
            authorization=_authorization(), actor_id="human-actor-1",
            issuance_payload=payload, issuance_signature=signature,
        )
    assert excinfo.value.reason_code == "ISSUER_UNAUTHORIZED"


# D3. wrong tenant/context -> DENY
def test_wrong_tenant_blocks(registry):
    payload, signature = signed_issuance(
        private_pem=registry.test_private_pem,
        authorization=_authorization(),
        actor_id="human-actor-1",
        tenant_reference="tenant-OTHER",
    )
    _assert_denied(registry, "ISSUER_UNAUTHORIZED", payload=payload, signature=signature)


# E. BAD_AUTH_PROOF: malformed signature
def test_malformed_signature_blocks(registry):
    payload, _ = signed_issuance(
        private_pem=registry.test_private_pem,
        authorization=_authorization(),
        actor_id="human-actor-1",
    )
    _assert_denied(registry, "AUTHENTICATION_FAILED", payload=payload, signature="zz-not-hex")


# F. expired/stale authentication proof
def test_stale_issuance_blocks(registry):
    payload, signature = signed_issuance(
        private_pem=registry.test_private_pem,
        authorization=_authorization(),
        actor_id="human-actor-1",
        issued_at="2020-01-01T00:00:00Z",
        expires_at="2020-01-01T01:00:00Z",
    )
    _assert_denied(registry, "ISSUANCE_STALE", payload=payload, signature=signature)


# G. revoked issuer -> BLOCK
def test_revoked_issuer_blocks(registry):
    registry.revoke_issuer(DEFAULT_ISSUER)
    payload, signature = signed_issuance(
        private_pem=registry.test_private_pem,
        authorization=_authorization(),
        actor_id="human-actor-1",
    )
    _assert_denied(registry, "ISSUER_REVOKED", payload=payload, signature=signature)


# H. REPLAYED_APPROVAL issuance: same signed envelope presented twice
def test_replayed_issuance_blocks(registry):
    payload, signature = signed_issuance(
        private_pem=registry.test_private_pem,
        authorization=_authorization(),
        actor_id="human-actor-1",
    )
    registry.register_approval(
        authorization=_authorization(), actor_id="human-actor-1",
        issuance_payload=payload, issuance_signature=signature,
    )
    with pytest.raises(ApprovalIssuanceDenied) as excinfo:
        registry.register_approval(
            authorization=_authorization(authorization_id="authz-is-0002"),
            actor_id="human-actor-1",
            issuance_payload=dict(payload, authorization_id="authz-is-0002"),
            issuance_signature=signature,
        )
    # replayed envelope fails authentication (payload changed) or nonce reuse
    assert excinfo.value.reason_code in ("AUTHENTICATION_FAILED", "ISSUANCE_REPLAYED")


def test_replayed_nonce_blocks(registry):
    nonce = uuid.uuid4().hex
    payload1, sig1 = signed_issuance(
        private_pem=registry.test_private_pem,
        authorization=_authorization(),
        actor_id="human-actor-1",
        nonce=nonce,
    )
    registry.register_approval(
        authorization=_authorization(), actor_id="human-actor-1",
        issuance_payload=payload1, issuance_signature=sig1,
    )
    auth2 = _authorization(authorization_id="authz-is-0002")
    payload2, sig2 = signed_issuance(
        private_pem=registry.test_private_pem,
        authorization=auth2,
        actor_id="human-actor-1",
        nonce=nonce,  # nonce reuse across otherwise-valid envelopes
    )
    with pytest.raises(ApprovalIssuanceDenied) as excinfo:
        registry.register_approval(
            authorization=auth2, actor_id="human-actor-1",
            issuance_payload=payload2, issuance_signature=sig2,
        )
    assert excinfo.value.reason_code == "ISSUANCE_REPLAYED"


# I. approval for actor A authenticated by an issuer not authorized for A
#    (covered by D) — plus issuer authorized for A cannot bind envelope to B
def test_envelope_actor_binding_mismatch_blocks(registry):
    registry.register_actor("someone-else")
    payload, signature = signed_issuance(
        private_pem=registry.test_private_pem,
        authorization=_authorization(),
        actor_id="someone-else",  # signed for a different subject
    )
    _assert_denied(registry, "PAYLOAD_BINDING_FAILED", payload=payload, signature=signature)


# J. TAMPERED_APPROVAL: mutation of any bound field after signing
@pytest.mark.parametrize("field,value", [
    ("actor_id", "attacker"),
    ("authorization_id", "authz-EVIL"),
    ("binding_hash", "0" * 64),
    ("nonce", "replacement-nonce"),
    ("expires_at", "2035-01-01T00:00:00Z"),
    ("tenant_reference", "tenant-OTHER"),
])
def test_tampered_payload_field_blocks(registry, field, value):
    payload, signature = signed_issuance(
        private_pem=registry.test_private_pem,
        authorization=_authorization(),
        actor_id="human-actor-1",
    )
    payload[field] = value
    with pytest.raises(ApprovalIssuanceDenied) as excinfo:
        registry.register_approval(
            authorization=_authorization(), actor_id="human-actor-1",
            issuance_payload=payload, issuance_signature=signature,
        )
    assert excinfo.value.reason_code == "AUTHENTICATION_FAILED"


# J2. tampered binding: valid signature but envelope binds another approval
def test_binding_hash_mismatch_blocks(registry):
    other = _authorization(max_duration_seconds=300)
    payload = build_issuance_payload(
        issuer_id=DEFAULT_ISSUER,
        actor_id="human-actor-1",
        authorization_id="authz-is-0001",
        binding_hash=authorization_binding_hash(other, "human-actor-1"),
        tenant_reference=DEFAULT_TENANT,
        nonce=uuid.uuid4().hex,
    )
    signature = sign_issuance(registry.test_private_pem, payload)
    _assert_denied(registry, "PAYLOAD_BINDING_FAILED", payload=payload, signature=signature)


# K/L. VALID_AUTHORIZED_ISSUER -> PASS, durable across restart, single-use
def test_valid_issuance_pass_and_persistence(tmp_path):
    path = tmp_path / "authority.db"
    reg = MediaAuthorityRegistry(path)
    private_pem = register_test_issuer(reg)
    reg.register_actor("human-actor-1")
    issue_approval(reg, private_pem=private_pem,
                   authorization=_authorization(), actor_id="human-actor-1")
    reopened = MediaAuthorityRegistry(path)  # restart/persistence
    first = reopened.verify_authority(_contract(), _authorization())
    assert first["decision"] == "ALLOW_AUTHORITY"
    replay = MediaAuthorityRegistry(path).verify_authority(
        _contract(execution_id="exec-is-0002"), _authorization()
    )
    assert replay["reason_code"] == "APPROVAL_REPLAYED"
    assert reopened.verify_issuance_audit_chain()


# M. concurrent duplicate registration -> exactly one success
def test_concurrent_duplicate_issuance_single_success(registry):
    results = []

    def attempt():
        try:
            issue_approval(
                registry, private_pem=registry.test_private_pem,
                authorization=_authorization(), actor_id="human-actor-1",
            )
            results.append("OK")
        except ApprovalIssuanceDenied as exc:
            results.append(exc.reason_code)
        except Exception as exc:  # sqlite lock contention still denies
            results.append(type(exc).__name__)

    threads = [threading.Thread(target=attempt) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("OK") == 1, results


# ---- audit evidence -------------------------------------------------------

def test_issuance_audit_events_and_chain(registry):
    # denied attempt (unknown issuer) then a valid issuance
    rogue_private, _ = generate_issuer_keypair()
    payload, signature = signed_issuance(
        private_pem=rogue_private, authorization=_authorization(),
        actor_id="human-actor-1", issuer_id="issuer-rogue",
    )
    with pytest.raises(ApprovalIssuanceDenied):
        registry.register_approval(
            authorization=_authorization(), actor_id="human-actor-1",
            issuance_payload=payload, issuance_signature=signature,
        )
    issue_approval(registry, private_pem=registry.test_private_pem,
                   authorization=_authorization(), actor_id="human-actor-1")
    events = registry.issuance_events()
    kinds = [event["event"] for event in events]
    assert "ISSUER_UNKNOWN" in kinds
    assert "APPROVAL_ISSUED" in kinds
    assert registry.verify_issuance_audit_chain()
    # no secrets/keys/raw credentials in evidence
    import json as _json
    blob = _json.dumps(events)
    assert "PRIVATE KEY" not in blob
    assert registry.test_private_pem not in blob


def test_issuance_audit_tampering_detected(registry):
    issue_approval(registry, private_pem=registry.test_private_pem,
                   authorization=_authorization(), actor_id="human-actor-1")
    assert registry.verify_issuance_audit_chain()
    import sqlite3
    with sqlite3.connect(registry.path) as conn:
        conn.execute("UPDATE issuance_audit SET actor_id = 'forged-actor'")
    assert not registry.verify_issuance_audit_chain()


# ---- issuer registration hygiene ------------------------------------------

def test_register_issuer_rejects_private_key_material(tmp_path):
    reg = MediaAuthorityRegistry(tmp_path / "fresh.db")
    private_pem, _ = generate_issuer_keypair()
    with pytest.raises(ValueError):
        reg.register_issuer(
            issuer_id="issuer-x", public_key_pem=private_pem,
            authorized_actors=("a",), authorized_providers=("p",),
        )


# bootstrap bypass: once provisioned, adding an issuer requires sponsorship
def test_second_issuer_requires_sponsor(registry):
    _, evil_public = generate_issuer_keypair()
    with pytest.raises(ValueError) as excinfo:
        registry.register_issuer(
            issuer_id="issuer-evil", public_key_pem=evil_public,
            authorized_actors=("attacker",), authorized_providers=("higgsfield",),
        )
    assert "issuer_sponsor_REQUIRED" in str(excinfo.value)
    # forged sponsorship also fails
    rogue_private, _ = generate_issuer_keypair()
    payload = build_issuer_registration_payload(
        issuer_id="issuer-evil", public_key_pem=evil_public,
        authorized_actors=("attacker",), authorized_providers=("higgsfield",),
    )
    with pytest.raises(ValueError) as excinfo2:
        registry.register_issuer(
            issuer_id="issuer-evil", public_key_pem=evil_public,
            authorized_actors=("attacker",), authorized_providers=("higgsfield",),
            sponsor_issuer_id=DEFAULT_ISSUER,
            sponsor_signature=sign_issuer_registration(rogue_private, payload),
        )
    assert "issuer_sponsor_signature_INVALID" in str(excinfo2.value)


def test_sponsored_issuer_registration_succeeds(registry):
    new_private, new_public = generate_issuer_keypair()
    payload = build_issuer_registration_payload(
        issuer_id="issuer-2", public_key_pem=new_public,
        authorized_actors=("human-actor-1",), authorized_providers=("higgsfield",),
        tenant_reference=DEFAULT_TENANT,
    )
    registry.register_issuer(
        issuer_id="issuer-2", public_key_pem=new_public,
        authorized_actors=("human-actor-1",), authorized_providers=("higgsfield",),
        tenant_reference=DEFAULT_TENANT,
        sponsor_issuer_id=DEFAULT_ISSUER,
        sponsor_signature=sign_issuer_registration(
            registry.test_private_pem, payload
        ),
    )
    issue_approval(registry, private_pem=new_private, issuer_id="issuer-2",
                   authorization=_authorization(), actor_id="human-actor-1")
    assert registry.verify_authority(
        _contract(), _authorization(), consume=False
    )["decision"] == "ALLOW_AUTHORITY"


# cross-tenant execution: tenant bound at issuance is enforced at execution
def test_cross_tenant_execution_blocks(registry):
    issue_approval(registry, private_pem=registry.test_private_pem,
                   authorization=_authorization(), actor_id="human-actor-1")
    decision = registry.verify_authority(
        _contract(tenant_reference="tenant-beta"), _authorization()
    )
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "APPROVAL_TENANT_MISMATCH"


# issuer revocation invalidates OUTSTANDING approvals
def test_issuer_revocation_invalidates_outstanding_approval(registry):
    issue_approval(registry, private_pem=registry.test_private_pem,
                   authorization=_authorization(), actor_id="human-actor-1")
    registry.revoke_issuer(DEFAULT_ISSUER)
    decision = registry.verify_authority(_contract(), _authorization())
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "ISSUER_REVOKED"


# audit deletion: mid-chain deletion detected; tail truncation detected
# only against an externally anchored head (labeled residual otherwise)
def test_audit_mid_chain_deletion_detected(registry):
    for i in range(3):
        auth = _authorization(authorization_id=f"authz-del-{i}")
        issue_approval(registry, private_pem=registry.test_private_pem,
                       authorization=auth, actor_id="human-actor-1")
    assert registry.verify_issuance_audit_chain()
    import sqlite3
    with sqlite3.connect(registry.path) as conn:
        conn.execute("DELETE FROM issuance_audit WHERE seq = 2")
    assert not registry.verify_issuance_audit_chain()


def test_audit_tail_truncation_detected_with_external_anchor(registry):
    issue_approval(registry, private_pem=registry.test_private_pem,
                   authorization=_authorization(), actor_id="human-actor-1")
    head = registry.issuance_audit_head()  # anchored OUTSIDE the database
    import sqlite3
    with sqlite3.connect(registry.path) as conn:
        conn.execute("DELETE FROM issuance_audit WHERE seq = (SELECT MAX(seq) FROM issuance_audit)")
    assert registry.verify_issuance_audit_chain()  # residual without anchor
    assert not registry.verify_issuance_audit_chain(expected_head=head)


# ---- execution boundary: rejected issuance never authorizes execution ------

def test_rejected_issuance_cannot_authorize_execution(registry, tmp_path):
    rogue_private, _ = generate_issuer_keypair()
    payload, signature = signed_issuance(
        private_pem=rogue_private, authorization=_authorization(),
        actor_id="human-actor-1", issuer_id="issuer-rogue",
    )
    with pytest.raises(ApprovalIssuanceDenied):
        registry.register_approval(
            authorization=_authorization(), actor_id="human-actor-1",
            issuance_payload=payload, issuance_signature=signature,
        )
    adapter = StubMediaProviderAdapter()
    store = MediaExecutionConsumptionStore(tmp_path / "consumption.db")
    evidence_log = tmp_path / "evidence.jsonl"
    result = execute_media_contract(
        _contract(), _authorization(), adapter,
        consumption_store=store, authority_registry=registry,
        evidence_log=evidence_log,
    )
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "APPROVAL_UNKNOWN"
    # EXECUTION_SIDE_EFFECT_COUNT = 0
    assert adapter.call_count == 0
    assert not evidence_log.exists()
