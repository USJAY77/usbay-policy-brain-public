"""Synthetic cryptographic continuity, uncertainty and restore-domain regressions."""
import json
import sqlite3
from types import SimpleNamespace

import pytest

from security import hydra_continuity as c
from security.hydra_continuity_contracts import ContinuityDenied, decode, digest, sign, trust
from security.hydra_continuity_store import LocalStore
from tests.helpers.hydra_transport import configure_transport_authority, NOW
from tests.test_hydra_live_client import authorized_context
from tests.test_hydra_transport_authority import authorize

pytestmark = [pytest.mark.governance, pytest.mark.regression]


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    signed, registry, record = configure_transport_authority(tmp_path, monkeypatch)
    return SimpleNamespace(signed=signed, registry=registry, record=record,
        ctx=signed(authorized_context()), authority=signed.continuity, path=tmp_path)


def fresh(f, identifier="auth-2", nonce="nonce-2"):
    context = authorized_context()
    context["hydra_remote_transport_authorization"]["authorization_id"] = identifier
    return f.signed(context, nonce=nonce)


@pytest.mark.parametrize("fault", ["delete", "empty", "corrupt", "metadata", "wrong_store", "locked"])
def test_local_store_is_open_only_and_blocks_before_service(fixture, monkeypatch, fault):
    f = fixture; path = f.path/"replay.db"; calls = []; held = None
    if fault == "delete": path.unlink()
    elif fault == "empty": path.write_bytes(b"")
    elif fault == "corrupt": path.write_bytes(b"not sqlite")
    elif fault == "metadata":
        with sqlite3.connect(path) as conn: conn.execute("DELETE FROM metadata")
    elif fault == "wrong_store":
        config = dict(f.authority.config, store_identity="sha256:"+"a"*64)
        f.authority.trust_path.write_text(json.dumps(config))
    else:
        held = sqlite3.connect(path, isolation_level=None); held.execute("BEGIN IMMEDIATE")
    monkeypatch.setattr(c, "exchange", lambda *a: calls.append(a))
    try:
        with pytest.raises(ValueError): authorize(f.ctx)
        assert calls == []
        if fault == "delete": assert not path.exists()
    finally:
        if held: held.close()


@pytest.mark.parametrize("domain", ["service", "witness"])
@pytest.mark.parametrize("fault", ["delete", "empty", "corrupt", "rollback"])
def test_independent_store_loss_or_rollback_stops_admission(fixture, domain, fault):
    f = fixture; target = getattr(f.authority, domain); path = target.log.path
    old = path.read_bytes()
    assert authorize(f.ctx)["decision"] == "ALLOW"
    if fault == "delete": path.unlink()
    elif fault == "empty": path.write_bytes(b"")
    elif fault == "corrupt": path.write_bytes(b"corrupt")
    else: path.write_bytes(old)
    with pytest.raises(ValueError, match="trust_unavailable"):
        authorize(fresh(f))
    if fault == "delete": assert not path.exists()
    # No self-baseline even if the caller subsequently supplies a readable image.
    path.write_bytes(old)
    with pytest.raises(ValueError): authorize(fresh(f, "auth-3", "nonce-3"))


def test_service_restart_preserves_consumption(fixture):
    f = fixture
    assert authorize(f.ctx)["decision"] == "ALLOW"
    old = f.authority.service
    f.authority.service = c.Authority(old.log.path, f.authority.config, f.authority.service_key)
    with pytest.raises(ContinuityDenied, match="replayed"):
        c.reserve(f.authority.config, f.ctx["hydra_remote_transport_authorization"])
    assert authorize(fresh(f))["decision"] == "ALLOW"


@pytest.mark.parametrize("remove", [False, True])
def test_witness_restart_never_reopens_or_replays_genesis(fixture, remove):
    f = fixture; old = f.authority.witness
    conn = old.log.open()
    try: old_grant = old.log.rows(conn)[0]["event"]["authorization"]
    finally: conn.close()
    if remove: old.log.path.unlink()
    f.authority.witness = c.Witness(old.log.path, f.authority.config, f.authority.witness_key)
    with pytest.raises(ContinuityDenied): f.authority.witness.provision(old_grant)
    with pytest.raises(ValueError): authorize(f.ctx)


@pytest.mark.parametrize("reuse", ["nonce", "authorization_id"])
def test_independent_uniqueness_survives_gateway_rollback(fixture, reuse):
    f = fixture; path = f.path/"replay.db"; before = path.read_bytes()
    assert authorize(f.ctx)["decision"] == "ALLOW"
    path.write_bytes(before)
    context = fresh(f, "different" if reuse == "nonce" else "auth-1",
                    "nonce-1" if reuse == "nonce" else "different")
    with pytest.raises(ValueError, match="replayed"): authorize(context)


def test_canonical_revocation_survives_all_gateway_file_rollback(fixture):
    from governance.durable_authority_registries import HUMAN_APPROVAL
    f = fixture
    files = [f.path/"replay.db", f.registry.registry_path, f.registry.evidence_path, f.authority.trust_path]
    images = {p: p.read_bytes() for p in files}
    f.registry.revoke_authority(HUMAN_APPROVAL, f.record["authority_reference"],
        tenant_reference=f.record["tenant_reference"], environment_reference=f.record["environment_reference"],
        reason_code="SYNTHETIC_REVOCATION")
    for path, raw in images.items(): path.write_bytes(raw)
    with pytest.raises(ValueError, match="issuer_invalid"): authorize(f.ctx)


@pytest.mark.parametrize("kind", ["receipt", "witness"])
def test_old_signed_response_cannot_answer_fresh_challenge(fixture, monkeypatch, kind):
    f = fixture; path = f.path/"replay.db"; before = path.read_bytes(); captured = []
    original = f.authority.exchange
    def capture(url, value):
        result = original(url, value)
        if (kind == "receipt" and value.get("operation") == "reserve") or (
                kind == "witness" and value.get("operation") == "observe"):
            captured.append(result)
        return result
    monkeypatch.setattr(c, "exchange", capture)
    assert authorize(f.ctx)["decision"] == "ALLOW"
    path.write_bytes(before)
    def replay(url, value):
        if (kind == "receipt" and value.get("operation") == "reserve") or (
                kind == "witness" and value.get("operation") == "observe"):
            return captured[0]
        return original(url, value)
    monkeypatch.setattr(c, "exchange", replay)
    with pytest.raises(ValueError): authorize(f.ctx)


@pytest.mark.parametrize("field", ["continuity_identity", "store_identity", "generation", "authority_epoch",
                                   "tenant_reference", "environment_reference", "policy_hash", "node_id", "endpoint_url_hash"])
def test_signed_receipt_substitution_is_rejected(fixture, monkeypatch, field):
    f = fixture; original = f.authority.exchange
    def wrong(url, request):
        result = original(url, request)
        if request.get("operation") == "reserve":
            payload = dict(result["payload"]); payload["binding"] = dict(payload["binding"])
            value = payload["binding"][field]
            payload["binding"][field] = value+1 if type(value) is int else "wrong"
            return sign(f.authority.service_key, payload)
        return result
    monkeypatch.setattr(c, "exchange", wrong)
    with pytest.raises(ValueError): authorize(f.ctx)


@pytest.mark.parametrize("key", ["service_public_key", "witness_public_key"])
def test_wrong_pinned_signature_key_blocks(fixture, key):
    from governance.approval_issuance import generate_issuer_keypair
    f = fixture; _, public = generate_issuer_keypair()
    config = dict(f.authority.config); config[key] = public
    f.authority.trust_path.write_text(json.dumps(config))
    with pytest.raises(ValueError): authorize(f.ctx)


@pytest.mark.parametrize("phase", ["before_service", "after_service", "after_witness"])
def test_lost_reply_or_witness_uncertainty_never_retries(fixture, monkeypatch, phase):
    f = fixture; original = f.authority.exchange
    def lost(url, request):
        operation = request.get("operation")
        if phase == "before_service" and operation == "reserve": raise TimeoutError()
        result = original(url, request)
        if (phase == "after_service" and operation == "reserve") or (phase == "after_witness" and operation == "advance"):
            raise TimeoutError()
        return result
    monkeypatch.setattr(c, "exchange", lost)
    with pytest.raises(ValueError): authorize(f.ctx)
    monkeypatch.setattr(c, "exchange", original)
    with pytest.raises(ValueError, match="replayed"): authorize(f.ctx)
    with sqlite3.connect(f.path/"replay.db") as conn:
        receipt = json.loads(conn.execute("SELECT receipt FROM hydra_transport_reservations").fetchone()[0])
    assert receipt["state"] == "CONTINUITY_PENDING"


@pytest.mark.parametrize("committed", [False, True])
def test_terminal_local_commit_failure_burns_authority(fixture, monkeypatch, committed):
    f = fixture; original = LocalStore.open; opens = []
    class FailCommit:
        def __init__(self, conn): self.conn = conn
        def execute(self, *args): return self.conn.execute(*args)
        def close(self): self.conn.close()
        def commit(self):
            if committed: self.conn.commit()
            raise sqlite3.OperationalError("SYNTHETIC_COMMIT_UNKNOWN")
    def opened(self):
        conn = original(self); opens.append(1)
        return FailCommit(conn) if len(opens) == 2 else conn
    monkeypatch.setattr(LocalStore, "open", opened)
    with pytest.raises(ValueError): authorize(f.ctx)
    monkeypatch.setattr(LocalStore, "open", original)
    with pytest.raises(ValueError, match="replayed"): authorize(f.ctx)
    with pytest.raises(ContinuityDenied, match="replayed"):
        c.reserve(f.authority.config, f.ctx["hydra_remote_transport_authorization"])


def test_private_inputs_are_absent_from_continuity_storage_and_errors(fixture):
    f = fixture; secret = "SYNTHETIC_PRIVATE_INPUT_MUST_NOT_PERSIST"
    f.ctx["private_request_input"] = secret
    assert authorize(f.ctx)["decision"] == "ALLOW"
    for path in (f.path/"replay.db", f.authority.service.log.path, f.authority.witness.log.path):
        raw = path.read_bytes()
        assert secret.encode() not in raw and b"PRIVATE KEY" not in raw
    with pytest.raises(ValueError) as denied: authorize(f.ctx)
    assert secret not in str(denied.value)


def test_duplicate_json_fields_and_operational_use_are_rejected(fixture, monkeypatch):
    with pytest.raises(ContinuityDenied): decode('{"scope":1,"scope":2}')
    monkeypatch.setenv("USBAY_ENV", "production")
    with pytest.raises(ContinuityDenied): trust(fixture.authority.config)


def test_wrong_control_key_and_replayed_control_do_not_advance(fixture):
    f = fixture; service = f.authority.service
    conn = service.log.open()
    try: row = service.log.rows(conn)[-1]
    finally: conn.close()
    from governance.durable_authority_registries import HUMAN_APPROVAL
    record=f.registry._latest(HUMAN_APPROVAL,f.record["authority_reference"])["record"]
    data = dict(previous=row["head"], sequence=row["sequence"]+1, record=record)
    grant = f.authority.authorization(service, "SET_ISSUER", data)
    wrong = sign(f.authority.service_key, grant["payload"])
    with pytest.raises(ContinuityDenied): service.handle(dict(operation="control", authorization=wrong))
    service.handle(dict(operation="control", authorization=grant))
    with pytest.raises(ContinuityDenied): service.handle(dict(operation="control", authorization=grant))


def test_old_challenge_is_consumed_independently_of_mandate(fixture):
    f = fixture; challenge = "a"*64
    first = dict(operation="reserve", mandate=f.ctx["hydra_remote_transport_authorization"], challenge=challenge)
    f.authority.service.handle(first)
    second = dict(first, mandate=fresh(f)["hydra_remote_transport_authorization"])
    with pytest.raises(ContinuityDenied, match="replayed"): f.authority.service.handle(second)


@pytest.mark.parametrize("target",["service","witness","local"])
def test_provisioning_cannot_be_replayed_after_loss(fixture,target):
    f=fixture
    if target=="local":
        instance=LocalStore(f.path/"new-local.db",f.authority.config)
        grant=f.authority.authorization(instance,"PROVISION_LOCAL",{})
        instance.provision(grant);path=instance.path
    else:
        instance=getattr(f.authority,target);path=instance.log.path
        conn=instance.log.open()
        try:grant=instance.log.rows(conn)[0]["event"]["authorization"]
        finally:conn.close()
    path.unlink()
    with pytest.raises(ContinuityDenied):instance.provision(grant)
    assert not path.exists()


@pytest.mark.parametrize("field",["continuity_identity","witness_identity","store_identity","generation",
    "authority_epoch","tenant_reference","environment_reference","policy_reference","policy_hash"])
def test_local_identity_and_scope_substitution_never_calls_authority(fixture,monkeypatch,field):
    f=fixture;config=dict(f.authority.config);value=config[field]
    config[field]=value+1 if type(value) is int else "sha256:"+"9"*64
    f.authority.trust_path.write_text(json.dumps(config));calls=[]
    monkeypatch.setattr(c,"exchange",lambda *args:calls.append(args))
    with pytest.raises(ValueError):authorize(f.ctx)
    assert calls==[]


def test_recovery_signature_is_review_only_and_cannot_provision_or_execute(fixture):
    f=fixture;service=f.authority.service
    data=dict(expected_head="a"*64,expected_sequence=1,target_generation=2,target_epoch=2,
        revocation_digest="b"*64,preservation_policy="PRESERVE_CONSUMPTION_AND_REVOCATION",
        recovery_mode="STOPPED_RECONCILIATION_ONLY")
    grant=f.authority.authorization(service,"RECOVER",data)
    parsed=c.validate_recovery_contract(grant,f.authority.config,service.boot_challenge,NOW)
    assert parsed["target_generation"]==2
    with pytest.raises(TypeError):parsed["target_generation"]=3
    with pytest.raises(ContinuityDenied):service.handle(dict(operation="control",authorization=grant))
    with pytest.raises(ContinuityDenied):service.provision(grant)
    with pytest.raises(ContinuityDenied):c.validate_recovery_contract(grant,f.authority.config,"wrong",NOW)
    assert authorize(f.ctx)["decision"]=="ALLOW"


def test_local_pending_rollback_during_reservation_denies_admission(fixture,monkeypatch):
    from security import hydra_transport_authority as transport
    f=fixture;path=f.path/"replay.db";snapshot=path.read_bytes()
    original=transport.reserve_continuity
    def restored_after_independent_commit(*args):
        packet=original(*args)
        path.write_bytes(snapshot)
        return packet
    monkeypatch.setattr(transport,"reserve_continuity",restored_after_independent_commit)
    with pytest.raises(ValueError,match="trust_unavailable"):authorize(f.ctx)
    # The independently committed mandate remains consumed after local loss.
    with pytest.raises(ContinuityDenied,match="replayed"):
        c.reserve(f.authority.config,f.ctx["hydra_remote_transport_authorization"])


@pytest.mark.parametrize("source,target,variant",[
    ("control_public_key","service_public_key",False),
    ("control_public_key","witness_public_key",False),
    ("service_public_key","witness_public_key",False),
    ("control_public_key","service_public_key",True),
])
def test_reference_key_purposes_cannot_alias(fixture,source,target,variant):
    config=dict(fixture.authority.config)
    config[target]=config[source]+("\n" if variant else "")
    with pytest.raises(ContinuityDenied):trust(config)


@pytest.mark.parametrize("field",["service_public_key","witness_public_key"])
def test_runtime_keys_cannot_be_human_transport_issuers(fixture,field):
    from governance.durable_authority_registries import HUMAN_APPROVAL,UPDATE,_normalize_record
    f=fixture
    record=f.registry._latest(HUMAN_APPROVAL,f.record["authority_reference"])["record"]
    record=_normalize_record(HUMAN_APPROVAL,dict(record,issuer_public_key_pem=f.authority.config[field]),UPDATE)
    with pytest.raises(ContinuityDenied):f.authority.publish(record)


@pytest.mark.parametrize("domain",["service","witness"])
def test_unexpected_sqlite_trigger_is_not_a_valid_store(fixture,domain):
    f=fixture;path=getattr(f.authority,domain).log.path
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TRIGGER discard_commits BEFORE INSERT ON events BEGIN SELECT RAISE(IGNORE); END")
    with pytest.raises(ValueError,match="trust_unavailable"):authorize(f.ctx)
