"""Local synthetic transaction tests; no operational trust/signing adapters."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta
import hashlib
import hmac
import json
import multiprocessing
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from governance.release_owner_contract import _hash
from governance.release_transaction_writer import (
    AuthorityObservation, HeldAuthorityFence, ReleaseAuthoritySource, ReleaseSigner,
    ReleaseTransactionStore, ReleaseTransactionWriter,
)
from security.runtime_artifact_provenance import canonical_bytes
from tests import test_release_owner_contract as chain_fixtures
from tests.test_release_owner_contract import NOW, START, mark
from security.runtime_artifact_provenance import public_key_id


class FixtureSource(ReleaseAuthoritySource):
    """Only synthetic test composition, not an installed authenticated service."""
    def __init__(self, records, trust, state):
        self.request_hash = _hash(json.loads(records["request"]))
        self.observation = AuthorityObservation(trust, state["adoption_reference"], state["source_commit"],
                                               state["source_tree"], state["policy_bundle_hash"])
        self.calls = 0
        self.fail_at = None
        self.fence_lock = multiprocessing.get_context("fork").RLock() if "fork" in multiprocessing.get_all_start_methods() else threading.RLock()
        self.fence_active = False
        self.fence_exits = 0
        self.fence_mutate = None

    @contextmanager
    def hold_fence(self, request_hash, state_hash):
        with self.fence_lock:
            self.fence_active = True
            try:
                fence=HeldAuthorityFence(request_hash,state_hash,self.observation.adoption_reference,
                                         mark("fixture-held-fence"),"2026-11-07T12:01:00Z")
                yield self.fence_mutate(fence) if self.fence_mutate else fence
            finally:
                self.fence_active = False
                self.fence_exits += 1

    def observe(self, request_hash, now, state_hash):
        assert self.fence_active
        self.calls += 1
        if self.calls == self.fail_at:
            raise RuntimeError("synthetic authority revoked")
        assert request_hash == self.request_hash
        assert state_hash == self.observation.trust.head_hash
        return self.observation


class MemorySigner(ReleaseSigner):
    def __init__(self):
        self.material = secrets.token_hex(32).encode("ascii")
        self.calls = 0
        self.verifications = 0

    @property
    def tool_id(self):
        return "synthetic-tool"

    def sign(self, raw):
        self.calls += 1
        return "hmac-sha256:" + hmac.new(self.material, raw, hashlib.sha256).hexdigest()

    def verify(self, raw, signature):
        self.verifications += 1
        if not hmac.compare_digest(signature, "hmac-sha256:" + hmac.new(self.material, raw, hashlib.sha256).hexdigest()):
            raise ValueError("synthetic signature mismatch")


class Clock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        return self.now


class FaultWriter(ReleaseTransactionWriter):
    def __init__(self, *args, fault=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fault = fault

    def _checkpoint(self, stage):
        if stage == self.fault:
            raise RuntimeError("synthetic crash")

    def _commit(self, connection):
        if self.fault == "commit_before":
            raise sqlite3.OperationalError("synthetic lost commit response")
        connection.commit()
        if self.fault == "commit_after":
            raise sqlite3.OperationalError("synthetic lost commit response")


class CrashWriter(FaultWriter):
    def _checkpoint(self, stage):
        if stage == self.fault:
            os._exit(73)


def _child_write(writer, records, core, barrier, queue):
    try:
        barrier.wait(timeout=10)
        result = writer.write(records, core)
        queue.put((result.outcome, result.signer_attempted))
    except Exception:
        queue.put(("CHILD_ERROR", False))


class ReleaseTransactionWriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse synthetic chain fixtures; keys stay in memory only.
        chain_fixtures.ReleaseOwnerContractTests.setUpClass()
        cls.fixture = chain_fixtures.ReleaseOwnerContractTests()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="usbay-synthetic-release-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "release.sqlite"
        self.state = dict(tenant_id="synthetic-tenant", target_id="synthetic-target",
            resource_id="synthetic-release", source_commit="1"*40, source_tree="2"*40,
            policy_bundle_hash=mark("bundle"), predecessor_hash=mark("previous"),
            epoch="synthetic-epoch", sequence=7, adoption_reference=mark("fixture-adoption"))
        node_id="usbay-node-"+hashlib.sha256(canonical_bytes({"node_label":"synthetic-compat-node"})).hexdigest()[:16]
        self.signer = MemorySigner()
        previous=dict(release_id="synthetic-parent",git_commit=self.state["source_commit"],
            policy_bundle_hash=self.state["policy_bundle_hash"].split(":")[1],
            deployment_timestamp="2026-11-07T11:58:00Z",activating_node_id=node_id,
            tenant_id=self.state["tenant_id"],previous_release_hash="GENESIS")
        self.state["predecessor_hash"]=_hash(previous)
        previous_signature="hmac-sha256:"+hmac.new(self.signer.material,canonical_bytes(previous),hashlib.sha256).hexdigest()
        self.store = ReleaseTransactionStore.provision(self.path, self.state)
        self.core = dict(release_id="synthetic-release", git_commit=self.state["source_commit"],
            policy_bundle_hash=self.state["policy_bundle_hash"].split(":")[1],
            deployment_timestamp=START, activating_node_id=node_id, tenant_id=self.state["tenant_id"],
            previous_release_hash=self.state["predecessor_hash"].split(":")[1],
            release_history=[dict(previous,release_signature=previous_signature)])
        self.records, self.trust = self.chain()
        self.source = FixtureSource(self.records, self.trust, self.state)
        self.clock = Clock()
        self.writer = self.writer_for()

    def chain(self, changes=None, state=None, core=None):
        state = self.state if state is None else state
        core = self.core if core is None else core
        def mutate(kind, payload):
            if kind in ("root", "issuer", "request"):
                payload["scope"]["release_core_hash"] = _hash(core)
                payload["scope"]["predecessor_hash"] = state["predecessor_hash"]
            if kind == "status":
                payload["head_hash"] = _hash(state)
                payload["epoch"] = state["epoch"]
                payload["sequence"] = state["sequence"]
            if changes:
                changes(kind, payload)
        records, trust = self.fixture.chain(mutate)
        return records, replace(trust, head_hash=_hash(state), epoch=state["epoch"], sequence=state["sequence"])

    def writer_for(self, **overrides):
        kwargs = dict(authority_source=self.source, signer=self.signer,
                      adoption_reference=self.state["adoption_reference"], clock=self.clock)
        kwargs.update(overrides)
        return FaultWriter(self.store, **kwargs)

    def counts(self):
        with sqlite3.connect(self.path) as db:
            return tuple(db.execute("SELECT COUNT(*) FROM " + name).fetchone()[0]
                         for name in ("outputs", "nonces", "budgets"))

    def successor_core(self,state):
        with sqlite3.connect(self.path) as db:
            previous=json.loads(db.execute("SELECT output FROM outputs ORDER BY rowid DESC").fetchone()[0])
        return dict(self.core,release_id="synthetic-successor",
            previous_release_hash=state["predecessor_hash"].split(":")[1],
            release_history=list(previous["release_history"])+[previous])

    def assert_denied_without_signing(self, result):
        self.assertEqual(result.outcome, "DENIED")
        self.assertFalse(result.signer_attempted)
        self.assertEqual(self.signer.calls, 0)
        self.assertEqual(self.counts(), (0,0,0))

    def test_one_transaction_commits_output_consumption_and_head(self):
        result = self.writer.write(self.records, self.core)
        self.assertEqual(result.outcome, "COMMITTED")
        self.assertEqual(self.counts(), (1,1,1))
        self.assertEqual(self.signer.calls, 1)
        self.assertEqual(self.signer.verifications, 2)
        self.assertEqual(self.source.calls, 3)
        self.assertEqual(self.store.state()["sequence"], 8)
        self.assertEqual(self.store.state()["predecessor_hash"], _hash(self.core))
        with sqlite3.connect(self.path) as db:
            output, receipt = db.execute("SELECT output,receipt FROM outputs").fetchone()
        decoded = json.loads(output)
        signature = decoded.pop("release_signature")
        self.assertEqual(decoded,self.core)
        self.signer.verify(canonical_bytes(decoded),signature)
        self.assertEqual(json.loads(receipt)["output_digest"], result.output_digest)
        self.assertEqual(set(Path(self.temp.name).iterdir()), {self.path})

    def test_default_configuration_does_not_open_store(self):
        missing=ReleaseTransactionStore(Path(self.temp.name)/"missing.sqlite")
        result=ReleaseTransactionWriter(missing).write(self.records,self.core)
        self.assertEqual(result.reason,"WRITER_AUTHORITY_UNAVAILABLE")
        self.assertFalse(missing.path.exists())

    def test_missing_signer(self):
        self.assert_denied_without_signing(self.writer_for(signer=None).write(self.records,self.core))

    def test_missing_authority_source(self):
        self.assert_denied_without_signing(self.writer_for(authority_source=None).write(self.records,self.core))

    def test_missing_adoption_pin(self):
        self.assert_denied_without_signing(self.writer_for(adoption_reference=None).write(self.records,self.core))

    def test_missing_clock(self):
        self.assert_denied_without_signing(self.writer_for(clock=None).write(self.records,self.core))

    def test_wrong_adoption(self):
        self.assert_denied_without_signing(self.writer_for(adoption_reference=mark("other")).write(self.records,self.core))

    def test_wrong_observed_adoption(self):
        self.source.observation=replace(self.source.observation,adoption_reference=mark("other"))
        self.assert_denied_without_signing(self.writer.write(self.records,self.core))

    def test_wrong_observed_source(self):
        self.source.observation=replace(self.source.observation,source_commit="f"*40)
        self.assert_denied_without_signing(self.writer.write(self.records,self.core))

    def test_wrong_observed_head(self):
        self.source.observation=replace(self.source.observation,trust=replace(self.trust,head_hash=mark("wrong")))
        self.assert_denied_without_signing(self.writer.write(self.records,self.core))

    def test_wrong_observed_epoch(self):
        self.source.observation=replace(self.source.observation,trust=replace(self.trust,epoch="previous"))
        self.assert_denied_without_signing(self.writer.write(self.records,self.core))

    def test_changed_core(self):
        core=dict(self.core,activating_node_id="different-node")
        self.assert_denied_without_signing(self.writer.write(self.records,core))

    def test_caller_cannot_request_a_different_tool(self):
        def mutate(kind,payload):
            if kind in ("root","issuer","request"):
                payload["scope"]["tool_id"]="another-signer"
        records,trust=self.chain(mutate)
        source=FixtureSource(records,trust,self.state)
        self.assert_denied_without_signing(self.writer_for(authority_source=source).write(records,self.core))

    def test_revocation_observed_after_lock_prevents_signing(self):
        self.source.fail_at=1
        self.assert_denied_without_signing(self.writer.write(self.records,self.core))

    def test_revocation_at_commit_rolls_back_signed_attempt(self):
        self.source.fail_at=3
        result=self.writer.write(self.records,self.core)
        self.assertEqual(result.outcome,"DENIED")
        self.assertTrue(result.signer_attempted)
        self.assertEqual(self.counts(),(0,0,0))
        self.assertEqual(self.store.state(),self.state)

    def test_expiry_just_before_signing_prevents_effect(self):
        def checkpoint(stage):
            if stage=="before_sign": self.clock.now=NOW+timedelta(seconds=30)
        self.writer._checkpoint=checkpoint
        self.assert_denied_without_signing(self.writer.write(self.records,self.core))

    def test_expiry_after_signing_rolls_back(self):
        def checkpoint(stage):
            if stage=="after_sign": self.clock.now=NOW+timedelta(seconds=30)
        self.writer._checkpoint=checkpoint
        result=self.writer.write(self.records,self.core)
        self.assertEqual(result.outcome,"DENIED")
        self.assertTrue(result.signer_attempted)
        self.assertEqual(self.counts(),(0,0,0))

    def test_replay_cannot_create_second_output(self):
        self.assertEqual(self.writer.write(self.records,self.core).outcome,"COMMITTED")
        self.assertEqual(self.writer.write(self.records,self.core).outcome,"DENIED")
        self.assertEqual(self.signer.calls,1)
        self.assertEqual(self.counts(),(1,1,1))

    def test_same_nonce_under_new_grant_cannot_create_second_output(self):
        self.assertEqual(self.writer.write(self.records,self.core).outcome,"COMMITTED")
        state=self.store.state()
        core=self.successor_core(state)
        def mutate(kind,payload):
            if kind=="issuer": payload["record_id"]="synthetic-rotated-grant"
        records,trust=self.chain(mutate,state=state,core=core)
        source=FixtureSource(records,trust,state)
        result=self.writer_for(authority_source=source).write(records,core)
        self.assertEqual(result.reason,"NONCE_CONSUMED")
        self.assertEqual(self.signer.calls,1)
        self.assertEqual(self.counts(),(1,1,1))

    def test_new_nonce_under_spent_grant_is_denied(self):
        # Establish a consumed budget independently of nonce lookup. The writer
        # must reject it even when the request nonce has never been seen.
        grant=json.loads(self.records["request"])["payload"]["issuer_grant_hash"]
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO budgets VALUES (?,?)",(grant,mark("previous-transaction")))
        result=self.writer.write(self.records,self.core)
        self.assertEqual(result.reason,"BUDGET_CONSUMED")
        self.assertFalse(result.signer_attempted)
        self.assertEqual(self.signer.calls,0)

    def test_threads_at_most_one_commit(self):
        barrier=threading.Barrier(2)
        def run(_):
            barrier.wait(timeout=10)
            return self.writer.write(self.records,self.core)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(run,range(2)))
        self.assertEqual(sum(r.outcome=="COMMITTED" for r in results),1)
        self.assertEqual(self.counts(),(1,1,1))
        self.assertEqual(self.signer.calls,1)

    @unittest.skipUnless("fork" in multiprocessing.get_all_start_methods(),"Linux fork validation only")
    def test_processes_at_most_one_commit(self):
        ctx=multiprocessing.get_context("fork")
        barrier=ctx.Barrier(2);queue=ctx.Queue()
        children=[ctx.Process(target=_child_write,args=(self.writer,self.records,self.core,barrier,queue)) for _ in range(2)]
        try:
            for child in children: child.start()
            results=[queue.get(timeout=15) for _ in children]
            for child in children:
                child.join(timeout=15)
                self.assertEqual(child.exitcode,0)
            self.assertEqual(sum(r[0]=="COMMITTED" for r in results),1)
            self.assertEqual(sum(r[1] for r in results),1)
            self.assertEqual(self.counts(),(1,1,1))
        finally:
            for child in children:
                if child.is_alive(): child.terminate();child.join(timeout=5)
            queue.close();queue.join_thread()

    def test_locked_store_fails_without_waiting_or_signing(self):
        with sqlite3.connect(self.path,isolation_level=None) as db:
            db.execute("BEGIN IMMEDIATE")
            self.assert_denied_without_signing(self.writer.write(self.records,self.core))
            db.rollback()

    def test_missing_store_does_not_self_provision(self):
        self.path.unlink()
        self.assertEqual(self.writer.write(self.records,self.core).outcome,"DENIED")
        self.assertFalse(self.path.exists())
        self.assertEqual(self.signer.calls,0)

    def test_corrupt_store_does_not_self_repair(self):
        self.path.write_bytes(b"synthetic-corrupt-database")
        self.assertEqual(self.writer.write(self.records,self.core).outcome,"DENIED")
        self.assertEqual(self.path.read_bytes(),b"synthetic-corrupt-database")
        self.assertEqual(self.signer.calls,0)

    def test_extra_schema_is_denied(self):
        with sqlite3.connect(self.path) as db: db.execute("CREATE TABLE unexpected (x TEXT)")
        self.assert_denied_without_signing(self.writer.write(self.records,self.core))

    def test_symlink_store_is_denied(self):
        moved=self.path.with_name("real.sqlite");self.path.rename(moved);self.path.symlink_to(moved)
        self.assertEqual(self.writer.write(self.records,self.core).outcome,"DENIED")
        self.assertEqual(self.signer.calls,0)

    def test_world_readable_store_is_denied(self):
        self.path.chmod(0o644)
        self.assertEqual(self.writer.write(self.records,self.core).outcome,"DENIED")
        self.assertEqual(self.signer.calls,0)

    def test_store_provision_never_replaces_existing(self):
        before=self.path.read_bytes()
        with self.assertRaises(FileExistsError):ReleaseTransactionStore.provision(self.path,self.state)
        self.assertEqual(self.path.read_bytes(),before)

    def test_missing_predecessor_is_not_genesis(self):
        state=dict(self.state,predecessor_hash="GENESIS")
        with self.assertRaises(ValueError):
            ReleaseTransactionStore.provision(Path(self.temp.name)/"other.sqlite",state)
        self.assertFalse((Path(self.temp.name)/"other.sqlite").exists())

    def test_reconcile_does_not_sign(self):
        result=self.writer.write(self.records,self.core)
        receipt=self.store.reconcile(result.transaction_id)
        self.assertEqual(receipt.outcome,"COMMITTED")
        self.assertEqual(receipt.output_digest,result.output_digest)
        self.assertEqual(self.signer.calls,1)

    def test_reconcile_missing_transaction_stays_unknown(self):
        self.assertEqual(self.store.reconcile(mark("absent")).outcome,"UNKNOWN")
        self.assertEqual(self.signer.calls,0)

    def test_reconcile_invalid_reference_does_not_echo_raw_input(self):
        result=self.store.reconcile("sensitive-untrusted-value")
        self.assertEqual(result.outcome,"UNKNOWN")
        self.assertIsNone(result.transaction_id)

    def test_authority_fence_held_until_after_commit(self):
        seen=[]
        original_commit=self.writer._commit
        def commit(db):
            self.assertTrue(self.source.fence_active)
            seen.append("commit")
            original_commit(db)
        def checkpoint(stage):
            if stage=="after_commit":
                self.assertTrue(self.source.fence_active)
                seen.append("after_commit")
        self.writer._commit=commit
        self.writer._checkpoint=checkpoint
        self.assertEqual(self.writer.write(self.records,self.core).outcome,"COMMITTED")
        self.assertEqual(seen,["commit","after_commit"])
        self.assertFalse(self.source.fence_active)
        self.assertEqual(self.source.fence_exits,1)

    def test_missing_authority_fence_does_not_sign(self):
        self.source.hold_fence=None
        self.assert_denied_without_signing(self.writer.write(self.records,self.core))

    def test_expired_authority_fence_does_not_sign(self):
        self.source.fence_mutate=lambda f:replace(f,valid_until="2026-11-07T12:00:00Z")
        self.assert_denied_without_signing(self.writer.write(self.records,self.core))

    def test_wrong_fence_binding_does_not_sign(self):
        self.source.fence_mutate=lambda f:replace(f,request_hash=mark("another-request"))
        self.assert_denied_without_signing(self.writer.write(self.records,self.core))

    def test_signer_failure_rolls_back(self):
        def fail(_):raise RuntimeError("untrusted private service message")
        self.signer.sign=fail
        result=self.writer.write(self.records,self.core)
        self.assertEqual(result.reason,"SIGNER_UNAVAILABLE")
        self.assertEqual(self.counts(),(0,0,0))

    def test_signer_verify_false_is_not_success(self):
        original_verify=self.signer.verify
        self.signer.verify=lambda raw,signature:False if raw==canonical_bytes(self.core) else original_verify(raw,signature)
        result=self.writer.write(self.records,self.core)
        self.assertEqual(result.reason,"SIGNER_OUTPUT_INVALID")
        self.assertEqual(self.counts(),(0,0,0))

    def test_same_nonce_survives_issuer_key_rotation(self):
        self.assertEqual(self.writer.write(self.records,self.core).outcome,"COMMITTED")
        state=self.store.state()
        core=self.successor_core(state)
        private=Ed25519PrivateKey.generate()
        public=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        identity=replace(self.fixture.identities["issuer"],key_id=public_key_id(public),public_key=public)
        with patch.dict(self.fixture.private,{"issuer":private}),patch.dict(self.fixture.identities,{"issuer":identity}):
            records,trust=self.chain(state=state,core=core)
        result=self.writer_for(authority_source=FixtureSource(records,trust,state)).write(records,core)
        self.assertEqual(result.reason,"NONCE_CONSUMED")
        self.assertEqual(self.counts(),(1,1,1))
        self.assertEqual(self.signer.calls,1)

    def test_hard_linked_store_denied(self):
        os.link(self.path,self.path.with_name("linked.sqlite"))
        self.assertEqual(self.writer.write(self.records,self.core).outcome,"DENIED")
        self.assertEqual(self.signer.calls,0)

    def test_reconcile_changed_output_stays_unknown(self):
        result=self.writer.write(self.records,self.core)
        with sqlite3.connect(self.path) as db:db.execute("UPDATE outputs SET output=?",(b"changed",))
        self.assertEqual(self.store.reconcile(result.transaction_id).outcome,"UNKNOWN")
        self.assertEqual(self.signer.calls,1)

    def test_authoritative_new_head_rejects_restored_old_store(self):
        old_bytes=self.path.read_bytes()
        self.assertEqual(self.writer.write(self.records,self.core).outcome,"COMMITTED")
        newer=self.store.state()
        self.path.write_bytes(old_bytes)
        self.source.observation=replace(self.source.observation,
            trust=replace(self.trust,head_hash=_hash(newer),sequence=newer["sequence"]))
        result=self.writer.write(self.records,self.core)
        self.assertEqual(result.outcome,"DENIED")
        self.assertEqual(self.signer.calls,1)
        # Restoring both source and DB is outside this fixture's proof.

    def test_source_change_after_signing_prevents_commit(self):
        def checkpoint(stage):
            if stage=="after_sign":
                self.source.observation=replace(self.source.observation,source_tree="f"*40)
        self.writer._checkpoint=checkpoint
        result=self.writer.write(self.records,self.core)
        self.assertEqual(result.reason,"SOURCE_OBSERVATION_MISMATCH")
        self.assertTrue(result.signer_attempted)
        self.assertEqual(self.counts(),(0,0,0))

    def test_sql_fence_blocks_competing_head_change_until_commit(self):
        def checkpoint(stage):
            if stage=="before_commit":
                with sqlite3.connect(self.path,timeout=0,isolation_level=None) as other:
                    with self.assertRaises(sqlite3.OperationalError):other.execute("BEGIN IMMEDIATE")
        self.writer._checkpoint=checkpoint
        self.assertEqual(self.writer.write(self.records,self.core).outcome,"COMMITTED")
        self.assertEqual(self.counts(),(1,1,1))

    def test_malformed_request_does_not_sign(self):
        records=dict(self.records,request=b'{"duplicate":1,"duplicate":2}')
        self.assert_denied_without_signing(self.writer.write(records,self.core))

    def test_wrong_output_algorithm_does_not_commit(self):
        self.signer.sign=lambda _:"ed25519:unsupported"
        result=self.writer.write(self.records,self.core)
        self.assertEqual(result.reason,"SIGNER_OUTPUT_INVALID")
        self.assertTrue(result.signer_attempted)
        self.assertEqual(self.counts(),(0,0,0))

    def test_invalid_hmac_does_not_commit(self):
        self.signer.sign=lambda _:"hmac-sha256:"+"0"*64
        result=self.writer.write(self.records,self.core)
        self.assertEqual(result.reason,"SIGNER_OUTPUT_INVALID")
        self.assertTrue(result.signer_attempted)
        self.assertEqual(self.counts(),(0,0,0))

    def test_request_key_list_cannot_bootstrap_authority_source(self):
        result=self.writer_for(authority_source={"keys":self.trust.identities}).write(self.records,self.core)
        self.assert_denied_without_signing(result)

    def test_missing_history_is_denied(self):
        core=dict(self.core);del core["release_history"]
        self.assert_denied_without_signing(self.writer.write(self.records,core))

    def test_empty_approved_history_is_denied(self):
        core=dict(self.core,release_history=[])
        records,trust=self.chain(core=core)
        result=self.writer_for(authority_source=FixtureSource(records,trust,self.state)).write(records,core)
        self.assertEqual(result.reason,"RELEASE_HISTORY_INVALID")
        self.assert_denied_without_signing(result)

    def test_forged_predecessor_signature_is_denied(self):
        previous=dict(self.core["release_history"][0],release_signature="hmac-sha256:"+"0"*64)
        core=dict(self.core,release_history=[previous])
        records,trust=self.chain(core=core)
        result=self.writer_for(authority_source=FixtureSource(records,trust,self.state)).write(records,core)
        self.assertEqual(result.reason,"PREDECESSOR_SIGNATURE_INVALID")
        self.assert_denied_without_signing(result)

    def test_unbound_predecessor_is_denied(self):
        previous=dict(self.core["release_history"][0],release_id="another-parent")
        payload=dict(previous);del payload["release_signature"]
        previous["release_signature"]="hmac-sha256:"+hmac.new(self.signer.material,canonical_bytes(payload),hashlib.sha256).hexdigest()
        core=dict(self.core,release_history=[previous])
        records,trust=self.chain(core=core)
        result=self.writer_for(authority_source=FixtureSource(records,trust,self.state)).write(records,core)
        self.assertEqual(result.reason,"RELEASE_HISTORY_INVALID")
        self.assert_denied_without_signing(result)

    def test_cross_tenant_predecessor_is_denied(self):
        previous=dict(self.core["release_history"][0],tenant_id="other-tenant")
        core=dict(self.core,release_history=[previous])
        records,trust=self.chain(core=core)
        result=self.writer_for(authority_source=FixtureSource(records,trust,self.state)).write(records,core)
        self.assertEqual(result.reason,"RELEASE_HISTORY_INVALID")
        self.assert_denied_without_signing(result)

    def test_oversized_history_is_denied(self):
        core=dict(self.core,release_history=self.core["release_history"]*33)
        records,trust=self.chain(core=core)
        result=self.writer_for(authority_source=FixtureSource(records,trust,self.state)).write(records,core)
        self.assertEqual(result.reason,"RELEASE_HISTORY_INVALID")
        self.assert_denied_without_signing(result)

    def test_signature_overhead_cannot_exceed_reconciliation_bound(self):
        core=dict(self.core,release_history=[{"padding":""}])
        base=len(canonical_bytes(core))
        core["release_history"][0]["padding"]="x"*(65536-40-base)
        self.assertLess(len(canonical_bytes(core)),65536)
        records,trust=self.chain(core=core)
        result=self.writer_for(authority_source=FixtureSource(records,trust,self.state)).write(records,core)
        self.assertEqual(result.reason,"RELEASE_CORE_INVALID")
        self.assert_denied_without_signing(result)

    def test_reconcile_wrong_budget_mapping_stays_unknown(self):
        result=self.writer.write(self.records,self.core)
        with sqlite3.connect(self.path) as db:db.execute("UPDATE budgets SET grant_hash=?",(mark("other-grant"),))
        self.assertEqual(self.store.reconcile(result.transaction_id).outcome,"UNKNOWN")
        self.assertEqual(self.signer.calls,1)

    @unittest.skipUnless("fork" in multiprocessing.get_all_start_methods(),"Linux fork validation only")
    def test_process_death_before_commit_rolls_back(self):
        writer=self.writer_for(fault="before_commit")
        writer.__class__=CrashWriter
        ctx=multiprocessing.get_context("fork")
        child=ctx.Process(target=writer.write,args=(self.records,self.core))
        child.start();child.join(timeout=15)
        if child.is_alive():child.terminate();child.join(timeout=5)
        self.assertEqual(child.exitcode,73)
        self.assertEqual(self.counts(),(0,0,0))
        self.assertEqual(self.store.state(),self.state)

    @unittest.skipUnless("fork" in multiprocessing.get_all_start_methods(),"Linux fork validation only")
    def test_process_death_after_commit_can_be_reconciled(self):
        writer=self.writer_for(fault="after_commit")
        writer.__class__=CrashWriter
        ctx=multiprocessing.get_context("fork")
        child=ctx.Process(target=writer.write,args=(self.records,self.core))
        child.start();child.join(timeout=15)
        if child.is_alive():child.terminate();child.join(timeout=5)
        self.assertEqual(child.exitcode,73)
        self.assertEqual(self.counts(),(1,1,1))
        transaction_id=_hash({"domain":"usbay.release_transaction_store.v1",
                              "request_hash":_hash(json.loads(self.records["request"]))})
        self.assertEqual(self.store.reconcile(transaction_id).outcome,"COMMITTED")


def fault_case(stage,expected,signed,counts,reconciled):
    def case(self):
        result=self.writer_for(fault=stage).write(self.records,self.core)
        self.assertEqual(result.outcome,expected)
        self.assertEqual(result.signer_attempted,signed)
        self.assertEqual(self.counts(),counts)
        if result.transaction_id:
            self.assertEqual(self.store.reconcile(result.transaction_id).outcome,reconciled)
        self.assertEqual(self.signer.calls,1 if signed else 0)
    return case


for stage,expected,signed,counts,reconciled in (
    ("before_sign","DENIED",False,(0,0,0),"UNKNOWN"),
    ("after_sign","DENIED",True,(0,0,0),"UNKNOWN"),
    ("before_commit","DENIED",True,(0,0,0),"UNKNOWN"),
    ("commit_before","UNKNOWN",True,(0,0,0),"UNKNOWN"),
    ("commit_after","UNKNOWN",True,(1,1,1),"COMMITTED"),
    ("after_commit","UNKNOWN",True,(1,1,1),"COMMITTED")):
    setattr(ReleaseTransactionWriterTests,"test_fault_"+stage,fault_case(stage,expected,signed,counts,reconciled))


def revoked_status_case(field):
    def case(self):
        def mutate(kind,payload):
            if kind=="status":payload[field]="REVOKED"
        records,trust=self.chain(mutate)
        source=FixtureSource(records,trust,self.state)
        self.assert_denied_without_signing(self.writer_for(authority_source=source).write(records,self.core))
    return case


for field in ("root_state","issuer_state","policy_state","owner_state"):
    setattr(ReleaseTransactionWriterTests,"test_signed_revoked_"+field,revoked_status_case(field))


if __name__=="__main__":unittest.main()
