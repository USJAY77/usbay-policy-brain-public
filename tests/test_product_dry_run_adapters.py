"""All issuer keys, approvals and databases below are synthetic test fixtures."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import pytest

pytestmark = pytest.mark.governance

from audit.hash_chain import verify_chain
from governance.approval_issuance import generate_issuer_keypair, sign_issuance
from governance.connector_framework import sha256_payload
from governance.product_dry_run import ProductDryRun
from governance.product_dry_run_adapters import (
    PersistentDryRunAttempts, ProductAuditWriter, SignedDryRunApprovals,
)


class IntegratedDryRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="usbay-product-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        from tests.test_product_dry_run import ProductDryRunTests
        self.fixture = ProductDryRunTests()
        self.fixture.setUp()
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.request = replace(self.fixture.request, tenant="t1")
        self.db = self.root / "approvals.sqlite"
        private, public = generate_issuer_keypair()
        self.payload = {
            "issuer_id": "synthetic-reviewer", "actor_id": self.request.actor,
            "authorization_id": "offline-product-dry-run-v1",
            "binding_hash": self.request.binding,
            "issued_at": (self.now - timedelta(seconds=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (self.now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "nonce": "synthetic-nonce", "tenant_reference": "t1",
            "execution_id": self.request.action_id,
        }
        self.signature = sign_issuance(private, self.payload)
        with sqlite3.connect(self.db) as conn:
            conn.executescript("CREATE TABLE issuers(id TEXT PRIMARY KEY, public_key TEXT, tenant TEXT, capability TEXT, revoked INTEGER); CREATE TABLE approvals(binding TEXT PRIMARY KEY,payload TEXT,signature TEXT,revoked INTEGER);")
            conn.execute("INSERT INTO issuers VALUES(?,?,?,?,0)",
                         ("synthetic-reviewer", public, "t1", "governance_review"))
            conn.execute("INSERT INTO approvals VALUES(?,?,?,0)",
                         (self.request.binding, json.dumps(self.payload), self.signature))

    def boundary(self, *, approvals=None, audit=None):
        return ProductDryRun(
            registry=self.fixture.registry,
            tenant_bindings={self.request.actor: ("t1",), self.request.agent: ("t1",)},
            policy_version=self.request.policy_version, grants={},
            approval_source=approvals or SignedDryRunApprovals(self.db),
            consume_attempt=PersistentDryRunAttempts(self.root / "attempts.sqlite"),
            audit=audit or ProductAuditWriter(tenant="t1", audit_tenant="t2", policy_hash="a" * 64, path=self.root / "audit.json"),
            clock=lambda: self.now,
        )

    def test_signed_approval_and_real_signed_audit_chain(self):
        result = self.boundary().prepare(self.request)
        self.assertEqual(result["decision"], "PREPARED_DRY_RUN")
        self.assertTrue(verify_chain(self.root / "audit.json"))
        contents = (self.root / "audit.json").read_text()
        self.assertNotIn(self.request.actor, contents)
        self.assertNotIn(self.request.tenant, contents)
        self.assertIn('"tenant_id": "t2"', contents)
        self.assertNotIn(self.signature, contents)
        self.assertFalse(result["execution_authorized"])

    def test_missing_database_blocks_without_creation(self):
        missing = self.root / "missing.sqlite"
        result = self.boundary(approvals=SignedDryRunApprovals(missing)).prepare(self.request)
        self.assertEqual(result["decision"], "BLOCKED")
        self.assertFalse(missing.exists())
        self.assertTrue(verify_chain(self.root / "audit.json"))

    def test_unsigned_or_tampered_approval_blocks(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE approvals SET signature=?", ("00" * 64,))
        self.assertEqual(self.boundary().prepare(self.request)["decision"], "BLOCKED")

    def test_tampered_signed_binding_blocks(self):
        self.payload["actor_id"] = "different-actor"
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE approvals SET payload=?", (json.dumps(self.payload),))
        self.assertEqual(self.boundary().prepare(self.request)["decision"], "BLOCKED")

    def test_issuer_revocation_is_reread_after_boundary_creation(self):
        boundary = self.boundary()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE issuers SET revoked=1")
        self.assertEqual(boundary.prepare(self.request)["decision"], "BLOCKED")

    def test_approval_revocation_is_reread(self):
        boundary = self.boundary()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE approvals SET revoked=1")
        self.assertEqual(boundary.prepare(self.request)["decision"], "BLOCKED")

    def test_issuer_tenant_and_capability_scope_block(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE issuers SET tenant='t2', capability='email_send'")
        self.assertEqual(self.boundary().prepare(self.request)["decision"], "BLOCKED")

    def test_replay_blocks_after_new_boundary_instance(self):
        self.assertEqual(self.boundary().prepare(self.request)["decision"], "PREPARED_DRY_RUN")
        self.assertIn("PERSISTENT_REPLAY_BLOCKED", self.boundary().prepare(self.request)["blockers"])

    def test_replay_survives_fresh_python_process(self):
        self.assertEqual(self.boundary().prepare(self.request)["decision"], "PREPARED_DRY_RUN")
        result = subprocess.run([
            sys.executable, "-c",
            "from pathlib import Path; from governance.product_dry_run_adapters import PersistentDryRunAttempts; import sys; print(PersistentDryRunAttempts(Path(sys.argv[1]))(sys.argv[2],sys.argv[3]))",
            str(self.root / "attempts.sqlite"), sha256_payload(self.request.action_id), self.request.binding,
        ], capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), "False")

    def test_real_chain_tampering_is_detected(self):
        self.assertEqual(self.boundary().prepare(self.request)["decision"], "PREPARED_DRY_RUN")
        path = self.root / "audit.json"
        chain = json.loads(path.read_text())
        chain[0]["decision"]["decision"] = "TAMPERED"
        path.write_text(json.dumps(chain))
        self.assertFalse(verify_chain(path))

    def test_distinct_requests_can_use_same_persistent_store(self):
        self.assertEqual(self.boundary().prepare(self.request)["decision"], "PREPARED_DRY_RUN")
        attempts = PersistentDryRunAttempts(self.root / "attempts.sqlite")
        self.assertTrue(attempts(sha256_payload("different-action"), sha256_payload("different-binding")))

    def test_idle_store_accepts_new_work_and_preserves_old_history(self):
        path = self.root / "idle.sqlite"
        old = (sha256_payload("old-action"), sha256_payload("old-binding"))
        self.assertTrue(PersistentDryRunAttempts(path, clock=lambda: 1000.0)(*old))
        reopened = PersistentDryRunAttempts(path, clock=lambda: 1000.0 + 86400 * 30)
        self.assertFalse(reopened(*old))
        self.assertTrue(reopened(sha256_payload("new-action"), sha256_payload("new-binding")))
        self.assertFalse(reopened(*old))

    def test_idle_policy_does_not_bypass_integrity_or_backward_clock(self):
        path = self.root / "integrity.sqlite"
        self.assertTrue(PersistentDryRunAttempts(path, clock=lambda: 1000.0)(sha256_payload("a"), sha256_payload("b")))
        self.assertFalse(PersistentDryRunAttempts(path, clock=lambda: 999.0)(sha256_payload("c"), sha256_payload("d")))
        with sqlite3.connect(path) as conn:
            conn.execute("UPDATE policy_authority_replay_metadata SET state_hash='tampered'")
        self.assertFalse(PersistentDryRunAttempts(path, clock=lambda: 2000.0)(sha256_payload("c"), sha256_payload("d")))

    def test_audit_partition_must_be_registered_and_distinct(self):
        with self.assertRaises(ValueError):
            ProductAuditWriter(tenant="t1", audit_tenant="t1", policy_hash="a" * 64, path=self.root / "audit.json")
        with self.assertRaises(Exception):
            ProductAuditWriter(tenant="t1", audit_tenant="unregistered", policy_hash="a" * 64, path=self.root / "audit.json")

    def test_audit_failure_burns_persistent_attempt(self):
        def fail(_):
            raise OSError("synthetic disk error")
        self.assertIn("AUDIT_FAILED", self.boundary(audit=fail).prepare(self.request)["blockers"])
        self.assertIn("PERSISTENT_REPLAY_BLOCKED", self.boundary().prepare(self.request)["blockers"])

    def test_audit_adapter_rejects_cross_tenant_and_live_flags(self):
        writer = ProductAuditWriter(tenant="t1", audit_tenant="t2", policy_hash="a" * 64, path=self.root / "audit.json")
        for event in (
            {"schema": "usbay.product_dry_run.v1", "request_hash": "b" * 64,
             "action_hash": "c" * 64, "decision": "BLOCKED", "blockers": [],
             "tenant_hash": sha256_payload("t2"), "execution_authorized": False, "external_mutation_performed": False},
            {"schema": "usbay.product_dry_run.v1", "request_hash": "b" * 64,
             "action_hash": "c" * 64, "decision": "BLOCKED", "blockers": [],
             "tenant_hash": sha256_payload("t1"), "execution_authorized": True, "external_mutation_performed": False},
        ):
            with self.assertRaises(ValueError):
                writer(event)
        self.assertFalse((self.root / "audit.json").exists())

    def test_audit_adapter_rejects_extra_payload_and_freeform_codes(self):
        writer = ProductAuditWriter(tenant="t1", audit_tenant="t2", policy_hash="a" * 64, path=self.root / "audit.json")
        event = {"schema": "usbay.product_dry_run.v1", "request_hash": "b" * 64,
                 "action_hash": "c" * 64, "tenant_hash": sha256_payload("t1"),
                 "decision": "BLOCKED", "blockers": [],
                 "execution_authorized": False, "external_mutation_performed": False}
        for update in ({"body": "synthetic private mail"}, {"blockers": ["synthetic private mail"]},
                       {"request_hash": "synthetic private mail"}):
            with self.assertRaises(ValueError):
                writer({**event, **update})
        self.assertFalse((self.root / "audit.json").exists())


if __name__ == "__main__":
    unittest.main()

