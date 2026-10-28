"""Synthetic offline boundary tests; no provider, mailbox or trading account."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import unittest
import pytest

pytestmark = pytest.mark.governance

from control_plane.agent_registry import (
    AgentRegistry, AgentHealth, ApprovalState, AuditState,
)
from governance.connector_framework import sha256_payload
from governance.product_dry_run import DryRunGrant, DryRunRequest, ProductDryRun


class ProductDryRunTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 28, tzinfo=timezone.utc)
        self.registry = AgentRegistry()
        self.registry.register("Governance Agent")
        self.registry.set_health("Governance Agent", AgentHealth.HEALTHY)
        self.registry.set_approval_state("Governance Agent", ApprovalState.APPROVED)
        self.registry.set_audit_state("Governance Agent", AuditState.EVIDENCE_READY)
        self.registry.enable("Governance Agent")
        self.request = DryRunRequest(
            "synthetic-action", "synthetic-actor", "Governance Agent", "tenant-a",
            "governance_review", "synthetic-policy-v1", "a" * 64, "b" * 64,
        )
        self.grant = DryRunGrant(
            self.request.binding, "synthetic-reviewer", self.now - timedelta(minutes=1),
            self.now + timedelta(minutes=5),
        )
        self.events = []

    def audit(self, event):
        self.events.append(event)
        return {"decision": "PASS", "audit_hash": sha256_payload(event)}

    def boundary(self, *, grant=None, audit=None, tenants=None):
        return ProductDryRun(
            registry=self.registry,
            tenant_bindings=tenants if tenants is not None else {
                "synthetic-actor": ("tenant-a",), "Governance Agent": ("tenant-a",),
            },
            policy_version="synthetic-policy-v1",
            grants={self.request.binding: grant or self.grant},
            audit=audit or self.audit, clock=lambda: self.now,
        )

    def test_offline_preparation_is_not_execution_authority(self):
        result = self.boundary().prepare(self.request)
        self.assertEqual(result["decision"], "PREPARED_DRY_RUN")
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["external_mutation_performed"])
        self.assertEqual(len(self.events), 1)

    def test_request_changes_invalidate_grant(self):
        changes = {"actor": "other", "agent": "EURIA", "tenant": "tenant-b",
                   "capability": "email_send", "policy_version": "other",
                   "target_hash": "c" * 64, "payload_hash": "d" * 64,
                   "action_id": "other", "dry_run": False}
        for field, value in changes.items():
            with self.subTest(field=field):
                result = self.boundary().prepare(replace(self.request, **{field: value}))
                self.assertEqual(result["decision"], "BLOCKED")
                self.assertIn("SCOPED_REVIEW_MISSING_OR_INVALID", result["blockers"])

    def test_missing_actor_or_agent_tenant_blocks(self):
        for tenant_map in ({}, {"synthetic-actor": ("tenant-a",)}, {"Governance Agent": ("tenant-a",)}):
            with self.subTest(tenant_map=tenant_map):
                self.assertEqual(self.boundary(tenants=tenant_map).prepare(self.request)["decision"], "BLOCKED")

    def test_agent_state_changes_block_existing_grant(self):
        for mutation in (
            lambda: self.registry.disable("Governance Agent"),
            lambda: self.registry.set_health("Governance Agent", AgentHealth.UNKNOWN),
            lambda: self.registry.set_approval_state("Governance Agent", ApprovalState.DENIED),
            lambda: self.registry.set_audit_state("Governance Agent", AuditState.EVIDENCE_INVALID),
        ):
            with self.subTest(mutation=mutation):
                self.setUp()
                boundary = self.boundary()
                mutation()
                self.assertIn("AGENT_NOT_READY_OR_CAPABILITY_DENIED", boundary.prepare(self.request)["blockers"])

    def test_revoked_expired_future_naive_or_self_review_blocks(self):
        grants = (
            replace(self.grant, revoked=True),
            replace(self.grant, expires_at=self.now),
            replace(self.grant, issued_at=self.now + timedelta(seconds=1)),
            replace(self.grant, issued_at=self.now.replace(tzinfo=None)),
            replace(self.grant, reviewer=self.request.actor),
            replace(self.grant, reviewer=self.request.agent),
            replace(self.grant, reviewer=""),
            replace(self.grant, request_binding="0" * 64),
        )
        for grant in grants:
            with self.subTest(grant=grant):
                self.assertEqual(self.boundary(grant=grant).prepare(self.request)["decision"], "BLOCKED")

    def test_missing_grant_blocks(self):
        boundary = self.boundary()
        boundary.grants.clear()
        self.assertIn("SCOPED_REVIEW_MISSING_OR_INVALID", boundary.prepare(self.request)["blockers"])

    def test_replay_and_payload_change_cannot_reuse_action_id(self):
        boundary = self.boundary()
        self.assertEqual(boundary.prepare(self.request)["decision"], "PREPARED_DRY_RUN")
        for request in (self.request, replace(self.request, payload_hash="c" * 64)):
            self.assertIn("ACTION_ID_REUSED", boundary.prepare(request)["blockers"])

    def test_concurrent_identical_requests_have_one_preparation(self):
        boundary = self.boundary()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(boundary.prepare, [self.request] * 16))
        self.assertEqual(sum(x["decision"] == "PREPARED_DRY_RUN" for x in results), 1)
        self.assertEqual(len(self.events), 16)

    def test_audit_failure_blocks_and_burns_attempt_id(self):
        def fail(_):
            raise OSError("synthetic failure")
        boundary = self.boundary(audit=fail)
        self.assertIn("AUDIT_FAILED", boundary.prepare(self.request)["blockers"])
        boundary.audit = self.audit
        self.assertIn("ACTION_ID_REUSED", boundary.prepare(self.request)["blockers"])

    def test_invalid_audit_receipts_block(self):
        for receipt in (None, {}, {"decision": "PASS", "audit_hash": "fake"},
                        {"decision": "FAIL", "audit_hash": "a" * 64}):
            with self.subTest(receipt=receipt):
                self.assertIn("AUDIT_FAILED", self.boundary(audit=lambda _: receipt).prepare(self.request)["blockers"])

    def test_audit_and_results_contain_no_raw_identifiers_or_grants(self):
        result = self.boundary().prepare(self.request)
        serialized = json.dumps([result, self.events])
        for secret in (self.request.actor, self.request.agent, self.request.tenant,
                       self.request.action_id, self.grant.reviewer):
            self.assertNotIn(secret, serialized)

    def test_malformed_hashes_and_empty_fields_block(self):
        for field in ("actor", "tenant", "policy_version", "action_id", "target_hash", "payload_hash"):
            with self.subTest(field=field):
                result = self.boundary().prepare(replace(self.request, **{field: ""}))
                self.assertEqual(result["decision"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
