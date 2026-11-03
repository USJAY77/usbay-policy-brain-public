"""Run only by the bounded runner inside an exact, test-signed candidate package."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

# Collection outside the opt-in isolated runner must not import the app or
# overwrite any real audit/replay state. This is not an OS sandbox.
_cwd = Path.cwd().resolve()
if (
    os.environ.get("USBAY_BOUNDED_EXTENDED_STARTUP") != "1"
    or not str(_cwd).startswith("/tmp/usbay-gitless-validation-")
    or _cwd.name != "full-package" or (_cwd / ".git").exists()
):
    raise unittest.SkipTest("requires the bounded, separate gitless candidate-package runner")

import gateway.app as gateway
from security import runtime_artifact_authority
from security import tenant_context
from security.decision_store import DecisionStoreError
from security.persistent_nonce_store import (
    LocalPersistentNonceStore, PersistentNonceStoreError, initialize_persistent_nonce_store,
)
from security.policy_registry import PolicyRegistryError
from security.runtime_artifact_provenance import RuntimeArtifactError
from audit.immutable_ledger import LedgerIntegrityError, ledger_path_for

spec = importlib.util.spec_from_file_location(
    "synthetic_startup_support",
    Path(__file__).resolve().parents[1] / "tools/startup_evidence_support.py",
)
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


class ExtendedStartupEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="extended-startup-fixture-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.configuration = support.configured_startup(self.directory / "registry")
        self.paths = self.configuration.__enter__()
        self.addCleanup(self.configuration.__exit__, None, None, None)
        # Exercise the actual ledger validator with a real empty genesis store.
        self.ledger = ledger_path_for(Path("tmp/audit_chain.json"))
        self.ledger.parent.mkdir(parents=True, exist_ok=True)
        self.ledger.write_text("")
        self.addCleanup(self.ledger.unlink, missing_ok=True)
        self.subprocess_guard = patch(
            "subprocess.run", side_effect=AssertionError("runtime Git/process forbidden"),
        )
        self.subprocess_guard.start()
        self.addCleanup(self.subprocess_guard.stop)

    def test_full_lifespan_runs_real_startup_sequence(self):
        trace = support.observe_startup()
        completed = [item.removesuffix(":passed") for item in trace if item.endswith(":passed")]
        self.assertEqual(completed, [
            "validate_no_forbidden_runtime_files", "runtime_provenance_authority",
            "load_tenant_policy", "validate_replay_policy_startup",
            "validate_hydra_consensus_startup", "assert_startup_release_integrity",
            "validate_runtime_governance_health", "assert_ledger_valid", "load_policy_registry",
        ])
        self.assertEqual(trace[-2:], ["lifespan:yielded", "lifespan:exited"])
        self.assertFalse(Path(".git").exists())
        self.assertEqual(os.environ["PATH"], "/nonexistent")
        evidence = Path(os.environ["USBAY_VALIDATION_EVIDENCE"])
        support.write_json(evidence / "full-startup-trace.json", {
            "NON_PRODUCTION": True, "trace": trace,
            "endpoint": "lifespan_exited_after_all_current_startup_validators",
            "request_identity_provisioned": False,
        })

    def test_invalid_tenant_policy_stops_startup(self):
        directory = self.directory / "tenant"
        support.write_json(directory / "governance/tenant_policy.json", {})
        with patch.object(tenant_context, "DEFAULT_TENANT_POLICY_ROOT", directory):
            with self.assertRaises(tenant_context.TenantIsolationError):
                support.observe_startup()

    def test_replay_fail_open_configuration_stops_startup(self):
        with patch.dict(os.environ, {"USBAY_REPLAY_FAIL_CLOSED": "false"}):
            with self.assertRaisesRegex(DecisionStoreError, "invalid_replay_policy"):
                support.observe_startup()

    def test_invalid_hydra_roles_stop_startup(self):
        with patch.object(gateway, "EXPECTED_NODE_ROLES", {}):
            with self.assertRaisesRegex(DecisionStoreError, "invalid_hydra_consensus_roles"):
                support.observe_startup()

    def test_corrupt_ledger_stops_startup(self):
        self.ledger.write_text("invalid-synthetic-ledger")
        with self.assertRaisesRegex(LedgerIntegrityError, "ledger_integrity_invalid"):
            support.observe_startup()

    def test_wrong_policy_signature_stops_startup(self):
        self.paths["POLICY_REGISTRY_SIGNATURE_PATH"].write_text("not-a-signature")
        with self.assertRaisesRegex(PolicyRegistryError, "signature_invalid"):
            support.observe_startup()

    def test_revoked_policy_key_stops_startup(self):
        config = json.loads(self.paths["POLICY_KEY_CONFIG_PATH"].read_text())
        config["revoked_keys"] = config["active_keys"]
        support.write_json(self.paths["POLICY_KEY_CONFIG_PATH"], config)
        with self.assertRaisesRegex(PolicyRegistryError, "public_key_revoked"):
            support.observe_startup()

    def test_policy_authority_role_mismatch_stops_startup(self):
        authority = json.loads(self.paths["POLICY_AUTHORITY_PATH"].read_text())
        authority["policy_author"] = "different-synthetic-author"
        support.write_json(self.paths["POLICY_AUTHORITY_PATH"], authority)
        with self.assertRaisesRegex(PolicyRegistryError, "unauthorized_policy_change"):
            support.observe_startup()

    def test_request_identity_is_not_manufactured_by_successful_startup(self):
        support.observe_startup()
        self.assertIs(
            gateway.evidence_export_identity_verifier,
            gateway.unavailable_evidence_export_identity_verifier,
        )

    def test_persistent_replay_initialization_and_reopen(self):
        from datetime import datetime, timezone
        path = self.directory / "nonces.json"
        missing = LocalPersistentNonceStore(path)
        with self.assertRaises(PersistentNonceStoreError):
            missing.lookup("a" * 64)
        initialize_persistent_nonce_store(path)
        now = datetime.now(timezone.utc)
        timestamp = now.isoformat()
        nonce = hashlib.sha256(b"synthetic-nonce-only").hexdigest()
        store = LocalPersistentNonceStore(path, now_fn=lambda: now.timestamp())
        first = store.reserve(nonce, decision_id="synthetic-decision", timestamp=timestamp)
        second = LocalPersistentNonceStore(path, now_fn=lambda: now.timestamp()).reserve(
            nonce, decision_id="synthetic-decision", timestamp=timestamp,
        )
        self.assertNotEqual(first, second)
        self.assertEqual(first["state"], "reserved")
        self.assertEqual(second["state"], "replay")

    def test_corrupt_persistent_replay_store_denied(self):
        path = self.directory / "nonces.json"
        path.write_text("invalid-json")
        with self.assertRaises(PersistentNonceStoreError):
            LocalPersistentNonceStore(path).lookup("a" * 64)

    def test_artifact_identity_changes_on_unmanaged_output(self):
        _, before = support.artifact_descriptor(Path.cwd())
        output = Path("tmp/synthetic-state.json")
        output.write_text("{}")
        try:
            _, after = support.artifact_descriptor(Path.cwd())
        finally:
            output.unlink()
        self.assertNotEqual(hashlib.sha256(before).hexdigest(), hashlib.sha256(after).hexdigest())

    def test_symlink_runtime_root_denied(self):
        authority = runtime_artifact_authority.get_runtime_artifact_authority()
        path = self.directory / "symlink"
        path.symlink_to(authority.root)
        # No source mutation: verify the original root remains mandatory.
        with self.assertRaisesRegex(RuntimeArtifactError, "root_invalid"):
            runtime_artifact_authority.load_runtime_artifact_authority(
                path, trust=authority._trust,
            )
