"""Synthetic packages; exercise actual scanner/provenance code, never a server."""
from __future__ import annotations

import base64
from dataclasses import replace, FrozenInstanceError
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import gateway.app as gateway
from security import deployment_attestation as deployment
from security import runtime_artifact_authority as authority_module
from security.policy_registry import PolicyRegistryError
from security.runtime_artifact_authority import (
    MANIFEST_NAME, get_runtime_artifact_authority, load_runtime_artifact_authority,
)
from security.runtime_artifact_package import package_runtime_artifact, main as package_main
from security import runtime_artifact_provenance as provenance


def git(root, *arguments):
    return subprocess.run(
        ["git", "-C", str(root), *arguments], check=True, capture_output=True,
        env={
            "PATH": os.environ["PATH"], "HOME": str(root),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }, timeout=30,
    ).stdout.decode("ascii").strip()


class GitlessRuntimeIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="usbay-artifact-test-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.source = self.base / "source"
        self.source.mkdir()
        (self.source / "application.py").write_text("VALUE = 1\n")
        fixture_root = Path(__file__).resolve().parents[1]
        for item in deployment.POLICY_BUNDLE_FILES:
            target = self.source / item
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(fixture_root / item, target)
            target.chmod(0o644)
        git(self.source, "init", "-q")
        git(self.source, "add", "--", ".")
        git(
            self.source, "-c", "user.name=Synthetic Artifact Test",
            "-c", "user.email=synthetic@example.invalid", "-c", "commit.gpgsign=false",
            "commit", "-qm", "Synthetic integration fixture",
        )
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        self.key_id = provenance.public_key_id(self.public)
        self.trust = provenance.ProducerTrust(self.public, self.key_id, "test", "test")
        self.package = self.base / "package"
        package_runtime_artifact(
            self.source, self.package, signing_key=self.key,
            producer_key_id=self.key_id, producer_scope="test",
        )
        self.raw = (self.package / MANIFEST_NAME).read_bytes()
        self.manifest = json.loads(self.raw)
        self.environment = {
            "PATH": "/nonexistent", "USBAY_ENV": "test",
            "USBAY_RUNTIME_SOURCE_MANIFEST": MANIFEST_NAME,
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY": base64.b64encode(self.public).decode(),
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID": self.key_id,
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE": "test",
        }
        env = patch.dict(os.environ, self.environment, clear=True)
        env.start()
        self.addCleanup(env.stop)
        root_patch = patch.object(authority_module, "REPO_ROOT", self.package)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        cache_patch = patch.object(authority_module, "_runtime_authority", None)
        cache_patch.start()
        self.addCleanup(cache_patch.stop)
        old = Path.cwd()
        os.chdir(self.package)
        self.addCleanup(os.chdir, old)
        self.release_path = self.base / "governance_release.json"
        manifest = {
            "release_id": "synthetic-integration",
            "deployment_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "git_commit": self.manifest["source_commit"],
            "policy_bundle_hash": deployment.policy_bundle_hash(),
            "previous_release_hash": "GENESIS", "tenant_id": "t1",
            "activating_node_id": deployment._canonical_activating_node_id(),
        }
        manifest["release_signature"] = deployment.sign_release_manifest(manifest)
        self.release_path.write_text(json.dumps(manifest))
        os.environ["USBAY_GOVERNANCE_RELEASE_PATH"] = str(self.release_path)

    def authority(self):
        return get_runtime_artifact_authority()

    def resign(self, changes):
        manifest = dict(self.manifest, **changes)
        manifest["manifest_digest"] = provenance.manifest_digest(manifest)
        manifest["signature"] = base64.b64encode(
            self.key.sign(provenance.signature_payload(manifest)),
        ).decode()
        (self.package / MANIFEST_NAME).write_bytes(provenance.canonical_bytes(manifest))

    def test_valid_gitless_package_scanner_and_provenance_share_authority(self):
        self.assertFalse((self.package / ".git").exists())
        self.assertIsNone(shutil.which("git"))
        with patch.object(subprocess, "run", side_effect=AssertionError("Runtime subprocess forbidden")):
            authority = self.authority()
            self.assertTrue(gateway.validate_no_forbidden_runtime_files(
                self.package, artifact_authority=authority,
            ))
            deployment_authority = deployment.resolve_runtime_provenance_authority(
                artifact_authority=authority,
            )
            self.assertIs(deployment_authority.artifact_authority, authority)
            self.assertIs(self.authority(), authority)
            self.assertEqual(deployment.current_git_commit(), authority.verified.source_commit)
            self.assertEqual(deployment_authority.context_dict()["current_commit"], authority.verified.source_commit)
            deployment.assert_runtime_provenance_authority(deployment_authority)

    def test_bounded_actual_startup_reaches_next_independent_validator(self):
        class BoundaryReached(RuntimeError):
            pass
        artifact = self.authority()
        seen = []
        scanner = gateway.validate_no_forbidden_runtime_files
        resolver = gateway.runtime_provenance_authority

        def scanned(*args, **kwargs):
            seen.append(kwargs["artifact_authority"])
            return scanner(*args, **kwargs)

        def resolved(*args, **kwargs):
            seen.append(kwargs["artifact_authority"])
            return resolver(*args, **kwargs)

        with (
            patch.object(gateway, "REPO_ROOT", self.package),
            patch.object(gateway, "validate_no_forbidden_runtime_files", side_effect=scanned),
            patch.object(gateway, "runtime_provenance_authority", side_effect=resolved),
            patch.object(gateway, "load_tenant_policy", side_effect=BoundaryReached("controlled test boundary")),
            patch.object(subprocess, "run", side_effect=AssertionError("Runtime subprocess forbidden")),
        ):
            with self.assertRaises(BoundaryReached):
                gateway.validate_policy_registry_startup()
        self.assertEqual(seen, [artifact, artifact])

    def test_missing_manifest_denied(self):
        (self.package / MANIFEST_NAME).unlink()
        with self.assertRaises(provenance.RuntimeArtifactError):
            self.authority()

    def test_unsigned_manifest_denied(self):
        manifest = dict(self.manifest)
        manifest.pop("signature")
        (self.package / MANIFEST_NAME).write_text(json.dumps(manifest))
        with self.assertRaises(provenance.RuntimeArtifactError):
            self.authority()

    def test_wrong_key_denied(self):
        other = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        os.environ["USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY"] = base64.b64encode(other).decode()
        os.environ["USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID"] = provenance.public_key_id(other)
        with self.assertRaises(provenance.RuntimeArtifactError):
            self.authority()

    def test_wrong_key_id_denied(self):
        os.environ["USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID"] = "sha256:" + "0" * 64
        with self.assertRaises(provenance.RuntimeArtifactError):
            self.authority()

    def test_manifest_mutation_after_scan_denied(self):
        authority = self.authority()
        gateway.validate_no_forbidden_runtime_files(self.package, artifact_authority=authority)
        self.resign({"manifest_id": "f" * 32})
        with self.assertRaises(deployment.DeploymentAttestationError):
            deployment.resolve_runtime_provenance_authority(artifact_authority=authority)

    def test_file_mutation_between_consumers_denied(self):
        authority = self.authority()
        gateway.validate_no_forbidden_runtime_files(self.package, artifact_authority=authority)
        (self.package / "application.py").write_text("VALUE = 2\n")
        with self.assertRaises(deployment.DeploymentAttestationError):
            deployment.resolve_runtime_provenance_authority(artifact_authority=authority)

    def test_deleted_managed_file_denied(self):
        (self.package / "application.py").unlink()
        with self.assertRaises(provenance.RuntimeArtifactError):
            self.authority()

    def test_unexpected_governed_file_denied(self):
        (self.package / "injected.py").write_text("VALUE = 2\n")
        with self.assertRaisesRegex(provenance.RuntimeArtifactError, "unexpected_governed_file"):
            self.authority()

    def test_new_governed_file_after_scan_denied(self):
        authority = self.authority()
        (self.package / "injected.py").write_text("VALUE = 2\n")
        with self.assertRaises(deployment.DeploymentAttestationError):
            deployment.resolve_runtime_provenance_authority(artifact_authority=authority)

    def test_unsafe_symlink_denied(self):
        path = self.package / "application.py"
        path.unlink()
        path.symlink_to(self.release_path)
        with self.assertRaises(provenance.RuntimeArtifactError):
            self.authority()

    def test_new_symlink_after_scan_denied(self):
        authority = self.authority()
        (self.package / "unexpected-link").symlink_to(self.release_path)
        with self.assertRaises(deployment.DeploymentAttestationError):
            deployment.resolve_runtime_provenance_authority(artifact_authority=authority)

    def test_path_traversal_denied_even_with_valid_signature(self):
        entries = [dict(item) for item in self.manifest["managed_files"]]
        entries[0]["path"] = "../escape"
        self.resign({
            "managed_files": entries,
            "managed_set_hash": hashlib.sha256(provenance.canonical_bytes(entries)).hexdigest(),
        })
        with self.assertRaises(provenance.RuntimeArtifactError):
            self.authority()

    def test_unsigned_source_commit_mutation_denied(self):
        manifest = dict(self.manifest, source_commit="f" * 40)
        (self.package / MANIFEST_NAME).write_text(json.dumps(manifest))
        with self.assertRaises(provenance.RuntimeArtifactError):
            self.authority()

    def test_unsigned_source_tree_mutation_denied(self):
        manifest = dict(self.manifest, source_tree_reference="f" * 40)
        (self.package / MANIFEST_NAME).write_text(json.dumps(manifest))
        with self.assertRaises(provenance.RuntimeArtifactError):
            self.authority()

    def test_managed_set_mutation_denied(self):
        self.resign({"managed_set_hash": "0" * 64})
        with self.assertRaises(provenance.RuntimeArtifactError):
            self.authority()

    def test_production_test_producer_denied(self):
        os.environ["USBAY_ENV"] = "production"
        with self.assertRaisesRegex(provenance.RuntimeArtifactError, "test_producer_denied"):
            self.authority()

    def test_production_missing_trust_denied_before_git(self):
        os.environ.clear()
        os.environ["USBAY_ENV"] = "production"
        with patch.object(subprocess, "run", side_effect=AssertionError("Git forbidden")):
            with self.assertRaisesRegex(provenance.RuntimeArtifactError, "trust_unavailable"):
                gateway.validate_policy_registry_startup()

    def test_release_commit_must_match_signed_artifact(self):
        manifest = json.loads(self.release_path.read_text())
        manifest["git_commit"] = "f" * 40
        manifest["release_signature"] = deployment.sign_release_manifest(manifest)
        self.release_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(deployment.DeploymentAttestationError, "git_commit_mismatch"):
            deployment.resolve_runtime_provenance_authority(artifact_authority=self.authority())

    def test_immutable_verified_object_and_forged_context_denied(self):
        authority = self.authority()
        with self.assertRaises(FrozenInstanceError):
            authority.verified = replace(authority.verified, source_commit="f" * 40)
        forged = replace(authority, verified=replace(authority.verified, source_commit="f" * 40))
        with self.assertRaises(provenance.RuntimeArtifactError):
            forged.assert_fresh()

    def test_default_hmac_does_not_replace_producer_trust(self):
        os.environ.pop("USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY")
        with self.assertRaises(provenance.RuntimeArtifactError):
            self.authority()

    def test_trust_configuration_change_between_consumers_denied(self):
        authority = self.authority()
        gateway.validate_no_forbidden_runtime_files(self.package, artifact_authority=authority)
        os.environ.pop("USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY")
        with self.assertRaises(deployment.DeploymentAttestationError):
            deployment.resolve_runtime_provenance_authority(artifact_authority=authority)

    def test_test_authority_cannot_be_reused_in_production(self):
        authority = self.authority()
        os.environ["USBAY_ENV"] = "production"
        with self.assertRaises(deployment.DeploymentAttestationError):
            deployment.resolve_runtime_provenance_authority(artifact_authority=authority)
        with self.assertRaises(PolicyRegistryError):
            gateway.validate_no_forbidden_runtime_files(self.package, artifact_authority=authority)

    def test_cached_manifest_path_traversal_denied(self):
        self.authority()
        os.environ["USBAY_RUNTIME_SOURCE_MANIFEST"] = "./" + MANIFEST_NAME
        with self.assertRaises(provenance.RuntimeArtifactError):
            self.authority()

    def test_existing_forbidden_file_rules_remain_active(self):
        tmp = self.package / "tmp"
        tmp.mkdir()
        (tmp / "private.key").write_text("synthetic-non-secret")
        with self.assertRaisesRegex(PolicyRegistryError, "forbidden_runtime_file_present"):
            gateway.validate_no_forbidden_runtime_files(self.package, artifact_authority=self.authority())

    def test_packager_missing_key_does_not_create_output(self):
        output = self.base / "no-key-output"
        with self.assertRaises(provenance.RuntimeArtifactError):
            package_runtime_artifact(
                self.source, output, signing_key=None,
                producer_key_id=self.key_id, producer_scope="test",
            )
        self.assertFalse(output.exists())

    def test_packager_never_overwrites_existing_destination(self):
        with self.assertRaises(provenance.RuntimeArtifactError):
            package_runtime_artifact(
                self.source, self.package, signing_key=self.key,
                producer_key_id=self.key_id, producer_scope="test",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
