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

    def test_enforcement_source_identity_uses_shared_artifact_authority(self):
        from runtime import enforcement_gateway

        artifact = self.authority()
        with (
            patch.object(enforcement_gateway, "ROOT", self.package),
            patch.object(subprocess, "run", side_effect=AssertionError("Runtime subprocess forbidden")),
        ):
            self.assertEqual(enforcement_gateway._git_commit_hash(), artifact.verified.source_commit)
            self.assertIs(self.authority(), artifact)
            (self.package / "application.py").write_text("changed runtime bytes")
            with self.assertRaises(provenance.RuntimeArtifactError):
                enforcement_gateway._git_commit_hash()

    def test_enforcement_missing_manifest_never_falls_back_to_git(self):
        from runtime import enforcement_gateway

        (self.package / MANIFEST_NAME).unlink()
        with (
            patch.object(enforcement_gateway, "ROOT", self.package),
            patch.object(subprocess, "run", side_effect=AssertionError("Runtime subprocess forbidden")),
        ):
            with self.assertRaises(provenance.RuntimeArtifactError):
                enforcement_gateway._git_commit_hash()

    def test_packaged_legacy_git_helpers_fail_closed_before_subprocess(self):
        from governance import release_integrity

        with patch.object(subprocess, "run", side_effect=AssertionError("Runtime subprocess forbidden")):
            for call in (
                lambda: deployment._git_ancestor("a" * 40, "a" * 40),
                lambda: deployment._git_parents("a" * 40),
                lambda: gateway._run_runtime_git(self.package, "status"),
                lambda: release_integrity._run_git(self.package, ["rev-parse", "HEAD"]),
                lambda: release_integrity.baseline_tag_commit(self.package, "unverified-tag"),
            ):
                with self.subTest(call=call):
                    with self.assertRaisesRegex(
                        RuntimeError, "runtime_git_forbidden|release_integrity_build_metadata_required",
                    ):
                        call()

    def test_production_runtime_identity_does_not_inspect_git_metadata(self):
        from runtime import enforcement_gateway

        self.resign({"producer_scope": "production"})
        os.environ.update(USBAY_ENV="production", USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE="production")
        original_stat, original_lstat = Path.stat, Path.lstat

        def checked(original):
            def inspect(path, *args, **kwargs):
                if ".git" in path.parts:
                    raise AssertionError("Runtime Git metadata access forbidden")
                return original(path, *args, **kwargs)
            return inspect

        with (
            patch.object(enforcement_gateway, "ROOT", self.package),
            patch.object(Path, "stat", checked(original_stat)),
            patch.object(Path, "lstat", checked(original_lstat)),
            patch.object(subprocess, "run", side_effect=AssertionError("Runtime subprocess forbidden")),
        ):
            artifact = self.authority()
            self.assertEqual(enforcement_gateway._git_commit_hash(), artifact.verified.source_commit)
            self.assertEqual(deployment.current_git_commit(), artifact.verified.source_commit)
            gateway.validate_no_forbidden_runtime_files(self.package, artifact_authority=artifact)

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

    def test_packaged_runtime_cannot_autogenerate_release(self):
        target = self.base / "must-not-create-release.json"
        with self.assertRaisesRegex(deployment.DeploymentAttestationError, "runtime_release_generation_denied"):
            deployment.ensure_runtime_release_manifest(target, force=True)
        self.assertFalse(target.exists())

    def test_production_each_missing_public_trust_field_denies_startup(self):
        for field in (
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY",
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID",
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE",
        ):
            with self.subTest(field=field), patch.dict(os.environ, self.environment, clear=True):
                os.environ["USBAY_ENV"] = "production"
                os.environ.pop(field)
                with patch.object(subprocess, "run", side_effect=AssertionError("Git forbidden")):
                    with self.assertRaisesRegex(provenance.RuntimeArtifactError, "trust_unavailable"):
                        gateway.validate_policy_registry_startup()

    def test_production_malformed_public_key_denies_startup(self):
        os.environ.update(USBAY_ENV="production", USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE="production")
        for value in ("not-base64", "AAAA"):
            with self.subTest(value=value):
                os.environ["USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY"] = value
                with patch.object(subprocess, "run", side_effect=AssertionError("Git forbidden")):
                    with self.assertRaisesRegex(provenance.RuntimeArtifactError, "trust_invalid"):
                        gateway.validate_policy_registry_startup()

    def test_production_wrong_producer_denies_startup(self):
        other = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        os.environ.update(
            USBAY_ENV="production", USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE="production",
            USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY=base64.b64encode(other).decode(),
            USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID=provenance.public_key_id(other),
        )
        with patch.object(subprocess, "run", side_effect=AssertionError("Git forbidden")):
            with self.assertRaisesRegex(provenance.RuntimeArtifactError, "producer_untrusted"):
                self.authority()

    def test_production_test_producer_blocks_actual_startup(self):
        os.environ["USBAY_ENV"] = "production"
        with patch.object(subprocess, "run", side_effect=AssertionError("Git forbidden")):
            with self.assertRaisesRegex(provenance.RuntimeArtifactError, "test_producer_denied"):
                gateway.validate_policy_registry_startup()

    def test_synthetic_production_startup_shares_authority_without_git(self):
        # Synthetic in-memory fixture only: no production key is provisioned.
        self.resign({"producer_scope": "production"})
        os.environ.update(
            USBAY_ENV="production", USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE="production",
            USBAY_DEPLOYMENT_SIGNING_MATERIAL="synthetic-production-path-test-only",
        )
        release = json.loads(self.release_path.read_text())
        release["release_signature"] = deployment.sign_release_manifest(release)
        self.release_path.write_text(json.dumps(release))
        self.test_bounded_actual_startup_reaches_next_independent_validator()

    def test_valid_production_artifact_does_not_replace_release_signing_trust(self):
        self.resign({"producer_scope": "production"})
        os.environ.update(USBAY_ENV="production", USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE="production")
        self.authority()
        with patch.object(gateway, "REPO_ROOT", self.package), patch.object(
            subprocess, "run", side_effect=AssertionError("Git forbidden"),
        ):
            with self.assertRaisesRegex(deployment.DeploymentAttestationError, "signing_material_required"):
                gateway.validate_policy_registry_startup()

    def test_valid_production_artifact_cannot_admit_development_hmac(self):
        material = deployment._signing_material()
        self.resign({"producer_scope": "production"})
        os.environ.update(
            USBAY_ENV="production", USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE="production",
            USBAY_DEPLOYMENT_SIGNING_MATERIAL=material,
        )
        self.authority()
        with patch.object(gateway, "REPO_ROOT", self.package), patch.object(
            subprocess, "run", side_effect=AssertionError("Git forbidden"),
        ):
            with self.assertRaisesRegex(deployment.DeploymentAttestationError, "development_signing_material_denied"):
                gateway.validate_policy_registry_startup()

    def test_packager_never_overwrites_existing_destination(self):
        with self.assertRaises(provenance.RuntimeArtifactError):
            package_runtime_artifact(
                self.source, self.package, signing_key=self.key,
                producer_key_id=self.key_id, producer_scope="test",
            )


class ReleaseSigningBoundaryTests(unittest.TestCase):
    """Synthetic HMAC checks; never consult the inherited process environment."""

    def setUp(self):
        environment = patch.dict(os.environ, {"USBAY_ENV": "test"}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.manifest = {"release_id": "synthetic-signing-boundary"}
        self.development_signature = deployment.sign_release_manifest(self.manifest)
        self.signed = dict(self.manifest, release_signature=self.development_signature)
        self.development_material = deployment._signing_material()

    def test_production_missing_material_denies_signing_and_verification(self):
        for config in ({"USBAY_ENV": "production"}, {"USBAY_ENVIRONMENT": "prod"}):
            with self.subTest(config=config), patch.dict(os.environ, config, clear=True):
                with self.assertRaisesRegex(deployment.DeploymentAttestationError, "signing_material_required"):
                    deployment.sign_release_manifest(self.manifest)
                with self.assertRaisesRegex(deployment.DeploymentAttestationError, "signing_material_required"):
                    deployment.verify_release_signature(self.signed)

    def test_production_blank_material_denied(self):
        os.environ["USBAY_ENV"] = "production"
        for value in ("", " ", "\t\n"):
            with self.subTest(value=repr(value)):
                os.environ["USBAY_DEPLOYMENT_SIGNING_MATERIAL"] = value
                with self.assertRaisesRegex(deployment.DeploymentAttestationError, "signing_material_required"):
                    deployment.verify_release_signature(self.signed)
                with self.assertRaisesRegex(deployment.DeploymentAttestationError, "signing_material_required"):
                    deployment.sign_release_manifest(self.manifest, signing_material=value)

    def test_production_explicit_development_material_denied(self):
        os.environ["USBAY_ENV"] = "production"
        os.environ["USBAY_DEPLOYMENT_SIGNING_MATERIAL"] = self.development_material
        with self.assertRaisesRegex(deployment.DeploymentAttestationError, "development_signing_material_denied"):
            deployment.verify_release_signature(self.signed)
        with self.assertRaisesRegex(deployment.DeploymentAttestationError, "development_signing_material_denied"):
            deployment.sign_release_manifest(self.manifest, signing_material=self.development_material)

    def test_development_forgery_rejected_with_explicit_synthetic_production_material(self):
        os.environ.update(
            USBAY_ENV="production", USBAY_DEPLOYMENT_SIGNING_MATERIAL="synthetic-independent-test-material",
        )
        self.assertFalse(deployment.verify_release_signature(self.signed))
        signed = dict(self.manifest, release_signature=deployment.sign_release_manifest(self.manifest))
        self.assertTrue(deployment.verify_release_signature(signed))

    def test_fallback_requires_explicit_development_scope(self):
        os.environ.clear()
        with self.assertRaisesRegex(deployment.DeploymentAttestationError, "signing_material_required"):
            deployment.sign_release_manifest(self.manifest)
        os.environ["USBAY_DEPLOYMENT_SIGNING_MATERIAL"] = self.development_material
        with self.assertRaisesRegex(deployment.DeploymentAttestationError, "development_signing_material_denied"):
            deployment.verify_release_signature(self.signed)

    def test_explicit_development_fallback_remains_scoped(self):
        for config in (
            {"USBAY_ENV": "test"}, {"USBAY_ENV": "development"},
            {"USBAY_ENVIRONMENT": "dev"}, {"USBAY_ENV": "test", "USBAY_ENVIRONMENT": "development"},
        ):
            with self.subTest(config=config), patch.dict(os.environ, config, clear=True):
                self.assertEqual(deployment.sign_release_manifest(self.manifest), self.development_signature)
                self.assertTrue(deployment.verify_release_signature(self.signed))

    def test_conflicting_modes_fail_before_git_or_signing(self):
        for primary, alternate in (("test", "production"), ("production", "test")):
            with self.subTest(primary=primary), patch.dict(os.environ, {
                "USBAY_ENV": primary, "USBAY_ENVIRONMENT": alternate,
            }, clear=True), patch.object(subprocess, "run", side_effect=AssertionError("Git forbidden")):
                with self.assertRaisesRegex(deployment.DeploymentAttestationError, "mode_conflict"):
                    deployment.sign_release_manifest(self.manifest)
                with self.assertRaisesRegex(provenance.RuntimeArtifactError, "mode_conflict"):
                    authority_module.artifact_runtime_required()
                with self.assertRaisesRegex(deployment.DeploymentAttestationError, "mode_conflict"):
                    deployment.ensure_runtime_release_manifest(force=True)

    def test_unknown_or_empty_explicit_modes_cannot_downgrade(self):
        for variable in ("USBAY_ENV", "USBAY_ENVIRONMENT"):
            for value in ("", "production-typo"):
                with self.subTest(variable=variable, value=value), patch.dict(
                    os.environ, {variable: value}, clear=True,
                ), patch.object(subprocess, "run", side_effect=AssertionError("Git forbidden")):
                    with self.assertRaisesRegex(deployment.DeploymentAttestationError, "mode_invalid"):
                        deployment.sign_release_manifest(self.manifest)
                    with self.assertRaisesRegex(provenance.RuntimeArtifactError, "mode_invalid"):
                        authority_module.artifact_runtime_required()

    def test_production_cannot_autogenerate_release_even_when_forced(self):
        os.environ["USBAY_ENV"] = "production"
        with patch.object(subprocess, "run", side_effect=AssertionError("Git forbidden")):
            with self.assertRaisesRegex(deployment.DeploymentAttestationError, "runtime_release_generation_denied"):
                deployment.ensure_runtime_release_manifest(force=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
