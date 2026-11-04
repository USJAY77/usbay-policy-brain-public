"""Standalone unittest suite: no Gateway, pytest fixtures, services or live keys.

Run in a credential-free subprocess with existing read-only dependencies.
All keys here are ephemeral synthetic TEST producers, never provisioned.
"""
from __future__ import annotations

import base64
import copy
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

from security import runtime_artifact_provenance as verifier
from security.runtime_artifact_builder import build_runtime_artifact_manifest


def git(root, *arguments):
    result = subprocess.run(
        ["git", "-C", str(root), *arguments], check=True, capture_output=True,
        env={
            "PATH": os.environ["PATH"], "HOME": str(root),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        },
        timeout=10,
    )
    return result.stdout.decode("ascii").strip()


class RuntimeArtifactTrustTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="usbay-artifact-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "application.py"
        self.path.write_bytes(b"VALUE = 1\n")
        self.path.chmod(0o644)
        git(self.root, "init", "-q")
        git(self.root, "add", "--", "application.py")
        git(
            self.root, "-c", "user.name=Synthetic Artifact Test",
            "-c", "user.email=synthetic@example.invalid", "-c", "commit.gpgsign=false",
            "commit", "-qm", "Synthetic fixture only",
        )
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        self.key_id = verifier.public_key_id(self.public)
        self.trust = verifier.ProducerTrust(self.public, self.key_id, "test", "test")
        self.raw = build_runtime_artifact_manifest(
            self.root, signing_key=self.key, producer_key_id=self.key_id,
            producer_scope="test", build_reference="synthetic-fixture",
        )
        self.manifest = json.loads(self.raw)

    def resign(self, manifest):
        manifest = copy.deepcopy(manifest)
        manifest["manifest_digest"] = verifier.manifest_digest(manifest)
        manifest["signature"] = base64.b64encode(
            self.key.sign(verifier.signature_payload(manifest)),
        ).decode("ascii")
        return verifier.canonical_bytes(manifest)

    def verify(self, raw=None, trust=None, **kwargs):
        return verifier.verify_runtime_artifact(
            self.raw if raw is None else raw, self.root,
            self.trust if trust is None else trust, **kwargs,
        )

    def denied(self, code, raw=None, trust=None, **kwargs):
        with self.assertRaisesRegex(verifier.RuntimeArtifactError, "^" + code + "$"):
            self.verify(raw=raw, trust=trust, **kwargs)

    def test_valid_separately_configured_test_producer(self):
        authority = self.verify()
        self.assertEqual(authority.source_commit, git(self.root, "rev-parse", "HEAD"))
        self.assertEqual(authority.source_tree_reference, git(self.root, "rev-parse", "HEAD^{tree}"))
        self.assertEqual(authority.producer_key_id, self.key_id)
        self.assertEqual(authority.managed_files[0].path, "application.py")
        with self.assertRaises(AttributeError):
            authority.source_commit = "0" * 40

    def _install_commit_replacement(self):
        original = self.manifest["source_commit"]
        self.path.write_bytes(b"VALUE = 2\n")
        git(self.root, "add", "--", "application.py")
        git(self.root, "-c", "user.name=Synthetic Artifact Test",
            "-c", "user.email=synthetic@example.invalid", "-c", "commit.gpgsign=false",
            "commit", "-qm", "Synthetic replacement fixture")
        replacement = git(self.root, "rev-parse", "HEAD")
        git(self.root, "reset", "--hard", original)
        git(self.root, "replace", original, replacement)
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), original)
        self.assertNotEqual(git(self.root, "rev-parse", "HEAD^{tree}"),
                            self.manifest["source_tree_reference"])
        return original

    def test_replaced_commit_cannot_sign_replacement_tree(self):
        self._install_commit_replacement()
        git(self.root, "read-tree", "--reset", "-u", "HEAD")
        # Git's default replacement view considers B's files clean under A's ID.
        self.assertEqual(git(self.root, "status", "--porcelain=v1"), "")
        with self.assertRaisesRegex(verifier.RuntimeArtifactError, "source_dirty|source_mismatch"):
            build_runtime_artifact_manifest(
                self.root, signing_key=self.key, producer_key_id=self.key_id,
                producer_scope="test",
            )

    def test_replacement_ref_does_not_change_original_source_binding(self):
        original = self._install_commit_replacement()
        # Original A's files remain checked out. An inherited override must not
        # re-enable replacement interpretation inside the build helper.
        with patch.dict(os.environ, {"GIT_NO_REPLACE_OBJECTS": "0"}):
            raw = build_runtime_artifact_manifest(
                self.root, signing_key=self.key, producer_key_id=self.key_id,
                producer_scope="test",
            )
        verified = verifier.verify_runtime_artifact(raw, self.root, self.trust)
        self.assertEqual(verified.source_commit, original)
        self.assertEqual(verified.source_tree_reference, self.manifest["source_tree_reference"])
        self.assertEqual(verified.managed_files[0].sha256, self.manifest["managed_files"][0]["sha256"])

    def test_gitless_verifier_never_calls_subprocess(self):
        shutil.rmtree(self.root / ".git")
        with patch.object(subprocess, "run", side_effect=AssertionError("Git forbidden")):
            self.assertEqual(self.verify().source_commit, self.manifest["source_commit"])

    def test_verifies_without_git_binary_on_path_or_git_directory(self):
        shutil.rmtree(self.root / ".git")
        with patch.dict(os.environ, {"PATH": "/nonexistent"}, clear=True):
            self.assertEqual(self.verify().producer_key_id, self.key_id)

    def test_public_environment_configuration_only(self):
        config = {
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY": base64.b64encode(self.public).decode("ascii"),
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID": self.key_id,
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE": "test",
            "USBAY_ENV": "test",
        }
        trust = verifier.producer_trust_from_environment(config)
        self.assertEqual(self.verify(trust=trust).producer_key_id, self.key_id)

    def test_missing_configuration_is_denied(self):
        with self.assertRaisesRegex(verifier.RuntimeArtifactError, "trust_unavailable"):
            verifier.producer_trust_from_environment({})

    def test_missing_each_configuration_field_is_denied(self):
        config = {
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY": base64.b64encode(self.public).decode("ascii"),
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID": self.key_id,
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE": "test", "USBAY_ENV": "test",
        }
        for field in list(config)[:3]:
            with self.subTest(field=field):
                altered = dict(config)
                del altered[field]
                with self.assertRaisesRegex(verifier.RuntimeArtifactError, "trust_unavailable"):
                    verifier.producer_trust_from_environment(altered)

    def test_no_trust_object_is_denied(self):
        with self.assertRaisesRegex(verifier.RuntimeArtifactError, "trust_unavailable"):
            verifier.verify_runtime_artifact(self.raw, self.root, None)

    def test_unknown_producer_is_denied(self):
        other = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        self.denied(
            "runtime_artifact_producer_untrusted",
            trust=verifier.ProducerTrust(other, verifier.public_key_id(other), "test", "test"),
        )

    def test_wrong_configured_key_id_is_denied(self):
        self.denied(
            "runtime_artifact_producer_key_id_mismatch",
            trust=verifier.ProducerTrust(self.public, "sha256:" + "0" * 64, "test", "test"),
        )

    def test_wrong_manifest_key_id_is_denied(self):
        altered = dict(self.manifest, producer_key_id="sha256:" + "0" * 64)
        self.denied("runtime_artifact_producer_untrusted", self.resign(altered))

    def test_signature_from_wrong_private_key_is_denied(self):
        altered = dict(self.manifest)
        wrong_key = Ed25519PrivateKey.generate()
        altered["signature"] = base64.b64encode(wrong_key.sign(
            verifier.signature_payload(altered),
        )).decode("ascii")
        self.denied("runtime_artifact_signature_invalid", verifier.canonical_bytes(altered))

    def test_test_producer_denied_in_production(self):
        self.denied(
            "runtime_artifact_test_producer_denied",
            trust=verifier.ProducerTrust(self.public, self.key_id, "test", "production"),
        )

    def test_test_manifest_cannot_override_production_scope(self):
        self.denied(
            "runtime_artifact_producer_scope_mismatch",
            trust=verifier.ProducerTrust(self.public, self.key_id, "production", "production"),
        )

    def test_environment_mode_conflict_is_denied(self):
        config = {
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY": base64.b64encode(self.public).decode("ascii"),
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID": self.key_id,
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE": "test",
            "USBAY_ENV": "test", "USBAY_ENVIRONMENT": "production",
        }
        with self.assertRaisesRegex(verifier.RuntimeArtifactError, "mode_conflict"):
            verifier.producer_trust_from_environment(config)

    def test_missing_build_key_is_denied(self):
        with self.assertRaisesRegex(verifier.RuntimeArtifactError, "signing_key_unavailable"):
            build_runtime_artifact_manifest(
                self.root, signing_key=None, producer_key_id=self.key_id, producer_scope="test",
            )

    def test_build_key_fingerprint_conflict_is_denied(self):
        with self.assertRaisesRegex(verifier.RuntimeArtifactError, "producer_key_id_mismatch"):
            build_runtime_artifact_manifest(
                self.root, signing_key=self.key,
                producer_key_id="sha256:" + "0" * 64, producer_scope="test",
            )

    def test_build_without_git_fails_closed(self):
        with patch.dict(os.environ, {"PATH": "/nonexistent"}, clear=True):
            with self.assertRaisesRegex(verifier.RuntimeArtifactError, "build_git_unavailable"):
                build_runtime_artifact_manifest(
                    self.root, signing_key=self.key,
                    producer_key_id=self.key_id, producer_scope="test",
                )

    def test_hmac_material_cannot_be_a_producer_signing_key(self):
        with self.assertRaisesRegex(verifier.RuntimeArtifactError, "signing_key_invalid"):
            build_runtime_artifact_manifest(
                self.root, signing_key=b"synthetic-hmac-not-an-ed25519-key",
                producer_key_id=self.key_id, producer_scope="test",
            )

    def test_default_hmac_configuration_cannot_establish_trust(self):
        with self.assertRaisesRegex(verifier.RuntimeArtifactError, "trust_unavailable"):
            verifier.producer_trust_from_environment({
                "USBAY_DEPLOYMENT_SIGNING_MATERIAL": "synthetic-only",
            })

    def test_runtime_does_not_load_private_key(self):
        # The standalone verifier imports only the public Ed25519 primitive.
        with patch.object(
            Ed25519PrivateKey, "from_private_bytes",
            side_effect=AssertionError("private key load forbidden"),
        ):
            self.assertEqual(self.verify().producer_key_id, self.key_id)

    def test_mutating_every_signed_field_is_denied(self):
        for field, value in {
            "source_commit": "0" * 40, "source_tree_reference": "0" * 40,
            "manifest_id": "0" * 32, "created_at": "2020-01-01T00:00:00Z",
            "build_reference": "changed", "managed_set_hash": "0" * 64,
            "manifest_digest": "0" * 64,
        }.items():
            with self.subTest(field=field):
                altered = dict(self.manifest)
                altered[field] = value
                self.denied("runtime_artifact_signature_invalid", verifier.canonical_bytes(altered))

    def test_managed_set_mutation_denied_before_file_access(self):
        altered = copy.deepcopy(self.manifest)
        altered["managed_files"][0]["path"] = "../outside"
        with patch.object(verifier, "inspect_managed_file", side_effect=AssertionError("file read forbidden")):
            self.denied("runtime_artifact_signature_invalid", verifier.canonical_bytes(altered))

    def test_corrupt_manifest_and_signature_are_denied(self):
        for raw in (b"", b"{", b"\xff", b"[]", b"null"):
            with self.subTest(raw_length=len(raw)):
                with self.assertRaises(verifier.RuntimeArtifactError):
                    self.verify(raw)
        altered = dict(self.manifest, signature="hmac-sha256:not-ed25519")
        self.denied("runtime_artifact_signature_invalid", verifier.canonical_bytes(altered))

    def test_duplicate_json_fields_are_denied(self):
        raw = self.raw[:-1] + b',"source_commit":"duplicate"}'
        self.denied("runtime_artifact_manifest_duplicate_field", raw)

    def test_oversized_manifest_is_denied(self):
        self.denied(
            "runtime_artifact_manifest_size_invalid",
            b" " * (verifier.MAX_MANIFEST_BYTES + 1),
        )

    def test_valid_signature_cannot_hide_inconsistent_manifest_digest(self):
        altered = dict(self.manifest, manifest_digest="0" * 64)
        altered["signature"] = base64.b64encode(
            self.key.sign(verifier.signature_payload(altered)),
        ).decode("ascii")
        self.denied(
            "runtime_artifact_manifest_digest_mismatch",
            verifier.canonical_bytes(altered),
        )

    def test_closed_schema_rejects_bundled_key_and_unknown_version(self):
        altered = dict(self.manifest, bundled_public_key="self-asserted")
        self.denied("runtime_artifact_contract_invalid", verifier.canonical_bytes(altered))
        altered = dict(self.manifest, schema_version="unknown")
        self.denied("runtime_artifact_schema_invalid", verifier.canonical_bytes(altered))

    def test_modified_file_is_denied(self):
        self.path.write_bytes(b"VALUE = 2\n")
        self.denied("runtime_artifact_file_digest_mismatch")

    def test_missing_file_is_denied(self):
        self.path.unlink()
        self.denied("runtime_artifact_file_unavailable")

    def test_size_and_mode_changes_are_denied(self):
        self.path.chmod(0o755)
        self.denied("runtime_artifact_file_mode_mismatch")
        self.path.chmod(0o644)
        self.path.write_bytes(b"longer synthetic value")
        self.denied("runtime_artifact_file_size_mismatch")

    def test_unsafe_file_and_parent_symlinks_are_denied(self):
        self.path.rename(self.root / "target")
        self.path.symlink_to("target")
        self.denied("runtime_artifact_file_unavailable")
        self.path.unlink()
        (self.root / "nested").symlink_to(self.root, target_is_directory=True)
        altered = copy.deepcopy(self.manifest)
        altered["managed_files"][0]["path"] = "nested/target"
        altered["managed_set_hash"] = hashlib.sha256(
            verifier.canonical_bytes(altered["managed_files"]),
        ).hexdigest()
        self.denied("runtime_artifact_file_unavailable", self.resign(altered))

    def test_symlink_root_is_denied(self):
        with tempfile.TemporaryDirectory(prefix="usbay-artifact-root-") as directory:
            linked_root = Path(directory) / "root"
            linked_root.symlink_to(self.root, target_is_directory=True)
            with self.assertRaisesRegex(verifier.RuntimeArtifactError, "root_invalid"):
                verifier.verify_runtime_artifact(self.raw, linked_root, self.trust)

    def test_manifest_with_nonregular_managed_file_is_denied(self):
        self.path.unlink()
        os.mkfifo(self.path)
        self.denied("runtime_artifact_file_type_invalid")

    def test_even_signed_unsafe_paths_are_denied(self):
        for path in ("../outside", "/outside", "a/../b", "a//b", ".git/config", "a\\b", "\ud800", "a\nb"):
            with self.subTest(path_kind=repr(path)):
                altered = copy.deepcopy(self.manifest)
                altered["managed_files"][0]["path"] = path
                altered["managed_set_hash"] = hashlib.sha256(
                    verifier.canonical_bytes(altered["managed_files"]),
                ).hexdigest()
                self.denied("runtime_artifact_path_invalid", self.resign(altered))

    def test_signed_managed_set_digest_and_duplicate_paths_denied(self):
        self.denied(
            "runtime_artifact_managed_set_mismatch",
            self.resign(dict(self.manifest, managed_set_hash="0" * 64)),
        )
        altered = copy.deepcopy(self.manifest)
        altered["managed_files"].append(dict(altered["managed_files"][0]))
        self.denied("runtime_artifact_managed_set_invalid", self.resign(altered))

    def test_invalid_entry_types_are_bounded(self):
        for field, value in (("mode", []), ("size", True), ("sha256", None), ("path", 1)):
            with self.subTest(field=field):
                altered = copy.deepcopy(self.manifest)
                altered["managed_files"][0][field] = value
                with self.assertRaises(verifier.RuntimeArtifactError):
                    self.verify(self.resign(altered))

    def test_expected_source_and_tree_conflicts_are_denied(self):
        self.denied("runtime_artifact_source_conflict", expected_source_commit="0" * 40)
        self.denied("runtime_artifact_source_conflict", expected_source_tree="0" * 40)

    def test_invalid_trust_modes_are_bounded(self):
        self.denied(
            "runtime_artifact_mode_invalid",
            trust=verifier.ProducerTrust(self.public, self.key_id, "test", []),
        )
        self.denied(
            "runtime_artifact_producer_trust_invalid",
            trust=verifier.ProducerTrust(self.public, self.key_id, [], "test"),
        )

    def test_invalid_public_key_configuration_is_denied(self):
        config = {
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY": "not-base64",
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID": self.key_id,
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE": "test", "USBAY_ENV": "test",
        }
        with self.assertRaisesRegex(verifier.RuntimeArtifactError, "trust_invalid"):
            verifier.producer_trust_from_environment(config)

    def test_replayed_signature_does_not_cover_changed_commit(self):
        altered = dict(self.manifest, source_commit="0" * 40)
        altered["manifest_digest"] = verifier.manifest_digest(altered)
        self.denied("runtime_artifact_signature_invalid", verifier.canonical_bytes(altered))

    def test_signed_invalid_metadata_is_denied(self):
        cases = (
            ("source_commit", "not-a-commit", "source_invalid"),
            ("source_tree_reference", None, "source_invalid"),
            ("manifest_id", "invalid", "manifest_id_invalid"),
            ("build_reference", "https://sensitive.invalid", "build_reference_invalid"),
            ("created_at", "9999-01-01T00:00:00Z", "timestamp_invalid"),
        )
        for field, value, code in cases:
            with self.subTest(field=field):
                self.denied("runtime_artifact_" + code, self.resign(dict(self.manifest, **{field: value})))

    def test_untracked_files_are_never_granted_managed_status(self):
        (self.root / "unexpected.py").write_bytes(b"unexpected\n")
        raw = build_runtime_artifact_manifest(
            self.root, signing_key=self.key, producer_key_id=self.key_id, producer_scope="test",
        )
        authority = self.verify(raw)
        self.assertEqual([entry.path for entry in authority.managed_files], ["application.py"])
        # Existing runtime scanner must still inspect unknown/untracked files.

    def test_dirty_tracked_source_is_denied(self):
        self.path.write_bytes(b"VALUE = 2\n")
        with self.assertRaisesRegex(verifier.RuntimeArtifactError, "build_source_dirty"):
            build_runtime_artifact_manifest(
                self.root, signing_key=self.key, producer_key_id=self.key_id, producer_scope="test",
            )

    def test_builder_never_omits_tracked_symlinks(self):
        (self.root / "link").symlink_to("application.py")
        git(self.root, "add", "link")
        git(
            self.root, "-c", "user.name=Synthetic Artifact Test",
            "-c", "user.email=synthetic@example.invalid", "-c", "commit.gpgsign=false",
            "commit", "-qm", "Synthetic symlink fixture",
        )
        with self.assertRaisesRegex(verifier.RuntimeArtifactError, "build_file_type_invalid"):
            build_runtime_artifact_manifest(
                self.root, signing_key=self.key, producer_key_id=self.key_id, producer_scope="test",
            )

    def test_no_gateway_or_private_signer_imported_by_verifier(self):
        import sys
        # Check verifier imports in a fresh interpreter, independently of test
        # collection having already imported Gateway in this parent process.
        root = str(Path(__file__).resolve().parents[1])
        code = (
            "import sys; sys.path.insert(0, " + repr(root) + "); "
            "from security import runtime_artifact_provenance as verifier; "
            "assert 'gateway.app' not in sys.modules; "
            "assert 'security.deployment_attestation' not in sys.modules; "
            "assert not hasattr(verifier, 'Ed25519PrivateKey')"
        )
        subprocess.run(
            [sys.executable, "-I", "-B", "-c", code], check=True,
            capture_output=True, timeout=30,
            env={"PATH": os.defpath, "HOME": str(self.root), "USBAY_ENV": "test"},
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
