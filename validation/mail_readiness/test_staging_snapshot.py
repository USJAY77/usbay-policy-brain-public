"""Pure source-preparation tests; no gateway import or lifespan execution."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


_helper = Path(__file__).resolve().parents[2] / "tests/helpers/staging_source_package.py"
_spec = importlib.util.spec_from_file_location("staging_source_package", _helper)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)


class StagingSnapshotTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="synthetic-source-preparation-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "source"
        self.root.mkdir()
        (self.root / "application.py").write_bytes(b"VALUE = 1\n")
        self.environment = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1",
                            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
                            "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0"}
        self.git("init", "-q")
        self.commit()

    def git(self, *arguments):
        return subprocess.run(["git", "-C", str(self.root), *arguments],
                              env=self.environment, check=True, capture_output=True,
                              timeout=10).stdout

    def commit(self):
        self.git("add", "--", ".")
        self.git("-c", "user.name=Synthetic Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                 "commit", "-qm", "Synthetic snapshot fixture")

    def test_snapshot_binds_exact_committed_bytes_and_identity(self):
        destination = self.base / "package"
        metadata = _module.snapshot_staging_source(self.root, destination)
        self.assertEqual(metadata["source_commit"], self.git("rev-parse", "HEAD").decode().strip())
        self.assertEqual(metadata["source_tree_reference"], self.git("rev-parse", "HEAD^{tree}").decode().strip())
        self.assertEqual((destination / "application.py").read_bytes(), b"VALUE = 1\n")
        self.assertEqual(metadata["managed_files"][0]["path"], "application.py")
        self.assertFalse((destination / ".git").exists())

    def test_dirty_tracked_source_is_not_packaged(self):
        (self.root / "application.py").write_bytes(b"VALUE = 2\n")
        destination = self.base / "package"
        with self.assertRaisesRegex(RuntimeError, "synthetic_source_requires_clean_candidate"):
            _module.snapshot_staging_source(self.root, destination)
        self.assertFalse(destination.exists())

    def test_tracked_symlink_is_not_followed(self):
        (self.root / "alias.py").symlink_to("application.py")
        self.commit()
        with self.assertRaisesRegex(RuntimeError, "synthetic_source_entry_invalid"):
            _module.snapshot_staging_source(self.root, self.base / "package")

    def test_existing_or_nested_destination_is_not_used(self):
        existing = self.base / "existing"
        existing.mkdir()
        for destination in (existing, self.root / "nested"):
            with self.subTest(destination=destination.name):
                with self.assertRaisesRegex(RuntimeError, "synthetic_source_destination_invalid"):
                    _module.snapshot_staging_source(self.root, destination)

    def test_source_mutation_during_copy_is_rejected(self):
        original = Path.read_bytes
        target = self.root / "application.py"

        def mutate(path):
            data = original(path)
            if path == target:
                path.write_bytes(b"VALUE = 2\n")
            return data

        with patch.object(Path, "read_bytes", mutate):
            with self.assertRaisesRegex(RuntimeError, "synthetic_source_requires_clean_candidate"):
                _module.snapshot_staging_source(self.root, self.base / "package")

    def test_committed_export_ignores_but_preserves_dirty_worktree(self):
        source = self.root / "application.py"
        source.write_bytes(b"VALUE = 2\n")
        destination = self.base / "package"
        metadata = _module.export_committed_staging_source(self.root, destination)
        self.assertEqual((destination / "application.py").read_bytes(), b"VALUE = 1\n")
        self.assertEqual(source.read_bytes(), b"VALUE = 2\n")
        self.assertEqual(metadata["source_commit"], self.git("rev-parse", "HEAD").decode().strip())
        self.assertFalse((destination / ".git").exists())

    def test_committed_export_rejects_symlink_objects(self):
        (self.root / "alias.py").symlink_to("application.py")
        self.commit()
        with self.assertRaisesRegex(RuntimeError, "synthetic_source_entry_invalid"):
            _module.export_committed_staging_source(self.root, self.base / "package")

    def test_committed_export_rejects_attribute_omission(self):
        (self.root / ".gitattributes").write_text("application.py export-ignore\n")
        self.commit()
        with self.assertRaisesRegex(RuntimeError, "synthetic_source_inventory_mismatch"):
            _module.export_committed_staging_source(self.root, self.base / "package")

    def test_committed_export_rejects_attribute_substitution(self):
        (self.root / "application.py").write_bytes(b"VALUE = '$Format:%H$'\n")
        (self.root / ".gitattributes").write_text("application.py export-subst\n")
        self.commit()
        with self.assertRaisesRegex(RuntimeError, "synthetic_source_changed"):
            _module.export_committed_staging_source(self.root, self.base / "package")

    def test_committed_export_rejects_changed_head(self):
        original = subprocess.run

        def move_head(arguments, **kwargs):
            result = original(arguments, **kwargs)
            if "archive" in arguments:
                (self.root / "application.py").write_bytes(b"VALUE = 3\n")
                self.commit()
            return result

        with patch.object(subprocess, "run", move_head):
            with self.assertRaisesRegex(RuntimeError, "synthetic_source_changed"):
                _module.export_committed_staging_source(self.root, self.base / "package")

    def test_committed_export_preserves_executable_mode(self):
        source = self.root / "application.py"
        source.chmod(0o755)
        self.commit()
        destination = self.base / "package"
        metadata = _module.export_committed_staging_source(self.root, destination)
        self.assertEqual(metadata["managed_files"][0]["mode"], "100755")
        self.assertEqual((destination / "application.py").stat().st_mode & 0o777, 0o755)

    def test_committed_export_rejects_unsafe_destination(self):
        with self.assertRaisesRegex(RuntimeError, "synthetic_source_destination_invalid"):
            _module.export_committed_staging_source(self.root, self.root / "nested")


if __name__ == "__main__":
    unittest.main()
