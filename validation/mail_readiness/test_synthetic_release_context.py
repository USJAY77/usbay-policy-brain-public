"""Pure fixture-context checks; no product module or application is imported."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch


_path = Path(__file__).resolve().parents[2] / "tests/helpers/release_environment.py"
_spec = importlib.util.spec_from_file_location("synthetic_release_environment", _path)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)


class EnvironmentRecorder:
    def __init__(self):
        self.calls = []

    def setenv(self, name, value):
        self.calls.append((name, value))
        os.environ[name] = value


class SyntheticReleaseContextTests(unittest.TestCase):
    def test_missing_mode_requires_explicit_fixture_opt_in(self):
        with patch.dict(os.environ, {}, clear=True):
            recorder = EnvironmentRecorder()
            _module.configure_test_release_environment(recorder)
            self.assertEqual(dict(os.environ), {"USBAY_ENV": "test"})
            self.assertEqual(recorder.calls, [("USBAY_ENV", "test")])

    def test_development_aliases_are_preserved(self):
        for name in ("USBAY_ENV", "USBAY_ENVIRONMENT"):
            for value in ("test", "development", "dev", " TEST "):
                with self.subTest(name=name, value=value), patch.dict(os.environ, {name: value}, clear=True):
                    recorder = EnvironmentRecorder()
                    _module.configure_test_release_environment(recorder)
                    self.assertEqual(dict(os.environ), {name: value})
                    self.assertEqual(recorder.calls, [])

    def test_production_invalid_and_conflicting_modes_are_not_downgraded(self):
        declarations = [{name: value} for name in ("USBAY_ENV", "USBAY_ENVIRONMENT")
                        for value in ("production", "prod", "", "staging", "typo")]
        declarations += [{"USBAY_ENV": "test", "USBAY_ENVIRONMENT": "production"},
                         {"USBAY_ENV": "production", "USBAY_ENVIRONMENT": "test"}]
        for declaration in declarations:
            with self.subTest(declaration=declaration), patch.dict(os.environ, declaration, clear=True):
                recorder = EnvironmentRecorder()
                with self.assertRaisesRegex(RuntimeError, "synthetic_release_test_context_required"):
                    _module.configure_test_release_environment(recorder)
                self.assertEqual(dict(os.environ), declaration)
                self.assertEqual(recorder.calls, [])

    def test_artifact_context_is_not_replaced(self):
        for declaration in ({"USBAY_RUNTIME_SOURCE_MANIFEST": "source.json"},
                            {"USBAY_ENV": "test", "USBAY_RUNTIME_SOURCE_MANIFEST": "source.json"}):
            with self.subTest(declaration=declaration), patch.dict(os.environ, declaration, clear=True):
                recorder = EnvironmentRecorder()
                with self.assertRaisesRegex(RuntimeError, "synthetic_release_git_context_required"):
                    _module.configure_test_release_environment(recorder)
                self.assertEqual(dict(os.environ), declaration)
                self.assertEqual(recorder.calls, [])

    def test_no_signing_or_provider_configuration_is_added(self):
        declaration = {"USBAY_ENV": "dev", "USBAY_ENVIRONMENT": "test"}
        with patch.dict(os.environ, declaration, clear=True):
            recorder = EnvironmentRecorder()
            _module.configure_test_release_environment(recorder)
            self.assertEqual(dict(os.environ), declaration)
            self.assertEqual(recorder.calls, [])


if __name__ == "__main__":
    unittest.main()
