from __future__ import annotations

import importlib
from pathlib import Path


def test_codex_trigger():
    assert True


def test_secret_provider_imports_for_codex_autofix_ci() -> None:
    module = importlib.import_module("utils.secret_provider")

    assert module.SecretProvider
    assert module.LocalFileSecretProvider
    assert module.VaultSecretProvider


def test_codex_autofix_ci_keeps_deterministic_import_path() -> None:
    workflow = Path(".github/workflows/codex-autofix-ci.yml").read_text(encoding="utf-8")

    assert "PYTHONPATH: ${{ github.workspace }}" in workflow
    assert "pip install -e ." in workflow
    assert "import utils.secret_provider" in workflow
    assert "VAULT_TOKEN" not in workflow
