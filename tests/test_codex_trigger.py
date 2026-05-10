from __future__ import annotations

import importlib
import subprocess
from pathlib import Path


def test_codex_trigger():
    assert True


def test_secret_provider_imports_for_codex_autofix_ci() -> None:
    module = importlib.import_module("utils.secret_provider")

    assert module.SecretProvider
    assert module.LocalFileSecretProvider
    assert module.VaultSecretProvider


def test_secret_provider_source_is_available_to_ci_checkout() -> None:
    assert Path("utils/__init__.py").read_text(encoding="utf-8").strip() == ""
    assert Path("utils/secret_provider.py").is_file()
    result = subprocess.run(
        ["git", "check-ignore", "-q", "utils/secret_provider.py"],
        check=False,
    )

    assert result.returncode == 1


def test_runtime_websocket_server_import_contract_for_ci() -> None:
    from runtime import websocket_server

    assert websocket_server.__name__ == "runtime.websocket_server"
    assert "websocket_server" in importlib.import_module("runtime").__all__
    assert Path("runtime/websocket_server.py").is_file()
    result = subprocess.run(
        ["git", "check-ignore", "-q", "runtime/websocket_server.py"],
        check=False,
    )

    assert result.returncode == 1


def test_codex_autofix_ci_keeps_deterministic_import_path() -> None:
    workflow = Path(".github/workflows/codex-autofix-ci.yml").read_text(encoding="utf-8")

    assert "PYTHONPATH: ${{ github.workspace }}" in workflow
    assert "python3 -m pip install --no-cache-dir -r requirements.txt" in workflow
    assert "python3 -m pip install -e ." in workflow
    assert "python3 -c \"import httpx\"" in workflow
    assert "python3 -c \"import requests\"" in workflow
    assert "python3 -m pytest --version" in workflow
    assert "import utils.secret_provider" in workflow
    assert workflow.index("python3 -m pip install --no-cache-dir -r requirements.txt") < workflow.index(
        "python3 -c \"import requests\""
    )
    assert workflow.index("python3 -m pip install -e .") < workflow.index("import utils.secret_provider")
    assert "github.event.pull_request.head.sha" in workflow
    assert "git rev-parse HEAD" in workflow
    assert "git ls-files | grep secret_provider" in workflow
    assert "VAULT_TOKEN" not in workflow


def test_requests_dependency_declared_for_secret_provider() -> None:
    requirements = Path("requirements.txt").read_text(encoding="utf-8").splitlines()

    assert "requests" in {line.strip() for line in requirements}


def test_pytest_dependency_declared_for_codex_autofix_ci() -> None:
    requirements = Path("requirements.txt").read_text(encoding="utf-8").splitlines()

    assert "pytest" in {line.strip() for line in requirements}


def test_httpx_dependency_declared_for_starlette_testclient() -> None:
    requirements = Path("requirements.txt").read_text(encoding="utf-8").splitlines()

    assert "httpx" in {line.strip() for line in requirements}
