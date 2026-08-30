import warnings

import pytest

from tests.helpers.audit_registry import install_isolated_audit_key_registry

warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL.*")
warnings.filterwarnings("ignore", message=".*LibreSSL.*")


@pytest.fixture(autouse=True)
def isolate_audit_key_registry(tmp_path, monkeypatch):
    install_isolated_audit_key_registry(monkeypatch, tmp_path)
