"""Explicit opt-in context for synthetic Git-backed release fixtures only."""
from __future__ import annotations

import os


def configure_test_release_environment(monkeypatch) -> None:
    """Never downgrade production, ambiguous modes or an artifact-backed context.

    This fixture does not issue trust, supply signing material or replace a
    validator. Existing production/artifact tests must supply their own inputs.
    """
    names = ("USBAY_ENV", "USBAY_ENVIRONMENT")
    declared = [os.environ[name] for name in names if name in os.environ]
    if any(value.strip().lower() not in {"test", "development", "dev"}
           for value in declared):
        raise RuntimeError("synthetic_release_test_context_required")
    if os.environ.get("USBAY_RUNTIME_SOURCE_MANIFEST"):
        raise RuntimeError("synthetic_release_git_context_required")
    if not declared:
        monkeypatch.setenv("USBAY_ENV", "test")
