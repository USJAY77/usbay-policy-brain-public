"""Explicit staging launch contract. Importing this module never starts a service."""
from __future__ import annotations

import os
from pathlib import Path
import sys
from typing import Mapping


def launch_arguments(environment: Mapping[str, str]) -> list[str]:
    if environment.get("USBAY_ENV") != "production":
        raise ValueError("STAGING_PRODUCTION_CHECKS_REQUIRED")
    if environment.get("USBAY_ENVIRONMENT", "production") != "production":
        raise ValueError("STAGING_SECURITY_MODE_CONFLICT")
    if environment.get("USBAY_RUNTIME_ENVIRONMENT") != "staging":
        raise ValueError("STAGING_AUTHORITY_SCOPE_REQUIRED")
    # The current scoped approval validator grants only production environment authority.
    # This launch profile must not relabel that authority or silently activate evaluation.
    if environment.get("USBAY_LIVE_POLICY_EVALUATION_ENABLED", "").lower() in {"1", "true", "yes"}:
        raise ValueError("STAGING_POLICY_APPROVAL_SCOPE_UNSUPPORTED")
    for name in ("WEB_CONCURRENCY", "UVICORN_WORKERS"):
        if environment.get(name, "1") != "1":
            raise ValueError("STAGING_SINGLE_WORKER_REQUIRED")
    if environment.get("UVICORN_RELOAD", "false").lower() not in {"false", "0"}:
        raise ValueError("STAGING_RELOAD_FORBIDDEN")
    if environment.get("UVICORN_LIFESPAN", "on") != "on":
        raise ValueError("STAGING_LIFESPAN_REQUIRED")
    if environment.get("UVICORN_ENV_FILE") or environment.get("UVICORN_APP_DIR"):
        raise ValueError("STAGING_SOURCE_ENV_OVERRIDE_FORBIDDEN")
    raw_port = environment.get("PORT", "")
    if not raw_port.isascii() or not raw_port.isdecimal() or not 1 <= int(raw_port) <= 65535:
        raise ValueError("STAGING_PORT_INVALID")
    return ["-m", "uvicorn", "gateway.app:app", "--host", "0.0.0.0", "--port", str(int(raw_port)), "--workers", "1", "--lifespan", "on"]


def main() -> None:
    arguments = launch_arguments(os.environ)
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    os.environ["PYTHONPATH"] = os.pathsep.join((str(root / "python"), str(root)))
    os.execv(sys.executable, [sys.executable, *arguments])


if __name__ == "__main__":
    main()
