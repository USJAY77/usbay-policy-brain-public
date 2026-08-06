"""Focused startup-readiness tests for the gateway boot wrapper.

Covers: fail-closed blocking before READY, FAILED never recovers,
invalid runtime commit stays blocked, warm READY transition, and
port-conflict behavior. No governance logic is exercised beyond the
wrapper's delegation contract.
"""
from __future__ import annotations

import asyncio
import importlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _fresh_boot():
    import gateway.boot as boot
    importlib.reload(boot)
    return boot


def _run(coro):
    return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(coro)


async def _call(boot, path="/execute", method="POST"):
    sent = []

    async def send(msg):
        sent.append(msg)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {"type": "http", "method": method, "path": path, "headers": []}
    await boot.asgi(scope, receive, send)
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, json.loads(body or b"{}")


def test_execution_blocked_while_starting():
    boot = _fresh_boot()
    assert boot._state["phase"] == "STARTING"
    status, body = _run(_call(boot, "/execute"))
    assert status == 503
    assert body["execution_authorized"] is False
    assert body["phase"] == "STARTING"


def test_all_paths_blocked_while_starting():
    boot = _fresh_boot()
    for path in ("/", "/health", "/api/status", "/api/governance/evidence"):
        status, body = _run(_call(boot, path, method="GET"))
        assert status == 503, path
        assert body["execution_authorized"] is False


def test_failed_state_blocks_forever():
    boot = _fresh_boot()
    boot._state["phase"] = "FAILED"
    boot._state["error_code"] = "DeploymentCommitMismatchError"
    status, body = _run(_call(boot, "/execute"))
    assert status == 503
    assert body["error_code"] == "DeploymentCommitMismatchError"
    assert body["execution_authorized"] is False


def _spawn(port: int, env_extra: dict) -> subprocess.Popen:
    env = dict(os.environ)
    env.update(env_extra)
    env["PORT"] = str(port)
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "gateway.boot:asgi",
         "--host", "127.0.0.1", "--port", str(port)],
        cwd=REPO, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )


def _wait_health(port: int, deadline: float = 90.0):
    """Poll /health until READY (200) or FAILED phase; return (status, body)."""
    import urllib.request
    import urllib.error

    t0 = time.time()
    last = (None, {})
    while time.time() - t0 < deadline:
        try:
            r = urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=3)
            return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            last = (e.code, json.load(e))
            if last[1].get("phase") == "FAILED":
                return last
        except Exception:
            pass
        time.sleep(0.3)
    return last


@pytest.mark.timeout(180)
def test_warm_start_reaches_ready_and_serves():
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO,
                          capture_output=True, text=True, check=True).stdout.strip()
    p = _spawn(5061, {"USBAY_EXPECTED_GIT_COMMIT": head})
    try:
        status, body = _wait_health(5061)
        assert status == 200, body
        assert body.get("status") in ("OK", "NORMAL")
    finally:
        p.terminate()
        p.wait(timeout=10)


@pytest.mark.timeout(180)
def test_invalid_runtime_commit_stays_blocked():
    bogus = "0" * 40
    p = _spawn(5062, {"USBAY_EXPECTED_GIT_COMMIT": bogus})
    try:
        status, body = _wait_health(5062)
        assert status == 503, body
        assert body["phase"] == "FAILED"
        assert body["execution_authorized"] is False
        assert body.get("error_code") == "DeploymentCommitMismatchError"
    finally:
        p.terminate()
        p.wait(timeout=10)


def test_port_conflict_fails_loudly():
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 5063))
    blocker.listen(1)
    try:
        p = _spawn(5063, {})
        out, _ = p.communicate(timeout=60)
        assert p.returncode != 0
        assert "address already in use" in out.lower() or "errno" in out.lower()
    finally:
        blocker.close()
