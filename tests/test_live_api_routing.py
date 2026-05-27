"""Live HTTP-socket roundtrip test for the /api/* routing contract.

The existing :mod:`tests.test_api_route_precedence` suite exercises the
FastAPI app through Starlette's in-process ``TestClient``. That covers
the route table and middleware behaviour but does *not* prove the
contract over a real TCP socket — and the live-deployment regression
report ("HTML on /api/status", evidence of ``/__replish/redirect/``)
was a transport-level symptom. This test spawns a real uvicorn
subprocess on an ephemeral port and hits it with plain ``urllib``,
proving that:

* ``/api/status`` returns ``application/json`` over the wire.
* ``/api/governance/evidence`` returns ``application/json`` over the
  wire (status 200/404/503 — fail-closed semantics preserved).
* Unknown ``/api/foo/bar`` returns a JSON 404 envelope, never HTML.
* ``/`` still returns ``text/html`` (dashboard).

If a future change ever re-introduces an SPA catch-all that shadows
/api/* (or removes the defensive middleware), this test fails at the
socket layer rather than waiting for a live-deployment regression
report.
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from contextlib import closing
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, *, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            with closing(socket.create_connection(("127.0.0.1", port), timeout=0.5)):
                return
        except OSError as exc:
            last_err = exc
            time.sleep(0.2)
    raise RuntimeError(f"uvicorn did not open port {port}: {last_err}")


def _request(port: int, path: str) -> tuple[int, str, bytes]:
    url = f"http://127.0.0.1:{port}{path}"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.headers.get("content-type", ""), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("content-type", ""), exc.read()


def _content_type(raw: str) -> str:
    return raw.split(";", 1)[0].strip().lower()


@pytest.fixture(scope="module")
def live_gateway():
    port = _free_port()
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "gateway.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=str(REPO_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_port(port)
        yield port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def test_live_api_status_is_json(live_gateway):
    status, ct, body = _request(live_gateway, "/api/status")
    assert status in (200, 503)
    assert _content_type(ct) == "application/json", (
        f"/api/status leaked non-JSON over the socket: ct={ct!r} "
        f"body[:80]={body[:80]!r}"
    )
    assert not body.lstrip().startswith(b"<"), (
        f"/api/status returned HTML body: {body[:80]!r}"
    )
    payload = json.loads(body)
    assert isinstance(payload, dict)
    # deployment-sync fields must be present (Task: deployment-sync)
    for key in ("git_commit", "deployment_revision", "policy_version", "runtime_status"):
        assert key in payload, f"/api/status missing field: {key}"


def test_live_api_governance_evidence_is_json(live_gateway):
    status, ct, body = _request(live_gateway, "/api/governance/evidence")
    assert status in (200, 404, 503)
    assert _content_type(ct) == "application/json", (
        f"/api/governance/evidence leaked non-JSON: ct={ct!r}"
    )
    assert not body.lstrip().startswith(b"<")
    payload = json.loads(body)
    assert payload.get("state") in ("VERIFIED", "UNVERIFIED", "MISSING")
    assert "provenance_source" in payload


def test_live_unknown_api_path_is_json_404(live_gateway):
    status, ct, body = _request(live_gateway, "/api/does/not/exist")
    assert status == 404
    assert _content_type(ct) == "application/json", (
        f"unknown /api/* leaked HTML: ct={ct!r}"
    )
    payload = json.loads(body)
    assert payload.get("error") == "api_route_not_found"


def test_live_root_still_renders_dashboard_html(live_gateway):
    status, ct, body = _request(live_gateway, "/")
    assert status == 200
    assert _content_type(ct) == "text/html", (
        f"root path no longer serves HTML: ct={ct!r}"
    )
    assert body.lstrip().lower().startswith(b"<")
