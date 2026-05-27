"""Lock the routing contract that prevents the frontend SPA catch-all
from shadowing `/api/*` paths.

The deployment regression that motivated this test was:

  curl -L .../api/status            -> HTML (dashboard page)
  curl -L .../api/governance/evidence -> HTML (dashboard page)

Both should return application/json. The root path `/` must keep
serving the dashboard HTML. The fail-closed semantics of
`/api/governance/evidence` (VERIFIED -> 200, MISSING -> 404,
UNVERIFIED -> 503) must be preserved.

These tests assert the contract end-to-end through the FastAPI app
without touching governance, evidence, replay, revocation, or
attestation logic.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import gateway.app as gateway_app


@pytest.fixture
def client():
    return TestClient(gateway_app.app, raise_server_exceptions=False)


def _content_type(response) -> str:
    return response.headers.get("content-type", "").split(";", 1)[0].strip().lower()


def test_root_serves_dashboard_html(client):
    res = client.get("/")
    assert res.status_code == 200
    assert _content_type(res) == "text/html"
    assert "<" in res.text  # smoke: actually HTML, not JSON


def test_api_status_returns_json(client):
    res = client.get("/api/status")
    assert res.status_code == 200
    assert _content_type(res) == "application/json"
    body = res.json()  # raises on non-JSON
    assert isinstance(body, dict)


def test_api_health_returns_json(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    assert _content_type(res) == "application/json"
    res.json()


def test_api_governance_evidence_returns_json(client):
    res = client.get("/api/governance/evidence")
    # VERIFIED -> 200, MISSING -> 404, UNVERIFIED -> 503; all JSON.
    assert res.status_code in (200, 404, 503)
    assert _content_type(res) == "application/json"
    body = res.json()
    assert isinstance(body, dict)
    assert body.get("state") in ("VERIFIED", "UNVERIFIED", "MISSING")
    # Fail-closed contract preserved: provenance source is always present.
    assert "provenance_source" in body


def test_unknown_api_path_returns_json_not_html(client):
    res = client.get("/api/this/does/not/exist")
    assert res.status_code == 404
    assert _content_type(res) == "application/json"
    body = res.json()
    assert body.get("error") == "api_route_not_found"


def test_spa_fallback_never_shadows_api_prefix(client):
    # Direct hit on the SPA catch-all path shape: must still refuse
    # to render HTML for anything under /api/.
    for path in ("/api/", "/api/status", "/api/governance/evidence", "/api/x/y/z"):
        res = client.get(path)
        assert _content_type(res) == "application/json", (
            f"{path} leaked through SPA fallback: content-type="
            f"{res.headers.get('content-type')!r}"
        )


def test_spa_fallback_still_serves_unknown_frontend_paths_as_html(client):
    res = client.get("/some/unknown/frontend/route")
    assert res.status_code == 200
    assert _content_type(res) == "text/html"
