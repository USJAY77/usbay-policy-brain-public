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


def test_api_middleware_rewrites_stray_html_to_json(client):
    # Defense-in-depth: even if some future router accidentally
    # returns HTML on an /api/* path, the gateway middleware must
    # rewrite it to a JSON envelope before it leaves the process.
    from fastapi.responses import HTMLResponse

    def _leak_html():  # pragma: no cover - registered for one test only
        return HTMLResponse("<!DOCTYPE html><html><body>leak</body></html>")

    gateway_app.app.add_api_route(
        "/api/_test/leak_html", _leak_html, methods=["GET"],
    )
    # Move the freshly-added route ahead of the catch-all `/api/{path}`
    # so it actually executes; otherwise the catch-all answers first
    # and we never exercise the middleware's HTML->JSON rewrite path.
    leaked = gateway_app.app.router.routes.pop()
    gateway_app.app.router.routes.insert(0, leaked)

    try:
        res = client.get("/api/_test/leak_html")
        assert _content_type(res) == "application/json", (
            f"HTML leaked through middleware on /api/*: "
            f"content-type={res.headers.get('content-type')!r}"
        )
        body = res.json()
        assert body.get("error") == "api_contract_violation"
        assert body.get("path") == "/api/_test/leak_html"
        assert res.status_code == 502
    finally:
        # Remove the test-only route so it doesn't bleed into other tests.
        gateway_app.app.router.routes = [
            r for r in gateway_app.app.router.routes
            if getattr(r, "path", None) != "/api/_test/leak_html"
        ]


def test_api_middleware_passes_through_non_html_non_json_responses(client):
    # The middleware must only guard against HTML leakage. Legitimate
    # non-JSON API responses (octet-stream binaries, SSE event streams,
    # 204 No Content with empty body) must pass through untouched.
    from fastapi import Response

    def _binary():  # pragma: no cover - test-only route
        return Response(
            content=b"\x00\x01\x02",
            media_type="application/octet-stream",
            status_code=200,
        )

    def _sse():  # pragma: no cover - test-only route
        return Response(
            content="data: ping\n\n",
            media_type="text/event-stream",
            status_code=200,
        )

    def _no_content():  # pragma: no cover - test-only route
        return Response(status_code=204)

    routes = [
        ("/api/_test/binary", _binary, "application/octet-stream", 200),
        ("/api/_test/sse", _sse, "text/event-stream", 200),
        ("/api/_test/empty", _no_content, "", 204),
    ]
    added = []
    for path, fn, _expected_ct, _expected_status in routes:
        gateway_app.app.add_api_route(path, fn, methods=["GET"])
        added.append(gateway_app.app.router.routes.pop())
    for r in reversed(added):
        gateway_app.app.router.routes.insert(0, r)

    try:
        for path, _fn, expected_ct, expected_status in routes:
            res = client.get(path)
            assert res.status_code == expected_status, (
                f"{path} status changed: got {res.status_code}"
            )
            actual_ct = _content_type(res)
            assert actual_ct == expected_ct, (
                f"{path} content-type rewritten by middleware: "
                f"expected={expected_ct!r} got={actual_ct!r}"
            )
    finally:
        leak_paths = {p for p, *_ in routes}
        gateway_app.app.router.routes = [
            r for r in gateway_app.app.router.routes
            if getattr(r, "path", None) not in leak_paths
        ]


def test_api_status_explicit_json_content_type(client):
    # Live-deployment regression: assert the exact application/json
    # content-type header for the two routes the report flagged.
    for path in ("/api/status", "/api/governance/evidence"):
        res = client.get(path)
        assert _content_type(res) == "application/json", (
            f"{path} returned non-JSON content-type="
            f"{res.headers.get('content-type')!r}"
        )
        assert not res.text.lstrip().startswith("<"), (
            f"{path} body looks like HTML: {res.text[:80]!r}"
        )
