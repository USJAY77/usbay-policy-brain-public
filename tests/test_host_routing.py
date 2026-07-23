"""Tests for fail-closed hostname surface routing (routing/host_router.py)."""

import pytest
from fastapi.testclient import TestClient

from gateway.app import app
from routing.host_router import normalize_host

client = TestClient(app)


def get(path, host, **kw):
    return client.get(path, headers={"X-USBAY-Host": host}, **kw)


class TestHostNormalization:
    def test_lowercase(self):
        assert normalize_host("GO.USBAY.GLOBAL") == "go.usbay.global"

    def test_strip_port(self):
        assert normalize_host("api.usbay.global:443") == "api.usbay.global"

    def test_malformed_rejected(self):
        assert normalize_host("bad host!") is None
        assert normalize_host("") is None
        assert normalize_host(None) is None
        assert normalize_host("host:notaport") is None
        assert normalize_host("a" * 600) is None


class TestSupportedHostnames:
    def test_landing(self):
        r = get("/", "go.usbay.global")
        assert r.status_code == 200
        assert "execution control layer" in r.text.lower()
        assert r.headers["X-USBAY-Surface"] == "go"

    def test_demo_dashboard_with_disclaimer(self):
        r = get("/", "demo.usbay.global")
        assert r.status_code == 200
        assert "DEMO ONLY" in r.text

    def test_demo_game_with_disclaimer(self):
        r = get("/game", "demo.usbay.global")
        assert r.status_code == 200
        assert "DEMO ONLY" in r.text

    def test_api_root_is_json_not_dashboard(self):
        r = get("/", "api.usbay.global")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/json")
        assert r.json()["service"] == "USBAY Gateway API"

    def test_api_allowed_endpoints(self):
        for path in ("/health", "/api/status", "/api/governance/evidence",
                     "/openapi.json"):
            r = get(path, "api.usbay.global")
            assert r.status_code == 200, path

    def test_pilot_preview_is_marked_restricted(self):
        r = get("/", "pilot.usbay.global")
        assert r.status_code == 200
        assert "PILOT ACCESS RESTRICTED" in r.text
        assert "fail-closed" in r.text.lower()
        # No fake authentication claims.
        assert "NOT CONFIGURED" in r.text

    def test_docs(self):
        r = get("/", "docs.usbay.global")
        assert r.status_code == 200
        assert "Governance model" in r.text or "governance model" in r.text.lower()

    def test_status(self):
        r = get("/", "status.usbay.global")
        assert r.status_code == 200
        assert "Last updated" in r.text


class TestFailClosed:
    def test_unknown_hostname(self):
        r = get("/", "evil.example.com")
        assert r.status_code == 404
        assert r.json()["error"] == "unknown_host"

    def test_hostname_with_port_routes(self):
        r = get("/", "go.usbay.global:443")
        assert r.status_code == 200
        assert r.headers["X-USBAY-Surface"] == "go"

    def test_uppercase_hostname_routes(self):
        r = get("/", "API.USBAY.GLOBAL")
        assert r.status_code == 200
        assert r.json()["service"] == "USBAY Gateway API"

    def test_malformed_host_header(self):
        r = get("/", "bad host !!")
        assert r.status_code == 400
        assert r.json()["error"] == "malformed_host"

    def test_console_locked_without_access_control(self):
        r = get("/", "console.usbay.global")
        assert r.status_code == 403
        assert r.headers["X-USBAY-Console"] == "locked-no-access-control"
        assert "locked" in r.text.lower()

    def test_console_locked_on_all_paths(self):
        for path in ("/game", "/api/status", "/health"):
            r = get(path, "console.usbay.global")
            assert r.status_code == 403, path


class TestNoCrossSurfaceLeakage:
    def test_landing_does_not_serve_game(self):
        assert get("/game", "go.usbay.global").status_code == 404

    def test_landing_does_not_serve_apis(self):
        assert get("/api/status", "go.usbay.global").status_code == 404

    def test_api_does_not_serve_game_or_simulator(self):
        assert get("/game", "api.usbay.global").status_code == 404
        assert get("/simulator", "api.usbay.global").status_code == 404

    def test_pilot_protected_routes_fail_closed(self):
        for path in ("/game", "/api/status", "/api/governance/evidence",
                     "/api/governance/evidence-export", "/simulator"):
            r = get(path, "pilot.usbay.global")
            assert r.status_code == 403, path
            assert r.json()["error"] == "pilot_access_restricted"

    def test_pilot_bypass_attempts_fail_closed(self):
        # Query parameters and cookies must not bypass the restriction.
        r = client.get("/api/status?admin=1&access=granted",
                       headers={"X-USBAY-Host": "pilot.usbay.global"},
                       cookies={"session": "forged", "access": "granted"})
        assert r.status_code == 403

    def test_status_does_not_serve_evidence_export(self):
        assert get("/api/governance/evidence-export",
                   "status.usbay.global").status_code == 404

    def test_docs_does_not_serve_dashboard_apis(self):
        assert get("/api/governance/evidence", "docs.usbay.global").status_code == 404


class TestExecuteFailClosedPreserved:
    def test_fallback_get_execute_404(self):
        r = client.get("/execute", headers={"X-USBAY-Host": "testserver"})
        assert r.status_code == 404

    def test_fallback_post_execute_403(self):
        r = client.post("/execute", json={},
                        headers={"X-USBAY-Host": "testserver"})
        assert r.status_code == 403

    def test_demo_post_execute_still_fail_closed(self):
        r = client.post("/execute", json={},
                        headers={"X-USBAY-Host": "demo.usbay.global"})
        assert r.status_code == 403

    def test_execute_not_exposed_on_api_surface(self):
        r = client.post("/execute", json={},
                        headers={"X-USBAY-Host": "api.usbay.global"})
        assert r.status_code == 404


class TestSecurityHeaders:
    def test_html_surfaces_get_security_headers(self):
        for host in ("go.usbay.global", "docs.usbay.global",
                     "status.usbay.global", "pilot.usbay.global"):
            r = get("/", host)
            assert r.headers["X-Content-Type-Options"] == "nosniff", host
            assert "Referrer-Policy" in r.headers, host
            assert "Permissions-Policy" in r.headers, host
            csp = r.headers.get("Content-Security-Policy", "")
            assert "frame-ancestors 'none'" in csp, host

    def test_pilot_and_console_no_store(self):
        assert get("/", "pilot.usbay.global").headers["Cache-Control"] == "no-store"
        assert get("/", "console.usbay.global").headers["Cache-Control"] == "no-store"

    def test_api_keeps_json_content_type(self):
        r = get("/api/status", "api.usbay.global")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/json")
        assert r.headers["X-Content-Type-Options"] == "nosniff"

    def test_console_bypass_via_query_and_cookies_denied(self):
        r = client.get("/?access=granted&token=x",
                       headers={"X-USBAY-Host": "console.usbay.global"},
                       cookies={"auth": "forged"})
        assert r.status_code == 403

    def test_status_page_has_no_sensitive_telemetry(self):
        text = get("/", "status.usbay.global").text
        for forbidden in ("traceback", "account_id", "CLOUDFLARE", "token",
                          "secret", "tenant_id"):
            assert forbidden.lower() not in text.lower(), forbidden
        assert "UNKNOWN" in text  # availability never fabricated


class TestMissingHost:
    def test_missing_host_denied(self):
        from routing.host_router import normalize_host
        assert normalize_host(None) is None
        assert normalize_host("") is None


class TestFallbackHost:
    def test_workers_dev_does_not_expose_internal_console(self):
        # The internal console exists only behind console.usbay.global,
        # which is always locked; the fallback host serves the standard
        # governed app and never a console surface.
        r = get("/", "usbay-demo-governance-app.security-usbay1.workers.dev")
        assert r.status_code == 200
        assert r.headers["X-USBAY-Surface"] == "fallback-non-canonical"
        assert "X-USBAY-Console" not in r.headers
        # Even a spoofed console host resolves to the locked surface.
        r2 = get("/", "console.usbay.global")
        assert r2.status_code == 403


    def test_workers_dev_serves_full_app_non_canonical(self):
        r = get("/health",
                "usbay-demo-governance-app.security-usbay1.workers.dev")
        assert r.status_code == 200
        assert r.headers["X-USBAY-Surface"] == "fallback-non-canonical"

    def test_testserver_is_fallback(self):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.headers["X-USBAY-Surface"] == "fallback-non-canonical"
