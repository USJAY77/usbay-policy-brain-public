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

    def test_pilot_dashboard(self):
        r = get("/", "pilot.usbay.global")
        assert r.status_code == 200
        assert "fail-closed" in r.text.lower()
        assert "Audit export controls" in r.text

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

    def test_pilot_does_not_serve_game(self):
        assert get("/game", "pilot.usbay.global").status_code == 404

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


class TestFallbackHost:
    def test_workers_dev_serves_full_app_non_canonical(self):
        r = get("/health",
                "usbay-demo-governance-app.security-usbay1.workers.dev")
        assert r.status_code == 200
        assert r.headers["X-USBAY-Surface"] == "fallback-non-canonical"

    def test_testserver_is_fallback(self):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.headers["X-USBAY-Surface"] == "fallback-non-canonical"
