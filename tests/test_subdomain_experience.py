from fastapi.testclient import TestClient

from gateway.app import app


client = TestClient(app, raise_server_exceptions=False)


def _get(host, path: str = "/", extra_headers=None):
    headers = dict(extra_headers or {})
    if host is not None:
        headers["host"] = host
    return client.get(path, headers=headers)


def _assert_blocked_host(response, reason: str):
    assert response.status_code == 421
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {
        "decision": "BLOCKED",
        "reason": reason,
        "host": "redacted",
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
    }


def test_localhost_preserves_existing_development_gateway_surface():
    response = _get("localhost")

    assert response.status_code == 200
    assert "USBAY" in response.text
    assert "application/json" not in response.headers["content-type"]


def test_localhost_with_port_preserves_existing_development_gateway_surface():
    response = _get("localhost:8000")

    assert response.status_code == 200
    assert "USBAY" in response.text
    assert "application/json" not in response.headers["content-type"]


def test_loopback_preserves_existing_development_gateway_surface():
    response = _get("127.0.0.1")

    assert response.status_code == 200
    assert "USBAY" in response.text
    assert "application/json" not in response.headers["content-type"]


def test_loopback_with_port_preserves_existing_development_gateway_surface():
    response = _get("127.0.0.1:8000")

    assert response.status_code == 200
    assert "USBAY" in response.text
    assert "application/json" not in response.headers["content-type"]


def test_each_canonical_subdomain_routes_to_assigned_surface():
    expected_surfaces = {
        "go.usbay.global": "USBAY Enterprise Governance",
        "demo.usbay.global": "USBAY Demo Governance Control Plane",
        "pilot.usbay.global": "USBAY Pilot Workspace",
        "docs.usbay.global": "USBAY Governance Documentation",
        "status.usbay.global": "USBAY Public Status",
        "console.usbay.global": "USBAY Governance Console",
    }
    for host, expected_text in expected_surfaces.items():
        response = _get(host)
        assert response.status_code in {200, 403}
        assert expected_text in response.text

    api_response = _get("api.usbay.global")
    assert api_response.status_code == 200
    assert api_response.headers["content-type"].startswith("application/json")
    assert api_response.json()["schema"] == "usbay.api_index.v1"


def test_uppercase_canonical_host_is_normalized_safely():
    response = _get("GO.USBAY.GLOBAL")

    assert response.status_code == 200
    assert "USBAY Enterprise Governance" in response.text


def test_canonical_host_with_allowed_port_routes_deterministically():
    response = _get("demo.usbay.global:443")

    assert response.status_code == 200
    assert "USBAY Demo Governance Control Plane" in response.text


def test_noncanonical_external_host_fails_closed():
    response = _get("attacker.example.com")

    _assert_blocked_host(response, "HOST_NOT_GOVERNED")


def test_workers_preview_host_fails_closed():
    response = _get("usbay-preview.workers.dev")

    _assert_blocked_host(response, "HOST_NOT_GOVERNED")


def test_malformed_host_fails_closed():
    response = _get("go.usbay.global@attacker.example")

    _assert_blocked_host(response, "HOST_HEADER_REQUIRED")


def test_missing_host_fails_closed():
    response = _get("")

    _assert_blocked_host(response, "HOST_HEADER_REQUIRED")


def test_spoofed_host_header_does_not_bypass_boundary():
    response = _get("attacker.example.com", extra_headers={"x-usbay-host": "go.usbay.global"})

    _assert_blocked_host(response, "HOST_NOT_GOVERNED")


def test_conflicting_proxy_host_does_not_override_localhost_boundary():
    response = _get("localhost", extra_headers={"x-usbay-host": "console.usbay.global"})

    assert response.status_code == 200
    assert "USBAY Governance Console" not in response.text
    assert "USBAY" in response.text


def test_existing_gateway_governance_routes_are_not_shadowed_for_local_development():
    response = _get("localhost", "/api/status")

    assert response.status_code in {200, 503}
    assert response.headers["content-type"].startswith("application/json")


def test_pilot_protected_routes_fail_closed_until_access_control_exists():
    response = _get("pilot.usbay.global", "/dashboard")

    assert response.status_code == 403
    assert "USBAY Pilot Workspace" in response.text
    assert "BLOCKED_403_PILOT_ACCESS_REQUIRED" in response.text


def _subdomain_get(host: str, path: str = "/"):
    return client.get(path, headers={"host": host})


def test_go_subdomain_renders_enterprise_landing_page():
    response = _subdomain_get("go.usbay.global")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "USBAY Enterprise Governance" in response.text
    assert "Paid Intake" in response.text
    assert "Book Demo CTA" in response.text
    assert "No production activation" in response.text


def test_demo_subdomain_renders_governance_demo_surface():
    response = _subdomain_get("demo.usbay.global")

    assert response.status_code == 200
    assert "Governance Control Plane" in response.text
    assert "USBAY Game" in response.text
    assert "Governance Simulator" in response.text
    assert "No runtime execution" in response.text


def test_api_subdomain_returns_json_only_index_and_docs():
    index_response = _subdomain_get("api.usbay.global")
    docs_response = _subdomain_get("api.usbay.global", "/docs")
    redoc_response = _subdomain_get("api.usbay.global", "/redoc")

    for response in (index_response, docs_response, redoc_response):
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        assert response.json()["json_only"] is True
        assert response.json()["execution_allowed"] is False
        assert response.json()["provider_execution"] is False
        assert response.json()["production_activation"] is False

    assert index_response.json()["openapi"] == "/openapi.json"
    assert docs_response.json()["openapi"] == "/openapi.json"
    assert redoc_response.json()["openapi"] == "/openapi.json"


def test_api_subdomain_unknown_paths_fail_closed_as_json():
    response = _subdomain_get("api.usbay.global", "/not-a-route")

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {
        "error": "api_route_not_found",
        "path": "/not-a-route",
        "json_only": True,
    }


def test_pilot_subdomain_renders_shell_without_activation():
    response = _subdomain_get("pilot.usbay.global")

    assert response.status_code == 200
    assert "USBAY Pilot Workspace" in response.text
    assert "Pilot Login Shell" in response.text
    assert "PILOT_SHELL_ONLY" in response.text
    assert "No production activation" in response.text


def test_docs_subdomain_renders_governance_documentation_sections():
    response = _subdomain_get("docs.usbay.global")

    assert response.status_code == 200
    assert "USBAY Governance Documentation" in response.text
    assert "Architecture" in response.text
    assert "Governance Manual" in response.text
    assert "Search" in response.text
    assert "No external indexing" in response.text


def test_status_subdomain_does_not_show_false_green_state():
    response = _subdomain_get("status.usbay.global")

    assert response.status_code == 200
    assert "USBAY Public Status" in response.text
    assert "UNVERIFIED_UNTIL_BACKEND_PROOF" in response.text
    assert "No false green state" in response.text


def test_console_subdomain_fails_closed_until_authenticated():
    response = _subdomain_get("console.usbay.global")

    assert response.status_code == 403
    assert "USBAY Governance Console" in response.text
    assert "Cloudflare Access Placeholder" in response.text
    assert "BLOCKED_403_AUTHENTICATION_REQUIRED" in response.text
    assert "Execution blocked" in response.text
    assert "Production activation blocked" in response.text


def test_internal_test_host_preserves_existing_gateway_surface():
    response = client.get("/")

    assert response.status_code == 200
    assert "USBAY" in response.text
    assert "application/json" not in response.headers["content-type"]
