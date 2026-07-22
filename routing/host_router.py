"""USBAY hostname surface router (fail-closed).

Maps each governed subdomain of usbay.global to a dedicated surface while
preserving the single shared FastAPI backend, its governance logic, audit
evidence, replay protection, and fail-closed defaults. No governance logic
lives here: this layer only decides which surface handles a request.

Fail-closed rules:
- malformed Host values      -> HTTP 400
- unknown hostnames          -> HTTP 404
- console without real ACL   -> HTTP 403 (locked state, no fake auth)
"""

import os
import re

from fastapi.responses import JSONResponse

from surfaces import landing, demo, api, pilot, docs, status, console

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")

SURFACE_HANDLERS = {
    "go.usbay.global": landing.handle,
    "demo.usbay.global": demo.handle,
    "api.usbay.global": api.handle,
    "pilot.usbay.global": pilot.handle,
    "docs.usbay.global": docs.handle,
    "status.usbay.global": status.handle,
    "console.usbay.global": console.handle,
}

_FALLBACK_EXACT = {"localhost", "127.0.0.1", "0.0.0.0", "testserver"}
_FALLBACK_SUFFIXES = (".workers.dev", ".replit.dev", ".repl.co", ".replit.app")


def normalize_host(raw):
    """Lowercase, strip the port, and validate the hostname.

    Returns the normalized hostname, or None when the value is malformed
    (the caller must fail closed with HTTP 400).
    """
    if raw is None:
        return None
    value = raw.strip().lower()
    if not value or len(value) > 512:
        return None
    if value.startswith("["):  # bracketed IPv6 literal, e.g. [::1]:5000
        end = value.find("]")
        if end == -1:
            return None
        host, rest = value[1:end], value[end + 1:]
        if rest and not re.fullmatch(r":\d{1,5}", rest):
            return None
        if not re.fullmatch(r"[0-9a-f:]+", host):
            return None
        return host
    if ":" in value:
        host, _, port = value.rpartition(":")
        if not re.fullmatch(r"\d{1,5}", port):
            return None
        value = host
    if not _HOST_RE.fullmatch(value):
        return None
    return value


def is_fallback_host(host):
    """Non-canonical diagnostic hosts (workers.dev, dev/test environments)."""
    if host in _FALLBACK_EXACT:
        return True
    dev_domain = (os.environ.get("REPLIT_DEV_DOMAIN") or "").strip().lower()
    if dev_domain and host == dev_domain:
        return True
    return any(host.endswith(suffix) for suffix in _FALLBACK_SUFFIXES)


def install_host_router(app):
    @app.middleware("http")
    async def usbay_host_surface_router(request, call_next):
        raw = request.headers.get("x-usbay-host") or request.headers.get("host")
        host = normalize_host(raw)
        if host is None:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "malformed_host",
                    "detail": "Host header is missing or malformed (fail-closed).",
                },
            )
        handler = SURFACE_HANDLERS.get(host)
        if handler is not None:
            response = await handler(request, call_next)
            response.headers.setdefault("X-USBAY-Surface", host.split(".")[0])
            return response
        if is_fallback_host(host):
            response = await call_next(request)
            response.headers.setdefault(
                "X-USBAY-Surface", "fallback-non-canonical"
            )
            return response
        return JSONResponse(
            status_code=404,
            content={
                "error": "unknown_host",
                "detail": "Hostname is not a governed USBAY surface (fail-closed).",
            },
        )

    return usbay_host_surface_router
