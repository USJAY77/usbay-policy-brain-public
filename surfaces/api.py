"""api.usbay.global - API-only surface (no demo dashboard)."""

from fastapi.responses import JSONResponse

from surfaces._shared import not_found

_ALLOWED_GET = {
    "/health",
    "/api/status",
    "/api/governance/evidence",
    "/openapi.json",
    "/docs",
    "/redoc",
    "/docs/oauth2-redirect",
}


async def handle(request, call_next):
    path = request.url.path
    if path in ("/", "") and request.method in ("GET", "HEAD"):
        return JSONResponse(
            content={
                "service": "USBAY Gateway API",
                "surface": "api.usbay.global",
                "endpoints": [
                    "GET /health",
                    "GET /api/status",
                    "GET /api/governance/evidence",
                    "GET /openapi.json",
                    "GET /docs",
                ],
                "documentation": "https://docs.usbay.global/",
                "governance": "fail-closed; execution only via the governed gateway",
            }
        )
    allowed = path in _ALLOWED_GET or path.startswith("/api/governance/")
    if allowed and request.method in ("GET", "HEAD"):
        return await call_next(request)
    return not_found("api.usbay.global")
