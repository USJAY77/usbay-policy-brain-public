"""Early-bind boot wrapper for the USBAY gateway.

Binds 0.0.0.0:$PORT within ~1s and exposes explicit startup phases while the
real gateway (``gateway.app``) imports and runs its fail-closed governance
lifespan in the background:

    STARTING   -> importing gateway.app (cold starts pay ~10s of bytecode
                  compilation here; the port is already bound)
    VERIFYING  -> gateway.app lifespan: runtime commit stamp, policy registry
                  validation, deployment commit sync (all fail-closed)
    READY      -> all governance checks passed; requests delegate to the app
    FAILED     -> a governance check raised; every request gets 503 forever

Fail-closed contract: until READY, EVERY path (including /execute) returns
503 with the current phase — no execution authorization is possible before
the governance checks pass, and FAILED never recovers without a restart.
No governance logic lives here; this only defers when the socket opens.
Diagnostics log phase, component, elapsed ms and PASS/FAIL only — no
payloads, no secrets.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

logger = logging.getLogger("usbay.gateway.boot")

_PHASE_STARTING = "STARTING"
_PHASE_VERIFYING = "VERIFYING"
_PHASE_READY = "READY"
_PHASE_FAILED = "FAILED"

_state = {
    "phase": _PHASE_STARTING,
    "error_code": None,  # non-sensitive exception class name only
    "t0": time.monotonic(),
    "timings_ms": {},
}
_real_app = None
_lifespan_cm = None


def _elapsed_ms() -> int:
    return int((time.monotonic() - _state["t0"]) * 1000)


def _mark(component: str, ok: bool) -> None:
    _state["timings_ms"][component] = _elapsed_ms()
    logger.info(
        "boot phase=%s component=%s elapsed_ms=%d result=%s",
        _state["phase"], component, _elapsed_ms(), "PASS" if ok else "FAIL",
    )


async def _bring_up() -> None:
    global _real_app, _lifespan_cm
    try:
        loop = asyncio.get_running_loop()

        def _import():
            from gateway.app import app as real_app  # heavy: full governance import
            return real_app

        _real_app = await loop.run_in_executor(None, _import)
        _mark("import_gateway_app", True)

        _state["phase"] = _PHASE_VERIFYING
        # Run the real app's fail-closed lifespan (runtime commit stamp,
        # policy registry validation, deployment commit sync). Any raise
        # here transitions to FAILED and stays blocked.
        _lifespan_cm = _real_app.router.lifespan_context(_real_app)
        await _lifespan_cm.__aenter__()
        _mark("governance_lifespan", True)

        _state["phase"] = _PHASE_READY
        _mark("ready", True)
    except BaseException as exc:  # noqa: BLE001 — must never fail open
        _state["phase"] = _PHASE_FAILED
        _state["error_code"] = type(exc).__name__
        _mark("bring_up", False)
        logger.error("boot FAILED error_code=%s (fail-closed; serving 503)", type(exc).__name__)


async def _send_json(send, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode()
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-type", b"application/json"), (b"cache-control", b"no-store")],
    })
    await send({"type": "http.response.body", "body": body})


async def asgi(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                asyncio.get_running_loop().create_task(_bring_up())
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                if _lifespan_cm is not None and _state["phase"] == _PHASE_READY:
                    try:
                        await _lifespan_cm.__aexit__(None, None, None)
                    except Exception:  # noqa: BLE001
                        logger.warning("boot shutdown: lifespan exit error (ignored)")
                await send({"type": "lifespan.shutdown.complete"})
                return
        return

    if _state["phase"] == _PHASE_READY and _real_app is not None:
        await _real_app(scope, receive, send)
        return

    # Not READY: fail closed for everything. 503 + Retry-After keeps the
    # Replit preview polling instead of showing a hard error.
    payload = {
        "status": _state["phase"],
        "phase": _state["phase"],
        "execution_authorized": False,
        "elapsed_ms": _elapsed_ms(),
    }
    if _state["error_code"]:
        payload["error_code"] = _state["error_code"]
    await _send_json(send, 503, payload)
