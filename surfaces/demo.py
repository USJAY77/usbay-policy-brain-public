"""demo.usbay.global - public demonstration environment.

Full passthrough to the governed backend (control plane demo, USBAY game,
governance simulator, guided tour, executive report preview) with a visible
DEMO ONLY disclaimer injected into every HTML page. No governance logic is
altered; /execute keeps its fail-closed behavior from the shared backend.
"""

from starlette.responses import Response

_BANNER = (
    b'<div style="position:sticky;top:0;z-index:2147483647;background:#7c2d12;'
    b'color:#ffedd5;font:600 12px/1.4 system-ui,sans-serif;text-align:center;'
    b'padding:6px 12px;letter-spacing:0.08em;" data-usbay-demo-banner="1">'
    b'DEMO ONLY &mdash; public demonstration environment. No real payments, '
    b'no real execution, no production credentials.</div>'
)


async def handle(request, call_next):
    response = await call_next(request)
    content_type = response.headers.get("content-type", "")
    if "text/html" not in content_type:
        return response
    chunks = [chunk async for chunk in response.body_iterator]
    body = b"".join(chunks)
    lowered = body.lower()
    idx = lowered.find(b"<body")
    if idx != -1:
        close = body.find(b">", idx)
        if close != -1:
            body = body[: close + 1] + _BANNER + body[close + 1:]
    headers = dict(response.headers)
    headers.pop("content-length", None)
    return Response(
        content=body,
        status_code=response.status_code,
        headers=headers,
        media_type=content_type.split(";")[0] or "text/html",
    )
