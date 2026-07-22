"""console.usbay.global - internal governance console (locked, fail-closed).

No real access-control mechanism (SSO/OIDC, mTLS, or Cloudflare Access) is
currently configured for this hostname, and fake authentication is
prohibited. Therefore every request renders a locked state with HTTP 403.
The access-control gap is reported explicitly so it can be remediated by
configuring a real mechanism (recommended: Cloudflare Access in front of
this hostname).
"""

from fastapi.responses import HTMLResponse

from surfaces._shared import STYLE

_LOCKED_HTML = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>USBAY Console — Locked</title>
<style>{STYLE}</style>
</head>
<body>
<div class="wrap">
  <header class="usb">
    <span class="logo">USBAY</span>
    <span class="role">Internal Governance Console</span>
  </header>
  <h1>Console locked (fail-closed)</h1>
  <p class="lead">This internal console (Policy Brain, runtime governance,
  audit viewer, evidence explorer, deployment state, system health) requires
  a real access-control mechanism. None is currently configured for
  <code>console.usbay.global</code>, so access is denied for all requests.
  No fake authentication is implemented.</p>
  <div class="card">
    <h2>Access-control gap</h2>
    <p>To unlock this surface, place a real identity-aware access layer in
    front of this hostname (for example Cloudflare Access with an identity
    provider, or mutual TLS). Until then the console remains locked and
    fail-closed.</p>
  </div>
</div>
</body>
</html>"""


async def handle(request, call_next):
    response = HTMLResponse(content=_LOCKED_HTML, status_code=403)
    response.headers["X-USBAY-Console"] = "locked-no-access-control"
    return response
