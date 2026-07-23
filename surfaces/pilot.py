"""pilot.usbay.global - governed pilot shell (fail-closed, access restricted).

Real identity and tenant isolation are not yet implemented, so this surface
permits only one explicitly marked preview page plus /health. Every other
route is blocked fail-closed with HTTP 403. No fake authentication claims,
no customer data, no live export controls.
"""

from fastapi.responses import JSONResponse

from surfaces._shared import page

_ALLOWED_GET = {"/health"}

_BODY = """
  <div style="background:#7c2d12;color:#ffedd5;border-radius:8px;padding:10px 16px;
       font-size:12px;font-weight:700;letter-spacing:0.08em;margin-bottom:20px">
    PILOT ACCESS RESTRICTED &mdash; EXPLICITLY MARKED PREVIEW PAGE ONLY.
    Real identity and tenant isolation are not yet active; all protected
    routes are blocked fail-closed.
  </div>
  <h1>Pilot dashboard (preview)</h1>
  <p class="lead">Governed customer pilot environment. Nothing on this page
  represents live customer data, and no authentication claim is made or
  implied.</p>
  <div class="grid">
    <div class="card"><h2>Login</h2>
      <p>Placeholder &mdash; verified identity control (for example
      Cloudflare Access) is not yet configured for this hostname. Until it
      is, sign-in is unavailable and protected routes return 403.</p>
      <p style="margin-top:8px"><span class="pill">Status: NOT CONFIGURED</span></p></div>
    <div class="card"><h2>Governance scans</h2>
      <p>Placeholder &mdash; pilot governance scans will appear here once
      pilot identity and tenant isolation are active.</p>
      <p style="margin-top:8px"><span class="pill">LOCKED (fail-closed)</span></p></div>
    <div class="card"><h2>Executive reports</h2>
      <p>Placeholder &mdash; executive governance reports are generated per
      tenant and require verified access.</p>
      <p style="margin-top:8px"><span class="pill">LOCKED (fail-closed)</span></p></div>
    <div class="card"><h2>Audit exports</h2>
      <p>Placeholder &mdash; audit evidence exports remain disabled on this
      surface until verified access controls are active.</p>
      <p style="margin-top:8px"><span class="pill">LOCKED (fail-closed)</span></p></div>
  </div>
  <p class="note">Requests without identity, tenant, policy, evidence, or
  approval context are rejected &mdash; never silently executed.</p>
"""


async def handle(request, call_next):
    path = request.url.path
    if path in ("/", "") and request.method in ("GET", "HEAD"):
        return page("USBAY Pilot — Access Restricted",
                    "Governed Pilot Environment (Preview)", _BODY)
    if path in _ALLOWED_GET and request.method in ("GET", "HEAD"):
        return await call_next(request)
    return JSONResponse(
        status_code=403,
        content={
            "error": "pilot_access_restricted",
            "detail": ("Protected pilot routes are blocked fail-closed until "
                       "verified identity and tenant isolation are active."),
        },
    )
