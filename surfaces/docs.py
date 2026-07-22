"""docs.usbay.global - documentation surface."""

from surfaces._shared import page, not_found

_ALLOWED_GET = {"/health", "/openapi.json", "/docs", "/redoc", "/docs/oauth2-redirect"}

_BODY = """
  <h1>USBAY documentation</h1>
  <p class="lead">Architecture, governance model, execution control layer,
  API reference, deployment, and the audit &amp; evidence model.</p>
  <div class="grid">
    <div class="card"><h2>Architecture</h2>
      <p>A single governed FastAPI gateway is the only execution path.
      A Cloudflare Worker proxies all traffic to the containerized gateway;
      each public hostname maps to a dedicated surface, and all surfaces
      share one backend &mdash; governance logic is never duplicated.</p></div>
    <div class="card"><h2>Governance model</h2>
      <p>Decisions flow through policy validation, runtime health authority,
      human approval controls, and replay protection. Defaults are
      fail-closed: missing context means rejection, never execution.</p></div>
    <div class="card"><h2>Execution control layer</h2>
      <p>Real execution cannot happen outside the gateway. The
      <code>/execute</code> endpoint rejects unauthenticated or
      contract-less requests, and every allowed execution emits signed
      audit evidence.</p></div>
    <div class="card"><h2>API documentation</h2>
      <p>Interactive reference and the OpenAPI schema:</p>
      <a class="btn primary" href="/docs">Interactive API docs</a>
      <a class="btn ghost" href="/openapi.json">openapi.json</a>
      <p style="margin-top:10px">API base: <code>https://api.usbay.global</code></p></div>
    <div class="card"><h2>Deployment</h2>
      <p>Deployed on Cloudflare Containers: a Worker fronts the gateway
      container (Firecracker microVM). The <code>workers.dev</code> hostname
      remains available as a non-canonical diagnostic fallback.</p></div>
    <div class="card"><h2>Audit &amp; evidence model</h2>
      <p>Every governed decision appends to a tamper-evident audit chain.
      Evidence bundles, execution contracts, and regulator-facing exports
      are available through the governance evidence API.</p></div>
  </div>
  <p class="note">This documentation contains no internal secrets or
  operational credentials.</p>
"""


async def handle(request, call_next):
    path = request.url.path
    if path in ("/", "") and request.method in ("GET", "HEAD"):
        return page("USBAY Docs", "Documentation", _BODY)
    if path in _ALLOWED_GET and request.method in ("GET", "HEAD"):
        return await call_next(request)
    return not_found("docs.usbay.global")
