"""go.usbay.global - public landing and paid intake surface."""

from surfaces._shared import page, not_found

_ALLOWED_PASSTHROUGH = {"/health"}

_BODY = """
  <h1>The execution control layer for governed AI operations</h1>
  <p class="lead">USBAY sits between intent and execution. Every action is
  policy-validated, evidence-backed, replay-protected, and fail-closed by
  default &mdash; nothing executes outside the governed gateway.</p>
  <div class="grid">
    <div class="card"><h2>Governance overview</h2>
      <ul>
        <li>Fail-closed execution gateway &mdash; no policy, no execution</li>
        <li>Human approval controls for privileged actions</li>
        <li>Tamper-evident audit chain and evidence exports</li>
        <li>Runtime health authority with policy-driven degradation</li>
      </ul>
    </div>
    <div class="card"><h2>Paid intake</h2>
      <p>Engage USBAY for a governed pilot or a production deployment.
      Submit a pilot request from the demonstration environment; every
      request is captured with an accountable requester and routed through
      governance approval before any environment is provisioned.</p>
      <a class="btn primary" href="https://demo.usbay.global/">Start a pilot request</a>
    </div>
    <div class="card"><h2>See it live</h2>
      <p>Explore the governance control plane, the simulator, and the
      interactive demonstration &mdash; no signup, no data collection.</p>
      <a class="btn ghost" href="https://demo.usbay.global/">Open the demo</a>
      <a class="btn ghost" href="https://docs.usbay.global/">Read the docs</a>
    </div>
  </div>
  <p class="note">This surface exposes no runtime controls and collects no
  customer data unless explicitly submitted. Service status:
  <a href="https://status.usbay.global/" style="color:#7dd3fc">status.usbay.global</a></p>
"""


async def handle(request, call_next):
    path = request.url.path
    if path in ("/", "") and request.method in ("GET", "HEAD"):
        return page("USBAY — Execution Control Layer", "Public Landing", _BODY)
    if path in _ALLOWED_PASSTHROUGH and request.method in ("GET", "HEAD"):
        return await call_next(request)
    return not_found("go.usbay.global")
