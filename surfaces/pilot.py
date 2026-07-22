"""pilot.usbay.global - governed customer pilot environment (fail-closed)."""

from surfaces._shared import page, not_found

_ALLOWED_GET = {
    "/health",
    "/api/status",
    "/api/governance/evidence",
    "/api/governance/evidence-store",
    "/api/governance/evidence-export",
    "/api/runtime/governance",
}

_BODY = """
  <h1>Pilot dashboard</h1>
  <p class="lead">Governed pilot environment. All execution is fail-closed:
  requests without identity, tenant, policy, evidence, or approval context
  are rejected by the gateway. No unrestricted execution exists on this
  surface.</p>
  <div class="grid">
    <div class="card"><h2>Governance status</h2>
      <p id="gov-status">Loading&hellip;</p></div>
    <div class="card"><h2>Evidence summary</h2>
      <p id="evidence">Loading&hellip;</p></div>
    <div class="card"><h2>Audit export controls</h2>
      <p>Export the current governance evidence bundle for audit review.</p>
      <a class="btn primary" href="/api/governance/evidence-export">Export evidence (JSON)</a>
      <a class="btn ghost" href="/api/governance/evidence-store">Evidence store</a>
    </div>
    <div class="card"><h2>Pilot state</h2>
      <p><span class="pill">Fail-closed enforcement: ACTIVE</span></p>
      <p id="pilot-state" style="margin-top:8px">Loading&hellip;</p></div>
  </div>
  <p class="note">Missing identity, tenant, policy, evidence, or approval
  context results in rejection &mdash; never silent execution.</p>
  <script>
    fetch('/api/status').then(function(r){return r.json();}).then(function(s){
      document.getElementById('gov-status').textContent =
        'Gateway ' + (s.status||'UNKNOWN') + ' | mode ' + (s.mode||'?') +
        ' | policy ' + (s.policy_state||'?') +
        ' | replay protection ' + (s.replay_protection_active ? 'active' : 'inactive');
      document.getElementById('pilot-state').textContent =
        'Runtime mode: ' + (s.mode||'?') + ' (' + (s.reason||'') + ')';
    }).catch(function(){
      document.getElementById('gov-status').textContent = 'Unavailable (fail-closed)';
      document.getElementById('pilot-state').textContent = 'Unavailable (fail-closed)';
    });
    fetch('/api/governance/evidence').then(function(r){return r.json();}).then(function(e){
      var keys = Object.keys(e||{});
      document.getElementById('evidence').textContent =
        keys.length ? ('Evidence available: ' + keys.slice(0,6).join(', ')) : 'No evidence returned';
    }).catch(function(){
      document.getElementById('evidence').textContent = 'Unavailable (fail-closed)';
    });
  </script>
"""


async def handle(request, call_next):
    path = request.url.path
    if path in ("/", "") and request.method in ("GET", "HEAD"):
        return page("USBAY Pilot", "Governed Pilot Environment", _BODY)
    if path in _ALLOWED_GET and request.method in ("GET", "HEAD"):
        return await call_next(request)
    return not_found("pilot.usbay.global")
