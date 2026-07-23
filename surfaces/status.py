"""status.usbay.global - public service status surface."""

from surfaces._shared import page, not_found

_ALLOWED_GET = {
    "/health",
    "/api/status",
    "/api/runtime/health",
    "/api/deployment/health",
}

_BODY = """
  <h1>USBAY service status</h1>
  <p class="lead">Live health of the governed gateway and its services.</p>
  <div class="card">
    <table class="status">
      <tr><td>Gateway health</td><td id="s-gateway">checking&hellip;</td></tr>
      <tr><td>API health</td><td id="s-api">checking&hellip;</td></tr>
      <tr><td>Runtime health</td><td id="s-runtime">checking&hellip;</td></tr>
      <tr><td>Evidence service</td><td id="s-evidence">checking&hellip;</td></tr>
      <tr><td>Incident state</td><td id="s-incident">checking&hellip;</td></tr>
      <tr><td>Availability</td><td id="s-avail" class="warn">UNKNOWN</td></tr>
    </table>
    <p class="note">Last updated: <span id="s-updated">&mdash;</span></p>
  </div>
  <script>
    var checked = 0;
    function mark(id, ok, label) {
      var el = document.getElementById(id);
      el.textContent = label;
      el.className = ok ? 'ok' : 'bad';
      checked++;
    }
    var incidents = 0;
    function done() {
      document.getElementById('s-updated').textContent = new Date().toISOString();
      var el = document.getElementById('s-incident');
      el.textContent = incidents === 0 ? 'No active incident' : 'Degraded service detected';
      el.className = incidents === 0 ? 'ok' : 'warn';
      // Availability reflects only what was just observed; it is never
      // fabricated. With no historical uptime evidence it stays qualitative.
      var av = document.getElementById('s-avail');
      if (checked === 0) { av.textContent = 'UNKNOWN'; av.className = 'warn'; }
      else if (incidents === 0) { av.textContent = 'AVAILABLE (live check)'; av.className = 'ok'; }
      else { av.textContent = 'DEGRADED'; av.className = 'warn'; }
    }
    Promise.all([
      fetch('/health').then(function(r){ mark('s-gateway', r.ok, r.ok?'OPERATIONAL':'UNAVAILABLE'); if(!r.ok) incidents++; })
        .catch(function(){ mark('s-gateway', false, 'UNAVAILABLE'); incidents++; }),
      fetch('/api/status').then(function(r){ return r.ok ? r.json() : Promise.reject(); })
        .then(function(s){
          var ok = (s.status === 'OK');
          mark('s-api', ok, ok?'OPERATIONAL':'DEGRADED'); if(!ok) incidents++;
          var ev = !!s.nonce_store_available;
          mark('s-evidence', ev, ev?'OPERATIONAL':'DEGRADED'); if(!ev) incidents++;
        })
        .catch(function(){ mark('s-api', false, 'UNAVAILABLE'); mark('s-evidence', false, 'UNKNOWN'); incidents++; }),
      fetch('/api/runtime/health').then(function(r){ return r.ok ? r.json() : Promise.reject(); })
        .then(function(h){
          var st = (h.status || h.state || 'UNKNOWN');
          var ok = String(st).toUpperCase().indexOf('FAIL') === -1;
          mark('s-runtime', ok, String(st).toUpperCase()); if(!ok) incidents++;
        })
        .catch(function(){ mark('s-runtime', false, 'UNAVAILABLE'); incidents++; })
    ]).then(done, done);
  </script>
"""


async def handle(request, call_next):
    path = request.url.path
    if path in ("/", "") and request.method in ("GET", "HEAD"):
        return page("USBAY Status", "Service Status", _BODY)
    if path in _ALLOWED_GET and request.method in ("GET", "HEAD"):
        return await call_next(request)
    return not_found("status.usbay.global")
