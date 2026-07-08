"""EURIA + AI Intake commercial experience (UI prototype only).

Additive, demo-only pages layered on top of the USBAY Governance Control
Plane. Strict constraints honoured by design:

- READ-ONLY UI: no forms, no buttons, no inputs, no POST probes.
- Demo data only: every value is a static in-page constant.
- No persistence, no backend mutations, no model calls, no provider calls.
- No governance surface touched: policy brain, enforcement gateway,
  runtime governance, evidence panel, execution authority, fail-closed
  logic and all existing routes are unchanged.

Routes registered (all GET/HEAD, HTML only):
    /euria           EURIA Intelligence profile
    /intake          AI Intake record (read-only)
    /pricing         Governance tier + dynamic pricing preview
    /proposal        Proposal preview
    /implementation  Implementation timeline (read-only)
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

_NAV_ITEMS = [
    ("/euria", "EURIA Intelligence"),
    ("/intake", "AI Intake"),
    ("/pricing", "Pricing"),
    ("/proposal", "Proposal"),
    ("/implementation", "Implementation"),
]

_STYLE = """
:root{--bg:#070d17;--panel:#0d1626;--panel2:#111d33;--line:#1d2c47;
--txt:#dbe6f5;--dim:#7e93b4;--acc:#38bdf8;--good:#34d399;--warn:#fbbf24;
--bad:#f87171;--mono:'SFMono-Regular',Consolas,monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font:15px/1.55 'Segoe UI',system-ui,sans-serif;min-height:100vh}
a{color:var(--acc);text-decoration:none}
header{border-bottom:1px solid var(--line);background:var(--panel);padding:14px 28px;
display:flex;flex-wrap:wrap;align-items:center;gap:18px}
header .brand{font-weight:700;letter-spacing:.14em;font-size:15px}
header .brand span{color:var(--acc)}
nav{display:flex;flex-wrap:wrap;gap:4px}
nav a{padding:6px 12px;border-radius:6px;color:var(--dim);font-size:13px}
nav a.on{background:var(--panel2);color:var(--txt);border:1px solid var(--line)}
nav a:hover{color:var(--txt)}
.tags{margin-left:auto;display:flex;gap:6px}
.tag{font:11px/1 var(--mono);letter-spacing:.08em;padding:5px 9px;border-radius:4px;
border:1px solid var(--line);color:var(--warn)}
.tag.ro{color:var(--good)}
main{max-width:1080px;margin:0 auto;padding:30px 24px 60px}
h1{font-size:22px;margin-bottom:4px}
.sub{color:var(--dim);font-size:13px;margin-bottom:26px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px 20px}
.card h2{font-size:13px;letter-spacing:.12em;text-transform:uppercase;color:var(--dim);margin-bottom:12px}
.kv{display:grid;grid-template-columns:minmax(140px,42%) 1fr;gap:6px 14px;font-size:13.5px}
.kv .k{color:var(--dim)}
.kv .v{font-family:var(--mono);font-size:12.5px;word-break:break-all}
.pill{display:inline-block;font:11px/1 var(--mono);padding:4px 8px;border-radius:4px;border:1px solid var(--line)}
.pill.g{color:var(--good)} .pill.w{color:var(--warn)} .pill.b{color:var(--bad)} .pill.a{color:var(--acc)}
.score{font:700 44px/1 var(--mono);color:var(--good)}
.bar{height:8px;background:var(--panel2);border-radius:4px;overflow:hidden;margin-top:10px}
.bar i{display:block;height:100%;background:linear-gradient(90deg,var(--acc),var(--good))}
table{width:100%;border-collapse:collapse;font-size:13px}
th{color:var(--dim);text-align:left;font-weight:600;font-size:11px;letter-spacing:.1em;
text-transform:uppercase;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
ul.plain{list-style:none} ul.plain li{padding:6px 0;border-bottom:1px dashed var(--line);font-size:13.5px}
ul.plain li:last-child{border-bottom:0}
.note{margin-top:26px;border:1px dashed var(--line);border-radius:8px;padding:12px 16px;
color:var(--dim);font:12px/1.6 var(--mono)}
.wide{grid-column:1/-1}
"""


def _shell(active: str, title: str, subtitle: str, body: str) -> str:
    nav = "".join(
        f'<a href="{href}" class="{"on" if href == active else ""}">{label}</a>'
        for href, label in _NAV_ITEMS
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — USBAY EURIA</title>
<style>{_STYLE}</style>
</head>
<body>
<header>
  <div class="brand">USBAY <span>/ EURIA</span></div>
  <nav>{nav}<a href="/">Dashboard</a></nav>
  <div class="tags"><span class="tag ro">DEMO ONLY</span><span class="tag ro">READ ONLY</span><span class="tag">NO REAL BOOKING</span><span class="tag">NO REAL PAYMENT</span></div>
</header>
<main>
  <h1>{title}</h1>
  <div class="sub">{subtitle}</div>
  {body}
  <div class="note">UI PROTOTYPE — demo data only · no persistence · no backend mutations ·
no model calls · no provider calls · governance control plane unchanged · execution authority unchanged</div>
</main>
</body>
</html>"""


def _kv(rows) -> str:
    return '<div class="kv">' + "".join(
        f'<div class="k">{k}</div><div class="v">{v}</div>' for k, v in rows
    ) + "</div>"


def _euria_html() -> str:
    body = f"""
<div class="grid">
  <div class="card"><h2>Customer Profile</h2>{_kv([
      ("Organization", "Aurora Health Systems (demo)"),
      ("Segment", "Enterprise — Regulated"),
      ("Employees", "12,400"),
      ("AI Maturity", '<span class="pill a">LEVEL 3 — SCALING</span>'),
      ("Engagement Stage", "Evaluation"),
  ])}</div>
  <div class="card"><h2>Industry &amp; Jurisdiction</h2>{_kv([
      ("Industry", "Healthcare / Payer-Provider"),
      ("Primary Jurisdiction", "United States (Federal)"),
      ("State Overlays", "CA, NY, TX"),
      ("Cross-Border Data", '<span class="pill w">EU ADEQUACY REVIEW</span>'),
      ("Sector Regulators", "HHS-OCR, FDA (SaMD watch)"),
  ])}</div>
  <div class="card"><h2>AI Use Case</h2>{_kv([
      ("Use Case", "Clinical intake triage assistant"),
      ("Modality", "LLM + retrieval (demo descriptor)"),
      ("Autonomy Level", '<span class="pill w">HUMAN-IN-THE-LOOP REQUIRED</span>'),
      ("Affected Population", "Patients &amp; care staff"),
      ("Deployment Target", "Internal pilot, non-production"),
  ])}</div>
  <div class="card"><h2>Risk Signals</h2>
    <ul class="plain">
      <li><span class="pill b">HIGH</span> &nbsp;Protected health information in scope</li>
      <li><span class="pill w">MEDIUM</span> &nbsp;Automated recommendation influence on care routing</li>
      <li><span class="pill w">MEDIUM</span> &nbsp;Multi-state regulatory overlay divergence</li>
      <li><span class="pill g">LOW</span> &nbsp;No autonomous execution authority requested</li>
      <li><span class="pill g">LOW</span> &nbsp;Existing audit culture (SOC 2 Type II, demo)</li>
    </ul>
  </div>
  <div class="card"><h2>Recommended Controls</h2>
    <ul class="plain">
      <li>Fail-closed execution gateway (USBAY enforcement layer)</li>
      <li>Human approval checkpoint before any care-affecting action</li>
      <li>Evidence-grade decision audit trail with export</li>
      <li>Jurisdiction-aware policy profiles (Federal + CA/NY/TX)</li>
      <li>Runtime health authority with degraded-mode blocking</li>
      <li>Quarterly governance readiness re-assessment</li>
    </ul>
  </div>
  <div class="card"><h2>Governance Readiness Score</h2>
    <div class="score">72<span style="font-size:20px;color:var(--dim)">/100</span></div>
    <div class="bar"><i style="width:72%"></i></div>
    {_kv([
      ("Rating", '<span class="pill w">CONDITIONALLY READY</span>'),
      ("Strongest Pillar", "Audit &amp; evidence culture"),
      ("Weakest Pillar", "Jurisdictional overlay coverage"),
      ("Assessment Basis", "Static demo rubric — illustrative only"),
    ])}
  </div>
</div>"""
    return _shell("/euria", "EURIA Intelligence",
                  "Customer governance intelligence profile — illustrative demo assessment.", body)


def _intake_html() -> str:
    body = f"""
<div class="grid">
  <div class="card"><h2>Organization</h2>{_kv([
      ("Legal Name", "Aurora Health Systems, Inc. (demo)"),
      ("Entity Type", "Private — Delaware C-Corp"),
      ("HQ", "Chicago, IL, USA"),
      ("Intake Reference", "USBAY-INTAKE-2026-0041 (demo)"),
  ])}</div>
  <div class="card"><h2>Contact</h2>{_kv([
      ("Sponsor", "J. Rivera — VP, Clinical Operations (demo)"),
      ("Governance Lead", "M. Chen — Director, AI Risk (demo)"),
      ("Channel", "Enterprise evaluation program"),
  ])}</div>
  <div class="card"><h2>AI System</h2>{_kv([
      ("System Name", "Triage Assist (demo)"),
      ("System Class", "Decision-support, non-autonomous"),
      ("Execution Authority", '<span class="pill g">NONE REQUESTED</span>'),
      ("Integration Point", "USBAY governed gateway only"),
  ])}</div>
  <div class="card"><h2>Data Classification</h2>{_kv([
      ("Highest Class", '<span class="pill b">RESTRICTED — PHI</span>'),
      ("Secondary", "Confidential — operational"),
      ("Training Data Use", "Prohibited (policy default)"),
      ("Retention Posture", "Evidence-only, demo descriptor"),
  ])}</div>
  <div class="card"><h2>Risk Category</h2>{_kv([
      ("Category", '<span class="pill w">HIGH-IMPACT / HUMAN-GATED</span>'),
      ("Basis", "Health context + population effect"),
      ("Autonomy Ceiling", "Recommend-only"),
  ])}</div>
  <div class="card"><h2>Regulatory Scope</h2>{_kv([
      ("Federal", "HIPAA / HHS-OCR oversight"),
      ("EU AI Act Mapping", "High-risk analogue (advisory)"),
      ("State", "CA CMIA, NY SHIELD, TX HB4 (demo mapping)"),
      ("Standards", "NIST AI RMF, ISO/IEC 42001 (advisory)"),
  ])}</div>
  <div class="card"><h2>Human Approval</h2>{_kv([
      ("Human Approval Required", '<span class="pill b">YES — MANDATORY</span>'),
      ("Approval Role", "Accountable clinical reviewer"),
      ("Bypass Path", '<span class="pill g">NONE — FAIL-CLOSED</span>'),
  ])}</div>
  <div class="card"><h2>Intake Evidence Hash</h2>{_kv([
      ("Algorithm", "SHA-256 (demo)"),
      ("Evidence Hash", "9f4c2a71d8b03e56aa17c94ef02b6d3358c1f7a2e94d0b68513fe2c7a90d4b1e"),
      ("Hash Scope", "Intake record snapshot (illustrative)"),
      ("Verification", "Demo value — not a live attestation"),
  ])}</div>
  <div class="card wide"><h2>Intake Decision — READ ONLY</h2>{_kv([
      ("Decision State", '<span class="pill w">PENDING HUMAN GOVERNANCE REVIEW</span>'),
      ("Automated Approval", '<span class="pill g">NOT PERMITTED</span>'),
      ("Decision Authority", "USBAY governance reviewer (human)"),
      ("Note", "This page displays a static demo intake record. Nothing is submitted, stored, or executed."),
  ])}</div>
</div>"""
    return _shell("/intake", "AI Intake",
                  "Read-only demo intake record — no submission, no persistence, no decision automation.", body)


def _pricing_html() -> str:
    body = f"""
<div class="grid">
  <div class="card"><h2>Estimated Governance Tier</h2>
    <div style="font:700 26px/1.2 var(--mono);color:var(--acc);margin-bottom:12px">GOVERNANCE RUNTIME</div>
    {_kv([
      ("Tier Basis", "High-impact, human-gated use case"),
      ("Alternative Below", "Pilot License"),
      ("Alternative Above", "Enterprise Sovereign"),
      ("Tier Status", '<span class="pill w">ESTIMATE — NON-BINDING</span>'),
    ])}</div>
  <div class="card"><h2>Dynamic Pricing Preview</h2>
    <table>
      <tr><th>Component</th><th>Driver</th><th>Preview</th></tr>
      <tr><td>Platform base</td><td>Governance Runtime tier</td><td>$8,500 / mo</td></tr>
      <tr><td>Jurisdiction overlays</td><td>Federal + 3 states</td><td>$1,200 / mo</td></tr>
      <tr><td>Evidence retention</td><td>Regulated profile</td><td>$900 / mo</td></tr>
      <tr><td>Human-approval workflow</td><td>Mandatory gate</td><td>Included</td></tr>
      <tr><td><b>Indicative total</b></td><td>Demo composition</td><td><b>$10,600 / mo</b></td></tr>
    </table>
  </div>
  <div class="card wide"><h2>Pricing Terms</h2>
    <ul class="plain">
      <li>All figures are illustrative demo values — not a quote or offer.</li>
      <li>No payment integration exists on this page. Nothing can be purchased here.</li>
      <li>Final pricing requires human commercial review and a signed order form.</li>
    </ul>
  </div>
</div>"""
    return _shell("/pricing", "Pricing",
                  "Estimated governance tier and dynamic pricing preview — illustrative only, no payment integration.", body)


def _proposal_html() -> str:
    body = f"""
<div class="grid">
  <div class="card wide"><h2>Proposal Preview</h2>{_kv([
      ("Proposal", "USBAY Governance Runtime — Aurora Health pilot (demo)"),
      ("Reference", "USBAY-PROP-2026-0041 (demo)"),
      ("Status", '<span class="pill w">DRAFT PREVIEW — NOT ISSUED</span>'),
      ("Validity", "Illustrative document, no commercial effect"),
  ])}</div>
  <div class="card"><h2>Scope</h2>
    <ul class="plain">
      <li>Governed execution gateway for the Triage Assist use case</li>
      <li>Fail-closed enforcement of all AI-initiated actions</li>
      <li>Jurisdiction-aware policy profiles (Federal + CA/NY/TX)</li>
      <li>Human approval checkpoint integration</li>
      <li>Out of scope: model development, autonomous execution</li>
    </ul>
  </div>
  <div class="card"><h2>Deliverables</h2>
    <ul class="plain">
      <li>Governance runtime environment (pilot boundary)</li>
      <li>Policy profile configuration workbook</li>
      <li>Evidence &amp; audit export capability</li>
      <li>Governance readiness assessment report</li>
      <li>Pilot exit review with readiness score update</li>
    </ul>
  </div>
  <div class="card"><h2>Evidence References</h2>
    <ul class="plain">
      <li>Intake evidence hash <span class="pill a">9f4c2a71…d4b1e</span> (demo)</li>
      <li>EURIA readiness assessment — score 72/100 (demo)</li>
      <li>Runtime stability visibility report (existing read-only API)</li>
      <li>Fail-closed enforcement demonstration record (demo)</li>
    </ul>
  </div>
  <div class="card"><h2>Human Approval Required</h2>{_kv([
      ("Commercial Approval", '<span class="pill b">REQUIRED — HUMAN ONLY</span>'),
      ("Governance Approval", '<span class="pill b">REQUIRED — HUMAN ONLY</span>'),
      ("Automated Issuance", '<span class="pill g">NOT PERMITTED</span>'),
      ("Current State", "Preview only — no approval captured here"),
  ])}</div>
</div>"""
    return _shell("/proposal", "Proposal",
                  "Draft proposal preview — demo content, requires human approval, never auto-issued.", body)


def _implementation_html() -> str:
    body = f"""
<div class="grid">
  <div class="card wide"><h2>Timeline (Demo)</h2>
    <table>
      <tr><th>Phase</th><th>Window</th><th>Focus</th><th>Status</th></tr>
      <tr><td>Phase 0 — Readiness</td><td>Weeks 1–2</td><td>EURIA assessment, intake finalization</td><td><span class="pill g">ILLUSTRATIVE</span></td></tr>
      <tr><td>Phase 1 — Foundation</td><td>Weeks 3–5</td><td>Governed gateway boundary, policy profiles</td><td><span class="pill a">ILLUSTRATIVE</span></td></tr>
      <tr><td>Phase 2 — Controls</td><td>Weeks 6–8</td><td>Human approval gate, evidence exports</td><td><span class="pill a">ILLUSTRATIVE</span></td></tr>
      <tr><td>Phase 3 — Pilot</td><td>Weeks 9–12</td><td>Supervised pilot, readiness re-score</td><td><span class="pill w">ILLUSTRATIVE</span></td></tr>
    </table>
  </div>
  <div class="card"><h2>Milestones</h2>
    <ul class="plain">
      <li>M1 — Intake record approved by human reviewer</li>
      <li>M2 — Policy profiles configured and verified</li>
      <li>M3 — Fail-closed enforcement demonstrated end-to-end</li>
      <li>M4 — Evidence export accepted by governance lead</li>
      <li>M5 — Pilot exit review and readiness score update</li>
    </ul>
  </div>
  <div class="card"><h2>Governance Checkpoints</h2>
    <ul class="plain">
      <li><span class="pill b">GATE</span> &nbsp;No phase advances without human sign-off</li>
      <li><span class="pill b">GATE</span> &nbsp;Execution authority remains fail-closed throughout</li>
      <li><span class="pill b">GATE</span> &nbsp;Evidence trail reviewed at every phase boundary</li>
      <li><span class="pill b">GATE</span> &nbsp;Production activation excluded from this plan</li>
    </ul>
  </div>
</div>"""
    return _shell("/implementation", "Implementation",
                  "Read-only implementation plan — illustrative timeline with mandatory governance checkpoints.", body)


_PAGES = {
    "/euria": _euria_html,
    "/intake": _intake_html,
    "/pricing": _pricing_html,
    "/proposal": _proposal_html,
    "/implementation": _implementation_html,
}


def register_euria_routes(app: FastAPI) -> None:
    """Register the demo-only EURIA commercial pages.

    Must be called before the SPA catch-all route is registered so these
    paths resolve to their own pages. All routes are GET/HEAD, HTML-only,
    read-only, and touch no governance state.
    """
    for path, builder in _PAGES.items():
        def _make(b):
            def _page():
                return HTMLResponse(b())
            return _page
        app.api_route(path, methods=["GET", "HEAD"], response_class=HTMLResponse)(_make(builder))
