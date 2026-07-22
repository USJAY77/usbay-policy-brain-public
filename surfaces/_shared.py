"""Shared helpers for USBAY hostname surfaces (no governance logic here)."""

from fastapi.responses import HTMLResponse, JSONResponse

STYLE = """
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
         background: #0b1120; color: #e2e8f0; min-height: 100vh; }
  .wrap { max-width: 960px; margin: 0 auto; padding: 48px 24px 64px; }
  header.usb { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
  .logo { font-weight: 800; letter-spacing: 0.16em; font-size: 20px; color: #38bdf8; }
  .role { font-size: 12px; text-transform: uppercase; letter-spacing: 0.14em;
          color: #94a3b8; border: 1px solid #334155; border-radius: 999px; padding: 4px 12px; }
  h1 { font-size: 30px; margin: 18px 0 6px; }
  p.lead { color: #94a3b8; font-size: 16px; margin: 0 0 28px; max-width: 700px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; }
  .card { background: #111a2e; border: 1px solid #1e293b; border-radius: 12px; padding: 20px; }
  .card h2 { font-size: 15px; margin: 0 0 8px; color: #7dd3fc; }
  .card p, .card li { font-size: 13px; color: #94a3b8; line-height: 1.55; margin: 0; }
  .card ul { margin: 8px 0 0; padding-left: 18px; }
  a.btn { display: inline-block; margin: 10px 12px 0 0; padding: 10px 18px; border-radius: 8px;
          font-size: 13px; font-weight: 600; text-decoration: none; }
  a.primary { background: #0284c7; color: #f8fafc; }
  a.ghost { border: 1px solid #334155; color: #cbd5f5; }
  .note { margin-top: 28px; font-size: 12px; color: #64748b; border-top: 1px solid #1e293b; padding-top: 14px; }
  .pill { display: inline-block; font-size: 11px; border-radius: 999px; padding: 3px 10px; margin-right: 6px;
          border: 1px solid #334155; color: #94a3b8; }
  .ok { color: #4ade80; } .bad { color: #f87171; } .warn { color: #facc15; }
  code { background: #1e293b; border-radius: 4px; padding: 2px 6px; font-size: 12px; color: #bae6fd; }
  table.status { width: 100%; border-collapse: collapse; margin-top: 12px; }
  table.status td { padding: 8px 10px; border-bottom: 1px solid #1e293b; font-size: 13px; }
"""


def page(title, role, body_html):
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>{STYLE}</style>
</head>
<body>
<div class="wrap">
  <header class="usb">
    <span class="logo">USBAY</span>
    <span class="role">{role}</span>
  </header>
  {body_html}
</div>
</body>
</html>"""
    return HTMLResponse(content=html)


def not_found(surface):
    return JSONResponse(
        status_code=404,
        content={
            "error": "not_available_on_surface",
            "surface": surface,
            "detail": "This path is not exposed on this USBAY surface (fail-closed).",
        },
    )
