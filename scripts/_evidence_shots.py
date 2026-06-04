import os, time, glob
from playwright.sync_api import sync_playwright

CHROME = "/nix/store/khk7xpgsm5insk81azy9d560yq4npf77-chromium-131.0.6778.204/bin/chromium"
URL = "http://localhost:5000/"
OUT = "/home/runner/workspace/evidence"
os.makedirs(OUT, exist_ok=True)
for f in glob.glob(os.path.join(OUT, "*.png")):
    os.remove(f)

SECTIONS = [
    ("1_requested_license", "Pilot request"),
    ("2_governance_challenge", "Governance challenge"),
    ("3_risk_summary", "Risk summary"),
    ("4_evidence_requirements", "Evidence requirements"),
    ("5_human_approval_requirements", "Human approval requirements"),
    ("6_pilot_timeline", "Pilot timeline"),
]

def shoot_sections(page, phase):
    secs = page.query_selector_all("#usbpr-body .usbsim-rpt-sec")
    by_head = {}
    for s in secs:
        h = s.query_selector("h4")
        if h:
            by_head[h.inner_text().strip().lower()] = s
    results = []
    for fname, head in SECTIONS:
        el = by_head.get(head.lower())
        path = os.path.join(OUT, f"{phase}_{fname}.png")
        if el:
            el.scroll_into_view_if_needed()
            time.sleep(0.15)
            el.screenshot(path=path)
            results.append((fname, "OK"))
        else:
            results.append((fname, "MISSING"))
    return results

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=CHROME, headless=True,
                                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
    page = browser.new_page(viewport={"width": 1440, "height": 2400}, device_scale_factor=2)
    page.goto(URL, wait_until="networkidle", timeout=60000)

    # 1. Assessment intake form -> Generate preview
    page.click("#usbsim-intake-open")
    page.wait_for_selector("#usbsim-intake-form", state="visible", timeout=10000)
    intake_selects = {
        "industry": "log",
        "usage": "customer",
        "concern": "regulator",
        "regexposure": "elevated",
    }
    for name, val in intake_selects.items():
        sel = page.query_selector(f"#usbsim-intake-form [name='{name}']")
        if sel:
            try:
                sel.select_option(value=val)
            except Exception:
                pass
    page.click("#usbsim-intake-submit")
    page.wait_for_selector("#usbsim-intake-out", state="visible", timeout=10000)
    time.sleep(0.4)

    # 2. Engagement context form -> Generate intake summary
    eng = {
        "company": "Northwind Logistics B.V.",
        "industry": "Logistics",
        "country": "Netherlands",
        "challenge": "Govern an AI-driven freight routing and claims triage system under the EU AI Act.",
        "aisystems": "Customer-facing routing AI, internal claims automation",
        "regulatory": "Elevated - sector regulator, EU AI Act",
    }
    for name, val in eng.items():
        loc = page.query_selector(f"#usbeng-form [name='{name}']")
        if loc:
            try:
                loc.fill(val)
            except Exception:
                pass
    geng = page.query_selector("#usbeng-generate")
    if geng:
        geng.click()
        time.sleep(0.4)

    # 3. Continue to Governance Pilot wizard
    page.wait_for_selector("#usbwiz-from-intake", state="visible", timeout=10000)
    page.click("#usbwiz-from-intake")
    page.wait_for_selector("#usbwiz", state="visible", timeout=10000)

    # 2. Walk the wizard forward, filling each active step
    for _ in range(14):
        active = page.query_selector(".usbwiz-step.on") or page
        for inp in active.query_selector_all("input[type='text'], textarea"):
            try:
                if not inp.input_value().strip():
                    inp.fill("Automated freight claims triage")
            except Exception:
                pass
        for cb in active.query_selector_all("input[type='checkbox']"):
            try:
                if not cb.is_checked():
                    cb.check()
            except Exception:
                pass
        for rb in active.query_selector_all("input[type='radio']"):
            try:
                rb.check()
            except Exception:
                pass
        for sel in active.query_selector_all("select"):
            o = sel.query_selector_all("option")
            if len(o) > 1:
                try:
                    sel.select_option(index=1)
                except Exception:
                    pass
        nxt = page.query_selector("#usbwiz-next")
        if not nxt:
            break
        txt = (nxt.inner_text() or "").strip().lower()
        nxt.click()
        time.sleep(0.25)
        if "done" in txt:
            break
    cl = page.query_selector("#usbwiz-close")
    if cl and page.query_selector("#usbwiz") and page.is_visible("#usbwiz"):
        try:
            cl.click()
        except Exception:
            pass
    time.sleep(0.3)

    # 3. Executive Governance Report -> Submit Pilot Request modal
    page.eval_on_selector("#usbsim-rpt-open", "el => el.click()")
    page.wait_for_selector("#usbsim-rpt", state="visible", timeout=10000)
    page.screenshot(path=os.path.join(OUT, "context_executive_report.png"))
    page.click("#usbsim-rpt-pilot")
    page.wait_for_selector("#usbpr-body", state="visible", timeout=10000)
    page.wait_for_selector("#usbpr-name", timeout=10000)
    time.sleep(0.4)

    # PRE-SUBMIT full modal + per-section
    page.screenshot(path=os.path.join(OUT, "presubmit_full_modal.png"), full_page=True)
    pre = shoot_sections(page, "presubmit")

    # 4. Fill requester + submit
    page.fill("#usbpr-name", "Alex Morgan")
    page.fill("#usbpr-org", "Northwind Logistics B.V.")
    page.fill("#usbpr-role", "Chief Risk Officer")
    page.click("[data-pr='submit']")
    page.wait_for_timeout(800)

    # POST-SUBMIT full modal + per-section
    page.screenshot(path=os.path.join(OUT, "postsubmit_full_modal.png"), full_page=True)
    post = shoot_sections(page, "postsubmit")

    # capture status text for evidence
    banner = page.query_selector("#usbpr-body .usbpr-status")
    status_txt = banner.inner_text().strip() if banner else "(none)"
    pr_id_el = page.query_selector("#usbpr-body .usbsim-rpt-kvv")
    print("STATUS_BADGE:", status_txt)
    print("PRE:", pre)
    print("POST:", post)
    browser.close()

print("FILES:")
for f in sorted(glob.glob(os.path.join(OUT, "*.png"))):
    print(" ", os.path.relpath(f, "/home/runner/workspace"), os.path.getsize(f), "bytes")
