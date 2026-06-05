import os, time, glob
from playwright.sync_api import sync_playwright

CHROME = "/nix/store/khk7xpgsm5insk81azy9d560yq4npf77-chromium-131.0.6778.204/bin/chromium"
URL = "http://localhost:5000/"
OUT = "/home/runner/workspace/evidence"
os.makedirs(OUT, exist_ok=True)
for f in glob.glob(os.path.join(OUT, "journey_*.png")):
    os.remove(f)


def shot(el, name):
    el.scroll_into_view_if_needed()
    time.sleep(0.2)
    el.screenshot(path=os.path.join(OUT, name))
    print("captured", name)


with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=CHROME, headless=True,
                                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
    page = browser.new_page(viewport={"width": 1440, "height": 2200}, device_scale_factor=2)
    page.goto(URL, wait_until="networkidle", timeout=60000)

    # --- 1. ASSESSMENT ---
    page.click("#usbsim-intake-open")
    page.wait_for_selector("#usbsim-intake-form", state="visible", timeout=10000)
    for name, val in {"industry": "log", "usage": "customer",
                      "concern": "regulator", "regexposure": "elevated"}.items():
        sel = page.query_selector(f"#usbsim-intake-form [name='{name}']")
        if sel:
            try:
                sel.select_option(value=val)
            except Exception:
                pass
    page.click("#usbsim-intake-submit")
    page.wait_for_selector("#usbsim-intake-out", state="visible", timeout=10000)
    time.sleep(0.5)
    shot(page.query_selector("#usbsim-gar"), "journey_1_assessment.png")

    # --- 2. LICENSE ---
    shot(page.query_selector("#usbsim-intake-lic"), "journey_2_license.png")

    # engagement context (feeds the pilot record)
    for name, val in {
        "company": "Northwind Logistics B.V.", "industry": "Logistics",
        "country": "Netherlands",
        "challenge": "Govern an AI-driven freight routing and claims triage system under the EU AI Act.",
        "aisystems": "Customer-facing routing AI, internal claims automation",
        "regulatory": "Elevated - sector regulator, EU AI Act",
    }.items():
        loc = page.query_selector(f"#usbeng-form [name='{name}']")
        if loc:
            try:
                loc.fill(val)
            except Exception:
                pass
    g = page.query_selector("#usbeng-generate")
    if g:
        g.click()
        time.sleep(0.3)

    # --- 3. PILOT WIZARD ---
    page.wait_for_selector("#usbwiz-from-intake", state="visible", timeout=10000)
    page.click("#usbwiz-from-intake")
    page.wait_for_selector("#usbwiz", state="visible", timeout=10000)
    time.sleep(0.4)
    shot(page.query_selector("#usbwiz .usbwiz-card"), "journey_3_pilot_wizard.png")
    # walk wizard to completion
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
        nxt = page.query_selector("#usbwiz-next")
        if not nxt:
            break
        txt = (nxt.inner_text() or "").strip().lower()
        nxt.click()
        time.sleep(0.2)
        if "done" in txt:
            break
    if page.query_selector("#usbwiz") and page.is_visible("#usbwiz"):
        cl = page.query_selector("#usbwiz-close")
        if cl:
            try:
                cl.click()
            except Exception:
                pass
    time.sleep(0.3)

    # --- 4. EXECUTIVE GOVERNANCE REPORT ---
    page.eval_on_selector("#usbsim-rpt-open", "el => el.click()")
    page.wait_for_selector("#usbsim-rpt", state="visible", timeout=10000)
    time.sleep(0.4)
    shot(page.query_selector("#usbsim-rpt .usbsim-rpt-card"), "journey_4_executive_report.png")

    # --- 5. PILOT REQUEST (pre-submit / Draft) ---
    page.click("#usbsim-rpt-pilot")
    page.wait_for_selector("#usbpr-name", timeout=10000)
    time.sleep(0.4)
    shot(page.query_selector("#usbpr .usbsim-rpt-card"), "journey_5_pilot_request.png")

    # --- 6. GOVERNANCE REVIEW (submitted / Pending Governance Review) ---
    page.fill("#usbpr-name", "Alex Morgan")
    page.fill("#usbpr-org", "Northwind Logistics B.V.")
    page.fill("#usbpr-role", "Chief Risk Officer")
    page.click("[data-pr='submit']")
    page.wait_for_timeout(700)
    shot(page.query_selector("#usbpr .usbsim-rpt-card"), "journey_6_governance_review.png")

    # --- 7. APPROVED (Governance Approved) ---
    appr = page.query_selector("[data-pr='approve']")
    appr.click()
    page.wait_for_timeout(700)
    shot(page.query_selector("#usbpr .usbsim-rpt-card"), "journey_7_approved.png")

    browser.close()

print("FILES:")
for f in sorted(glob.glob(os.path.join(OUT, "journey_*.png"))):
    print(" ", os.path.relpath(f, "/home/runner/workspace"), os.path.getsize(f), "bytes")
