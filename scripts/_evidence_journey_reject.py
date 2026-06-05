import os, time, glob
from playwright.sync_api import sync_playwright

CHROME = "/nix/store/khk7xpgsm5insk81azy9d560yq4npf77-chromium-131.0.6778.204/bin/chromium"
URL = "http://localhost:5000/"
OUT = "/home/runner/workspace/evidence"
os.makedirs(OUT, exist_ok=True)
for f in glob.glob(os.path.join(OUT, "journey_7_rejected.png")):
    os.remove(f)

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=CHROME, headless=True,
                                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
    page = browser.new_page(viewport={"width": 1440, "height": 2200}, device_scale_factor=2)
    page.goto(URL, wait_until="networkidle", timeout=60000)

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
    time.sleep(0.4)
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

    page.wait_for_selector("#usbwiz-from-intake", state="visible", timeout=10000)
    page.click("#usbwiz-from-intake")
    page.wait_for_selector("#usbwiz", state="visible", timeout=10000)
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

    page.eval_on_selector("#usbsim-rpt-open", "el => el.click()")
    page.wait_for_selector("#usbsim-rpt", state="visible", timeout=10000)
    page.click("#usbsim-rpt-pilot")
    page.wait_for_selector("#usbpr-name", timeout=10000)
    page.fill("#usbpr-name", "Alex Morgan")
    page.fill("#usbpr-org", "Northwind Logistics B.V.")
    page.fill("#usbpr-role", "Chief Risk Officer")
    page.click("[data-pr='submit']")
    page.wait_for_timeout(700)

    rej = page.query_selector("[data-pr='reject']")
    assert rej and "reject" in (rej.inner_text() or "").lower()
    rej.click()
    page.wait_for_timeout(700)

    banner = page.query_selector("#usbpr-body .usbpr-status")
    print("status:", banner.inner_text().strip() if banner else "(none)")
    card = page.query_selector("#usbpr .usbsim-rpt-card")
    card.scroll_into_view_if_needed()
    time.sleep(0.2)
    card.screenshot(path=os.path.join(OUT, "journey_7_rejected.png"))
    print("captured journey_7_rejected.png",
          os.path.getsize(os.path.join(OUT, "journey_7_rejected.png")), "bytes")
    browser.close()
