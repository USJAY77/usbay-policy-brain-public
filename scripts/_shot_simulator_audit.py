import os, time
from playwright.sync_api import sync_playwright

CHROME = "/nix/store/khk7xpgsm5insk81azy9d560yq4npf77-chromium-131.0.6778.204/bin/chromium"
URL = "http://localhost:5000/simulator"
OUT = "/home/runner/workspace/evidence/audit"
os.makedirs(OUT, exist_ok=True)

console_errors = []

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=CHROME, headless=True,
                                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
    page = browser.new_page(viewport={"width": 1280, "height": 1500}, device_scale_factor=1)
    page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: console_errors.append("PAGEERROR: " + str(e)))
    page.goto(URL, wait_until="domcontentloaded", timeout=45000)
    page.wait_for_selector("#incident .inc-title", state="attached", timeout=15000)
    page.add_style_tag(content="*{transition:none !important;animation:none !important;}")
    time.sleep(0.3)

    # 5. Homepage (above-the-fold viewport)
    page.screenshot(path=os.path.join(OUT, "05_homepage.png"), animations="disabled")
    print("05 homepage", flush=True)

    # 6. Incident screen — the Incident Queue panel
    inc = page.query_selector("section[aria-label='Incident']")
    inc.scroll_into_view_if_needed(); time.sleep(0.2)
    inc.screenshot(path=os.path.join(OUT, "06_incident.png"), animations="disabled")
    print("06 incident", flush=True)

    # 7. EURIA Advisor panel
    eu = page.query_selector("section[aria-label='EURIA Advisor']")
    eu.scroll_into_view_if_needed(); time.sleep(0.2)
    eu.screenshot(path=os.path.join(OUT, "07_euria.png"), animations="disabled")
    print("07 euria", flush=True)

    # 8. Scoring system — USBAY Score panel (after a decision so deltas show)
    page.eval_on_selector('[data-scn="0"]', "e => e.click()")
    time.sleep(0.15)
    page.eval_on_selector('.btn.b-human', "e => e.click()")
    time.sleep(0.3)
    sc = page.query_selector("section[aria-label='USBAY Scores']")
    sc.scroll_into_view_if_needed(); time.sleep(0.2)
    sc.screenshot(path=os.path.join(OUT, "08_scoring.png"), animations="disabled")
    print("08 scoring", flush=True)

    # 9. Audit evidence after decisions — make a few varied decisions then capture the log
    page.eval_on_selector('[data-scn="1"]', "e => e.click()")
    time.sleep(0.15)
    page.eval_on_selector('.btn.b-approve', "e => e.click()")
    time.sleep(0.2)
    page.eval_on_selector('[data-scn="3"]', "e => e.click()")
    time.sleep(0.15)
    page.eval_on_selector('.btn.b-block', "e => e.click()")
    time.sleep(0.3)
    logcount = page.eval_on_selector("#log-count", "e => e.textContent")
    print("log", logcount, flush=True)
    audit = page.query_selector("section[aria-label='Audit log']")
    audit.scroll_into_view_if_needed(); time.sleep(0.2)
    audit.screenshot(path=os.path.join(OUT, "09_audit_evidence.png"), animations="disabled")
    print("09 audit evidence", flush=True)

    browser.close()

print("CONSOLE ERRORS:", console_errors if console_errors else "NONE")
print("DONE", flush=True)
