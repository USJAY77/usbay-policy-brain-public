import os, time
from playwright.sync_api import sync_playwright

CHROME = "/nix/store/khk7xpgsm5insk81azy9d560yq4npf77-chromium-131.0.6778.204/bin/chromium"
URL = "http://localhost:5000/"
OUT = "/home/runner/workspace/evidence"
os.makedirs(OUT, exist_ok=True)

console_errors = []

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=CHROME, headless=True,
                                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
    page = browser.new_page(viewport={"width": 1240, "height": 1600}, device_scale_factor=1)
    page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: console_errors.append("PAGEERROR: " + str(e)))
    page.goto(URL, wait_until="domcontentloaded", timeout=45000)
    page.wait_for_selector("#usbprc .usbprc-card", state="attached", timeout=15000)
    page.add_style_tag(content="*{transition:none !important;animation:none !important;}"
                       " .topbar{display:none !important;} body::before{display:none !important;}")
    el = page.query_selector("#usbprc")
    el.scroll_into_view_if_needed()
    time.sleep(0.5)
    cards = page.query_selector_all("#usbprc .usbprc-card")
    print("cards", len(cards), flush=True)
    overall = page.eval_on_selector("#usbprc .usbprc-overall-v", "e => e.textContent")
    print("overall", overall, flush=True)
    el.screenshot(path=os.path.join(OUT, "pilot_readiness_dashboard.png"), animations="disabled")
    print("captured dashboard", flush=True)
    browser.close()

print("CONSOLE ERRORS:", console_errors if console_errors else "NONE")
print("DONE", flush=True)
