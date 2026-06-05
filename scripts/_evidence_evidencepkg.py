import os, time, glob
from playwright.sync_api import sync_playwright

CHROME = "/nix/store/khk7xpgsm5insk81azy9d560yq4npf77-chromium-131.0.6778.204/bin/chromium"
URL = "http://localhost:5000/"
OUT = "/home/runner/workspace/evidence"
os.makedirs(OUT, exist_ok=True)
for f in glob.glob(os.path.join(OUT, "evidencepkg_*.png")):
    os.remove(f)

console_errors = []

VARIANTS = [
    ("approved", "1_approved"),
    ("human", "2_human_review"),
    ("rejected", "3_rejected"),
]

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=CHROME, headless=True,
                                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
    page = browser.new_page(viewport={"width": 1240, "height": 1480}, device_scale_factor=1)
    page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: console_errors.append("PAGEERROR: " + str(e)))
    page.goto(URL, wait_until="domcontentloaded", timeout=45000)
    page.wait_for_selector("#usbep-doc .usbep-card", state="visible", timeout=15000)
    page.add_style_tag(content="*{transition:none !important;animation:none !important;}"
                       " .topbar{display:none !important;} body::before{display:none !important;}")
    el = page.query_selector("#usbep")
    cover = page.query_selector("#usbep-cover")
    el.scroll_into_view_if_needed()
    time.sleep(0.4)
    print("ready", flush=True)

    for key, name in VARIANTS:
        page.eval_on_selector("#usbep-switch [data-ep='%s']" % key, "e => e.click()")
        time.sleep(0.3)
        el.screenshot(path=os.path.join(OUT, "evidencepkg_%s.png" % name), animations="disabled")
        print("captured", name, flush=True)

    # Board-ready executive report preview (cover only, approved variant)
    page.eval_on_selector("#usbep-switch [data-ep='approved']", "e => e.click()")
    time.sleep(0.3)
    cover.scroll_into_view_if_needed()
    time.sleep(0.2)
    cover.screenshot(path=os.path.join(OUT, "evidencepkg_executive_report.png"), animations="disabled")
    print("captured executive_report", flush=True)

    browser.close()

print("CONSOLE ERRORS:", console_errors if console_errors else "NONE")
print("DONE", flush=True)
