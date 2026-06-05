import os, time, glob
from playwright.sync_api import sync_playwright

CHROME = "/nix/store/khk7xpgsm5insk81azy9d560yq4npf77-chromium-131.0.6778.204/bin/chromium"
URL = "http://localhost:5000/"
OUT = "/home/runner/workspace/evidence"
os.makedirs(OUT, exist_ok=True)
for f in glob.glob(os.path.join(OUT, "lifecycle_*.png")):
    os.remove(f)

console_errors = []

STAGES = [
    "assessment", "license", "engagement", "request", "queue",
    "review", "human", "accepted", "report",
]

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=CHROME, headless=True,
                                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
    page = browser.new_page(viewport={"width": 1240, "height": 1320}, device_scale_factor=1)
    page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: console_errors.append("PAGEERROR: " + str(e)))
    page.goto(URL, wait_until="domcontentloaded", timeout=45000)
    page.wait_for_selector("#usblc-rail .usblc-node", state="visible", timeout=15000)
    page.add_style_tag(content="*{transition:none !important;animation:none !important;}")
    el = page.query_selector("#usblc")
    el.scroll_into_view_if_needed()
    time.sleep(0.4)
    print("ready", flush=True)

    for i, key in enumerate(STAGES):
        page.eval_on_selector("#usblc-rail [data-lc='%d']" % i, "e => e.click()")
        time.sleep(0.3)
        el.screenshot(path=os.path.join(OUT, "lifecycle_%d_%s.png" % (i + 1, key)),
                      animations="disabled")
        print("captured", i + 1, key, flush=True)

    browser.close()

print("CONSOLE ERRORS:", console_errors if console_errors else "NONE")
print("DONE", flush=True)
