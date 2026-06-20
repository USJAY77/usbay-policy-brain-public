import os, time
from playwright.sync_api import sync_playwright

CHROME = "/nix/store/khk7xpgsm5insk81azy9d560yq4npf77-chromium-131.0.6778.204/bin/chromium"
URL = "http://localhost:5000/simulator"
OUT = "/home/runner/workspace/evidence"
os.makedirs(OUT, exist_ok=True)

console_errors = []

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=CHROME, headless=True,
                                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
    page = browser.new_page(viewport={"width": 1280, "height": 1700}, device_scale_factor=1)
    page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: console_errors.append("PAGEERROR: " + str(e)))
    page.goto(URL, wait_until="domcontentloaded", timeout=45000)
    page.wait_for_selector("#incident .inc-title", state="attached", timeout=15000)
    page.add_style_tag(content="*{transition:none !important;animation:none !important;}")

    title = page.eval_on_selector("#incident .inc-title", "e => e.textContent")
    print("incident", title, flush=True)
    euria = page.eval_on_selector("#euria .euria-act", "e => e.textContent")
    print("euria reco", euria, flush=True)

    # exercise a governance-breach decision (APPROVE on a high-risk incident)
    page.eval_on_selector('.btn.b-approve', "e => e.click()")
    time.sleep(0.4)
    verdict = page.eval_on_selector("#verdict .vk", "e => e.textContent")
    print("verdict after approve", verdict, flush=True)
    # a governed decision (HUMAN REVIEW) on second scenario
    page.eval_on_selector('[data-scn="1"]', "e => e.click()")
    time.sleep(0.2)
    page.eval_on_selector('.btn.b-human', "e => e.click()")
    time.sleep(0.2)
    page.eval_on_selector('[data-scn="3"]', "e => e.click()")
    time.sleep(0.2)
    page.eval_on_selector('.btn.b-block', "e => e.click()")
    time.sleep(0.4)
    logcount = page.eval_on_selector("#log-count", "e => e.textContent")
    print("log", logcount, flush=True)

    page.screenshot(path=os.path.join(OUT, "governance_simulator.png"), full_page=True, animations="disabled")
    print("captured simulator", flush=True)
    browser.close()

print("CONSOLE ERRORS:", console_errors if console_errors else "NONE")
print("DONE", flush=True)
