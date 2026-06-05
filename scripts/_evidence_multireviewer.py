import os, time, glob
from playwright.sync_api import sync_playwright

CHROME = "/nix/store/khk7xpgsm5insk81azy9d560yq4npf77-chromium-131.0.6778.204/bin/chromium"
URL = "http://localhost:5000/"
OUT = "/home/runner/workspace/evidence"
os.makedirs(OUT, exist_ok=True)
for f in glob.glob(os.path.join(OUT, "multireviewer_*.png")):
    os.remove(f)

console_errors = []


def btn(lane, act):
    return "#usbmr-lanes [data-mr='%s'][data-act='%s']" % (lane, act)


with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=CHROME, headless=True,
                                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
    page = browser.new_page(viewport={"width": 1240, "height": 1320}, device_scale_factor=1)
    page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: console_errors.append("PAGEERROR: " + str(e)))
    page.goto(URL, wait_until="domcontentloaded", timeout=45000)
    page.wait_for_selector("#usbmr-lanes .usbmr-lane", state="visible", timeout=15000)
    page.add_style_tag(content="*{transition:none !important;animation:none !important;}")
    el = page.query_selector("#usbmr")
    el.scroll_into_view_if_needed()
    time.sleep(0.4)
    print("ready", flush=True)

    def reset():
        page.eval_on_selector("#usbmr-reset", "e => e.click()")
        time.sleep(0.2)

    def click(lane, act):
        page.eval_on_selector(btn(lane, act), "e => e.click()")
        time.sleep(0.25)

    def shot(name):
        el.screenshot(path=os.path.join(OUT, "multireviewer_%s.png" % name), animations="disabled")
        print("captured", name, flush=True)

    # 1-4: cumulative reviewer approvals
    reset()
    click("compliance", "approve");  shot("1_compliance")
    click("legal", "approve");       shot("2_legal")
    click("security", "approve");    shot("3_security")
    click("executive", "approve");   shot("4_executive")

    # 6: final approved state (all four lanes approved)
    shot("6_final_approved")

    # 5: human review escalation (a lane escalated -> mandatory human review)
    reset()
    click("compliance", "approve")
    click("legal", "approve")
    click("security", "escalate")
    shot("5_human_review")

    # 7: final rejected state (a lane rejects -> fail-closed block)
    reset()
    click("compliance", "approve")
    click("legal", "reject")
    shot("7_final_rejected")

    browser.close()

print("CONSOLE ERRORS:", console_errors if console_errors else "NONE")
print("DONE", flush=True)
