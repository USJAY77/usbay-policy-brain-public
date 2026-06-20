import os, time
from playwright.sync_api import sync_playwright

CHROME = "/nix/store/khk7xpgsm5insk81azy9d560yq4npf77-chromium-131.0.6778.204/bin/chromium"
URL = "http://localhost:5000/simulator"
OUT = "/home/runner/workspace/evidence/audit"
os.makedirs(OUT, exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=CHROME, headless=True,
                                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
    ctx = browser.new_context(viewport={"width": 1280, "height": 1700}, device_scale_factor=1)
    page = ctx.new_page()
    page.goto(URL, wait_until="domcontentloaded", timeout=45000)
    page.evaluate("() => { try { localStorage.clear(); } catch(e){} }")
    page.reload(wait_until="domcontentloaded")
    page.wait_for_selector("#pf-name", timeout=15000)
    page.add_style_tag(content="*{transition:none !important;animation:none !important;}")

    # Make several decisions to populate profile + audit history
    seq = [("0", ".btn.b-human"), ("2", ".btn.b-block"), ("3", ".btn.b-block"),
           ("1", ".btn.b-human"), ("4", ".btn.b-block")]
    for scn, btn in seq:
        page.eval_on_selector('[data-scn="%s"]' % scn, "e => e.click()")
        page.eval_on_selector(btn, "e => e.click()")
        time.sleep(0.1)
    time.sleep(0.3)

    # 1. Profile panel
    pf = page.query_selector("section[aria-label='Operator Profile']")
    pf.scroll_into_view_if_needed(); time.sleep(0.2)
    pf.screenshot(path=os.path.join(OUT, "v2_01_profile.png"))
    print("01 profile", flush=True)

    # 2. Audit history timeline
    audit = page.query_selector("section[aria-label='Audit log']")
    audit.scroll_into_view_if_needed(); time.sleep(0.2)
    audit.screenshot(path=os.path.join(OUT, "v2_02_audit_history.png"))
    print("02 audit history", flush=True)

    # 3. Export button (highlight the profile actions row)
    page.eval_on_selector("section[aria-label='Operator Profile']", "e => e.scrollIntoView()")
    time.sleep(0.2)
    actions = page.query_selector(".pf-main")
    actions.screenshot(path=os.path.join(OUT, "v2_03_export_button.png"))
    print("03 export button", flush=True)

    # 4. Reset confirmation modal
    page.eval_on_selector("#btn-reset", "e => e.click()")
    time.sleep(0.3)
    page.screenshot(path=os.path.join(OUT, "v2_04_reset_modal.png"))
    print("04 reset modal", flush=True)
    page.eval_on_selector("#modal-cancel", "e => e.click()")
    time.sleep(0.2)

    # 5. Restored state after refresh (full page top)
    page.reload(wait_until="domcontentloaded")
    page.wait_for_selector("#pf-name", timeout=15000)
    page.add_style_tag(content="*{transition:none !important;animation:none !important;}")
    time.sleep(0.3)
    page.set_viewport_size({"width": 1280, "height": 900})
    page.screenshot(path=os.path.join(OUT, "v2_05_restored_after_refresh.png"))
    print("05 restored after refresh", flush=True)

    browser.close()

print("DONE", flush=True)
