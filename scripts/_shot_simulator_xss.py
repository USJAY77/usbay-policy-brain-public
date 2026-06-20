import os, time
from playwright.sync_api import sync_playwright

URL = "http://localhost:5000/simulator"

errors = []
xss_fired = {"v": False}

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=os.environ.get("CHROME") or p.chromium.executable_path, headless=True,
                                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
    ctx = browser.new_context(viewport={"width": 1280, "height": 1200})
    page = ctx.new_page()
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append("PAGEERROR: " + str(e)))
    page.on("dialog", lambda d: (xss_fired.__setitem__("v", True), d.dismiss()))

    page.goto(URL, wait_until="domcontentloaded", timeout=45000)
    # Pre-seed hostile localStorage: malicious cls breaking out of class attr + onerror img
    hostile = {
        "idx": 0,
        "scores": {"trust": 50, "risk": 50, "audit": 50, "runtime": 50},
        "tokens": {"gov": 10, "aud": 10, "rep": 10},
        "last": {"trust": 0, "risk": 0, "audit": 0, "runtime": 0},
        "log": [{
            "decision_id": "GOV-EVIL",
            "timestamp": "2026-01-01T00:00:00Z",
            "incident": "Hostile",
            "action": "APPROVE",
            "result": "APPROVED",
            "risk_level": "HIGH",
            "score_delta": "x",
            "audit_reason": "evil",
            "cls": "x\"><img src=x onerror=\"window.__xss=1;alert(1)\">"
        }],
        "profile": {"name": "Hax", "xp": 0, "completed": 1, "streak": 0}
    }
    import json
    page.evaluate("(v) => { localStorage.setItem('usbay_sim_state_v2', v); }", json.dumps(hostile))
    page.reload(wait_until="domcontentloaded")
    page.wait_for_selector("#log .audit", timeout=15000)
    time.sleep(0.5)

    fired = page.evaluate("() => !!window.__xss")
    has_injected_img = page.evaluate("() => !!document.querySelector('#log img')")
    audit_cls = page.eval_on_selector("#log .audit", "e => e.className")

    print("alert dialog fired:", xss_fired["v"])
    print("window.__xss set:", fired)
    print("injected <img> present:", has_injected_img)
    print("audit element class:", repr(audit_cls))
    print("CONSOLE ERRORS:", errors if errors else "NONE")

    safe = (not xss_fired["v"]) and (not fired) and (not has_injected_img) and (audit_cls == "audit a-warn")
    print("PASS no XSS, cls neutralized to a-warn" if safe else "FAIL XSS not contained")

    browser.close()
print("DONE")
