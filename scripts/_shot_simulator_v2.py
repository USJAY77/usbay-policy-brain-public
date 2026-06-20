import os, time, json
from playwright.sync_api import sync_playwright

CHROME = "/nix/store/khk7xpgsm5insk81azy9d560yq4npf77-chromium-131.0.6778.204/bin/chromium"
URL = "http://localhost:5000/simulator"
DASH = "http://localhost:5000/"
OUT = "/home/runner/workspace/evidence/audit"
DL = "/home/runner/workspace/evidence/audit/downloads"
os.makedirs(OUT, exist_ok=True)
os.makedirs(DL, exist_ok=True)

errors = []
results = []

def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name, flush=True)

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=CHROME, headless=True,
                                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
    ctx = browser.new_context(viewport={"width": 1280, "height": 1700}, device_scale_factor=1,
                              accept_downloads=True)
    page = ctx.new_page()
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append("PAGEERROR: " + str(e)))

    # Start clean
    page.goto(URL, wait_until="domcontentloaded", timeout=45000)
    page.evaluate("() => { try { localStorage.clear(); } catch(e){} }")
    page.reload(wait_until="domcontentloaded")
    page.wait_for_selector("#pf-name", timeout=15000)
    page.add_style_tag(content="*{transition:none !important;animation:none !important;}")

    # 1. simulator loads
    check("/simulator loads", page.query_selector("#incident .inc-title") is not None)

    # baseline completed = 0
    base_completed = page.eval_on_selector("#pf-completed", "e => e.textContent")
    check("profile starts at 0 completed", base_completed == "0")

    # 2. decision creates audit evidence + 3. scores update
    trust_before = page.eval_on_selector("#scores .sr-v", "e => e.textContent")
    page.eval_on_selector('[data-scn="0"]', "e => e.click()")
    page.eval_on_selector('.btn.b-human', "e => e.click()")
    time.sleep(0.3)
    logcount = page.eval_on_selector("#log-count", "e => e.textContent")
    check("decision creates audit evidence", "1 record" in logcount)
    check("audit entry has result field", page.query_selector(".audit-result") is not None)
    completed_after = page.eval_on_selector("#pf-completed", "e => e.textContent")
    check("completed incremented", completed_after == "1")
    xp_after = page.eval_on_selector("#pf-xp", "e => e.textContent")
    check("xp gained > 0", int(xp_after) > 0)
    streak_after = page.eval_on_selector("#pf-streak", "e => e.textContent")
    check("streak incremented on sound decision", streak_after == "1")

    # progression: make 2 more sound decisions -> 3 completed -> Operator rank
    page.eval_on_selector('[data-scn="2"]', "e => e.click()")   # gov -> BLOCK is sound
    page.eval_on_selector('.btn.b-block', "e => e.click()")
    page.eval_on_selector('[data-scn="3"]', "e => e.click()")   # av -> BLOCK is sound
    page.eval_on_selector('.btn.b-block', "e => e.click()")
    time.sleep(0.3)
    rank = page.eval_on_selector("#pf-rank", "e => e.textContent")
    check("rank unlocks Operator at 3 incidents", rank == "Operator")

    # 4. localStorage persists after refresh
    page.reload(wait_until="domcontentloaded")
    page.wait_for_selector("#pf-name", timeout=15000)
    completed_restored = page.eval_on_selector("#pf-completed", "e => e.textContent")
    rank_restored = page.eval_on_selector("#pf-rank", "e => e.textContent")
    log_restored = page.eval_on_selector("#log-count", "e => e.textContent")
    check("state persists after refresh (completed)", completed_restored == "3")
    check("rank persists after refresh", rank_restored == "Operator")
    check("audit history persists after refresh", "3 record" in log_restored)

    # 5. export button produces JSON
    page.add_style_tag(content="*{transition:none !important;animation:none !important;}")
    with page.expect_download(timeout=10000) as dlinfo:
        page.eval_on_selector("#btn-export", "e => e.click()")
    dl = dlinfo.value
    dlpath = os.path.join(DL, "export.json")
    dl.save_as(dlpath)
    with open(dlpath) as f:
        exported = json.load(f)
    check("export produces JSON file", os.path.exists(dlpath))
    check("export has simulator_version", exported.get("simulator_version") == "usbay-sim-3.0")
    check("export has profile", exported.get("profile", {}).get("completed_incidents") == 3)
    check("export has decision_history (3)", len(exported.get("decision_history", [])) == 3)
    check("export has generated_at", bool(exported.get("generated_at")))

    # 6. reset clears simulator state only (with confirmation modal)
    page.eval_on_selector("#btn-reset", "e => e.click()")
    time.sleep(0.2)
    modal_shown = page.eval_on_selector("#modal", "e => e.classList.contains('show')")
    check("reset shows confirmation modal", modal_shown)
    page.eval_on_selector("#modal-confirm", "e => e.click()")
    time.sleep(0.3)
    completed_reset = page.eval_on_selector("#pf-completed", "e => e.textContent")
    rank_reset = page.eval_on_selector("#pf-rank", "e => e.textContent")
    log_reset = page.eval_on_selector("#log-count", "e => e.textContent")
    check("reset clears completed", completed_reset == "0")
    check("reset restores Trainee rank", rank_reset == "Trainee")
    check("reset clears audit history", "0 record" in log_reset)
    # confirm reset persisted
    page.reload(wait_until="domcontentloaded")
    page.wait_for_selector("#pf-name", timeout=15000)
    check("reset persists after refresh", page.eval_on_selector("#pf-completed", "e => e.textContent") == "0")

    # 7. dashboard / control-plane still loads
    dpage = ctx.new_page()
    resp = dpage.goto(DASH, wait_until="domcontentloaded", timeout=30000)
    check("dashboard/control-plane still loads (200)", resp.status == 200)
    dpage.close()

    browser.close()

print("\nCONSOLE ERRORS:", errors if errors else "NONE")
passed = sum(1 for _, ok in results if ok)
print("RESULT: %d/%d checks passed" % (passed, len(results)))
print("DONE", flush=True)
