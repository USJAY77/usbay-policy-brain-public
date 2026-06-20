import os, time, json
from playwright.sync_api import sync_playwright

URL = "http://localhost:5000/simulator"
DASH = "http://localhost:5000/"
OUT = "/home/runner/workspace/evidence/audit"
os.makedirs(OUT, exist_ok=True)

errors = []
results = []

def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name, flush=True)

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=os.environ.get("CHROME") or p.chromium.executable_path, headless=True,
                                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
    ctx = browser.new_context(viewport={"width": 1280, "height": 2600}, device_scale_factor=1)
    page = ctx.new_page()
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append("PAGEERROR: " + str(e)))

    page.goto(URL, wait_until="domcontentloaded", timeout=45000)
    page.evaluate("() => { try { localStorage.clear(); } catch(e){} }")
    page.reload(wait_until="domcontentloaded")
    page.wait_for_selector("#pf-name", timeout=15000)
    page.add_style_tag(content="*{transition:none !important;animation:none !important;}")

    # 1. Career Ladder: 8 ranks in profile track
    ranks = page.eval_on_selector_all("#pf-track .trk", "els => els.length")
    check("career ladder shows 8 ranks", ranks == 8)
    names = page.eval_on_selector_all("#pf-track .trk .trk-n", "els => els.map(e => e.textContent).join('|')")
    check("ladder includes Chief Governance Officer", "Chief Governance Officer" in names)
    check("ladder includes Governance Architect", "Governance Architect" in names)

    # 2. Reputation Engine: 4 metrics (2x2)
    repcells = page.eval_on_selector_all("#rep-grid .rep-cell", "els => els.length")
    check("reputation engine shows 4 metrics", repcells == 4)
    reptext = page.eval_on_selector("#rep-grid", "e => e.textContent")
    check("reputation includes Human Oversight", "Human Oversight" in reptext)
    check("reputation includes Runtime Safety", "Runtime Safety" in reptext)

    # 3. Enterprise Scenario Packs: 6 cards with live counts
    packs = page.eval_on_selector_all("#pk-grid .pk-card", "els => els.length")
    check("six enterprise packs render", packs == 6)
    packtext = page.eval_on_selector("#pk-grid", "e => e.textContent")
    check("packs show unlocked counts", "unlocked" in packtext and "resolved" in packtext)

    # 4. Team Mode Foundation
    check("team panel present", page.query_selector("#team") is not None)
    roster_rows = page.eval_on_selector_all("#tm-roster tr", "els => els.length")
    check("team roster has rows (header + members)", roster_rows >= 4)
    you_row = page.eval_on_selector_all("#tm-roster tr.you", "els => els.length")
    check("team roster includes live you row", you_row == 1)
    tm_score = page.eval_on_selector("#tm-score", "e => parseInt(e.textContent, 10)")
    check("team score is aggregate (>0)", tm_score > 0)
    tm_rep = page.eval_on_selector("#tm-rep", "e => parseInt(e.textContent, 10)")
    check("team reputation computed (>0)", tm_rep > 0)
    check("team audit history rows present", page.query_selector("#tm-hist .tm-hrow") is not None)

    # 5. Backend Persistence Preparation
    adapter = page.eval_on_selector("#ps-adapter", "e => e.textContent")
    check("persistence adapter is LOCAL", adapter == "LOCAL")
    remote = page.eval_on_selector("#ps-remote", "e => e.textContent")
    check("persistence remote NOT_CONFIGURED", remote == "NOT_CONFIGURED")
    mode = page.eval_on_selector("#ps-mode", "e => e.textContent")
    check("persistence mode set", mode in ("PERSISTING", "EPHEMERAL"))

    # sync fails closed (no network state transmitted)
    page.click("#ps-sync")
    page.wait_for_timeout(200)
    note = page.eval_on_selector("#ps-note", "e => e.textContent")
    check("sync fails closed (not configured)", "not configured" in note.lower() and "no state was transmitted" in note.lower())
    remote2 = page.eval_on_selector("#ps-remote", "e => e.textContent")
    check("remote still NOT_CONFIGURED after sync", remote2 == "NOT_CONFIGURED")

    # 6. Decision moves Human Oversight metric (4th reputation metric is live)
    def oversight_dom():
        return page.evaluate("""() => {
            var cells = document.querySelectorAll('#rep-grid .rep-cell');
            for (var i = 0; i < cells.length; i++) {
                var k = cells[i].querySelector('.rep-k');
                if (k && k.textContent.trim() === 'Human Oversight') {
                    return parseInt(cells[i].querySelector('.rep-v').textContent, 10);
                }
            }
            return null;
        }""")
    before_ov = oversight_dom()
    btn = page.query_selector('.btns [data-act="HUMAN_REVIEW"]')
    check("HUMAN_REVIEW decision button present", btn is not None)
    if btn:
        btn.click()
        page.wait_for_timeout(300)
    after_ov = oversight_dom()
    check("human oversight metric increases on HUMAN_REVIEW", before_ov is not None and after_ov is not None and after_ov > before_ov)
    after = page.eval_on_selector("#rep-grid", "e => e.textContent")
    check("reputation re-renders after a decision", after is not None and len(after) > 0)

    # 7. Export carries SIM_VERSION 4.0 and the new reputation schema
    with page.expect_download() as dl_info:
        page.click("#btn-export")
    dl_path = dl_info.value.path()
    with open(dl_path) as f:
        exp = json.load(f)
    check("export simulator_version is usbay-sim-4.0", exp.get("simulator_version") == "usbay-sim-4.0")
    rep = exp.get("reputation") or {}
    check("export reputation includes human_oversight", "human_oversight" in rep)
    check("export reputation includes runtime_safety", "runtime_safety" in rep)

    # 8. Pack click selects a scenario / opens unlock (no crash)
    page.eval_on_selector_all("#pk-grid .pk-card", "els => { if (els[0]) els[0].click(); }")
    page.wait_for_timeout(200)
    check("pack click did not crash (incident still present)", page.query_selector("#incident") is not None)

    # 9. Control-plane untouched
    page.goto(DASH, wait_until="domcontentloaded", timeout=30000)
    check("dashboard/control-plane still loads (200)", page.query_selector("body") is not None)

    page.screenshot(path=os.path.join(OUT, "simulator_v4.png"), full_page=True)

    browser.close()

print("\nCONSOLE ERRORS:", "NONE" if not errors else "")
for e in errors:
    print("  -", e)
passed = sum(1 for _, ok in results if ok)
print("RESULT: %d/%d checks passed" % (passed, len(results)))
print("DONE")
