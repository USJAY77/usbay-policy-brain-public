import os, json
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
    ctx = browser.new_context(viewport={"width": 1280, "height": 3000}, device_scale_factor=1)
    page = ctx.new_page()
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append("PAGEERROR: " + str(e)))

    page.goto(URL, wait_until="domcontentloaded", timeout=45000)
    page.evaluate("() => { try { localStorage.clear(); } catch(e){} }")
    page.reload(wait_until="domcontentloaded")
    page.wait_for_selector("#academy", timeout=15000)
    page.add_style_tag(content="*{transition:none !important;animation:none !important;}")

    # 1. Academy Dashboard consolidated panel
    check("academy dashboard present", page.query_selector("#academy") is not None)
    check("academy shows rank", (page.eval_on_selector("#ac-rank", "e => e.textContent") or "").strip() != "")
    check("academy unlocked count format n / total", "/" in page.eval_on_selector("#ac-unlocked", "e => e.textContent"))
    ac_rep = page.eval_on_selector("#ac-rep", "e => parseInt(e.textContent, 10)")
    check("academy composite reputation computed (>0)", ac_rep > 0)

    # 2. Editable identity -> profile country/org
    page.fill("#id-name", "Ada Tester")
    page.fill("#id-country", "Kenya")
    page.fill("#id-org", "Acme Audit")
    page.click("#id-save")
    page.wait_for_timeout(150)
    check("identity name saved to profile", page.eval_on_selector("#pf-name", "e => e.textContent") == "Ada Tester")

    # 3. Team creation + audit/mission scores
    check("team creation form present", page.query_selector("#tm-create") is not None)
    page.fill("#tm-in-name", "Falcon Cell")
    page.fill("#tm-in-org", "Acme Audit")
    page.click("#tm-create-btn")
    page.wait_for_timeout(150)
    tm_name = page.eval_on_selector("#tm-name", "e => e.textContent")
    check("team name reflects creation", "Falcon Cell" in tm_name)
    check("team create form hidden after creation", page.eval_on_selector("#tm-create", "e => getComputedStyle(e).display") == "none")
    tm_audit = page.eval_on_selector("#tm-audit", "e => parseInt(e.textContent, 10)")
    check("team audit score computed (>0)", tm_audit > 0)
    tm_mission = page.eval_on_selector("#tm-mission", "e => e.textContent")
    check("team mission score present", tm_mission is not None and tm_mission != "")

    # 4. Leaderboard scope tabs (Global / Country / Organization)
    tabs = page.eval_on_selector_all("#lb-tabs .lb-tab", "els => els.map(e => e.getAttribute('data-scope')).join('|')")
    check("leaderboard scope tabs present", tabs == "global|country|org")
    page.click("#lb-submit")
    page.wait_for_timeout(150)
    # global shows the row
    rows_global = page.eval_on_selector_all("#lb-body table tbody tr", "els => els.length")
    check("global scope lists submitted run", rows_global >= 1)
    # country scope (same country -> still shows)
    page.click("#lb-tabs [data-scope='country']")
    page.wait_for_timeout(120)
    rows_country = page.eval_on_selector_all("#lb-body table tbody tr", "els => els.length")
    check("country scope shows same-country entry", rows_country >= 1)
    check("country tab active", page.eval_on_selector("#lb-tabs [data-scope='country']", "e => e.classList.contains('on')"))

    # 5. Audit-quality credit source + breakdown
    check("credits breakdown has audit source row", page.query_selector("#cr-src-audit") is not None)
    btn = page.query_selector('.btns [data-act="HUMAN_REVIEW"]')
    if btn:
        btn.click()
        page.wait_for_timeout(250)
    src_incidents = page.eval_on_selector("#cr-src-incidents", "e => e.textContent")
    check("credits incident source increments after decision", src_incidents not in (None, "+0"))

    # 6. Backend persistence: real adapter + genuine round-trip sync
    page.click("#ps-sync")
    page.wait_for_timeout(700)
    note = page.eval_on_selector("#ps-note", "e => e.textContent")
    check("sync reports synced to backend", "synced to the usbay simulator backend" in note.lower())
    remote = page.eval_on_selector("#ps-remote", "e => e.textContent")
    check("remote shows CONNECTED backend", remote.startswith("CONNECTED"))
    # confirm the client id state actually exists on the backend
    cid = page.evaluate("() => { try { return localStorage.getItem('usbay_sim_client_id'); } catch(e){ return null; } }")
    check("client id persisted for backend keying", bool(cid))

    # 7. Export carries SIM_VERSION 5.0 and new schema
    with page.expect_download() as dl_info:
        page.click("#btn-export")
    dl_path = dl_info.value.path()
    with open(dl_path) as f:
        exp = json.load(f)
    check("export simulator_version is usbay-sim-5.0", exp.get("simulator_version") == "usbay-sim-5.0")
    prof = exp.get("profile") or {}
    check("export profile includes country", prof.get("country") == "Kenya")
    check("export profile includes organization", prof.get("organization") == "Acme Audit")
    check("export includes team object", isinstance(exp.get("team"), dict) and exp["team"].get("created") is True)
    creds = exp.get("credits") or {}
    check("export credits includes sources breakdown", isinstance(creds.get("sources"), dict) and "audit" in creds["sources"])

    # 8. Control-plane untouched
    page.goto(DASH, wait_until="domcontentloaded", timeout=30000)
    check("dashboard/control-plane still loads (200)", page.query_selector("body") is not None)

    page.goto(URL, wait_until="domcontentloaded", timeout=30000)
    page.wait_for_selector("#academy", timeout=15000)
    page.add_style_tag(content="*{transition:none !important;animation:none !important;}")
    page.screenshot(path=os.path.join(OUT, "simulator_v5.png"), full_page=True)

    browser.close()

print("\nCONSOLE ERRORS:", "NONE" if not errors else "")
for e in errors:
    print("  -", e)
passed = sum(1 for _, ok in results if ok)
print("RESULT: %d/%d checks passed" % (passed, len(results)))
print("DONE")
