import os, time, json
from playwright.sync_api import sync_playwright

CHROME = "/nix/store/khk7xpgsm5insk81azy9d560yq4npf77-chromium-131.0.6778.204/bin/chromium"
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
    browser = p.chromium.launch(executable_path=CHROME, headless=True,
                                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
    ctx = browser.new_context(viewport={"width": 1280, "height": 2200}, device_scale_factor=1)
    page = ctx.new_page()
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append("PAGEERROR: " + str(e)))

    page.goto(URL, wait_until="domcontentloaded", timeout=45000)
    page.evaluate("() => { try { localStorage.clear(); } catch(e){} }")
    page.reload(wait_until="domcontentloaded")
    page.wait_for_selector("#pf-name", timeout=15000)
    page.add_style_tag(content="*{transition:none !important;animation:none !important;}")

    # 1. new gamification sections present
    check("reputation grid present", page.query_selector("#rep-grid .rep-cell") is not None)
    check("credits balance present", page.query_selector("#cr-balance") is not None)
    check("missions grid present", page.query_selector("#ms-grid .ms-card") is not None)
    check("leaderboard body present", page.query_selector("#lb-body") is not None)

    # 2. starting credits = 500 balance, 0 earned/spent
    bal = page.eval_on_selector("#cr-balance", "e => e.textContent")
    check("starting balance 500", bal == "500")
    start = page.eval_on_selector("#cr-start", "e => e.textContent")
    check("starting credits 500", start == "500")

    # 3. tiered rail: standard scenarios unlocked, critical/nation locked
    check("standard group present", page.query_selector('.scn-group .scn-btn[data-scn]') is not None)
    locked = page.query_selector_all('.scn-btn.locked[data-lock]')
    check("locked scenarios present (>=4)", len(locked) >= 4)

    # 4. decision awards credits + advances daily mission
    page.eval_on_selector('[data-scn="0"]', "e => e.click()")
    page.eval_on_selector('.btn.b-human', "e => e.click()")
    time.sleep(0.3)
    earned = page.eval_on_selector("#cr-earned", "e => e.textContent")
    check("credits earned after decision", earned != "+0")
    bal2 = int(page.eval_on_selector("#cr-balance", "e => e.textContent"))
    check("balance increased above 500", bal2 > 500)

    # 5. unlock modal opens for a locked scenario
    page.eval_on_selector('.scn-btn.locked[data-lock]', "e => e.click()")
    time.sleep(0.2)
    check("unlock modal shows", "show" in (page.eval_on_selector("#umodal", "e => e.className") or ""))
    # fail closed: not enough incidents -> bad message
    page.eval_on_selector("#umodal-confirm", "e => e.click()")
    time.sleep(0.2)
    umsg = page.eval_on_selector("#umodal-msg", "e => e.textContent") or ""
    check("unlock fails closed when requirement unmet", "Locked" in umsg)
    still_locked = page.eval_on_selector("#umodal", "e => e.className")
    check("modal stays open on failed unlock", "show" in still_locked)
    page.eval_on_selector("#umodal-cancel", "e => e.click()")

    # 6. global leaderboard sync fails closed (no network, warning shown)
    page.eval_on_selector("#lb-global", "e => e.click()")
    time.sleep(0.2)
    note = page.eval_on_selector("#lb-note", "e => e.textContent") or ""
    check("global sync fails closed", "fails closed" in note or "not configured" in note)

    # 7. submit local leaderboard entry
    page.eval_on_selector("#lb-submit", "e => e.click()")
    time.sleep(0.2)
    check("leaderboard row added", page.query_selector("#lb-body .lb-table tr.you") is not None)

    # 8. export includes new fields
    new_keys = page.evaluate("""() => {
        const raw = localStorage.getItem('usbay_sim_state_v2');
        return raw ? Object.keys(JSON.parse(raw)) : [];
    }""")
    for k in ("credits", "unlocked", "missions", "leaderboard"):
        check("state has " + k, k in new_keys)

    # 9. unlock bypass via tampered localStorage fails closed
    # seed a state whose idx points at an IN-BOUNDS locked nation-tier scenario with no unlocks
    page.goto(URL, wait_until="domcontentloaded", timeout=45000)
    # discover an in-bounds index that is currently rendered as locked
    locked_idx = page.evaluate("""() => {
        const b = document.querySelector('.scn-btn.locked[data-lock]');
        return b ? parseInt(b.getAttribute('data-lock'), 10) : -1;
    }""")
    check("found in-bounds locked index", locked_idx >= 0)
    page.evaluate("""(li) => {
        const tampered = {
            idx: li, scores:{trust:78,risk:34,audit:80,runtime:88}, tokens:{gov:120,aud:40,rep:64},
            last:{trust:0,risk:0,audit:0,runtime:0}, log:[],
            profile:{name:'X', xp:0, level:1, completed:0, streak:0},
            credits:{start:500,earned:0,spent:0}, unlocked:{}, leaderboard:[]
        };
        localStorage.setItem('usbay_sim_state_v2', JSON.stringify(tampered));
    }""", locked_idx)
    page.reload(wait_until="domcontentloaded")
    page.wait_for_selector("#incident .inc-title", timeout=15000)
    # idx must be clamped to exactly one unlocked (standard) scenario, NOT the tampered locked one
    active_idx = page.evaluate("""() => {
        const a = document.querySelector('.scn-btn.active[data-scn]');
        return a ? parseInt(a.getAttribute('data-scn'), 10) : -1;
    }""")
    check("exactly one active scenario after tamper", page.eval_on_selector_all(".scn-btn.active[data-scn]", "els => els.length") == 1)
    check("active scenario is not the tampered locked idx", active_idx != locked_idx and active_idx >= 0)
    # attempt to act on the (clamped) scenario is allowed only because it is unlocked;
    # the originally-tampered locked scenario must still be locked & unplayable
    still_locked = page.evaluate("""(li) => {
        return !!document.querySelector('.scn-btn.locked[data-lock="' + li + '"]');
    }""", locked_idx)
    check("tampered locked scenario remains locked", still_locked)
    completed0 = page.eval_on_selector("#pf-completed", "e => e.textContent")
    check("tampered state did not unlock anything (completed 0)", completed0 == "0")
    locked2 = page.query_selector_all('.scn-btn.locked[data-lock]')
    check("locked scenarios remain locked after tamper", len(locked2) >= 4)

    # 10. control plane unaffected
    r = page.goto(DASH, wait_until="domcontentloaded")
    check("dashboard/control-plane still loads (200)", r.status == 200)

    print("\nCONSOLE ERRORS: " + ("NONE" if not errors else "\n".join(errors)), flush=True)
    passed = sum(1 for _, c in results if c)
    print("RESULT: %d/%d checks passed" % (passed, len(results)), flush=True)
    browser.close()
    print("DONE", flush=True)
