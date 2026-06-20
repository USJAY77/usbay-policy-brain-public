import os
from playwright.sync_api import sync_playwright

URL = "http://localhost:5000/simulator"
ROUTES = ["/simulator", "/", "/dashboard", "/playground", "/health", "/simulator/storage/health"]
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
    ctx = browser.new_context(viewport={"width": 1280, "height": 3200}, device_scale_factor=1)
    page = ctx.new_page()
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append("PAGEERROR: " + str(e)))

    page.goto(URL, wait_until="domcontentloaded", timeout=45000)
    page.evaluate("() => { try { localStorage.clear(); } catch(e){} }")
    page.reload(wait_until="domcontentloaded")
    page.wait_for_selector("#travel", timeout=15000)
    page.add_style_tag(content="*{transition:none !important;animation:none !important;}")

    # Panel + exact disclaimer present
    check("travel panel present", page.query_selector("#travel") is not None)
    EXPECT_DISC = ("USBAY credits are training points only. They are not money, not crypto, "
                   "not stored value, not transferable, and not redeemable for cash. Any real "
                   "discount must be partner-funded and validated outside USBAY payment flow.")
    check("fail-closed disclaimer exact text", page.eval_on_selector("#trv-disc", "e => e.textContent") == EXPECT_DISC)
    # All five partner types rendered
    cards = page.eval_on_selector_all("#trv-grid .trv-card", "els => els.map(e => e.getAttribute('data-trv')).join('|')")
    check("five partner types rendered", cards == "airline|train|bus|cruise|hotel")
    # Voucher model fields exposed in UI
    vch0 = page.eval_on_selector("#trv-grid .trv-card .trv-vch", "e => e.textContent")
    check("voucher exposes id/rule/status fields", all(k in vch0 for k in ["voucher_id", "rule_id", "status", "expires_at"]))
    check("voucher shows non-monetary flags", page.query_selector("#trv-grid .trv-flags") is not None)

    # TEST 1: blocked when partner rule missing -> NO_PARTNER_RULE
    v_missing = page.evaluate("() => window.__usbayTravel.evalVoucher('charter', {})")
    check("missing partner rule -> blocked", v_missing["status"] == "blocked")
    check("missing partner rule -> NO_PARTNER_RULE", "NO_PARTNER_RULE" in v_missing["reasons"])
    check("missing partner rule -> rule_id null", v_missing["rule_id"] is None)

    # TEST 2: blocked when eligibility incomplete (fresh state, high-tier partner)
    v_cruise = page.evaluate("() => window.__usbayTravel.evalVoucher('cruise', {})")
    check("incomplete eligibility -> blocked", v_cruise["status"] == "blocked")
    check("incomplete eligibility -> RANK reason", "RANK_BELOW_REQUIREMENT" in v_cruise["reasons"])
    check("incomplete eligibility -> MISSIONS reason", "MISSIONS_BELOW_REQUIREMENT" in v_cruise["reasons"])
    # entry-tier partner (bus) is eligible on fresh state -> proves eligible path works
    v_bus = page.evaluate("() => window.__usbayTravel.evalVoucher('bus', {})")
    check("entry-tier partner eligible on fresh state", v_bus["status"] == "eligible")
    check("eligible voucher carries ELIGIBLE_PREVIEW", "ELIGIBLE_PREVIEW" in v_bus["reasons"])
    check("eligible voucher partner-funded non-transferable no-cash",
          v_bus["funding"] == "partner_funded" and v_bus["transferable"] is False and v_bus["cash_value"] == "none")

    # preview_only: non-binding voucher (instantiated but not evaluated)
    v_prev = page.evaluate("() => window.__usbayTravel.evalVoucher('hotel', {preview: true})")
    check("preview mode -> preview_only status", v_prev["status"] == "preview_only")
    check("preview voucher carries PREVIEW_ONLY reason", "PREVIEW_ONLY" in v_prev["reasons"])
    check("preview voucher non-monetary", v_prev["cash_value"] == "none" and v_prev["transferable"] is False and v_prev["funding"] == "partner_funded")

    # TEST 3: blocked when voucher is expired (otherwise-eligible partner, expiry in the past)
    v_exp = page.evaluate("() => window.__usbayTravel.evalVoucher('bus', {now: 1000000, expiresAt: 999000})")
    check("expired voucher -> blocked", v_exp["status"] == "blocked")
    check("expired voucher -> VOUCHER_EXPIRED", "VOUCHER_EXPIRED" in v_exp["reasons"])

    # TEST 4: blocked / unchanged when client tampers with credits
    before = page.evaluate("() => window.__usbayTravel.partners.map(p => window.__usbayTravel.evalVoucher(p.type, {}).status)")
    page.evaluate("""() => {
        try {
            state.credits.start = 100000000;
            state.credits.earned = 100000000;
            state.credits.spent = 0;
            state.credits.sources = {incidents: 100000000, missions: 100000000, audit: 100000000};
        } catch(e){}
    }""")
    after = page.evaluate("() => window.__usbayTravel.partners.map(p => window.__usbayTravel.evalVoucher(p.type, {}).status)")
    check("credit tamper does not change eligibility statuses", before == after)
    v_air_tamper = page.evaluate("() => window.__usbayTravel.evalVoucher('airline', {})")
    check("credit tamper leaves blocked partner blocked", v_air_tamper["status"] == "blocked")

    # TEST 5: no network / payment / booking call exists
    seen = []
    page.on("request", lambda r: seen.append(r.url))
    seen.clear()
    page.evaluate("() => { window.__usbayTravel.partners.forEach(p => window.__usbayTravel.evalVoucher(p.type, {})); }")
    page.wait_for_timeout(300)
    travel_requests = [u for u in seen if u]
    check("evaluating travel triggers zero network requests", len(travel_requests) == 0)
    src = page.content().lower()
    # travel layer must not reference booking/payment/checkout rails
    banned = ["stripe", "paypal", "checkout.session", "payment_intent", "/book", "booking_id", "card_number"]
    check("no payment/booking rails referenced", not any(b in src for b in banned))

    # TEST 6: audit evidence section shows decisions incl. missing-rule self-test
    arows = page.eval_on_selector_all("#trv-audit .trv-arow", "els => els.length")
    check("audit evidence lists every partner + self-test", arows == 6)
    audit_txt = page.eval_on_selector("#trv-audit", "e => e.textContent")
    check("audit evidence surfaces NO_PARTNER_RULE state", "NO_PARTNER_RULE" in audit_txt)

    # Existing simulator routes still return 200
    for rt in ROUTES:
        resp = page.request.get("http://localhost:5000" + rt)
        check("route 200 " + rt, resp.status == 200)

    page.goto(URL, wait_until="domcontentloaded", timeout=30000)
    page.wait_for_selector("#travel", timeout=15000)
    page.add_style_tag(content="*{transition:none !important;animation:none !important;}")
    page.screenshot(path=os.path.join(OUT, "travel_v1.png"), full_page=True)
    page.locator("#travel").screenshot(path=os.path.join(OUT, "travel_panel_v1.png"))

    browser.close()

print("\nCONSOLE ERRORS:", "NONE" if not errors else "")
for e in errors:
    print("  -", e)
passed = sum(1 for _, ok in results if ok)
print("RESULT: %d/%d checks passed" % (passed, len(results)))
print("DONE")
