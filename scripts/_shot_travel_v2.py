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
    ctx = browser.new_context(viewport={"width": 1280, "height": 3600}, device_scale_factor=1)
    page = ctx.new_page()
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append("PAGEERROR: " + str(e)))

    page.goto(URL, wait_until="domcontentloaded", timeout=45000)
    page.evaluate("() => { try { localStorage.clear(); } catch(e){} }")
    page.reload(wait_until="domcontentloaded")
    page.wait_for_selector("#travel", timeout=15000)
    page.add_style_tag(content="*{transition:none !important;animation:none !important;}")

    # 1. Travel Partner Catalog: Airline/Train/Bus/Cruise/Hotel
    cards = page.eval_on_selector_all("#trv-grid .trv-card", "els => els.map(e => e.getAttribute('data-trv')).join('|')")
    check("partner catalog has all five partners", cards == "airline|train|bus|cruise|hotel")

    # 2. Eligibility Rule Engine derives from rank/mission/audit/reputation (not credits)
    v_cruise = page.evaluate("() => window.__usbayTravel.evalVoucher('cruise', {})")
    check("rule engine evaluates rank", "RANK_BELOW_REQUIREMENT" in v_cruise["reasons"])
    check("rule engine evaluates missions", "MISSIONS_BELOW_REQUIREMENT" in v_cruise["reasons"])

    # 3. Voucher Object contract: voucher_id, partner_id, expires_at, eligible, transferable=false, cash_value=none
    v_bus = page.evaluate("() => window.__usbayTravel.evalVoucher('bus', {})")
    check("voucher has voucher_id", isinstance(v_bus.get("voucher_id"), str) and v_bus["voucher_id"].startswith("VCHR-"))
    check("voucher has partner_id", v_bus.get("partner_id") == "bus")
    check("voucher has expires_at", isinstance(v_bus.get("expires_at"), str))
    check("voucher eligible is boolean true for qualifying partner", v_bus.get("eligible") is True)
    check("voucher transferable=false", v_bus.get("transferable") is False)
    check("voucher cash_value=none", v_bus.get("cash_value") == "none")
    check("eligible field exposed in voucher UI", "eligible" in page.eval_on_selector("#trv-grid .trv-card .trv-vch", "e => e.textContent"))
    check("partner_id field exposed in voucher UI", "partner_id" in page.eval_on_selector("#trv-grid .trv-card .trv-vch", "e => e.textContent"))

    # blocked partner -> eligible false (fail-closed)
    v_air = page.evaluate("() => window.__usbayTravel.evalVoucher('airline', {})")
    check("blocked partner eligible=false", v_air.get("eligible") is False and v_air["status"] == "blocked")
    # preview_only -> eligible false (non-binding, confers nothing)
    v_prev = page.evaluate("() => window.__usbayTravel.evalVoucher('bus', {preview: true})")
    check("preview_only eligible=false", v_prev.get("eligible") is False and v_prev["status"] == "preview_only")

    # 4. Voucher Audit Evidence: issuance / expiration / revocation
    issued = page.evaluate("() => window.__usbayTravel.lifecycle(window.__usbayTravel.evalVoucher('bus', {}))")
    issued_events = [e["event"] for e in issued]
    check("issued voucher lifecycle has ISSUANCE", "ISSUANCE" in issued_events)
    check("issued voucher lifecycle has EXPIRATION", "EXPIRATION" in issued_events)

    revoked = page.evaluate("() => window.__usbayTravel.evalVoucher('bus', {revoke: true})")
    check("revoke -> status revoked", revoked["status"] == "revoked")
    check("revoke -> eligible false (fail-closed)", revoked.get("eligible") is False)
    check("revoke -> VOUCHER_REVOKED reason", "VOUCHER_REVOKED" in revoked["reasons"])
    check("revoke -> revoked_at timestamp set", isinstance(revoked.get("revoked_at"), str))
    check("revoked voucher still non-monetary", revoked["cash_value"] == "none" and revoked["transferable"] is False and revoked["funding"] == "partner_funded")
    rev_events = [e["event"] for e in page.evaluate("() => window.__usbayTravel.lifecycle(window.__usbayTravel.evalVoucher('bus', {revoke: true}))")]
    check("revoked voucher lifecycle has REVOCATION", "REVOCATION" in rev_events)

    # lifecycle audit evidence table rendered with all three event types
    page.wait_for_selector("#trv-life .trv-lrow", timeout=10000)
    life_txt = page.eval_on_selector("#trv-life", "e => e.textContent")
    check("lifecycle table shows ISSUANCE", "ISSUANCE" in life_txt)
    check("lifecycle table shows EXPIRATION", "EXPIRATION" in life_txt)
    check("lifecycle table shows REVOCATION", "REVOCATION" in life_txt)

    # 6. Fail-Closed Verification: unknown partner has no rule -> not eligible, fail closed
    v_missing = page.evaluate("() => window.__usbayTravel.evalVoucher('charter', {})")
    check("unknown partner fail-closed (not eligible)", v_missing.get("eligible") is False and v_missing["status"] == "blocked")
    check("unknown partner -> NO_PARTNER_RULE", "NO_PARTNER_RULE" in v_missing["reasons"])
    # expired -> fail closed
    v_exp = page.evaluate("() => window.__usbayTravel.evalVoucher('bus', {now: 1000000, expiresAt: 999000})")
    check("expired voucher fail-closed (not eligible)", v_exp.get("eligible") is False and "VOUCHER_EXPIRED" in v_exp["reasons"])

    # credit tamper cannot grant eligibility
    before = page.evaluate("() => window.__usbayTravel.partners.map(p => window.__usbayTravel.evalVoucher(p.type, {}).eligible)")
    page.evaluate("""() => {
        try {
            state.credits.start = 100000000;
            state.credits.earned = 100000000;
            state.credits.spent = 0;
            state.credits.sources = {incidents: 100000000, missions: 100000000, audit: 100000000};
        } catch(e){}
    }""")
    after = page.evaluate("() => window.__usbayTravel.partners.map(p => window.__usbayTravel.evalVoucher(p.type, {}).eligible)")
    check("credit tamper does not change eligibility", before == after)

    # Rules constraint: no payment / booking / partner-API / crypto / cashback rails
    seen = []
    page.on("request", lambda r: seen.append(r.url))
    seen.clear()
    page.evaluate("() => { window.__usbayTravel.partners.forEach(p => window.__usbayTravel.evalVoucher(p.type, {revoke:true})); }")
    page.wait_for_timeout(300)
    check("voucher lifecycle triggers zero network requests", len([u for u in seen if u]) == 0)
    src = page.content().lower()
    banned = ["stripe", "paypal", "checkout.session", "payment_intent", "/book", "booking_id", "card_number", "cashback", "crypto wallet"]
    check("no payment/booking/partner-api rails referenced", not any(b in src for b in banned))

    # existing routes still 200 (additive only)
    for rt in ROUTES:
        resp = page.request.get("http://localhost:5000" + rt)
        check("route 200 " + rt, resp.status == 200)

    page.goto(URL, wait_until="domcontentloaded", timeout=30000)
    page.wait_for_selector("#trv-life .trv-lrow", timeout=15000)
    page.add_style_tag(content="*{transition:none !important;animation:none !important;}")
    page.screenshot(path=os.path.join(OUT, "travel_v2.png"), full_page=True)
    page.locator("#travel").screenshot(path=os.path.join(OUT, "travel_panel_v2.png"))

    browser.close()

print("\nCONSOLE ERRORS:", "NONE" if not errors else "")
for e in errors:
    print("  -", e)
passed = sum(1 for _, ok in results if ok)
print("RESULT: %d/%d checks passed" % (passed, len(results)))
print("DONE")
