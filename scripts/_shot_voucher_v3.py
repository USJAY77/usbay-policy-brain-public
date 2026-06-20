"""PB-TRAVEL-003 Voucher Redemption Authority — Playwright UI suite.

Drives the Partner Verification Console on /simulator: issues server-signed
vouchers and verifies them against the authority, asserting fail-closed
behaviour for tamper / revoked / wrong-owner, the redemption audit trail, and
that no payment/booking/cash/crypto rails leak into the page.
"""

import os
from playwright.sync_api import sync_playwright

URL = "http://localhost:5000/simulator"
ROUTES = [
    "/simulator",
    "/simulator/voucher/issue?partner_id=bus&client_id=trainee01",
    "/simulator/storage/health",
]
OUT = "/home/runner/workspace/evidence/audit"
os.makedirs(OUT, exist_ok=True)

errors = []
results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name, flush=True)


with sync_playwright() as p:
    browser = p.chromium.launch(
        executable_path=os.environ.get("CHROME") or p.chromium.executable_path,
        headless=True,
        args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
    )
    ctx = browser.new_context(viewport={"width": 1280, "height": 3800}, device_scale_factor=1)
    page = ctx.new_page()
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append("PAGEERROR: " + str(e)))

    page.goto(URL, wait_until="domcontentloaded", timeout=45000)
    page.evaluate("() => { try { localStorage.clear(); } catch(e){} }")
    page.reload(wait_until="domcontentloaded")
    page.wait_for_selector("#pv-block", timeout=15000)
    page.add_style_tag(content="*{transition:none !important;animation:none !important;}")

    # 1. Console + controls present
    check("partner verification console present", page.query_selector("#pv-block") is not None)
    opts = page.eval_on_selector_all("#pv-partner option", "els => els.map(e => e.value).join('|')")
    check("partner selector populated", opts == "airline|train|bus|cruise|hotel")
    check("verify disabled before issue", page.eval_on_selector("#pv-verify", "e => e.disabled") is True)

    # window bridge available
    check("voucher bridge exposed", page.evaluate("() => !!(window.__usbayVoucher && window.__usbayVoucher.issue)"))

    # 2. Issue active voucher via window bridge (deterministic), then verify
    issued = page.evaluate("async () => { await window.__usbayVoucher.issue(false); return window.__usbayVoucher.current(); }")
    check("issued voucher has signature", bool(issued and issued.get("voucher_signature")))
    check("issued voucher bound to client_id", bool(issued and issued.get("client_id")))
    check("issued voucher has partner_id", bool(issued and issued.get("partner_id")))
    check("issued voucher cash_value none", issued and issued.get("cash_value") == "none")
    check("issued voucher non-transferable", issued and issued.get("transferable") is False)

    res_active = page.evaluate("async () => window.__usbayVoucher.verify(window.__usbayVoucher.current())")
    check("active verify valid", res_active.get("valid") is True)
    check("active status active", res_active.get("status") == "active")
    check("active reason VOUCHER_ACTIVE", res_active.get("reasons") == ["VOUCHER_ACTIVE"])

    # 2b. Governance approval evidence surfaced (evidence only, no value)
    check("issued voucher carries approval evidence",
          bool(issued and issued.get("approval_evidence")))
    check("approval evidence confers no value",
          issued and issued.get("approval_evidence", {}).get("confers_value") == "none")
    check("active verify reports approval approved",
          res_active.get("approval", {}).get("status") == "approved")

    # 3. Redemption audit trail issued/viewed/verified/approved
    trail_events = [e["event"] for e in res_active.get("audit_trail", [])]
    check("audit trail issued/viewed/verified/approved",
          trail_events == ["issued", "viewed", "verified", "approved"])

    # 4. Tamper -> fail closed (BAD_SIGNATURE)
    res_tamper = page.evaluate("async () => window.__usbayVoucher.verify(window.__usbayVoucher.tamperCurrent())")
    check("tamper invalid", res_tamper.get("valid") is False)
    check("tamper BAD_SIGNATURE", res_tamper.get("reasons") == ["BAD_SIGNATURE"])

    # 5. Wrong owner -> fail closed (OWNERSHIP_MISMATCH)
    res_owner = page.evaluate("async () => window.__usbayVoucher.verify(window.__usbayVoucher.current(), 'not-the-owner')")
    check("wrong owner invalid", res_owner.get("valid") is False)
    check("wrong owner OWNERSHIP_MISMATCH", res_owner.get("reasons") == ["OWNERSHIP_MISMATCH"])

    # 6. Revoked voucher -> fail closed, audit trail includes revoked
    revoked = page.evaluate("async () => { await window.__usbayVoucher.issue(true); return window.__usbayVoucher.current(); }")
    res_revoked = page.evaluate("async () => window.__usbayVoucher.verify(window.__usbayVoucher.current())")
    check("revoked invalid", res_revoked.get("valid") is False)
    check("revoked status revoked", res_revoked.get("status") == "revoked")
    rev_events = [e["event"] for e in res_revoked.get("audit_trail", [])]
    check("revoked audit trail has approved+revoked events",
          rev_events == ["issued", "viewed", "verified", "approved", "revoked"])

    # 6a. Governance approval evidence fail-closed paths (evidence only)
    res_noap = page.evaluate("async () => { await window.__usbayVoucher.issue(false); return window.__usbayVoucher.verifyNoApproval(); }")
    check("no-approval fails closed", res_noap.get("valid") is False)
    check("no-approval APPROVAL_MISSING", res_noap.get("reasons") == ["APPROVAL_MISSING"])
    noap_events = [e["event"] for e in res_noap.get("audit_trail", [])]
    check("no-approval audit trail has approval_failed", "approval_failed" in noap_events)
    res_badap = page.evaluate("async () => window.__usbayVoucher.verifyTamperApproval()")
    check("tampered-approval fails closed", res_badap.get("valid") is False)
    check("tampered-approval APPROVAL_INVALID", res_badap.get("reasons") == ["APPROVAL_INVALID"])

    # 6b. Central revocation registry (CRL): issue active -> revoke -> verify
    # must fail closed via the registry (not a signed revoked_at field).
    check("revoke bridge exposed", page.evaluate("() => !!(window.__usbayVoucher && window.__usbayVoucher.revoke)"))
    crl = page.evaluate(
        "async () => {"
        " await window.__usbayVoucher.issue(false);"
        " var before = await window.__usbayVoucher.verify(window.__usbayVoucher.current());"
        " await window.__usbayVoucher.revoke();"
        " var after = await window.__usbayVoucher.verify(window.__usbayVoucher.current());"
        " return {before: before, after: after};"
        "}"
    )
    check("crl active before revoke", crl["before"].get("status") == "active" and crl["before"].get("valid") is True)
    check("crl revoked after revoke", crl["after"].get("valid") is False and crl["after"].get("status") == "revoked")
    check("crl reason VOUCHER_REVOKED", crl["after"].get("reasons") == ["VOUCHER_REVOKED"])
    check("crl revocation block present", bool(crl["after"].get("revocation")))
    crl_events = [e["event"] for e in crl["after"].get("audit_trail", [])]
    check("crl audit trail has approved+revoked events",
          crl_events == ["issued", "viewed", "verified", "approved", "revoked"])
    crl_rows = crl["after"].get("audit_trail", [])
    check("crl audit rows carry client_ref/status/reason_code",
          all(("client_ref" in r and "status" in r and "reason_code" in r) for r in crl_rows))
    check("crl audit rows omit raw client_id", all("client_id" not in r for r in crl_rows))

    # 7. Signing secret never reaches the browser (only HMAC hex is present)
    body = page.content().lower()
    check("no signing secret in page", "usbay-sim-voucher-secret" not in body and "training-voucher-authority" not in body)

    # 8. No payment / booking / cash rails in page
    for banned in ("stripe", "paypal", "payment_intent", "checkout.session", "booking_id", "card_number", "cashback", "wallet", "stored-value", "stored_value"):
        check("no rail: " + banned, banned not in body)

    # 9. Click-driven UI smoke: issue then verify through the buttons
    page.click("#pv-issue")
    page.wait_for_timeout(400)
    check("verify enabled after issue click", page.eval_on_selector("#pv-verify", "e => e.disabled") is False)
    page.click("#pv-verify")
    page.wait_for_timeout(400)
    verdict = page.eval_on_selector("#pv-res .pv-verdict", "e => e.textContent")
    check("ui verdict VALID after verify", verdict == "VALID")
    trail_rows = page.eval_on_selector_all("#pv-trail .pv-trow", "els => els.length")
    check("ui renders audit trail rows", trail_rows >= 3)

    # 10. UI tamper button -> rejected
    page.click("#pv-tamper")
    page.wait_for_timeout(400)
    verdict2 = page.eval_on_selector("#pv-res .pv-verdict", "e => e.textContent")
    check("ui tamper verdict REJECTED", verdict2 == "REJECTED")

    # 10b. UI verify-without-approval button -> rejected, evidence only
    page.click("#pv-issue")
    page.wait_for_timeout(400)
    page.click("#pv-noapproval")
    page.wait_for_timeout(400)
    verdict3 = page.eval_on_selector("#pv-res .pv-verdict", "e => e.textContent")
    check("ui no-approval verdict REJECTED", verdict3 == "REJECTED")
    res_text = page.eval_on_selector("#pv-res", "e => e.textContent")
    check("ui no-approval surfaces APPROVAL_MISSING", "APPROVAL_MISSING" in res_text)

    # 10c. PB-SIM-TRAVEL-006 -- preview-only, partner-side redemption hardening
    check("redeem bridge exposed",
          page.evaluate("() => !!(window.__usbayVoucher && window.__usbayVoucher.redeem && window.__usbayVoucher.preview)"))
    rdm = page.evaluate(
        "async () => {"
        " await window.__usbayVoucher.issue(false);"
        " return await window.__usbayVoucher.redeem();"
        "}"
    )
    check("redeem active is redeemable", rdm.get("redeemable") is True)
    check("redeem preview_only flag", rdm.get("preview_only") is True)
    check("redeem partner_side flag", rdm.get("partner_side") is True)
    check("redeem confers no value", rdm.get("confers_value") == "none")
    check("redeem audit has redeem_preview",
          "redeem_preview" in [e["event"] for e in rdm.get("audit_trail", [])])
    # a revoked voucher can never become redeemable (fail-closed)
    blk = page.evaluate(
        "async () => {"
        " await window.__usbayVoucher.issue(false);"
        " await window.__usbayVoucher.revoke();"
        " return await window.__usbayVoucher.redeem();"
        "}"
    )
    check("redeem revoked blocked", blk.get("redeemable") is False)
    check("redeem revoked status revoked", blk.get("status") == "revoked")
    check("redeem blocked audit has redeem_blocked",
          "redeem_blocked" in [e["event"] for e in blk.get("audit_trail", [])])
    # preview action emits the preview vocabulary
    prv = page.evaluate(
        "async () => {"
        " await window.__usbayVoucher.issue(false);"
        " return await window.__usbayVoucher.preview();"
        "}"
    )
    check("preview action is preview", prv.get("action") == "preview")
    check("preview audit has preview event",
          "preview" in [e["event"] for e in prv.get("audit_trail", [])])

    # 10d. UI redeem button smoke
    page.click("#pv-issue")
    page.wait_for_timeout(400)
    check("redeem enabled after issue", page.eval_on_selector("#pv-redeem", "e => e.disabled") is False)
    page.click("#pv-redeem")
    page.wait_for_timeout(400)
    rverdict = page.eval_on_selector("#pv-res .pv-verdict", "e => e.textContent")
    check("ui redeem verdict REDEEM OK", rverdict == "REDEEM OK")

    # 11. Routes reachable
    for r in ROUTES:
        resp = page.request.get("http://localhost:5000" + r)
        check("route " + str(resp.status) + " " + r, resp.status == 200)

    page.screenshot(path=os.path.join(OUT, "voucher_v3.png"), full_page=True)
    pv = page.query_selector("#pv-block")
    if pv:
        pv.screenshot(path=os.path.join(OUT, "voucher_panel_v3.png"))

    browser.close()

print("\nCONSOLE ERRORS: " + ("NONE" if not errors else "\n".join(errors)), flush=True)
passed = sum(1 for _, ok in results if ok)
print("RESULT: %d/%d checks passed" % (passed, len(results)), flush=True)
print("DONE", flush=True)
