import os, time, glob
from playwright.sync_api import sync_playwright

CHROME = "/nix/store/khk7xpgsm5insk81azy9d560yq4npf77-chromium-131.0.6778.204/bin/chromium"
URL = "http://localhost:5000/"
OUT = "/home/runner/workspace/evidence"
os.makedirs(OUT, exist_ok=True)
for f in glob.glob(os.path.join(OUT, "queue_*.png")):
    os.remove(f)

console_errors = []


def shot(el, name):
    el.scroll_into_view_if_needed()
    time.sleep(0.25)
    el.screenshot(path=os.path.join(OUT, name))
    print("captured", name)


with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=CHROME, headless=True,
                                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
    page = browser.new_page(viewport={"width": 1760, "height": 2200}, device_scale_factor=2)
    page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: console_errors.append("PAGEERROR: " + str(e)))
    page.goto(URL, wait_until="networkidle", timeout=60000)
    time.sleep(0.5)

    # Open Executive Report -> Intake Queue
    page.click("#usbsim-rpt-open")
    page.wait_for_selector("#usbsim-rpt", state="visible", timeout=10000)
    time.sleep(0.4)
    page.click("#usbsim-rpt-queue")
    page.wait_for_selector("#usbpq", state="visible", timeout=10000)
    page.wait_for_selector("#usbpq-body .usbpq-table", state="visible", timeout=10000)
    # Evidence-only: widen modal so all 8 columns are visible (no app code change).
    page.add_style_tag(content="#usbpq .usbsim-rpt-card{max-width:1680px !important;width:1680px !important;} "
                               "#usbpq .usbpq-tablewrap{overflow:visible !important;} "
                               "#usbpq .usbpq-table{width:100% !important;}")
    time.sleep(0.4)

    card = page.query_selector("#usbpq .usbsim-rpt-card")

    # 1. Populated Intake Queue (full modal, ALL filter)
    shot(card, "queue_1_populated.png")

    # 7. Per-status counts visible (stats strip at top)
    stats = page.query_selector("#usbpq-body .usbpq-stats")
    shot(stats, "queue_7_counts.png")

    # 6. Status legend visible (legend block)
    legend = page.query_selector("#usbpq-body .usbpq-legend")
    shot(legend, "queue_6_legend.png")

    def filter_and_shot(status, name):
        btn = page.query_selector("#usbpq-body [data-pqf='%s']" % status)
        btn.click()
        time.sleep(0.35)
        shot(page.query_selector("#usbpq .usbsim-rpt-card"), name)

    # 2/3/4 filtered views
    filter_and_shot("PENDING_GOVERNANCE_REVIEW", "queue_2_pending.png")
    filter_and_shot("HUMAN_REVIEW_REQUIRED", "queue_3_human.png")
    filter_and_shot("APPROVED", "queue_4_approved.png")

    # Back to ALL, then 5. Governance Approval modal from a queue row
    page.query_selector("#usbpq-body [data-pqf='ALL']").click()
    time.sleep(0.3)
    # Click Review on the PENDING row (index 0 -> still pending, shows approve/reject/human actions)
    review = page.query_selector("#usbpq-body [data-pq='0']")
    review.click()
    page.wait_for_selector("#usbpr", state="visible", timeout=10000)
    page.wait_for_selector("#usbpr-body .usbpr-actions", state="visible", timeout=10000)
    time.sleep(0.4)
    shot(page.query_selector("#usbpr .usbsim-rpt-card"), "queue_5_approval_modal.png")

    browser.close()

print("CONSOLE ERRORS:", console_errors if console_errors else "NONE")
