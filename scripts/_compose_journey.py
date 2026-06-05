import os
from PIL import Image, ImageDraw, ImageFont

OUT = "/home/runner/workspace/evidence"

STAGES = [
    ("journey_1_assessment.png", "1. ASSESSMENT", "Governance assessment result"),
    ("journey_2_license.png", "2. LICENSE", "Recommended license tier"),
    ("journey_3_pilot_wizard.png", "3. PILOT PLAN", "Governance pilot wizard"),
    ("journey_4_executive_report.png", "4. EXECUTIVE REPORT", "Executive governance report"),
    ("journey_5_pilot_request.png", "5. PILOT REQUEST", "Sealed, accountable requester"),
    ("journey_7_approved.png", "6. GOVERNANCE DECISION", "Approved \u2014 single threaded record"),
]

BG = (7, 12, 20)
PANEL = (12, 22, 36)
BORDER = (31, 58, 82)
CYAN = (34, 211, 238)
WHITE = (230, 237, 246)
GREY = (148, 163, 184)
ARROW = (45, 212, 191)

COL_W = 760          # rendered image width per stage
HEAD_H = 92          # header band per stage
GAP = 70             # gap (for arrow) between stages
PAD = 60             # outer padding
TITLE_H = 150


def font(sz, bold=True):
    try:
        return ImageFont.load_default(size=sz)
    except Exception:
        return ImageFont.load_default()


F_TITLE = font(46)
F_SUB = font(24, bold=False)
F_HEAD = font(30)
F_HSUB = font(20, bold=False)

# load + scale each stage image to COL_W
imgs = []
for fn, _, _ in STAGES:
    im = Image.open(os.path.join(OUT, fn)).convert("RGB")
    w, h = im.size
    nh = int(h * COL_W / w)
    imgs.append(im.resize((COL_W, nh), Image.LANCZOS))

col_total_h = max(HEAD_H + im.size[1] for im in imgs)
canvas_h = TITLE_H + col_total_h + PAD * 2
canvas_w = PAD * 2 + COL_W * len(imgs) + GAP * (len(imgs) - 1)

canvas = Image.new("RGB", (canvas_w, canvas_h), BG)
d = ImageDraw.Draw(canvas)

# title
d.text((PAD, 44), "USBAY \u2014 Single Governance Journey", font=F_TITLE, fill=WHITE)
d.text((PAD, 100),
       "One continuous session: Assessment \u2192 License \u2192 Pilot Plan \u2192 Executive Report \u2192 Pilot Request \u2192 Governance Decision."
       "  Preview-only \u2014 nothing stored, transmitted, or persisted.",
       font=F_SUB, fill=GREY)

y0 = TITLE_H + PAD
for i, (im, (fn, head, sub)) in enumerate(zip(imgs, STAGES)):
    x = PAD + i * (COL_W + GAP)
    # header band
    d.rounded_rectangle([x, y0, x + COL_W, y0 + HEAD_H - 12], radius=10,
                        fill=PANEL, outline=BORDER, width=2)
    d.text((x + 18, y0 + 14), head, font=F_HEAD, fill=CYAN)
    d.text((x + 18, y0 + 52), sub, font=F_HSUB, fill=GREY)
    # image with border
    iy = y0 + HEAD_H
    canvas.paste(im, (x, iy))
    d.rectangle([x, iy, x + COL_W - 1, iy + im.size[1] - 1], outline=BORDER, width=2)
    # arrow to next
    if i < len(imgs) - 1:
        ax = x + COL_W + GAP // 2
        ay = y0 + HEAD_H + 120
        d.line([(ax - 22, ay), (ax + 14, ay)], fill=ARROW, width=6)
        d.polygon([(ax + 14, ay - 14), (ax + 34, ay), (ax + 14, ay + 14)], fill=ARROW)

out = os.path.join(OUT, "journey_map_single_journey.png")
canvas.save(out)
print("saved", out, canvas.size, os.path.getsize(out), "bytes")
