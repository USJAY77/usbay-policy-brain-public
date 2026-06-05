import os
from PIL import Image, ImageDraw, ImageFont

OUT = "/home/runner/workspace/evidence"

SHOTS = [
    ("multireviewer_1_compliance.png", "1. COMPLIANCE APPROVAL", "Compliance Reviewer approves"),
    ("multireviewer_2_legal.png", "2. LEGAL APPROVAL", "Legal Reviewer approves"),
    ("multireviewer_3_security.png", "3. SECURITY APPROVAL", "Security Reviewer approves"),
    ("multireviewer_4_executive.png", "4. EXECUTIVE APPROVAL", "Human executive gate approves"),
    ("multireviewer_5_human_review.png", "5. HUMAN REVIEW ESCALATION", "Escalated - mandatory human review"),
    ("multireviewer_6_final_approved.png", "6. FINAL APPROVED", "All lanes clear - pilot authorized"),
    ("multireviewer_7_final_rejected.png", "7. FINAL REJECTED", "Fail-closed - pilot blocked"),
]

BG = (5, 11, 19)
PANEL = (12, 22, 36)
BORDER = (31, 58, 82)
CYAN = (34, 211, 238)
WHITE = (235, 243, 252)
GREY = (148, 163, 184)
ARROW = (45, 212, 191)

COLS = 4
COL_W = 720
HEAD_H = 96
GAP_X = 70
GAP_Y = 70
PAD = 60
TITLE_H = 170


def font(sz):
    try:
        return ImageFont.load_default(size=sz)
    except Exception:
        return ImageFont.load_default()


F_TITLE = font(48)
F_SUB = font(24)
F_HEAD = font(28)
F_HSUB = font(20)
F_BADGE = font(20)

imgs = []
for fn, _, _ in SHOTS:
    im = Image.open(os.path.join(OUT, fn)).convert("RGB")
    w, h = im.size
    nh = int(h * COL_W / w)
    imgs.append(im.resize((COL_W, nh), Image.LANCZOS))

cell_img_h = max(im.size[1] for im in imgs)
cell_h = HEAD_H + cell_img_h
rows = (len(SHOTS) + COLS - 1) // COLS

canvas_w = PAD * 2 + COL_W * COLS + GAP_X * (COLS - 1)
canvas_h = TITLE_H + cell_h * rows + GAP_Y * (rows - 1) + PAD * 2

canvas = Image.new("RGB", (canvas_w, canvas_h), BG)
d = ImageDraw.Draw(canvas)

d.text((PAD, 40), "USBAY - Multi-Reviewer Governance Approval Journey", font=F_TITLE, fill=WHITE)
d.text((PAD, 100),
       "Four reviewer lanes (Compliance, Legal, Security, Executive) with approve / reject / escalate-to-human outcomes.",
       font=F_SUB, fill=GREY)
d.text((PAD, 132),
       "USBAY = ENFORCEMENT_AUTHORITY   |   Euria = ANALYSIS_ONLY   |   Human approval = MANDATORY   |   Fail closed = DEFAULT   |   Preview-only, nothing stored or persisted.",
       font=F_BADGE, fill=CYAN)

for idx, (im, (fn, head, sub)) in enumerate(zip(imgs, SHOTS)):
    r = idx // COLS
    c = idx % COLS
    x = PAD + c * (COL_W + GAP_X)
    y0 = TITLE_H + r * (cell_h + GAP_Y)
    d.rounded_rectangle([x, y0, x + COL_W, y0 + HEAD_H - 14], radius=10,
                        fill=PANEL, outline=BORDER, width=2)
    d.text((x + 18, y0 + 14), head, font=F_HEAD, fill=CYAN)
    d.text((x + 18, y0 + 52), sub, font=F_HSUB, fill=GREY)
    iy = y0 + HEAD_H
    canvas.paste(im, (x, iy))
    d.rectangle([x, iy, x + COL_W - 1, iy + im.size[1] - 1], outline=BORDER, width=2)
    if c < COLS - 1 and idx < len(SHOTS) - 1:
        ax = x + COL_W + GAP_X // 2
        ay = iy + 120
        d.line([(ax - 20, ay), (ax + 12, ay)], fill=ARROW, width=6)
        d.polygon([(ax + 12, ay - 13), (ax + 32, ay), (ax + 12, ay + 13)], fill=ARROW)

out = os.path.join(OUT, "multireviewer_journey_full.png")
canvas.save(out)
print("saved", out, canvas.size, os.path.getsize(out), "bytes")
