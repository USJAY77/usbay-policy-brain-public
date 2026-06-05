import os
from PIL import Image, ImageDraw, ImageFont

OUT = "/home/runner/workspace/evidence"

SHOTS = [
    ("evidencepkg_1_approved.png", "APPROVED", "All lanes clear + human gate - pilot authorized"),
    ("evidencepkg_2_human_review.png", "HUMAN REVIEW REQUIRED", "Escalated - awaiting mandatory human gate"),
    ("evidencepkg_3_rejected.png", "REJECTED", "Fail-closed - pilot blocked, no execution"),
]

BG = (5, 11, 19)
PANEL = (12, 22, 36)
BORDER = (31, 58, 82)
CYAN = (34, 211, 238)
WHITE = (235, 243, 252)
GREY = (148, 163, 184)
ARROW = (45, 212, 191)

COLS = 3
COL_W = 760
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

d.text((PAD, 40), "USBAY - Governance Evidence Package Generator", font=F_TITLE, fill=WHITE)
d.text((PAD, 100),
       "Board-ready post-approval evidence package: executive cover + 10 documented sections, across three governance outcomes.",
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

out = os.path.join(OUT, "evidencepkg_journey_full.png")
canvas.save(out)
print("saved", out, canvas.size, os.path.getsize(out), "bytes")
