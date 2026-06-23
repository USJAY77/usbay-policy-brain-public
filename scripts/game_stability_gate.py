#!/usr/bin/env python3
"""USBAY-GAME-010R - Game demo prototype stability gate.

A single, repeatable stability/testing command for the additive, demo-only
``/game`` prototype. It is the final stability gate after USBAY-GAME-009B and is
strictly STABILITY/TESTING ONLY and READ-ONLY:

  * It does NOT modify or exercise ``/execute``, governance enforcement,
    booking, payment, the simulator, or any external API.
  * It does NOT change gameplay. It only renders ``/game`` in-process, runs the
    existing GAME-008 / GAME-009 / GAME-010R browser-level DOM tests, captures a
    runtime benchmark, verifies the safety-regression contract, and writes a
    short stability report.

What it does, in order:
  1. Boot check  - import the app in-process and confirm ``GET /game`` -> 200.
  2. DOM tests   - run the three shared-render DOM suites under one jsdom render;
                   fail loudly on any failure, error, OR skip (no silent skips).
  3. Benchmark   - read the phase timing emitted by the harness for this run.
  4. Safety gate - re-verify the 8 safety properties from the same render.
  5. Guardrails  - enforce the documented timeout threshold with a clear reason.
  6. Forbidden   - confirm no forbidden (app/governance/execute/simulator/
                   payment/booking) file changed in the working tree.
  7. Report      - write evidence/audit/GAME_DEMO_STABILITY_GATE_010R.md.

Exit code is 0 only if every check passes; otherwise non-zero with a clear
reason. Run with:  python3.11 scripts/game_stability_gate.py
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STABILITY_COMMAND = "python3.11 scripts/game_stability_gate.py"

DOM_TEST_FILES = [
    "tests/test_game_interactive_dom.py",       # GAME-008
    "tests/test_game_ux_hardening_dom.py",       # GAME-009R
    "tests/test_game_stability_gate_dom.py",     # GAME-010R safety contract
]
DUMP_PATH = "/tmp/game_stability_dom.json"
REPORT_PATH = ROOT / "evidence" / "audit" / "GAME_DEMO_STABILITY_GATE_010R.md"

# ---- Timeout guardrails (documented, single source of truth) ----
EXPECTED_WARM_RUNTIME_S = 60     # boot + warm jsdom render + pytest overhead
EXPECTED_COLD_RUNTIME_S = 120    # first cold render (page cache empty) + overhead
TIMEOUT_THRESHOLD_S = 300        # HARD fail above this; matches harness subprocess timeout

# 009A staged cold-probe baseline. Cold cache CANNOT be force-reproduced here
# (dropping the OS page cache needs root), so cold timing is cited, not measured.
COLD_BASELINE_MS = {
    "importMs": 74934,
    "constructMs": 3547,
    "executionMs": 13,
    "totalMs": 78662,
}

# Forbidden surfaces for GAME-010R. The gateway is a single-file FastAPI app, so
# /execute, governance enforcement, the simulator, booking and payment all live
# in gateway/app.py; runtime/* holds governance/policy enforcement code.
FORBIDDEN_EXACT = {"gateway/app.py"}
FORBIDDEN_PREFIXES = ("runtime/",)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def boot_check() -> tuple[bool, str, int, int]:
    """Import the app in-process and confirm GET /game returns 200."""
    try:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from fastapi.testclient import TestClient

        from gateway.app import app

        client = TestClient(app)
        resp = client.get("/game")
        code = resp.status_code
        nbytes = len(resp.text)
        ok = code == 200 and nbytes > 0
        detail = f"GET /game -> {code} ({nbytes} bytes)"
        return ok, detail, code, nbytes
    except Exception as exc:  # pragma: no cover - boot failure path
        return False, f"app failed to boot: {exc!r}", 0, 0


def run_dom_tests(timeout_s: int) -> dict:
    """Run the three shared-render DOM suites; treat skip as failure."""
    env = dict(os.environ)
    env["GAME_STABILITY_DUMP"] = DUMP_PATH
    if os.path.exists(DUMP_PATH):
        try:
            os.remove(DUMP_PATH)
        except OSError:
            pass
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        *DOM_TEST_FILES,
        "-p",
        "no:cacheprovider",
        "-q",
        "-rs",
    ]
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "timed_out": True,
            "elapsed_s": round(time.monotonic() - t0, 1),
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "errors": 0,
            "summary": f"pytest exceeded {timeout_s}s timeout threshold",
            "output": "",
        }
    elapsed = round(time.monotonic() - t0, 1)
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")

    def _count(word: str) -> int:
        m = re.search(rf"(\d+) {word}", out)
        return int(m.group(1)) if m else 0

    passed = _count("passed")
    failed = _count("failed")
    skipped = _count("skipped")
    errors = _count("error")
    summary_line = ""
    for line in reversed(out.strip().splitlines()):
        if "passed" in line or "failed" in line or "error" in line or "no tests ran" in line:
            summary_line = line.strip()
            break
    ok = (
        proc.returncode == 0
        and failed == 0
        and errors == 0
        and skipped == 0
        and passed > 0
    )
    return {
        "ok": ok,
        "timed_out": False,
        "elapsed_s": elapsed,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "errors": errors,
        "returncode": proc.returncode,
        "summary": summary_line or "(no pytest summary line found)",
        "output": out,
    }


def load_dump() -> dict | None:
    try:
        with open(DUMP_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def safety_regression(d: dict | None) -> list[tuple[str, bool, str]]:
    """Re-verify the 8 safety properties from the same render. Returns
    (property, ok, detail) rows."""
    rows: list[tuple[str, bool, str]] = []
    if not d:
        names = [
            "demo banner remains visible",
            "no booking/payment UI",
            "no external network calls",
            "no personal data persisted",
            "VIP discount remains demo-only",
            "route selection deterministic",
            "child-safe active after interactions",
            "accessibility active after interactions",
        ]
        return [(n, False, "no render dump available") for n in names]

    banner = d.get("banner", {})
    load = banner.get("load", {})
    b_ok = (
        load.get("present") is True
        and "DEMO ONLY - NO REAL BOOKING" in load.get("text", "")
        and "NO REAL PAYMENT" in load.get("text", "")
        and banner.get("afterRoute") is True
        and banner.get("afterCs") is True
        and banner.get("afterA11y") is True
    )
    rows.append(("demo banner remains visible", b_ok, "present at load + after route/cs/a11y"))

    u = d.get("unsafe", {})
    rows.append(
        (
            "no booking/payment UI",
            u.get("buttonsBad") == [] and u.get("inputs") == [],
            f"buttonsBad={u.get('buttonsBad')} inputs={u.get('inputs')}",
        )
    )
    rows.append(
        ("no external network calls", u.get("net") == [], f"net={u.get('net')}")
    )
    rows.append(
        (
            "no personal data persisted",
            u.get("persist") == [] and u.get("cookie") == "",
            f"persist={u.get('persist')} cookie={u.get('cookie')!r}",
        )
    )

    disc = d.get("discount", {})
    modes = disc.get("modes", {})
    kinds = ["air", "rail", "bus", "cruise", "ferry", "hotel", "logistics"]
    vip_ok = disc.get("vipOn") is True and d.get("rewardsDisclaimer") is True
    vip_ok = vip_ok and d.get("forbidden", {}).get("found") == []
    for k in kinds:
        cell = modes.get(k)
        if not cell or cell.get("pv") != round(cell.get("po", 0) * 0.8) or "-20%" not in cell.get("vd", ""):
            vip_ok = False
            break
    rows.append(("VIP discount remains demo-only", vip_ok, "fixed 20% cut, no real-money language"))

    r = d.get("route", {})
    w = r.get("winners", {})
    route_ok = (
        "Line 3 - Teal" in w.get("cheapest", "")
        and "Line 3 - Teal" in w.get("fastest", "")
        and "Pacific Star" in w.get("xp", "")
        and "Atlas Express R-12" in w.get("gov", "")
        and r.get("tripCount") == 15
    )
    rows.append(("route selection deterministic", route_ok, "fixed winners + 15 trips"))

    ux = d.get("ux009r", {})
    rows.append(
        (
            "child-safe active after interactions",
            ux.get("csActiveAfterRoute") is True and ux.get("csBannerAfterRoute") is True,
            "child-safe + banner persist after route",
        )
    )
    rows.append(
        (
            "accessibility active after interactions",
            ux.get("a11yActiveAfterRoute") is True and ux.get("a11yBannerAfterRoute") is True,
            "a11y + banner persist after route",
        )
    )
    return rows


def forbidden_file_check() -> tuple[bool, list[str], str]:
    """Confirm no forbidden file changed in the working tree (vs HEAD)."""
    try:
        proc = subprocess.run(
            ["git", "--no-optional-locks", "diff", "--name-only", "HEAD"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception as exc:  # pragma: no cover
        return False, [], f"git unavailable - cannot verify forbidden files (fail-closed): {exc!r}"
    if proc.returncode != 0:
        return False, [], "git diff failed - cannot verify forbidden files (fail-closed)"
    changed = [p.strip() for p in proc.stdout.splitlines() if p.strip()]
    violations = [
        p
        for p in changed
        if p in FORBIDDEN_EXACT or p.startswith(FORBIDDEN_PREFIXES)
    ]
    return (not violations), violations, f"{len(changed)} files changed in working tree"


def write_report(ctx: dict) -> None:
    t = ctx["timing"] or {}
    cold = COLD_BASELINE_MS
    rows = "\n".join(
        f"| {name} | {'PASS' if ok else 'FAIL'} | {detail} |"
        for name, ok, detail in ctx["safety"]
    )
    fb = ctx["forbidden"]
    overall = "PASS" if ctx["overall_ok"] else "FAIL"
    body = f"""# GAME Demo Prototype Stability Gate (USBAY-GAME-010R)

_Last run: {ctx['ts']}_  ·  **Overall result: {overall}**

**Scope:** STABILITY / TESTING ONLY, additive, read-only. This gate never
modifies or exercises `/execute`, governance enforcement, the simulator,
booking, or payment, and makes no external network calls. `gateway/app.py` and
the `/game` prototype are not modified.

## Stability command
```bash
{STABILITY_COMMAND}
```

## Boot check
- {ctx['boot_detail']}

## DOM test result
- Suites: `{'`, `'.join(DOM_TEST_FILES)}` (one shared jsdom render)
- Summary: `{ctx['dom']['summary']}`
- passed={ctx['dom']['passed']} failed={ctx['dom']['failed']} skipped={ctx['dom']['skipped']} errors={ctx['dom']['errors']}
- Result: **{'PASS' if ctx['dom']['ok'] else 'FAIL'}** (a skip is treated as a failure - no silent skips)

## Runtime benchmark
- Total gate runtime: **{ctx['total_s']} s**
- DOM-suite phase: {ctx['dom']['elapsed_s']} s
- Warm run (this run, from harness `__timing`): import={t.get('importMs','?')} ms · construct={t.get('constructMs','?')} ms · execution={t.get('executionMs','?')} ms · total={t.get('totalMs','?')} ms
- Cold run (009A staged baseline, cited): import={cold['importMs']} ms · construct={cold['constructMs']} ms · total={cold['totalMs']} ms

## Timeout guardrails
- Expected warm runtime: ~{EXPECTED_WARM_RUNTIME_S} s
- Expected cold runtime: ~{EXPECTED_COLD_RUNTIME_S} s
- Acceptable timeout threshold (hard fail above this): {TIMEOUT_THRESHOLD_S} s
- This run: {ctx['total_s']} s -> {ctx['threshold_note']}

## Safety regression result
| Property | Result | Detail |
| --- | --- | --- |
{rows}

## Forbidden-file check
- {fb[2]}
- Forbidden surfaces: `{'`, `'.join(sorted(FORBIDDEN_EXACT))}`, prefixes `{'`, `'.join(FORBIDDEN_PREFIXES)}`
- Violations: {('NONE' if not fb[1] else ', '.join(fb[1]))} -> **{'PASS' if fb[0] else 'FAIL'}**

## Remaining limitations / gaps
- jsdom module import dominates wall-clock (cold ~75 s / warm ~32 s); it is
  irreducible here - jsdom 29 cannot be bundled into one file (it reads its own
  data assets from disk at runtime).
- Cold cache cannot be force-reproduced (no privilege to drop the OS page cache),
  so cold timing is cited from the 009A staged probe, not measured live.
- Boot is verified in-process via `TestClient` (the same path the DOM tests use),
  not against the long-running workflow server.

## Rollback
```bash
git checkout HEAD -- tests/conftest.py
rm -f tests/test_game_stability_gate_dom.py scripts/game_stability_gate.py \\
      evidence/audit/GAME_DEMO_STABILITY_GATE_010R.md
```
"""
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(body, encoding="utf-8")


def main() -> int:
    t_start = time.monotonic()
    ts = _now()
    print(f"[stability-gate] {ts}  command: {STABILITY_COMMAND}")

    boot_ok, boot_detail, _code, _bytes = boot_check()
    print(f"[boot] {'OK' if boot_ok else 'FAIL'} - {boot_detail}")

    dom = run_dom_tests(TIMEOUT_THRESHOLD_S)
    print(
        f"[dom] {'OK' if dom['ok'] else 'FAIL'} - {dom['summary']} "
        f"(passed={dom['passed']} failed={dom['failed']} skipped={dom['skipped']} "
        f"errors={dom['errors']}, {dom['elapsed_s']}s)"
    )
    if not dom["ok"] and dom.get("output"):
        sys.stdout.write(dom["output"][-1500:] + "\n")

    timing = (load_dump() or {}).get("__timing") if dom["passed"] else None
    safety = safety_regression(load_dump())
    safety_ok = all(ok for _n, ok, _d in safety)
    for name, ok, _detail in safety:
        print(f"[safety] {'PASS' if ok else 'FAIL'} - {name}")

    fb_ok, fb_violations, fb_detail = forbidden_file_check()
    print(f"[forbidden] {'PASS' if fb_ok else 'FAIL'} - {fb_detail} (violations: {fb_violations or 'none'})")

    total_s = round(time.monotonic() - t_start, 1)
    within_threshold = total_s <= TIMEOUT_THRESHOLD_S
    if dom.get("timed_out"):
        threshold_note = f"TIMED OUT (> {TIMEOUT_THRESHOLD_S}s) - FAIL"
    elif not within_threshold:
        threshold_note = f"EXCEEDED threshold {TIMEOUT_THRESHOLD_S}s - FAIL"
    elif total_s > EXPECTED_COLD_RUNTIME_S:
        threshold_note = f"within hard threshold {TIMEOUT_THRESHOLD_S}s (slower than expected cold {EXPECTED_COLD_RUNTIME_S}s)"
    else:
        threshold_note = f"within expected window (<= {TIMEOUT_THRESHOLD_S}s)"

    overall_ok = boot_ok and dom["ok"] and safety_ok and fb_ok and within_threshold

    write_report(
        {
            "ts": ts,
            "boot_detail": boot_detail,
            "dom": dom,
            "timing": timing,
            "safety": safety,
            "forbidden": (fb_ok, fb_violations, fb_detail),
            "total_s": total_s,
            "threshold_note": threshold_note,
            "overall_ok": overall_ok,
        }
    )

    print(f"[report] wrote {REPORT_PATH.relative_to(ROOT)}")
    print(
        f"[stability-gate] OVERALL {'PASS' if overall_ok else 'FAIL'} "
        f"(total {total_s}s; {threshold_note})"
    )
    if not overall_ok:
        reasons = []
        if not boot_ok:
            reasons.append("boot/GET /game != 200")
        if not dom["ok"]:
            reasons.append(
                "DOM tests not all-passed"
                + (" (skips present)" if dom["skipped"] else "")
                + (" (timed out)" if dom.get("timed_out") else "")
            )
        if not safety_ok:
            reasons.append("safety regression failed")
        if not fb_ok:
            reasons.append(f"forbidden files changed: {fb_violations}")
        if not within_threshold:
            reasons.append(f"runtime {total_s}s exceeded threshold {TIMEOUT_THRESHOLD_S}s")
        print("[stability-gate] FAIL reasons: " + "; ".join(reasons))
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
