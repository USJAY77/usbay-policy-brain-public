#!/usr/bin/env python3
"""One-shot validation harness for the hash-pinned launcher's supervisor."""
import ast
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "attached_assets/usbay-fda-readonly-diskutil-diagnostic.zsh"
PROPOSAL = ROOT / "attached_assets/usbay-temporary-terminal-full-disk-access-diagnostic-proposal.md"
EVIDENCE = Path(__file__).resolve().parent / "evidence"
EXPECTED_LAUNCHER = "b19bd48a797b3f5659c6fb850d4baff1792c6c73153bfec13b4eb6f5976f320b"
EXPECTED_PROPOSAL = "ef648fadc31e252ce91ff6ee754b0670e6f477b5afd8a5e4a5bc3cdcb675429c"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract_source():
    raw = LAUNCHER.read_text()
    py = raw.split("<<'PY'\n", 1)[1].split("\ntry:\n    final_status=main()", 1)[0]
    tree = ast.parse(py)
    chosen = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef)) and (
            not isinstance(node, ast.FunctionDef) or node.name != "main"
        ):
            chosen.append(node)
    module = ast.Module(body=chosen, type_ignores=[])
    source = ast.unparse(module) + "\n"
    # The digest is evidence of the exact extracted AST, while execution below
    # uses the original source slices (not a rewritten implementation).
    namespace = {"__name__": "extracted_supervisor"}
    exec(compile(ast.Module(body=chosen, type_ignores=[]), str(LAUNCHER), "exec"), namespace)
    return py, namespace, [f"{n.__class__.__name__}:{getattr(n, 'name', '')}" for n in chosen], hashlib.sha256(source.encode()).hexdigest()


def synthetic(kind):
    if kind == "exit0":
        return ["/bin/sh", "-c", "exit 0"]
    if kind == "exit124":
        return ["/bin/sh", "-c", "exit 124"]
    if kind == "exit125":
        return ["/bin/sh", "-c", "exit 125"]
    if kind in ("sleep", "ignore-term"):
        command = "trap '' TERM; sleep 0.35" if kind == "ignore-term" else "sleep 0.35"
        return ["/bin/sh", "-c", command]
    if kind == "descendant":
        return ["/bin/sh", "-c", "sleep 0.32 & exit 0"]
    raise ValueError(kind)


def worker(case, source_path):
    source, ns, _, _ = extract_source()
    # Explicit external instrumentation: only test globals are monkeypatched.
    trace = []
    stdout = tempfile.TemporaryFile()
    stderr = tempfile.TemporaryFile()
    original = {}
    timer = None
    if case.startswith("signal-"):
        sig = {"signal-SIGINT": signal.SIGINT, "signal-SIGTERM": signal.SIGTERM,
               "signal-SIGHUP": signal.SIGHUP}[case]
        timer = threading.Timer(0.04, os.kill, args=(os.getpid(), sig))
        timer.start()
    if case == "cleanup-denial":
        original["signal_group"] = ns["signal_group"]
        ns["signal_group"] = lambda *args: "denied"
    elif case == "probe-exception":
        original["group_state"] = ns["group_state"]
        def raise_probe(*args, **kwargs):
            raise RuntimeError("injected-probe")
        ns["group_state"] = raise_probe
    elif case == "drain-exception":
        original["sigpending"] = ns["signal"].sigpending
        ns["signal"].sigpending = lambda: (_ for _ in ()).throw(RuntimeError("injected-drain"))
    elif case == "term-to-kill":
        original["signal_group"] = ns["signal_group"]
        def delayed_group(*args):
            if args[1] == signal.SIGTERM:
                return "sent"
            return original["signal_group"](*args)
        ns["signal_group"] = delayed_group
    try:
        kind = "sleep" if case.startswith("signal-") else case
        status, reason = ns["bounded"](synthetic(kind), 0.08, stdout, stderr, trace)
        result = {"status": status, "reason": reason, "trace": trace}
    except BaseException as exc:
        result = {"worker_exception": type(exc).__name__, "message": str(exc), "trace": trace}
    finally:
        if timer:
            timer.cancel()
        stdout.close()
        stderr.close()
    Path(source_path).write_text(json.dumps(result, sort_keys=True) + "\n")


def run_case(case, extracted_path):
    out = EVIDENCE / (case + ".json")
    cmd = [sys.executable, str(Path(__file__).resolve()), "--worker", case, str(out)]
    start = time.monotonic()
    proc = subprocess.Popen(cmd, start_new_session=True)
    owned = {"pid": proc.pid, "pgid": os.getpgid(proc.pid), "case": case}
    watchdog = "running"
    try:
        proc.wait(timeout=1.5)
        watchdog = "exited"
    except subprocess.TimeoutExpired:
        watchdog = "watchdog-timeout"
        os.killpg(owned["pgid"], signal.SIGKILL)
        proc.wait(timeout=1)
    result = json.loads(out.read_text()) if out.exists() else {"missing": True}
    result.update({"case": case, "expected_watchdog": "exited", "watchdog": watchdog,
                   "owned_process": owned, "elapsed_ms": round((time.monotonic() - start) * 1000)})
    return result


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    pre = {"launcher": digest(LAUNCHER), "proposal": digest(PROPOSAL)}
    if pre != {"launcher": EXPECTED_LAUNCHER, "proposal": EXPECTED_PROPOSAL}:
        raise SystemExit("hash precondition failed")
    source, _, locations, extraction_hash = extract_source()
    extracted_path = EVIDENCE / "extracted_supervisor_source.py"
    extracted_path.write_text(source)
    cases = ["exit0", "exit124", "exit125", "sleep", "descendant",
             "signal-SIGINT", "signal-SIGTERM", "signal-SIGHUP",
             "term-to-kill", "cleanup-denial", "probe-exception", "drain-exception"]
    results = [run_case(case, extracted_path) for case in cases]
    post = {"launcher": digest(LAUNCHER), "proposal": digest(PROPOSAL)}
    raw = {"pre_hashes": pre, "post_hashes": post, "source_extraction_sha256": extraction_hash,
           "source_locations": locations, "cases": results,
           "environment": {"python": sys.version, "platform": sys.platform, "pid": os.getpid()},
           "instrumentation": "Only extracted module globals signal_group, group_state, and signal.sigpending were monkeypatched in named cases; production source was not edited."}
    (EVIDENCE / "raw.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    (EVIDENCE / "report.txt").write_text(
        "Bounded validation batch\n\n"
        "Source assessment: bounded() has child.wait(seconds), wait_group_clean term/kill deadlines, "
        "and terminate_child waits, but evidence emission after finish() has no total deadline. "
        "Watched signals remain blocked through the caller's evidence emission. Process-group cleanup "
        "cannot reach descendants that escape the child process group. Exceptions outside the narrowly "
        "caught paths (including trace/event or evidence I/O failures) can prevent structured evidence.\n\n"
        + json.dumps(results, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps({"files": sorted(str(p.relative_to(ROOT)) for p in EVIDENCE.iterdir()),
                      "post_hashes": post, "cases": results}, indent=2))


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--worker":
        worker(sys.argv[2], sys.argv[3])
    else:
        main()