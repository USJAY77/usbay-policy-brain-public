#!/usr/bin/env python3
"""Preparation-only harness for the seven not-yet-executed supervisor cases."""
import ast
import ctypes
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "attached_assets/usbay-fda-readonly-diskutil-diagnostic.zsh"
PROPOSAL = ROOT / "attached_assets/usbay-temporary-terminal-full-disk-access-diagnostic-proposal.md"
EVIDENCE = Path(__file__).resolve().parent / "evidence"
MISSING_EVIDENCE = EVIDENCE / "missing_cases_batch"
EXPECTED_LAUNCHER = "b19bd48a797b3f5659c6fb850d4baff1792c6c73153bfec13b4eb6f5976f320b"
EXPECTED_PROPOSAL = "ef648fadc31e252ce91ff6ee754b0670e6f477b5afd8a5e4a5bc3cdcb675429c"
CHILD_WAIT_SECONDS = 0.08
TERM_GRACE_SECONDS = 2
KILL_GRACE_SECONDS = 2
WATCHDOG_CLEANUP_SECONDS = 3
CASE_EXECUTION_SECONDS = 12
MISSING_CASES = (
    "term-to-kill", "cleanup-denial", "probe-exception", "drain-exception",
    "cleanup-signal-SIGINT", "cleanup-signal-SIGTERM", "cleanup-signal-SIGHUP",
)
CASE_TO_SYNTHETIC = {
    "term-to-kill": "term_ignore_ready",
    "cleanup-denial": "sleep",
    "probe-exception": "exit0",
    "drain-exception": "exit0",
    "cleanup-signal-SIGINT": "sleep",
    "cleanup-signal-SIGTERM": "sleep",
    "cleanup-signal-SIGHUP": "sleep",
}
CONTAINMENT_ASSERTION_MARKERS = (
    "worker authorization",
    "supervisor-child record",
    "malformed ownership",
    "containment unproven",
    "watchdog did not observe clean exit",
    "owned supervisor group remained",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_stability(pre, post):
    """Assess only equality of the recorded pre/post source hashes."""
    return "PROVEN" if dict(pre) == dict(post) else "FAILED"


def parse_cli(argv):
    """Validate dispatch without touching evidence, channels, or processes."""
    args = list(argv)
    if args in (["--help"], ["-h"]):
        return {"mode": "help"}
    if args == ["--scheduler-self-test"]:
        return {"mode": "scheduler-self-test"}
    if args == []:
        return {"mode": "main"}
    if len(args) == 6 and args[0] == "--worker":
        case, ownership, result, auth, nonce = args[1:]
        if case not in MISSING_CASES or not nonce or nonce.startswith("-"):
            raise SystemExit("invalid worker case or nonce")
        paths = (ownership, result, auth)
        if any(not item or item.startswith("-") for item in paths):
            raise SystemExit("invalid worker paths")
        return {"mode": "worker", "case": case, "paths": paths, "nonce": nonce}
    raise SystemExit("unknown or malformed arguments")


def print_help():
    print("usage: run_validation.py [--scheduler-self-test|--worker CASE OWNERSHIP RESULT AUTH NONCE]")


def cli_parser_self_test():
    """Pure parser/dispatch checks; no evidence, channels, or processes."""
    side_effects = {"count": 0}
    for argv, expected in (
        (["--help"], "help"),
        (["--scheduler-self-test"], "scheduler-self-test"),
    ):
        parsed = parse_cli(argv)
        assert parsed["mode"] == expected
        assert side_effects["count"] == 0
    for argv in (
        ["--unknown"],
        ["--worker", "bad", "a", "b", "c", "n"],
        ["--worker", "term-to-kill", "a", "b", "c"],
        ["--worker", "term-to-kill", "-a", "b", "c", "n"],
        ["--worker", "term-to-kill", "a", "--b", "c", "n"],
        ["--worker", "term-to-kill", "a", "b", "c", "-n"],
    ):
        try:
            parse_cli(argv)
        except SystemExit:
            pass
        else:
            raise AssertionError("malformed CLI accepted")
        assert side_effects["count"] == 0


def extract_source():
    raw = LAUNCHER.read_text()
    py = raw.split("<<'PY'\n", 1)[1].split("\ntry:\n    final_status=main()", 1)[0]
    tree = ast.parse(py)
    chosen = [
        node for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef))
        and (not isinstance(node, ast.FunctionDef) or node.name != "main")
    ]
    source = ast.unparse(ast.Module(body=chosen, type_ignores=[])) + "\n"
    namespace = {"__name__": "extracted_supervisor"}
    exec(compile(ast.Module(body=chosen, type_ignores=[]), str(LAUNCHER), "exec"), namespace)
    locations = [f"{node.__class__.__name__}:{getattr(node, 'name', '')}" for node in chosen]
    return source, namespace, locations, hashlib.sha256(source.encode()).hexdigest()


def synthetic(kind, gate_path, nonce, worker_pid, ready_path=None):
    behavior = {
        "sleep": "time.sleep(.35)",
        "exit0": "raise SystemExit(0)",
        "term_ignore_ready": (
            "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            "pathlib.Path(sys.argv[3]).write_text('READY\\n')\n"
            "time.sleep(10)"
        ),
    }[kind]
    code = (
        "import ctypes,os,pathlib,signal,sys,time\n"
        "if ctypes.CDLL(None).prctl(1,signal.SIGKILL) != 0: raise SystemExit(91)\n"
        "if os.getppid() != int(sys.argv[4]): raise SystemExit(92)\n"
        "gate=pathlib.Path(sys.argv[1]); nonce=sys.argv[2]\n"
        "while True:\n"
        "    try:\n"
        "        if gate.read_text().strip()==nonce: break\n"
        "    except (FileNotFoundError,OSError): pass\n"
        "    time.sleep(.01)\n"
        + behavior + "\n"
    )
    return [
        sys.executable, "-c", "exec(" + repr(code) + ")",
        str(gate_path), nonce, str(ready_path or ""), str(worker_pid),
    ]


def append_json(path, item):
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(item, sort_keys=True) + "\n")
        stream.flush()


def worker(case, ownership_path, result_path, auth_path, nonce):
    while auth_path.read_text(encoding="utf-8").strip() != nonce:
        time.sleep(0.01)
    _, ns, _, _ = extract_source()
    trace = []
    stdout = tempfile.TemporaryFile()
    stderr = tempfile.TemporaryFile()
    originals = {}
    helper = None
    checkpoint = threading.Event()
    acknowledgement = threading.Event()
    ready_path = Path(str(result_path) + ".ready")
    child_gate = Path(str(result_path) + ".child-gate")
    containment = {
        "nonce": nonce,
        "worker_pid": os.getpid(),
        "controller_mechanism": "Linux prctl(PR_SET_PDEATHSIG, SIGKILL) with child PPID check",
        "records": [],
    }

    original_popen = ns["subprocess"].Popen
    def recording_popen(*args, **kwargs):
        child = original_popen(*args, **kwargs)
        record = {"pgid": None}
        try:
            record = {
                "kind": "supervisor-child", "nonce": nonce, "pid": child.pid,
                "pgid": os.getpgid(child.pid), "session_id": os.getsid(child.pid),
                "start_new_session": kwargs.get("start_new_session", False),
                "worker_pid": os.getpid(), "case": case, "child_gate": str(child_gate),
            }
            if not child_owned(record, nonce, case, os.getpid()):
                raise RuntimeError("supervisor-child ownership validation failed")
            containment["records"].append(record)
            append_json(ownership_path, record)
            child_gate.write_text(nonce + "\n", encoding="utf-8")
            if case == "term-to-kill":
                deadline = time.monotonic() + 2
                while not ready_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not ready_path.exists():
                    raise RuntimeError("TERM handler readiness was not proven")
        except BaseException:
            if isinstance(record.get("pgid"), int):
                try:
                    os.killpg(record["pgid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                child.kill()
            try:
                child.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
            raise
        return child

    ns["subprocess"].Popen = recording_popen
    if case == "cleanup-denial":
        originals["signal_group"] = ns["signal_group"]
        def denied_signal_group(pgid, sig, trace_arg, phase):
            outcome = "denied"
            ns["trace_event"](trace_arg, "injected-group-signal", phase=phase,
                              signal=int(sig), outcome=outcome)
            return outcome
        ns["signal_group"] = denied_signal_group
    elif case == "probe-exception":
        originals["group_state"] = ns["group_state"]
        def injected_probe(*args, **kwargs):
            raise RuntimeError("injected-probe")
        ns["group_state"] = injected_probe
    elif case == "drain-exception":
        originals["sigpending"] = ns["signal"].sigpending
        ns["signal"].sigpending = lambda: (_ for _ in ()).throw(RuntimeError("injected-drain"))
    elif case.startswith("cleanup-signal-"):
        originals["signal_group"] = ns["signal_group"]
        requested = {
            "cleanup-signal-SIGINT": signal.SIGINT,
            "cleanup-signal-SIGTERM": signal.SIGTERM,
            "cleanup-signal-SIGHUP": signal.SIGHUP,
        }[case]
        def synchronized_signal_group(*args):
            pgid, sig, trace_arg, phase = args
            if phase == "term" and not checkpoint.is_set():
                ns["trace_event"](trace_arg, "test-cleanup-checkpoint",
                                  phase="term", signal=int(requested))
                checkpoint.set()
                def deliver():
                    if checkpoint.wait(1):
                        os.kill(os.getpid(), requested)
                        ns["trace_event"](trace_arg, "test-cleanup-signal-sent",
                                          phase="term", signal=int(requested))
                        acknowledgement.set()
                nonlocal helper
                helper = threading.Thread(target=deliver, daemon=True)
                helper.start()
                if not acknowledgement.wait(1):
                    raise RuntimeError("cleanup signal acknowledgement timeout")
            return originals["signal_group"](*args)
        ns["signal_group"] = synchronized_signal_group

    try:
        kind = CASE_TO_SYNTHETIC[case]
        status, reason = ns["bounded"](
            synthetic(kind, child_gate, nonce, os.getpid(), ready_path),
            CHILD_WAIT_SECONDS,
            stdout,
            stderr,
            trace,
        )
        result = {"status": status, "reason": reason, "trace": trace}
    except BaseException as exc:
        result = {"worker_exception": type(exc).__name__, "message": str(exc), "trace": trace}
    finally:
        ns["subprocess"].Popen = original_popen
        for name, value in originals.items():
            if name == "sigpending":
                ns["signal"].sigpending = value
            else:
                ns[name] = value
        if helper:
            helper.join(timeout=1)
        stdout.close()
        stderr.close()
    result["containment"] = containment
    Path(result_path).write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")


def process_owned(record, nonce, case):
    return (
        record.get("nonce") == nonce and record.get("case") == case
        and isinstance(record.get("pid"), int) and record.get("pid") > 0
        and record.get("pgid") == record.get("pid")
        and record.get("session_id") == record.get("pid")
        and record.get("start_new_session") is True
    )


def child_owned(record, nonce, case, worker_pid):
    return (
        record.get("kind") == "supervisor-child"
        and record.get("worker_pid") == worker_pid
        and process_owned(record, nonce, case)
    )


def group_present(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def wait_group_absent(pgid, deadline):
    while group_present(pgid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


def parent_watchdog_cleanup(proc, worker_record, records, nonce, case,
                            watchdog, ownership_path, result_path,
                            malformed_records=None, live_handles=None,
                            group_present_fn=None, wait_group_absent_fn=None,
                            signal_fn=None, monotonic_fn=None):
    """The single parent-watchdog path used by lifecycle and focused tests."""
    group_present_fn = group_present_fn or group_present
    wait_group_absent_fn = wait_group_absent_fn or wait_group_absent
    monotonic_fn = monotonic_fn or time.monotonic
    cleanup_start = monotonic_fn()
    cleanup_deadline = cleanup_start + WATCHDOG_CLEANUP_SECONDS
    malformed_records = list(malformed_records or [])
    valid = [record for record in records
             if child_owned(record, nonce, case, proc.pid)]
    worker_owned = process_owned(worker_record, nonce, case)
    containment_ok = worker_owned and len(valid) == 1
    residual = [record for record in valid if group_present_fn(record["pgid"])]
    if residual and watchdog == "exited":
        watchdog = "residual-process"
    actions = []
    cleanup_errors = []
    if live_handles is not None:
        live_by_pid = {
            getattr(item, "record", {}).get("pid"): item
            for item in live_handles
        }
        for record in valid + [worker_record]:
            handle = live_by_pid.get(record.get("pid"))
            if (handle is None or getattr(handle, "pidfd", None) is None
                    or getattr(handle, "record", {}).get("pid") != record.get("pid")):
                cleanup_errors.append(
                    f"missing-live-handle:{record.get('pid')}")
    if watchdog != "exited" or not containment_ok:
        watchdog = watchdog if watchdog != "exited" else "containment-unproven"
        for record in valid:
            if group_present_fn(record["pgid"]):
                try:
                    if live_handles is not None:
                        handle = next((item for item in live_handles
                                       if item.record.get("pid") == record["pid"]), None)
                        if (handle is None or handle.pidfd is None
                                or handle.record.get("pid") != record["pid"]):
                            raise RuntimeError("live child handle missing or mismatched")
                        outcome = signal_fn(handle, signal.SIGKILL) if signal_fn else signal.pidfd_send_signal(handle.pidfd, signal.SIGKILL)
                    else:
                        outcome = signal_fn(record, signal.SIGKILL) if signal_fn else os.killpg(record["pgid"], signal.SIGKILL)
                    actions.append({"target": "child", "pgid": record["pgid"],
                                    "signal": int(signal.SIGKILL), "outcome": "sent"})
                except ProcessLookupError:
                    actions.append({"target": "child", "pgid": record["pgid"],
                                    "signal": int(signal.SIGKILL), "outcome": "absent"})
                except BaseException as error:
                    cleanup_errors.append(f"child-signal:{type(error).__name__}:{error}")
        if worker_owned and group_present_fn(worker_record["pgid"]):
            try:
                if live_handles is not None:
                    handle = next((item for item in live_handles
                                   if item.record.get("pid") == worker_record["pid"]), None)
                    if (handle is None or handle.pidfd is None
                            or handle.record.get("pid") != worker_record["pid"]):
                        raise RuntimeError("live worker handle missing or mismatched")
                    outcome = signal_fn(handle, signal.SIGKILL) if signal_fn else signal.pidfd_send_signal(handle.pidfd, signal.SIGKILL)
                else:
                    outcome = signal_fn(worker_record, signal.SIGKILL) if signal_fn else os.killpg(worker_record["pgid"], signal.SIGKILL)
                actions.append({"target": "worker", "pgid": worker_record["pgid"],
                                "signal": int(signal.SIGKILL), "outcome": "sent"})
            except ProcessLookupError:
                actions.append({"target": "worker", "pgid": worker_record["pgid"],
                                "signal": int(signal.SIGKILL), "outcome": "absent"})
            except BaseException as error:
                cleanup_errors.append(f"worker-signal:{type(error).__name__}:{error}")
        try:
                proc.wait(timeout=max(0, cleanup_deadline - monotonic_fn()))
        except subprocess.TimeoutExpired:
            watchdog = "worker-cleanup-timeout"
    remaining_owned_groups = [
        record for record in valid
        if not wait_group_absent_fn(record["pgid"], cleanup_deadline)
    ]
    worker_group_absent = (
        wait_group_absent_fn(worker_record["pgid"], cleanup_deadline)
        if worker_owned else False
    )
    cleanup_complete = monotonic_fn()
    cleanup_state = ("PROVEN" if worker_owned and len(valid) == 1
                     and worker_group_absent and not malformed_records
                     and not remaining_owned_groups
                     and not cleanup_errors and proc.poll() is not None
                     and cleanup_complete <= cleanup_deadline else "UNKNOWN")
    return {
        "watchdog": watchdog, "containment_ok": worker_owned and len(valid) == 1
        and not malformed_records, "worker_reaped": proc.poll() is not None,
        "residual_owned_groups": residual,
        "remaining_owned_groups": remaining_owned_groups,
         "worker_group_absent": worker_group_absent,
         "child_groups_absent": not remaining_owned_groups,
        "malformed_ownership_records": malformed_records, "valid_records": valid,
        "cleanup_actions": actions, "cleanup_errors": cleanup_errors,
        "cleanup_start_monotonic": cleanup_start,
        "cleanup_deadline_monotonic": cleanup_deadline,
        "cleanup_complete_monotonic": cleanup_complete,
        "cleanup_elapsed_seconds": cleanup_complete - cleanup_start,
        "cleanup_deadline_started": True,
        "cleanup_state": cleanup_state,
    }


def run_case(case):
    nonce = uuid.uuid4().hex
    ownership_path = MISSING_EVIDENCE / f"{case}.{nonce}.ownership.jsonl"
    result_path = MISSING_EVIDENCE / f"{case}.{nonce}.result.json"
    auth_path = MISSING_EVIDENCE / f"{case}.{nonce}.worker-authorized"
    ownership_path.touch(exist_ok=False)
    result_path.touch(exist_ok=False)
    auth_path.touch(exist_ok=False)
    cmd = [sys.executable, str(Path(__file__).resolve()), "--worker", case,
           str(ownership_path), str(result_path), str(auth_path), nonce]
    proc = subprocess.Popen(cmd, start_new_session=True)
    worker_record = {
        "kind": "worker", "nonce": nonce, "pid": proc.pid,
        "pgid": None, "session_id": None, "start_new_session": True,
        "worker_pid": os.getpid(), "case": case,
    }
    worker_authorized = False
    setup_error = None
    try:
        worker_record["pgid"] = os.getpgid(proc.pid)
        worker_record["session_id"] = os.getsid(proc.pid)
        worker_authorized = process_owned(worker_record, nonce, case)
        if not worker_authorized:
            raise RuntimeError("worker ownership validation failed")
        append_json(ownership_path, worker_record)
        auth_path.write_text(nonce + "\n", encoding="utf-8")
    except BaseException as error:
        setup_error = {"type": type(error).__name__, "message": str(error)}
        try:
            if worker_authorized and group_present(worker_record["pgid"]):
                os.killpg(worker_record["pgid"], signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
        except subprocess.TimeoutExpired:
            setup_error["cleanup"] = "worker-reap-timeout"
        return {
            "case": case,
            "nonce": nonce,
            "spawned": True,
            "worker_authorized": worker_authorized,
            "containment_ok": False,
            "watchdog": "worker-setup-failed",
            "setup_error": setup_error,
            "assertion_failures": ["worker setup/authorization failed"],
        }
    watchdog = "exited"
    try:
        proc.wait(timeout=CASE_EXECUTION_SECONDS)
    except subprocess.TimeoutExpired:
        watchdog = "watchdog-timeout"
    records = []
    malformed_records = []
    for line in ownership_path.read_text().splitlines():
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            malformed_records.append(line)
    cleanup = parent_watchdog_cleanup(
        proc, worker_record, records, nonce, case, watchdog,
        ownership_path, result_path, malformed_records,
    )
    watchdog = cleanup["watchdog"]
    valid = cleanup["valid_records"]
    remaining_owned_groups = cleanup["remaining_owned_groups"]
    containment_ok = worker_authorized and cleanup["containment_ok"]
    worker_reaped = cleanup["worker_reaped"]
    result = json.loads(result_path.read_text()) if result_path.stat().st_size else {}
    observed = {"case": case, "nonce": nonce, "watchdog": watchdog,
                "execution_state": "EXECUTED",
                "ownership_path": str(ownership_path.relative_to(ROOT)),
                "result_path": str(result_path.relative_to(ROOT)),
                "ownership_records": records, "containment_ok": containment_ok,
                "worker_reaped": worker_reaped,
                 "residual_owned_groups": cleanup["residual_owned_groups"],
                "remaining_owned_groups": remaining_owned_groups,
                 "worker_group_absent": cleanup["worker_group_absent"],
                 "child_groups_absent": cleanup["child_groups_absent"],
                 "cleanup_state": cleanup["cleanup_state"],
                 "cleanup_errors": cleanup["cleanup_errors"],
                 "cleanup_start_monotonic": cleanup["cleanup_start_monotonic"],
                 "cleanup_deadline_monotonic": cleanup["cleanup_deadline_monotonic"],
                 "cleanup_complete_monotonic": cleanup["cleanup_complete_monotonic"],
                 "cleanup_elapsed_seconds": cleanup["cleanup_elapsed_seconds"],
                 "cleanup_deadline_started": cleanup["cleanup_deadline_started"],
                "malformed_ownership_records": malformed_records,
                 "cleanup_actions": cleanup["cleanup_actions"],
                "result": result}
    expected = {
        "term-to-kill": (124, "timeout-clean", ("group-signal", "cleanup-result")),
        "cleanup-denial": (125, "timeout-cleanup-unproven", ("injected-group-signal",)),
        "probe-exception": (70, "post-wait-probe-exception-clean", ("post-wait-probe-exception",)),
        "drain-exception": (125, "pending-signal-drain-cleanup-unproven", ("pending-signal-drain-exception",)),
        "cleanup-signal-SIGINT": (130, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
        "cleanup-signal-SIGTERM": (143, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
        "cleanup-signal-SIGHUP": (129, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
    }[case]
    events = result.get("trace", [])
    names = {event.get("event") for event in events}
    observed["expected"] = {"status": expected[0], "reason": expected[1], "events": expected[2]}
    observed["assertion_failures"] = []
    if result.get("status") != expected[0] or result.get("reason") != expected[1]:
        observed["assertion_failures"].append("status/reason mismatch")
    if any(event not in names for event in expected[2]):
        observed["assertion_failures"].append("required trace event missing")
    if case.startswith("cleanup-signal-"):
        requested = {
            "cleanup-signal-SIGINT": int(signal.SIGINT),
            "cleanup-signal-SIGTERM": int(signal.SIGTERM),
            "cleanup-signal-SIGHUP": int(signal.SIGHUP),
        }[case]
        checkpoint_events = [
            e for e in events
            if e.get("event") == "test-cleanup-checkpoint"
            and e.get("phase") == "term" and e.get("signal") == requested
        ]
        sent_events = [
            e for e in events
            if e.get("event") == "test-cleanup-signal-sent"
            and e.get("phase") == "term" and e.get("signal") == requested
        ]
        delivery_events = [
            e for e in events
            if e.get("event") == "signal-delivery"
            and e.get("signal") == requested
            and e.get("stage") == "cleanup-pending-drain"
        ]
        if not (checkpoint_events and sent_events and delivery_events):
            observed["assertion_failures"].append(
                "exact cleanup signal checkpoint/sent/pending-drain proof missing"
            )
        else:
            positions = [
                next(i for i, e in enumerate(events) if e is item)
                for item in (checkpoint_events[0], sent_events[0], delivery_events[0])
            ]
            if not (positions[0] < positions[1] < positions[2]):
                observed["assertion_failures"].append(
                    "cleanup signal trace order checkpoint<sent<delivery failed"
                )
    if case == "term-to-kill":
        signals = {(e.get("phase"), e.get("signal"), e.get("outcome")) for e in events if e.get("event") == "group-signal"}
        if ("term", int(signal.SIGTERM), "sent") not in signals:
            observed["assertion_failures"].append("actual TERM sent not observed")
        if ("kill", int(signal.SIGKILL), "sent") not in signals:
            observed["assertion_failures"].append("actual KILL sent not observed")
        if not any(e.get("event") == "cleanup-result" and e.get("reason") == "kill-clean" for e in events):
            observed["assertion_failures"].append("kill-clean not observed")
    if case == "cleanup-denial":
        denials = {
            (event.get("phase"), event.get("signal"), event.get("outcome"))
            for event in events
            if event.get("event") == "injected-group-signal"
        }
        if ("term", int(signal.SIGTERM), "denied") not in denials:
            observed["assertion_failures"].append(
                "injected TERM denial not observed"
            )
        if ("kill", int(signal.SIGKILL), "denied") not in denials:
            observed["assertion_failures"].append(
                "injected KILL denial not observed"
            )
    if not worker_authorized:
        observed["assertion_failures"].append("worker authorization handshake failed")
    if len(valid) != 1:
        observed["assertion_failures"].append("expected exactly one valid supervisor-child record")
    if malformed_records:
        observed["assertion_failures"].append("malformed ownership record")
    if not containment_ok:
        observed["assertion_failures"].append("containment unproven")
    if watchdog != "exited":
        observed["assertion_failures"].append("watchdog did not observe clean exit")
    if remaining_owned_groups:
        observed["assertion_failures"].append("owned supervisor group remained present")
    return observed


def containment_blocker(result):
    if not isinstance(result, dict):
        return "case result is not an object"
    if result.get("containment_ok") is not True:
        return "containment_ok is not proven true"
    if result.get("worker_reaped") is not True:
        return "worker reaping is not proven"
    if result.get("cleanup_state") != "PROVEN":
        return "cleanup state is missing or not proven"
    if result.get("worker_group_absent") is not True:
        return "worker group absence is not proven"
    if result.get("child_groups_absent") is not True:
        return "child group absence is not proven"
    if not isinstance(result.get("cleanup_errors"), list):
        return "cleanup errors are missing or malformed"
    if result["cleanup_errors"]:
        return "cleanup errors are present"
    if result.get("cleanup_deadline_started") is not True:
        return "cleanup deadline evidence is missing"
    timing = [
        result.get("cleanup_start_monotonic"),
        result.get("cleanup_deadline_monotonic"),
        result.get("cleanup_complete_monotonic"),
        result.get("cleanup_elapsed_seconds"),
    ]
    if any(isinstance(value, bool) or not isinstance(value, (int, float))
           or not math.isfinite(value) for value in timing):
        return "cleanup timing evidence is missing or malformed"
    start, deadline, complete, elapsed = timing
    if not (start <= complete <= deadline and elapsed >= 0):
        return "cleanup timing is contradictory"
    tolerance = 1e-6
    if abs(elapsed - (complete - start)) > tolerance:
        return "cleanup elapsed time is inconsistent"
    if abs((deadline - start) - WATCHDOG_CLEANUP_SECONDS) > tolerance:
        return "cleanup deadline budget is inconsistent"
    for field in (
        "remaining_owned_groups",
        "malformed_ownership_records",
        "assertion_failures",
    ):
        if not isinstance(result.get(field), list):
            return f"{field} is missing or malformed"
    if result["remaining_owned_groups"]:
        return "owned supervisor groups remain present"
    if result["malformed_ownership_records"]:
        return "ownership evidence is malformed"
    for failure in result["assertion_failures"]:
        if not isinstance(failure, str):
            return "assertion failure evidence is malformed"
        if any(marker in failure for marker in CONTAINMENT_ASSERTION_MARKERS):
            return f"containment assertion failed: {failure}"
    if result.get("watchdog") == "worker-cleanup-timeout":
        return "watchdog could not reap the worker"
    return None


def schedule_cases(case_runner=run_case, cases=MISSING_CASES):
    results = []
    for index, case in enumerate(cases):
        try:
            result = case_runner(case)
        except BaseException as error:
            result = {
                "case": case,
                "execution_state": "EXECUTION_ERROR",
                "containment_ok": False,
                "worker_reaped": False,
                "remaining_owned_groups": [],
                "malformed_ownership_records": [],
                "assertion_failures": ["unexpected case exception"],
                "exception_type": type(error).__name__,
                "exception_message": str(error),
            }
        results.append(result)
        blocker = containment_blocker(result)
        if blocker is None:
            continue
        for remaining in cases[index + 1:]:
            results.append({
                "case": remaining,
                "execution_state": "NOT_EXECUTED",
                "blocked_by": case,
                "blocking_reason": blocker,
                "containment_ok": False,
                "assertion_failures": ["not executed after containment stop"],
            })
        break
    return results


def scheduler_self_test():
    base = {
        "execution_state": "EXECUTED",
        "containment_ok": True,
        "worker_reaped": True,
        "remaining_owned_groups": [],
        "malformed_ownership_records": [],
        "assertion_failures": [],
        "watchdog": "exited",
        "cleanup_state": "PROVEN",
        "cleanup_errors": [],
        "cleanup_deadline_started": True,
        "cleanup_start_monotonic": 10.0,
        "cleanup_deadline_monotonic": 13.0,
        "cleanup_complete_monotonic": 12.0,
        "cleanup_elapsed_seconds": 2.0,
        "worker_group_absent": True,
        "child_groups_absent": True,
    }
    scenarios = {
        "proven-permits-next": (
            lambda case: dict(base, case=case),
            2,
            ["EXECUTED", "EXECUTED"],
        ),
        "false-stops": (
            lambda case: dict(base, case=case, containment_ok=False),
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-stops": (
            lambda case: {
                key: value for key, value in dict(base, case=case).items()
                if key != "containment_ok"
            },
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "contradiction-stops": (
            lambda case: dict(
                base,
                case=case,
                remaining_owned_groups=[{"pgid": 999999}],
            ),
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-state": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_state"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "unknown-cleanup-state": (
            lambda case: dict(base, case=case, cleanup_state="UNKNOWN"),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-worker-absence": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "worker_group_absent"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-child-absence": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "child_groups_absent"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "cleanup-error-stops": (
            lambda case: dict(base, case=case, cleanup_errors=["injected"]),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-errors": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_errors"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "malformed-cleanup-errors": (
            lambda case: dict(base, case=case, cleanup_errors="bad"),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-timing": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_complete_monotonic"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "completion-after-deadline": (
            lambda case: dict(base, case=case, cleanup_complete_monotonic=14.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "negative-elapsed": (
            lambda case: dict(base, case=case, cleanup_elapsed_seconds=-1.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "inconsistent-elapsed": (
            lambda case: dict(base, case=case, cleanup_elapsed_seconds=1.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "wrong-cleanup-budget": (
            lambda case: dict(base, case=case, cleanup_deadline_monotonic=14.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
    }
    outcomes = {}
    cases = ("first", "second")
    for name, (runner, expected_count, expected_states) in scenarios.items():
        results = schedule_cases(runner, cases)
        states = [item.get("execution_state") for item in results]
        passed = len(results) == expected_count and states == expected_states
        outcomes[name] = {"passed": passed, "states": states}
    calls = []
    def raising_runner(case):
        calls.append(case)
        raise RuntimeError("fabricated scheduler exception")
    exception_results = schedule_cases(raising_runner, cases)
    exception_states = [
        item.get("execution_state") for item in exception_results
    ]
    outcomes["exception-stops"] = {
        "passed": calls == ["first"]
        and exception_states == ["EXECUTION_ERROR", "NOT_EXECUTED"],
        "states": exception_states,
    }
    print(json.dumps(outcomes, indent=2, sort_keys=True))
    if not all(item["passed"] for item in outcomes.values()):
        raise SystemExit("scheduler self-test failed")
    cli_parser_self_test()
    assert source_stability({"a": "1"}, {"a": "1"}) == "PROVEN"
    assert source_stability({"a": "1"}, {"a": "2"}) == "FAILED"


def main():
    pre = {"launcher": digest(LAUNCHER), "proposal": digest(PROPOSAL)}
    if pre != {"launcher": EXPECTED_LAUNCHER, "proposal": EXPECTED_PROPOSAL}:
        raise SystemExit("hash precondition failed")
    harness_paths = {
        "run_validation": Path(__file__).resolve(),
        "run_containment": Path(__file__).resolve().with_name("run_containment.py"),
    }
    source_pre = {name: digest(path) for name, path in harness_paths.items()}
    source, constants, locations, extraction_hash = extract_source()
    if (
        constants["TERM_WAIT_SECONDS"] != TERM_GRACE_SECONDS
        or constants["KILL_WAIT_SECONDS"] != KILL_GRACE_SECONDS
    ):
        raise SystemExit("extracted cleanup grace mismatch")
    MISSING_EVIDENCE.mkdir(parents=True, exist_ok=False)
    (MISSING_EVIDENCE / "extracted_supervisor_source.py").write_text(source, encoding="utf-8")
    results = schedule_cases()
    post = {"launcher": digest(LAUNCHER), "proposal": digest(PROPOSAL)}
    source_post = {name: digest(path) for name, path in harness_paths.items()}
    raw = {"batch": "missing_cases_only", "pre_hashes": pre, "post_hashes": post,
           "source_extraction_sha256": extraction_hash, "source_locations": locations,
           "harness_source_pre_hashes": source_pre,
           "harness_source_post_hashes": source_post,
           "harness_source_stability": (
               source_stability(source_pre, source_post)
           ),
           "harness_source_stability_limit": (
               "Pre/post hashes do not prove absence of transient changes during execution."
           ),
            "case_execution_seconds": CASE_EXECUTION_SECONDS,
            "watchdog_cleanup_seconds": WATCHDOG_CLEANUP_SECONDS,
            "child_wait_seconds": CHILD_WAIT_SECONDS,
             "term_grace_seconds": TERM_GRACE_SECONDS, "kill_grace_seconds": KILL_GRACE_SECONDS,
           "case_to_synthetic": CASE_TO_SYNTHETIC, "cases": results,
             "instrumentation": "External namespace Popen recording/readiness wrapper, Linux PR_SET_PDEATHSIG child lifetime guard, and named monkeypatches only; child controller configuration is recorded, not runtime-proven.",
           "assertions_failed": [r for r in results if r["assertion_failures"]]}
    (MISSING_EVIDENCE / "raw.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    failures = raw["assertions_failed"]
    if raw["harness_source_stability"] != "PROVEN":
        raise SystemExit("harness source stability failed after evidence write")
    if failures:
        raise SystemExit(f"validation assertions failed after evidence write: {len(failures)}")


if __name__ == "__main__":
    cli = parse_cli(sys.argv[1:])
    if cli["mode"] == "help":
        print_help()
    elif cli["mode"] == "worker":
        worker(cli["case"], *(Path(path) for path in cli["paths"]), cli["nonce"])
    elif cli["mode"] == "scheduler-self-test":
        scheduler_self_test()
    else:
        main()
#!/usr/bin/env python3
"""Preparation-only harness for the seven not-yet-executed supervisor cases."""
import ast
import ctypes
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "attached_assets/usbay-fda-readonly-diskutil-diagnostic.zsh"
PROPOSAL = ROOT / "attached_assets/usbay-temporary-terminal-full-disk-access-diagnostic-proposal.md"
EVIDENCE = Path(__file__).resolve().parent / "evidence"
MISSING_EVIDENCE = EVIDENCE / "missing_cases_batch"
EXPECTED_LAUNCHER = "b19bd48a797b3f5659c6fb850d4baff1792c6c73153bfec13b4eb6f5976f320b"
EXPECTED_PROPOSAL = "ef648fadc31e252ce91ff6ee754b0670e6f477b5afd8a5e4a5bc3cdcb675429c"
CHILD_WAIT_SECONDS = 0.08
TERM_GRACE_SECONDS = 2
KILL_GRACE_SECONDS = 2
WATCHDOG_CLEANUP_SECONDS = 3
CASE_EXECUTION_SECONDS = 12
MISSING_CASES = (
    "term-to-kill", "cleanup-denial", "probe-exception", "drain-exception",
    "cleanup-signal-SIGINT", "cleanup-signal-SIGTERM", "cleanup-signal-SIGHUP",
)
CASE_TO_SYNTHETIC = {
    "term-to-kill": "term_ignore_ready",
    "cleanup-denial": "sleep",
    "probe-exception": "exit0",
    "drain-exception": "exit0",
    "cleanup-signal-SIGINT": "sleep",
    "cleanup-signal-SIGTERM": "sleep",
    "cleanup-signal-SIGHUP": "sleep",
}
CONTAINMENT_ASSERTION_MARKERS = (
    "worker authorization",
    "supervisor-child record",
    "malformed ownership",
    "containment unproven",
    "watchdog did not observe clean exit",
    "owned supervisor group remained",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_stability(pre, post):
    """Assess only equality of the recorded pre/post source hashes."""
    return "PROVEN" if dict(pre) == dict(post) else "FAILED"


def parse_cli(argv):
    """Validate dispatch without touching evidence, channels, or processes."""
    args = list(argv)
    if args in (["--help"], ["-h"]):
        return {"mode": "help"}
    if args == ["--scheduler-self-test"]:
        return {"mode": "scheduler-self-test"}
    if args == []:
        return {"mode": "main"}
    if len(args) == 6 and args[0] == "--worker":
        case, ownership, result, auth, nonce = args[1:]
        if case not in MISSING_CASES or not nonce or nonce.startswith("-"):
            raise SystemExit("invalid worker case or nonce")
        paths = (ownership, result, auth)
        if any(not item or item.startswith("-") for item in paths):
            raise SystemExit("invalid worker paths")
        return {"mode": "worker", "case": case, "paths": paths, "nonce": nonce}
    raise SystemExit("unknown or malformed arguments")


def print_help():
    print("usage: run_validation.py [--scheduler-self-test|--worker CASE OWNERSHIP RESULT AUTH NONCE]")


def cli_parser_self_test():
    """Pure parser/dispatch checks; no evidence, channels, or processes."""
    side_effects = {"count": 0}
    for argv, expected in (
        (["--help"], "help"),
        (["--scheduler-self-test"], "scheduler-self-test"),
    ):
        parsed = parse_cli(argv)
        assert parsed["mode"] == expected
        assert side_effects["count"] == 0
    for argv in (
        ["--unknown"],
        ["--worker", "bad", "a", "b", "c", "n"],
        ["--worker", "term-to-kill", "a", "b", "c"],
        ["--worker", "term-to-kill", "-a", "b", "c", "n"],
        ["--worker", "term-to-kill", "a", "--b", "c", "n"],
        ["--worker", "term-to-kill", "a", "b", "c", "-n"],
    ):
        try:
            parse_cli(argv)
        except SystemExit:
            pass
        else:
            raise AssertionError("malformed CLI accepted")
        assert side_effects["count"] == 0


def extract_source():
    raw = LAUNCHER.read_text()
    py = raw.split("<<'PY'\n", 1)[1].split("\ntry:\n    final_status=main()", 1)[0]
    tree = ast.parse(py)
    chosen = [
        node for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef))
        and (not isinstance(node, ast.FunctionDef) or node.name != "main")
    ]
    source = ast.unparse(ast.Module(body=chosen, type_ignores=[])) + "\n"
    namespace = {"__name__": "extracted_supervisor"}
    exec(compile(ast.Module(body=chosen, type_ignores=[]), str(LAUNCHER), "exec"), namespace)
    locations = [f"{node.__class__.__name__}:{getattr(node, 'name', '')}" for node in chosen]
    return source, namespace, locations, hashlib.sha256(source.encode()).hexdigest()


def synthetic(kind, gate_path, nonce, worker_pid, ready_path=None):
    behavior = {
        "sleep": "time.sleep(.35)",
        "exit0": "raise SystemExit(0)",
        "term_ignore_ready": (
            "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            "pathlib.Path(sys.argv[3]).write_text('READY\\n')\n"
            "time.sleep(10)"
        ),
    }[kind]
    code = (
        "import ctypes,os,pathlib,signal,sys,time\n"
        "if ctypes.CDLL(None).prctl(1,signal.SIGKILL) != 0: raise SystemExit(91)\n"
        "if os.getppid() != int(sys.argv[4]): raise SystemExit(92)\n"
        "gate=pathlib.Path(sys.argv[1]); nonce=sys.argv[2]\n"
        "while True:\n"
        "    try:\n"
        "        if gate.read_text().strip()==nonce: break\n"
        "    except (FileNotFoundError,OSError): pass\n"
        "    time.sleep(.01)\n"
        + behavior + "\n"
    )
    return [
        sys.executable, "-c", "exec(" + repr(code) + ")",
        str(gate_path), nonce, str(ready_path or ""), str(worker_pid),
    ]


def append_json(path, item):
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(item, sort_keys=True) + "\n")
        stream.flush()


def worker(case, ownership_path, result_path, auth_path, nonce):
    while auth_path.read_text(encoding="utf-8").strip() != nonce:
        time.sleep(0.01)
    _, ns, _, _ = extract_source()
    trace = []
    stdout = tempfile.TemporaryFile()
    stderr = tempfile.TemporaryFile()
    originals = {}
    helper = None
    checkpoint = threading.Event()
    acknowledgement = threading.Event()
    ready_path = Path(str(result_path) + ".ready")
    child_gate = Path(str(result_path) + ".child-gate")
    containment = {
        "nonce": nonce,
        "worker_pid": os.getpid(),
        "controller_mechanism": "Linux prctl(PR_SET_PDEATHSIG, SIGKILL) with child PPID check",
        "records": [],
    }

    original_popen = ns["subprocess"].Popen
    def recording_popen(*args, **kwargs):
        child = original_popen(*args, **kwargs)
        record = {"pgid": None}
        try:
            record = {
                "kind": "supervisor-child", "nonce": nonce, "pid": child.pid,
                "pgid": os.getpgid(child.pid), "session_id": os.getsid(child.pid),
                "start_new_session": kwargs.get("start_new_session", False),
                "worker_pid": os.getpid(), "case": case, "child_gate": str(child_gate),
            }
            if not child_owned(record, nonce, case, os.getpid()):
                raise RuntimeError("supervisor-child ownership validation failed")
            containment["records"].append(record)
            append_json(ownership_path, record)
            child_gate.write_text(nonce + "\n", encoding="utf-8")
            if case == "term-to-kill":
                deadline = time.monotonic() + 2
                while not ready_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not ready_path.exists():
                    raise RuntimeError("TERM handler readiness was not proven")
        except BaseException:
            if isinstance(record.get("pgid"), int):
                try:
                    os.killpg(record["pgid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                child.kill()
            try:
                child.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
            raise
        return child

    ns["subprocess"].Popen = recording_popen
    if case == "cleanup-denial":
        originals["signal_group"] = ns["signal_group"]
        def denied_signal_group(pgid, sig, trace_arg, phase):
            outcome = "denied"
            ns["trace_event"](trace_arg, "injected-group-signal", phase=phase,
                              signal=int(sig), outcome=outcome)
            return outcome
        ns["signal_group"] = denied_signal_group
    elif case == "probe-exception":
        originals["group_state"] = ns["group_state"]
        def injected_probe(*args, **kwargs):
            raise RuntimeError("injected-probe")
        ns["group_state"] = injected_probe
    elif case == "drain-exception":
        originals["sigpending"] = ns["signal"].sigpending
        ns["signal"].sigpending = lambda: (_ for _ in ()).throw(RuntimeError("injected-drain"))
    elif case.startswith("cleanup-signal-"):
        originals["signal_group"] = ns["signal_group"]
        requested = {
            "cleanup-signal-SIGINT": signal.SIGINT,
            "cleanup-signal-SIGTERM": signal.SIGTERM,
            "cleanup-signal-SIGHUP": signal.SIGHUP,
        }[case]
        def synchronized_signal_group(*args):
            pgid, sig, trace_arg, phase = args
            if phase == "term" and not checkpoint.is_set():
                ns["trace_event"](trace_arg, "test-cleanup-checkpoint",
                                  phase="term", signal=int(requested))
                checkpoint.set()
                def deliver():
                    if checkpoint.wait(1):
                        os.kill(os.getpid(), requested)
                        ns["trace_event"](trace_arg, "test-cleanup-signal-sent",
                                          phase="term", signal=int(requested))
                        acknowledgement.set()
                nonlocal helper
                helper = threading.Thread(target=deliver, daemon=True)
                helper.start()
                if not acknowledgement.wait(1):
                    raise RuntimeError("cleanup signal acknowledgement timeout")
            return originals["signal_group"](*args)
        ns["signal_group"] = synchronized_signal_group

    try:
        kind = CASE_TO_SYNTHETIC[case]
        status, reason = ns["bounded"](
            synthetic(kind, child_gate, nonce, os.getpid(), ready_path),
            CHILD_WAIT_SECONDS,
            stdout,
            stderr,
            trace,
        )
        result = {"status": status, "reason": reason, "trace": trace}
    except BaseException as exc:
        result = {"worker_exception": type(exc).__name__, "message": str(exc), "trace": trace}
    finally:
        ns["subprocess"].Popen = original_popen
        for name, value in originals.items():
            if name == "sigpending":
                ns["signal"].sigpending = value
            else:
                ns[name] = value
        if helper:
            helper.join(timeout=1)
        stdout.close()
        stderr.close()
    result["containment"] = containment
    Path(result_path).write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")


def process_owned(record, nonce, case):
    return (
        record.get("nonce") == nonce and record.get("case") == case
        and isinstance(record.get("pid"), int) and record.get("pid") > 0
        and record.get("pgid") == record.get("pid")
        and record.get("session_id") == record.get("pid")
        and record.get("start_new_session") is True
    )


def child_owned(record, nonce, case, worker_pid):
    return (
        record.get("kind") == "supervisor-child"
        and record.get("worker_pid") == worker_pid
        and process_owned(record, nonce, case)
    )


def group_present(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def wait_group_absent(pgid, deadline):
    while group_present(pgid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


def parent_watchdog_cleanup(proc, worker_record, records, nonce, case,
                            watchdog, ownership_path, result_path,
                            malformed_records=None, live_handles=None,
                            group_present_fn=None, wait_group_absent_fn=None,
                            signal_fn=None, monotonic_fn=None):
    """The single parent-watchdog path used by lifecycle and focused tests."""
    group_present_fn = group_present_fn or group_present
    wait_group_absent_fn = wait_group_absent_fn or wait_group_absent
    monotonic_fn = monotonic_fn or time.monotonic
    cleanup_start = monotonic_fn()
    cleanup_deadline = cleanup_start + WATCHDOG_CLEANUP_SECONDS
    malformed_records = list(malformed_records or [])
    valid = [record for record in records
             if child_owned(record, nonce, case, proc.pid)]
    worker_owned = process_owned(worker_record, nonce, case)
    containment_ok = worker_owned and len(valid) == 1
    residual = [record for record in valid if group_present_fn(record["pgid"])]
    if residual and watchdog == "exited":
        watchdog = "residual-process"
    actions = []
    cleanup_errors = []
    if live_handles is not None:
        live_by_pid = {
            getattr(item, "record", {}).get("pid"): item
            for item in live_handles
        }
        for record in valid + [worker_record]:
            handle = live_by_pid.get(record.get("pid"))
            if (handle is None or getattr(handle, "pidfd", None) is None
                    or getattr(handle, "record", {}).get("pid") != record.get("pid")):
                cleanup_errors.append(
                    f"missing-live-handle:{record.get('pid')}")
    if watchdog != "exited" or not containment_ok:
        watchdog = watchdog if watchdog != "exited" else "containment-unproven"
        for record in valid:
            if group_present_fn(record["pgid"]):
                try:
                    if live_handles is not None:
                        handle = next((item for item in live_handles
                                       if item.record.get("pid") == record["pid"]), None)
                        if (handle is None or handle.pidfd is None
                                or handle.record.get("pid") != record["pid"]):
                            raise RuntimeError("live child handle missing or mismatched")
                        outcome = signal_fn(handle, signal.SIGKILL) if signal_fn else signal.pidfd_send_signal(handle.pidfd, signal.SIGKILL)
                    else:
                        outcome = signal_fn(record, signal.SIGKILL) if signal_fn else os.killpg(record["pgid"], signal.SIGKILL)
                    actions.append({"target": "child", "pgid": record["pgid"],
                                    "signal": int(signal.SIGKILL), "outcome": "sent"})
                except ProcessLookupError:
                    actions.append({"target": "child", "pgid": record["pgid"],
                                    "signal": int(signal.SIGKILL), "outcome": "absent"})
                except BaseException as error:
                    cleanup_errors.append(f"child-signal:{type(error).__name__}:{error}")
        if worker_owned and group_present_fn(worker_record["pgid"]):
            try:
                if live_handles is not None:
                    handle = next((item for item in live_handles
                                   if item.record.get("pid") == worker_record["pid"]), None)
                    if (handle is None or handle.pidfd is None
                            or handle.record.get("pid") != worker_record["pid"]):
                        raise RuntimeError("live worker handle missing or mismatched")
                    outcome = signal_fn(handle, signal.SIGKILL) if signal_fn else signal.pidfd_send_signal(handle.pidfd, signal.SIGKILL)
                else:
                    outcome = signal_fn(worker_record, signal.SIGKILL) if signal_fn else os.killpg(worker_record["pgid"], signal.SIGKILL)
                actions.append({"target": "worker", "pgid": worker_record["pgid"],
                                "signal": int(signal.SIGKILL), "outcome": "sent"})
            except ProcessLookupError:
                actions.append({"target": "worker", "pgid": worker_record["pgid"],
                                "signal": int(signal.SIGKILL), "outcome": "absent"})
            except BaseException as error:
                cleanup_errors.append(f"worker-signal:{type(error).__name__}:{error}")
        try:
                proc.wait(timeout=max(0, cleanup_deadline - monotonic_fn()))
        except subprocess.TimeoutExpired:
            watchdog = "worker-cleanup-timeout"
    remaining_owned_groups = [
        record for record in valid
        if not wait_group_absent_fn(record["pgid"], cleanup_deadline)
    ]
    worker_group_absent = (
        wait_group_absent_fn(worker_record["pgid"], cleanup_deadline)
        if worker_owned else False
    )
    cleanup_complete = monotonic_fn()
    cleanup_state = ("PROVEN" if worker_owned and len(valid) == 1
                     and worker_group_absent and not malformed_records
                     and not remaining_owned_groups
                     and not cleanup_errors and proc.poll() is not None
                     and cleanup_complete <= cleanup_deadline else "UNKNOWN")
    return {
        "watchdog": watchdog, "containment_ok": worker_owned and len(valid) == 1
        and not malformed_records, "worker_reaped": proc.poll() is not None,
        "residual_owned_groups": residual,
        "remaining_owned_groups": remaining_owned_groups,
         "worker_group_absent": worker_group_absent,
         "child_groups_absent": not remaining_owned_groups,
        "malformed_ownership_records": malformed_records, "valid_records": valid,
        "cleanup_actions": actions, "cleanup_errors": cleanup_errors,
        "cleanup_start_monotonic": cleanup_start,
        "cleanup_deadline_monotonic": cleanup_deadline,
        "cleanup_complete_monotonic": cleanup_complete,
        "cleanup_elapsed_seconds": cleanup_complete - cleanup_start,
        "cleanup_deadline_started": True,
        "cleanup_state": cleanup_state,
    }


def run_case(case):
    nonce = uuid.uuid4().hex
    ownership_path = MISSING_EVIDENCE / f"{case}.{nonce}.ownership.jsonl"
    result_path = MISSING_EVIDENCE / f"{case}.{nonce}.result.json"
    auth_path = MISSING_EVIDENCE / f"{case}.{nonce}.worker-authorized"
    ownership_path.touch(exist_ok=False)
    result_path.touch(exist_ok=False)
    auth_path.touch(exist_ok=False)
    cmd = [sys.executable, str(Path(__file__).resolve()), "--worker", case,
           str(ownership_path), str(result_path), str(auth_path), nonce]
    proc = subprocess.Popen(cmd, start_new_session=True)
    worker_record = {
        "kind": "worker", "nonce": nonce, "pid": proc.pid,
        "pgid": None, "session_id": None, "start_new_session": True,
        "worker_pid": os.getpid(), "case": case,
    }
    worker_authorized = False
    setup_error = None
    try:
        worker_record["pgid"] = os.getpgid(proc.pid)
        worker_record["session_id"] = os.getsid(proc.pid)
        worker_authorized = process_owned(worker_record, nonce, case)
        if not worker_authorized:
            raise RuntimeError("worker ownership validation failed")
        append_json(ownership_path, worker_record)
        auth_path.write_text(nonce + "\n", encoding="utf-8")
    except BaseException as error:
        setup_error = {"type": type(error).__name__, "message": str(error)}
        try:
            if worker_authorized and group_present(worker_record["pgid"]):
                os.killpg(worker_record["pgid"], signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
        except subprocess.TimeoutExpired:
            setup_error["cleanup"] = "worker-reap-timeout"
        return {
            "case": case,
            "nonce": nonce,
            "spawned": True,
            "worker_authorized": worker_authorized,
            "containment_ok": False,
            "watchdog": "worker-setup-failed",
            "setup_error": setup_error,
            "assertion_failures": ["worker setup/authorization failed"],
        }
    watchdog = "exited"
    try:
        proc.wait(timeout=CASE_EXECUTION_SECONDS)
    except subprocess.TimeoutExpired:
        watchdog = "watchdog-timeout"
    records = []
    malformed_records = []
    for line in ownership_path.read_text().splitlines():
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            malformed_records.append(line)
    cleanup = parent_watchdog_cleanup(
        proc, worker_record, records, nonce, case, watchdog,
        ownership_path, result_path, malformed_records,
    )
    watchdog = cleanup["watchdog"]
    valid = cleanup["valid_records"]
    remaining_owned_groups = cleanup["remaining_owned_groups"]
    containment_ok = worker_authorized and cleanup["containment_ok"]
    worker_reaped = cleanup["worker_reaped"]
    result = json.loads(result_path.read_text()) if result_path.stat().st_size else {}
    observed = {"case": case, "nonce": nonce, "watchdog": watchdog,
                "execution_state": "EXECUTED",
                "ownership_path": str(ownership_path.relative_to(ROOT)),
                "result_path": str(result_path.relative_to(ROOT)),
                "ownership_records": records, "containment_ok": containment_ok,
                "worker_reaped": worker_reaped,
                 "residual_owned_groups": cleanup["residual_owned_groups"],
                "remaining_owned_groups": remaining_owned_groups,
                 "worker_group_absent": cleanup["worker_group_absent"],
                 "child_groups_absent": cleanup["child_groups_absent"],
                 "cleanup_state": cleanup["cleanup_state"],
                 "cleanup_errors": cleanup["cleanup_errors"],
                 "cleanup_start_monotonic": cleanup["cleanup_start_monotonic"],
                 "cleanup_deadline_monotonic": cleanup["cleanup_deadline_monotonic"],
                 "cleanup_complete_monotonic": cleanup["cleanup_complete_monotonic"],
                 "cleanup_elapsed_seconds": cleanup["cleanup_elapsed_seconds"],
                 "cleanup_deadline_started": cleanup["cleanup_deadline_started"],
                "malformed_ownership_records": malformed_records,
                 "cleanup_actions": cleanup["cleanup_actions"],
                "result": result}
    expected = {
        "term-to-kill": (124, "timeout-clean", ("group-signal", "cleanup-result")),
        "cleanup-denial": (125, "timeout-cleanup-unproven", ("injected-group-signal",)),
        "probe-exception": (70, "post-wait-probe-exception-clean", ("post-wait-probe-exception",)),
        "drain-exception": (125, "pending-signal-drain-cleanup-unproven", ("pending-signal-drain-exception",)),
        "cleanup-signal-SIGINT": (130, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
        "cleanup-signal-SIGTERM": (143, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
        "cleanup-signal-SIGHUP": (129, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
    }[case]
    events = result.get("trace", [])
    names = {event.get("event") for event in events}
    observed["expected"] = {"status": expected[0], "reason": expected[1], "events": expected[2]}
    observed["assertion_failures"] = []
    if result.get("status") != expected[0] or result.get("reason") != expected[1]:
        observed["assertion_failures"].append("status/reason mismatch")
    if any(event not in names for event in expected[2]):
        observed["assertion_failures"].append("required trace event missing")
    if case.startswith("cleanup-signal-"):
        requested = {
            "cleanup-signal-SIGINT": int(signal.SIGINT),
            "cleanup-signal-SIGTERM": int(signal.SIGTERM),
            "cleanup-signal-SIGHUP": int(signal.SIGHUP),
        }[case]
        checkpoint_events = [
            e for e in events
            if e.get("event") == "test-cleanup-checkpoint"
            and e.get("phase") == "term" and e.get("signal") == requested
        ]
        sent_events = [
            e for e in events
            if e.get("event") == "test-cleanup-signal-sent"
            and e.get("phase") == "term" and e.get("signal") == requested
        ]
        delivery_events = [
            e for e in events
            if e.get("event") == "signal-delivery"
            and e.get("signal") == requested
            and e.get("stage") == "cleanup-pending-drain"
        ]
        if not (checkpoint_events and sent_events and delivery_events):
            observed["assertion_failures"].append(
                "exact cleanup signal checkpoint/sent/pending-drain proof missing"
            )
        else:
            positions = [
                next(i for i, e in enumerate(events) if e is item)
                for item in (checkpoint_events[0], sent_events[0], delivery_events[0])
            ]
            if not (positions[0] < positions[1] < positions[2]):
                observed["assertion_failures"].append(
                    "cleanup signal trace order checkpoint<sent<delivery failed"
                )
    if case == "term-to-kill":
        signals = {(e.get("phase"), e.get("signal"), e.get("outcome")) for e in events if e.get("event") == "group-signal"}
        if ("term", int(signal.SIGTERM), "sent") not in signals:
            observed["assertion_failures"].append("actual TERM sent not observed")
        if ("kill", int(signal.SIGKILL), "sent") not in signals:
            observed["assertion_failures"].append("actual KILL sent not observed")
        if not any(e.get("event") == "cleanup-result" and e.get("reason") == "kill-clean" for e in events):
            observed["assertion_failures"].append("kill-clean not observed")
    if case == "cleanup-denial":
        denials = {
            (event.get("phase"), event.get("signal"), event.get("outcome"))
            for event in events
            if event.get("event") == "injected-group-signal"
        }
        if ("term", int(signal.SIGTERM), "denied") not in denials:
            observed["assertion_failures"].append(
                "injected TERM denial not observed"
            )
        if ("kill", int(signal.SIGKILL), "denied") not in denials:
            observed["assertion_failures"].append(
                "injected KILL denial not observed"
            )
    if not worker_authorized:
        observed["assertion_failures"].append("worker authorization handshake failed")
    if len(valid) != 1:
        observed["assertion_failures"].append("expected exactly one valid supervisor-child record")
    if malformed_records:
        observed["assertion_failures"].append("malformed ownership record")
    if not containment_ok:
        observed["assertion_failures"].append("containment unproven")
    if watchdog != "exited":
        observed["assertion_failures"].append("watchdog did not observe clean exit")
    if remaining_owned_groups:
        observed["assertion_failures"].append("owned supervisor group remained present")
    return observed


def containment_blocker(result):
    if not isinstance(result, dict):
        return "case result is not an object"
    if result.get("containment_ok") is not True:
        return "containment_ok is not proven true"
    if result.get("worker_reaped") is not True:
        return "worker reaping is not proven"
    if result.get("cleanup_state") != "PROVEN":
        return "cleanup state is missing or not proven"
    if result.get("worker_group_absent") is not True:
        return "worker group absence is not proven"
    if result.get("child_groups_absent") is not True:
        return "child group absence is not proven"
    if not isinstance(result.get("cleanup_errors"), list):
        return "cleanup errors are missing or malformed"
    if result["cleanup_errors"]:
        return "cleanup errors are present"
    if result.get("cleanup_deadline_started") is not True:
        return "cleanup deadline evidence is missing"
    timing = [
        result.get("cleanup_start_monotonic"),
        result.get("cleanup_deadline_monotonic"),
        result.get("cleanup_complete_monotonic"),
        result.get("cleanup_elapsed_seconds"),
    ]
    if any(isinstance(value, bool) or not isinstance(value, (int, float))
           or not math.isfinite(value) for value in timing):
        return "cleanup timing evidence is missing or malformed"
    start, deadline, complete, elapsed = timing
    if not (start <= complete <= deadline and elapsed >= 0):
        return "cleanup timing is contradictory"
    tolerance = 1e-6
    if abs(elapsed - (complete - start)) > tolerance:
        return "cleanup elapsed time is inconsistent"
    if abs((deadline - start) - WATCHDOG_CLEANUP_SECONDS) > tolerance:
        return "cleanup deadline budget is inconsistent"
    for field in (
        "remaining_owned_groups",
        "malformed_ownership_records",
        "assertion_failures",
    ):
        if not isinstance(result.get(field), list):
            return f"{field} is missing or malformed"
    if result["remaining_owned_groups"]:
        return "owned supervisor groups remain present"
    if result["malformed_ownership_records"]:
        return "ownership evidence is malformed"
    for failure in result["assertion_failures"]:
        if not isinstance(failure, str):
            return "assertion failure evidence is malformed"
        if any(marker in failure for marker in CONTAINMENT_ASSERTION_MARKERS):
            return f"containment assertion failed: {failure}"
    if result.get("watchdog") == "worker-cleanup-timeout":
        return "watchdog could not reap the worker"
    return None


def schedule_cases(case_runner=run_case, cases=MISSING_CASES):
    results = []
    for index, case in enumerate(cases):
        try:
            result = case_runner(case)
        except BaseException as error:
            result = {
                "case": case,
                "execution_state": "EXECUTION_ERROR",
                "containment_ok": False,
                "worker_reaped": False,
                "remaining_owned_groups": [],
                "malformed_ownership_records": [],
                "assertion_failures": ["unexpected case exception"],
                "exception_type": type(error).__name__,
                "exception_message": str(error),
            }
        results.append(result)
        blocker = containment_blocker(result)
        if blocker is None:
            continue
        for remaining in cases[index + 1:]:
            results.append({
                "case": remaining,
                "execution_state": "NOT_EXECUTED",
                "blocked_by": case,
                "blocking_reason": blocker,
                "containment_ok": False,
                "assertion_failures": ["not executed after containment stop"],
            })
        break
    return results


def scheduler_self_test():
    base = {
        "execution_state": "EXECUTED",
        "containment_ok": True,
        "worker_reaped": True,
        "remaining_owned_groups": [],
        "malformed_ownership_records": [],
        "assertion_failures": [],
        "watchdog": "exited",
        "cleanup_state": "PROVEN",
        "cleanup_errors": [],
        "cleanup_deadline_started": True,
        "cleanup_start_monotonic": 10.0,
        "cleanup_deadline_monotonic": 13.0,
        "cleanup_complete_monotonic": 12.0,
        "cleanup_elapsed_seconds": 2.0,
        "worker_group_absent": True,
        "child_groups_absent": True,
    }
    scenarios = {
        "proven-permits-next": (
            lambda case: dict(base, case=case),
            2,
            ["EXECUTED", "EXECUTED"],
        ),
        "false-stops": (
            lambda case: dict(base, case=case, containment_ok=False),
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-stops": (
            lambda case: {
                key: value for key, value in dict(base, case=case).items()
                if key != "containment_ok"
            },
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "contradiction-stops": (
            lambda case: dict(
                base,
                case=case,
                remaining_owned_groups=[{"pgid": 999999}],
            ),
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-state": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_state"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "unknown-cleanup-state": (
            lambda case: dict(base, case=case, cleanup_state="UNKNOWN"),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-worker-absence": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "worker_group_absent"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-child-absence": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "child_groups_absent"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "cleanup-error-stops": (
            lambda case: dict(base, case=case, cleanup_errors=["injected"]),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-errors": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_errors"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "malformed-cleanup-errors": (
            lambda case: dict(base, case=case, cleanup_errors="bad"),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-timing": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_complete_monotonic"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "completion-after-deadline": (
            lambda case: dict(base, case=case, cleanup_complete_monotonic=14.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "negative-elapsed": (
            lambda case: dict(base, case=case, cleanup_elapsed_seconds=-1.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "inconsistent-elapsed": (
            lambda case: dict(base, case=case, cleanup_elapsed_seconds=1.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "wrong-cleanup-budget": (
            lambda case: dict(base, case=case, cleanup_deadline_monotonic=14.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
    }
    outcomes = {}
    cases = ("first", "second")
    for name, (runner, expected_count, expected_states) in scenarios.items():
        results = schedule_cases(runner, cases)
        states = [item.get("execution_state") for item in results]
        passed = len(results) == expected_count and states == expected_states
        outcomes[name] = {"passed": passed, "states": states}
    calls = []
    def raising_runner(case):
        calls.append(case)
        raise RuntimeError("fabricated scheduler exception")
    exception_results = schedule_cases(raising_runner, cases)
    exception_states = [
        item.get("execution_state") for item in exception_results
    ]
    outcomes["exception-stops"] = {
        "passed": calls == ["first"]
        and exception_states == ["EXECUTION_ERROR", "NOT_EXECUTED"],
        "states": exception_states,
    }
    print(json.dumps(outcomes, indent=2, sort_keys=True))
    if not all(item["passed"] for item in outcomes.values()):
        raise SystemExit("scheduler self-test failed")
    cli_parser_self_test()
    assert source_stability({"a": "1"}, {"a": "1"}) == "PROVEN"
    assert source_stability({"a": "1"}, {"a": "2"}) == "FAILED"


def main():
    pre = {"launcher": digest(LAUNCHER), "proposal": digest(PROPOSAL)}
    if pre != {"launcher": EXPECTED_LAUNCHER, "proposal": EXPECTED_PROPOSAL}:
        raise SystemExit("hash precondition failed")
    harness_paths = {
        "run_validation": Path(__file__).resolve(),
        "run_containment": Path(__file__).resolve().with_name("run_containment.py"),
    }
    source_pre = {name: digest(path) for name, path in harness_paths.items()}
    source, constants, locations, extraction_hash = extract_source()
    if (
        constants["TERM_WAIT_SECONDS"] != TERM_GRACE_SECONDS
        or constants["KILL_WAIT_SECONDS"] != KILL_GRACE_SECONDS
    ):
        raise SystemExit("extracted cleanup grace mismatch")
    MISSING_EVIDENCE.mkdir(parents=True, exist_ok=False)
    (MISSING_EVIDENCE / "extracted_supervisor_source.py").write_text(source, encoding="utf-8")
    results = schedule_cases()
    post = {"launcher": digest(LAUNCHER), "proposal": digest(PROPOSAL)}
    source_post = {name: digest(path) for name, path in harness_paths.items()}
    raw = {"batch": "missing_cases_only", "pre_hashes": pre, "post_hashes": post,
           "source_extraction_sha256": extraction_hash, "source_locations": locations,
           "harness_source_pre_hashes": source_pre,
           "harness_source_post_hashes": source_post,
           "harness_source_stability": (
               source_stability(source_pre, source_post)
           ),
           "harness_source_stability_limit": (
               "Pre/post hashes do not prove absence of transient changes during execution."
           ),
            "case_execution_seconds": CASE_EXECUTION_SECONDS,
            "watchdog_cleanup_seconds": WATCHDOG_CLEANUP_SECONDS,
            "child_wait_seconds": CHILD_WAIT_SECONDS,
             "term_grace_seconds": TERM_GRACE_SECONDS, "kill_grace_seconds": KILL_GRACE_SECONDS,
           "case_to_synthetic": CASE_TO_SYNTHETIC, "cases": results,
             "instrumentation": "External namespace Popen recording/readiness wrapper, Linux PR_SET_PDEATHSIG child lifetime guard, and named monkeypatches only; child controller configuration is recorded, not runtime-proven.",
           "assertions_failed": [r for r in results if r["assertion_failures"]]}
    (MISSING_EVIDENCE / "raw.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    failures = raw["assertions_failed"]
    if raw["harness_source_stability"] != "PROVEN":
        raise SystemExit("harness source stability failed after evidence write")
    if failures:
        raise SystemExit(f"validation assertions failed after evidence write: {len(failures)}")


if __name__ == "__main__":
    cli = parse_cli(sys.argv[1:])
    if cli["mode"] == "help":
        print_help()
    elif cli["mode"] == "worker":
        worker(cli["case"], *(Path(path) for path in cli["paths"]), cli["nonce"])
    elif cli["mode"] == "scheduler-self-test":
        scheduler_self_test()
    else:
        main()
#!/usr/bin/env python3
"""Preparation-only harness for the seven not-yet-executed supervisor cases."""
import ast
import ctypes
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "attached_assets/usbay-fda-readonly-diskutil-diagnostic.zsh"
PROPOSAL = ROOT / "attached_assets/usbay-temporary-terminal-full-disk-access-diagnostic-proposal.md"
EVIDENCE = Path(__file__).resolve().parent / "evidence"
MISSING_EVIDENCE = EVIDENCE / "missing_cases_batch"
EXPECTED_LAUNCHER = "b19bd48a797b3f5659c6fb850d4baff1792c6c73153bfec13b4eb6f5976f320b"
EXPECTED_PROPOSAL = "ef648fadc31e252ce91ff6ee754b0670e6f477b5afd8a5e4a5bc3cdcb675429c"
CHILD_WAIT_SECONDS = 0.08
TERM_GRACE_SECONDS = 2
KILL_GRACE_SECONDS = 2
WATCHDOG_CLEANUP_SECONDS = 3
CASE_EXECUTION_SECONDS = 12
MISSING_CASES = (
    "term-to-kill", "cleanup-denial", "probe-exception", "drain-exception",
    "cleanup-signal-SIGINT", "cleanup-signal-SIGTERM", "cleanup-signal-SIGHUP",
)
CASE_TO_SYNTHETIC = {
    "term-to-kill": "term_ignore_ready",
    "cleanup-denial": "sleep",
    "probe-exception": "exit0",
    "drain-exception": "exit0",
    "cleanup-signal-SIGINT": "sleep",
    "cleanup-signal-SIGTERM": "sleep",
    "cleanup-signal-SIGHUP": "sleep",
}
CONTAINMENT_ASSERTION_MARKERS = (
    "worker authorization",
    "supervisor-child record",
    "malformed ownership",
    "containment unproven",
    "watchdog did not observe clean exit",
    "owned supervisor group remained",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_stability(pre, post):
    """Assess only equality of the recorded pre/post source hashes."""
    return "PROVEN" if dict(pre) == dict(post) else "FAILED"


def parse_cli(argv):
    """Validate dispatch without touching evidence, channels, or processes."""
    args = list(argv)
    if args in (["--help"], ["-h"]):
        return {"mode": "help"}
    if args == ["--scheduler-self-test"]:
        return {"mode": "scheduler-self-test"}
    if args == []:
        return {"mode": "main"}
    if len(args) == 6 and args[0] == "--worker":
        case, ownership, result, auth, nonce = args[1:]
        if case not in MISSING_CASES or not nonce or nonce.startswith("-"):
            raise SystemExit("invalid worker case or nonce")
        paths = (ownership, result, auth)
        if any(not item or item.startswith("-") for item in paths):
            raise SystemExit("invalid worker paths")
        return {"mode": "worker", "case": case, "paths": paths, "nonce": nonce}
    raise SystemExit("unknown or malformed arguments")


def print_help():
    print("usage: run_validation.py [--scheduler-self-test|--worker CASE OWNERSHIP RESULT AUTH NONCE]")


def cli_parser_self_test():
    """Pure parser/dispatch checks; no evidence, channels, or processes."""
    side_effects = {"count": 0}
    for argv, expected in (
        (["--help"], "help"),
        (["--scheduler-self-test"], "scheduler-self-test"),
    ):
        parsed = parse_cli(argv)
        assert parsed["mode"] == expected
        assert side_effects["count"] == 0
    for argv in (
        ["--unknown"],
        ["--worker", "bad", "a", "b", "c", "n"],
        ["--worker", "term-to-kill", "a", "b", "c"],
        ["--worker", "term-to-kill", "-a", "b", "c", "n"],
        ["--worker", "term-to-kill", "a", "--b", "c", "n"],
        ["--worker", "term-to-kill", "a", "b", "c", "-n"],
    ):
        try:
            parse_cli(argv)
        except SystemExit:
            pass
        else:
            raise AssertionError("malformed CLI accepted")
        assert side_effects["count"] == 0


def extract_source():
    raw = LAUNCHER.read_text()
    py = raw.split("<<'PY'\n", 1)[1].split("\ntry:\n    final_status=main()", 1)[0]
    tree = ast.parse(py)
    chosen = [
        node for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef))
        and (not isinstance(node, ast.FunctionDef) or node.name != "main")
    ]
    source = ast.unparse(ast.Module(body=chosen, type_ignores=[])) + "\n"
    namespace = {"__name__": "extracted_supervisor"}
    exec(compile(ast.Module(body=chosen, type_ignores=[]), str(LAUNCHER), "exec"), namespace)
    locations = [f"{node.__class__.__name__}:{getattr(node, 'name', '')}" for node in chosen]
    return source, namespace, locations, hashlib.sha256(source.encode()).hexdigest()


def synthetic(kind, gate_path, nonce, worker_pid, ready_path=None):
    behavior = {
        "sleep": "time.sleep(.35)",
        "exit0": "raise SystemExit(0)",
        "term_ignore_ready": (
            "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            "pathlib.Path(sys.argv[3]).write_text('READY\\n')\n"
            "time.sleep(10)"
        ),
    }[kind]
    code = (
        "import ctypes,os,pathlib,signal,sys,time\n"
        "if ctypes.CDLL(None).prctl(1,signal.SIGKILL) != 0: raise SystemExit(91)\n"
        "if os.getppid() != int(sys.argv[4]): raise SystemExit(92)\n"
        "gate=pathlib.Path(sys.argv[1]); nonce=sys.argv[2]\n"
        "while True:\n"
        "    try:\n"
        "        if gate.read_text().strip()==nonce: break\n"
        "    except (FileNotFoundError,OSError): pass\n"
        "    time.sleep(.01)\n"
        + behavior + "\n"
    )
    return [
        sys.executable, "-c", "exec(" + repr(code) + ")",
        str(gate_path), nonce, str(ready_path or ""), str(worker_pid),
    ]


def append_json(path, item):
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(item, sort_keys=True) + "\n")
        stream.flush()


def worker(case, ownership_path, result_path, auth_path, nonce):
    while auth_path.read_text(encoding="utf-8").strip() != nonce:
        time.sleep(0.01)
    _, ns, _, _ = extract_source()
    trace = []
    stdout = tempfile.TemporaryFile()
    stderr = tempfile.TemporaryFile()
    originals = {}
    helper = None
    checkpoint = threading.Event()
    acknowledgement = threading.Event()
    ready_path = Path(str(result_path) + ".ready")
    child_gate = Path(str(result_path) + ".child-gate")
    containment = {
        "nonce": nonce,
        "worker_pid": os.getpid(),
        "controller_mechanism": "Linux prctl(PR_SET_PDEATHSIG, SIGKILL) with child PPID check",
        "records": [],
    }

    original_popen = ns["subprocess"].Popen
    def recording_popen(*args, **kwargs):
        child = original_popen(*args, **kwargs)
        record = {"pgid": None}
        try:
            record = {
                "kind": "supervisor-child", "nonce": nonce, "pid": child.pid,
                "pgid": os.getpgid(child.pid), "session_id": os.getsid(child.pid),
                "start_new_session": kwargs.get("start_new_session", False),
                "worker_pid": os.getpid(), "case": case, "child_gate": str(child_gate),
            }
            if not child_owned(record, nonce, case, os.getpid()):
                raise RuntimeError("supervisor-child ownership validation failed")
            containment["records"].append(record)
            append_json(ownership_path, record)
            child_gate.write_text(nonce + "\n", encoding="utf-8")
            if case == "term-to-kill":
                deadline = time.monotonic() + 2
                while not ready_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not ready_path.exists():
                    raise RuntimeError("TERM handler readiness was not proven")
        except BaseException:
            if isinstance(record.get("pgid"), int):
                try:
                    os.killpg(record["pgid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                child.kill()
            try:
                child.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
            raise
        return child

    ns["subprocess"].Popen = recording_popen
    if case == "cleanup-denial":
        originals["signal_group"] = ns["signal_group"]
        def denied_signal_group(pgid, sig, trace_arg, phase):
            outcome = "denied"
            ns["trace_event"](trace_arg, "injected-group-signal", phase=phase,
                              signal=int(sig), outcome=outcome)
            return outcome
        ns["signal_group"] = denied_signal_group
    elif case == "probe-exception":
        originals["group_state"] = ns["group_state"]
        def injected_probe(*args, **kwargs):
            raise RuntimeError("injected-probe")
        ns["group_state"] = injected_probe
    elif case == "drain-exception":
        originals["sigpending"] = ns["signal"].sigpending
        ns["signal"].sigpending = lambda: (_ for _ in ()).throw(RuntimeError("injected-drain"))
    elif case.startswith("cleanup-signal-"):
        originals["signal_group"] = ns["signal_group"]
        requested = {
            "cleanup-signal-SIGINT": signal.SIGINT,
            "cleanup-signal-SIGTERM": signal.SIGTERM,
            "cleanup-signal-SIGHUP": signal.SIGHUP,
        }[case]
        def synchronized_signal_group(*args):
            pgid, sig, trace_arg, phase = args
            if phase == "term" and not checkpoint.is_set():
                ns["trace_event"](trace_arg, "test-cleanup-checkpoint",
                                  phase="term", signal=int(requested))
                checkpoint.set()
                def deliver():
                    if checkpoint.wait(1):
                        os.kill(os.getpid(), requested)
                        ns["trace_event"](trace_arg, "test-cleanup-signal-sent",
                                          phase="term", signal=int(requested))
                        acknowledgement.set()
                nonlocal helper
                helper = threading.Thread(target=deliver, daemon=True)
                helper.start()
                if not acknowledgement.wait(1):
                    raise RuntimeError("cleanup signal acknowledgement timeout")
            return originals["signal_group"](*args)
        ns["signal_group"] = synchronized_signal_group

    try:
        kind = CASE_TO_SYNTHETIC[case]
        status, reason = ns["bounded"](
            synthetic(kind, child_gate, nonce, os.getpid(), ready_path),
            CHILD_WAIT_SECONDS,
            stdout,
            stderr,
            trace,
        )
        result = {"status": status, "reason": reason, "trace": trace}
    except BaseException as exc:
        result = {"worker_exception": type(exc).__name__, "message": str(exc), "trace": trace}
    finally:
        ns["subprocess"].Popen = original_popen
        for name, value in originals.items():
            if name == "sigpending":
                ns["signal"].sigpending = value
            else:
                ns[name] = value
        if helper:
            helper.join(timeout=1)
        stdout.close()
        stderr.close()
    result["containment"] = containment
    Path(result_path).write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")


def process_owned(record, nonce, case):
    return (
        record.get("nonce") == nonce and record.get("case") == case
        and isinstance(record.get("pid"), int) and record.get("pid") > 0
        and record.get("pgid") == record.get("pid")
        and record.get("session_id") == record.get("pid")
        and record.get("start_new_session") is True
    )


def child_owned(record, nonce, case, worker_pid):
    return (
        record.get("kind") == "supervisor-child"
        and record.get("worker_pid") == worker_pid
        and process_owned(record, nonce, case)
    )


def group_present(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def wait_group_absent(pgid, deadline):
    while group_present(pgid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


def parent_watchdog_cleanup(proc, worker_record, records, nonce, case,
                            watchdog, ownership_path, result_path,
                            malformed_records=None, live_handles=None,
                            group_present_fn=None, wait_group_absent_fn=None,
                            signal_fn=None, monotonic_fn=None):
    """The single parent-watchdog path used by lifecycle and focused tests."""
    group_present_fn = group_present_fn or group_present
    wait_group_absent_fn = wait_group_absent_fn or wait_group_absent
    monotonic_fn = monotonic_fn or time.monotonic
    cleanup_start = monotonic_fn()
    cleanup_deadline = cleanup_start + WATCHDOG_CLEANUP_SECONDS
    malformed_records = list(malformed_records or [])
    valid = [record for record in records
             if child_owned(record, nonce, case, proc.pid)]
    worker_owned = process_owned(worker_record, nonce, case)
    containment_ok = worker_owned and len(valid) == 1
    residual = [record for record in valid if group_present_fn(record["pgid"])]
    if residual and watchdog == "exited":
        watchdog = "residual-process"
    actions = []
    cleanup_errors = []
    if live_handles is not None:
        live_by_pid = {
            getattr(item, "record", {}).get("pid"): item
            for item in live_handles
        }
        for record in valid + [worker_record]:
            handle = live_by_pid.get(record.get("pid"))
            if (handle is None or getattr(handle, "pidfd", None) is None
                    or getattr(handle, "record", {}).get("pid") != record.get("pid")):
                cleanup_errors.append(
                    f"missing-live-handle:{record.get('pid')}")
    if watchdog != "exited" or not containment_ok:
        watchdog = watchdog if watchdog != "exited" else "containment-unproven"
        for record in valid:
            if group_present_fn(record["pgid"]):
                try:
                    if live_handles is not None:
                        handle = next((item for item in live_handles
                                       if item.record.get("pid") == record["pid"]), None)
                        if (handle is None or handle.pidfd is None
                                or handle.record.get("pid") != record["pid"]):
                            raise RuntimeError("live child handle missing or mismatched")
                        outcome = signal_fn(handle, signal.SIGKILL) if signal_fn else signal.pidfd_send_signal(handle.pidfd, signal.SIGKILL)
                    else:
                        outcome = signal_fn(record, signal.SIGKILL) if signal_fn else os.killpg(record["pgid"], signal.SIGKILL)
                    actions.append({"target": "child", "pgid": record["pgid"],
                                    "signal": int(signal.SIGKILL), "outcome": "sent"})
                except ProcessLookupError:
                    actions.append({"target": "child", "pgid": record["pgid"],
                                    "signal": int(signal.SIGKILL), "outcome": "absent"})
                except BaseException as error:
                    cleanup_errors.append(f"child-signal:{type(error).__name__}:{error}")
        if worker_owned and group_present_fn(worker_record["pgid"]):
            try:
                if live_handles is not None:
                    handle = next((item for item in live_handles
                                   if item.record.get("pid") == worker_record["pid"]), None)
                    if (handle is None or handle.pidfd is None
                            or handle.record.get("pid") != worker_record["pid"]):
                        raise RuntimeError("live worker handle missing or mismatched")
                    outcome = signal_fn(handle, signal.SIGKILL) if signal_fn else signal.pidfd_send_signal(handle.pidfd, signal.SIGKILL)
                else:
                    outcome = signal_fn(worker_record, signal.SIGKILL) if signal_fn else os.killpg(worker_record["pgid"], signal.SIGKILL)
                actions.append({"target": "worker", "pgid": worker_record["pgid"],
                                "signal": int(signal.SIGKILL), "outcome": "sent"})
            except ProcessLookupError:
                actions.append({"target": "worker", "pgid": worker_record["pgid"],
                                "signal": int(signal.SIGKILL), "outcome": "absent"})
            except BaseException as error:
                cleanup_errors.append(f"worker-signal:{type(error).__name__}:{error}")
        try:
                proc.wait(timeout=max(0, cleanup_deadline - monotonic_fn()))
        except subprocess.TimeoutExpired:
            watchdog = "worker-cleanup-timeout"
    remaining_owned_groups = [
        record for record in valid
        if not wait_group_absent_fn(record["pgid"], cleanup_deadline)
    ]
    worker_group_absent = (
        wait_group_absent_fn(worker_record["pgid"], cleanup_deadline)
        if worker_owned else False
    )
    cleanup_complete = monotonic_fn()
    cleanup_state = ("PROVEN" if worker_owned and len(valid) == 1
                     and worker_group_absent and not malformed_records
                     and not remaining_owned_groups
                     and not cleanup_errors and proc.poll() is not None
                     and cleanup_complete <= cleanup_deadline else "UNKNOWN")
    return {
        "watchdog": watchdog, "containment_ok": worker_owned and len(valid) == 1
        and not malformed_records, "worker_reaped": proc.poll() is not None,
        "residual_owned_groups": residual,
        "remaining_owned_groups": remaining_owned_groups,
         "worker_group_absent": worker_group_absent,
         "child_groups_absent": not remaining_owned_groups,
        "malformed_ownership_records": malformed_records, "valid_records": valid,
        "cleanup_actions": actions, "cleanup_errors": cleanup_errors,
        "cleanup_start_monotonic": cleanup_start,
        "cleanup_deadline_monotonic": cleanup_deadline,
        "cleanup_complete_monotonic": cleanup_complete,
        "cleanup_elapsed_seconds": cleanup_complete - cleanup_start,
        "cleanup_deadline_started": True,
        "cleanup_state": cleanup_state,
    }


def run_case(case):
    nonce = uuid.uuid4().hex
    ownership_path = MISSING_EVIDENCE / f"{case}.{nonce}.ownership.jsonl"
    result_path = MISSING_EVIDENCE / f"{case}.{nonce}.result.json"
    auth_path = MISSING_EVIDENCE / f"{case}.{nonce}.worker-authorized"
    ownership_path.touch(exist_ok=False)
    result_path.touch(exist_ok=False)
    auth_path.touch(exist_ok=False)
    cmd = [sys.executable, str(Path(__file__).resolve()), "--worker", case,
           str(ownership_path), str(result_path), str(auth_path), nonce]
    proc = subprocess.Popen(cmd, start_new_session=True)
    worker_record = {
        "kind": "worker", "nonce": nonce, "pid": proc.pid,
        "pgid": None, "session_id": None, "start_new_session": True,
        "worker_pid": os.getpid(), "case": case,
    }
    worker_authorized = False
    setup_error = None
    try:
        worker_record["pgid"] = os.getpgid(proc.pid)
        worker_record["session_id"] = os.getsid(proc.pid)
        worker_authorized = process_owned(worker_record, nonce, case)
        if not worker_authorized:
            raise RuntimeError("worker ownership validation failed")
        append_json(ownership_path, worker_record)
        auth_path.write_text(nonce + "\n", encoding="utf-8")
    except BaseException as error:
        setup_error = {"type": type(error).__name__, "message": str(error)}
        try:
            if worker_authorized and group_present(worker_record["pgid"]):
                os.killpg(worker_record["pgid"], signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
        except subprocess.TimeoutExpired:
            setup_error["cleanup"] = "worker-reap-timeout"
        return {
            "case": case,
            "nonce": nonce,
            "spawned": True,
            "worker_authorized": worker_authorized,
            "containment_ok": False,
            "watchdog": "worker-setup-failed",
            "setup_error": setup_error,
            "assertion_failures": ["worker setup/authorization failed"],
        }
    watchdog = "exited"
    try:
        proc.wait(timeout=CASE_EXECUTION_SECONDS)
    except subprocess.TimeoutExpired:
        watchdog = "watchdog-timeout"
    records = []
    malformed_records = []
    for line in ownership_path.read_text().splitlines():
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            malformed_records.append(line)
    cleanup = parent_watchdog_cleanup(
        proc, worker_record, records, nonce, case, watchdog,
        ownership_path, result_path, malformed_records,
    )
    watchdog = cleanup["watchdog"]
    valid = cleanup["valid_records"]
    remaining_owned_groups = cleanup["remaining_owned_groups"]
    containment_ok = worker_authorized and cleanup["containment_ok"]
    worker_reaped = cleanup["worker_reaped"]
    result = json.loads(result_path.read_text()) if result_path.stat().st_size else {}
    observed = {"case": case, "nonce": nonce, "watchdog": watchdog,
                "execution_state": "EXECUTED",
                "ownership_path": str(ownership_path.relative_to(ROOT)),
                "result_path": str(result_path.relative_to(ROOT)),
                "ownership_records": records, "containment_ok": containment_ok,
                "worker_reaped": worker_reaped,
                 "residual_owned_groups": cleanup["residual_owned_groups"],
                "remaining_owned_groups": remaining_owned_groups,
                 "worker_group_absent": cleanup["worker_group_absent"],
                 "child_groups_absent": cleanup["child_groups_absent"],
                 "cleanup_state": cleanup["cleanup_state"],
                 "cleanup_errors": cleanup["cleanup_errors"],
                 "cleanup_start_monotonic": cleanup["cleanup_start_monotonic"],
                 "cleanup_deadline_monotonic": cleanup["cleanup_deadline_monotonic"],
                 "cleanup_complete_monotonic": cleanup["cleanup_complete_monotonic"],
                 "cleanup_elapsed_seconds": cleanup["cleanup_elapsed_seconds"],
                 "cleanup_deadline_started": cleanup["cleanup_deadline_started"],
                "malformed_ownership_records": malformed_records,
                 "cleanup_actions": cleanup["cleanup_actions"],
                "result": result}
    expected = {
        "term-to-kill": (124, "timeout-clean", ("group-signal", "cleanup-result")),
        "cleanup-denial": (125, "timeout-cleanup-unproven", ("injected-group-signal",)),
        "probe-exception": (70, "post-wait-probe-exception-clean", ("post-wait-probe-exception",)),
        "drain-exception": (125, "pending-signal-drain-cleanup-unproven", ("pending-signal-drain-exception",)),
        "cleanup-signal-SIGINT": (130, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
        "cleanup-signal-SIGTERM": (143, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
        "cleanup-signal-SIGHUP": (129, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
    }[case]
    events = result.get("trace", [])
    names = {event.get("event") for event in events}
    observed["expected"] = {"status": expected[0], "reason": expected[1], "events": expected[2]}
    observed["assertion_failures"] = []
    if result.get("status") != expected[0] or result.get("reason") != expected[1]:
        observed["assertion_failures"].append("status/reason mismatch")
    if any(event not in names for event in expected[2]):
        observed["assertion_failures"].append("required trace event missing")
    if case.startswith("cleanup-signal-"):
        requested = {
            "cleanup-signal-SIGINT": int(signal.SIGINT),
            "cleanup-signal-SIGTERM": int(signal.SIGTERM),
            "cleanup-signal-SIGHUP": int(signal.SIGHUP),
        }[case]
        checkpoint_events = [
            e for e in events
            if e.get("event") == "test-cleanup-checkpoint"
            and e.get("phase") == "term" and e.get("signal") == requested
        ]
        sent_events = [
            e for e in events
            if e.get("event") == "test-cleanup-signal-sent"
            and e.get("phase") == "term" and e.get("signal") == requested
        ]
        delivery_events = [
            e for e in events
            if e.get("event") == "signal-delivery"
            and e.get("signal") == requested
            and e.get("stage") == "cleanup-pending-drain"
        ]
        if not (checkpoint_events and sent_events and delivery_events):
            observed["assertion_failures"].append(
                "exact cleanup signal checkpoint/sent/pending-drain proof missing"
            )
        else:
            positions = [
                next(i for i, e in enumerate(events) if e is item)
                for item in (checkpoint_events[0], sent_events[0], delivery_events[0])
            ]
            if not (positions[0] < positions[1] < positions[2]):
                observed["assertion_failures"].append(
                    "cleanup signal trace order checkpoint<sent<delivery failed"
                )
    if case == "term-to-kill":
        signals = {(e.get("phase"), e.get("signal"), e.get("outcome")) for e in events if e.get("event") == "group-signal"}
        if ("term", int(signal.SIGTERM), "sent") not in signals:
            observed["assertion_failures"].append("actual TERM sent not observed")
        if ("kill", int(signal.SIGKILL), "sent") not in signals:
            observed["assertion_failures"].append("actual KILL sent not observed")
        if not any(e.get("event") == "cleanup-result" and e.get("reason") == "kill-clean" for e in events):
            observed["assertion_failures"].append("kill-clean not observed")
    if case == "cleanup-denial":
        denials = {
            (event.get("phase"), event.get("signal"), event.get("outcome"))
            for event in events
            if event.get("event") == "injected-group-signal"
        }
        if ("term", int(signal.SIGTERM), "denied") not in denials:
            observed["assertion_failures"].append(
                "injected TERM denial not observed"
            )
        if ("kill", int(signal.SIGKILL), "denied") not in denials:
            observed["assertion_failures"].append(
                "injected KILL denial not observed"
            )
    if not worker_authorized:
        observed["assertion_failures"].append("worker authorization handshake failed")
    if len(valid) != 1:
        observed["assertion_failures"].append("expected exactly one valid supervisor-child record")
    if malformed_records:
        observed["assertion_failures"].append("malformed ownership record")
    if not containment_ok:
        observed["assertion_failures"].append("containment unproven")
    if watchdog != "exited":
        observed["assertion_failures"].append("watchdog did not observe clean exit")
    if remaining_owned_groups:
        observed["assertion_failures"].append("owned supervisor group remained present")
    return observed


def containment_blocker(result):
    if not isinstance(result, dict):
        return "case result is not an object"
    if result.get("containment_ok") is not True:
        return "containment_ok is not proven true"
    if result.get("worker_reaped") is not True:
        return "worker reaping is not proven"
    if result.get("cleanup_state") != "PROVEN":
        return "cleanup state is missing or not proven"
    if result.get("worker_group_absent") is not True:
        return "worker group absence is not proven"
    if result.get("child_groups_absent") is not True:
        return "child group absence is not proven"
    if not isinstance(result.get("cleanup_errors"), list):
        return "cleanup errors are missing or malformed"
    if result["cleanup_errors"]:
        return "cleanup errors are present"
    if result.get("cleanup_deadline_started") is not True:
        return "cleanup deadline evidence is missing"
    timing = [
        result.get("cleanup_start_monotonic"),
        result.get("cleanup_deadline_monotonic"),
        result.get("cleanup_complete_monotonic"),
        result.get("cleanup_elapsed_seconds"),
    ]
    if any(isinstance(value, bool) or not isinstance(value, (int, float))
           or not math.isfinite(value) for value in timing):
        return "cleanup timing evidence is missing or malformed"
    start, deadline, complete, elapsed = timing
    if not (start <= complete <= deadline and elapsed >= 0):
        return "cleanup timing is contradictory"
    tolerance = 1e-6
    if abs(elapsed - (complete - start)) > tolerance:
        return "cleanup elapsed time is inconsistent"
    if abs((deadline - start) - WATCHDOG_CLEANUP_SECONDS) > tolerance:
        return "cleanup deadline budget is inconsistent"
    for field in (
        "remaining_owned_groups",
        "malformed_ownership_records",
        "assertion_failures",
    ):
        if not isinstance(result.get(field), list):
            return f"{field} is missing or malformed"
    if result["remaining_owned_groups"]:
        return "owned supervisor groups remain present"
    if result["malformed_ownership_records"]:
        return "ownership evidence is malformed"
    for failure in result["assertion_failures"]:
        if not isinstance(failure, str):
            return "assertion failure evidence is malformed"
        if any(marker in failure for marker in CONTAINMENT_ASSERTION_MARKERS):
            return f"containment assertion failed: {failure}"
    if result.get("watchdog") == "worker-cleanup-timeout":
        return "watchdog could not reap the worker"
    return None


def schedule_cases(case_runner=run_case, cases=MISSING_CASES):
    results = []
    for index, case in enumerate(cases):
        try:
            result = case_runner(case)
        except BaseException as error:
            result = {
                "case": case,
                "execution_state": "EXECUTION_ERROR",
                "containment_ok": False,
                "worker_reaped": False,
                "remaining_owned_groups": [],
                "malformed_ownership_records": [],
                "assertion_failures": ["unexpected case exception"],
                "exception_type": type(error).__name__,
                "exception_message": str(error),
            }
        results.append(result)
        blocker = containment_blocker(result)
        if blocker is None:
            continue
        for remaining in cases[index + 1:]:
            results.append({
                "case": remaining,
                "execution_state": "NOT_EXECUTED",
                "blocked_by": case,
                "blocking_reason": blocker,
                "containment_ok": False,
                "assertion_failures": ["not executed after containment stop"],
            })
        break
    return results


def scheduler_self_test():
    base = {
        "execution_state": "EXECUTED",
        "containment_ok": True,
        "worker_reaped": True,
        "remaining_owned_groups": [],
        "malformed_ownership_records": [],
        "assertion_failures": [],
        "watchdog": "exited",
        "cleanup_state": "PROVEN",
        "cleanup_errors": [],
        "cleanup_deadline_started": True,
        "cleanup_start_monotonic": 10.0,
        "cleanup_deadline_monotonic": 13.0,
        "cleanup_complete_monotonic": 12.0,
        "cleanup_elapsed_seconds": 2.0,
        "worker_group_absent": True,
        "child_groups_absent": True,
    }
    scenarios = {
        "proven-permits-next": (
            lambda case: dict(base, case=case),
            2,
            ["EXECUTED", "EXECUTED"],
        ),
        "false-stops": (
            lambda case: dict(base, case=case, containment_ok=False),
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-stops": (
            lambda case: {
                key: value for key, value in dict(base, case=case).items()
                if key != "containment_ok"
            },
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "contradiction-stops": (
            lambda case: dict(
                base,
                case=case,
                remaining_owned_groups=[{"pgid": 999999}],
            ),
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-state": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_state"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "unknown-cleanup-state": (
            lambda case: dict(base, case=case, cleanup_state="UNKNOWN"),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-worker-absence": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "worker_group_absent"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-child-absence": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "child_groups_absent"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "cleanup-error-stops": (
            lambda case: dict(base, case=case, cleanup_errors=["injected"]),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-errors": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_errors"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "malformed-cleanup-errors": (
            lambda case: dict(base, case=case, cleanup_errors="bad"),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-timing": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_complete_monotonic"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "completion-after-deadline": (
            lambda case: dict(base, case=case, cleanup_complete_monotonic=14.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "negative-elapsed": (
            lambda case: dict(base, case=case, cleanup_elapsed_seconds=-1.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "inconsistent-elapsed": (
            lambda case: dict(base, case=case, cleanup_elapsed_seconds=1.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "wrong-cleanup-budget": (
            lambda case: dict(base, case=case, cleanup_deadline_monotonic=14.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
    }
    outcomes = {}
    cases = ("first", "second")
    for name, (runner, expected_count, expected_states) in scenarios.items():
        results = schedule_cases(runner, cases)
        states = [item.get("execution_state") for item in results]
        passed = len(results) == expected_count and states == expected_states
        outcomes[name] = {"passed": passed, "states": states}
    calls = []
    def raising_runner(case):
        calls.append(case)
        raise RuntimeError("fabricated scheduler exception")
    exception_results = schedule_cases(raising_runner, cases)
    exception_states = [
        item.get("execution_state") for item in exception_results
    ]
    outcomes["exception-stops"] = {
        "passed": calls == ["first"]
        and exception_states == ["EXECUTION_ERROR", "NOT_EXECUTED"],
        "states": exception_states,
    }
    print(json.dumps(outcomes, indent=2, sort_keys=True))
    if not all(item["passed"] for item in outcomes.values()):
        raise SystemExit("scheduler self-test failed")
    cli_parser_self_test()
    assert source_stability({"a": "1"}, {"a": "1"}) == "PROVEN"
    assert source_stability({"a": "1"}, {"a": "2"}) == "FAILED"


def main():
    pre = {"launcher": digest(LAUNCHER), "proposal": digest(PROPOSAL)}
    if pre != {"launcher": EXPECTED_LAUNCHER, "proposal": EXPECTED_PROPOSAL}:
        raise SystemExit("hash precondition failed")
    harness_paths = {
        "run_validation": Path(__file__).resolve(),
        "run_containment": Path(__file__).resolve().with_name("run_containment.py"),
    }
    source_pre = {name: digest(path) for name, path in harness_paths.items()}
    source, constants, locations, extraction_hash = extract_source()
    if (
        constants["TERM_WAIT_SECONDS"] != TERM_GRACE_SECONDS
        or constants["KILL_WAIT_SECONDS"] != KILL_GRACE_SECONDS
    ):
        raise SystemExit("extracted cleanup grace mismatch")
    MISSING_EVIDENCE.mkdir(parents=True, exist_ok=False)
    (MISSING_EVIDENCE / "extracted_supervisor_source.py").write_text(source, encoding="utf-8")
    results = schedule_cases()
    post = {"launcher": digest(LAUNCHER), "proposal": digest(PROPOSAL)}
    source_post = {name: digest(path) for name, path in harness_paths.items()}
    raw = {"batch": "missing_cases_only", "pre_hashes": pre, "post_hashes": post,
           "source_extraction_sha256": extraction_hash, "source_locations": locations,
           "harness_source_pre_hashes": source_pre,
           "harness_source_post_hashes": source_post,
           "harness_source_stability": (
               source_stability(source_pre, source_post)
           ),
           "harness_source_stability_limit": (
               "Pre/post hashes do not prove absence of transient changes during execution."
           ),
            "case_execution_seconds": CASE_EXECUTION_SECONDS,
            "watchdog_cleanup_seconds": WATCHDOG_CLEANUP_SECONDS,
            "child_wait_seconds": CHILD_WAIT_SECONDS,
             "term_grace_seconds": TERM_GRACE_SECONDS, "kill_grace_seconds": KILL_GRACE_SECONDS,
           "case_to_synthetic": CASE_TO_SYNTHETIC, "cases": results,
             "instrumentation": "External namespace Popen recording/readiness wrapper, Linux PR_SET_PDEATHSIG child lifetime guard, and named monkeypatches only; child controller configuration is recorded, not runtime-proven.",
           "assertions_failed": [r for r in results if r["assertion_failures"]]}
    (MISSING_EVIDENCE / "raw.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    failures = raw["assertions_failed"]
    if raw["harness_source_stability"] != "PROVEN":
        raise SystemExit("harness source stability failed after evidence write")
    if failures:
        raise SystemExit(f"validation assertions failed after evidence write: {len(failures)}")


if __name__ == "__main__":
    cli = parse_cli(sys.argv[1:])
    if cli["mode"] == "help":
        print_help()
    elif cli["mode"] == "worker":
        worker(cli["case"], *(Path(path) for path in cli["paths"]), cli["nonce"])
    elif cli["mode"] == "scheduler-self-test":
        scheduler_self_test()
    else:
        main()
#!/usr/bin/env python3
"""Preparation-only harness for the seven not-yet-executed supervisor cases."""
import ast
import ctypes
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "attached_assets/usbay-fda-readonly-diskutil-diagnostic.zsh"
PROPOSAL = ROOT / "attached_assets/usbay-temporary-terminal-full-disk-access-diagnostic-proposal.md"
EVIDENCE = Path(__file__).resolve().parent / "evidence"
MISSING_EVIDENCE = EVIDENCE / "missing_cases_batch"
EXPECTED_LAUNCHER = "b19bd48a797b3f5659c6fb850d4baff1792c6c73153bfec13b4eb6f5976f320b"
EXPECTED_PROPOSAL = "ef648fadc31e252ce91ff6ee754b0670e6f477b5afd8a5e4a5bc3cdcb675429c"
CHILD_WAIT_SECONDS = 0.08
TERM_GRACE_SECONDS = 2
KILL_GRACE_SECONDS = 2
WATCHDOG_CLEANUP_SECONDS = 3
CASE_EXECUTION_SECONDS = 12
MISSING_CASES = (
    "term-to-kill", "cleanup-denial", "probe-exception", "drain-exception",
    "cleanup-signal-SIGINT", "cleanup-signal-SIGTERM", "cleanup-signal-SIGHUP",
)
CASE_TO_SYNTHETIC = {
    "term-to-kill": "term_ignore_ready",
    "cleanup-denial": "sleep",
    "probe-exception": "exit0",
    "drain-exception": "exit0",
    "cleanup-signal-SIGINT": "sleep",
    "cleanup-signal-SIGTERM": "sleep",
    "cleanup-signal-SIGHUP": "sleep",
}
CONTAINMENT_ASSERTION_MARKERS = (
    "worker authorization",
    "supervisor-child record",
    "malformed ownership",
    "containment unproven",
    "watchdog did not observe clean exit",
    "owned supervisor group remained",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_stability(pre, post):
    """Assess only equality of the recorded pre/post source hashes."""
    return "PROVEN" if dict(pre) == dict(post) else "FAILED"


def parse_cli(argv):
    """Validate dispatch without touching evidence, channels, or processes."""
    args = list(argv)
    if args in (["--help"], ["-h"]):
        return {"mode": "help"}
    if args == ["--scheduler-self-test"]:
        return {"mode": "scheduler-self-test"}
    if args == []:
        return {"mode": "main"}
    if len(args) == 6 and args[0] == "--worker":
        case, ownership, result, auth, nonce = args[1:]
        if case not in MISSING_CASES or not nonce or nonce.startswith("-"):
            raise SystemExit("invalid worker case or nonce")
        paths = (ownership, result, auth)
        if any(not item or item.startswith("-") for item in paths):
            raise SystemExit("invalid worker paths")
        return {"mode": "worker", "case": case, "paths": paths, "nonce": nonce}
    raise SystemExit("unknown or malformed arguments")


def print_help():
    print("usage: run_validation.py [--scheduler-self-test|--worker CASE OWNERSHIP RESULT AUTH NONCE]")


def cli_parser_self_test():
    """Pure parser/dispatch checks; no evidence, channels, or processes."""
    side_effects = {"count": 0}
    for argv, expected in (
        (["--help"], "help"),
        (["--scheduler-self-test"], "scheduler-self-test"),
    ):
        parsed = parse_cli(argv)
        assert parsed["mode"] == expected
        assert side_effects["count"] == 0
    for argv in (
        ["--unknown"],
        ["--worker", "bad", "a", "b", "c", "n"],
        ["--worker", "term-to-kill", "a", "b", "c"],
        ["--worker", "term-to-kill", "-a", "b", "c", "n"],
        ["--worker", "term-to-kill", "a", "--b", "c", "n"],
        ["--worker", "term-to-kill", "a", "b", "c", "-n"],
    ):
        try:
            parse_cli(argv)
        except SystemExit:
            pass
        else:
            raise AssertionError("malformed CLI accepted")
        assert side_effects["count"] == 0


def extract_source():
    raw = LAUNCHER.read_text()
    py = raw.split("<<'PY'\n", 1)[1].split("\ntry:\n    final_status=main()", 1)[0]
    tree = ast.parse(py)
    chosen = [
        node for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef))
        and (not isinstance(node, ast.FunctionDef) or node.name != "main")
    ]
    source = ast.unparse(ast.Module(body=chosen, type_ignores=[])) + "\n"
    namespace = {"__name__": "extracted_supervisor"}
    exec(compile(ast.Module(body=chosen, type_ignores=[]), str(LAUNCHER), "exec"), namespace)
    locations = [f"{node.__class__.__name__}:{getattr(node, 'name', '')}" for node in chosen]
    return source, namespace, locations, hashlib.sha256(source.encode()).hexdigest()


def synthetic(kind, gate_path, nonce, worker_pid, ready_path=None):
    behavior = {
        "sleep": "time.sleep(.35)",
        "exit0": "raise SystemExit(0)",
        "term_ignore_ready": (
            "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            "pathlib.Path(sys.argv[3]).write_text('READY\\n')\n"
            "time.sleep(10)"
        ),
    }[kind]
    code = (
        "import ctypes,os,pathlib,signal,sys,time\n"
        "if ctypes.CDLL(None).prctl(1,signal.SIGKILL) != 0: raise SystemExit(91)\n"
        "if os.getppid() != int(sys.argv[4]): raise SystemExit(92)\n"
        "gate=pathlib.Path(sys.argv[1]); nonce=sys.argv[2]\n"
        "while True:\n"
        "    try:\n"
        "        if gate.read_text().strip()==nonce: break\n"
        "    except (FileNotFoundError,OSError): pass\n"
        "    time.sleep(.01)\n"
        + behavior + "\n"
    )
    return [
        sys.executable, "-c", "exec(" + repr(code) + ")",
        str(gate_path), nonce, str(ready_path or ""), str(worker_pid),
    ]


def append_json(path, item):
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(item, sort_keys=True) + "\n")
        stream.flush()


def worker(case, ownership_path, result_path, auth_path, nonce):
    while auth_path.read_text(encoding="utf-8").strip() != nonce:
        time.sleep(0.01)
    _, ns, _, _ = extract_source()
    trace = []
    stdout = tempfile.TemporaryFile()
    stderr = tempfile.TemporaryFile()
    originals = {}
    helper = None
    checkpoint = threading.Event()
    acknowledgement = threading.Event()
    ready_path = Path(str(result_path) + ".ready")
    child_gate = Path(str(result_path) + ".child-gate")
    containment = {
        "nonce": nonce,
        "worker_pid": os.getpid(),
        "controller_mechanism": "Linux prctl(PR_SET_PDEATHSIG, SIGKILL) with child PPID check",
        "records": [],
    }

    original_popen = ns["subprocess"].Popen
    def recording_popen(*args, **kwargs):
        child = original_popen(*args, **kwargs)
        record = {"pgid": None}
        try:
            record = {
                "kind": "supervisor-child", "nonce": nonce, "pid": child.pid,
                "pgid": os.getpgid(child.pid), "session_id": os.getsid(child.pid),
                "start_new_session": kwargs.get("start_new_session", False),
                "worker_pid": os.getpid(), "case": case, "child_gate": str(child_gate),
            }
            if not child_owned(record, nonce, case, os.getpid()):
                raise RuntimeError("supervisor-child ownership validation failed")
            containment["records"].append(record)
            append_json(ownership_path, record)
            child_gate.write_text(nonce + "\n", encoding="utf-8")
            if case == "term-to-kill":
                deadline = time.monotonic() + 2
                while not ready_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not ready_path.exists():
                    raise RuntimeError("TERM handler readiness was not proven")
        except BaseException:
            if isinstance(record.get("pgid"), int):
                try:
                    os.killpg(record["pgid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                child.kill()
            try:
                child.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
            raise
        return child

    ns["subprocess"].Popen = recording_popen
    if case == "cleanup-denial":
        originals["signal_group"] = ns["signal_group"]
        def denied_signal_group(pgid, sig, trace_arg, phase):
            outcome = "denied"
            ns["trace_event"](trace_arg, "injected-group-signal", phase=phase,
                              signal=int(sig), outcome=outcome)
            return outcome
        ns["signal_group"] = denied_signal_group
    elif case == "probe-exception":
        originals["group_state"] = ns["group_state"]
        def injected_probe(*args, **kwargs):
            raise RuntimeError("injected-probe")
        ns["group_state"] = injected_probe
    elif case == "drain-exception":
        originals["sigpending"] = ns["signal"].sigpending
        ns["signal"].sigpending = lambda: (_ for _ in ()).throw(RuntimeError("injected-drain"))
    elif case.startswith("cleanup-signal-"):
        originals["signal_group"] = ns["signal_group"]
        requested = {
            "cleanup-signal-SIGINT": signal.SIGINT,
            "cleanup-signal-SIGTERM": signal.SIGTERM,
            "cleanup-signal-SIGHUP": signal.SIGHUP,
        }[case]
        def synchronized_signal_group(*args):
            pgid, sig, trace_arg, phase = args
            if phase == "term" and not checkpoint.is_set():
                ns["trace_event"](trace_arg, "test-cleanup-checkpoint",
                                  phase="term", signal=int(requested))
                checkpoint.set()
                def deliver():
                    if checkpoint.wait(1):
                        os.kill(os.getpid(), requested)
                        ns["trace_event"](trace_arg, "test-cleanup-signal-sent",
                                          phase="term", signal=int(requested))
                        acknowledgement.set()
                nonlocal helper
                helper = threading.Thread(target=deliver, daemon=True)
                helper.start()
                if not acknowledgement.wait(1):
                    raise RuntimeError("cleanup signal acknowledgement timeout")
            return originals["signal_group"](*args)
        ns["signal_group"] = synchronized_signal_group

    try:
        kind = CASE_TO_SYNTHETIC[case]
        status, reason = ns["bounded"](
            synthetic(kind, child_gate, nonce, os.getpid(), ready_path),
            CHILD_WAIT_SECONDS,
            stdout,
            stderr,
            trace,
        )
        result = {"status": status, "reason": reason, "trace": trace}
    except BaseException as exc:
        result = {"worker_exception": type(exc).__name__, "message": str(exc), "trace": trace}
    finally:
        ns["subprocess"].Popen = original_popen
        for name, value in originals.items():
            if name == "sigpending":
                ns["signal"].sigpending = value
            else:
                ns[name] = value
        if helper:
            helper.join(timeout=1)
        stdout.close()
        stderr.close()
    result["containment"] = containment
    Path(result_path).write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")


def process_owned(record, nonce, case):
    return (
        record.get("nonce") == nonce and record.get("case") == case
        and isinstance(record.get("pid"), int) and record.get("pid") > 0
        and record.get("pgid") == record.get("pid")
        and record.get("session_id") == record.get("pid")
        and record.get("start_new_session") is True
    )


def child_owned(record, nonce, case, worker_pid):
    return (
        record.get("kind") == "supervisor-child"
        and record.get("worker_pid") == worker_pid
        and process_owned(record, nonce, case)
    )


def group_present(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def wait_group_absent(pgid, deadline):
    while group_present(pgid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


def parent_watchdog_cleanup(proc, worker_record, records, nonce, case,
                            watchdog, ownership_path, result_path,
                            malformed_records=None, live_handles=None,
                            group_present_fn=None, wait_group_absent_fn=None,
                            signal_fn=None, monotonic_fn=None):
    """The single parent-watchdog path used by lifecycle and focused tests."""
    group_present_fn = group_present_fn or group_present
    wait_group_absent_fn = wait_group_absent_fn or wait_group_absent
    monotonic_fn = monotonic_fn or time.monotonic
    cleanup_start = monotonic_fn()
    cleanup_deadline = cleanup_start + WATCHDOG_CLEANUP_SECONDS
    malformed_records = list(malformed_records or [])
    valid = [record for record in records
             if child_owned(record, nonce, case, proc.pid)]
    worker_owned = process_owned(worker_record, nonce, case)
    containment_ok = worker_owned and len(valid) == 1
    residual = [record for record in valid if group_present_fn(record["pgid"])]
    if residual and watchdog == "exited":
        watchdog = "residual-process"
    actions = []
    cleanup_errors = []
    if live_handles is not None:
        live_by_pid = {
            getattr(item, "record", {}).get("pid"): item
            for item in live_handles
        }
        for record in valid + [worker_record]:
            handle = live_by_pid.get(record.get("pid"))
            if (handle is None or getattr(handle, "pidfd", None) is None
                    or getattr(handle, "record", {}).get("pid") != record.get("pid")):
                cleanup_errors.append(
                    f"missing-live-handle:{record.get('pid')}")
    if watchdog != "exited" or not containment_ok:
        watchdog = watchdog if watchdog != "exited" else "containment-unproven"
        for record in valid:
            if group_present_fn(record["pgid"]):
                try:
                    if live_handles is not None:
                        handle = next((item for item in live_handles
                                       if item.record.get("pid") == record["pid"]), None)
                        if (handle is None or handle.pidfd is None
                                or handle.record.get("pid") != record["pid"]):
                            raise RuntimeError("live child handle missing or mismatched")
                        outcome = signal_fn(handle, signal.SIGKILL) if signal_fn else signal.pidfd_send_signal(handle.pidfd, signal.SIGKILL)
                    else:
                        outcome = signal_fn(record, signal.SIGKILL) if signal_fn else os.killpg(record["pgid"], signal.SIGKILL)
                    actions.append({"target": "child", "pgid": record["pgid"],
                                    "signal": int(signal.SIGKILL), "outcome": "sent"})
                except ProcessLookupError:
                    actions.append({"target": "child", "pgid": record["pgid"],
                                    "signal": int(signal.SIGKILL), "outcome": "absent"})
                except BaseException as error:
                    cleanup_errors.append(f"child-signal:{type(error).__name__}:{error}")
        if worker_owned and group_present_fn(worker_record["pgid"]):
            try:
                if live_handles is not None:
                    handle = next((item for item in live_handles
                                   if item.record.get("pid") == worker_record["pid"]), None)
                    if (handle is None or handle.pidfd is None
                            or handle.record.get("pid") != worker_record["pid"]):
                        raise RuntimeError("live worker handle missing or mismatched")
                    outcome = signal_fn(handle, signal.SIGKILL) if signal_fn else signal.pidfd_send_signal(handle.pidfd, signal.SIGKILL)
                else:
                    outcome = signal_fn(worker_record, signal.SIGKILL) if signal_fn else os.killpg(worker_record["pgid"], signal.SIGKILL)
                actions.append({"target": "worker", "pgid": worker_record["pgid"],
                                "signal": int(signal.SIGKILL), "outcome": "sent"})
            except ProcessLookupError:
                actions.append({"target": "worker", "pgid": worker_record["pgid"],
                                "signal": int(signal.SIGKILL), "outcome": "absent"})
            except BaseException as error:
                cleanup_errors.append(f"worker-signal:{type(error).__name__}:{error}")
        try:
                proc.wait(timeout=max(0, cleanup_deadline - monotonic_fn()))
        except subprocess.TimeoutExpired:
            watchdog = "worker-cleanup-timeout"
    remaining_owned_groups = [
        record for record in valid
        if not wait_group_absent_fn(record["pgid"], cleanup_deadline)
    ]
    worker_group_absent = (
        wait_group_absent_fn(worker_record["pgid"], cleanup_deadline)
        if worker_owned else False
    )
    cleanup_complete = monotonic_fn()
    cleanup_state = ("PROVEN" if worker_owned and len(valid) == 1
                     and worker_group_absent and not malformed_records
                     and not remaining_owned_groups
                     and not cleanup_errors and proc.poll() is not None
                     and cleanup_complete <= cleanup_deadline else "UNKNOWN")
    return {
        "watchdog": watchdog, "containment_ok": worker_owned and len(valid) == 1
        and not malformed_records, "worker_reaped": proc.poll() is not None,
        "residual_owned_groups": residual,
        "remaining_owned_groups": remaining_owned_groups,
         "worker_group_absent": worker_group_absent,
         "child_groups_absent": not remaining_owned_groups,
        "malformed_ownership_records": malformed_records, "valid_records": valid,
        "cleanup_actions": actions, "cleanup_errors": cleanup_errors,
        "cleanup_start_monotonic": cleanup_start,
        "cleanup_deadline_monotonic": cleanup_deadline,
        "cleanup_complete_monotonic": cleanup_complete,
        "cleanup_elapsed_seconds": cleanup_complete - cleanup_start,
        "cleanup_deadline_started": True,
        "cleanup_state": cleanup_state,
    }


def run_case(case):
    nonce = uuid.uuid4().hex
    ownership_path = MISSING_EVIDENCE / f"{case}.{nonce}.ownership.jsonl"
    result_path = MISSING_EVIDENCE / f"{case}.{nonce}.result.json"
    auth_path = MISSING_EVIDENCE / f"{case}.{nonce}.worker-authorized"
    ownership_path.touch(exist_ok=False)
    result_path.touch(exist_ok=False)
    auth_path.touch(exist_ok=False)
    cmd = [sys.executable, str(Path(__file__).resolve()), "--worker", case,
           str(ownership_path), str(result_path), str(auth_path), nonce]
    proc = subprocess.Popen(cmd, start_new_session=True)
    worker_record = {
        "kind": "worker", "nonce": nonce, "pid": proc.pid,
        "pgid": None, "session_id": None, "start_new_session": True,
        "worker_pid": os.getpid(), "case": case,
    }
    worker_authorized = False
    setup_error = None
    try:
        worker_record["pgid"] = os.getpgid(proc.pid)
        worker_record["session_id"] = os.getsid(proc.pid)
        worker_authorized = process_owned(worker_record, nonce, case)
        if not worker_authorized:
            raise RuntimeError("worker ownership validation failed")
        append_json(ownership_path, worker_record)
        auth_path.write_text(nonce + "\n", encoding="utf-8")
    except BaseException as error:
        setup_error = {"type": type(error).__name__, "message": str(error)}
        try:
            if worker_authorized and group_present(worker_record["pgid"]):
                os.killpg(worker_record["pgid"], signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
        except subprocess.TimeoutExpired:
            setup_error["cleanup"] = "worker-reap-timeout"
        return {
            "case": case,
            "nonce": nonce,
            "spawned": True,
            "worker_authorized": worker_authorized,
            "containment_ok": False,
            "watchdog": "worker-setup-failed",
            "setup_error": setup_error,
            "assertion_failures": ["worker setup/authorization failed"],
        }
    watchdog = "exited"
    try:
        proc.wait(timeout=CASE_EXECUTION_SECONDS)
    except subprocess.TimeoutExpired:
        watchdog = "watchdog-timeout"
    records = []
    malformed_records = []
    for line in ownership_path.read_text().splitlines():
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            malformed_records.append(line)
    cleanup = parent_watchdog_cleanup(
        proc, worker_record, records, nonce, case, watchdog,
        ownership_path, result_path, malformed_records,
    )
    watchdog = cleanup["watchdog"]
    valid = cleanup["valid_records"]
    remaining_owned_groups = cleanup["remaining_owned_groups"]
    containment_ok = worker_authorized and cleanup["containment_ok"]
    worker_reaped = cleanup["worker_reaped"]
    result = json.loads(result_path.read_text()) if result_path.stat().st_size else {}
    observed = {"case": case, "nonce": nonce, "watchdog": watchdog,
                "execution_state": "EXECUTED",
                "ownership_path": str(ownership_path.relative_to(ROOT)),
                "result_path": str(result_path.relative_to(ROOT)),
                "ownership_records": records, "containment_ok": containment_ok,
                "worker_reaped": worker_reaped,
                 "residual_owned_groups": cleanup["residual_owned_groups"],
                "remaining_owned_groups": remaining_owned_groups,
                 "worker_group_absent": cleanup["worker_group_absent"],
                 "child_groups_absent": cleanup["child_groups_absent"],
                 "cleanup_state": cleanup["cleanup_state"],
                 "cleanup_errors": cleanup["cleanup_errors"],
                 "cleanup_start_monotonic": cleanup["cleanup_start_monotonic"],
                 "cleanup_deadline_monotonic": cleanup["cleanup_deadline_monotonic"],
                 "cleanup_complete_monotonic": cleanup["cleanup_complete_monotonic"],
                 "cleanup_elapsed_seconds": cleanup["cleanup_elapsed_seconds"],
                 "cleanup_deadline_started": cleanup["cleanup_deadline_started"],
                "malformed_ownership_records": malformed_records,
                 "cleanup_actions": cleanup["cleanup_actions"],
                "result": result}
    expected = {
        "term-to-kill": (124, "timeout-clean", ("group-signal", "cleanup-result")),
        "cleanup-denial": (125, "timeout-cleanup-unproven", ("injected-group-signal",)),
        "probe-exception": (70, "post-wait-probe-exception-clean", ("post-wait-probe-exception",)),
        "drain-exception": (125, "pending-signal-drain-cleanup-unproven", ("pending-signal-drain-exception",)),
        "cleanup-signal-SIGINT": (130, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
        "cleanup-signal-SIGTERM": (143, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
        "cleanup-signal-SIGHUP": (129, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
    }[case]
    events = result.get("trace", [])
    names = {event.get("event") for event in events}
    observed["expected"] = {"status": expected[0], "reason": expected[1], "events": expected[2]}
    observed["assertion_failures"] = []
    if result.get("status") != expected[0] or result.get("reason") != expected[1]:
        observed["assertion_failures"].append("status/reason mismatch")
    if any(event not in names for event in expected[2]):
        observed["assertion_failures"].append("required trace event missing")
    if case.startswith("cleanup-signal-"):
        requested = {
            "cleanup-signal-SIGINT": int(signal.SIGINT),
            "cleanup-signal-SIGTERM": int(signal.SIGTERM),
            "cleanup-signal-SIGHUP": int(signal.SIGHUP),
        }[case]
        checkpoint_events = [
            e for e in events
            if e.get("event") == "test-cleanup-checkpoint"
            and e.get("phase") == "term" and e.get("signal") == requested
        ]
        sent_events = [
            e for e in events
            if e.get("event") == "test-cleanup-signal-sent"
            and e.get("phase") == "term" and e.get("signal") == requested
        ]
        delivery_events = [
            e for e in events
            if e.get("event") == "signal-delivery"
            and e.get("signal") == requested
            and e.get("stage") == "cleanup-pending-drain"
        ]
        if not (checkpoint_events and sent_events and delivery_events):
            observed["assertion_failures"].append(
                "exact cleanup signal checkpoint/sent/pending-drain proof missing"
            )
        else:
            positions = [
                next(i for i, e in enumerate(events) if e is item)
                for item in (checkpoint_events[0], sent_events[0], delivery_events[0])
            ]
            if not (positions[0] < positions[1] < positions[2]):
                observed["assertion_failures"].append(
                    "cleanup signal trace order checkpoint<sent<delivery failed"
                )
    if case == "term-to-kill":
        signals = {(e.get("phase"), e.get("signal"), e.get("outcome")) for e in events if e.get("event") == "group-signal"}
        if ("term", int(signal.SIGTERM), "sent") not in signals:
            observed["assertion_failures"].append("actual TERM sent not observed")
        if ("kill", int(signal.SIGKILL), "sent") not in signals:
            observed["assertion_failures"].append("actual KILL sent not observed")
        if not any(e.get("event") == "cleanup-result" and e.get("reason") == "kill-clean" for e in events):
            observed["assertion_failures"].append("kill-clean not observed")
    if case == "cleanup-denial":
        denials = {
            (event.get("phase"), event.get("signal"), event.get("outcome"))
            for event in events
            if event.get("event") == "injected-group-signal"
        }
        if ("term", int(signal.SIGTERM), "denied") not in denials:
            observed["assertion_failures"].append(
                "injected TERM denial not observed"
            )
        if ("kill", int(signal.SIGKILL), "denied") not in denials:
            observed["assertion_failures"].append(
                "injected KILL denial not observed"
            )
    if not worker_authorized:
        observed["assertion_failures"].append("worker authorization handshake failed")
    if len(valid) != 1:
        observed["assertion_failures"].append("expected exactly one valid supervisor-child record")
    if malformed_records:
        observed["assertion_failures"].append("malformed ownership record")
    if not containment_ok:
        observed["assertion_failures"].append("containment unproven")
    if watchdog != "exited":
        observed["assertion_failures"].append("watchdog did not observe clean exit")
    if remaining_owned_groups:
        observed["assertion_failures"].append("owned supervisor group remained present")
    return observed


def containment_blocker(result):
    if not isinstance(result, dict):
        return "case result is not an object"
    if result.get("containment_ok") is not True:
        return "containment_ok is not proven true"
    if result.get("worker_reaped") is not True:
        return "worker reaping is not proven"
    if result.get("cleanup_state") != "PROVEN":
        return "cleanup state is missing or not proven"
    if result.get("worker_group_absent") is not True:
        return "worker group absence is not proven"
    if result.get("child_groups_absent") is not True:
        return "child group absence is not proven"
    if not isinstance(result.get("cleanup_errors"), list):
        return "cleanup errors are missing or malformed"
    if result["cleanup_errors"]:
        return "cleanup errors are present"
    if result.get("cleanup_deadline_started") is not True:
        return "cleanup deadline evidence is missing"
    timing = [
        result.get("cleanup_start_monotonic"),
        result.get("cleanup_deadline_monotonic"),
        result.get("cleanup_complete_monotonic"),
        result.get("cleanup_elapsed_seconds"),
    ]
    if any(isinstance(value, bool) or not isinstance(value, (int, float))
           or not math.isfinite(value) for value in timing):
        return "cleanup timing evidence is missing or malformed"
    start, deadline, complete, elapsed = timing
    if not (start <= complete <= deadline and elapsed >= 0):
        return "cleanup timing is contradictory"
    tolerance = 1e-6
    if abs(elapsed - (complete - start)) > tolerance:
        return "cleanup elapsed time is inconsistent"
    if abs((deadline - start) - WATCHDOG_CLEANUP_SECONDS) > tolerance:
        return "cleanup deadline budget is inconsistent"
    for field in (
        "remaining_owned_groups",
        "malformed_ownership_records",
        "assertion_failures",
    ):
        if not isinstance(result.get(field), list):
            return f"{field} is missing or malformed"
    if result["remaining_owned_groups"]:
        return "owned supervisor groups remain present"
    if result["malformed_ownership_records"]:
        return "ownership evidence is malformed"
    for failure in result["assertion_failures"]:
        if not isinstance(failure, str):
            return "assertion failure evidence is malformed"
        if any(marker in failure for marker in CONTAINMENT_ASSERTION_MARKERS):
            return f"containment assertion failed: {failure}"
    if result.get("watchdog") == "worker-cleanup-timeout":
        return "watchdog could not reap the worker"
    return None


def schedule_cases(case_runner=run_case, cases=MISSING_CASES):
    results = []
    for index, case in enumerate(cases):
        try:
            result = case_runner(case)
        except BaseException as error:
            result = {
                "case": case,
                "execution_state": "EXECUTION_ERROR",
                "containment_ok": False,
                "worker_reaped": False,
                "remaining_owned_groups": [],
                "malformed_ownership_records": [],
                "assertion_failures": ["unexpected case exception"],
                "exception_type": type(error).__name__,
                "exception_message": str(error),
            }
        results.append(result)
        blocker = containment_blocker(result)
        if blocker is None:
            continue
        for remaining in cases[index + 1:]:
            results.append({
                "case": remaining,
                "execution_state": "NOT_EXECUTED",
                "blocked_by": case,
                "blocking_reason": blocker,
                "containment_ok": False,
                "assertion_failures": ["not executed after containment stop"],
            })
        break
    return results


def scheduler_self_test():
    base = {
        "execution_state": "EXECUTED",
        "containment_ok": True,
        "worker_reaped": True,
        "remaining_owned_groups": [],
        "malformed_ownership_records": [],
        "assertion_failures": [],
        "watchdog": "exited",
        "cleanup_state": "PROVEN",
        "cleanup_errors": [],
        "cleanup_deadline_started": True,
        "cleanup_start_monotonic": 10.0,
        "cleanup_deadline_monotonic": 13.0,
        "cleanup_complete_monotonic": 12.0,
        "cleanup_elapsed_seconds": 2.0,
        "worker_group_absent": True,
        "child_groups_absent": True,
    }
    scenarios = {
        "proven-permits-next": (
            lambda case: dict(base, case=case),
            2,
            ["EXECUTED", "EXECUTED"],
        ),
        "false-stops": (
            lambda case: dict(base, case=case, containment_ok=False),
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-stops": (
            lambda case: {
                key: value for key, value in dict(base, case=case).items()
                if key != "containment_ok"
            },
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "contradiction-stops": (
            lambda case: dict(
                base,
                case=case,
                remaining_owned_groups=[{"pgid": 999999}],
            ),
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-state": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_state"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "unknown-cleanup-state": (
            lambda case: dict(base, case=case, cleanup_state="UNKNOWN"),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-worker-absence": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "worker_group_absent"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-child-absence": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "child_groups_absent"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "cleanup-error-stops": (
            lambda case: dict(base, case=case, cleanup_errors=["injected"]),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-errors": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_errors"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "malformed-cleanup-errors": (
            lambda case: dict(base, case=case, cleanup_errors="bad"),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-timing": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_complete_monotonic"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "completion-after-deadline": (
            lambda case: dict(base, case=case, cleanup_complete_monotonic=14.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "negative-elapsed": (
            lambda case: dict(base, case=case, cleanup_elapsed_seconds=-1.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "inconsistent-elapsed": (
            lambda case: dict(base, case=case, cleanup_elapsed_seconds=1.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "wrong-cleanup-budget": (
            lambda case: dict(base, case=case, cleanup_deadline_monotonic=14.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
    }
    outcomes = {}
    cases = ("first", "second")
    for name, (runner, expected_count, expected_states) in scenarios.items():
        results = schedule_cases(runner, cases)
        states = [item.get("execution_state") for item in results]
        passed = len(results) == expected_count and states == expected_states
        outcomes[name] = {"passed": passed, "states": states}
    calls = []
    def raising_runner(case):
        calls.append(case)
        raise RuntimeError("fabricated scheduler exception")
    exception_results = schedule_cases(raising_runner, cases)
    exception_states = [
        item.get("execution_state") for item in exception_results
    ]
    outcomes["exception-stops"] = {
        "passed": calls == ["first"]
        and exception_states == ["EXECUTION_ERROR", "NOT_EXECUTED"],
        "states": exception_states,
    }
    print(json.dumps(outcomes, indent=2, sort_keys=True))
    if not all(item["passed"] for item in outcomes.values()):
        raise SystemExit("scheduler self-test failed")
    cli_parser_self_test()
    assert source_stability({"a": "1"}, {"a": "1"}) == "PROVEN"
    assert source_stability({"a": "1"}, {"a": "2"}) == "FAILED"


def main():
    pre = {"launcher": digest(LAUNCHER), "proposal": digest(PROPOSAL)}
    if pre != {"launcher": EXPECTED_LAUNCHER, "proposal": EXPECTED_PROPOSAL}:
        raise SystemExit("hash precondition failed")
    harness_paths = {
        "run_validation": Path(__file__).resolve(),
        "run_containment": Path(__file__).resolve().with_name("run_containment.py"),
    }
    source_pre = {name: digest(path) for name, path in harness_paths.items()}
    source, constants, locations, extraction_hash = extract_source()
    if (
        constants["TERM_WAIT_SECONDS"] != TERM_GRACE_SECONDS
        or constants["KILL_WAIT_SECONDS"] != KILL_GRACE_SECONDS
    ):
        raise SystemExit("extracted cleanup grace mismatch")
    MISSING_EVIDENCE.mkdir(parents=True, exist_ok=False)
    (MISSING_EVIDENCE / "extracted_supervisor_source.py").write_text(source, encoding="utf-8")
    results = schedule_cases()
    post = {"launcher": digest(LAUNCHER), "proposal": digest(PROPOSAL)}
    source_post = {name: digest(path) for name, path in harness_paths.items()}
    raw = {"batch": "missing_cases_only", "pre_hashes": pre, "post_hashes": post,
           "source_extraction_sha256": extraction_hash, "source_locations": locations,
           "harness_source_pre_hashes": source_pre,
           "harness_source_post_hashes": source_post,
           "harness_source_stability": (
               source_stability(source_pre, source_post)
           ),
           "harness_source_stability_limit": (
               "Pre/post hashes do not prove absence of transient changes during execution."
           ),
            "case_execution_seconds": CASE_EXECUTION_SECONDS,
            "watchdog_cleanup_seconds": WATCHDOG_CLEANUP_SECONDS,
            "child_wait_seconds": CHILD_WAIT_SECONDS,
             "term_grace_seconds": TERM_GRACE_SECONDS, "kill_grace_seconds": KILL_GRACE_SECONDS,
           "case_to_synthetic": CASE_TO_SYNTHETIC, "cases": results,
             "instrumentation": "External namespace Popen recording/readiness wrapper, Linux PR_SET_PDEATHSIG child lifetime guard, and named monkeypatches only; child controller configuration is recorded, not runtime-proven.",
           "assertions_failed": [r for r in results if r["assertion_failures"]]}
    (MISSING_EVIDENCE / "raw.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    failures = raw["assertions_failed"]
    if raw["harness_source_stability"] != "PROVEN":
        raise SystemExit("harness source stability failed after evidence write")
    if failures:
        raise SystemExit(f"validation assertions failed after evidence write: {len(failures)}")


if __name__ == "__main__":
    cli = parse_cli(sys.argv[1:])
    if cli["mode"] == "help":
        print_help()
    elif cli["mode"] == "worker":
        worker(cli["case"], *(Path(path) for path in cli["paths"]), cli["nonce"])
    elif cli["mode"] == "scheduler-self-test":
        scheduler_self_test()
    else:
        main()
#!/usr/bin/env python3
"""Preparation-only harness for the seven not-yet-executed supervisor cases."""
import ast
import ctypes
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "attached_assets/usbay-fda-readonly-diskutil-diagnostic.zsh"
PROPOSAL = ROOT / "attached_assets/usbay-temporary-terminal-full-disk-access-diagnostic-proposal.md"
EVIDENCE = Path(__file__).resolve().parent / "evidence"
MISSING_EVIDENCE = EVIDENCE / "missing_cases_batch"
EXPECTED_LAUNCHER = "b19bd48a797b3f5659c6fb850d4baff1792c6c73153bfec13b4eb6f5976f320b"
EXPECTED_PROPOSAL = "ef648fadc31e252ce91ff6ee754b0670e6f477b5afd8a5e4a5bc3cdcb675429c"
CHILD_WAIT_SECONDS = 0.08
TERM_GRACE_SECONDS = 2
KILL_GRACE_SECONDS = 2
WATCHDOG_CLEANUP_SECONDS = 3
CASE_EXECUTION_SECONDS = 12
MISSING_CASES = (
    "term-to-kill", "cleanup-denial", "probe-exception", "drain-exception",
    "cleanup-signal-SIGINT", "cleanup-signal-SIGTERM", "cleanup-signal-SIGHUP",
)
CASE_TO_SYNTHETIC = {
    "term-to-kill": "term_ignore_ready",
    "cleanup-denial": "sleep",
    "probe-exception": "exit0",
    "drain-exception": "exit0",
    "cleanup-signal-SIGINT": "sleep",
    "cleanup-signal-SIGTERM": "sleep",
    "cleanup-signal-SIGHUP": "sleep",
}
CONTAINMENT_ASSERTION_MARKERS = (
    "worker authorization",
    "supervisor-child record",
    "malformed ownership",
    "containment unproven",
    "watchdog did not observe clean exit",
    "owned supervisor group remained",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_stability(pre, post):
    """Assess only equality of the recorded pre/post source hashes."""
    return "PROVEN" if dict(pre) == dict(post) else "FAILED"


def parse_cli(argv):
    """Validate dispatch without touching evidence, channels, or processes."""
    args = list(argv)
    if args in (["--help"], ["-h"]):
        return {"mode": "help"}
    if args == ["--scheduler-self-test"]:
        return {"mode": "scheduler-self-test"}
    if args == []:
        return {"mode": "main"}
    if len(args) == 6 and args[0] == "--worker":
        case, ownership, result, auth, nonce = args[1:]
        if case not in MISSING_CASES or not nonce or nonce.startswith("-"):
            raise SystemExit("invalid worker case or nonce")
        paths = (ownership, result, auth)
        if any(not item or item.startswith("-") for item in paths):
            raise SystemExit("invalid worker paths")
        return {"mode": "worker", "case": case, "paths": paths, "nonce": nonce}
    raise SystemExit("unknown or malformed arguments")


def print_help():
    print("usage: run_validation.py [--scheduler-self-test|--worker CASE OWNERSHIP RESULT AUTH NONCE]")


def cli_parser_self_test():
    """Pure parser/dispatch checks; no evidence, channels, or processes."""
    side_effects = {"count": 0}
    for argv, expected in (
        (["--help"], "help"),
        (["--scheduler-self-test"], "scheduler-self-test"),
    ):
        parsed = parse_cli(argv)
        assert parsed["mode"] == expected
        assert side_effects["count"] == 0
    for argv in (
        ["--unknown"],
        ["--worker", "bad", "a", "b", "c", "n"],
        ["--worker", "term-to-kill", "a", "b", "c"],
        ["--worker", "term-to-kill", "-a", "b", "c", "n"],
        ["--worker", "term-to-kill", "a", "--b", "c", "n"],
        ["--worker", "term-to-kill", "a", "b", "c", "-n"],
    ):
        try:
            parse_cli(argv)
        except SystemExit:
            pass
        else:
            raise AssertionError("malformed CLI accepted")
        assert side_effects["count"] == 0


def extract_source():
    raw = LAUNCHER.read_text()
    py = raw.split("<<'PY'\n", 1)[1].split("\ntry:\n    final_status=main()", 1)[0]
    tree = ast.parse(py)
    chosen = [
        node for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef))
        and (not isinstance(node, ast.FunctionDef) or node.name != "main")
    ]
    source = ast.unparse(ast.Module(body=chosen, type_ignores=[])) + "\n"
    namespace = {"__name__": "extracted_supervisor"}
    exec(compile(ast.Module(body=chosen, type_ignores=[]), str(LAUNCHER), "exec"), namespace)
    locations = [f"{node.__class__.__name__}:{getattr(node, 'name', '')}" for node in chosen]
    return source, namespace, locations, hashlib.sha256(source.encode()).hexdigest()


def synthetic(kind, gate_path, nonce, worker_pid, ready_path=None):
    behavior = {
        "sleep": "time.sleep(.35)",
        "exit0": "raise SystemExit(0)",
        "term_ignore_ready": (
            "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            "pathlib.Path(sys.argv[3]).write_text('READY\\n')\n"
            "time.sleep(10)"
        ),
    }[kind]
    code = (
        "import ctypes,os,pathlib,signal,sys,time\n"
        "if ctypes.CDLL(None).prctl(1,signal.SIGKILL) != 0: raise SystemExit(91)\n"
        "if os.getppid() != int(sys.argv[4]): raise SystemExit(92)\n"
        "gate=pathlib.Path(sys.argv[1]); nonce=sys.argv[2]\n"
        "while True:\n"
        "    try:\n"
        "        if gate.read_text().strip()==nonce: break\n"
        "    except (FileNotFoundError,OSError): pass\n"
        "    time.sleep(.01)\n"
        + behavior + "\n"
    )
    return [
        sys.executable, "-c", "exec(" + repr(code) + ")",
        str(gate_path), nonce, str(ready_path or ""), str(worker_pid),
    ]


def append_json(path, item):
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(item, sort_keys=True) + "\n")
        stream.flush()


def worker(case, ownership_path, result_path, auth_path, nonce):
    while auth_path.read_text(encoding="utf-8").strip() != nonce:
        time.sleep(0.01)
    _, ns, _, _ = extract_source()
    trace = []
    stdout = tempfile.TemporaryFile()
    stderr = tempfile.TemporaryFile()
    originals = {}
    helper = None
    checkpoint = threading.Event()
    acknowledgement = threading.Event()
    ready_path = Path(str(result_path) + ".ready")
    child_gate = Path(str(result_path) + ".child-gate")
    containment = {
        "nonce": nonce,
        "worker_pid": os.getpid(),
        "controller_mechanism": "Linux prctl(PR_SET_PDEATHSIG, SIGKILL) with child PPID check",
        "records": [],
    }

    original_popen = ns["subprocess"].Popen
    def recording_popen(*args, **kwargs):
        child = original_popen(*args, **kwargs)
        record = {"pgid": None}
        try:
            record = {
                "kind": "supervisor-child", "nonce": nonce, "pid": child.pid,
                "pgid": os.getpgid(child.pid), "session_id": os.getsid(child.pid),
                "start_new_session": kwargs.get("start_new_session", False),
                "worker_pid": os.getpid(), "case": case, "child_gate": str(child_gate),
            }
            if not child_owned(record, nonce, case, os.getpid()):
                raise RuntimeError("supervisor-child ownership validation failed")
            containment["records"].append(record)
            append_json(ownership_path, record)
            child_gate.write_text(nonce + "\n", encoding="utf-8")
            if case == "term-to-kill":
                deadline = time.monotonic() + 2
                while not ready_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not ready_path.exists():
                    raise RuntimeError("TERM handler readiness was not proven")
        except BaseException:
            if isinstance(record.get("pgid"), int):
                try:
                    os.killpg(record["pgid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                child.kill()
            try:
                child.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
            raise
        return child

    ns["subprocess"].Popen = recording_popen
    if case == "cleanup-denial":
        originals["signal_group"] = ns["signal_group"]
        def denied_signal_group(pgid, sig, trace_arg, phase):
            outcome = "denied"
            ns["trace_event"](trace_arg, "injected-group-signal", phase=phase,
                              signal=int(sig), outcome=outcome)
            return outcome
        ns["signal_group"] = denied_signal_group
    elif case == "probe-exception":
        originals["group_state"] = ns["group_state"]
        def injected_probe(*args, **kwargs):
            raise RuntimeError("injected-probe")
        ns["group_state"] = injected_probe
    elif case == "drain-exception":
        originals["sigpending"] = ns["signal"].sigpending
        ns["signal"].sigpending = lambda: (_ for _ in ()).throw(RuntimeError("injected-drain"))
    elif case.startswith("cleanup-signal-"):
        originals["signal_group"] = ns["signal_group"]
        requested = {
            "cleanup-signal-SIGINT": signal.SIGINT,
            "cleanup-signal-SIGTERM": signal.SIGTERM,
            "cleanup-signal-SIGHUP": signal.SIGHUP,
        }[case]
        def synchronized_signal_group(*args):
            pgid, sig, trace_arg, phase = args
            if phase == "term" and not checkpoint.is_set():
                ns["trace_event"](trace_arg, "test-cleanup-checkpoint",
                                  phase="term", signal=int(requested))
                checkpoint.set()
                def deliver():
                    if checkpoint.wait(1):
                        os.kill(os.getpid(), requested)
                        ns["trace_event"](trace_arg, "test-cleanup-signal-sent",
                                          phase="term", signal=int(requested))
                        acknowledgement.set()
                nonlocal helper
                helper = threading.Thread(target=deliver, daemon=True)
                helper.start()
                if not acknowledgement.wait(1):
                    raise RuntimeError("cleanup signal acknowledgement timeout")
            return originals["signal_group"](*args)
        ns["signal_group"] = synchronized_signal_group

    try:
        kind = CASE_TO_SYNTHETIC[case]
        status, reason = ns["bounded"](
            synthetic(kind, child_gate, nonce, os.getpid(), ready_path),
            CHILD_WAIT_SECONDS,
            stdout,
            stderr,
            trace,
        )
        result = {"status": status, "reason": reason, "trace": trace}
    except BaseException as exc:
        result = {"worker_exception": type(exc).__name__, "message": str(exc), "trace": trace}
    finally:
        ns["subprocess"].Popen = original_popen
        for name, value in originals.items():
            if name == "sigpending":
                ns["signal"].sigpending = value
            else:
                ns[name] = value
        if helper:
            helper.join(timeout=1)
        stdout.close()
        stderr.close()
    result["containment"] = containment
    Path(result_path).write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")


def process_owned(record, nonce, case):
    return (
        record.get("nonce") == nonce and record.get("case") == case
        and isinstance(record.get("pid"), int) and record.get("pid") > 0
        and record.get("pgid") == record.get("pid")
        and record.get("session_id") == record.get("pid")
        and record.get("start_new_session") is True
    )


def child_owned(record, nonce, case, worker_pid):
    return (
        record.get("kind") == "supervisor-child"
        and record.get("worker_pid") == worker_pid
        and process_owned(record, nonce, case)
    )


def group_present(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def wait_group_absent(pgid, deadline):
    while group_present(pgid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


def parent_watchdog_cleanup(proc, worker_record, records, nonce, case,
                            watchdog, ownership_path, result_path,
                            malformed_records=None, live_handles=None,
                            group_present_fn=None, wait_group_absent_fn=None,
                            signal_fn=None, monotonic_fn=None):
    """The single parent-watchdog path used by lifecycle and focused tests."""
    group_present_fn = group_present_fn or group_present
    wait_group_absent_fn = wait_group_absent_fn or wait_group_absent
    monotonic_fn = monotonic_fn or time.monotonic
    cleanup_start = monotonic_fn()
    cleanup_deadline = cleanup_start + WATCHDOG_CLEANUP_SECONDS
    malformed_records = list(malformed_records or [])
    valid = [record for record in records
             if child_owned(record, nonce, case, proc.pid)]
    worker_owned = process_owned(worker_record, nonce, case)
    containment_ok = worker_owned and len(valid) == 1
    residual = [record for record in valid if group_present_fn(record["pgid"])]
    if residual and watchdog == "exited":
        watchdog = "residual-process"
    actions = []
    cleanup_errors = []
    if live_handles is not None:
        live_by_pid = {
            getattr(item, "record", {}).get("pid"): item
            for item in live_handles
        }
        for record in valid + [worker_record]:
            handle = live_by_pid.get(record.get("pid"))
            if (handle is None or getattr(handle, "pidfd", None) is None
                    or getattr(handle, "record", {}).get("pid") != record.get("pid")):
                cleanup_errors.append(
                    f"missing-live-handle:{record.get('pid')}")
    if watchdog != "exited" or not containment_ok:
        watchdog = watchdog if watchdog != "exited" else "containment-unproven"
        for record in valid:
            if group_present_fn(record["pgid"]):
                try:
                    if live_handles is not None:
                        handle = next((item for item in live_handles
                                       if item.record.get("pid") == record["pid"]), None)
                        if (handle is None or handle.pidfd is None
                                or handle.record.get("pid") != record["pid"]):
                            raise RuntimeError("live child handle missing or mismatched")
                        outcome = signal_fn(handle, signal.SIGKILL) if signal_fn else signal.pidfd_send_signal(handle.pidfd, signal.SIGKILL)
                    else:
                        outcome = signal_fn(record, signal.SIGKILL) if signal_fn else os.killpg(record["pgid"], signal.SIGKILL)
                    actions.append({"target": "child", "pgid": record["pgid"],
                                    "signal": int(signal.SIGKILL), "outcome": "sent"})
                except ProcessLookupError:
                    actions.append({"target": "child", "pgid": record["pgid"],
                                    "signal": int(signal.SIGKILL), "outcome": "absent"})
                except BaseException as error:
                    cleanup_errors.append(f"child-signal:{type(error).__name__}:{error}")
        if worker_owned and group_present_fn(worker_record["pgid"]):
            try:
                if live_handles is not None:
                    handle = next((item for item in live_handles
                                   if item.record.get("pid") == worker_record["pid"]), None)
                    if (handle is None or handle.pidfd is None
                            or handle.record.get("pid") != worker_record["pid"]):
                        raise RuntimeError("live worker handle missing or mismatched")
                    outcome = signal_fn(handle, signal.SIGKILL) if signal_fn else signal.pidfd_send_signal(handle.pidfd, signal.SIGKILL)
                else:
                    outcome = signal_fn(worker_record, signal.SIGKILL) if signal_fn else os.killpg(worker_record["pgid"], signal.SIGKILL)
                actions.append({"target": "worker", "pgid": worker_record["pgid"],
                                "signal": int(signal.SIGKILL), "outcome": "sent"})
            except ProcessLookupError:
                actions.append({"target": "worker", "pgid": worker_record["pgid"],
                                "signal": int(signal.SIGKILL), "outcome": "absent"})
            except BaseException as error:
                cleanup_errors.append(f"worker-signal:{type(error).__name__}:{error}")
        try:
                proc.wait(timeout=max(0, cleanup_deadline - monotonic_fn()))
        except subprocess.TimeoutExpired:
            watchdog = "worker-cleanup-timeout"
    remaining_owned_groups = [
        record for record in valid
        if not wait_group_absent_fn(record["pgid"], cleanup_deadline)
    ]
    worker_group_absent = (
        wait_group_absent_fn(worker_record["pgid"], cleanup_deadline)
        if worker_owned else False
    )
    cleanup_complete = monotonic_fn()
    cleanup_state = ("PROVEN" if worker_owned and len(valid) == 1
                     and worker_group_absent and not malformed_records
                     and not remaining_owned_groups
                     and not cleanup_errors and proc.poll() is not None
                     and cleanup_complete <= cleanup_deadline else "UNKNOWN")
    return {
        "watchdog": watchdog, "containment_ok": worker_owned and len(valid) == 1
        and not malformed_records, "worker_reaped": proc.poll() is not None,
        "residual_owned_groups": residual,
        "remaining_owned_groups": remaining_owned_groups,
         "worker_group_absent": worker_group_absent,
         "child_groups_absent": not remaining_owned_groups,
        "malformed_ownership_records": malformed_records, "valid_records": valid,
        "cleanup_actions": actions, "cleanup_errors": cleanup_errors,
        "cleanup_start_monotonic": cleanup_start,
        "cleanup_deadline_monotonic": cleanup_deadline,
        "cleanup_complete_monotonic": cleanup_complete,
        "cleanup_elapsed_seconds": cleanup_complete - cleanup_start,
        "cleanup_deadline_started": True,
        "cleanup_state": cleanup_state,
    }


def run_case(case):
    nonce = uuid.uuid4().hex
    ownership_path = MISSING_EVIDENCE / f"{case}.{nonce}.ownership.jsonl"
    result_path = MISSING_EVIDENCE / f"{case}.{nonce}.result.json"
    auth_path = MISSING_EVIDENCE / f"{case}.{nonce}.worker-authorized"
    ownership_path.touch(exist_ok=False)
    result_path.touch(exist_ok=False)
    auth_path.touch(exist_ok=False)
    cmd = [sys.executable, str(Path(__file__).resolve()), "--worker", case,
           str(ownership_path), str(result_path), str(auth_path), nonce]
    proc = subprocess.Popen(cmd, start_new_session=True)
    worker_record = {
        "kind": "worker", "nonce": nonce, "pid": proc.pid,
        "pgid": None, "session_id": None, "start_new_session": True,
        "worker_pid": os.getpid(), "case": case,
    }
    worker_authorized = False
    setup_error = None
    try:
        worker_record["pgid"] = os.getpgid(proc.pid)
        worker_record["session_id"] = os.getsid(proc.pid)
        worker_authorized = process_owned(worker_record, nonce, case)
        if not worker_authorized:
            raise RuntimeError("worker ownership validation failed")
        append_json(ownership_path, worker_record)
        auth_path.write_text(nonce + "\n", encoding="utf-8")
    except BaseException as error:
        setup_error = {"type": type(error).__name__, "message": str(error)}
        try:
            if worker_authorized and group_present(worker_record["pgid"]):
                os.killpg(worker_record["pgid"], signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
        except subprocess.TimeoutExpired:
            setup_error["cleanup"] = "worker-reap-timeout"
        return {
            "case": case,
            "nonce": nonce,
            "spawned": True,
            "worker_authorized": worker_authorized,
            "containment_ok": False,
            "watchdog": "worker-setup-failed",
            "setup_error": setup_error,
            "assertion_failures": ["worker setup/authorization failed"],
        }
    watchdog = "exited"
    try:
        proc.wait(timeout=CASE_EXECUTION_SECONDS)
    except subprocess.TimeoutExpired:
        watchdog = "watchdog-timeout"
    records = []
    malformed_records = []
    for line in ownership_path.read_text().splitlines():
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            malformed_records.append(line)
    cleanup = parent_watchdog_cleanup(
        proc, worker_record, records, nonce, case, watchdog,
        ownership_path, result_path, malformed_records,
    )
    watchdog = cleanup["watchdog"]
    valid = cleanup["valid_records"]
    remaining_owned_groups = cleanup["remaining_owned_groups"]
    containment_ok = worker_authorized and cleanup["containment_ok"]
    worker_reaped = cleanup["worker_reaped"]
    result = json.loads(result_path.read_text()) if result_path.stat().st_size else {}
    observed = {"case": case, "nonce": nonce, "watchdog": watchdog,
                "execution_state": "EXECUTED",
                "ownership_path": str(ownership_path.relative_to(ROOT)),
                "result_path": str(result_path.relative_to(ROOT)),
                "ownership_records": records, "containment_ok": containment_ok,
                "worker_reaped": worker_reaped,
                 "residual_owned_groups": cleanup["residual_owned_groups"],
                "remaining_owned_groups": remaining_owned_groups,
                 "worker_group_absent": cleanup["worker_group_absent"],
                 "child_groups_absent": cleanup["child_groups_absent"],
                 "cleanup_state": cleanup["cleanup_state"],
                 "cleanup_errors": cleanup["cleanup_errors"],
                 "cleanup_start_monotonic": cleanup["cleanup_start_monotonic"],
                 "cleanup_deadline_monotonic": cleanup["cleanup_deadline_monotonic"],
                 "cleanup_complete_monotonic": cleanup["cleanup_complete_monotonic"],
                 "cleanup_elapsed_seconds": cleanup["cleanup_elapsed_seconds"],
                 "cleanup_deadline_started": cleanup["cleanup_deadline_started"],
                "malformed_ownership_records": malformed_records,
                 "cleanup_actions": cleanup["cleanup_actions"],
                "result": result}
    expected = {
        "term-to-kill": (124, "timeout-clean", ("group-signal", "cleanup-result")),
        "cleanup-denial": (125, "timeout-cleanup-unproven", ("injected-group-signal",)),
        "probe-exception": (70, "post-wait-probe-exception-clean", ("post-wait-probe-exception",)),
        "drain-exception": (125, "pending-signal-drain-cleanup-unproven", ("pending-signal-drain-exception",)),
        "cleanup-signal-SIGINT": (130, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
        "cleanup-signal-SIGTERM": (143, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
        "cleanup-signal-SIGHUP": (129, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
    }[case]
    events = result.get("trace", [])
    names = {event.get("event") for event in events}
    observed["expected"] = {"status": expected[0], "reason": expected[1], "events": expected[2]}
    observed["assertion_failures"] = []
    if result.get("status") != expected[0] or result.get("reason") != expected[1]:
        observed["assertion_failures"].append("status/reason mismatch")
    if any(event not in names for event in expected[2]):
        observed["assertion_failures"].append("required trace event missing")
    if case.startswith("cleanup-signal-"):
        requested = {
            "cleanup-signal-SIGINT": int(signal.SIGINT),
            "cleanup-signal-SIGTERM": int(signal.SIGTERM),
            "cleanup-signal-SIGHUP": int(signal.SIGHUP),
        }[case]
        checkpoint_events = [
            e for e in events
            if e.get("event") == "test-cleanup-checkpoint"
            and e.get("phase") == "term" and e.get("signal") == requested
        ]
        sent_events = [
            e for e in events
            if e.get("event") == "test-cleanup-signal-sent"
            and e.get("phase") == "term" and e.get("signal") == requested
        ]
        delivery_events = [
            e for e in events
            if e.get("event") == "signal-delivery"
            and e.get("signal") == requested
            and e.get("stage") == "cleanup-pending-drain"
        ]
        if not (checkpoint_events and sent_events and delivery_events):
            observed["assertion_failures"].append(
                "exact cleanup signal checkpoint/sent/pending-drain proof missing"
            )
        else:
            positions = [
                next(i for i, e in enumerate(events) if e is item)
                for item in (checkpoint_events[0], sent_events[0], delivery_events[0])
            ]
            if not (positions[0] < positions[1] < positions[2]):
                observed["assertion_failures"].append(
                    "cleanup signal trace order checkpoint<sent<delivery failed"
                )
    if case == "term-to-kill":
        signals = {(e.get("phase"), e.get("signal"), e.get("outcome")) for e in events if e.get("event") == "group-signal"}
        if ("term", int(signal.SIGTERM), "sent") not in signals:
            observed["assertion_failures"].append("actual TERM sent not observed")
        if ("kill", int(signal.SIGKILL), "sent") not in signals:
            observed["assertion_failures"].append("actual KILL sent not observed")
        if not any(e.get("event") == "cleanup-result" and e.get("reason") == "kill-clean" for e in events):
            observed["assertion_failures"].append("kill-clean not observed")
    if case == "cleanup-denial":
        denials = {
            (event.get("phase"), event.get("signal"), event.get("outcome"))
            for event in events
            if event.get("event") == "injected-group-signal"
        }
        if ("term", int(signal.SIGTERM), "denied") not in denials:
            observed["assertion_failures"].append(
                "injected TERM denial not observed"
            )
        if ("kill", int(signal.SIGKILL), "denied") not in denials:
            observed["assertion_failures"].append(
                "injected KILL denial not observed"
            )
    if not worker_authorized:
        observed["assertion_failures"].append("worker authorization handshake failed")
    if len(valid) != 1:
        observed["assertion_failures"].append("expected exactly one valid supervisor-child record")
    if malformed_records:
        observed["assertion_failures"].append("malformed ownership record")
    if not containment_ok:
        observed["assertion_failures"].append("containment unproven")
    if watchdog != "exited":
        observed["assertion_failures"].append("watchdog did not observe clean exit")
    if remaining_owned_groups:
        observed["assertion_failures"].append("owned supervisor group remained present")
    return observed


def containment_blocker(result):
    if not isinstance(result, dict):
        return "case result is not an object"
    if result.get("containment_ok") is not True:
        return "containment_ok is not proven true"
    if result.get("worker_reaped") is not True:
        return "worker reaping is not proven"
    if result.get("cleanup_state") != "PROVEN":
        return "cleanup state is missing or not proven"
    if result.get("worker_group_absent") is not True:
        return "worker group absence is not proven"
    if result.get("child_groups_absent") is not True:
        return "child group absence is not proven"
    if not isinstance(result.get("cleanup_errors"), list):
        return "cleanup errors are missing or malformed"
    if result["cleanup_errors"]:
        return "cleanup errors are present"
    if result.get("cleanup_deadline_started") is not True:
        return "cleanup deadline evidence is missing"
    timing = [
        result.get("cleanup_start_monotonic"),
        result.get("cleanup_deadline_monotonic"),
        result.get("cleanup_complete_monotonic"),
        result.get("cleanup_elapsed_seconds"),
    ]
    if any(isinstance(value, bool) or not isinstance(value, (int, float))
           or not math.isfinite(value) for value in timing):
        return "cleanup timing evidence is missing or malformed"
    start, deadline, complete, elapsed = timing
    if not (start <= complete <= deadline and elapsed >= 0):
        return "cleanup timing is contradictory"
    tolerance = 1e-6
    if abs(elapsed - (complete - start)) > tolerance:
        return "cleanup elapsed time is inconsistent"
    if abs((deadline - start) - WATCHDOG_CLEANUP_SECONDS) > tolerance:
        return "cleanup deadline budget is inconsistent"
    for field in (
        "remaining_owned_groups",
        "malformed_ownership_records",
        "assertion_failures",
    ):
        if not isinstance(result.get(field), list):
            return f"{field} is missing or malformed"
    if result["remaining_owned_groups"]:
        return "owned supervisor groups remain present"
    if result["malformed_ownership_records"]:
        return "ownership evidence is malformed"
    for failure in result["assertion_failures"]:
        if not isinstance(failure, str):
            return "assertion failure evidence is malformed"
        if any(marker in failure for marker in CONTAINMENT_ASSERTION_MARKERS):
            return f"containment assertion failed: {failure}"
    if result.get("watchdog") == "worker-cleanup-timeout":
        return "watchdog could not reap the worker"
    return None


def schedule_cases(case_runner=run_case, cases=MISSING_CASES):
    results = []
    for index, case in enumerate(cases):
        try:
            result = case_runner(case)
        except BaseException as error:
            result = {
                "case": case,
                "execution_state": "EXECUTION_ERROR",
                "containment_ok": False,
                "worker_reaped": False,
                "remaining_owned_groups": [],
                "malformed_ownership_records": [],
                "assertion_failures": ["unexpected case exception"],
                "exception_type": type(error).__name__,
                "exception_message": str(error),
            }
        results.append(result)
        blocker = containment_blocker(result)
        if blocker is None:
            continue
        for remaining in cases[index + 1:]:
            results.append({
                "case": remaining,
                "execution_state": "NOT_EXECUTED",
                "blocked_by": case,
                "blocking_reason": blocker,
                "containment_ok": False,
                "assertion_failures": ["not executed after containment stop"],
            })
        break
    return results


def scheduler_self_test():
    base = {
        "execution_state": "EXECUTED",
        "containment_ok": True,
        "worker_reaped": True,
        "remaining_owned_groups": [],
        "malformed_ownership_records": [],
        "assertion_failures": [],
        "watchdog": "exited",
        "cleanup_state": "PROVEN",
        "cleanup_errors": [],
        "cleanup_deadline_started": True,
        "cleanup_start_monotonic": 10.0,
        "cleanup_deadline_monotonic": 13.0,
        "cleanup_complete_monotonic": 12.0,
        "cleanup_elapsed_seconds": 2.0,
        "worker_group_absent": True,
        "child_groups_absent": True,
    }
    scenarios = {
        "proven-permits-next": (
            lambda case: dict(base, case=case),
            2,
            ["EXECUTED", "EXECUTED"],
        ),
        "false-stops": (
            lambda case: dict(base, case=case, containment_ok=False),
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-stops": (
            lambda case: {
                key: value for key, value in dict(base, case=case).items()
                if key != "containment_ok"
            },
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "contradiction-stops": (
            lambda case: dict(
                base,
                case=case,
                remaining_owned_groups=[{"pgid": 999999}],
            ),
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-state": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_state"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "unknown-cleanup-state": (
            lambda case: dict(base, case=case, cleanup_state="UNKNOWN"),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-worker-absence": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "worker_group_absent"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-child-absence": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "child_groups_absent"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "cleanup-error-stops": (
            lambda case: dict(base, case=case, cleanup_errors=["injected"]),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-errors": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_errors"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "malformed-cleanup-errors": (
            lambda case: dict(base, case=case, cleanup_errors="bad"),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-timing": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_complete_monotonic"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "completion-after-deadline": (
            lambda case: dict(base, case=case, cleanup_complete_monotonic=14.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "negative-elapsed": (
            lambda case: dict(base, case=case, cleanup_elapsed_seconds=-1.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "inconsistent-elapsed": (
            lambda case: dict(base, case=case, cleanup_elapsed_seconds=1.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "wrong-cleanup-budget": (
            lambda case: dict(base, case=case, cleanup_deadline_monotonic=14.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
    }
    outcomes = {}
    cases = ("first", "second")
    for name, (runner, expected_count, expected_states) in scenarios.items():
        results = schedule_cases(runner, cases)
        states = [item.get("execution_state") for item in results]
        passed = len(results) == expected_count and states == expected_states
        outcomes[name] = {"passed": passed, "states": states}
    calls = []
    def raising_runner(case):
        calls.append(case)
        raise RuntimeError("fabricated scheduler exception")
    exception_results = schedule_cases(raising_runner, cases)
    exception_states = [
        item.get("execution_state") for item in exception_results
    ]
    outcomes["exception-stops"] = {
        "passed": calls == ["first"]
        and exception_states == ["EXECUTION_ERROR", "NOT_EXECUTED"],
        "states": exception_states,
    }
    print(json.dumps(outcomes, indent=2, sort_keys=True))
    if not all(item["passed"] for item in outcomes.values()):
        raise SystemExit("scheduler self-test failed")
    cli_parser_self_test()
    assert source_stability({"a": "1"}, {"a": "1"}) == "PROVEN"
    assert source_stability({"a": "1"}, {"a": "2"}) == "FAILED"


def main():
    pre = {"launcher": digest(LAUNCHER), "proposal": digest(PROPOSAL)}
    if pre != {"launcher": EXPECTED_LAUNCHER, "proposal": EXPECTED_PROPOSAL}:
        raise SystemExit("hash precondition failed")
    harness_paths = {
        "run_validation": Path(__file__).resolve(),
        "run_containment": Path(__file__).resolve().with_name("run_containment.py"),
    }
    source_pre = {name: digest(path) for name, path in harness_paths.items()}
    source, constants, locations, extraction_hash = extract_source()
    if (
        constants["TERM_WAIT_SECONDS"] != TERM_GRACE_SECONDS
        or constants["KILL_WAIT_SECONDS"] != KILL_GRACE_SECONDS
    ):
        raise SystemExit("extracted cleanup grace mismatch")
    MISSING_EVIDENCE.mkdir(parents=True, exist_ok=False)
    (MISSING_EVIDENCE / "extracted_supervisor_source.py").write_text(source, encoding="utf-8")
    results = schedule_cases()
    post = {"launcher": digest(LAUNCHER), "proposal": digest(PROPOSAL)}
    source_post = {name: digest(path) for name, path in harness_paths.items()}
    raw = {"batch": "missing_cases_only", "pre_hashes": pre, "post_hashes": post,
           "source_extraction_sha256": extraction_hash, "source_locations": locations,
           "harness_source_pre_hashes": source_pre,
           "harness_source_post_hashes": source_post,
           "harness_source_stability": (
               source_stability(source_pre, source_post)
           ),
           "harness_source_stability_limit": (
               "Pre/post hashes do not prove absence of transient changes during execution."
           ),
            "case_execution_seconds": CASE_EXECUTION_SECONDS,
            "watchdog_cleanup_seconds": WATCHDOG_CLEANUP_SECONDS,
            "child_wait_seconds": CHILD_WAIT_SECONDS,
             "term_grace_seconds": TERM_GRACE_SECONDS, "kill_grace_seconds": KILL_GRACE_SECONDS,
           "case_to_synthetic": CASE_TO_SYNTHETIC, "cases": results,
             "instrumentation": "External namespace Popen recording/readiness wrapper, Linux PR_SET_PDEATHSIG child lifetime guard, and named monkeypatches only; child controller configuration is recorded, not runtime-proven.",
           "assertions_failed": [r for r in results if r["assertion_failures"]]}
    (MISSING_EVIDENCE / "raw.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    failures = raw["assertions_failed"]
    if raw["harness_source_stability"] != "PROVEN":
        raise SystemExit("harness source stability failed after evidence write")
    if failures:
        raise SystemExit(f"validation assertions failed after evidence write: {len(failures)}")


if __name__ == "__main__":
    cli = parse_cli(sys.argv[1:])
    if cli["mode"] == "help":
        print_help()
    elif cli["mode"] == "worker":
        worker(cli["case"], *(Path(path) for path in cli["paths"]), cli["nonce"])
    elif cli["mode"] == "scheduler-self-test":
        scheduler_self_test()
    else:
        main()
#!/usr/bin/env python3
"""Preparation-only harness for the seven not-yet-executed supervisor cases."""
import ast
import ctypes
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "attached_assets/usbay-fda-readonly-diskutil-diagnostic.zsh"
PROPOSAL = ROOT / "attached_assets/usbay-temporary-terminal-full-disk-access-diagnostic-proposal.md"
EVIDENCE = Path(__file__).resolve().parent / "evidence"
MISSING_EVIDENCE = EVIDENCE / "missing_cases_batch"
EXPECTED_LAUNCHER = "b19bd48a797b3f5659c6fb850d4baff1792c6c73153bfec13b4eb6f5976f320b"
EXPECTED_PROPOSAL = "ef648fadc31e252ce91ff6ee754b0670e6f477b5afd8a5e4a5bc3cdcb675429c"
CHILD_WAIT_SECONDS = 0.08
TERM_GRACE_SECONDS = 2
KILL_GRACE_SECONDS = 2
WATCHDOG_CLEANUP_SECONDS = 3
CASE_EXECUTION_SECONDS = 12
MISSING_CASES = (
    "term-to-kill", "cleanup-denial", "probe-exception", "drain-exception",
    "cleanup-signal-SIGINT", "cleanup-signal-SIGTERM", "cleanup-signal-SIGHUP",
)
CASE_TO_SYNTHETIC = {
    "term-to-kill": "term_ignore_ready",
    "cleanup-denial": "sleep",
    "probe-exception": "exit0",
    "drain-exception": "exit0",
    "cleanup-signal-SIGINT": "sleep",
    "cleanup-signal-SIGTERM": "sleep",
    "cleanup-signal-SIGHUP": "sleep",
}
CONTAINMENT_ASSERTION_MARKERS = (
    "worker authorization",
    "supervisor-child record",
    "malformed ownership",
    "containment unproven",
    "watchdog did not observe clean exit",
    "owned supervisor group remained",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_stability(pre, post):
    """Assess only equality of the recorded pre/post source hashes."""
    return "PROVEN" if dict(pre) == dict(post) else "FAILED"


def parse_cli(argv):
    """Validate dispatch without touching evidence, channels, or processes."""
    args = list(argv)
    if args in (["--help"], ["-h"]):
        return {"mode": "help"}
    if args == ["--scheduler-self-test"]:
        return {"mode": "scheduler-self-test"}
    if args == []:
        return {"mode": "main"}
    if len(args) == 6 and args[0] == "--worker":
        case, ownership, result, auth, nonce = args[1:]
        if case not in MISSING_CASES or not nonce or nonce.startswith("-"):
            raise SystemExit("invalid worker case or nonce")
        paths = (ownership, result, auth)
        if any(not item or item.startswith("-") for item in paths):
            raise SystemExit("invalid worker paths")
        return {"mode": "worker", "case": case, "paths": paths, "nonce": nonce}
    raise SystemExit("unknown or malformed arguments")


def print_help():
    print("usage: run_validation.py [--scheduler-self-test|--worker CASE OWNERSHIP RESULT AUTH NONCE]")


def cli_parser_self_test():
    """Pure parser/dispatch checks; no evidence, channels, or processes."""
    side_effects = {"count": 0}
    for argv, expected in (
        (["--help"], "help"),
        (["--scheduler-self-test"], "scheduler-self-test"),
    ):
        parsed = parse_cli(argv)
        assert parsed["mode"] == expected
        assert side_effects["count"] == 0
    for argv in (
        ["--unknown"],
        ["--worker", "bad", "a", "b", "c", "n"],
        ["--worker", "term-to-kill", "a", "b", "c"],
        ["--worker", "term-to-kill", "-a", "b", "c", "n"],
        ["--worker", "term-to-kill", "a", "--b", "c", "n"],
        ["--worker", "term-to-kill", "a", "b", "c", "-n"],
    ):
        try:
            parse_cli(argv)
        except SystemExit:
            pass
        else:
            raise AssertionError("malformed CLI accepted")
        assert side_effects["count"] == 0


def extract_source():
    raw = LAUNCHER.read_text()
    py = raw.split("<<'PY'\n", 1)[1].split("\ntry:\n    final_status=main()", 1)[0]
    tree = ast.parse(py)
    chosen = [
        node for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef))
        and (not isinstance(node, ast.FunctionDef) or node.name != "main")
    ]
    source = ast.unparse(ast.Module(body=chosen, type_ignores=[])) + "\n"
    namespace = {"__name__": "extracted_supervisor"}
    exec(compile(ast.Module(body=chosen, type_ignores=[]), str(LAUNCHER), "exec"), namespace)
    locations = [f"{node.__class__.__name__}:{getattr(node, 'name', '')}" for node in chosen]
    return source, namespace, locations, hashlib.sha256(source.encode()).hexdigest()


def synthetic(kind, gate_path, nonce, worker_pid, ready_path=None):
    behavior = {
        "sleep": "time.sleep(.35)",
        "exit0": "raise SystemExit(0)",
        "term_ignore_ready": (
            "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            "pathlib.Path(sys.argv[3]).write_text('READY\\n')\n"
            "time.sleep(10)"
        ),
    }[kind]
    code = (
        "import ctypes,os,pathlib,signal,sys,time\n"
        "if ctypes.CDLL(None).prctl(1,signal.SIGKILL) != 0: raise SystemExit(91)\n"
        "if os.getppid() != int(sys.argv[4]): raise SystemExit(92)\n"
        "gate=pathlib.Path(sys.argv[1]); nonce=sys.argv[2]\n"
        "while True:\n"
        "    try:\n"
        "        if gate.read_text().strip()==nonce: break\n"
        "    except (FileNotFoundError,OSError): pass\n"
        "    time.sleep(.01)\n"
        + behavior + "\n"
    )
    return [
        sys.executable, "-c", "exec(" + repr(code) + ")",
        str(gate_path), nonce, str(ready_path or ""), str(worker_pid),
    ]


def append_json(path, item):
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(item, sort_keys=True) + "\n")
        stream.flush()


def worker(case, ownership_path, result_path, auth_path, nonce):
    while auth_path.read_text(encoding="utf-8").strip() != nonce:
        time.sleep(0.01)
    _, ns, _, _ = extract_source()
    trace = []
    stdout = tempfile.TemporaryFile()
    stderr = tempfile.TemporaryFile()
    originals = {}
    helper = None
    checkpoint = threading.Event()
    acknowledgement = threading.Event()
    ready_path = Path(str(result_path) + ".ready")
    child_gate = Path(str(result_path) + ".child-gate")
    containment = {
        "nonce": nonce,
        "worker_pid": os.getpid(),
        "controller_mechanism": "Linux prctl(PR_SET_PDEATHSIG, SIGKILL) with child PPID check",
        "records": [],
    }

    original_popen = ns["subprocess"].Popen
    def recording_popen(*args, **kwargs):
        child = original_popen(*args, **kwargs)
        record = {"pgid": None}
        try:
            record = {
                "kind": "supervisor-child", "nonce": nonce, "pid": child.pid,
                "pgid": os.getpgid(child.pid), "session_id": os.getsid(child.pid),
                "start_new_session": kwargs.get("start_new_session", False),
                "worker_pid": os.getpid(), "case": case, "child_gate": str(child_gate),
            }
            if not child_owned(record, nonce, case, os.getpid()):
                raise RuntimeError("supervisor-child ownership validation failed")
            containment["records"].append(record)
            append_json(ownership_path, record)
            child_gate.write_text(nonce + "\n", encoding="utf-8")
            if case == "term-to-kill":
                deadline = time.monotonic() + 2
                while not ready_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not ready_path.exists():
                    raise RuntimeError("TERM handler readiness was not proven")
        except BaseException:
            if isinstance(record.get("pgid"), int):
                try:
                    os.killpg(record["pgid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                child.kill()
            try:
                child.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
            raise
        return child

    ns["subprocess"].Popen = recording_popen
    if case == "cleanup-denial":
        originals["signal_group"] = ns["signal_group"]
        def denied_signal_group(pgid, sig, trace_arg, phase):
            outcome = "denied"
            ns["trace_event"](trace_arg, "injected-group-signal", phase=phase,
                              signal=int(sig), outcome=outcome)
            return outcome
        ns["signal_group"] = denied_signal_group
    elif case == "probe-exception":
        originals["group_state"] = ns["group_state"]
        def injected_probe(*args, **kwargs):
            raise RuntimeError("injected-probe")
        ns["group_state"] = injected_probe
    elif case == "drain-exception":
        originals["sigpending"] = ns["signal"].sigpending
        ns["signal"].sigpending = lambda: (_ for _ in ()).throw(RuntimeError("injected-drain"))
    elif case.startswith("cleanup-signal-"):
        originals["signal_group"] = ns["signal_group"]
        requested = {
            "cleanup-signal-SIGINT": signal.SIGINT,
            "cleanup-signal-SIGTERM": signal.SIGTERM,
            "cleanup-signal-SIGHUP": signal.SIGHUP,
        }[case]
        def synchronized_signal_group(*args):
            pgid, sig, trace_arg, phase = args
            if phase == "term" and not checkpoint.is_set():
                ns["trace_event"](trace_arg, "test-cleanup-checkpoint",
                                  phase="term", signal=int(requested))
                checkpoint.set()
                def deliver():
                    if checkpoint.wait(1):
                        os.kill(os.getpid(), requested)
                        ns["trace_event"](trace_arg, "test-cleanup-signal-sent",
                                          phase="term", signal=int(requested))
                        acknowledgement.set()
                nonlocal helper
                helper = threading.Thread(target=deliver, daemon=True)
                helper.start()
                if not acknowledgement.wait(1):
                    raise RuntimeError("cleanup signal acknowledgement timeout")
            return originals["signal_group"](*args)
        ns["signal_group"] = synchronized_signal_group

    try:
        kind = CASE_TO_SYNTHETIC[case]
        status, reason = ns["bounded"](
            synthetic(kind, child_gate, nonce, os.getpid(), ready_path),
            CHILD_WAIT_SECONDS,
            stdout,
            stderr,
            trace,
        )
        result = {"status": status, "reason": reason, "trace": trace}
    except BaseException as exc:
        result = {"worker_exception": type(exc).__name__, "message": str(exc), "trace": trace}
    finally:
        ns["subprocess"].Popen = original_popen
        for name, value in originals.items():
            if name == "sigpending":
                ns["signal"].sigpending = value
            else:
                ns[name] = value
        if helper:
            helper.join(timeout=1)
        stdout.close()
        stderr.close()
    result["containment"] = containment
    Path(result_path).write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")


def process_owned(record, nonce, case):
    return (
        record.get("nonce") == nonce and record.get("case") == case
        and isinstance(record.get("pid"), int) and record.get("pid") > 0
        and record.get("pgid") == record.get("pid")
        and record.get("session_id") == record.get("pid")
        and record.get("start_new_session") is True
    )


def child_owned(record, nonce, case, worker_pid):
    return (
        record.get("kind") == "supervisor-child"
        and record.get("worker_pid") == worker_pid
        and process_owned(record, nonce, case)
    )


def group_present(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def wait_group_absent(pgid, deadline):
    while group_present(pgid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


def parent_watchdog_cleanup(proc, worker_record, records, nonce, case,
                            watchdog, ownership_path, result_path,
                            malformed_records=None, live_handles=None,
                            group_present_fn=None, wait_group_absent_fn=None,
                            signal_fn=None, monotonic_fn=None):
    """The single parent-watchdog path used by lifecycle and focused tests."""
    group_present_fn = group_present_fn or group_present
    wait_group_absent_fn = wait_group_absent_fn or wait_group_absent
    monotonic_fn = monotonic_fn or time.monotonic
    cleanup_start = monotonic_fn()
    cleanup_deadline = cleanup_start + WATCHDOG_CLEANUP_SECONDS
    malformed_records = list(malformed_records or [])
    valid = [record for record in records
             if child_owned(record, nonce, case, proc.pid)]
    worker_owned = process_owned(worker_record, nonce, case)
    containment_ok = worker_owned and len(valid) == 1
    residual = [record for record in valid if group_present_fn(record["pgid"])]
    if residual and watchdog == "exited":
        watchdog = "residual-process"
    actions = []
    cleanup_errors = []
    if live_handles is not None:
        live_by_pid = {
            getattr(item, "record", {}).get("pid"): item
            for item in live_handles
        }
        for record in valid + [worker_record]:
            handle = live_by_pid.get(record.get("pid"))
            if (handle is None or getattr(handle, "pidfd", None) is None
                    or getattr(handle, "record", {}).get("pid") != record.get("pid")):
                cleanup_errors.append(
                    f"missing-live-handle:{record.get('pid')}")
    if watchdog != "exited" or not containment_ok:
        watchdog = watchdog if watchdog != "exited" else "containment-unproven"
        for record in valid:
            if group_present_fn(record["pgid"]):
                try:
                    if live_handles is not None:
                        handle = next((item for item in live_handles
                                       if item.record.get("pid") == record["pid"]), None)
                        if (handle is None or handle.pidfd is None
                                or handle.record.get("pid") != record["pid"]):
                            raise RuntimeError("live child handle missing or mismatched")
                        outcome = signal_fn(handle, signal.SIGKILL) if signal_fn else signal.pidfd_send_signal(handle.pidfd, signal.SIGKILL)
                    else:
                        outcome = signal_fn(record, signal.SIGKILL) if signal_fn else os.killpg(record["pgid"], signal.SIGKILL)
                    actions.append({"target": "child", "pgid": record["pgid"],
                                    "signal": int(signal.SIGKILL), "outcome": "sent"})
                except ProcessLookupError:
                    actions.append({"target": "child", "pgid": record["pgid"],
                                    "signal": int(signal.SIGKILL), "outcome": "absent"})
                except BaseException as error:
                    cleanup_errors.append(f"child-signal:{type(error).__name__}:{error}")
        if worker_owned and group_present_fn(worker_record["pgid"]):
            try:
                if live_handles is not None:
                    handle = next((item for item in live_handles
                                   if item.record.get("pid") == worker_record["pid"]), None)
                    if (handle is None or handle.pidfd is None
                            or handle.record.get("pid") != worker_record["pid"]):
                        raise RuntimeError("live worker handle missing or mismatched")
                    outcome = signal_fn(handle, signal.SIGKILL) if signal_fn else signal.pidfd_send_signal(handle.pidfd, signal.SIGKILL)
                else:
                    outcome = signal_fn(worker_record, signal.SIGKILL) if signal_fn else os.killpg(worker_record["pgid"], signal.SIGKILL)
                actions.append({"target": "worker", "pgid": worker_record["pgid"],
                                "signal": int(signal.SIGKILL), "outcome": "sent"})
            except ProcessLookupError:
                actions.append({"target": "worker", "pgid": worker_record["pgid"],
                                "signal": int(signal.SIGKILL), "outcome": "absent"})
            except BaseException as error:
                cleanup_errors.append(f"worker-signal:{type(error).__name__}:{error}")
        try:
                proc.wait(timeout=max(0, cleanup_deadline - monotonic_fn()))
        except subprocess.TimeoutExpired:
            watchdog = "worker-cleanup-timeout"
    remaining_owned_groups = [
        record for record in valid
        if not wait_group_absent_fn(record["pgid"], cleanup_deadline)
    ]
    worker_group_absent = (
        wait_group_absent_fn(worker_record["pgid"], cleanup_deadline)
        if worker_owned else False
    )
    cleanup_complete = monotonic_fn()
    cleanup_state = ("PROVEN" if worker_owned and len(valid) == 1
                     and worker_group_absent and not malformed_records
                     and not remaining_owned_groups
                     and not cleanup_errors and proc.poll() is not None
                     and cleanup_complete <= cleanup_deadline else "UNKNOWN")
    return {
        "watchdog": watchdog, "containment_ok": worker_owned and len(valid) == 1
        and not malformed_records, "worker_reaped": proc.poll() is not None,
        "residual_owned_groups": residual,
        "remaining_owned_groups": remaining_owned_groups,
         "worker_group_absent": worker_group_absent,
         "child_groups_absent": not remaining_owned_groups,
        "malformed_ownership_records": malformed_records, "valid_records": valid,
        "cleanup_actions": actions, "cleanup_errors": cleanup_errors,
        "cleanup_start_monotonic": cleanup_start,
        "cleanup_deadline_monotonic": cleanup_deadline,
        "cleanup_complete_monotonic": cleanup_complete,
        "cleanup_elapsed_seconds": cleanup_complete - cleanup_start,
        "cleanup_deadline_started": True,
        "cleanup_state": cleanup_state,
    }


def run_case(case):
    nonce = uuid.uuid4().hex
    ownership_path = MISSING_EVIDENCE / f"{case}.{nonce}.ownership.jsonl"
    result_path = MISSING_EVIDENCE / f"{case}.{nonce}.result.json"
    auth_path = MISSING_EVIDENCE / f"{case}.{nonce}.worker-authorized"
    ownership_path.touch(exist_ok=False)
    result_path.touch(exist_ok=False)
    auth_path.touch(exist_ok=False)
    cmd = [sys.executable, str(Path(__file__).resolve()), "--worker", case,
           str(ownership_path), str(result_path), str(auth_path), nonce]
    proc = subprocess.Popen(cmd, start_new_session=True)
    worker_record = {
        "kind": "worker", "nonce": nonce, "pid": proc.pid,
        "pgid": None, "session_id": None, "start_new_session": True,
        "worker_pid": os.getpid(), "case": case,
    }
    worker_authorized = False
    setup_error = None
    try:
        worker_record["pgid"] = os.getpgid(proc.pid)
        worker_record["session_id"] = os.getsid(proc.pid)
        worker_authorized = process_owned(worker_record, nonce, case)
        if not worker_authorized:
            raise RuntimeError("worker ownership validation failed")
        append_json(ownership_path, worker_record)
        auth_path.write_text(nonce + "\n", encoding="utf-8")
    except BaseException as error:
        setup_error = {"type": type(error).__name__, "message": str(error)}
        try:
            if worker_authorized and group_present(worker_record["pgid"]):
                os.killpg(worker_record["pgid"], signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
        except subprocess.TimeoutExpired:
            setup_error["cleanup"] = "worker-reap-timeout"
        return {
            "case": case,
            "nonce": nonce,
            "spawned": True,
            "worker_authorized": worker_authorized,
            "containment_ok": False,
            "watchdog": "worker-setup-failed",
            "setup_error": setup_error,
            "assertion_failures": ["worker setup/authorization failed"],
        }
    watchdog = "exited"
    try:
        proc.wait(timeout=CASE_EXECUTION_SECONDS)
    except subprocess.TimeoutExpired:
        watchdog = "watchdog-timeout"
    records = []
    malformed_records = []
    for line in ownership_path.read_text().splitlines():
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            malformed_records.append(line)
    cleanup = parent_watchdog_cleanup(
        proc, worker_record, records, nonce, case, watchdog,
        ownership_path, result_path, malformed_records,
    )
    watchdog = cleanup["watchdog"]
    valid = cleanup["valid_records"]
    remaining_owned_groups = cleanup["remaining_owned_groups"]
    containment_ok = worker_authorized and cleanup["containment_ok"]
    worker_reaped = cleanup["worker_reaped"]
    result = json.loads(result_path.read_text()) if result_path.stat().st_size else {}
    observed = {"case": case, "nonce": nonce, "watchdog": watchdog,
                "execution_state": "EXECUTED",
                "ownership_path": str(ownership_path.relative_to(ROOT)),
                "result_path": str(result_path.relative_to(ROOT)),
                "ownership_records": records, "containment_ok": containment_ok,
                "worker_reaped": worker_reaped,
                 "residual_owned_groups": cleanup["residual_owned_groups"],
                "remaining_owned_groups": remaining_owned_groups,
                 "worker_group_absent": cleanup["worker_group_absent"],
                 "child_groups_absent": cleanup["child_groups_absent"],
                 "cleanup_state": cleanup["cleanup_state"],
                 "cleanup_errors": cleanup["cleanup_errors"],
                 "cleanup_start_monotonic": cleanup["cleanup_start_monotonic"],
                 "cleanup_deadline_monotonic": cleanup["cleanup_deadline_monotonic"],
                 "cleanup_complete_monotonic": cleanup["cleanup_complete_monotonic"],
                 "cleanup_elapsed_seconds": cleanup["cleanup_elapsed_seconds"],
                 "cleanup_deadline_started": cleanup["cleanup_deadline_started"],
                "malformed_ownership_records": malformed_records,
                 "cleanup_actions": cleanup["cleanup_actions"],
                "result": result}
    expected = {
        "term-to-kill": (124, "timeout-clean", ("group-signal", "cleanup-result")),
        "cleanup-denial": (125, "timeout-cleanup-unproven", ("injected-group-signal",)),
        "probe-exception": (70, "post-wait-probe-exception-clean", ("post-wait-probe-exception",)),
        "drain-exception": (125, "pending-signal-drain-cleanup-unproven", ("pending-signal-drain-exception",)),
        "cleanup-signal-SIGINT": (130, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
        "cleanup-signal-SIGTERM": (143, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
        "cleanup-signal-SIGHUP": (129, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
    }[case]
    events = result.get("trace", [])
    names = {event.get("event") for event in events}
    observed["expected"] = {"status": expected[0], "reason": expected[1], "events": expected[2]}
    observed["assertion_failures"] = []
    if result.get("status") != expected[0] or result.get("reason") != expected[1]:
        observed["assertion_failures"].append("status/reason mismatch")
    if any(event not in names for event in expected[2]):
        observed["assertion_failures"].append("required trace event missing")
    if case.startswith("cleanup-signal-"):
        requested = {
            "cleanup-signal-SIGINT": int(signal.SIGINT),
            "cleanup-signal-SIGTERM": int(signal.SIGTERM),
            "cleanup-signal-SIGHUP": int(signal.SIGHUP),
        }[case]
        checkpoint_events = [
            e for e in events
            if e.get("event") == "test-cleanup-checkpoint"
            and e.get("phase") == "term" and e.get("signal") == requested
        ]
        sent_events = [
            e for e in events
            if e.get("event") == "test-cleanup-signal-sent"
            and e.get("phase") == "term" and e.get("signal") == requested
        ]
        delivery_events = [
            e for e in events
            if e.get("event") == "signal-delivery"
            and e.get("signal") == requested
            and e.get("stage") == "cleanup-pending-drain"
        ]
        if not (checkpoint_events and sent_events and delivery_events):
            observed["assertion_failures"].append(
                "exact cleanup signal checkpoint/sent/pending-drain proof missing"
            )
        else:
            positions = [
                next(i for i, e in enumerate(events) if e is item)
                for item in (checkpoint_events[0], sent_events[0], delivery_events[0])
            ]
            if not (positions[0] < positions[1] < positions[2]):
                observed["assertion_failures"].append(
                    "cleanup signal trace order checkpoint<sent<delivery failed"
                )
    if case == "term-to-kill":
        signals = {(e.get("phase"), e.get("signal"), e.get("outcome")) for e in events if e.get("event") == "group-signal"}
        if ("term", int(signal.SIGTERM), "sent") not in signals:
            observed["assertion_failures"].append("actual TERM sent not observed")
        if ("kill", int(signal.SIGKILL), "sent") not in signals:
            observed["assertion_failures"].append("actual KILL sent not observed")
        if not any(e.get("event") == "cleanup-result" and e.get("reason") == "kill-clean" for e in events):
            observed["assertion_failures"].append("kill-clean not observed")
    if case == "cleanup-denial":
        denials = {
            (event.get("phase"), event.get("signal"), event.get("outcome"))
            for event in events
            if event.get("event") == "injected-group-signal"
        }
        if ("term", int(signal.SIGTERM), "denied") not in denials:
            observed["assertion_failures"].append(
                "injected TERM denial not observed"
            )
        if ("kill", int(signal.SIGKILL), "denied") not in denials:
            observed["assertion_failures"].append(
                "injected KILL denial not observed"
            )
    if not worker_authorized:
        observed["assertion_failures"].append("worker authorization handshake failed")
    if len(valid) != 1:
        observed["assertion_failures"].append("expected exactly one valid supervisor-child record")
    if malformed_records:
        observed["assertion_failures"].append("malformed ownership record")
    if not containment_ok:
        observed["assertion_failures"].append("containment unproven")
    if watchdog != "exited":
        observed["assertion_failures"].append("watchdog did not observe clean exit")
    if remaining_owned_groups:
        observed["assertion_failures"].append("owned supervisor group remained present")
    return observed


def containment_blocker(result):
    if not isinstance(result, dict):
        return "case result is not an object"
    if result.get("containment_ok") is not True:
        return "containment_ok is not proven true"
    if result.get("worker_reaped") is not True:
        return "worker reaping is not proven"
    if result.get("cleanup_state") != "PROVEN":
        return "cleanup state is missing or not proven"
    if result.get("worker_group_absent") is not True:
        return "worker group absence is not proven"
    if result.get("child_groups_absent") is not True:
        return "child group absence is not proven"
    if not isinstance(result.get("cleanup_errors"), list):
        return "cleanup errors are missing or malformed"
    if result["cleanup_errors"]:
        return "cleanup errors are present"
    if result.get("cleanup_deadline_started") is not True:
        return "cleanup deadline evidence is missing"
    timing = [
        result.get("cleanup_start_monotonic"),
        result.get("cleanup_deadline_monotonic"),
        result.get("cleanup_complete_monotonic"),
        result.get("cleanup_elapsed_seconds"),
    ]
    if any(isinstance(value, bool) or not isinstance(value, (int, float))
           or not math.isfinite(value) for value in timing):
        return "cleanup timing evidence is missing or malformed"
    start, deadline, complete, elapsed = timing
    if not (start <= complete <= deadline and elapsed >= 0):
        return "cleanup timing is contradictory"
    tolerance = 1e-6
    if abs(elapsed - (complete - start)) > tolerance:
        return "cleanup elapsed time is inconsistent"
    if abs((deadline - start) - WATCHDOG_CLEANUP_SECONDS) > tolerance:
        return "cleanup deadline budget is inconsistent"
    for field in (
        "remaining_owned_groups",
        "malformed_ownership_records",
        "assertion_failures",
    ):
        if not isinstance(result.get(field), list):
            return f"{field} is missing or malformed"
    if result["remaining_owned_groups"]:
        return "owned supervisor groups remain present"
    if result["malformed_ownership_records"]:
        return "ownership evidence is malformed"
    for failure in result["assertion_failures"]:
        if not isinstance(failure, str):
            return "assertion failure evidence is malformed"
        if any(marker in failure for marker in CONTAINMENT_ASSERTION_MARKERS):
            return f"containment assertion failed: {failure}"
    if result.get("watchdog") == "worker-cleanup-timeout":
        return "watchdog could not reap the worker"
    return None


def schedule_cases(case_runner=run_case, cases=MISSING_CASES):
    results = []
    for index, case in enumerate(cases):
        try:
            result = case_runner(case)
        except BaseException as error:
            result = {
                "case": case,
                "execution_state": "EXECUTION_ERROR",
                "containment_ok": False,
                "worker_reaped": False,
                "remaining_owned_groups": [],
                "malformed_ownership_records": [],
                "assertion_failures": ["unexpected case exception"],
                "exception_type": type(error).__name__,
                "exception_message": str(error),
            }
        results.append(result)
        blocker = containment_blocker(result)
        if blocker is None:
            continue
        for remaining in cases[index + 1:]:
            results.append({
                "case": remaining,
                "execution_state": "NOT_EXECUTED",
                "blocked_by": case,
                "blocking_reason": blocker,
                "containment_ok": False,
                "assertion_failures": ["not executed after containment stop"],
            })
        break
    return results


def scheduler_self_test():
    base = {
        "execution_state": "EXECUTED",
        "containment_ok": True,
        "worker_reaped": True,
        "remaining_owned_groups": [],
        "malformed_ownership_records": [],
        "assertion_failures": [],
        "watchdog": "exited",
        "cleanup_state": "PROVEN",
        "cleanup_errors": [],
        "cleanup_deadline_started": True,
        "cleanup_start_monotonic": 10.0,
        "cleanup_deadline_monotonic": 13.0,
        "cleanup_complete_monotonic": 12.0,
        "cleanup_elapsed_seconds": 2.0,
        "worker_group_absent": True,
        "child_groups_absent": True,
    }
    scenarios = {
        "proven-permits-next": (
            lambda case: dict(base, case=case),
            2,
            ["EXECUTED", "EXECUTED"],
        ),
        "false-stops": (
            lambda case: dict(base, case=case, containment_ok=False),
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-stops": (
            lambda case: {
                key: value for key, value in dict(base, case=case).items()
                if key != "containment_ok"
            },
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "contradiction-stops": (
            lambda case: dict(
                base,
                case=case,
                remaining_owned_groups=[{"pgid": 999999}],
            ),
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-state": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_state"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "unknown-cleanup-state": (
            lambda case: dict(base, case=case, cleanup_state="UNKNOWN"),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-worker-absence": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "worker_group_absent"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-child-absence": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "child_groups_absent"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "cleanup-error-stops": (
            lambda case: dict(base, case=case, cleanup_errors=["injected"]),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-errors": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_errors"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "malformed-cleanup-errors": (
            lambda case: dict(base, case=case, cleanup_errors="bad"),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-timing": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_complete_monotonic"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "completion-after-deadline": (
            lambda case: dict(base, case=case, cleanup_complete_monotonic=14.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "negative-elapsed": (
            lambda case: dict(base, case=case, cleanup_elapsed_seconds=-1.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "inconsistent-elapsed": (
            lambda case: dict(base, case=case, cleanup_elapsed_seconds=1.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "wrong-cleanup-budget": (
            lambda case: dict(base, case=case, cleanup_deadline_monotonic=14.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
    }
    outcomes = {}
    cases = ("first", "second")
    for name, (runner, expected_count, expected_states) in scenarios.items():
        results = schedule_cases(runner, cases)
        states = [item.get("execution_state") for item in results]
        passed = len(results) == expected_count and states == expected_states
        outcomes[name] = {"passed": passed, "states": states}
    calls = []
    def raising_runner(case):
        calls.append(case)
        raise RuntimeError("fabricated scheduler exception")
    exception_results = schedule_cases(raising_runner, cases)
    exception_states = [
        item.get("execution_state") for item in exception_results
    ]
    outcomes["exception-stops"] = {
        "passed": calls == ["first"]
        and exception_states == ["EXECUTION_ERROR", "NOT_EXECUTED"],
        "states": exception_states,
    }
    print(json.dumps(outcomes, indent=2, sort_keys=True))
    if not all(item["passed"] for item in outcomes.values()):
        raise SystemExit("scheduler self-test failed")
    cli_parser_self_test()
    assert source_stability({"a": "1"}, {"a": "1"}) == "PROVEN"
    assert source_stability({"a": "1"}, {"a": "2"}) == "FAILED"


def main():
    pre = {"launcher": digest(LAUNCHER), "proposal": digest(PROPOSAL)}
    if pre != {"launcher": EXPECTED_LAUNCHER, "proposal": EXPECTED_PROPOSAL}:
        raise SystemExit("hash precondition failed")
    harness_paths = {
        "run_validation": Path(__file__).resolve(),
        "run_containment": Path(__file__).resolve().with_name("run_containment.py"),
    }
    source_pre = {name: digest(path) for name, path in harness_paths.items()}
    source, constants, locations, extraction_hash = extract_source()
    if (
        constants["TERM_WAIT_SECONDS"] != TERM_GRACE_SECONDS
        or constants["KILL_WAIT_SECONDS"] != KILL_GRACE_SECONDS
    ):
        raise SystemExit("extracted cleanup grace mismatch")
    MISSING_EVIDENCE.mkdir(parents=True, exist_ok=False)
    (MISSING_EVIDENCE / "extracted_supervisor_source.py").write_text(source, encoding="utf-8")
    results = schedule_cases()
    post = {"launcher": digest(LAUNCHER), "proposal": digest(PROPOSAL)}
    source_post = {name: digest(path) for name, path in harness_paths.items()}
    raw = {"batch": "missing_cases_only", "pre_hashes": pre, "post_hashes": post,
           "source_extraction_sha256": extraction_hash, "source_locations": locations,
           "harness_source_pre_hashes": source_pre,
           "harness_source_post_hashes": source_post,
           "harness_source_stability": (
               source_stability(source_pre, source_post)
           ),
           "harness_source_stability_limit": (
               "Pre/post hashes do not prove absence of transient changes during execution."
           ),
            "case_execution_seconds": CASE_EXECUTION_SECONDS,
            "watchdog_cleanup_seconds": WATCHDOG_CLEANUP_SECONDS,
            "child_wait_seconds": CHILD_WAIT_SECONDS,
             "term_grace_seconds": TERM_GRACE_SECONDS, "kill_grace_seconds": KILL_GRACE_SECONDS,
           "case_to_synthetic": CASE_TO_SYNTHETIC, "cases": results,
             "instrumentation": "External namespace Popen recording/readiness wrapper, Linux PR_SET_PDEATHSIG child lifetime guard, and named monkeypatches only; child controller configuration is recorded, not runtime-proven.",
           "assertions_failed": [r for r in results if r["assertion_failures"]]}
    (MISSING_EVIDENCE / "raw.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    failures = raw["assertions_failed"]
    if raw["harness_source_stability"] != "PROVEN":
        raise SystemExit("harness source stability failed after evidence write")
    if failures:
        raise SystemExit(f"validation assertions failed after evidence write: {len(failures)}")


if __name__ == "__main__":
    cli = parse_cli(sys.argv[1:])
    if cli["mode"] == "help":
        print_help()
    elif cli["mode"] == "worker":
        worker(cli["case"], *(Path(path) for path in cli["paths"]), cli["nonce"])
    elif cli["mode"] == "scheduler-self-test":
        scheduler_self_test()
    else:
        main()
#!/usr/bin/env python3
"""Preparation-only harness for the seven not-yet-executed supervisor cases."""
import ast
import ctypes
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "attached_assets/usbay-fda-readonly-diskutil-diagnostic.zsh"
PROPOSAL = ROOT / "attached_assets/usbay-temporary-terminal-full-disk-access-diagnostic-proposal.md"
EVIDENCE = Path(__file__).resolve().parent / "evidence"
MISSING_EVIDENCE = EVIDENCE / "missing_cases_batch"
EXPECTED_LAUNCHER = "b19bd48a797b3f5659c6fb850d4baff1792c6c73153bfec13b4eb6f5976f320b"
EXPECTED_PROPOSAL = "ef648fadc31e252ce91ff6ee754b0670e6f477b5afd8a5e4a5bc3cdcb675429c"
CHILD_WAIT_SECONDS = 0.08
TERM_GRACE_SECONDS = 2
KILL_GRACE_SECONDS = 2
WATCHDOG_CLEANUP_SECONDS = 3
CASE_EXECUTION_SECONDS = 12
MISSING_CASES = (
    "term-to-kill", "cleanup-denial", "probe-exception", "drain-exception",
    "cleanup-signal-SIGINT", "cleanup-signal-SIGTERM", "cleanup-signal-SIGHUP",
)
CASE_TO_SYNTHETIC = {
    "term-to-kill": "term_ignore_ready",
    "cleanup-denial": "sleep",
    "probe-exception": "exit0",
    "drain-exception": "exit0",
    "cleanup-signal-SIGINT": "sleep",
    "cleanup-signal-SIGTERM": "sleep",
    "cleanup-signal-SIGHUP": "sleep",
}
CONTAINMENT_ASSERTION_MARKERS = (
    "worker authorization",
    "supervisor-child record",
    "malformed ownership",
    "containment unproven",
    "watchdog did not observe clean exit",
    "owned supervisor group remained",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_stability(pre, post):
    """Assess only equality of the recorded pre/post source hashes."""
    return "PROVEN" if dict(pre) == dict(post) else "FAILED"


def parse_cli(argv):
    """Validate dispatch without touching evidence, channels, or processes."""
    args = list(argv)
    if args in (["--help"], ["-h"]):
        return {"mode": "help"}
    if args == ["--scheduler-self-test"]:
        return {"mode": "scheduler-self-test"}
    if args == []:
        return {"mode": "main"}
    if len(args) == 6 and args[0] == "--worker":
        case, ownership, result, auth, nonce = args[1:]
        if case not in MISSING_CASES or not nonce or nonce.startswith("-"):
            raise SystemExit("invalid worker case or nonce")
        paths = (ownership, result, auth)
        if any(not item or item.startswith("-") for item in paths):
            raise SystemExit("invalid worker paths")
        return {"mode": "worker", "case": case, "paths": paths, "nonce": nonce}
    raise SystemExit("unknown or malformed arguments")


def print_help():
    print("usage: run_validation.py [--scheduler-self-test|--worker CASE OWNERSHIP RESULT AUTH NONCE]")


def cli_parser_self_test():
    """Pure parser/dispatch checks; no evidence, channels, or processes."""
    side_effects = {"count": 0}
    for argv, expected in (
        (["--help"], "help"),
        (["--scheduler-self-test"], "scheduler-self-test"),
    ):
        parsed = parse_cli(argv)
        assert parsed["mode"] == expected
        assert side_effects["count"] == 0
    for argv in (
        ["--unknown"],
        ["--worker", "bad", "a", "b", "c", "n"],
        ["--worker", "term-to-kill", "a", "b", "c"],
        ["--worker", "term-to-kill", "-a", "b", "c", "n"],
        ["--worker", "term-to-kill", "a", "--b", "c", "n"],
        ["--worker", "term-to-kill", "a", "b", "c", "-n"],
    ):
        try:
            parse_cli(argv)
        except SystemExit:
            pass
        else:
            raise AssertionError("malformed CLI accepted")
        assert side_effects["count"] == 0


def extract_source():
    raw = LAUNCHER.read_text()
    py = raw.split("<<'PY'\n", 1)[1].split("\ntry:\n    final_status=main()", 1)[0]
    tree = ast.parse(py)
    chosen = [
        node for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef))
        and (not isinstance(node, ast.FunctionDef) or node.name != "main")
    ]
    source = ast.unparse(ast.Module(body=chosen, type_ignores=[])) + "\n"
    namespace = {"__name__": "extracted_supervisor"}
    exec(compile(ast.Module(body=chosen, type_ignores=[]), str(LAUNCHER), "exec"), namespace)
    locations = [f"{node.__class__.__name__}:{getattr(node, 'name', '')}" for node in chosen]
    return source, namespace, locations, hashlib.sha256(source.encode()).hexdigest()


def synthetic(kind, gate_path, nonce, worker_pid, ready_path=None):
    behavior = {
        "sleep": "time.sleep(.35)",
        "exit0": "raise SystemExit(0)",
        "term_ignore_ready": (
            "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            "pathlib.Path(sys.argv[3]).write_text('READY\\n')\n"
            "time.sleep(10)"
        ),
    }[kind]
    code = (
        "import ctypes,os,pathlib,signal,sys,time\n"
        "if ctypes.CDLL(None).prctl(1,signal.SIGKILL) != 0: raise SystemExit(91)\n"
        "if os.getppid() != int(sys.argv[4]): raise SystemExit(92)\n"
        "gate=pathlib.Path(sys.argv[1]); nonce=sys.argv[2]\n"
        "while True:\n"
        "    try:\n"
        "        if gate.read_text().strip()==nonce: break\n"
        "    except (FileNotFoundError,OSError): pass\n"
        "    time.sleep(.01)\n"
        + behavior + "\n"
    )
    return [
        sys.executable, "-c", "exec(" + repr(code) + ")",
        str(gate_path), nonce, str(ready_path or ""), str(worker_pid),
    ]


def append_json(path, item):
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(item, sort_keys=True) + "\n")
        stream.flush()


def worker(case, ownership_path, result_path, auth_path, nonce):
    while auth_path.read_text(encoding="utf-8").strip() != nonce:
        time.sleep(0.01)
    _, ns, _, _ = extract_source()
    trace = []
    stdout = tempfile.TemporaryFile()
    stderr = tempfile.TemporaryFile()
    originals = {}
    helper = None
    checkpoint = threading.Event()
    acknowledgement = threading.Event()
    ready_path = Path(str(result_path) + ".ready")
    child_gate = Path(str(result_path) + ".child-gate")
    containment = {
        "nonce": nonce,
        "worker_pid": os.getpid(),
        "controller_mechanism": "Linux prctl(PR_SET_PDEATHSIG, SIGKILL) with child PPID check",
        "records": [],
    }

    original_popen = ns["subprocess"].Popen
    def recording_popen(*args, **kwargs):
        child = original_popen(*args, **kwargs)
        record = {"pgid": None}
        try:
            record = {
                "kind": "supervisor-child", "nonce": nonce, "pid": child.pid,
                "pgid": os.getpgid(child.pid), "session_id": os.getsid(child.pid),
                "start_new_session": kwargs.get("start_new_session", False),
                "worker_pid": os.getpid(), "case": case, "child_gate": str(child_gate),
            }
            if not child_owned(record, nonce, case, os.getpid()):
                raise RuntimeError("supervisor-child ownership validation failed")
            containment["records"].append(record)
            append_json(ownership_path, record)
            child_gate.write_text(nonce + "\n", encoding="utf-8")
            if case == "term-to-kill":
                deadline = time.monotonic() + 2
                while not ready_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not ready_path.exists():
                    raise RuntimeError("TERM handler readiness was not proven")
        except BaseException:
            if isinstance(record.get("pgid"), int):
                try:
                    os.killpg(record["pgid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                child.kill()
            try:
                child.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
            raise
        return child

    ns["subprocess"].Popen = recording_popen
    if case == "cleanup-denial":
        originals["signal_group"] = ns["signal_group"]
        def denied_signal_group(pgid, sig, trace_arg, phase):
            outcome = "denied"
            ns["trace_event"](trace_arg, "injected-group-signal", phase=phase,
                              signal=int(sig), outcome=outcome)
            return outcome
        ns["signal_group"] = denied_signal_group
    elif case == "probe-exception":
        originals["group_state"] = ns["group_state"]
        def injected_probe(*args, **kwargs):
            raise RuntimeError("injected-probe")
        ns["group_state"] = injected_probe
    elif case == "drain-exception":
        originals["sigpending"] = ns["signal"].sigpending
        ns["signal"].sigpending = lambda: (_ for _ in ()).throw(RuntimeError("injected-drain"))
    elif case.startswith("cleanup-signal-"):
        originals["signal_group"] = ns["signal_group"]
        requested = {
            "cleanup-signal-SIGINT": signal.SIGINT,
            "cleanup-signal-SIGTERM": signal.SIGTERM,
            "cleanup-signal-SIGHUP": signal.SIGHUP,
        }[case]
        def synchronized_signal_group(*args):
            pgid, sig, trace_arg, phase = args
            if phase == "term" and not checkpoint.is_set():
                ns["trace_event"](trace_arg, "test-cleanup-checkpoint",
                                  phase="term", signal=int(requested))
                checkpoint.set()
                def deliver():
                    if checkpoint.wait(1):
                        os.kill(os.getpid(), requested)
                        ns["trace_event"](trace_arg, "test-cleanup-signal-sent",
                                          phase="term", signal=int(requested))
                        acknowledgement.set()
                nonlocal helper
                helper = threading.Thread(target=deliver, daemon=True)
                helper.start()
                if not acknowledgement.wait(1):
                    raise RuntimeError("cleanup signal acknowledgement timeout")
            return originals["signal_group"](*args)
        ns["signal_group"] = synchronized_signal_group

    try:
        kind = CASE_TO_SYNTHETIC[case]
        status, reason = ns["bounded"](
            synthetic(kind, child_gate, nonce, os.getpid(), ready_path),
            CHILD_WAIT_SECONDS,
            stdout,
            stderr,
            trace,
        )
        result = {"status": status, "reason": reason, "trace": trace}
    except BaseException as exc:
        result = {"worker_exception": type(exc).__name__, "message": str(exc), "trace": trace}
    finally:
        ns["subprocess"].Popen = original_popen
        for name, value in originals.items():
            if name == "sigpending":
                ns["signal"].sigpending = value
            else:
                ns[name] = value
        if helper:
            helper.join(timeout=1)
        stdout.close()
        stderr.close()
    result["containment"] = containment
    Path(result_path).write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")


def process_owned(record, nonce, case):
    return (
        record.get("nonce") == nonce and record.get("case") == case
        and isinstance(record.get("pid"), int) and record.get("pid") > 0
        and record.get("pgid") == record.get("pid")
        and record.get("session_id") == record.get("pid")
        and record.get("start_new_session") is True
    )


def child_owned(record, nonce, case, worker_pid):
    return (
        record.get("kind") == "supervisor-child"
        and record.get("worker_pid") == worker_pid
        and process_owned(record, nonce, case)
    )


def group_present(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def wait_group_absent(pgid, deadline):
    while group_present(pgid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


def parent_watchdog_cleanup(proc, worker_record, records, nonce, case,
                            watchdog, ownership_path, result_path,
                            malformed_records=None, live_handles=None,
                            group_present_fn=None, wait_group_absent_fn=None,
                            signal_fn=None, monotonic_fn=None):
    """The single parent-watchdog path used by lifecycle and focused tests."""
    group_present_fn = group_present_fn or group_present
    wait_group_absent_fn = wait_group_absent_fn or wait_group_absent
    monotonic_fn = monotonic_fn or time.monotonic
    cleanup_start = monotonic_fn()
    cleanup_deadline = cleanup_start + WATCHDOG_CLEANUP_SECONDS
    malformed_records = list(malformed_records or [])
    valid = [record for record in records
             if child_owned(record, nonce, case, proc.pid)]
    worker_owned = process_owned(worker_record, nonce, case)
    containment_ok = worker_owned and len(valid) == 1
    residual = [record for record in valid if group_present_fn(record["pgid"])]
    if residual and watchdog == "exited":
        watchdog = "residual-process"
    actions = []
    cleanup_errors = []
    if live_handles is not None:
        live_by_pid = {
            getattr(item, "record", {}).get("pid"): item
            for item in live_handles
        }
        for record in valid + [worker_record]:
            handle = live_by_pid.get(record.get("pid"))
            if (handle is None or getattr(handle, "pidfd", None) is None
                    or getattr(handle, "record", {}).get("pid") != record.get("pid")):
                cleanup_errors.append(
                    f"missing-live-handle:{record.get('pid')}")
    if watchdog != "exited" or not containment_ok:
        watchdog = watchdog if watchdog != "exited" else "containment-unproven"
        for record in valid:
            if group_present_fn(record["pgid"]):
                try:
                    if live_handles is not None:
                        handle = next((item for item in live_handles
                                       if item.record.get("pid") == record["pid"]), None)
                        if (handle is None or handle.pidfd is None
                                or handle.record.get("pid") != record["pid"]):
                            raise RuntimeError("live child handle missing or mismatched")
                        outcome = signal_fn(handle, signal.SIGKILL) if signal_fn else signal.pidfd_send_signal(handle.pidfd, signal.SIGKILL)
                    else:
                        outcome = signal_fn(record, signal.SIGKILL) if signal_fn else os.killpg(record["pgid"], signal.SIGKILL)
                    actions.append({"target": "child", "pgid": record["pgid"],
                                    "signal": int(signal.SIGKILL), "outcome": "sent"})
                except ProcessLookupError:
                    actions.append({"target": "child", "pgid": record["pgid"],
                                    "signal": int(signal.SIGKILL), "outcome": "absent"})
                except BaseException as error:
                    cleanup_errors.append(f"child-signal:{type(error).__name__}:{error}")
        if worker_owned and group_present_fn(worker_record["pgid"]):
            try:
                if live_handles is not None:
                    handle = next((item for item in live_handles
                                   if item.record.get("pid") == worker_record["pid"]), None)
                    if (handle is None or handle.pidfd is None
                            or handle.record.get("pid") != worker_record["pid"]):
                        raise RuntimeError("live worker handle missing or mismatched")
                    outcome = signal_fn(handle, signal.SIGKILL) if signal_fn else signal.pidfd_send_signal(handle.pidfd, signal.SIGKILL)
                else:
                    outcome = signal_fn(worker_record, signal.SIGKILL) if signal_fn else os.killpg(worker_record["pgid"], signal.SIGKILL)
                actions.append({"target": "worker", "pgid": worker_record["pgid"],
                                "signal": int(signal.SIGKILL), "outcome": "sent"})
            except ProcessLookupError:
                actions.append({"target": "worker", "pgid": worker_record["pgid"],
                                "signal": int(signal.SIGKILL), "outcome": "absent"})
            except BaseException as error:
                cleanup_errors.append(f"worker-signal:{type(error).__name__}:{error}")
        try:
                proc.wait(timeout=max(0, cleanup_deadline - monotonic_fn()))
        except subprocess.TimeoutExpired:
            watchdog = "worker-cleanup-timeout"
    remaining_owned_groups = [
        record for record in valid
        if not wait_group_absent_fn(record["pgid"], cleanup_deadline)
    ]
    worker_group_absent = (
        wait_group_absent_fn(worker_record["pgid"], cleanup_deadline)
        if worker_owned else False
    )
    cleanup_complete = monotonic_fn()
    cleanup_state = ("PROVEN" if worker_owned and len(valid) == 1
                     and worker_group_absent and not malformed_records
                     and not remaining_owned_groups
                     and not cleanup_errors and proc.poll() is not None
                     and cleanup_complete <= cleanup_deadline else "UNKNOWN")
    return {
        "watchdog": watchdog, "containment_ok": worker_owned and len(valid) == 1
        and not malformed_records, "worker_reaped": proc.poll() is not None,
        "residual_owned_groups": residual,
        "remaining_owned_groups": remaining_owned_groups,
         "worker_group_absent": worker_group_absent,
         "child_groups_absent": not remaining_owned_groups,
        "malformed_ownership_records": malformed_records, "valid_records": valid,
        "cleanup_actions": actions, "cleanup_errors": cleanup_errors,
        "cleanup_start_monotonic": cleanup_start,
        "cleanup_deadline_monotonic": cleanup_deadline,
        "cleanup_complete_monotonic": cleanup_complete,
        "cleanup_elapsed_seconds": cleanup_complete - cleanup_start,
        "cleanup_deadline_started": True,
        "cleanup_state": cleanup_state,
    }


def run_case(case):
    nonce = uuid.uuid4().hex
    ownership_path = MISSING_EVIDENCE / f"{case}.{nonce}.ownership.jsonl"
    result_path = MISSING_EVIDENCE / f"{case}.{nonce}.result.json"
    auth_path = MISSING_EVIDENCE / f"{case}.{nonce}.worker-authorized"
    ownership_path.touch(exist_ok=False)
    result_path.touch(exist_ok=False)
    auth_path.touch(exist_ok=False)
    cmd = [sys.executable, str(Path(__file__).resolve()), "--worker", case,
           str(ownership_path), str(result_path), str(auth_path), nonce]
    proc = subprocess.Popen(cmd, start_new_session=True)
    worker_record = {
        "kind": "worker", "nonce": nonce, "pid": proc.pid,
        "pgid": None, "session_id": None, "start_new_session": True,
        "worker_pid": os.getpid(), "case": case,
    }
    worker_authorized = False
    setup_error = None
    try:
        worker_record["pgid"] = os.getpgid(proc.pid)
        worker_record["session_id"] = os.getsid(proc.pid)
        worker_authorized = process_owned(worker_record, nonce, case)
        if not worker_authorized:
            raise RuntimeError("worker ownership validation failed")
        append_json(ownership_path, worker_record)
        auth_path.write_text(nonce + "\n", encoding="utf-8")
    except BaseException as error:
        setup_error = {"type": type(error).__name__, "message": str(error)}
        try:
            if worker_authorized and group_present(worker_record["pgid"]):
                os.killpg(worker_record["pgid"], signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
        except subprocess.TimeoutExpired:
            setup_error["cleanup"] = "worker-reap-timeout"
        return {
            "case": case,
            "nonce": nonce,
            "spawned": True,
            "worker_authorized": worker_authorized,
            "containment_ok": False,
            "watchdog": "worker-setup-failed",
            "setup_error": setup_error,
            "assertion_failures": ["worker setup/authorization failed"],
        }
    watchdog = "exited"
    try:
        proc.wait(timeout=CASE_EXECUTION_SECONDS)
    except subprocess.TimeoutExpired:
        watchdog = "watchdog-timeout"
    records = []
    malformed_records = []
    for line in ownership_path.read_text().splitlines():
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            malformed_records.append(line)
    cleanup = parent_watchdog_cleanup(
        proc, worker_record, records, nonce, case, watchdog,
        ownership_path, result_path, malformed_records,
    )
    watchdog = cleanup["watchdog"]
    valid = cleanup["valid_records"]
    remaining_owned_groups = cleanup["remaining_owned_groups"]
    containment_ok = worker_authorized and cleanup["containment_ok"]
    worker_reaped = cleanup["worker_reaped"]
    result = json.loads(result_path.read_text()) if result_path.stat().st_size else {}
    observed = {"case": case, "nonce": nonce, "watchdog": watchdog,
                "execution_state": "EXECUTED",
                "ownership_path": str(ownership_path.relative_to(ROOT)),
                "result_path": str(result_path.relative_to(ROOT)),
                "ownership_records": records, "containment_ok": containment_ok,
                "worker_reaped": worker_reaped,
                 "residual_owned_groups": cleanup["residual_owned_groups"],
                "remaining_owned_groups": remaining_owned_groups,
                 "worker_group_absent": cleanup["worker_group_absent"],
                 "child_groups_absent": cleanup["child_groups_absent"],
                 "cleanup_state": cleanup["cleanup_state"],
                 "cleanup_errors": cleanup["cleanup_errors"],
                 "cleanup_start_monotonic": cleanup["cleanup_start_monotonic"],
                 "cleanup_deadline_monotonic": cleanup["cleanup_deadline_monotonic"],
                 "cleanup_complete_monotonic": cleanup["cleanup_complete_monotonic"],
                 "cleanup_elapsed_seconds": cleanup["cleanup_elapsed_seconds"],
                 "cleanup_deadline_started": cleanup["cleanup_deadline_started"],
                "malformed_ownership_records": malformed_records,
                 "cleanup_actions": cleanup["cleanup_actions"],
                "result": result}
    expected = {
        "term-to-kill": (124, "timeout-clean", ("group-signal", "cleanup-result")),
        "cleanup-denial": (125, "timeout-cleanup-unproven", ("injected-group-signal",)),
        "probe-exception": (70, "post-wait-probe-exception-clean", ("post-wait-probe-exception",)),
        "drain-exception": (125, "pending-signal-drain-cleanup-unproven", ("pending-signal-drain-exception",)),
        "cleanup-signal-SIGINT": (130, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
        "cleanup-signal-SIGTERM": (143, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
        "cleanup-signal-SIGHUP": (129, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
    }[case]
    events = result.get("trace", [])
    names = {event.get("event") for event in events}
    observed["expected"] = {"status": expected[0], "reason": expected[1], "events": expected[2]}
    observed["assertion_failures"] = []
    if result.get("status") != expected[0] or result.get("reason") != expected[1]:
        observed["assertion_failures"].append("status/reason mismatch")
    if any(event not in names for event in expected[2]):
        observed["assertion_failures"].append("required trace event missing")
    if case.startswith("cleanup-signal-"):
        requested = {
            "cleanup-signal-SIGINT": int(signal.SIGINT),
            "cleanup-signal-SIGTERM": int(signal.SIGTERM),
            "cleanup-signal-SIGHUP": int(signal.SIGHUP),
        }[case]
        checkpoint_events = [
            e for e in events
            if e.get("event") == "test-cleanup-checkpoint"
            and e.get("phase") == "term" and e.get("signal") == requested
        ]
        sent_events = [
            e for e in events
            if e.get("event") == "test-cleanup-signal-sent"
            and e.get("phase") == "term" and e.get("signal") == requested
        ]
        delivery_events = [
            e for e in events
            if e.get("event") == "signal-delivery"
            and e.get("signal") == requested
            and e.get("stage") == "cleanup-pending-drain"
        ]
        if not (checkpoint_events and sent_events and delivery_events):
            observed["assertion_failures"].append(
                "exact cleanup signal checkpoint/sent/pending-drain proof missing"
            )
        else:
            positions = [
                next(i for i, e in enumerate(events) if e is item)
                for item in (checkpoint_events[0], sent_events[0], delivery_events[0])
            ]
            if not (positions[0] < positions[1] < positions[2]):
                observed["assertion_failures"].append(
                    "cleanup signal trace order checkpoint<sent<delivery failed"
                )
    if case == "term-to-kill":
        signals = {(e.get("phase"), e.get("signal"), e.get("outcome")) for e in events if e.get("event") == "group-signal"}
        if ("term", int(signal.SIGTERM), "sent") not in signals:
            observed["assertion_failures"].append("actual TERM sent not observed")
        if ("kill", int(signal.SIGKILL), "sent") not in signals:
            observed["assertion_failures"].append("actual KILL sent not observed")
        if not any(e.get("event") == "cleanup-result" and e.get("reason") == "kill-clean" for e in events):
            observed["assertion_failures"].append("kill-clean not observed")
    if case == "cleanup-denial":
        denials = {
            (event.get("phase"), event.get("signal"), event.get("outcome"))
            for event in events
            if event.get("event") == "injected-group-signal"
        }
        if ("term", int(signal.SIGTERM), "denied") not in denials:
            observed["assertion_failures"].append(
                "injected TERM denial not observed"
            )
        if ("kill", int(signal.SIGKILL), "denied") not in denials:
            observed["assertion_failures"].append(
                "injected KILL denial not observed"
            )
    if not worker_authorized:
        observed["assertion_failures"].append("worker authorization handshake failed")
    if len(valid) != 1:
        observed["assertion_failures"].append("expected exactly one valid supervisor-child record")
    if malformed_records:
        observed["assertion_failures"].append("malformed ownership record")
    if not containment_ok:
        observed["assertion_failures"].append("containment unproven")
    if watchdog != "exited":
        observed["assertion_failures"].append("watchdog did not observe clean exit")
    if remaining_owned_groups:
        observed["assertion_failures"].append("owned supervisor group remained present")
    return observed


def containment_blocker(result):
    if not isinstance(result, dict):
        return "case result is not an object"
    if result.get("containment_ok") is not True:
        return "containment_ok is not proven true"
    if result.get("worker_reaped") is not True:
        return "worker reaping is not proven"
    if result.get("cleanup_state") != "PROVEN":
        return "cleanup state is missing or not proven"
    if result.get("worker_group_absent") is not True:
        return "worker group absence is not proven"
    if result.get("child_groups_absent") is not True:
        return "child group absence is not proven"
    if not isinstance(result.get("cleanup_errors"), list):
        return "cleanup errors are missing or malformed"
    if result["cleanup_errors"]:
        return "cleanup errors are present"
    if result.get("cleanup_deadline_started") is not True:
        return "cleanup deadline evidence is missing"
    timing = [
        result.get("cleanup_start_monotonic"),
        result.get("cleanup_deadline_monotonic"),
        result.get("cleanup_complete_monotonic"),
        result.get("cleanup_elapsed_seconds"),
    ]
    if any(isinstance(value, bool) or not isinstance(value, (int, float))
           or not math.isfinite(value) for value in timing):
        return "cleanup timing evidence is missing or malformed"
    start, deadline, complete, elapsed = timing
    if not (start <= complete <= deadline and elapsed >= 0):
        return "cleanup timing is contradictory"
    tolerance = 1e-6
    if abs(elapsed - (complete - start)) > tolerance:
        return "cleanup elapsed time is inconsistent"
    if abs((deadline - start) - WATCHDOG_CLEANUP_SECONDS) > tolerance:
        return "cleanup deadline budget is inconsistent"
    for field in (
        "remaining_owned_groups",
        "malformed_ownership_records",
        "assertion_failures",
    ):
        if not isinstance(result.get(field), list):
            return f"{field} is missing or malformed"
    if result["remaining_owned_groups"]:
        return "owned supervisor groups remain present"
    if result["malformed_ownership_records"]:
        return "ownership evidence is malformed"
    for failure in result["assertion_failures"]:
        if not isinstance(failure, str):
            return "assertion failure evidence is malformed"
        if any(marker in failure for marker in CONTAINMENT_ASSERTION_MARKERS):
            return f"containment assertion failed: {failure}"
    if result.get("watchdog") == "worker-cleanup-timeout":
        return "watchdog could not reap the worker"
    return None


def schedule_cases(case_runner=run_case, cases=MISSING_CASES):
    results = []
    for index, case in enumerate(cases):
        try:
            result = case_runner(case)
        except BaseException as error:
            result = {
                "case": case,
                "execution_state": "EXECUTION_ERROR",
                "containment_ok": False,
                "worker_reaped": False,
                "remaining_owned_groups": [],
                "malformed_ownership_records": [],
                "assertion_failures": ["unexpected case exception"],
                "exception_type": type(error).__name__,
                "exception_message": str(error),
            }
        results.append(result)
        blocker = containment_blocker(result)
        if blocker is None:
            continue
        for remaining in cases[index + 1:]:
            results.append({
                "case": remaining,
                "execution_state": "NOT_EXECUTED",
                "blocked_by": case,
                "blocking_reason": blocker,
                "containment_ok": False,
                "assertion_failures": ["not executed after containment stop"],
            })
        break
    return results


def scheduler_self_test():
    base = {
        "execution_state": "EXECUTED",
        "containment_ok": True,
        "worker_reaped": True,
        "remaining_owned_groups": [],
        "malformed_ownership_records": [],
        "assertion_failures": [],
        "watchdog": "exited",
        "cleanup_state": "PROVEN",
        "cleanup_errors": [],
        "cleanup_deadline_started": True,
        "cleanup_start_monotonic": 10.0,
        "cleanup_deadline_monotonic": 13.0,
        "cleanup_complete_monotonic": 12.0,
        "cleanup_elapsed_seconds": 2.0,
        "worker_group_absent": True,
        "child_groups_absent": True,
    }
    scenarios = {
        "proven-permits-next": (
            lambda case: dict(base, case=case),
            2,
            ["EXECUTED", "EXECUTED"],
        ),
        "false-stops": (
            lambda case: dict(base, case=case, containment_ok=False),
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-stops": (
            lambda case: {
                key: value for key, value in dict(base, case=case).items()
                if key != "containment_ok"
            },
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "contradiction-stops": (
            lambda case: dict(
                base,
                case=case,
                remaining_owned_groups=[{"pgid": 999999}],
            ),
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-state": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_state"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "unknown-cleanup-state": (
            lambda case: dict(base, case=case, cleanup_state="UNKNOWN"),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-worker-absence": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "worker_group_absent"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-child-absence": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "child_groups_absent"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "cleanup-error-stops": (
            lambda case: dict(base, case=case, cleanup_errors=["injected"]),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-errors": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_errors"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "malformed-cleanup-errors": (
            lambda case: dict(base, case=case, cleanup_errors="bad"),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-timing": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_complete_monotonic"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "completion-after-deadline": (
            lambda case: dict(base, case=case, cleanup_complete_monotonic=14.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "negative-elapsed": (
            lambda case: dict(base, case=case, cleanup_elapsed_seconds=-1.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "inconsistent-elapsed": (
            lambda case: dict(base, case=case, cleanup_elapsed_seconds=1.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "wrong-cleanup-budget": (
            lambda case: dict(base, case=case, cleanup_deadline_monotonic=14.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
    }
    outcomes = {}
    cases = ("first", "second")
    for name, (runner, expected_count, expected_states) in scenarios.items():
        results = schedule_cases(runner, cases)
        states = [item.get("execution_state") for item in results]
        passed = len(results) == expected_count and states == expected_states
        outcomes[name] = {"passed": passed, "states": states}
    calls = []
    def raising_runner(case):
        calls.append(case)
        raise RuntimeError("fabricated scheduler exception")
    exception_results = schedule_cases(raising_runner, cases)
    exception_states = [
        item.get("execution_state") for item in exception_results
    ]
    outcomes["exception-stops"] = {
        "passed": calls == ["first"]
        and exception_states == ["EXECUTION_ERROR", "NOT_EXECUTED"],
        "states": exception_states,
    }
    print(json.dumps(outcomes, indent=2, sort_keys=True))
    if not all(item["passed"] for item in outcomes.values()):
        raise SystemExit("scheduler self-test failed")
    cli_parser_self_test()
    assert source_stability({"a": "1"}, {"a": "1"}) == "PROVEN"
    assert source_stability({"a": "1"}, {"a": "2"}) == "FAILED"


def main():
    pre = {"launcher": digest(LAUNCHER), "proposal": digest(PROPOSAL)}
    if pre != {"launcher": EXPECTED_LAUNCHER, "proposal": EXPECTED_PROPOSAL}:
        raise SystemExit("hash precondition failed")
    harness_paths = {
        "run_validation": Path(__file__).resolve(),
        "run_containment": Path(__file__).resolve().with_name("run_containment.py"),
    }
    source_pre = {name: digest(path) for name, path in harness_paths.items()}
    source, constants, locations, extraction_hash = extract_source()
    if (
        constants["TERM_WAIT_SECONDS"] != TERM_GRACE_SECONDS
        or constants["KILL_WAIT_SECONDS"] != KILL_GRACE_SECONDS
    ):
        raise SystemExit("extracted cleanup grace mismatch")
    MISSING_EVIDENCE.mkdir(parents=True, exist_ok=False)
    (MISSING_EVIDENCE / "extracted_supervisor_source.py").write_text(source, encoding="utf-8")
    results = schedule_cases()
    post = {"launcher": digest(LAUNCHER), "proposal": digest(PROPOSAL)}
    source_post = {name: digest(path) for name, path in harness_paths.items()}
    raw = {"batch": "missing_cases_only", "pre_hashes": pre, "post_hashes": post,
           "source_extraction_sha256": extraction_hash, "source_locations": locations,
           "harness_source_pre_hashes": source_pre,
           "harness_source_post_hashes": source_post,
           "harness_source_stability": (
               source_stability(source_pre, source_post)
           ),
           "harness_source_stability_limit": (
               "Pre/post hashes do not prove absence of transient changes during execution."
           ),
            "case_execution_seconds": CASE_EXECUTION_SECONDS,
            "watchdog_cleanup_seconds": WATCHDOG_CLEANUP_SECONDS,
            "child_wait_seconds": CHILD_WAIT_SECONDS,
             "term_grace_seconds": TERM_GRACE_SECONDS, "kill_grace_seconds": KILL_GRACE_SECONDS,
           "case_to_synthetic": CASE_TO_SYNTHETIC, "cases": results,
             "instrumentation": "External namespace Popen recording/readiness wrapper, Linux PR_SET_PDEATHSIG child lifetime guard, and named monkeypatches only; child controller configuration is recorded, not runtime-proven.",
           "assertions_failed": [r for r in results if r["assertion_failures"]]}
    (MISSING_EVIDENCE / "raw.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    failures = raw["assertions_failed"]
    if raw["harness_source_stability"] != "PROVEN":
        raise SystemExit("harness source stability failed after evidence write")
    if failures:
        raise SystemExit(f"validation assertions failed after evidence write: {len(failures)}")


if __name__ == "__main__":
    cli = parse_cli(sys.argv[1:])
    if cli["mode"] == "help":
        print_help()
    elif cli["mode"] == "worker":
        worker(cli["case"], *(Path(path) for path in cli["paths"]), cli["nonce"])
    elif cli["mode"] == "scheduler-self-test":
        scheduler_self_test()
    else:
        main()
#!/usr/bin/env python3
"""Preparation-only harness for the seven not-yet-executed supervisor cases."""
import ast
import ctypes
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "attached_assets/usbay-fda-readonly-diskutil-diagnostic.zsh"
PROPOSAL = ROOT / "attached_assets/usbay-temporary-terminal-full-disk-access-diagnostic-proposal.md"
EVIDENCE = Path(__file__).resolve().parent / "evidence"
MISSING_EVIDENCE = EVIDENCE / "missing_cases_batch"
EXPECTED_LAUNCHER = "b19bd48a797b3f5659c6fb850d4baff1792c6c73153bfec13b4eb6f5976f320b"
EXPECTED_PROPOSAL = "ef648fadc31e252ce91ff6ee754b0670e6f477b5afd8a5e4a5bc3cdcb675429c"
CHILD_WAIT_SECONDS = 0.08
TERM_GRACE_SECONDS = 2
KILL_GRACE_SECONDS = 2
WATCHDOG_CLEANUP_SECONDS = 3
CASE_EXECUTION_SECONDS = 12
MISSING_CASES = (
    "term-to-kill", "cleanup-denial", "probe-exception", "drain-exception",
    "cleanup-signal-SIGINT", "cleanup-signal-SIGTERM", "cleanup-signal-SIGHUP",
)
CASE_TO_SYNTHETIC = {
    "term-to-kill": "term_ignore_ready",
    "cleanup-denial": "sleep",
    "probe-exception": "exit0",
    "drain-exception": "exit0",
    "cleanup-signal-SIGINT": "sleep",
    "cleanup-signal-SIGTERM": "sleep",
    "cleanup-signal-SIGHUP": "sleep",
}
CONTAINMENT_ASSERTION_MARKERS = (
    "worker authorization",
    "supervisor-child record",
    "malformed ownership",
    "containment unproven",
    "watchdog did not observe clean exit",
    "owned supervisor group remained",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_stability(pre, post):
    """Assess only equality of the recorded pre/post source hashes."""
    return "PROVEN" if dict(pre) == dict(post) else "FAILED"


def parse_cli(argv):
    """Validate dispatch without touching evidence, channels, or processes."""
    args = list(argv)
    if args in (["--help"], ["-h"]):
        return {"mode": "help"}
    if args == ["--scheduler-self-test"]:
        return {"mode": "scheduler-self-test"}
    if args == []:
        return {"mode": "main"}
    if len(args) == 6 and args[0] == "--worker":
        case, ownership, result, auth, nonce = args[1:]
        if case not in MISSING_CASES or not nonce or nonce.startswith("-"):
            raise SystemExit("invalid worker case or nonce")
        paths = (ownership, result, auth)
        if any(not item or item.startswith("-") for item in paths):
            raise SystemExit("invalid worker paths")
        return {"mode": "worker", "case": case, "paths": paths, "nonce": nonce}
    raise SystemExit("unknown or malformed arguments")


def print_help():
    print("usage: run_validation.py [--scheduler-self-test|--worker CASE OWNERSHIP RESULT AUTH NONCE]")


def cli_parser_self_test():
    """Pure parser/dispatch checks; no evidence, channels, or processes."""
    side_effects = {"count": 0}
    for argv, expected in (
        (["--help"], "help"),
        (["--scheduler-self-test"], "scheduler-self-test"),
    ):
        parsed = parse_cli(argv)
        assert parsed["mode"] == expected
        assert side_effects["count"] == 0
    for argv in (
        ["--unknown"],
        ["--worker", "bad", "a", "b", "c", "n"],
        ["--worker", "term-to-kill", "a", "b", "c"],
        ["--worker", "term-to-kill", "-a", "b", "c", "n"],
        ["--worker", "term-to-kill", "a", "--b", "c", "n"],
        ["--worker", "term-to-kill", "a", "b", "c", "-n"],
    ):
        try:
            parse_cli(argv)
        except SystemExit:
            pass
        else:
            raise AssertionError("malformed CLI accepted")
        assert side_effects["count"] == 0


def extract_source():
    raw = LAUNCHER.read_text()
    py = raw.split("<<'PY'\n", 1)[1].split("\ntry:\n    final_status=main()", 1)[0]
    tree = ast.parse(py)
    chosen = [
        node for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef))
        and (not isinstance(node, ast.FunctionDef) or node.name != "main")
    ]
    source = ast.unparse(ast.Module(body=chosen, type_ignores=[])) + "\n"
    namespace = {"__name__": "extracted_supervisor"}
    exec(compile(ast.Module(body=chosen, type_ignores=[]), str(LAUNCHER), "exec"), namespace)
    locations = [f"{node.__class__.__name__}:{getattr(node, 'name', '')}" for node in chosen]
    return source, namespace, locations, hashlib.sha256(source.encode()).hexdigest()


def synthetic(kind, gate_path, nonce, worker_pid, ready_path=None):
    behavior = {
        "sleep": "time.sleep(.35)",
        "exit0": "raise SystemExit(0)",
        "term_ignore_ready": (
            "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            "pathlib.Path(sys.argv[3]).write_text('READY\\n')\n"
            "time.sleep(10)"
        ),
    }[kind]
    code = (
        "import ctypes,os,pathlib,signal,sys,time\n"
        "if ctypes.CDLL(None).prctl(1,signal.SIGKILL) != 0: raise SystemExit(91)\n"
        "if os.getppid() != int(sys.argv[4]): raise SystemExit(92)\n"
        "gate=pathlib.Path(sys.argv[1]); nonce=sys.argv[2]\n"
        "while True:\n"
        "    try:\n"
        "        if gate.read_text().strip()==nonce: break\n"
        "    except (FileNotFoundError,OSError): pass\n"
        "    time.sleep(.01)\n"
        + behavior + "\n"
    )
    return [
        sys.executable, "-c", "exec(" + repr(code) + ")",
        str(gate_path), nonce, str(ready_path or ""), str(worker_pid),
    ]


def append_json(path, item):
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(item, sort_keys=True) + "\n")
        stream.flush()


def worker(case, ownership_path, result_path, auth_path, nonce):
    while auth_path.read_text(encoding="utf-8").strip() != nonce:
        time.sleep(0.01)
    _, ns, _, _ = extract_source()
    trace = []
    stdout = tempfile.TemporaryFile()
    stderr = tempfile.TemporaryFile()
    originals = {}
    helper = None
    checkpoint = threading.Event()
    acknowledgement = threading.Event()
    ready_path = Path(str(result_path) + ".ready")
    child_gate = Path(str(result_path) + ".child-gate")
    containment = {
        "nonce": nonce,
        "worker_pid": os.getpid(),
        "controller_mechanism": "Linux prctl(PR_SET_PDEATHSIG, SIGKILL) with child PPID check",
        "records": [],
    }

    original_popen = ns["subprocess"].Popen
    def recording_popen(*args, **kwargs):
        child = original_popen(*args, **kwargs)
        record = {"pgid": None}
        try:
            record = {
                "kind": "supervisor-child", "nonce": nonce, "pid": child.pid,
                "pgid": os.getpgid(child.pid), "session_id": os.getsid(child.pid),
                "start_new_session": kwargs.get("start_new_session", False),
                "worker_pid": os.getpid(), "case": case, "child_gate": str(child_gate),
            }
            if not child_owned(record, nonce, case, os.getpid()):
                raise RuntimeError("supervisor-child ownership validation failed")
            containment["records"].append(record)
            append_json(ownership_path, record)
            child_gate.write_text(nonce + "\n", encoding="utf-8")
            if case == "term-to-kill":
                deadline = time.monotonic() + 2
                while not ready_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not ready_path.exists():
                    raise RuntimeError("TERM handler readiness was not proven")
        except BaseException:
            if isinstance(record.get("pgid"), int):
                try:
                    os.killpg(record["pgid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                child.kill()
            try:
                child.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
            raise
        return child

    ns["subprocess"].Popen = recording_popen
    if case == "cleanup-denial":
        originals["signal_group"] = ns["signal_group"]
        def denied_signal_group(pgid, sig, trace_arg, phase):
            outcome = "denied"
            ns["trace_event"](trace_arg, "injected-group-signal", phase=phase,
                              signal=int(sig), outcome=outcome)
            return outcome
        ns["signal_group"] = denied_signal_group
    elif case == "probe-exception":
        originals["group_state"] = ns["group_state"]
        def injected_probe(*args, **kwargs):
            raise RuntimeError("injected-probe")
        ns["group_state"] = injected_probe
    elif case == "drain-exception":
        originals["sigpending"] = ns["signal"].sigpending
        ns["signal"].sigpending = lambda: (_ for _ in ()).throw(RuntimeError("injected-drain"))
    elif case.startswith("cleanup-signal-"):
        originals["signal_group"] = ns["signal_group"]
        requested = {
            "cleanup-signal-SIGINT": signal.SIGINT,
            "cleanup-signal-SIGTERM": signal.SIGTERM,
            "cleanup-signal-SIGHUP": signal.SIGHUP,
        }[case]
        def synchronized_signal_group(*args):
            pgid, sig, trace_arg, phase = args
            if phase == "term" and not checkpoint.is_set():
                ns["trace_event"](trace_arg, "test-cleanup-checkpoint",
                                  phase="term", signal=int(requested))
                checkpoint.set()
                def deliver():
                    if checkpoint.wait(1):
                        os.kill(os.getpid(), requested)
                        ns["trace_event"](trace_arg, "test-cleanup-signal-sent",
                                          phase="term", signal=int(requested))
                        acknowledgement.set()
                nonlocal helper
                helper = threading.Thread(target=deliver, daemon=True)
                helper.start()
                if not acknowledgement.wait(1):
                    raise RuntimeError("cleanup signal acknowledgement timeout")
            return originals["signal_group"](*args)
        ns["signal_group"] = synchronized_signal_group

    try:
        kind = CASE_TO_SYNTHETIC[case]
        status, reason = ns["bounded"](
            synthetic(kind, child_gate, nonce, os.getpid(), ready_path),
            CHILD_WAIT_SECONDS,
            stdout,
            stderr,
            trace,
        )
        result = {"status": status, "reason": reason, "trace": trace}
    except BaseException as exc:
        result = {"worker_exception": type(exc).__name__, "message": str(exc), "trace": trace}
    finally:
        ns["subprocess"].Popen = original_popen
        for name, value in originals.items():
            if name == "sigpending":
                ns["signal"].sigpending = value
            else:
                ns[name] = value
        if helper:
            helper.join(timeout=1)
        stdout.close()
        stderr.close()
    result["containment"] = containment
    Path(result_path).write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")


def process_owned(record, nonce, case):
    return (
        record.get("nonce") == nonce and record.get("case") == case
        and isinstance(record.get("pid"), int) and record.get("pid") > 0
        and record.get("pgid") == record.get("pid")
        and record.get("session_id") == record.get("pid")
        and record.get("start_new_session") is True
    )


def child_owned(record, nonce, case, worker_pid):
    return (
        record.get("kind") == "supervisor-child"
        and record.get("worker_pid") == worker_pid
        and process_owned(record, nonce, case)
    )


def group_present(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def wait_group_absent(pgid, deadline):
    while group_present(pgid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


def parent_watchdog_cleanup(proc, worker_record, records, nonce, case,
                            watchdog, ownership_path, result_path,
                            malformed_records=None, live_handles=None,
                            group_present_fn=None, wait_group_absent_fn=None,
                            signal_fn=None, monotonic_fn=None):
    """The single parent-watchdog path used by lifecycle and focused tests."""
    group_present_fn = group_present_fn or group_present
    wait_group_absent_fn = wait_group_absent_fn or wait_group_absent
    monotonic_fn = monotonic_fn or time.monotonic
    cleanup_start = monotonic_fn()
    cleanup_deadline = cleanup_start + WATCHDOG_CLEANUP_SECONDS
    malformed_records = list(malformed_records or [])
    valid = [record for record in records
             if child_owned(record, nonce, case, proc.pid)]
    worker_owned = process_owned(worker_record, nonce, case)
    containment_ok = worker_owned and len(valid) == 1
    residual = [record for record in valid if group_present_fn(record["pgid"])]
    if residual and watchdog == "exited":
        watchdog = "residual-process"
    actions = []
    cleanup_errors = []
    if live_handles is not None:
        live_by_pid = {
            getattr(item, "record", {}).get("pid"): item
            for item in live_handles
        }
        for record in valid + [worker_record]:
            handle = live_by_pid.get(record.get("pid"))
            if (handle is None or getattr(handle, "pidfd", None) is None
                    or getattr(handle, "record", {}).get("pid") != record.get("pid")):
                cleanup_errors.append(
                    f"missing-live-handle:{record.get('pid')}")
    if watchdog != "exited" or not containment_ok:
        watchdog = watchdog if watchdog != "exited" else "containment-unproven"
        for record in valid:
            if group_present_fn(record["pgid"]):
                try:
                    if live_handles is not None:
                        handle = next((item for item in live_handles
                                       if item.record.get("pid") == record["pid"]), None)
                        if (handle is None or handle.pidfd is None
                                or handle.record.get("pid") != record["pid"]):
                            raise RuntimeError("live child handle missing or mismatched")
                        outcome = signal_fn(handle, signal.SIGKILL) if signal_fn else signal.pidfd_send_signal(handle.pidfd, signal.SIGKILL)
                    else:
                        outcome = signal_fn(record, signal.SIGKILL) if signal_fn else os.killpg(record["pgid"], signal.SIGKILL)
                    actions.append({"target": "child", "pgid": record["pgid"],
                                    "signal": int(signal.SIGKILL), "outcome": "sent"})
                except ProcessLookupError:
                    actions.append({"target": "child", "pgid": record["pgid"],
                                    "signal": int(signal.SIGKILL), "outcome": "absent"})
                except BaseException as error:
                    cleanup_errors.append(f"child-signal:{type(error).__name__}:{error}")
        if worker_owned and group_present_fn(worker_record["pgid"]):
            try:
                if live_handles is not None:
                    handle = next((item for item in live_handles
                                   if item.record.get("pid") == worker_record["pid"]), None)
                    if (handle is None or handle.pidfd is None
                            or handle.record.get("pid") != worker_record["pid"]):
                        raise RuntimeError("live worker handle missing or mismatched")
                    outcome = signal_fn(handle, signal.SIGKILL) if signal_fn else signal.pidfd_send_signal(handle.pidfd, signal.SIGKILL)
                else:
                    outcome = signal_fn(worker_record, signal.SIGKILL) if signal_fn else os.killpg(worker_record["pgid"], signal.SIGKILL)
                actions.append({"target": "worker", "pgid": worker_record["pgid"],
                                "signal": int(signal.SIGKILL), "outcome": "sent"})
            except ProcessLookupError:
                actions.append({"target": "worker", "pgid": worker_record["pgid"],
                                "signal": int(signal.SIGKILL), "outcome": "absent"})
            except BaseException as error:
                cleanup_errors.append(f"worker-signal:{type(error).__name__}:{error}")
        try:
                proc.wait(timeout=max(0, cleanup_deadline - monotonic_fn()))
        except subprocess.TimeoutExpired:
            watchdog = "worker-cleanup-timeout"
    remaining_owned_groups = [
        record for record in valid
        if not wait_group_absent_fn(record["pgid"], cleanup_deadline)
    ]
    worker_group_absent = (
        wait_group_absent_fn(worker_record["pgid"], cleanup_deadline)
        if worker_owned else False
    )
    cleanup_complete = monotonic_fn()
    cleanup_state = ("PROVEN" if worker_owned and len(valid) == 1
                     and worker_group_absent and not malformed_records
                     and not remaining_owned_groups
                     and not cleanup_errors and proc.poll() is not None
                     and cleanup_complete <= cleanup_deadline else "UNKNOWN")
    return {
        "watchdog": watchdog, "containment_ok": worker_owned and len(valid) == 1
        and not malformed_records, "worker_reaped": proc.poll() is not None,
        "residual_owned_groups": residual,
        "remaining_owned_groups": remaining_owned_groups,
         "worker_group_absent": worker_group_absent,
         "child_groups_absent": not remaining_owned_groups,
        "malformed_ownership_records": malformed_records, "valid_records": valid,
        "cleanup_actions": actions, "cleanup_errors": cleanup_errors,
        "cleanup_start_monotonic": cleanup_start,
        "cleanup_deadline_monotonic": cleanup_deadline,
        "cleanup_complete_monotonic": cleanup_complete,
        "cleanup_elapsed_seconds": cleanup_complete - cleanup_start,
        "cleanup_deadline_started": True,
        "cleanup_state": cleanup_state,
    }


def run_case(case):
    nonce = uuid.uuid4().hex
    ownership_path = MISSING_EVIDENCE / f"{case}.{nonce}.ownership.jsonl"
    result_path = MISSING_EVIDENCE / f"{case}.{nonce}.result.json"
    auth_path = MISSING_EVIDENCE / f"{case}.{nonce}.worker-authorized"
    ownership_path.touch(exist_ok=False)
    result_path.touch(exist_ok=False)
    auth_path.touch(exist_ok=False)
    cmd = [sys.executable, str(Path(__file__).resolve()), "--worker", case,
           str(ownership_path), str(result_path), str(auth_path), nonce]
    proc = subprocess.Popen(cmd, start_new_session=True)
    worker_record = {
        "kind": "worker", "nonce": nonce, "pid": proc.pid,
        "pgid": None, "session_id": None, "start_new_session": True,
        "worker_pid": os.getpid(), "case": case,
    }
    worker_authorized = False
    setup_error = None
    try:
        worker_record["pgid"] = os.getpgid(proc.pid)
        worker_record["session_id"] = os.getsid(proc.pid)
        worker_authorized = process_owned(worker_record, nonce, case)
        if not worker_authorized:
            raise RuntimeError("worker ownership validation failed")
        append_json(ownership_path, worker_record)
        auth_path.write_text(nonce + "\n", encoding="utf-8")
    except BaseException as error:
        setup_error = {"type": type(error).__name__, "message": str(error)}
        try:
            if worker_authorized and group_present(worker_record["pgid"]):
                os.killpg(worker_record["pgid"], signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=WATCHDOG_CLEANUP_SECONDS)
        except subprocess.TimeoutExpired:
            setup_error["cleanup"] = "worker-reap-timeout"
        return {
            "case": case,
            "nonce": nonce,
            "spawned": True,
            "worker_authorized": worker_authorized,
            "containment_ok": False,
            "watchdog": "worker-setup-failed",
            "setup_error": setup_error,
            "assertion_failures": ["worker setup/authorization failed"],
        }
    watchdog = "exited"
    try:
        proc.wait(timeout=CASE_EXECUTION_SECONDS)
    except subprocess.TimeoutExpired:
        watchdog = "watchdog-timeout"
    records = []
    malformed_records = []
    for line in ownership_path.read_text().splitlines():
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            malformed_records.append(line)
    cleanup = parent_watchdog_cleanup(
        proc, worker_record, records, nonce, case, watchdog,
        ownership_path, result_path, malformed_records,
    )
    watchdog = cleanup["watchdog"]
    valid = cleanup["valid_records"]
    remaining_owned_groups = cleanup["remaining_owned_groups"]
    containment_ok = worker_authorized and cleanup["containment_ok"]
    worker_reaped = cleanup["worker_reaped"]
    result = json.loads(result_path.read_text()) if result_path.stat().st_size else {}
    observed = {"case": case, "nonce": nonce, "watchdog": watchdog,
                "execution_state": "EXECUTED",
                "ownership_path": str(ownership_path.relative_to(ROOT)),
                "result_path": str(result_path.relative_to(ROOT)),
                "ownership_records": records, "containment_ok": containment_ok,
                "worker_reaped": worker_reaped,
                 "residual_owned_groups": cleanup["residual_owned_groups"],
                "remaining_owned_groups": remaining_owned_groups,
                 "worker_group_absent": cleanup["worker_group_absent"],
                 "child_groups_absent": cleanup["child_groups_absent"],
                 "cleanup_state": cleanup["cleanup_state"],
                 "cleanup_errors": cleanup["cleanup_errors"],
                 "cleanup_start_monotonic": cleanup["cleanup_start_monotonic"],
                 "cleanup_deadline_monotonic": cleanup["cleanup_deadline_monotonic"],
                 "cleanup_complete_monotonic": cleanup["cleanup_complete_monotonic"],
                 "cleanup_elapsed_seconds": cleanup["cleanup_elapsed_seconds"],
                 "cleanup_deadline_started": cleanup["cleanup_deadline_started"],
                "malformed_ownership_records": malformed_records,
                 "cleanup_actions": cleanup["cleanup_actions"],
                "result": result}
    expected = {
        "term-to-kill": (124, "timeout-clean", ("group-signal", "cleanup-result")),
        "cleanup-denial": (125, "timeout-cleanup-unproven", ("injected-group-signal",)),
        "probe-exception": (70, "post-wait-probe-exception-clean", ("post-wait-probe-exception",)),
        "drain-exception": (125, "pending-signal-drain-cleanup-unproven", ("pending-signal-drain-exception",)),
        "cleanup-signal-SIGINT": (130, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
        "cleanup-signal-SIGTERM": (143, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
        "cleanup-signal-SIGHUP": (129, "interrupted-clean", ("test-cleanup-checkpoint", "signal-delivery")),
    }[case]
    events = result.get("trace", [])
    names = {event.get("event") for event in events}
    observed["expected"] = {"status": expected[0], "reason": expected[1], "events": expected[2]}
    observed["assertion_failures"] = []
    if result.get("status") != expected[0] or result.get("reason") != expected[1]:
        observed["assertion_failures"].append("status/reason mismatch")
    if any(event not in names for event in expected[2]):
        observed["assertion_failures"].append("required trace event missing")
    if case.startswith("cleanup-signal-"):
        requested = {
            "cleanup-signal-SIGINT": int(signal.SIGINT),
            "cleanup-signal-SIGTERM": int(signal.SIGTERM),
            "cleanup-signal-SIGHUP": int(signal.SIGHUP),
        }[case]
        checkpoint_events = [
            e for e in events
            if e.get("event") == "test-cleanup-checkpoint"
            and e.get("phase") == "term" and e.get("signal") == requested
        ]
        sent_events = [
            e for e in events
            if e.get("event") == "test-cleanup-signal-sent"
            and e.get("phase") == "term" and e.get("signal") == requested
        ]
        delivery_events = [
            e for e in events
            if e.get("event") == "signal-delivery"
            and e.get("signal") == requested
            and e.get("stage") == "cleanup-pending-drain"
        ]
        if not (checkpoint_events and sent_events and delivery_events):
            observed["assertion_failures"].append(
                "exact cleanup signal checkpoint/sent/pending-drain proof missing"
            )
        else:
            positions = [
                next(i for i, e in enumerate(events) if e is item)
                for item in (checkpoint_events[0], sent_events[0], delivery_events[0])
            ]
            if not (positions[0] < positions[1] < positions[2]):
                observed["assertion_failures"].append(
                    "cleanup signal trace order checkpoint<sent<delivery failed"
                )
    if case == "term-to-kill":
        signals = {(e.get("phase"), e.get("signal"), e.get("outcome")) for e in events if e.get("event") == "group-signal"}
        if ("term", int(signal.SIGTERM), "sent") not in signals:
            observed["assertion_failures"].append("actual TERM sent not observed")
        if ("kill", int(signal.SIGKILL), "sent") not in signals:
            observed["assertion_failures"].append("actual KILL sent not observed")
        if not any(e.get("event") == "cleanup-result" and e.get("reason") == "kill-clean" for e in events):
            observed["assertion_failures"].append("kill-clean not observed")
    if case == "cleanup-denial":
        denials = {
            (event.get("phase"), event.get("signal"), event.get("outcome"))
            for event in events
            if event.get("event") == "injected-group-signal"
        }
        if ("term", int(signal.SIGTERM), "denied") not in denials:
            observed["assertion_failures"].append(
                "injected TERM denial not observed"
            )
        if ("kill", int(signal.SIGKILL), "denied") not in denials:
            observed["assertion_failures"].append(
                "injected KILL denial not observed"
            )
    if not worker_authorized:
        observed["assertion_failures"].append("worker authorization handshake failed")
    if len(valid) != 1:
        observed["assertion_failures"].append("expected exactly one valid supervisor-child record")
    if malformed_records:
        observed["assertion_failures"].append("malformed ownership record")
    if not containment_ok:
        observed["assertion_failures"].append("containment unproven")
    if watchdog != "exited":
        observed["assertion_failures"].append("watchdog did not observe clean exit")
    if remaining_owned_groups:
        observed["assertion_failures"].append("owned supervisor group remained present")
    return observed


def containment_blocker(result):
    if not isinstance(result, dict):
        return "case result is not an object"
    if result.get("containment_ok") is not True:
        return "containment_ok is not proven true"
    if result.get("worker_reaped") is not True:
        return "worker reaping is not proven"
    if result.get("cleanup_state") != "PROVEN":
        return "cleanup state is missing or not proven"
    if result.get("worker_group_absent") is not True:
        return "worker group absence is not proven"
    if result.get("child_groups_absent") is not True:
        return "child group absence is not proven"
    if not isinstance(result.get("cleanup_errors"), list):
        return "cleanup errors are missing or malformed"
    if result["cleanup_errors"]:
        return "cleanup errors are present"
    if result.get("cleanup_deadline_started") is not True:
        return "cleanup deadline evidence is missing"
    timing = [
        result.get("cleanup_start_monotonic"),
        result.get("cleanup_deadline_monotonic"),
        result.get("cleanup_complete_monotonic"),
        result.get("cleanup_elapsed_seconds"),
    ]
    if any(isinstance(value, bool) or not isinstance(value, (int, float))
           or not math.isfinite(value) for value in timing):
        return "cleanup timing evidence is missing or malformed"
    start, deadline, complete, elapsed = timing
    if not (start <= complete <= deadline and elapsed >= 0):
        return "cleanup timing is contradictory"
    tolerance = 1e-6
    if abs(elapsed - (complete - start)) > tolerance:
        return "cleanup elapsed time is inconsistent"
    if abs((deadline - start) - WATCHDOG_CLEANUP_SECONDS) > tolerance:
        return "cleanup deadline budget is inconsistent"
    for field in (
        "remaining_owned_groups",
        "malformed_ownership_records",
        "assertion_failures",
    ):
        if not isinstance(result.get(field), list):
            return f"{field} is missing or malformed"
    if result["remaining_owned_groups"]:
        return "owned supervisor groups remain present"
    if result["malformed_ownership_records"]:
        return "ownership evidence is malformed"
    for failure in result["assertion_failures"]:
        if not isinstance(failure, str):
            return "assertion failure evidence is malformed"
        if any(marker in failure for marker in CONTAINMENT_ASSERTION_MARKERS):
            return f"containment assertion failed: {failure}"
    if result.get("watchdog") == "worker-cleanup-timeout":
        return "watchdog could not reap the worker"
    return None


def schedule_cases(case_runner=run_case, cases=MISSING_CASES):
    results = []
    for index, case in enumerate(cases):
        try:
            result = case_runner(case)
        except BaseException as error:
            result = {
                "case": case,
                "execution_state": "EXECUTION_ERROR",
                "containment_ok": False,
                "worker_reaped": False,
                "remaining_owned_groups": [],
                "malformed_ownership_records": [],
                "assertion_failures": ["unexpected case exception"],
                "exception_type": type(error).__name__,
                "exception_message": str(error),
            }
        results.append(result)
        blocker = containment_blocker(result)
        if blocker is None:
            continue
        for remaining in cases[index + 1:]:
            results.append({
                "case": remaining,
                "execution_state": "NOT_EXECUTED",
                "blocked_by": case,
                "blocking_reason": blocker,
                "containment_ok": False,
                "assertion_failures": ["not executed after containment stop"],
            })
        break
    return results


def scheduler_self_test():
    base = {
        "execution_state": "EXECUTED",
        "containment_ok": True,
        "worker_reaped": True,
        "remaining_owned_groups": [],
        "malformed_ownership_records": [],
        "assertion_failures": [],
        "watchdog": "exited",
        "cleanup_state": "PROVEN",
        "cleanup_errors": [],
        "cleanup_deadline_started": True,
        "cleanup_start_monotonic": 10.0,
        "cleanup_deadline_monotonic": 13.0,
        "cleanup_complete_monotonic": 12.0,
        "cleanup_elapsed_seconds": 2.0,
        "worker_group_absent": True,
        "child_groups_absent": True,
    }
    scenarios = {
        "proven-permits-next": (
            lambda case: dict(base, case=case),
            2,
            ["EXECUTED", "EXECUTED"],
        ),
        "false-stops": (
            lambda case: dict(base, case=case, containment_ok=False),
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-stops": (
            lambda case: {
                key: value for key, value in dict(base, case=case).items()
                if key != "containment_ok"
            },
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "contradiction-stops": (
            lambda case: dict(
                base,
                case=case,
                remaining_owned_groups=[{"pgid": 999999}],
            ),
            2,
            ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-state": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_state"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "unknown-cleanup-state": (
            lambda case: dict(base, case=case, cleanup_state="UNKNOWN"),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-worker-absence": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "worker_group_absent"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-child-absence": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "child_groups_absent"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "cleanup-error-stops": (
            lambda case: dict(base, case=case, cleanup_errors=["injected"]),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-errors": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_errors"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "malformed-cleanup-errors": (
            lambda case: dict(base, case=case, cleanup_errors="bad"),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "missing-cleanup-timing": (
            lambda case: {key: value for key, value in dict(base, case=case).items()
                          if key != "cleanup_complete_monotonic"},
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "completion-after-deadline": (
            lambda case: dict(base, case=case, cleanup_complete_monotonic=14.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "negative-elapsed": (
            lambda case: dict(base, case=case, cleanup_elapsed_seconds=-1.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "inconsistent-elapsed": (
            lambda case: dict(base, case=case, cleanup_elapsed_seconds=1.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
        "wrong-cleanup-budget": (
            lambda case: dict(base, case=case, cleanup_deadline_monotonic=14.0),
            2, ["EXECUTED", "NOT_EXECUTED"],
        ),
    }
    outcomes = {}
    cases = ("first", "second")
    for name, (runner, expected_count, expected_states) in scenarios.items():
        results = schedule_cases(runner, cases)
        states = [item.get("execution_state") for item in results]
        passed = len(results) == expected_count and states == expected_states
        outcomes[name] = {"passed": passed, "states": states}
    calls = []
    def raising_runner(case):
        calls.append(case)
        raise RuntimeError("fabricated scheduler exception")
    exception_results = schedule_cases(raising_runner, cases)
    exception_states = [
        item.get("execution_state") for item in exception_results
    ]
    outcomes["exception-stops"] = {
        "passed": calls == ["first"]
        and exception_states == ["EXECUTION_ERROR", "NOT_EXECUTED"],
        "states": exception_states,
    }
    print(json.dumps(outcomes, indent=2, sort_keys=True))
    if not all(item["passed"] for item in outcomes.values()):
        raise SystemExit("scheduler self-test failed")
    cli_parser_self_test()
    assert source_stability({"a": "1"}, {"a": "1"}) == "PROVEN"
    assert source_stability({"a": "1"}, {"a": "2"}) == "FAILED"


def main():
    pre = {"launcher": digest(LAUNCHER), "proposal": digest(PROPOSAL)}
    if pre != {"launcher": EXPECTED_LAUNCHER, "proposal": EXPECTED_PROPOSAL}:
        raise SystemExit("hash precondition failed")
    harness_paths = {
        "run_validation": Path(__file__).resolve(),
        "run_containment": Path(__file__).resolve().with_name("run_containment.py"),
    }
    source_pre = {name: digest(path) for name, path in harness_paths.items()}
    source, constants, locations, extraction_hash = extract_source()
    if (
        constants["TERM_WAIT_SECONDS"] != TERM_GRACE_SECONDS
        or constants["KILL_WAIT_SECONDS"] != KILL_GRACE_SECONDS
    ):
        raise SystemExit("extracted cleanup grace mismatch")
    MISSING_EVIDENCE.mkdir(parents=True, exist_ok=False)
    (MISSING_EVIDENCE / "extracted_supervisor_source.py").write_text(source, encoding="utf-8")
    results = schedule_cases()
    post = {"launcher": digest(LAUNCHER), "proposal": digest(PROPOSAL)}
    source_post = {name: digest(path) for name, path in harness_paths.items()}
    raw = {"batch": "missing_cases_only", "pre_hashes": pre, "post_hashes": post,
           "source_extraction_sha256": extraction_hash, "source_locations": locations,
           "harness_source_pre_hashes": source_pre,
           "harness_source_post_hashes": source_post,
           "harness_source_stability": (
               source_stability(source_pre, source_post)
           ),
           "harness_source_stability_limit": (
               "Pre/post hashes do not prove absence of transient changes during execution."
           ),
            "case_execution_seconds": CASE_EXECUTION_SECONDS,
            "watchdog_cleanup_seconds": WATCHDOG_CLEANUP_SECONDS,
            "child_wait_seconds": CHILD_WAIT_SECONDS,
             "term_grace_seconds": TERM_GRACE_SECONDS, "kill_grace_seconds": KILL_GRACE_SECONDS,
           "case_to_synthetic": CASE_TO_SYNTHETIC, "cases": results,
             "instrumentation": "External namespace Popen recording/readiness wrapper, Linux PR_SET_PDEATHSIG child lifetime guard, and named monkeypatches only; child controller configuration is recorded, not runtime-proven.",
           "assertions_failed": [r for r in results if r["assertion_failures"]]}
    (MISSING_EVIDENCE / "raw.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    failures = raw["assertions_failed"]
    if raw["harness_source_stability"] != "PROVEN":
        raise SystemExit("harness source stability failed after evidence write")
    if failures:
        raise SystemExit(f"validation assertions failed after evidence write: {len(failures)}")


if __name__ == "__main__":
    cli = parse_cli(sys.argv[1:])
    if cli["mode"] == "help":
        print_help()
    elif cli["mode"] == "worker":
        worker(cli["case"], *(Path(path) for path in cli["paths"]), cli["nonce"])
    elif cli["mode"] == "scheduler-self-test":
        scheduler_self_test()
    else:
        main()
