#!/usr/bin/env python3
"""Focused, non-production containment checks for the remaining windows.

This entry point is deliberately separate from run_validation.py: it never
imports or schedules MISSING_CASES and reserves a new evidence directory for
each invocation.
"""
import hashlib
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
import run_validation as shared_validation
from run_validation import (group_present, parent_watchdog_cleanup,
                            scheduler_self_test, child_owned, wait_group_absent)
LAUNCHER = ROOT / "attached_assets/usbay-fda-readonly-diskutil-diagnostic.zsh"
PROPOSAL = ROOT / "attached_assets/usbay-temporary-terminal-full-disk-access-diagnostic-proposal.md"
CASE_EXECUTION_SECONDS = 12
WATCHDOG_CLEANUP_SECONDS = 3
HANDSHAKE_SECONDS = 5
CASES = ("A1", "A2", "B")
LINUX = sys.platform.startswith("linux")
ACTIVE_HANDLES = set()
ACTIVE_RESOURCES = set()
ACTIVE_PROCS = set()
FAULT_MODE = None


def parse_cli(argv):
    """Pure dispatch validation; no evidence or runtime channels are touched."""
    args = list(argv)
    if args in (["--help"], ["-h"]):
        return {"mode": "help"}
    if args == ["--state-machine-self-test"]:
        return {"mode": "state-machine-self-test"}
    if args == ["--fault-checks"]:
        return {"mode": "fault-checks"}
    if args == ["--fault-pre-guard"] or args == ["--fault-post-guard"]:
        return {"mode": args[0].removeprefix("--fault-")}
    if args == ["--cases", "A2", "B"]:
        return {"mode": "main", "cases": ("A2", "B")}
    if args == []:
        return {"mode": "main", "cases": CASES}
    if len(args) == 7 and args[0] == "--worker":
        case, observation, ownership, nonce, channel_fd, release_fd = args[1:]
        if case not in CASES or not nonce or nonce.startswith("-") or any(
                not item or item.startswith("-")
                for item in (observation, ownership)):
            raise SystemExit("invalid worker arguments")
        try:
            if int(channel_fd) < 0 or int(release_fd) < 0:
                raise ValueError
        except ValueError:
            raise SystemExit("worker descriptors must be integers")
        return {"mode": "worker", "args": (case, observation, ownership,
                                           nonce, channel_fd, release_fd)}
    if len(args) == 7 and args[0] == "--child":
        release_fd, observation, nonce, worker_pid, case, hold = args[1:]
        if (case not in CASES or hold not in ("0", "1") or not nonce
                or nonce.startswith("-") or not observation
                or observation.startswith("-")):
            raise SystemExit("invalid child arguments")
        try:
            if int(release_fd) < 0 or int(worker_pid) <= 0:
                raise ValueError
        except ValueError:
            raise SystemExit("child descriptors and worker PID must be integers")
        return {"mode": "child", "args": (release_fd, observation, nonce,
                                          worker_pid, case, hold)}
    raise SystemExit("unknown or malformed arguments")


def print_help():
    print("usage: run_containment.py [--cases A2 B|--state-machine-self-test|--fault-checks]")


def cli_parser_self_test():
    """Pure parser checks; dispatch never invokes an injected side effect."""
    side_effects = {"count": 0}
    assert parse_cli(["--help"])["mode"] == "help"
    assert parse_cli(["--fault-checks"])["mode"] == "fault-checks"
    for argv in (
        ["--unknown"],
        ["--cases", "A1", "B"],
        ["--worker", "A1", "a", "b", "n", "x"],
        ["--worker", "A1", "a", "b", "n", "x", "y"],
        ["--worker", "A1", "a", "b", "n", "not-int", "2"],
        ["--worker", "A1", "a", "b", "n", "-1", "2"],
        ["--worker", "A1", "a", "b", "-n", "1", "2"],
        ["--worker", "A1", "-a", "b", "n", "1", "2"],
        ["--child", "1", "a", "n", "not-int", "A1", "0"],
        ["--child", "1", "a", "n", "2", "A1"],
        ["--child", "-1", "a", "n", "2", "A1", "0"],
        ["--child", "1", "a", "n", "0", "A1", "0"],
        ["--child", "1", "-a", "n", "2", "A1", "0"],
        ["--child", "1", "a", "-n", "2", "A1", "0"],
        ["--child", "1", "a", "n", "2", "A1", "2"],
    ):
        try:
            parse_cli(argv)
        except SystemExit:
            pass
        else:
            raise AssertionError("malformed CLI accepted")
        assert side_effects["count"] == 0


class OwnedHandle:
    """Live authority retained from creation; evidence records are not authority."""

    def __init__(self, proc, record, pidfd):
        self.proc = proc
        self.record = dict(record)
        self.pidfd = pidfd

    @property
    def pid(self):
        return self.record["pid"]

    @property
    def pgid(self):
        return self.record["pgid"]

    def close(self):
        if self.pidfd is not None:
            os.close(self.pidfd)
            self.pidfd = None


def open_owned_pidfd(pid):
    if not LINUX or not hasattr(os, "pidfd_open"):
        raise RuntimeError("Linux pidfd support is required")
    return os.pidfd_open(pid, 0)


def send_pidfd(sock, pidfd):
    sock.sendmsg([b"p"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                           struct.pack("i", pidfd))])


def parse_pidfd_pid(info):
    line = next(line for line in info.splitlines() if line.startswith("Pid:"))
    return int(line.split(":", 1)[1].strip())


def bind_pidfd_info(info, expected_pid):
    """Pure binding predicate used by runtime and childless tests."""
    return parse_pidfd_pid(info) == expected_pid


def receive_pidfd(sock, deadline, expected_pid):
    sock.settimeout(max(0.0, deadline - time.monotonic()))
    data, ancdata, flags, _ = sock.recvmsg(
        1, socket.CMSG_SPACE(struct.calcsize("i") * 8))
    received = []
    for level, kind, payload in ancdata:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            for offset in range(0, len(payload) - 3, struct.calcsize("i")):
                received.append(struct.unpack("i", payload[offset:offset + 4])[0])
    if flags & socket.MSG_CTRUNC or data != b"p":
        for fd in received:
            os.close(fd)
        raise RuntimeError("invalid or truncated child handle handshake")
    if len(ancdata) != 1:
        for fd in received:
            os.close(fd)
        raise RuntimeError("unexpected ancillary record count")
    for level, kind, payload in ancdata:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            for fd in received:
                os.close(fd)
            raise RuntimeError("unexpected ancillary type")
        if len(payload) != struct.calcsize("i"):
            for fd in received:
                os.close(fd)
            raise RuntimeError("invalid child pidfd ancillary length")
    if len(received) != 1:
        for fd in received:
            os.close(fd)
        raise RuntimeError("wrong child pidfd ancillary count")
    fd = received[0]
    try:
        info = Path(f"/proc/self/fdinfo/{fd}").read_text()
        bound_pid = parse_pidfd_pid(info)
    except (OSError, StopIteration, ValueError):
        os.close(fd)
        raise RuntimeError("child pidfd binding could not be inspected")
    if not bind_pidfd_info(info, expected_pid):
        os.close(fd)
        raise RuntimeError("child pidfd bound to unexpected PID")
    return fd


def pidfd_signal(handle, sig):
    if not isinstance(handle, OwnedHandle) or handle.pidfd is None:
        return "not-authorized"
    try:
        signal.pidfd_send_signal(handle.pidfd, sig)
        return "sent"
    except ProcessLookupError:
        return "absent"


def read_jsonl_complete(path):
    """Only complete valid records can advance a checkpoint."""
    records = []
    for line in Path(path).read_text(encoding="utf-8").splitlines(keepends=True):
        if not line.endswith("\n"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def read_jsonl_evidence(path):
    """Return valid records separately from malformed/unterminated evidence."""
    valid, malformed = [], []
    for line in Path(path).read_text(encoding="utf-8").splitlines(keepends=True):
        if not line.endswith("\n"):
            malformed.append({"kind": "unterminated", "line": line})
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            malformed.append({"kind": "malformed", "line": line,
                              "error": str(error)})
            continue
        if isinstance(record, dict):
            valid.append(record)
        else:
            malformed.append({"kind": "non-object", "line": line})
    return valid, malformed


def checkpoint(records, case, nonce, name, predicate=None):
    for item in records:
        if (item.get("case") == case and item.get("nonce") == nonce
                and item.get("checkpoint") == name
                and (predicate is None or predicate(item))):
            return item
    return None


def wait_checkpoint(path, case, nonce, name, deadline, predicate=None):
    while time.monotonic() < deadline:
        item = checkpoint(read_jsonl_complete(path), case, nonce, name, predicate)
        if item is not None:
            return item
        time.sleep(.01)
    return None


def wait_event(path, case, nonce, event, deadline, predicate=None):
    while time.monotonic() < deadline:
        for item in read_jsonl_complete(path):
            if (item.get("case") == case and item.get("nonce") == nonce
                    and item.get("event") == event
                    and (predicate is None or predicate(item))):
                return item
        time.sleep(.01)
    return None


def wait_records(path, deadline, predicate, exactly_one=False):
    while time.monotonic() < deadline:
        matches = [item for item in read_jsonl_complete(path)
                   if predicate(item)]
        if matches and (not exactly_one or len(matches) == 1):
            return matches[0] if exactly_one else matches
        time.sleep(.01)
    return None


def owned(pid, nonce, case, expected_kind=None):
    try:
        value = {
            "pid": pid, "pgid": os.getpgid(pid), "session_id": os.getsid(pid),
            "nonce": nonce, "case": case,
        }
    except (ProcessLookupError, PermissionError):
        return None
    if value["pgid"] != pid or value["session_id"] != pid:
        return None
    if expected_kind:
        value["kind"] = expected_kind
    return value


def present(pgid):
    return group_present(pgid)


def absent(pgid, deadline):
    return wait_group_absent(pgid, deadline)


def child_main(release_fd, observation, nonce, worker_pid, case, hold):
    if hold not in ("0", "1"):
        raise SystemExit("invalid child hold mode")
    libc = __import__("ctypes").CDLL(None)
    pre = {"kind": "child", "case": case, "nonce": nonce, "pid": os.getpid()}
    with open(observation, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(dict(pre, checkpoint="before-prctl")) + "\n")
    if os.read(int(release_fd), 1) != b"r":
        raise SystemExit("release handshake failed")
    if libc.prctl(1, signal.SIGKILL) != 0:
        raise SystemExit(91)
    ppid_ok = os.getppid() == int(worker_pid)
    record = dict(pre, checkpoint="after-prctl-ppid", ppid=os.getppid(),
                  ppid_verified=ppid_ok, pgid=os.getpgid(0),
                  session_id=os.getsid(0))
    with open(observation, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")
    if not ppid_ok:
        raise SystemExit(92)
    if hold == "1":
        time.sleep(30)


def worker_main(case, paths, nonce, channel_fd, release_fd):
    observation, ownership = map(Path, paths)
    channel = socket.socket(fileno=int(channel_fd))
    child = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--child",
         str(release_fd), str(observation), nonce, str(os.getpid()), case,
         "1" if case in ("A2", "B") else "0"],
        start_new_session=True,
        pass_fds=(int(release_fd),),
    )
    worker_record = owned(os.getpid(), nonce, case, "worker")
    with open(observation, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(dict(worker_record, event="worker-observation")) + "\n")
    record = owned(child.pid, nonce, case, "child")
    if not record:
        child.kill()
        child.wait()
        raise SystemExit("child ownership validation failed")
    record["kind"] = "supervisor-child" if case == "B" else "child"
    record["worker_pid"] = os.getpid()
    record["start_new_session"] = True
    with open(observation, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(dict(record, event="controller-observation")) + "\n")
    child_pidfd = open_owned_pidfd(child.pid)
    send_pidfd(channel, child_pidfd)
    os.close(child_pidfd)
    channel.close()
    # B intentionally persists the ordinary record; A1/A2 intentionally do not.
    if case == "B":
        with open(ownership, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(record) + "\n")
    while True:
        time.sleep(1)


def cleanup_active_case(handles, procs=()):
    """Bounded cleanup for the active case; JSONL is never an authority."""
    started = time.monotonic()
    deadline = started + WATCHDOG_CLEANUP_SECONDS
    actions, errors, remaining, termination_observed, reaped = [], [], [], [], []
    for proc in tuple(procs):
        try:
            proc.kill()
            proc.wait(timeout=max(0, deadline - time.monotonic()))
            reaped.append(proc.pid)
            actions.append({"pid": proc.pid, "authority": "setup-Popen",
                            "outcome": "killed-and-reaped"})
        except BaseException as error:
            errors.append(f"setup-reap:{type(error).__name__}:{error}")
    for handle in tuple(handles):
        if not isinstance(handle, OwnedHandle) or handle.pidfd is None:
            errors.append("missing-or-closed-live-handle")
            continue
        try:
            actions.append({"pid": handle.pid, "signal": int(signal.SIGKILL),
                            "outcome": pidfd_signal(handle, signal.SIGKILL)})
        except BaseException as error:
            errors.append(f"pidfd-signal:{type(error).__name__}:{error}")
    for handle in tuple(handles):
        if handle.record.get("kind") == "worker" and handle.proc is not None:
            try:
                handle.proc.wait(timeout=max(0, deadline - time.monotonic()))
                reaped.append(handle.pid)
            except BaseException as error:
                errors.append(f"worker-reap:{type(error).__name__}:{error}")
    for handle in tuple(handles):
        if handle.record.get("kind") in ("child", "supervisor-child"):
            try:
                absent_now = wait_group_absent(handle.pgid, deadline)
                termination_observed.append(
                    {"pid": handle.pid, "role": "child", "group_absent": absent_now})
                if not absent_now:
                    remaining.append({"pid": handle.pid, "pgid": handle.pgid})
            except BaseException as error:
                errors.append(f"child-observe:{type(error).__name__}:{error}")
    for handle in tuple(handles):
        if handle.record.get("kind") == "worker":
            try:
                absent_now = wait_group_absent(handle.pgid, deadline)
                termination_observed.append(
                    {"pid": handle.pid, "role": "worker", "group_absent": absent_now})
                if not absent_now:
                    remaining.append({"pid": handle.pid, "pgid": handle.pgid})
            except BaseException as error:
                errors.append(f"worker-observe:{type(error).__name__}:{error}")
    completed = time.monotonic()
    for handle in tuple(handles):
        handle.close()
        ACTIVE_HANDLES.discard(handle)
    for resource in tuple(ACTIVE_RESOURCES):
        try:
            resource.close() if hasattr(resource, "close") else os.close(resource)
        except OSError:
            pass
        ACTIVE_RESOURCES.discard(resource)
    for proc in tuple(procs):
        ACTIVE_PROCS.discard(proc)
    worker_expected = any(h.record.get("kind") == "worker" for h in handles)
    child_expected = any(
        h.record.get("kind") in ("child", "supervisor-child") for h in handles)
    worker_reaped = any(
        h.record.get("kind") == "worker" and h.pid in reaped for h in handles)
    child_absent = all(
        item.get("group_absent") for item in termination_observed
        if any(h.pid == item.get("pid") and
               h.record.get("kind") in ("child", "supervisor-child")
               for h in handles))
    return {
        "cleanup_start_monotonic": started,
        "cleanup_deadline_monotonic": deadline,
        "cleanup_complete_monotonic": completed,
        "cleanup_elapsed_seconds": completed - started,
        "cleanup_actions": actions,
        "termination_observed": termination_observed,
        "reaped_pids": reaped,
        "remaining_groups": remaining,
        "cleanup_errors": errors,
        "expected_worker_registered": worker_expected,
        "expected_child_registered": child_expected,
        "worker_reaped": worker_reaped,
        "child_groups_absent": child_absent,
        "cleanup_state": "PROVEN" if len(handles) >= 2
        and worker_expected and child_expected and worker_reaped and child_absent
        and not remaining and not errors and completed <= deadline else "UNKNOWN",
    }


def run_a(case, evidence):
    nonce = uuid.uuid4().hex
    observation, ownership = [evidence / f"{case}.{suffix}" for suffix in
                              ("observation.jsonl", "ownership.jsonl")]
    for path in (observation, ownership):
        path.touch(exist_ok=False)
    parent_channel, worker_channel = socket.socketpair(socket.AF_UNIX,
                                                       socket.SOCK_STREAM)
    release_read, release_write = os.pipe()
    ACTIVE_RESOURCES.update(
        (parent_channel, worker_channel, release_read, release_write))
    worker = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                               "--worker", case, str(observation), str(ownership),
                               nonce,
                               str(worker_channel.fileno()), str(release_read)],
                              start_new_session=True,
                              pass_fds=(worker_channel.fileno(), release_read))
    ACTIVE_PROCS.add(worker)
    worker_channel.close()
    ACTIVE_RESOURCES.discard(worker_channel)
    os.close(release_read)
    ACTIVE_RESOURCES.discard(release_read)
    worker_pidfd = open_owned_pidfd(worker.pid)
    worker_record = owned(worker.pid, nonce, case, "worker")
    if not worker_record:
        signal.pidfd_send_signal(worker_pidfd, signal.SIGKILL)
        os.close(worker_pidfd)
        raise RuntimeError("worker ownership/cleanup capability not validated")
    worker_record["start_new_session"] = True
    deadline = time.monotonic() + HANDSHAKE_SECONDS
    worker_handle = OwnedHandle(worker, worker_record, worker_pidfd)
    ACTIVE_HANDLES.add(worker_handle)
    ACTIVE_PROCS.discard(worker)
    first = wait_checkpoint(observation, case, nonce, "before-prctl", deadline)
    if first is None:
        raise RuntimeError("pre-guard checkpoint not observed")
    observations = read_jsonl_complete(observation)
    child_record = owned(first["pid"], nonce, case, "child")
    if not child_record:
        raise RuntimeError("child cleanup capability not validated")
    child_record["start_new_session"] = True
    controller_child = wait_event(
        observation, case, nonce, "controller-observation",
        deadline, lambda item: item.get("pid") == child_record["pid"]
        and item.get("worker_pid") == worker.pid
        and item.get("pgid") == child_record.get("pgid")
        and item.get("session_id") == child_record.get("session_id"))
    if controller_child is None:
        raise RuntimeError("exact child ownership checkpoint not proven")
    child_pidfd = receive_pidfd(parent_channel, deadline, child_record["pid"])
    parent_channel.close()
    ACTIVE_RESOURCES.discard(parent_channel)
    child_handle = OwnedHandle(None, child_record, child_pidfd)
    ACTIVE_HANDLES.add(child_handle)
    if FAULT_MODE == "pre-guard":
        raise RuntimeError("deterministic pre-guard controller fault")
    if ownership.read_text():
        raise RuntimeError("ordinary ownership record unexpectedly persisted")
    if case == "A2":
        os.write(release_write, b"r")
        deadline = time.monotonic() + HANDSHAKE_SECONDS
        if wait_checkpoint(
                observation, case, nonce, "after-prctl-ppid", deadline,
                lambda item: item.get("ppid_verified") is True) is None:
            raise RuntimeError("post-guard PPID checkpoint not proven")
        if FAULT_MODE == "post-guard":
            raise RuntimeError("deterministic post-guard controller fault")
    if case == "A1":
        worker_action = pidfd_signal(worker_handle, signal.SIGKILL)
        worker.wait(timeout=HANDSHAKE_SECONDS)
        os.write(release_write, b"r")
    else:
        worker_action = pidfd_signal(worker_handle, signal.SIGKILL)
    worker.wait(timeout=HANDSHAKE_SECONDS)
    if case == "A1":
        deadline = time.monotonic() + HANDSHAKE_SECONDS
        if wait_checkpoint(
                observation, case, nonce, "after-prctl-ppid", deadline,
                lambda item: item.get("ppid_verified") is False) is None:
            raise RuntimeError("A1 PPID-mismatch observation not proven")
    guard_deadline = time.monotonic() + HANDSHAKE_SECONDS
    guard_absent = absent(child_record["pgid"], guard_deadline)
    fallback_used = False
    fallback_action = None
    if not guard_absent:
        fallback_used = True
        fallback_action = pidfd_signal(child_handle, signal.SIGKILL)
        if not absent(child_record["pgid"], time.monotonic() + WATCHDOG_CLEANUP_SECONDS):
            raise RuntimeError("validated child remained after fallback cleanup")
    child_action = None
    child_absent = absent(child_record["pgid"], time.monotonic() + WATCHDOG_CLEANUP_SECONDS)
    observations = read_jsonl_complete(observation)
    checkpoint_order = [item.get("checkpoint") for item in observations
                        if item.get("checkpoint")]
    worker_handle.close()
    child_handle.close()
    os.close(release_write)
    ACTIVE_RESOURCES.discard(release_write)
    ACTIVE_HANDLES.discard(worker_handle)
    ACTIVE_HANDLES.discard(child_handle)
    return {"case": case, "nonce": nonce, "checkpoint_order": checkpoint_order,
            "ordinary_ownership_records": read_jsonl_complete(ownership),
            "worker": worker_record, "child": child_record,
            "worker_termination": worker_action, "child_cleanup": child_action,
            "guard_absent_before_fallback": guard_absent,
            "fallback_used": fallback_used, "fallback_action": fallback_action,
            "guard_result": ("PASSED" if guard_absent and not fallback_used
                             else "FAILED/INCONCLUSIVE"),
            "worker_reaped": worker.poll() is not None,
            "child_group_absent": child_absent, "observations": observations,
             "expected": "PPID exit before release handshake" if case == "A1" else
                        "PDEATHSIG termination after verified guard"}


def run_b(evidence):
    nonce = uuid.uuid4().hex
    observation, ownership = [evidence / f"B.{suffix}" for suffix in
                              ("observation.jsonl", "ownership.jsonl")]
    for path in (observation, ownership):
        path.touch(exist_ok=False)
    parent_channel, worker_channel = socket.socketpair(socket.AF_UNIX,
                                                       socket.SOCK_STREAM)
    release_read, release_write = os.pipe()
    ACTIVE_RESOURCES.update(
        (parent_channel, worker_channel, release_read, release_write))
    worker = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                               "--worker", "B", str(observation), str(ownership),
                               nonce,
                               str(worker_channel.fileno()), str(release_read)],
                              start_new_session=True,
                              pass_fds=(worker_channel.fileno(), release_read))
    ACTIVE_PROCS.add(worker)
    worker_channel.close()
    ACTIVE_RESOURCES.discard(worker_channel)
    os.close(release_read)
    ACTIVE_RESOURCES.discard(release_read)
    worker_pidfd = open_owned_pidfd(worker.pid)
    worker_record = owned(worker.pid, nonce, "B", "worker")
    if not worker_record:
        signal.pidfd_send_signal(worker_pidfd, signal.SIGKILL)
        os.close(worker_pidfd)
        raise RuntimeError("worker ownership validation failed")
    worker_record["start_new_session"] = True
    worker_handle = OwnedHandle(worker, worker_record, worker_pidfd)
    ACTIVE_HANDLES.add(worker_handle)
    ACTIVE_PROCS.discard(worker)
    deadline = time.monotonic() + HANDSHAKE_SECONDS
    controller_child = wait_event(
        observation, "B", nonce, "controller-observation", deadline,
        lambda item: item.get("pid") is not None
        and item.get("worker_pid") == worker.pid
        and item.get("pgid") == item.get("pid")
        and item.get("session_id") == item.get("pid"))
    if controller_child is None:
        raise RuntimeError("exact B child ownership checkpoint not proven")
    child_pid = controller_child["pid"]
    runtime_child = owned(child_pid, nonce, "B", "child")
    if (runtime_child is None
            or any(runtime_child.get(key) != controller_child.get(key)
                   for key in ("pid", "pgid", "session_id"))):
        raise RuntimeError("B child runtime identity mismatch")
    child_pidfd = receive_pidfd(parent_channel, deadline, child_pid)
    parent_channel.close()
    ACTIVE_RESOURCES.discard(parent_channel)
    child = dict(controller_child)
    child["start_new_session"] = True
    child_handle = OwnedHandle(None, child, child_pidfd)
    ACTIVE_HANDLES.add(child_handle)
    persisted_child = wait_records(
        ownership, deadline,
        lambda item: child_owned(item, nonce, "B", worker.pid)
        and all(item.get(key) == runtime_child.get(key)
                for key in ("pid", "pgid", "session_id")),
        exactly_one=True)
    if persisted_child is None:
        raise RuntimeError("exact B persisted ownership record not proven")
    if any(persisted_child.get(key) != child.get(key)
           for key in ("pid", "pgid", "session_id", "worker_pid",
                       "case", "nonce", "kind")):
        raise RuntimeError("B persisted/controller identity mismatch")
    persisted_child_original = dict(persisted_child)
    readiness_start = time.monotonic()
    os.write(release_write, b"r")
    ready = wait_checkpoint(
        observation, "B", nonce, "after-prctl-ppid",
        readiness_start + HANDSHAKE_SECONDS,
        lambda item: item.get("ppid_verified") is True,
    )
    if ready is None:
        raise RuntimeError("B child guard readiness not proven")
    execution_start = time.monotonic()
    try:
        worker.wait(timeout=CASE_EXECUTION_SECONDS)
    except subprocess.TimeoutExpired:
        timeout_observed = True
    else:
        raise RuntimeError("B worker exited before execution timeout")
    timeout_at = time.monotonic()
    cleanup_start = timeout_at
    cleanup_deadline = cleanup_start + WATCHDOG_CLEANUP_SECONDS
    cleanup = parent_watchdog_cleanup(
        worker, worker_record, [child], nonce, "B", "watchdog-timeout",
        ownership, observation, live_handles=(worker_handle, child_handle),
    )
    cleanup_complete = cleanup["cleanup_complete_monotonic"]
    worker_handle.close()
    child_handle.close()
    os.close(release_write)
    ACTIVE_RESOURCES.discard(release_write)
    ACTIVE_HANDLES.discard(worker_handle)
    ACTIVE_HANDLES.discard(child_handle)
    return {"case": "B", "nonce": nonce, "execution_start_monotonic":
            execution_start, "execution_timeout_seconds":
            CASE_EXECUTION_SECONDS, "cleanup_deadline_seconds":
            WATCHDOG_CLEANUP_SECONDS, "timeout_observed": timeout_observed,
            "timeout_timestamp_monotonic": timeout_at,
            "cleanup_deadline_monotonic": cleanup["cleanup_deadline_monotonic"],
            "cleanup_complete_monotonic": cleanup_complete,
            "cleanup_start_monotonic": cleanup["cleanup_start_monotonic"],
            "cleanup_elapsed_seconds": cleanup["cleanup_elapsed_seconds"],
            "cleanup_within_budget": cleanup["cleanup_state"] == "PROVEN",
            "cleanup_state": cleanup["cleanup_state"],
            "cleanup_errors": cleanup["cleanup_errors"],
            "cleanup_started_after_timeout": True,
             "worker": worker_record, "child": child,
            "actions": cleanup["cleanup_actions"],
             "worker_reaped": cleanup["worker_reaped"],
             "child_group_absent": not cleanup["remaining_owned_groups"],
             "ordinary_ownership_records": [persisted_child_original],
             "ownership_annotations": {
                 "persisted": True,
                 "record_matches_runtime": True,
             },
             "cleanup_errors": cleanup["cleanup_errors"],
             "remaining_owned_groups": cleanup["remaining_owned_groups"],
             "worker_group_absent": cleanup["worker_group_absent"],
             "child_groups_absent": cleanup["child_groups_absent"],
            "expected": "watchdog cleans separate groups and reaps worker"}


def main(cases=CASES):
    if hashlib.sha256(LAUNCHER.read_bytes()).hexdigest() != \
            "b19bd48a797b3f5659c6fb850d4baff1792c6c73153bfec13b4eb6f5976f320b":
        raise SystemExit("launcher hash precondition failed")
    harness_paths = {
        "run_containment": Path(__file__).resolve(),
        "run_validation": HERE / "run_validation.py",
    }
    source_pre_hashes = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in harness_paths.items()
    }
    evidence = HERE / f"evidence/containment_{time.strftime('%Y%m%dT%H%M%S')}_{uuid.uuid4().hex}"
    evidence.mkdir(parents=True, exist_ok=False)
    results = []
    for case in cases:
        try:
            result = run_b(evidence) if case == "B" else run_a(case, evidence)
            if not result.get("child_group_absent"):
                raise RuntimeError("child-group absence unproven")
            if case != "B" and result.get("guard_result") != "PASSED":
                raise RuntimeError("parent-death guard outcome failed/inconclusive")
            if not result.get("worker_reaped"):
                raise RuntimeError("worker reaping unproven")
            if case == "B" and not result.get("worker_reaped"):
                raise RuntimeError("watchdog worker reaping unproven")
            if case == "B" and (
                    result.get("cleanup_state") != "PROVEN"
                    or not result.get("cleanup_within_budget")):
                raise RuntimeError("watchdog cleanup was not proven within budget")
            results.append(result)
        except BaseException as error:
            cleanup_result = cleanup_active_case(tuple(ACTIVE_HANDLES),
                                                 tuple(ACTIVE_PROCS))
            observation_file = evidence / f"{case}.observation.jsonl"
            ownership_file = evidence / f"{case}.ownership.jsonl"
            observed, malformed = (read_jsonl_evidence(observation_file)
                                   if observation_file.exists() else ([], []))
            owned_records, ownership_malformed = (
                read_jsonl_evidence(ownership_file)
                if ownership_file.exists() else ([], []))
            results.append({"case": case, "execution_state": "EXECUTION_ERROR",
                            "original_exception": {
                                "type": type(error).__name__, "message": str(error)},
                            "cleanup": cleanup_result,
                            "observations": observed,
                            "malformed_observations": malformed,
                            "ownership_records": owned_records,
                            "malformed_ownership": ownership_malformed,
                            "error": f"{type(error).__name__}: {error}"})
            results.extend({"case": remaining, "execution_state": "NOT_EXECUTED",
                            "blocked_by": case,
                            "blocking_reason": "containment validation stopped",
                            "assertion_failures": ["not executed after containment stop"]}
                           for remaining in cases[cases.index(case) + 1:])
            break
    source_post_hashes = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in harness_paths.items()
    }
    (evidence / "raw.json").write_text(json.dumps({
        "cases": cases, "results": results,
        "launcher_sha256": hashlib.sha256(LAUNCHER.read_bytes()).hexdigest(),
        "proposal_sha256": hashlib.sha256(PROPOSAL.read_bytes()).hexdigest(),
        "harness_source_pre_hashes": source_pre_hashes,
        "harness_source_post_hashes": source_post_hashes,
        "harness_source_stability": shared_validation.source_stability(
            source_pre_hashes, source_post_hashes
        ),
        "harness_source_stability_limit":
            "Pre/post hashes do not prove absence of transient changes during execution.",
        "attempt_metadata": {"evidence_directory_created_exist_ok_false": True,
                             "execution_entrypoint": str(Path(__file__).resolve())},
    }, indent=2) + "\n")
    if shared_validation.source_stability(
            source_pre_hashes, source_post_hashes
    ) != "PROVEN":
        raise SystemExit("harness source stability failed after evidence write")
    if FAULT_MODE and len(results) == len(cases) and all(
            item.get("cleanup", {}).get("cleanup_state") == "PROVEN"
            for item in results):
        return
    if len(results) != len(cases) or any("error" in item for item in results):
        raise SystemExit("containment validation stopped fail-closed")


def fault_main(mode):
    global FAULT_MODE
    if mode not in ("pre-guard", "post-guard"):
        raise SystemExit("invalid fault mode")
    FAULT_MODE = mode
    main(("A1" if mode == "pre-guard" else "A2",))


def checkpoint_state_self_test():
    """Isolated synthetic executable checks; no real process operations."""
    nonce = "n"
    valid = {"case": "A2", "nonce": nonce, "checkpoint": "after-prctl-ppid",
             "ppid_verified": True}
    assert checkpoint([valid], "A2", nonce, "after-prctl-ppid",
                      lambda item: item["ppid_verified"])
    assert checkpoint([dict(valid, case="A1")], "A2", nonce,
                      "after-prctl-ppid") is None
    assert checkpoint([dict(valid, nonce="stale")], "A2", nonce,
                      "after-prctl-ppid") is None
    with tempfile.NamedTemporaryFile(mode="w+", delete=True) as stream:
        stream.write(json.dumps(valid) + "\n")
        stream.write('{"case":"A2"')
        stream.flush()
        parsed = read_jsonl_complete(Path(stream.name))
        assert len(parsed) == 1
        assert wait_checkpoint(Path(stream.name), "A2", nonce,
                               "missing", time.monotonic() + .01) is None
    assert parse_pidfd_pid("Pid:\t42\nNSpid:\t42\n") == 42
    assert bind_pidfd_info("Pid:\t42\n", 42)
    assert not bind_pidfd_info("Pid:\t42\n", 43)
    persisted = {"kind": "supervisor-child", "nonce": "n", "case": "B",
                 "worker_pid": 123, "pid": 124, "pgid": 124,
                 "session_id": 124, "start_new_session": True}
    assert child_owned(persisted, "n", "B", 123)
    assert not child_owned(dict(persisted, worker_pid=999), "n", "B", 123)
    assert not child_owned(dict(persisted, case="A2"), "n", "B", 123)
    assert not child_owned(dict(persisted, nonce="stale"), "n", "B", 123)
    assert pidfd_signal(OwnedHandle(None, {"pid": 1, "pgid": 1}, None),
                        signal.SIGKILL) == "not-authorized"
    scheduler_self_test()
    class FakeProc:
        pid = 12345

        def __init__(self, reap=True):
            self.reap = reap
            self.calls = []

        def poll(self):
            self.calls.append(("poll",))
            return 0 if self.reap else None

        def wait(self, timeout=None):
            self.calls.append(("wait", timeout))
            if not self.reap:
                raise subprocess.TimeoutExpired("fake", timeout)
            return 0

    unset = object()

    def cleanup_fixture(*, present=(), remaining=(), reap=True,
                        signal_error=False, times=(10.0, 10.5, 11.0),
                        live_handles=unset, worker_mutation=None):
        worker = {
            "pid": 12345, "pgid": 12345, "session_id": 12345,
            "nonce": nonce, "case": "B", "start_new_session": True,
        }
        if worker_mutation:
            worker.update(worker_mutation)
        child = {
            "kind": "supervisor-child", "pid": 999998, "pgid": 999998,
            "session_id": 999998, "worker_pid": 12345, "nonce": nonce,
            "case": "B", "start_new_session": True,
        }
        calls = {"present": [], "absent": [], "signal": []}
        present = set(present)
        remaining = set(remaining)

        def fake_group_present(pgid):
            calls["present"].append(pgid)
            return pgid in present

        def fake_wait_group_absent(pgid, deadline):
            calls["absent"].append((pgid, deadline))
            return pgid not in remaining

        def fake_signal(record, signum):
            calls["signal"].append((record["pid"], signum))
            if signal_error:
                raise RuntimeError("injected signal failure")
            return "sent"

        proc = FakeProc(reap=reap)
        kwargs = {}
        if live_handles is not unset:
            kwargs["live_handles"] = live_handles
        result = parent_watchdog_cleanup(
            proc, worker, [child], nonce, "B", "watchdog-timeout",
            Path("/dev/null"), Path("/dev/null"),
            group_present_fn=fake_group_present,
            wait_group_absent_fn=fake_wait_group_absent,
            signal_fn=fake_signal,
            monotonic_fn=iter(times).__next__,
            **kwargs,
        )
        return result, calls, proc, worker, child

    baseline, baseline_calls, baseline_proc, worker, child = cleanup_fixture()
    assert baseline["cleanup_state"] == "PROVEN"
    assert baseline["worker_reaped"] is True
    assert baseline["worker_group_absent"] is True
    assert baseline["child_groups_absent"] is True
    assert baseline["cleanup_errors"] == []
    assert baseline["cleanup_complete_monotonic"] <= baseline[
        "cleanup_deadline_monotonic"
    ]
    assert any(call[0] == "wait" for call in baseline_proc.calls)
    assert worker["pgid"] in baseline_calls["present"]
    assert child["pgid"] in baseline_calls["present"]

    invalid, invalid_calls, _, invalid_worker, _ = cleanup_fixture(
        worker_mutation={"pgid": 999999},
    )
    assert invalid_worker["pgid"] != invalid_worker["pid"]
    assert invalid["cleanup_state"] == "UNKNOWN"
    assert invalid["containment_ok"] is False
    assert invalid["worker_group_absent"] is False
    assert invalid_calls["signal"] == []
    assert invalid_worker["pgid"] not in [
        pgid for pgid, _ in invalid_calls["absent"]
    ]

    worker_residual, worker_calls, _, worker, _ = cleanup_fixture(
        present=(12345,), remaining=(12345,),
    )
    assert worker_residual["cleanup_state"] == "UNKNOWN"
    assert worker_residual["worker_group_absent"] is False
    assert worker_calls["signal"] == [(worker["pid"], signal.SIGKILL)]
    assert any(pgid == worker["pgid"] for pgid, _ in worker_calls["absent"])

    child_residual, child_calls, _, _, child = cleanup_fixture(
        present=(999998,), remaining=(999998,),
    )
    assert child_residual["cleanup_state"] == "UNKNOWN"
    assert child_residual["child_groups_absent"] is False
    assert child_residual["remaining_owned_groups"] == [child]
    assert child_calls["signal"] == [(child["pid"], signal.SIGKILL)]
    assert any(pgid == child["pgid"] for pgid, _ in child_calls["absent"])

    reap_failure, reap_calls, reap_proc, _, _ = cleanup_fixture(reap=False)
    assert reap_failure["cleanup_state"] == "UNKNOWN"
    assert reap_failure["worker_reaped"] is False
    assert reap_failure["watchdog"] == "worker-cleanup-timeout"
    assert reap_calls["signal"] == []
    assert any(call[0] == "wait" for call in reap_proc.calls)

    signal_failure, signal_calls, _, _, child = cleanup_fixture(
        present=(999998,), signal_error=True,
    )
    assert signal_failure["cleanup_state"] == "UNKNOWN"
    assert any(error.startswith("child-signal:RuntimeError:")
               for error in signal_failure["cleanup_errors"])
    assert signal_calls["signal"] == [(child["pid"], signal.SIGKILL)]

    deadline_failure, deadline_calls, _, _, _ = cleanup_fixture(
        times=(10.0, 10.5, 14.0),
    )
    assert deadline_failure["cleanup_state"] == "UNKNOWN"
    assert deadline_failure["cleanup_complete_monotonic"] > deadline_failure[
        "cleanup_deadline_monotonic"
    ]
    assert deadline_calls["present"]
    assert deadline_calls["absent"]

    missing_handles, handle_calls, _, worker, child = cleanup_fixture(
        live_handles=(),
    )
    assert missing_handles["cleanup_state"] == "UNKNOWN"
    assert sorted(missing_handles["cleanup_errors"]) == sorted([
        f"missing-live-handle:{worker['pid']}",
        f"missing-live-handle:{child['pid']}",
    ])
    assert worker["pgid"] in handle_calls["present"]
    assert child["pgid"] in handle_calls["present"]
    assert handle_calls["absent"]

    dispatch_self_test()
    cli_parser_self_test()
    assert shared_validation.source_stability({"a": "1"}, {"a": "1"}) == "PROVEN"
    assert shared_validation.source_stability({"a": "1"}, {"a": "2"}) == "FAILED"
    print(json.dumps({"passed": True, "checks": [
        "exact-case-nonce-checkpoint", "wrong-case-rejected",
        "stale-nonce-rejected", "empty-parser", "stale-pidfd-rejected",
        "cleanup-proven-baseline", "cleanup-discriminating-failure-matrix",
        "invalid-ownership-separate", "fault-dispatch-recording-stubs",
        "cli-parser-side-effect-free",
        "source-stability-mismatch"
    ]}, sort_keys=True))


def fault_checks():
    """Deterministic pre/post-guard and scheduler checks; never spawns."""
    assert checkpoint([], "A1", "n", "before-prctl") is None
    assert checkpoint([{"case": "A1", "nonce": "n", "checkpoint": "before-prctl"}],
                      "A1", "n", "before-prctl") is not None
    assert checkpoint([{"case": "A2", "nonce": "n", "checkpoint": "after-prctl-ppid",
                        "ppid_verified": True}], "A1", "n",
                      "after-prctl-ppid") is None
    print(json.dumps({"passed": True, "faults": ["pre-guard-deadline",
                                                  "post-guard-wrong-case"]}))


def dispatch_argv(argv, *, help_fn=print_help,
                  state_test_fn=checkpoint_state_self_test,
                  fault_checks_fn=fault_checks, fault_main_fn=fault_main,
                  child_fn=child_main, worker_fn=worker_main, main_fn=main):
    """Parse then dispatch through injectable handlers for isolated tests."""
    cli = parse_cli(argv)
    if cli["mode"] == "help":
        return help_fn()
    elif cli["mode"] == "state-machine-self-test":
        return state_test_fn()
    elif cli["mode"] == "fault-checks":
        return fault_checks_fn()
    elif cli["mode"] in ("pre-guard", "post-guard"):
        return fault_main_fn(cli["mode"])
    elif cli["mode"] == "child":
        return child_fn(*cli["args"])
    elif cli["mode"] == "worker":
        return worker_fn(cli["args"][0], cli["args"][1:3], cli["args"][3],
                         cli["args"][4], cli["args"][5])
    return main_fn(cli["cases"])


def dispatch_self_test():
    """Exercise complete parse-to-dispatch fault routes with recording stubs."""
    def explicit_handlers(calls, fault_handler=None):
        def unexpected(name):
            def fail(*args):
                calls.append((name, args))
                raise AssertionError(f"unexpected {name} handler call: {args}")
            return fail

        return {
            "help_fn": unexpected("help"),
            "state_test_fn": unexpected("state-test"),
            "fault_checks_fn": unexpected("fault-checks"),
            "fault_main_fn": fault_handler or unexpected("fault"),
            "child_fn": unexpected("child"),
            "worker_fn": unexpected("worker"),
            "main_fn": unexpected("main"),
        }

    for flag, expected in (
        ("--fault-pre-guard", "pre-guard"),
        ("--fault-post-guard", "post-guard"),
    ):
        calls = []

        def record_fault(mode):
            calls.append(("fault", mode))

        dispatch_argv(
            [flag],
            **explicit_handlers(calls, fault_handler=record_fault),
        )
        assert calls == [("fault", expected)]

    for argv in (
        ["--unknown"],
        ["--fault-pre-guard", "extra"],
        ["--worker", "A1", "a", "b", "n", "-1", "2"],
        ["--child", "-1", "a", "n", "0", "A1", "0"],
    ):
        calls = []
        try:
            dispatch_argv(argv, **explicit_handlers(calls))
        except SystemExit:
            pass
        else:
            raise AssertionError("malformed dispatch arguments accepted")
        assert calls == []


if __name__ == "__main__":
    dispatch_argv(sys.argv[1:])
