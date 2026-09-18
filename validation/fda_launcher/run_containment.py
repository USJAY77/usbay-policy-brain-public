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
    child["ownership_persisted"] = True
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
            "ordinary_ownership_records": [child],
            "expected": "watchdog cleans separate groups and reaps worker"}


def main(cases=CASES):
    if hashlib.sha256(LAUNCHER.read_bytes()).hexdigest() != \
            "b19bd48a797b3f5659c6fb850d4baff1792c6c73153bfec13b4eb6f5976f320b":
        raise SystemExit("launcher hash precondition failed")
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
    (evidence / "raw.json").write_text(json.dumps({
        "cases": cases, "results": results,
        "launcher_sha256": hashlib.sha256(LAUNCHER.read_bytes()).hexdigest(),
        "proposal_sha256": hashlib.sha256(PROPOSAL.read_bytes()).hexdigest(),
        "attempt_metadata": {"evidence_directory_created_exist_ok_false": True,
                             "execution_entrypoint": str(Path(__file__).resolve())},
    }, indent=2) + "\n")
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
    """Childless checks of the real parser, identity and scheduling predicates."""
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
        def poll(self):
            return 0
        def wait(self, timeout=None):
            return 0
    worker = {"pid": 12345, "pgid": 999999, "session_id": 12345,
              "nonce": nonce, "case": "B", "start_new_session": True}
    child = {"kind": "supervisor-child", "pid": 999998, "pgid": 999998,
             "session_id": 999998, "worker_pid": 12345, "nonce": nonce,
             "case": "B", "start_new_session": True}
    helper = parent_watchdog_cleanup(
        FakeProc(), worker, [child], nonce, "B", "watchdog-timeout",
        Path("/dev/null"), Path("/dev/null"),
    )
    assert helper["worker_reaped"] is True
    assert helper["cleanup_deadline_started"] is True
    original_group_present = shared_validation.group_present
    shared_validation.group_present = lambda pgid: False
    try:
        focused_unknown = parent_watchdog_cleanup(
            FakeProc(), worker, [child], nonce, "B", "watchdog-timeout",
            Path("/dev/null"), Path("/dev/null"), live_handles=())
    finally:
        shared_validation.group_present = original_group_present
    assert focused_unknown["cleanup_state"] == "UNKNOWN"
    print(json.dumps({"passed": True, "checks": [
        "exact-case-nonce-checkpoint", "wrong-case-rejected",
        "stale-nonce-rejected", "empty-parser", "stale-pidfd-rejected"
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


if __name__ == "__main__":
    if sys.argv[1:] == ["--state-machine-self-test"]:
        checkpoint_state_self_test()
    elif sys.argv[1:] == ["--fault-checks"]:
        fault_checks()
    elif sys.argv[1:] == ["--fault-pre-guard"]:
        fault_main("pre-guard")
    elif sys.argv[1:] == ["--fault-post-guard"]:
        fault_main("post-guard")
    elif sys.argv[1:] == ["--cases", "A2", "B"]:
        main(("A2", "B"))
    elif sys.argv[1:] == ["--child", *sys.argv[2:]]:
        child_main(*sys.argv[2:])
    elif len(sys.argv) == 8 and sys.argv[1] == "--worker":
        worker_main(sys.argv[2], sys.argv[3:5], sys.argv[5], sys.argv[6],
                    sys.argv[7])
    else:
        main()