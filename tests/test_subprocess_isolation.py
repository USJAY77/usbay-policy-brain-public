"""GAP 2 — subprocess secret isolation + execution bounds (fail-closed).

Tests A–F from the governance hardening batch spec. These exercise the
governed subprocess layer (security.execution_guard._run_command) directly;
the gateway approval chain around it is covered by test_execution_guard.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from security.execution_guard import (
    MAX_SUBPROCESS_OUTPUT_BYTES,
    _run_command,
)

PY = sys.executable or "python3"


@pytest.fixture()
def evidence_path(tmp_path):
    return tmp_path / "subprocess_evidence.jsonl"


def _meta(evidence_path, **kw):
    meta = {"execution_evidence_path": str(evidence_path)}
    meta.update(kw)
    return meta


def _print_env_cmd(tmp_path, var: str) -> str:
    script = tmp_path / "print_env.py"
    script.write_text(
        "import os\nprint(os.environ.get(%r, 'ABSENT'))\n" % var,
        encoding="utf-8",
    )
    return f"{PY} {script}"


# A. unapproved secret is NOT visible to child process
def test_unapproved_secret_not_visible_to_child(tmp_path, evidence_path, monkeypatch):
    monkeypatch.setenv("FAKE_TEST_SECRET_VALUE", "sk-fake-must-not-leak")
    result = _run_command(
        _print_env_cmd(tmp_path, "FAKE_TEST_SECRET_VALUE"), _meta(evidence_path)
    )
    assert result["returncode"] == 0
    assert "ABSENT" in result["stdout"]
    assert "sk-fake-must-not-leak" not in result["stdout"]


def test_parent_environment_not_copied_wholesale(tmp_path, evidence_path, monkeypatch):
    monkeypatch.setenv("UNRELATED_PARENT_VAR", "parent-only-value")
    result = _run_command(
        _print_env_cmd(tmp_path, "UNRELATED_PARENT_VAR"), _meta(evidence_path)
    )
    assert result["returncode"] == 0
    assert "ABSENT" in result["stdout"]


# B. approved minimal variable passes when explicitly authorized
def test_approved_env_var_passes_when_authorized(tmp_path, evidence_path, monkeypatch):
    monkeypatch.setenv("USBAY_TEST_PLAIN_FLAG", "flag-value-ok")
    result = _run_command(
        _print_env_cmd(tmp_path, "USBAY_TEST_PLAIN_FLAG"),
        _meta(evidence_path, approved_env=["USBAY_TEST_PLAIN_FLAG"]),
    )
    assert result["returncode"] == 0
    assert "flag-value-ok" in result["stdout"]


def test_secretlike_approved_env_name_denied(tmp_path, evidence_path, monkeypatch):
    monkeypatch.setenv("MY_API_TOKEN", "tok-fake")
    result = _run_command(
        _print_env_cmd(tmp_path, "MY_API_TOKEN"),
        _meta(evidence_path, approved_env=["MY_API_TOKEN"]),
    )
    assert result["error"] == "execution_failed"
    assert result["reason"] == "approved_env_secretlike_denied"
    assert "tok-fake" not in json.dumps(result)


# C/D. timeout terminates the process and is never reported as success
def test_timeout_terminates_and_is_not_success(tmp_path, evidence_path):
    script = tmp_path / "sleep_forever.py"
    script.write_text("import time\ntime.sleep(600)\n", encoding="utf-8")
    result = _run_command(
        f"{PY} {script}",
        _meta(evidence_path, subprocess_timeout_seconds=1),
    )
    assert result["error"] == "execution_timeout"
    assert result["timed_out"] is True
    assert "returncode" not in result  # cannot be mistaken for success
    assert "stdout" not in result


def test_timeout_out_of_bounds_rejected(tmp_path, evidence_path):
    script = tmp_path / "noop.py"
    script.write_text("print('hi')\n", encoding="utf-8")
    for bad in (0, -5, 10**9, "soon"):
        result = _run_command(
            f"{PY} {script}", _meta(evidence_path, subprocess_timeout_seconds=bad)
        )
        assert result["error"] == "execution_failed"


# E. child-process failure produces evidence
def test_child_failure_produces_evidence(tmp_path, evidence_path):
    script = tmp_path / "fail.py"
    script.write_text("import sys\nsys.exit(3)\n", encoding="utf-8")
    result = _run_command(f"{PY} {script}", _meta(evidence_path))
    assert result["returncode"] == 3
    raw = evidence_path.read_text()
    assert "local_subprocess_execution" in raw
    assert result["command_hash"] in raw


def test_timeout_produces_evidence(tmp_path, evidence_path):
    script = tmp_path / "sleep.py"
    script.write_text("import time\ntime.sleep(600)\n", encoding="utf-8")
    _run_command(f"{PY} {script}", _meta(evidence_path, subprocess_timeout_seconds=1))
    raw = evidence_path.read_text()
    assert "timeout_terminated" in raw
    assert "FAIL_CLOSED" in raw


def test_spawn_failure_fails_closed_without_raw_detail(tmp_path, evidence_path):
    result = _run_command(
        "/nonexistent/binary-xyz --flag", _meta(evidence_path)
    )
    assert result["error"] == "execution_failed"
    # sanitized: exception class name only, no path/strerror detail
    assert "/nonexistent/binary-xyz" not in json.dumps(result)
    raw = evidence_path.read_text()
    assert "spawn_failed" in raw


# F. no raw secret appears in logs/evidence/client response
def test_no_raw_secret_in_evidence_or_result(tmp_path, evidence_path, monkeypatch):
    monkeypatch.setenv("FAKE_LEAKY_SECRET", "sk-canary-9f8e7d")
    script = tmp_path / "noop.py"
    script.write_text("print('done')\n", encoding="utf-8")
    result = _run_command(f"{PY} {script}", _meta(evidence_path))
    assert "sk-canary-9f8e7d" not in json.dumps(result)
    assert "sk-canary-9f8e7d" not in evidence_path.read_text()


def test_evidence_contains_no_env_values(tmp_path, evidence_path, monkeypatch):
    monkeypatch.setenv("USBAY_TEST_PLAIN_FLAG", "flag-value-ok")
    script = tmp_path / "noop.py"
    script.write_text("print('done')\n", encoding="utf-8")
    _run_command(
        f"{PY} {script}",
        _meta(evidence_path, approved_env=["USBAY_TEST_PLAIN_FLAG"]),
    )
    raw = evidence_path.read_text()
    assert "flag-value-ok" not in raw
    assert "env_policy" in raw


# output bounding
def test_output_is_capped(tmp_path, evidence_path):
    script = tmp_path / "spam.py"
    script.write_text(
        "import sys\nsys.stdout.write('x' * (%d * 4))\n" % MAX_SUBPROCESS_OUTPUT_BYTES,
        encoding="utf-8",
    )
    result = _run_command(f"{PY} {script}", _meta(evidence_path))
    assert result["returncode"] == 0
    assert len(result["stdout"].encode("utf-8")) <= MAX_SUBPROCESS_OUTPUT_BYTES + 100
    assert "OUTPUT TRUNCATED" in result["stdout"]


# existing valid subprocess path must keep working
def test_existing_py_compile_path_still_works(tmp_path, evidence_path):
    target = tmp_path / "ok.py"
    target.write_text("VALUE = 1\n", encoding="utf-8")
    result = _run_command(f"{PY} -m py_compile {target}", _meta(evidence_path))
    assert result["returncode"] == 0


# runaway child: forked grandchildren die with the process group on timeout
def test_forked_grandchild_killed_on_timeout(tmp_path, evidence_path):
    import os as _os
    import time as _time

    pid_file = tmp_path / "grandchild.pid"
    script = tmp_path / "forker.py"
    script.write_text(
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)'])\n"
        "open(%r, 'w').write(str(child.pid))\n"
        "time.sleep(600)\n" % str(pid_file),
        encoding="utf-8",
    )
    result = _run_command(
        f"{PY} {script}", _meta(evidence_path, subprocess_timeout_seconds=2)
    )
    assert result["error"] == "execution_timeout"
    # allow the group SIGKILL to land
    deadline = _time.time() + 5
    grandchild_pid = int(pid_file.read_text())
    alive = True
    while _time.time() < deadline:
        try:
            _os.kill(grandchild_pid, 0)
        except ProcessLookupError:
            alive = False
            break
        _time.sleep(0.2)
    if alive:
        _os.kill(grandchild_pid, 9)  # cleanup before failing
    assert not alive, "grandchild survived timeout — process group not killed"
