"""Deterministic GitHub-to-Replit deployment sync control.

This module is the runtime side of the GitHub -> Replit deployment sync
contract. It provides:

* :func:`deployment_sync_snapshot` — a small, stable JSON-serializable
  view of the deployment's current commit, deployment revision, policy
  version, and runtime status. The gateway exposes this on
  ``/api/status`` so operators (and the dashboard) can verify whether
  the live deployment is actually running the commit that was merged
  to GitHub ``main``.

* :func:`validate_deployment_commit_sync` — a fail-closed startup
  check. When the environment declares an expected GitHub ``main``
  commit (``USBAY_EXPECTED_GIT_COMMIT`` or ``GITHUB_MAIN_SHA``) and
  the runtime commit does not match, startup raises
  :class:`DeploymentCommitMismatchError`. The mismatch is logged
  through a dedicated structured logger and recorded in the audit
  chain via the injected audit hook. SHAs are *not* secrets and are
  logged verbatim; no environment values other than the two commit
  SHAs are emitted.

* When no expected commit is declared (typical for local dev / test),
  the validator is a no-op and the snapshot reports
  ``commit_match="unenforced"`` rather than failing closed. This
  preserves existing developer workflows while making the production
  guarantee deterministic.

The runtime commit is resolved via
:func:`security.deployment_attestation.current_git_commit`, which in
turn uses ``git rev-parse HEAD`` and falls back to the build-time
``governance/runtime_commit.txt`` stamp (see
``scripts/stamp_runtime_commit.py``). This is the same source used by
the rest of the attestation surface, so ``/api/status`` cannot drift
from the signed runtime release manifest.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Callable, Mapping

from security.deployment_attestation import (
    DeploymentAttestationError,
    current_git_commit,
)

deployment_sync_logger = logging.getLogger("usbay.gateway.deployment_sync")

EXPECTED_COMMIT_ENV_VARS = ("USBAY_EXPECTED_GIT_COMMIT", "GITHUB_MAIN_SHA")
DEPLOYMENT_REVISION_ENV_VARS = (
    "REPLIT_DEPLOYMENT_ID",
    "REPLIT_DEPLOYMENT",
    "DEPLOYMENT_ID",
)

COMMIT_MATCH_OK = "match"
COMMIT_MATCH_MISMATCH = "mismatch"
COMMIT_MATCH_UNENFORCED = "unenforced"
COMMIT_MATCH_UNKNOWN = "unknown"

RUNTIME_STATUS_NORMAL = "NORMAL"
RUNTIME_STATUS_DEGRADED = "DEGRADED"
RUNTIME_STATUS_FAIL_CLOSED = "FAIL_CLOSED"

MISMATCH_AUDIT_ACTION = "deployment_commit_mismatch"

_HEX = set("0123456789abcdef")


class DeploymentCommitMismatchError(RuntimeError):
    """Raised at startup when runtime commit != expected GitHub main commit."""

    def __init__(self, *, expected: str, actual: str) -> None:
        # SHAs are non-secret. Include both so the deployment log makes
        # the mismatch obvious without requiring an extra audit lookup.
        super().__init__(
            f"deployment_commit_mismatch: expected={expected} actual={actual}"
        )
        self.expected = expected
        self.actual = actual


def _normalize_sha(value: str | None) -> str:
    candidate = (value or "").strip().lower()
    if len(candidate) == 40 and all(ch in _HEX for ch in candidate):
        return candidate
    return ""


def expected_github_main_commit() -> str:
    """Return the expected GitHub ``main`` commit SHA from the environment.

    Returns an empty string if no expected commit is configured, which
    signals the validator to operate in *unenforced* mode (no-op).
    """
    for name in EXPECTED_COMMIT_ENV_VARS:
        sha = _normalize_sha(os.getenv(name))
        if sha:
            return sha
    return ""


def current_runtime_commit() -> str:
    """Return the runtime commit SHA, or empty string if unresolvable.

    Wraps :func:`security.deployment_attestation.current_git_commit` so
    that the snapshot surface never raises — health/status must remain
    serviceable even when commit provenance is unavailable, while the
    explicit :func:`validate_deployment_commit_sync` still fails closed
    when an expected commit is declared.
    """
    try:
        sha = current_git_commit()
    except DeploymentAttestationError:
        return ""
    return _normalize_sha(sha)


def deployment_revision() -> str:
    """Return the Replit deployment revision identifier.

    Prefers ``REPLIT_DEPLOYMENT_ID`` (set by Replit Deployments) so that
    each promote of the same git commit is still distinguishable. Falls
    back to the runtime commit so dev/test environments report a stable
    revision.
    """
    for name in DEPLOYMENT_REVISION_ENV_VARS:
        value = (os.getenv(name) or "").strip()
        if value:
            return value
    return current_runtime_commit()


def _runtime_status(
    runtime_mode: str | None,
    *,
    registry_available: bool,
) -> str:
    if not registry_available:
        return RUNTIME_STATUS_FAIL_CLOSED
    mode = (runtime_mode or "").strip().upper()
    if mode == RUNTIME_STATUS_NORMAL:
        return RUNTIME_STATUS_NORMAL
    if mode in {RUNTIME_STATUS_DEGRADED, "FAIL_CLOSED"}:
        return mode if mode == RUNTIME_STATUS_DEGRADED else RUNTIME_STATUS_FAIL_CLOSED
    return RUNTIME_STATUS_DEGRADED


def _commit_match_state(actual: str, expected: str) -> str:
    if not expected:
        return COMMIT_MATCH_UNENFORCED
    if not actual:
        return COMMIT_MATCH_UNKNOWN
    return COMMIT_MATCH_OK if actual == expected else COMMIT_MATCH_MISMATCH


def deployment_sync_snapshot(
    *,
    runtime_mode: str | None,
    policy_version: str | None,
    registry_available: bool,
) -> dict[str, Any]:
    """Return the JSON-serializable deployment-sync view.

    Fields:
        git_commit           runtime commit SHA (empty if unresolvable)
        deployment_revision  Replit deployment id, or commit SHA fallback
        policy_version       active policy registry version
        runtime_status       NORMAL | DEGRADED | FAIL_CLOSED
        expected_git_commit  expected GitHub main SHA from env (or "")
        commit_match         match | mismatch | unenforced | unknown
    """
    actual = current_runtime_commit()
    expected = expected_github_main_commit()
    return {
        "git_commit": actual,
        "deployment_revision": deployment_revision(),
        "policy_version": (policy_version or "").strip(),
        "runtime_status": _runtime_status(
            runtime_mode, registry_available=registry_available
        ),
        "expected_git_commit": expected,
        "commit_match": _commit_match_state(actual, expected),
    }


def _safe_audit(
    audit_hook: Callable[[str, Mapping[str, Any]], Any] | None,
    event: Mapping[str, Any],
) -> None:
    if audit_hook is None:
        return
    try:
        audit_hook(MISMATCH_AUDIT_ACTION, dict(event))
    except Exception:
        # Audit append must never mask the fail-closed error itself.
        deployment_sync_logger.exception(
            "deployment_commit_mismatch_audit_append_failed"
        )


def validate_deployment_commit_sync(
    *,
    audit_hook: Callable[[str, Mapping[str, Any]], Any] | None = None,
) -> dict[str, Any]:
    """Fail closed if the runtime commit differs from the expected commit.

    Behaviour matrix:

    * No expected commit declared -> returns a snapshot with
      ``commit_match="unenforced"``. Never raises. This is the dev /
      test default and preserves existing local workflows.
    * Expected declared and matches runtime -> returns
      ``commit_match="match"``.
    * Expected declared but runtime commit unresolvable -> raises
      :class:`DeploymentCommitMismatchError` with ``actual=""``. We
      treat "unknown" as a mismatch in enforced mode rather than
      silently passing.
    * Expected declared and differs from runtime -> structured log,
      audit-chain append, then raises
      :class:`DeploymentCommitMismatchError`.

    The structured log and audit event include only the two commit
    SHAs (which are non-secret) plus the deployment revision. No
    other environment values are read or emitted.
    """
    actual = current_runtime_commit()
    expected = expected_github_main_commit()
    revision = deployment_revision()

    if not expected:
        return {
            "git_commit": actual,
            "expected_git_commit": "",
            "deployment_revision": revision,
            "commit_match": COMMIT_MATCH_UNENFORCED,
        }

    if actual and actual == expected:
        return {
            "git_commit": actual,
            "expected_git_commit": expected,
            "deployment_revision": revision,
            "commit_match": COMMIT_MATCH_OK,
        }

    event = {
        "event": MISMATCH_AUDIT_ACTION,
        "expected_git_commit": expected,
        "actual_git_commit": actual,
        "deployment_revision": revision,
    }
    deployment_sync_logger.error(
        "deployment_commit_mismatch expected=%s actual=%s revision=%s",
        expected,
        actual or "<unresolved>",
        revision or "<unresolved>",
        extra={"deployment_sync": event},
    )
    _safe_audit(audit_hook, event)
    raise DeploymentCommitMismatchError(expected=expected, actual=actual)
