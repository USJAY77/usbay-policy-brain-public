"""Tests for refined public-vs-private PEM classification in the
forbidden-runtime-file validator.

Locks the contract:
  - ``*.pub.pem`` and ``*_public_key.pem`` whose body actually
    contains a PUBLIC KEY block (and no PRIVATE KEY block) are
    allowed without being on the static APPROVED_PUBLIC_PEM_PATHS
    list.
  - A file with a public-looking name but private-key body is still
    blocked fail-closed.
  - A `.pem` file with neither public naming convention nor an entry
    in APPROVED_PUBLIC_PEM_PATHS is blocked.
  - Diagnostics remain deterministic: each blocked file carries its
    matched rule identifier.

Does not modify fail-closed behaviour, replay protection, runtime
startup semantics, deployment config, or governance evidence logic.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import gateway.app as gateway_app
from security.policy_registry import PolicyRegistryError


PUBLIC_PEM_BODY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAhTGzB039ozE7Q9/eWKlouOlQYij9NR8/PHO+GN+ZooE=\n"
    "-----END PUBLIC KEY-----\n"
)

PRIVATE_PEM_BODY = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIN3kZJ1+local+placeholder+not+a+real+secret==\n"
    "-----END PRIVATE KEY-----\n"
)


def _write(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def test_pub_pem_with_public_body_is_allowed(tmp_path: Path) -> None:
    _write(tmp_path / "keys_runtime" / "release_ed25519.pub.pem", PUBLIC_PEM_BODY)
    _write(tmp_path / "keys_runtime" / "root_authority_ed25519.pub.pem", PUBLIC_PEM_BODY)
    assert gateway_app.forbidden_runtime_file_findings(repo_root=tmp_path) == []


def test_public_key_pem_naming_with_public_body_is_allowed(tmp_path: Path) -> None:
    _write(tmp_path / "approvals" / "approver7_public_key.pem", PUBLIC_PEM_BODY)
    _write(tmp_path / "approvals" / "prod" / "approver_z_public_key.pem", PUBLIC_PEM_BODY)
    assert gateway_app.forbidden_runtime_file_findings(repo_root=tmp_path) == []


def test_public_named_pem_with_private_body_is_blocked(tmp_path: Path) -> None:
    target = _write(
        tmp_path / "keys_runtime" / "malicious.pub.pem", PRIVATE_PEM_BODY
    )
    findings = gateway_app.forbidden_runtime_file_findings(repo_root=tmp_path)
    rules = {(f["path"], f["rule"]) for f in findings}
    # Naming passes but content must fail -> classified as not-public.
    # The private-key marker scan also triggers for the same path.
    assert ("keys_runtime/malicious.pub.pem", gateway_app.FORBIDDEN_RUNTIME_RULE_PEM_NOT_PUBLIC_KEY) in rules
    with pytest.raises(PolicyRegistryError, match="forbidden_runtime_file_present"):
        gateway_app.validate_no_forbidden_runtime_files(repo_root=tmp_path)
    assert target.exists()  # validator never mutates the offender


def test_unconventional_pem_path_is_blocked(tmp_path: Path) -> None:
    _write(tmp_path / "lib" / "random_cert.pem", PUBLIC_PEM_BODY)
    findings = gateway_app.forbidden_runtime_file_findings(repo_root=tmp_path)
    rules = {(f["path"], f["rule"]) for f in findings}
    assert (
        "lib/random_cert.pem",
        gateway_app.FORBIDDEN_RUNTIME_RULE_PEM_UNAPPROVED_PATH,
    ) in rules


def test_private_signing_pem_still_blocked_fail_closed(tmp_path: Path) -> None:
    _write(tmp_path / "keys_runtime" / "release_signing.pem", PRIVATE_PEM_BODY)
    with pytest.raises(PolicyRegistryError, match="forbidden_runtime_file_present"):
        gateway_app.validate_no_forbidden_runtime_files(repo_root=tmp_path)


def test_pem_naming_alone_does_not_globally_whitelist(tmp_path: Path) -> None:
    # An empty `.pub.pem` (no PUBLIC KEY body) must still be blocked --
    # naming does not by itself authorise the file.
    _write(tmp_path / "keys_runtime" / "empty.pub.pem", "")
    findings = gateway_app.forbidden_runtime_file_findings(repo_root=tmp_path)
    rules = {(f["path"], f["rule"]) for f in findings}
    assert (
        "keys_runtime/empty.pub.pem",
        gateway_app.FORBIDDEN_RUNTIME_RULE_PEM_NOT_PUBLIC_KEY,
    ) in rules


def test_legacy_whitelist_path_still_allowed_when_public(tmp_path: Path) -> None:
    # `audit/public_key.pem` is on APPROVED_PUBLIC_PEM_PATHS but does
    # not match the *.pub.pem / *_public_key.pem naming convention
    # (it's just `public_key.pem`). It should still resolve as allowed
    # via the explicit whitelist when the body is public.
    _write(tmp_path / "audit" / "public_key.pem", PUBLIC_PEM_BODY)
    assert gateway_app.forbidden_runtime_file_findings(repo_root=tmp_path) == []


def test_classification_helpers_are_deterministic() -> None:
    assert gateway_app._has_public_pem_naming("keys_runtime/release_ed25519.pub.pem") is True
    assert gateway_app._has_public_pem_naming("approvals/x_public_key.pem") is True
    assert gateway_app._has_public_pem_naming("lib/random.pem") is False
    assert gateway_app._has_public_pem_naming("config/secret.key") is False


def test_real_runtime_keys_are_not_flagged() -> None:
    # Smoke against the real repo: the validator must not flag the
    # actual on-disk public verification PEMs as forbidden. (Other
    # forbidden artifacts in the live tree are out of scope here --
    # this test asserts only that the listed public PEMs do not
    # appear as offenders.)
    findings = gateway_app.forbidden_runtime_file_findings()
    offender_paths = {f["path"] for f in findings}
    for known_public in (
        "keys_runtime/release_ed25519.pub.pem",
        "keys_runtime/root_authority_ed25519.pub.pem",
        "approvals/dev-ci/approver1_public_key.pem",
        "approvals/dev-ci/approver2_public_key.pem",
    ):
        if (Path(gateway_app.REPO_ROOT) / known_public).is_file():
            assert known_public not in offender_paths, (
                f"public verification PEM wrongly flagged: {known_public}"
            )
