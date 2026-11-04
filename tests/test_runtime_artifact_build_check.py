"""Synthetic producer-to-intake handoff; no platform, live trust or app server."""
from __future__ import annotations

import base64
from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from security import runtime_artifact_build_check as intake
from security.runtime_artifact_package import package_runtime_artifact
from security.runtime_artifact_provenance import RuntimeArtifactError, public_key_id


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    source = tmp_path / "producer"
    source.mkdir()
    (source / "application.py").write_bytes(b"VALUE = 1\n")
    environment = {"PATH": os.defpath, "HOME": str(tmp_path),
                   "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    for args in (("init", "-q"), ("add", "."),
                 ("-c", "user.name=Synthetic Producer", "-c", "user.email=synthetic@example.invalid",
                  "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "Synthetic source")):
        subprocess.run(["git", *args], cwd=source, env=environment, check=True, capture_output=True)
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    root = tmp_path / "artifact"
    package_runtime_artifact(source, root, signing_key=private,
                             producer_key_id=public_key_id(public), producer_scope="test")
    manifest = json.loads((root / "runtime_source_manifest.json").read_bytes())
    # Producer Git and signing input are unavailable at the intake boundary.
    shutil.rmtree(source)
    for name in list(os.environ):
        if name.startswith("USBAY_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("USBAY_ENV", "test")
    monkeypatch.setenv("USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY", base64.b64encode(public).decode())
    monkeypatch.setenv("USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID", public_key_id(public))
    monkeypatch.setenv("USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE", "test")
    return SimpleNamespace(root=root, manifest=manifest, tmp=tmp_path)


def check(bundle, **pins):
    return intake.check_prebuilt_runtime_artifact(
        bundle.root,
        expected_source_commit=pins.get("commit", bundle.manifest["source_commit"]),
        expected_source_tree=pins.get("tree", bundle.manifest["source_tree_reference"]),
    )


def test_existing_package_is_checked_without_git_signer_or_writes(bundle, monkeypatch):
    before = {p.name: (p.read_bytes(), p.stat().st_mode) for p in bundle.root.iterdir()}
    monkeypatch.setenv("PATH", "/nonexistent")
    with patch.object(subprocess, "run", side_effect=AssertionError("Intake subprocess forbidden")):
        result = check(bundle)
    assert result.source_commit == bundle.manifest["source_commit"]
    assert result.source_tree_reference == bundle.manifest["source_tree_reference"]
    assert result.manifest_digest == bundle.manifest["manifest_digest"]
    assert not (bundle.root / ".git").exists()
    assert before == {p.name: (p.read_bytes(), p.stat().st_mode) for p in bundle.root.iterdir()}
    assert not any((result.execution_authorized, result.deployment_authorized,
                    result.activation_authorized, result.claim_freshness_verified,
                    result.image_identity_verified))
    with pytest.raises(FrozenInstanceError):
        result.deployment_authorized = True


@pytest.mark.parametrize("pin", [None, True, "", "*", "a" * 39, "A" * 40, "../source", "a" * 40])
@pytest.mark.parametrize("name", ["commit", "tree"])
def test_both_source_pins_are_required_and_exact(bundle, pin, name):
    with pytest.raises(RuntimeArtifactError):
        check(bundle, **{name: pin})


@pytest.mark.parametrize("name", ["USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY",
                                 "USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID",
                                 "USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE"])
def test_missing_independent_trust_denies(bundle, monkeypatch, name):
    monkeypatch.delenv(name)
    with pytest.raises(RuntimeArtifactError):
        check(bundle)


def test_wrong_independent_producer_denies(bundle, monkeypatch):
    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    monkeypatch.setenv("USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY", base64.b64encode(other).decode())
    monkeypatch.setenv("USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID", public_key_id(other))
    with pytest.raises(RuntimeArtifactError):
        check(bundle)


def test_test_trust_cannot_be_used_in_production(bundle, monkeypatch):
    monkeypatch.setenv("USBAY_ENV", "production")
    with pytest.raises(RuntimeArtifactError):
        check(bundle)


@pytest.mark.parametrize("kind", ["content", "mode", "missing_file", "missing_manifest",
                                  "signature", "source_commit", "symlink", "extra_file"])
def test_tampered_or_incomplete_package_denies(bundle, kind):
    application = bundle.root / "application.py"
    manifest_path = bundle.root / "runtime_source_manifest.json"
    if kind == "content":
        application.write_bytes(b"CHANGED = 1\n")
    elif kind == "mode":
        application.chmod(0o755)
    elif kind == "missing_file":
        application.unlink()
    elif kind == "missing_manifest":
        manifest_path.unlink()
    elif kind == "symlink":
        outside = bundle.tmp / "outside.py"
        outside.write_bytes(application.read_bytes())
        application.unlink()
        application.symlink_to(outside)
    elif kind == "extra_file":
        (bundle.root / "extra.py").write_text("UNKNOWN = True\n")
    else:
        manifest = dict(bundle.manifest)
        manifest[kind] = "f" * 40 if kind == "source_commit" else base64.b64encode(bytes(64)).decode()
        manifest_path.write_text(json.dumps(manifest))
    with pytest.raises((RuntimeArtifactError, OSError)):
        check(bundle)


@pytest.mark.parametrize("name", ["USBAY_RUNTIME_SOURCE_MANIFEST", "USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE"])
def test_configuration_change_during_intake_denies(bundle, monkeypatch, name):
    original = intake.load_runtime_artifact_authority

    def changed(*args, **kwargs):
        authority = original(*args, **kwargs)
        monkeypatch.setenv(name, "different.json" if name.endswith("MANIFEST") else "production")
        return authority

    monkeypatch.setattr(intake, "load_runtime_artifact_authority", changed)
    with pytest.raises(RuntimeArtifactError):
        check(bundle)


def test_noncanonical_manifest_selection_denies(bundle, monkeypatch):
    monkeypatch.setenv("USBAY_RUNTIME_SOURCE_MANIFEST", "other.json")
    with pytest.raises(RuntimeArtifactError):
        check(bundle)


def test_file_change_after_loading_is_rejected(bundle, monkeypatch):
    original = intake.load_runtime_artifact_authority

    def changed(*args, **kwargs):
        authority = original(*args, **kwargs)
        (bundle.root / "application.py").write_bytes(b"CHANGED_DURING_INTAKE = 1\n")
        return authority

    monkeypatch.setattr(intake, "load_runtime_artifact_authority", changed)
    with pytest.raises(RuntimeArtifactError):
        check(bundle)


def test_repeated_check_does_not_claim_freshness_or_consume_authority(bundle):
    assert check(bundle) == check(bundle)
    assert check(bundle).claim_freshness_verified is False


def test_cli_returns_only_bounded_status(bundle, capsys):
    arguments = ["--artifact-root", str(bundle.root),
                 "--expected-source-commit", bundle.manifest["source_commit"],
                 "--expected-source-tree", bundle.manifest["source_tree_reference"]]
    assert intake.main(arguments) == 0
    assert capsys.readouterr().out == "runtime_prebuilt_source_verified\n"
    (bundle.root / "runtime_source_manifest.json").unlink()
    assert intake.main(arguments) == 1
    output = capsys.readouterr()
    assert output.out == "" and output.err == "runtime_prebuilt_source_denied\n"


@pytest.mark.parametrize("arguments", [[], ["--unknown", "private-input-sentinel"]])
def test_cli_argument_errors_do_not_echo_inputs(arguments, capsys):
    assert intake.main(arguments) == 1
    assert capsys.readouterr().err == "runtime_prebuilt_source_denied\n"


def test_cli_symlink_loop_returns_bounded_error(bundle, capsys):
    loop = bundle.tmp / "private-path-sentinel"
    loop.symlink_to(loop)
    assert intake.main([
        "--artifact-root", str(loop),
        "--expected-source-commit", bundle.manifest["source_commit"],
        "--expected-source-tree", bundle.manifest["source_tree_reference"],
    ]) == 1
    output = capsys.readouterr()
    assert output.out == "" and output.err == "runtime_prebuilt_source_denied\n"


def test_actual_cli_checks_handoff_from_gitless_artifact_directory(bundle):
    root = str(Path(__file__).resolve().parents[1])
    environment = {name: value for name, value in os.environ.items()
                   if name in {"USBAY_ENV", "USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY",
                               "USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID",
                               "USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE"}}
    environment.update(PATH="/nonexistent", PYTHONPATH=root, PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(
        [sys.executable, "-B", "-m", "security.runtime_artifact_build_check",
         "--artifact-root", str(bundle.root),
         "--expected-source-commit", bundle.manifest["source_commit"],
         "--expected-source-tree", bundle.manifest["source_tree_reference"]],
        cwd=bundle.root, env=environment, capture_output=True, timeout=30,
    )
    assert result.returncode == 0
    assert result.stdout == b"runtime_prebuilt_source_verified\n"
    assert result.stderr == b""


def test_checker_import_has_no_builder_signer_or_gateway_dependency():
    root = str(Path(__file__).resolve().parents[1])
    code = ("import sys;sys.path.insert(0," + repr(root) + ");"
            "from security import runtime_artifact_build_check;"
            "assert 'security.runtime_artifact_builder' not in sys.modules;"
            "assert 'security.runtime_artifact_package' not in sys.modules;"
            "assert 'gateway.app' not in sys.modules;"
            "assert 'security.deployment_attestation' not in sys.modules")
    subprocess.run([sys.executable, "-I", "-B", "-c", code], check=True,
                   capture_output=True, timeout=30, env={"PATH": os.defpath})
