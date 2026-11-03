"""Credential-free validation in a disposable tracked-source copy.

Invoke with the existing interpreter using -I -S -B. No venv/install/workflow.
This is a development test guard, not a sandbox for hostile arbitrary code.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DEPENDENCIES = Path("/home/runner/workspace/.pythonlibs/lib/python3.11/site-packages")
SOURCE_FILES = (
    ".replit", ".gitignore", "gateway/app.py", "security/deployment_attestation.py",
    "security/runtime_artifact_provenance.py",
    "security/runtime_artifact_authority.py", "security/runtime_artifact_package.py",
    "tests/test_gitless_runtime_integration.py", "tools/run_gitless_integration_validation.py",
    "docs/runtime-artifact-producer-trust.md", "tests/test_deployment_provenance.py",
)


def hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCE_FILES}


def guard(fixture: Path, evidence: Path) -> None:
    test_root = fixture.parent.parent if fixture.name == "full-package" else fixture.parent
    read_roots = (test_root, evidence, DEPENDENCIES, Path("/nix/store"), Path("/usr"), Path("/lib"))

    def bounded(path, writing=False):
        if isinstance(path, int):
            return
        path = Path(os.fsdecode(path)).absolute()
        roots = (test_root, evidence) if writing else read_roots
        if path == Path("/dev/null") or any(path.is_relative_to(root) for root in roots):
            return
        if not writing and str(path) in {"/etc/localtime", "/etc/ld.so.cache", "/etc/mime.types"}:
            return
        raise PermissionError("validation_filesystem_boundary")

    def audit(event, args):
        if event in {"socket.connect", "socket.connect_ex", "socket.bind", "socket.getaddrinfo"}:
            raise PermissionError("validation_network_boundary")
        if event in {"os.system", "os.exec", "os.fork", "os.forkpty", "os.posix_spawn"}:
            raise PermissionError("validation_process_boundary")
        if event == "subprocess.Popen":
            command = args[1]
            cwd = Path(args[2] or Path.cwd()).absolute()
            if (
                not isinstance(command, (list, tuple)) or command[0] != "git"
                or not cwd.is_relative_to(test_root)
            ):
                raise PermissionError("validation_subprocess_boundary")
            if "-C" in command:
                target = Path(command[command.index("-C") + 1]).absolute()
                if not target.is_relative_to(test_root):
                    raise PermissionError("validation_git_boundary")
        if event == "open":
            mode = args[1] or ""
            flags = args[2]
            writing = any(char in mode for char in "wax+") or bool(
                flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
            )
            bounded(args[0], writing)
        if event in {"os.listdir", "os.scandir", "os.chdir"}:
            bounded(args[0])
        if event in {"os.mkdir", "os.remove", "os.rmdir", "os.chmod", "os.utime", "shutil.rmtree"}:
            bounded(args[0], True)
        if event in {"os.rename", "os.link"}:
            bounded(args[0], True)
            bounded(args[1], True)
        if event == "os.symlink":
            # Synthetic tests may create unsafe targets; opening them is denied.
            bounded(args[1], True)

    sys.addaudithook(audit)


def child(fixture: Path, evidence: Path, phase: str) -> int:
    os.chdir(fixture)
    sys.path[:0] = [str(fixture / "python"), str(fixture), str(DEPENDENCIES)]
    guard(fixture, evidence)
    print("ISOLATED_ROOT", fixture, flush=True)
    print("INTERPRETER", sys.executable, sys.version, flush=True)
    if phase == "package":
        import base64
        from datetime import datetime, timezone
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from security.runtime_artifact_package import package_runtime_artifact
        from security.runtime_artifact_provenance import public_key_id
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        destination = fixture / "full-package"
        package_runtime_artifact(
            fixture, destination, signing_key=key,
            producer_key_id=public_key_id(public), producer_scope="test",
        )
        from security import deployment_attestation as deployment
        artifact = json.loads((destination / "runtime_source_manifest.json").read_bytes())
        os.chdir(destination)
        release = {
            "release_id": "synthetic-full-package",
            "deployment_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "git_commit": artifact["source_commit"],
            "policy_bundle_hash": deployment.policy_bundle_hash(),
            "tenant_id": "t1", "previous_release_hash": "GENESIS",
            "activating_node_id": deployment._canonical_activating_node_id(),
        }
        release["release_signature"] = deployment.sign_release_manifest(release)
        (evidence / "packaged-startup-release.json").write_text(json.dumps(release))
        (evidence / "packaged-public-trust.json").write_text(json.dumps({
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY": base64.b64encode(public).decode(),
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID": public_key_id(public),
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE": "test",
        }))
        print("PACKAGED_FILE_COUNT", len(artifact["managed_files"]), flush=True)
        print("PACKAGED_GIT_ABSENT", not (destination / ".git").exists(), flush=True)
        return 0
    if phase == "startup":
        import gateway.app as gateway
        from unittest.mock import patch
        class BoundaryReached(RuntimeError):
            pass
        try:
            with patch.object(gateway, "load_tenant_policy", side_effect=BoundaryReached):
                gateway.validate_policy_registry_startup()
        except BoundaryReached:
            print("GITLESS_PROVENANCE_PASSED", flush=True)
            print("STARTUP_PATH_REACHED=before_load_tenant_policy", flush=True)
            print("NEXT_STARTUP_BLOCKER=NOT_EVALUATED_CONTROLLED_TEST_STOP", flush=True)
            return 0
        except Exception as exc:
            print("STARTUP_BOUNDARY_FAILED", type(exc).__name__, str(exc).split(":")[0], flush=True)
            return 1
        raise RuntimeError("Expected bounded startup stop was not reached")
    if phase == "trust":
        import runpy
        sys.argv = [str(fixture / "tests/test_runtime_artifact_provenance.py")]
        runpy.run_path(sys.argv[0], run_name="__main__")
        return 0
    import pytest
    arguments = [
        "-q", "-p", "no:cacheprovider", "--basetemp", str(fixture.parent / (phase + "-pytest-temp")),
        "--junitxml", str(evidence / (phase + ".xml")), "--tb=short",
    ]
    if phase == "integration":
        arguments += ["tests/test_gitless_runtime_integration.py"]
    else:
        arguments += [
            "tests/test_public_release_safety.py", "tests/test_deployment_provenance.py",
            "tests/test_governance_release_integrity.py", "tests/test_tenant_boundary_contracts.py",
            "tests/test_replay_protection.py", "tests/test_policy_registry_contracts.py",
            "tests/test_runtime_governance_monitor.py", "tests/test_hydra_consensus_contracts.py",
        ]
        # Repository-wide export scan and external process contracts are not
        # scanner/provenance regressions. Keep their first-run failures intact;
        # never widen the execution guard merely to run those unrelated checks.
        arguments += ["-k", (
            "not test_public_repo_contains_no_private_key_material "
            "and not test_mac_validation_script_has_single_valid_invalid_output_contract "
            "and not test_public_release_check_cli_validates_clean_minimal_tree "
            "and not test_pre_commit_hook_blocks_staged_private_key"
        )]
    print("PYTEST_ARGUMENTS", json.dumps(arguments), flush=True)
    return pytest.main(arguments)


def main() -> int:
    if len(sys.argv) == 5 and sys.argv[1] == "--child":
        return child(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
    evidence = Path(sys.argv[1]).absolute()
    before = hashes()
    (evidence / "source-before.json").write_text(json.dumps(before, indent=2) + "\n")
    temporary = Path(tempfile.mkdtemp(prefix="usbay-gitless-validation-"))
    fixture = temporary / "source"
    fixture.mkdir()
    environment = {
        "PATH": os.environ["PATH"], "HOME": "/nonexistent",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1",
    }
    listing = subprocess.run(
        ["git", "-C", str(ROOT), "ls-tree", "-rz", "--name-only", "HEAD"],
        capture_output=True, check=True, env=environment,
    ).stdout
    # Copy committed paths plus only the exact candidate overlays. Never copy
    # ignored/untracked state, keys, configuration outside the scoped sources.
    paths = {item.decode("utf-8") for item in listing.split(b"\0") if item}
    paths.update(SOURCE_FILES)
    for name in sorted(paths):
        source = ROOT / name
        target = fixture / name
        if source.is_symlink() or not source.is_file():
            raise RuntimeError("validation_source_type_unsupported")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)
    os.chdir(fixture)
    for command in (
        ["git", "init", "-q"], ["git", "add", "--force", "--", "."],
        ["git", "-c", "user.name=Synthetic Validation", "-c", "user.email=synthetic@example.invalid",
         "-c", "commit.gpgsign=false", "commit", "-qm", "Synthetic validation snapshot only"],
    ):
        subprocess.run(command, check=True, env=environment, capture_output=True)
    result = {}
    # Preserve the disposable fixture for failure inspection, never activate it.
    (evidence / "isolated-root.txt").write_text(str(fixture) + "\n")
    for phase in ("trust", "integration", "regressions", "package", "startup"):
        phase_root = temporary / phase
        if phase == "startup":
            phase_root = temporary / "package/full-package"
            if not phase_root.is_dir():
                result[phase] = "BLOCKED_BY_PACKAGE"
                continue
        else:
            shutil.copytree(fixture, phase_root)
        temps = temporary / (phase + "-tempfiles")
        temps.mkdir()
        env = dict(
            environment, TMPDIR=str(temps), PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
            USBAY_ENV="test", PYTHONDONTWRITEBYTECODE="1",
            USBAY_DEPLOYMENT_SIGNING_MATERIAL="synthetic-validation-only-release-hmac",
            USBAY_GENERATED_GOVERNANCE_RELEASE_DIR=str(phase_root / "tmp/generated-release"),
        )
        if phase == "startup":
            env.update(json.loads((evidence / "packaged-public-trust.json").read_text()))
            env.update(
                PATH="/nonexistent",
                USBAY_RUNTIME_SOURCE_MANIFEST="runtime_source_manifest.json",
                USBAY_GOVERNANCE_RELEASE_PATH=str(evidence / "packaged-startup-release.json"),
            )
        command = [
            sys.executable, "-I", "-S", "-B", str(phase_root / "tools/run_gitless_integration_validation.py"),
            "--child", str(phase_root), str(evidence), phase,
        ]
        (evidence / (phase + "-command.json")).write_text(json.dumps(command) + "\n")
        with (evidence / (phase + "-output.txt")).open("wb") as output:
            try:
                completed = subprocess.run(command, cwd=phase_root, env=env, stdout=output, stderr=subprocess.STDOUT, timeout=600)
                result[phase] = completed.returncode
            except subprocess.TimeoutExpired:
                result[phase] = "TIMEOUT"
        print("PHASE_EXIT", phase, result[phase], flush=True)
    after = hashes()
    (evidence / "source-after.json").write_text(json.dumps(after, indent=2) + "\n")
    (evidence / "phase-exits.json").write_text(json.dumps(result, indent=2) + "\n")
    if before != after:
        raise RuntimeError("validation_candidate_source_changed")
    print("SOURCE_PRESERVATION", "MATCH", flush=True)
    return 0 if all(code == 0 for code in result.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
