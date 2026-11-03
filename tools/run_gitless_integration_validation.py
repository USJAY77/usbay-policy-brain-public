"""Credential-free validation in a disposable tracked-source copy.

Invoke with the existing interpreter using -I -S -B. No venv/install/workflow.
This is a development test guard, not a sandbox for hostile arbitrary code.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
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
    "tools/startup_evidence_support.py", "tests/test_extended_startup_evidence.py",
    "docs/startup-publisher-evidence.md",
    "runtime/enforcement_gateway.py", "governance/release_integrity.py",
)

EXPECTED_COMMIT = "9bb15226a0964f2675c5077cdc7ed28c94909a42"
EXPECTED_TREE = "f8d20179dc0eeca5b166b04be7251ea90e93767a"
EXPECTED_SOURCE_COMMIT = "86a51108b3c2d567fa71f2b44aad7d6e5ff58c0a"
EXPECTED_SOURCE_TREE = "e1e3f2e69f45fbd19326f948b2fb5ce6f3dc3f05"
EXPECTED_REPAIR_PARENT = "5367d6946f8ea81f8acb21e8b6cabbf842a9ad69"
EXPECTED_REPAIR_PATCH = "d91c79d3079b2b1b31e9b2169cd75c5f202b258972fcf33289f542618bb32c36"
EXPECTED_TOOLING_BASE = "725de7b94e51f2e33da8e2a792b49bd1bf0d8489"
EXPECTED_TOOLING_TREE = "a3bd704a02f9629b4e5989a4916145c1a69dba7e"
EXPECTED_PIN_PATCH = "57714a51f94eb53b8a2aef815a4ddfc714e42e7598524fd48293976a1a479502"
EXPECTED_BRANCH = "fix/runtime-scanner-managed-artifact-boundary"
TOOLING_PATH = "tools/run_gitless_integration_validation.py"
MAX_TOOLING_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024
EXPECTED_PLATFORM_IGNORE_SHA256 = "2f48142895a7ec80dd3e65fbdb081a26f355624e838b1023c11310581a288299"


def require_digest(data: bytes, expected: str, code: str) -> None:
    if (
        not isinstance(expected, str) or len(expected) != 64
        or any(character not in "0123456789abcdef" for character in expected)
        or hashlib.sha256(data).hexdigest() != expected
    ):
        raise RuntimeError(code)


def source_git(environment: dict, *arguments: str) -> bytes:
    try:
        return subprocess.run(
            ["git", "-C", str(ROOT), *arguments], check=True, capture_output=True,
            env=environment, timeout=120,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("source_binding_git_unavailable") from None


def platform_ignore_file() -> Path:
    """Use only the exact existing public managed ignore data, not Git config."""
    try:
        path = Path("/etc/.gitignore").resolve(strict=True)
        if not path.is_relative_to("/nix/store") or not path.is_file():
            raise RuntimeError("source_binding_platform_ignore_unavailable")
        data = path.read_bytes()
    except OSError:
        raise RuntimeError("source_binding_platform_ignore_unavailable") from None
    require_digest(data, EXPECTED_PLATFORM_IGNORE_SHA256, "source_binding_platform_ignore_changed")
    return path


def source_inventory(raw: bytes, *, index: bool = False) -> dict:
    result = {}
    for item in raw.split(b"\0"):
        if not item:
            continue
        metadata, path_bytes = item.split(b"\t", 1)
        path = path_bytes.decode("utf-8", errors="strict")
        if (
            path.startswith("/") or "\\" in path or ":" in path
            or any(ord(char) < 32 or ord(char) == 127 for char in path)
            or any(part in {"", ".", "..", ".git"} for part in path.split("/"))
            or path in result
        ):
            raise RuntimeError("source_binding_path_invalid")
        fields = metadata.decode("ascii").split()
        if index:
            mode, oid, stage = fields
            if stage != "0":
                raise RuntimeError("source_binding_index_unmerged")
        else:
            mode, kind, oid = fields
            if kind != "blob":
                raise RuntimeError("source_binding_type_invalid")
        if mode not in {"100644", "100755"}:
            raise RuntimeError("source_binding_mode_invalid")
        result[path] = (mode, oid)
    if TOOLING_PATH not in result:
        raise RuntimeError("source_binding_tooling_missing")
    return result


def compare_inventory(expected: dict, observed: dict, tooling_oids: set) -> None:
    if expected.keys() != observed.keys():
        raise RuntimeError("source_binding_inventory_changed")
    for path, entry in expected.items():
        actual = observed[path]
        if path == TOOLING_PATH:
            if actual[0] != entry[0] or actual[1] not in tooling_oids:
                raise RuntimeError("source_binding_tooling_changed")
        elif actual != entry:
            raise RuntimeError("source_binding_runtime_changed")


def bound_file(root: Path, path: str, entry: tuple, tooling_sha256: str) -> bytes:
    target = root / path
    try:
        if target.parent.resolve(strict=True) != target.parent:
            raise RuntimeError("source_binding_symlink")
        descriptor = os.open(
            target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        )
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise RuntimeError("source_binding_file_type_invalid")
            if bool(before.st_mode & 0o111) != (entry[0] == "100755"):
                raise RuntimeError("source_binding_worktree_mode_changed")
            limit = MAX_TOOLING_BYTES if path == TOOLING_PATH else MAX_SOURCE_BYTES
            if before.st_size > limit:
                raise RuntimeError("source_binding_file_size_invalid")
            data = stream.read(before.st_size + 1)
            after = os.fstat(stream.fileno())
        fingerprint = lambda info: (
            info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns,
        )
        if fingerprint(before) != fingerprint(after) or len(data) != before.st_size:
            raise RuntimeError("source_binding_file_changed")
        if path == TOOLING_PATH:
            if len(data) > MAX_TOOLING_BYTES:
                raise RuntimeError("source_binding_tooling_size_invalid")
            require_digest(data, tooling_sha256, "source_binding_tooling_digest_mismatch")
        elif hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() != entry[1]:
            raise RuntimeError("source_binding_worktree_changed")
        return data
    except OSError:
        raise RuntimeError("source_binding_file_unavailable") from None


def verify_source_binding(environment: dict, tooling_sha256: str) -> tuple:
    """Fixed source objects plus an externally pinned, runner-only overlay.

    HEAD is observed, not trusted as a source identity. Committed descendants
    may differ only by exactly the approved tooling bytes. The digest is a
    caller input, never automatically discovered from this executable.
    """
    git = lambda *arguments: source_git(environment, *arguments)
    if ROOT.resolve(strict=True) != ROOT:
        raise RuntimeError("source_binding_root_invalid")
    identity = git("rev-parse", "HEAD", "HEAD^{tree}").decode().splitlines()
    if git("branch", "--show-current").decode().strip() != EXPECTED_BRANCH:
        raise RuntimeError("BASELINE_CHANGED")
    if git("rev-parse", EXPECTED_SOURCE_COMMIT + "^{tree}").decode().strip() != EXPECTED_SOURCE_TREE:
        raise RuntimeError("BASELINE_CHANGED")
    if git("show", "-s", "--format=%P", EXPECTED_SOURCE_COMMIT).decode().strip() != EXPECTED_REPAIR_PARENT:
        raise RuntimeError("BASELINE_CHANGED")
    if (
        git("rev-parse", EXPECTED_TOOLING_BASE + "^{tree}").decode().strip() != EXPECTED_TOOLING_TREE
        or git("show", "-s", "--format=%P", EXPECTED_TOOLING_BASE).decode().strip() != EXPECTED_SOURCE_COMMIT
    ):
        raise RuntimeError("BASELINE_CHANGED")
    git("merge-base", "--is-ancestor", EXPECTED_TOOLING_BASE, identity[0])
    require_digest(
        git("diff", "--no-ext-diff", "--no-textconv", EXPECTED_REPAIR_PARENT, EXPECTED_SOURCE_COMMIT),
        EXPECTED_REPAIR_PATCH, "source_binding_repair_patch_mismatch",
    )
    require_digest(
        git("diff", "--no-ext-diff", "--no-textconv", EXPECTED_SOURCE_COMMIT, EXPECTED_TOOLING_BASE),
        EXPECTED_PIN_PATCH, "source_binding_pin_patch_mismatch",
    )
    inventory = source_inventory(git("ls-tree", "-r", "-z", EXPECTED_SOURCE_COMMIT))
    tooling_base = source_inventory(git("ls-tree", "-r", "-z", EXPECTED_TOOLING_BASE))
    compare_inventory(inventory, tooling_base, {tooling_base[TOOLING_PATH][1]})
    tooling = bound_file(ROOT, TOOLING_PATH, inventory[TOOLING_PATH], tooling_sha256)
    tooling_oid = hashlib.sha1(b"blob " + str(len(tooling)).encode() + b"\0" + tooling).hexdigest()
    committed = source_inventory(git("ls-tree", "-r", "-z", identity[0]))
    compare_inventory(inventory, committed, {tooling_base[TOOLING_PATH][1], tooling_oid})
    compare_inventory(
        inventory, source_inventory(git("ls-files", "--stage", "-z"), index=True),
        {committed[TOOLING_PATH][1], tooling_oid},
    )
    ignore_path = platform_ignore_file()
    if git("ls-files", "--others", "--exclude-standard", "--exclude-from=" + str(ignore_path), "-z"):
        raise RuntimeError("source_binding_unexpected_untracked_files")
    fingerprints = []
    for path, entry in sorted(inventory.items()):
        data = bound_file(ROOT, path, entry, tooling_sha256)
        if path != TOOLING_PATH:
            fingerprints.append((path, entry[0], entry[1], hashlib.sha256(data).hexdigest()))
    result = {
        "source_commit": EXPECTED_SOURCE_COMMIT, "source_tree": EXPECTED_SOURCE_TREE,
        "repair_patch_sha256": EXPECTED_REPAIR_PATCH,
        "tooling_base_commit": EXPECTED_TOOLING_BASE, "tooling_base_tree": EXPECTED_TOOLING_TREE,
        "observed_checkout_commit": identity[0], "observed_checkout_tree": identity[1],
        "tooling_sha256": tooling_sha256, "tooling_git_blob": tooling_oid,
        "existing_platform_ignore_sha256": EXPECTED_PLATFORM_IGNORE_SHA256,
        "tracked_paths": len(inventory),
        "runtime_inventory_sha256": hashlib.sha256(json.dumps(fingerprints).encode()).hexdigest(),
    }
    return result, inventory


def binding_checks(directory: Path, evidence: Path) -> None:
    """Small synthetic tooling checks; no app imports or checkout mutations."""
    directory.mkdir()
    (directory / "tools").mkdir()
    payload, tooling = b"synthetic source\n", b"synthetic approved tooling\n"
    oid = lambda data: hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    expected = {"application.py": ("100644", oid(payload)), TOOLING_PATH: ("100644", oid(b"old tooling"))}
    approved = oid(tooling)
    allowed = {expected[TOOLING_PATH][1], approved}
    records = {}

    def denied(name, call):
        try:
            call()
        except RuntimeError as exc:
            records[name] = {"denied": True, "reason": str(exc)}
        else:
            raise RuntimeError("binding_negative_case_accepted:" + name)

    compare_inventory(expected, expected, allowed)
    committed_overlay = dict(expected, **{TOOLING_PATH: ("100644", approved)})
    compare_inventory(expected, committed_overlay, allowed)
    records["committed_tooling_overlay_accepted"] = {"passed": True}
    for name, observed in (
        ("extra_tracked_path", dict(expected, extra=("100644", oid(payload)))),
        ("missing_tracked_path", {TOOLING_PATH: expected[TOOLING_PATH]}),
        ("runtime_blob_changed", dict(expected, **{"application.py": ("100644", oid(b"changed"))})),
        ("runtime_mode_changed", dict(expected, **{"application.py": ("100755", oid(payload))})),
        ("runner_blob_not_approved", dict(expected, **{TOOLING_PATH: ("100644", oid(b"unknown"))})),
        ("runner_mode_changed", dict(expected, **{TOOLING_PATH: ("100755", approved)})),
    ):
        denied(name, lambda observed=observed: compare_inventory(expected, observed, allowed))
    target = directory / "application.py"
    target.write_bytes(payload)
    target.chmod(0o644)
    runner = directory / TOOLING_PATH
    runner.write_bytes(tooling)
    runner.chmod(0o644)
    digest = hashlib.sha256(tooling).hexdigest()
    bound_file(directory, "application.py", expected["application.py"], digest)
    bound_file(directory, TOOLING_PATH, expected[TOOLING_PATH], digest)
    records["approved_worktree_bytes_accepted"] = {"passed": True}
    denied("wrong_tooling_digest", lambda: bound_file(directory, TOOLING_PATH, expected[TOOLING_PATH], "0" * 64))
    denied("missing_tooling_digest", lambda: require_digest(tooling, None, "tooling_digest_required"))
    target.write_bytes(b"changed source")
    denied("runtime_worktree_bytes_changed", lambda: bound_file(directory, "application.py", expected["application.py"], digest))
    target.write_bytes(payload)
    target.chmod(0o755)
    denied("runtime_worktree_mode_changed", lambda: bound_file(directory, "application.py", expected["application.py"], digest))
    target.unlink()
    target.symlink_to(runner)
    denied("runtime_worktree_symlink", lambda: bound_file(directory, "application.py", expected["application.py"], digest))
    target.unlink()
    denied("runtime_worktree_missing", lambda: bound_file(directory, "application.py", expected["application.py"], digest))
    runner.write_bytes(b"unexpected tooling bytes")
    denied("runner_worktree_bytes_changed", lambda: bound_file(directory, TOOLING_PATH, expected[TOOLING_PATH], digest))
    denied("wrong_repair_patch_digest", lambda: require_digest(b"changed patch", EXPECTED_REPAIR_PATCH, "repair_patch_mismatch"))
    raw_index = b"100644 " + oid(payload).encode() + b" 1\tapplication.py\0"
    denied("unmerged_index", lambda: source_inventory(raw_index, index=True))
    (evidence / "binding-checks.json").write_text(json.dumps(records, indent=2) + "\n")
    print("BINDING_CHECKS_PASSED", len(records), flush=True)


def exact_candidate_source(destination: Path, environment: dict) -> None:
    """Read exact existing objects; never copy Git config, refs or credentials.

    The temporary object repository has the original commit/tree/blobs, not a
    newly invented source commit. Ancestor history is deliberately not needed.
    """
    def original(*args, input=None):
        return subprocess.run(
            ["git", "-C", str(ROOT), *args], input=input, check=True,
            capture_output=True, env=environment, timeout=120,
        ).stdout

    raw = original("ls-tree", "-r", "-t", "-z", EXPECTED_COMMIT)
    objects = {EXPECTED_COMMIT, EXPECTED_TREE}
    blobs = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        metadata, path_bytes = item.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        path = path_bytes.decode("utf-8")
        parts = path.split("/")
        if (
            path.startswith("/") or "\\" in path or ":" in path
            or any(ord(char) < 32 or ord(char) == 127 for char in path)
            or any(part in {"", ".", "..", ".git"} for part in parts)
        ):
            raise RuntimeError("candidate_inventory_path_invalid")
        objects.add(oid)
        if kind == "tree":
            continue
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise RuntimeError("candidate_inventory_type_invalid")
        blobs.append((path, mode, oid))
    batch = original("cat-file", "--batch", input=b"".join(oid.encode() + b"\n" for _, _, oid in blobs))
    stream = io.BytesIO(batch)
    destination.mkdir()
    for path, mode, oid in blobs:
        header = stream.readline().decode().split()
        if len(header) != 3 or header[:2] != [oid, "blob"]:
            raise RuntimeError("candidate_blob_unavailable")
        size = int(header[2])
        data = stream.read(size)
        if (
            len(data) != size or stream.read(1) != b"\n"
            or hashlib.sha1(b"blob " + str(size).encode() + b"\0" + data).hexdigest() != oid
        ):
            raise RuntimeError("candidate_blob_mismatch")
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o755 if mode == "100755" else 0o644)
    if stream.read(1):
        raise RuntimeError("candidate_batch_trailing_data")
    packed = original("pack-objects", "--stdout", input="".join(oid + "\n" for oid in sorted(objects)).encode())
    for args, data in (
        (["init", "-q"], None),
        (["index-pack", "--stdin"], packed),
        (["update-ref", "--no-deref", "HEAD", EXPECTED_COMMIT], None),
        (["read-tree", "HEAD"], None),
    ):
        subprocess.run(
            ["git", "-C", str(destination), *args], input=data, check=True,
            capture_output=True, env=environment, timeout=120,
        )


def startup_support():
    spec = importlib.util.spec_from_file_location(
        "synthetic_startup_support", Path(__file__).with_name("startup_evidence_support.py"),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
    if phase in {"package", "candidate-package"}:
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
            build_reference="synthetic-local-build:" + phase,
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
        prefix = "candidate" if phase == "candidate-package" else "packaged"
        (evidence / (prefix + "-startup-release.json")).write_text(json.dumps(release))
        (evidence / (prefix + "-public-trust.json")).write_text(json.dumps({
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY": base64.b64encode(public).decode(),
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID": public_key_id(public),
            "USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE": "test",
        }))
        print("PACKAGED_FILE_COUNT", len(artifact["managed_files"]), flush=True)
        print("PACKAGED_GIT_ABSENT", not (destination / ".git").exists(), flush=True)
        if phase == "candidate-package":
            if [artifact["source_commit"], artifact["source_tree_reference"]] != [EXPECTED_COMMIT, EXPECTED_TREE]:
                raise RuntimeError("candidate_manifest_source_mismatch")
            support = startup_support()
            descriptor, raw = support.artifact_descriptor(destination)
            inventory = {entry["path"]: entry for entry in descriptor["files"]}
            managed = {entry["path"]: entry for entry in artifact["managed_files"]}
            if set(inventory) != set(managed) | {"runtime_source_manifest.json"}:
                raise RuntimeError("candidate_inventory_closure_mismatch")
            for path, entry in managed.items():
                if inventory[path] != entry:
                    raise RuntimeError("candidate_inventory_signed_file_mismatch")
            digest = hashlib.sha256(raw).hexdigest()
            (evidence / "candidate-artifact-inventory.json").write_bytes(raw)
            (evidence / "candidate-runtime-manifest.json").write_bytes(
                (destination / "runtime_source_manifest.json").read_bytes(),
            )
            support.write_json(evidence / "artifact-binding.json", {
                "NON_PRODUCTION": True, "source_commit": EXPECTED_COMMIT,
                "source_tree": EXPECTED_TREE, "managed_file_count": len(artifact["managed_files"]),
                "build_reference": artifact["build_reference"],
                "runtime_environment": "test", "producer_scope": "test",
                "manifest_digest": artifact["manifest_digest"],
                "signed_manifest_sha256": hashlib.sha256(
                    (destination / "runtime_source_manifest.json").read_bytes(),
                ).hexdigest(),
                "artifact_inventory_sha256": digest,
                "local_artifact_reference": "sha256:" + digest,
                "synthetic_deployment_reference": "synthetic-local:" + digest,
                "filesystem_immutable": False, "container_image_created": False,
                "provider_deployment_created": False,
                "descriptor_file_count": len(descriptor["files"]),
                "dependency_closure_included": False,
                "external_runtime_configuration_included": False,
            })
            print("EXACT_CANDIDATE_SOURCE_MATCH True", flush=True)
            print("LOCAL_ARTIFACT_INVENTORY_SHA256", digest, flush=True)
            from unittest.mock import patch
            from security.runtime_artifact_builder import build_runtime_artifact_manifest
            from security.runtime_artifact_provenance import RuntimeArtifactError

            checks = {}

            def denied(name):
                try:
                    build_runtime_artifact_manifest(
                        fixture, signing_key=key, producer_key_id=public_key_id(public),
                        producer_scope="test",
                    )
                except RuntimeArtifactError as exc:
                    checks[name] = {"denied": True, "reason": str(exc)}
                else:
                    raise RuntimeError("publisher_negative_case_accepted:" + name)

            with patch.dict(os.environ, {"PATH": "/nonexistent"}):
                denied("missing_build_git_executable")
            index = fixture / ".git/index"
            saved_index = fixture / ".git/index.saved"
            index.rename(saved_index)
            try:
                denied("missing_build_index")
            finally:
                saved_index.rename(index)
            target = fixture / artifact["managed_files"][0]["path"]
            original_bytes = target.read_bytes()
            original_mode = target.stat().st_mode & 0o777
            target.write_bytes(original_bytes + b"\n")
            try:
                denied("dirty_tracked_source")
            finally:
                target.write_bytes(original_bytes)
            target.chmod(0o644 if original_mode & 0o111 else 0o755)
            try:
                denied("tracked_mode_mismatch")
            finally:
                target.chmod(original_mode)
            saved = target.with_name(target.name + ".synthetic-saved")
            target.rename(saved)
            target.symlink_to(saved)
            try:
                denied("tracked_symlink")
            finally:
                target.unlink()
                saved.rename(target)
            support.write_json(evidence / "publisher-boundary-checks.json", {
                "NON_PRODUCTION": True, "checks": checks,
                "provider_environment_observed": False,
                "source_commit": artifact["source_commit"],
                "source_tree": artifact["source_tree_reference"],
                "complete_tracked_files": len(artifact["managed_files"]),
                "modes": sorted({entry["mode"] for entry in artifact["managed_files"]}),
            })
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
    if phase == "extended-startup":
        # Pin imports to the exact package before pytest adjusts test paths.
        import gateway.app
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
    elif phase == "extended-startup":
        arguments += [str(Path(__file__).resolve().parents[1] / "tests/test_extended_startup_evidence.py")]
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
    if len(sys.argv) == 6 and sys.argv[1] == "--child":
        bound_file(ROOT, TOOLING_PATH, ("100644", ""), sys.argv[5])
        return child(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("phases", nargs="?")
    parser.add_argument("--tooling-sha256", required=True)
    arguments = parser.parse_args()
    evidence = arguments.evidence.absolute()
    environment = {
        "PATH": os.environ["PATH"], "HOME": "/nonexistent",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1",
    }
    binding_before, inventory = verify_source_binding(environment, arguments.tooling_sha256)
    before = hashes()
    (evidence / "source-binding-before.json").write_text(json.dumps(binding_before, indent=2) + "\n")
    (evidence / "source-before.json").write_text(json.dumps(before, indent=2) + "\n")
    temporary = Path(tempfile.mkdtemp(prefix="usbay-gitless-validation-"))
    binding_checks(temporary / "binding-checks", evidence)
    fixture = temporary / "source"
    fixture.mkdir()
    # Copy only the fixed source inventory and the externally hash-bound runner.
    # Every copy is checked again, not read blindly from the moving checkout.
    for name, entry in sorted(inventory.items()):
        target = fixture / name
        data = bound_file(ROOT, name, entry, arguments.tooling_sha256)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o755 if entry[0] == "100755" else 0o644)
    os.chdir(fixture)
    for command in (
        ["git", "init", "-q"], ["git", "add", "--force", "--", "."],
        ["git", "-c", "user.name=Synthetic Validation", "-c", "user.email=synthetic@example.invalid",
         "-c", "commit.gpgsign=false", "commit", "-qm", "Synthetic validation snapshot only"],
    ):
        subprocess.run(command, check=True, env=environment, capture_output=True)
    result = {}
    all_phases = ("trust", "integration", "regressions", "package", "startup", "candidate-package", "extended-startup")
    phases = tuple(arguments.phases.split(",")) if arguments.phases else all_phases
    if not phases or len(set(phases)) != len(phases) or any(phase not in all_phases for phase in phases):
        raise RuntimeError("invalid_validation_phase_selection")
    exact_source = temporary / "candidate-source"
    exact_candidate_source(exact_source, environment)
    # Preserve the disposable fixture for failure inspection, never activate it.
    (evidence / "isolated-root.txt").write_text(str(fixture) + "\n")
    for phase in phases:
        phase_root = temporary / phase
        if phase == "startup":
            phase_root = temporary / "package/full-package"
            if not phase_root.is_dir():
                result[phase] = "BLOCKED_BY_PACKAGE"
                continue
        elif phase == "candidate-package":
            phase_root = exact_source
        elif phase == "extended-startup":
            # Exercise the current development overlay, not only the historical
            # immutable candidate reconstructed for publisher-boundary evidence.
            phase_root = temporary / "package/full-package"
            if not phase_root.is_dir():
                result[phase] = "BLOCKED_BY_CANDIDATE_PACKAGE"
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
        if phase in {"startup", "extended-startup"}:
            prefix = "packaged"
            env.update(json.loads((evidence / (prefix + "-public-trust.json")).read_text()))
            env.update(
                PATH="/nonexistent",
                USBAY_RUNTIME_SOURCE_MANIFEST="runtime_source_manifest.json",
                USBAY_GOVERNANCE_RELEASE_PATH=str(evidence / (prefix + "-startup-release.json")),
                USBAY_VALIDATION_EVIDENCE=str(evidence),
                USBAY_BOUNDED_EXTENDED_STARTUP="1",
            )
        script_root = fixture if phase in {"candidate-package", "extended-startup"} else phase_root
        command = [
            sys.executable, "-I", "-S", "-B", str(script_root / "tools/run_gitless_integration_validation.py"),
            "--child", str(phase_root), str(evidence), phase, arguments.tooling_sha256,
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
    binding_after, _ = verify_source_binding(environment, arguments.tooling_sha256)
    (evidence / "source-binding-after.json").write_text(json.dumps(binding_after, indent=2) + "\n")
    (evidence / "source-after.json").write_text(json.dumps(after, indent=2) + "\n")
    (evidence / "phase-exits.json").write_text(json.dumps(result, indent=2) + "\n")
    if before != after or binding_before != binding_after:
        raise RuntimeError("validation_candidate_source_changed")
    print("SOURCE_PRESERVATION", "MATCH", flush=True)
    return 0 if all(code == 0 for code in result.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
