"""Cold package imports and the real artifact gates, stopped before tenant gates.

No server, operational trust, platform build, or full-startup claim. The child
imports Gateway only from a disposable complete signed package. A deliberate
sentinel replaces the next independent validator; artifact checks stay real.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from security import deployment_attestation as deployment
from security.runtime_artifact_package import package_runtime_artifact
from security.runtime_artifact_provenance import public_key_id


CHILD = r'''
import json, os, sys
from pathlib import Path
root = Path.cwd()
sys.path[:0] = [str(root / "python"), str(root)]
def guard(event, arguments):
    if event == "subprocess.Popen" or event.startswith("socket."):
        raise AssertionError("Cold runtime process/network forbidden")
sys.addaudithook(guard)
import gateway.app as gateway
from security import runtime_artifact_authority as artifacts
from security.runtime_artifact_provenance import RuntimeArtifactError
from security.deployment_attestation import DeploymentAttestationError
from security.policy_registry import PolicyRegistryError
assert Path(gateway.__file__).resolve().parents[1] == root
assert artifacts.REPO_ROOT == root
assert "security.runtime_artifact_builder" not in sys.modules
assert "security.runtime_artifact_package" not in sys.modules
class IndependentGateReached(Exception):
    pass
seen = []
scanner, resolver = gateway.validate_no_forbidden_runtime_files, gateway.runtime_provenance_authority
def scan(*args, **kwargs):
    seen.append(kwargs["artifact_authority"])
    return scanner(*args, **kwargs)
def resolve(*args, **kwargs):
    seen.append(kwargs["artifact_authority"])
    return resolver(*args, **kwargs)
def stop_before_tenant():
    raise IndependentGateReached()
gateway.validate_no_forbidden_runtime_files = scan
gateway.runtime_provenance_authority = resolve
gateway.load_tenant_policy = stop_before_tenant
try:
    gateway.validate_policy_registry_startup()
except IndependentGateReached:
    assert len(seen) == 2 and seen[0] is seen[1]
    assert seen[0].verified.source_commit == os.environ["EXPECTED_SOURCE_COMMIT"]
    assert seen[0].verified.source_tree_reference == os.environ["EXPECTED_SOURCE_TREE"]
    assert seen[0] is artifacts.get_runtime_artifact_authority()
    print(json.dumps({"stage": "INDEPENDENT_TENANT_GATE_REACHED", "shared_authority": True}))
except (RuntimeArtifactError, DeploymentAttestationError, PolicyRegistryError) as error:
    print(json.dumps({"stage": "DENIED_BEFORE_TENANT", "error_type": type(error).__name__}))
else:
    raise AssertionError("Expected bounded startup stop")
'''


@pytest.fixture(scope="module")
def signed_packages(tmp_path_factory):
    base = tmp_path_factory.mktemp("cold-source-packages")
    source = Path(__file__).resolve().parents[1]
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    packages = {}
    for scope in ("test", "production"):
        root = base / scope
        package_runtime_artifact(source, root, signing_key=private,
                                 producer_key_id=public_key_id(public), producer_scope=scope)
        packages[scope] = root
    # These production-shaped inputs exist only in this disposable test fixture.
    return packages, public


@pytest.mark.parametrize("case", ["valid_test", "valid_synthetic_production", "missing_manifest",
                                  "missing_trust", "tampered_file", "test_producer_in_production"])
def test_cold_packaged_gateway_reaches_or_denies_before_independent_gate(signed_packages, tmp_path, case):
    packages, public = signed_packages
    scope = "production" if case == "valid_synthetic_production" else "test"
    root = tmp_path / "artifact"
    shutil.copytree(packages[scope], root)
    manifest = json.loads((root / "runtime_source_manifest.json").read_bytes())
    assert not (root / ".git").exists()
    release = {
        "release_id": "synthetic-cold-start",
        "deployment_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_commit": manifest["source_commit"],
        "policy_bundle_hash": deployment.policy_bundle_hash(),
        "tenant_id": "t1", "previous_release_hash": "GENESIS",
        "activating_node_id": deployment._canonical_activating_node_id(),
    }
    material = "synthetic-cold-start-release-material"
    release["release_signature"] = deployment.sign_release_manifest(release, material)
    release_path = tmp_path / "release.json"
    release_path.write_text(json.dumps(release))
    mode = "production" if case in {"valid_synthetic_production", "test_producer_in_production"} else "test"
    environment = {
        "PATH": "/nonexistent", "HOME": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "1",
        "USBAY_ENV": mode, "USBAY_RUNTIME_SOURCE_MANIFEST": "runtime_source_manifest.json",
        "USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY": base64.b64encode(public).decode(),
        "USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID": public_key_id(public),
        "USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE": scope,
        "USBAY_DEPLOYMENT_SIGNING_MATERIAL": material,
        "USBAY_GOVERNANCE_RELEASE_PATH": str(release_path),
        "EXPECTED_SOURCE_COMMIT": manifest["source_commit"],
        "EXPECTED_SOURCE_TREE": manifest["source_tree_reference"],
    }
    if case == "missing_manifest":
        (root / "runtime_source_manifest.json").unlink()
    elif case == "missing_trust":
        del environment["USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY"]
    elif case == "tampered_file":
        # Corrupt a non-imported managed file, never execute modified Python.
        (root / ".replit").write_bytes(b"TAMPERED = true\n")
    completed = subprocess.run([sys.executable, "-I", "-B", "-c", CHILD], cwd=root,
                               env=environment, capture_output=True, timeout=60)
    assert completed.returncode == 0, completed.stderr.decode()[-3000:]
    assert completed.stderr == b""
    result = json.loads(completed.stdout)
    if case in {"valid_test", "valid_synthetic_production"}:
        assert result == {"stage": "INDEPENDENT_TENANT_GATE_REACHED", "shared_authority": True}
    else:
        assert result["stage"] == "DENIED_BEFORE_TENANT"
