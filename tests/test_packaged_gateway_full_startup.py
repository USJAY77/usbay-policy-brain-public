"""Complete local TEST lifespan; actual validators, no stop sentinel or server."""
from datetime import datetime, timezone
import base64
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from audit.immutable_ledger import ledger_path_for
from security import deployment_attestation as deployment
from security.runtime_artifact_provenance import public_key_id
from tests.helpers.packaged_startup import synthetic_policy_inputs
from tests.test_packaged_gateway_cold_start import signed_packages


CHILD = r'''
import json, os, sys
from pathlib import Path
root = Path.cwd()
sys.path[:0] = [str(root / "python"), str(root)]
def guard(event, arguments):
    if event == "subprocess.Popen" or event in {"socket.connect", "socket.connect_ex", "socket.bind", "socket.getaddrinfo"}:
        raise AssertionError("Runtime process/network forbidden")
sys.addaudithook(guard)
import gateway.app as gateway
from security import runtime_artifact_authority as artifacts
from tests.helpers.packaged_startup import observe_startup
assert Path(gateway.__file__).resolve().parents[1] == root
assert "security.runtime_artifact_builder" not in sys.modules
assert "security.runtime_artifact_package" not in sys.modules
for name, value in json.loads(os.environ["SYNTHETIC_POLICY_PATHS"]).items():
    setattr(gateway, name, Path(value))
gateway._policy_registry_cache = None
gateway._policy_registry_cache_key = None
case = os.environ["SYNTHETIC_STARTUP_CASE"]
if case == "hydra_roles":
    gateway.EXPECTED_NODE_ROLES = {}  # Invalid fixture data, not a validator replacement.
trace = []
completed_runs = []
try:
    for run in range(2 if case in {"restart_valid", "revoked_between_restarts", "tampered_between_restarts"} else 1):
        trace = []
        observe_startup(trace)
        completed_runs.append(trace)
        if run == 0 and case == "revoked_between_restarts":
            path = gateway.POLICY_KEY_CONFIG_PATH
            data = json.loads(path.read_text())
            data["revoked_keys"] = data["active_keys"]
            path.write_text(json.dumps(data))
        elif run == 0 and case == "tampered_between_restarts":
            (root / ".replit").write_bytes(b"TAMPERED_BETWEEN_STARTUPS = true\n")
except Exception as error:
    # Keep output bounded; no exception text, keys, inputs or policy bodies.
    print(json.dumps({"status": "DENIED", "error_type": type(error).__name__, "trace": trace, "completed_runs": completed_runs}))
else:
    assert artifacts.get_runtime_artifact_authority().root == root
    print(json.dumps({"status": "LIFESPAN_COMPLETED_TEST_ONLY", "trace": trace, "completed_runs": completed_runs}))
'''


@pytest.mark.parametrize("case,blocked_stage,error_type", [
    ("valid", None, None),
    ("restart_valid", None, None),
    # Release/provenance validates tenant membership before the separate tenant gate.
    ("invalid_tenant", "runtime_provenance_authority", "TenantIsolationError"),
    ("replay_fail_open", "validate_replay_policy_startup", "DecisionStoreError"),
    ("hydra_roles", "validate_hydra_consensus_startup", "DecisionStoreError"),
    ("corrupt_ledger", "assert_ledger_valid", "LedgerIntegrityError"),
    ("wrong_policy_signature", "load_policy_registry", "PolicyRegistryError"),
    ("revoked_policy_key", "load_policy_registry", "PolicyRegistryError"),
    ("policy_role_mismatch", "load_policy_registry", "PolicyRegistryError"),
    ("wrong_release_source", "runtime_provenance_authority", "DeploymentAttestationError"),
    ("stale_release", "validate_runtime_governance_health", "RuntimeGovernanceDriftError"),
    ("revoked_between_restarts", "load_policy_registry", "PolicyRegistryError"),
    ("tampered_between_restarts", "before_scanner", "RuntimeArtifactError"),
])
def test_complete_test_lifespan_without_git_or_runtime_processes(
        signed_packages, tmp_path, case, blocked_stage, error_type):
    packages, public = signed_packages
    root = tmp_path / "artifact"
    shutil.copytree(packages["test"], root)
    manifest = json.loads((root / "runtime_source_manifest.json").read_bytes())
    paths = synthetic_policy_inputs(tmp_path / "independent-policy")
    if case == "wrong_policy_signature":
        paths["POLICY_REGISTRY_SIGNATURE_PATH"].write_text("invalid-synthetic-signature")
    elif case == "revoked_policy_key":
        path = paths["POLICY_KEY_CONFIG_PATH"]
        data = json.loads(path.read_text())
        data["revoked_keys"] = data["active_keys"]
        path.write_text(json.dumps(data))
    elif case == "policy_role_mismatch":
        path = paths["POLICY_AUTHORITY_PATH"]
        data = json.loads(path.read_text())
        data["policy_author"] = "other-synthetic-author"
        path.write_text(json.dumps(data))
    release = {
        "release_id": "synthetic-complete-startup",
        "deployment_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_commit": manifest["source_commit"],
        "policy_bundle_hash": deployment.policy_bundle_hash(), "tenant_id": "t1",
        "previous_release_hash": "GENESIS",
        "activating_node_id": deployment._canonical_activating_node_id(),
    }
    if case == "wrong_release_source":
        release["git_commit"] = "f" * 40
    elif case == "stale_release":
        release["deployment_timestamp"] = "1970-01-01T00:00:00Z"
    material = "synthetic-complete-startup-release-material"
    release["release_signature"] = deployment.sign_release_manifest(release, material)
    release_path = tmp_path / "release.json"
    release_path.write_text(json.dumps(release))
    ledger = root / ledger_path_for(Path("tmp/audit_chain.json"))
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_bytes(b"")  # Fresh synthetic namespace; never reset an existing store.
    if case == "corrupt_ledger":
        ledger.write_bytes(b"invalid-synthetic-ledger")
    environment = {
        "PATH": "/nonexistent", "HOME": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "1",
        "USBAY_ENV": "test", "USBAY_RUNTIME_SOURCE_MANIFEST": "runtime_source_manifest.json",
        "USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY": base64.b64encode(public).decode(),
        "USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID": public_key_id(public),
        "USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE": "test",
        "USBAY_DEPLOYMENT_SIGNING_MATERIAL": material,
        "USBAY_GOVERNANCE_RELEASE_PATH": str(release_path),
        "SYNTHETIC_POLICY_PATHS": json.dumps({name: str(path) for name, path in paths.items()}),
        "SYNTHETIC_STARTUP_CASE": case,
    }
    if case == "invalid_tenant":
        tenant_root = tmp_path / "invalid-tenant"
        path = tenant_root / "governance/tenant_policy.json"
        path.parent.mkdir(parents=True)
        path.write_text("{}")
        environment["USBAY_TENANT_POLICY_ROOT"] = str(tenant_root)
    elif case == "replay_fail_open":
        path = tmp_path / "replay.json"
        path.write_text(json.dumps({"replay_fail_closed": False}))
        environment["USBAY_REPLAY_POLICY_PATH"] = str(path)
    completed = subprocess.run([sys.executable, "-I", "-B", "-c", CHILD], cwd=root,
                               env=environment, capture_output=True, timeout=60)
    assert completed.returncode == 0, completed.stderr.decode()[-3000:]
    assert completed.stderr == b""
    result = json.loads(completed.stdout)
    if blocked_stage is not None:
        assert result["status"] == "DENIED", result
        assert result["error_type"] == error_type, result
        assert "lifespan:yielded" not in result["trace"], result
        if blocked_stage == "before_scanner":
            assert result["trace"] == []
        else:
            assert result["trace"][-1] == blocked_stage + ":entered", result
        assert len(result["completed_runs"]) == (1 if case.endswith("between_restarts") else 0)
        return
    assert result["status"] == "LIFESPAN_COMPLETED_TEST_ONLY", result
    passed = [item.removesuffix(":passed") for item in result["trace"] if item.endswith(":passed")]
    assert passed == ["validate_no_forbidden_runtime_files", "runtime_provenance_authority",
                      "load_tenant_policy", "validate_replay_policy_startup",
                      "validate_hydra_consensus_startup", "assert_startup_release_integrity",
                      "validate_runtime_governance_health", "assert_ledger_valid", "load_policy_registry"]
    assert result["trace"][-2:] == ["lifespan:yielded", "lifespan:exited"]
    assert len(result["completed_runs"]) == (2 if case == "restart_valid" else 1)
