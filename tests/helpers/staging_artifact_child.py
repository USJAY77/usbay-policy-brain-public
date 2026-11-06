"""Fixed synthetic lifespan child. No HTTP server, operational trust or key files."""
from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "python")]
sys.dont_write_bytecode = True


def main() -> dict:
    inputs, state, mutation = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    if mutation not in {"valid", "missing", "tampered", "stale"}:
        raise RuntimeError("synthetic_staging_case_invalid")
    if (ROOT / ".git").exists() or state.is_relative_to(ROOT):
        raise RuntimeError("synthetic_staging_layout_invalid")
    metadata = json.loads(inputs.read_text(encoding="utf-8"))
    os.environ.update(USBAY_ENV="production", USBAY_RUNTIME_ENVIRONMENT="staging",
                      USBAY_DEPLOYMENT_SIGNING_MATERIAL=secrets.token_hex(32))
    from validation.mail_readiness.execution_boundary import install_no_exec, fresh_exec_gate_pass
    gate = install_no_exec()
    if not fresh_exec_gate_pass(gate):
        raise RuntimeError("synthetic_staging_exec_gate_invalid")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from security import runtime_artifact_provenance as provenance
    from security.runtime_artifact_authority import MANIFEST_NAME, get_runtime_artifact_authority

    # Synthetic issuer only, scoped to this subprocess. No private serialization.
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = provenance.public_key_id(public)
    entries = metadata["managed_files"]
    manifest = {"schema_version": provenance.MANIFEST_SCHEMA,
                "producer_contract": provenance.PRODUCER_CONTRACT,
                "producer_key_id": key_id, "producer_scope": "production",
                "source_commit": metadata["source_commit"],
                "source_tree_reference": metadata["source_tree_reference"],
                "managed_files": entries,
                "managed_set_hash": hashlib.sha256(provenance.canonical_bytes(entries)).hexdigest(),
                "build_reference": None,
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "manifest_id": secrets.token_hex(16)}
    manifest["manifest_digest"] = provenance.manifest_digest(manifest)
    manifest["signature"] = base64.b64encode(key.sign(provenance.signature_payload(manifest))).decode("ascii")
    (ROOT / MANIFEST_NAME).write_bytes(provenance.canonical_bytes(manifest))
    os.environ.update(USBAY_RUNTIME_SOURCE_MANIFEST=MANIFEST_NAME,
                      USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY=base64.b64encode(public).decode("ascii"),
                      USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID=key_id,
                      USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE="production")
    artifact = get_runtime_artifact_authority()
    release_path = state / "synthetic-release.json"
    os.environ["USBAY_GOVERNANCE_RELEASE_PATH"] = str(release_path)
    from security import deployment_attestation as deployment
    release = deployment.build_release_manifest(tenant_id="t1")
    if mutation == "tampered":
        release["release_signature"] = "invalid"
    elif mutation == "stale":
        from governance_runtime_monitor import load_runtime_governance_policy
        age = load_runtime_governance_policy().release_manifest_max_age_seconds
        release["deployment_timestamp"] = (datetime.now(timezone.utc) - timedelta(seconds=age + 10)).isoformat()
        release["release_signature"] = deployment.sign_release_manifest(release)
    if mutation != "missing":
        release_path.write_bytes(provenance.canonical_bytes(release))

    from gateway import app as gateway
    from runtime import enforcement_gateway
    if (deployment._artifact_authority() is not artifact
            or enforcement_gateway._git_commit_hash() != metadata["source_commit"]):
        raise RuntimeError("synthetic_staging_authority_mismatch")

    def verify_origins():
        expected = {item["path"]: item["sha256"] for item in entries}
        for name, module in tuple(sys.modules.items()):
            filename = getattr(module, "__file__", None)
            if not filename:
                continue
            path = Path(filename).resolve()
            module_path = name.replace(".", "/")
            candidates = {module_path + ".py", module_path + "/__init__.py",
                          "python/" + module_path + ".py", "python/" + module_path + "/__init__.py"}
            if candidates.intersection(expected) and not path.is_relative_to(ROOT):
                raise RuntimeError("synthetic_staging_module_origin_invalid")
            if path.is_relative_to(ROOT):
                relative = path.relative_to(ROOT).as_posix()
                if (relative not in expected
                        or hashlib.sha256(path.read_bytes()).hexdigest() != expected[relative]):
                    raise RuntimeError("synthetic_staging_module_origin_invalid")
        for module in (gateway, deployment):
            if not Path(module.__file__).resolve().is_relative_to(ROOT):
                raise RuntimeError("synthetic_staging_module_origin_invalid")

    verify_origins()

    async def enter():
        async with gateway.app.router.lifespan_context(gateway.app):
            authority = gateway.runtime_provenance_authority()
            if authority.artifact_authority is not artifact or authority.release_path != str(release_path):
                raise RuntimeError("synthetic_staging_authority_mismatch")

    reason = None
    try:
        asyncio.run(enter())
    except Exception as error:
        # Bounded classifications only; unknown errors remain failed tests.
        for code in ("release_manifest_missing", "release_signature_invalid", "release_manifest_freshness"):
            if code in str(error):
                reason = code
                break
        if reason is None:
            raise RuntimeError("synthetic_staging_unclassified_failure") from None
    verify_origins()
    artifact.assert_fresh()
    return {"case": mutation, "outcome": "DENY" if reason else "PASS", "reason": reason,
            "source_commit": metadata["source_commit"], "source_tree": metadata["source_tree_reference"],
            "module_origins_verified": True, "same_source_authority": True,
            "no_exec_gate": gate, "verification_functions_replaced": False}


if __name__ == "__main__":
    try:
        print(json.dumps(main(), sort_keys=True))
    except Exception as error:
        # Do not emit arbitrary exception text, paths, inputs or tracebacks.
        code = str(error)
        known = {"synthetic_staging_layout_invalid", "synthetic_staging_exec_gate_invalid",
                 "synthetic_staging_module_origin_invalid", "synthetic_staging_authority_mismatch",
                 "runtime_artifact_manifest_id_invalid", "runtime_artifact_producer_trust_unavailable",
                 "runtime_artifact_mode_invalid", "runtime_artifact_mode_conflict",
                 "runtime_artifact_unexpected_governed_file", "runtime_artifact_state_changed",
                 "deployment_signing_material_required", "release_integrity_build_metadata_required",
                 "NO_EXEC_FILTER_FAILED", "NO_EXEC_FILTER_NOT_PROVEN", "UNSUPPORTED_SECCOMP_ARCH"}
        if code not in known:
            code = "synthetic_staging_unclassified_failure"
        case = sys.argv[3] if len(sys.argv) == 4 else "invalid"
        if case not in {"valid", "missing", "tampered", "stale"}:
            case = "invalid"
        kind = type(error).__name__
        if kind not in {"PolicyRegistryError", "RuntimeArtifactError", "DecisionStoreError",
                        "DeploymentAttestationError", "RuntimeGovernanceDriftError",
                        "RuntimeError", "ModuleNotFoundError", "ImportError"}:
            kind = "OTHER"
        print(json.dumps({"case": case, "outcome": "ERROR", "reason": code, "error_type": kind}))
